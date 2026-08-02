//! Continuous health tests for raw noise sources, per NIST SP 800-90B §4.4.
//!
//! These run on the *raw* bytes from each TRNG before they are absorbed. A secure
//! element that has died and started returning zeroes, or an STM32 RNG left disabled,
//! must be detected — not quietly folded into the pool where it looks like entropy.

/// Repetition Count Test cutoff for a source assumed to deliver `H` bits of entropy
/// per byte, at a false-positive rate of 2^-30.
///
/// `C = 1 + ceil(-log2(alpha) / H)`, SP 800-90B §4.4.1. For a full-entropy byte
/// source (`H = 8`): `C = 1 + ceil(30/8) = 5`.
pub const REPETITION_CUTOFF: usize = 5;

/// Adaptive Proportion Test window and cutoff, SP 800-90B §4.4.2, for `H = 8` and
/// `W = 512` at alpha = 2^-30. The cutoff is the smallest `C` with
/// `Pr[Binomial(511, 2^-8) >= C-1] <= 2^-30`; for these parameters that is 13.
pub const ADAPTIVE_WINDOW: usize = 512;
pub const ADAPTIVE_CUTOFF: usize = 13;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum HealthError {
    /// The same byte value repeated too many times in a row: a stuck source.
    Repetition { value: u8, run: usize },
    /// One value dominated a 512-byte window far beyond chance.
    AdaptiveProportion { value: u8, count: usize },
    /// The whole sample was a single repeated byte (all-zero, all-0xff). Caught by the
    /// repetition test too, but reported distinctly because it is the classic
    /// "peripheral not enabled" and "dead secure element" signature.
    Constant { value: u8 },
    /// Too few bytes to judge. Callers must not credit entropy for these.
    TooShort { len: usize },
}

/// Stateful continuous tester. One instance per noise source, kept across draws so a
/// run that straddles two reads is still caught.
#[derive(Clone, Debug)]
pub struct ContinuousTest {
    last: Option<u8>,
    run: usize,
    /// Adaptive-proportion window state.
    window_value: u8,
    window_count: usize,
    window_seen: usize,
    window_started: bool,
}

impl Default for ContinuousTest {
    fn default() -> Self {
        Self::new()
    }
}

impl ContinuousTest {
    pub const fn new() -> Self {
        Self {
            last: None,
            run: 0,
            window_value: 0,
            window_count: 0,
            window_seen: 0,
            window_started: false,
        }
    }

    /// Feed a fresh sample. Returns `Err` the moment a test trips.
    pub fn check(&mut self, sample: &[u8]) -> Result<(), HealthError> {
        if sample.len() < MIN_SAMPLE {
            return Err(HealthError::TooShort { len: sample.len() });
        }

        // Constant-sample shortcut, so the caller gets the clearer diagnosis.
        let first = sample[0];
        if sample.iter().all(|&b| b == first) {
            return Err(HealthError::Constant { value: first });
        }

        for &b in sample {
            // -- repetition count --
            if self.last == Some(b) {
                self.run += 1;
            } else {
                self.last = Some(b);
                self.run = 1;
            }
            if self.run >= REPETITION_CUTOFF {
                return Err(HealthError::Repetition {
                    value: b,
                    run: self.run,
                });
            }

            // -- adaptive proportion --
            if !self.window_started {
                self.window_started = true;
                self.window_value = b;
                self.window_count = 1;
                self.window_seen = 1;
                continue;
            }
            self.window_seen += 1;
            if b == self.window_value {
                self.window_count += 1;
                if self.window_count >= ADAPTIVE_CUTOFF {
                    return Err(HealthError::AdaptiveProportion {
                        value: self.window_value,
                        count: self.window_count,
                    });
                }
            }
            if self.window_seen >= ADAPTIVE_WINDOW {
                self.window_started = false;
            }
        }
        Ok(())
    }
}

/// Shortest sample we will judge. Below this the tests have no power, and crediting
/// entropy for an unjudged sample is the failure mode we are guarding against.
pub const MIN_SAMPLE: usize = 8;

/// One-shot check for callers that do not keep state.
pub fn check_once(sample: &[u8]) -> Result<(), HealthError> {
    ContinuousTest::new().check(sample)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic non-random-looking-but-varied filler for the happy paths.
    fn counter(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn varied_sample_passes() {
        assert!(check_once(&counter(256)).is_ok());
    }

    #[test]
    fn all_zero_is_rejected() {
        assert_eq!(
            check_once(&[0u8; 32]),
            Err(HealthError::Constant { value: 0 })
        );
    }

    #[test]
    fn all_ones_is_rejected() {
        assert_eq!(
            check_once(&[0xffu8; 32]),
            Err(HealthError::Constant { value: 0xff })
        );
    }

    #[test]
    fn a_long_run_inside_a_varied_sample_is_rejected() {
        let mut s = counter(64);
        for b in &mut s[10..10 + REPETITION_CUTOFF] {
            *b = 0x5a;
        }
        assert!(matches!(
            check_once(&s),
            Err(HealthError::Repetition { value: 0x5a, .. })
        ));
    }

    #[test]
    fn a_run_just_under_the_cutoff_passes() {
        let mut s = counter(64);
        for b in &mut s[10..10 + REPETITION_CUTOFF - 1] {
            *b = 0x5a;
        }
        assert!(check_once(&s).is_ok());
    }

    #[test]
    fn a_run_straddling_two_draws_is_still_caught() {
        let mut t = ContinuousTest::new();
        // Ends with three 0x11s ...
        let mut a = counter(32);
        let n = a.len();
        a[n - 3..].fill(0x11);
        assert!(t.check(&a).is_ok());
        // ... and the next draw starts with more. A stateless check would miss this.
        let mut b = counter(32);
        b[..2].fill(0x11);
        assert!(matches!(t.check(&b), Err(HealthError::Repetition { .. })));
    }

    #[test]
    fn a_biased_source_trips_the_adaptive_proportion_test() {
        // 0x42 appears far more often than 1/256 of the time, without ever repeating
        // consecutively — so only the adaptive test can catch it.
        let mut s = Vec::new();
        for i in 0..ADAPTIVE_WINDOW {
            s.push(0x42);
            s.push((i % 97) as u8 | 1);
        }
        assert!(matches!(
            check_once(&s),
            Err(HealthError::AdaptiveProportion { value: 0x42, .. })
        ));
    }

    #[test]
    fn short_samples_are_refused_rather_than_credited() {
        assert!(matches!(
            check_once(&[1, 2, 3]),
            Err(HealthError::TooShort { len: 3 })
        ));
        assert!(matches!(
            check_once(&[]),
            Err(HealthError::TooShort { len: 0 })
        ));
    }

    #[test]
    fn a_realistic_random_stream_passes() {
        // SHA-256 output chained: statistically indistinguishable from a good TRNG,
        // so the tests must not fire on it.
        use sha2::{Digest, Sha256};
        let mut out = Vec::new();
        let mut h = [0u8; 32];
        for i in 0..64u32 {
            let mut d = Sha256::new();
            d.update(h);
            d.update(i.to_le_bytes());
            h = d.finalize().into();
            out.extend_from_slice(&h);
        }
        let mut t = ContinuousTest::new();
        assert!(t.check(&out).is_ok(), "false positive on good randomness");
    }
}
