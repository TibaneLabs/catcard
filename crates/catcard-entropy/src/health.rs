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

/// Consecutive samples the start-up test must see pass before a source's output is used.
///
/// SP 800-90B §4.3: the start-up tests use the §4.4 health tests "on at least 1024
/// consecutive samples" before the first use of the noise source. A sample here is one
/// byte, as it is for the continuous tests.
pub const STARTUP_SAMPLES: usize = 1024;

/// Where a source's start-up test stands.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Startup {
    /// Still collecting: `tested` consecutive bytes have passed so far.
    Pending { tested: usize },
    /// [`STARTUP_SAMPLES`] consecutive bytes passed the continuous tests.
    Passed,
    /// A continuous test tripped inside the start-up window. Sticky: a source that fails
    /// its start-up test stays failed for the rest of the session, however well it
    /// behaves afterwards.
    Failed(HealthError),
}

/// The SP 800-90B §4.3 start-up test for one source: the §4.4 continuous tests (same
/// cutoffs, same state carried across reads) run over the first [`STARTUP_SAMPLES`]
/// bytes the source produces, and a verdict on those.
///
/// The continuous tests keep running after the verdict, so one instance is all a source
/// needs; [`feed`](Self::feed) returns the continuous verdict for each read.
#[derive(Clone, Debug)]
pub struct StartupTest {
    continuous: ContinuousTest,
    state: Startup,
}

impl Default for StartupTest {
    fn default() -> Self {
        Self::new()
    }
}

impl StartupTest {
    pub const fn new() -> Self {
        Self {
            continuous: ContinuousTest::new(),
            state: Startup::Pending { tested: 0 },
        }
    }

    pub fn state(&self) -> Startup {
        self.state
    }

    pub fn passed(&self) -> bool {
        self.state == Startup::Passed
    }

    /// Feed the source's next read. Runs the continuous tests on it and advances the
    /// start-up verdict; returns the continuous verdict for this read, which is what
    /// decides whether *this read* is credited.
    ///
    /// A read too short to judge ([`HealthError::TooShort`]) neither advances nor fails
    /// the start-up test: it was not tested, so it cannot count as a tested sample, and a
    /// short answer is not evidence of a fault.
    pub fn feed(&mut self, sample: &[u8]) -> Result<(), HealthError> {
        let verdict = self.continuous.check(sample);
        if let Startup::Pending { tested } = self.state {
            self.state = match verdict {
                Ok(()) => {
                    let tested = tested.saturating_add(sample.len());
                    if tested >= STARTUP_SAMPLES {
                        Startup::Passed
                    } else {
                        Startup::Pending { tested }
                    }
                }
                Err(HealthError::TooShort { .. }) => self.state,
                Err(e) => Startup::Failed(e),
            };
        }
        verdict
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream(tag: u8, n: usize) -> Vec<u8> {
        use purecrypto::hash::{Digest, Sha256};
        let mut out = Vec::new();
        let mut h = [tag; 32];
        while out.len() < n {
            h = Sha256::digest(&h);
            out.extend_from_slice(&h);
        }
        out.truncate(n);
        out
    }

    #[test]
    fn startup_needs_the_full_window_before_it_passes() {
        let mut t = StartupTest::new();
        let s = stream(1, STARTUP_SAMPLES);
        let (a, b) = s.split_at(STARTUP_SAMPLES - 32);
        assert!(t.feed(a).is_ok());
        assert_eq!(
            t.state(),
            Startup::Pending {
                tested: STARTUP_SAMPLES - 32
            }
        );
        assert!(!t.passed());
        assert!(t.feed(b).is_ok());
        assert!(t.passed());
    }

    #[test]
    fn a_fault_inside_the_window_fails_startup_for_good() {
        let mut t = StartupTest::new();
        t.feed(&stream(2, 256)).unwrap();
        assert!(t.feed(&[0u8; 32]).is_err());
        assert_eq!(
            t.state(),
            Startup::Failed(HealthError::Constant { value: 0 })
        );
        // Behaving afterwards does not bring it back.
        for i in 0..8 {
            assert!(t.feed(&stream(10 + i, 512)).is_ok());
        }
        assert!(matches!(t.state(), Startup::Failed(_)));
    }

    #[test]
    fn a_fault_after_startup_is_a_continuous_failure_only() {
        let mut t = StartupTest::new();
        t.feed(&stream(3, STARTUP_SAMPLES)).unwrap();
        assert!(t.passed());
        assert!(
            t.feed(&[0xffu8; 32]).is_err(),
            "the read itself still fails"
        );
        assert!(
            t.passed(),
            "the start-up verdict is about the start-up window"
        );
    }

    #[test]
    fn a_run_straddling_reads_inside_the_window_fails_startup() {
        let mut t = StartupTest::new();
        let mut a = stream(4, 64);
        a[61..].fill(0x33);
        t.feed(&a).unwrap();
        let mut b = stream(5, 64);
        b[..2].fill(0x33);
        assert!(t.feed(&b).is_err());
        assert!(matches!(
            t.state(),
            Startup::Failed(HealthError::Repetition { value: 0x33, .. })
        ));
    }

    #[test]
    fn short_reads_neither_advance_nor_fail_startup() {
        let mut t = StartupTest::new();
        assert!(t.feed(&[1, 2, 3]).is_err());
        assert_eq!(t.state(), Startup::Pending { tested: 0 });
    }

    #[test]
    fn a_biased_source_fails_startup_on_the_adaptive_test() {
        let mut s = Vec::new();
        for i in 0..STARTUP_SAMPLES / 2 {
            s.push(0x42);
            s.push((i % 97) as u8 | 1);
        }
        let mut t = StartupTest::new();
        for chunk in s.chunks(32) {
            let _ = t.feed(chunk);
        }
        assert!(matches!(
            t.state(),
            Startup::Failed(HealthError::AdaptiveProportion { value: 0x42, .. })
        ));
    }

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
        use purecrypto::hash::{Digest, Sha256};
        let mut out = Vec::new();
        let mut h = [0u8; 32];
        for i in 0..64u32 {
            let mut d = Sha256::new();
            d.update(&h);
            d.update(&i.to_le_bytes());
            h = d.finalize();
            out.extend_from_slice(&h);
        }
        let mut t = ContinuousTest::new();
        assert!(t.check(&out).is_ok(), "false positive on good randomness");
    }
}
