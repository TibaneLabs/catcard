//! The entropy accumulator.
//!
//! # Why this exists
//!
//! The stock Coldcard firmware derives the BIP-39 wallet seed from two chained
//! software PRNGs XORed together, not from the hardware TRNG. On mk3 the whole state
//! reduces to roughly 22 bits; on mk4 a partial mitigation reseeds only 32 bits of it.
//! Two specific mistakes made that possible, and this module is built to make both
//! unrepresentable:
//!
//! 1. **Truncating a good source.** Sources are absorbed whole, never narrowed to a
//!    word. There is no API that takes a `u32` of "entropy".
//! 2. **Combining by XOR.** Everything goes through a cryptographic accumulator with
//!    domain separation, so a predictable source can only ever fail to help — it can
//!    never cancel a good one.
//!
//! A third protection is added on top: the pool **counts** what it has absorbed and
//! [`draw`](EntropyPool::draw) refuses to produce seed material until the policy is
//! met. Silently proceeding with weak entropy is the failure mode that matters, so it
//! is a `Result`, not a warning.
//!
//! # Construction
//!
//! `state <- SHA-512(state || tag || len_be64 || data)`, and output is
//! `SHA-512(state || "catcard/draw" || counter)` — a fresh chain per draw, so drawing
//! never rewinds the pool or lets one output reveal another.

use core::fmt;
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::health::{ContinuousTest, HealthError};

/// Where a contribution came from. The variant decides how much entropy is credited.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Source {
    /// STM32 hardware TRNG (`RNG_DR`), read directly by us.
    Stm32Trng,
    /// The bootloader's own read of the STM32 TRNG, via callgate 17.
    BootloaderTrng,
    /// ATECC608 `Random`, via callgate 26 source 1.
    Se1Trng,
    /// Second secure element TRNG, via callgate 26 source 2 (mk4+).
    Se2Trng,
    /// Timing jitter from user interaction (DWT cycle counts at keypress edges).
    /// Real but low-rate entropy; credited conservatively.
    UserTiming,
    /// Anything else worth mixing but not worth trusting: uptime, SD card serial,
    /// uninitialised RAM patterns. Credited **zero**.
    Auxiliary,
    /// Values that are per-device constants or public. Mixed for domain separation
    /// only. Credited **zero** — the device unique ID is the textbook example, since
    /// it is published as the USB serial number.
    NonSecret,
}

impl Source {
    /// A dedicated hardware noise source, as opposed to a derived or public value.
    pub const fn is_hardware_trng(self) -> bool {
        matches!(
            self,
            Source::Stm32Trng | Source::BootloaderTrng | Source::Se1Trng | Source::Se2Trng
        )
    }

    /// Bits of entropy credited per byte absorbed.
    ///
    /// Hardware TRNGs are credited at 4 bits/byte, half their nominal rate. That
    /// haircut is deliberate: it means a 32-byte TRNG read counts for 128 bits, so the
    /// 256-bit policy cannot be satisfied by a single 32-byte read from a single chip.
    const fn bits_per_byte(self) -> u32 {
        match self {
            Source::Stm32Trng | Source::BootloaderTrng | Source::Se1Trng | Source::Se2Trng => 4,
            // A keypress timestamp is a handful of unpredictable low bits at best.
            Source::UserTiming => 1,
            Source::Auxiliary | Source::NonSecret => 0,
        }
    }

    /// Domain-separation tag. Distinct byte strings, so no two sources can alias.
    const fn tag(self) -> &'static [u8] {
        match self {
            Source::Stm32Trng => b"catcard/src/stm32-trng",
            Source::BootloaderTrng => b"catcard/src/bl-trng",
            Source::Se1Trng => b"catcard/src/se1-trng",
            Source::Se2Trng => b"catcard/src/se2-trng",
            Source::UserTiming => b"catcard/src/user-timing",
            Source::Auxiliary => b"catcard/src/aux",
            Source::NonSecret => b"catcard/src/non-secret",
        }
    }

    const fn index(self) -> usize {
        match self {
            Source::Stm32Trng => 0,
            Source::BootloaderTrng => 1,
            Source::Se1Trng => 2,
            Source::Se2Trng => 3,
            Source::UserTiming => 4,
            Source::Auxiliary => 5,
            Source::NonSecret => 6,
        }
    }
}

const NUM_SOURCES: usize = 7;

/// The bar a pool must clear before it may produce wallet-seed material.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// Total credited entropy required.
    pub min_bits: u32,
    /// How many *distinct* hardware TRNGs must have contributed.
    ///
    /// Two is the right answer on mk4/Q, which have the STM32 RNG plus two secure
    /// elements. On mk3 only the STM32 RNG is reachable, so a mk3 pool must either
    /// relax this to 1 or make up the difference with user timing — see
    /// [`Policy::single_trng`].
    pub min_hw_sources: u32,
}

impl Policy {
    /// The default for seed generation on hardware with more than one TRNG.
    pub const STRICT: Policy = Policy {
        min_bits: 256,
        min_hw_sources: 2,
    };

    /// For boards with exactly one reachable TRNG (mk3). Still demands 256 credited
    /// bits, which at 4 bits/byte means at least 64 bytes drawn from that TRNG.
    pub const fn single_trng() -> Policy {
        Policy {
            min_bits: 256,
            min_hw_sources: 1,
        }
    }
}

impl Default for Policy {
    fn default() -> Self {
        Policy::STRICT
    }
}

/// Why a draw was refused.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Insufficient {
    /// Not enough credited entropy yet.
    Bits { have: u32, need: u32 },
    /// Not enough independent hardware noise sources.
    HardwareSources { have: u32, need: u32 },
    /// A source failed its health test; the pool is poisoned until it is rebuilt.
    Unhealthy { source: Source, error: HealthError },
}

impl fmt::Display for Insufficient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Insufficient::Bits { have, need } => {
                write!(f, "entropy pool holds {have} bits, need {need}")
            }
            Insufficient::HardwareSources { have, need } => {
                write!(f, "{have} hardware TRNG(s) contributed, need {need}")
            }
            Insufficient::Unhealthy { source, error } => {
                write!(
                    f,
                    "noise source {source:?} failed its health test: {error:?}"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Insufficient {}

/// Accumulates entropy from every available source and hands out seed material.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EntropyPool {
    state: [u8; 64],
    #[zeroize(skip)]
    credited_bits: u32,
    #[zeroize(skip)]
    bytes_from: [u32; NUM_SOURCES],
    #[zeroize(skip)]
    health: [ContinuousTest; NUM_SOURCES],
    #[zeroize(skip)]
    poisoned: Option<(Source, HealthError)>,
    #[zeroize(skip)]
    draw_counter: u64,
    #[zeroize(skip)]
    policy: Policy,
}

impl EntropyPool {
    pub fn new(policy: Policy) -> Self {
        let mut state = [0u8; 64];
        // Fix the start of the chain to a domain-separating constant, so a pool that
        // absorbed nothing is not the same chain as anything else.
        let seed = Sha512::digest(b"catcard/entropy-pool/v1");
        state.copy_from_slice(&seed);
        Self {
            state,
            credited_bits: 0,
            bytes_from: [0; NUM_SOURCES],
            health: core::array::from_fn(|_| ContinuousTest::new()),
            poisoned: None,
            draw_counter: 0,
            policy,
        }
    }

    /// Absorb a contribution.
    ///
    /// Health-tested sources that fail poison the pool: [`draw`](Self::draw) will
    /// refuse until the pool is rebuilt. The data is absorbed either way — a failing
    /// source may still hold *some* unpredictability, it just cannot be credited.
    pub fn add(&mut self, source: Source, data: &[u8]) {
        // Health-test the real noise sources. Derived and public values are not noise
        // and would fail these tests for legitimate reasons.
        if source.is_hardware_trng() {
            if let Err(e) = self.health[source.index()].check(data) {
                if self.poisoned.is_none() {
                    self.poisoned = Some((source, e));
                }
                self.absorb(source, data);
                return;
            }
        }

        self.absorb(source, data);

        let bits = (data.len() as u64).saturating_mul(source.bits_per_byte() as u64);
        self.credited_bits = self
            .credited_bits
            .saturating_add(bits.min(u32::MAX as u64) as u32);
        self.bytes_from[source.index()] =
            self.bytes_from[source.index()].saturating_add(data.len() as u32);
    }

    /// Absorb a single timing observation (e.g. `DWT_CYCCNT` at a keypress edge).
    pub fn add_timing(&mut self, cycles: u32) {
        self.add(Source::UserTiming, &cycles.to_le_bytes());
    }

    fn absorb(&mut self, source: Source, data: &[u8]) {
        let mut h = Sha512::new();
        h.update(self.state);
        h.update(source.tag());
        // Length-prefix so `add(X, "ab") ; add(X, "c")` cannot collide with
        // `add(X, "abc")`.
        h.update((data.len() as u64).to_be_bytes());
        h.update(data);
        self.state.copy_from_slice(&h.finalize());
    }

    /// Total credited entropy.
    pub fn credited_bits(&self) -> u32 {
        self.credited_bits
    }

    /// Distinct hardware TRNGs that have contributed at least one byte.
    pub fn hardware_sources(&self) -> u32 {
        [
            Source::Stm32Trng,
            Source::BootloaderTrng,
            Source::Se1Trng,
            Source::Se2Trng,
        ]
        .iter()
        .filter(|s| self.bytes_from[s.index()] > 0)
        .count() as u32
    }

    /// Whether a draw would succeed right now.
    pub fn check(&self) -> Result<(), Insufficient> {
        if let Some((source, error)) = self.poisoned {
            return Err(Insufficient::Unhealthy { source, error });
        }
        let hw = self.hardware_sources();
        if hw < self.policy.min_hw_sources {
            return Err(Insufficient::HardwareSources {
                have: hw,
                need: self.policy.min_hw_sources,
            });
        }
        if self.credited_bits < self.policy.min_bits {
            return Err(Insufficient::Bits {
                have: self.credited_bits,
                need: self.policy.min_bits,
            });
        }
        Ok(())
    }

    /// Produce entropy for a wallet seed.
    ///
    /// Refuses unless the policy is satisfied. Each call uses a fresh counter, so
    /// repeated draws are independent and none of them reveals the pool state.
    ///
    /// `out` may be up to 64 bytes.
    pub fn draw(&mut self, out: &mut [u8]) -> Result<(), Insufficient> {
        assert!(out.len() <= 64, "a single draw yields at most 64 bytes");
        self.check()?;

        self.draw_counter += 1;
        let mut h = Sha512::new();
        h.update(self.state);
        h.update(b"catcard/draw/v1");
        h.update(self.draw_counter.to_be_bytes());
        let full = h.finalize();
        out.copy_from_slice(&full[..out.len()]);

        // Ratchet the pool forward so the state that produced this output is gone. A
        // later compromise of the pool cannot reconstruct an earlier seed.
        self.absorb(Source::Auxiliary, b"ratchet");
        Ok(())
    }

    /// 256 bits for a BIP-39 seed.
    pub fn draw_seed(&mut self) -> Result<[u8; 32], Insufficient> {
        let mut out = [0u8; 32];
        self.draw(&mut out)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Varied bytes that pass the health tests, distinct per `tag`.
    fn noise(tag: u8, n: usize) -> Vec<u8> {
        use sha2::Sha256;
        let mut out = Vec::new();
        let mut h = [tag; 32];
        while out.len() < n {
            h = Sha256::digest(h).into();
            out.extend_from_slice(&h);
        }
        out.truncate(n);
        out
    }

    fn full_pool() -> EntropyPool {
        let mut p = EntropyPool::new(Policy::STRICT);
        p.add(Source::Stm32Trng, &noise(1, 32));
        p.add(Source::Se1Trng, &noise(2, 32));
        p
    }

    #[test]
    fn a_fresh_pool_refuses_to_produce_a_seed() {
        let mut p = EntropyPool::new(Policy::STRICT);
        assert!(matches!(
            p.draw_seed(),
            Err(Insufficient::HardwareSources { have: 0, .. })
        ));
    }

    #[test]
    fn one_trng_read_is_not_enough_under_the_strict_policy() {
        let mut p = EntropyPool::new(Policy::STRICT);
        p.add(Source::Stm32Trng, &noise(1, 32));
        // 32 bytes * 4 bits = 128 credited bits, and only one hardware source.
        assert_eq!(p.credited_bits(), 128);
        assert!(matches!(
            p.draw_seed(),
            Err(Insufficient::HardwareSources { have: 1, need: 2 })
        ));
    }

    #[test]
    fn two_trngs_at_32_bytes_each_satisfy_the_strict_policy() {
        let mut p = full_pool();
        assert_eq!(p.credited_bits(), 256);
        assert_eq!(p.hardware_sources(), 2);
        assert!(p.draw_seed().is_ok());
    }

    #[test]
    fn single_trng_policy_demands_64_bytes_from_that_trng() {
        let mut p = EntropyPool::new(Policy::single_trng());
        p.add(Source::Stm32Trng, &noise(1, 32));
        assert!(matches!(
            p.draw_seed(),
            Err(Insufficient::Bits {
                have: 128,
                need: 256
            })
        ));
        p.add(Source::Stm32Trng, &noise(9, 32));
        assert!(p.draw_seed().is_ok());
    }

    #[test]
    fn public_and_auxiliary_values_are_credited_nothing() {
        let mut p = EntropyPool::new(Policy::single_trng());
        // The device unique ID: mixing it must not move the counter one bit. This is
        // the specific mistake that made the original seed guessable.
        p.add(Source::NonSecret, &[0xde; 12]);
        p.add(Source::Auxiliary, &noise(3, 1024));
        assert_eq!(p.credited_bits(), 0);
        assert!(matches!(
            p.draw_seed(),
            Err(Insufficient::HardwareSources { .. })
        ));
    }

    #[test]
    fn user_timing_alone_cannot_unlock_a_seed() {
        let mut p = EntropyPool::new(Policy::single_trng());
        for i in 0..10_000u32 {
            p.add_timing(i.wrapping_mul(2_654_435_761));
        }
        // Plenty of credited bits, but no hardware noise source at all.
        assert!(p.credited_bits() >= 256);
        assert!(matches!(
            p.draw_seed(),
            Err(Insufficient::HardwareSources { have: 0, need: 1 })
        ));
    }

    #[test]
    fn a_dead_trng_poisons_the_pool() {
        let mut p = EntropyPool::new(Policy::STRICT);
        p.add(Source::Stm32Trng, &noise(1, 64));
        // A secure element that has stopped working returns zeroes.
        p.add(Source::Se1Trng, &[0u8; 32]);
        assert!(matches!(
            p.draw_seed(),
            Err(Insufficient::Unhealthy {
                source: Source::Se1Trng,
                ..
            })
        ));
    }

    #[test]
    fn a_dead_trng_is_not_credited() {
        let mut p = EntropyPool::new(Policy::STRICT);
        p.add(Source::Se1Trng, &[0u8; 32]);
        assert_eq!(p.credited_bits(), 0);
        assert_eq!(p.hardware_sources(), 0);
    }

    #[test]
    fn poisoning_is_sticky() {
        let mut p = EntropyPool::new(Policy::STRICT);
        p.add(Source::Se2Trng, &[0xffu8; 32]);
        // Adding good entropy afterwards must not clear the fault.
        p.add(Source::Stm32Trng, &noise(1, 64));
        p.add(Source::Se1Trng, &noise(2, 64));
        assert!(matches!(p.draw_seed(), Err(Insufficient::Unhealthy { .. })));
    }

    #[test]
    fn draws_are_independent() {
        let mut p = full_pool();
        let a = p.draw_seed().unwrap();
        let b = p.draw_seed().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn absorbing_is_order_dependent() {
        let mut a = EntropyPool::new(Policy::single_trng());
        a.add(Source::Stm32Trng, &noise(1, 32));
        a.add(Source::Stm32Trng, &noise(2, 32));

        let mut b = EntropyPool::new(Policy::single_trng());
        b.add(Source::Stm32Trng, &noise(2, 32));
        b.add(Source::Stm32Trng, &noise(1, 32));

        assert_ne!(a.draw_seed().unwrap(), b.draw_seed().unwrap());
    }

    #[test]
    fn sources_are_domain_separated() {
        // The same bytes from a different source must give a different pool state,
        // so a value an attacker controls in one channel cannot mimic another.
        let data = noise(7, 64);
        let mut a = EntropyPool::new(Policy::single_trng());
        a.add(Source::Stm32Trng, &data);
        let mut b = EntropyPool::new(Policy::single_trng());
        b.add(Source::Se1Trng, &data);
        assert_ne!(a.draw_seed().unwrap(), b.draw_seed().unwrap());
    }

    #[test]
    fn concatenation_is_unambiguous() {
        // add("ab") + add("c") must not equal add("abc") -- the length prefix.
        let mut a = EntropyPool::new(Policy::single_trng());
        a.add(Source::Stm32Trng, &noise(1, 40));
        a.add(Source::Stm32Trng, &noise(1, 64)[40..]);

        let mut b = EntropyPool::new(Policy::single_trng());
        b.add(Source::Stm32Trng, &noise(1, 64));

        assert_ne!(a.draw_seed().unwrap(), b.draw_seed().unwrap());
    }

    #[test]
    fn a_predictable_source_cannot_cancel_a_good_one() {
        // Under the original XOR-combining design, a source an attacker controls can
        // erase a good one. Here mixing anything at all must change the output but
        // can never restore a previous state.
        let base = full_pool().draw_seed().unwrap();

        let mut p = full_pool();
        p.add(Source::Auxiliary, &[0u8; 32]);
        let after_zero = p.draw_seed().unwrap();
        assert_ne!(after_zero, base);

        let mut q = full_pool();
        q.add(Source::Auxiliary, &[0u8; 32]);
        q.add(Source::Auxiliary, &[0u8; 32]);
        assert_ne!(q.draw_seed().unwrap(), base);
        assert_ne!(q.draw_seed().unwrap(), after_zero);
    }

    #[test]
    fn draw_is_deterministic_for_a_given_history() {
        // Same inputs, same outputs -- the property that makes this testable at all.
        let mut a = full_pool();
        let mut b = full_pool();
        assert_eq!(a.draw_seed().unwrap(), b.draw_seed().unwrap());
    }

    #[test]
    fn seed_output_is_not_the_raw_source_bytes() {
        let src = noise(1, 32);
        let mut p = EntropyPool::new(Policy::single_trng());
        p.add(Source::Stm32Trng, &src);
        p.add(Source::Stm32Trng, &noise(2, 32));
        assert_ne!(&p.draw_seed().unwrap()[..], &src[..]);
    }

    #[test]
    fn draw_can_fill_up_to_64_bytes() {
        let mut p = full_pool();
        let mut out = [0u8; 64];
        assert!(p.draw(&mut out).is_ok());
        assert!(out.iter().any(|&b| b != 0));
    }

    #[test]
    #[should_panic(expected = "at most 64 bytes")]
    fn draw_rejects_oversized_requests() {
        let mut p = full_pool();
        let mut out = [0u8; 65];
        let _ = p.draw(&mut out);
    }
}
