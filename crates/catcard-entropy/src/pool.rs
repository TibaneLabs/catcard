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
use purecrypto::hash::{Digest, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::health::ContinuousTest;

/// Where a contribution came from. The variant decides how much entropy is credited.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Source {
    /// STM32 hardware TRNG (`RNG_DR`), read directly by us.
    Stm32Trng,
    /// The bootloader's own read of the STM32 TRNG, via callgate 17.
    ///
    /// Mixed, **credited zero, and not counted as a hardware source.** It is the same
    /// generator as [`Source::Stm32Trng`] -- the callgate returns the MCU TRNG
    /// (`rng_buffer`), not a secure element -- so counting it would let one chip satisfy a
    /// two-source policy on its own. It is also not known whether that buffer is filled per
    /// call or once. Mixing it can only help; trusting it could only mislead.
    /// Source: hw-reference/platform.md §3 "Reading the SE1 RNG on mk3" [C]
    BootloaderTrng,
    /// ATECC608 `Random`, via callgate 26 source 1.
    Se1Trng,
    /// Second secure element TRNG, via callgate 26 source 2 (mk4+).
    Se2Trng,
    /// SE1's `Random`, read by the firmware itself over the raw single-wire bus -- the only
    /// way to reach it on mk3, whose bootloader has no callgate for SE randomness.
    ///
    /// Mixed, **credited zero, and not counted as a hardware source.** Unlike callgate 26
    /// on mk4+, which authenticates the element against the pairing secret, this read is
    /// unauthenticated: anything on that wire can supply the bytes. Mixing an
    /// attacker-chosen input into the pool cannot remove entropy, so it is always worth
    /// adding. Crediting it is another matter -- it would let a tampered bus satisfy the
    /// policy on a board whose real TRNG had failed, and a pool that refuses is the
    /// property this crate exists to keep.
    /// Source: hw-reference/platform.md §3 "Reading the SE1 RNG on mk3" [C]
    Se1TrngUnauthenticated,
    /// Timing jitter from user interaction (DWT cycle counts at keypress edges).
    /// Real but low-rate entropy; credited conservatively.
    UserTiming,
    /// The digits a user chose while key-mashing -- the values, as a die's faces are, not
    /// the timing.
    ///
    /// Credited **nothing per byte**: a run of user symbols is counted as a whole, by
    /// [`EntropyPool::add_user`], which is where the length and frequency gate lives. A
    /// bare `add` of typed digits mixes them and counts zero, so there is no way to get
    /// an ungated run counted. Runs no health test either -- it is not a noise source and
    /// a human legitimately repeats keys -- and never counts as a hardware source, so it
    /// stays additive and can never be a precondition.
    UserKeypad,
    /// Die faces (1..6) a user rolled and entered. Same footing as [`Source::UserKeypad`]:
    /// credited only as a gated run through [`EntropyPool::add_user`], never as a
    /// hardware source. See [`crate::user`] for the digest convention.
    UserDice,
    /// Coin flips (0/1) a user entered. Same footing as [`Source::UserDice`].
    UserCoin,
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
        matches!(self, Source::Stm32Trng | Source::Se1Trng | Source::Se2Trng)
    }

    /// Bits of entropy credited per byte absorbed.
    ///
    /// Hardware TRNGs are credited at 4 bits/byte, half their nominal rate. That
    /// haircut is deliberate: it means a 32-byte TRNG read counts for 128 bits, so the
    /// 256-bit policy cannot be satisfied by a single 32-byte read from a single chip.
    const fn bits_per_byte(self) -> u32 {
        match self {
            Source::Stm32Trng | Source::Se1Trng | Source::Se2Trng => 4,
            // Real noise, but not trusted to count: see the variants.
            Source::BootloaderTrng | Source::Se1TrngUnauthenticated => 0,
            // A keypress timestamp is a handful of unpredictable low bits at best.
            Source::UserTiming => 1,
            // Typed symbols are credited per *run*, by `add_user`, not per byte. Zero
            // here means a raw `add` of somebody's rolls mixes them without counting
            // them, and the gate cannot be walked around.
            Source::UserKeypad | Source::UserDice | Source::UserCoin => 0,
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
            Source::Se1TrngUnauthenticated => b"catcard/src/se1-trng-unauthenticated",
            Source::UserTiming => b"catcard/src/user-timing",
            Source::UserKeypad => b"catcard/src/user-keypad",
            Source::UserDice => b"catcard/src/user-dice",
            Source::UserCoin => b"catcard/src/user-coin",
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
            Source::UserKeypad => 7,
            Source::UserDice => 8,
            Source::UserCoin => 9,
            Source::Se1TrngUnauthenticated => 10,
            Source::Auxiliary => 5,
            Source::NonSecret => 6,
        }
    }
}

const NUM_SOURCES: usize = 11;

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
            draw_counter: 0,
            policy,
        }
    }

    /// Absorb a contribution.
    ///
    /// A health-tested source that fails is still absorbed -- it may hold *some*
    /// unpredictability, and mixing it cannot reduce what the good sources contributed --
    /// but it is credited **nothing** and does not count toward the hardware-source
    /// requirement. It does **not** poison the pool: the point of combining several
    /// sources is that any healthy one keeps the whole draw safe, so one failing source
    /// must never be able to block a draw the healthy ones have already earned.
    pub fn add(&mut self, source: Source, data: &[u8]) {
        // Health-test the real noise sources. Derived and public values are not noise
        // and would fail these tests for legitimate reasons.
        if source.is_hardware_trng() && self.health[source.index()].check(data).is_err() {
            // Absorb it for whatever unpredictability it holds, but credit nothing and do
            // not count it as a healthy source.
            self.absorb(source, data);
            return;
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

    /// Absorb a run of symbols the owner typed -- dice, coin flips, a keypad mash -- and
    /// credit it by keyspace. Returns the bits credited.
    ///
    /// The run goes in as SHA-256 over its ASCII digits, the public dice convention (see
    /// [`crate::user`]), so an owner can recompute off the device what their rolls should
    /// have contributed.
    ///
    /// Three properties together are what make this safe to offer at all:
    ///
    /// - **It adds.** The digest is absorbed like any other contribution, into the same
    ///   chain the TRNGs went into. It cannot replace them, and there is no API here that
    ///   would let it: a seed made with 10 rolls is the one that would have been made
    ///   without them, stirred further. The stock firmware *replaces* the seed with
    ///   `sha256(rolls)`, which is why a short run there is a weak wallet.
    /// - **A weak run counts zero, but is still mixed.** Mixing cannot subtract, so
    ///   there is nothing to gain by discarding a short or lopsided run -- only by
    ///   refusing to count it. `run.weakness()` says which way it fell short.
    /// - **It is never a hardware source.** No amount of typing satisfies a policy's
    ///   two-TRNG bar, so a device whose TRNGs are unhealthy cannot be talked into a
    ///   wallet by hand.
    pub fn add_user(&mut self, run: &crate::user::UserSymbols) -> u32 {
        let source = run.alphabet().source();
        let mut digest = run.digest();
        self.absorb(source, &digest);
        digest.zeroize();

        let bits = run.credited_bits();
        self.credited_bits = self.credited_bits.saturating_add(bits);
        // Count the symbols, not the digest's 32 bytes: the report should say how many
        // times the owner rolled.
        self.bytes_from[source.index()] =
            self.bytes_from[source.index()].saturating_add(run.count());
        bits
    }

    fn absorb(&mut self, source: Source, data: &[u8]) {
        let mut h = Sha512::new();
        h.update(&self.state);
        h.update(source.tag());
        // Length-prefix so `add(X, "ab") ; add(X, "c")` cannot collide with
        // `add(X, "abc")`.
        h.update(&(data.len() as u64).to_be_bytes());
        h.update(data);
        self.state.copy_from_slice(&h.finalize());
    }

    /// Total credited entropy.
    pub fn credited_bits(&self) -> u32 {
        self.credited_bits
    }

    /// Distinct hardware TRNGs that have contributed at least one byte.
    pub fn hardware_sources(&self) -> u32 {
        [Source::Stm32Trng, Source::Se1Trng, Source::Se2Trng]
            .iter()
            .filter(|s| self.bytes_from[s.index()] > 0)
            .count() as u32
    }

    /// Whether a draw would succeed right now.
    ///
    /// The verdict rests only on what healthy sources contributed: enough credited bits
    /// from enough distinct hardware TRNGs. A source that failed its health test simply
    /// contributed nothing to either count; it cannot make an otherwise-sufficient pool
    /// refuse.
    pub fn check(&self) -> Result<(), Insufficient> {
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
        h.update(&self.state);
        h.update(b"catcard/draw/v1");
        h.update(&self.draw_counter.to_be_bytes());
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
    fn boot_timing_on_a_fixed_path_is_credited_nothing() {
        // What boot does with its cycle-counter samples: sixteen reads of `DWT_CYCCNT`
        // on a straight-line path before any human input. Those land near the same
        // values every boot, so they go in as `Auxiliary` -- and the counter must not
        // move, or a board whose TRNG had failed could be talked a few bits closer to
        // its policy by rebooting.
        let mut p = EntropyPool::new(Policy::single_trng());
        for i in 0..16u32 {
            p.add(Source::Auxiliary, &(1_000 + i * 97).to_le_bytes());
        }
        assert_eq!(p.credited_bits(), 0);
        assert_eq!(p.hardware_sources(), 0);
        // And the boards' policies are met without them: mk3 on the chip TRNG alone ...
        p.add(Source::Stm32Trng, &noise(1, 64));
        assert_eq!(p.credited_bits(), 256);
        assert!(p.draw_seed().is_ok());
        // ... mk4 and Q1 on the chip plus the two secure elements.
        let mut strict = EntropyPool::new(Policy::STRICT);
        for i in 0..16u32 {
            strict.add(Source::Auxiliary, &(1_000 + i * 97).to_le_bytes());
        }
        strict.add(Source::Stm32Trng, &noise(1, 64));
        strict.add(Source::Se1Trng, &noise(2, 64));
        strict.add(Source::Se2Trng, &noise(3, 64));
        assert_eq!(strict.credited_bits(), 768);
        assert!(strict.draw_seed().is_ok());
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
    fn a_dead_trng_is_not_credited() {
        let mut p = EntropyPool::new(Policy::STRICT);
        p.add(Source::Se1Trng, &[0u8; 32]);
        assert_eq!(p.credited_bits(), 0);
        assert_eq!(p.hardware_sources(), 0);
    }

    #[test]
    fn a_dead_trng_does_not_count_toward_the_hardware_requirement() {
        let mut p = EntropyPool::new(Policy::STRICT);
        p.add(Source::Stm32Trng, &noise(1, 64));
        // A secure element that has stopped working returns zeroes: credited nothing and
        // not counted, so only one healthy hardware source remains -- short of STRICT's
        // two. It refuses for lack of a second source, not because the pool is "poisoned".
        p.add(Source::Se1Trng, &[0u8; 32]);
        assert_eq!(p.hardware_sources(), 1);
        assert!(matches!(
            p.draw_seed(),
            Err(Insufficient::HardwareSources { have: 1, need: 2 })
        ));
    }

    #[test]
    fn a_dead_source_does_not_block_a_healthy_pool() {
        // The property that matters: one failing source must never veto a draw the
        // healthy sources have already earned. Mixing it in cannot reduce their entropy,
        // so there is nothing to protect against by refusing.
        let mut p = EntropyPool::new(Policy::STRICT);
        p.add(Source::Se2Trng, &[0xffu8; 32]); // dead element, stuck high
        p.add(Source::Stm32Trng, &noise(1, 64));
        p.add(Source::Se1Trng, &noise(2, 64));
        assert_eq!(p.hardware_sources(), 2, "the two healthy TRNGs still count");
        assert!(
            p.draw_seed().is_ok(),
            "a dead source blocked an otherwise-sufficient pool"
        );
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
    fn one_chip_read_twice_is_still_one_chip() {
        // Callgate 17 hands back the same MCU TRNG this firmware reads directly. Counted
        // as its own source, one generator would satisfy a two-source policy by being
        // asked twice -- so it is mixed and nothing more.
        let mut p = EntropyPool::new(Policy::STRICT);
        p.add(Source::Stm32Trng, &noise(3, 128));
        p.add(Source::BootloaderTrng, &noise(4, 128));
        assert_eq!(p.hardware_sources(), 1);
        assert!(
            p.check().is_err(),
            "a single generator passed a two-source policy"
        );
    }

    #[test]
    fn an_unauthenticated_wire_can_add_but_never_vouch() {
        // SE1 read over the raw single-wire bus on mk3: anything on that wire can supply
        // the bytes. Whatever it sends must change the pool -- more material never hurts --
        // but it must not credit a single bit or count as a generator, or a tampered bus
        // could stand in for a TRNG that has failed.
        let mut p = EntropyPool::new(Policy::single_trng());
        p.add(Source::Se1TrngUnauthenticated, &noise(5, 1024));
        assert_eq!(p.credited_bits(), 0);
        assert_eq!(p.hardware_sources(), 0);
        assert!(
            p.check().is_err(),
            "an unauthenticated source satisfied the policy alone"
        );

        // And on top of a real source it still changes the result.
        let base = full_pool().draw_seed().unwrap();
        let mut q = full_pool();
        q.add(Source::Se1TrngUnauthenticated, &noise(6, 32));
        assert_ne!(q.draw_seed().unwrap(), base);
    }

    #[test]
    fn the_authenticated_and_unauthenticated_se1_reads_do_not_alias() {
        let data = noise(9, 64);
        let mut a = full_pool();
        a.add(Source::Se1Trng, &data);
        let mut b = full_pool();
        b.add(Source::Se1TrngUnauthenticated, &data);
        assert_ne!(a.draw_seed().unwrap(), b.draw_seed().unwrap());
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

    // ---- user-supplied entropy -------------------------------------------------
    //
    // The property under test throughout is the one that decides whether offering dice
    // at all is safe: **user input adds, it never replaces**. A wallet made with rolls
    // must be at least as strong as the same wallet made without them, and no run of
    // typing may stand in for a hardware source.

    use crate::user::{Alphabet, UserSymbols};

    /// `n` rolls that use every face evenly -- what a real die gives.
    fn rolls(n: u32) -> UserSymbols {
        let mut u = UserSymbols::new(Alphabet::Dice);
        for i in 0..n {
            u.push(b'1' + (i % 6) as u8).unwrap();
        }
        u
    }

    #[test]
    fn ten_dice_rolls_leave_a_seed_no_weaker_than_none() {
        // The headline property. Take a pool that has already met its policy, hand it a
        // run far too short to be credited, and nothing about its standing may go
        // backwards: not the credited bits, not the hardware sources, not the verdict.
        let before = full_pool();
        let mut after = full_pool();
        let credited = after.add_user(&rolls(10));

        assert_eq!(credited, 0, "ten rolls must not be counted");
        assert!(after.credited_bits() >= before.credited_bits());
        assert_eq!(after.hardware_sources(), before.hardware_sources());
        assert!(
            after.check().is_ok(),
            "a short user run took a good pool below its policy"
        );

        // And it did land: the seed is a different one, stirred by the rolls rather than
        // replaced by them.
        let mut a = full_pool();
        let mut b = full_pool();
        b.add_user(&rolls(10));
        assert_ne!(a.draw_seed().unwrap(), b.draw_seed().unwrap());
    }

    #[test]
    fn no_run_of_any_length_can_weaken_a_pool() {
        // The same statement over the whole range, including the lopsided run that is
        // credited nothing and the long one that is capped.
        let mut lopsided = UserSymbols::new(Alphabet::Dice);
        for _ in 0..200 {
            lopsided.push(b'6').unwrap();
        }
        let base = full_pool();
        for run in [rolls(0), rolls(1), rolls(49), rolls(50), rolls(400)] {
            let mut p = full_pool();
            p.add_user(&run);
            assert!(p.credited_bits() >= base.credited_bits());
            assert_eq!(p.hardware_sources(), base.hardware_sources());
            assert!(p.check().is_ok());
        }
        let mut p = full_pool();
        p.add_user(&lopsided);
        assert_eq!(p.credited_bits(), base.credited_bits());
        assert!(p.check().is_ok());
    }

    #[test]
    fn user_input_can_never_replace_the_pool() {
        // A thousand rolls into a pool with no hardware behind it still produces
        // nothing. This is the difference from the stock firmware, where the seed *is*
        // sha256(rolls) and a device with a dead TRNG happily makes a wallet.
        let mut p = EntropyPool::new(Policy::single_trng());
        p.add_user(&rolls(500));
        assert!(p.credited_bits() >= 256, "the rolls were credited");
        assert_eq!(p.hardware_sources(), 0);
        assert!(matches!(
            p.draw_seed(),
            Err(Insufficient::HardwareSources { have: 0, need: 1 })
        ));

        // Nor can it rescue a board whose second element is dead under STRICT.
        let mut q = EntropyPool::new(Policy::STRICT);
        q.add(Source::Stm32Trng, &noise(1, 64));
        q.add(Source::Se1Trng, &[0u8; 32]);
        q.add_user(&rolls(500));
        assert!(matches!(
            q.draw_seed(),
            Err(Insufficient::HardwareSources { have: 1, need: 2 })
        ));
    }

    #[test]
    fn fifty_fair_rolls_are_credited_129_bits() {
        let mut p = EntropyPool::new(Policy::STRICT);
        assert_eq!(p.add_user(&rolls(50)), 129);
        assert_eq!(p.credited_bits(), 129);
        // Long runs are capped at what one 32-byte digest can carry.
        let mut q = EntropyPool::new(Policy::STRICT);
        assert_eq!(q.add_user(&rolls(400)), 256);
    }

    #[test]
    fn typed_symbols_are_only_ever_counted_through_the_gate() {
        // The gate lives in `add_user`. Handing the same digits to `add` -- the way a
        // future caller might, reaching for the obvious function -- mixes them and
        // credits nothing, so there is no path that counts an ungated run.
        let mut p = EntropyPool::new(Policy::STRICT);
        p.add(Source::UserDice, b"123456123456123456");
        p.add(Source::UserKeypad, &[5; 200]);
        p.add(Source::UserCoin, b"0101010101");
        assert_eq!(p.credited_bits(), 0);
        assert_eq!(p.hardware_sources(), 0);
    }

    #[test]
    fn the_three_user_alphabets_are_domain_separated() {
        // The same typed string as dice and as a keypad mash must not produce the same
        // pool, or one channel could stand in for another.
        let mut dice = UserSymbols::new(Alphabet::Dice);
        let mut mash = UserSymbols::new(Alphabet::Keypad);
        for i in 0..60u32 {
            dice.push(b'1' + (i % 6) as u8).unwrap();
            mash.push(b'1' + (i % 6) as u8).unwrap();
        }
        assert_eq!(dice.digest(), mash.digest(), "same symbols, same digest");

        let mut a = full_pool();
        a.add_user(&dice);
        let mut b = full_pool();
        b.add_user(&mash);
        assert_ne!(a.draw_seed().unwrap(), b.draw_seed().unwrap());
    }

    #[test]
    fn a_dice_run_reaches_the_pool_as_its_published_digest() {
        // What the pool absorbs is exactly sha256 of the ASCII rolls, so the owner's own
        // check of their written-down rolls describes what the device actually did.
        let run = rolls(60);
        let mut a = full_pool();
        a.add_user(&run);

        let mut b = full_pool();
        b.add(Source::UserDice, &run.digest());
        assert_eq!(
            a.draw_seed().unwrap(),
            b.draw_seed().unwrap(),
            "the run is absorbed as something other than its digest"
        );
    }

    #[test]
    fn keypad_taps_count_by_keyspace_and_are_not_hardware() {
        let mut p = EntropyPool::new(Policy::STRICT);
        let mut mash = UserSymbols::new(Alphabet::Keypad);
        for i in 0..100u32 {
            mash.push(b'0' + (i % 10) as u8).unwrap();
        }
        // log2(10) * 100 = 332 bits of keyspace, capped at the 256 a digest can carry.
        assert_eq!(p.add_user(&mash), 256);
        // ...but it is not a hardware source, so it cannot satisfy the two-TRNG bar.
        assert_eq!(p.hardware_sources(), 0);
        assert!(matches!(
            p.check(),
            Err(Insufficient::HardwareSources { .. })
        ));
    }

    #[test]
    fn a_mash_of_one_key_is_not_counted() {
        // A human leaning on the 5 key is not 300 bits of anything.
        let mut p = EntropyPool::new(Policy::STRICT);
        let mut mash = UserSymbols::new(Alphabet::Keypad);
        for _ in 0..100 {
            mash.push(b'5').unwrap();
        }
        assert_eq!(p.add_user(&mash), 0);
        assert_eq!(p.credited_bits(), 0);
    }
}
