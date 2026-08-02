//! Entropy and random-number generation for CatCard.
//!
//! Two separate things live here, and keeping them separate is the point:
//!
//! - [`EntropyPool`] — accumulates real noise from every hardware source on the board
//!   and produces **wallet seed material**. It refuses to produce anything until it
//!   has verifiably collected enough.
//! - [`HmacDrbg`] — a deterministic generator for **everything else**: nonces, UI
//!   shuffles, keypad scan randomisation, padding.
//!
//! The stock firmware's seed generator is a known-weak software PRNG, and one of the
//! things that made it enumerable was that ordinary UI operations advanced the same
//! generator the seed came from. Nothing in this crate lets that happen: `EntropyPool`
//! has no "give me a random number" API, and `HmacDrbg` cannot be used as a seed
//! source. See `docs/ENTROPY.md`.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

pub mod drbg;
pub mod health;
pub mod pool;

pub use drbg::HmacDrbg;
pub use health::{ContinuousTest, HealthError};
pub use pool::{EntropyPool, Insufficient, Policy, Source};

/// Personalization strings for [`HmacDrbg`] instances.
///
/// One DRBG per purpose, each personalized differently, so that observing the output
/// of one (the keypad scan order is observable by anyone watching the pins) tells an
/// attacker nothing about another.
pub mod domain {
    /// Anti-Tempest keypad scan order, and other UI randomisation.
    pub const UI: &[u8] = b"catcard/drbg/ui/v1";
    /// Protocol nonces, session keys, padding.
    pub const PROTOCOL: &[u8] = b"catcard/drbg/protocol/v1";
    /// Deterministic-signing auxiliary randomness (RFC 6979 extra entropy).
    pub const SIGNING: &[u8] = b"catcard/drbg/signing/v1";
}

/// Build the per-purpose DRBGs from a pool that has met its policy.
///
/// Takes the pool by `&mut` and draws once per DRBG, so each gets independent seed
/// material rather than a shared secret split by personalization alone.
pub fn spawn_drbg(
    pool: &mut EntropyPool,
    personalization: &[u8],
    nonce: &[u8],
) -> Result<HmacDrbg, Insufficient> {
    let mut seed = [0u8; 48];
    pool.draw(&mut seed)?;
    let d = HmacDrbg::new(&seed, nonce, personalization);
    // `seed` is a stack copy of seed material; clear it before returning.
    zeroize::Zeroize::zeroize(&mut seed);
    Ok(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noise(tag: u8, n: usize) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut out = Vec::new();
        let mut h = [tag; 32];
        while out.len() < n {
            h = Sha256::digest(h).into();
            out.extend_from_slice(&h);
        }
        out.truncate(n);
        out
    }

    fn ready_pool() -> EntropyPool {
        let mut p = EntropyPool::new(Policy::STRICT);
        p.add(Source::Stm32Trng, &noise(1, 32));
        p.add(Source::Se1Trng, &noise(2, 32));
        p
    }

    #[test]
    fn spawn_refuses_from_an_unready_pool() {
        let mut p = EntropyPool::new(Policy::STRICT);
        assert!(spawn_drbg(&mut p, domain::UI, &[]).is_err());
    }

    #[test]
    fn each_domain_gets_an_independent_stream() {
        let mut p = ready_pool();
        let mut ui = spawn_drbg(&mut p, domain::UI, &[]).unwrap();
        let mut proto = spawn_drbg(&mut p, domain::PROTOCOL, &[]).unwrap();

        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        ui.generate(&mut a).unwrap();
        proto.generate(&mut b).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn ui_randomness_does_not_disturb_the_seed_pool() {
        // The whole point: run a realistic amount of keypad shuffling, then confirm
        // the seed the pool produces is the one it would have produced anyway.
        let mut a = ready_pool();
        let expected = a.draw_seed().unwrap();

        let mut b = ready_pool();
        let mut ui = HmacDrbg::new(&noise(3, 32), &[], domain::UI);
        for _ in 0..500 {
            let mut order = [0u8, 1, 2, 3];
            ui.shuffle(&mut order).unwrap();
        }
        assert_eq!(b.draw_seed().unwrap(), expected);
    }

    #[test]
    fn domains_are_distinct() {
        let all = [domain::UI, domain::PROTOCOL, domain::SIGNING];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }
}
