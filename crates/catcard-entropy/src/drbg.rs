//! HMAC-DRBG (SHA-256), NIST SP 800-90A §10.1.2.
//!
//! # Why a separate DRBG
//!
//! Wallet-seed entropy comes from [`EntropyPool`](crate::EntropyPool) and nowhere
//! else. Everything *else* that wants randomness — signing nonces, UI shuffles,
//! anti-Tempest keypad scan order, padding — draws from this DRBG instead.
//!
//! Keeping them apart is not tidiness. In the stock firmware the numpad's
//! anti-Tempest scan shuffle drew from the same generator as the wallet seed, which
//! is what tied the seed's state to the number of keypresses and made it enumerable.
//! A routine UI operation must not be able to move the seed generator.

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

const OUTLEN: usize = 32;

/// SP 800-90A requires a reseed before this many generate calls. We are far below any
/// realistic usage, but the counter is here so exceeding it is an error rather than
/// something nobody noticed.
pub const RESEED_INTERVAL: u64 = 1 << 32;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// `generate` was called more than [`RESEED_INTERVAL`] times without a reseed.
    ReseedRequired,
    /// A single `generate` call may produce at most 2^16 bits (SP 800-90A Table 2).
    TooMuchAtOnce { len: usize },
}

/// The maximum bytes one `generate` call may return.
pub const MAX_BYTES_PER_REQUEST: usize = 1 << 13; // 2^16 bits

/// HMAC-DRBG instance.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HmacDrbg {
    key: [u8; OUTLEN],
    v: [u8; OUTLEN],
    #[zeroize(skip)]
    reseed_counter: u64,
}

fn hmac(key: &[u8; OUTLEN], parts: &[&[u8]]) -> [u8; OUTLEN] {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

impl HmacDrbg {
    /// Instantiate from seed material. `personalization` separates instances that
    /// share seed material; pass a distinct constant per use (see
    /// [`Domain`](crate::Domain)).
    ///
    /// SP 800-90A §10.1.2.3: `seed_material = entropy_input || nonce || personalization`.
    pub fn new(entropy: &[u8], nonce: &[u8], personalization: &[u8]) -> Self {
        let mut this = Self {
            key: [0x00; OUTLEN],
            v: [0x01; OUTLEN],
            reseed_counter: 1,
        };
        this.update(&[entropy, nonce, personalization]);
        this
    }

    /// SP 800-90A §10.1.2.2 — the DRBG update function.
    fn update(&mut self, provided: &[&[u8]]) {
        let any = provided.iter().any(|p| !p.is_empty());

        let mut parts: heapless_parts::Parts = heapless_parts::Parts::new();
        parts.push(&self.v);
        parts.push(&[0x00]);
        for p in provided {
            parts.push(p);
        }
        self.key = hmac(&self.key, parts.as_slice());
        self.v = hmac(&self.key, &[&self.v]);

        if !any {
            return;
        }

        let mut parts: heapless_parts::Parts = heapless_parts::Parts::new();
        parts.push(&self.v);
        parts.push(&[0x01]);
        for p in provided {
            parts.push(p);
        }
        self.key = hmac(&self.key, parts.as_slice());
        self.v = hmac(&self.key, &[&self.v]);
    }

    /// SP 800-90A §10.1.2.4 — reseed with fresh entropy.
    pub fn reseed(&mut self, entropy: &[u8], additional: &[u8]) {
        self.update(&[entropy, additional]);
        self.reseed_counter = 1;
    }

    /// SP 800-90A §10.1.2.5 — generate pseudorandom bytes.
    pub fn generate(&mut self, out: &mut [u8]) -> Result<(), Error> {
        self.generate_with(out, &[])
    }

    pub fn generate_with(&mut self, out: &mut [u8], additional: &[u8]) -> Result<(), Error> {
        if out.len() > MAX_BYTES_PER_REQUEST {
            return Err(Error::TooMuchAtOnce { len: out.len() });
        }
        if self.reseed_counter > RESEED_INTERVAL {
            return Err(Error::ReseedRequired);
        }
        if !additional.is_empty() {
            self.update(&[additional]);
        }

        for chunk in out.chunks_mut(OUTLEN) {
            self.v = hmac(&self.key, &[&self.v]);
            chunk.copy_from_slice(&self.v[..chunk.len()]);
        }

        if additional.is_empty() {
            self.update(&[]);
        } else {
            self.update(&[additional]);
        }
        self.reseed_counter += 1;
        Ok(())
    }

    /// Uniform integer in `0..n`, by rejection sampling. Never modulo-biased.
    ///
    /// `n` must be non-zero.
    pub fn below(&mut self, n: u32) -> Result<u32, Error> {
        assert!(n > 0, "below(0) has no valid result");
        if n == 1 {
            return Ok(0);
        }
        // Accept only the largest prefix of `0..2^32` whose size is a multiple of `n`,
        // so every residue is equally likely. `2^32 mod n` computed without overflow:
        let rem = (u32::MAX % n) + 1;
        let limit = if rem == n { u32::MAX } else { u32::MAX - rem };
        loop {
            let mut b = [0u8; 4];
            self.generate(&mut b)?;
            let v = u32::from_le_bytes(b);
            if v <= limit {
                return Ok(v % n);
            }
        }
    }

    /// In-place Fisher-Yates shuffle. Used for the anti-Tempest keypad scan order —
    /// which is exactly the operation that must never touch seed entropy.
    pub fn shuffle<T>(&mut self, items: &mut [T]) -> Result<(), Error> {
        if items.len() < 2 {
            return Ok(());
        }
        for i in (1..items.len()).rev() {
            let j = self.below(i as u32 + 1)? as usize;
            items.swap(i, j);
        }
        Ok(())
    }
}

/// A tiny fixed-capacity slice-of-slices builder, so `update` can assemble its HMAC
/// input without allocating.
mod heapless_parts {
    const CAP: usize = 8;

    pub struct Parts<'a> {
        parts: [&'a [u8]; CAP],
        len: usize,
    }

    impl<'a> Parts<'a> {
        pub fn new() -> Self {
            Self {
                parts: [&[]; CAP],
                len: 0,
            }
        }
        pub fn push(&mut self, p: &'a [u8]) {
            assert!(self.len < CAP, "too many HMAC input parts");
            self.parts[self.len] = p;
            self.len += 1;
        }
        pub fn as_slice(&self) -> &[&'a [u8]] {
            &self.parts[..self.len]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drbg() -> HmacDrbg {
        HmacDrbg::new(&[0x42; 32], &[0x01; 16], b"catcard/test")
    }

    #[test]
    fn output_is_deterministic_for_a_given_seed() {
        let mut a = drbg();
        let mut b = drbg();
        let (mut x, mut y) = ([0u8; 128], [0u8; 128]);
        a.generate(&mut x).unwrap();
        b.generate(&mut y).unwrap();
        assert_eq!(x, y);
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Cross-checked byte-for-byte against an independent implementation of
    /// SP 800-90A §10.1.2, written separately from the spec text
    /// (`tools/reference/drbg_ref.py`). These pin the exact generator behaviour so a
    /// refactor cannot silently change it.
    ///
    /// TODO(#1): also import the NIST CAVP `HMAC_DRBG.rsp` SHA-256 vectors, which
    /// validate against the standard rather than against a second reading of it.
    #[test]
    fn matches_the_cross_checked_reference_vectors() {
        // Instantiate with 32 zero bytes, no nonce, no personalization.
        let mut d = HmacDrbg::new(&[0x00; 32], &[], &[]);
        let mut out = [0u8; 32];
        d.generate(&mut out).unwrap();
        assert_eq!(
            hex(&out),
            "3bfcfcbce13be445f7a300bb7c9fcf74ff3e9739735a418f87bfaaf46c0cee17"
        );

        // The fixture used throughout these tests, first 128 bytes: exercises the
        // multi-block generate loop.
        let mut d = drbg();
        let mut out = [0u8; 128];
        d.generate(&mut out).unwrap();
        assert_eq!(
            hex(&out),
            "32199266c0fb7f1e7756ccc51fc0248b8a55f517230e9db7a4bde94e54638952\
             bc2696f67a0d4ea48b6e913fdfe6fdef66e65bb95f09bf6119f08897537dd96f\
             62d6274c5af08e5df9838b2ef5c6c4d3254dfafc4ea47096ed0a35d5448eb808\
             930ca669eba0e6ea967e433e9aab528f6f67a23301610110e519900fb640ecb2"
        );

        // Unaligned length: the final partial block must be a truncation of V, not a
        // fresh draw.
        let mut d = drbg();
        let mut out = [0u8; 33];
        d.generate(&mut out).unwrap();
        assert_eq!(
            hex(&out),
            "32199266c0fb7f1e7756ccc51fc0248b8a55f517230e9db7a4bde94e54638952bc"
        );

        // After a reseed.
        let mut d = drbg();
        d.reseed(&[0x99; 32], &[]);
        let mut out = [0u8; 32];
        d.generate(&mut out).unwrap();
        assert_eq!(
            hex(&out),
            "476fa2ba918af5b9d8f76a787d0bcaec731f056881505cdd44145bc6d037cb87"
        );
    }

    #[test]
    fn different_personalization_gives_different_streams() {
        let mut a = HmacDrbg::new(&[7; 32], &[], b"ui");
        let mut b = HmacDrbg::new(&[7; 32], &[], b"nonces");
        let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
        a.generate(&mut x).unwrap();
        b.generate(&mut y).unwrap();
        assert_ne!(x, y);
    }

    #[test]
    fn successive_generates_differ() {
        let mut d = drbg();
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        d.generate(&mut a).unwrap();
        d.generate(&mut b).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn reseeding_changes_the_stream() {
        let mut a = drbg();
        let mut b = drbg();
        b.reseed(&[0x99; 32], &[]);
        let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
        a.generate(&mut x).unwrap();
        b.generate(&mut y).unwrap();
        assert_ne!(x, y);
    }

    #[test]
    fn generate_fills_lengths_that_are_not_multiples_of_the_block() {
        let mut d = drbg();
        for len in [1usize, 31, 32, 33, 64, 100] {
            let mut out = vec![0u8; len];
            d.generate(&mut out).unwrap();
            assert_eq!(out.len(), len);
            assert!(out.iter().any(|&b| b != 0));
        }
    }

    #[test]
    fn oversized_requests_are_refused() {
        let mut d = drbg();
        let mut out = vec![0u8; MAX_BYTES_PER_REQUEST + 1];
        assert!(matches!(
            d.generate(&mut out),
            Err(Error::TooMuchAtOnce { .. })
        ));
    }

    #[test]
    fn below_stays_in_range() {
        let mut d = drbg();
        for n in [1u32, 2, 3, 4, 12, 100, 0xffff] {
            for _ in 0..200 {
                assert!(d.below(n).unwrap() < n);
            }
        }
    }

    #[test]
    fn below_is_not_modulo_biased() {
        // With a modulo-biased implementation, low values are over-represented for an
        // n that does not divide 2^32. Check the distribution is flat to within a
        // generous tolerance.
        let mut d = drbg();
        let n = 3u32;
        let mut counts = [0u32; 3];
        const TRIALS: u32 = 30_000;
        for _ in 0..TRIALS {
            counts[d.below(n).unwrap() as usize] += 1;
        }
        let expect = TRIALS / n;
        for c in counts {
            let delta = (c as i64 - expect as i64).unsigned_abs();
            assert!(
                delta < expect as u64 / 10,
                "skewed distribution: {counts:?}"
            );
        }
    }

    #[test]
    fn shuffle_is_a_permutation() {
        let mut d = drbg();
        for _ in 0..100 {
            let mut v: Vec<u32> = (0..12).collect();
            d.shuffle(&mut v).unwrap();
            let mut sorted = v.clone();
            sorted.sort();
            assert_eq!(sorted, (0..12).collect::<Vec<_>>());
        }
    }

    #[test]
    fn shuffle_actually_shuffles() {
        let mut d = drbg();
        let identity: Vec<u32> = (0..12).collect();
        let mut moved = 0;
        for _ in 0..50 {
            let mut v = identity.clone();
            d.shuffle(&mut v).unwrap();
            if v != identity {
                moved += 1;
            }
        }
        assert!(moved > 45, "shuffle left the order untouched too often");
    }

    #[test]
    fn shuffle_handles_degenerate_lengths() {
        let mut d = drbg();
        let mut empty: [u8; 0] = [];
        d.shuffle(&mut empty).unwrap();
        let mut one = [1u8];
        d.shuffle(&mut one).unwrap();
        assert_eq!(one, [1]);
    }

    #[test]
    fn reseed_counter_enforces_the_interval() {
        let mut d = drbg();
        d.reseed_counter = RESEED_INTERVAL + 1;
        let mut out = [0u8; 8];
        assert_eq!(d.generate(&mut out), Err(Error::ReseedRequired));
        d.reseed(&[1; 32], &[]);
        assert!(d.generate(&mut out).is_ok());
    }
}
