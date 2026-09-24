//! Seed XOR: one BIP-39 phrase carried as several, XOR-ed bit for bit.
//!
//! A seed is split into parts that are themselves ordinary BIP-39 phrases of the same
//! length. XOR all of them together and the original comes back; hold all but one and
//! you have nothing -- the missing part is as unknown as the seed was. So the parts can
//! go to different places, and none of those places is a wallet.
//!
//! It is not Shamir: there is no threshold, every part is needed. What it buys instead
//! is that a part is a plain seed phrase, so it needs no special software to store, to
//! stamp into metal, or to read back -- and a part can be given a decoy wallet of its
//! own by whoever holds it.
//!
//! # What is XOR-ed
//!
//! The *entropy*, not the words and not the checksum. A phrase is `ENT` bits of entropy
//! plus `ENT/32` bits of checksum, cut into 11-bit words, so XOR-ing the word indices
//! bit for bit and XOR-ing the entropy are the same operation everywhere except in the
//! checksum bits -- which are not combined at all. Each part carries its own checksum,
//! protecting that part, and the result's checksum is computed fresh from the entropy
//! that came out.
//!
//! That is why the published examples show the last word's low bits as `x`: in a
//! 24-word split the final 8 bits of the XOR are discarded and recomputed, and in a
//! 12-word split the final 4.
//!
//! # Making the parts
//!
//! All but one part is a hash; the last is whatever XOR-es the others back to the
//! secret, which is what makes the set add up. "A hash" is `SHA-256(SHA-256(x))`
//! truncated to the secret's length, and `x` is either
//!
//! - **deterministic**: [`TAG`], the secret, and `"<i> of <n> parts"`, so the same seed
//!   split the same way tomorrow gives the same words and the owner can check what they
//!   wrote down; or
//! - **random**: bytes from the device's own TRNGs, hashed the same way.
//!
//! Both are the same strength -- the last part carries the entropy of the secret either
//! way -- and the choice is about whether the split is reproducible.
//!
//! Source: Coldcard's published Seed XOR description and its worked examples, which the
//! tests below are taken from verbatim. The exact deterministic preimage is `[?]`: the
//! description names its three pieces but not the bytes between them, and only
//! reproducing a stock device's *deterministic* split depends on getting it right. A
//! split made here always recombines to the seed it came from, whatever the preimage
//! was, and joining is defined by the bits rather than by any string.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::bip39::{MAX_ENTROPY_LEN, Mnemonic, words_for_entropy};

/// Fewest parts a split can have. One part is the seed itself.
pub const MIN_PARTS: usize = 2;

/// Most parts a split can have.
///
/// Stock's limit, and a practical one: every part has to be written down and kept
/// somewhere different, and the number of places that are genuinely different is small.
pub const MAX_PARTS: usize = 4;

/// The fixed string the deterministic preimage starts with.
///
/// Its only job is domain separation -- so this hash of the secret cannot collide with
/// some other use of a hash of the secret. Source: as the module note says, `[?]`.
pub const TAG: &[u8] = b"Batshitoshi ";

/// Longest deterministic preimage: the tag, a 32-byte secret, and `"0 of 4 parts"`.
const PREIMAGE_MAX: usize = TAG.len() + MAX_ENTROPY_LEN + 16;

/// Why a split or a join was refused.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Fewer than [`MIN_PARTS`] or more than [`MAX_PARTS`].
    PartCount,
    /// Not a BIP-39 entropy length, so there is no phrase of that size; or, for a random
    /// split, a noise slice with fewer bytes than the secret.
    Length,
    /// The parts are not all the same length. Seed XOR is only defined between phrases
    /// of equal length -- a 12-word part and a 24-word part combine to nothing.
    Mixed,
}

/// XOR `src` into `dst`, byte for byte. Stops at the shorter of the two.
fn xor_into(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= s;
    }
}

/// `SHA-256(SHA-256(input))`, truncated to `out`.
fn hash_into(input: &[u8], out: &mut [u8]) {
    use purecrypto::hash::{Digest as _, Sha256};
    let first = Sha256::digest(input);
    let second = Sha256::digest(first.as_slice());
    let n = out.len().min(second.as_slice().len());
    out[..n].copy_from_slice(&second.as_slice()[..n]);
}

/// The deterministic preimage for part `i` of `count`, written into `buf`.
///
/// `i` is zero-based, as the published description has it: `0 of 4 parts`.
fn preimage<'a>(
    secret: &[u8],
    i: usize,
    count: usize,
    buf: &'a mut [u8; PREIMAGE_MAX],
) -> &'a [u8] {
    let mut n = 0;
    let mut put = |bytes: &[u8]| {
        let end = (n + bytes.len()).min(buf.len());
        buf[n..end].copy_from_slice(&bytes[..end - n]);
        n = end;
    };
    put(TAG);
    put(secret);
    // `"<i> of <n> parts"` without a formatter: both numbers are one digit, because
    // `count` is at most `MAX_PARTS` and `i` is below it.
    put(&[b'0' + (i % 10) as u8]);
    put(b" of ");
    put(&[b'0' + (count % 10) as u8]);
    put(b" parts");
    &buf[..n]
}

/// A secret, cut into parts that XOR back to it.
///
/// Every part is as sensitive as the seed: any one of them plus the others is the
/// wallet. They are wiped when this is dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Parts {
    data: [[u8; MAX_ENTROPY_LEN]; MAX_PARTS],
    /// Entropy length of each part, which is the secret's.
    #[zeroize(skip)]
    len: usize,
    #[zeroize(skip)]
    count: usize,
}

impl Parts {
    /// Split `secret` into `count` parts, reproducibly.
    ///
    /// The same secret and count give the same parts every time, which is what lets an
    /// owner check the words they wrote down yesterday.
    pub fn deterministic(secret: &[u8], count: usize, kw: &crate::KeyWork) -> Result<Self, Error> {
        let mut this = Self::blank(secret, count)?;
        let mut buf = [0u8; PREIMAGE_MAX];
        for i in 0..count - 1 {
            let pre = preimage(secret, i, count, &mut buf);
            let mut part = [0u8; MAX_ENTROPY_LEN];
            hash_into(pre, &mut part[..this.len]);
            this.data[i][..this.len].copy_from_slice(&part[..this.len]);
            part.zeroize();
        }
        buf.zeroize();
        this.close(secret, kw);
        Ok(this)
    }

    /// Split `secret` into parts made from `noise`, one slice per part but the last.
    ///
    /// The noise is hashed, not used raw: a part is always `SHA-256(SHA-256(x))`, so a
    /// TRNG with a bias cannot put that bias straight into a phrase someone stamps into
    /// metal. Each slice must have at least as many bytes as the secret: shorter noise is
    /// refused with [`Error::Length`], since hashing stretches nothing -- a part made from
    /// four bytes of noise has sixteen bits of entropy however long the hash is, and every
    /// other part is then as weak as the secret XOR that one.
    pub fn from_noise(secret: &[u8], noise: &[&[u8]], kw: &crate::KeyWork) -> Result<Self, Error> {
        let mut this = Self::blank(secret, noise.len() + 1)?;
        if noise.iter().any(|n| n.len() < secret.len()) {
            return Err(Error::Length);
        }
        for (i, n) in noise.iter().enumerate() {
            let mut part = [0u8; MAX_ENTROPY_LEN];
            hash_into(n, &mut part[..this.len]);
            this.data[i][..this.len].copy_from_slice(&part[..this.len]);
            part.zeroize();
        }
        this.close(secret, kw);
        Ok(this)
    }

    /// An empty set of `count` parts for a secret of a length BIP-39 has words for.
    fn blank(secret: &[u8], count: usize) -> Result<Self, Error> {
        if !(MIN_PARTS..=MAX_PARTS).contains(&count) {
            return Err(Error::PartCount);
        }
        if words_for_entropy(secret.len()).is_none() {
            return Err(Error::Length);
        }
        Ok(Self {
            data: [[0u8; MAX_ENTROPY_LEN]; MAX_PARTS],
            len: secret.len(),
            count,
        })
    }

    /// Fill the last part with whatever makes the set XOR back to `secret`.
    ///
    /// This is where the entropy of the secret ends up, which is why the last part is
    /// no weaker than the others however the others were made.
    fn close(&mut self, secret: &[u8], _kw: &crate::KeyWork) {
        let (last, rest) = (self.count - 1, self.count - 1);
        self.data[last][..self.len].copy_from_slice(secret);
        for i in 0..rest {
            let (head, tail) = self.data.split_at_mut(last);
            xor_into(&mut tail[0][..self.len], &head[i][..self.len]);
        }
    }

    /// How many parts there are.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Part `i`'s entropy, or `None` past the end.
    pub fn part(&self, i: usize) -> Option<&[u8]> {
        (i < self.count).then(|| &self.data[i][..self.len])
    }

    /// Part `i` as a phrase, with its own checksum.
    pub fn mnemonic(&self, i: usize, kw: &crate::KeyWork) -> Option<Mnemonic> {
        Mnemonic::from_entropy(self.part(i)?, kw).ok()
    }

    /// XOR every part back together into `out`, which is the secret again.
    ///
    /// For the check a split should make before it shows anybody any words: the parts
    /// are only a backup if they actually recombine.
    pub fn recombine(&self, out: &mut [u8], _kw: &crate::KeyWork) -> usize {
        let n = out.len().min(self.len);
        out[..n].fill(0);
        for i in 0..self.count {
            xor_into(&mut out[..n], &self.data[i][..n]);
        }
        n
    }
}

/// XOR the entropy of every part in `parts` into `out`, returning its length.
///
/// The parts must be the same length; their checksums are each part's own and take no
/// part in this. What comes out is entropy, not a phrase --
/// [`Mnemonic::from_entropy`] puts the new checksum on it.
pub fn join(parts: &[&[u8]], out: &mut [u8], _kw: &crate::KeyWork) -> Result<usize, Error> {
    if !(MIN_PARTS..=MAX_PARTS).contains(&parts.len()) {
        return Err(Error::PartCount);
    }
    let len = parts[0].len();
    if parts.iter().any(|p| p.len() != len) {
        return Err(Error::Mixed);
    }
    if words_for_entropy(len).is_none() || len > out.len() {
        return Err(Error::Length);
    }
    out[..len].fill(0);
    for p in parts {
        xor_into(&mut out[..len], p);
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyWork;

    /// The tests are not key work, but the API is. Interrupts are not a thing here.
    fn kw() -> KeyWork {
        // SAFETY: a host test; there is nothing to mask and nothing to time.
        unsafe { KeyWork::assume_masked() }
    }

    fn entropy_of(phrase: &str) -> Vec<u8> {
        Mnemonic::parse(phrase, &kw())
            .expect("vector parses")
            .entropy()
            .to_vec()
    }

    const A24: &str = "romance wink lottery autumn shop bring dawn tongue range crater truth ability miss spice fitness easy legal release recall obey exchange recycle dragon room";
    const B24: &str = "lion misery divide hurry latin fluid camp advance illegal lab pyramid unaware eager fringe sick camera series noodle toy crowd jeans select depth lounge";
    const C24: &str = "vault nominee cradle silk own frown throw leg cactus recall talent worry gadget surface shy planet purpose coffee drip few seven term squeeze educate";
    const R24: &str = "silent toe meat possible chair blossom wait occur this worth option bag nurse find fish scene bench asthma bike wage world quit primary indoor";

    const A12: &str =
        "romance wink lottery autumn shop bring dawn tongue range crater truth ability";
    const B12: &str =
        "boat unfair shell violin tree robust open ride visual forest vintage approve";
    const C12: &str =
        "lion misery divide hurry latin fluid camp advance illegal lab pyramid unhappy";
    const R12: &str =
        "cannon opinion leader nephew found yard metal galaxy crouch between real trade";

    /// The published 24-word example, three parts. This is the whole definition of the
    /// scheme as far as anyone else's software is concerned, so it is checked against
    /// the words rather than against our own round trip.
    #[test]
    fn the_published_24_word_example_joins() {
        let (a, b, c) = (entropy_of(A24), entropy_of(B24), entropy_of(C24));
        let mut out = [0u8; MAX_ENTROPY_LEN];
        let n = join(&[&a, &b, &c], &mut out, &kw()).unwrap();
        assert_eq!(n, 32);
        let joined = Mnemonic::from_entropy(&out[..n], &kw()).unwrap();
        let words: Vec<&str> = joined.words().collect();
        assert_eq!(words.join(" "), R24);
    }

    /// And the 12-word one, because the checksum is 4 bits there rather than 8 -- the
    /// part of the result that is *not* the XOR.
    #[test]
    fn the_published_12_word_example_joins() {
        let (a, b, c) = (entropy_of(A12), entropy_of(B12), entropy_of(C12));
        let mut out = [0u8; MAX_ENTROPY_LEN];
        let n = join(&[&a, &b, &c], &mut out, &kw()).unwrap();
        assert_eq!(n, 16);
        let joined = Mnemonic::from_entropy(&out[..n], &kw()).unwrap();
        let words: Vec<&str> = joined.words().collect();
        assert_eq!(words.join(" "), R12);
    }

    /// The last word of a part carries checksum bits that are *not* XOR-ed, so the
    /// result's last word is not the XOR of the parts' last words. If this ever passed
    /// by accident it would mean the checksum was being combined too.
    #[test]
    fn the_checksum_is_not_carried_through() {
        let idx = |phrase: &str| -> u16 {
            let m = Mnemonic::parse(phrase, &kw()).unwrap();
            let mut out = [0u16; crate::bip39::MAX_WORDS];
            let n = m.word_indices(&mut out);
            out[n - 1]
        };
        let xor_of_last = idx(A24) ^ idx(B24) ^ idx(C24);
        // The entropy bits agree -- the top 3 of the last word, in a 24-word phrase.
        assert_eq!(xor_of_last >> 8, idx(R24) >> 8);
        // The checksum bits do not, on this vector: 0x98 recomputed against 0x?? XOR-ed.
        assert_ne!(xor_of_last, idx(R24));
    }

    /// Only phrases of one length combine. A 12-word part and a 24-word part is a
    /// mistake with no sensible answer, so it is refused rather than truncated.
    #[test]
    fn parts_of_different_lengths_are_refused() {
        let (a, b) = (entropy_of(A24), entropy_of(B12));
        let mut out = [0u8; MAX_ENTROPY_LEN];
        assert_eq!(join(&[&a, &b], &mut out, &kw()), Err(Error::Mixed));
    }

    #[test]
    fn one_part_is_not_a_split_and_five_is_too_many() {
        let a = entropy_of(A24);
        let mut out = [0u8; MAX_ENTROPY_LEN];
        assert_eq!(join(&[&a], &mut out, &kw()), Err(Error::PartCount));
        assert_eq!(
            join(&[&a, &a, &a, &a, &a], &mut out, &kw()),
            Err(Error::PartCount)
        );
    }

    /// Whatever the parts are made of, they have to come back. This is the property the
    /// owner is actually relying on, and it holds for every count and every length.
    #[test]
    fn every_split_recombines_to_what_it_came_from() {
        for len in [16usize, 20, 24, 28, 32] {
            let secret: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(37) ^ 0x5a)
                .collect();
            for count in MIN_PARTS..=MAX_PARTS {
                let parts = Parts::deterministic(&secret, count, &kw()).unwrap();
                assert_eq!(parts.count(), count);
                let mut back = [0u8; MAX_ENTROPY_LEN];
                let n = parts.recombine(&mut back, &kw());
                assert_eq!(&back[..n], &secret[..], "{len} bytes in {count} parts");
                // And through the words, which is how they will actually be written
                // down and typed back in.
                let each: Vec<Vec<u8>> = (0..count)
                    .map(|i| {
                        let m = parts.mnemonic(i, &kw()).unwrap();
                        let words: Vec<&str> = m.words().collect();
                        let reparsed = Mnemonic::parse(&words.join(" "), &kw()).unwrap();
                        reparsed.entropy().to_vec()
                    })
                    .collect();
                let refs: Vec<&[u8]> = each.iter().map(|v| v.as_slice()).collect();
                let mut out = [0u8; MAX_ENTROPY_LEN];
                let n = join(&refs, &mut out, &kw()).unwrap();
                assert_eq!(&out[..n], &secret[..]);
            }
        }
    }

    /// The point of the deterministic mode: split it again tomorrow, get the same words.
    #[test]
    fn the_deterministic_split_is_the_same_every_time() {
        let secret = [0x11u8; 32];
        let a = Parts::deterministic(&secret, 3, &kw()).unwrap();
        let b = Parts::deterministic(&secret, 3, &kw()).unwrap();
        for i in 0..3 {
            assert_eq!(a.part(i), b.part(i));
        }
        // And a different count is a different split, not the same parts plus one.
        let c = Parts::deterministic(&secret, 2, &kw()).unwrap();
        assert_ne!(a.part(0), c.part(0));
    }

    /// No part may be the secret itself, or equal to another part: either would hand
    /// the wallet to whoever holds that one piece of paper. With hashes for all but the
    /// last this is overwhelmingly unlikely rather than impossible, so it is asserted
    /// on the cases we can enumerate.
    #[test]
    fn no_part_is_the_secret_or_a_twin_of_another() {
        for count in MIN_PARTS..=MAX_PARTS {
            let secret = [0x77u8; 32];
            let parts = Parts::deterministic(&secret, count, &kw()).unwrap();
            for i in 0..count {
                assert_ne!(parts.part(i).unwrap(), &secret[..]);
                for j in i + 1..count {
                    assert_ne!(parts.part(i), parts.part(j));
                }
            }
        }
    }

    /// Random-mode parts are hashed, not taken raw, so the bytes on the paper are never
    /// the bytes the TRNG produced.
    #[test]
    fn noise_is_hashed_before_it_becomes_a_part() {
        let secret = [0x22u8; 32];
        let noise = [0x33u8; 32];
        let parts = Parts::from_noise(&secret, &[&noise], &kw()).unwrap();
        assert_eq!(parts.count(), 2);
        assert_ne!(parts.part(0).unwrap(), &noise[..]);
        let mut back = [0u8; MAX_ENTROPY_LEN];
        let n = parts.recombine(&mut back, &kw());
        assert_eq!(&back[..n], &secret[..]);
    }

    /// Noise shorter than the secret is refused, not hashed up to size: the hash makes a
    /// part the right length out of anything, and a part from too little noise is a part
    /// with too little in it.
    #[test]
    fn noise_shorter_than_the_secret_is_refused() {
        let secret = [0x22u8; 32];
        let short = [0x33u8; 31];
        let enough = [0x44u8; 32];
        assert_eq!(
            Parts::from_noise(&secret, &[&short], &kw()).err(),
            Some(Error::Length)
        );
        // One short slice among enough ones is still a refusal.
        assert_eq!(
            Parts::from_noise(&secret, &[&enough, &short], &kw()).err(),
            Some(Error::Length)
        );
        assert!(Parts::from_noise(&secret, &[&enough, &enough], &kw()).is_ok());
        // Longer than the secret is fine: more noise, not less.
        let long = [0x55u8; 64];
        assert!(Parts::from_noise(&secret, &[&long], &kw()).is_ok());
    }

    #[test]
    fn a_secret_of_no_bip39_length_has_no_split() {
        assert_eq!(
            Parts::deterministic(&[0u8; 17], 2, &kw()).err(),
            Some(Error::Length)
        );
    }
}
