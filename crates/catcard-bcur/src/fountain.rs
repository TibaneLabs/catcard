//! Which fragments a part past the end carries, and how one is put back together.
//!
//! BC-UR is a fountain code. Parts numbered 1 to `seq_len` are single fragments, and a
//! sender that stopped there would have sent everything. Past that, a part is the XOR of
//! several fragments chosen by a PRNG seeded from the part number and the message
//! checksum -- so a receiver that missed part 3 can still recover it from a mixture that
//! covers 3 and two fragments it already holds.
//!
//! # Why this exists, having been deliberately left out
//!
//! The first version took pure parts only, on the reasoning that every conforming
//! encoder emits those first and a decoder could simply wait for the animation to come
//! round. The reasoning was wrong about real senders: the reference encoder's
//! `nextPart()` increments its sequence number for ever and never wraps, so a wallet
//! page shows parts 1..n once and then nothing but mixtures for as long as it is open.
//! Aiming a camera at one a few seconds late means never seeing a pure part at all,
//! which on this device looked exactly like a scanner that had stopped working.
//!
//! # What has to agree with the sender, exactly
//!
//! All of it, bit for bit: a different degree, or the same degree over a different set
//! of indexes, recovers a fragment that is not the one the sender mixed. So this follows
//! the reference implementation step for step -- Xoshiro256\*\*, the alias-method
//! sampler over `1/i` weights, and a Fisher-Yates shuffle that draws with `next_int` --
//! and is checked against the published test vectors rather than against itself.
//!
//! Source: `BlockchainCommons/bc-ur`, `fountain-utils.cpp`, `random-sampler.cpp`,
//! `xoshiro256.cpp`. [C]

/// The most fragments a message may be split into here.
///
/// A ceiling on the work a single scanned line can ask for: the sampler and the shuffle
/// are both `O(seq_len)` with `seq_len` taken from the part's own header, so a line
/// claiming four billion fragments would otherwise be a line that stops the device.
pub const MAX_FRAGMENTS: usize = 256;

/// Xoshiro256\*\*, seeded as BC-UR seeds it.
///
/// The seed is the SHA-256 of the bytes given, read as four big-endian 64-bit words.
/// [C] `xoshiro256.cpp`: `hash_then_set_s`.
pub struct Xoshiro256 {
    s: [u64; 4],
}

impl Xoshiro256 {
    /// Seed from arbitrary bytes, through SHA-256.
    pub fn new(seed: &[u8]) -> Self {
        let digest = outscript::hash::sha256_once(seed);
        let mut s = [0u64; 4];
        for (i, word) in s.iter_mut().enumerate() {
            let mut v = 0u64;
            for n in 0..8 {
                v = (v << 8) | u64::from(digest[i * 8 + n]);
            }
            *word = v;
        }
        Xoshiro256 { s }
    }

    /// The next 64-bit output. [C] `xoshiro256.cpp`: `next`.
    ///
    /// Named as the reference names it, not as an iterator: it yields for ever and has
    /// no `Item`, and calling it `next_u64` would make the correspondence with the
    /// algorithm it must match harder to check.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> u64 {
        let result = self.s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        result
    }

    /// The next output as a fraction of one.
    ///
    /// `next() / (u64::MAX + 1)`, in double precision, because that is the arithmetic
    /// the sender used to choose the same number. [C] `xoshiro256.cpp`: `next_double`.
    pub fn next_double(&mut self) -> f64 {
        const M: f64 = 18_446_744_073_709_551_616.0; // 2^64
        self.next() as f64 / M
    }

    /// A number in `low..=high`. [C] `xoshiro256.cpp`: `next_int`.
    fn next_int(&mut self, low: u64, high: u64) -> u64 {
        (self.next_double() * (high - low + 1) as f64) as u64 + low
    }
}

/// How many fragments a mixture combines.
///
/// Weighted towards one: the probabilities are `1/1, 1/2, ... 1/seq_len`, sampled by the
/// alias method. Written out here rather than approximated, because a degree that
/// differs from the sender's by one is a fragment recovered from the wrong mixture.
/// [C] `fountain-utils.cpp`: `choose_degree`; `random-sampler.cpp`.
fn choose_degree(seq_len: usize, rng: &mut Xoshiro256) -> usize {
    // The alias table, built exactly as `RandomSampler`'s constructor builds it --
    // including its reversed index order, which decides which alias a given draw lands
    // on and so cannot be tidied away.
    let n = seq_len;
    let mut p = [0.0f64; MAX_FRAGMENTS];
    let mut sum = 0.0;
    for i in 0..n {
        sum += 1.0 / (i + 1) as f64;
    }
    for (i, slot) in p.iter_mut().enumerate().take(n) {
        *slot = (1.0 / (i + 1) as f64) * n as f64 / sum;
    }

    let mut small = [0usize; MAX_FRAGMENTS];
    let mut large = [0usize; MAX_FRAGMENTS];
    let (mut ns, mut nl) = (0usize, 0usize);
    for i in (0..n).rev() {
        if p[i] < 1.0 {
            small[ns] = i;
            ns += 1;
        } else {
            large[nl] = i;
            nl += 1;
        }
    }

    let mut probs = [0.0f64; MAX_FRAGMENTS];
    let mut aliases = [0usize; MAX_FRAGMENTS];
    while ns > 0 && nl > 0 {
        ns -= 1;
        let a = small[ns];
        nl -= 1;
        let g = large[nl];
        probs[a] = p[a];
        aliases[a] = g;
        p[g] += p[a] - 1.0;
        if p[g] < 1.0 {
            small[ns] = g;
            ns += 1;
        } else {
            large[nl] = g;
            nl += 1;
        }
    }
    while nl > 0 {
        nl -= 1;
        probs[large[nl]] = 1.0;
    }
    while ns > 0 {
        ns -= 1;
        probs[small[ns]] = 1.0;
    }

    // Two draws: one picks the column, the other decides between it and its alias.
    let r1 = rng.next_double();
    let r2 = rng.next_double();
    let i = (n as f64 * r1) as usize;
    let i = i.min(n - 1);
    if r2 < probs[i] { i + 1 } else { aliases[i] + 1 }
}

/// Which fragments part `seq_num` carries, as a bitmap over `0..seq_len`.
///
/// A pure part carries exactly one. A mixture carries `degree` of them, drawn by
/// shuffling every index and taking the first `degree`. [C] `fountain-utils.cpp`:
/// `choose_fragments`.
pub fn choose_fragments(seq_num: u32, seq_len: usize, checksum: u32) -> Option<Bitmap> {
    if seq_len == 0 || seq_len > MAX_FRAGMENTS {
        return None;
    }
    let mut out = Bitmap::new();
    if seq_num as usize <= seq_len {
        out.set(seq_num as usize - 1);
        return Some(out);
    }

    let mut seed = [0u8; 8];
    seed[..4].copy_from_slice(&seq_num.to_be_bytes());
    seed[4..].copy_from_slice(&checksum.to_be_bytes());
    let mut rng = Xoshiro256::new(&seed);
    let degree = choose_degree(seq_len, &mut rng);

    // Fisher-Yates as the reference writes it: draw an index out of what is left, take
    // that item, and close the gap by shifting -- not by swapping with the end, which
    // shuffles just as well and produces a different order.
    let mut remaining = [0usize; MAX_FRAGMENTS];
    for (i, slot) in remaining.iter_mut().enumerate().take(seq_len) {
        *slot = i;
    }
    let mut left = seq_len;
    for _ in 0..degree {
        let at = rng.next_int(0, left as u64 - 1) as usize;
        out.set(remaining[at]);
        for j in at..left - 1 {
            remaining[j] = remaining[j + 1];
        }
        left -= 1;
    }
    Some(out)
}

/// A set of fragment indexes, small enough to copy.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Bitmap {
    words: [u64; MAX_FRAGMENTS / 64],
}

impl Bitmap {
    pub const fn new() -> Self {
        Bitmap {
            words: [0; MAX_FRAGMENTS / 64],
        }
    }

    pub fn set(&mut self, i: usize) {
        if i < MAX_FRAGMENTS {
            self.words[i / 64] |= 1 << (i % 64);
        }
    }

    pub fn clear(&mut self, i: usize) {
        if i < MAX_FRAGMENTS {
            self.words[i / 64] &= !(1 << (i % 64));
        }
    }

    pub fn has(&self, i: usize) -> bool {
        i < MAX_FRAGMENTS && self.words[i / 64] & (1 << (i % 64)) != 0
    }

    pub fn count(&self) -> usize {
        self.words.iter().map(|w| w.count_ones() as usize).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|&w| w == 0)
    }

    /// The only index set, when exactly one is.
    pub fn only(&self) -> Option<usize> {
        if self.count() != 1 {
            return None;
        }
        (0..MAX_FRAGMENTS).find(|&i| self.has(i))
    }

    /// Remove everything in `other` from this.
    pub fn subtract(&mut self, other: &Bitmap) {
        for (a, b) in self.words.iter_mut().zip(other.words.iter()) {
            *a &= !*b;
        }
    }

    /// Whether every index of this is also in `other`.
    pub fn within(&self, other: &Bitmap) -> bool {
        self.words
            .iter()
            .zip(other.words.iter())
            .all(|(a, b)| a & !b == 0)
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    extern crate std;

    use super::*;
    use alloc::vec::Vec;

    /// The generator's own published output, so a wrong rotate or multiply is caught
    /// before anything built on it is.
    ///
    /// Source: `bc-ur`, `test.cpp`: `test_rng_1`, seeded with the string "Wolf". [C]
    #[test]
    fn the_generator_matches_its_published_output() {
        let mut rng = Xoshiro256::new(b"Wolf");
        let got: Vec<u64> = (0..20).map(|_| rng.next() % 100).collect();
        assert_eq!(
            got,
            std::vec![
                42, 81, 85, 8, 82, 84, 76, 73, 70, 88, 2, 74, 40, 48, 77, 54, 88, 7, 5, 88
            ]
        );
    }

    /// The degree chooser's published output, which is the alias table and both draws.
    ///
    /// Source: `bc-ur`, `test.cpp`: `test_choose_degree`, over eleven fragments with the
    /// generator seeded "Wolf-1", "Wolf-2" and so on. [C]
    #[test]
    fn the_degree_chooser_matches_its_published_output() {
        let expected = [
            11usize, 3, 6, 5, 2, 1, 2, 11, 1, 3, 9, 10, 10, 4, 2, 1, 1, 2, 1, 1,
        ];
        for (i, want) in expected.iter().enumerate() {
            let mut seed: heapless::String<16> = heapless::String::new();
            use core::fmt::Write as _;
            let _ = write!(seed, "Wolf-{}", i + 1);
            let mut rng = Xoshiro256::new(seed.as_bytes());
            assert_eq!(choose_degree(11, &mut rng), *want, "degree {}", i + 1);
        }
    }

    /// Which fragments each part carries, against the published table.
    ///
    /// The whole point of this module in one assertion: parts 1 to 11 are the pure
    /// fragments, and parts 12 onwards are mixtures whose membership has to be the
    /// sender's exactly. The checksum is that of the reference's own 1024-byte test
    /// message, recomputed here rather than trusted: `0x2f19f3bb`.
    ///
    /// Source: `bc-ur`, `test.cpp`: `test_choose_fragments`. [C]
    #[test]
    fn the_fragment_chooser_matches_its_published_table() {
        const CHECKSUM: u32 = 0x2f19_f3bb;
        let expected: [&[usize]; 30] = [
            &[0],
            &[1],
            &[2],
            &[3],
            &[4],
            &[5],
            &[6],
            &[7],
            &[8],
            &[9],
            &[10],
            &[9],
            &[2, 5, 6, 8, 9, 10],
            &[8],
            &[1, 5],
            &[1],
            &[0, 2, 4, 5, 8, 10],
            &[5],
            &[2],
            &[2],
            &[0, 1, 3, 4, 5, 7, 9, 10],
            &[0, 1, 2, 3, 5, 6, 8, 9, 10],
            &[0, 2, 4, 5, 7, 8, 9, 10],
            &[3, 5],
            &[4],
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            &[0, 1, 3, 4, 5, 6, 7, 9, 10],
            &[6],
            &[5, 6],
            &[7],
        ];
        for (i, want) in expected.iter().enumerate() {
            let seq = i as u32 + 1;
            let got = choose_fragments(seq, 11, CHECKSUM).expect("in range");
            let listed: Vec<usize> = (0..11).filter(|&i| got.has(i)).collect();
            assert_eq!(&listed[..], *want, "part {seq}");
        }
    }

    /// A bitmap is a set, and the operations the solver leans on are the set ones.
    #[test]
    fn a_bitmap_is_a_set() {
        let mut a = Bitmap::new();
        a.set(1);
        a.set(5);
        a.set(200);
        assert_eq!(a.count(), 3);
        assert!(a.has(200) && !a.has(199));
        assert_eq!(a.only(), None);

        let mut b = Bitmap::new();
        b.set(1);
        b.set(200);
        assert!(b.within(&a));
        assert!(!a.within(&b));

        let mut c = a;
        c.subtract(&b);
        assert_eq!(c.only(), Some(5));
        c.clear(5);
        assert!(c.is_empty());
    }

    /// Nothing claims more fragments than there is room to reason about.
    #[test]
    fn an_absurd_part_count_is_refused() {
        assert!(choose_fragments(1, 0, 7).is_none());
        assert!(choose_fragments(1, MAX_FRAGMENTS + 1, 7).is_none());
        assert!(choose_fragments(1, MAX_FRAGMENTS, 7).is_some());
    }
}
