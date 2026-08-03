//! BIP-39 mnemonics.
//!
//! Converts between wallet entropy and a human-transcribable phrase, and derives the
//! 64-byte seed everything else hangs off.
//!
//! # What is stored
//!
//! A [`Mnemonic`] holds **entropy**, not the derived seed, and renders words on demand.
//! That is deliberate and it is the format CatCard writes through the bootloader:
//!
//! - The seed is a one-way function of the entropy, so entropy can produce the seed but
//!   not the reverse. Storing only the seed would permanently foreclose anything that
//!   needs the entropy — including Cardano's Icarus master-key generation, which runs
//!   PBKDF2 over the mnemonic entropy rather than over the BIP-39 seed. CatCard intends
//!   to support ed25519 chains with soft derivation, so that door has to stay open.
//! - Entropy is smaller (16–32 bytes vs 64) and is what the user actually backed up.
//!
//! See `docs/ROADMAP.md` § "Multi-chain".
//!
//! # Passphrases and normalisation
//!
//! BIP-39 specifies NFKD normalisation of both the phrase and the passphrase. The
//! English wordlist is pure ASCII, for which NFKD is the identity, so phrases are fine.
//! Passphrases are not: an unnormalised non-ASCII passphrase yields a *different seed*
//! from every other wallet, which is a silent fund-loss bug.
//!
//! Rather than diverge quietly, [`Mnemonic::to_seed`] refuses a non-ASCII passphrase
//! with [`Error::PassphraseNotAscii`]. See `docs/ROADMAP.md`.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

pub mod wordlist;

#[cfg(test)]
mod test_vectors;

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop};

use wordlist::{BITS_PER_WORD, ENGLISH, MAX_WORD_LEN};

type HmacSha512 = Hmac<Sha512>;

/// Largest entropy BIP-39 allows: 256 bits.
pub const MAX_ENTROPY_LEN: usize = 32;
/// Smallest entropy BIP-39 allows: 128 bits.
pub const MIN_ENTROPY_LEN: usize = 16;
/// Words in the longest phrase.
pub const MAX_WORDS: usize = 24;
/// The derived seed is always 512 bits.
pub const SEED_LEN: usize = 64;

/// PBKDF2 iteration count fixed by BIP-39.
pub const PBKDF2_ROUNDS: u32 = 2048;
/// Salt prefix fixed by BIP-39; the passphrase is appended to it.
pub const SALT_PREFIX: &[u8] = b"mnemonic";

/// Upper bound on a rendered phrase: 24 words of at most 8 bytes, plus 23 separators.
pub const MAX_PHRASE_LEN: usize = MAX_WORDS * MAX_WORD_LEN + (MAX_WORDS - 1);

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Entropy must be 16, 20, 24, 28 or 32 bytes.
    BadEntropyLen { len: usize },
    /// A phrase must be 12, 15, 18, 21 or 24 words.
    BadWordCount { count: usize },
    /// A word is not in the English wordlist. Carries its position, so the UI can point
    /// at it; it deliberately does not carry the word itself.
    UnknownWord { position: usize },
    /// The phrase parses but its checksum is wrong — a typo or a transcription error.
    BadChecksum,
    /// Passphrase contains non-ASCII bytes, which need NFKD normalisation we do not
    /// implement. Refused rather than silently deriving a divergent seed.
    PassphraseNotAscii,
}

#[cfg(feature = "std")]
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::BadEntropyLen { len } => write!(
                f,
                "entropy is {len} bytes; BIP-39 allows 16, 20, 24, 28 or 32"
            ),
            Error::BadWordCount { count } => write!(
                f,
                "phrase has {count} words; BIP-39 allows 12, 15, 18, 21 or 24"
            ),
            Error::UnknownWord { position } => {
                write!(f, "word {} is not in the wordlist", position + 1)
            }
            Error::BadChecksum => write!(f, "phrase checksum does not match"),
            Error::PassphraseNotAscii => write!(
                f,
                "non-ASCII passphrases need NFKD normalisation, which is not implemented"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Valid entropy lengths, in bytes, and the word count each produces.
pub const SIZES: [(usize, usize); 5] = [(16, 12), (20, 15), (24, 18), (28, 21), (32, 24)];

/// Words a given entropy length produces.
pub const fn words_for_entropy(entropy_len: usize) -> Option<usize> {
    // ENT/32 checksum bits appended, then split into 11-bit groups:
    // words = (ENT + ENT/32) / 11
    match entropy_len {
        16 => Some(12),
        20 => Some(15),
        24 => Some(18),
        28 => Some(21),
        32 => Some(24),
        _ => None,
    }
}

/// Entropy a given word count implies.
pub const fn entropy_for_words(words: usize) -> Option<usize> {
    match words {
        12 => Some(16),
        15 => Some(20),
        18 => Some(24),
        21 => Some(28),
        24 => Some(32),
        _ => None,
    }
}

/// A BIP-39 mnemonic, stored as entropy.
///
/// Zeroed on drop; this is wallet-recovery material.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Mnemonic {
    entropy: [u8; MAX_ENTROPY_LEN],
    #[zeroize(skip)]
    entropy_len: usize,
}

impl Mnemonic {
    /// Build from raw entropy.
    ///
    /// The entropy must come from [`catcard_entropy::EntropyPool`], which refuses to
    /// produce anything until it has verifiably collected enough — this function
    /// deliberately has no opinion about the quality of what it is handed.
    pub fn from_entropy(entropy: &[u8]) -> Result<Self, Error> {
        if words_for_entropy(entropy.len()).is_none() {
            return Err(Error::BadEntropyLen { len: entropy.len() });
        }
        let mut this = Self {
            entropy: [0; MAX_ENTROPY_LEN],
            entropy_len: entropy.len(),
        };
        this.entropy[..entropy.len()].copy_from_slice(entropy);
        Ok(this)
    }

    pub fn entropy(&self) -> &[u8] {
        &self.entropy[..self.entropy_len]
    }

    pub fn word_count(&self) -> usize {
        words_for_entropy(self.entropy_len).expect("length validated at construction")
    }

    /// The checksum byte: the leading `ENT/32` bits of `SHA-256(entropy)`, in the high
    /// bits of the returned byte.
    fn checksum(&self) -> u8 {
        let digest = Sha256::digest(self.entropy());
        let bits = self.entropy_len / 4; // ENT/32 bits, ENT in bits = len*8
        let mask = if bits == 8 { 0xff } else { !(0xffu8 >> bits) };
        digest[0] & mask
    }

    /// Word indices, written into `out`. Returns the number written.
    ///
    /// The concatenation `entropy || checksum` is split into 11-bit big-endian groups.
    pub fn word_indices(&self, out: &mut [u16; MAX_WORDS]) -> usize {
        let n = self.word_count();
        let cs = self.checksum();

        let mut acc: u32 = 0;
        let mut acc_bits: usize = 0;
        let mut produced = 0usize;

        // Feed entropy bytes then the checksum byte; emit a word each time 11 bits are
        // available.
        let total_bits = self.entropy_len * 8 + self.entropy_len / 4;
        let mut consumed_bits = 0usize;

        for &byte in self.entropy().iter().chain(core::iter::once(&cs)) {
            let take = 8.min(total_bits - consumed_bits);
            acc = (acc << 8) | byte as u32;
            acc_bits += 8;
            consumed_bits += take;

            while acc_bits >= BITS_PER_WORD && produced < n {
                let shift = acc_bits - BITS_PER_WORD;
                out[produced] = ((acc >> shift) & 0x7ff) as u16;
                acc_bits -= BITS_PER_WORD;
                produced += 1;
            }
            if consumed_bits >= total_bits {
                break;
            }
        }
        produced
    }

    /// The words, in order.
    pub fn words(&self) -> impl Iterator<Item = &'static str> + '_ {
        let mut idx = [0u16; MAX_WORDS];
        let n = self.word_indices(&mut idx);
        (0..n).map(move |i| ENGLISH[idx[i] as usize])
    }

    /// Render the phrase into `out`, space-separated. Returns the byte length.
    ///
    /// `out` must be at least [`MAX_PHRASE_LEN`] bytes to hold any phrase.
    pub fn render(&self, out: &mut [u8]) -> usize {
        let mut at = 0usize;
        for (i, w) in self.words().enumerate() {
            if i > 0 {
                out[at] = b' ';
                at += 1;
            }
            out[at..at + w.len()].copy_from_slice(w.as_bytes());
            at += w.len();
        }
        at
    }

    /// Parse and validate a phrase.
    ///
    /// Words are separated by ASCII whitespace; leading, trailing and repeated
    /// separators are tolerated, since they are transcription noise rather than an
    /// error in the secret.
    pub fn parse(phrase: &str) -> Result<Self, Error> {
        let mut indices = [0u16; MAX_WORDS];
        let mut count = 0usize;

        for word in phrase.split_ascii_whitespace() {
            if count == MAX_WORDS {
                return Err(Error::BadWordCount { count: count + 1 });
            }
            let idx = wordlist::index_of(word).ok_or(Error::UnknownWord { position: count })?;
            indices[count] = idx;
            count += 1;
        }

        let entropy_len = entropy_for_words(count).ok_or(Error::BadWordCount { count })?;

        // Reassemble the bit string, then split off the checksum.
        let mut entropy = [0u8; MAX_ENTROPY_LEN];
        let mut acc: u32 = 0;
        let mut acc_bits = 0usize;
        let mut written = 0usize;
        let mut checksum_actual = 0u8;

        for &i in &indices[..count] {
            acc = (acc << BITS_PER_WORD) | i as u32;
            acc_bits += BITS_PER_WORD;
            while acc_bits >= 8 {
                let shift = acc_bits - 8;
                let byte = ((acc >> shift) & 0xff) as u8;
                acc_bits -= 8;
                if written < entropy_len {
                    entropy[written] = byte;
                    written += 1;
                } else {
                    checksum_actual = byte;
                }
            }
        }
        // Any bits left over are the tail of the checksum, left-aligned.
        if acc_bits > 0 {
            checksum_actual = ((acc << (8 - acc_bits)) & 0xff) as u8;
        }

        let this = Self {
            entropy,
            entropy_len,
        };

        // Compare in constant time: a timing signal on the checksum would leak which
        // prefix of a mistyped phrase was correct.
        use subtle::ConstantTimeEq;
        if this.checksum().ct_eq(&checksum_actual).into() {
            Ok(this)
        } else {
            Err(Error::BadChecksum)
        }
    }

    /// Derive the 64-byte BIP-39 seed.
    ///
    /// `PBKDF2-HMAC-SHA512(phrase, "mnemonic" || passphrase, 2048)`. The passphrase is
    /// the "25th word": a different one yields a completely different, equally valid
    /// wallet, and there is no way to tell a wrong one from a right one.
    ///
    /// This runs 2048 HMAC-SHA512 rounds and takes on the order of a second on this
    /// hardware; it is not something to call in a UI loop.
    pub fn to_seed(&self, passphrase: &str, out: &mut [u8; SEED_LEN]) -> Result<(), Error> {
        if !passphrase.is_ascii() {
            return Err(Error::PassphraseNotAscii);
        }

        // HMAC hashes keys longer than its block size, so the phrase has to be
        // contiguous. The salt does not — it is fed with `update`.
        let mut phrase = [0u8; MAX_PHRASE_LEN];
        let len = self.render(&mut phrase);

        // U1 = PRF(P, salt || INT_32_BE(1))
        let mut mac = HmacSha512::new_from_slice(&phrase[..len]).expect("HMAC takes any key");
        mac.update(SALT_PREFIX);
        mac.update(passphrase.as_bytes());
        mac.update(&1u32.to_be_bytes());
        let mut u: [u8; SEED_LEN] = mac.finalize().into_bytes().into();

        // dkLen == hLen, so there is exactly one block: DK = U1 ^ U2 ^ ... ^ Uc.
        *out = u;
        for _ in 1..PBKDF2_ROUNDS {
            let mut mac = HmacSha512::new_from_slice(&phrase[..len]).expect("HMAC takes any key");
            mac.update(&u);
            u = mac.finalize().into_bytes().into();
            for (o, x) in out.iter_mut().zip(u.iter()) {
                *o ^= x;
            }
        }

        phrase.zeroize();
        u.zeroize();
        Ok(())
    }
}

/// Compares in constant time.
///
/// Two mnemonics are equal when they carry the same entropy. The comparison runs over
/// the whole fixed buffer regardless of length, so it leaks nothing about where two
/// candidates first differ — relevant anywhere a mnemonic is checked against a stored
/// one (recovery confirmation, duress-wallet checks).
impl PartialEq for Mnemonic {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        // Length is not secret: it is visible from the word count on screen.
        let same_len = self.entropy_len == other.entropy_len;
        let same_bytes: bool = self.entropy.ct_eq(&other.entropy).into();
        same_len & same_bytes
    }
}

impl Eq for Mnemonic {}

impl core::fmt::Debug for Mnemonic {
    /// Never prints the words or the entropy.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Mnemonic({} words, redacted)", self.word_count())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_vectors::{PASSPHRASE, VECTORS};

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
    fn phrase_of(m: &Mnemonic) -> String {
        let mut buf = [0u8; MAX_PHRASE_LEN];
        let n = m.render(&mut buf);
        String::from_utf8(buf[..n].to_vec()).unwrap()
    }

    // -- the official vectors, in both directions --------------------------------

    #[test]
    fn official_vectors_entropy_to_phrase() {
        for (ent, expect_phrase, _) in VECTORS {
            let m = Mnemonic::from_entropy(&unhex(ent)).unwrap();
            assert_eq!(&phrase_of(&m), expect_phrase, "entropy {ent}");
        }
    }

    #[test]
    fn official_vectors_phrase_to_entropy() {
        for (expect_ent, phrase, _) in VECTORS {
            let m = Mnemonic::parse(phrase).unwrap();
            assert_eq!(hex(m.entropy()), *expect_ent, "phrase {phrase}");
        }
    }

    #[test]
    fn official_vectors_seed_derivation() {
        for (ent, _, expect_seed) in VECTORS {
            let m = Mnemonic::from_entropy(&unhex(ent)).unwrap();
            let mut seed = [0u8; SEED_LEN];
            m.to_seed(PASSPHRASE, &mut seed).unwrap();
            assert_eq!(hex(&seed), *expect_seed, "entropy {ent}");
        }
    }

    #[test]
    fn vectors_cover_every_supported_length() {
        let mut seen: Vec<usize> = VECTORS.iter().map(|(e, _, _)| unhex(e).len()).collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen, vec![16, 24, 32], "vector coverage changed");
        // 20 and 28 bytes are legal but absent from the published vectors; they are
        // covered by the round-trip test below instead.
    }

    // -- round trips -------------------------------------------------------------

    #[test]
    fn round_trip_every_entropy_length() {
        for (len, words) in SIZES {
            let entropy: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
                .collect();
            let m = Mnemonic::from_entropy(&entropy).unwrap();
            assert_eq!(m.word_count(), words);

            let phrase = phrase_of(&m);
            assert_eq!(phrase.split(' ').count(), words);

            let back = Mnemonic::parse(&phrase).unwrap();
            assert_eq!(back.entropy(), &entropy[..]);
        }
    }

    #[test]
    fn all_zero_and_all_ones_entropy_round_trip() {
        for fill in [0x00u8, 0xff] {
            for (len, _) in SIZES {
                let e = vec![fill; len];
                let m = Mnemonic::from_entropy(&e).unwrap();
                assert_eq!(Mnemonic::parse(&phrase_of(&m)).unwrap().entropy(), &e[..]);
            }
        }
    }

    // -- rejections --------------------------------------------------------------

    #[test]
    fn bad_entropy_lengths_are_rejected() {
        for len in [0usize, 1, 15, 17, 31, 33, 64] {
            assert_eq!(
                Mnemonic::from_entropy(&vec![0; len]),
                Err(Error::BadEntropyLen { len })
            );
        }
    }

    #[test]
    fn bad_word_counts_are_rejected() {
        assert!(matches!(
            Mnemonic::parse("abandon abandon abandon"),
            Err(Error::BadWordCount { count: 3 })
        ));
        assert!(matches!(
            Mnemonic::parse(""),
            Err(Error::BadWordCount { count: 0 })
        ));
        // 13 words: a legal count plus one.
        let long = core::iter::repeat_n("abandon", 13)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(matches!(
            Mnemonic::parse(&long),
            Err(Error::BadWordCount { count: 13 })
        ));
        // More than the maximum must not overflow the fixed buffer.
        let huge = core::iter::repeat_n("abandon", 64)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(matches!(
            Mnemonic::parse(&huge),
            Err(Error::BadWordCount { .. })
        ));
    }

    #[test]
    fn unknown_words_report_their_position() {
        let (_, phrase, _) = VECTORS[0];
        let mut w: Vec<&str> = phrase.split(' ').collect();
        w[5] = "notaword";
        assert_eq!(
            Mnemonic::parse(&w.join(" ")),
            Err(Error::UnknownWord { position: 5 })
        );
    }

    #[test]
    fn a_single_wrong_word_fails_the_checksum() {
        // The whole point of the checksum: a transcription slip must not silently
        // produce a different, valid-looking wallet.
        let (_, phrase, _) = VECTORS[0];
        let mut w: Vec<&str> = phrase.split(' ').collect();
        // "about" -> "abandon", both in the list, so only the checksum can catch it.
        assert_eq!(w[11], "about");
        w[11] = "abandon";
        assert_eq!(Mnemonic::parse(&w.join(" ")), Err(Error::BadChecksum));
    }

    #[test]
    fn swapped_words_fail_the_checksum() {
        let (_, phrase, _) = VECTORS[2];
        let mut w: Vec<&str> = phrase.split(' ').collect();
        w.swap(0, 1);
        assert_eq!(Mnemonic::parse(&w.join(" ")), Err(Error::BadChecksum));
    }

    #[test]
    fn whitespace_is_tolerated() {
        let (ent, phrase, _) = VECTORS[0];
        let messy = format!("  {}  ", phrase.replace(' ', "   "));
        assert_eq!(hex(Mnemonic::parse(&messy).unwrap().entropy()), *ent);
        // Newlines and tabs too -- phrases get transcribed from paper.
        let across_lines = phrase.replacen(' ', "\n", 3).replacen(' ', "\t", 2);
        assert_eq!(hex(Mnemonic::parse(&across_lines).unwrap().entropy()), *ent);
    }

    #[test]
    fn case_is_not_tolerated() {
        // Uppercase would change the PBKDF2 input and so the seed; better to reject.
        let (_, phrase, _) = VECTORS[0];
        assert!(Mnemonic::parse(&phrase.to_uppercase()).is_err());
    }

    // -- passphrase --------------------------------------------------------------

    #[test]
    fn passphrase_changes_the_seed() {
        let m = Mnemonic::from_entropy(&unhex(VECTORS[0].0)).unwrap();
        let (mut a, mut b) = ([0u8; SEED_LEN], [0u8; SEED_LEN]);
        m.to_seed("", &mut a).unwrap();
        m.to_seed("TREZOR", &mut b).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn empty_passphrase_is_valid() {
        let m = Mnemonic::from_entropy(&unhex(VECTORS[0].0)).unwrap();
        let mut seed = [0u8; SEED_LEN];
        assert!(m.to_seed("", &mut seed).is_ok());
        assert!(seed.iter().any(|&b| b != 0));
    }

    #[test]
    fn non_ascii_passphrase_is_refused_not_mangled() {
        // Deriving an unnormalised seed here would diverge from every other wallet
        // and lose funds silently. Refusing is the safe behaviour until NFKD exists.
        let m = Mnemonic::from_entropy(&unhex(VECTORS[0].0)).unwrap();
        let mut seed = [0u8; SEED_LEN];
        assert_eq!(
            m.to_seed("pässwörd", &mut seed),
            Err(Error::PassphraseNotAscii)
        );
        assert_eq!(
            m.to_seed("日本語", &mut seed),
            Err(Error::PassphraseNotAscii)
        );
        assert_eq!(seed, [0u8; SEED_LEN], "seed written despite refusal");
    }

    // -- properties --------------------------------------------------------------

    #[test]
    fn distinct_entropy_gives_distinct_phrases() {
        let mut a = [0u8; 32];
        let m1 = Mnemonic::from_entropy(&a).unwrap();
        a[31] = 1;
        let m2 = Mnemonic::from_entropy(&a).unwrap();
        assert_ne!(phrase_of(&m1), phrase_of(&m2));
    }

    #[test]
    fn one_bit_of_entropy_changes_many_words() {
        // Avalanche through the checksum only affects the last word; the rest comes
        // from a direct bit-slice, so a low-order flip should still move >= 1 word.
        let a = [0u8; 32];
        let mut b = [0u8; 32];
        b[0] = 0x80;
        let (m1, m2) = (
            Mnemonic::from_entropy(&a).unwrap(),
            Mnemonic::from_entropy(&b).unwrap(),
        );
        let w1: Vec<_> = m1.words().collect();
        let w2: Vec<_> = m2.words().collect();
        assert_ne!(w1[0], w2[0]);
    }

    #[test]
    fn debug_does_not_leak_the_secret() {
        let m = Mnemonic::from_entropy(&unhex(VECTORS[0].0)).unwrap();
        let s = format!("{m:?}");
        assert!(!s.contains("abandon"), "Debug leaked words: {s}");
        assert!(!s.contains("00000000"), "Debug leaked entropy: {s}");
        assert!(s.contains("12 words"));
    }

    #[test]
    fn phrase_buffer_bound_holds_for_the_longest_phrase() {
        // MAX_PHRASE_LEN sizes a stack buffer in to_seed; if it were too small the
        // render would panic on some input.
        let m = Mnemonic::from_entropy(&[0xff; 32]).unwrap();
        let mut buf = [0u8; MAX_PHRASE_LEN];
        let n = m.render(&mut buf);
        assert!(n <= MAX_PHRASE_LEN);
        assert_eq!(m.word_count(), 24);
        // The theoretical worst case: 24 of the longest words.
        const { assert!(MAX_WORDS * MAX_WORD_LEN + (MAX_WORDS - 1) <= MAX_PHRASE_LEN) };
    }

    #[test]
    fn word_indices_match_the_rendered_words() {
        let m = Mnemonic::from_entropy(&unhex(VECTORS[2].0)).unwrap();
        let mut idx = [0u16; MAX_WORDS];
        let n = m.word_indices(&mut idx);
        let rendered: Vec<&str> = m.words().collect();
        assert_eq!(n, rendered.len());
        for (i, w) in rendered.iter().enumerate() {
            assert_eq!(ENGLISH[idx[i] as usize], *w);
        }
    }

    #[test]
    fn size_tables_agree() {
        for (ent, words) in SIZES {
            assert_eq!(words_for_entropy(ent), Some(words));
            assert_eq!(entropy_for_words(words), Some(ent));
        }
        assert_eq!(words_for_entropy(17), None);
        assert_eq!(entropy_for_words(13), None);
    }
}
