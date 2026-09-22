//! SeedQR: a BIP-39 phrase written as a QR code.
//!
//! A seed backup that a camera can read and a person can transcribe by hand onto a grid.
//! The convention is SeedSigner's, and it is a *public format* rather than anyone's
//! implementation: two shapes, both of which this reads and writes.
//!
//! - **Standard.** Each word's index in the BIP-39 English wordlist, **counted from
//!   zero**, written as four zero-padded decimal digits and concatenated with nothing
//!   between them. Twelve words are 48 digits, twenty-four are 96. Every character is a
//!   digit, so the symbol goes in QR's numeric mode -- ten bits per three digits -- and
//!   any phone's QR reader shows the digits back as text.
//! - **Compact.** The mnemonic's raw entropy, 16 to 32 bytes, in a byte-mode symbol. The
//!   checksum is not carried: it is `ENT/32` bits of `SHA-256(entropy)` and is recomputed
//!   when the code is read, which is what makes the symbol one version smaller.
//!
//! Source: SeedSigner's published SeedQR description, <https://github.com/SeedSigner/seedsigner>
//! `docs/seed_qr/README.md` -- "code always starts counting list items from zero", four
//! digits a word, numeric mode for Standard and raw entropy in byte mode for Compact. [C]
//! Its two worked vectors are the first two tests below.
//!
//! # What is *not* in a SeedQR
//!
//! A passphrase. Neither shape carries one, so a SeedQR of a passphrase wallet restores
//! the words and lands in a different wallet -- the same gap Seed XOR has, and worth
//! saying on the screen that shows one.
//!
//! # Lengths
//!
//! SeedSigner's own tool writes 12 and 24 words. Nothing in either shape depends on the
//! count, so 15, 18 and 21 are read and written here too: the digits are four per word
//! whatever the count, and the entropy lengths BIP-39 defines are all whole bytes. A
//! reader that only knows the two will refuse the others, which is its business and not
//! a reason to refuse them here.
//!
//! # Telling the two apart
//!
//! By length, and the two sets do not overlap by accident -- 48, 60, 72, 84 and 96 digit
//! characters against 16, 20, 24, 28 and 32 entropy bytes. [`kind_of`] is the strict
//! sniff for a caller holding bytes that might be anything: it requires every character
//! of a Standard payload to be an ASCII digit, so ordinary text of the same length is not
//! claimed as a seed. [`parse`] is for a caller that has already decided the payload is
//! meant to be one, and reports *why* it is not.

use zeroize::Zeroizing;

use crate::bip39::{
    self, MAX_ENTROPY_LEN, MAX_PHRASE_LEN, MAX_WORDS, Mnemonic, entropy_for_words, wordlist,
    words_for_entropy,
};

/// Decimal digits a word takes. Four holds 2047, the largest index there is.
pub const DIGITS_PER_WORD: usize = 4;

/// Digits in the longest Standard payload: 24 words.
pub const MAX_DIGITS: usize = MAX_WORDS * DIGITS_PER_WORD;

/// Which of the two shapes a payload is.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Kind {
    /// Four zero-padded digits per word, in numeric mode.
    Standard,
    /// The raw entropy, in byte mode.
    Compact,
}

impl Kind {
    /// What to call it on a screen.
    pub fn name(self) -> &'static str {
        match self {
            Kind::Standard => "Standard",
            Kind::Compact => "Compact",
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Not a length either shape has: 48/60/72/84/96 digits, or 16/20/24/28/32 bytes.
    BadLength { len: usize },
    /// A Standard payload with something in it that is not an ASCII digit. Carries the
    /// position, so a screen can point at it; deliberately not the character.
    NotDigits { position: usize },
    /// A four-digit group of 2048 or more. There is no such word.
    NoSuchWord { position: usize },
    /// The payload decodes, and the phrase it decodes to is not a valid one -- a wrong
    /// checksum, above all, which is what a mistranscribed digit looks like.
    Phrase(bip39::Error),
}

impl From<bip39::Error> for Error {
    fn from(e: bip39::Error) -> Self {
        Error::Phrase(e)
    }
}

#[cfg(feature = "std")]
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::BadLength { len } => write!(f, "{len} is not a SeedQR length"),
            Error::NotDigits { position } => {
                write!(f, "character {position} is not a digit")
            }
            Error::NoSuchWord { position } => {
                write!(f, "word {} has no index in the wordlist", position + 1)
            }
            Error::Phrase(e) => write!(f, "{e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Digits a Standard payload of `words` words has, or `None` for a count BIP-39 has no
/// phrase of.
pub const fn digits_for_words(words: usize) -> Option<usize> {
    match entropy_for_words(words) {
        Some(_) => Some(words * DIGITS_PER_WORD),
        None => None,
    }
}

/// What `payload` claims to be, if it claims to be either.
///
/// Strict on purpose. It is what a scanner's sniff should ask, where the alternative
/// reading of the same bytes is "some text" or "some file": a Standard payload has to be
/// all ASCII digits at one of five lengths, and a Compact one has to be one of five byte
/// counts. It says nothing about whether the phrase inside checks out -- that costs a
/// SHA-256 and needs a [`KeyWork`](crate::KeyWork), and it is [`parse`]'s answer.
///
/// The digit lengths and the entropy lengths are disjoint, so nothing is ever both.
pub fn kind_of(payload: &[u8]) -> Option<Kind> {
    if is_digit_length(payload.len()) && payload.iter().all(u8::is_ascii_digit) {
        return Some(Kind::Standard);
    }
    if words_for_entropy(payload.len()).is_some() {
        return Some(Kind::Compact);
    }
    None
}

/// Whether `len` is a Standard payload's length.
fn is_digit_length(len: usize) -> bool {
    len.is_multiple_of(DIGITS_PER_WORD) && entropy_for_words(len / DIGITS_PER_WORD).is_some()
}

/// Write the wallet as Standard SeedQR digits. Returns how many were written.
///
/// Four per word, zero-padded, nothing between them.
pub fn digits(m: &Mnemonic, out: &mut [u8; MAX_DIGITS], _kw: &crate::KeyWork) -> usize {
    let mut idx = [0u16; MAX_WORDS];
    let n = m.word_indices(&mut idx);
    for (w, &i) in idx[..n].iter().enumerate() {
        let at = w * DIGITS_PER_WORD;
        // Four digits, most significant first. The index is under 2048 because it came
        // out of an 11-bit group, so the thousands digit is 0 or 1 and never overflows.
        out[at] = b'0' + (i / 1000) as u8;
        out[at + 1] = b'0' + (i / 100 % 10) as u8;
        out[at + 2] = b'0' + (i / 10 % 10) as u8;
        out[at + 3] = b'0' + (i % 10) as u8;
    }
    n * DIGITS_PER_WORD
}

/// The Compact SeedQR payload: the entropy itself, 16 to 32 bytes.
///
/// A borrow rather than a copy -- there is nothing to compute, and a second copy of the
/// seed is a second thing to wipe. The caller shows these bytes in a byte-mode symbol.
pub fn compact<'a>(m: &'a Mnemonic, _kw: &crate::KeyWork) -> &'a [u8] {
    m.entropy()
}

/// Read either shape, deciding by length.
///
/// For a caller that has already decided these bytes are meant to be a SeedQR -- the
/// scanner, after [`kind_of`] said so -- and wants to know why if they are not. The digit
/// lengths are checked first; they cannot collide with the entropy lengths.
pub fn parse(payload: &[u8], kw: &crate::KeyWork) -> Result<Mnemonic, Error> {
    if is_digit_length(payload.len()) {
        return from_digits(payload, kw);
    }
    if words_for_entropy(payload.len()).is_some() {
        return from_compact(payload, kw);
    }
    Err(Error::BadLength { len: payload.len() })
}

/// Read a Standard payload: four digits a word, and the checksum has to come out.
///
/// The digits are turned back into words and the phrase is parsed, rather than the bits
/// being reassembled here. That is not indirection for its own sake: [`Mnemonic::parse`]
/// is what checks the checksum, in constant time, and a second path to the same answer is
/// a second path that can disagree with it.
///
/// **A wrong checksum is the expected failure.** These digits were transcribed by hand
/// off a metal plate, and a single wrong digit gives a different, perfectly valid word --
/// so the checksum is the only thing between a typo and a wallet nobody can find again.
pub fn from_digits(payload: &[u8], kw: &crate::KeyWork) -> Result<Mnemonic, Error> {
    if !is_digit_length(payload.len()) {
        return Err(Error::BadLength { len: payload.len() });
    }
    if let Some(position) = payload.iter().position(|b| !b.is_ascii_digit()) {
        return Err(Error::NotDigits { position });
    }

    // The phrase is the secret from here down, so it is built in a buffer that is wiped
    // when this returns -- by whichever path, including the error ones.
    let mut phrase = Zeroizing::new([0u8; MAX_PHRASE_LEN]);
    let mut at = 0usize;
    for (position, group) in payload.as_chunks::<DIGITS_PER_WORD>().0.iter().enumerate() {
        let index = group
            .iter()
            .fold(0usize, |acc, &b| acc * 10 + (b - b'0') as usize);
        let word = wordlist::ENGLISH
            .get(index)
            .ok_or(Error::NoSuchWord { position })?;
        if at > 0 {
            phrase[at] = b' ';
            at += 1;
        }
        phrase[at..at + word.len()].copy_from_slice(word.as_bytes());
        at += word.len();
    }

    // Every byte written came from the wordlist or is a space, so this is ASCII.
    let text = core::str::from_utf8(&phrase[..at]).map_err(|_| Error::BadLength { len: at })?;
    Ok(Mnemonic::parse(text, kw)?)
}

/// Read a Compact payload: the entropy, with the checksum computed fresh.
///
/// There is nothing to verify. Any 16, 20, 24, 28 or 32 bytes are a valid seed, and the
/// checksum is a function of them -- which is the whole reason the shape can leave it
/// out, and also why a Compact code cannot tell you that it was misread. A Standard one
/// can; that is the trade the two shapes make.
pub fn from_compact(payload: &[u8], kw: &crate::KeyWork) -> Result<Mnemonic, Error> {
    if words_for_entropy(payload.len()).is_none() {
        return Err(Error::BadLength { len: payload.len() });
    }
    debug_assert!(payload.len() <= MAX_ENTROPY_LEN);
    Ok(Mnemonic::from_entropy(payload, kw)?)
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

    fn of(phrase: &str) -> Mnemonic {
        Mnemonic::parse(phrase, &kw()).expect("vector parses")
    }

    fn words_of(m: &Mnemonic) -> String {
        m.words().collect::<Vec<_>>().join(" ")
    }

    fn digits_of(m: &Mnemonic) -> String {
        let mut out = [0u8; MAX_DIGITS];
        let n = digits(m, &mut out, &kw());
        String::from_utf8(out[..n].to_vec()).unwrap()
    }

    /// SeedSigner's own worked example, both directions. This is the whole definition of
    /// the format as far as every other wallet is concerned: four digits a word, indices
    /// counted from **zero** -- one-based indices would give a digit string that differs
    /// in every group, and a seed nobody else could read.
    ///
    /// Source: seedsigner `docs/seed_qr/README.md`, the "vacuum bridge" example. [C]
    #[test]
    fn the_published_standard_example() {
        const PHRASE: &str =
            "vacuum bridge buddy supreme exclude milk consider tail expand wasp pattern nuclear";
        const DIGITS: &str = "192402220235174306311124037817700641198012901210";

        assert_eq!(digits_of(&of(PHRASE)), DIGITS);
        assert_eq!(
            words_of(&from_digits(DIGITS.as_bytes(), &kw()).unwrap()),
            PHRASE
        );
    }

    /// The format's other published vector, which gives the Compact bytestream as well
    /// as the digits -- so it pins both shapes of the same seed against the same words.
    ///
    /// Source: seedsigner `docs/seed_qr/README.md`, test vector 4. [C]
    #[test]
    fn the_published_compact_example() {
        const PHRASE: &str =
            "forum undo fragile fade shy sign arrest garment culture tube off merit";
        const DIGITS: &str = "073318950739065415961602009907670428187212261116";
        const ENTROPY: [u8; 16] = [
            0x5b, 0xbd, 0x9d, 0x71, 0xa8, 0xec, 0x79, 0x90, 0x83, 0x1a, 0xff, 0x35, 0x9d, 0x42,
            0x65, 0x45,
        ];

        let m = of(PHRASE);
        assert_eq!(digits_of(&m), DIGITS);
        assert_eq!(compact(&m, &kw()), &ENTROPY);
        assert_eq!(words_of(&from_compact(&ENTROPY, &kw()).unwrap()), PHRASE);
    }

    /// Zero padding is not decoration: an index under 1000 written as three digits would
    /// shift every group after it, and the phrase would still be 12 words of real words.
    #[test]
    fn low_indices_keep_their_leading_zeros() {
        // `abandon` is index 0 and `art` is 1601; the entropy is all zeros.
        let m = of(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        );
        let d = digits_of(&m);
        assert_eq!(d.len(), 48);
        assert!(d.starts_with("000000000000"), "{d}");
        assert_eq!(&d[44..], "0003"); // `about`
    }

    /// Every length BIP-39 defines, not just the two SeedSigner's tool writes.
    #[test]
    fn every_word_count_round_trips_as_digits() {
        for (bytes, words) in bip39::SIZES {
            // Distinct, non-degenerate entropy per length.
            let entropy: Vec<u8> = (0..bytes)
                .map(|i| (i as u8).wrapping_mul(37) ^ 0x5a)
                .collect();
            let m = Mnemonic::from_entropy(&entropy, &kw()).unwrap();
            assert_eq!(m.word_count(), words);

            let d = digits_of(&m);
            assert_eq!(d.len(), digits_for_words(words).unwrap());
            let back = from_digits(d.as_bytes(), &kw()).unwrap();
            assert_eq!(back.entropy(), &entropy[..]);
            assert_eq!(words_of(&back), words_of(&m));
        }
    }

    /// And the same for the Compact shape, which is the entropy unchanged.
    #[test]
    fn every_word_count_round_trips_as_compact() {
        for (bytes, words) in bip39::SIZES {
            let entropy: Vec<u8> = (0..bytes)
                .map(|i| (i as u8).wrapping_mul(11) ^ 0xa5)
                .collect();
            let m = Mnemonic::from_entropy(&entropy, &kw()).unwrap();
            let payload = compact(&m, &kw()).to_vec();
            assert_eq!(payload, entropy);

            let back = from_compact(&payload, &kw()).unwrap();
            assert_eq!(back.entropy(), &entropy[..]);
            assert_eq!(back.word_count(), words);
        }
    }

    /// A digit string one group short is not a shorter seed. 44 digits is 11 words, which
    /// BIP-39 has no phrase of, and reading it as one would invent a twelfth word.
    #[test]
    fn a_length_between_the_word_counts_is_refused() {
        let d = "1924022202351743063111240378177006411980129012".as_bytes(); // 46
        assert_eq!(parse(d, &kw()), Err(Error::BadLength { len: 46 }));

        let short = "192402220235174306311124037817700641198012901".as_bytes(); // 45
        assert_eq!(parse(short, &kw()), Err(Error::BadLength { len: 45 }));

        // 44 digits is a whole number of groups, and still not a word count.
        let eleven = "19240222023517430631112403781770064119801290".as_bytes();
        assert_eq!(
            from_digits(eleven, &kw()),
            Err(Error::BadLength { len: 44 })
        );
    }

    /// A payload of the right length with something in it that is not a digit. This is
    /// what a text QR of 48 characters looks like from here, and taking the low four bits
    /// of a letter would turn it into a wallet.
    #[test]
    fn a_non_digit_in_a_standard_payload_is_refused() {
        let mut d = *b"192402220235174306311124037817700641198012901210";
        d[17] = b'x';
        assert_eq!(
            from_digits(&d, &kw()),
            Err(Error::NotDigits { position: 17 })
        );
        // And the strict sniff does not claim it at all.
        assert_eq!(kind_of(&d), None);
    }

    /// `2048` is four digits and is not a word: the list ends at 2047.
    #[test]
    fn an_index_past_the_end_of_the_wordlist_is_refused() {
        let mut d = *b"192402220235174306311124037817700641198012901210";
        d[8..12].copy_from_slice(b"2048");
        assert_eq!(
            from_digits(&d, &kw()),
            Err(Error::NoSuchWord { position: 2 })
        );
        d[8..12].copy_from_slice(b"9999");
        assert_eq!(
            from_digits(&d, &kw()),
            Err(Error::NoSuchWord { position: 2 })
        );
    }

    /// One digit wrong gives twelve real words that are not a seed. Refusing that is the
    /// only thing standing between a mistranscribed backup and an empty wallet: the
    /// device cannot know what was meant, only that this is not it.
    #[test]
    fn digits_whose_words_do_not_checksum_are_refused() {
        // The published example with its last group moved to another real word.
        let mut d = *b"192402220235174306311124037817700641198012901210";
        assert!(from_digits(&d, &kw()).is_ok());
        d[44..].copy_from_slice(b"1211");
        assert_eq!(
            from_digits(&d, &kw()),
            Err(Error::Phrase(bip39::Error::BadChecksum))
        );
    }

    /// Compact has no checksum to fail, so the only thing to refuse is a length that is
    /// not an entropy size -- and every one of those must be refused, because there is
    /// nothing else that can tell a truncated payload from a whole one.
    #[test]
    fn a_compact_payload_of_the_wrong_length_is_refused() {
        for len in [0usize, 1, 15, 17, 18, 21, 31, 33, 64] {
            let payload = vec![0x11u8; len];
            assert_eq!(
                from_compact(&payload, &kw()),
                Err(Error::BadLength { len }),
                "{len} bytes"
            );
            assert_eq!(kind_of(&payload), None, "{len} bytes");
        }
    }

    /// The sniff, which is what a scanner asks of bytes that could be anything.
    #[test]
    fn the_sniff_claims_only_what_it_should() {
        let compact_16 = [0x5bu8; 16];
        assert_eq!(kind_of(&compact_16), Some(Kind::Compact));
        assert_eq!(
            kind_of(b"192402220235174306311124037817700641198012901210"),
            Some(Kind::Standard)
        );
        // Ordinary text, of a length neither shape has.
        assert_eq!(kind_of(b"bitcoin"), None);
        assert_eq!(kind_of(b""), None);
        // An address is 42 characters and not digits: not a seed.
        assert_eq!(kind_of(b"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"), None);
    }

    /// Twenty-four digit characters are a *Compact* payload, not a short Standard one:
    /// 24 is an entropy length and is not a digit length. Getting the priority wrong
    /// would read six words' worth of digits as a 18-word seed made of their ASCII.
    #[test]
    fn a_twenty_four_character_digit_string_is_compact() {
        let payload = b"192402220235174306311124";
        assert_eq!(kind_of(payload), Some(Kind::Compact));
        let m = parse(payload, &kw()).unwrap();
        assert_eq!(m.word_count(), 18);
        assert_eq!(m.entropy(), payload);
    }

    /// Nothing is left of the phrase in the buffer that built it. The check is indirect
    /// -- the buffer is gone by the time the test could look -- so this asserts the shape
    /// that makes it true: the decoder hands back a `Mnemonic`, which owns entropy and
    /// zeroizes on drop, and never a borrowed phrase.
    #[test]
    fn the_decoder_hands_back_only_entropy() {
        let m = from_digits(b"192402220235174306311124037817700641198012901210", &kw()).unwrap();
        assert_eq!(m.entropy().len(), 16);
        drop(m);
    }
}
