//! Signing a message with an Ethereum key: EIP-191 `personal_sign`, and Tron's TIP-191,
//! which is the same construction under another header.
//!
//! What a site asks for when it says "sign in with your wallet", and what a person is
//! asked for as proof that an address is theirs. The digest is
//!
//! ```text
//! keccak256( 0x19 || "Ethereum Signed Message:\n" || len(message) in decimal || message )
//! ```
//!
//! and the signature is the 65 bytes `r || s || v` with `v` 27 or 28.
//!
//! Source: EIP-191 "Signed Data Standard", version byte `0x45` (`E`) [C]. Public standard.
//!
//! Tron's is the same with `"TRON Signed Message:\n"` for the header ([`TRON_PREFIX`]),
//! and the same 65 bytes for the signature: what TronWeb's `signMessageV2` makes and
//! `verifyMessageV2` checks. Not the older `signMessage`, which signs a fixed "32" and a
//! hash the person never sees.
//!
//! Source: TIP-191 "Signed Data Standard"; TronWeb `hashMessage` documentation [C].
//!
//! # Why it cannot move coins
//!
//! The first byte signed is `0x19`. A transaction is an RLP list (first byte `0xc0` or
//! above) or a type byte below `0x80` followed by one (EIP-2718); neither starts with
//! `0x19`, so no message digest is a transaction's signing hash. That is the whole reason
//! for the prefix, and the reason nothing here signs a bare digest.
//!
//! # What this refuses
//!
//! Only text a screen can show faithfully: printable ASCII in lines. A message with a
//! control character, a byte outside ASCII, a line that begins or ends in a space, or a
//! blank first or last line reads on the device as some other message would, and the
//! owner would be signing something other than what they read. Typed data (EIP-712,
//! version byte `0x01`) is a different construction and is not this.

/// What every message digest begins with: the version-`0x45` EIP-191 header.
/// Source: EIP-191 [C]
pub const PREFIX: &[u8] = b"\x19Ethereum Signed Message:\n";

/// What a Tron message digest begins with.
/// Source: TIP-191; TronWeb `hashMessage` (`"\x19TRON Signed Message:\n"`) [C]
pub const TRON_PREFIX: &[u8] = b"\x19TRON Signed Message:\n";

/// The longer of the two headers, for [`scratch_len`].
const PREFIX_MAX: usize = if PREFIX.len() > TRON_PREFIX.len() {
    PREFIX.len()
} else {
    TRON_PREFIX.len()
};

/// Longest message signed. Enough for a sign-in statement; bounded because the whole of
/// it has to be read on a small screen before it is signed.
pub const MAX_MESSAGE: usize = 960;

/// Most lines a message may have.
pub const MAX_LINES: usize = 24;

/// A signature: `r`, `s`, `v`.
pub const SIG_LEN: usize = 65;

/// Decimal digits [`MAX_MESSAGE`] can take.
const LEN_DIGITS: usize = 3;
const _: () = assert!(MAX_MESSAGE < 1000);

/// Bytes [`digest`] needs to lay a message of `len` bytes out in.
pub const fn scratch_len(len: usize) -> usize {
    PREFIX_MAX + LEN_DIGITS + len
}

/// Why a message cannot be signed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Unshowable {
    /// Nothing in it.
    Empty,
    /// Longer than [`MAX_MESSAGE`].
    TooLong,
    /// More than [`MAX_LINES`] lines.
    TooManyLines,
    /// A byte that is not printable ASCII or a line break.
    NotText,
    /// A line beginning or ending in a space, or a blank first or last line: something a
    /// screen would not show.
    Edge,
}

impl Unshowable {
    /// The same, in the words a screen or a refusal has.
    pub const fn why(self) -> &'static str {
        match self {
            Unshowable::Empty => "nothing to sign in that",
            Unshowable::TooLong => "message too long",
            Unshowable::TooManyLines => "message has too many lines",
            Unshowable::NotText => "plain ASCII text only",
            Unshowable::Edge => "a line starts or ends blank",
        }
    }
}

/// `message` as the text it will be shown as, or why it cannot be shown.
pub fn text(message: &[u8]) -> Result<&str, Unshowable> {
    if message.is_empty() {
        return Err(Unshowable::Empty);
    }
    if message.len() > MAX_MESSAGE {
        return Err(Unshowable::TooLong);
    }
    if !message
        .iter()
        .all(|&b| (0x20..0x7f).contains(&b) || b == b'\n')
    {
        return Err(Unshowable::NotText);
    }
    // All ASCII, so this cannot fail; the error is the nearest true thing if it did.
    let text = core::str::from_utf8(message).map_err(|_| Unshowable::NotText)?;
    let mut lines = 0usize;
    for line in text.split('\n') {
        lines += 1;
        if lines > MAX_LINES {
            return Err(Unshowable::TooManyLines);
        }
        if line.starts_with(' ') || line.ends_with(' ') {
            return Err(Unshowable::Edge);
        }
    }
    if text.starts_with('\n') || text.ends_with('\n') {
        return Err(Unshowable::Edge);
    }
    Ok(text)
}

/// The digest a `personal_sign` signature is made over.
///
/// `scratch` is where the header, the length and the message are laid out to be hashed
/// in one pass: at least [`scratch_len`]`(message.len())` bytes. `None` when it is
/// smaller, or the message is longer than [`MAX_MESSAGE`].
///
/// Any bytes hash; whether they may be *signed* is [`text`]'s to say, and a caller signs
/// only what it has shown.
pub fn digest(message: &[u8], scratch: &mut [u8]) -> Option<[u8; 32]> {
    digest_under(PREFIX, message, scratch)
}

/// [`digest`] under the header `prefix`: [`PREFIX`] or [`TRON_PREFIX`].
pub fn digest_under(prefix: &[u8], message: &[u8], scratch: &mut [u8]) -> Option<[u8; 32]> {
    if message.len() > MAX_MESSAGE {
        return None;
    }
    let mut digits = [0u8; LEN_DIGITS];
    let mut at = LEN_DIGITS;
    let mut n = message.len();
    loop {
        at -= 1;
        digits[at] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    let digits = &digits[at..];
    let total = prefix.len() + digits.len() + message.len();
    let buf = scratch.get_mut(..total)?;
    let (head, rest) = buf.split_at_mut(prefix.len());
    head.copy_from_slice(prefix);
    let (len, body) = rest.split_at_mut(digits.len());
    len.copy_from_slice(digits);
    body.copy_from_slice(message);
    Some(outscript::hash::keccak256_once(buf))
}

/// `r || s || v` for a signature with this recovery id, as
/// [`outscript::crypto::secp256k1`] returns it.
///
/// `None` for a recovery id above 1: `v` is 27 or 28 and says only which of two points
/// `r` is the x coordinate of. The other two ids mean `r` overflowed the group order,
/// which happens about once in 2^128 signatures and has no encoding here.
pub fn signature(r: &[u8; 32], s: &[u8; 32], recid: u8) -> Option<[u8; SIG_LEN]> {
    if recid > 1 {
        return None;
    }
    let mut out = [0u8; SIG_LEN];
    out[..32].copy_from_slice(r);
    out[32..64].copy_from_slice(s);
    out[64] = 27 + recid;
    Some(out)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;

    fn hex(d: &[u8; 32]) -> std::string::String {
        d.iter().map(|b| std::format!("{b:02x}")).collect()
    }

    fn digest_of(m: &[u8]) -> std::string::String {
        let mut scratch = vec![0u8; scratch_len(m.len())];
        hex(&digest(m, &mut scratch).unwrap())
    }

    // The expected values were computed apart from this code, by a Keccak-f[1600] written
    // from FIPS 202 with the legacy 0x01 padding, over the bytes EIP-191 lays out. The
    // first is also the value every Ethereum library documents for `hashMessage("hello
    // world")`.
    #[test]
    fn the_digest_is_eip_191s() {
        assert_eq!(
            digest_of(b"hello world"),
            "d9eba16ed0ecae432b71fe008c98cc872bb4cc214d3220a36f365326cf807d68"
        );
        assert_eq!(
            digest_of(b"Hello World"),
            "a1de988600a42c4b4ab089b619297c17d53cffae5d5120d82d8a92d0bb3b78f2"
        );
    }

    // Computed the same way, under Tron's header.
    #[test]
    fn trons_digest_differs_only_in_the_header() {
        let of = |m: &[u8]| {
            let mut scratch = vec![0u8; scratch_len(m.len())];
            hex(&digest_under(TRON_PREFIX, m, &mut scratch).unwrap())
        };
        assert_eq!(
            of(b"hello world"),
            "cf02daeb2bea196ed5692322a66ed50080ce74ff8cb711199f1b04f3c13bc10d"
        );
        assert_eq!(
            of(b"a\nb"),
            "25c631a24794571e85c37141eb7dfa3ba73701054df38ea256a4f65bbafac1df"
        );
        assert_ne!(of(b"hello world"), digest_of(b"hello world"));
        assert_eq!(TRON_PREFIX[0], 0x19);
    }

    #[test]
    fn the_length_is_decimal_and_counts_line_breaks() {
        // One digit, with a line break inside the three bytes.
        assert_eq!(
            digest_of(b"a\nb"),
            "2501af0621ba54325054a679e48c5b16d507d2b4d4dca5fa49b77c8e25e5c237"
        );
        // Three digits.
        assert_eq!(
            digest_of(&[b'x'; 200]),
            "307ada3d8ece59db76f5e921f9f455631d20ca1f1a30a63c5c4907b7f60dbf75"
        );
    }

    #[test]
    fn the_digest_needs_its_scratch_and_a_message_within_the_bound() {
        let m = [b'x'; 200];
        let mut scratch = vec![0u8; scratch_len(m.len())];
        assert!(digest(&m, &mut scratch).is_some());
        // Three digits of length are needed here, so two bytes fewer is too few.
        let short = PREFIX.len() + 2 + m.len();
        assert!(digest(&m, &mut scratch[..short]).is_none());
        // The longest message fits the scratch its length asks for.
        let long = vec![b'y'; MAX_MESSAGE];
        let mut scratch = vec![0u8; scratch_len(long.len())];
        assert!(digest(&long, &mut scratch).is_some());
        let over = vec![b'y'; MAX_MESSAGE + 1];
        let mut scratch = vec![0u8; scratch_len(over.len()) + 8];
        assert!(digest(&over, &mut scratch).is_none());
    }

    #[test]
    fn a_message_digest_is_never_a_transactions() {
        // What is hashed begins with 0x19: not an RLP list, not a typed envelope.
        assert_eq!(PREFIX[0], 0x19);
        assert!(crate::parse(PREFIX).is_err());
    }

    #[test]
    fn only_text_a_screen_shows_faithfully_is_signed() {
        assert_eq!(
            text(b"Sign in to example.com"),
            Ok("Sign in to example.com")
        );
        assert_eq!(text(b"one\n\nthree"), Ok("one\n\nthree"));
        assert_eq!(text(b""), Err(Unshowable::Empty));
        assert_eq!(text(&[b'a'; MAX_MESSAGE + 1]), Err(Unshowable::TooLong));
        assert!(text(&[b'a'; MAX_MESSAGE]).is_ok());
        // Control characters, and anything past ASCII.
        assert_eq!(text(b"a\tb"), Err(Unshowable::NotText));
        assert_eq!(text(b"a\r\nb"), Err(Unshowable::NotText));
        assert_eq!(text(b"a\0b"), Err(Unshowable::NotText));
        assert_eq!(text("caf\u{e9}".as_bytes()), Err(Unshowable::NotText));
        assert_eq!(text(&[0x7f]), Err(Unshowable::NotText));
        // What a screen would swallow.
        assert_eq!(text(b" a"), Err(Unshowable::Edge));
        assert_eq!(text(b"a "), Err(Unshowable::Edge));
        assert_eq!(text(b"a\n b"), Err(Unshowable::Edge));
        assert_eq!(text(b"a \nb"), Err(Unshowable::Edge));
        assert_eq!(text(b"a\n"), Err(Unshowable::Edge));
        assert_eq!(text(b"\na"), Err(Unshowable::Edge));
        assert_eq!(text(b"\n"), Err(Unshowable::Edge));
    }

    #[test]
    fn the_line_count_is_bounded() {
        let mut m = std::vec::Vec::new();
        for i in 0..MAX_LINES {
            if i > 0 {
                m.push(b'\n');
            }
            m.push(b'x');
        }
        assert!(text(&m).is_ok());
        m.extend_from_slice(b"\nx");
        assert_eq!(text(&m), Err(Unshowable::TooManyLines));
    }

    #[test]
    fn v_is_27_or_28_and_nothing_else() {
        let (r, s) = ([1u8; 32], [2u8; 32]);
        let sig = signature(&r, &s, 0).unwrap();
        assert_eq!(&sig[..32], &r);
        assert_eq!(&sig[32..64], &s);
        assert_eq!(sig[64], 27);
        assert_eq!(signature(&r, &s, 1).unwrap()[64], 28);
        assert!(signature(&r, &s, 2).is_none());
        assert!(signature(&r, &s, 3).is_none());
    }

    #[test]
    fn a_signature_recovers_to_the_key_that_made_it() {
        use outscript::crypto::secp256k1::{SecpPrivateKey, recover_public_key};
        let key = SecpPrivateKey::from_bytes(&[0x11; 32]).unwrap();
        let m = b"Sign in to example.com\nNonce: 1";
        let mut scratch = vec![0u8; scratch_len(m.len())];
        let hash = digest(m, &mut scratch).unwrap();
        let (r, s, recid) = key.sign_recoverable(&hash);
        let sig = signature(&r, &s, recid).unwrap();
        let got = recover_public_key(&r, &s, sig[64] - 27, &hash).unwrap();
        assert_eq!(
            got.serialize_compressed(),
            key.public_key().serialize_compressed()
        );
        // And not to it for another message.
        let other = digest(b"Sign in to example.org\nNonce: 1", &mut scratch).unwrap();
        let wrong = recover_public_key(&r, &s, recid, &other);
        assert!(
            wrong.is_err() || {
                wrong.unwrap().serialize_compressed() != key.public_key().serialize_compressed()
            }
        );
    }
}
