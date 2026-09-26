//! Signing a message with a wallet key.
//!
//! Proving control of an address without spending from it: an exchange asks, a service asks,
//! or the owner wants a note tied to a key. The signature is over the message alone, so it
//! can never move coins -- which is the reason the format prefixes a fixed string: the
//! digest of a message can then never be the digest of a transaction.
//!
//! # The legacy format
//!
//! ```text
//! digest = SHA256d( varstr("Bitcoin Signed Message:\n") || varstr(message) )
//! ```
//!
//! and the signature is 65 bytes -- a header byte, then `r` and `s` -- written in base64.
//! The header carries the recovery id *and* which address type the signer used, so a
//! verifier can recover the public key and check it against the address:
//!
//! | header | address |
//! |---|---|
//! | 27..30 | P2PKH, uncompressed key |
//! | 31..34 | P2PKH, compressed key |
//! | 35..38 | P2SH-P2WPKH |
//! | 39..42 | P2WPKH |
//!
//! Only compressed keys are produced here, so 27..30 never occurs.
//!
//! Source: BIP-137 (header ranges), and the "Bitcoin Signed Message" construction as
//! Bitcoin Core's `signmessage` has always used it -- public standards [C].

use outscript::crypto::secp256k1::{SecpPrivateKey, recover_public_key};
use purecrypto::hash::{Digest, Sha256};

use crate::address::AddressKind;
use crate::bip32::DerivationPath;
use crate::bip32::path::ParseError;

/// The prefix every signed message commits to, so a message digest can never collide with
/// a transaction's.
pub const PREFIX: &str = "Bitcoin Signed Message:\n";

/// A legacy signature: header byte, `r`, `s`.
pub const SIG_LEN: usize = 65;

/// Longest message this signs. Long enough for a proof-of-ownership note, bounded because
/// the digest is computed in one pass over a caller buffer.
pub const MAX_MESSAGE: usize = 240;

/// Longest *multi-line* body [`sign_lines`] signs: the detached signature over a set of
/// exported files is one `<sha256 hex>  <name>` line per file, and a handful of those
/// runs past [`MAX_MESSAGE`]. Separate from it on purpose -- a typed message stays one
/// line the screen can show whole.
pub const MAX_LINES: usize = 1024;

/// Base64 of [`SIG_LEN`] bytes, which is 88 characters with its padding.
pub const MAX_ARMOURED: usize = 88;

/// Why a message could not be signed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Longer than [`MAX_MESSAGE`].
    TooLong { len: usize },
    /// The message holds a character this will not sign: a control character, or one
    /// outside ASCII. A verifier that normalises differently would check a different
    /// message, so these are refused rather than passed through.
    NotPrintable,
    /// The address type has no legacy message format (taproot).
    UnsupportedKind,
    /// The key was not usable.
    BadKey,
    /// The output buffer was too small.
    BufferTooSmall,
}

/// Write a compact-size length followed by the bytes.
fn put_varstr(h: &mut Sha256, bytes: &[u8]) {
    let n = bytes.len();
    if n < 0xfd {
        h.update(&[n as u8]);
    } else {
        h.update(&[0xfd]);
        h.update(&(n as u16).to_le_bytes());
    }
    h.update(bytes);
}

/// The construction itself, over bytes already checked.
fn hash(message: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    put_varstr(&mut h, PREFIX.as_bytes());
    put_varstr(&mut h, message);
    let once = h.finalize();
    let twice = Sha256::digest(&once);
    let mut out = [0u8; 32];
    out.copy_from_slice(&twice);
    out
}

/// The digest a legacy signed message commits to.
pub fn digest(message: &str) -> Result<[u8; 32], Error> {
    if message.len() > MAX_MESSAGE {
        return Err(Error::TooLong { len: message.len() });
    }
    // Printable ASCII only: the same reasoning as refusing a non-NFKD passphrase. A
    // verifier that treats the bytes differently checks something else, and the owner sees
    // no difference on screen.
    if !message.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        return Err(Error::NotPrintable);
    }
    Ok(hash(message.as_bytes()))
}

/// The digest of a body of printable lines: the same construction, with `\n` allowed
/// between lines and [`MAX_LINES`] as the bound.
///
/// For the detached signature over exported files, whose body is one line per file. The
/// line break is the one control character admitted, because a screen shows such a body
/// as its lines and nothing is lost; a tab or a carriage return still refuses.
pub fn digest_lines(message: &str) -> Result<[u8; 32], Error> {
    if message.len() > MAX_LINES {
        return Err(Error::TooLong { len: message.len() });
    }
    if !message
        .bytes()
        .all(|b| (0x20..0x7f).contains(&b) || b == b'\n')
    {
        return Err(Error::NotPrintable);
    }
    Ok(hash(message.as_bytes()))
}

/// The header byte's base for an address type, to which the recovery id is added.
/// Source: BIP-137 [C]
const fn header_base(kind: AddressKind) -> Result<u8, Error> {
    match kind {
        AddressKind::P2pkh => Ok(31),
        AddressKind::P2shP2wpkh => Ok(35),
        AddressKind::P2wpkh => Ok(39),
        // Taproot signs messages through BIP-322, which is a different construction.
        AddressKind::P2tr => Err(Error::UnsupportedKind),
    }
}

/// Sign `message` with `secret`, as an address of `kind` would.
///
/// Returns the 65-byte signature. Deterministic (RFC 6979), so the same message and key
/// always produce the same bytes.
pub fn sign(
    message: &str,
    secret: &[u8; 32],
    kind: AddressKind,
    kw: &crate::KeyWork,
) -> Result<[u8; SIG_LEN], Error> {
    sign_digest(&digest(message)?, secret, kind, kw)
}

/// [`sign`] for a body of printable lines -- see [`digest_lines`].
pub fn sign_lines(
    message: &str,
    secret: &[u8; 32],
    kind: AddressKind,
    kw: &crate::KeyWork,
) -> Result<[u8; SIG_LEN], Error> {
    sign_digest(&digest_lines(message)?, secret, kind, kw)
}

fn sign_digest(
    digest: &[u8; 32],
    secret: &[u8; 32],
    kind: AddressKind,
    _kw: &crate::KeyWork,
) -> Result<[u8; SIG_LEN], Error> {
    let base = header_base(kind)?;
    let key = SecpPrivateKey::from_bytes(secret).map_err(|_| Error::BadKey)?;
    let (r, s, recid) = key.sign_recoverable(digest);
    let mut out = [0u8; SIG_LEN];
    out[0] = base + recid;
    out[1..33].copy_from_slice(&r);
    out[33..].copy_from_slice(&s);
    Ok(out)
}

/// Base64 of a signature, as the armoured form used everywhere.
pub fn armour(sig: &[u8; SIG_LEN], out: &mut [u8]) -> Result<usize, Error> {
    outscript::base64::encode_to_slice(sig, out).map_err(|_| Error::BufferTooSmall)
}

/// The public key a signature recovers to, and the address type its header claims.
///
/// What a verifier does: recover, then check the key against the address. Having it here
/// means the device can check its own work -- a signature that does not recover to the
/// signing key is not handed to anyone.
pub fn recover(message: &str, sig: &[u8; SIG_LEN]) -> Result<([u8; 33], AddressKind), Error> {
    recover_digest(&digest(message)?, sig)
}

/// [`recover`] for a body of printable lines -- see [`digest_lines`].
pub fn recover_lines(message: &str, sig: &[u8; SIG_LEN]) -> Result<([u8; 33], AddressKind), Error> {
    recover_digest(&digest_lines(message)?, sig)
}

fn recover_digest(
    digest: &[u8; 32],
    sig: &[u8; SIG_LEN],
) -> Result<([u8; 33], AddressKind), Error> {
    let header = sig[0];
    let (kind, base) = match header {
        31..=34 => (AddressKind::P2pkh, 31),
        35..=38 => (AddressKind::P2shP2wpkh, 35),
        39..=42 => (AddressKind::P2wpkh, 39),
        _ => return Err(Error::UnsupportedKind),
    };
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig[1..33]);
    s.copy_from_slice(&sig[33..]);
    let key = recover_public_key(&r, &s, header - base, digest).map_err(|_| Error::BadKey)?;
    Ok((key.serialize_compressed(), kind))
}

// ---------------------------------------------------------------------------
// The signing request file.
// ---------------------------------------------------------------------------

/// A signing request, as a `.txt` file on the card or a scanned code carries it.
///
/// The public format Sparrow and the stock documentation use for "Sign Text File": up to
/// three lines -- the message, then an optional derivation path, then an optional address
/// format. A line that is absent leaves the field `None`, and the device chooses (or asks).
///
/// ```text
/// This is the message
/// m/84h/0h/0h/0/0
/// p2wpkh
/// ```
///
/// Source: hw-reference/firmware-features.md §6 "request via file, text, or the
/// Sparrow-style form" [C]; the line order is Coldcard's public "Sign Text File" format.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Request<'a> {
    /// The message, exactly as it will be signed.
    pub message: &'a str,
    /// The path the request asked for, if it named one.
    pub path: Option<DerivationPath>,
    /// The address format the request asked for, if it named one.
    pub kind: Option<AddressKind>,
}

/// Why a request could not be read.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum RequestError {
    /// No message line.
    Empty,
    /// The message itself is not signable: too long, or not plain ASCII.
    Message(Error),
    /// The second line is neither a derivation path nor an address format.
    BadPath(ParseError),
    /// The third line is not one of the address formats this signs for.
    BadFormat,
    /// A fourth non-empty line: the file is something else.
    TooManyLines,
}

/// The address format a request line names, if it names one.
///
/// Case-insensitive, and both spellings of the nested form, because both are written.
pub fn kind_named(word: &str) -> Option<AddressKind> {
    let word = word.trim();
    const NAMES: [(&str, AddressKind); 5] = [
        ("p2pkh", AddressKind::P2pkh),
        ("p2sh-p2wpkh", AddressKind::P2shP2wpkh),
        ("p2wpkh-p2sh", AddressKind::P2shP2wpkh),
        ("p2wpkh", AddressKind::P2wpkh),
        ("p2tr", AddressKind::P2tr),
    ];
    NAMES
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(word))
        .map(|(_, kind)| *kind)
}

/// The name [`kind_named`] reads back, as a request file writes it.
pub const fn kind_name(kind: AddressKind) -> &'static str {
    match kind {
        AddressKind::P2pkh => "p2pkh",
        AddressKind::P2shP2wpkh => "p2sh-p2wpkh",
        AddressKind::P2wpkh => "p2wpkh",
        AddressKind::P2tr => "p2tr",
    }
}

/// Read a signing request.
///
/// Line endings may be either kind; blank lines at the end are the editor's. Trailing
/// whitespace on the message line is dropped for the same reason -- invisible on screen,
/// and signing it would produce a signature over a string nobody can see the shape of.
/// Leading whitespace stays: it is visible, and it is part of what was asked for.
///
/// The second line is a path, or -- for a request that names only a format -- the
/// format itself. The message is checked here, with [`digest`]'s rules, so a request
/// this cannot sign is refused before a key is touched.
pub fn parse_request(text: &str) -> Result<Request<'_>, RequestError> {
    let mut lines = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
    let message = lines.next().ok_or(RequestError::Empty)?.trim_end();
    if message.is_empty() {
        return Err(RequestError::Empty);
    }
    digest(message).map_err(RequestError::Message)?;

    let mut path = None;
    let mut kind = None;
    let mut rest = lines.map(str::trim).filter(|l| !l.is_empty());
    if let Some(second) = rest.next() {
        match kind_named(second) {
            Some(k) => kind = Some(k),
            None => {
                path = Some(
                    second
                        .parse::<DerivationPath>()
                        .map_err(RequestError::BadPath)?,
                );
                if let Some(third) = rest.next() {
                    kind = Some(kind_named(third).ok_or(RequestError::BadFormat)?);
                }
            }
        }
    }
    if rest.next().is_some() {
        return Err(RequestError::TooManyLines);
    }
    Ok(Request {
        message,
        path,
        kind,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyWork;

    /// `m/84h/0h/0h/0/0` of BIP-84's test mnemonic, and the digest and signature an
    /// independent implementation of the documented construction produces for "CatCard".
    const SECRET: [u8; 32] = [
        0x46, 0x04, 0xb4, 0xb7, 0x10, 0xfe, 0x91, 0xf5, 0x84, 0xff, 0xf0, 0x84, 0xe1, 0xa9, 0x15,
        0x9f, 0xe4, 0xf8, 0x40, 0x8f, 0xff, 0x38, 0x05, 0x96, 0xa6, 0x04, 0x94, 0x84, 0x74, 0xce,
        0x4f, 0xa3,
    ];
    const PUBKEY: [u8; 33] = [
        0x03, 0x30, 0xd5, 0x4f, 0xd0, 0xdd, 0x42, 0x0a, 0x6e, 0x5f, 0x8d, 0x36, 0x24, 0xf5, 0xf3,
        0x48, 0x2c, 0xae, 0x35, 0x0f, 0x79, 0xd5, 0xf0, 0x75, 0x3b, 0xf5, 0xbe, 0xef, 0x9c, 0x2d,
        0x91, 0xaf, 0x3c,
    ];
    const DIGEST: [u8; 32] = [
        0x56, 0xc6, 0xfd, 0x0e, 0xc1, 0xdb, 0x41, 0xf1, 0x49, 0x52, 0xa2, 0xfe, 0x0e, 0x09, 0xae,
        0xf4, 0x46, 0xdd, 0xd2, 0x3b, 0xb8, 0xfe, 0xbf, 0x79, 0xdf, 0xfe, 0x57, 0xc7, 0x73, 0x2b,
        0x64, 0xfa,
    ];
    const ARMOURED_P2WPKH: &str =
        "J0w2VKe84xIt6nMsi4HBwRdXrRJKo5WBZ8VZKJvOVDxPQ1v1EO7XB8GMgebEHVedoSPc8rNG9l6vBsRLBdjgz68=";

    #[test]
    fn the_digest_matches_the_documented_construction() {
        assert_eq!(digest("CatCard").unwrap(), DIGEST);
        // The prefix is what keeps a message digest away from a transaction's: the same
        // text with the prefix left out hashes to something else entirely.
        let plain = {
            let once = Sha256::digest(b"CatCard");
            Sha256::digest(&once)
        };
        assert_ne!(&DIGEST[..], &plain[..]);
    }

    #[test]
    fn a_signature_matches_an_independent_implementation_byte_for_byte() {
        let kw = KeyWork::host();
        let sig = sign("CatCard", &SECRET, AddressKind::P2wpkh, &kw).unwrap();
        let mut out = [0u8; MAX_ARMOURED];
        let n = armour(&sig, &mut out).unwrap();
        assert_eq!(core::str::from_utf8(&out[..n]).unwrap(), ARMOURED_P2WPKH);
    }

    #[test]
    fn the_header_says_which_address_type_signed() {
        let kw = KeyWork::host();
        for (kind, base) in [
            (AddressKind::P2pkh, 31u8),
            (AddressKind::P2shP2wpkh, 35),
            (AddressKind::P2wpkh, 39),
        ] {
            let sig = sign("CatCard", &SECRET, kind, &kw).unwrap();
            assert!((base..base + 4).contains(&sig[0]), "{kind:?}");
            // Only the header differs between the three: the signature is over the message.
            let other = sign("CatCard", &SECRET, AddressKind::P2wpkh, &kw).unwrap();
            assert_eq!(sig[1..], other[1..], "{kind:?}");
        }
        assert_eq!(
            sign("CatCard", &SECRET, AddressKind::P2tr, &kw),
            Err(Error::UnsupportedKind)
        );
    }

    #[test]
    fn a_signature_recovers_to_the_key_that_made_it() {
        let kw = KeyWork::host();
        for kind in [
            AddressKind::P2pkh,
            AddressKind::P2shP2wpkh,
            AddressKind::P2wpkh,
        ] {
            let sig = sign("CatCard", &SECRET, kind, &kw).unwrap();
            let (key, recovered_kind) = recover("CatCard", &sig).unwrap();
            assert_eq!(key, PUBKEY, "{kind:?}");
            assert_eq!(recovered_kind, kind);
        }
        // A different message recovers a different key, which is how a verifier catches a
        // signature pasted onto other text.
        let sig = sign("CatCard", &SECRET, AddressKind::P2wpkh, &kw).unwrap();
        let (other, _) = recover("CatCarD", &sig).unwrap();
        assert_ne!(other, PUBKEY);
    }

    #[test]
    fn a_message_this_cannot_show_faithfully_is_refused() {
        let kw = KeyWork::host();
        let long = "x".repeat(MAX_MESSAGE + 1);
        assert_eq!(
            sign(&long, &SECRET, AddressKind::P2wpkh, &kw),
            Err(Error::TooLong {
                len: MAX_MESSAGE + 1
            })
        );
        for bad in ["two\nlines", "tab\there", "caf\u{e9}"] {
            assert_eq!(
                sign(bad, &SECRET, AddressKind::P2wpkh, &kw),
                Err(Error::NotPrintable),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn signing_is_deterministic() {
        let kw = KeyWork::host();
        let a = sign("CatCard", &SECRET, AddressKind::P2wpkh, &kw).unwrap();
        let b = sign("CatCard", &SECRET, AddressKind::P2wpkh, &kw).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn a_body_of_lines_signs_and_recovers_but_a_single_line_signer_refuses_it() {
        let kw = KeyWork::host();
        let body = "aa  one.txt\nbb  two.txt";
        assert_eq!(
            sign(body, &SECRET, AddressKind::P2pkh, &kw),
            Err(Error::NotPrintable)
        );
        let sig = sign_lines(body, &SECRET, AddressKind::P2pkh, &kw).unwrap();
        let (key, kind) = recover_lines(body, &sig).unwrap();
        assert_eq!(key, PUBKEY);
        assert_eq!(kind, AddressKind::P2pkh);
        // One line is the same digest either way: the line variant is a superset, not a
        // different construction.
        assert_eq!(digest("CatCard").unwrap(), digest_lines("CatCard").unwrap());
        // A carriage return or a tab is still not a line.
        for bad in ["a\r\nb", "a\tb"] {
            assert_eq!(digest_lines(bad), Err(Error::NotPrintable), "{bad:?}");
        }
        let long = "x".repeat(MAX_LINES + 1);
        assert!(matches!(digest_lines(&long), Err(Error::TooLong { .. })));
    }

    /// The three-line form, as Sparrow writes it and the stock documentation shows it.
    #[test]
    fn a_full_request_reads_its_three_lines() {
        let req = parse_request("Hello world\nm/84h/0h/0h/0/0\np2wpkh\n").unwrap();
        assert_eq!(req.message, "Hello world");
        let path: DerivationPath = "m/84h/0h/0h/0/0".parse().unwrap();
        assert_eq!(req.path, Some(path));
        assert_eq!(req.kind, Some(AddressKind::P2wpkh));
    }

    #[test]
    fn a_request_may_leave_the_path_and_format_out() {
        let req = parse_request("just a message").unwrap();
        assert_eq!(req.message, "just a message");
        assert_eq!(req.path, None);
        assert_eq!(req.kind, None);

        // A path alone.
        let req = parse_request("msg\r\nm/44'/0'/0'/0/5\r\n\r\n").unwrap();
        let path: DerivationPath = "m/44h/0h/0h/0/5".parse().unwrap();
        assert_eq!(req.path, Some(path));
        assert_eq!(req.kind, None);

        // A format alone, on the second line.
        let req = parse_request("msg\nP2SH-P2WPKH\n").unwrap();
        assert_eq!(req.path, None);
        assert_eq!(req.kind, Some(AddressKind::P2shP2wpkh));
    }

    #[test]
    fn the_message_line_keeps_its_leading_space_and_loses_its_trailing_one() {
        let req = parse_request("  padded   \n").unwrap();
        assert_eq!(req.message, "  padded");
    }

    #[test]
    fn a_request_this_cannot_sign_is_refused_before_any_key_is_touched() {
        assert_eq!(parse_request(""), Err(RequestError::Empty));
        assert_eq!(parse_request("\n\nm/84h\n"), Err(RequestError::Empty));
        assert_eq!(
            parse_request("caf\u{e9}\n"),
            Err(RequestError::Message(Error::NotPrintable))
        );
        assert!(matches!(
            parse_request("msg\nnot/a/path\n"),
            Err(RequestError::BadPath(_))
        ));
        assert_eq!(
            parse_request("msg\nm/84h/0h/0h/0/0\np2wsh\n"),
            Err(RequestError::BadFormat)
        );
        assert_eq!(
            parse_request("msg\nm/84h/0h/0h/0/0\np2wpkh\nfourth\n"),
            Err(RequestError::TooManyLines)
        );
    }

    #[test]
    fn format_names_round_trip_and_read_both_nested_spellings() {
        for kind in [
            AddressKind::P2pkh,
            AddressKind::P2shP2wpkh,
            AddressKind::P2wpkh,
            AddressKind::P2tr,
        ] {
            assert_eq!(kind_named(kind_name(kind)), Some(kind));
        }
        assert_eq!(kind_named("p2wpkh-p2sh"), Some(AddressKind::P2shP2wpkh));
        assert_eq!(kind_named(" P2PKH "), Some(AddressKind::P2pkh));
        assert_eq!(kind_named("p2wsh"), None);
    }
}
