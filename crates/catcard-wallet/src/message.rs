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

/// The prefix every signed message commits to, so a message digest can never collide with
/// a transaction's.
pub const PREFIX: &str = "Bitcoin Signed Message:\n";

/// A legacy signature: header byte, `r`, `s`.
pub const SIG_LEN: usize = 65;

/// Longest message this signs. Long enough for a proof-of-ownership note, bounded because
/// the digest is computed in one pass over a caller buffer.
pub const MAX_MESSAGE: usize = 240;

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
    let mut h = Sha256::new();
    put_varstr(&mut h, PREFIX.as_bytes());
    put_varstr(&mut h, message.as_bytes());
    let once = h.finalize();
    let twice = Sha256::digest(&once);
    let mut out = [0u8; 32];
    out.copy_from_slice(&twice);
    Ok(out)
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
    _kw: &crate::KeyWork,
) -> Result<[u8; SIG_LEN], Error> {
    let base = header_base(kind)?;
    let digest = digest(message)?;
    let key = SecpPrivateKey::from_bytes(secret).map_err(|_| Error::BadKey)?;
    let (r, s, recid) = key.sign_recoverable(&digest);
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
    let digest = digest(message)?;
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
    let key = recover_public_key(&r, &s, header - base, &digest).map_err(|_| Error::BadKey)?;
    Ok((key.serialize_compressed(), kind))
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
}
