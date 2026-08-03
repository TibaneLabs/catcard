//! Signing.
//!
//! Two schemes, because Bitcoin uses two: ECDSA for pre-taproot outputs and Schnorr
//! (BIP-340) for taproot.
//!
//! # Why the nonce is deterministic
//!
//! ECDSA leaks the private key outright if a nonce is ever reused across two different
//! messages, and leaks it to lattice attacks if the nonce is merely biased. On a device
//! whose RNG is the reason this project exists, deriving the nonce from a random source
//! is the wrong dependency to take.
//!
//! So nonces come from RFC 6979: `k = HMAC-DRBG(private_key, message_hash)`. Signing is
//! then a pure function of the key and the message, which is also what makes it
//! testable against fixed vectors. BIP-340 does the same for Schnorr with a tagged hash.
//!
//! # Low-S
//!
//! For every ECDSA signature `(r, s)`, `(r, n - s)` is equally valid. Bitcoin's policy
//! rules require the smaller `s` — a signature with high `s` is valid under consensus
//! but will not relay, so a wallet that emits one produces transactions that quietly
//! never confirm. Every signature here is normalised.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use k256::schnorr::signature::hazmat::PrehashSigner as _;

/// Compressed public key.
pub const PUBKEY_LEN: usize = 33;
/// x-only public key (BIP-340).
pub const XONLY_LEN: usize = 32;
/// Compact ECDSA signature, `r || s`.
pub const COMPACT_SIG_LEN: usize = 64;
/// A Schnorr signature.
pub const SCHNORR_SIG_LEN: usize = 64;
/// Longest DER signature Bitcoin will accept, before the sighash byte.
pub const MAX_DER_LEN: usize = 72;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Key bytes are not a valid secp256k1 scalar.
    InvalidKey,
    /// Signing failed. Cryptographically negligible.
    SigningFailed,
    /// The output buffer is too small.
    BufferTooSmall { need: usize, have: usize },
}

/// Sighash type byte appended to a script signature.
///
/// The flag is not cosmetic: it selects which parts of the transaction the signature
/// commits to, so getting it wrong can authorise a transaction the user never saw.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum SigHashType {
    /// Commits to every input and output. The only one a wallet should use by default.
    All = 0x01,
    /// Commits to no outputs — anyone can redirect the funds.
    None = 0x02,
    /// Commits only to the output at the same index.
    Single = 0x03,
    /// `All`, but only this input. Combines with the above.
    AllPlusAnyoneCanPay = 0x81,
    NonePlusAnyoneCanPay = 0x82,
    SinglePlusAnyoneCanPay = 0x83,
}

impl SigHashType {
    pub const fn to_byte(self) -> u8 {
        self as u8
    }

    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(SigHashType::All),
            0x02 => Some(SigHashType::None),
            0x03 => Some(SigHashType::Single),
            0x81 => Some(SigHashType::AllPlusAnyoneCanPay),
            0x82 => Some(SigHashType::NonePlusAnyoneCanPay),
            0x83 => Some(SigHashType::SinglePlusAnyoneCanPay),
            _ => None,
        }
    }

    /// True unless this signature commits to every output.
    ///
    /// Anything other than `All` lets someone else alter where the money goes, so the
    /// UI must say so explicitly rather than showing a generic confirmation.
    pub const fn is_permissive(self) -> bool {
        !matches!(self, SigHashType::All)
    }
}

fn signing_key(secret: &[u8; 32]) -> Result<SigningKey, Error> {
    SigningKey::from_slice(secret).map_err(|_| Error::InvalidKey)
}

/// Sign a 32-byte hash with deterministic ECDSA, returning compact `r || s`, low-S.
pub fn ecdsa_sign(secret: &[u8; 32], hash: &[u8; 32]) -> Result<[u8; COMPACT_SIG_LEN], Error> {
    let key = signing_key(secret)?;
    let sig: Signature = key.sign_prehash(hash).map_err(|_| Error::SigningFailed)?;
    // Idempotent: returns the same signature when `s` was already in the lower half.
    let sig = sig.normalize_s();
    Ok(sig.to_bytes().into())
}

/// Verify a compact ECDSA signature against a compressed public key.
pub fn ecdsa_verify(
    pubkey: &[u8; PUBKEY_LEN],
    hash: &[u8; 32],
    sig: &[u8; COMPACT_SIG_LEN],
) -> Result<bool, Error> {
    let vk = VerifyingKey::from_sec1_bytes(pubkey).map_err(|_| Error::InvalidKey)?;
    let Ok(sig) = Signature::from_slice(sig) else {
        // A malformed signature is a verification failure, not a caller error.
        return Ok(false);
    };
    Ok(vk.verify_prehash(hash, &sig).is_ok())
}

/// Encode a compact signature as DER, as a scriptSig or witness item requires.
///
/// Returns the length written. Bitcoin's strict-DER rules mean each integer is
/// minimally encoded and gets a leading `0x00` only when its high bit would otherwise
/// make it negative.
pub fn to_der(sig: &[u8; COMPACT_SIG_LEN], out: &mut [u8]) -> Result<usize, Error> {
    let (r, s) = sig.split_at(32);
    let r = der_int(r);
    let s = der_int(s);
    let total = 2 + r.1 + 2 + s.1;
    let need = 2 + total;
    if out.len() < need {
        return Err(Error::BufferTooSmall {
            need,
            have: out.len(),
        });
    }

    out[0] = 0x30; // SEQUENCE
    out[1] = total as u8;
    let mut at = 2;
    for (bytes, len) in [r, s] {
        out[at] = 0x02; // INTEGER
        out[at + 1] = len as u8;
        at += 2;
        if bytes[0] & 0x80 != 0 {
            out[at] = 0x00;
            at += 1;
            out[at..at + bytes.len()].copy_from_slice(bytes);
            at += bytes.len();
        } else {
            out[at..at + bytes.len()].copy_from_slice(bytes);
            at += bytes.len();
        }
    }
    Ok(at)
}

/// Strip leading zeros and report the DER content length, including any pad byte.
fn der_int(v: &[u8]) -> (&[u8], usize) {
    let trimmed = {
        let mut i = 0;
        while i < v.len() - 1 && v[i] == 0 {
            i += 1;
        }
        &v[i..]
    };
    let pad = usize::from(trimmed[0] & 0x80 != 0);
    (trimmed, trimmed.len() + pad)
}

/// Sign for a taproot key-path spend (BIP-340 Schnorr).
///
/// The key must already be tweaked — see `catcard_address::taproot_output_key`. Signing
/// with the untweaked internal key produces a signature that verifies against the wrong
/// public key and is rejected by consensus.
pub fn schnorr_sign(secret: &[u8; 32], hash: &[u8; 32]) -> Result<[u8; SCHNORR_SIG_LEN], Error> {
    let key =
        k256::schnorr::SigningKey::from_bytes(secret.into()).map_err(|_| Error::InvalidKey)?;
    let sig = key.sign_prehash(hash).map_err(|_| Error::SigningFailed)?;
    Ok(sig.to_bytes())
}

/// Verify a Schnorr signature against an x-only public key.
pub fn schnorr_verify(
    xonly: &[u8; XONLY_LEN],
    hash: &[u8; 32],
    sig: &[u8; SCHNORR_SIG_LEN],
) -> Result<bool, Error> {
    use k256::schnorr::signature::hazmat::PrehashVerifier as _;
    let vk =
        k256::schnorr::VerifyingKey::from_bytes(xonly.into()).map_err(|_| Error::InvalidKey)?;
    let Ok(sig) = k256::schnorr::Signature::try_from(&sig[..]) else {
        return Ok(false);
    };
    Ok(vk.verify_prehash(hash, &sig).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::sec1::ToSec1Point;

    fn pubkey_of(secret: &[u8; 32]) -> [u8; PUBKEY_LEN] {
        let key = SigningKey::from_slice(secret).unwrap();
        let vk = VerifyingKey::from(&key);
        let p = vk.to_sec1_point(true);
        let mut out = [0u8; PUBKEY_LEN];
        out.copy_from_slice(p.as_ref());
        out
    }

    const SECRET: [u8; 32] = [0x11; 32];
    const HASH: [u8; 32] = [0x42; 32];

    #[test]
    fn signing_is_deterministic() {
        // The property RFC 6979 exists for, and the one that makes fixed vectors
        // possible at all.
        let a = ecdsa_sign(&SECRET, &HASH).unwrap();
        let b = ecdsa_sign(&SECRET, &HASH).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_messages_give_different_nonces() {
        // Reusing a nonce across two messages exposes the private key outright.
        let a = ecdsa_sign(&SECRET, &[0x01; 32]).unwrap();
        let b = ecdsa_sign(&SECRET, &[0x02; 32]).unwrap();
        assert_ne!(&a[..32], &b[..32], "r repeated across two messages");
    }

    #[test]
    fn sign_then_verify() {
        let sig = ecdsa_sign(&SECRET, &HASH).unwrap();
        assert!(ecdsa_verify(&pubkey_of(&SECRET), &HASH, &sig).unwrap());
    }

    #[test]
    fn a_signature_does_not_verify_against_another_message_or_key() {
        let sig = ecdsa_sign(&SECRET, &HASH).unwrap();
        assert!(!ecdsa_verify(&pubkey_of(&SECRET), &[0x43; 32], &sig).unwrap());
        assert!(!ecdsa_verify(&pubkey_of(&[0x22; 32]), &HASH, &sig).unwrap());
    }

    #[test]
    fn signatures_are_low_s() {
        // A high-S signature is valid under consensus but will not relay, so a wallet
        // that emits one produces transactions that quietly never confirm.
        let half_order = [
            0x7Fu8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46,
            0x68, 0x1B, 0x20, 0xA0,
        ];
        for i in 0..64u8 {
            let mut secret = [1u8; 32];
            secret[31] = i.max(1);
            let sig = ecdsa_sign(&secret, &HASH).unwrap();
            assert!(sig[32..] <= half_order[..], "high S for key byte {i}");
        }
    }

    #[test]
    fn a_tampered_signature_is_rejected_cleanly() {
        let mut sig = ecdsa_sign(&SECRET, &HASH).unwrap();
        sig[10] ^= 0x01;
        assert!(!ecdsa_verify(&pubkey_of(&SECRET), &HASH, &sig).unwrap());
        assert!(!ecdsa_verify(&pubkey_of(&SECRET), &HASH, &[0u8; 64]).unwrap());
    }

    #[test]
    fn an_invalid_private_key_is_rejected() {
        assert_eq!(ecdsa_sign(&[0u8; 32], &HASH), Err(Error::InvalidKey));
        assert_eq!(ecdsa_sign(&[0xFF; 32], &HASH), Err(Error::InvalidKey));
    }

    // -- DER --------------------------------------------------------------------

    fn der_of(sig: &[u8; 64]) -> Vec<u8> {
        let mut out = [0u8; MAX_DER_LEN];
        let n = to_der(sig, &mut out).unwrap();
        out[..n].to_vec()
    }

    #[test]
    fn der_has_the_expected_shape() {
        let der = der_of(&ecdsa_sign(&SECRET, &HASH).unwrap());
        assert_eq!(der[0], 0x30, "not a SEQUENCE");
        assert_eq!(der[1] as usize, der.len() - 2, "length header is wrong");
        assert_eq!(der[2], 0x02, "r is not an INTEGER");
        let r_len = der[3] as usize;
        assert_eq!(der[4 + r_len], 0x02, "s is not an INTEGER");
        assert!(der.len() <= MAX_DER_LEN);
    }

    #[test]
    fn der_pads_a_high_bit_integer() {
        // Without the pad, DER would read the value as negative.
        let mut sig = [0u8; 64];
        sig[0] = 0x80; // r has its high bit set
        sig[32] = 0x01; // s does not
        let der = der_of(&sig);
        assert_eq!(der[2], 0x02);
        assert_eq!(der[3], 33, "r should have been padded to 33 bytes");
        assert_eq!(der[4], 0x00, "missing pad byte");
    }

    #[test]
    fn der_trims_leading_zeros() {
        // Strict DER requires minimal integers; a leading zero that is not needed for
        // sign makes the signature non-standard and unrelayable.
        let mut sig = [0u8; 64];
        sig[31] = 0x01; // r = 1, with 31 leading zero bytes
        sig[63] = 0x02; // s = 2
        let der = der_of(&sig);
        assert_eq!(der, vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);
    }

    #[test]
    fn der_handles_an_all_zero_integer() {
        // Not a real signature, but the trimmer must not consume the last byte.
        let der = der_of(&[0u8; 64]);
        assert_eq!(der, vec![0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn der_into_a_small_buffer_errors() {
        let sig = ecdsa_sign(&SECRET, &HASH).unwrap();
        let mut tiny = [0u8; 8];
        assert!(matches!(
            to_der(&sig, &mut tiny),
            Err(Error::BufferTooSmall { .. })
        ));
    }

    // -- Schnorr ----------------------------------------------------------------

    #[test]
    fn schnorr_sign_then_verify() {
        let key = k256::schnorr::SigningKey::from_bytes((&SECRET).into()).unwrap();
        let xonly: [u8; 32] = key.verifying_key().to_bytes().into();
        let sig = schnorr_sign(&SECRET, &HASH).unwrap();
        assert!(schnorr_verify(&xonly, &HASH, &sig).unwrap());
    }

    #[test]
    fn schnorr_rejects_a_wrong_message() {
        let key = k256::schnorr::SigningKey::from_bytes((&SECRET).into()).unwrap();
        let xonly: [u8; 32] = key.verifying_key().to_bytes().into();
        let sig = schnorr_sign(&SECRET, &HASH).unwrap();
        assert!(!schnorr_verify(&xonly, &[0x43; 32], &sig).unwrap());
    }

    #[test]
    fn schnorr_signatures_are_64_bytes() {
        assert_eq!(schnorr_sign(&SECRET, &HASH).unwrap().len(), SCHNORR_SIG_LEN);
    }

    // -- sighash flags ----------------------------------------------------------

    #[test]
    fn sighash_bytes_round_trip() {
        for t in [
            SigHashType::All,
            SigHashType::None,
            SigHashType::Single,
            SigHashType::AllPlusAnyoneCanPay,
            SigHashType::NonePlusAnyoneCanPay,
            SigHashType::SinglePlusAnyoneCanPay,
        ] {
            assert_eq!(SigHashType::from_byte(t.to_byte()), Some(t));
        }
        assert_eq!(SigHashType::from_byte(0x00), None);
        assert_eq!(SigHashType::from_byte(0x04), None);
        assert_eq!(SigHashType::from_byte(0xff), None);
    }

    #[test]
    fn only_sighash_all_is_non_permissive() {
        // Everything else lets a third party change where the money goes, which the UI
        // has to say out loud rather than showing a generic confirmation.
        assert!(!SigHashType::All.is_permissive());
        for t in [
            SigHashType::None,
            SigHashType::Single,
            SigHashType::AllPlusAnyoneCanPay,
            SigHashType::NonePlusAnyoneCanPay,
            SigHashType::SinglePlusAnyoneCanPay,
        ] {
            assert!(t.is_permissive(), "{t:?}");
        }
    }
}
