//! secp256k1 ECDSA signing and verification of firmware images.
//!
//! The bootloader calls `uECC_verify(approved_pubkeys[pubkey_num], digest, 32,
//! signature, uECC_secp256k1())` on the double-SHA256 digest, with the signature as
//! raw `r || s` — not DER. Source: `hw-reference/firmware-signing.md §3` [C].

use anyhow::{bail, Context, Result};
use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use k256::SecretKey;

/// `approved_pubkeys[0]` — the published developer key, raw `X || Y`.
/// Source: firmware-signing.md §4 [C].
pub const DEV_PUBKEY: [u8; 64] = [
    0xb4, 0xcb, 0x41, 0x26, 0xf7, 0xe1, 0x6c, 0xf3, 0x8f, 0xf2, 0xb4, 0x71, 0x1d, 0xfb, 0x23, 0x01,
    0x0d, 0x76, 0xd6, 0x66, 0xa7, 0x8a, 0xa3, 0x6c, 0x9b, 0x53, 0xf9, 0xf6, 0x7b, 0x58, 0x18, 0x05,
    0x58, 0x0b, 0x3b, 0xe9, 0x31, 0xc4, 0x9f, 0xb8, 0x44, 0x04, 0x3c, 0x11, 0x96, 0x08, 0x0f, 0x47,
    0x81, 0x25, 0xed, 0x37, 0x7a, 0x23, 0x9e, 0x4a, 0xaf, 0xb7, 0x18, 0x38, 0xba, 0x38, 0x04, 0xda,
];

/// The dev key, embedded so a clean checkout can build a loadable image with no setup.
/// It is public by design — see `keys/README.md`.
pub const DEV_PRIVKEY_PEM: &str = include_str!("../../../keys/dev-privkey.pem");

/// Load a secp256k1 signing key from a SEC1 `EC PRIVATE KEY` PEM.
pub fn load_key(pem: &str) -> Result<SigningKey> {
    let sk = SecretKey::from_sec1_pem(pem.trim())
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("not a valid secp256k1 SEC1 private key PEM")?;
    Ok(SigningKey::from(sk))
}

/// Sign a 32-byte digest, returning raw `r || s`.
pub fn sign_digest(key: &SigningKey, digest: &[u8; 32]) -> Result<[u8; 64]> {
    let sig: Signature = key
        .sign_prehash(digest)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("ECDSA signing failed")?;
    Ok(sig.to_bytes().into())
}

/// The public key matching a signing key, as raw `X || Y`.
pub fn public_key_bytes(key: &SigningKey) -> [u8; 64] {
    let vk = VerifyingKey::from(key);
    // `false` = uncompressed SEC1: 0x04 || X || Y.
    let point = vk.to_sec1_point(false);
    let bytes = point.as_ref();
    debug_assert_eq!(bytes.len(), 65);
    debug_assert_eq!(bytes[0], 0x04);
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes[1..65]);
    out
}

/// Verify `signature` over `digest` against a raw `X || Y` public key.
pub fn verify_digest(pubkey: &[u8; 64], digest: &[u8; 32], signature: &[u8; 64]) -> Result<bool> {
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(pubkey);
    let vk = VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("public key is not a valid secp256k1 point")?;

    let sig = match Signature::from_slice(signature) {
        Ok(s) => s,
        // A malformed signature is a verification failure, not a tool error.
        Err(_) => return Ok(false),
    };
    Ok(vk.verify_prehash(digest, &sig).is_ok())
}

/// The public key for a bootloader key slot, where we know it.
pub fn pubkey_for_slot(slot: u32) -> Result<[u8; 64]> {
    match slot {
        0 => Ok(DEV_PUBKEY),
        1..=5 => bail!(
            "pubkey_num {slot} is a Coinkite production key; its public key is not \
             published, so this image cannot be verified here (the device still can)"
        ),
        _ => bail!("pubkey_num {slot} is out of range (bootloader has 6 key slots)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_dev_key_matches_the_published_public_key() {
        // If these ever disagree, either the PEM or the constant is wrong and every
        // image we produce would be rejected by the bootloader.
        let key = load_key(DEV_PRIVKEY_PEM).unwrap();
        assert_eq!(
            hex::encode(public_key_bytes(&key)),
            hex::encode(DEV_PUBKEY),
            "keys/dev-privkey.pem does not correspond to the documented dev public key"
        );
    }

    #[test]
    fn sign_then_verify() {
        let key = load_key(DEV_PRIVKEY_PEM).unwrap();
        let digest = [0x5au8; 32];
        let sig = sign_digest(&key, &digest).unwrap();
        assert!(verify_digest(&DEV_PUBKEY, &digest, &sig).unwrap());
    }

    #[test]
    fn a_different_digest_does_not_verify() {
        let key = load_key(DEV_PRIVKEY_PEM).unwrap();
        let sig = sign_digest(&key, &[0x5au8; 32]).unwrap();
        assert!(!verify_digest(&DEV_PUBKEY, &[0x5bu8; 32], &sig).unwrap());
    }

    #[test]
    fn a_tampered_signature_does_not_verify() {
        let key = load_key(DEV_PRIVKEY_PEM).unwrap();
        let digest = [0x11u8; 32];
        let mut sig = sign_digest(&key, &digest).unwrap();
        sig[10] ^= 0x01;
        // Either it fails to parse or it fails to verify; both report `false`.
        assert!(!verify_digest(&DEV_PUBKEY, &digest, &sig).unwrap());
    }

    #[test]
    fn an_all_zero_signature_is_rejected_cleanly() {
        assert!(!verify_digest(&DEV_PUBKEY, &[0u8; 32], &[0u8; 64]).unwrap());
    }

    #[test]
    fn signature_is_raw_64_bytes_not_der() {
        // DER-encoded ECDSA starts with 0x30; raw r||s must not be length-prefixed.
        let key = load_key(DEV_PRIVKEY_PEM).unwrap();
        let sig = sign_digest(&key, &[7u8; 32]).unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn bad_pem_is_an_error_not_a_panic() {
        assert!(
            load_key("-----BEGIN EC PRIVATE KEY-----\nzzzz\n-----END EC PRIVATE KEY-----").is_err()
        );
        assert!(load_key("").is_err());
    }

    #[test]
    fn production_slots_report_why_they_cannot_be_checked() {
        assert!(pubkey_for_slot(0).is_ok());
        let err = pubkey_for_slot(3).unwrap_err().to_string();
        assert!(err.contains("not published"), "{err}");
        assert!(pubkey_for_slot(6).is_err());
    }
}
