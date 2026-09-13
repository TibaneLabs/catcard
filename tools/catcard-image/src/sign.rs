//! secp256k1 ECDSA signing and verification of firmware images.
//!
//! The bootloader calls `uECC_verify(approved_pubkeys[pubkey_num], digest, 32,
//! signature, uECC_secp256k1())` on the double-SHA256 digest, with the signature as
//! raw `r || s` — not DER. Source: `hw-reference/firmware-signing.md §3` [C].

use anyhow::{Context, Result, bail};
use purecrypto::ec::CurveId;
use purecrypto::ec::boxed::BoxedEcdsaPrivateKey;
use purecrypto::ec::secp256k1::ecdsa::{Secp256k1EcdsaPublicKey, Secp256k1EcdsaSignature};
use purecrypto::hash::Sha256;

/// `approved_pubkeys[0]` — the published developer key, re-exported from the crate the
/// firmware also reads it from, so the host tool and the device cannot disagree about
/// which key slot 0 is.
pub use catcard_fwhdr::DEV_PUBKEY;

/// The dev key, embedded so a clean checkout can build a loadable image with no setup.
/// It is public by design — see `keys/README.md`.
pub const DEV_PRIVKEY_PEM: &str = include_str!("../../../keys/dev-privkey.pem");

/// Load a secp256k1 signing key from a SEC1 `EC PRIVATE KEY` PEM.
///
/// The host may allocate, so the runtime-curve `BoxedEcdsaPrivateKey` (which owns the
/// PEM/DER machinery) is used here; the device signs with the allocation-free
/// `secp256k1::ecdsa` type instead, and the two produce identical RFC 6979 signatures.
pub fn load_key(pem: &str) -> Result<BoxedEcdsaPrivateKey> {
    let key = BoxedEcdsaPrivateKey::from_sec1_pem(pem.trim())
        .map_err(|e| anyhow::anyhow!("{e:?}"))
        .context("not a valid secp256k1 SEC1 private key PEM")?;
    if key.curve() != CurveId::Secp256k1 {
        bail!("key is on {:?}, not secp256k1", key.curve());
    }
    Ok(key)
}

/// Sign a 32-byte digest, returning raw `r || s`, low-S.
pub fn sign_digest(key: &BoxedEcdsaPrivateKey, digest: &[u8; 32]) -> Result<[u8; 64]> {
    let sig = key
        .sign_prehash::<Sha256>(digest)
        .map_err(|e| anyhow::anyhow!("{e:?}"))
        .context("ECDSA signing failed")?
        .to_low_s(CurveId::Secp256k1);
    let bytes = sig.to_bytes(CurveId::Secp256k1);
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// The public key matching a signing key, as raw `X || Y`.
pub fn public_key_bytes(key: &BoxedEcdsaPrivateKey) -> [u8; 64] {
    // Uncompressed SEC1: 0x04 || X || Y.
    let sec1 = key.public_key().to_sec1();
    debug_assert_eq!(sec1.len(), 65);
    debug_assert_eq!(sec1[0], 0x04);
    let mut out = [0u8; 64];
    out.copy_from_slice(&sec1[1..65]);
    out
}

/// Verify `signature` over `digest` against a raw `X || Y` public key.
pub fn verify_digest(pubkey: &[u8; 64], digest: &[u8; 32], signature: &[u8; 64]) -> Result<bool> {
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(pubkey);
    let vk = Secp256k1EcdsaPublicKey::from_sec1(&sec1)
        .map_err(|e| anyhow::anyhow!("{e:?}"))
        .context("public key is not a valid secp256k1 point")?;
    // `from_bytes` just splits `r || s`; an out-of-range half is caught by verify.
    let sig = Secp256k1EcdsaSignature::from_bytes(signature);
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
