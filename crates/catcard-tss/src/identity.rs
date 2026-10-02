//! A member's per-session identity key: what signs its messages and what its unicasts
//! are encrypted to.
//!
//! tsslib assumes a transport that authenticates senders and keeps point-to-point
//! messages private (its module docs: "the broker is trusted to authenticate message
//! origin"). An SD card or a QR code does neither, so each session makes its own: a
//! fresh secp256k1 key per member, published in round 0 and pinned by the session code
//! the user compares across devices.
//!
//! - **Signing** is ECDSA with an RFC 6979 nonce over SHA-256, normalised to low-S;
//!   verification refuses a high-S signature, so one message has one valid signature.
//! - **Unicast encryption**: AES-256-GCM under a key that is used once. Both ends compute
//!   the ECDH point `a·B = b·A` and take `K = HMAC-SHA256(x(a·B), domain || session ||
//!   roster digest || round || from || to)`. A session accepts one message per (round,
//!   from, to), so each `K` encrypts exactly one payload and a fixed nonce is sound
//!   (SP 800-38D §8: uniqueness of the (key, IV) pair). The envelope header is the AAD.

use alloc::vec::Vec;
use purecrypto::cipher::{Aes256, Gcm};
use purecrypto::ec::secp256k1::ecdsa::{
    Secp256k1EcdsaPrivateKey, Secp256k1EcdsaPublicKey, Secp256k1EcdsaSignature,
};
use purecrypto::ec::secp256k1::{AffinePoint, Scalar};
use purecrypto::hash::{HmacSha256, Sha256};
use zeroize::Zeroize;

use crate::envelope::SIG_LEN;
use crate::rng::{Entropy, draw};
use crate::{Error, PUBKEY_LEN};

const UNICAST_DOMAIN: &[u8] = b"CatCard TSS unicast v1\0";
const GCM_NONCE: [u8; 12] = [0; 12];
/// The tag appended to an encrypted payload.
pub const TAG_LEN: usize = 16;

/// A session's private identity key. Wiped on drop (purecrypto's key wipes its scalar).
pub(crate) struct IdentityKey {
    key: Secp256k1EcdsaPrivateKey,
    public: [u8; PUBKEY_LEN],
}

impl IdentityKey {
    /// A fresh key from `source`: 32 bytes, redrawn in the 2^-128 case they are not a
    /// valid scalar.
    pub(crate) fn generate(source: &mut dyn Entropy) -> Result<Self, Error> {
        let mut buf = [0u8; 32];
        // Bounded: the chance of a single rejection is below 2^-127.
        for _ in 0..4 {
            draw(source, &mut buf)?;
            let made = Secp256k1EcdsaPrivateKey::from_bytes(&buf);
            buf.zeroize();
            if let Ok(key) = made {
                let public = key.public_key().to_sec1_compressed();
                return Ok(IdentityKey { key, public });
            }
        }
        Err(Error::Randomness)
    }

    pub(crate) fn public(&self) -> &[u8; PUBKEY_LEN] {
        &self.public
    }

    pub(crate) fn sign(&self, digest: &[u8; 32]) -> Result<[u8; SIG_LEN], Error> {
        let sig = self
            .key
            .sign_prehash::<Sha256>(digest)
            .map_err(|_| Error::State("identity signature"))?;
        Ok(sig.to_low_s().to_bytes())
    }

    /// The one-message AES key for (round, from, to) with the member whose identity is
    /// `peer`.
    fn unicast_key(
        &self,
        peer: &[u8; PUBKEY_LEN],
        context: &UnicastContext<'_>,
    ) -> Result<[u8; 32], Error> {
        let point = AffinePoint::from_sec1(peer).map_err(|_| Error::Format("identity key"))?;
        let mut d = self.key.to_bytes();
        let scalar = Scalar::from_bytes_be(&d);
        d.zeroize();
        let scalar = scalar.map_err(|_| Error::State("identity key"))?;
        let shared = point
            .to_projective()
            .mul(&scalar)
            .to_affine()
            .ok_or(Error::Format("identity key"))?;
        let mut x = shared.x_bytes();
        let mut mac = HmacSha256::new(&x);
        x.zeroize();
        mac.update(UNICAST_DOMAIN);
        mac.update(context.session);
        mac.update(context.roster);
        mac.update(&[context.round, context.from, context.to]);
        Ok(mac.finalize())
    }

    /// Encrypt a unicast payload in place; returns it with the tag appended.
    pub(crate) fn seal(
        &self,
        peer: &[u8; PUBKEY_LEN],
        context: &UnicastContext<'_>,
        aad: &[u8],
        mut plain: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        let mut k = self.unicast_key(peer, context)?;
        let gcm = Gcm::new(Aes256::new(&k));
        k.zeroize();
        let tag = gcm.encrypt(&GCM_NONCE, aad, &mut plain);
        plain.extend_from_slice(&tag);
        Ok(plain)
    }

    /// Decrypt a unicast payload; `None` if the tag does not verify.
    pub(crate) fn open(
        &self,
        peer: &[u8; PUBKEY_LEN],
        context: &UnicastContext<'_>,
        aad: &[u8],
        sealed: &[u8],
    ) -> Result<Option<Vec<u8>>, Error> {
        let Some(body_len) = sealed.len().checked_sub(TAG_LEN) else {
            return Ok(None);
        };
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&sealed[body_len..]);
        let mut k = self.unicast_key(peer, context)?;
        let gcm = Gcm::new(Aes256::new(&k));
        k.zeroize();
        let mut body = sealed[..body_len].to_vec();
        match gcm.decrypt(&GCM_NONCE, aad, &mut body, &tag) {
            Ok(()) => Ok(Some(body)),
            Err(_) => Ok(None),
        }
    }
}

/// What a unicast key is bound to besides the two identities.
pub(crate) struct UnicastContext<'a> {
    pub session: &'a [u8],
    pub roster: &'a [u8; 32],
    pub round: u8,
    pub from: u8,
    pub to: u8,
}

/// Whether `sig` is a low-S signature by `public` over `digest`.
pub(crate) fn verify(public: &[u8; PUBKEY_LEN], digest: &[u8; 32], sig: &[u8; SIG_LEN]) -> bool {
    let Ok(key) = Secp256k1EcdsaPublicKey::from_sec1(public) else {
        return false;
    };
    let sig = Secp256k1EcdsaSignature::from_bytes(sig);
    sig.is_low_s() && key.verify_prehash(digest, &sig).is_ok()
}

/// Whether `bytes` is a valid compressed secp256k1 point.
pub(crate) fn valid_public(bytes: &[u8]) -> bool {
    bytes.len() == PUBKEY_LEN && Secp256k1EcdsaPublicKey::from_sec1(bytes).is_ok()
}
