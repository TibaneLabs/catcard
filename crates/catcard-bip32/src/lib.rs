//! BIP-32 hierarchical deterministic keys over secp256k1.
//!
//! Covers derivation (hardened and normal), fingerprints, and the `xprv`/`xpub`
//! serialisation. Allocation-free and `no_std`.
//!
//! # The hardened/normal distinction
//!
//! Normal derivation is what makes watch-only wallets possible: a child *public* key is
//! computable from the parent public key alone. It is also what makes an exposed child
//! *private* key catastrophic — parent chain code plus any normal child private key
//! recovers the parent private key, and therefore every sibling. Hardened derivation
//! blocks that by feeding the parent private key into the HMAC, at the cost of no
//! public-only derivation.
//!
//! Account-level paths are hardened for exactly that reason; only the last two levels
//! (change and index) are normal.
//!
//! Reference: BIP-32.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

pub mod path;
pub mod serialize;

#[cfg(test)]
mod test_vectors;

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, ProjectivePoint, PublicKey, Scalar, SecretKey};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use path::{ChildNumber, DerivationPath, HARDENED_OFFSET, MAX_PATH_DEPTH};
pub use serialize::Network;

type HmacSha512 = Hmac<Sha512>;

/// A compressed secp256k1 point.
pub const PUBKEY_LEN: usize = 33;
/// A 256-bit scalar.
pub const PRIVKEY_LEN: usize = 32;
/// BIP-32 chain code.
pub const CHAIN_CODE_LEN: usize = 32;
/// Truncated HASH160 identifying a key.
pub const FINGERPRINT_LEN: usize = 4;

/// The HMAC key BIP-32 fixes for master-key generation.
pub const MASTER_KEY_SALT: &[u8] = b"Bitcoin seed";

/// BIP-32 requires a seed of 128 to 512 bits.
pub const MIN_SEED_LEN: usize = 16;
pub const MAX_SEED_LEN: usize = 64;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Seed outside the 16..=64 byte range BIP-32 permits.
    BadSeedLen { len: usize },
    /// The derived scalar was zero or exceeded the curve order, or a derived point was
    /// the identity.
    ///
    /// BIP-32 says to skip to the next child index when this happens. It occurs with
    /// probability around 2^-127, so this is reported rather than silently retried:
    /// seeing it means something is wrong, not that an index was unlucky.
    UnusableChild { index: u32 },
    /// Normal (non-hardened) derivation was requested from a public key, which is fine,
    /// or hardened derivation was — which is not possible without the private key.
    HardenedFromPublic { index: u32 },
    /// Key bytes are not a valid secp256k1 scalar or point.
    InvalidKey,
    /// Derivation path deeper than [`MAX_PATH_DEPTH`], or depth would exceed 255.
    TooDeep,
}

/// RIPEMD160(SHA256(data)) — the identifier BIP-32 fingerprints are taken from.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    Ripemd160::digest(sha).into()
}

/// An extended private key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ExtendedPrivKey {
    #[zeroize(skip)]
    pub network: Network,
    #[zeroize(skip)]
    pub depth: u8,
    #[zeroize(skip)]
    pub parent_fingerprint: [u8; FINGERPRINT_LEN],
    #[zeroize(skip)]
    pub child_number: ChildNumber,
    pub chain_code: [u8; CHAIN_CODE_LEN],
    secret: [u8; PRIVKEY_LEN],
}

/// An extended public key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ExtendedPubKey {
    pub network: Network,
    pub depth: u8,
    pub parent_fingerprint: [u8; FINGERPRINT_LEN],
    pub child_number: ChildNumber,
    pub chain_code: [u8; CHAIN_CODE_LEN],
    /// Compressed SEC1 encoding.
    pub public_key: [u8; PUBKEY_LEN],
}

fn scalar_from_bytes(b: &[u8; 32]) -> Option<Scalar> {
    let sk = SecretKey::from_slice(b).ok()?;
    Some(*sk.to_nonzero_scalar().as_ref())
}

/// Interpret 32 bytes as a scalar, rejecting values at or above the curve order.
///
/// BIP-32 requires this check. Reducing modulo n instead — which is what a `Reduce`
/// conversion would do — maps two distinct HMAC outputs onto the same key, so the
/// canonical `from_repr` is used: it returns `None` rather than wrapping.
fn scalar_in_range(b: &[u8; 32]) -> Option<Scalar> {
    Option::from(Scalar::from_repr((*b).into()))
}

fn compress(point: &ProjectivePoint) -> Option<[u8; PUBKEY_LEN]> {
    let affine = AffinePoint::from(point);
    let pk = PublicKey::from_affine(affine).ok()?;
    let enc = pk.to_sec1_point(true);
    let bytes = enc.as_bytes();
    if bytes.len() != PUBKEY_LEN {
        return None;
    }
    let mut out = [0u8; PUBKEY_LEN];
    out.copy_from_slice(bytes);
    Some(out)
}

impl ExtendedPrivKey {
    /// Derive a master key from a seed.
    ///
    /// `I = HMAC-SHA512("Bitcoin seed", seed)`; the left half is the key, the right the
    /// chain code.
    pub fn from_seed(seed: &[u8], network: Network) -> Result<Self, Error> {
        if !(MIN_SEED_LEN..=MAX_SEED_LEN).contains(&seed.len()) {
            return Err(Error::BadSeedLen { len: seed.len() });
        }
        let mut mac = HmacSha512::new_from_slice(MASTER_KEY_SALT).expect("HMAC takes any key");
        mac.update(seed);
        let i = mac.finalize().into_bytes();

        let mut secret = [0u8; PRIVKEY_LEN];
        secret.copy_from_slice(&i[..32]);
        let mut chain_code = [0u8; CHAIN_CODE_LEN];
        chain_code.copy_from_slice(&i[32..]);

        // A master key outside the curve order is astronomically unlikely but must be
        // rejected rather than reduced.
        if scalar_from_bytes(&secret).is_none() {
            return Err(Error::InvalidKey);
        }

        Ok(Self {
            network,
            depth: 0,
            parent_fingerprint: [0; FINGERPRINT_LEN],
            child_number: ChildNumber::ZERO,
            chain_code,
            secret,
        })
    }

    /// Assemble from already-validated parts. Used by deserialisation.
    pub(crate) fn from_parts(
        network: Network,
        depth: u8,
        parent_fingerprint: [u8; FINGERPRINT_LEN],
        child_number: ChildNumber,
        chain_code: [u8; CHAIN_CODE_LEN],
        secret: [u8; PRIVKEY_LEN],
    ) -> Self {
        Self {
            network,
            depth,
            parent_fingerprint,
            child_number,
            chain_code,
            secret,
        }
    }

    /// The raw 32-byte scalar.
    pub fn secret_bytes(&self) -> &[u8; PRIVKEY_LEN] {
        &self.secret
    }

    /// The matching public key.
    pub fn public_key(&self) -> [u8; PUBKEY_LEN] {
        let scalar = scalar_from_bytes(&self.secret).expect("validated at construction");
        compress(&(ProjectivePoint::GENERATOR * scalar)).expect("scalar is non-zero")
    }

    pub fn identifier(&self) -> [u8; 20] {
        hash160(&self.public_key())
    }

    pub fn fingerprint(&self) -> [u8; FINGERPRINT_LEN] {
        let id = self.identifier();
        let mut out = [0u8; FINGERPRINT_LEN];
        out.copy_from_slice(&id[..FINGERPRINT_LEN]);
        out
    }

    /// Derive one child.
    pub fn derive_child(&self, child: ChildNumber) -> Result<Self, Error> {
        if self.depth == u8::MAX {
            return Err(Error::TooDeep);
        }
        let mut mac = HmacSha512::new_from_slice(&self.chain_code).expect("HMAC takes any key");
        if child.is_hardened() {
            // 0x00 || ser256(k_par) || ser32(i)
            mac.update(&[0u8]);
            mac.update(&self.secret);
        } else {
            // serP(point(k_par)) || ser32(i)
            mac.update(&self.public_key());
        }
        mac.update(&child.to_bytes());
        let i = mac.finalize().into_bytes();

        let mut il = [0u8; 32];
        il.copy_from_slice(&i[..32]);

        // k_i = parse256(I_L) + k_par (mod n); invalid if I_L >= n or k_i == 0.
        let tweak = scalar_in_range(&il).ok_or(Error::UnusableChild { index: child.0 })?;
        let parent = scalar_from_bytes(&self.secret).expect("validated at construction");
        let derived = tweak + parent;
        if bool::from(derived.is_zero()) {
            return Err(Error::UnusableChild { index: child.0 });
        }

        let mut secret = [0u8; PRIVKEY_LEN];
        secret.copy_from_slice(&derived.to_bytes());
        let mut chain_code = [0u8; CHAIN_CODE_LEN];
        chain_code.copy_from_slice(&i[32..]);
        il.zeroize();

        Ok(Self {
            network: self.network,
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(),
            child_number: child,
            chain_code,
            secret,
        })
    }

    /// Derive along a whole path.
    pub fn derive_path(&self, path: &DerivationPath) -> Result<Self, Error> {
        let mut key = self.clone();
        for child in path.iter() {
            key = key.derive_child(child)?;
        }
        Ok(key)
    }

    pub fn to_extended_pub(&self) -> ExtendedPubKey {
        ExtendedPubKey {
            network: self.network,
            depth: self.depth,
            parent_fingerprint: self.parent_fingerprint,
            child_number: self.child_number,
            chain_code: self.chain_code,
            public_key: self.public_key(),
        }
    }
}

impl core::fmt::Debug for ExtendedPrivKey {
    /// Never prints key material.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ExtendedPrivKey(depth {}, child {}, redacted)",
            self.depth, self.child_number.0
        )
    }
}

impl PartialEq for ExtendedPrivKey {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        let secret_eq: bool = self.secret.ct_eq(&other.secret).into();
        let cc_eq: bool = self.chain_code.ct_eq(&other.chain_code).into();
        self.network == other.network
            && self.depth == other.depth
            && self.parent_fingerprint == other.parent_fingerprint
            && self.child_number == other.child_number
            && (secret_eq & cc_eq)
    }
}
impl Eq for ExtendedPrivKey {}

impl ExtendedPubKey {
    pub fn identifier(&self) -> [u8; 20] {
        hash160(&self.public_key)
    }

    pub fn fingerprint(&self) -> [u8; FINGERPRINT_LEN] {
        let id = self.identifier();
        let mut out = [0u8; FINGERPRINT_LEN];
        out.copy_from_slice(&id[..FINGERPRINT_LEN]);
        out
    }

    /// Derive a child public key. Only normal (non-hardened) indices are possible.
    pub fn derive_child(&self, child: ChildNumber) -> Result<Self, Error> {
        if child.is_hardened() {
            return Err(Error::HardenedFromPublic { index: child.0 });
        }
        if self.depth == u8::MAX {
            return Err(Error::TooDeep);
        }

        let mut mac = HmacSha512::new_from_slice(&self.chain_code).expect("HMAC takes any key");
        mac.update(&self.public_key);
        mac.update(&child.to_bytes());
        let i = mac.finalize().into_bytes();

        let mut il = [0u8; 32];
        il.copy_from_slice(&i[..32]);
        let tweak = scalar_in_range(&il).ok_or(Error::UnusableChild { index: child.0 })?;

        let parent = PublicKey::from_sec1_bytes(&self.public_key).map_err(|_| Error::InvalidKey)?;
        let point = ProjectivePoint::from(parent.as_affine()) + ProjectivePoint::GENERATOR * tweak;
        let public_key = compress(&point).ok_or(Error::UnusableChild { index: child.0 })?;

        let mut chain_code = [0u8; CHAIN_CODE_LEN];
        chain_code.copy_from_slice(&i[32..]);

        Ok(Self {
            network: self.network,
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(),
            child_number: child,
            chain_code,
            public_key,
        })
    }

    pub fn derive_path(&self, path: &DerivationPath) -> Result<Self, Error> {
        let mut key = *self;
        for child in path.iter() {
            key = key.derive_child(child)?;
        }
        Ok(key)
    }
}

impl core::fmt::Debug for ExtendedPubKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ExtendedPubKey(depth {}, child {})",
            self.depth, self.child_number.0
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_vectors::VECTORS;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn official_vectors_private_derivation() {
        for (n, v) in VECTORS.iter().enumerate() {
            let master = ExtendedPrivKey::from_seed(&unhex(v.seed), Network::Mainnet).unwrap();
            for (path_str, _, want_xprv) in v.chains {
                let path: DerivationPath = path_str.parse().unwrap();
                let key = master.derive_path(&path).unwrap();
                assert_eq!(
                    key.to_base58(),
                    *want_xprv,
                    "vector {} path {path_str}",
                    n + 1
                );
            }
        }
    }

    #[test]
    fn official_vectors_public_serialisation() {
        for (n, v) in VECTORS.iter().enumerate() {
            let master = ExtendedPrivKey::from_seed(&unhex(v.seed), Network::Mainnet).unwrap();
            for (path_str, want_xpub, _) in v.chains {
                let path: DerivationPath = path_str.parse().unwrap();
                let key = master.derive_path(&path).unwrap();
                assert_eq!(
                    key.to_extended_pub().to_base58(),
                    *want_xpub,
                    "vector {} path {path_str}",
                    n + 1
                );
            }
        }
    }

    /// Public-only derivation must reach the same key as private derivation, for every
    /// non-hardened step in the official vectors. This is the property watch-only
    /// wallets depend on.
    #[test]
    fn public_derivation_agrees_with_private() {
        for v in VECTORS {
            let master = ExtendedPrivKey::from_seed(&unhex(v.seed), Network::Mainnet).unwrap();
            for (path_str, want_xpub, _) in v.chains {
                let path: DerivationPath = path_str.parse().unwrap();
                if path.iter().any(|c| c.is_hardened()) {
                    continue;
                }
                let via_public = master.to_extended_pub().derive_path(&path).unwrap();
                assert_eq!(via_public.to_base58(), *want_xpub, "path {path_str}");
            }
        }
    }

    #[test]
    fn hardened_derivation_from_a_public_key_is_refused() {
        let master = ExtendedPrivKey::from_seed(&[0x42; 32], Network::Mainnet).unwrap();
        let xpub = master.to_extended_pub();
        assert_eq!(
            xpub.derive_child(ChildNumber::hardened(0).unwrap()),
            Err(Error::HardenedFromPublic {
                index: HARDENED_OFFSET
            })
        );
    }

    #[test]
    fn seed_length_bounds_are_enforced() {
        for len in [0usize, 15, 65, 128] {
            assert_eq!(
                ExtendedPrivKey::from_seed(&vec![7u8; len], Network::Mainnet),
                Err(Error::BadSeedLen { len })
            );
        }
        assert!(ExtendedPrivKey::from_seed(&[7u8; 16], Network::Mainnet).is_ok());
        assert!(ExtendedPrivKey::from_seed(&[7u8; 64], Network::Mainnet).is_ok());
    }

    #[test]
    fn fingerprints_chain_correctly() {
        let master = ExtendedPrivKey::from_seed(&unhex(VECTORS[0].seed), Network::Mainnet).unwrap();
        assert_eq!(master.parent_fingerprint, [0; 4]);
        assert_eq!(master.depth, 0);

        let child = master
            .derive_child(ChildNumber::hardened(0).unwrap())
            .unwrap();
        assert_eq!(child.depth, 1);
        assert_eq!(child.parent_fingerprint, master.fingerprint());

        let grand = child.derive_child(ChildNumber::normal(1).unwrap()).unwrap();
        assert_eq!(grand.depth, 2);
        assert_eq!(grand.parent_fingerprint, child.fingerprint());
    }

    #[test]
    fn xprv_and_xpub_agree_on_identity() {
        let master = ExtendedPrivKey::from_seed(&unhex(VECTORS[0].seed), Network::Mainnet).unwrap();
        let xpub = master.to_extended_pub();
        assert_eq!(master.identifier(), xpub.identifier());
        assert_eq!(master.fingerprint(), xpub.fingerprint());
    }

    #[test]
    fn hardened_and_normal_children_differ() {
        let master = ExtendedPrivKey::from_seed(&unhex(VECTORS[0].seed), Network::Mainnet).unwrap();
        let h = master
            .derive_child(ChildNumber::hardened(0).unwrap())
            .unwrap();
        let n = master
            .derive_child(ChildNumber::normal(0).unwrap())
            .unwrap();
        assert_ne!(h.secret_bytes(), n.secret_bytes());
        assert_ne!(h.chain_code, n.chain_code);
    }

    #[test]
    fn debug_does_not_leak_key_material() {
        let master = ExtendedPrivKey::from_seed(&unhex(VECTORS[0].seed), Network::Mainnet).unwrap();
        let s = format!("{master:?}");
        assert!(s.contains("redacted"));

        // Check 4-byte windows, not individual bytes: a two-character hex string like
        // "ed" occurs in ordinary English ("redacted"), so a per-byte check reports
        // leaks that are not leaks.
        let hex: String = master
            .secret_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        for w in hex.as_bytes().windows(8) {
            let window = core::str::from_utf8(w).unwrap();
            assert!(!s.contains(window), "leaked {window} in {s}");
        }
        assert!(!s.contains(&hex), "leaked the whole secret");
    }

    #[test]
    fn scalar_range_check_rejects_values_at_or_above_the_order() {
        // secp256k1 group order.
        let n = unhex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        let mut b = [0u8; 32];
        b.copy_from_slice(&n);
        assert!(
            scalar_in_range(&b).is_none(),
            "order itself must be rejected"
        );
        b[31] = 0x40; // n - 1
        assert!(scalar_in_range(&b).is_some());
        assert!(scalar_in_range(&[0xff; 32]).is_none());
        assert!(
            scalar_in_range(&[0u8; 32]).is_some(),
            "zero is in range, if unusable"
        );
    }

    #[test]
    fn hash160_is_ripemd_of_sha256() {
        let data = b"catcard";
        let expect: [u8; 20] = Ripemd160::digest(Sha256::digest(data)).into();
        assert_eq!(hash160(data), expect);
    }
}
