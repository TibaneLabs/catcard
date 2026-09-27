//! Credential keys, derived from the wallet and never stored.
//!
//! # The derivation
//!
//! ```text
//! master     = HMAC-SHA512(key = "CatCard FIDO v1",
//!                          msg = chain_code ‖ private_key ‖ generation_be32)
//!              of the wallet in force's BIP-32 master node (m)
//! mac_key    = master[0..32]
//! key_key    = master[32..64]
//!
//! credential id (33 bytes) = 0x01 ‖ nonce(16) ‖ tag(16)
//!   nonce  = 16 bytes from the device's DRBG, fresh per registration
//!   tag    = HMAC-SHA256(mac_key, "id" ‖ 0x01 ‖ rpIdHash ‖ nonce)[0..16]
//!
//! private key = the first d_i with 1 <= d_i < n, i = 0, 1, ...:
//!   d_i = HMAC-SHA256(key_key, "key" ‖ 0x01 ‖ rpIdHash ‖ nonce ‖ i)  (big-endian)
//! ```
//!
//! **Nothing is kept on the device.** A credential id carries everything needed to
//! recompute its key -- given the same wallet -- and a MAC that says whether it was made
//! by this wallet, for this site. So:
//!
//! - The same seed and passphrase on another CatCard answers for every site registered
//!   here. A lost device is recovered by restoring the seed, like the wallet itself.
//! - A passphrase wallet, a BIP-85 child, an imported XPRV: each is its own master node,
//!   so each is its own security key. A credential id made under one fails the MAC under
//!   every other and is simply not ours.
//! - `generation` is a per-wallet number kept in the wallet's settings. A reset raises it,
//!   and every credential id made before fails the MAC from then on: that is the whole of
//!   `authenticatorReset` here, and it cannot be undone except by writing the old number
//!   back.
//!
//! # Separation from every Bitcoin key
//!
//! No BIP-32 step keys HMAC-SHA512 with anything but `"Bitcoin seed"` (for the master)
//! or a chain code (for a child), and no BIP-85 application uses this label; so `master`
//! is an independent function of the node, and knowing any number of FIDO keys says
//! nothing about the wallet's. The HMAC is one-way: the FIDO master reveals nothing
//! about the node either.
//!
//! # The retry rule
//!
//! A uniformly random 256-bit value is at or above the P-256 group order with probability
//! about 2^-32, and zero with probability 2^-256. Such a value is not reduced (reducing
//! would make two derivations land on one key); the counter moves on and the next is
//! tried. [`MAX_TRIES`] bounds it, at a failure probability no device will meet. Whether
//! a retry happened is the one thing this leaks through timing, and it happens once in
//! four billion registrations.

use catcard_wallet::KeyWork;
use catcard_wallet::bip32::ExtendedPrivKey;
use purecrypto::ct::ConstantTimeEq;
use purecrypto::ec::ecdsa::EcdsaPrivateKey;
use purecrypto::hash::{Digest, HmacSha256, HmacSha512, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The HMAC key that sets the FIDO master apart from every other use of the node.
pub const MASTER_LABEL: &[u8] = b"CatCard FIDO v1";
/// The first byte of every credential id this device makes.
pub const CRED_VERSION: u8 = 0x01;
pub const NONCE_LEN: usize = 16;
pub const TAG_LEN: usize = 16;
/// A credential id's length: version, nonce, tag. Also the U2F key handle.
pub const CRED_ID_LEN: usize = 1 + NONCE_LEN + TAG_LEN;
/// Candidates tried for a private key before giving up. See the module notes.
pub const MAX_TRIES: u8 = 16;

/// The FIDO master of one wallet at one generation.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Master {
    mac: [u8; 32],
    key: [u8; 32],
}

impl Master {
    /// From the wallet in force's master node.
    pub fn derive(root: &ExtendedPrivKey, generation: u32, kw: &KeyWork) -> Master {
        Self::from_parts(&root.chain_code, root.secret_bytes(), generation, kw)
    }

    /// From a node's chain code and private key, as [`derive`](Self::derive) takes them.
    pub fn from_parts(
        chain_code: &[u8; 32],
        secret: &[u8; 32],
        generation: u32,
        _kw: &KeyWork,
    ) -> Master {
        let mut h = HmacSha512::new(MASTER_LABEL);
        h.update(chain_code);
        h.update(secret);
        h.update(&generation.to_be_bytes());
        let mut out = h.finalize();
        let mut m = Master {
            mac: [0; 32],
            key: [0; 32],
        };
        m.mac.copy_from_slice(&out[..32]);
        m.key.copy_from_slice(&out[32..]);
        out.zeroize();
        m
    }

    fn tag(&self, rp_id_hash: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> [u8; 32] {
        let mut h = HmacSha256::new(&self.mac);
        h.update(b"id");
        h.update(&[CRED_VERSION]);
        h.update(rp_id_hash);
        h.update(nonce);
        h.finalize()
    }

    /// A new credential id for the site whose `rpIdHash` (U2F: application parameter)
    /// this is, from a fresh random `nonce`.
    pub fn credential_id(
        &self,
        rp_id_hash: &[u8; 32],
        nonce: &[u8; NONCE_LEN],
        _kw: &KeyWork,
    ) -> [u8; CRED_ID_LEN] {
        let mut id = [0u8; CRED_ID_LEN];
        id[0] = CRED_VERSION;
        id[1..1 + NONCE_LEN].copy_from_slice(nonce);
        let mut t = self.tag(rp_id_hash, nonce);
        id[1 + NONCE_LEN..].copy_from_slice(&t[..TAG_LEN]);
        t.zeroize();
        id
    }

    /// The nonce inside `id`, if `id` is a credential this wallet made for this site.
    ///
    /// The length and version byte are public and checked first; the tag is compared in
    /// constant time, so a host guessing tags learns nothing from how long a wrong one
    /// took.
    pub fn owns(&self, rp_id_hash: &[u8; 32], id: &[u8], _kw: &KeyWork) -> Option<[u8; NONCE_LEN]> {
        if id.len() != CRED_ID_LEN || id[0] != CRED_VERSION {
            return None;
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&id[1..1 + NONCE_LEN]);
        let mut t = self.tag(rp_id_hash, &nonce);
        let ok = bool::from(t[..TAG_LEN].ct_eq(&id[1 + NONCE_LEN..]));
        t.zeroize();
        ok.then_some(nonce)
    }

    /// The key this wallet's passkey file is sealed under, and the eight bytes that name
    /// the file ([`crate::passkeys`]). HMACs of the MAC half under labels no credential id
    /// uses, so neither says anything about a credential, or the other.
    pub fn passkey_key(&self, _kw: &KeyWork) -> crate::passkeys::PasskeyKey {
        let mac = |label: &[u8]| {
            let mut h = HmacSha256::new(&self.mac);
            h.update(b"passkeys");
            h.update(&[CRED_VERSION]);
            h.update(label);
            h.finalize()
        };
        let mut enc = mac(b"enc");
        let mut auth = mac(b"mac");
        let mut name = mac(b"name");
        let mut k = crate::passkeys::PasskeyKey {
            enc: [0; 32],
            mac: [0; 32],
            name: [0; 8],
        };
        k.enc.copy_from_slice(&enc);
        k.mac.copy_from_slice(&auth);
        k.name.copy_from_slice(&name[..8]);
        enc.zeroize();
        auth.zeroize();
        name.zeroize();
        k
    }

    /// The credential's signing key. `None` only after [`MAX_TRIES`] out-of-range
    /// candidates in a row, which does not happen.
    pub fn signing_key(
        &self,
        rp_id_hash: &[u8; 32],
        nonce: &[u8; NONCE_LEN],
        _kw: &KeyWork,
    ) -> Option<SigningKey> {
        for i in 0..MAX_TRIES {
            let mut h = HmacSha256::new(&self.key);
            h.update(b"key");
            h.update(&[CRED_VERSION]);
            h.update(rp_id_hash);
            h.update(nonce);
            h.update(&[i]);
            let mut d = h.finalize();
            let k = EcdsaPrivateKey::from_bytes(&d);
            d.zeroize();
            if let Ok(k) = k {
                return Some(SigningKey(k));
            }
        }
        None
    }
}

/// One credential's P-256 private key. Wiped on drop (by `purecrypto`'s own `Drop`).
pub struct SigningKey(EcdsaPrivateKey);

impl SigningKey {
    /// The public key as an uncompressed SEC 1 point, `04 ‖ x ‖ y`.
    pub fn public_sec1(&self, _kw: &KeyWork) -> [u8; 65] {
        self.0.public_key().to_sec1()
    }

    /// ES256 over the concatenation of `parts`: SHA-256, then ECDSA with an RFC 6979
    /// deterministic nonce -- no randomness is needed, and none can leak the key. Returns
    /// `(r, s)`, big-endian.
    ///
    /// Constant-time as `purecrypto` implements it: the fixed-base multiplication is a
    /// windowed ladder with masked table reads, and the nonce inverse is a Fermat
    /// exponentiation, never the variable-time extended Euclid.
    pub fn sign(&self, parts: &[&[u8]], _kw: &KeyWork) -> Option<([u8; 32], [u8; 32])> {
        let mut h = Sha256::new();
        for p in parts {
            h.update(p);
        }
        let digest = h.finalize();
        let sig = self.0.sign_prehash::<Sha256>(&digest).ok()?;
        Some((sig.r_bytes(), sig.s_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use purecrypto::ec::ecdsa::{EcdsaPublicKey, Signature};

    fn kw() -> KeyWork {
        KeyWork::host()
    }

    fn master(generation: u32) -> Master {
        Master::from_parts(&[7; 32], &[9; 32], generation, &kw())
    }

    #[test]
    fn a_credential_id_opens_under_its_own_wallet_site_and_generation_only() {
        let m = master(0);
        let rp = Sha256::digest(b"example.com");
        let nonce = [3u8; 16];
        let id = m.credential_id(&rp, &nonce, &kw());
        assert_eq!(id.len(), 33);
        assert_eq!(id[0], CRED_VERSION);
        assert_eq!(m.owns(&rp, &id, &kw()), Some(nonce));

        // Another site.
        let other_rp = Sha256::digest(b"example.org");
        assert_eq!(m.owns(&other_rp, &id, &kw()), None);
        // Another wallet: a passphrase, a BIP-85 child -- any other node.
        let other = Master::from_parts(&[7; 32], &[8; 32], 0, &kw());
        assert_eq!(other.owns(&rp, &id, &kw()), None);
        // The same wallet after a reset.
        assert_eq!(master(1).owns(&rp, &id, &kw()), None);
        // Tampered anywhere, or the wrong length or version.
        for i in 0..id.len() {
            let mut bad = id;
            bad[i] ^= 1;
            assert_eq!(m.owns(&rp, &bad, &kw()), None, "byte {i}");
        }
        assert_eq!(m.owns(&rp, &id[..32], &kw()), None);
        let mut longer = id.to_vec();
        longer.push(0);
        assert_eq!(m.owns(&rp, &longer, &kw()), None);
    }

    #[test]
    fn the_key_is_a_function_of_wallet_site_and_nonce_and_it_signs() {
        let m = master(0);
        let rp = Sha256::digest(b"example.com");
        let k1 = m.signing_key(&rp, &[1; 16], &kw()).unwrap();
        let k1b = m.signing_key(&rp, &[1; 16], &kw()).unwrap();
        let k2 = m.signing_key(&rp, &[2; 16], &kw()).unwrap();
        let k3 = master(1).signing_key(&rp, &[1; 16], &kw()).unwrap();
        let p1 = k1.public_sec1(&kw());
        assert_eq!(p1, k1b.public_sec1(&kw()), "deterministic");
        assert_ne!(p1, k2.public_sec1(&kw()));
        assert_ne!(p1, k3.public_sec1(&kw()));
        assert_eq!(p1[0], 0x04);

        let (r, s) = k1.sign(&[b"auth", b"data"], &kw()).unwrap();
        let pk = EcdsaPublicKey::from_sec1(&p1).unwrap();
        pk.verify::<Sha256>(b"authdata", &Signature::from_components(&r, &s))
            .unwrap();
        assert!(
            pk.verify::<Sha256>(b"authdatb", &Signature::from_components(&r, &s))
                .is_err()
        );
        // RFC 6979: the same message signs the same way.
        assert_eq!(k1.sign(&[b"authdata"], &kw()), Some((r, s)));
    }

    /// One vector cross-checked outside this code: Python's `hmac`/`hashlib` for the
    /// derivation and `cryptography` 50.0.1 (OpenSSL) for the key and for an RFC 6979
    /// deterministic signature, which came out byte-identical. Re-run with the snippet
    /// in `docs/FIDO.md` §"Checking the derivation".
    #[test]
    fn a_vector_cross_checked_with_python_cryptography() {
        let kw = KeyWork::host();
        let m = Master::from_parts(&[7; 32], &[9; 32], 0, &kw);
        let rp = Sha256::digest(b"example.com");
        let id = m.credential_id(&rp, &[0x11; 16], &kw);
        let k = m.signing_key(&rp, &[0x11; 16], &kw).unwrap();
        let (r, s) = k.sign(&[b"catcard fido vector"], &kw).unwrap();
        let h = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(
            h(&id),
            "0111111111111111111111111111111111b1046afa0d51e09005b172beb4269978"
        );
        assert_eq!(
            h(&k.public_sec1(&kw)),
            concat!(
                "04c3412cc4ff6b78f18a0f505c9fc0a4c8cd1ba04d1aea463e94cfc775e9f4796d",
                "0008a044930bb5f4de9fbba9fad7028c6bf1fbd41715aab22707d6d29c3c72c4"
            )
        );
        assert_eq!(
            h(&r),
            "29a507668fcf1f2ea0e1f7d14ff261782cb5f03134926877dd0a7ed85ae311ef"
        );
        assert_eq!(
            h(&s),
            "d1b890ed8be0b4452d16a5c71eb30656474d9ab3c19111205584eeb8ed724291"
        );
    }

    /// The derivation, pinned: these bytes are what a restored seed on another device
    /// must reproduce, so any change to the construction shows up here as a failure
    /// rather than as every registered site quietly stopping working.
    #[test]
    fn the_derivation_is_pinned() {
        let m = master(0);
        let rp = Sha256::digest(b"example.com");
        let id = m.credential_id(&rp, &[0x11; 16], &kw());
        let pk = m
            .signing_key(&rp, &[0x11; 16], &kw())
            .unwrap()
            .public_sec1(&kw());
        // Independently: HMAC-SHA512 and HMAC-SHA256 as the module notes spell them.
        let mut msg = Vec::new();
        msg.extend_from_slice(&[7; 32]);
        msg.extend_from_slice(&[9; 32]);
        msg.extend_from_slice(&0u32.to_be_bytes());
        let master = HmacSha512::mac(MASTER_LABEL, &msg);
        let mut t = Vec::new();
        t.extend_from_slice(b"id\x01");
        t.extend_from_slice(&rp);
        t.extend_from_slice(&[0x11; 16]);
        let tag = HmacSha256::mac(&master[..32], &t);
        assert_eq!(&id[17..], &tag[..16]);
        let mut k = Vec::new();
        k.extend_from_slice(b"key\x01");
        k.extend_from_slice(&rp);
        k.extend_from_slice(&[0x11; 16]);
        k.push(0);
        let d = HmacSha256::mac(&master[32..], &k);
        let expect = EcdsaPrivateKey::from_bytes(&d)
            .unwrap()
            .public_key()
            .to_sec1();
        assert_eq!(pk, expect);
    }
}
