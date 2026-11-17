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
//! credential id (33 bytes) = v ‖ nonce(16) ‖ tag(16)
//!   v      = 0x01 for ES256, 0x02 for EdDSA (the credential's algorithm)
//!   nonce  = 16 bytes from the device's DRBG, fresh per registration
//!   tag    = HMAC-SHA256(mac_key, "id" ‖ v ‖ rpIdHash ‖ nonce)[0..16]
//!
//! ES256 private key = the first d_i with 1 <= d_i < n, i = 0, 1, ...:
//!   d_i = HMAC-SHA256(key_key, "key" ‖ 0x01 ‖ rpIdHash ‖ nonce ‖ i)  (big-endian)
//!
//! EdDSA private key (an RFC 8032 Ed25519 seed; every 32-byte string is one):
//!   seed = HMAC-SHA256(key_key, "key" ‖ 0x02 ‖ rpIdHash ‖ nonce ‖ 0x00)
//! ```
//!
//! # The algorithm is part of the credential
//!
//! The version byte says which algorithm a credential id is for, and it is inside the
//! tag's MAC, so a host cannot turn an ES256 id into an EdDSA one by changing the byte:
//! the tag fails. The byte is also in the key derivation, so the two algorithms never
//! derive from the same HMAC output -- one nonce under both would give unrelated keys.
//! An ES256 id is byte for byte what it was before EdDSA existed, so every site already
//! registered keeps working.
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
use purecrypto::ec::ed25519::Ed25519PrivateKey;
use purecrypto::hash::{Digest, HmacSha256, HmacSha512, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The HMAC key that sets the FIDO master apart from every other use of the node.
pub const MASTER_LABEL: &[u8] = b"CatCard FIDO v1";
/// The first byte of an ES256 credential id, and of every one made before EdDSA.
pub const CRED_VERSION: u8 = 0x01;
/// The first byte of an EdDSA (Ed25519) credential id.
pub const CRED_VERSION_EDDSA: u8 = 0x02;
pub const NONCE_LEN: usize = 16;
pub const TAG_LEN: usize = 16;
/// A credential id's length: version, nonce, tag. Also the U2F key handle.
pub const CRED_ID_LEN: usize = 1 + NONCE_LEN + TAG_LEN;
/// Candidates tried for a private key before giving up. See the module notes.
pub const MAX_TRIES: u8 = 16;

/// A credential's signature algorithm. Source: RFC 9053 §2.1 (ES256, -7) and RFC 8152
/// §8.2 / RFC 9053 §2.2 (EdDSA, -8, Ed25519 on OKP curve 6); WebAuthn L2 §5.8.5 [C]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Alg {
    /// ECDSA over P-256 with SHA-256. What every credential was before EdDSA.
    Es256,
    /// PureEdDSA over Ed25519 (RFC 8032 §5.1). OpenSSH's `ed25519-sk`.
    EdDsa,
}

impl Alg {
    /// Preferred first: GetInfo's `algorithms` lists them in this order.
    pub const ALL: [Alg; 2] = [Alg::Es256, Alg::EdDsa];

    /// The COSE algorithm identifier.
    pub const fn cose(self) -> i64 {
        match self {
            Alg::Es256 => -7,
            Alg::EdDsa => -8,
        }
    }

    /// The algorithm a COSE identifier names, if this device does it.
    pub const fn from_cose(alg: i64) -> Option<Alg> {
        match alg {
            -7 => Some(Alg::Es256),
            -8 => Some(Alg::EdDsa),
            _ => None,
        }
    }

    /// The credential id's first byte.
    pub const fn version(self) -> u8 {
        match self {
            Alg::Es256 => CRED_VERSION,
            Alg::EdDsa => CRED_VERSION_EDDSA,
        }
    }

    /// The algorithm a credential id's first byte names.
    pub const fn from_version(v: u8) -> Option<Alg> {
        match v {
            CRED_VERSION => Some(Alg::Es256),
            CRED_VERSION_EDDSA => Some(Alg::EdDsa),
            _ => None,
        }
    }
}

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

    fn tag(&self, alg: Alg, rp_id_hash: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> [u8; 32] {
        let mut h = HmacSha256::new(&self.mac);
        h.update(b"id");
        h.update(&[alg.version()]);
        h.update(rp_id_hash);
        h.update(nonce);
        h.finalize()
    }

    /// A new `alg` credential id for the site whose `rpIdHash` (U2F: application
    /// parameter) this is, from a fresh random `nonce`.
    pub fn credential_id(
        &self,
        alg: Alg,
        rp_id_hash: &[u8; 32],
        nonce: &[u8; NONCE_LEN],
        _kw: &KeyWork,
    ) -> [u8; CRED_ID_LEN] {
        let mut id = [0u8; CRED_ID_LEN];
        id[0] = alg.version();
        id[1..1 + NONCE_LEN].copy_from_slice(nonce);
        let mut t = self.tag(alg, rp_id_hash, nonce);
        id[1 + NONCE_LEN..].copy_from_slice(&t[..TAG_LEN]);
        t.zeroize();
        id
    }

    /// The algorithm and nonce inside `id`, if `id` is a credential this wallet made for
    /// this site.
    ///
    /// The length and version byte are public and checked first; the tag is compared in
    /// constant time, so a host guessing tags learns nothing from how long a wrong one
    /// took.
    pub fn owns(
        &self,
        rp_id_hash: &[u8; 32],
        id: &[u8],
        _kw: &KeyWork,
    ) -> Option<(Alg, [u8; NONCE_LEN])> {
        if id.len() != CRED_ID_LEN {
            return None;
        }
        let alg = Alg::from_version(id[0])?;
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&id[1..1 + NONCE_LEN]);
        let mut t = self.tag(alg, rp_id_hash, &nonce);
        let ok = bool::from(t[..TAG_LEN].ct_eq(&id[1 + NONCE_LEN..]));
        t.zeroize();
        ok.then_some((alg, nonce))
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

    fn candidate(
        &self,
        alg: Alg,
        rp_id_hash: &[u8; 32],
        nonce: &[u8; NONCE_LEN],
        i: u8,
    ) -> [u8; 32] {
        let mut h = HmacSha256::new(&self.key);
        h.update(b"key");
        h.update(&[alg.version()]);
        h.update(rp_id_hash);
        h.update(nonce);
        h.update(&[i]);
        h.finalize()
    }

    /// The credential's signing key. `None` only for ES256 after [`MAX_TRIES`]
    /// out-of-range candidates in a row, which does not happen; an Ed25519 seed has no
    /// range to miss.
    pub fn signing_key(
        &self,
        alg: Alg,
        rp_id_hash: &[u8; 32],
        nonce: &[u8; NONCE_LEN],
        _kw: &KeyWork,
    ) -> Option<SigningKey> {
        match alg {
            Alg::Es256 => {
                for i in 0..MAX_TRIES {
                    let mut d = self.candidate(alg, rp_id_hash, nonce, i);
                    let k = EcdsaPrivateKey::from_bytes(&d);
                    d.zeroize();
                    if let Ok(k) = k {
                        return Some(SigningKey::Es256(k));
                    }
                }
                None
            }
            Alg::EdDsa => {
                // `from_bytes` takes the seed by value: the copy it keeps is wiped by its
                // own `Drop`, and this one here.
                let mut seed = self.candidate(alg, rp_id_hash, nonce, 0);
                let k = Ed25519PrivateKey::from_bytes(seed);
                seed.zeroize();
                Some(SigningKey::EdDsa(k))
            }
        }
    }
}

/// The longest message [`SigningKey::sign`] takes for EdDSA, which signs the message
/// itself rather than a hash of it: a MakeCredential's authenticator data and its
/// clientDataHash, the longest thing signed here, with room to spare.
pub const EDDSA_MSG_MAX: usize = 256;

/// The longest signature [`SigningKey::sign`] writes: an ES256 DER signature, which is
/// longer than EdDSA's 64 bytes.
pub const SIG_MAX: usize = crate::der::SIG_MAX;
const _: () = assert!(SIG_MAX >= 64);

/// One credential's private key. Wiped on drop (by `purecrypto`'s own `Drop` for both).
pub enum SigningKey {
    Es256(EcdsaPrivateKey),
    EdDsa(Ed25519PrivateKey),
}

/// A credential's public key, as the wire formats need it.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum PublicKey {
    /// An uncompressed SEC 1 point, `04 ‖ x ‖ y`.
    Es256([u8; 65]),
    /// An RFC 8032 encoded Ed25519 point.
    EdDsa([u8; 32]),
}

impl SigningKey {
    pub fn alg(&self) -> Alg {
        match self {
            SigningKey::Es256(_) => Alg::Es256,
            SigningKey::EdDsa(_) => Alg::EdDsa,
        }
    }

    pub fn public(&self, _kw: &KeyWork) -> PublicKey {
        match self {
            SigningKey::Es256(k) => PublicKey::Es256(k.public_key().to_sec1()),
            SigningKey::EdDsa(k) => PublicKey::EdDsa(k.public_key().to_bytes()),
        }
    }

    /// Sign the concatenation of `parts` into `out`, encoded as WebAuthn wants each
    /// algorithm's signature (§6.5.5): ES256 as a DER `Ecdsa-Sig-Value`, EdDSA as the raw
    /// 64 bytes `R ‖ S`. The signature's length; `None` if signing failed, or for EdDSA
    /// if the message is longer than [`EDDSA_MSG_MAX`].
    ///
    /// Both are deterministic -- RFC 6979 nonces for ES256, RFC 8032's hashed nonce for
    /// EdDSA -- so no randomness is needed, and none can leak the key. Constant-time as
    /// `purecrypto` implements them: the fixed-base multiplications are ladders with
    /// masked table reads, and the ES256 nonce inverse is a Fermat exponentiation, never
    /// the variable-time extended Euclid.
    pub fn sign(&self, parts: &[&[u8]], out: &mut [u8; SIG_MAX], _kw: &KeyWork) -> Option<usize> {
        match self {
            SigningKey::Es256(k) => {
                let mut h = Sha256::new();
                for p in parts {
                    h.update(p);
                }
                let digest = h.finalize();
                let sig = k.sign_prehash::<Sha256>(&digest).ok()?;
                Some(crate::der::signature(&sig.r_bytes(), &sig.s_bytes(), out))
            }
            SigningKey::EdDsa(k) => {
                // PureEdDSA hashes the message twice, so it has to be in one piece. The
                // message is public (authenticator data and a client data hash); only
                // its length is checked, and that is fixed by the request's shape.
                let mut msg = [0u8; EDDSA_MSG_MAX];
                let mut n = 0;
                for p in parts {
                    msg.get_mut(n..n + p.len())?.copy_from_slice(p);
                    n += p.len();
                }
                out[..64].copy_from_slice(&k.sign(&msg[..n]).to_bytes());
                Some(64)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use purecrypto::ec::ecdsa::{EcdsaPublicKey, Signature};
    use purecrypto::ec::ed25519::{Ed25519PublicKey, Ed25519Signature};

    fn kw() -> KeyWork {
        KeyWork::host()
    }

    fn master(generation: u32) -> Master {
        Master::from_parts(&[7; 32], &[9; 32], generation, &kw())
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn sec1(k: &SigningKey) -> [u8; 65] {
        match k.public(&kw()) {
            PublicKey::Es256(p) => p,
            PublicKey::EdDsa(_) => panic!("not ES256"),
        }
    }

    fn ed(k: &SigningKey) -> [u8; 32] {
        match k.public(&kw()) {
            PublicKey::EdDsa(p) => p,
            PublicKey::Es256(_) => panic!("not EdDSA"),
        }
    }

    /// `(r, s)` out of the DER `SEQUENCE { INTEGER r, INTEGER s }` ES256 signs into.
    fn rs(der: &[u8]) -> ([u8; 32], [u8; 32]) {
        assert_eq!(der[0], 0x30);
        assert_eq!(der[1] as usize, der.len() - 2);
        let mut at = 2;
        let mut out = [[0u8; 32]; 2];
        for v in &mut out {
            assert_eq!(der[at], 0x02);
            let n = der[at + 1] as usize;
            let int = &der[at + 2..at + 2 + n];
            let int = if int.len() == 33 { &int[1..] } else { int };
            v[32 - int.len()..].copy_from_slice(int);
            at += 2 + n;
        }
        assert_eq!(at, der.len());
        (out[0], out[1])
    }

    fn sign(k: &SigningKey, parts: &[&[u8]]) -> Vec<u8> {
        let mut sig = [0u8; SIG_MAX];
        let n = k.sign(parts, &mut sig, &kw()).unwrap();
        sig[..n].to_vec()
    }

    #[test]
    fn a_credential_id_opens_under_its_own_wallet_site_generation_and_algorithm_only() {
        let m = master(0);
        let rp = Sha256::digest(b"example.com");
        let nonce = [3u8; 16];
        for alg in Alg::ALL {
            let id = m.credential_id(alg, &rp, &nonce, &kw());
            assert_eq!(id.len(), 33);
            assert_eq!(id[0], alg.version());
            assert_eq!(m.owns(&rp, &id, &kw()), Some((alg, nonce)));

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
    }

    /// The version byte is under the MAC: an ES256 id relabelled EdDSA (or back) is not
    /// ours, so a host cannot make the device sign with the other algorithm's key.
    #[test]
    fn the_algorithm_cannot_be_swapped_on_an_id() {
        let m = master(0);
        let rp = Sha256::digest(b"example.com");
        let es = m.credential_id(Alg::Es256, &rp, &[5; 16], &kw());
        let ed = m.credential_id(Alg::EdDsa, &rp, &[5; 16], &kw());
        assert_ne!(es[17..], ed[17..], "different tags for the same nonce");
        let mut swapped = es;
        swapped[0] = CRED_VERSION_EDDSA;
        assert_eq!(m.owns(&rp, &swapped, &kw()), None);
        let mut swapped = ed;
        swapped[0] = CRED_VERSION;
        assert_eq!(m.owns(&rp, &swapped, &kw()), None);
        let mut unknown = es;
        unknown[0] = 0x03;
        assert_eq!(m.owns(&rp, &unknown, &kw()), None);
    }

    #[test]
    fn the_key_is_a_function_of_wallet_site_and_nonce_and_it_signs() {
        let m = master(0);
        let rp = Sha256::digest(b"example.com");
        let k1 = m.signing_key(Alg::Es256, &rp, &[1; 16], &kw()).unwrap();
        let k1b = m.signing_key(Alg::Es256, &rp, &[1; 16], &kw()).unwrap();
        let k2 = m.signing_key(Alg::Es256, &rp, &[2; 16], &kw()).unwrap();
        let k3 = master(1)
            .signing_key(Alg::Es256, &rp, &[1; 16], &kw())
            .unwrap();
        let p1 = sec1(&k1);
        assert_eq!(p1, sec1(&k1b), "deterministic");
        assert_ne!(p1, sec1(&k2));
        assert_ne!(p1, sec1(&k3));
        assert_eq!(p1[0], 0x04);
        assert_eq!(k1.alg(), Alg::Es256);

        let (r, s) = rs(&sign(&k1, &[b"auth", b"data"]));
        let pk = EcdsaPublicKey::from_sec1(&p1).unwrap();
        pk.verify::<Sha256>(b"authdata", &Signature::from_components(&r, &s))
            .unwrap();
        assert!(
            pk.verify::<Sha256>(b"authdatb", &Signature::from_components(&r, &s))
                .is_err()
        );
        // RFC 6979: the same message signs the same way.
        assert_eq!(rs(&sign(&k1, &[b"authdata"])), (r, s));
    }

    #[test]
    fn an_eddsa_key_is_a_function_of_wallet_site_and_nonce_and_it_signs() {
        let m = master(0);
        let rp = Sha256::digest(b"example.com");
        let k1 = m.signing_key(Alg::EdDsa, &rp, &[1; 16], &kw()).unwrap();
        let k1b = m.signing_key(Alg::EdDsa, &rp, &[1; 16], &kw()).unwrap();
        let k2 = m.signing_key(Alg::EdDsa, &rp, &[2; 16], &kw()).unwrap();
        let k3 = master(1)
            .signing_key(Alg::EdDsa, &rp, &[1; 16], &kw())
            .unwrap();
        let p1 = ed(&k1);
        assert_eq!(p1, ed(&k1b), "deterministic");
        assert_ne!(p1, ed(&k2));
        assert_ne!(p1, ed(&k3));
        assert_eq!(k1.alg(), Alg::EdDsa);

        let sig = sign(&k1, &[b"auth", b"data"]);
        assert_eq!(sig.len(), 64, "raw R || S, not DER");
        let pk = Ed25519PublicKey::from_bytes(p1);
        let sig = Ed25519Signature::from_bytes(sig.try_into().unwrap());
        pk.verify(b"authdata", &sig).unwrap();
        assert!(pk.verify(b"authdatb", &sig).is_err());
        // Pieces or one slice: the same message.
        assert_eq!(
            sign(&k1, &[b"authdata"]),
            sign(&k1, &[b"au", b"th", b"", b"data"])
        );
        // Longer than the buffer: refused, not cut.
        let long = [0u8; EDDSA_MSG_MAX + 1];
        let mut out = [0u8; SIG_MAX];
        assert_eq!(k1.sign(&[&long], &mut out, &kw()), None);
        assert!(
            k1.sign(&[&long[..EDDSA_MSG_MAX]], &mut out, &kw())
                .is_some()
        );
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
        let id = m.credential_id(Alg::Es256, &rp, &[0x11; 16], &kw);
        let k = m.signing_key(Alg::Es256, &rp, &[0x11; 16], &kw).unwrap();
        let (r, s) = rs(&sign(&k, &[b"catcard fido vector"]));
        assert_eq!(
            hex(&id),
            "0111111111111111111111111111111111b1046afa0d51e09005b172beb4269978"
        );
        assert_eq!(
            hex(&sec1(&k)),
            concat!(
                "04c3412cc4ff6b78f18a0f505c9fc0a4c8cd1ba04d1aea463e94cfc775e9f4796d",
                "0008a044930bb5f4de9fbba9fad7028c6bf1fbd41715aab22707d6d29c3c72c4"
            )
        );
        assert_eq!(
            hex(&r),
            "29a507668fcf1f2ea0e1f7d14ff261782cb5f03134926877dd0a7ed85ae311ef"
        );
        assert_eq!(
            hex(&s),
            "d1b890ed8be0b4452d16a5c71eb30656474d9ab3c19111205584eeb8ed724291"
        );
    }

    /// The EdDSA side of the same vector: Python's `hmac`/`hashlib` for the id and the
    /// seed, `cryptography` 50.0.0 (OpenSSL) for the Ed25519 public key and signature.
    /// Re-run with the snippet in `docs/FIDO.md` §"Checking the derivation".
    #[test]
    fn an_eddsa_vector_cross_checked_with_python_cryptography() {
        let kw = KeyWork::host();
        let m = Master::from_parts(&[7; 32], &[9; 32], 0, &kw);
        let rp = Sha256::digest(b"example.com");
        let id = m.credential_id(Alg::EdDsa, &rp, &[0x11; 16], &kw);
        let k = m.signing_key(Alg::EdDsa, &rp, &[0x11; 16], &kw).unwrap();
        assert_eq!(
            hex(&id),
            "0211111111111111111111111111111111d69b486bf7bdd15ae8ed0113f8c17fb8"
        );
        assert_eq!(
            hex(&ed(&k)),
            "b595b14ff130ec70e9137c8bb8fccaf867ed1077cac29a8d269b298c37c1a819"
        );
        assert_eq!(
            hex(&sign(&k, &[b"catcard fido vector"])),
            concat!(
                "cb51d46781ecb8181adc75e3cb5ae8c30204d5f33a16c8990cf80a02ae7bdbed",
                "6d79d9b28a15e737de8a3415218f09f79100b292894ee9a80392c271c08dd103"
            )
        );
    }

    /// The derivation, pinned: these bytes are what a restored seed on another device
    /// must reproduce, so any change to the construction shows up here as a failure
    /// rather than as every registered site quietly stopping working.
    #[test]
    fn the_derivation_is_pinned() {
        let m = master(0);
        let rp = Sha256::digest(b"example.com");
        let id = m.credential_id(Alg::Es256, &rp, &[0x11; 16], &kw());
        let pk = sec1(&m.signing_key(Alg::Es256, &rp, &[0x11; 16], &kw()).unwrap());
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

        // EdDSA: the same with version byte 0x02, and the HMAC output is the seed.
        let id = m.credential_id(Alg::EdDsa, &rp, &[0x11; 16], &kw());
        let pk = ed(&m.signing_key(Alg::EdDsa, &rp, &[0x11; 16], &kw()).unwrap());
        t[2] = 0x02;
        assert_eq!(&id[17..], &HmacSha256::mac(&master[..32], &t)[..16]);
        k[3] = 0x02;
        let seed = HmacSha256::mac(&master[32..], &k);
        let expect = Ed25519PrivateKey::from_bytes(seed).public_key().to_bytes();
        assert_eq!(pk, expect);
    }
}
