//! Bitcoin addresses.
//!
//! Four output types, matching the four BIP-44/49/84/86 script conventions:
//!
//! | type | derivation | encoding | witness |
//! |---|---|---|---|
//! | P2PKH | BIP-44 `m/44'` | Base58Check | — |
//! | P2SH-P2WPKH | BIP-49 `m/49'` | Base58Check | v0 nested in P2SH |
//! | P2WPKH | BIP-84 `m/84'` | Bech32 | v0 |
//! | P2TR | BIP-86 `m/86'` | Bech32m | v1 |
//!
//! # What an address commits to
//!
//! An address is a rendering of a scriptPubKey. Displaying the wrong one, or one
//! derived from the wrong key, sends funds somewhere unrecoverable — so every
//! construction here goes from a public key through a documented hash, and the
//! [`AddressKind`] is explicit rather than inferred from the derivation path. A wallet
//! that guesses the script type from `m/84'` and then encodes P2PKH would produce a
//! valid-looking address nobody can spend from.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

use catcard_bip32::{hash160, Network};
use catcard_encoding::{base58, bech32};
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, ProjectivePoint, PublicKey, Scalar};
use sha2::{Digest, Sha256};

/// Longest address string: a Bech32m P2TR at 62 characters, with headroom.
pub const MAX_ADDRESS_LEN: usize = bech32::MAX_LENGTH;

/// Compressed public key length.
pub const PUBKEY_LEN: usize = 33;
/// x-only public key length (BIP-340).
pub const XONLY_LEN: usize = 32;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum AddressKind {
    /// Pay to public key hash. `OP_DUP OP_HASH160 <h160> OP_EQUALVERIFY OP_CHECKSIG`.
    P2pkh,
    /// P2WPKH nested in P2SH, for wallets that cannot send to bech32.
    P2shP2wpkh,
    /// Native segwit v0. `OP_0 <h160>`.
    P2wpkh,
    /// Taproot, segwit v1. `OP_1 <32-byte tweaked x-only key>`.
    P2tr,
}

impl AddressKind {
    /// The BIP-44-family purpose index that conventionally derives this type.
    ///
    /// Advisory only: nothing here infers the script type from a path, because that
    /// inference is exactly how a wallet ends up showing an unspendable address.
    pub const fn bip44_purpose(self) -> u32 {
        match self {
            AddressKind::P2pkh => 44,
            AddressKind::P2shP2wpkh => 49,
            AddressKind::P2wpkh => 84,
            AddressKind::P2tr => 86,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Public key is not a valid compressed secp256k1 point.
    InvalidKey,
    /// The taproot tweak produced an unusable point. Cryptographically negligible.
    TweakFailed,
    Base58(base58::Error),
    Bech32(bech32::Error),
    /// Output buffer too small for the address.
    BufferTooSmall {
        need: usize,
        have: usize,
    },
}

impl From<base58::Error> for Error {
    fn from(e: base58::Error) -> Self {
        Error::Base58(e)
    }
}
impl From<bech32::Error> for Error {
    fn from(e: bech32::Error) -> Self {
        Error::Bech32(e)
    }
}

/// Network parameters that affect address rendering.
pub trait NetworkParams {
    /// Version byte for Base58Check P2PKH.
    fn p2pkh_version(self) -> u8;
    /// Version byte for Base58Check P2SH.
    fn p2sh_version(self) -> u8;
    /// Bech32 human-readable part.
    fn bech32_hrp(self) -> &'static str;
}

impl NetworkParams for Network {
    fn p2pkh_version(self) -> u8 {
        match self {
            Network::Mainnet => 0x00,
            Network::Testnet => 0x6f,
        }
    }
    fn p2sh_version(self) -> u8 {
        match self {
            Network::Mainnet => 0x05,
            Network::Testnet => 0xc4,
        }
    }
    fn bech32_hrp(self) -> &'static str {
        match self {
            Network::Mainnet => "bc",
            Network::Testnet => "tb",
        }
    }
}

/// BIP-340 tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || data)`.
///
/// The doubled tag digest is what makes the hash domain-separated: no chosen `data` can
/// make one tag's hash collide with another's.
pub fn tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut h = Sha256::new();
    h.update(tag_hash);
    h.update(tag_hash);
    h.update(data);
    h.finalize().into()
}

/// The x coordinate of a compressed key, discarding the parity byte (BIP-340).
pub fn x_only(pubkey: &[u8; PUBKEY_LEN]) -> [u8; XONLY_LEN] {
    let mut out = [0u8; XONLY_LEN];
    out.copy_from_slice(&pubkey[1..]);
    out
}

/// Apply the BIP-86 key-path-only taproot tweak.
///
/// `Q = lift_x(P) + int(tagged_hash("TapTweak", P_x)) * G`, returning `Q`'s x
/// coordinate. With no script tree the tweak commits to the internal key alone, which
/// is what makes a BIP-86 output provably key-path only.
pub fn taproot_output_key(internal: &[u8; PUBKEY_LEN]) -> Result<[u8; XONLY_LEN], Error> {
    let x = x_only(internal);

    // lift_x: the point with this x and *even* y, regardless of the input's parity.
    let mut even = [0u8; PUBKEY_LEN];
    even[0] = 0x02;
    even[1..].copy_from_slice(&x);
    let p = PublicKey::from_sec1_bytes(&even).map_err(|_| Error::InvalidKey)?;

    let t = tagged_hash(b"TapTweak", &x);
    let scalar: Scalar = Option::from(Scalar::from_repr(t.into())).ok_or(Error::TweakFailed)?;

    let q = ProjectivePoint::from(p.as_affine()) + ProjectivePoint::GENERATOR * scalar;
    let affine = AffinePoint::from(&q);
    let pk = PublicKey::from_affine(affine).map_err(|_| Error::TweakFailed)?;
    let enc = pk.to_sec1_point(true);
    let bytes = enc.as_bytes();
    if bytes.len() != PUBKEY_LEN {
        return Err(Error::TweakFailed);
    }
    let mut out = [0u8; XONLY_LEN];
    out.copy_from_slice(&bytes[1..]);
    Ok(out)
}

/// The redeem script a P2SH-P2WPKH address commits to: `OP_0 PUSH20 <hash160(pubkey)>`.
pub fn p2wpkh_redeem_script(pubkey: &[u8; PUBKEY_LEN]) -> [u8; 22] {
    let mut script = [0u8; 22];
    script[0] = 0x00; // OP_0 — the witness version
    script[1] = 0x14; // push 20 bytes
    script[2..].copy_from_slice(&hash160(pubkey));
    script
}

/// Render an address into `out`; returns the length written.
pub fn encode(
    kind: AddressKind,
    network: Network,
    pubkey: &[u8; PUBKEY_LEN],
    out: &mut [u8],
) -> Result<usize, Error> {
    // Reject anything that is not a point on the curve before hashing it: an address
    // derived from a malformed key is unspendable and looks perfectly normal.
    if PublicKey::from_sec1_bytes(pubkey).is_err() {
        return Err(Error::InvalidKey);
    }

    match kind {
        AddressKind::P2pkh => {
            let mut payload = [0u8; 21];
            payload[0] = network.p2pkh_version();
            payload[1..].copy_from_slice(&hash160(pubkey));
            Ok(base58::encode_check(&payload, out)?)
        }
        AddressKind::P2shP2wpkh => {
            let script = p2wpkh_redeem_script(pubkey);
            let mut payload = [0u8; 21];
            payload[0] = network.p2sh_version();
            payload[1..].copy_from_slice(&hash160(&script));
            Ok(base58::encode_check(&payload, out)?)
        }
        AddressKind::P2wpkh => Ok(bech32::encode_segwit(
            network.bech32_hrp(),
            0,
            &hash160(pubkey),
            out,
        )?),
        AddressKind::P2tr => {
            let output = taproot_output_key(pubkey)?;
            Ok(bech32::encode_segwit(
                network.bech32_hrp(),
                1,
                &output,
                out,
            )?)
        }
    }
}

#[cfg(feature = "std")]
/// Render an address as a `String`.
pub fn encode_string(
    kind: AddressKind,
    network: Network,
    pubkey: &[u8; PUBKEY_LEN],
) -> Result<std::string::String, Error> {
    let mut buf = [0u8; MAX_ADDRESS_LEN];
    let n = encode(kind, network, pubkey, &mut buf)?;
    Ok(core::str::from_utf8(&buf[..n])
        .expect("addresses are ASCII")
        .into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use catcard_bip32::{DerivationPath, ExtendedPrivKey};
    use catcard_bip39::Mnemonic;

    /// The seed every one of BIP-49/84/86's test vectors uses.
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon \
                                 abandon abandon abandon abandon abandon about";

    fn key_at(path: &str, network: Network) -> [u8; PUBKEY_LEN] {
        let m = Mnemonic::parse(TEST_MNEMONIC).unwrap();
        let mut seed = [0u8; 64];
        m.to_seed("", &mut seed).unwrap();
        let master = ExtendedPrivKey::from_seed(&seed, network).unwrap();
        let p: DerivationPath = path.parse().unwrap();
        master.derive_path(&p).unwrap().public_key()
    }

    fn addr(kind: AddressKind, network: Network, path: &str) -> String {
        encode_string(kind, network, &key_at(path, network)).unwrap()
    }

    /// BIP-84 test vectors — native segwit, mainnet.
    #[test]
    fn bip84_p2wpkh_vectors() {
        for (path, want) in [
            (
                "m/84'/0'/0'/0/0",
                "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
            ),
            (
                "m/84'/0'/0'/0/1",
                "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
            ),
            (
                "m/84'/0'/0'/1/0",
                "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el",
            ),
        ] {
            assert_eq!(
                addr(AddressKind::P2wpkh, Network::Mainnet, path),
                want,
                "{path}"
            );
        }
    }

    /// BIP-86 test vectors — taproot, mainnet. These exercise the tweak.
    #[test]
    fn bip86_p2tr_vectors() {
        for (path, want) in [
            (
                "m/86'/0'/0'/0/0",
                "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
            ),
            (
                "m/86'/0'/0'/0/1",
                "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh",
            ),
            (
                "m/86'/0'/0'/1/0",
                "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7",
            ),
        ] {
            assert_eq!(
                addr(AddressKind::P2tr, Network::Mainnet, path),
                want,
                "{path}"
            );
        }
    }

    /// BIP-49 test vector — P2SH-wrapped segwit, testnet.
    #[test]
    fn bip49_p2sh_p2wpkh_vector() {
        assert_eq!(
            addr(AddressKind::P2shP2wpkh, Network::Testnet, "m/49'/1'/0'/0/0"),
            "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2"
        );
    }

    /// The canonical Base58Check worked example: hash160 payload to P2PKH address.
    #[test]
    fn p2pkh_encoding_matches_the_documented_example() {
        let hash = [
            0xf5, 0x4a, 0x58, 0x51, 0xe9, 0x37, 0x2b, 0x87, 0x81, 0x0a, 0x8e, 0x60, 0xcd, 0xd2,
            0xe7, 0xcf, 0xd8, 0x0b, 0x6e, 0x31,
        ];
        let mut payload = [0u8; 21];
        payload[0] = Network::Mainnet.p2pkh_version();
        payload[1..].copy_from_slice(&hash);
        let mut out = [0u8; MAX_ADDRESS_LEN];
        let n = base58::encode_check(&payload, &mut out).unwrap();
        assert_eq!(
            core::str::from_utf8(&out[..n]).unwrap(),
            "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
        );
    }

    #[test]
    fn address_prefixes_are_what_users_recognise() {
        let k = key_at("m/0", Network::Mainnet);
        assert!(encode_string(AddressKind::P2pkh, Network::Mainnet, &k)
            .unwrap()
            .starts_with('1'));
        assert!(encode_string(AddressKind::P2shP2wpkh, Network::Mainnet, &k)
            .unwrap()
            .starts_with('3'));
        assert!(encode_string(AddressKind::P2wpkh, Network::Mainnet, &k)
            .unwrap()
            .starts_with("bc1q"));
        assert!(encode_string(AddressKind::P2tr, Network::Mainnet, &k)
            .unwrap()
            .starts_with("bc1p"));

        let t = key_at("m/0", Network::Testnet);
        let tp = encode_string(AddressKind::P2pkh, Network::Testnet, &t).unwrap();
        assert!(tp.starts_with('m') || tp.starts_with('n'), "{tp}");
        assert!(encode_string(AddressKind::P2shP2wpkh, Network::Testnet, &t)
            .unwrap()
            .starts_with('2'));
        assert!(encode_string(AddressKind::P2wpkh, Network::Testnet, &t)
            .unwrap()
            .starts_with("tb1q"));
    }

    #[test]
    fn every_kind_produces_a_distinct_address_for_one_key() {
        // The same key under four script types must never collide; if it did, a
        // wallet showing the wrong type would still look self-consistent.
        let k = key_at("m/0", Network::Mainnet);
        let all: Vec<String> = [
            AddressKind::P2pkh,
            AddressKind::P2shP2wpkh,
            AddressKind::P2wpkh,
            AddressKind::P2tr,
        ]
        .iter()
        .map(|kind| encode_string(*kind, Network::Mainnet, &k).unwrap())
        .collect();
        let mut sorted = all.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 4, "collision among {all:?}");
    }

    #[test]
    fn mainnet_and_testnet_addresses_never_coincide() {
        let k = key_at("m/0", Network::Mainnet);
        for kind in [
            AddressKind::P2pkh,
            AddressKind::P2shP2wpkh,
            AddressKind::P2wpkh,
            AddressKind::P2tr,
        ] {
            assert_ne!(
                encode_string(kind, Network::Mainnet, &k).unwrap(),
                encode_string(kind, Network::Testnet, &k).unwrap(),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn segwit_addresses_decode_back_to_their_programs() {
        let k = key_at("m/0", Network::Mainnet);
        let mut prog = [0u8; 40];

        let a = encode_string(AddressKind::P2wpkh, Network::Mainnet, &k).unwrap();
        let (v, n) = bech32::decode_segwit(&a, "bc", &mut prog).unwrap();
        assert_eq!(v, 0);
        assert_eq!(&prog[..n], &hash160(&k));

        let a = encode_string(AddressKind::P2tr, Network::Mainnet, &k).unwrap();
        let (v, n) = bech32::decode_segwit(&a, "bc", &mut prog).unwrap();
        assert_eq!(v, 1);
        assert_eq!(&prog[..n], &taproot_output_key(&k).unwrap());
    }

    #[test]
    fn an_invalid_public_key_is_rejected_before_it_becomes_an_address() {
        let mut bad = [0u8; PUBKEY_LEN];
        bad[0] = 0x02;
        bad[1..].fill(0xff); // x coordinate not on the curve
        let mut out = [0u8; MAX_ADDRESS_LEN];
        for kind in [
            AddressKind::P2pkh,
            AddressKind::P2shP2wpkh,
            AddressKind::P2wpkh,
            AddressKind::P2tr,
        ] {
            assert_eq!(
                encode(kind, Network::Mainnet, &bad, &mut out),
                Err(Error::InvalidKey),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn taproot_tweak_is_not_the_identity() {
        // A missing tweak would produce an address that looks fine and is unspendable
        // by any BIP-86 wallet.
        let k = key_at("m/0", Network::Mainnet);
        assert_ne!(taproot_output_key(&k).unwrap(), x_only(&k));
    }

    #[test]
    fn taproot_tweak_ignores_the_parity_of_the_internal_key() {
        // lift_x always takes the even-y point, so both encodings of one x must tweak
        // to the same output key.
        let k = key_at("m/0", Network::Mainnet);
        let mut flipped = k;
        flipped[0] = if k[0] == 0x02 { 0x03 } else { 0x02 };
        // The flipped key may not be a valid point; only compare when it is.
        if PublicKey::from_sec1_bytes(&flipped).is_ok() {
            assert_eq!(
                taproot_output_key(&k).unwrap(),
                taproot_output_key(&flipped).unwrap()
            );
        }
    }

    #[test]
    fn tagged_hash_is_domain_separated() {
        assert_ne!(
            tagged_hash(b"TapTweak", b"x"),
            tagged_hash(b"TapLeaf", b"x")
        );
        // And matches the BIP-340 construction explicitly.
        let t = Sha256::digest(b"TapTweak");
        let mut h = Sha256::new();
        h.update(t);
        h.update(t);
        h.update(b"x");
        let expect: [u8; 32] = h.finalize().into();
        assert_eq!(tagged_hash(b"TapTweak", b"x"), expect);
    }

    #[test]
    fn redeem_script_shape() {
        let k = key_at("m/0", Network::Mainnet);
        let s = p2wpkh_redeem_script(&k);
        assert_eq!(s[0], 0x00, "witness version 0");
        assert_eq!(s[1], 0x14, "20-byte push");
        assert_eq!(&s[2..], &hash160(&k));
    }

    #[test]
    fn purposes_match_their_bips() {
        assert_eq!(AddressKind::P2pkh.bip44_purpose(), 44);
        assert_eq!(AddressKind::P2shP2wpkh.bip44_purpose(), 49);
        assert_eq!(AddressKind::P2wpkh.bip44_purpose(), 84);
        assert_eq!(AddressKind::P2tr.bip44_purpose(), 86);
    }
}
