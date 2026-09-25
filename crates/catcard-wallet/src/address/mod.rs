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

use crate::bip32::{Network, hash160};
use crate::encoding::{base58, bech32};
use purecrypto::ec::secp256k1::{AffinePoint, ProjectivePoint, Scalar};
use purecrypto::hash::{Digest, Sha256};

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
    /// Whether this type renders as bech32/bech32m rather than Base58Check.
    ///
    /// The QR payload turns on this and not on the look of the string: base58 is a
    /// mixed-case alphabet, so "does it contain an upper-case letter" is a guess that is
    /// almost always right and catastrophic when it is not.
    pub const fn is_bech32(self) -> bool {
        matches!(self, AddressKind::P2wpkh | AddressKind::P2tr)
    }

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
        // Regtest shares testnet's base58 versions. [C] wallet-export-formats.md §Chain parameters
        if self.is_mainnet() { 0x00 } else { 0x6f }
    }
    fn p2sh_version(self) -> u8 {
        if self.is_mainnet() { 0x05 } else { 0xc4 }
    }
    fn bech32_hrp(self) -> &'static str {
        // Each network has its own segwit prefix; regtest's `bcrt` is the one thing that
        // sets it apart from testnet. [C] wallet-export-formats.md §Chain parameters
        match self {
            Network::Mainnet => "bc",
            Network::Testnet => "tb",
            Network::Regtest => "bcrt",
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
    h.update(&tag_hash);
    h.update(&tag_hash);
    h.update(data);
    h.finalize()
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
    let p = AffinePoint::from_sec1(&even).map_err(|_| Error::InvalidKey)?;

    let t = tagged_hash(b"TapTweak", &x);
    let scalar = Scalar::from_bytes_be(&t).map_err(|_| Error::TweakFailed)?;

    let q = p
        .to_projective()
        .add(&ProjectivePoint::mul_generator(&scalar));
    let compressed = q
        .to_affine()
        .ok_or(Error::TweakFailed)?
        .to_sec1_compressed();
    let mut out = [0u8; XONLY_LEN];
    out.copy_from_slice(&compressed[1..]);
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

/// The scriptPubKey an address of `kind` for `pubkey` pays to, written into `out`.
///
/// The inverse of [`from_script`], and what change checking needs: an output claimed as
/// change is ours only if its script is the one our own key produces.
pub fn script_pubkey(
    kind: AddressKind,
    pubkey: &[u8; PUBKEY_LEN],
    out: &mut [u8],
) -> Result<usize, Error> {
    let write = |out: &mut [u8], parts: &[&[u8]]| -> Result<usize, Error> {
        let len: usize = parts.iter().map(|p| p.len()).sum();
        let have = out.len();
        let room = out
            .get_mut(..len)
            .ok_or(Error::BufferTooSmall { need: len, have })?;
        let mut at = 0;
        for p in parts {
            room[at..at + p.len()].copy_from_slice(p);
            at += p.len();
        }
        Ok(len)
    };
    match kind {
        AddressKind::P2pkh => write(out, &[&[0x76, 0xa9, 0x14], &hash160(pubkey), &[0x88, 0xac]]),
        AddressKind::P2shP2wpkh => {
            let redeem = p2wpkh_redeem_script(pubkey);
            write(out, &[&[0xa9, 0x14], &hash160(&redeem), &[0x87]])
        }
        AddressKind::P2wpkh => write(out, &[&[0x00, 0x14], &hash160(pubkey)]),
        AddressKind::P2tr => write(out, &[&[0x51, 0x20], &taproot_output_key(pubkey)?]),
    }
}

/// The address a scriptPubKey pays to, written into `out`; returns the length.
///
/// For showing a transaction's destinations: a PSBT gives outputs as scripts, and an
/// address is what a person can compare against what they meant to pay. A script this does
/// not recognise -- bare multisig, a data carrier, a future witness version -- has no
/// address, and gets `None` rather than an invented one.
///
/// The encoding itself is `outscript`'s, so only the classification is here.
pub fn from_script(script: &[u8], network: Network, out: &mut [u8]) -> Option<usize> {
    // Witness outputs render through our own bech32 so each network gets its own HRP --
    // regtest's `bcrt` included, which `outscript` does not carry. For mainnet and testnet
    // this is byte-for-byte what `outscript` produced, since both compute the same bech32.
    // Source: hw-reference/wallet-export-formats.md §"Chain parameters" [C].
    let witness = match script {
        [0x00, 0x14, h @ ..] if h.len() == 20 => Some((0u8, h)),
        [0x00, 0x20, h @ ..] if h.len() == 32 => Some((0u8, h)),
        [0x51, 0x20, h @ ..] if h.len() == 32 => Some((1u8, h)),
        _ => None,
    };
    if let Some((version, program)) = witness {
        return crate::encoding::bech32::encode_segwit(network.bech32_hrp(), version, program, out)
            .ok();
    }
    // Base58 outputs: regtest shares testnet's version bytes, so `outscript`'s testnet
    // network renders both.
    let format = match script {
        [0x76, 0xa9, 0x14, h @ .., 0x88, 0xac] if h.len() == 20 => "p2pkh",
        [0xa9, 0x14, h @ .., 0x87] if h.len() == 20 => "p2sh",
        _ => return None,
    };
    let net = if network.is_mainnet() {
        "bitcoin"
    } else {
        "bitcoin-testnet"
    };
    outscript::address::encode_address_to_slice(format, script, net, out).ok()
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
    if AffinePoint::from_sec1(pubkey).is_err() {
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

/// The BIP-21 scheme, as it is written in the standard.
pub const QR_SCHEME: &str = "bitcoin:";

/// Longest QR payload: the scheme plus the longest address.
pub const MAX_QR_PAYLOAD: usize = QR_SCHEME.len() + MAX_ADDRESS_LEN;

/// The form of `address` to put in a QR code.
///
/// Two shapes, because the two address encodings have opposite constraints:
///
/// - **Bech32 and bech32m** (`bc1...`) are upper-cased and carry **no scheme**. Upper case
///   is what BIP-173 asks for in QR codes: it is in QR's alphanumeric character set, so the
///   address encodes at 5.5 bits a character instead of 8 -- typically a whole version
///   smaller, which on a 64-row panel is the difference between two pixels a module and one.
///   A `bitcoin:` prefix would undo exactly that, since lower-case letters are not in the
///   set and one of them drops the whole payload into byte mode.
/// - **Base58** (`1...`, `3...`) keeps its case, because there the case carries the
///   checksum and an upper-cased legacy address is not the same address but an invalid one.
///   That payload is in byte mode whatever we do, so the `bitcoin:` scheme is free, and it
///   is what lets a phone's camera recognise the code as a payment rather than as text.
///
/// `None` if the result does not fit in `out` or the address is not ASCII. Refusing beats
/// truncating: a shortened address rendered as a QR is a payment nobody receives.
pub fn qr_payload<'a>(
    address: &str,
    kind: AddressKind,
    out: &'a mut [u8; MAX_QR_PAYLOAD],
) -> Option<&'a str> {
    qr_payload_of(address, kind.is_bech32(), out)
}

/// As [`qr_payload`], for an address whose form is known without an [`AddressKind`].
///
/// A multisig wallet's addresses have no single-signature kind to name them by -- the
/// script form is the wallet's, not a key's -- and the encoding is the only thing this
/// decision turns on, so it is asked for directly rather than through a stand-in kind that
/// would be a lie about what is being shown.
pub fn qr_payload_of<'a>(
    address: &str,
    bech32: bool,
    out: &'a mut [u8; MAX_QR_PAYLOAD],
) -> Option<&'a str> {
    let bytes = address.as_bytes();
    if bytes.is_empty() || !address.is_ascii() {
        return None;
    }
    let head = if bech32 { 0 } else { QR_SCHEME.len() };
    if head + bytes.len() > out.len() {
        return None;
    }
    out[..head].copy_from_slice(&QR_SCHEME.as_bytes()[..head]);
    let end = head + bytes.len();
    out[head..end].copy_from_slice(bytes);
    if bech32 {
        out[..end].make_ascii_uppercase();
    }
    core::str::from_utf8(&out[..end]).ok()
}

/// `payload` without the BIP-21 scheme: what a person reads off the screen and compares
/// against their wallet, which is the address and never the URI around it.
pub fn qr_address(payload: &str) -> &str {
    payload.strip_prefix(QR_SCHEME).unwrap_or(payload)
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
mod qr_payload_tests {
    use super::*;

    fn payload(address: &str, kind: AddressKind) -> Option<std::string::String> {
        let mut out = [0u8; MAX_QR_PAYLOAD];
        qr_payload(address, kind, &mut out).map(std::string::String::from)
    }

    #[test]
    fn bech32_is_upper_cased_and_carries_no_scheme() {
        // The scheme would cost what the upper-casing just bought: one lower-case letter
        // drops the whole payload out of QR's alphanumeric set and into byte mode.
        assert_eq!(
            payload(
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                AddressKind::P2wpkh
            )
            .as_deref(),
            Some("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4")
        );
        assert_eq!(
            payload(
                "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
                AddressKind::P2tr
            )
            .as_deref(),
            Some("BC1P0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQZK5JJ0")
        );
    }

    #[test]
    fn base58_keeps_its_case_and_gets_the_scheme() {
        // Case is the checksum here, so nothing is touched -- and the payload is in byte
        // mode either way, which is what makes the scheme free.
        for (legacy, kind) in [
            ("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", AddressKind::P2pkh),
            (
                "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
                AddressKind::P2shP2wpkh,
            ),
        ] {
            let got = payload(legacy, kind).unwrap();
            assert_eq!(got, std::format!("bitcoin:{legacy}"));
            assert_eq!(qr_address(&got), legacy);
        }
    }

    #[test]
    fn an_already_upper_cased_bech32_is_left_alone() {
        let upper = "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4";
        assert_eq!(payload(upper, AddressKind::P2wpkh).as_deref(), Some(upper));
    }

    #[test]
    fn what_is_read_out_is_the_address_without_the_uri_around_it() {
        assert_eq!(
            qr_address("bitcoin:1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"),
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
        );
        assert_eq!(
            qr_address("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"),
            "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"
        );
    }
}

#[cfg(test)]
mod tests {
    /// Each script form round-trips to the address `encode` produces for the same key, so
    /// the classification and the encoder agree with our own address code.
    #[test]
    fn a_script_renders_the_same_address_as_the_key_it_pays() {
        use super::*;
        let pubkey: [u8; PUBKEY_LEN] = [
            0x02, 0x50, 0x86, 0x3a, 0xd6, 0x4a, 0x87, 0xae, 0x8a, 0x2f, 0xe8, 0x3c, 0x1a, 0xf1,
            0xa8, 0x40, 0x3c, 0xb5, 0x3f, 0x53, 0xe4, 0x86, 0xd8, 0x51, 0x1d, 0xad, 0x8a, 0x04,
            0x88, 0x7e, 0x5b, 0x23, 0x52,
        ];
        for kind in [
            AddressKind::P2pkh,
            AddressKind::P2shP2wpkh,
            AddressKind::P2wpkh,
            AddressKind::P2tr,
        ] {
            for network in [Network::Mainnet, Network::Testnet] {
                let mut from_key = [0u8; MAX_ADDRESS_LEN];
                let n = encode(kind, network, &pubkey, &mut from_key).unwrap();
                let mut script = [0u8; 34];
                let sn = script_pubkey(kind, &pubkey, &mut script).unwrap();
                let mut from_spk = [0u8; MAX_ADDRESS_LEN];
                let m = from_script(&script[..sn], network, &mut from_spk).unwrap();
                assert_eq!(
                    core::str::from_utf8(&from_key[..n]),
                    core::str::from_utf8(&from_spk[..m]),
                    "{kind:?} {network:?}"
                );
            }
        }
    }

    /// Regtest wears `bcrt` on its segwit addresses and testnet's `m`/`2` on its legacy
    /// ones, and `encode` and `from_script` agree on every one.
    #[test]
    fn regtest_addresses_use_the_bcrt_prefix() {
        use super::*;
        let pubkey: [u8; PUBKEY_LEN] = [
            0x02, 0x50, 0x86, 0x3a, 0xd6, 0x4a, 0x87, 0xae, 0x8a, 0x2f, 0xe8, 0x3c, 0x1a, 0xf1,
            0xa8, 0x40, 0x3c, 0xb5, 0x3f, 0x53, 0xe4, 0x86, 0xd8, 0x51, 0x1d, 0xad, 0x8a, 0x04,
            0x88, 0x7e, 0x5b, 0x23, 0x52,
        ];
        // Native segwit and taproot carry the regtest HRP; legacy shares testnet's base58.
        let bech32_prefixes = [(AddressKind::P2wpkh, "bcrt1"), (AddressKind::P2tr, "bcrt1")];
        for (kind, want) in bech32_prefixes {
            let s = encode_string(kind, Network::Regtest, &pubkey).unwrap();
            assert!(s.starts_with(want), "{kind:?} gave {s}");
        }
        // The base58 forms are identical to testnet's, since the version bytes are shared.
        for kind in [AddressKind::P2pkh, AddressKind::P2shP2wpkh] {
            let r = encode_string(kind, Network::Regtest, &pubkey).unwrap();
            let t = encode_string(kind, Network::Testnet, &pubkey).unwrap();
            assert_eq!(r, t, "{kind:?} base58 must match testnet");
        }
        // `from_script` reproduces exactly what `encode` wrote, regtest HRP and all.
        for kind in [
            AddressKind::P2pkh,
            AddressKind::P2shP2wpkh,
            AddressKind::P2wpkh,
            AddressKind::P2tr,
        ] {
            let mut from_key = [0u8; MAX_ADDRESS_LEN];
            let n = encode(kind, Network::Regtest, &pubkey, &mut from_key).unwrap();
            let mut script = [0u8; 34];
            let sn = script_pubkey(kind, &pubkey, &mut script).unwrap();
            let mut from_spk = [0u8; MAX_ADDRESS_LEN];
            let m = from_script(&script[..sn], Network::Regtest, &mut from_spk).unwrap();
            assert_eq!(&from_key[..n], &from_spk[..m], "{kind:?}");
        }
    }

    #[test]
    fn a_script_with_no_address_gets_none_not_a_guess() {
        use super::*;
        let mut out = [0u8; MAX_ADDRESS_LEN];
        // OP_RETURN, bare multisig, and a witness version this does not know.
        for script in [
            &[0x6a, 0x04, 1, 2, 3, 4][..],
            &[0x51, 0x21, 2][..],
            &[0x60, 0x02, 0xaa, 0xbb][..],
            &[][..],
        ] {
            assert!(from_script(script, Network::Mainnet, &mut out).is_none());
        }
    }

    use super::*;
    use crate::bip32::{DerivationPath, ExtendedPrivKey};
    use crate::bip39::Mnemonic;

    /// The seed every one of BIP-49/84/86's test vectors uses.
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon \
                                 abandon abandon abandon abandon abandon about";

    fn key_at(path: &str, network: Network) -> [u8; PUBKEY_LEN] {
        let m = Mnemonic::parse(TEST_MNEMONIC, &crate::KeyWork::host()).unwrap();
        let mut seed = [0u8; 64];
        m.to_seed("", &mut seed, &crate::KeyWork::host()).unwrap();
        let master = ExtendedPrivKey::from_seed(&seed, network, &crate::KeyWork::host()).unwrap();
        let p: DerivationPath = path.parse().unwrap();
        master
            .derive_path(&p, &crate::KeyWork::host())
            .unwrap()
            .public_key(&crate::KeyWork::host())
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
        assert!(
            encode_string(AddressKind::P2pkh, Network::Mainnet, &k)
                .unwrap()
                .starts_with('1')
        );
        assert!(
            encode_string(AddressKind::P2shP2wpkh, Network::Mainnet, &k)
                .unwrap()
                .starts_with('3')
        );
        assert!(
            encode_string(AddressKind::P2wpkh, Network::Mainnet, &k)
                .unwrap()
                .starts_with("bc1q")
        );
        assert!(
            encode_string(AddressKind::P2tr, Network::Mainnet, &k)
                .unwrap()
                .starts_with("bc1p")
        );

        let t = key_at("m/0", Network::Testnet);
        let tp = encode_string(AddressKind::P2pkh, Network::Testnet, &t).unwrap();
        assert!(tp.starts_with('m') || tp.starts_with('n'), "{tp}");
        assert!(
            encode_string(AddressKind::P2shP2wpkh, Network::Testnet, &t)
                .unwrap()
                .starts_with('2')
        );
        assert!(
            encode_string(AddressKind::P2wpkh, Network::Testnet, &t)
                .unwrap()
                .starts_with("tb1q")
        );
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
        if AffinePoint::from_sec1(&flipped).is_ok() {
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
        h.update(&t);
        h.update(&t);
        h.update(b"x");
        let expect: [u8; 32] = h.finalize();
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
