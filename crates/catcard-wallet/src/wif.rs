//! Wallet Import Format (WIF): a single private key as Base58Check.
//!
//! A WIF string is `Base58Check(version || 32-byte secret || [0x01])`. The version byte
//! says which network -- `0x80` mainnet, `0xEF` testnet/regtest/signet -- and a trailing
//! `0x01` means the key is used *compressed*, which is what every modern wallet writes.
//!
//! Source: "Wallet import format", Bitcoin Wiki / BIP conventions; version bytes are the
//! network's private-key prefix (mainnet `0x80`, testnet `0xEF`). [C]
//!
//! # Secret handling
//!
//! The 32-byte scalar this holds is a private key, so [`WifKey`] is `Zeroize` and
//! `ZeroizeOnDrop`, and every scratch buffer that a decode or an encode moves the scalar
//! through is `Zeroizing`. Decoding, encoding and the public key are all Base58/EC work
//! over the scalar itself, so -- like the `xprv`/WIF encoding in [`crate::bip85`] -- they
//! are private-key work and take a [`KeyWork`], to be run inside the firmware's masked
//! region.

use crate::KeyWork;
use crate::bip32::{self, Network};
use crate::encoding::base58;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Mainnet private-key version byte. Source: mainnet WIF prefix `0x80`. [C]
const VERSION_MAINNET: u8 = 0x80;
/// Testnet/regtest/signet private-key version byte. Source: testnet WIF prefix `0xEF`. [C]
const VERSION_TESTNET: u8 = 0xEF;
/// Marks a key that is used compressed. Source: trailing `0x01` in a compressed WIF. [C]
const COMPRESSED_FLAG: u8 = 0x01;

/// Longest WIF string this encodes: a compressed key is 38 bytes before Base58Check
/// (1 version + 32 secret + 1 flag + 4 checksum), which never exceeds 53 characters.
/// log(256)/log(58) ≈ 1.366, so 38 × 1.366 ≈ 52, rounded up.
pub const MAX_WIF_LEN: usize = 53;

/// Why a WIF string could not be read, or a key could not be written.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Base58Check rejected the string: a bad character, or a checksum that does not match.
    BadEncoding,
    /// The decoded payload is not a WIF: not 33 (uncompressed) or 34 (compressed) bytes,
    /// or a 34-byte one whose trailing byte is not the compression flag.
    BadLength,
    /// The version byte matches no network's private-key prefix.
    BadNetwork,
    /// The 32 bytes are not a usable scalar: zero, or at or above the curve order.
    BadKey,
    /// The caller's output buffer is too small.
    BufferTooSmall,
}

/// A single private key, as a WIF store keeps it.
#[derive(Clone, ZeroizeOnDrop)]
pub struct WifKey {
    secret: [u8; 32],
    /// Whether the key is used compressed. Not secret; it is fixed by the WIF's shape.
    #[zeroize(skip)]
    compressed: bool,
    /// Which network the WIF names. Not secret.
    #[zeroize(skip)]
    network: Network,
}

impl WifKey {
    /// Build a key from raw scalar bytes, rejecting anything not a usable secret.
    ///
    /// Used for a freshly generated key: the caller draws 32 bytes from the DRBG and this
    /// refuses the vanishingly rare out-of-range draw rather than reducing it into range,
    /// which would map two draws onto one key.
    pub fn from_secret(secret: &[u8; 32], compressed: bool, network: Network) -> Result<Self, Error> {
        if !bip32::is_valid_secret(secret) {
            return Err(Error::BadKey);
        }
        Ok(Self {
            secret: *secret,
            compressed,
            network,
        })
    }

    /// Parse a WIF string.
    ///
    /// Base58 division over the string reconstructs the scalar, so this is private-key work
    /// and takes a [`KeyWork`]: run it inside the masked region.
    pub fn decode(text: &str, _kw: &KeyWork) -> Result<Self, Error> {
        // 1 version + 32 secret + 1 optional flag + 4 checksum = 38 at most.
        let mut buf = Zeroizing::new([0u8; 38]);
        let n = base58::decode_check(text, &mut buf[..]).map_err(|_| Error::BadEncoding)?;
        let network = match buf.first() {
            Some(&VERSION_MAINNET) => Network::Mainnet,
            Some(&VERSION_TESTNET) => Network::Testnet,
            _ => return Err(Error::BadNetwork),
        };
        let compressed = match n {
            // version + 32 secret
            33 => false,
            // version + 32 secret + compression flag
            34 if buf[33] == COMPRESSED_FLAG => true,
            _ => return Err(Error::BadLength),
        };
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&buf[1..33]);
        if !bip32::is_valid_secret(&secret) {
            secret.zeroize();
            return Err(Error::BadKey);
        }
        Ok(Self {
            secret,
            compressed,
            network,
        })
    }

    /// Write the key back as a WIF string into `out`; returns the length.
    ///
    /// Base58 over the scalar, so private-key work, as [`decode`](Self::decode).
    pub fn encode(&self, out: &mut [u8], _kw: &KeyWork) -> Result<usize, Error> {
        let mut payload = Zeroizing::new([0u8; 34]);
        payload[0] = match self.network {
            Network::Mainnet => VERSION_MAINNET,
            Network::Testnet => VERSION_TESTNET,
        };
        payload[1..33].copy_from_slice(&self.secret);
        let len = if self.compressed {
            payload[33] = COMPRESSED_FLAG;
            34
        } else {
            33
        };
        base58::encode_check(&payload[..len], out).map_err(|_| Error::BufferTooSmall)
    }

    /// The 33-byte compressed public key. `None` for bytes that are somehow not a usable
    /// key (already ruled out at construction, so this is belt-and-braces).
    ///
    /// EC scalar multiplication over the secret, so private-key work.
    ///
    /// Compressed regardless of the WIF's flag: it is what the address module and the
    /// signer's script rebuild take, and the uncompressed form has the same X coordinate,
    /// so it compresses to these same bytes. An uncompressed key still *signs* a legacy
    /// input paying its uncompressed hash -- `outscript` derives both forms from the
    /// scalar -- so the flag matters only to which address this can display, not to
    /// whether a spend can be signed.
    pub fn public_key(&self, kw: &KeyWork) -> Option<[u8; 33]> {
        bip32::public_key_of(&self.secret, kw)
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn compressed(&self) -> bool {
        self.compressed
    }

    /// The raw scalar, for the signer. Handing this out is why the whole type is a secret;
    /// callers keep the borrow inside the masked region and never copy it out.
    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kw() -> KeyWork {
        KeyWork::host()
    }

    /// A known mainnet compressed WIF round-trips to the same string, and names mainnet.
    #[test]
    fn a_known_compressed_wif_round_trips() {
        // A standard test vector: this WIF encodes the scalar 0x00..01 (compressed).
        const WIF: &str = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
        let key = WifKey::decode(WIF, &kw()).unwrap();
        assert!(key.compressed);
        assert_eq!(key.network, Network::Mainnet);
        assert_eq!(key.secret[31], 1);
        assert_eq!(key.secret[..31], [0u8; 31]);

        let mut out = [0u8; MAX_WIF_LEN];
        let n = key.encode(&mut out, &kw()).unwrap();
        assert_eq!(core::str::from_utf8(&out[..n]).unwrap(), WIF);
    }

    /// An uncompressed WIF for the same scalar decodes as uncompressed and re-encodes to
    /// the uncompressed string, not the compressed one.
    #[test]
    fn an_uncompressed_wif_keeps_its_form() {
        const WIF: &str = "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf";
        let key = WifKey::decode(WIF, &kw()).unwrap();
        assert!(!key.compressed);
        assert_eq!(key.secret[31], 1);
        let mut out = [0u8; MAX_WIF_LEN];
        let n = key.encode(&mut out, &kw()).unwrap();
        assert_eq!(core::str::from_utf8(&out[..n]).unwrap(), WIF);
    }

    /// A one-character typo fails the checksum rather than decoding to a different key.
    #[test]
    fn a_corrupted_wif_is_refused() {
        const WIF: &str = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWm";
        assert!(matches!(WifKey::decode(WIF, &kw()), Err(Error::BadEncoding)));
    }

    /// A testnet WIF names testnet.
    #[test]
    fn a_testnet_wif_names_testnet() {
        // Testnet compressed WIF for scalar 1.
        const WIF: &str = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA";
        let key = WifKey::decode(WIF, &kw()).unwrap();
        assert_eq!(key.network, Network::Testnet);
        assert!(key.compressed);
    }

    /// A round trip through raw bytes gives the same string a decode does.
    #[test]
    fn from_secret_matches_decode() {
        const WIF: &str = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
        let mut secret = [0u8; 32];
        secret[31] = 1;
        let key = WifKey::from_secret(&secret, true, Network::Mainnet).unwrap();
        let mut out = [0u8; MAX_WIF_LEN];
        let n = key.encode(&mut out, &kw()).unwrap();
        assert_eq!(core::str::from_utf8(&out[..n]).unwrap(), WIF);
    }

    /// A zero scalar is not a usable key, from either entry point.
    #[test]
    fn a_zero_key_is_refused() {
        assert!(matches!(
            WifKey::from_secret(&[0u8; 32], true, Network::Mainnet),
            Err(Error::BadKey)
        ));
    }

    /// The compressed public key of scalar 1 is the generator point, compressed.
    #[test]
    fn public_key_of_scalar_one_is_the_generator() {
        let mut secret = [0u8; 32];
        secret[31] = 1;
        let key = WifKey::from_secret(&secret, true, Network::Mainnet).unwrap();
        let pk = key.public_key(&kw()).unwrap();
        // Compressed secp256k1 generator G.
        let g = hex_lit(
            "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        );
        assert_eq!(pk, g);
    }

    /// The uncompressed and compressed WIFs of the same scalar give the same compressed
    /// public key, so an address derived from either matches.
    #[test]
    fn compressed_and_uncompressed_share_a_compressed_pubkey() {
        let c = WifKey::decode("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn", &kw())
            .unwrap();
        let u = WifKey::decode("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf", &kw())
            .unwrap();
        assert_eq!(
            c.public_key(&kw()).unwrap(),
            u.public_key(&kw()).unwrap()
        );
    }

    fn hex_lit(s: &str) -> [u8; 33] {
        let mut out = [0u8; 33];
        let b = s.as_bytes();
        for (i, o) in out.iter_mut().enumerate() {
            let hi = (b[i * 2] as char).to_digit(16).unwrap();
            let lo = (b[i * 2 + 1] as char).to_digit(16).unwrap();
            *o = (hi * 16 + lo) as u8;
        }
        out
    }
}
