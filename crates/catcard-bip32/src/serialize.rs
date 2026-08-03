//! The 78-byte extended-key serialisation and its Base58Check form.
//!
//! ```text
//! version(4) || depth(1) || parent_fingerprint(4) || child_number(4)
//!            || chain_code(32) || key(33)
//! ```
//!
//! For a private key the 33-byte field is `0x00 || ser256(k)`; for a public key it is
//! the compressed point. The leading zero byte is what makes both 33 wide, so the two
//! forms are the same length and only the version prefix distinguishes them.

use catcard_encoding::base58;

use crate::{
    ChildNumber, ExtendedPrivKey, ExtendedPubKey, CHAIN_CODE_LEN, FINGERPRINT_LEN, PRIVKEY_LEN,
    PUBKEY_LEN,
};

/// Serialised length before Base58Check.
pub const RAW_LEN: usize = 78;
/// Enough room for the Base58Check form of [`RAW_LEN`] plus a checksum.
pub const MAX_BASE58_LEN: usize = 128;

/// Which network's version bytes to use.
///
/// Regtest and signet share testnet's prefixes, so they are not separate variants —
/// the prefix carries no more information than "not mainnet".
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    /// `xprv` / `tprv`.
    pub const fn private_version(self) -> [u8; 4] {
        match self {
            Network::Mainnet => 0x0488_ADE4u32.to_be_bytes(),
            Network::Testnet => 0x0435_8394u32.to_be_bytes(),
        }
    }

    /// `xpub` / `tpub`.
    pub const fn public_version(self) -> [u8; 4] {
        match self {
            Network::Mainnet => 0x0488_B21Eu32.to_be_bytes(),
            Network::Testnet => 0x0435_87CFu32.to_be_bytes(),
        }
    }

    fn from_version(v: &[u8]) -> Option<(Network, bool)> {
        let b: [u8; 4] = v.try_into().ok()?;
        for n in [Network::Mainnet, Network::Testnet] {
            if b == n.private_version() {
                return Some((n, true));
            }
            if b == n.public_version() {
                return Some((n, false));
            }
        }
        None
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Not 78 bytes after Base58Check decoding.
    BadLength { len: usize },
    /// Version bytes match no known network, or the wrong key kind for the call.
    BadVersion,
    /// A private key's 33-byte field must begin with 0x00.
    BadPrivatePrefix,
    /// Key bytes are not a valid scalar or point.
    InvalidKey,
    /// Base58Check rejected the string.
    Base58(base58::Error),
    /// Depth is zero but the fingerprint or child number is not, or vice versa.
    InconsistentDepth,
}

impl From<base58::Error> for Error {
    fn from(e: base58::Error) -> Self {
        Error::Base58(e)
    }
}

fn write_common(
    out: &mut [u8; RAW_LEN],
    version: [u8; 4],
    depth: u8,
    fingerprint: [u8; FINGERPRINT_LEN],
    child: ChildNumber,
    chain_code: &[u8; CHAIN_CODE_LEN],
) {
    out[0..4].copy_from_slice(&version);
    out[4] = depth;
    out[5..9].copy_from_slice(&fingerprint);
    out[9..13].copy_from_slice(&child.to_bytes());
    out[13..45].copy_from_slice(chain_code);
}

/// Fields shared by both key kinds, as read back off the wire.
struct Common {
    network: Network,
    is_private: bool,
    depth: u8,
    parent_fingerprint: [u8; FINGERPRINT_LEN],
    child_number: ChildNumber,
    chain_code: [u8; CHAIN_CODE_LEN],
    key: [u8; PUBKEY_LEN],
}

fn read_common(raw: &[u8]) -> Result<Common, Error> {
    if raw.len() != RAW_LEN {
        return Err(Error::BadLength { len: raw.len() });
    }
    let (network, is_private) = Network::from_version(&raw[0..4]).ok_or(Error::BadVersion)?;

    let depth = raw[4];
    let mut parent_fingerprint = [0u8; FINGERPRINT_LEN];
    parent_fingerprint.copy_from_slice(&raw[5..9]);
    let child_number = ChildNumber(u32::from_be_bytes(raw[9..13].try_into().unwrap()));
    let mut chain_code = [0u8; CHAIN_CODE_LEN];
    chain_code.copy_from_slice(&raw[13..45]);
    let mut key = [0u8; PUBKEY_LEN];
    key.copy_from_slice(&raw[45..78]);

    // A master key has no parent, so both fields must be zero. Accepting a non-zero
    // fingerprint at depth 0 would let two different serialisations describe the same
    // key, which breaks fingerprint-based wallet matching.
    if depth == 0 && (parent_fingerprint != [0; FINGERPRINT_LEN] || child_number.0 != 0) {
        return Err(Error::InconsistentDepth);
    }

    Ok(Common {
        network,
        is_private,
        depth,
        parent_fingerprint,
        child_number,
        chain_code,
        key,
    })
}

impl ExtendedPrivKey {
    /// The raw 78-byte form.
    pub fn to_raw(&self) -> [u8; RAW_LEN] {
        let mut out = [0u8; RAW_LEN];
        write_common(
            &mut out,
            self.network.private_version(),
            self.depth,
            self.parent_fingerprint,
            self.child_number,
            &self.chain_code,
        );
        out[45] = 0x00;
        out[46..78].copy_from_slice(self.secret_bytes());
        out
    }

    /// The `xprv`/`tprv` string.
    #[cfg(feature = "std")]
    pub fn to_base58(&self) -> alloc_string::String {
        let mut buf = [0u8; MAX_BASE58_LEN];
        let n = self.write_base58(&mut buf).expect("buffer is large enough");
        core::str::from_utf8(&buf[..n])
            .expect("Base58 output is ASCII")
            .into()
    }

    /// Write the `xprv` string into `out`; returns the length.
    pub fn write_base58(&self, out: &mut [u8]) -> Result<usize, Error> {
        Ok(base58::encode_check(&self.to_raw(), out)?)
    }

    /// Parse an `xprv`/`tprv` string.
    pub fn from_base58(text: &str) -> Result<Self, Error> {
        let mut raw = [0u8; base58::MAX_DECODED];
        let n = base58::decode_check(text, &mut raw)?;
        Self::from_raw(&raw[..n])
    }

    pub fn from_raw(raw: &[u8]) -> Result<Self, Error> {
        let c = read_common(raw)?;
        if !c.is_private {
            return Err(Error::BadVersion);
        }
        if c.key[0] != 0x00 {
            return Err(Error::BadPrivatePrefix);
        }
        let mut secret = [0u8; PRIVKEY_LEN];
        secret.copy_from_slice(&c.key[1..]);
        // Reject zero and out-of-range scalars rather than carrying an unusable key.
        if k256::SecretKey::from_slice(&secret).is_err() {
            return Err(Error::InvalidKey);
        }
        Ok(Self::from_parts(
            c.network,
            c.depth,
            c.parent_fingerprint,
            c.child_number,
            c.chain_code,
            secret,
        ))
    }
}

impl ExtendedPubKey {
    pub fn to_raw(&self) -> [u8; RAW_LEN] {
        let mut out = [0u8; RAW_LEN];
        write_common(
            &mut out,
            self.network.public_version(),
            self.depth,
            self.parent_fingerprint,
            self.child_number,
            &self.chain_code,
        );
        out[45..78].copy_from_slice(&self.public_key);
        out
    }

    #[cfg(feature = "std")]
    pub fn to_base58(&self) -> alloc_string::String {
        let mut buf = [0u8; MAX_BASE58_LEN];
        let n = self.write_base58(&mut buf).expect("buffer is large enough");
        core::str::from_utf8(&buf[..n])
            .expect("Base58 output is ASCII")
            .into()
    }

    pub fn write_base58(&self, out: &mut [u8]) -> Result<usize, Error> {
        Ok(base58::encode_check(&self.to_raw(), out)?)
    }

    pub fn from_base58(text: &str) -> Result<Self, Error> {
        let mut raw = [0u8; base58::MAX_DECODED];
        let n = base58::decode_check(text, &mut raw)?;
        Self::from_raw(&raw[..n])
    }

    pub fn from_raw(raw: &[u8]) -> Result<Self, Error> {
        let c = read_common(raw)?;
        if c.is_private {
            return Err(Error::BadVersion);
        }
        // Must be a compressed point on the curve; 0x04 (uncompressed) is not valid
        // here, and neither is an off-curve x coordinate.
        if k256::PublicKey::from_sec1_bytes(&c.key).is_err() {
            return Err(Error::InvalidKey);
        }
        Ok(Self {
            network: c.network,
            depth: c.depth,
            parent_fingerprint: c.parent_fingerprint,
            child_number: c.child_number,
            chain_code: c.chain_code,
            public_key: c.key,
        })
    }
}

#[cfg(feature = "std")]
mod alloc_string {
    pub use std::string::String;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors::VECTORS;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn version_bytes_match_the_published_prefixes() {
        // These are what make a string start with xprv/xpub/tprv/tpub.
        assert_eq!(Network::Mainnet.private_version(), [0x04, 0x88, 0xAD, 0xE4]);
        assert_eq!(Network::Mainnet.public_version(), [0x04, 0x88, 0xB2, 0x1E]);
        assert_eq!(Network::Testnet.private_version(), [0x04, 0x35, 0x83, 0x94]);
        assert_eq!(Network::Testnet.public_version(), [0x04, 0x35, 0x87, 0xCF]);
    }

    #[test]
    fn serialised_length_is_78() {
        let k = ExtendedPrivKey::from_seed(&[7u8; 32], Network::Mainnet).unwrap();
        assert_eq!(k.to_raw().len(), RAW_LEN);
        assert_eq!(k.to_extended_pub().to_raw().len(), RAW_LEN);
    }

    #[test]
    fn official_vectors_round_trip_through_base58() {
        for v in VECTORS {
            let master = ExtendedPrivKey::from_seed(&unhex(v.seed), Network::Mainnet).unwrap();
            for (path, want_xpub, want_xprv) in v.chains {
                let key = master.derive_path(&path.parse().unwrap()).unwrap();
                let xprv = key.to_base58();
                let xpub = key.to_extended_pub().to_base58();
                assert_eq!(xprv, *want_xprv);
                assert_eq!(xpub, *want_xpub);

                // And back again.
                assert_eq!(ExtendedPrivKey::from_base58(&xprv).unwrap(), key);
                assert_eq!(
                    ExtendedPubKey::from_base58(&xpub).unwrap(),
                    key.to_extended_pub()
                );
            }
        }
    }

    #[test]
    fn prefixes_are_what_users_recognise() {
        let m = ExtendedPrivKey::from_seed(&[7u8; 32], Network::Mainnet).unwrap();
        assert!(m.to_base58().starts_with("xprv"));
        assert!(m.to_extended_pub().to_base58().starts_with("xpub"));

        let t = ExtendedPrivKey::from_seed(&[7u8; 32], Network::Testnet).unwrap();
        assert!(t.to_base58().starts_with("tprv"));
        assert!(t.to_extended_pub().to_base58().starts_with("tpub"));
    }

    #[test]
    fn an_xpub_cannot_be_parsed_as_an_xprv() {
        // Confusing the two would be catastrophic in either direction.
        let m = ExtendedPrivKey::from_seed(&[7u8; 32], Network::Mainnet).unwrap();
        let xpub = m.to_extended_pub().to_base58();
        assert_eq!(ExtendedPrivKey::from_base58(&xpub), Err(Error::BadVersion));

        let xprv = m.to_base58();
        assert_eq!(ExtendedPubKey::from_base58(&xprv), Err(Error::BadVersion));
    }

    #[test]
    fn a_private_key_field_must_be_zero_padded() {
        let m = ExtendedPrivKey::from_seed(&[7u8; 32], Network::Mainnet).unwrap();
        let mut raw = m.to_raw();
        raw[45] = 0x01;
        assert_eq!(
            ExtendedPrivKey::from_raw(&raw),
            Err(Error::BadPrivatePrefix)
        );
    }

    #[test]
    fn unknown_version_bytes_are_rejected() {
        let m = ExtendedPrivKey::from_seed(&[7u8; 32], Network::Mainnet).unwrap();
        let mut raw = m.to_raw();
        raw[0..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(ExtendedPrivKey::from_raw(&raw), Err(Error::BadVersion));
    }

    #[test]
    fn wrong_length_is_rejected() {
        let m = ExtendedPrivKey::from_seed(&[7u8; 32], Network::Mainnet).unwrap();
        let raw = m.to_raw();
        assert!(matches!(
            ExtendedPrivKey::from_raw(&raw[..77]),
            Err(Error::BadLength { len: 77 })
        ));
    }

    #[test]
    fn a_zero_private_key_is_rejected() {
        // Not reachable by derivation, but reachable by a crafted xprv.
        let m = ExtendedPrivKey::from_seed(&[7u8; 32], Network::Mainnet).unwrap();
        let mut raw = m.to_raw();
        raw[46..78].fill(0);
        assert_eq!(ExtendedPrivKey::from_raw(&raw), Err(Error::InvalidKey));
    }

    #[test]
    fn an_off_curve_public_key_is_rejected() {
        let m = ExtendedPrivKey::from_seed(&[7u8; 32], Network::Mainnet).unwrap();
        let mut raw = m.to_extended_pub().to_raw();
        // Valid prefix, x coordinate that is not on the curve.
        raw[45] = 0x02;
        raw[46..78].fill(0xff);
        assert_eq!(ExtendedPubKey::from_raw(&raw), Err(Error::InvalidKey));
    }

    #[test]
    fn depth_zero_must_have_no_parent() {
        let m = ExtendedPrivKey::from_seed(&[7u8; 32], Network::Mainnet).unwrap();
        let mut raw = m.to_raw();
        raw[5..9].copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(
            ExtendedPrivKey::from_raw(&raw),
            Err(Error::InconsistentDepth)
        );

        let mut raw = m.to_raw();
        raw[9..13].copy_from_slice(&[0, 0, 0, 1]);
        assert_eq!(
            ExtendedPrivKey::from_raw(&raw),
            Err(Error::InconsistentDepth)
        );
    }

    #[test]
    fn a_corrupted_base58_string_fails_the_checksum() {
        let m = ExtendedPrivKey::from_seed(&[7u8; 32], Network::Mainnet).unwrap();
        let good = m.to_base58();
        let mut chars: Vec<char> = good.chars().collect();
        chars[10] = if chars[10] == 'A' { 'B' } else { 'A' };
        let bad: String = chars.into_iter().collect();
        assert!(matches!(
            ExtendedPrivKey::from_base58(&bad),
            Err(Error::Base58(base58::Error::BadChecksum))
        ));
    }

    #[test]
    fn write_base58_agrees_with_to_base58() {
        let m = ExtendedPrivKey::from_seed(&[7u8; 32], Network::Mainnet).unwrap();
        let mut buf = [0u8; MAX_BASE58_LEN];
        let n = m.write_base58(&mut buf).unwrap();
        assert_eq!(core::str::from_utf8(&buf[..n]).unwrap(), m.to_base58());
    }
}
