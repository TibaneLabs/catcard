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

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::encoding::base58;

use super::{
    CHAIN_CODE_LEN, ChildNumber, ExtendedPrivKey, ExtendedPubKey, FINGERPRINT_LEN, PRIVKEY_LEN,
    PUBKEY_LEN,
};

/// Serialised length before Base58Check.
pub const RAW_LEN: usize = 78;
/// Enough room for the Base58Check form of [`RAW_LEN`] plus a checksum.
pub const MAX_BASE58_LEN: usize = 128;

/// Which network's parameters to use.
///
/// Testnet4 and regtest **share the same extended-key version bytes and the same base58
/// address prefixes** — the version bytes carry no more than "not mainnet". They differ
/// only in the bech32 HRP (`tb` vs `bcrt`) and in nothing else, so regtest is a variant
/// for the address layer's sake and reads back as [`Network::Testnet`] off any serialised
/// key. Both use SLIP-44 coin type 1.
///
/// Source: hw-reference/wallet-export-formats.md §"Chain parameters" [C].
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum Network {
    #[default]
    Mainnet,
    Testnet,
    Regtest,
}

impl Network {
    /// Whether this is mainnet. Mainnet is the only network with its own version bytes
    /// and base58 prefixes; testnet and regtest share a single "not mainnet" set.
    pub const fn is_mainnet(self) -> bool {
        matches!(self, Network::Mainnet)
    }

    /// The SLIP-44 coin type for the `m/{purpose}'/<coin>'` level: `0` on mainnet, `1` on
    /// both testnet and regtest. SLIP-0044 reserves coin type 1 for "Testnet (all coins)".
    ///
    /// Source: hw-reference/firmware-features.md §1 [C]; SLIP-0044 coin type 1 [C].
    pub const fn coin_type(self) -> u32 {
        if self.is_mainnet() { 0 } else { 1 }
    }

    /// `xprv` / `tprv`.
    pub const fn private_version(self) -> [u8; 4] {
        if self.is_mainnet() {
            0x0488_ADE4u32.to_be_bytes()
        } else {
            0x0435_8394u32.to_be_bytes()
        }
    }

    /// `xpub` / `tpub`.
    pub const fn public_version(self) -> [u8; 4] {
        if self.is_mainnet() {
            0x0488_B21Eu32.to_be_bytes()
        } else {
            0x0435_87CFu32.to_be_bytes()
        }
    }

    /// Read four version bytes back: the network, whether the key is private, and the
    /// SLIP-132 form they were written in.
    ///
    /// Every SLIP-132 form is accepted on the way in, as stock does ("read always"): a
    /// `zpub` is the same 74 bytes of key as its `xpub`, and refusing it would refuse
    /// every wallet that exports native-segwit keys the way SLIP-132 says to. The form is
    /// returned rather than dropped, so a caller with an opinion about the script type --
    /// a multisig descriptor, which states one -- can check the hint against it.
    ///
    /// Regtest is not listed: it shares testnet's bytes, so a key with these prefixes
    /// reads back as `Testnet`. Regtest is a display-time choice the bytes do not record.
    /// Source: SLIP-0132 registry, Bitcoin and Bitcoin Testnet rows [C].
    fn from_version(v: &[u8]) -> Option<(Network, bool, Slip132)> {
        let b: [u8; 4] = v.try_into().ok()?;
        for n in [Network::Mainnet, Network::Testnet] {
            for form in Slip132::ALL {
                if b == form.private_version(n) {
                    return Some((n, true, form));
                }
                if b == form.version(n) {
                    return Some((n, false, form));
                }
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
///
/// For a private key `key` holds the scalar, so the whole thing is wiped on drop --
/// including when `from_raw` refuses what it read.
#[derive(Zeroize, ZeroizeOnDrop)]
struct Common {
    #[zeroize(skip)]
    network: Network,
    #[zeroize(skip)]
    is_private: bool,
    /// The SLIP-132 form the version bytes announced; [`Slip132::Classic`] for a plain
    /// `xpub`/`xprv`.
    #[zeroize(skip)]
    form: Slip132,
    depth: u8,
    parent_fingerprint: [u8; FINGERPRINT_LEN],
    #[zeroize(skip)]
    child_number: ChildNumber,
    chain_code: [u8; CHAIN_CODE_LEN],
    key: [u8; PUBKEY_LEN],
}

fn read_common(raw: &[u8]) -> Result<Common, Error> {
    if raw.len() != RAW_LEN {
        return Err(Error::BadLength { len: raw.len() });
    }
    let (network, is_private, form) = Network::from_version(&raw[0..4]).ok_or(Error::BadVersion)?;

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
        form,
        depth,
        parent_fingerprint,
        child_number,
        chain_code,
        key,
    })
}

impl ExtendedPrivKey {
    /// The raw 78-byte form. It carries the scalar, so it wipes itself when dropped, and
    /// like every other copy of the scalar it is made inside the masked region.
    pub fn to_raw(&self, _kw: &crate::KeyWork) -> Zeroizing<[u8; RAW_LEN]> {
        let mut out = Zeroizing::new([0u8; RAW_LEN]);
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
    pub fn to_base58(&self, kw: &crate::KeyWork) -> alloc_string::String {
        let mut buf = Zeroizing::new([0u8; MAX_BASE58_LEN]);
        let n = self
            .write_base58(&mut buf[..], kw)
            .expect("buffer is large enough");
        core::str::from_utf8(&buf[..n])
            .expect("Base58 output is ASCII")
            .into()
    }

    /// Write the `xprv` string into `out`; returns the length.
    ///
    /// Base58 is repeated big-integer division, whose running time depends on the digits --
    /// here, the private key's.
    pub fn write_base58(&self, out: &mut [u8], kw: &crate::KeyWork) -> Result<usize, Error> {
        Ok(base58::encode_check(&self.to_raw(kw)[..], out)?)
    }

    /// Parse an `xprv`/`tprv` string, or a SLIP-132 form of one (`yprv`, `zprv`, ...):
    /// the form is only a hint about how the key is meant to be spent, and the key itself
    /// is the same either way.
    pub fn from_base58(text: &str, kw: &crate::KeyWork) -> Result<Self, Error> {
        let mut raw = Zeroizing::new([0u8; base58::MAX_DECODED]);
        let n = base58::decode_check(text, &mut raw[..])?;
        Self::from_raw(&raw[..n], kw)
    }

    /// Parse the raw 78-byte form. Private-key work: the bytes are the scalar, and the
    /// range check on it is arithmetic over it.
    pub fn from_raw(raw: &[u8], _kw: &crate::KeyWork) -> Result<Self, Error> {
        // `c` and `secret` both hold the scalar, and both are wiped on every exit path,
        // the refusals below included.
        let c = read_common(raw)?;
        if !c.is_private {
            return Err(Error::BadVersion);
        }
        if c.key[0] != 0x00 {
            return Err(Error::BadPrivatePrefix);
        }
        let mut secret = Zeroizing::new([0u8; PRIVKEY_LEN]);
        secret.copy_from_slice(&c.key[1..]);
        // Reject zero and out-of-range scalars rather than carrying an unusable key.
        if super::scalar_from_bytes(&secret).is_none() {
            return Err(Error::InvalidKey);
        }
        Ok(Self::from_parts(
            c.network,
            c.depth,
            c.parent_fingerprint,
            c.child_number,
            c.chain_code,
            *secret,
        ))
    }
}

/// SLIP-132 version bytes: the same key, announced as the script type it is for.
///
/// An `xpub` says nothing about how its keys are meant to be spent, so SLIP-132 gives
/// each script type its own version bytes and therefore its own prefix -- `ypub` for
/// BIP-49, `zpub` for BIP-84, and the capitalised pair for the BIP-48 multisig levels.
/// The key material is identical; only the four bytes in front of it differ.
///
/// It is not a BIP and plenty of software ignores it, which is why exports carry the
/// classic form as `xpub` and add this alongside as `_pub` only when it differs.
///
/// Source: hw-reference/wallet-export-formats.md §"Chain parameters" [C].
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Slip132 {
    /// `xpub` / `tpub` -- BIP-44, and the form everything understands.
    Classic,
    /// `ypub` / `upub` -- BIP-49, P2WPKH nested in P2SH.
    P2wpkhP2sh,
    /// `zpub` / `vpub` -- BIP-84, native P2WPKH.
    P2wpkh,
    /// `Ypub` / `Upub` -- BIP-48 `.../1h`, P2WSH nested in P2SH.
    P2wshP2sh,
    /// `Zpub` / `Vpub` -- BIP-48 `.../2h`, native P2WSH.
    P2wsh,
}

impl Slip132 {
    /// Every form, classic first.
    pub const ALL: [Slip132; 5] = [
        Slip132::Classic,
        Slip132::P2wpkhP2sh,
        Slip132::P2wpkh,
        Slip132::P2wshP2sh,
        Slip132::P2wsh,
    ];

    /// The prefix a public key in this form starts with, for a screen or a log.
    pub const fn prefix(self, network: Network) -> &'static str {
        match (self, network.is_mainnet()) {
            (Slip132::Classic, true) => "xpub",
            (Slip132::Classic, false) => "tpub",
            (Slip132::P2wpkhP2sh, true) => "ypub",
            (Slip132::P2wpkhP2sh, false) => "upub",
            (Slip132::P2wpkh, true) => "zpub",
            (Slip132::P2wpkh, false) => "vpub",
            (Slip132::P2wshP2sh, true) => "Ypub",
            (Slip132::P2wshP2sh, false) => "Upub",
            (Slip132::P2wsh, true) => "Zpub",
            (Slip132::P2wsh, false) => "Vpub",
        }
    }

    /// The four version bytes of this form's *private* key: `yprv`, `zprv`, `Yprv`,
    /// `Zprv`, and the testnet `uprv`/`vprv`/`Uprv`/`Vprv`.
    ///
    /// Read on import only -- this firmware never writes a private key in a SLIP-132
    /// form -- so a `zprv` typed in from another wallet's backup is taken as the `xprv`
    /// it is. Source: SLIP-0132 registry, Bitcoin and Bitcoin Testnet rows [C].
    pub const fn private_version(self, network: Network) -> [u8; 4] {
        let v: u32 = match (self, network.is_mainnet()) {
            (Slip132::Classic, true) => 0x0488_ADE4,
            (Slip132::Classic, false) => 0x0435_8394,
            (Slip132::P2wpkhP2sh, true) => 0x049D_7878,
            (Slip132::P2wpkhP2sh, false) => 0x044A_4E28,
            (Slip132::P2wpkh, true) => 0x04B2_430C,
            (Slip132::P2wpkh, false) => 0x045F_18BC,
            (Slip132::P2wshP2sh, true) => 0x0295_B005,
            (Slip132::P2wshP2sh, false) => 0x0242_85B5,
            (Slip132::P2wsh, true) => 0x02AA_7A99,
            (Slip132::P2wsh, false) => 0x0257_5048,
        };
        v.to_be_bytes()
    }

    /// The four version bytes this form is announced with.
    ///
    /// Regtest shares testnet's SLIP-132 bytes, so the table turns on
    /// [`Network::is_mainnet`] rather than the exact network.
    /// Source: hw-reference/wallet-export-formats.md §"Chain parameters" [C].
    pub const fn version(self, network: Network) -> [u8; 4] {
        let v: u32 = match (self, network.is_mainnet()) {
            (Slip132::Classic, true) => 0x0488_B21E,
            (Slip132::Classic, false) => 0x0435_87CF,
            (Slip132::P2wpkhP2sh, true) => 0x049D_7CB2,
            (Slip132::P2wpkhP2sh, false) => 0x044A_5262,
            (Slip132::P2wpkh, true) => 0x04B2_4746,
            (Slip132::P2wpkh, false) => 0x045F_1CF6,
            (Slip132::P2wshP2sh, true) => 0x0295_B43F,
            (Slip132::P2wshP2sh, false) => 0x0242_89EF,
            (Slip132::P2wsh, true) => 0x02AA_7ED3,
            (Slip132::P2wsh, false) => 0x0257_5483,
        };
        v.to_be_bytes()
    }
}

impl ExtendedPubKey {
    /// As [`write_base58`](Self::write_base58), in a SLIP-132 form.
    ///
    /// Only the version bytes change; the depth, fingerprint, chain code and key are the
    /// same bytes in the same places, so the two encodings describe one key.
    pub fn write_base58_as(&self, form: Slip132, out: &mut [u8]) -> Result<usize, Error> {
        let mut raw = self.to_raw();
        raw[..4].copy_from_slice(&form.version(self.network));
        Ok(base58::encode_check(&raw, out)?)
    }

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

    /// Parse an `xpub`/`tpub` string, or any SLIP-132 form of one (`ypub`, `zpub`,
    /// `Ypub`, `Zpub` and the testnet `upub`/`vpub`/`Upub`/`Vpub`).
    ///
    /// The form is dropped: it is a hint about the script type, and a caller with no
    /// script type to check it against has no use for it. [`Self::from_base58_with_form`]
    /// keeps it.
    pub fn from_base58(text: &str) -> Result<Self, Error> {
        Self::from_base58_with_form(text).map(|(key, _)| key)
    }

    /// As [`Self::from_base58`], also returning which SLIP-132 form the text was in.
    pub fn from_base58_with_form(text: &str) -> Result<(Self, Slip132), Error> {
        let mut raw = [0u8; base58::MAX_DECODED];
        let n = base58::decode_check(text, &mut raw)?;
        Self::from_raw_with_form(&raw[..n])
    }

    /// Parse the raw 78-byte form, in the classic or any SLIP-132 version.
    pub fn from_raw(raw: &[u8]) -> Result<Self, Error> {
        Self::from_raw_with_form(raw).map(|(key, _)| key)
    }

    /// As [`Self::from_raw`], also returning which SLIP-132 form the bytes were in.
    ///
    /// The key comes back normalised: its own [`Self::to_raw`] writes the classic version
    /// bytes whatever it was read from, so two spellings of one key compare equal.
    pub fn from_raw_with_form(raw: &[u8]) -> Result<(Self, Slip132), Error> {
        let c = read_common(raw)?;
        if c.is_private {
            return Err(Error::BadVersion);
        }
        // Must be a compressed point on the curve; 0x04 (uncompressed) is not valid
        // here, and neither is an off-curve x coordinate.
        if purecrypto::ec::secp256k1::AffinePoint::from_sec1(&c.key).is_err() {
            return Err(Error::InvalidKey);
        }
        Ok((
            Self {
                network: c.network,
                depth: c.depth,
                parent_fingerprint: c.parent_fingerprint,
                child_number: c.child_number,
                chain_code: c.chain_code,
                public_key: c.key,
            },
            c.form,
        ))
    }
}

#[cfg(feature = "std")]
mod alloc_string {
    pub use std::string::String;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip32::test_vectors::VECTORS;

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

    /// Regtest borrows testnet's version bytes exactly, and its coin type. The two are
    /// interchangeable at the serialisation layer; only the bech32 HRP tells them apart.
    #[test]
    fn regtest_shares_testnet_version_bytes_and_coin_type() {
        assert_eq!(
            Network::Regtest.private_version(),
            Network::Testnet.private_version()
        );
        assert_eq!(
            Network::Regtest.public_version(),
            Network::Testnet.public_version()
        );
        assert_eq!(Network::Mainnet.coin_type(), 0);
        assert_eq!(Network::Testnet.coin_type(), 1);
        assert_eq!(Network::Regtest.coin_type(), 1);
    }

    /// A regtest key serialises with testnet's `tprv` prefix -- the bytes do not record
    /// regtest -- so it reads back as [`Network::Testnet`].
    #[test]
    fn a_regtest_key_reads_back_as_testnet() {
        let r = ExtendedPrivKey::from_seed(&[7u8; 32], Network::Regtest, &crate::KeyWork::host())
            .unwrap();
        assert!(r.to_base58(&crate::KeyWork::host()).starts_with("tprv"));
        let parsed = ExtendedPrivKey::from_base58(
            &r.to_base58(&crate::KeyWork::host()),
            &crate::KeyWork::host(),
        )
        .unwrap();
        assert_eq!(parsed.network, Network::Testnet);
    }

    #[test]
    fn serialised_length_is_78() {
        let k = ExtendedPrivKey::from_seed(&[7u8; 32], Network::Mainnet, &crate::KeyWork::host())
            .unwrap();
        assert_eq!(k.to_raw(&crate::KeyWork::host()).len(), RAW_LEN);
        assert_eq!(
            k.to_extended_pub(&crate::KeyWork::host()).to_raw().len(),
            RAW_LEN
        );
    }

    #[test]
    fn official_vectors_round_trip_through_base58() {
        for v in VECTORS {
            let master = ExtendedPrivKey::from_seed(
                &unhex(v.seed),
                Network::Mainnet,
                &crate::KeyWork::host(),
            )
            .unwrap();
            for (path, want_xpub, want_xprv) in v.chains {
                let key = master
                    .derive_path(&path.parse().unwrap(), &crate::KeyWork::host())
                    .unwrap();
                let xprv = key.to_base58(&crate::KeyWork::host());
                let xpub = key.to_extended_pub(&crate::KeyWork::host()).to_base58();
                assert_eq!(xprv, *want_xprv);
                assert_eq!(xpub, *want_xpub);

                // And back again.
                assert_eq!(
                    ExtendedPrivKey::from_base58(&xprv, &crate::KeyWork::host()).unwrap(),
                    key
                );
                assert_eq!(
                    ExtendedPubKey::from_base58(&xpub).unwrap(),
                    key.to_extended_pub(&crate::KeyWork::host())
                );
            }
        }
    }

    #[test]
    fn prefixes_are_what_users_recognise() {
        let m = ExtendedPrivKey::from_seed(&[7u8; 32], Network::Mainnet, &crate::KeyWork::host())
            .unwrap();
        assert!(m.to_base58(&crate::KeyWork::host()).starts_with("xprv"));
        assert!(
            m.to_extended_pub(&crate::KeyWork::host())
                .to_base58()
                .starts_with("xpub")
        );

        let t = ExtendedPrivKey::from_seed(&[7u8; 32], Network::Testnet, &crate::KeyWork::host())
            .unwrap();
        assert!(t.to_base58(&crate::KeyWork::host()).starts_with("tprv"));
        assert!(
            t.to_extended_pub(&crate::KeyWork::host())
                .to_base58()
                .starts_with("tpub")
        );
    }

    #[test]
    fn an_xpub_cannot_be_parsed_as_an_xprv() {
        // Confusing the two would be catastrophic in either direction.
        let m = ExtendedPrivKey::from_seed(&[7u8; 32], Network::Mainnet, &crate::KeyWork::host())
            .unwrap();
        let xpub = m.to_extended_pub(&crate::KeyWork::host()).to_base58();
        assert_eq!(
            ExtendedPrivKey::from_base58(&xpub, &crate::KeyWork::host()),
            Err(Error::BadVersion)
        );

        let xprv = m.to_base58(&crate::KeyWork::host());
        assert_eq!(ExtendedPubKey::from_base58(&xprv), Err(Error::BadVersion));
    }

    #[test]
    fn a_private_key_field_must_be_zero_padded() {
        let m = ExtendedPrivKey::from_seed(&[7u8; 32], Network::Mainnet, &crate::KeyWork::host())
            .unwrap();
        let mut raw = m.to_raw(&crate::KeyWork::host());
        raw[45] = 0x01;
        assert_eq!(
            ExtendedPrivKey::from_raw(&raw[..], &crate::KeyWork::host()),
            Err(Error::BadPrivatePrefix)
        );
    }

    #[test]
    fn unknown_version_bytes_are_rejected() {
        let m = ExtendedPrivKey::from_seed(&[7u8; 32], Network::Mainnet, &crate::KeyWork::host())
            .unwrap();
        let mut raw = m.to_raw(&crate::KeyWork::host());
        raw[0..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(
            ExtendedPrivKey::from_raw(&raw[..], &crate::KeyWork::host()),
            Err(Error::BadVersion)
        );
    }

    #[test]
    fn wrong_length_is_rejected() {
        let m = ExtendedPrivKey::from_seed(&[7u8; 32], Network::Mainnet, &crate::KeyWork::host())
            .unwrap();
        let raw = m.to_raw(&crate::KeyWork::host());
        assert!(matches!(
            ExtendedPrivKey::from_raw(&raw[..77], &crate::KeyWork::host()),
            Err(Error::BadLength { len: 77 })
        ));
    }

    #[test]
    fn a_zero_private_key_is_rejected() {
        // Not reachable by derivation, but reachable by a crafted xprv.
        let m = ExtendedPrivKey::from_seed(&[7u8; 32], Network::Mainnet, &crate::KeyWork::host())
            .unwrap();
        let mut raw = m.to_raw(&crate::KeyWork::host());
        raw[46..78].fill(0);
        assert_eq!(
            ExtendedPrivKey::from_raw(&raw[..], &crate::KeyWork::host()),
            Err(Error::InvalidKey)
        );
    }

    #[test]
    fn an_off_curve_public_key_is_rejected() {
        let m = ExtendedPrivKey::from_seed(&[7u8; 32], Network::Mainnet, &crate::KeyWork::host())
            .unwrap();
        let mut raw = m.to_extended_pub(&crate::KeyWork::host()).to_raw();
        // Valid prefix, x coordinate that is not on the curve.
        raw[45] = 0x02;
        raw[46..78].fill(0xff);
        assert_eq!(ExtendedPubKey::from_raw(&raw[..]), Err(Error::InvalidKey));
    }

    #[test]
    fn depth_zero_must_have_no_parent() {
        let m = ExtendedPrivKey::from_seed(&[7u8; 32], Network::Mainnet, &crate::KeyWork::host())
            .unwrap();
        let mut raw = m.to_raw(&crate::KeyWork::host());
        raw[5..9].copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(
            ExtendedPrivKey::from_raw(&raw[..], &crate::KeyWork::host()),
            Err(Error::InconsistentDepth)
        );

        let mut raw = m.to_raw(&crate::KeyWork::host());
        raw[9..13].copy_from_slice(&[0, 0, 0, 1]);
        assert_eq!(
            ExtendedPrivKey::from_raw(&raw[..], &crate::KeyWork::host()),
            Err(Error::InconsistentDepth)
        );
    }

    #[test]
    fn a_corrupted_base58_string_fails_the_checksum() {
        let m = ExtendedPrivKey::from_seed(&[7u8; 32], Network::Mainnet, &crate::KeyWork::host())
            .unwrap();
        let good = m.to_base58(&crate::KeyWork::host());
        let mut chars: Vec<char> = good.chars().collect();
        chars[10] = if chars[10] == 'A' { 'B' } else { 'A' };
        let bad: String = chars.into_iter().collect();
        assert!(matches!(
            ExtendedPrivKey::from_base58(&bad, &crate::KeyWork::host()),
            Err(Error::Base58(base58::Error::BadChecksum))
        ));
    }

    #[test]
    fn write_base58_agrees_with_to_base58() {
        let m = ExtendedPrivKey::from_seed(&[7u8; 32], Network::Mainnet, &crate::KeyWork::host())
            .unwrap();
        let mut buf = [0u8; MAX_BASE58_LEN];
        let n = m.write_base58(&mut buf, &crate::KeyWork::host()).unwrap();
        assert_eq!(
            core::str::from_utf8(&buf[..n]).unwrap(),
            m.to_base58(&crate::KeyWork::host())
        );
    }
}

#[cfg(test)]
mod slip132_tests {
    use super::*;

    /// Each form announces itself with the prefix the table says.
    ///
    /// The prefixes are the observable part: software recognises `zpub` and not the four
    /// bytes behind it, so a wrong version byte shows up as a key nobody will take.
    #[test]
    fn every_form_produces_its_documented_prefix() {
        // A key whose contents do not matter: only the version bytes are under test, and
        // base58 puts them in the first characters.
        let key = ExtendedPubKey {
            network: Network::Mainnet,
            depth: 3,
            parent_fingerprint: [1, 2, 3, 4],
            child_number: crate::bip32::ChildNumber::hardened(0).unwrap(),
            chain_code: [7u8; 32],
            public_key: {
                // A valid compressed point: the generator.
                let mut k = [0u8; 33];
                k[0] = 0x02;
                k[32] = 1;
                k
            },
        };
        for (form, want) in [
            (Slip132::Classic, "xpub"),
            (Slip132::P2wpkhP2sh, "ypub"),
            (Slip132::P2wpkh, "zpub"),
            (Slip132::P2wshP2sh, "Ypub"),
            (Slip132::P2wsh, "Zpub"),
        ] {
            let mut out = [0u8; MAX_BASE58_LEN];
            let n = key.write_base58_as(form, &mut out).expect("encodes");
            let text = core::str::from_utf8(&out[..n]).unwrap();
            assert!(text.starts_with(want), "{form:?} gave {}", &text[..4]);
        }
    }

    /// Testnet has its own set, and they are not the mainnet ones.
    #[test]
    fn testnet_has_its_own_prefixes() {
        for form in [
            Slip132::Classic,
            Slip132::P2wpkhP2sh,
            Slip132::P2wpkh,
            Slip132::P2wshP2sh,
            Slip132::P2wsh,
        ] {
            assert_ne!(
                form.version(Network::Mainnet),
                form.version(Network::Testnet),
                "{form:?} must differ by network"
            );
            // Regtest borrows testnet's SLIP-132 bytes (upub/vpub/Upub/Vpub).
            assert_eq!(
                form.version(Network::Regtest),
                form.version(Network::Testnet),
                "{form:?} regtest must match testnet"
            );
        }
    }

    /// The classic form is byte-for-byte what the ordinary encoder writes.
    ///
    /// If it were not, an export's `xpub` field and its `_pub` field would disagree about
    /// the same key, and the rule for emitting `_pub` -- only when it differs -- would be
    /// comparing the wrong things.
    #[test]
    fn the_classic_form_is_the_ordinary_one() {
        let key = ExtendedPubKey {
            network: Network::Mainnet,
            depth: 1,
            parent_fingerprint: [0; 4],
            child_number: crate::bip32::ChildNumber::normal(0).unwrap(),
            chain_code: [9u8; 32],
            public_key: {
                let mut k = [0u8; 33];
                k[0] = 0x03;
                k[32] = 2;
                k
            },
        };
        let (mut a, mut b) = ([0u8; MAX_BASE58_LEN], [0u8; MAX_BASE58_LEN]);
        let n = key.write_base58(&mut a).unwrap();
        let m = key.write_base58_as(Slip132::Classic, &mut b).unwrap();
        assert_eq!(&a[..n], &b[..m]);
    }

    /// SLIP-0132's own test vectors: the BIP-39 test mnemonic, its three account keys,
    /// and each in its published prefix. Source: SLIP-0132 §"Test vectors" [C].
    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const VECTORS: [(u32, Slip132, &str, &str); 3] = [
        (
            44,
            Slip132::Classic,
            "xprv9xpXFhFpqdQK3TmytPBqXtGSwS3DLjojFhTGht8gwAAii8py5X6pxeBnQ6ehJiyJ6nDjWGJfZ95WxByFXVkDxHXrqu53WCRGypk2ttuqncb",
            "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj",
        ),
        (
            49,
            Slip132::P2wpkhP2sh,
            "yprvAHwhK6RbpuS3dgCYHM5jc2ZvEKd7Bi61u9FVhYMpgMSuZS613T1xxQeKTffhrHY79hZ5PsskBjcc6C2V7DrnsMsNaGDaWev3GLRQRgV7hxF",
            "ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP",
        ),
        (
            84,
            Slip132::P2wpkh,
            "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE",
            "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
        ),
    ];

    /// `m/{purpose}h/0h/0h` of the SLIP-132 test mnemonic.
    fn account_of(purpose: u32) -> ExtendedPrivKey {
        use crate::bip39::{Mnemonic, SEED_LEN};
        let kw = crate::KeyWork::host();
        let m = Mnemonic::parse(MNEMONIC, &kw).unwrap();
        let mut seed = [0u8; SEED_LEN];
        m.to_seed("", &mut seed, &kw).unwrap();
        let mut key = ExtendedPrivKey::from_seed(&seed, Network::Mainnet, &kw).unwrap();
        for step in [purpose, 0, 0] {
            key = key
                .derive_child(crate::bip32::ChildNumber::hardened(step).unwrap(), &kw)
                .unwrap();
        }
        key
    }

    /// The published `ypub`/`zpub` strings are what this writes for those accounts.
    #[test]
    fn slip132_vectors_encode() {
        for (purpose, form, _, want_pub) in VECTORS {
            let key = account_of(purpose).to_extended_pub(&crate::KeyWork::host());
            let mut out = [0u8; MAX_BASE58_LEN];
            let n = key.write_base58_as(form, &mut out).unwrap();
            assert_eq!(core::str::from_utf8(&out[..n]).unwrap(), want_pub);
        }
    }

    /// A `ypub`/`zpub` reads back as the same key its `xpub` does, and says which form
    /// it was in.
    #[test]
    fn slip132_vectors_parse_as_the_same_key_with_their_form() {
        let kw = crate::KeyWork::host();
        for (purpose, form, want_prv, want_pub) in VECTORS {
            let expect = account_of(purpose);
            let (got, got_form) = ExtendedPubKey::from_base58_with_form(want_pub).unwrap();
            assert_eq!(got_form, form, "{want_pub}");
            assert_eq!(got, expect.to_extended_pub(&kw), "{want_pub}");
            // Normalised on the way in: it writes itself back as a classic xpub.
            assert!(got.to_base58().starts_with("xpub"));
            // And the plain parser takes it too, form dropped.
            assert_eq!(ExtendedPubKey::from_base58(want_pub).unwrap(), got);

            // The private forms are the same scalar as the xprv.
            let prv = ExtendedPrivKey::from_base58(want_prv, &kw).unwrap();
            assert_eq!(prv.secret_bytes(), expect.secret_bytes(), "{want_prv}");
            assert_eq!(prv.to_extended_pub(&kw), got);
        }
    }

    /// The testnet and multisig forms round-trip through their own bytes too, and a
    /// public form is still refused where a private key is wanted.
    #[test]
    fn every_form_round_trips_on_both_networks() {
        let kw = crate::KeyWork::host();
        for network in [Network::Mainnet, Network::Testnet] {
            let mut key = account_of(84).to_extended_pub(&kw);
            key.network = network;
            for form in Slip132::ALL {
                let mut out = [0u8; MAX_BASE58_LEN];
                let n = key.write_base58_as(form, &mut out).unwrap();
                let text = core::str::from_utf8(&out[..n]).unwrap();
                assert!(text.starts_with(form.prefix(network)), "{text}");
                let (back, got_form) = ExtendedPubKey::from_base58_with_form(text).unwrap();
                assert_eq!((back, got_form), (key, form), "{text}");
                assert_eq!(
                    ExtendedPrivKey::from_base58(text, &kw).err(),
                    Some(Error::BadVersion),
                    "a public key is not a private one, whatever its prefix"
                );
            }
        }
    }
}
