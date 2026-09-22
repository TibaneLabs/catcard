//! `crypto-output` and `crypto-account`: the account xpubs a wallet imports.
//!
//! Source: BCR-2020-010 §CDDL for the output descriptor, BCR-2020-015 §CDDL for the
//! account that bundles several of them. [C]
//!
//! An account is a master fingerprint and one output descriptor per script type, each
//! wrapping the account-level extended key for that type:
//!
//! ```text
//! { 1: <master fingerprint>, 2: [ 308(<script tags>(303(<hdkey>))), ... ] }
//! ```
//!
//! # A deliberately narrow reader
//!
//! An output descriptor's script functions nest freely -- `sh`, `wsh`, `multi`,
//! `sortedmulti`, `raw`, `addr`, a bare public key. This reads the seven forms
//! BCR-2020-015 lists as account-level derivations and refuses the rest, rather than
//! understanding half of a descriptor. A device that shows an address it derived from
//! a script it only partly parsed is showing somebody else's address.
//!
//! The version-3 body under tag #6.40308 -- a text descriptor with a keys array, from
//! BCR-2023-010 -- is a different structure and is refused as such, not misread as
//! this one. [C]

use super::hdkey::{self, Tags};
use super::{
    Component, Error, HdKey, KeyPath, TAG_ACCOUNT_V1, TAG_ACCOUNT_V2, TAG_HDKEY_V1, TAG_HDKEY_V2,
    TAG_OUTPUT_V1, TAG_OUTPUT_V2,
};
use crate::cbor::{self, Reader, Writer};

// Script-function tags. Source: BCR-2020-010 §CDDL [C]
const TAG_SH: u64 = 400;
const TAG_WSH: u64 = 401;
const TAG_PKH: u64 = 403;
const TAG_WPKH: u64 = 404;
const TAG_TR: u64 = 409;
const TAG_COSIGNER: u64 = 410;

/// The script an account-level key is for.
///
/// Exactly the set BCR-2020-015 tabulates, with the derivations it gives for Bitcoin
/// mainnet account 0. [C] BCR-2020-015 §Introduction
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Script {
    /// `pkh(KEY)`, `m/44'/0'/0'`. [C]
    Pkh,
    /// `sh(wpkh(KEY))`, `m/49'/0'/0'`. [C]
    ShWpkh,
    /// `wpkh(KEY)`, `m/84'/0'/0'`. [C]
    Wpkh,
    /// `sh(cosigner(KEY))`, `m/45'`. [C]
    ShCosigner,
    /// `sh(wsh(cosigner(KEY)))`, `m/48'/0'/0'/1'`. [C]
    ShWshCosigner,
    /// `wsh(cosigner(KEY))`, `m/48'/0'/0'/2'`. [C]
    WshCosigner,
    /// `tr(KEY)`, `m/86'/0'/0'`. [C]
    Tr,
}

/// The tag chain for each script, outermost first. The key's own tag follows.
const CHAINS: [(Script, &[u64]); 7] = [
    (Script::Pkh, &[TAG_PKH]),
    (Script::ShWpkh, &[TAG_SH, TAG_WPKH]),
    (Script::Wpkh, &[TAG_WPKH]),
    (Script::ShCosigner, &[TAG_SH, TAG_COSIGNER]),
    (Script::ShWshCosigner, &[TAG_SH, TAG_WSH, TAG_COSIGNER]),
    (Script::WshCosigner, &[TAG_WSH, TAG_COSIGNER]),
    (Script::Tr, &[TAG_TR]),
];

/// The deepest tag chain, plus the `crypto-output` wrapper.
const MAX_CHAIN: usize = 4;

impl Script {
    /// The script a chain of tags names, or `None` if it is not one of the seven.
    fn from_tags(tags: &[u64]) -> Option<Script> {
        CHAINS
            .iter()
            .find(|(_, chain)| *chain == tags)
            .map(|&(script, _)| script)
    }

    /// The tags this script is written as, outermost first.
    const fn tags(self) -> &'static [u64] {
        // A match rather than a table lookup, so the compiler proves it total.
        match self {
            Script::Pkh => &[TAG_PKH],
            Script::ShWpkh => &[TAG_SH, TAG_WPKH],
            Script::Wpkh => &[TAG_WPKH],
            Script::ShCosigner => &[TAG_SH, TAG_COSIGNER],
            Script::ShWshCosigner => &[TAG_SH, TAG_WSH, TAG_COSIGNER],
            Script::WshCosigner => &[TAG_WSH, TAG_COSIGNER],
            Script::Tr => &[TAG_TR],
        }
    }

    /// The BIP-44 purpose level this script's account is derived under, as
    /// BCR-2020-015 tabulates it. `None` for the two BIP-48 cosigner forms and for
    /// BIP-45, whose paths are not a single purpose number.
    pub const fn bip44_purpose(self) -> Option<u32> {
        match self {
            Script::Pkh => Some(44),
            Script::ShWpkh => Some(49),
            Script::Wpkh => Some(84),
            Script::Tr => Some(86),
            Script::ShCosigner | Script::ShWshCosigner | Script::WshCosigner => None,
        }
    }
}

/// One output descriptor: a script and the account-level key it holds.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Descriptor {
    pub script: Script,
    pub key: HdKey,
}

impl Descriptor {
    /// Read one `crypto-output` message.
    pub fn decode(message: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(message);
        let d = Self::read(&mut r)?;
        if !r.at_end() {
            return Err(Error::Trailing);
        }
        Ok(d)
    }

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        let mut chain: heapless::Vec<u64, MAX_CHAIN> = heapless::Vec::new();
        // Walk the tags until the one that starts the key. `peek_tag` rather than
        // `tag`, so the key's own tag is left for `HdKey::read` to check.
        while let Some(tag) = r.peek_tag() {
            if tag == TAG_HDKEY_V1 || tag == TAG_HDKEY_V2 {
                break;
            }
            // A version-3 output descriptor is a map with a text `source`, not a tag
            // chain. Say so rather than failing on the shape underneath.
            if tag == TAG_OUTPUT_V2 {
                return Err(Error::Unsupported);
            }
            let _ = r.tag()?;
            // At the top level of a `ur:crypto-output` there is no #6.308; inside an
            // account there is. Either way it is not part of the script.
            if tag == TAG_OUTPUT_V1 && chain.is_empty() {
                continue;
            }
            chain.push(tag).map_err(|_| Error::Unsupported)?;
        }
        // Nothing but an HD key is read: a `crypto-eckey` or a `crypto-address` in the
        // key position leaves the loop with no key tag in sight.
        let script = Script::from_tags(&chain).ok_or(Error::Unsupported)?;
        Ok(Descriptor {
            script,
            key: HdKey::read(r)?,
        })
    }

    /// An account-level descriptor, from the BIP-32 parts of the key.
    ///
    /// `path` is the derivation, all hardened, each index without the hardening bit --
    /// one of [`STANDARD`]'s rows. The three optional fields BCR-2020-007 calls out
    /// are all filled in: with the chain code, the origin and the parent fingerprint
    /// present, the key is isomorphic with its BIP-32 serialization, and a wallet that
    /// receives anything less cannot derive an address from it.
    /// [C] BCR-2020-007 §"CDDL for HDKey"
    ///
    /// `use-info` is deliberately absent: an omitted one means mainnet Bitcoin, which
    /// is what this is, and every published vector leaves it out for that reason. [C]
    pub fn account_key(
        script: Script,
        path: &[u32],
        master_fingerprint: u32,
        parent_fingerprint: u32,
        public_key: [u8; 33],
        chain_code: [u8; 32],
    ) -> Result<Self, Error> {
        let mut components: heapless::Vec<Component, { hdkey::MAX_COMPONENTS }> =
            heapless::Vec::new();
        for &index in path {
            components
                .push(Component::hardened(index))
                .map_err(|_| Error::TooMany)?;
        }
        let mut key = HdKey::derived(public_key);
        key.chain_code = Some(chain_code);
        key.parent_fingerprint = Some(parent_fingerprint);
        key.origin = Some(KeyPath::new(master_fingerprint, &components)?);
        Ok(Descriptor { script, key })
    }

    /// Write one `crypto-output` message, untagged as a UR's top level.
    ///
    /// Version 1 throughout: the script tags only exist in a version-1 descriptor, so
    /// the key inside carries the version-1 tags to match.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        self.write(&mut w)?;
        Ok(w.len())
    }

    pub(crate) fn write(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        for &tag in self.script.tags() {
            w.tag(tag)?;
        }
        w.tag(Tags::V1.hdkey())?;
        self.key.write(Tags::V1, w)
    }
}

/// The standard account derivations, with the script each one is for.
///
/// Exactly BCR-2020-015's table, for Bitcoin mainnet and account zero. Every level is
/// hardened, and the index is written without the hardening bit -- 44, not the number
/// BIP-32 derives with -- because the BCR carries the flag beside the number.
/// [C] BCR-2020-015 §Introduction, BCR-2020-007 §"CDDL for Key Path"
///
/// Here rather than in the firmware, so that the table the device exports from is the
/// one the published vector is checked against.
pub const STANDARD: [(Script, &[u32]); 7] = [
    (Script::Pkh, &[44, 0, 0]),
    (Script::ShWpkh, &[49, 0, 0]),
    (Script::Wpkh, &[84, 0, 0]),
    // BIP-45's path is a single level and takes neither coin nor account. [C]
    (Script::ShCosigner, &[45]),
    (Script::ShWshCosigner, &[48, 0, 0, 1]),
    (Script::WshCosigner, &[48, 0, 0, 2]),
    (Script::Tr, &[86, 0, 0]),
];

/// The most output descriptors an account may carry.
///
/// BCR-2020-015 lists seven standard script types; this leaves room for a sender that
/// adds a few of its own without letting a length field turn a scan into a hang.
pub const MAX_DESCRIPTORS: usize = 16;

/// A BIP-44 account: a master fingerprint and its per-script account keys.
///
/// The descriptors are not held -- they are read out of the message one at a time by
/// [`Account::descriptors`]. Seven `HdKey`s at once is most of a kilobyte, and on the
/// Q1 the stack is the scarce thing.
#[derive(Clone, Debug)]
pub struct Account<'a> {
    /// The fingerprint of the master public key, per BIP-32. This is the source of
    /// truth for any key inside that omits its own. [C] BCR-2020-015 §Introduction
    pub master_fingerprint: u32,
    body: Reader<'a>,
    count: usize,
}

impl<'a> Account<'a> {
    // Map keys. Source: BCR-2020-015 §CDDL [C]
    const MASTER_FINGERPRINT: u64 = 1;
    const DESCRIPTORS: u64 = 2;

    /// Read one `crypto-account` message.
    pub fn decode(message: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(message);
        if let Some(tag) = r.peek_tag() {
            // The version-2 `account-descriptor` holds version-3 output descriptors,
            // which are a different structure.
            if tag == TAG_ACCOUNT_V2 {
                return Err(Error::Unsupported);
            }
            if tag != TAG_ACCOUNT_V1 {
                return Err(Error::Tag(tag));
            }
            let _ = r.tag()?;
        }

        let pairs = r.map()?;
        if pairs > 16 {
            return Err(Error::Cbor(cbor::Error::TooDeep));
        }
        let mut fingerprint = None;
        let mut body = None;
        for _ in 0..pairs {
            match r.uint()? {
                Self::MASTER_FINGERPRINT => fingerprint = Some(r.u32()?),
                Self::DESCRIPTORS => {
                    let mut probe = r.clone();
                    let count = probe.array()?;
                    // "[+ output-exp]" -- one or more. [C]
                    if count == 0 || count as usize > MAX_DESCRIPTORS {
                        return Err(Error::TooMany);
                    }
                    body = Some((probe, count as usize));
                    r.skip()?;
                }
                _ => r.skip()?,
            }
        }
        if !r.at_end() {
            return Err(Error::Trailing);
        }

        let master_fingerprint = fingerprint.ok_or(Error::Field(Self::MASTER_FINGERPRINT as u8))?;
        let (body, count) = body.ok_or(Error::Field(Self::DESCRIPTORS as u8))?;
        Ok(Account {
            master_fingerprint,
            body,
            count,
        })
    }

    /// How many output descriptors the account claims.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Never true: the CDDL requires at least one descriptor, and [`Account::decode`]
    /// refuses a message that has none.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The descriptors, read one at a time.
    ///
    /// Each is a separate `Result`: one descriptor in a shape this does not read does
    /// not make the others unreadable, and a caller importing an account wants the
    /// script types it understands.
    pub fn descriptors(&self) -> Descriptors<'a> {
        Descriptors {
            r: self.body.clone(),
            left: self.count,
        }
    }
}

/// The iterator [`Account::descriptors`] hands back.
pub struct Descriptors<'a> {
    r: Reader<'a>,
    left: usize,
}

impl Iterator for Descriptors<'_> {
    type Item = Result<Descriptor, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;
        let got = Descriptor::read(&mut self.r);
        // A descriptor that would not read leaves the cursor part way through it, so
        // the ones after it cannot be found. Stop rather than return noise.
        if got.is_err() {
            self.left = 0;
        }
        Some(got)
    }
}

/// Writes a `crypto-account`, one descriptor at a time.
///
/// A CBOR array declares its length before its elements, so the count is fixed up
/// front and [`Encoder::finish`] refuses if fewer arrived: an array header that
/// promises seven and delivers five is a document that lies about itself, and a
/// decoder would read whatever followed as the sixth.
pub struct Encoder<'a> {
    w: Writer<'a>,
    left: u32,
}

impl<'a> Encoder<'a> {
    /// Begin an account of exactly `count` descriptors.
    pub fn new(out: &'a mut [u8], master_fingerprint: u32, count: u32) -> Result<Self, Error> {
        if count == 0 || count as usize > MAX_DESCRIPTORS {
            return Err(Error::TooMany);
        }
        let mut w = Writer::new(out);
        w.map(2)?;
        w.uint(Account::MASTER_FINGERPRINT)?;
        w.uint(master_fingerprint as u64)?;
        w.uint(Account::DESCRIPTORS)?;
        w.array(count as u64)?;
        Ok(Encoder { w, left: count })
    }

    /// Add one output descriptor.
    pub fn push(&mut self, script: Script, key: &HdKey) -> Result<(), Error> {
        if self.left == 0 {
            return Err(Error::TooMany);
        }
        self.left -= 1;
        // `output_exp = #6.308(crypto-output)`: inside an account each descriptor is
        // tagged, unlike a standalone `ur:crypto-output`. [C] BCR-2020-015 §CDDL
        self.w.tag(TAG_OUTPUT_V1)?;
        for &tag in script.tags() {
            self.w.tag(tag)?;
        }
        self.w.tag(Tags::V1.hdkey())?;
        key.write(Tags::V1, &mut self.w)
    }

    /// Finish, giving the length of the message.
    pub fn finish(self) -> Result<usize, Error> {
        if self.left != 0 {
            return Err(Error::Field(Account::DESCRIPTORS as u8));
        }
        Ok(self.w.len())
    }
}
