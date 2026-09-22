//! The registry items a UR carries, once the transport has put the message back
//! together.
//!
//! The UR type names the item; the message is that item's CBOR. Without this the
//! message reaches the rest of the firmware with a CBOR header still on the front --
//! a PSBT with `58 a7` before `psbt\xff`, which parses as neither.
//!
//! # Two generations of names, and which this device writes
//!
//! BCR-2020-006's registry renamed every `crypto-*` type in 2023 and renumbered its
//! CBOR tag: `crypto-hdkey` #6.303 became `hdkey` #6.40303, `crypto-psbt` #6.310
//! became `psbt` #6.40310, and so on. The registry recommends reading the old names
//! and writing the new ones. [C] BCR-2020-006 §"Registry"
//!
//! **Both are read. `crypto-psbt` is what is written**, against that recommendation
//! and deliberately: the wallets a Coldcard is pointed at -- the ones that will be
//! holding the camera -- read `crypto-psbt`, and several still do not read `psbt`. A
//! QR that a wallet refuses is a device that cannot sign. The names are one constant
//! each ([`Kind::written_as`]), so this reverses in one line when the installed base
//! moves.
//!
//! # What is read, and what is not
//!
//! The rename was not always only a rename. `output-descriptor` #6.40308
//! (BCR-2023-010) and `account-descriptor` #6.40311 (BCR-2023-019) are *different
//! structures* from the `crypto-output` #6.308 and `crypto-account` #6.311 they
//! replaced: a text descriptor with a keys array, rather than a chain of script tags
//! around a key. [C] BCR-2023-010 §CDDL, BCR-2023-019 §CDDL
//!
//! So the new names are accepted and the new bodies are not: an item under tag 40308
//! or 40311 is refused as [`Error::Unsupported`] rather than read as though it were
//! the old shape. Half-understanding a descriptor is how a device shows an address
//! that belongs to somebody else.

use crate::cbor;

pub mod account;
pub mod bytestring;
pub mod hdkey;

pub use account::{Account, Descriptor, Script};
pub use hdkey::{CoinInfo, Component, HdKey, KeyPath, Tags};

/// Why a message is not the registry item its UR type claims.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// The CBOR itself is malformed, or outside the subset that is read.
    Cbor(cbor::Error),
    /// A CBOR tag that does not belong where it was found.
    Tag(u64),
    /// A field the item cannot do without is missing, or appeared twice. The value is
    /// the field's map key, as the BCR numbers it.
    Field(u8),
    /// A byte string of a length the field does not have -- a 33-byte key, a 32-byte
    /// chain code.
    Size(usize),
    /// Bytes after the item. The message is then not this item, whatever its front
    /// looked like.
    Trailing,
    /// A shape the specification defines and this does not read: a version-3 output
    /// descriptor, a script function outside the account-level set, a key that is not
    /// an HD key.
    Unsupported,
    /// More path components, or more output descriptors, than the fixed room here.
    TooMany,
}

impl From<cbor::Error> for Error {
    fn from(e: cbor::Error) -> Self {
        Error::Cbor(e)
    }
}

// CBOR tags, both generations. Source: BCR-2020-006 §"Registry" [C]
//
// The version-1 tags are three digits, the version-2 tags the same number plus 40000.
// Script-function tags 400..=410 were never renumbered -- they are not registry types,
// only the internals of a version-1 `crypto-output`. [C] BCR-2020-010 §CDDL

/// `crypto-hdkey`, BCR-2020-007. [C]
pub const TAG_HDKEY_V1: u64 = 303;
/// `hdkey`, BCR-2020-007. [C]
pub const TAG_HDKEY_V2: u64 = 40303;
/// `crypto-keypath`, BCR-2020-007. [C]
pub const TAG_KEYPATH_V1: u64 = 304;
/// `keypath`, BCR-2020-007. [C]
pub const TAG_KEYPATH_V2: u64 = 40304;
/// `crypto-coin-info`, BCR-2020-007. [C]
pub const TAG_COININFO_V1: u64 = 305;
/// `coin-info`, BCR-2020-007. [C]
pub const TAG_COININFO_V2: u64 = 40305;
/// `crypto-output`, BCR-2020-010. [C]
pub const TAG_OUTPUT_V1: u64 = 308;
/// `output-descriptor`, BCR-2023-010 -- a different body, refused. [C]
pub const TAG_OUTPUT_V2: u64 = 40308;
/// `crypto-psbt`, BCR-2020-006. [C]
pub const TAG_PSBT_V1: u64 = 310;
/// `psbt`, BCR-2020-006. [C]
pub const TAG_PSBT_V2: u64 = 40310;
/// `crypto-account`, BCR-2020-015. [C]
pub const TAG_ACCOUNT_V1: u64 = 311;
/// `account-descriptor`, BCR-2023-019 -- a different body, refused. [C]
pub const TAG_ACCOUNT_V2: u64 = 40311;

/// A registry item this device knows what to do with.
///
/// Anything else is still received -- the transport does not care what it is carrying
/// -- it simply arrives as an unrecognised type rather than as a PSBT.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Kind {
    /// An opaque byte string, `bytes`. BCR-2020-006. [C]
    Bytes,
    /// A PSBT, `crypto-psbt` / `psbt`. BCR-2020-006 §PSBT. [C]
    Psbt,
    /// An HD key, `crypto-hdkey` / `hdkey`. BCR-2020-007. [C]
    HdKey,
    /// A derivation path, `crypto-keypath` / `keypath`. BCR-2020-007. [C]
    KeyPath,
    /// Coin and network, `crypto-coin-info` / `coin-info`. BCR-2020-007. [C]
    CoinInfo,
    /// A BIP-44 account, `crypto-account` / `account`. BCR-2020-015. [C]
    Account,
    /// An output descriptor, `crypto-output` / `output-descriptor`. BCR-2020-010. [C]
    Output,
}

impl Kind {
    /// The kind a UR type names, of either generation, in either ASCII case.
    ///
    /// `account-descriptor` and the version-3 `output-descriptor` body are deliberately
    /// absent from the write side but present here: the name is recognised so the
    /// device can say *what* it will not read, instead of "unrecognised data".
    pub fn from_ur_type(ty: &str) -> Option<Kind> {
        // A UR type is letters, digits and hyphens, and a QR carries it upper-cased.
        // [C] BCR-2020-005 §"Types"
        const TABLE: &[(&str, Kind)] = &[
            ("bytes", Kind::Bytes),
            ("crypto-psbt", Kind::Psbt),
            ("psbt", Kind::Psbt),
            ("crypto-hdkey", Kind::HdKey),
            ("hdkey", Kind::HdKey),
            ("crypto-keypath", Kind::KeyPath),
            ("keypath", Kind::KeyPath),
            ("crypto-coin-info", Kind::CoinInfo),
            ("coin-info", Kind::CoinInfo),
            ("crypto-account", Kind::Account),
            ("account", Kind::Account),
            ("account-descriptor", Kind::Account),
            ("crypto-output", Kind::Output),
            ("output-descriptor", Kind::Output),
        ];
        TABLE
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(ty))
            .map(|&(_, kind)| kind)
    }

    /// The UR type this device writes for a kind.
    ///
    /// The 2020 names, for the interoperability reason in this module's header -- not
    /// because the 2023 ones are wrong.
    pub const fn written_as(self) -> &'static str {
        match self {
            Kind::Bytes => "bytes",
            Kind::Psbt => "crypto-psbt",
            Kind::HdKey => "crypto-hdkey",
            Kind::KeyPath => "crypto-keypath",
            Kind::CoinInfo => "crypto-coin-info",
            Kind::Account => "crypto-account",
            Kind::Output => "crypto-output",
        }
    }
}

/// Step over an optional tag that must be one of `allowed` if it is there at all.
///
/// A registry item is untagged at the top level of a UR -- the UR type is what says
/// what it is -- and tagged when it is embedded in another item. [C] BCR-2020-006
/// §"Registry". Some encoders tag it anyway; reading its own tag costs nothing and
/// cannot turn one item into another, because any other tag is refused.
pub(crate) fn optional_tag(r: &mut cbor::Reader<'_>, allowed: [u64; 2]) -> Result<(), Error> {
    if r.is_tag() {
        let tag = r.tag()?;
        if tag != allowed[0] && tag != allowed[1] {
            return Err(Error::Tag(tag));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
