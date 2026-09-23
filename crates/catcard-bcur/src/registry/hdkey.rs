//! `crypto-hdkey`, `crypto-keypath` and `crypto-coin-info`: a BIP-32 key and the two
//! structures that describe it.
//!
//! Source: BCR-2020-007, §"CDDL for HDKey", §"CDDL for Key Path", §"CDDL for Coin
//! Info". [C]
//!
//! An `hdkey` is isomorphic with a BIP-32 serialization when `chain-code`, `origin`
//! and `parent-fingerprint` are all present -- that is the form this device writes,
//! because a wallet that receives anything less cannot derive addresses from it. [C]
//! BCR-2020-007 §"CDDL for HDKey"

use super::{
    Error, TAG_COININFO_V1, TAG_COININFO_V2, TAG_HDKEY_V1, TAG_HDKEY_V2, TAG_KEYPATH_V1,
    TAG_KEYPATH_V2, bounded, optional_tag,
};
use crate::cbor::{self, Reader, Writer};

/// Which generation of CBOR tags the parts nested inside an item carry.
///
/// BCR-2020-007's own test vectors use both: vector 1 has no nested tags at all,
/// vector 2 (the current revision) tags its coin-info #6.40305 and its keypath
/// #6.40304, and BCR-2020-015's account vector tags the same structures #6.305 and
/// #6.304. Reading takes either; writing has to pick, so the caller says.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Tags {
    /// The 2020 tags: 303, 304, 305. What `crypto-*` documents use.
    V1,
    /// The 2023 tags: 40303, 40304, 40305. What `hdkey` documents use.
    V2,
}

impl Tags {
    const fn keypath(self) -> u64 {
        match self {
            Tags::V1 => TAG_KEYPATH_V1,
            Tags::V2 => TAG_KEYPATH_V2,
        }
    }

    const fn coininfo(self) -> u64 {
        match self {
            Tags::V1 => TAG_COININFO_V1,
            Tags::V2 => TAG_COININFO_V2,
        }
    }

    /// The tag an embedded `hdkey` carries -- what an output descriptor puts around it.
    pub(crate) const fn hdkey(self) -> u64 {
        match self {
            Tags::V1 => TAG_HDKEY_V1,
            Tags::V2 => TAG_HDKEY_V2,
        }
    }
}

// --- coin info ----------------------------------------------------------------------

/// What chain a key is for, and which of its networks.
///
/// Source: BCR-2020-007 §"CDDL for Coin Info" [C]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct CoinInfo {
    /// SLIP-44 coin type with the hardening bit off; 0 is Bitcoin. [C]
    pub coin_type: u32,
    /// Coin-specific network; 0 is mainnet, 1 is Bitcoin testnet. Declared `int`, so
    /// it may be negative. [C]
    pub network: i32,
}

impl CoinInfo {
    /// Both fields at their default, which is what an omitted `use-info` means. [C]
    /// BCR-2020-007: "If the `use-info` field is omitted, defaults (mainnet BTC key)
    /// are assumed."
    pub const BITCOIN: CoinInfo = CoinInfo {
        coin_type: 0,
        network: 0,
    };

    /// Whether this is the default, and so may be left out entirely.
    pub const fn is_default(&self) -> bool {
        self.coin_type == 0 && self.network == 0
    }

    // Map keys. Source: BCR-2020-007 §"CDDL for Coin Info" [C]
    const TYPE: u64 = 1;
    const NETWORK: u64 = 2;

    /// Read one, tagged or not.
    pub fn decode(message: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(message);
        let coin = Self::read(&mut r)?;
        if !r.at_end() {
            return Err(Error::Trailing);
        }
        Ok(coin)
    }

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        optional_tag(r, [TAG_COININFO_V1, TAG_COININFO_V2])?;
        let pairs = r.map()?;
        let mut coin = CoinInfo::BITCOIN;
        for _ in 0..bounded(pairs)? {
            match r.uint()? {
                Self::TYPE => coin.coin_type = r.u32()?,
                Self::NETWORK => {
                    coin.network = i32::try_from(r.int()?).map_err(|_| cbor::Error::TooLarge)?;
                }
                // An unknown key is stepped over rather than refused: the registry adds
                // fields, and a coin info with one more of them is still this coin info.
                _ => r.skip()?,
            }
        }
        Ok(coin)
    }

    /// Write one, without a tag.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        self.write(&mut w)?;
        Ok(w.len())
    }

    pub(crate) fn write(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        // Defaults are omitted, so that a Bitcoin mainnet key is the short form every
        // published vector shows.
        let fields = u64::from(self.coin_type != 0) + u64::from(self.network != 0);
        w.map(fields)?;
        if self.coin_type != 0 {
            w.uint(Self::TYPE)?;
            w.uint(self.coin_type as u64)?;
        }
        if self.network != 0 {
            w.uint(Self::NETWORK)?;
            w.int(self.network as i64)?;
        }
        Ok(())
    }
}

// --- key path -----------------------------------------------------------------------

/// The most derivation steps a path read here may have.
///
/// BIP-32 allows 255 levels; a path that reaches an account is three, an address five,
/// and BIP-48's cosigner path four. Eight is room for every one of those plus a
/// descriptor's two child steps, and it is what a [`KeyPath`] costs on the stack --
/// which on the Q1 is the scarce thing.
pub const MAX_COMPONENTS: usize = 8;

/// One step of a derivation path.
///
/// Source: BCR-2020-007 §"CDDL for Key Path", `path-component`. [C]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Component {
    /// A single child, `44'` or `0`.
    Index { index: u32, hardened: bool },
    /// A range of children, `[low, high]` with `low < high`.
    Range { low: u32, high: u32, hardened: bool },
    /// Every child: the `*` of an output descriptor.
    Wildcard { hardened: bool },
    /// The `<0;1>` pair an output descriptor uses for external and internal chains.
    Pair {
        external: (u32, bool),
        internal: (u32, bool),
    },
}

impl Component {
    /// A plain unhardened step.
    pub const fn normal(index: u32) -> Self {
        Component::Index {
            index,
            hardened: false,
        }
    }

    /// A plain hardened step. The index is the one *without* the hardening bit -- 44',
    /// not 0x8000002C, which is how the BCR writes them. [C] BCR-2020-007: `child-index
    /// = uint31`, with `is-hardened` carried separately.
    pub const fn hardened(index: u32) -> Self {
        Component::Index {
            index,
            hardened: true,
        }
    }

    /// How many CBOR array elements this occupies. An index, a range and a wildcard are
    /// each a value followed by its `is-hardened` flag; a pair is one nested array.
    const fn elements(&self) -> u64 {
        match self {
            Component::Pair { .. } => 1,
            _ => 2,
        }
    }
}

/// A complete or partial derivation path, with the key it started from.
///
/// Source: BCR-2020-007 §"CDDL for Key Path". [C]
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KeyPath {
    pub components: heapless::Vec<Component, MAX_COMPONENTS>,
    /// The fingerprint of the ancestor the path starts at. Must be present when
    /// `components` is empty, and is then a master key's fingerprint. Never zero. [C]
    pub source_fingerprint: Option<u32>,
    /// How many derivation steps the key is below the master, whether or not they are
    /// all listed in `components`. [C]
    pub depth: Option<u8>,
}

impl KeyPath {
    // Map keys. Source: BCR-2020-007 §"CDDL for Key Path" [C]
    const COMPONENTS: u64 = 1;
    const SOURCE_FINGERPRINT: u64 = 2;
    const DEPTH: u64 = 3;

    /// An empty path rooted at a master key's fingerprint.
    pub fn from_master(fingerprint: u32) -> Self {
        KeyPath {
            components: heapless::Vec::new(),
            source_fingerprint: Some(fingerprint),
            depth: None,
        }
    }

    /// A path of plain steps below a named ancestor.
    pub fn new(source_fingerprint: u32, steps: &[Component]) -> Result<Self, Error> {
        Ok(KeyPath {
            components: heapless::Vec::from_slice(steps).map_err(|_| Error::TooMany)?,
            source_fingerprint: Some(source_fingerprint),
            depth: None,
        })
    }

    /// Read one, tagged or not.
    pub fn decode(message: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(message);
        let path = Self::read(&mut r)?;
        if !r.at_end() {
            return Err(Error::Trailing);
        }
        Ok(path)
    }

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        optional_tag(r, [TAG_KEYPATH_V1, TAG_KEYPATH_V2])?;
        let pairs = r.map()?;
        let mut path = KeyPath {
            components: heapless::Vec::new(),
            source_fingerprint: None,
            depth: None,
        };
        let mut seen_components = false;
        for _ in 0..bounded(pairs)? {
            match r.uint()? {
                Self::COMPONENTS => {
                    seen_components = true;
                    read_components(r, &mut path.components)?;
                }
                Self::SOURCE_FINGERPRINT => path.source_fingerprint = Some(r.u32()?),
                Self::DEPTH => {
                    path.depth = Some(u8::try_from(r.uint()?).map_err(|_| cbor::Error::TooLarge)?);
                }
                _ => r.skip()?,
            }
        }
        // `components` is not optional: a keypath without it says nothing about a path.
        if !seen_components {
            return Err(Error::Field(Self::COMPONENTS as u8));
        }
        // "If `components` is empty, then `source-fingerprint` MUST be present." [C]
        if path.components.is_empty() && path.source_fingerprint.is_none() {
            return Err(Error::Field(Self::SOURCE_FINGERPRINT as u8));
        }
        Ok(path)
    }

    /// Write one, without a tag.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        self.write(&mut w)?;
        Ok(w.len())
    }

    pub(crate) fn write(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        // A source fingerprint of zero is forbidden (`uint32 .ne 0`), so it is dropped
        // rather than written as a lie about an ancestor. [C]
        let source = self.source_fingerprint.filter(|&fp| fp != 0);
        let fields = 1 + u64::from(source.is_some()) + u64::from(self.depth.is_some());
        w.map(fields)?;

        w.uint(Self::COMPONENTS)?;
        let elements: u64 = self.components.iter().map(Component::elements).sum();
        w.array(elements)?;
        for c in &self.components {
            match *c {
                Component::Index { index, hardened } => {
                    w.uint(index as u64)?;
                    w.bool(hardened)?;
                }
                Component::Range {
                    low,
                    high,
                    hardened,
                } => {
                    w.array(2)?;
                    w.uint(low as u64)?;
                    w.uint(high as u64)?;
                    w.bool(hardened)?;
                }
                Component::Wildcard { hardened } => {
                    w.array(0)?;
                    w.bool(hardened)?;
                }
                Component::Pair { external, internal } => {
                    w.array(4)?;
                    w.uint(external.0 as u64)?;
                    w.bool(external.1)?;
                    w.uint(internal.0 as u64)?;
                    w.bool(internal.1)?;
                }
            }
        }

        if let Some(fp) = source {
            w.uint(Self::SOURCE_FINGERPRINT)?;
            w.uint(fp as u64)?;
        }
        if let Some(depth) = self.depth {
            w.uint(Self::DEPTH)?;
            w.uint(depth as u64)?;
        }
        Ok(())
    }
}

/// Read the `components` array, whose elements are a flattened mixture of shapes.
fn read_components(
    r: &mut Reader<'_>,
    into: &mut heapless::Vec<Component, MAX_COMPONENTS>,
) -> Result<(), Error> {
    let mut left = bounded(r.array()?)?;
    while left > 0 {
        let component = if r.peek()? == cbor::ARRAY {
            // A nested array is a range, a wildcard, or a whole pair -- told apart by
            // its length, which is how the CDDL distinguishes them. [C]
            match r.array()? {
                0 => Component::Wildcard {
                    hardened: r.bool()?,
                },
                2 => {
                    let low = r.u32()?;
                    let high = r.u32()?;
                    // "[low, high] where low < high" [C]
                    if low >= high {
                        return Err(Error::Unsupported);
                    }
                    Component::Range {
                        low,
                        high,
                        hardened: r.bool()?,
                    }
                }
                4 => Component::Pair {
                    external: (r.u32()?, r.bool()?),
                    internal: (r.u32()?, r.bool()?),
                },
                _ => return Err(Error::Unsupported),
            }
        } else {
            Component::Index {
                index: r.u32()?,
                hardened: r.bool()?,
            }
        };
        let used = component.elements() as usize;
        if used > left {
            return Err(Error::Cbor(cbor::Error::Short));
        }
        left -= used;
        into.push(component).map_err(|_| Error::TooMany)?;
    }
    Ok(())
}

// --- the key itself -------------------------------------------------------------------

/// A BIP-32 extended key, as a UR carries it.
///
/// Source: BCR-2020-007 §"CDDL for HDKey". [C]
///
/// `name` and `note` are read past rather than kept: they are free text a sender
/// chooses, this device has nowhere to show them, and holding a borrowed string would
/// tie the key to the buffer it arrived in.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HdKey {
    /// A master key: always private, no derivation information, chain code required.
    pub is_master: bool,
    /// Whether `key_data` is a private key. Defaults to false. [C]
    pub is_private: bool,
    /// The key itself.
    ///
    /// Thirty-three bytes for the curve the specification was written around: a
    /// compressed public key, or `0x00` followed by a 32-byte secret. [C]
    ///
    /// **Thirty-two for an ed25519 key**, which is what Keystone writes for Solana and
    /// what the wallets on the other side base58 to get an address `[C]`
    /// (`@keystonehq/sol-keyring`: `bs58.encode(each.getKey())`). Outside BCR-2020-007,
    /// which knows one curve -- but it is what the format is used for in practice, and a
    /// reader that insisted on 33 would refuse every Solana account anybody exports.
    pub key_data: heapless::Vec<u8, 33>,
    /// 32 bytes. Absent means no further key may be derived from this one. [C]
    pub chain_code: Option<[u8; 32]>,
    /// What the key is for. Absent means mainnet Bitcoin. [C]
    pub use_info: Option<CoinInfo>,
    /// How this key was derived.
    pub origin: Option<KeyPath>,
    /// What children should be derived from it.
    pub children: Option<KeyPath>,
    /// The fingerprint of the direct ancestor, per BIP-32. Never zero. [C]
    pub parent_fingerprint: Option<u32>,
    /// What to call this key on the screen of whatever imports it. [C] BCR-2020-007
    /// `name`; read by every wallet that shows a list of imported accounts.
    pub name: Option<heapless::String<NAME_MAX>>,
}

/// How long a key's name may be here.
///
/// Long enough for a chain's name and an account number, which is what this device puts
/// in one.
pub const NAME_MAX: usize = 24;

impl HdKey {
    // Map keys. Source: BCR-2020-007 §"CDDL for HDKey" [C]
    const IS_MASTER: u64 = 1;
    const IS_PRIVATE: u64 = 2;
    const KEY_DATA: u64 = 3;
    const CHAIN_CODE: u64 = 4;
    const USE_INFO: u64 = 5;
    const ORIGIN: u64 = 6;
    const CHILDREN: u64 = 7;
    const PARENT_FINGERPRINT: u64 = 8;
    const NAME: u64 = 9;

    /// A derived public key, from the bytes it is.
    ///
    /// Thirty-three bytes for secp256k1, thirty-two for ed25519; anything else is not a
    /// key this format carries.
    pub fn of(key_data: &[u8]) -> Result<Self, Error> {
        if key_data.len() != 33 && key_data.len() != 32 {
            return Err(Error::Size(key_data.len()));
        }
        Ok(HdKey {
            key_data: heapless::Vec::from_slice(key_data).map_err(|_| Error::TooMany)?,
            ..Self::derived([0u8; 33])
        })
    }

    /// An empty derived public key, to be filled in.
    pub fn derived(key_data: [u8; 33]) -> Self {
        HdKey {
            is_master: false,
            is_private: false,
            key_data: heapless::Vec::from_slice(&key_data).unwrap_or_default(),
            chain_code: None,
            use_info: None,
            origin: None,
            children: None,
            parent_fingerprint: None,
            name: None,
        }
    }

    /// Read one `crypto-hdkey` / `hdkey` message.
    pub fn decode(message: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(message);
        let key = Self::read(&mut r)?;
        if !r.at_end() {
            return Err(Error::Trailing);
        }
        Ok(key)
    }

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        optional_tag(r, [TAG_HDKEY_V1, TAG_HDKEY_V2])?;
        let pairs = r.map()?;
        let mut key = HdKey::derived([0u8; 33]);
        let mut seen_key_data = false;
        for _ in 0..bounded(pairs)? {
            match r.uint()? {
                Self::IS_MASTER => key.is_master = r.bool()?,
                Self::IS_PRIVATE => key.is_private = r.bool()?,
                Self::KEY_DATA => {
                    let data = r.bytes()?;
                    if data.len() != 33 && data.len() != 32 {
                        return Err(Error::Size(data.len()));
                    }
                    key.key_data =
                        heapless::Vec::from_slice(data).map_err(|_| Error::Size(data.len()))?;
                    seen_key_data = true;
                }
                Self::CHAIN_CODE => key.chain_code = Some(fixed(r.bytes()?)?),
                Self::USE_INFO => key.use_info = Some(CoinInfo::read(r)?),
                Self::ORIGIN => key.origin = Some(KeyPath::read(r)?),
                Self::CHILDREN => key.children = Some(KeyPath::read(r)?),
                Self::PARENT_FINGERPRINT => key.parent_fingerprint = Some(r.u32()?),
                Self::NAME => {
                    let text = r.text()?;
                    key.name = heapless::String::try_from(text).ok();
                }
                // `name` and `note`, and anything a later revision adds.
                _ => r.skip()?,
            }
        }
        if !seen_key_data {
            return Err(Error::Field(Self::KEY_DATA as u8));
        }
        // "A master key is always private ... and always includes a chain code." [C]
        if key.is_master && key.chain_code.is_none() {
            return Err(Error::Field(Self::CHAIN_CODE as u8));
        }
        Ok(key)
    }

    /// Write one `crypto-hdkey` / `hdkey` message, untagged as a UR's top level.
    pub fn encode(&self, tags: Tags, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        self.write(tags, &mut w)?;
        Ok(w.len())
    }

    pub(crate) fn write(&self, tags: Tags, w: &mut Writer<'_>) -> Result<(), Error> {
        // A zero parent fingerprint is forbidden (`uint32 .ne 0`) -- a master key's
        // BIP-32 serialization has one, and here that is said by `is-master` instead.
        let parent = self.parent_fingerprint.filter(|&fp| fp != 0);
        // Defaults are omitted, which is what makes the output match the vectors.
        let use_info = self.use_info.filter(|c| !c.is_default());
        let fields = u64::from(self.is_master)
            + u64::from(self.is_private)
            + 1
            + u64::from(self.chain_code.is_some())
            + u64::from(use_info.is_some())
            + u64::from(self.origin.is_some())
            + u64::from(self.children.is_some())
            + u64::from(parent.is_some())
            + u64::from(self.name.is_some());
        w.map(fields)?;

        // Ascending key order, as every published vector writes it.
        if self.is_master {
            w.uint(Self::IS_MASTER)?;
            w.bool(true)?;
        }
        if self.is_private {
            w.uint(Self::IS_PRIVATE)?;
            w.bool(true)?;
        }
        w.uint(Self::KEY_DATA)?;
        w.bytes(&self.key_data)?;
        if let Some(chain) = &self.chain_code {
            w.uint(Self::CHAIN_CODE)?;
            w.bytes(chain)?;
        }
        if let Some(coin) = &use_info {
            w.uint(Self::USE_INFO)?;
            w.tag(tags.coininfo())?;
            coin.write(w)?;
        }
        if let Some(origin) = &self.origin {
            w.uint(Self::ORIGIN)?;
            w.tag(tags.keypath())?;
            origin.write(w)?;
        }
        if let Some(children) = &self.children {
            w.uint(Self::CHILDREN)?;
            w.tag(tags.keypath())?;
            children.write(w)?;
        }
        if let Some(fp) = parent {
            w.uint(Self::PARENT_FINGERPRINT)?;
            w.uint(fp as u64)?;
        }
        if let Some(name) = &self.name {
            w.uint(Self::NAME)?;
            w.text(name)?;
        }
        Ok(())
    }
}

/// A byte string that must be exactly `N` bytes -- a key, a chain code.
fn fixed<const N: usize>(data: &[u8]) -> Result<[u8; N], Error> {
    <[u8; N]>::try_from(data).map_err(|_| Error::Size(data.len()))
}
