//! Partially Signed Bitcoin Transactions: reading one, safely.
//!
//! # What a signer is actually deciding
//!
//! Everything a PSBT says is the host's claim. The amounts, the destinations, the keys,
//! even which outputs are "change" -- all of it arrives from a computer that may be lying.
//! So this module only *reads*: it hands back what each field says, in the shape the
//! standard defines, and leaves every judgement to the caller, which checks the claims
//! against what the signature will actually commit to (see `super::tx::sighash`).
//!
//! # Borrowed, not owned
//!
//! A PSBT is a sequence of key-value maps: one global map, then one per input and one per
//! output of the unsigned transaction inside it. Nothing here is copied or allocated: a
//! [`Psbt`] holds slices into the buffer it was parsed from, and maps are re-walked on
//! demand ([`Psbt::input`], [`Psbt::output`]). A transaction with a hundred inputs
//! therefore costs no more RAM than one with one, which is what lets a device with 320 KB
//! consider a PSBT at all.
//!
//! # Strictness
//!
//! A malformed PSBT is refused, never guessed at:
//!
//! - the magic must be exact;
//! - every compact-size integer must be minimally encoded (`tx::varint` enforces it);
//! - a length must fit inside what is left of the buffer;
//! - a key must not repeat within one map, and a keyed field's key data must be the length
//!   its type defines;
//! - the global map must carry an unsigned transaction with empty scriptSigs, and the
//!   number of input and output maps must match it.
//!
//! Version 2 (BIP-370) moves the transaction into the maps; this reads version 0, and says
//! so rather than misreading a v2 PSBT as truncated.
//!
//! Sources: BIP-174 (format, roles, signer rules, test vectors), BIP-370 (version 2),
//! BIP-371 (taproot fields) -- public standards [C].

use crate::tx::varint::VarInt;
use crate::tx::{Error as TxError, Reader, Transaction};

/// `psbt` followed by `0xff`. Source: BIP-174 [C]
pub const MAGIC: [u8; 5] = [0x70, 0x73, 0x62, 0x74, 0xFF];

/// Global field types. Source: BIP-174, BIP-370 [C]
pub mod global {
    pub const UNSIGNED_TX: u64 = 0x00;
    pub const XPUB: u64 = 0x01;
    pub const VERSION: u64 = 0xFB;
    pub const PROPRIETARY: u64 = 0xFC;
}

/// Per-input field types. Source: BIP-174, BIP-371 [C]
pub mod input {
    pub const NON_WITNESS_UTXO: u64 = 0x00;
    pub const WITNESS_UTXO: u64 = 0x01;
    pub const PARTIAL_SIG: u64 = 0x02;
    pub const SIGHASH_TYPE: u64 = 0x03;
    pub const REDEEM_SCRIPT: u64 = 0x04;
    pub const WITNESS_SCRIPT: u64 = 0x05;
    pub const BIP32_DERIVATION: u64 = 0x06;
    pub const FINAL_SCRIPTSIG: u64 = 0x07;
    pub const FINAL_SCRIPTWITNESS: u64 = 0x08;
    /// Taproot key-path signature. Source: BIP-371 [C]
    pub const TAP_KEY_SIG: u64 = 0x13;
    /// Taproot x-only key and its derivation. Source: BIP-371 [C]
    pub const TAP_BIP32_DERIVATION: u64 = 0x16;
    pub const TAP_INTERNAL_KEY: u64 = 0x17;
}

/// Per-output field types. Source: BIP-174, BIP-371 [C]
pub mod output {
    pub const REDEEM_SCRIPT: u64 = 0x00;
    pub const WITNESS_SCRIPT: u64 = 0x01;
    pub const BIP32_DERIVATION: u64 = 0x02;
    pub const TAP_INTERNAL_KEY: u64 = 0x05;
    pub const TAP_BIP32_DERIVATION: u64 = 0x07;
}

/// Why a PSBT was refused.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// The first five bytes are not the PSBT magic: a raw transaction, or something else.
    NotPsbt,
    /// The bytes ran out mid-record.
    Truncated,
    /// Trailing bytes after the last map.
    TrailingData,
    /// A compact-size integer was not minimally encoded, or a length overflowed.
    BadLength,
    /// A map has two records with the same key.
    DuplicateKey { keytype: u64 },
    /// A field's key data is the wrong length for its type, or its value is.
    BadField { keytype: u64 },
    /// The global map has no unsigned transaction (or more than one).
    NoUnsignedTx,
    /// The unsigned transaction did not parse, or carries scriptSigs or a witness.
    BadUnsignedTx,
    /// The number of input or output maps does not match the transaction.
    MapCount { expected: usize, found: usize },
    /// A PSBT version this does not read -- version 2 keeps the transaction in the maps.
    UnsupportedVersion { version: u32 },
}

impl From<TxError> for Error {
    fn from(_: TxError) -> Self {
        // The transaction reader's positions describe the inner transaction, not the PSBT,
        // so they would be misleading here; what matters is that it did not parse.
        Error::Truncated
    }
}

/// One key-value record: the key's type, the rest of its key, and its value.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Record<'a> {
    pub keytype: u64,
    /// Whatever follows the key type inside the key -- a public key, an xpub, nothing.
    pub keydata: &'a [u8],
    pub value: &'a [u8],
}

/// The records of one map, walked on demand.
#[derive(Copy, Clone, Debug)]
pub struct Map<'a> {
    data: &'a [u8],
}

impl<'a> Map<'a> {
    /// Every record in order. Stops at the map's terminator.
    pub fn records(&self) -> impl Iterator<Item = Result<Record<'a>, Error>> + 'a {
        let mut r = Reader::new(self.data);
        let mut done = false;
        core::iter::from_fn(move || {
            if done {
                return None;
            }
            match next_record(&mut r) {
                Ok(Some(rec)) => Some(Ok(rec)),
                Ok(None) => {
                    done = true;
                    None
                }
                Err(e) => {
                    done = true;
                    Some(Err(e))
                }
            }
        })
    }

    /// The value of the single record of `keytype` that carries no key data.
    ///
    /// `None` if absent. An error if it appears twice or carries key data, both of which
    /// the standard forbids for these types.
    pub fn keyless(&self, keytype: u64) -> Result<Option<&'a [u8]>, Error> {
        let mut found = None;
        for rec in self.records() {
            let rec = rec?;
            if rec.keytype != keytype {
                continue;
            }
            if !rec.keydata.is_empty() {
                return Err(Error::BadField { keytype });
            }
            if found.is_some() {
                return Err(Error::DuplicateKey { keytype });
            }
            found = Some(rec.value);
        }
        Ok(found)
    }

    /// Every record of `keytype`, key data included.
    pub fn all(&self, keytype: u64) -> impl Iterator<Item = Result<Record<'a>, Error>> + 'a {
        self.records()
            .filter(move |r| r.as_ref().map(|r| r.keytype == keytype).unwrap_or(true))
    }

    /// Check that no key repeats. Walked once, on parse, so later lookups need not.
    fn check_unique(&self) -> Result<(), Error> {
        // Quadratic in the number of records within one map, which is a handful: a
        // single-key input carries a UTXO, a derivation, maybe a script and a signature.
        // Nothing here allocates, which a set would.
        for (i, a) in self.records().enumerate() {
            let a = a?;
            for b in self.records().skip(i + 1) {
                let b = b?;
                if a.keytype == b.keytype && a.keydata == b.keydata {
                    return Err(Error::DuplicateKey { keytype: a.keytype });
                }
            }
        }
        Ok(())
    }
}

/// Read one record, or `None` at the map's `0x00` terminator.
fn next_record<'a>(r: &mut Reader<'a>) -> Result<Option<Record<'a>>, Error> {
    if r.remaining() == 0 {
        // A map must be terminated; running out of bytes is not a terminator.
        return Err(Error::Truncated);
    }
    let keylen = VarInt::read(r).map_err(|_| Error::BadLength)?;
    if keylen == 0 {
        return Ok(None);
    }
    let key = r
        .take(usize::try_from(keylen).map_err(|_| Error::BadLength)?)
        .map_err(|_| Error::Truncated)?;
    let mut kr = Reader::new(key);
    let keytype = VarInt::read(&mut kr).map_err(|_| Error::BadLength)?;
    let keydata = &key[kr.position()..];
    let valuelen = VarInt::read(r).map_err(|_| Error::BadLength)?;
    let value = r
        .take(usize::try_from(valuelen).map_err(|_| Error::BadLength)?)
        .map_err(|_| Error::Truncated)?;
    Ok(Some(Record {
        keytype,
        keydata,
        value,
    }))
}

/// Skip one map, returning the bytes it occupied (terminator included).
fn split_map<'a>(rest: &'a [u8]) -> Result<(Map<'a>, &'a [u8]), Error> {
    let mut r = Reader::new(rest);
    while next_record(&mut r)?.is_some() {}
    let end = r.position();
    Ok((Map { data: &rest[..end] }, &rest[end..]))
}

/// Which map a record came from, and so which field types apply to it.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum Section {
    Global,
    Input,
    Output,
}

/// A compressed public key; 65 is an uncompressed one, which the format still allows.
const PUBKEY_LENS: [usize; 2] = [33, 65];
/// An x-only key (BIP-340), as taproot records carry.
const XONLY_LEN: usize = 32;
/// A serialised extended public key.
const XPUB_LEN: usize = 78;

/// Check every record of a map against what its type allows.
///
/// A field that takes no key data must have none, and a field keyed by a public key must
/// carry one of the right length: BIP-174's invalid vectors are mostly this -- a witness
/// UTXO keyed by a stray byte, a partial signature keyed by a truncated pubkey. Reading
/// such a record as though the extra bytes were not there is how a signer ends up signing
/// against the wrong key or amount, so the container is refused instead.
///
/// Unknown types pass: the standard requires a signer to tolerate fields it does not know.
fn validate_map(section: Section, map: &Map<'_>) -> Result<(), Error> {
    for rec in map.records() {
        let rec = rec?;
        let bad = || Error::BadField {
            keytype: rec.keytype,
        };
        // `None` for a type this does not constrain.
        let keydata_ok: Option<bool> = match (section, rec.keytype) {
            (Section::Global, global::UNSIGNED_TX | global::VERSION) => {
                Some(rec.keydata.is_empty())
            }
            (Section::Global, global::XPUB) => Some(rec.keydata.len() == XPUB_LEN),
            (
                Section::Input,
                input::NON_WITNESS_UTXO
                | input::WITNESS_UTXO
                | input::SIGHASH_TYPE
                | input::REDEEM_SCRIPT
                | input::WITNESS_SCRIPT
                | input::FINAL_SCRIPTSIG
                | input::FINAL_SCRIPTWITNESS
                | input::TAP_KEY_SIG
                | input::TAP_INTERNAL_KEY,
            ) => Some(rec.keydata.is_empty()),
            (Section::Input, input::PARTIAL_SIG | input::BIP32_DERIVATION) => {
                Some(PUBKEY_LENS.contains(&rec.keydata.len()))
            }
            (Section::Input, input::TAP_BIP32_DERIVATION) => Some(rec.keydata.len() == XONLY_LEN),
            (
                Section::Output,
                output::REDEEM_SCRIPT | output::WITNESS_SCRIPT | output::TAP_INTERNAL_KEY,
            ) => Some(rec.keydata.is_empty()),
            (Section::Output, output::BIP32_DERIVATION) => {
                Some(PUBKEY_LENS.contains(&rec.keydata.len()))
            }
            (Section::Output, output::TAP_BIP32_DERIVATION) => Some(rec.keydata.len() == XONLY_LEN),
            _ => None,
        };
        if keydata_ok == Some(false) {
            return Err(bad());
        }
        // Value lengths that the format fixes.
        let value_ok = match (section, rec.keytype) {
            (Section::Global, global::VERSION) | (Section::Input, input::SIGHASH_TYPE) => {
                rec.value.len() == 4
            }
            (Section::Input, input::TAP_INTERNAL_KEY)
            | (Section::Output, output::TAP_INTERNAL_KEY) => rec.value.len() == XONLY_LEN,
            // A Schnorr signature, with or without a trailing sighash byte.
            (Section::Input, input::TAP_KEY_SIG) => matches!(rec.value.len(), 64 | 65),
            (Section::Global, global::XPUB) => parse_origin(rec.keytype, rec.value)
                .is_ok_and(|o| o.depth() == rec.keydata[4] as usize),
            (Section::Input, input::BIP32_DERIVATION)
            | (Section::Output, output::BIP32_DERIVATION) => {
                parse_origin(rec.keytype, rec.value).is_ok()
            }
            _ => true,
        };
        if !value_ok {
            return Err(bad());
        }
    }
    Ok(())
}

/// A parsed PSBT: its unsigned transaction and its maps.
#[derive(Copy, Clone, Debug)]
pub struct Psbt<'a> {
    /// The global map.
    pub globals: Map<'a>,
    /// The unsigned transaction's serialisation, as the global map carries it.
    pub unsigned_tx: &'a [u8],
    /// Where the input maps start, and how many follow.
    inputs: &'a [u8],
    input_count: usize,
    output_count: usize,
}

impl<'a> Psbt<'a> {
    /// Parse `bytes`. Everything the standard requires of the container is checked here, so
    /// a caller that gets a `Psbt` back is reading a well-formed one.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < MAGIC.len() || bytes[..MAGIC.len()] != MAGIC {
            return Err(Error::NotPsbt);
        }
        let (globals, rest) = split_map(&bytes[MAGIC.len()..])?;
        globals.check_unique()?;
        validate_map(Section::Global, &globals)?;

        // Version 0 is the absence of the field; version 2 is a different container.
        if let Some(v) = globals.keyless(global::VERSION)? {
            let version = u32::from_le_bytes(v.try_into().map_err(|_| Error::BadField {
                keytype: global::VERSION,
            })?);
            if version != 0 {
                return Err(Error::UnsupportedVersion { version });
            }
        }

        let unsigned_tx = globals
            .keyless(global::UNSIGNED_TX)?
            .ok_or(Error::NoUnsignedTx)?;
        // BIP-174 has valid vectors whose unsigned transaction has no inputs at all.
        let tx =
            Transaction::parse_possibly_empty(unsigned_tx).map_err(|_| Error::BadUnsignedTx)?;
        // "The scriptSigs and witnesses for each input must be empty" -- an unsigned
        // transaction with a scriptSig is a signed one, and its txid is not what the
        // inputs' prevouts were computed against.
        if tx.has_witness {
            return Err(Error::BadUnsignedTx);
        }
        for txin in tx.inputs.iter() {
            if !txin
                .map_err(|_| Error::BadUnsignedTx)?
                .script_sig
                .is_empty()
            {
                return Err(Error::BadUnsignedTx);
            }
        }
        let input_count = usize::try_from(tx.inputs.count()).map_err(|_| Error::BadLength)?;
        let output_count = usize::try_from(tx.outputs.count()).map_err(|_| Error::BadLength)?;

        // Walk every map now: the counts must match the transaction, no key may repeat, and
        // nothing may follow the last output map. Cheap, and it means no later lookup has to
        // deal with a container that turns out to be malformed half way through a signing.
        let mut tail = rest;
        for i in 0..input_count + output_count {
            let (map, next) = split_map(tail).map_err(|e| match e {
                Error::Truncated => Error::MapCount {
                    expected: input_count + output_count,
                    found: i,
                },
                other => other,
            })?;
            map.check_unique()?;
            validate_map(
                if i < input_count {
                    Section::Input
                } else {
                    Section::Output
                },
                &map,
            )?;
            tail = next;
        }
        if !tail.is_empty() {
            return Err(Error::TrailingData);
        }

        Ok(Self {
            globals,
            unsigned_tx,
            inputs: rest,
            input_count,
            output_count,
        })
    }

    /// The unsigned transaction, parsed.
    pub fn tx(&self) -> Transaction<'a> {
        // Parsed once in `parse`; a second failure here is impossible.
        Transaction::parse_possibly_empty(self.unsigned_tx).expect("checked in parse")
    }

    pub fn input_count(&self) -> usize {
        self.input_count
    }

    pub fn output_count(&self) -> usize {
        self.output_count
    }

    /// The PSBT version: 0 unless stated.
    pub fn version(&self) -> u32 {
        match self.globals.keyless(global::VERSION) {
            Ok(Some(v)) if v.len() == 4 => u32::from_le_bytes(v.try_into().expect("4 bytes")),
            _ => 0,
        }
    }

    /// Input `index`'s map.
    pub fn input(&self, index: usize) -> Option<Map<'a>> {
        if index >= self.input_count {
            return None;
        }
        self.map_at(index)
    }

    /// Output `index`'s map.
    pub fn output(&self, index: usize) -> Option<Map<'a>> {
        if index >= self.output_count {
            return None;
        }
        self.map_at(self.input_count + index)
    }

    fn map_at(&self, skip: usize) -> Option<Map<'a>> {
        let mut tail = self.inputs;
        for _ in 0..skip {
            tail = split_map(tail).ok()?.1;
        }
        Some(split_map(tail).ok()?.0)
    }
}

/// A key's origin: whose master key it came from, and the path under it.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Origin<'a> {
    pub fingerprint: [u8; 4],
    /// The path, still as little-endian 32-bit indices. Use [`Origin::steps`].
    raw_path: &'a [u8],
}

impl Origin<'_> {
    /// The path's child numbers, hardened bit included.
    pub fn steps(&self) -> impl Iterator<Item = u32> + '_ {
        self.raw_path
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| u32::from_le_bytes(*c))
    }

    pub fn depth(&self) -> usize {
        self.raw_path.len() / 4
    }
}

/// A public key with its origin, from a `BIP32_DERIVATION` record.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct KeyOrigin<'a> {
    /// The key as the record carries it: 33 bytes compressed, or 32 x-only for taproot.
    pub pubkey: &'a [u8],
    pub origin: Origin<'a>,
}

/// Read a `<4 byte fingerprint> <32-bit little endian uint path element>*` value.
pub fn parse_origin<'a>(keytype: u64, value: &'a [u8]) -> Result<Origin<'a>, Error> {
    if value.len() < 4 || !(value.len() - 4).is_multiple_of(4) {
        return Err(Error::BadField { keytype });
    }
    let mut fingerprint = [0u8; 4];
    fingerprint.copy_from_slice(&value[..4]);
    Ok(Origin {
        fingerprint,
        raw_path: &value[4..],
    })
}

impl<'a> Map<'a> {
    /// Every key in this map with a derivation path: the BIP-32 ones, and taproot's.
    ///
    /// Key lengths are checked against the record type, so a 32-byte key never arrives
    /// where a 33-byte one is expected.
    pub fn derivations(
        &self,
        bip32: u64,
        taproot: u64,
    ) -> impl Iterator<Item = Result<KeyOrigin<'a>, Error>> + 'a {
        self.records().filter_map(move |rec| {
            let rec = match rec {
                Ok(rec) => rec,
                Err(e) => return Some(Err(e)),
            };
            if rec.keytype == bip32 {
                if rec.keydata.len() != 33 {
                    return Some(Err(Error::BadField { keytype: bip32 }));
                }
                return Some(parse_origin(bip32, rec.value).map(|origin| KeyOrigin {
                    pubkey: rec.keydata,
                    origin,
                }));
            }
            if rec.keytype == taproot {
                if rec.keydata.len() != 32 {
                    return Some(Err(Error::BadField { keytype: taproot }));
                }
                // Taproot's derivation value is a list of leaf hashes, then the origin.
                let mut r = Reader::new(rec.value);
                let leaves = match VarInt::read(&mut r) {
                    Ok(n) => n,
                    Err(_) => return Some(Err(Error::BadField { keytype: taproot })),
                };
                let skip = usize::try_from(leaves).ok().and_then(|n| n.checked_mul(32));
                let Some(skip) = skip else {
                    return Some(Err(Error::BadField { keytype: taproot }));
                };
                if r.take(skip).is_err() {
                    return Some(Err(Error::BadField { keytype: taproot }));
                }
                let at = r.position();
                return Some(
                    parse_origin(taproot, &rec.value[at..]).map(|origin| KeyOrigin {
                        pubkey: rec.keydata,
                        origin,
                    }),
                );
            }
            None
        })
    }
}

#[cfg(test)]
mod test_vectors;
#[cfg(test)]
mod tests;
