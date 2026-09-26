//! PSBT version 2 (BIP-370), as a view over the version-0 machinery.
//!
//! A v2 PSBT carries no unsigned transaction. Each input map says what it spends
//! (`PSBT_IN_PREVIOUS_TXID`, `PSBT_IN_OUTPUT_INDEX`, `PSBT_IN_SEQUENCE`) and what lock time
//! it needs; each output map says its amount and script; the global map says the
//! transaction version, the fallback lock time and how many maps follow. The transaction
//! every signature commits to is *rebuilt* from those fields, by the rules the BIP lays
//! down -- which is exactly what a v0 PSBT carries ready-made.
//!
//! So this module does three things and nothing else:
//!
//! 1. [`V2::parse`] reads and validates a v2 container: every v2 field is either
//!    understood and checked to its stated shape, or -- for a field the BIP requires and
//!    this cannot find -- refused by name. Unknown and proprietary records are carried, not
//!    dropped.
//! 2. [`V2::to_v0`] writes the equivalent v0 PSBT: the rebuilt unsigned transaction in the
//!    global map, and every map with its v2-only records removed. The review
//!    ([`crate::psbtview`]) and the signer ([`crate::signer`]) then run on that view
//!    unchanged, so a v2 file gets the same refusals and the same signatures as its v0 twin
//!    -- byte for byte, since the digest is over the same transaction.
//! 3. [`V2::write_back`] merges the signed v0 view back into the original v2 container:
//!    the v2 fields are kept as they were, the signatures (or the finalised witnesses) are
//!    inserted, and the modifiable flags are updated as the BIP's Signer role requires. A
//!    host that speaks v2 gets v2 back.
//!
//! What is refused ahead of signing ([`V2::check_for_signing`]): lock-time constraints no
//! single `nLockTime` satisfies (that one at parse), a modifiable-flags byte with bits this
//! does not know, and a transaction still declared modifiable -- see there for why the last
//! is a refusal and not a shrug.
//!
//! Source: BIP-370 "Specification", "Determining Lock Time", "Signer" [C]

use outscript::psbt::{MAGIC, Psbt, Record, global as v0_global};

use crate::tx::VarInt;

/// The v2 global key types. Source: BIP-370 "Specification" [C]
pub mod global {
    /// `<32-bit little endian int version>`: the transaction version.
    pub const TX_VERSION: u64 = 0x02;
    /// `<32-bit little endian uint locktime>`: used when no input requires a lock time.
    pub const FALLBACK_LOCKTIME: u64 = 0x03;
    /// `<compact size uint>`: how many input maps follow the global map.
    pub const INPUT_COUNT: u64 = 0x04;
    /// `<compact size uint>`: how many output maps follow the input maps.
    pub const OUTPUT_COUNT: u64 = 0x05;
    /// `<8-bit uint flags>`: see [`Flags`](super::Flags).
    pub const TX_MODIFIABLE: u64 = 0x06;
    /// `<32-bit little endian uint>`: the PSBT version, shared with v0's key table.
    pub const VERSION: u64 = 0xfb;
}

/// The v2 per-input key types. Source: BIP-370 "Specification" [C]
pub mod input {
    /// `<32 byte txid>`, in the byte order a transaction serialises it.
    pub const PREVIOUS_TXID: u64 = 0x0e;
    /// `<32-bit little endian uint index>`.
    pub const OUTPUT_INDEX: u64 = 0x0f;
    /// `<32-bit little endian uint sequence>`; `0xffffffff` when absent.
    pub const SEQUENCE: u64 = 0x10;
    /// `<32-bit little endian uint locktime>`, at or above 500 000 000.
    pub const REQUIRED_TIME_LOCKTIME: u64 = 0x11;
    /// `<32-bit little endian uint locktime>`, above zero and below 500 000 000.
    pub const REQUIRED_HEIGHT_LOCKTIME: u64 = 0x12;
}

/// The v2 per-output key types. Source: BIP-370 "Specification" [C]
pub mod output {
    /// `<64-bit little endian int amount>`.
    pub const AMOUNT: u64 = 0x03;
    /// `<bytes script>`: the scriptPubKey.
    pub const SCRIPT: u64 = 0x04;
}

/// The lock-time threshold between a height and a Unix time.
/// Source: Bitcoin consensus `LOCKTIME_THRESHOLD`; BIP-370 field definitions [C]
const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// The sequence an input has when its map does not say. Source: BIP-370 [C]
const SEQUENCE_FINAL: u32 = 0xffff_ffff;

/// The `PSBT_GLOBAL_TX_MODIFIABLE` bits. Source: BIP-370 "Specification" [C]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Flags(pub u8);

impl Flags {
    /// Bit 0: inputs may still be added or removed.
    pub const INPUTS_MODIFIABLE: u8 = 1 << 0;
    /// Bit 1: outputs may still be added or removed.
    pub const OUTPUTS_MODIFIABLE: u8 = 1 << 1;
    /// Bit 2: a `SIGHASH_SINGLE` signature exists whose input/output pairing must hold.
    pub const HAS_SIGHASH_SINGLE: u8 = 1 << 2;
    /// The bits the BIP defines; 3-7 are not.
    pub const DEFINED: u8 =
        Self::INPUTS_MODIFIABLE | Self::OUTPUTS_MODIFIABLE | Self::HAS_SIGHASH_SINGLE;

    pub fn inputs_modifiable(self) -> bool {
        self.0 & Self::INPUTS_MODIFIABLE != 0
    }

    pub fn outputs_modifiable(self) -> bool {
        self.0 & Self::OUTPUTS_MODIFIABLE != 0
    }

    pub fn has_sighash_single(self) -> bool {
        self.0 & Self::HAS_SIGHASH_SINGLE != 0
    }

    /// The bits the BIP does not define, as set here.
    pub fn undefined(self) -> u8 {
        self.0 & !Self::DEFINED
    }
}

/// Why a v2 PSBT was not accepted.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// The bytes do not start with the PSBT magic.
    Magic,
    /// The PSBT is version 0 (or names no version), which [`Psbt`] handles directly.
    NotV2,
    /// A version this firmware does not speak: neither 0 nor 2.
    UnsupportedVersion(u32),
    /// The data ends inside a map or a record.
    Truncated,
    /// A compact-size integer that could have been shorter.
    NonCanonical,
    /// A map holds the same key twice.
    DuplicateKey,
    /// A v2 PSBT carries `PSBT_GLOBAL_UNSIGNED_TX`, which the BIP forbids: two sources
    /// for the transaction is one too many.
    UnsignedTxPresent,
    /// A global field the BIP requires is absent, by key type.
    MissingGlobal(u64),
    /// A global field has key data, or a value not of the stated shape.
    BadGlobal(u64),
    /// An input field the BIP requires is absent.
    MissingInputField { input: usize, key: u64 },
    /// An input field has key data, or a value not of the stated shape or range.
    BadInputField { input: usize, key: u64 },
    /// An output field the BIP requires is absent.
    MissingOutputField { output: usize, key: u64 },
    /// An output field has key data, or a value not of the stated shape.
    BadOutputField { output: usize, key: u64 },
    /// The maps present do not match `PSBT_GLOBAL_INPUT_COUNT` and
    /// `PSBT_GLOBAL_OUTPUT_COUNT`: too few, or bytes left over after the last.
    CountMismatch,
    /// One input needs a height lock, another a time lock, and no single `nLockTime` is
    /// both. Source: BIP-370 "Determining Lock Time" [C]
    LocktimeConflict,
    /// The modifiable-flags byte has bits set that the BIP does not define.
    UnknownFlags(u8),
    /// The transaction is still declared modifiable; see [`V2::check_for_signing`].
    StillModifiable(Flags),
    /// The output buffer is too small for what would be written.
    BufferTooSmall,
    /// The signed v0 view handed to [`V2::write_back`] has a different shape from this
    /// container: it was made from something else.
    Mismatch,
    /// The v0 view was refused by the v0 parser. The v2 fields were sound; something in a
    /// record both versions share was not.
    Psbt(outscript::Error),
}

impl From<outscript::Error> for Error {
    fn from(e: outscript::Error) -> Self {
        Error::Psbt(e)
    }
}

/// One input of a v2 PSBT, as its own fields describe it.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Input<'a> {
    /// The txid being spent, in transaction byte order.
    pub txid: [u8; 32],
    pub vout: u32,
    pub sequence: u32,
    pub required_time: Option<u32>,
    pub required_height: Option<u32>,
    /// The map's records, v2 fields included, without the terminator.
    records: &'a [u8],
}

/// One output of a v2 PSBT.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Output<'a> {
    pub amount: u64,
    pub script: &'a [u8],
    records: &'a [u8],
}

/// A validated, zero-copy view of a version-2 PSBT.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct V2<'a> {
    bytes: &'a [u8],
    /// The global records, without the terminator.
    global: &'a [u8],
    /// Offset of the first input map.
    maps_at: usize,
    input_count: usize,
    output_count: usize,
    tx_version: u32,
    fallback_locktime: Option<u32>,
    modifiable: Option<Flags>,
    locktime: u32,
}

/// The PSBT version a container declares: `0` when it says nothing.
///
/// Reads the global map alone, so a v0 file costs one pass over its first map and a v2
/// file can be routed to [`V2::parse`] before anything else looks at it.
pub fn version(bytes: &[u8]) -> Result<u32, Error> {
    if bytes.get(..MAGIC.len()) != Some(&MAGIC[..]) {
        return Err(Error::Magic);
    }
    let mut c = Cursor::new(bytes, MAGIC.len());
    let global = read_map(&mut c)?;
    match find(global, global::VERSION) {
        None => Ok(0),
        Some(rec) => {
            if !rec.key_data.is_empty() {
                return Err(Error::BadGlobal(global::VERSION));
            }
            u32_of(rec.value).ok_or(Error::BadGlobal(global::VERSION))
        }
    }
}

/// Whether `bytes` declare themselves a version-2 PSBT.
pub fn is_v2(bytes: &[u8]) -> bool {
    version(bytes) == Ok(2)
}

impl<'a> V2<'a> {
    /// Parse and validate a v2 container.
    ///
    /// Everything BIP-370 says about the v2 fields is checked here: presence of the
    /// required ones, absence of key data, the length of each value, the ranges of the two
    /// required lock times, the map count against the declared counts, and the lock-time
    /// determination. A version-0 file is [`Error::NotV2`], so a caller can fall through to
    /// [`Psbt::parse`]. Records this does not know are passed over, to be validated by the
    /// v0 parser on the view or carried untouched.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        match version(bytes)? {
            2 => {}
            0 => return Err(Error::NotV2),
            v => return Err(Error::UnsupportedVersion(v)),
        }
        let mut c = Cursor::new(bytes, MAGIC.len());
        let global = read_map(&mut c)?;
        check_duplicates(global)?;

        let mut tx_version = None;
        let mut fallback_locktime = None;
        let mut input_count = None;
        let mut output_count = None;
        let mut modifiable = None;
        for rec in records(global) {
            let rec = rec?;
            let t = rec.key_type;
            let bad = Error::BadGlobal(t);
            let no_key_data = || {
                if rec.key_data.is_empty() {
                    Ok(())
                } else {
                    Err(bad)
                }
            };
            match t {
                v0_global::UNSIGNED_TX => return Err(Error::UnsignedTxPresent),
                global::TX_VERSION => {
                    no_key_data()?;
                    tx_version = Some(u32_of(rec.value).ok_or(bad)?);
                }
                global::FALLBACK_LOCKTIME => {
                    no_key_data()?;
                    fallback_locktime = Some(u32_of(rec.value).ok_or(bad)?);
                }
                global::INPUT_COUNT => {
                    no_key_data()?;
                    input_count = Some(count_of(rec.value).ok_or(bad)?);
                }
                global::OUTPUT_COUNT => {
                    no_key_data()?;
                    output_count = Some(count_of(rec.value).ok_or(bad)?);
                }
                global::TX_MODIFIABLE => {
                    no_key_data()?;
                    match rec.value {
                        [f] => modifiable = Some(Flags(*f)),
                        _ => return Err(bad),
                    }
                }
                _ => {}
            }
        }
        let tx_version = tx_version.ok_or(Error::MissingGlobal(global::TX_VERSION))?;
        let input_count = input_count.ok_or(Error::MissingGlobal(global::INPUT_COUNT))?;
        let output_count = output_count.ok_or(Error::MissingGlobal(global::OUTPUT_COUNT))?;

        let mut v2 = V2 {
            bytes,
            global,
            maps_at: c.pos,
            input_count,
            output_count,
            tx_version,
            fallback_locktime,
            modifiable,
            locktime: 0,
        };

        // The maps, each read once for its framing and its v2 fields. A map that is not
        // there is a count that lies, and so are bytes after the last one.
        for i in 0..input_count {
            if c.is_empty() {
                return Err(Error::CountMismatch);
            }
            let map = read_map(&mut c)?;
            check_duplicates(map)?;
            parse_input(i, map)?;
        }
        for i in 0..output_count {
            if c.is_empty() {
                return Err(Error::CountMismatch);
            }
            let map = read_map(&mut c)?;
            check_duplicates(map)?;
            parse_output(i, map)?;
        }
        if !c.is_empty() {
            return Err(Error::CountMismatch);
        }

        v2.locktime = v2.determine_locktime()?;
        Ok(v2)
    }

    /// The bytes this was parsed from.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn input_count(&self) -> usize {
        self.input_count
    }

    pub fn output_count(&self) -> usize {
        self.output_count
    }

    /// The transaction version the v2 fields name.
    pub fn tx_version(&self) -> u32 {
        self.tx_version
    }

    /// `PSBT_GLOBAL_FALLBACK_LOCKTIME`, if present.
    pub fn fallback_locktime(&self) -> Option<u32> {
        self.fallback_locktime
    }

    /// `PSBT_GLOBAL_TX_MODIFIABLE`, if present.
    pub fn modifiable(&self) -> Option<Flags> {
        self.modifiable
    }

    /// The `nLockTime` the BIP's rules give this transaction.
    pub fn locktime(&self) -> u32 {
        self.locktime
    }

    /// The input maps, in order.
    pub fn inputs(&self) -> impl Iterator<Item = Input<'a>> + 'a {
        let mut c = Cursor::new(self.bytes, self.maps_at);
        (0..self.input_count).map_while(move |i| {
            let map = read_map(&mut c).ok()?;
            parse_input(i, map).ok()
        })
    }

    /// The output maps, in order.
    pub fn outputs(&self) -> impl Iterator<Item = Output<'a>> + 'a {
        let mut c = Cursor::new(self.bytes, self.maps_at);
        for _ in 0..self.input_count {
            if read_map(&mut c).is_err() {
                break;
            }
        }
        (0..self.output_count).map_while(move |i| {
            let map = read_map(&mut c).ok()?;
            parse_output(i, map).ok()
        })
    }

    pub fn input(&self, index: usize) -> Option<Input<'a>> {
        self.inputs().nth(index)
    }

    pub fn output(&self, index: usize) -> Option<Output<'a>> {
        self.outputs().nth(index)
    }

    /// BIP-370 "Determining Lock Time".
    ///
    /// With no input naming a lock, the fallback (or zero). Otherwise the kind every
    /// locked input supports -- height when all of them carry a height, else time when all
    /// carry a time -- at the largest value asked for; height wins a tie. An input naming
    /// neither takes either. No common kind is [`Error::LocktimeConflict`].
    fn determine_locktime(&self) -> Result<u32, Error> {
        let mut any = false;
        let mut height_ok = true;
        let mut time_ok = true;
        let mut max_height = 0u32;
        let mut max_time = 0u32;
        for inp in self.inputs() {
            if inp.required_height.is_none() && inp.required_time.is_none() {
                continue;
            }
            any = true;
            match inp.required_height {
                Some(h) => max_height = max_height.max(h),
                None => height_ok = false,
            }
            match inp.required_time {
                Some(t) => max_time = max_time.max(t),
                None => time_ok = false,
            }
        }
        if !any {
            return Ok(self.fallback_locktime.unwrap_or(0));
        }
        if height_ok {
            Ok(max_height)
        } else if time_ok {
            Ok(max_time)
        } else {
            Err(Error::LocktimeConflict)
        }
    }

    /// Whether this may be put in front of the owner and signed.
    ///
    /// Two refusals beyond what [`parse`](Self::parse) already made:
    ///
    /// - A flags byte with bits the BIP does not define. A bit this cannot read may mean
    ///   "something else about this transaction may change", and a signer that cannot
    ///   read it cannot say what it is signing.
    /// - Inputs or outputs still declared modifiable. By the BIP a Constructor clears
    ///   those bits, or drops the field, once the transaction is what it will be; a PSBT
    ///   that reaches a signer with either set is announcing that what the owner is
    ///   about to review is not final. The only signature that survives such a change is
    ///   one that does not cover the inputs or the outputs -- the non-`ALL` types the
    ///   sighash policy exists to refuse. So it is refused here, by name, and the cure is
    ///   for the host to finish constructing the transaction first.
    ///
    /// `Has SIGHASH_SINGLE` is not a refusal: it is a fact about someone else's earlier
    /// signature, and this device's own signature commits to what it reviewed either way.
    /// Source: BIP-370 "Constructor", "Signer" [C]
    pub fn check_for_signing(&self) -> Result<(), Error> {
        if let Some(flags) = self.modifiable {
            if flags.undefined() != 0 {
                return Err(Error::UnknownFlags(flags.undefined()));
            }
            if flags.inputs_modifiable() || flags.outputs_modifiable() {
                return Err(Error::StillModifiable(flags));
            }
        }
        Ok(())
    }

    /// Length of the unsigned transaction the v2 fields describe.
    fn unsigned_tx_len(&self) -> usize {
        let mut c = Counter(0);
        // A counter never runs out of room.
        let _ = self.write_unsigned_tx(&mut c);
        c.0
    }

    /// Serialise the transaction the v2 fields describe, with empty scriptSigs.
    fn write_unsigned_tx(&self, w: &mut dyn Sink) -> Result<(), Error> {
        w.put(&self.tx_version.to_le_bytes())?;
        w.varint(self.input_count as u64)?;
        for inp in self.inputs() {
            w.put(&inp.txid)?;
            w.put(&inp.vout.to_le_bytes())?;
            w.put(&[0x00])?;
            w.put(&inp.sequence.to_le_bytes())?;
        }
        w.varint(self.output_count as u64)?;
        for out in self.outputs() {
            w.put(&out.amount.to_le_bytes())?;
            w.varint(out.script.len() as u64)?;
            w.put(out.script)?;
        }
        w.put(&self.locktime.to_le_bytes())?;
        Ok(())
    }

    /// An upper bound on what [`to_v0`](Self::to_v0) writes.
    pub fn v0_len_bound(&self) -> usize {
        // The container less its v2 records, plus one record holding the transaction:
        // a 1-byte key length, the key, up to 9 bytes of value length, and the value.
        self.bytes.len() + 1 + 1 + 9 + self.unsigned_tx_len()
    }

    /// Write the equivalent version-0 PSBT into `out`; returns its length.
    ///
    /// The global map gets `PSBT_GLOBAL_UNSIGNED_TX` built from the v2 fields, keeps every
    /// record that is not v2-specific (xpubs, proprietary, unknown), and drops
    /// `PSBT_GLOBAL_VERSION` -- absent means 0. Each input and output map keeps everything
    /// but its v2 fields. The result is parsed by the v0 parser before it is returned, so
    /// what comes back is a PSBT the rest of this crate has already accepted.
    pub fn to_v0(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = SliceSink { out, at: 0 };
        w.put(&MAGIC)?;
        // The unsigned transaction first: key `00`, then the serialised transaction.
        w.put(&[0x01, v0_global::UNSIGNED_TX as u8])?;
        w.varint(self.unsigned_tx_len() as u64)?;
        self.write_unsigned_tx(&mut w)?;
        copy_records(self.global, &mut w, |t| !is_v2_global(t))?;
        w.put(&[0x00])?;
        for inp in self.inputs() {
            copy_records(inp.records, &mut w, |t| !is_v2_input(t))?;
            w.put(&[0x00])?;
        }
        for o in self.outputs() {
            copy_records(o.records, &mut w, |t| !is_v2_output(t))?;
            w.put(&[0x00])?;
        }
        let n = w.at;
        Psbt::parse(&w.out[..n])?;
        Ok(n)
    }

    /// Merge `signed`, the signed (or finalised) v0 view of this container, back into it
    /// as version 2, written into `out`; returns the length.
    ///
    /// Each map is the original's v2 records plus whatever the v0 map now holds -- which
    /// is the original's non-v2 records, the partial signatures the signer added, or after
    /// finalisation the final scriptSig/witness with the fields BIP-174 says to clear
    /// already cleared. The global map is carried as it was, except
    /// `PSBT_GLOBAL_TX_MODIFIABLE`, which is brought up to date with the signatures now
    /// present as the BIP's Signer role requires: a signature not `ANYONECANPAY` clears
    /// Inputs Modifiable, one not `NONE` clears Outputs Modifiable, and a `SINGLE` one sets
    /// Has SIGHASH_SINGLE. Source: BIP-370 "Signer", "Input Finalizer" [C]
    pub fn write_back(&self, signed: &Psbt<'_>, out: &mut [u8]) -> Result<usize, Error> {
        let tx = signed.unsigned_tx();
        if tx.input_count() != self.input_count || tx.output_count() != self.output_count {
            return Err(Error::Mismatch);
        }
        let flags = self.flags_after(signed);

        let mut w = SliceSink { out, at: 0 };
        w.put(&MAGIC)?;
        // Global: as it was, with the flags byte replaced (or appended) where it changed.
        let mut wrote_flags = false;
        for rec in records(self.global) {
            let rec = rec?;
            if rec.key_type == global::TX_MODIFIABLE
                && let Some(f) = flags
            {
                put_record(&mut w, rec.key, &[f.0])?;
                wrote_flags = true;
                continue;
            }
            put_record(&mut w, rec.key, rec.value)?;
        }
        if let (Some(f), false) = (flags, wrote_flags) {
            put_record(&mut w, &[global::TX_MODIFIABLE as u8], &[f.0])?;
        }
        w.put(&[0x00])?;

        for (i, inp) in self.inputs().enumerate() {
            let v0 = signed.input(i).ok_or(Error::Mismatch)?.map();
            merge_map(inp.records, is_v2_input, v0.records(), &mut w)?;
            w.put(&[0x00])?;
        }
        for (i, o) in self.outputs().enumerate() {
            let v0 = signed.output(i).ok_or(Error::Mismatch)?.map();
            merge_map(o.records, is_v2_output, v0.records(), &mut w)?;
            w.put(&[0x00])?;
        }
        let n = w.at;
        V2::parse(&w.out[..n])?;
        Ok(n)
    }

    /// The modifiable flags after the signatures `signed` carries, when they differ from
    /// what the container says (or when it says nothing and a `SINGLE` signature now
    /// exists). `None` when nothing needs writing.
    fn flags_after(&self, signed: &Psbt<'_>) -> Option<Flags> {
        use crate::tx::sighash::{
            SIGHASH_ANYONECANPAY, SIGHASH_MASK, SIGHASH_NONE, SIGHASH_SINGLE,
        };
        let mut clear_inputs = false;
        let mut clear_outputs = false;
        let mut single = false;
        let mut note = |kind: u32| {
            if kind & SIGHASH_ANYONECANPAY == 0 {
                clear_inputs = true;
            }
            if kind & SIGHASH_MASK != SIGHASH_NONE {
                clear_outputs = true;
            }
            if kind & SIGHASH_MASK == SIGHASH_SINGLE {
                single = true;
            }
        };
        for inp in signed.inputs() {
            for (_, sig) in inp.partial_sigs() {
                if let Some(&t) = sig.last() {
                    note(u32::from(t));
                }
            }
            if let Some(sig) = inp.tap_key_sig() {
                // 64 bytes is the default type (`ALL`); a 65th byte names another.
                note(if sig.len() == 65 {
                    u32::from(sig[64])
                } else {
                    1
                });
            }
            for (_, _, sig) in inp.tap_script_sigs() {
                note(if sig.len() == 65 {
                    u32::from(sig[64])
                } else {
                    1
                });
            }
            // A finalised input's signature type is inside its witness, which this does
            // not read; `ALL` is what this device produces, and any other type was a
            // partial signature noted above before finalisation cleared it.
            if inp.is_finalized() && inp.partial_sigs().next().is_none() {
                note(1);
            }
        }
        let mut f = self.modifiable.unwrap_or_default();
        if clear_inputs {
            f.0 &= !Flags::INPUTS_MODIFIABLE;
        }
        if clear_outputs {
            f.0 &= !Flags::OUTPUTS_MODIFIABLE;
        }
        if single {
            f.0 |= Flags::HAS_SIGHASH_SINGLE;
        }
        match self.modifiable {
            Some(was) if was == f => None,
            Some(_) => Some(f),
            None if f.0 != 0 => Some(f),
            None => None,
        }
    }
}

fn is_v2_global(t: u64) -> bool {
    matches!(
        t,
        global::TX_VERSION
            | global::FALLBACK_LOCKTIME
            | global::INPUT_COUNT
            | global::OUTPUT_COUNT
            | global::TX_MODIFIABLE
            | global::VERSION
    )
}

fn is_v2_input(t: u64) -> bool {
    (input::PREVIOUS_TXID..=input::REQUIRED_HEIGHT_LOCKTIME).contains(&t)
}

fn is_v2_output(t: u64) -> bool {
    matches!(t, output::AMOUNT | output::SCRIPT)
}

/// Write the v2 records of `original` and every record of `v0`, in ascending key-type
/// order as far as the two sources allow: the v2 range sits between v0's key types, so the
/// v0 records below it go first, then the v2 ones, then the rest.
fn merge_map<'m>(
    original: &[u8],
    is_v2: fn(u64) -> bool,
    v0: impl Iterator<Item = Record<'m>>,
    w: &mut SliceSink<'_>,
) -> Result<(), Error> {
    let first_v2 = (0..=0xffu64).find(|&t| is_v2(t)).unwrap_or(u64::MAX);
    let mut v2_written = false;
    for rec in v0 {
        let t = rec.key_type();
        if !v2_written && t > first_v2 {
            copy_records(original, w, is_v2)?;
            v2_written = true;
        }
        // The v0 parser refuses v2 keys, so none is here; the guard states the shape.
        if is_v2(t) {
            continue;
        }
        put_record(w, rec.key, rec.value)?;
    }
    if !v2_written {
        copy_records(original, w, is_v2)?;
    }
    Ok(())
}

/// The v2 fields of one input map, checked.
fn parse_input(index: usize, map: &[u8]) -> Result<Input<'_>, Error> {
    let mut txid = None;
    let mut vout = None;
    let mut sequence = None;
    let mut required_time = None;
    let mut required_height = None;
    for rec in records(map) {
        let rec = rec?;
        let t = rec.key_type;
        if !is_v2_input(t) {
            continue;
        }
        let bad = Error::BadInputField {
            input: index,
            key: t,
        };
        if !rec.key_data.is_empty() {
            return Err(bad);
        }
        match t {
            input::PREVIOUS_TXID => {
                let id: [u8; 32] = rec.value.try_into().map_err(|_| bad)?;
                txid = Some(id);
            }
            input::OUTPUT_INDEX => vout = Some(u32_of(rec.value).ok_or(bad)?),
            input::SEQUENCE => sequence = Some(u32_of(rec.value).ok_or(bad)?),
            input::REQUIRED_TIME_LOCKTIME => {
                let t = u32_of(rec.value).ok_or(bad)?;
                if t < LOCKTIME_THRESHOLD {
                    return Err(bad);
                }
                required_time = Some(t);
            }
            input::REQUIRED_HEIGHT_LOCKTIME => {
                let h = u32_of(rec.value).ok_or(bad)?;
                if h == 0 || h >= LOCKTIME_THRESHOLD {
                    return Err(bad);
                }
                required_height = Some(h);
            }
            _ => {}
        }
    }
    let missing = |key| Error::MissingInputField { input: index, key };
    Ok(Input {
        txid: txid.ok_or(missing(input::PREVIOUS_TXID))?,
        vout: vout.ok_or(missing(input::OUTPUT_INDEX))?,
        sequence: sequence.unwrap_or(SEQUENCE_FINAL),
        required_time,
        required_height,
        records: map,
    })
}

/// The v2 fields of one output map, checked.
fn parse_output(index: usize, map: &[u8]) -> Result<Output<'_>, Error> {
    let mut amount = None;
    let mut script = None;
    for rec in records(map) {
        let rec = rec?;
        let t = rec.key_type;
        if !is_v2_output(t) {
            continue;
        }
        let bad = Error::BadOutputField {
            output: index,
            key: t,
        };
        if !rec.key_data.is_empty() {
            return Err(bad);
        }
        match t {
            output::AMOUNT => {
                let a: [u8; 8] = rec.value.try_into().map_err(|_| bad)?;
                amount = Some(u64::from_le_bytes(a));
            }
            output::SCRIPT => script = Some(rec.value),
            _ => {}
        }
    }
    let missing = |key| Error::MissingOutputField { output: index, key };
    Ok(Output {
        amount: amount.ok_or(missing(output::AMOUNT))?,
        script: script.ok_or(missing(output::SCRIPT))?,
        records: map,
    })
}

fn u32_of(value: &[u8]) -> Option<u32> {
    let v: [u8; 4] = value.try_into().ok()?;
    Some(u32::from_le_bytes(v))
}

/// A compact-size value that fills its record exactly.
fn count_of(value: &[u8]) -> Option<usize> {
    let mut c = Cursor::new(value, 0);
    let n = c.varint().ok()?;
    if !c.is_empty() {
        return None;
    }
    usize::try_from(n).ok()
}

// --- map framing ---

/// A bounds-checked position in a byte slice.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8], pos: usize) -> Self {
        Cursor { buf, pos }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Truncated)?;
        let s = self.buf.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(s)
    }

    /// A canonical compact-size integer. Source: Bitcoin serialisation `CompactSize` [C]
    fn varint(&mut self) -> Result<u64, Error> {
        let first = self.take(1)?[0];
        let (value, min) = match first {
            0..=0xfc => return Ok(u64::from(first)),
            0xfd => (
                u64::from(u16::from_le_bytes(self.take(2)?.try_into().unwrap())),
                0xfd,
            ),
            0xfe => (
                u64::from(u32::from_le_bytes(self.take(4)?.try_into().unwrap())),
                0x1_0000,
            ),
            _ => (
                u64::from_le_bytes(self.take(8)?.try_into().unwrap()),
                0x1_0000_0000,
            ),
        };
        if value < min {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }

    /// A length-prefixed byte string.
    fn var_slice(&mut self) -> Result<&'a [u8], Error> {
        let n = self.varint()?;
        self.take(usize::try_from(n).map_err(|_| Error::Truncated)?)
    }
}

/// Read one map -- records up to and including the `00` terminator -- returning the
/// records without the terminator.
fn read_map<'a>(c: &mut Cursor<'a>) -> Result<&'a [u8], Error> {
    let start = c.pos;
    loop {
        let at = c.pos;
        let key = c.var_slice()?;
        if key.is_empty() {
            return Ok(&c.buf[start..at]);
        }
        // The key type has to be a readable compact size on its own.
        Cursor::new(key, 0).varint()?;
        c.var_slice()?;
    }
}

/// One record of a map.
#[derive(Copy, Clone)]
struct Rec<'a> {
    /// The whole key: type then data.
    key: &'a [u8],
    key_type: u64,
    key_data: &'a [u8],
    value: &'a [u8],
}

/// The records of a map body, in order.
fn records(map: &[u8]) -> impl Iterator<Item = Result<Rec<'_>, Error>> + '_ {
    let mut c = Cursor::new(map, 0);
    core::iter::from_fn(move || {
        if c.is_empty() {
            return None;
        }
        Some((|| {
            let key = c.var_slice()?;
            let value = c.var_slice()?;
            let mut kc = Cursor::new(key, 0);
            let key_type = kc.varint()?;
            Ok(Rec {
                key,
                key_type,
                key_data: &key[kc.pos..],
                value,
            })
        })())
    })
}

/// The first record of `key_type` in `map`.
fn find(map: &[u8], key_type: u64) -> Option<Rec<'_>> {
    records(map)
        .filter_map(|r| r.ok())
        .find(|r| r.key_type == key_type)
}

fn check_duplicates(map: &[u8]) -> Result<(), Error> {
    for (i, a) in records(map).enumerate() {
        let a = a?;
        for b in records(map).skip(i + 1) {
            if b?.key == a.key {
                return Err(Error::DuplicateKey);
            }
        }
    }
    Ok(())
}

/// Copy the records of `map` whose key type passes `keep` into `w`.
fn copy_records(map: &[u8], w: &mut dyn Sink, keep: impl Fn(u64) -> bool) -> Result<(), Error> {
    for rec in records(map) {
        let rec = rec?;
        if keep(rec.key_type) {
            put_record(w, rec.key, rec.value)?;
        }
    }
    Ok(())
}

fn put_record(w: &mut dyn Sink, key: &[u8], value: &[u8]) -> Result<(), Error> {
    w.varint(key.len() as u64)?;
    w.put(key)?;
    w.varint(value.len() as u64)?;
    w.put(value)
}

// --- writing ---

trait Sink {
    fn put(&mut self, bytes: &[u8]) -> Result<(), Error>;
    fn varint(&mut self, v: u64) -> Result<(), Error> {
        let mut buf = [0u8; 9];
        let n = VarInt::write(v, &mut buf).map_err(|_| Error::BufferTooSmall)?;
        self.put(&buf[..n])
    }
}

struct Counter(usize);

impl Sink for Counter {
    fn put(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.0 += bytes.len();
        Ok(())
    }
}

struct SliceSink<'o> {
    out: &'o mut [u8],
    at: usize,
}

impl Sink for SliceSink<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let end = self
            .at
            .checked_add(bytes.len())
            .ok_or(Error::BufferTooSmall)?;
        let room = self
            .out
            .get_mut(self.at..end)
            .ok_or(Error::BufferTooSmall)?;
        room.copy_from_slice(bytes);
        self.at = end;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
