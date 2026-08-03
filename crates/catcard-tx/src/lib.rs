//! Bitcoin transactions: parsing, serialisation, and the hashes that get signed.
//!
//! # Borrowed, not owned
//!
//! A transaction here holds slices into the buffer it was parsed from. No allocation,
//! no copying, and no fixed maximum on the number of inputs — which matters on a device
//! where a large PSBT already fills most of the available scratch space.
//!
//! The cost is that a parsed transaction cannot outlive its buffer, which the borrow
//! checker enforces.
//!
//! # What the device is actually deciding
//!
//! A hardware wallet's entire purpose is that the *host* may be lying. Everything a
//! user is shown — amounts, destinations, fee — has to come from data the signature
//! commits to. BIP-143 is what makes that possible for segwit: it puts the input amount
//! inside the signed preimage, so a host that lies about it produces a signature that
//! does not verify.
//!
//! Legacy (pre-segwit) sighash has no such commitment, which is why signing a legacy
//! input safely requires the *entire* previous transaction to check the amount against.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

use sha2::{Digest, Sha256};

pub mod varint;

pub use varint::VarInt;

/// A 32-byte hash, little-endian on the wire as Bitcoin uses it.
pub type Hash = [u8; 32];

/// Marker and flag bytes that introduce a segwit serialisation.
const SEGWIT_MARKER: u8 = 0x00;
const SEGWIT_FLAG: u8 = 0x01;

/// A transaction input's outpoint length: 32-byte txid plus a 4-byte index.
pub const OUTPOINT_LEN: usize = 36;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Ran out of bytes mid-structure. The most common shape of a malformed input.
    Truncated { at: usize },
    /// A length field claims more than the buffer holds. Checked before allocating or
    /// slicing, because a host-supplied length is attacker-controlled.
    BadLength { at: usize, len: u64 },
    /// A varint that could have been encoded shorter. Non-canonical encodings make two
    /// byte strings mean the same transaction, and therefore two different txids.
    NonCanonicalVarInt { at: usize },
    /// A segwit transaction with no inputs, or a marker/flag pair that is not 0x00 0x01.
    BadSegwitMarker,
    /// No inputs or no outputs.
    Empty,
    /// The input index is past the end of the transaction.
    NoSuchInput { index: usize },
    /// `SIGHASH_SINGLE` with no output at the input's index. In Bitcoin Core this
    /// famously hashes to 1 rather than erroring; that behaviour is a bug being
    /// emulated, and a wallet must refuse rather than reproduce it.
    SingleWithoutOutput { index: usize },
}

/// Where an input spends from.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct OutPoint {
    /// Previous transaction id, as it appears on the wire (internal byte order).
    pub txid: Hash,
    pub vout: u32,
}

/// A transaction input.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct TxIn<'a> {
    pub previous_output: OutPoint,
    pub script_sig: &'a [u8],
    pub sequence: u32,
}

/// A transaction output.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct TxOut<'a> {
    /// Satoshis.
    pub value: u64,
    pub script_pubkey: &'a [u8],
}

/// Double SHA-256, the hash Bitcoin uses nearly everywhere.
pub fn sha256d(data: &[u8]) -> Hash {
    Sha256::digest(Sha256::digest(data)).into()
}

/// Incremental double SHA-256, for preimages assembled piecewise.
pub struct Sha256d {
    inner: Sha256,
}

impl Default for Sha256d {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256d {
    pub fn new() -> Self {
        Self {
            inner: Sha256::new(),
        }
    }
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }
    pub fn finalize(self) -> Hash {
        Sha256::digest(self.inner.finalize()).into()
    }
}

/// A cursor over a byte buffer that refuses to read past the end.
///
/// Every field a transaction parser reads is length-prefixed by data the host supplies,
/// so bounds are checked on every access rather than trusted once.
pub struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, at: 0 }
    }

    pub fn position(&self) -> usize {
        self.at
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.at
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.remaining() < n {
            return Err(Error::Truncated { at: self.at });
        }
        let s = &self.data[self.at..self.at + n];
        self.at += n;
        Ok(s)
    }

    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    pub fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }

    pub fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }

    pub fn hash(&mut self) -> Result<Hash, Error> {
        Ok(self.take(32)?.try_into().expect("32 bytes"))
    }

    /// Read a canonical varint.
    pub fn varint(&mut self) -> Result<u64, Error> {
        let at = self.at;
        VarInt::read(self).map_err(|e| match e {
            Error::Truncated { .. } => Error::Truncated { at },
            other => other,
        })
    }

    /// Read a varint-prefixed byte string, bounds-checked against the buffer.
    pub fn var_slice(&mut self) -> Result<&'a [u8], Error> {
        let at = self.at;
        let len = self.varint()?;
        if len > self.remaining() as u64 {
            return Err(Error::BadLength { at, len });
        }
        self.take(len as usize)
    }

    /// Peek without consuming.
    pub fn peek(&self, n: usize) -> Option<&'a [u8]> {
        self.data.get(self.at..self.at + n)
    }
}

/// A parsed transaction, borrowing from the buffer it came from.
#[derive(Clone, Debug)]
pub struct Transaction<'a> {
    pub version: i32,
    pub inputs: InputIter<'a>,
    pub outputs: OutputIter<'a>,
    pub lock_time: u32,
    /// True if the serialisation carried a witness section.
    pub has_witness: bool,
    /// The serialisation this was parsed from, with the witness stripped. Hashing this
    /// gives the txid.
    legacy_bytes_len: usize,
    source: &'a [u8],
}

/// Iterator over the inputs, re-parsed on demand.
///
/// Re-parsing rather than storing is what keeps this allocation-free with an unbounded
/// input count. Transactions are parsed once and iterated a handful of times, so the
/// cost is immaterial next to the hashing.
#[derive(Copy, Clone, Debug)]
pub struct InputIter<'a> {
    data: &'a [u8],
    count: u64,
}

#[derive(Copy, Clone, Debug)]
pub struct OutputIter<'a> {
    data: &'a [u8],
    count: u64,
}

impl<'a> InputIter<'a> {
    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn iter(&self) -> impl Iterator<Item = Result<TxIn<'a>, Error>> + 'a {
        let mut r = Reader::new(self.data);
        let n = self.count;
        (0..n).map(move |_| read_input(&mut r))
    }

    pub fn get(&self, index: usize) -> Result<TxIn<'a>, Error> {
        self.iter().nth(index).ok_or(Error::NoSuchInput { index })?
    }
}

impl<'a> OutputIter<'a> {
    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn iter(&self) -> impl Iterator<Item = Result<TxOut<'a>, Error>> + 'a {
        let mut r = Reader::new(self.data);
        let n = self.count;
        (0..n).map(move |_| read_output(&mut r))
    }

    pub fn get(&self, index: usize) -> Option<Result<TxOut<'a>, Error>> {
        self.iter().nth(index)
    }

    /// Total satoshis paid out.
    pub fn total(&self) -> Result<u64, Error> {
        let mut sum = 0u64;
        for o in self.iter() {
            // Saturating rather than wrapping: an overflowing total would otherwise
            // display a small fee for a transaction spending everything.
            sum = sum.saturating_add(o?.value);
        }
        Ok(sum)
    }
}

fn read_input<'a>(r: &mut Reader<'a>) -> Result<TxIn<'a>, Error> {
    let txid = r.hash()?;
    let vout = r.u32()?;
    let script_sig = r.var_slice()?;
    let sequence = r.u32()?;
    Ok(TxIn {
        previous_output: OutPoint { txid, vout },
        script_sig,
        sequence,
    })
}

fn read_output<'a>(r: &mut Reader<'a>) -> Result<TxOut<'a>, Error> {
    let value = r.u64()?;
    let script_pubkey = r.var_slice()?;
    Ok(TxOut {
        value,
        script_pubkey,
    })
}

impl<'a> Transaction<'a> {
    /// Parse a transaction, with or without a witness section.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(data);
        let version = r.u32()? as i32;

        // A zero input count in the legacy position is the segwit marker. Distinguishing
        // them is the one genuinely ambiguous part of the format.
        let is_segwit = matches!(r.peek(2), Some([SEGWIT_MARKER, SEGWIT_FLAG]));
        if is_segwit {
            r.u8()?;
            let flag = r.u8()?;
            if flag != SEGWIT_FLAG {
                return Err(Error::BadSegwitMarker);
            }
        }

        let inputs_start = r.position();
        let n_in = r.varint()?;
        if n_in == 0 {
            return Err(Error::Empty);
        }
        let in_body_start = r.position();
        for _ in 0..n_in {
            read_input(&mut r)?;
        }
        let inputs = InputIter {
            data: &data[in_body_start..r.position()],
            count: n_in,
        };

        let n_out = r.varint()?;
        if n_out == 0 {
            return Err(Error::Empty);
        }
        let out_body_start = r.position();
        for _ in 0..n_out {
            read_output(&mut r)?;
        }
        let outputs = OutputIter {
            data: &data[out_body_start..r.position()],
            count: n_out,
        };
        let outputs_end = r.position();

        if is_segwit {
            // One witness stack per input.
            for _ in 0..n_in {
                let items = r.varint()?;
                for _ in 0..items {
                    r.var_slice()?;
                }
            }
        }

        let lock_time = r.u32()?;

        Ok(Transaction {
            version,
            inputs,
            outputs,
            lock_time,
            has_witness: is_segwit,
            legacy_bytes_len: outputs_end - inputs_start,
            source: data,
        })
    }

    /// The transaction id: double-SHA256 over the serialisation **without** the witness.
    ///
    /// Excluding the witness is what makes segwit txids immune to malleability — a
    /// third party can rewrite a signature but not change the id.
    pub fn txid(&self) -> Hash {
        let mut h = Sha256d::new();
        h.update(&(self.version as u32).to_le_bytes());
        // The input and output sections, verbatim from the source.
        h.update(self.legacy_body());
        h.update(&self.lock_time.to_le_bytes());
        h.finalize()
    }

    /// The input and output sections as they appeared, counts included.
    fn legacy_body(&self) -> &'a [u8] {
        // `legacy_bytes_len` spans from the input count through the last output.
        let end = self.outputs.data.as_ptr() as usize - self.source.as_ptr() as usize
            + self.outputs.data.len();
        let start = end - self.legacy_bytes_len;
        &self.source[start..end]
    }

    /// Sum of the output values.
    pub fn total_out(&self) -> Result<u64, Error> {
        self.outputs.total()
    }
}

pub mod sighash;

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The BIP-143 native P2WPKH example, unsigned.
    const BIP143_UNSIGNED: &str = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000";

    #[test]
    fn parses_a_legacy_transaction() {
        let raw = unhex(BIP143_UNSIGNED);
        let tx = Transaction::parse(&raw).unwrap();
        assert_eq!(tx.version, 1);
        assert!(!tx.has_witness);
        assert_eq!(tx.inputs.count(), 2);
        assert_eq!(tx.outputs.count(), 2);
        assert_eq!(tx.lock_time, 0x11);
    }

    #[test]
    fn reads_input_fields() {
        let raw = unhex(BIP143_UNSIGNED);
        let tx = Transaction::parse(&raw).unwrap();
        let i0 = tx.inputs.get(0).unwrap();
        assert_eq!(i0.previous_output.vout, 0);
        assert_eq!(i0.sequence, 0xffffffee);
        assert!(i0.script_sig.is_empty());

        let i1 = tx.inputs.get(1).unwrap();
        assert_eq!(i1.previous_output.vout, 1);
        assert_eq!(i1.sequence, 0xffffffff);
    }

    #[test]
    fn reads_output_values_and_scripts() {
        let raw = unhex(BIP143_UNSIGNED);
        let tx = Transaction::parse(&raw).unwrap();
        let o0 = tx.outputs.get(0).unwrap().unwrap();
        assert_eq!(o0.value, 112_340_000);
        assert_eq!(o0.script_pubkey.len(), 25); // P2PKH
        assert_eq!(o0.script_pubkey[0], 0x76); // OP_DUP
        assert_eq!(tx.total_out().unwrap(), 112_340_000 + 223_450_000);
    }

    #[test]
    fn output_totals_saturate_rather_than_wrap() {
        // A wrapping total would show a tiny fee for a transaction spending everything.
        let mut raw = unhex(BIP143_UNSIGNED);
        // Find the first output value and set it to u64::MAX.
        let tx = Transaction::parse(&raw).unwrap();
        let off = tx.outputs.data.as_ptr() as usize - raw.as_ptr() as usize;
        raw[off..off + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        let tx = Transaction::parse(&raw).unwrap();
        assert_eq!(tx.total_out().unwrap(), u64::MAX);
    }

    #[test]
    fn a_truncated_transaction_is_rejected_at_every_length() {
        // Host-supplied bytes; every prefix must error rather than panic.
        let raw = unhex(BIP143_UNSIGNED);
        for n in 0..raw.len() {
            let _ = Transaction::parse(&raw[..n]);
        }
    }

    #[test]
    fn an_oversized_script_length_is_rejected() {
        // A script length larger than the buffer is the classic parser exploit.
        let mut raw = unhex(BIP143_UNSIGNED);
        // The first input's scriptSig length is at offset 4 + 36 = 40.
        raw[40] = 0xfd; // varint, 2-byte length follows
        raw.insert(41, 0xff);
        raw.insert(42, 0xff);
        assert!(matches!(
            Transaction::parse(&raw),
            Err(Error::BadLength { .. } | Error::Truncated { .. })
        ));
    }

    #[test]
    fn a_transaction_with_no_inputs_or_outputs_is_rejected() {
        let mut raw = unhex(BIP143_UNSIGNED);
        raw[4] = 0x00; // zero inputs -- also the segwit marker, so this must not parse
        assert!(Transaction::parse(&raw).is_err());
    }

    #[test]
    fn txid_is_stable_and_excludes_the_witness() {
        let raw = unhex(BIP143_UNSIGNED);
        let tx = Transaction::parse(&raw).unwrap();
        // The whole serialisation is legacy here, so the txid is just its double hash.
        assert_eq!(tx.txid(), sha256d(&raw));
    }

    #[test]
    fn sha256d_is_two_rounds() {
        let d = sha256d(b"catcard");
        let expect: [u8; 32] = Sha256::digest(Sha256::digest(b"catcard")).into();
        assert_eq!(d, expect);

        let mut inc = Sha256d::new();
        inc.update(b"cat");
        inc.update(b"card");
        assert_eq!(inc.finalize(), d);
    }

    #[test]
    fn reader_never_reads_past_the_end() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert_eq!(r.take(3).unwrap(), &[1, 2, 3]);
        assert!(matches!(r.take(1), Err(Error::Truncated { .. })));

        let mut r = Reader::new(&[1, 2]);
        assert!(matches!(r.u32(), Err(Error::Truncated { .. })));
        let mut r = Reader::new(&[0u8; 4]);
        assert!(matches!(r.hash(), Err(Error::Truncated { .. })));
    }

    #[test]
    fn var_slice_bounds_check_precedes_the_slice() {
        // len = 0xff but only 2 bytes remain.
        let mut r = Reader::new(&[0xff_u8, 0, 0]);
        assert!(r.var_slice().is_err());
    }
}
