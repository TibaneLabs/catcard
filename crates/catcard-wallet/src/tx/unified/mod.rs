//! The unified opt-in signature hash: one message for every input type.
//!
//! A spender opts in per signature by setting [`SIGHASH_UNIFIED`] (`0x20`) in the hash
//! type byte. The message that results is shaped like BIP-341's and replaces the legacy
//! and BIP-143 ones for that signature, which:
//!
//! - commits to **every** spent output's amount and scriptPubKey, closing CVE-2020-14199
//!   -- the defect that lets a host show a device a small fee and combine its signatures
//!   from two sessions into a transaction paying an enormous one;
//! - is linear in the number of inputs, closing CVE-2013-2292;
//! - and, being a message no other chain computes for that byte, cannot be replayed onto
//!   one that does not implement it.
//!
//! Source: `doc/unified-sighash.md` in Bitcoin Knots (status: draft), read as a
//! specification document; checked against its own 166 published vectors in the tests
//! below. It is **not** a BIP, and no BIP number exists for it [?].
//!
//! # Why this is behind `multichain`
//!
//! It is one fork's consensus rule, not Bitcoin's. A Bitcoin-only build carries none of
//! this code, exactly as it carries no other chain's; a multichain build can produce the
//! signature for someone who wants it. Nothing here changes what an existing signature
//! means: a transaction that does not set the bit is untouched, and this device never
//! sets it on its own.

use super::{Transaction, VarInt};
use crate::tx::Error;
use crate::tx::sighash::{SIGHASH_MASK, SIGHASH_NONE, SIGHASH_SINGLE};
use purecrypto::hash::{Digest, Sha256};

/// The opt-in bit. Set in the hash type byte, it selects this algorithm.
pub const SIGHASH_UNIFIED: u8 = 0x20;

/// The tag the message is hashed under, BIP-340 style.
const TAG: &[u8] = b"UnifiedSighash";

/// An output being spent: what the message commits to for every input, not just this one.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct SpentOutput<'a> {
    pub value: u64,
    pub script_pubkey: &'a [u8],
}

/// Which script type is being spent, and the tail that type carries.
///
/// The discriminant is the script type byte in the message: separating the four means a
/// signature made for one can never be valid for another.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Spend<'a> {
    /// Bare or P2SH. `script_code` is the scriptPubKey or the redeemScript, with the
    /// signature removed where the script contains it, as the legacy algorithm does.
    Legacy { script_code: &'a [u8] },
    /// Segwit v0. `script_code` is what BIP-143 uses: the witnessScript for P2WSH, and
    /// for P2WPKH the implied P2PKH script ([`super::sighash::p2wpkh_script_code`]).
    SegwitV0 { script_code: &'a [u8] },
    /// Taproot, key path.
    KeyPath { annex: Option<&'a [u8]> },
    /// Tapscript. The leaf hash is BIP-341's, and `codesep` is the position of the last
    /// executed `OP_CODESEPARATOR`, or `NO_CODESEPARATOR`.
    Tapscript {
        annex: Option<&'a [u8]>,
        tapleaf_hash: [u8; 32],
        codesep: u32,
    },
}

/// What `codesep` carries when no `OP_CODESEPARATOR` has executed.
pub const NO_CODESEPARATOR: u32 = 0xffff_ffff;

impl Spend<'_> {
    /// The script type byte this spend writes into the message.
    pub fn script_type(&self) -> u8 {
        match self {
            Spend::Legacy { .. } => 0,
            Spend::SegwitV0 { .. } => 1,
            Spend::KeyPath { .. } => 2,
            Spend::Tapscript { .. } => 3,
        }
    }
}

/// The five aggregates, each a **single** SHA-256 over every input or output.
///
/// Computed once per transaction and reused for each of its inputs, which is what makes
/// signing linear rather than quadratic.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Aggregates {
    pub prevouts: [u8; 32],
    pub amounts: [u8; 32],
    pub scripts: [u8; 32],
    pub sequences: [u8; 32],
    pub outputs: [u8; 32],
}

impl Aggregates {
    /// Compute them for `tx`, whose inputs spend `spent` in order.
    ///
    /// `spent` must have one entry per input: the message commits to all of them, and a
    /// short list would mean signing a claim about a transaction rather than about this
    /// one.
    pub fn compute(tx: &Transaction<'_>, spent: &[SpentOutput<'_>]) -> Result<Self, Error> {
        let mut prevouts = Sha256::new();
        let mut sequences = Sha256::new();
        let mut count = 0usize;
        for input in tx.inputs.iter() {
            let i = input?;
            prevouts.update(&i.previous_output.txid);
            prevouts.update(&i.previous_output.vout.to_le_bytes());
            sequences.update(&i.sequence.to_le_bytes());
            count += 1;
        }
        if spent.len() != count {
            return Err(Error::SpentOutputCount {
                inputs: count,
                given: spent.len(),
            });
        }

        let mut amounts = Sha256::new();
        let mut scripts = Sha256::new();
        for out in spent {
            amounts.update(&out.value.to_le_bytes());
            write_var_slice(&mut scripts, out.script_pubkey);
        }

        let mut outputs = Sha256::new();
        for output in tx.outputs.iter() {
            let o = output?;
            outputs.update(&o.value.to_le_bytes());
            write_var_slice(&mut outputs, o.script_pubkey);
        }

        Ok(Self {
            prevouts: finish(prevouts),
            amounts: finish(amounts),
            scripts: finish(scripts),
            sequences: finish(sequences),
            outputs: finish(outputs),
        })
    }
}

fn finish(h: Sha256) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

fn write_var_slice(h: &mut Sha256, data: &[u8]) {
    let mut buf = [0u8; 9];
    let n = VarInt::write(data.len() as u64, &mut buf).expect("9 bytes is enough");
    h.update(&buf[..n]);
    h.update(data);
}

/// The unified signature hash for one input.
///
/// `flag` is the whole hash type byte, [`SIGHASH_UNIFIED`] included: it is committed to,
/// so the byte signed and the byte written into the signature must be the same one. A
/// byte rather than [`super::sighash::SigHashFlag`], because the message has room for one
/// and a wider value would sign something other than what it declares.
///
/// Refuses `SIGHASH_SINGLE` with no output at this input's index, which the two algorithms
/// this replaces both allow -- one hashing the constant 1, the other a zero hash. Neither
/// is carried over, and neither was ever safe to sign.
pub fn unified(
    tx: &Transaction<'_>,
    aggregates: &Aggregates,
    input_index: usize,
    spent: &[SpentOutput<'_>],
    spend: Spend<'_>,
    flag: u8,
) -> Result<[u8; 32], Error> {
    let input = tx.inputs.get(input_index)?;
    let base = u32::from(flag) & SIGHASH_MASK;
    let anyone_can_pay = flag & 0x80 != 0;
    // `TaggedHash(tag, message)` is SHA256(SHA256(tag) || SHA256(tag) || message), and the
    // message is streamed into it rather than built in a buffer: it carries the whole
    // transaction's aggregates and a script, and this device has nowhere to put a copy.
    let tag = Sha256::digest(TAG);
    let mut m = Sha256::new();
    m.update(&tag);
    m.update(&tag);

    // The epoch is BIP-341's, kept so a later revision has the same room to move.
    m.update(&[0]);
    m.update(&[flag]);
    m.update(&(tx.version as u32).to_le_bytes());
    // Five bytes, not four: the field is widened here so a later hardfork that widens it
    // in a transaction need not invalidate every signature made under this message.
    m.update(&tx.lock_time.to_le_bytes());
    m.update(&[0]);

    if !anyone_can_pay {
        m.update(&aggregates.prevouts);
        m.update(&aggregates.amounts);
        m.update(&aggregates.scripts);
        m.update(&aggregates.sequences);
    }
    // Every value that is not NONE or SINGLE signs all the outputs, as the legacy
    // algorithm does -- reachable for script types 0 and 1, the two that take any byte.
    if base != SIGHASH_NONE && base != SIGHASH_SINGLE {
        m.update(&aggregates.outputs);
    }

    m.update(&[spend.script_type()]);

    if anyone_can_pay {
        // Without the aggregates, this input carries its own outpoint, what it spends and
        // its sequence, so the input stays bound to those while its position does not.
        let mine = spent.get(input_index).ok_or(Error::SpentOutputCount {
            inputs: input_index + 1,
            given: spent.len(),
        })?;
        m.update(&input.previous_output.txid);
        m.update(&input.previous_output.vout.to_le_bytes());
        m.update(&mine.value.to_le_bytes());
        write_var_slice(&mut m, mine.script_pubkey);
        m.update(&input.sequence.to_le_bytes());
    } else {
        m.update(&(input_index as u32).to_le_bytes());
    }

    match spend {
        Spend::Legacy { script_code } | Spend::SegwitV0 { script_code } => {
            write_var_slice(&mut m, script_code);
        }
        Spend::KeyPath { annex } | Spend::Tapscript { annex, .. } => {
            m.update(&[u8::from(annex.is_some())]);
            if let Some(annex) = annex {
                let mut h = Sha256::new();
                write_var_slice(&mut h, annex);
                m.update(&finish(h));
            }
        }
    }

    if base == SIGHASH_SINGLE {
        let out = tx
            .outputs
            .get(input_index)
            .ok_or(Error::SingleWithoutOutput { index: input_index })??;
        let mut h = Sha256::new();
        h.update(&out.value.to_le_bytes());
        write_var_slice(&mut h, out.script_pubkey);
        m.update(&finish(h));
    }

    if let Spend::Tapscript {
        tapleaf_hash,
        codesep,
        ..
    } = spend
    {
        m.update(&tapleaf_hash);
        // Key version 0: BIP-341's, and the only one defined.
        m.update(&[0]);
        m.update(&codesep.to_le_bytes());
    }

    Ok(finish(m))
}

#[cfg(test)]
mod tests;
