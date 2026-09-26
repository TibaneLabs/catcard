//! Recognising a *proof of reserves* PSBT before it is signed, and the checks that make
//! signing one safe.
//!
//! A proof of reserves arrives as an ordinary PSBT: BIP-322's `to_sign` with the
//! wallet's real outputs added as inputs 1..N, ready for a signer. Reviewed as a spend it
//! would look like the worst transaction imaginable -- every coin in, nothing but an
//! `OP_RETURN` out, the whole balance to fees -- and be refused. Reviewed as what it is,
//! it moves nothing: input 0 spends `to_spend`, `to_spend` spends an output that does not
//! exist, and every signature is `SIGHASH_ALL` over that input. Drop input 0 and every
//! signature dies with it.
//!
//! That argument is only as good as its premises, so this module checks them and nothing
//! signs a proof without it:
//!
//! - **The shape.** Exactly one output, worth nothing, paying `OP_RETURN` and nothing
//!   after it. An output that pays anyone is a spend, however the rest looks.
//! - **Input 0 is `to_spend`.** Its txid is recomputed from the message the owner
//!   confirmed and the challenge script the PSBT carries, and has to equal the outpoint.
//!   A host cannot substitute a real outpoint there: the recomputed txid is of a
//!   transaction whose only input is the null outpoint, which no chain can hold.
//! - **`SIGHASH_ALL` on every input**, whatever the sighash policy says elsewhere. Under
//!   `ANYONECANPAY` a signature would not commit to input 0, and the proof would become
//!   a real transaction burning the coins to fees.
//! - **Every input has its spent output**, so the total can be stated, and no more than
//!   [`MAX_POF_INPUTS`] of them.
//!
//! Source: BIP-322 §Full (Proof of Funds) for the construction [C]; the safety argument
//! is the BIP's own, spelled out.

use super::full::MAX_POF_INPUTS;
use super::{MAX_SCRIPT, OP_RETURN, SIGHASH_ALL, message_hash, to_spend_txid_of};
use crate::tx::Reader;
use outscript::psbt::Psbt;

/// What a proof of reserves PSBT says about itself, before any of it is signed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Proof {
    challenge: [u8; MAX_SCRIPT],
    challenge_len: usize,
    /// The message hash `to_spend` commits to, when the PSBT carried `to_spend` itself as
    /// input 0's previous transaction. Absent with a witness UTXO alone; the outpoint
    /// check in [`confirm_message`] settles the message either way.
    pub message_hash: Option<[u8; 32]>,
    /// Input 0's outpoint txid, in display order: what `to_spend` has to hash to.
    pub to_spend_txid: [u8; 32],
    /// Inputs in all, `to_spend`'s included.
    pub inputs: usize,
    /// The real outputs being proven: every input but the first.
    pub utxos: usize,
    /// Their total, in satoshis.
    pub total: u64,
}

impl Proof {
    /// The scriptPubKey the message is signed for: the address the proof speaks for.
    pub fn challenge(&self) -> &[u8] {
        &self.challenge[..self.challenge_len]
    }
}

/// Why a PSBT that looks like a proof will not be signed as one.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// Not the shape of a proof at all: this is a spend, and gets the spend review.
    NotAProof,
    /// Input 0's previous transaction is not a `to_spend`.
    BadToSpend,
    /// More than [`MAX_POF_INPUTS`].
    TooManyInputs { inputs: usize },
    /// An input without the output it spends: nothing says what is being proven.
    MissingUtxo { input: usize },
    /// An input asking for a sighash type other than `SIGHASH_ALL`. Never signed in a
    /// proof, under any policy: see the module note.
    Sighash { input: usize, kind: u32 },
    /// The message the owner gave is not the one `to_spend` commits to.
    WrongMessage,
    /// Already finalised; nothing to sign.
    AlreadyFinal,
}

/// Does this PSBT have the shape of a proof of reserves?
///
/// The cheap test the signing screen asks before deciding which review to run: one
/// output, worth nothing, paying `OP_RETURN`; and input 0 spending output 0 of something
/// worth nothing. A transaction meeting that is no spend anyone could want, so handing
/// it to the proof review costs a real spend nothing -- and [`inspect`] then says
/// whether it really is a proof.
pub fn is_proof(psbt: &Psbt<'_>) -> bool {
    let tx = psbt.unsigned_tx();
    if tx.input_count() == 0 || tx.output_count() != 1 {
        return false;
    }
    let Some(out) = tx.outputs().next() else {
        return false;
    };
    if out.amount != 0 || out.script != &OP_RETURN[..] {
        return false;
    }
    let Some(first) = tx.inputs().next() else {
        return false;
    };
    first.vout == 0 && psbt.utxo(0).is_ok_and(|u| u.amount == 0)
}

/// Read the proof out of a PSBT, or say why it is not one.
///
/// Everything but the message is settled here: the challenge script, the total, the
/// sighash types. The message is the owner's to supply, and [`confirm_message`] closes
/// the loop.
pub fn inspect(psbt: &Psbt<'_>) -> Result<Proof, Refusal> {
    if !is_proof(psbt) {
        return Err(Refusal::NotAProof);
    }
    if psbt.is_finalized() {
        return Err(Refusal::AlreadyFinal);
    }
    let tx = psbt.unsigned_tx();
    let inputs = tx.input_count();
    if inputs > MAX_POF_INPUTS {
        return Err(Refusal::TooManyInputs { inputs });
    }
    let first = tx.inputs().next().ok_or(Refusal::NotAProof)?;
    let spent = psbt
        .utxo(0)
        .map_err(|_| Refusal::MissingUtxo { input: 0 })?;
    if spent.script.len() > MAX_SCRIPT {
        return Err(Refusal::NotAProof);
    }
    let mut challenge = [0u8; MAX_SCRIPT];
    challenge[..spent.script.len()].copy_from_slice(spent.script);

    // When `to_spend` itself is here, read it: it has to be one, and its output has to
    // be the challenge `utxo` just returned (which it is, since `utxo` read it from the
    // same bytes -- but the version, lock time and input are what make it unspendable,
    // and those are checked).
    let message_hash = match psbt.input(0).and_then(|i| i.non_witness_utxo()) {
        Some(prev) => {
            let (hash, out_script) = parse_to_spend(prev).ok_or(Refusal::BadToSpend)?;
            if out_script != spent.script {
                return Err(Refusal::BadToSpend);
            }
            Some(hash)
        }
        None => None,
    };

    let mut total = 0u64;
    for index in 0..inputs {
        let inp = psbt
            .input(index)
            .ok_or(Refusal::MissingUtxo { input: index })?;
        match inp.sighash_type() {
            None => {}
            Some(kind) if kind == SIGHASH_ALL => {}
            Some(kind) => return Err(Refusal::Sighash { input: index, kind }),
        }
        if index == 0 {
            continue;
        }
        let utxo = psbt
            .utxo(index)
            .map_err(|_| Refusal::MissingUtxo { input: index })?;
        total = total.saturating_add(utxo.amount);
    }
    Ok(Proof {
        challenge,
        challenge_len: spent.script.len(),
        message_hash,
        to_spend_txid: first.txid,
        inputs,
        utxos: inputs - 1,
        total,
    })
}

/// Is `message` the message this proof is of?
///
/// The definitive check: `to_spend` is rebuilt from the message and the challenge, and
/// its txid has to be input 0's outpoint. Nothing the PSBT says about the message is
/// taken on trust -- a carried `to_spend` is checked the same way, since a host could
/// write any hash into one.
pub fn confirm_message(proof: &Proof, message: &[u8]) -> Result<(), Refusal> {
    let hash = message_hash(message);
    if proof.message_hash.is_some_and(|h| h != hash) {
        return Err(Refusal::WrongMessage);
    }
    if to_spend_txid_of(&hash, proof.challenge()) != proof.to_spend_txid {
        return Err(Refusal::WrongMessage);
    }
    Ok(())
}

/// Read a serialised `to_spend`: version 0, lock time 0, one input spending the null
/// outpoint with sequence 0 and `OP_0 PUSH32 <hash>` as its scriptSig, one output worth
/// nothing. Returns the hash and the output's script.
///
/// Source: BIP-322 §Full [C]
pub fn parse_to_spend(bytes: &[u8]) -> Option<([u8; 32], &[u8])> {
    let mut r = Reader::new(bytes);
    if r.u32().ok()? != 0 {
        return None;
    }
    if r.varint().ok()? != 1 {
        return None;
    }
    if r.hash().ok()? != [0u8; 32] || r.u32().ok()? != 0xFFFF_FFFF {
        return None;
    }
    let script_sig = r.var_slice().ok()?;
    let [0x00, 0x20, hash @ ..] = script_sig else {
        return None;
    };
    let hash: [u8; 32] = hash.try_into().ok()?;
    if r.u32().ok()? != 0 {
        return None;
    }
    if r.varint().ok()? != 1 {
        return None;
    }
    if r.u64().ok()? != 0 {
        return None;
    }
    let script = r.var_slice().ok()?;
    if r.u32().ok()? != 0 || r.remaining() != 0 {
        return None;
    }
    Some((hash, script))
}

/// Serialise the `to_spend` of `message` for `challenge` into `out`: what a host puts on
/// input 0 as the previous transaction, and what the tests build proofs from.
pub fn write_to_spend(
    message: &[u8],
    challenge: &[u8],
    out: &mut [u8],
) -> Result<usize, super::Error> {
    use outscript::btcraw::{RawTx, RawTxIn, RawTxOut};
    let mut script_sig = [0u8; 34];
    script_sig[0] = 0x00;
    script_sig[1] = 0x20;
    script_sig[2..].copy_from_slice(&message_hash(message));
    let inputs = [RawTxIn {
        txid: [0u8; 32],
        vout: 0xFFFF_FFFF,
        script_sig: &script_sig,
        sequence: 0,
        witness: &[],
    }];
    let outputs = [RawTxOut {
        amount: 0,
        script: challenge,
    }];
    RawTx {
        version: 0,
        inputs: &inputs,
        outputs: &outputs,
        locktime: 0,
    }
    .serialize_to_slice(out)
    .map_err(|_| super::Error::BufferTooSmall)
}

#[cfg(test)]
mod tests;
