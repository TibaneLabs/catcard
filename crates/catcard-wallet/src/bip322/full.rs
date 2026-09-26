//! The *full* and *proof of funds* variants: a whole `to_sign` transaction, and the
//! hashing engine every variant shares.
//!
//! A *full* signature is `to_sign` itself, consensus-encoded with its witness, behind the
//! prefix `ful`. It exists for two reasons the *simple* form cannot meet: a P2SH-wrapped
//! address needs a `scriptSig` (the push of its redeem script), and a signer may set a
//! version, sequence or lock time of its own. A *proof of funds* is the finalised PSBT of
//! a `to_sign` that spends real outputs as additional inputs, behind the prefix `pof`: the
//! signatures on those inputs prove the coins are controlled, and the PSBT carries the
//! outputs they spend so a verifier can check them without a chain of its own.
//!
//! Source: BIP-322 §Full, §Full (Proof of Funds), §Types of Signatures [C].
//!
//! # One engine, three transaction shapes
//!
//! Everything here hashes a transaction it did not build: the fixed `to_sign` of a simple
//! signature, a `to_sign` read off a file, or a PSBT's unsigned transaction with its
//! finalised inputs. [`TxView`] is the shape they share -- version, lock time, inputs with
//! their `scriptSig` and witness, outputs -- and [`Prevouts`] is where the spent outputs
//! come from. [`segwit_v0`] and [`taproot`] stream BIP-143 and BIP-341 over those two, so
//! a proof of reserves with sixty inputs costs no array of sixty anything. `outscript`
//! computes the same digests from an in-memory transaction; the tests compare the two.
//!
//! # Why the `to_sign` of a proof cannot move a coin
//!
//! Its first input spends `to_spend`, and `to_spend` spends output `0xFFFFFFFF` of the
//! null txid, which does not exist. Every signature over `to_sign` is `SIGHASH_ALL`, so
//! each one commits to that first input; drop it and every signature is void. That is
//! the whole safety argument, and it is why [`verify_pof`] and [`super::por`] both insist
//! on `SIGHASH_ALL` and recompute the `to_spend` txid from the message rather than take
//! the PSBT's word for it.

use super::{
    Error, MAX_SCRIPT, MAX_SIG, OP_RETURN, SIGHASH_ALL, Variant, armour_with, check_input,
    classify, decode_witness, ecdsa_sig, parse_multisig, to_spend_txid,
};
use crate::KeyWork;
use crate::address::{self, AddressKind};
use crate::bip32::{ChildNumber, ExtendedPrivKey, HARDENED_OFFSET, hash160};
use crate::multisig::{self, MAX_COSIGNERS, Multisig};
use crate::tx::{Reader, Sha256d, VarInt};
use outscript::btcraw::{RawTx, RawTxIn, RawTxOut};
use outscript::crypto::secp256k1::{SecpPrivateKey, SecpPublicKey};
use outscript::psbt::Psbt;
use purecrypto::hash::{Digest as _, Sha256};

/// Most inputs a proof of funds may have. The same figure the signing screen reads in
/// one pass; past it the answer is [`Error::TooManyInputs`] rather than a longer walk.
pub const MAX_POF_INPUTS: usize = 64;

/// Longest `to_sign` a single-key *full* signature serialises to: version, the segwit
/// marker, one input with a nested-P2WPKH `scriptSig`, one `OP_RETURN` output, a
/// two-item witness and the lock time.
pub const MAX_SINGLE_TX: usize =
    4 + 2 + 1 + (32 + 4 + 1 + 23 + 4) + 1 + (8 + 1 + 1) + (1 + 1 + MAX_SIG + 1 + 33) + 4;

/// Longest `to_sign` a multisig *full* signature serialises to: a nested-P2WSH
/// `scriptSig`, and a witness of the dummy, fifteen signatures and the script.
pub const MAX_MULTISIG_TX: usize = 4
    + 2
    + 1
    + (32 + 4 + 1 + 35 + 4)
    + 1
    + (8 + 1 + 1)
    + (1 + 1 + MAX_COSIGNERS * (1 + MAX_SIG) + 3 + multisig::MAX_SCRIPT)
    + 4;

/// Base64 of [`MAX_SINGLE_TX`], plus the prefix.
pub const MAX_FULL_ARMOURED: usize = 3 + MAX_SINGLE_TX.div_ceil(3) * 4;

/// Base64 of [`MAX_MULTISIG_TX`], plus the prefix.
pub const MAX_MULTISIG_ARMOURED: usize = 3 + MAX_MULTISIG_TX.div_ceil(3) * 4;

/// Longest `to_sign` one cosigner's partial signature serialises to: as
/// [`MAX_MULTISIG_TX`] with a single signature in the witness. What a device holding one
/// key of a wallet writes.
pub const MAX_PARTIAL_TX: usize = MAX_MULTISIG_TX - (MAX_COSIGNERS - 1) * (1 + MAX_SIG);

/// Base64 of [`MAX_PARTIAL_TX`], plus the prefix.
pub const MAX_PARTIAL_ARMOURED: usize = 3 + MAX_PARTIAL_TX.div_ceil(3) * 4;

/// One input of a transaction, as the engine reads it.
#[derive(Copy, Clone, Debug)]
pub struct InView<'a> {
    /// The spent txid in display byte order -- the order [`super::to_spend_txid`] gives.
    pub txid: [u8; 32],
    pub vout: u32,
    pub sequence: u32,
    pub script_sig: &'a [u8],
    /// The witness stack, consensus-encoded; empty when the input has none.
    pub witness: &'a [u8],
}

/// A transaction the engine can hash, whatever it was parsed from.
pub trait TxView<'a> {
    fn version(&self) -> u32;
    fn locktime(&self) -> u32;
    fn input_count(&self) -> usize;
    fn input(&self, index: usize) -> Option<InView<'a>>;
    fn output_count(&self) -> usize;
    /// The amount and scriptPubKey of output `index`.
    fn output(&self, index: usize) -> Option<(u64, &'a [u8])>;
}

/// Where the outputs a transaction spends come from.
pub trait Prevouts<'a> {
    /// The amount and scriptPubKey input `index` spends, or nothing known.
    fn prevout(&self, index: usize) -> Option<(u64, &'a [u8])>;
}

/// Which signature hash an input's script needs.
pub enum Sighash<'a> {
    /// BIP-143, `SIGHASH_ALL`, over `script_code`: the implied P2PKH script for P2WPKH,
    /// the witness script for P2WSH.
    SegwitV0 { script_code: &'a [u8] },
    /// BIP-341 key path, with `hash_type` `0x00` (`SIGHASH_DEFAULT`) or `0x01`.
    Taproot { hash_type: u8 },
}

/// A source of signature hashes for one input.
pub trait Digests {
    fn digest(&self, which: Sighash<'_>) -> Result<[u8; 32], Error>;
}

/// The digests of input `index` of a transaction, over its spent outputs.
pub struct Engine<'e, 'a, T: TxView<'a>, P: Prevouts<'a>> {
    tx: &'e T,
    prevouts: &'e P,
    index: usize,
    _life: core::marker::PhantomData<&'a ()>,
}

impl<'e, 'a, T: TxView<'a>, P: Prevouts<'a>> Engine<'e, 'a, T, P> {
    pub fn new(tx: &'e T, prevouts: &'e P, index: usize) -> Self {
        Self {
            tx,
            prevouts,
            index,
            _life: core::marker::PhantomData,
        }
    }
}

impl<'a, T: TxView<'a>, P: Prevouts<'a>> Digests for Engine<'_, 'a, T, P> {
    fn digest(&self, which: Sighash<'_>) -> Result<[u8; 32], Error> {
        match which {
            Sighash::SegwitV0 { script_code } => {
                segwit_v0(self.tx, self.prevouts, self.index, script_code)
            }
            Sighash::Taproot { hash_type } => {
                taproot(self.tx, self.prevouts, self.index, hash_type)
            }
        }
    }
}

/// Feed a compact-size and the bytes it counts to a hash.
fn put_var<H: FnMut(&[u8])>(h: &mut H, bytes: &[u8]) {
    let mut len = [0u8; 9];
    let n = VarInt::write(bytes.len() as u64, &mut len).unwrap_or(0);
    h(&len[..n]);
    h(bytes);
}

/// The BIP-143 digest of input `index` under `SIGHASH_ALL`.
///
/// Streams the three midstates over the view -- no input array -- and then the preimage.
/// Source: BIP-143 §Specification [C]
pub fn segwit_v0<'a>(
    tx: &dyn TxView<'a>,
    prevouts: &dyn Prevouts<'a>,
    index: usize,
    script_code: &[u8],
) -> Result<[u8; 32], Error> {
    let mut hash_prevouts = Sha256d::new();
    let mut hash_sequence = Sha256d::new();
    for i in 0..tx.input_count() {
        let inp = tx.input(i).ok_or(Error::Malformed)?;
        let mut wire = inp.txid;
        wire.reverse();
        hash_prevouts.update(&wire);
        hash_prevouts.update(&inp.vout.to_le_bytes());
        hash_sequence.update(&inp.sequence.to_le_bytes());
    }
    let mut hash_outputs = Sha256d::new();
    for j in 0..tx.output_count() {
        let (amount, script) = tx.output(j).ok_or(Error::Malformed)?;
        hash_outputs.update(&amount.to_le_bytes());
        put_var(&mut |b| hash_outputs.update(b), script);
    }
    let inp = tx.input(index).ok_or(Error::Malformed)?;
    let (amount, _) = prevouts.prevout(index).ok_or(Error::MissingUtxo)?;
    let mut wire = inp.txid;
    wire.reverse();

    let mut h = Sha256d::new();
    h.update(&tx.version().to_le_bytes());
    h.update(&hash_prevouts.finalize());
    h.update(&hash_sequence.finalize());
    h.update(&wire);
    h.update(&inp.vout.to_le_bytes());
    put_var(&mut |b| h.update(b), script_code);
    h.update(&amount.to_le_bytes());
    h.update(&inp.sequence.to_le_bytes());
    h.update(&hash_outputs.finalize());
    h.update(&tx.locktime().to_le_bytes());
    h.update(&SIGHASH_ALL.to_le_bytes());
    Ok(h.finalize())
}

/// The BIP-341 key-path digest of input `index`, no annex, under `hash_type` `0x00` or
/// `0x01` -- the two BIP-322 admits, both of which commit to every input and output.
///
/// Source: BIP-341 §Common Signature Message [C]
pub fn taproot<'a>(
    tx: &dyn TxView<'a>,
    prevouts: &dyn Prevouts<'a>,
    index: usize,
    hash_type: u8,
) -> Result<[u8; 32], Error> {
    if hash_type > 0x01 {
        return Err(Error::Invalid);
    }
    let mut sha_prevouts = Sha256::new();
    let mut sha_amounts = Sha256::new();
    let mut sha_scripts = Sha256::new();
    let mut sha_sequences = Sha256::new();
    for i in 0..tx.input_count() {
        let inp = tx.input(i).ok_or(Error::Malformed)?;
        let (amount, script) = prevouts.prevout(i).ok_or(Error::MissingUtxo)?;
        let mut wire = inp.txid;
        wire.reverse();
        sha_prevouts.update(&wire);
        sha_prevouts.update(&inp.vout.to_le_bytes());
        sha_amounts.update(&amount.to_le_bytes());
        put_var(&mut |b| sha_scripts.update(b), script);
        sha_sequences.update(&inp.sequence.to_le_bytes());
    }
    let mut sha_outputs = Sha256::new();
    for j in 0..tx.output_count() {
        let (amount, script) = tx.output(j).ok_or(Error::Malformed)?;
        sha_outputs.update(&amount.to_le_bytes());
        put_var(&mut |b| sha_outputs.update(b), script);
    }
    if index >= tx.input_count() {
        return Err(Error::Malformed);
    }

    // `tagged_hash("TapSighash", 0x00 || SigMsg)`, streamed: the tag digest twice, then
    // the epoch and the message fields in BIP-341's order.
    let tag = Sha256::digest(b"TapSighash");
    let mut h = Sha256::new();
    h.update(&tag);
    h.update(&tag);
    h.update(&[0x00, hash_type]);
    h.update(&tx.version().to_le_bytes());
    h.update(&tx.locktime().to_le_bytes());
    h.update(&sha_prevouts.finalize());
    h.update(&sha_amounts.finalize());
    h.update(&sha_scripts.finalize());
    h.update(&sha_sequences.finalize());
    h.update(&sha_outputs.finalize());
    // spend_type: key path (ext_flag 0), no annex.
    h.update(&[0x00]);
    h.update(&(index as u32).to_le_bytes());
    Ok(h.finalize())
}

/// A consensus-encoded transaction, read strictly, and the offsets its parts sit at.
///
/// Inputs, outputs and witness stacks are re-read on demand rather than stored, which is
/// what keeps this free of arrays: a stack item is found by walking the stacks before it.
/// The whole thing is validated once, at [`parse`](Self::parse), so a later walk cannot
/// run off the end.
pub struct ToSignBytes<'a> {
    bytes: &'a [u8],
    version: u32,
    locktime: u32,
    n_in: usize,
    n_out: usize,
    inputs_at: usize,
    outputs_at: usize,
    witness_at: Option<usize>,
}

impl<'a> ToSignBytes<'a> {
    /// Parse `bytes` as a transaction with at most [`MAX_POF_INPUTS`] inputs, refusing a
    /// trailing byte, a non-canonical length, or a witness stack too long to be one this
    /// checks.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let bad = |_| Error::Malformed;
        let mut r = Reader::new(bytes);
        let version = r.u32().map_err(bad)?;
        let segwit = matches!(r.peek(2), Some([0x00, 0x01]));
        if segwit {
            r.take(2).map_err(bad)?;
        }
        let n_in = r.varint().map_err(bad)?;
        if n_in == 0 {
            return Err(Error::Malformed);
        }
        if n_in > MAX_POF_INPUTS as u64 {
            return Err(Error::TooManyInputs);
        }
        let n_in = n_in as usize;
        let inputs_at = r.position();
        for _ in 0..n_in {
            r.take(36).map_err(bad)?;
            r.var_slice().map_err(bad)?;
            r.u32().map_err(bad)?;
        }
        let n_out = r.varint().map_err(bad)?;
        if n_out == 0 || n_out > MAX_POF_INPUTS as u64 {
            return Err(Error::Malformed);
        }
        let n_out = n_out as usize;
        let outputs_at = r.position();
        for _ in 0..n_out {
            r.u64().map_err(bad)?;
            r.var_slice().map_err(bad)?;
        }
        let witness_at = if segwit {
            let at = r.position();
            for _ in 0..n_in {
                let items = r.varint().map_err(bad)?;
                if items > super::MAX_WITNESS_ITEMS as u64 {
                    return Err(Error::Malformed);
                }
                for _ in 0..items {
                    r.var_slice().map_err(bad)?;
                }
            }
            Some(at)
        } else {
            None
        };
        let locktime = r.u32().map_err(bad)?;
        if r.remaining() != 0 {
            return Err(Error::Malformed);
        }
        Ok(Self {
            bytes,
            version,
            locktime,
            n_in,
            n_out,
            inputs_at,
            outputs_at,
            witness_at,
        })
    }

    /// The byte range of input `index`'s witness stack. `parse` walked every stack, so
    /// the reads here cannot fail; a `None` is a bug rather than a case.
    fn witness_range(&self, index: usize) -> Option<(usize, usize)> {
        let start = self.witness_at?;
        let mut r = Reader::new(self.bytes);
        r.take(start).ok()?;
        for _ in 0..index {
            let items = r.varint().ok()? as usize;
            for _ in 0..items {
                r.var_slice().ok()?;
            }
        }
        let from = r.position();
        let items = r.varint().ok()? as usize;
        for _ in 0..items {
            r.var_slice().ok()?;
        }
        Some((from, r.position()))
    }
}

impl<'a> TxView<'a> for ToSignBytes<'a> {
    fn version(&self) -> u32 {
        self.version
    }
    fn locktime(&self) -> u32 {
        self.locktime
    }
    fn input_count(&self) -> usize {
        self.n_in
    }
    fn input(&self, index: usize) -> Option<InView<'a>> {
        if index >= self.n_in {
            return None;
        }
        let mut r = Reader::new(self.bytes);
        r.take(self.inputs_at).ok()?;
        for _ in 0..index {
            r.take(36).ok()?;
            r.var_slice().ok()?;
            r.u32().ok()?;
        }
        let mut txid = r.hash().ok()?;
        txid.reverse();
        let vout = r.u32().ok()?;
        let script_sig = r.var_slice().ok()?;
        let sequence = r.u32().ok()?;
        let witness = match self.witness_range(index) {
            Some((from, to)) => &self.bytes[from..to],
            None => &[],
        };
        Some(InView {
            txid,
            vout,
            sequence,
            script_sig,
            witness,
        })
    }
    fn output_count(&self) -> usize {
        self.n_out
    }
    fn output(&self, index: usize) -> Option<(u64, &'a [u8])> {
        if index >= self.n_out {
            return None;
        }
        let mut r = Reader::new(self.bytes);
        r.take(self.outputs_at).ok()?;
        for _ in 0..index {
            r.u64().ok()?;
            r.var_slice().ok()?;
        }
        let amount = r.u64().ok()?;
        let script = r.var_slice().ok()?;
        Some((amount, script))
    }
}

/// The one spent output a *full* signature has: `to_spend`'s, worth nothing.
struct SoleChallenge<'a>(&'a [u8]);

impl<'a> Prevouts<'a> for SoleChallenge<'a> {
    fn prevout(&self, index: usize) -> Option<(u64, &'a [u8])> {
        (index == 0).then_some((0, self.0))
    }
}

/// A finalised PSBT as the engine reads it: the unsigned transaction's fields, with each
/// input's final `scriptSig` and witness.
pub struct PsbtTx<'a> {
    psbt: Psbt<'a>,
}

impl<'a> PsbtTx<'a> {
    pub fn new(psbt: Psbt<'a>) -> Self {
        Self { psbt }
    }
}

impl<'a> TxView<'a> for PsbtTx<'a> {
    fn version(&self) -> u32 {
        self.psbt.unsigned_tx().version()
    }
    fn locktime(&self) -> u32 {
        self.psbt.unsigned_tx().locktime()
    }
    fn input_count(&self) -> usize {
        self.psbt.unsigned_tx().input_count()
    }
    fn input(&self, index: usize) -> Option<InView<'a>> {
        let raw = self.psbt.unsigned_tx().inputs().nth(index)?;
        let map = self.psbt.input(index)?;
        Some(InView {
            txid: raw.txid,
            vout: raw.vout,
            sequence: raw.sequence,
            script_sig: map.final_script_sig().unwrap_or(&[]),
            witness: map.final_script_witness().unwrap_or(&[]),
        })
    }
    fn output_count(&self) -> usize {
        self.psbt.unsigned_tx().output_count()
    }
    fn output(&self, index: usize) -> Option<(u64, &'a [u8])> {
        let out = self.psbt.unsigned_tx().outputs().nth(index)?;
        Some((out.amount, out.script))
    }
}

/// The outputs a proof of funds spends: `to_spend`'s for input 0, and for the rest
/// whatever the PSBT carries -- a previous transaction checked against the outpoint, or
/// a witness UTXO.
pub struct PsbtPrevouts<'a> {
    psbt: Psbt<'a>,
    challenge: &'a [u8],
}

impl<'a> Prevouts<'a> for PsbtPrevouts<'a> {
    fn prevout(&self, index: usize) -> Option<(u64, &'a [u8])> {
        if index == 0 {
            return Some((0, self.challenge));
        }
        let out = self.psbt.utxo(index).ok()?;
        Some((out.amount, out.script))
    }
}

/// A *full* signature: `to_sign`, consensus-encoded with its witness.
///
/// `N` is the buffer: [`MAX_SINGLE_TX`] for a single key, [`MAX_MULTISIG_TX`] for a
/// cosigner's partial signature or a merged one.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Full<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> Full<N> {
    /// The consensus encoding, which is what the base64 of a *full* signature holds.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// The signature as it is written into a file: `ful` and then base64.
    pub fn armour(&self, out: &mut [u8]) -> Result<usize, Error> {
        armour_with(super::PREFIX_FULL, self.as_bytes(), out)
    }
}

/// Serialise a default `to_sign` -- version 0, sequence 0, lock time 0 -- spending
/// `to_spend` with `script_sig` and `witness`, into `out`.
pub fn write_to_sign(
    to_spend: &[u8; 32],
    script_sig: &[u8],
    witness: &[&[u8]],
    out: &mut [u8],
) -> Result<usize, Error> {
    write_to_sign_with(0, to_spend, 0, script_sig, witness, 0, out)
}

/// Serialise a `to_sign` with the given version, sequence and lock time.
pub fn write_to_sign_with(
    version: u32,
    to_spend: &[u8; 32],
    sequence: u32,
    script_sig: &[u8],
    witness: &[&[u8]],
    locktime: u32,
    out: &mut [u8],
) -> Result<usize, Error> {
    let inputs = [RawTxIn {
        txid: *to_spend,
        vout: 0,
        script_sig,
        sequence,
        witness,
    }];
    let outputs = [RawTxOut {
        amount: 0,
        script: &OP_RETURN,
    }];
    RawTx {
        version,
        inputs: &inputs,
        outputs: &outputs,
        locktime,
    }
    .serialize_to_slice(out)
    .map_err(|_| Error::BufferTooSmall)
}

/// The scriptPubKey an address of `kind` for `pubkey` pays to, for the *full* variant:
/// every kind but P2PKH, which has [`crate::message`] and nothing to gain from a
/// transaction around it.
pub fn challenge(kind: AddressKind, pubkey: &[u8; 33], out: &mut [u8]) -> Result<usize, Error> {
    if kind == AddressKind::P2pkh {
        return Err(Error::UnsupportedKind);
    }
    address::script_pubkey(kind, pubkey, out).map_err(|_| Error::BadKey)
}

/// Sign `message` for the address of `kind` behind `secret`, in the *full* variant.
///
/// Deterministic, as [`super::sign`] is. The `to_sign` is the default one -- version 0,
/// sequence 0, lock time 0 -- with the P2SH push in its `scriptSig` where the address
/// needs one.
pub fn sign_full(
    message: &[u8],
    secret: &[u8; 32],
    kind: AddressKind,
    _kw: &KeyWork,
) -> Result<Full<MAX_SINGLE_TX>, Error> {
    let key = SecpPrivateKey::from_bytes(secret).map_err(|_| Error::BadKey)?;
    let pubkey = key.public_key().serialize_compressed();
    let mut script = [0u8; MAX_SCRIPT];
    let n = challenge(kind, &pubkey, &mut script)?;
    let script = &script[..n];
    let prev = to_spend_txid(message, script);
    let tx = ToSignFixed::new(prev);
    let sole = SoleChallenge(script);
    let engine = Engine::new(&tx, &sole, 0);

    let mut buf = [0u8; MAX_SINGLE_TX];
    let len = match kind {
        AddressKind::P2wpkh | AddressKind::P2shP2wpkh => {
            let key_hash = hash160(&pubkey);
            let code = crate::tx::sighash::p2wpkh_script_code(&key_hash);
            let sighash = engine.digest(Sighash::SegwitV0 { script_code: &code })?;
            let sig = ecdsa_sig(&key, &sighash)?;
            // Nested: the scriptSig is one push of the redeem script.
            let mut script_sig = [0u8; 23];
            let script_sig: &[u8] = if kind == AddressKind::P2shP2wpkh {
                script_sig[0] = 22;
                script_sig[1..].copy_from_slice(&address::p2wpkh_redeem_script(&pubkey));
                &script_sig
            } else {
                &[]
            };
            write_to_sign(&prev, script_sig, &[sig.as_bytes(), &pubkey], &mut buf)?
        }
        AddressKind::P2tr => {
            let sighash = engine.digest(Sighash::Taproot { hash_type: 0x00 })?;
            let sig = key.sign_taproot(&sighash).map_err(|_| Error::BadKey)?;
            write_to_sign(&prev, &[], &[&sig], &mut buf)?
        }
        AddressKind::P2pkh => return Err(Error::UnsupportedKind),
    };
    Ok(Full { buf, len })
}

/// The default `to_sign` before its witness, as the engine sees it while signing.
struct ToSignFixed {
    prev: [u8; 32],
}

impl ToSignFixed {
    fn new(prev: [u8; 32]) -> Self {
        Self { prev }
    }
}

impl<'a> TxView<'a> for ToSignFixed {
    fn version(&self) -> u32 {
        0
    }
    fn locktime(&self) -> u32 {
        0
    }
    fn input_count(&self) -> usize {
        1
    }
    fn input(&self, index: usize) -> Option<InView<'a>> {
        (index == 0).then_some(InView {
            txid: self.prev,
            vout: 0,
            sequence: 0,
            script_sig: &[],
            witness: &[],
        })
    }
    fn output_count(&self) -> usize {
        1
    }
    fn output(&self, index: usize) -> Option<(u64, &'a [u8])> {
        (index == 0).then_some((0, &OP_RETURN[..]))
    }
}

/// The scriptPubKey and `scriptSig` a multisig script of `kind` signs under.
///
/// `sh(multi)` is not here: BIP-322 does not forbid it, but a bare-P2SH message needs the
/// legacy signature hash, which nothing else in this device computes.
fn multisig_challenge(
    kind: multisig::Kind,
    script: &[u8],
    challenge_out: &mut [u8; MAX_SCRIPT],
    script_sig_out: &mut [u8; 35],
) -> Result<(usize, usize), Error> {
    let sha = Sha256::digest(script);
    let mut program = [0u8; 34];
    program[0] = 0x00;
    program[1] = 0x20;
    program[2..].copy_from_slice(&sha);
    match kind {
        multisig::Kind::P2wsh => {
            challenge_out[..34].copy_from_slice(&program);
            Ok((34, 0))
        }
        multisig::Kind::P2shP2wsh => {
            challenge_out[0] = 0xa9;
            challenge_out[1] = 0x14;
            challenge_out[2..22].copy_from_slice(&hash160(&program));
            challenge_out[22] = 0x87;
            script_sig_out[0] = 34;
            script_sig_out[1..].copy_from_slice(&program);
            Ok((23, 35))
        }
        multisig::Kind::P2sh => Err(Error::UnsupportedKind),
    }
}

/// One cosigner's signature on `message` for the multisig `witness_script` of `kind`:
/// a `to_sign` whose witness is `OP_0 <sig> <script>`, short of the script's threshold
/// unless that threshold is one.
///
/// `secret` has to be one of the script's keys; a key the script does not name is
/// refused rather than signed with. [`merge`] puts several of these together.
pub fn sign_multisig_partial(
    message: &[u8],
    kind: multisig::Kind,
    witness_script: &[u8],
    secret: &[u8; 32],
    _kw: &KeyWork,
) -> Result<Full<MAX_MULTISIG_TX>, Error> {
    let ms = parse_multisig(witness_script).ok_or(Error::UnsupportedScript)?;
    let key = SecpPrivateKey::from_bytes(secret).map_err(|_| Error::BadKey)?;
    let pubkey = key.public_key().serialize_compressed();
    if !ms.keys[..ms.n].iter().any(|k| *k == pubkey) {
        return Err(Error::BadKey);
    }
    let mut challenge = [0u8; MAX_SCRIPT];
    let mut script_sig = [0u8; 35];
    let (cn, sn) = multisig_challenge(kind, witness_script, &mut challenge, &mut script_sig)?;
    let challenge = &challenge[..cn];
    let prev = to_spend_txid(message, challenge);
    let tx = ToSignFixed::new(prev);
    let sole = SoleChallenge(challenge);
    let engine = Engine::new(&tx, &sole, 0);
    let sighash = engine.digest(Sighash::SegwitV0 {
        script_code: witness_script,
    })?;
    let sig = ecdsa_sig(&key, &sighash)?;
    let mut buf = [0u8; MAX_MULTISIG_TX];
    let len = write_to_sign(
        &prev,
        &script_sig[..sn],
        &[&[], sig.as_bytes(), witness_script],
        &mut buf,
    )?;
    Ok(Full { buf, len })
}

/// Sign `message` as this device's share of a registered multisig `wallet`, for the
/// address at `branch`/`index`.
///
/// The cosigner is proven, not claimed: [`multisig::our_cosigner`] derives `master` down
/// the origin the wallet records and requires the key it reaches to be the one the
/// descriptor names. The witness script is rebuilt from the wallet's own record, so what
/// is signed is the address that wallet really produces. Returns the challenge script's
/// length in `challenge_out` beside the signature, for the address to show.
pub fn sign_cosigner(
    message: &[u8],
    wallet: &Multisig,
    branch: u32,
    index: u32,
    master: &ExtendedPrivKey,
    challenge_out: &mut [u8; MAX_SCRIPT],
    kw: &KeyWork,
) -> Result<(Full<MAX_MULTISIG_TX>, usize), Error> {
    let at = multisig::our_cosigner(wallet, master, kw)
        .map_err(|_| Error::BadKey)?
        .ok_or(Error::BadKey)?;
    let cosigner = wallet.cosigners()[at];
    let mut key = master.clone();
    for &step in cosigner.origin() {
        let child = if step & HARDENED_OFFSET != 0 {
            ChildNumber::hardened(step & !HARDENED_OFFSET)
        } else {
            ChildNumber::normal(step)
        };
        key = child
            .and_then(|c| key.derive_child(c, kw))
            .map_err(|_| Error::BadKey)?;
    }
    for level in [branch, index] {
        key = ChildNumber::normal(level)
            .and_then(|c| key.derive_child(c, kw))
            .map_err(|_| Error::BadKey)?;
    }
    let mut script = [0u8; multisig::MAX_SCRIPT];
    let n = wallet
        .script(branch, index, &mut script)
        .map_err(|_| Error::BadKey)?;
    let script = &script[..n];
    let mut script_sig = [0u8; 35];
    let (cn, _) = multisig_challenge(wallet.kind, script, challenge_out, &mut script_sig)?;
    let mut secret = *key.secret_bytes();
    let signed = sign_multisig_partial(message, wallet.kind, script, &secret, kw);
    zeroize::Zeroize::zeroize(&mut secret);
    Ok((signed?, cn))
}

/// Combine two partial multisig signatures over the same message and script into one.
///
/// Each signature is placed by the key it verifies under, so the result is in
/// `CHECKMULTISIG`'s key order whatever order the cosigners signed in; a signature that
/// verifies under no key, or a `to_sign` that is not the same transaction, is refused.
/// Returns the merged signature and, when it still falls short, how many more it needs.
pub fn merge(
    message: &[u8],
    challenge: &[u8],
    a: &[u8],
    b: &[u8],
) -> Result<(Full<MAX_MULTISIG_TX>, Option<u8>), Error> {
    let ta = ToSignBytes::parse(a)?;
    let tb = ToSignBytes::parse(b)?;
    let ia = ta.input(0).ok_or(Error::Malformed)?;
    let ib = tb.input(0).ok_or(Error::Malformed)?;
    let prev = to_spend_txid(message, challenge);
    if ia.txid != prev || ib.txid != prev || ia.script_sig != ib.script_sig {
        return Err(Error::Invalid);
    }
    if ta.version() != tb.version() || ta.locktime() != tb.locktime() || ia.sequence != ib.sequence
    {
        return Err(Error::Invalid);
    }
    let wa = decode_witness(ia.witness)?;
    let wb = decode_witness(ib.witness)?;
    let (Some(script), Some(other)) = (wa.items().last(), wb.items().last()) else {
        return Err(Error::Malformed);
    };
    if script != other {
        return Err(Error::Invalid);
    }
    let ms = parse_multisig(script).ok_or(Error::UnsupportedScript)?;
    let sole = SoleChallenge(challenge);
    let engine = Engine::new(&ta, &sole, 0);
    let sighash = engine.digest(Sighash::SegwitV0 {
        script_code: script,
    })?;

    // Which key each signature is for, and the signature itself, in key order.
    let mut slots: [Option<&[u8]>; MAX_COSIGNERS] = [None; MAX_COSIGNERS];
    for w in [&wa, &wb] {
        let items = w.items();
        if items.len() < 2 || !items[0].is_empty() {
            return Err(Error::Malformed);
        }
        for sig in &items[1..items.len() - 1] {
            let (r, s) = super::parse_sig(sig)?;
            let at = (0..ms.n)
                .find(|&i| {
                    SecpPublicKey::from_sec1(ms.keys[i]).is_ok_and(|k| k.verify(&sighash, &r, &s))
                })
                .ok_or(Error::Invalid)?;
            slots[at] = Some(sig);
        }
    }
    let mut items: [&[u8]; super::MAX_WITNESS_ITEMS] = [&[]; super::MAX_WITNESS_ITEMS];
    let mut count = 1usize;
    for sig in slots[..ms.n].iter().flatten() {
        if count == usize::from(ms.m) + 1 {
            break;
        }
        items[count] = sig;
        count += 1;
    }
    items[count] = *script;
    count += 1;
    // The merged `to_sign` keeps `a`'s version, sequence and lock time: those are part
    // of what was signed, and `b` was checked to be the same transaction.
    let mut buf = [0u8; MAX_MULTISIG_TX];
    let len = write_to_sign_with(
        ta.version(),
        &prev,
        ia.sequence,
        ia.script_sig,
        &items[..count],
        ta.locktime(),
        &mut buf,
    )?;
    let have = (count - 2) as u8;
    let short = (have < ms.m).then_some(ms.m - have);
    Ok((Full { buf, len }, short))
}

/// Is `to_sign` this `challenge`'s *full* signature on `message`?
///
/// The transaction is read as itself: its version has to be one BIP-322 defines (0 or 2,
/// anything else being *inconclusive* rather than wrong), it has to spend `to_spend` and
/// nothing else, and pay `OP_RETURN` and nothing else. Its own sequence and lock time are
/// hashed as found, since a signer may set them. Then the input is checked as any other.
pub fn verify_full(message: &[u8], challenge: &[u8], to_sign: &[u8]) -> Result<(), Error> {
    classify(challenge)?;
    let tx = ToSignBytes::parse(to_sign)?;
    check_shape(&tx, message, challenge, false)?;
    let inp = tx.input(0).ok_or(Error::Malformed)?;
    let sole = SoleChallenge(challenge);
    let engine = Engine::new(&tx, &sole, 0);
    check_input(challenge, inp.script_sig, inp.witness, &engine)
}

/// The rules every `to_sign` meets before a signature in it is looked at.
///
/// `more_inputs` says whether inputs past the first are allowed (a proof of funds) or
/// not (a full signature: BIP-322 says a `to_sign` with additional inputs is a `pof`).
fn check_shape<'a>(
    tx: &dyn TxView<'a>,
    message: &[u8],
    challenge: &[u8],
    more_inputs: bool,
) -> Result<(), Error> {
    if !matches!(tx.version(), 0 | 2) {
        return Err(Error::Inconclusive);
    }
    let n = tx.input_count();
    if n == 0 || (n > 1 && !more_inputs) {
        return Err(Error::Invalid);
    }
    if n > MAX_POF_INPUTS {
        return Err(Error::TooManyInputs);
    }
    if tx.output_count() != 1 {
        return Err(Error::Invalid);
    }
    let (amount, script) = tx.output(0).ok_or(Error::Malformed)?;
    if amount != 0 || script != &OP_RETURN[..] {
        return Err(Error::Invalid);
    }
    let first = tx.input(0).ok_or(Error::Malformed)?;
    if first.txid != to_spend_txid(message, challenge) || first.vout != 0 {
        return Err(Error::Invalid);
    }
    Ok(())
}

/// Is this finalised PSBT a *proof of funds* by `challenge` over `message`?
///
/// Input 0 is checked as a full signature would be; every further input has to spend an
/// output the PSBT carries, with a final `scriptSig` and witness that satisfy it over the
/// whole transaction -- so the proof stands or falls as one. What is proven is control
/// of those outputs at the time of signing; whether they still exist unspent is a
/// question for a node, which BIP-322 leaves to the verifier and this device cannot ask.
///
/// The result says how many outputs were proven and their total.
pub fn verify_pof(message: &[u8], challenge: &[u8], psbt: &[u8]) -> Result<Variant, Error> {
    classify(challenge)?;
    let parsed = Psbt::parse(psbt).map_err(|_| Error::Malformed)?;
    if !parsed.is_finalized() {
        return Err(Error::NotAProof);
    }
    let tx = PsbtTx::new(parsed);
    check_shape(&tx, message, challenge, true)?;
    let prevouts = PsbtPrevouts {
        psbt: parsed,
        challenge,
    };
    let n = tx.input_count();
    let mut total = 0u64;
    for index in 0..n {
        let inp = tx.input(index).ok_or(Error::Malformed)?;
        let (amount, script) = prevouts.prevout(index).ok_or(Error::MissingUtxo)?;
        let engine = Engine::new(&tx, &prevouts, index);
        check_input(script, inp.script_sig, inp.witness, &engine)?;
        if index > 0 {
            total = total.saturating_add(amount);
        }
    }
    Ok(Variant::Proof {
        utxos: n - 1,
        total,
    })
}

#[cfg(test)]
mod tests;
