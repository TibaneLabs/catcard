//! BIP-322 signed messages: the *simple*, *full* and *proof of funds* variants.
//!
//! The legacy format ([`crate::message`]) can only ever speak for a key behind a P2PKH
//! address: the signature is a bare recoverable ECDSA signature, so a verifier recovers a
//! key and checks it against a hash. There is nowhere in that to put a script, which is
//! why every wallet that signs for a segwit address has had to invent a convention --
//! BIP-137 header ranges, or "pretend it is P2PKH and hope" -- and why none of them can
//! sign for taproot at all.
//!
//! BIP-322 answers it the other way round: a message is proven by *spending* it. Two
//! virtual transactions are built, neither of which can exist on any network, and the
//! proof is the witness that satisfies the address's own scriptPubKey.
//!
//! ```text
//! to_spend:  in  0000..0000:0xFFFFFFFF  seq 0  scriptSig OP_0 PUSH32[message_hash]
//!            out 0 sats                        scriptPubKey = the address's script
//! to_sign:   in  to_spend.txid:0        seq 0  scriptSig empty (or the P2SH push)
//!            out 0 sats                        scriptPubKey = OP_RETURN
//! ```
//!
//! `to_spend` spends an output that does not exist (`0xFFFFFFFF` of the null txid), so
//! neither transaction is relayable and a signature made here can never move a coin.
//!
//! Three encodings of the same proof, each named by a prefix on the base64:
//!
//! - **`smp`, simple**: the witness stack of `to_sign`'s first input, consensus-encoded.
//!   Enough for a native-segwit or taproot address, where the witness is the whole
//!   solution. This module's [`sign`] and [`verify`].
//! - **`ful`, full**: the whole `to_sign` transaction, consensus-encoded. The only form
//!   that can carry a `scriptSig`, which is what a P2SH-wrapped address needs, and the
//!   one that lets a signer vary the version, sequence or lock time. [`full`].
//! - **`pof`, proof of funds**: the *finalised PSBT* of a `to_sign` that spends real
//!   coins as additional inputs: a proof of reserves. [`full::verify_pof`] checks one;
//!   [`por`] recognises a PSBT that is one before it is signed.
//!
//! Source: BIP-322 v2.0.0, "Generic Signed Message Format" -- a public standard. The
//! construction above is quoted from its *Full* section, the encodings from *Types of
//! Signatures* and the tag from the `message_hash` definition [C]. Checked against the
//! BIP's own `basic-test-vectors.json` and `generated-test-vectors.json` in the tests.
//!
//! # What is checked, and by whom
//!
//! Every variant ends in the same place: a witness stack (and perhaps a `scriptSig`) that
//! has to satisfy a scriptPubKey over a signature hash of `to_sign`. That check is
//! [`check_input`], and it reads five scripts: **P2WPKH**, **P2TR key path**, **P2WSH
//! `multi`/`sortedmulti`**, and the P2SH-wrapped forms of the first and the last. Nothing
//! else -- there is no script interpreter here, only the five shapes this device itself
//! produces, matched byte for byte. A P2WSH stack with fewer signatures than the script's
//! `M` is reported as [`Error::NeedsCosigners`], not as valid and not as forged.
//!
//! The signature hashes come from one streaming engine ([`full::Digests`]) over a
//! transaction view, so a fixed `to_sign`, a full one read off a file, and a proof of
//! reserves with sixty inputs are all hashed by the same code -- which the BIP's vectors
//! then check for the single-input case and a comparison against `outscript`'s own
//! implementation for the rest.

use crate::KeyWork;
use crate::address::{self, AddressKind, tagged_hash};
use crate::bip32::hash160;
use crate::multisig::MAX_COSIGNERS;
use outscript::btcraw::{RawTx, RawTxIn, RawTxOut};
use outscript::crypto::secp256k1::{
    SecpPrivateKey, SecpPublicKey, bip340_verify, parse_der_signature,
};
use purecrypto::hash::{Digest as _, Sha256};

pub mod full;
pub mod por;

use full::{Digests, Sighash};

/// The BIP-340 tag the message is hashed under.
///
/// Source: BIP-322 §Full, `message_hash` [C]
pub const TAG: &[u8] = b"BIP0322-signed-message";

/// The human-readable prefix a *simple* signature carries.
///
/// Source: BIP-322 §Types of Signatures [C]. Added in the BIP's 1.0.0 revision; a
/// verifier "might assume the simple variant in the absence of a prefix", which is what
/// [`verify_armoured`] does.
pub const PREFIX: &str = "smp";

/// The prefix of a *full* signature: the whole `to_sign` transaction.
/// Source: BIP-322 §Types of Signatures [C]
pub const PREFIX_FULL: &str = "ful";

/// The prefix of a *proof of funds*: the finalised PSBT of `to_sign`.
/// Source: BIP-322 §Types of Signatures [C]
pub const PREFIX_POF: &str = "pof";

/// Longest witness stack a *simple* signature produces or accepts: a compact-size count,
/// a 73-byte signature and a 33-byte key, each length-prefixed.
pub const MAX_WITNESS: usize = 1 + 1 + 73 + 1 + 33;

/// Base64 of [`MAX_WITNESS`] bytes, plus the three prefix characters.
pub const MAX_ARMOURED: usize = PREFIX.len() + MAX_WITNESS.div_ceil(3) * 4;

/// Longest scriptPubKey any supported address has (P2TR and P2WSH: `OP_n PUSH32`).
pub const MAX_SCRIPT: usize = 34;

/// Most items a witness stack this reads may have: the `OP_0` dummy, fifteen
/// signatures, and the script.
pub const MAX_WITNESS_ITEMS: usize = 2 + MAX_COSIGNERS;

/// A DER signature with its sighash byte, at its longest.
pub const MAX_SIG: usize = 73;

/// `SIGHASH_ALL`, the only type BIP-322 allows outside taproot.
///
/// Source: BIP-322 §Verification Process, "required rules" [C]
pub const SIGHASH_ALL: u32 = 0x01;

/// Why a message could not be signed, or a signature could not be accepted.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// The address type has no signature in the variant asked for: see the module note.
    UnsupportedKind,
    /// The scriptPubKey is not one this can satisfy or check.
    UnsupportedScript,
    /// The key was not usable.
    BadKey,
    /// The witness stack or transaction is not well formed: a truncated item, a trailing
    /// byte, or more items than any supported type has.
    Malformed,
    /// Well formed, and not this address's signature on this message. The only answer a
    /// verifier ever gives about a signature that does not check out.
    Invalid,
    /// The output buffer was too small.
    BufferTooSmall,
    /// A multisig stack whose signatures all check out but fall short of the script's
    /// threshold: a cosigner's partial signature, waiting on the others.
    NeedsCosigners { have: u8, need: u8 },
    /// Well formed under a rule BIP-322 marks *upgradeable* -- a `to_sign` version other
    /// than 0 or 2 -- so the answer is neither yes nor no.
    Inconclusive,
    /// A proof of funds whose PSBT is not the shape of one: not finalised, more than one
    /// output, or an output that pays something.
    NotAProof,
    /// More inputs than [`full::MAX_POF_INPUTS`].
    TooManyInputs,
    /// An input of a proof of funds without the output it claims to spend.
    MissingUtxo,
}

/// Which variant a signature turned out to be, from [`verify_armoured_in`].
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Variant {
    Simple,
    Full,
    /// A proof of funds over this many real outputs, worth this many satoshis together.
    Proof {
        utxos: usize,
        total: u64,
    },
}

/// The digest `to_spend` commits to: `tagged_hash("BIP0322-signed-message", m)`.
///
/// `m` is the message as-is -- no length prefix, no terminator, and no normalisation.
/// Bytes rather than `&str` because the hash is over bytes and the BIP's own vectors
/// include one that is not ASCII.
///
/// Source: BIP-322 §Full [C]
pub fn message_hash(message: &[u8]) -> [u8; 32] {
    tagged_hash(TAG, message)
}

/// The txid of `to_spend`, in display byte order, from the hash it commits to.
///
/// Every field of it is fixed by the BIP; nothing here is a choice.
pub fn to_spend_txid_of(hash: &[u8; 32], challenge: &[u8]) -> [u8; 32] {
    // scriptSig = OP_0 PUSH32[message_hash]: 34 bytes, minimally encoded.
    let mut script_sig = [0u8; 34];
    script_sig[0] = 0x00; // OP_0
    script_sig[1] = 0x20; // push 32
    script_sig[2..].copy_from_slice(hash);
    let inputs = [RawTxIn {
        // The null txid; `vout` 0xFFFFFFFF of it is the output that does not exist and
        // never will, which is what makes these transactions unspendable.
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
    .txid()
}

/// The txid of `to_spend`, in display byte order.
pub fn to_spend_txid(message: &[u8], challenge: &[u8]) -> [u8; 32] {
    to_spend_txid_of(&message_hash(message), challenge)
}

/// `to_sign`'s only output: `OP_RETURN`, and nothing after it.
pub(crate) const OP_RETURN: [u8; 1] = [0x6a];

/// The txid of `to_sign`, in display byte order, before any witness is attached.
///
/// A witness does not change a txid, so this is the same before and after signing -- it
/// is what the BIP's vectors publish as `to_sign_tx_hash`.
pub fn to_sign_txid(message: &[u8], challenge: &[u8]) -> [u8; 32] {
    let prev = to_spend_txid(message, challenge);
    let inputs = [RawTxIn {
        txid: prev,
        vout: 0,
        script_sig: &[],
        sequence: 0,
        witness: &[],
    }];
    let outputs = [RawTxOut {
        amount: 0,
        script: &OP_RETURN,
    }];
    RawTx {
        version: 0,
        inputs: &inputs,
        outputs: &outputs,
        locktime: 0,
    }
    .txid()
}

/// A *simple* signature: the witness stack of `to_sign`'s first input, consensus-encoded.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Simple {
    buf: [u8; MAX_WITNESS],
    len: usize,
}

impl Simple {
    /// The consensus encoding, which is what the base64 of a *simple* signature holds.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// The signature as it is written into a file: `smp` and then base64.
    pub fn armour(&self, out: &mut [u8]) -> Result<usize, Error> {
        armour_with(PREFIX, self.as_bytes(), out)
    }
}

/// `prefix` and then the base64 of `bytes`, into `out`.
pub(crate) fn armour_with(prefix: &str, bytes: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let n = prefix.len();
    if out.len() < n {
        return Err(Error::BufferTooSmall);
    }
    out[..n].copy_from_slice(prefix.as_bytes());
    let more = outscript::base64::encode_to_slice(bytes, &mut out[n..])
        .map_err(|_| Error::BufferTooSmall)?;
    Ok(n + more)
}

/// Write a witness stack: a compact-size item count, then each item length-prefixed.
///
/// Only the small end of compact-size can occur here -- two items, the longest 73 bytes --
/// so a value of 0xfd or more is a bug rather than a case to encode.
fn encode_witness(items: &[&[u8]]) -> Simple {
    let mut buf = [0u8; MAX_WITNESS];
    let mut at = 0;
    debug_assert!(items.len() < 0xfd);
    buf[at] = items.len() as u8;
    at += 1;
    for item in items {
        debug_assert!(item.len() < 0xfd);
        buf[at] = item.len() as u8;
        at += 1;
        buf[at..at + item.len()].copy_from_slice(item);
        at += item.len();
    }
    Simple { buf, len: at }
}

/// The items of a witness stack, borrowed out of the encoding.
pub(crate) struct Witness<'a> {
    items: [&'a [u8]; MAX_WITNESS_ITEMS],
    count: usize,
}

impl<'a> Witness<'a> {
    pub(crate) fn items(&self) -> &[&'a [u8]] {
        &self.items[..self.count]
    }
}

/// One compact-size, canonical, and no larger than a witness item can be.
///
/// Two forms only: a single byte, or `0xfd` and two more. A stack item is at most a
/// witness script (a few hundred bytes), so the four- and eight-byte forms cannot name
/// anything real and are refused rather than read.
fn compact(bytes: &[u8]) -> Result<(usize, &[u8]), Error> {
    let (&first, rest) = bytes.split_first().ok_or(Error::Malformed)?;
    match first {
        0..=0xfc => Ok((first as usize, rest)),
        0xfd => {
            let (n, rest) = rest.split_at_checked(2).ok_or(Error::Malformed)?;
            let n = u16::from_le_bytes([n[0], n[1]]) as usize;
            if n < 0xfd {
                return Err(Error::Malformed);
            }
            Ok((n, rest))
        }
        _ => Err(Error::Malformed),
    }
}

/// Parse a consensus-encoded witness stack of at most [`MAX_WITNESS_ITEMS`] items.
///
/// Strict on purpose: a trailing byte, a truncated item, or one item too many is
/// [`Error::Malformed`] rather than something to ignore. A verifier that ignores bytes it
/// did not understand is one that can be handed two readings of the same file.
pub(crate) fn decode_witness(bytes: &[u8]) -> Result<Witness<'_>, Error> {
    let (count, mut rest) = compact(bytes)?;
    if count == 0 || count > MAX_WITNESS_ITEMS {
        return Err(Error::Malformed);
    }
    let mut items: [&[u8]; MAX_WITNESS_ITEMS] = [&[]; MAX_WITNESS_ITEMS];
    for slot in items.iter_mut().take(count) {
        let (len, tail) = compact(rest)?;
        let (item, tail) = tail.split_at_checked(len).ok_or(Error::Malformed)?;
        *slot = item;
        rest = tail;
    }
    if !rest.is_empty() {
        return Err(Error::Malformed);
    }
    Ok(Witness { items, count })
}

/// Which supported script a scriptPubKey is, and the program it carries.
pub(crate) enum Challenge<'a> {
    /// `OP_0 PUSH20 <hash160(pubkey)>`.
    P2wpkh(&'a [u8; 20]),
    /// `OP_0 PUSH32 <sha256(witness script)>`.
    P2wsh(&'a [u8; 32]),
    /// `OP_1 PUSH32 <tweaked x-only key>`.
    P2tr(&'a [u8; 32]),
    /// `OP_HASH160 PUSH20 <hash160(redeem script)> OP_EQUAL`: what is inside is settled
    /// by the `scriptSig`, which only the *full* variants carry.
    P2sh(&'a [u8; 20]),
}

pub(crate) fn classify(script: &[u8]) -> Result<Challenge<'_>, Error> {
    match script {
        [0x00, 0x14, program @ ..] => program
            .try_into()
            .map(Challenge::P2wpkh)
            .map_err(|_| Error::UnsupportedScript),
        [0x00, 0x20, program @ ..] => program
            .try_into()
            .map(Challenge::P2wsh)
            .map_err(|_| Error::UnsupportedScript),
        [0x51, 0x20, program @ ..] => program
            .try_into()
            .map(Challenge::P2tr)
            .map_err(|_| Error::UnsupportedScript),
        [0xa9, 0x14, hash @ .., 0x87] => hash
            .try_into()
            .map(Challenge::P2sh)
            .map_err(|_| Error::UnsupportedScript),
        _ => Err(Error::UnsupportedScript),
    }
}

/// The scriptPubKey an address of `kind` for `pubkey` pays to, which is
/// `message_challenge`. For the *simple* variant: P2PKH and nested segwit are refused,
/// since neither has a simple signature ([`full::challenge`] takes the latter).
pub fn challenge(kind: AddressKind, pubkey: &[u8; 33], out: &mut [u8]) -> Result<usize, Error> {
    match kind {
        AddressKind::P2wpkh | AddressKind::P2tr => {}
        // Not "unsupported address": these two have messages of their own. See the module
        // note for why neither travels as a simple signature.
        AddressKind::P2pkh | AddressKind::P2shP2wpkh => return Err(Error::UnsupportedKind),
    }
    address::script_pubkey(kind, pubkey, out).map_err(|_| Error::BadKey)
}

/// The fixed `to_sign` of the *simple* variant -- version 0, sequence 0, lock time 0 --
/// as the hashing engine sees it.
struct FixedToSign<'a> {
    prev: [u8; 32],
    challenge: &'a [u8],
}

impl<'a> FixedToSign<'a> {
    fn new(message: &[u8], challenge: &'a [u8]) -> Self {
        Self {
            prev: to_spend_txid(message, challenge),
            challenge,
        }
    }
}

impl<'a> full::TxView<'a> for FixedToSign<'a> {
    fn version(&self) -> u32 {
        0
    }
    fn locktime(&self) -> u32 {
        0
    }
    fn input_count(&self) -> usize {
        1
    }
    fn input(&self, index: usize) -> Option<full::InView<'a>> {
        (index == 0).then_some(full::InView {
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

impl<'a> full::Prevouts<'a> for FixedToSign<'a> {
    fn prevout(&self, index: usize) -> Option<(u64, &'a [u8])> {
        (index == 0).then_some((0, self.challenge))
    }
}

/// A DER signature with its sighash byte after it, as a witness carries one.
pub(crate) struct SigBytes {
    buf: [u8; MAX_SIG],
    len: usize,
}

impl SigBytes {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

/// Sign `digest` with `key`, and append `SIGHASH_ALL`.
pub(crate) fn ecdsa_sig(key: &SecpPrivateKey, digest: &[u8; 32]) -> Result<SigBytes, Error> {
    let der = key.sign_der(digest);
    let mut buf = [0u8; MAX_SIG];
    let len = der.as_bytes().len();
    if len + 1 > buf.len() {
        return Err(Error::BadKey);
    }
    buf[..len].copy_from_slice(der.as_bytes());
    buf[len] = SIGHASH_ALL as u8;
    Ok(SigBytes { buf, len: len + 1 })
}

/// Sign `message` for the address of `kind` behind `secret`, in the *simple* variant.
///
/// Deterministic: RFC 6979 for the ECDSA half, BIP-340 with zero auxiliary randomness for
/// the Schnorr one, so the same key and message always produce the same bytes and a
/// signature can be reproduced and checked.
pub fn sign(
    message: &[u8],
    secret: &[u8; 32],
    kind: AddressKind,
    _kw: &KeyWork,
) -> Result<Simple, Error> {
    let key = SecpPrivateKey::from_bytes(secret).map_err(|_| Error::BadKey)?;
    let pubkey = key.public_key().serialize_compressed();
    let mut script = [0u8; MAX_SCRIPT];
    let n = challenge(kind, &pubkey, &mut script)?;
    let script = &script[..n];
    let tx = FixedToSign::new(message, script);
    let engine = full::Engine::new(&tx, &tx, 0);

    match kind {
        AddressKind::P2wpkh => {
            let key_hash = hash160(&pubkey);
            let code = crate::tx::sighash::p2wpkh_script_code(&key_hash);
            let sighash = engine.digest(Sighash::SegwitV0 { script_code: &code })?;
            // The witness of any P2WPKH spend: the signature with its sighash byte, then
            // the key it is checked against.
            let sig = ecdsa_sig(&key, &sighash)?;
            Ok(encode_witness(&[sig.as_bytes(), &pubkey]))
        }
        AddressKind::P2tr => {
            // SIGHASH_DEFAULT: the 64-byte form, with no type byte to get wrong.
            let sighash = engine.digest(Sighash::Taproot { hash_type: 0x00 })?;
            // BIP-86: the output key is the internal key tweaked with an empty merkle
            // root, so the signature is made with the key tweaked the same way.
            let sig = key.sign_taproot(&sighash).map_err(|_| Error::BadKey)?;
            Ok(encode_witness(&[&sig]))
        }
        AddressKind::P2pkh | AddressKind::P2shP2wpkh => Err(Error::UnsupportedKind),
    }
}

/// Is `witness` this `challenge`'s *simple* signature on `message`?
///
/// `Ok(())` is the only "yes". Everything else says why not, and nothing here trusts a
/// claim made by the signature itself: the key comes out of the witness and has to hash
/// or tweak to the program the address commits to before its signature is even checked.
pub fn verify(message: &[u8], challenge_script: &[u8], witness: &[u8]) -> Result<(), Error> {
    // The script first, and the witness only once there is something it could satisfy: a
    // stack this cannot read is a different answer from a script this cannot check.
    classify(challenge_script)?;
    let tx = FixedToSign::new(message, challenge_script);
    let engine = full::Engine::new(&tx, &tx, 0);
    check_input(challenge_script, &[], witness, &engine)
}

/// Does `script_sig` and `witness` satisfy `challenge` over the digests `d` computes?
///
/// The one verifier behind every variant. Five shapes, and for each the key or script is
/// taken out of the stack and made to hash to the program the challenge commits to
/// *before* any signature is checked against it.
pub(crate) fn check_input(
    challenge: &[u8],
    script_sig: &[u8],
    witness: &[u8],
    d: &dyn Digests,
) -> Result<(), Error> {
    match classify(challenge)? {
        Challenge::P2wpkh(key_hash) => {
            if !script_sig.is_empty() {
                return Err(Error::Invalid);
            }
            check_p2wpkh(key_hash, witness, d)
        }
        Challenge::P2wsh(sha) => {
            if !script_sig.is_empty() {
                return Err(Error::Invalid);
            }
            check_p2wsh(sha, witness, d)
        }
        Challenge::P2tr(output_key) => {
            if !script_sig.is_empty() {
                return Err(Error::Invalid);
            }
            check_p2tr(output_key, witness, d)
        }
        Challenge::P2sh(hash) => match script_sig {
            // A simple signature has no scriptSig, and a P2SH address needs one.
            [] => Err(Error::UnsupportedKind),
            // `PUSH22 <OP_0 PUSH20 h160>`: nested P2WPKH. The redeem script has to hash
            // to the address before the key inside it is looked at.
            [0x16, redeem @ ..] if redeem.len() == 22 => {
                if hash160(redeem) != *hash {
                    return Err(Error::Invalid);
                }
                let [0x00, 0x14, program @ ..] = redeem else {
                    return Err(Error::UnsupportedScript);
                };
                let program: &[u8; 20] = program.try_into().map_err(|_| Error::Malformed)?;
                check_p2wpkh(program, witness, d)
            }
            // `PUSH34 <OP_0 PUSH32 sha256>`: nested P2WSH.
            [0x22, redeem @ ..] if redeem.len() == 34 => {
                if hash160(redeem) != *hash {
                    return Err(Error::Invalid);
                }
                let [0x00, 0x20, program @ ..] = redeem else {
                    return Err(Error::UnsupportedScript);
                };
                let program: &[u8; 32] = program.try_into().map_err(|_| Error::Malformed)?;
                check_p2wsh(program, witness, d)
            }
            _ => Err(Error::UnsupportedScript),
        },
    }
}

/// `<sig> <pubkey>` against `OP_0 PUSH20 <key_hash>`.
fn check_p2wpkh(key_hash: &[u8; 20], witness: &[u8], d: &dyn Digests) -> Result<(), Error> {
    let stack = decode_witness(witness)?;
    let [sig, pubkey] = stack.items() else {
        return Err(Error::Malformed);
    };
    let pubkey: &[u8; 33] = (*pubkey).try_into().map_err(|_| Error::Invalid)?;
    // The key has to be the one the address names before anything else happens.
    if hash160(pubkey) != *key_hash {
        return Err(Error::Invalid);
    }
    let (r, s) = parse_sig(sig)?;
    let code = crate::tx::sighash::p2wpkh_script_code(key_hash);
    let sighash = d.digest(Sighash::SegwitV0 { script_code: &code })?;
    let key = SecpPublicKey::from_sec1(pubkey).map_err(|_| Error::Invalid)?;
    if key.verify(&sighash, &r, &s) {
        Ok(())
    } else {
        Err(Error::Invalid)
    }
}

/// `<sig>` against `OP_1 PUSH32 <output key>`.
fn check_p2tr(output_key: &[u8; 32], witness: &[u8], d: &dyn Digests) -> Result<(), Error> {
    let stack = decode_witness(witness)?;
    let [item] = stack.items() else {
        return Err(Error::Malformed);
    };
    // 64 bytes is SIGHASH_DEFAULT; 65 carries the type, and BIP-341 makes an explicit
    // 0x00 invalid, so SIGHASH_ALL is the only byte that can appear.
    let (sig, hash_type) = match item.len() {
        64 => (*item, 0x00u8),
        65 => (&item[..64], item[64]),
        _ => return Err(Error::Malformed),
    };
    if hash_type != 0x00 && u32::from(hash_type) != SIGHASH_ALL {
        return Err(Error::Invalid);
    }
    if item.len() == 65 && hash_type == 0x00 {
        return Err(Error::Invalid);
    }
    let sighash = d.digest(Sighash::Taproot { hash_type })?;
    let sig: &[u8; 64] = sig.try_into().map_err(|_| Error::Malformed)?;
    if bip340_verify(output_key, &sighash, sig) {
        Ok(())
    } else {
        Err(Error::Invalid)
    }
}

/// `OP_0 <sig>... <script>` against `OP_0 PUSH32 <sha256(script)>`, for a
/// `multi`/`sortedmulti` script.
///
/// `CHECKMULTISIG`'s rule: the signatures are in the order of the keys they match, each
/// key tried once. Every signature has to check out -- BIP-322 requires `NULLFAIL`, so a
/// signature that fails is a failure, never a skip. Fewer than `M` of them is a partial
/// signature and said as such; more than `M` would leave the stack unclean.
fn check_p2wsh(sha: &[u8; 32], witness: &[u8], d: &dyn Digests) -> Result<(), Error> {
    let stack = decode_witness(witness)?;
    let items = stack.items();
    if items.len() < 2 {
        return Err(Error::Malformed);
    }
    let script = items[items.len() - 1];
    if Sha256::digest(script)[..] != sha[..] {
        return Err(Error::Invalid);
    }
    let ms = parse_multisig(script).ok_or(Error::UnsupportedScript)?;
    // The dummy element `CHECKMULTISIG` pops and BIP-147 requires to be empty.
    if !items[0].is_empty() {
        return Err(Error::Invalid);
    }
    let sigs = &items[1..items.len() - 1];
    if sigs.len() > usize::from(ms.m) {
        return Err(Error::Invalid);
    }
    let sighash = d.digest(Sighash::SegwitV0 {
        script_code: script,
    })?;
    let mut next_key = 0usize;
    for sig in sigs {
        let (r, s) = parse_sig(sig)?;
        let mut matched = false;
        while next_key < ms.n {
            let key = ms.keys[next_key];
            next_key += 1;
            let Ok(key) = SecpPublicKey::from_sec1(key) else {
                return Err(Error::Invalid);
            };
            if key.verify(&sighash, &r, &s) {
                matched = true;
                break;
            }
        }
        if !matched {
            return Err(Error::Invalid);
        }
    }
    if sigs.len() < usize::from(ms.m) {
        return Err(Error::NeedsCosigners {
            have: sigs.len() as u8,
            need: ms.m,
        });
    }
    Ok(())
}

/// A DER signature with its sighash byte, read strictly: `SIGHASH_ALL` and low-S only.
pub(crate) fn parse_sig(sig: &[u8]) -> Result<([u8; 32], [u8; 32]), Error> {
    // The sighash byte is part of the signature and part of what was signed, so it is
    // checked rather than read: BIP-322 allows only SIGHASH_ALL here.
    let (&flag, der) = sig.split_last().ok_or(Error::Malformed)?;
    if u32::from(flag) != SIGHASH_ALL {
        return Err(Error::Invalid);
    }
    let (r, s) = parse_der_signature(der).map_err(|_| Error::Invalid)?;
    // LOW_S: the other half of every signature pair is equally valid arithmetic and is
    // not a valid Bitcoin signature. Accepting it would let anyone produce a second
    // distinct "signature" from one they were given.
    if !is_low_s(&s) {
        return Err(Error::Invalid);
    }
    Ok((r, s))
}

/// An `OP_M <key>... OP_N OP_CHECKMULTISIG` script, taken apart.
pub(crate) struct MultisigScript<'a> {
    pub(crate) m: u8,
    pub(crate) keys: [&'a [u8]; MAX_COSIGNERS],
    pub(crate) n: usize,
}

/// Read a bare multisig script of compressed keys, or nothing.
///
/// The exact shape [`crate::multisig::assemble`] writes: `OP_1..OP_15`, then `PUSH33`
/// keys, then `OP_n` and `OP_CHECKMULTISIG`. Anything else -- an uncompressed key, a
/// script with more in it -- is not a script this can read, whatever it hashes to.
pub(crate) fn parse_multisig(script: &[u8]) -> Option<MultisigScript<'_>> {
    let (&first, mut rest) = script.split_first()?;
    let m = first.checked_sub(0x50)?;
    if m == 0 || usize::from(m) > MAX_COSIGNERS {
        return None;
    }
    let mut keys: [&[u8]; MAX_COSIGNERS] = [&[]; MAX_COSIGNERS];
    let mut n = 0usize;
    while let Some((&0x21, tail)) = rest.split_first() {
        if n == MAX_COSIGNERS {
            return None;
        }
        let (key, tail) = tail.split_at_checked(33)?;
        keys[n] = key;
        n += 1;
        rest = tail;
    }
    if n == 0 || usize::from(m) > n {
        return None;
    }
    let [op_n, 0xae] = rest else {
        return None;
    };
    if usize::from(op_n.checked_sub(0x50)?) != n {
        return None;
    }
    Some(MultisigScript { m, keys, n })
}

/// Half the curve order, rounded down: `s` above this is the high half.
///
/// Source: secp256k1 group order, and BIP-146/BIP-322's LOW_S rule [C]
const HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

fn is_low_s(s: &[u8; 32]) -> bool {
    *s <= HALF_ORDER
}

/// Which variant an armoured signature says it is, and the base64 after the prefix.
///
/// The `smp` prefix is required of a signer and optional of a verifier: BIP-322 says a
/// verifier "might assume the simple variant in the absence of a prefix", and its own
/// vectors include one written before the prefix existed.
pub fn variant_of(text: &str) -> (Variant, &str) {
    let text = text.trim();
    match text.get(..3) {
        Some(PREFIX) => (Variant::Simple, &text[3..]),
        Some(PREFIX_FULL) => (Variant::Full, &text[3..]),
        Some(PREFIX_POF) => (Variant::Proof { utxos: 0, total: 0 }, &text[3..]),
        _ => (Variant::Simple, text),
    }
}

/// Decode the armoured form of a *simple* signature into its witness bytes.
///
/// A `ful` or `pof` prefix names another variant, which [`verify_armoured_in`] reads;
/// here it is refused as itself rather than decoded as a witness.
pub fn dearmour(text: &str, out: &mut [u8]) -> Result<usize, Error> {
    let (variant, body) = variant_of(text);
    if variant != Variant::Simple {
        return Err(Error::UnsupportedKind);
    }
    outscript::base64::decode_to_slice(body, out).map_err(|_| Error::Malformed)
}

/// Check an armoured signature of any variant against a message and a scriptPubKey.
///
/// `scratch` holds the decoded bytes: a witness stack, a whole `to_sign`, or -- for a
/// proof of funds -- the finalised PSBT, which can run to kilobytes. The caller sizes
/// it; the decode fails cleanly rather than truncating when it is short.
pub fn verify_armoured_in(
    message: &[u8],
    challenge_script: &[u8],
    text: &str,
    scratch: &mut [u8],
) -> Result<Variant, Error> {
    classify(challenge_script)?;
    let (variant, body) = variant_of(text);
    let n = outscript::base64::decode_to_slice(body, scratch).map_err(|_| Error::Malformed)?;
    let bytes = &scratch[..n];
    match variant {
        Variant::Simple => verify(message, challenge_script, bytes).map(|()| Variant::Simple),
        Variant::Full => {
            full::verify_full(message, challenge_script, bytes).map(|()| Variant::Full)
        }
        Variant::Proof { .. } => full::verify_pof(message, challenge_script, bytes),
    }
}

/// Room [`verify_armoured`] gives a decoded signature: a full multisig `to_sign`.
const ARMOURED_SCRATCH: usize = full::MAX_MULTISIG_TX;

/// Check an armoured *simple* or *full* signature against a message and a scriptPubKey.
///
/// The proof-of-funds variant needs a buffer sized to its PSBT, which is
/// [`verify_armoured_in`]'s business; here it is refused as too large.
pub fn verify_armoured(message: &[u8], challenge_script: &[u8], text: &str) -> Result<(), Error> {
    if matches!(variant_of(text).0, Variant::Proof { .. }) {
        return Err(Error::BufferTooSmall);
    }
    let mut scratch = [0u8; ARMOURED_SCRATCH];
    verify_armoured_in(message, challenge_script, text, &mut scratch).map(|_| ())
}

#[cfg(test)]
mod tests;
