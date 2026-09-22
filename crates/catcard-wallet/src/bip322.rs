//! BIP-322 signed messages: the *simple* variant.
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
//! to_sign:   in  to_spend.txid:0        seq 0  scriptSig empty
//!            out 0 sats                        scriptPubKey = OP_RETURN
//! ```
//!
//! `to_spend` spends an output that does not exist (`0xFFFFFFFF` of the null txid), so
//! neither transaction is relayable and a signature made here can never move a coin.
//!
//! A *simple* signature is the witness stack of `to_sign`'s first input, consensus-encoded
//! (a compact-size count, then each item length-prefixed) and base64'd, carrying the
//! human-readable prefix `smp`. That is all a verifier needs: it rebuilds both
//! transactions from the message and the address and checks the witness against them.
//!
//! Source: BIP-322 v2.0.0, "Generic Signed Message Format" -- a public standard. The
//! construction above is quoted from its *Full* section, the encoding from *Simple*, and
//! the tag from the `message_hash` definition [C]. Checked against the BIP's own
//! `basic-test-vectors.json` and `generated-test-vectors.json` in the tests below.
//!
//! # What is here and what is not
//!
//! Signing and verifying the two native-segwit single-key types: **P2WPKH** and
//! **P2TR key path**. Those are the ones a device holding one key can satisfy on its own.
//!
//! Not here, and refused rather than approximated:
//!
//! - **P2WSH** (multisig). The witness is a script and its solution; checking one means a
//!   script interpreter, and producing one means coordinating cosigners.
//! - **P2SH-P2WPKH and P2PKH.** BIP-322 excludes both from the *simple* variant -- a P2SH
//!   spend needs a `scriptSig`, which a witness stack has nowhere to put -- so they would
//!   have to travel as the *full* variant, a whole serialised transaction. P2PKH messages
//!   have [`crate::message`], which every verifier already reads.
//! - **`ful` and `pof`.** Parsing an arbitrary transaction or PSBT out of a file and
//!   deciding it is really a BIP-322 envelope is a much larger attack surface than
//!   checking a two-item witness stack.

use crate::KeyWork;
use crate::address::{self, AddressKind, tagged_hash};
use crate::bip32::hash160;
use outscript::btcraw::{PrevOut, RawTx, RawTxIn, RawTxOut};
use outscript::crypto::secp256k1::{
    SecpPrivateKey, SecpPublicKey, bip340_verify, parse_der_signature,
};

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

/// Longest witness stack this produces or accepts: a compact-size count, a 73-byte
/// signature and a 33-byte key, each length-prefixed.
pub const MAX_WITNESS: usize = 1 + 1 + 73 + 1 + 33;

/// Base64 of [`MAX_WITNESS`] bytes, plus the three prefix characters.
pub const MAX_ARMOURED: usize = PREFIX.len() + MAX_WITNESS.div_ceil(3) * 4;

/// Longest scriptPubKey any supported address has (P2TR: `OP_1 PUSH32`).
pub const MAX_SCRIPT: usize = 34;

/// Why a message could not be signed, or a signature could not be accepted.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// The address type has no *simple* BIP-322 signature: see the module note.
    UnsupportedKind,
    /// The scriptPubKey is not one this can satisfy or check.
    UnsupportedScript,
    /// The key was not usable.
    BadKey,
    /// The witness stack is not well formed: a truncated item, a trailing byte, or more
    /// items than any supported type has.
    Malformed,
    /// Well formed, and not this address's signature on this message. The only answer a
    /// verifier ever gives about a signature that does not check out.
    Invalid,
    /// The output buffer was too small.
    BufferTooSmall,
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

/// The txid of `to_spend`, in display byte order.
///
/// Every field of it is fixed by the BIP; nothing here is a choice.
pub fn to_spend_txid(message: &[u8], challenge: &[u8]) -> [u8; 32] {
    // scriptSig = OP_0 PUSH32[message_hash]: 34 bytes, minimally encoded.
    let mut script_sig = [0u8; 34];
    script_sig[0] = 0x00; // OP_0
    script_sig[1] = 0x20; // push 32
    script_sig[2..].copy_from_slice(&message_hash(message));
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

/// `to_sign`'s only output: `OP_RETURN`, and nothing after it.
const OP_RETURN: [u8; 1] = [0x6a];

/// The txid of `to_sign`, in display byte order, before any witness is attached.
///
/// A witness does not change a txid, so this is the same before and after signing -- it
/// is what the BIP's vectors publish as `to_sign_tx_hash`.
pub fn to_sign_txid(message: &[u8], challenge: &[u8]) -> [u8; 32] {
    let prev = to_spend_txid(message, challenge);
    let inputs = [to_sign_input(&prev)];
    let outputs = [RawTxOut {
        amount: 0,
        script: &OP_RETURN,
    }];
    to_sign(&inputs, &outputs).txid()
}

/// `to_sign`'s only input: `to_spend`'s output, at rest.
fn to_sign_input(to_spend_txid: &[u8; 32]) -> RawTxIn<'static> {
    RawTxIn {
        txid: *to_spend_txid,
        vout: 0,
        script_sig: &[],
        sequence: 0,
        // The witness is what is being computed, and it is not part of any sighash.
        witness: &[],
    }
}

fn to_sign<'a>(inputs: &'a [RawTxIn<'a>], outputs: &'a [RawTxOut<'a>]) -> RawTx<'a> {
    RawTx {
        version: 0,
        inputs,
        outputs,
        locktime: 0,
    }
}

/// The sighash `to_sign`'s input commits to, for a P2WPKH challenge.
///
/// BIP-143 with the amount at zero -- `to_spend`'s output is worth nothing -- and
/// `SIGHASH_ALL`, which BIP-322 requires. The scriptCode is the implied P2PKH script,
/// as it is for any P2WPKH spend.
fn p2wpkh_sighash(
    message: &[u8],
    challenge: &[u8],
    key_hash: &[u8; 20],
) -> Result<[u8; 32], Error> {
    let prev = to_spend_txid(message, challenge);
    let inputs = [to_sign_input(&prev)];
    let outputs = [RawTxOut {
        amount: 0,
        script: &OP_RETURN,
    }];
    let tx = to_sign(&inputs, &outputs);
    let code = crate::tx::sighash::p2wpkh_script_code(key_hash);
    tx.segwit_v0_sighash(0, &code, 0, SIGHASH_ALL)
        .map_err(|_| Error::Malformed)
}

/// `SIGHASH_ALL`, the only type BIP-322 allows outside taproot.
///
/// Source: BIP-322 §Verification Process, "required rules" [C]
const SIGHASH_ALL: u32 = 0x01;

/// The sighash a taproot key-path spend of `to_sign` commits to.
///
/// `hash_type` is `0x00` (`SIGHASH_DEFAULT`, the 64-byte signature) or `0x01`
/// (`SIGHASH_ALL`, which carries the byte as a 65th). BIP-341's message commits to every
/// spent output, which here is the single zero-valued output of `to_spend`.
fn p2tr_sighash(message: &[u8], challenge: &[u8], hash_type: u8) -> Result<[u8; 32], Error> {
    let prev = to_spend_txid(message, challenge);
    let inputs = [to_sign_input(&prev)];
    let outputs = [RawTxOut {
        amount: 0,
        script: &OP_RETURN,
    }];
    let tx = to_sign(&inputs, &outputs);
    let prevouts = [PrevOut {
        amount: 0,
        script: challenge,
    }];
    let mid = tx
        .taproot_midstate(&prevouts)
        .map_err(|_| Error::Malformed)?;
    mid.key_spend_sighash_with_type(0, hash_type)
        .map_err(|_| Error::Malformed)
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
        let n = PREFIX.len();
        if out.len() < n {
            return Err(Error::BufferTooSmall);
        }
        out[..n].copy_from_slice(PREFIX.as_bytes());
        let more = outscript::base64::encode_to_slice(self.as_bytes(), &mut out[n..])
            .map_err(|_| Error::BufferTooSmall)?;
        Ok(n + more)
    }
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
struct Witness<'a> {
    items: [&'a [u8]; 2],
    count: usize,
}

/// Parse a consensus-encoded witness stack of at most two items.
///
/// Strict on purpose: a trailing byte, a truncated item, or a third item is
/// [`Error::Malformed`] rather than something to ignore. A verifier that ignores bytes it
/// did not understand is one that can be handed two readings of the same file.
fn decode_witness(bytes: &[u8]) -> Result<Witness<'_>, Error> {
    let (&count, mut rest) = bytes.split_first().ok_or(Error::Malformed)?;
    // A compact-size that needs its escape prefix cannot be an item count here.
    if count == 0 || count as usize > 2 {
        return Err(Error::Malformed);
    }
    let mut items: [&[u8]; 2] = [&[], &[]];
    for slot in items.iter_mut().take(count as usize) {
        let (&len, tail) = rest.split_first().ok_or(Error::Malformed)?;
        if len >= 0xfd {
            return Err(Error::Malformed);
        }
        let len = len as usize;
        if tail.len() < len {
            return Err(Error::Malformed);
        }
        let (item, tail) = tail.split_at(len);
        *slot = item;
        rest = tail;
    }
    if !rest.is_empty() {
        return Err(Error::Malformed);
    }
    Ok(Witness {
        items,
        count: count as usize,
    })
}

/// Which supported script a scriptPubKey is, and the program it carries.
enum Challenge<'a> {
    /// `OP_0 PUSH20 <hash160(pubkey)>`.
    P2wpkh(&'a [u8; 20]),
    /// `OP_1 PUSH32 <tweaked x-only key>`.
    P2tr(&'a [u8; 32]),
}

fn classify(script: &[u8]) -> Result<Challenge<'_>, Error> {
    match script {
        [0x00, 0x14, program @ ..] => program
            .try_into()
            .map(Challenge::P2wpkh)
            .map_err(|_| Error::UnsupportedScript),
        [0x51, 0x20, program @ ..] => program
            .try_into()
            .map(Challenge::P2tr)
            .map_err(|_| Error::UnsupportedScript),
        _ => Err(Error::UnsupportedScript),
    }
}

/// The scriptPubKey an address of `kind` for `pubkey` pays to, which is
/// `message_challenge`.
pub fn challenge(kind: AddressKind, pubkey: &[u8; 33], out: &mut [u8]) -> Result<usize, Error> {
    match kind {
        AddressKind::P2wpkh | AddressKind::P2tr => {}
        // Not "unsupported address": these two have messages of their own. See the module
        // note for why neither travels as a simple signature.
        AddressKind::P2pkh | AddressKind::P2shP2wpkh => return Err(Error::UnsupportedKind),
    }
    address::script_pubkey(kind, pubkey, out).map_err(|_| Error::BadKey)
}

/// Sign `message` for the address of `kind` behind `secret`.
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

    match kind {
        AddressKind::P2wpkh => {
            let key_hash = hash160(&pubkey);
            let sighash = p2wpkh_sighash(message, script, &key_hash)?;
            let der = key.sign_der(&sighash);
            // The witness of any P2WPKH spend: the signature with its sighash byte, then
            // the key it is checked against.
            let mut sig = [0u8; 73];
            let len = der.as_bytes().len();
            if len + 1 > sig.len() {
                return Err(Error::BadKey);
            }
            sig[..len].copy_from_slice(der.as_bytes());
            sig[len] = SIGHASH_ALL as u8;
            Ok(encode_witness(&[&sig[..len + 1], &pubkey]))
        }
        AddressKind::P2tr => {
            // SIGHASH_DEFAULT: the 64-byte form, with no type byte to get wrong.
            let sighash = p2tr_sighash(message, script, 0x00)?;
            // BIP-86: the output key is the internal key tweaked with an empty merkle
            // root, so the signature is made with the key tweaked the same way.
            let sig = key.sign_taproot(&sighash).map_err(|_| Error::BadKey)?;
            Ok(encode_witness(&[&sig]))
        }
        AddressKind::P2pkh | AddressKind::P2shP2wpkh => Err(Error::UnsupportedKind),
    }
}

/// Is `witness` this `challenge`'s signature on `message`?
///
/// `Ok(())` is the only "yes". Everything else says why not, and nothing here trusts a
/// claim made by the signature itself: the key comes out of the witness and has to hash
/// or tweak to the program the address commits to before its signature is even checked.
pub fn verify(message: &[u8], challenge_script: &[u8], witness: &[u8]) -> Result<(), Error> {
    // The script first, and the witness only once there is something it could satisfy: a
    // stack this cannot read is a different answer from a script this cannot check, and a
    // P2WSH file would otherwise be reported as a malformed signature.
    let challenge = classify(challenge_script)?;
    let stack = decode_witness(witness)?;
    match challenge {
        Challenge::P2wpkh(key_hash) => {
            if stack.count != 2 {
                return Err(Error::Malformed);
            }
            let (sig, pubkey) = (stack.items[0], stack.items[1]);
            let pubkey: &[u8; 33] = pubkey.try_into().map_err(|_| Error::Invalid)?;
            // The key has to be the one the address names before anything else happens.
            if hash160(pubkey) != *key_hash {
                return Err(Error::Invalid);
            }
            // The sighash byte is part of the signature and part of what was signed, so
            // it is checked rather than read: BIP-322 allows only SIGHASH_ALL here.
            let (&flag, der) = sig.split_last().ok_or(Error::Malformed)?;
            if u32::from(flag) != SIGHASH_ALL {
                return Err(Error::Invalid);
            }
            let (r, s) = parse_der_signature(der).map_err(|_| Error::Invalid)?;
            // LOW_S: the other half of every signature pair is equally valid arithmetic
            // and is not a valid Bitcoin signature. Accepting it would let anyone produce
            // a second distinct "signature" from one they were given.
            if !is_low_s(&s) {
                return Err(Error::Invalid);
            }
            let sighash = p2wpkh_sighash(message, challenge_script, key_hash)?;
            let key = SecpPublicKey::from_sec1(pubkey).map_err(|_| Error::Invalid)?;
            if key.verify(&sighash, &r, &s) {
                Ok(())
            } else {
                Err(Error::Invalid)
            }
        }
        Challenge::P2tr(output_key) => {
            if stack.count != 1 {
                return Err(Error::Malformed);
            }
            let item = stack.items[0];
            // 64 bytes is SIGHASH_DEFAULT; 65 carries the type, and BIP-341 makes an
            // explicit 0x00 invalid, so SIGHASH_ALL is the only byte that can appear.
            let (sig, hash_type) = match item.len() {
                64 => (item, 0x00u8),
                65 => (&item[..64], item[64]),
                _ => return Err(Error::Malformed),
            };
            if hash_type != 0x00 && u32::from(hash_type) != SIGHASH_ALL {
                return Err(Error::Invalid);
            }
            if item.len() == 65 && hash_type == 0x00 {
                return Err(Error::Invalid);
            }
            let sighash = p2tr_sighash(message, challenge_script, hash_type)?;
            let sig: &[u8; 64] = sig.try_into().map_err(|_| Error::Malformed)?;
            if bip340_verify(output_key, &sighash, sig) {
                Ok(())
            } else {
                Err(Error::Invalid)
            }
        }
    }
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

/// Decode the armoured form of a *simple* signature into its witness bytes.
///
/// The `smp` prefix is required of a signer and optional of a verifier: BIP-322 says a
/// verifier "might assume the simple variant in the absence of a prefix", and its own
/// vectors include one written before the prefix existed. A `ful` or `pof` prefix is a
/// variant this does not implement and says so, rather than trying to read it as base64.
pub fn dearmour(text: &str, out: &mut [u8]) -> Result<usize, Error> {
    let text = text.trim();
    let body = match text.get(..PREFIX.len()) {
        Some(PREFIX) => &text[PREFIX.len()..],
        Some("ful") | Some("pof") => return Err(Error::UnsupportedKind),
        _ => text,
    };
    outscript::base64::decode_to_slice(body, out).map_err(|_| Error::Malformed)
}

/// Check an armoured *simple* signature against a message and a scriptPubKey.
pub fn verify_armoured(message: &[u8], challenge_script: &[u8], text: &str) -> Result<(), Error> {
    classify(challenge_script)?;
    let mut witness = [0u8; MAX_WITNESS];
    let n = dearmour(text, &mut witness)?;
    verify(message, challenge_script, &witness[..n])
}

#[cfg(test)]
mod tests;
