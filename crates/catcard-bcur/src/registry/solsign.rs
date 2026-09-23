//! `sol-sign-request` and `sol-signature`: being asked for a Solana signature, and
//! answering.
//!
//! Not a Blockchain Commons BCR. These two are Keystone's extension to the registry, and
//! they are what a wallet that talks to an air-gapped Solana signer actually emits --
//! `@keystonehq/bc-ur-registry-sol`, which is where the tags and map keys below come
//! from. [C] Read from that package's `RegistryType.ts` and `SolSignRequest.ts`.
//!
//! # What the shape says about the exchange
//!
//! The answer carries a signature and nothing else: no transaction, no message. So the
//! side that asked is the side that reassembles, and this device never has to send back
//! the kilobyte it received. That is also why `sign_data` is the bytes to sign rather
//! than a transaction -- the request says *what to sign*, and what to do with the result
//! is the asker's problem.
//!
//! What it does not say is whether those bytes are a whole transaction or just its
//! message, and both are in the wild. Deciding is left to the caller, which can try one
//! reading and fall back to the other -- the same "decide by parsing" test the rest of
//! this firmware uses, rather than a guess dressed up as a constant.

use super::{Error, TAG_UUID, bounded, optional_tag};
use crate::cbor::{Reader, Writer};
use crate::registry::hdkey::KeyPath;

/// `sol-sign-request`. [C] `@keystonehq/bc-ur-registry-sol`
pub const TAG_SOL_SIGN_REQUEST: u64 = 1101;
/// `sol-signature`. [C] `@keystonehq/bc-ur-registry-sol`
pub const TAG_SOL_SIGNATURE: u64 = 1102;

/// What the request is asking to have signed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SignType {
    /// A transaction, or the message inside one. [C] `SignType.Transaction = 1`
    Transaction,
    /// An off-chain message. [C] `SignType.Message = 2`
    Message,
    /// A value this build has not been written against. Carried rather than refused
    /// here, so the screen can say what it was asked for instead of "bad request".
    Other(u64),
}

/// A request for a signature, borrowed from the message it arrived in.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignRequest<'a> {
    /// The asker's handle for this request, echoed back in the answer so it can be
    /// matched to what it was asked about. Sixteen bytes of UUID when present.
    pub request_id: Option<&'a [u8]>,
    /// The bytes to sign.
    pub sign_data: &'a [u8],
    /// Which key is being asked for.
    pub path: KeyPath,
    /// The address the asker expects that key to be, when it says: 32 bytes of ed25519
    /// public key. Worth checking rather than trusting -- if it is not the key this
    /// device would derive, one of the two sides is wrong about whose signature this is.
    pub address: Option<&'a [u8]>,
    /// Transaction or message.
    pub sign_type: SignType,
}

// Map keys. [C] `SolSignRequest.ts`, `enum Keys`.
const REQUEST_ID: u64 = 1;
const SIGN_DATA: u64 = 2;
const DERIVATION_PATH: u64 = 3;
const ADDRESS: u64 = 4;
// `origin` (5) is read past rather than kept: it is a string chosen by whoever built
// the QR, and a familiar name on the screen beside a transaction is worth more to
// somebody forging one than it is to the person reading.
const SIGN_TYPE: u64 = 6;

/// Read a `sol-sign-request`.
pub fn decode(message: &[u8]) -> Result<SignRequest<'_>, Error> {
    let mut r = Reader::new(message);
    // Untagged at the top level of a UR, tagged when embedded. Reading its own tag costs
    // nothing and cannot turn one item into another.
    optional_tag(&mut r, [TAG_SOL_SIGN_REQUEST, TAG_SOL_SIGN_REQUEST])?;
    let pairs = r.map()?;

    let mut request_id = None;
    let mut sign_data = None;
    let mut path = None;
    let mut address = None;
    let mut sign_type = None;
    for _ in 0..bounded(pairs)? {
        match r.uint()? {
            REQUEST_ID => {
                optional_tag(&mut r, [TAG_UUID, TAG_UUID])?;
                request_id = Some(r.bytes()?);
            }
            SIGN_DATA => sign_data = Some(r.bytes()?),
            DERIVATION_PATH => path = Some(KeyPath::read(&mut r)?),
            ADDRESS => address = Some(r.bytes()?),
            SIGN_TYPE => {
                sign_type = Some(match r.uint()? {
                    1 => SignType::Transaction,
                    2 => SignType::Message,
                    other => SignType::Other(other),
                });
            }
            // `origin`, and anything a later revision adds.
            _ => r.skip()?,
        }
    }

    let sign_data = sign_data.ok_or(Error::Field(SIGN_DATA as u8))?;
    // Without a path there is no saying which key was asked for, and signing with the
    // one this device happens to prefer would be answering a question nobody asked.
    let path = path.ok_or(Error::Field(DERIVATION_PATH as u8))?;
    // Not defaulted. A request that does not say whether those bytes are a transaction
    // or a message is a request this device cannot answer safely: the two are signed the
    // same way, and only the asker knows which it will treat the answer as.
    let sign_type = sign_type.ok_or(Error::Field(SIGN_TYPE as u8))?;
    if !r.at_end() {
        return Err(Error::Trailing);
    }
    Ok(SignRequest {
        request_id,
        sign_data,
        path,
        address,
        sign_type,
    })
}

/// Bytes an answer takes, for a caller sizing a buffer.
pub const fn signature_len(request_id: usize) -> usize {
    // A map of one or two pairs, each key one byte. The signature is a 64-byte string
    // (two bytes of head); a request id is tagged (two bytes) and at most 16 bytes.
    let id = if request_id == 0 {
        0
    } else {
        1 + 2 + 2 + request_id
    };
    1 + 1 + 2 + 64 + id
}

/// Write a `sol-signature`: the signature, and the handle it answers.
pub fn encode_signature(
    signature: &[u8; 64],
    request_id: Option<&[u8]>,
    out: &mut [u8],
) -> Result<usize, Error> {
    let mut w = Writer::new(out);
    w.map(1 + u64::from(request_id.is_some()))?;
    if let Some(id) = request_id {
        w.uint(REQUEST_ID)?;
        w.tag(TAG_UUID)?;
        w.bytes(id)?;
    }
    w.uint(SIGNATURE)?;
    w.bytes(signature)?;
    Ok(w.len())
}

// Map keys of the answer. [C] `SolSignature.ts`, `enum Keys`.
const SIGNATURE: u64 = 2;
