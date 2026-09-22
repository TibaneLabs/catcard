//! `bytes` and `crypto-psbt`: a registry item that is one CBOR byte string.
//!
//! `bytes` is an opaque payload; `psbt` is "a single, deterministic length byte string
//! ... a valid Partially Signed Bitcoin Transaction encoded in the binary format
//! specified by BIP-174". [C] BCR-2020-006 §"Partially Signed Bitcoin Transaction
//! (PSBT) `psbt`". Same shape, so the same codec, and the UR type is what distinguishes
//! them.
//!
//! This is the gap that mattered most: without it a scanned `crypto-psbt` reaches the
//! signing path as `58 a7 70 73 62 74 ff ...` -- the PSBT with a two-byte CBOR header
//! in front of it, which is not a PSBT.

use super::{Error, TAG_PSBT_V1, TAG_PSBT_V2, optional_tag};
use crate::cbor::{self, Reader, Writer};

/// The payload of a `bytes` or `crypto-psbt` message, borrowed from it.
///
/// Refuses anything after the byte string: a message with a tail is not this item, and
/// silently ignoring the tail would let a sender append to a document the user approved.
pub fn decode(message: &[u8]) -> Result<&[u8], Error> {
    let mut r = Reader::new(message);
    // `bytes` has no tag of its own. A `psbt` embedded elsewhere would carry #6.310 or
    // #6.40310; at the top level of a UR it must not, but reading one is free.
    optional_tag(&mut r, [TAG_PSBT_V1, TAG_PSBT_V2])?;
    let data = r.bytes()?;
    if !r.at_end() {
        return Err(Error::Trailing);
    }
    Ok(data)
}

/// Bytes the encoded form of a `len`-byte payload will occupy.
pub const fn encoded_len(len: usize) -> usize {
    // A CBOR byte-string head is one byte up to length 23, then one plus the width of
    // the length. RFC 8949 §3. [C]
    let head = match len {
        0..=23 => 1,
        24..=0xFF => 2,
        0x100..=0xFFFF => 3,
        _ => 5,
    };
    head + len
}

/// Write `data` as the CBOR byte string a `bytes` or `crypto-psbt` message is.
pub fn encode(data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let mut w = Writer::new(out);
    w.bytes(data)?;
    Ok(w.len())
}

/// Whether a message looks like this item at all, without reading it.
///
/// Used where a guess has to be made cheaply; a real read is [`decode`].
pub fn is_byte_string(message: &[u8]) -> bool {
    message.first().is_some_and(|&h| h >> 5 == cbor::BYTES)
}
