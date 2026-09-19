//! Just enough CBOR to read a multi-part UR header.
//!
//! A part is `[seqNum, seqLen, messageLen, checksum, data]` -- four unsigned integers
//! and a byte string, in a definite-length array of five. That is the whole grammar
//! this needs, so that is the whole grammar it has: no maps, no tags, no indefinite
//! lengths, no floats, nothing nested. Anything else is refused.
//!
//! A general CBOR reader would be more code and more surface in the path that decides
//! what gets signed, to parse shapes that a conforming sender never produces.
//!
//! Source: BCR-2024-001 for the array, RFC 8949 for the encoding.

use crate::Part;

/// What the bytes are not.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Ran out of bytes part way through a value.
    Short,
    /// A major type or additional-information value this does not read.
    Unsupported(u8),
    /// Not an array of exactly five elements.
    NotAPart,
    /// An integer too large for the field it belongs to.
    TooLarge,
}

/// Read one unsigned integer, returning it and what follows.
fn uint(at: &[u8]) -> Result<(u64, &[u8]), Error> {
    let (&head, rest) = at.split_first().ok_or(Error::Short)?;
    // Major type 0 is an unsigned integer; anything else here is not a part.
    if head >> 5 != 0 {
        return Err(Error::Unsupported(head));
    }
    read_count(head & 0x1F, rest)
}

/// The count an item's additional-information field encodes, and what follows it.
fn read_count(info: u8, rest: &[u8]) -> Result<(u64, &[u8]), Error> {
    let width = match info {
        0..=23 => return Ok((info as u64, rest)),
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        // 28..=30 are reserved; 31 is an indefinite length, which a part never has.
        other => return Err(Error::Unsupported(other)),
    };
    if rest.len() < width {
        return Err(Error::Short);
    }
    let (bytes, rest) = rest.split_at(width);
    let mut n = 0u64;
    for &b in bytes {
        n = n << 8 | b as u64;
    }
    Ok((n, rest))
}

/// Read a multi-part UR header, returning it and the range of `data` within `buf`.
///
/// A range rather than a slice: the caller owns the buffer and often wants to keep
/// using it, and handing back a borrow of it would stop that for no reason.
pub fn part(buf: &[u8]) -> Result<(Part, core::ops::Range<usize>), Error> {
    let (&head, rest) = buf.split_first().ok_or(Error::Short)?;
    // Major type 4 is an array, and a part is five elements.
    if head >> 5 != 4 {
        return Err(Error::NotAPart);
    }
    let (count, rest) = read_count(head & 0x1F, rest)?;
    if count != 5 {
        return Err(Error::NotAPart);
    }

    let (seq_num, rest) = uint(rest)?;
    let (seq_len, rest) = uint(rest)?;
    let (message_len, rest) = uint(rest)?;
    let (checksum, rest) = uint(rest)?;

    // The fifth element is the fragment, major type 2.
    let (&head, after) = rest.split_first().ok_or(Error::Short)?;
    if head >> 5 != 2 {
        return Err(Error::NotAPart);
    }
    let (len, after) = read_count(head & 0x1F, after)?;
    let len = usize::try_from(len).map_err(|_| Error::TooLarge)?;
    if after.len() < len {
        return Err(Error::Short);
    }
    // Where that landed in the original buffer.
    let start = buf.len() - after.len();

    Ok((
        Part {
            seq_num: u32::try_from(seq_num).map_err(|_| Error::TooLarge)?,
            seq_len: u32::try_from(seq_len).map_err(|_| Error::TooLarge)?,
            message_len: u32::try_from(message_len).map_err(|_| Error::TooLarge)?,
            checksum: u32::try_from(checksum).map_err(|_| Error::TooLarge)?,
        },
        start..start + len,
    ))
}
