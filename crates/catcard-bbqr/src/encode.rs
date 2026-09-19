//! Writing BBQr parts, for showing a file on the screen rather than reading one.
//!
//! The export direction, and the one that has to come first: a watch-only wallet cannot
//! send a PSBT to this device until it has been told which keys the device holds.
//!
//! # Every character is alphanumeric, which is the point
//!
//! QR's *alphanumeric* mode holds 4,296 characters in the largest symbol against 2,953
//! bytes in byte mode, and it covers `0-9 A-Z` and a handful of symbols including `$`.
//! A BBQr line is `B$`, a letter, a digit or letter, four base36 digits and then base32
//! -- upper case and digits throughout. So the whole line encodes in the dense mode
//! without anything having to arrange it, which is most of why this format is worth
//! preferring over one that spells bytes in lower-case words.

use crate::{Encoding, Error, FileType, HEADER_LEN};

/// RFC 4648's alphabet, which is what [`Encoding::Base32`] means.
const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
/// Base36, for the two-character part counts.
const B36: &[u8; 36] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// Characters a part of `bytes` bytes will occupy, header included.
pub const fn encoded_len(bytes: usize) -> usize {
    // Five bytes become eight characters; a partial group still needs its characters.
    HEADER_LEN + (bytes * 8).div_ceil(5)
}

/// The most bytes a part may carry if its line must fit `chars` characters.
///
/// For choosing a part size from what the screen can draw legibly, rather than from
/// what a symbol could theoretically hold.
pub const fn fits(chars: usize) -> usize {
    if chars <= HEADER_LEN {
        return 0;
    }
    // The inverse of `encoded_len`: eight characters carry five bytes.
    (chars - HEADER_LEN) / 8 * 5
}

/// How many parts a file of `len` bytes needs at `per` bytes each.
pub const fn parts_needed(len: usize, per: usize) -> usize {
    if per == 0 {
        return 0;
    }
    // A file of nothing is still one part, or there would be nothing to show.
    if len == 0 { 1 } else { len.div_ceil(per) }
}

/// Write one part's line into `out`, returning how many characters it took.
///
/// `chunk` is this part's slice of the file: `total` and `index` describe where it sits,
/// and every part but the last must be the same length -- that is what lets a reader
/// place a part it receives before the ones in front of it.
pub fn part(
    chunk: &[u8],
    filetype: FileType,
    total: u16,
    index: u16,
    out: &mut [u8],
) -> Result<usize, Error> {
    // Two base36 digits, so a file is at most 1296 parts and an index below its total.
    if total == 0 || index >= total || total as usize > 36 * 36 {
        return Err(Error::Numbering);
    }
    let need = encoded_len(chunk.len());
    if need > out.len() {
        return Err(Error::TooLong);
    }

    out[0] = b'B';
    out[1] = b'$';
    out[2] = b'2'; // base32; `H` and `Z` are not written
    out[3] = filetype.0;
    out[4] = B36[total as usize / 36];
    out[5] = B36[total as usize % 36];
    out[6] = B36[index as usize / 36];
    out[7] = B36[index as usize % 36];

    // Five bits at a time out of a bit accumulator, most significant first.
    let (mut acc, mut bits, mut at) = (0u32, 0u32, HEADER_LEN);
    for &b in chunk {
        acc = acc << 8 | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out[at] = B32[((acc >> bits) & 31) as usize];
            at += 1;
        }
    }
    if bits > 0 {
        // The last characters carry the remaining bits, padded with zeroes -- which is
        // what the reader checks for, so they must actually be zero.
        out[at] = B32[((acc << (5 - bits)) & 31) as usize];
        at += 1;
    }
    debug_assert_eq!(at, need);
    Ok(at)
}

/// The encoding these parts are written in. Stated so a caller reading the module can
/// see that the writer and the reader agree.
pub const WRITES: Encoding = Encoding::Base32;
