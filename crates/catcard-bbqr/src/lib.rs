//! Placing BBQr parts as they are caught, without holding on to any of them.
//!
//! The format itself -- headers, base32, hex, deflate -- is [`outscript::bbqr`]. What is
//! here is the one thing that crate deliberately does not do without an allocator: work
//! out *where* a part belongs so it can be written straight to its destination and
//! forgotten.
//!
//! # Why not `outscript::bbqr::Joiner`
//!
//! `Joiner` keeps every part in a `Vec<Vec<u8>>` until the file is whole, which is the
//! right shape on a host and impossible here: the largest thing this device reads by QR
//! is a firmware image, and the only memory it fits in is the staging area it is being
//! written into. There is nowhere to hold a second copy.
//!
//! So [`Collector`] holds no data at all -- a bitmap of which parts have been seen, and
//! the part length, which is all that is needed to turn an index into an offset. Each
//! part is decoded once, straight to where it goes.
//!
//! # `accept` then `confirm`, in that order
//!
//! A part is counted only once the caller has actually stored it. A collector that
//! counted on sight would report a complete file after a write that failed, and for a
//! firmware image the only remaining check would be the signature.
//!
//! # `Z` reassembles a stream, not a file
//!
//! [`Encoding::Zlib`] deflates the whole file and only then cuts it up, so the parts
//! place and reassemble exactly as any others do -- what comes out is the compressed
//! stream. [`Collector::compressed`] says so; expanding it is the caller's, because
//! only the caller knows where the bytes landed and what it can spend.
//!
//! # Where the bytes go is the caller's business
//!
//! Two consumers want different destinations: a firmware image goes to the staging area,
//! which takes whole words at an offset; a PSBT goes into a plain buffer. So `accept`
//! says where a part belongs and leaves the decoding to the caller, and [`Collector::take`]
//! is the convenience for the buffer case.

#![no_std]

pub use outscript::bbqr::{
    Encoding, FileType, HEADER_LEN, Header, MAX_PARTS, decode_part_to_slice, decoded_len_bound,
    encode_part_to_slice, encoded_len,
};

/// What went wrong with a part.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// The format itself refused it: not a header, bad base32, an index out of range.
    Codec(outscript::bbqr::Error),
    /// This part disagrees with the ones already seen about what file this is.
    Mismatch,
    /// The payload decodes to more than the caller left room for.
    TooLong,
    /// The last part arrived before any other, so there is nothing to measure a full
    /// part against and its offset is not yet knowable. Keep scanning.
    PartLenUnknown,
}

impl From<outscript::bbqr::Error> for Error {
    fn from(e: outscript::bbqr::Error) -> Self {
        Error::Codec(e)
    }
}

/// Where a part belongs, and how far along the file is.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Placed {
    /// Zero-based part number.
    pub index: u16,
    /// Where its bytes go in the file.
    pub offset: usize,
    /// How many bytes it carried.
    pub len: usize,
    /// True if this part had not been seen before.
    pub fresh: bool,
    /// Parts seen so far, and how many there are in all.
    pub have: u16,
    pub total: u16,
}

/// Which parts of one file have arrived.
pub struct Collector {
    /// What every part agrees on. Its `index` is not meaningful.
    header: Option<Header>,
    /// The length of a full part, learned from the first one that is not the last.
    part_len: usize,
    /// The last part's length, which is the only one that may be short.
    last_len: usize,
    seen: [u64; MAX_PARTS.div_ceil(64)],
    count: u16,
}

impl Default for Collector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector {
    pub const fn new() -> Self {
        Collector {
            header: None,
            part_len: 0,
            last_len: 0,
            seen: [0; MAX_PARTS.div_ceil(64)],
            count: 0,
        }
    }

    /// Forget everything, so a different file can be read.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// What is being collected, once a part has been seen.
    pub fn header(&self) -> Option<Header> {
        self.header
    }

    /// Whether what is being collected is a deflate stream rather than the file.
    ///
    /// `Z` compresses the whole file before cutting it up, so the parts reassemble into
    /// something that still has to be expanded. Nothing here does that -- the caller
    /// knows where the bytes went and what it can spend on expanding them.
    pub fn compressed(&self) -> bool {
        self.header.is_some_and(|h| h.encoding == Encoding::Zlib)
    }

    /// Whether every part has been seen.
    pub fn complete(&self) -> bool {
        self.header.is_some_and(|h| self.count == h.num_parts)
    }

    /// Parts seen so far.
    pub fn have(&self) -> u16 {
        self.count
    }

    /// Work out where a part belongs, without storing it.
    ///
    /// Does **not** count the part; [`confirm`](Self::confirm) does, once the caller has
    /// written it.
    pub fn accept(&mut self, line: &str) -> Result<Placed, Error> {
        let (header, body) = Header::parse(line)?;
        // A body of a length that cannot decode is refused here, before anything is
        // learned from it. `decoded_len_bound` floors, so a body one character long
        // still yields a length -- and a length committed as `part_len` from a part
        // that then fails to decode is a measure no correct part will ever match. The
        // scan would refuse every one of them as `Mismatch` and never complete, from
        // one damaged frame. The rule is the codec's: hex is whole pairs, and base32
        // without padding has no group of 1, 3 or 6 characters.
        let decodable = match header.encoding {
            Encoding::Hex => body.len().is_multiple_of(2),
            Encoding::Base32 | Encoding::Zlib => !matches!(body.len() % 8, 1 | 3 | 6),
        };
        if !decodable {
            return Err(Error::Codec(outscript::bbqr::Error::InvalidEncoding));
        }
        let len = decoded_len_bound(header.encoding, body.len());
        let is_last = header.index + 1 == header.num_parts;

        match self.header {
            None => self.header = Some(Header { index: 0, ..header }),
            Some(seen) => {
                // The same file, or a different one. Everything but the index agrees.
                if seen != (Header { index: 0, ..header }) {
                    return Err(Error::Mismatch);
                }
            }
        }

        if !is_last {
            match self.part_len {
                0 => self.part_len = len,
                known if known != len => return Err(Error::Mismatch),
                _ => {}
            }
        } else if header.index == 0 {
            // Both the first part and the last: the whole file is this one code, so its
            // offset is zero and there is nothing to measure it against. Without this a
            // single-code file -- which most wallet exports are -- waits forever for a
            // full part that is never coming.
            self.part_len = len;
        } else if self.part_len == 0 {
            // The last part, and nothing to measure it against yet.
            return Err(Error::PartLenUnknown);
        } else if len > self.part_len {
            // A "last" part longer than a full one is not this file's last part.
            return Err(Error::Mismatch);
        }

        let offset = self.part_len * header.index as usize;
        offset.checked_add(len).ok_or(Error::TooLong)?;

        let bit = 1u64 << (header.index % 64);
        let fresh = self.seen[header.index as usize / 64] & bit == 0;
        Ok(Placed {
            index: header.index,
            offset,
            len,
            fresh,
            have: self.count,
            total: header.num_parts,
        })
    }

    /// Record that a part accepted by [`accept`](Self::accept) has been written.
    ///
    /// Returns what the count is now, with `fresh` saying whether this was the first
    /// sighting -- the animation loops, so most parts are confirmed many times.
    pub fn confirm(&mut self, placed: Placed) -> Placed {
        if placed.index + 1 == placed.total {
            self.last_len = placed.len;
        }
        let bit = 1u64 << (placed.index % 64);
        let word = placed.index as usize / 64;
        let fresh = self.seen[word] & bit == 0;
        if fresh {
            self.seen[word] |= bit;
            self.count += 1;
        }
        Placed {
            fresh,
            have: self.count,
            ..placed
        }
    }

    /// Take one line, decoding it into `out` at the offset it belongs.
    ///
    /// The convenience for a caller filling one buffer. A firmware image does not use
    /// this -- it goes to the staging area a word at a time -- but a PSBT does.
    pub fn take(&mut self, line: &str, out: &mut [u8]) -> Result<Placed, Error> {
        let placed = self.accept(line)?;
        let end = placed.offset + placed.len;
        let room = out.get_mut(placed.offset..end).ok_or(Error::TooLong)?;
        decode_part_to_slice(line, room)?;
        Ok(self.confirm(placed))
    }

    /// The file's length, once every part has been seen.
    ///
    /// `None` until then: the last part is the only one that is not full, so until it
    /// has arrived the total is unknown however many others there are.
    pub fn file_len(&self) -> Option<usize> {
        let h = self.header?;
        self.complete()
            .then(|| self.part_len * (h.num_parts as usize - 1) + self.last_len)
    }
}

/// Characters a part of `bytes` bytes will occupy, header included.
pub const fn part_len(encoding: Encoding, bytes: usize) -> usize {
    HEADER_LEN + encoded_len(encoding, bytes)
}

/// The most bytes a part may carry if its line must fit `chars` characters.
///
/// For choosing a part size from what a screen can draw legibly, or from what a scanner
/// will hold, rather than from what a symbol could theoretically contain.
pub const fn fits(encoding: Encoding, chars: usize) -> usize {
    if chars <= HEADER_LEN {
        return 0;
    }
    let body = chars - HEADER_LEN;
    match encoding {
        Encoding::Hex => body / 2,
        // Eight characters carry five bytes, and a part that is not the last must be a
        // whole number of groups or the ones after it do not line up.
        Encoding::Base32 | Encoding::Zlib => body / 8 * 5,
    }
}

/// How many parts a file of `len` bytes needs at `per` bytes each.
pub const fn parts_needed(len: usize, per: usize) -> usize {
    if per == 0 {
        return 0;
    }
    // A file of nothing is still one part, or there would be nothing to show.
    if len == 0 { 1 } else { len.div_ceil(per) }
}

#[cfg(test)]
mod tests;
