//! BBQr: one file split across a series of QR codes.
//!
//! A QR code holds a few kilobytes at most, so anything larger arrives as a sequence of
//! them shown in turn while the scanner watches. BBQr is the format Coldcard's tooling
//! writes for that, and this reads it.
//!
//! Each code carries one line:
//!
//! ```text
//! B$ <encoding> <filetype> <total> <index> <payload>
//!    1 char     1 char     2 chars 2 chars
//! ```
//!
//! `total` and `index` are base36 (`0-9A-Z`), so a file can be up to 1296 parts and the
//! index is zero-based. Every part of a file agrees on the header but for its index, and
//! every part but the last carries the same number of payload bytes -- which is what
//! lets a part be placed without having seen the ones before it.
//!
//! # `Z` is deferred, and which payload you are carrying decides whether that matters
//!
//! [`Encoding::Base32`] and [`Encoding::Hex`] are read. `Z` -- deflate, then base32 --
//! is not, **yet**, and the reason is about size rather than about the format.
//!
//! `Z` compresses the whole file before splitting it, so no part decodes on its own:
//! the entire compressed stream must be reassembled before any of it becomes data. For
//! a **firmware image** that is a third of a megabyte, and the only place it fits is the
//! PSRAM the image is being staged into -- so inflating would read that part while
//! writing to it, and interleaved reads and writes are the documented way to corrupt it
//! (`hw-reference/storage.md`). Uncompressed, a part decodes straight to its offset and
//! is forgotten.
//!
//! For a **PSBT** none of that applies. A few kilobytes of compressed stream sits in the
//! heap, and inflating from there into the signing workspace reads SRAM and writes
//! PSRAM, which is not the pattern that corrupts anything. PSBTs also compress well, so
//! `Z` is the encoding that matters for them and is worth adding when they arrive.
//!
//! # Where the bytes go is the caller's business
//!
//! Two consumers want different destinations: a firmware image goes to the staging area
//! through `Staged::place`, which takes whole words at an offset; a PSBT goes into a
//! plain buffer. So [`Collector::accept`] works out *where* a part belongs and hands
//! back its still-encoded payload, leaving the caller to decode it wherever it likes.
//! [`Collector::take`] is the convenience for the buffer case.

#![no_std]

pub mod encode;

/// What a line is not.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Not a BBQr line at all: no `B$`, or too short to hold a header.
    NotBbqr,
    /// The encoding character is not one this reads.
    Encoding(u8),
    /// `total` or `index` is not base36, or the index is not below the total.
    Numbering,
    /// The payload is not valid for its encoding, or is not a whole number of bytes.
    Payload,
    /// The payload decodes to more than the caller left room for.
    TooLong,
    /// This part disagrees with the ones already seen about what file this is.
    Mismatch,
    /// The last part arrived before any other, so there is nothing to measure a full
    /// part against and its offset is not yet knowable. Keep scanning.
    PartLenUnknown,
}

/// How a part's payload is written.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Encoding {
    /// RFC 4648 base32, no padding. Alphanumeric, which is the QR mode that fits most.
    Base32,
    /// Plain hex, upper case. Half the density; accepted because it is trivial to make.
    Hex,
}

/// What kind of file the parts carry. Passed through rather than acted on, except that
/// a screen expecting one kind should refuse another.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct FileType(pub u8);

impl FileType {
    /// A firmware image, as `catcard-image` writes it.
    pub const BINARY: FileType = FileType(b'B');
    /// An executable, which some tools use for the same thing.
    pub const EXECUTABLE: FileType = FileType(b'X');
    /// A PSBT.
    pub const PSBT: FileType = FileType(b'P');
}

/// A part's header: which file, how many parts, and which one this is.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Header {
    pub encoding: Encoding,
    pub filetype: FileType,
    pub total: u16,
    pub index: u16,
}

/// Bytes of header before the payload.
pub const HEADER_LEN: usize = 8;

/// One base36 digit.
fn base36(c: u8) -> Option<u16> {
    match c {
        b'0'..=b'9' => Some((c - b'0') as u16),
        b'A'..=b'Z' => Some((c - b'A') as u16 + 10),
        _ => None,
    }
}

/// Split a line into its header and its still-encoded payload.
pub fn parse(line: &[u8]) -> Result<(Header, &[u8]), Error> {
    if line.len() < HEADER_LEN || &line[..2] != b"B$" {
        return Err(Error::NotBbqr);
    }
    let encoding = match line[2] {
        b'2' => Encoding::Base32,
        b'H' => Encoding::Hex,
        other => return Err(Error::Encoding(other)),
    };
    let total = base36(line[4])
        .zip(base36(line[5]))
        .map(|(a, b)| a * 36 + b)
        .ok_or(Error::Numbering)?;
    let index = base36(line[6])
        .zip(base36(line[7]))
        .map(|(a, b)| a * 36 + b)
        .ok_or(Error::Numbering)?;
    // A file of no parts, or a part past the end, describes nothing that can be
    // assembled. Caught here so no caller has to wonder whether it was checked.
    if total == 0 || index >= total {
        return Err(Error::Numbering);
    }
    Ok((
        Header {
            encoding,
            filetype: FileType(line[3]),
            total,
            index,
        },
        &line[HEADER_LEN..],
    ))
}

/// How many bytes `payload` will decode to, without decoding it.
///
/// For deciding whether it fits before writing any of it.
pub fn decoded_len(encoding: Encoding, payload: &[u8]) -> Result<usize, Error> {
    match encoding {
        // Five bytes per eight characters. Anything else is a part that was cut.
        Encoding::Base32 => match payload.len() % 8 {
            0 => Ok(payload.len() / 8 * 5),
            // The tail lengths base32 can legitimately end on, and what each carries.
            2 => Ok(payload.len() / 8 * 5 + 1),
            4 => Ok(payload.len() / 8 * 5 + 2),
            5 => Ok(payload.len() / 8 * 5 + 3),
            7 => Ok(payload.len() / 8 * 5 + 4),
            _ => Err(Error::Payload),
        },
        Encoding::Hex => payload
            .len()
            .is_multiple_of(2)
            .then_some(payload.len() / 2)
            .ok_or(Error::Payload),
    }
}

/// Decode `payload` into `out`, returning how many bytes it produced.
pub fn decode(encoding: Encoding, payload: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let need = decoded_len(encoding, payload)?;
    if need > out.len() {
        return Err(Error::TooLong);
    }
    match encoding {
        Encoding::Base32 => decode_base32(payload, &mut out[..need]),
        Encoding::Hex => decode_hex(payload, &mut out[..need]),
    }?;
    Ok(need)
}

/// One base32 character, RFC 4648: `A-Z` then `2-7`.
fn b32(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'2'..=b'7' => Some((c - b'2') as u32 + 26),
        _ => None,
    }
}

fn decode_base32(payload: &[u8], out: &mut [u8]) -> Result<(), Error> {
    // Five bits at a time into a bit accumulator, a byte out whenever eight are in.
    let (mut acc, mut bits, mut at) = (0u32, 0u32, 0usize);
    for &c in payload {
        acc = (acc << 5) | b32(c).ok_or(Error::Payload)?;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            let byte = (acc >> bits) as u8;
            // The final characters of a part can carry padding bits beyond the last
            // whole byte; those are dropped rather than written past the end.
            if at < out.len() {
                out[at] = byte;
                at += 1;
            }
            acc &= (1 << bits) - 1;
        }
    }
    // Whatever is left is padding, and padding must be zero. A non-zero tail means the
    // characters were not produced by this encoding, and taking it anyway would accept
    // a part that had been altered.
    if acc != 0 {
        return Err(Error::Payload);
    }
    (at == out.len()).then_some(()).ok_or(Error::Payload)
}

fn decode_hex(payload: &[u8], out: &mut [u8]) -> Result<(), Error> {
    fn nib(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'A'..=b'F' => Some(c - b'A' + 10),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    }
    for (slot, pair) in out.iter_mut().zip(payload.chunks(2)) {
        let hi = nib(pair[0]).ok_or(Error::Payload)?;
        let lo = nib(pair[1]).ok_or(Error::Payload)?;
        *slot = hi << 4 | lo;
    }
    Ok(())
}

/// The most parts a file can be split into: two base36 digits.
pub const MAX_PARTS: usize = 36 * 36;

/// Which parts of a file have been seen, and where the next one belongs.
///
/// Holds no data. A part is decoded straight into whatever the caller is filling --
/// which for a firmware image is the staging area -- so nothing here grows with the
/// size of the file.
pub struct Collector {
    header: Option<Header>,
    /// The payload length of a full part, learned from the first one seen. Every part
    /// but the last carries this much, which is what makes an index an offset.
    part_len: usize,
    /// The last part's length, which with `part_len` gives the file's size.
    last_len: usize,
    seen: [u64; MAX_PARTS / 64],
    count: u16,
}

/// What a part turned out to be.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Placed {
    /// Which part this is, zero-based.
    pub index: u16,
    /// Where its bytes belong in the file.
    pub offset: usize,
    /// How many bytes it carried.
    pub len: usize,
    /// True if this part had not been seen before.
    pub fresh: bool,
    /// Parts seen so far, and how many there are in all.
    pub have: u16,
    pub total: u16,
}

impl Collector {
    pub const fn new() -> Self {
        Collector {
            header: None,
            part_len: 0,
            last_len: 0,
            seen: [0; MAX_PARTS / 64],
            count: 0,
        }
    }

    /// Forget everything, so a different file can be read.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// The header of the file being collected, once a part has been seen.
    pub fn header(&self) -> Option<Header> {
        self.header
    }

    /// Whether every part has been seen.
    pub fn complete(&self) -> bool {
        self.header.is_some_and(|h| self.count == h.total)
    }

    /// Parts seen so far.
    pub fn have(&self) -> u16 {
        self.count
    }

    /// Work out where a part belongs, without decoding it.
    ///
    /// Returns the placement and the part's still-encoded payload, so the caller can
    /// decode it into whatever it is filling -- a buffer, or a staging area that takes
    /// words at an offset. [`take`](Self::take) is the same thing for the simple case.
    ///
    /// This does **not** count the part. [`confirm`](Self::confirm) does, once the
    /// caller has actually written it.
    ///
    /// That way round on purpose. A caller that forgets to confirm gets a scan that
    /// never finishes, which is irritating; a collector that counted a part whose write
    /// then failed would report a complete file with a hole in it, and for a firmware
    /// image that is an install whose only remaining check is the signature.
    pub fn accept<'a>(&mut self, line: &'a [u8]) -> Result<(Placed, &'a [u8]), Error> {
        let (header, payload) = parse(line)?;
        let len = decoded_len(header.encoding, payload)?;
        let is_last = header.index + 1 == header.total;

        match self.header {
            None => self.header = Some(header),
            Some(seen) => {
                // The same file, or a different one. Everything but the index agrees.
                if (seen.encoding, seen.filetype, seen.total)
                    != (header.encoding, header.filetype, header.total)
                {
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
        Ok((
            Placed {
                index: header.index,
                offset,
                len,
                fresh,
                have: self.count,
                total: header.total,
            },
            payload,
        ))
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

    /// Take one line, decoding its payload into `out` at the offset it belongs.
    ///
    /// The convenience for a caller filling one buffer. A firmware image does not use
    /// this -- it goes to the staging area a word at a time -- but a PSBT does.
    pub fn take(&mut self, line: &[u8], out: &mut [u8]) -> Result<Placed, Error> {
        let (placed, payload) = self.accept(line)?;
        let end = placed.offset + placed.len;
        if end > out.len() {
            return Err(Error::TooLong);
        }
        let encoding = self.header.expect("accept set it").encoding;
        decode(encoding, payload, &mut out[placed.offset..end])?;
        Ok(self.confirm(placed))
    }

    /// The file's length, once every part has been seen.
    ///
    /// `None` until then: the last part is the only one that is not full, so until it
    /// has arrived the total is unknown however many others there are.
    pub fn file_len(&self) -> Option<usize> {
        let h = self.header?;
        self.complete()
            .then(|| self.part_len * (h.total as usize - 1) + self.last_len)
    }
}

impl Default for Collector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
