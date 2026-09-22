//! Reading a PNG on a device that cannot hold one.
//!
//! A photograph off a microSD card is a few megabytes compressed and tens of megabytes
//! expanded; the screen it is going to is 320x240. Nothing here ever holds a whole
//! image, or even a whole expanded scanline of one at full width in more than two
//! copies: the file is pulled in a kilobyte at a time, pushed through the inflater a
//! kilobyte at a time, and what comes out the other side is reduced to the width of the
//! screen as it arrives. Peak memory is the deflate window plus two source scanlines
//! plus one output row, and it does not grow with the size of the picture.
//!
//! # The shape of it
//!
//! [`render`] drives everything. It pulls bytes with the caller's `read`, walks the
//! chunk structure, feeds `IDAT` into [`minizlib::Decompressor`], un-filters each
//! scanline as it completes, and hands finished output rows to the caller's `sink` in
//! top-to-bottom order. The caller sizes its buffers from [`Header`] and [`Plan`]
//! beforehand, so a picture too wide to read is refused before anything is allocated
//! rather than partway down the image.
//!
//! # Resizing, and why this filter
//!
//! **Area averaging.** Every output pixel is the average of exactly the source pixels
//! it covers, weighted by how much of each it covers. It is the right answer for
//! shrinking by a lot -- which is the case here, because anything from a camera is ten
//! or twenty times the width of the panel -- and, unlike nearest-neighbour, it cannot
//! drop a feature that happens to fall between sample points. Text in a screenshot
//! stays readable rather than turning into gravel.
//!
//! It is also the filter that fits the memory: the weights along a row depend only on
//! the column, and vertically each source row contributes to at most two output rows,
//! so the whole thing runs on one accumulator row. A filter with a wider kernel --
//! Lanczos, bicubic -- would need several source rows resident at once and would spend
//! its sharpness budget on an image that is about to be quantised to 16-bit colour
//! anyway.
//!
//! **Enlarging is nearest-neighbour, by whole steps only** ([`Scale::Up`]). A 27x30
//! icon on a 320x240 panel is drawn at 8x, crisp, rather than blurred up by a
//! fractional factor; anything that does not fit a whole number of times is left at 1:1
//! and centred. Smoothly enlarging a small picture invents detail that is not in the
//! file, and on a wallet screen that is the wrong instinct.
//!
//! The aspect ratio is kept in both directions; the caller is told the size it will get
//! and places it.
//!
//! # What it will not read
//!
//! Interlaced files ([`Error::Interlaced`]). Adam7 delivers the image as seven
//! interleaved passes, so a row of the picture is not finished until the last pass
//! reaches it -- which means holding the whole image, which is the one thing this
//! cannot do. Refused by name, so the screen can say why rather than showing a mess.
//!
//! Source: the PNG specification (W3C REC-png-3 / ISO 15948), §4 chunk layout, §9
//! filtering, §13.9 the filter-type byte. Public standard.

#![no_std]
#![forbid(unsafe_code)]

mod pixels;
mod resize;

#[cfg(test)]
mod tests;

pub use resize::{Plan, Scale, fit};

use minizlib::{Decompressor, Error as ZError, Stream, Zlib};

/// The eight bytes every PNG begins with. Source: PNG spec §5.2 [C]
pub const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

/// Bytes of history the inflater is given.
///
/// Deflate's window is at most 32 KiB and an encoder is free to use all of it, so
/// anything less is a file this cannot read -- and unlike BBQr, where both ends are
/// ours, nothing constrains what wrote the PNG. This is the one large buffer.
pub const WINDOW: usize = 32 * 1024;

/// How many bytes of the file [`header`] needs: the signature, the `IHDR` chunk header,
/// and its thirteen bytes of content.
pub const HEADER_BYTES: usize = 8 + 8 + 13;

/// Why a file could not be shown.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// It does not begin with the PNG signature.
    NotPng,
    /// It ended in the middle of something.
    Truncated,
    /// The header is not one this can make sense of: a zero dimension, a bit depth the
    /// colour type does not allow, an unknown colour type, or an unknown compression or
    /// filter method.
    BadHeader,
    /// Adam7 interlaced, which cannot be done a row at a time.
    Interlaced,
    /// The compressed data is damaged, or is not what it claims to be.
    Damaged,
    /// A chunk's CRC does not match its contents.
    BadCrc,
    /// A palette entry was used that the file never defined.
    BadPalette,
    /// Wider than the buffers given: the caller sized them for a different header.
    Buffers,
    /// The file could not be read: the card, not the picture.
    Read,
    /// The caller's sink refused a row: the screen, not the picture.
    Sink,
}

impl Error {
    /// The few words a screen has for it.
    pub fn why(self) -> &'static str {
        match self {
            Error::NotPng => "not a PNG file",
            Error::Truncated => "the file ends early",
            Error::BadHeader => "this PNG is not one we can read",
            Error::Interlaced => "interlaced PNGs are not supported",
            Error::Damaged => "the image data is damaged",
            Error::BadCrc => "the file is corrupt",
            Error::BadPalette => "the palette is incomplete",
            Error::Buffers => "not enough memory for this image",
            Error::Read => "the card stopped responding",
            Error::Sink => "the screen refused it",
        }
    }
}

/// How the samples in a file are laid out. Source: PNG spec §6.1, table 6.1 [C]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Colour {
    /// One greyscale sample. Type 0.
    Grey,
    /// Red, green, blue. Type 2.
    Rgb,
    /// One palette index, with `PLTE` giving the colours. Type 3.
    Indexed,
    /// Greyscale and alpha. Type 4.
    GreyAlpha,
    /// Red, green, blue and alpha. Type 6.
    Rgba,
}

impl Colour {
    /// Samples per pixel.
    pub const fn channels(self) -> usize {
        match self {
            Colour::Grey | Colour::Indexed => 1,
            Colour::GreyAlpha => 2,
            Colour::Rgb => 3,
            Colour::Rgba => 4,
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0 => Colour::Grey,
            2 => Colour::Rgb,
            3 => Colour::Indexed,
            4 => Colour::GreyAlpha,
            6 => Colour::Rgba,
            _ => return None,
        })
    }

    /// Whether a bit depth is allowed with this colour type. Source: spec table 6.1 [C]
    fn allows(self, depth: u8) -> bool {
        match self {
            Colour::Grey => matches!(depth, 1 | 2 | 4 | 8 | 16),
            Colour::Indexed => matches!(depth, 1 | 2 | 4 | 8),
            Colour::Rgb | Colour::GreyAlpha | Colour::Rgba => matches!(depth, 8 | 16),
        }
    }
}

/// What `IHDR` says the picture is.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Header {
    pub width: u32,
    pub height: u32,
    /// Bits per sample: 1, 2, 4, 8 or 16.
    pub depth: u8,
    pub colour: Colour,
}

impl Header {
    /// Bytes in one un-filtered scanline, not counting the filter-type byte.
    pub const fn stride(&self) -> usize {
        let bits = self.width as usize * self.colour.channels() * self.depth as usize;
        bits.div_ceil(8)
    }

    /// The filter's notion of "the pixel before this one", in whole bytes, never less
    /// than one. Source: PNG spec §9.2 [C]
    pub const fn filter_step(&self) -> usize {
        let bits = self.colour.channels() * self.depth as usize;
        let bytes = bits / 8;
        if bytes == 0 { 1 } else { bytes }
    }

    /// How many bytes of line buffer [`render`] needs for this image: the row being
    /// built and the one above it, which every filter but the first can refer to.
    pub const fn lines_needed(&self) -> usize {
        2 * self.stride()
    }

    /// Everything the inflater should ever produce for this image, which is what the
    /// decompressor is capped at: a stream that keeps going past the last scanline is
    /// refused rather than followed.
    const fn raw_len(&self) -> u64 {
        (self.stride() as u64 + 1) * self.height as u64
    }
}

/// Read the header out of the first [`HEADER_BYTES`] bytes of a file.
///
/// Separate from [`render`] because the caller has to know the size before it can size
/// the buffers, and because a file that is not a PNG at all should cost one short read
/// rather than an allocation.
pub fn header(bytes: &[u8]) -> Result<Header, Error> {
    if bytes.len() < HEADER_BYTES {
        return Err(Error::Truncated);
    }
    if bytes[..8] != SIGNATURE {
        return Err(Error::NotPng);
    }
    if &bytes[12..16] != b"IHDR" || be32(&bytes[8..12]) != 13 {
        return Err(Error::BadHeader);
    }
    parse_ihdr(&bytes[16..29])
}

fn parse_ihdr(b: &[u8]) -> Result<Header, Error> {
    if b.len() != 13 {
        return Err(Error::BadHeader);
    }
    let width = be32(&b[0..4]);
    let height = be32(&b[4..8]);
    let depth = b[8];
    let colour = Colour::from_byte(b[9]).ok_or(Error::BadHeader)?;
    // Compression method 0 (deflate) and filter method 0 (the five filters) are the
    // only ones the format has ever defined. Source: PNG spec §11.2.2 [C]
    if b[10] != 0 || b[11] != 0 {
        return Err(Error::BadHeader);
    }
    if b[12] == 1 {
        return Err(Error::Interlaced);
    }
    if b[12] != 0 {
        return Err(Error::BadHeader);
    }
    if width == 0 || height == 0 || !colour.allows(depth) {
        return Err(Error::BadHeader);
    }
    // A width whose scanline cannot be counted in a `usize` is not a picture this will
    // ever draw, and rejecting it here keeps every later size calculation honest.
    if width > u16::MAX as u32 || height > u16::MAX as u32 {
        return Err(Error::BadHeader);
    }
    Ok(Header {
        width,
        height,
        depth,
        colour,
    })
}

/// The scratch [`render`] needs, all of it the caller's.
///
/// Nothing here is sized by this crate: a device decides what it can spare and asks the
/// header what it would take, so "this picture is too big for this device" is answered
/// before the first byte is read rather than by failing partway.
pub struct Buffers<'a> {
    /// The inflater's history. At least [`WINDOW`].
    pub window: &'a mut [u8],
    /// Two scanlines: [`Header::lines_needed`].
    pub lines: &'a mut [u8],
    /// Resampling accumulators: `6 * plan.w` entries -- three channels being summed
    /// down the image, and three being summed across the row.
    pub acc: &'a mut [u32],
    /// One finished row of the panel: `plan.w` entries.
    pub out: &'a mut [u16],
}

impl Buffers<'_> {
    /// How many `u32`s [`Buffers::acc`] needs for an output `w` pixels wide.
    pub const fn acc_needed(w: usize) -> usize {
        6 * w
    }

    fn fits(&self, hdr: &Header, plan: &Plan) -> bool {
        self.window.len() >= WINDOW
            && self.lines.len() >= hdr.lines_needed()
            && self.acc.len() >= Self::acc_needed(plan.w)
            && self.out.len() >= plan.w
    }
}

/// Read a PNG and hand back the rows of it, resized, in RGB565.
///
/// `read` fills a buffer from the file and returns how many bytes it put there, zero
/// meaning the end; it is called from the start of the file, so a caller that has
/// already peeked at the header must rewind. `sink` is given each output row in turn,
/// top first, as `plan.w` pixels. Both report failure by returning `Err(())`, which
/// comes back as [`Error::Read`] and [`Error::Sink`]: the distinction matters on a
/// screen, where "the card went away" and "the picture is broken" are different things
/// to say.
///
/// `background` is what a transparent pixel is composited onto, since the panel has no
/// alpha; pass the colour the picture is being drawn on.
pub fn render<R, S>(
    hdr: &Header,
    plan: &Plan,
    bufs: Buffers<'_>,
    background: [u8; 3],
    mut read: R,
    mut sink: S,
) -> Result<(), Error>
where
    R: FnMut(&mut [u8]) -> Result<usize, ()>,
    S: FnMut(usize, &[u16]) -> Result<(), ()>,
{
    if !bufs.fits(hdr, plan) {
        return Err(Error::Buffers);
    }
    let mut src = Src::new(&mut read);
    let mut sig = [0u8; 8];
    src.exact(&mut sig)?;
    if sig != SIGNATURE {
        return Err(Error::NotPng);
    }

    // The palette, and its alpha if the file carries one. Held here rather than in the
    // row state because `PLTE` arrives before `IDAT` and the row state is borrowed by
    // the inflater for as long as that lasts.
    let mut palette = pixels::Palette::new();

    // The header again, from the file this time. The caller passed one in, but it may
    // have read it from a different copy of the file, or from the same file before
    // something else wrote to the card.
    let (len, kind) = src.chunk_header()?;
    if &kind != b"IHDR" || len != 13 {
        return Err(Error::BadHeader);
    }
    let mut ihdr = [0u8; 13];
    src.exact(&mut ihdr)?;
    src.end_chunk(&kind, &ihdr)?;
    if parse_ihdr(&ihdr)? != *hdr {
        return Err(Error::BadHeader);
    }

    // Everything before the first `IDAT`. A file may carry any number of chunks this
    // does not care about, and the two it does care about both come first by the
    // format's own ordering rules. Source: PNG spec §5.6 [C]
    let idat_len = loop {
        let (len, kind) = src.chunk_header()?;
        match &kind {
            b"IDAT" => break len,
            b"PLTE" => {
                let mut bytes = [0u8; 256 * 3];
                let n = len as usize;
                if n > bytes.len() || !n.is_multiple_of(3) {
                    return Err(Error::BadHeader);
                }
                src.exact(&mut bytes[..n])?;
                src.end_chunk(&kind, &bytes[..n])?;
                palette.set_colours(&bytes[..n]);
            }
            b"tRNS" => {
                let mut bytes = [0u8; 256];
                let n = len as usize;
                if n > bytes.len() {
                    return Err(Error::BadHeader);
                }
                src.exact(&mut bytes[..n])?;
                src.end_chunk(&kind, &bytes[..n])?;
                palette.set_alpha(hdr.colour, &bytes[..n]);
            }
            b"IEND" => return Err(Error::Truncated),
            _ => src.skip_chunk(len)?,
        }
    };

    // From here the row state is borrowed by the inflater's sink, so anything the chunk
    // loop needs to know afterwards has to come back through a `Cell`.
    let failed = core::cell::Cell::new(None);
    let Buffers {
        window,
        lines,
        acc,
        out,
    } = bufs;
    let mut rows = resize::Rows::new(hdr, plan, lines, acc, out, background, palette, &mut sink);
    let produced;
    {
        let stream = Stream::new(window, hdr.raw_len(), |data: &[u8]| {
            rows.feed(data).map_err(|why| {
                failed.set(Some(why));
                ZError::Io
            })
        });
        let mut dec = Decompressor::<_, Zlib>::new(stream);

        let mut len = idat_len;
        let mut kind = *b"IDAT";
        // Set when the compressed stream ends, which is where reading stops.
        let mut done = false;
        // Whether something has come between the image data chunks. The format requires
        // them to be consecutive, and a file that splits them is one whose zlib stream
        // this would be reassembling on a guess.
        let mut gap_after_idat = false;
        loop {
            if &kind == b"IEND" {
                break;
            }
            if &kind == b"IDAT" {
                if gap_after_idat {
                    return Err(Error::Damaged);
                }
                // The CRC covers the chunk type as well as the data, and the data goes
                // straight to the inflater without being kept, so the type is hashed
                // first and each piece as it passes.
                let mut crc = Crc32::new();
                crc.update(&kind);
                let mut left = len as usize;
                while left > 0 {
                    let piece = src.take(left)?;
                    crc.update(piece);
                    let n = piece.len();
                    let taken = dec
                        .write(piece)
                        .map_err(|e| zerror(e, &failed, Error::Damaged))?;
                    src.consume(taken);
                    left -= taken;
                    // **The last scanline is the last thing worth reading.** Once the
                    // stream has ended, whatever follows it -- padding inside this
                    // chunk, more chunks, a second image somebody appended -- cannot
                    // change a pixel, and reading it would be time spent on a card for
                    // nothing. A file that is merely long stops costing here; a file
                    // that is long on purpose stops being a way to keep the device
                    // busy.
                    //
                    // Nothing is lost by not walking to `IEND`: the check that the
                    // picture is whole is the byte count below, not the presence of a
                    // chunk at the end of the file.
                    if dec.is_done() {
                        done = true;
                        break;
                    }
                    if taken != n {
                        // Not done, and yet it took less than it was given: the
                        // decompressor is neither finished nor hungry, which it cannot
                        // be on well-formed input.
                        return Err(Error::Damaged);
                    }
                }
                if done {
                    // The chunk itself is still checked when the stream ended exactly
                    // where the chunk did, which is where an encoder puts it; only the
                    // file past this point goes unread. A stream that ended mid-chunk
                    // leaves bytes this never hashed, so there is no CRC to compare --
                    // what vouches for the picture there is the Adler-32 the zlib
                    // stream carries over the scanlines themselves.
                    if left == 0 {
                        src.check_crc(crc)?;
                    }
                    break;
                }
                src.check_crc(crc)?;
            } else {
                gap_after_idat = true;
                src.skip_chunk(len)?;
            }
            (len, kind) = src.chunk_header()?;
        }
        produced = dec
            .finish()
            .map_err(|e| zerror(e, &failed, Error::Damaged))?;
    }

    if produced != hdr.raw_len() {
        return Err(Error::Truncated);
    }
    rows.finish()
}

/// Turn a decompressor failure into ours, preferring what the sink recorded.
///
/// `Error::Io` out of the decompressor means the sink refused, and the sink's own
/// reason is the useful one -- "the card went away" rather than "the data is damaged".
fn zerror(e: ZError, failed: &core::cell::Cell<Option<Error>>, fallback: Error) -> Error {
    match (e, failed.get()) {
        (_, Some(why)) => why,
        (ZError::WindowTooSmall, None) => Error::Buffers,
        (_, None) => fallback,
    }
}

/// CRC-32 as the PNG format uses it: the same polynomial as zlib, computed without a
/// table. Source: PNG spec §5.5 and Annex D [C]
///
/// Bitwise rather than table-driven on purpose: a 1 KiB table for a few hundred
/// kilobytes of chunk data is the wrong trade on this device, and the whole-file cost
/// is a fraction of the inflate it runs beside.
struct Crc32(u32);

impl Crc32 {
    fn new() -> Self {
        Crc32(0xFFFF_FFFF)
    }

    fn update(&mut self, data: &[u8]) {
        let mut c = self.0;
        for &b in data {
            c ^= b as u32;
            for _ in 0..8 {
                c = (c >> 1) ^ (0xEDB8_8320 & (0u32.wrapping_sub(c & 1)));
            }
        }
        self.0 = c;
    }

    fn finish(self) -> u32 {
        self.0 ^ 0xFFFF_FFFF
    }
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// The file, pulled through a small buffer.
///
/// The parser wants a few bytes at a time and the card wants to be read in blocks, so
/// something has to sit between them. This is that, and it is the only place the
/// caller's reader is touched.
struct Src<'r, R> {
    read: &'r mut R,
    buf: [u8; SRC_CHUNK],
    at: usize,
    end: usize,
    eof: bool,
}

/// How much is asked of the reader at once. A FAT read is sectors either way, and a
/// kilobyte keeps the call count down without putting a page on the stack.
const SRC_CHUNK: usize = 1024;

impl<'r, R: FnMut(&mut [u8]) -> Result<usize, ()>> Src<'r, R> {
    fn new(read: &'r mut R) -> Self {
        Src {
            read,
            buf: [0; SRC_CHUNK],
            at: 0,
            end: 0,
            eof: false,
        }
    }

    /// Make sure at least one byte is buffered, if the file has any left.
    fn fill(&mut self) -> Result<(), Error> {
        if self.at < self.end || self.eof {
            return Ok(());
        }
        self.at = 0;
        self.end = (self.read)(&mut self.buf).map_err(|()| Error::Read)?;
        if self.end == 0 {
            self.eof = true;
        }
        Ok(())
    }

    /// Up to `want` contiguous bytes, without consuming them.
    fn take(&mut self, want: usize) -> Result<&[u8], Error> {
        self.fill()?;
        let have = self.end - self.at;
        if have == 0 {
            return Err(Error::Truncated);
        }
        Ok(&self.buf[self.at..self.at + have.min(want)])
    }

    fn consume(&mut self, n: usize) {
        self.at += n;
    }

    /// Exactly `out.len()` bytes, or [`Error::Truncated`].
    fn exact(&mut self, out: &mut [u8]) -> Result<(), Error> {
        let mut done = 0;
        while done < out.len() {
            let piece = self.take(out.len() - done)?;
            let n = piece.len();
            out[done..done + n].copy_from_slice(piece);
            self.consume(n);
            done += n;
        }
        Ok(())
    }

    /// A chunk's length and four-byte type.
    fn chunk_header(&mut self) -> Result<(u32, [u8; 4]), Error> {
        let mut head = [0u8; 8];
        self.exact(&mut head)?;
        let len = be32(&head[..4]);
        // The format caps a chunk at 2^31-1, and anything near it is not a file this
        // device is going to finish anyway. Source: PNG spec §5.3 [C]
        if len > i32::MAX as u32 {
            return Err(Error::BadHeader);
        }
        Ok((len, [head[4], head[5], head[6], head[7]]))
    }

    /// Check the CRC of a chunk whose content is in hand.
    fn end_chunk(&mut self, kind: &[u8; 4], data: &[u8]) -> Result<(), Error> {
        let mut crc = Crc32::new();
        crc.update(kind);
        crc.update(data);
        self.check_crc(crc)
    }

    /// Read the four CRC bytes that end a chunk and check them.
    fn check_crc(&mut self, crc: Crc32) -> Result<(), Error> {
        let mut want = [0u8; 4];
        self.exact(&mut want)?;
        if be32(&want) != crc.finish() {
            return Err(Error::BadCrc);
        }
        Ok(())
    }

    /// Step over a chunk this does not care about, and its CRC.
    fn skip_chunk(&mut self, len: u32) -> Result<(), Error> {
        let mut left = len as usize + 4;
        while left > 0 {
            let piece = self.take(left)?;
            let n = piece.len();
            self.consume(n);
            left -= n;
        }
        Ok(())
    }
}
