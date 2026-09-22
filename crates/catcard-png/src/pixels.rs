//! Turning whatever a PNG stores into eight-bit red, green and blue.
//!
//! The format has five colour types and five bit depths, and not every pair exists, but
//! the ones that do span one bit per pixel up to sixteen bits per channel with alpha.
//! Everything downstream of here works in `[u8; 3]`, so this is where that variety
//! stops.
//!
//! # Alpha is resolved here, not carried
//!
//! The panel has no alpha channel and the image is about to be averaged, so a
//! transparent pixel has to become some actual colour before it can be weighed against
//! its neighbours. It is composited onto the background the caller names -- what the
//! picture is being drawn on -- which is the only answer that is right at the edges of
//! a logo as well as in the middle of one.
//!
//! # Sixteen-bit samples lose their low byte
//!
//! The panel takes five or six bits per channel. Averaging in sixteen and rounding to
//! five would be arithmetic nobody could see the result of, so the high byte is taken
//! at the door. Source: PNG spec §12.6, which describes exactly this as the sample
//! depth conversion. [C]

use crate::{Colour, Error, Header};

/// A file's palette, and its per-entry alpha if it carries one.
///
/// Fixed size because the format caps it: 256 entries, three bytes each, and `tRNS` no
/// longer than the palette. Source: PNG spec §11.2.3 and §11.3.2 [C]
pub(crate) struct Palette {
    rgb: [[u8; 3]; 256],
    alpha: [u8; 256],
    /// How many entries `PLTE` actually defined. An index past this is a broken file,
    /// not a black pixel.
    len: usize,
    /// For the greyscale and truecolour types, the one sample value the file declares
    /// fully transparent, if it declared one.
    transparent: Option<[u16; 3]>,
}

impl Palette {
    pub(crate) fn new() -> Self {
        Palette {
            rgb: [[0; 3]; 256],
            // Opaque unless `tRNS` says otherwise, which is what the format means by
            // the chunk being optional.
            alpha: [0xFF; 256],
            len: 0,
            transparent: None,
        }
    }

    pub(crate) fn set_colours(&mut self, bytes: &[u8]) {
        self.len = bytes.len() / 3;
        for (i, c) in bytes.as_chunks::<3>().0.iter().enumerate() {
            self.rgb[i] = [c[0], c[1], c[2]];
        }
    }

    /// Take `tRNS`, whose meaning depends on the colour type.
    ///
    /// For an indexed image it is one alpha byte per palette entry; for greyscale and
    /// truecolour it is a single sample value that means "fully transparent". It is
    /// meaningless for the two types that already carry alpha, and is ignored there.
    /// Source: PNG spec §11.3.2 [C]
    pub(crate) fn set_alpha(&mut self, colour: Colour, bytes: &[u8]) {
        match colour {
            Colour::Indexed => {
                for (i, &a) in bytes.iter().enumerate().take(256) {
                    self.alpha[i] = a;
                }
            }
            Colour::Grey if bytes.len() >= 2 => {
                let g = u16::from_be_bytes([bytes[0], bytes[1]]);
                self.transparent = Some([g, g, g]);
            }
            Colour::Rgb if bytes.len() >= 6 => {
                self.transparent = Some([
                    u16::from_be_bytes([bytes[0], bytes[1]]),
                    u16::from_be_bytes([bytes[2], bytes[3]]),
                    u16::from_be_bytes([bytes[4], bytes[5]]),
                ]);
            }
            _ => {}
        }
    }
}

/// Reads pixels out of one un-filtered scanline.
///
/// Built once per image rather than per row: what it holds is the header, the palette
/// and the background, none of which change between rows.
pub(crate) struct Reader {
    hdr: Header,
    palette: Palette,
    background: [u8; 3],
    /// The largest value a sample of this depth can hold, for scaling to eight bits.
    max: u32,
}

impl Reader {
    /// The palette is moved in: it is a kilobyte that belongs to the image, and a
    /// borrow of it would have to outlive the row state that the inflater holds.
    pub(crate) fn new(hdr: &Header, palette: Palette, background: [u8; 3]) -> Self {
        Reader {
            hdr: *hdr,
            palette,
            background,
            max: (1u32 << hdr.depth.min(16)) - 1,
        }
    }

    /// Pixel `i` of `line`, as red, green and blue.
    pub(crate) fn at(&self, line: &[u8], i: usize) -> Result<[u8; 3], Error> {
        match self.hdr.colour {
            Colour::Indexed => {
                let idx = self.sample(line, i, 1, 0)? as usize;
                if idx >= self.palette.len {
                    return Err(Error::BadPalette);
                }
                Ok(self.over(self.palette.rgb[idx], self.palette.alpha[idx] as u32, 255))
            }
            Colour::Grey => {
                let g = self.sample(line, i, 1, 0)?;
                let v = self.to8(g);
                let clear = self.palette.transparent.is_some_and(|t| t[0] as u32 == g);
                Ok(self.over([v, v, v], u32::from(!clear) * 255, 255))
            }
            Colour::Rgb => {
                let r = self.sample(line, i, 3, 0)?;
                let g = self.sample(line, i, 3, 1)?;
                let b = self.sample(line, i, 3, 2)?;
                let clear = self
                    .palette
                    .transparent
                    .is_some_and(|t| [t[0] as u32, t[1] as u32, t[2] as u32] == [r, g, b]);
                let rgb = [self.to8(r), self.to8(g), self.to8(b)];
                Ok(self.over(rgb, u32::from(!clear) * 255, 255))
            }
            Colour::GreyAlpha => {
                let g = self.sample(line, i, 2, 0)?;
                let a = self.sample(line, i, 2, 1)?;
                let v = self.to8(g);
                Ok(self.over([v, v, v], a, self.max))
            }
            Colour::Rgba => {
                let r = self.sample(line, i, 4, 0)?;
                let g = self.sample(line, i, 4, 1)?;
                let b = self.sample(line, i, 4, 2)?;
                let a = self.sample(line, i, 4, 3)?;
                let rgb = [self.to8(r), self.to8(g), self.to8(b)];
                Ok(self.over(rgb, a, self.max))
            }
        }
    }

    /// Sample `which` of pixel `i`, where a pixel has `channels` of them.
    ///
    /// Depths of 8 and 16 are whole bytes; 1, 2 and 4 pack several pixels into a byte,
    /// most significant bits first, and only ever with one channel.
    /// Source: PNG spec §7.2 [C]
    fn sample(&self, line: &[u8], i: usize, channels: usize, which: usize) -> Result<u32, Error> {
        match self.hdr.depth {
            8 => line
                .get(i * channels + which)
                .map(|&b| b as u32)
                .ok_or(Error::Buffers),
            16 => {
                let at = (i * channels + which) * 2;
                let hi = *line.get(at).ok_or(Error::Buffers)?;
                let lo = *line.get(at + 1).ok_or(Error::Buffers)?;
                Ok(u16::from_be_bytes([hi, lo]) as u32)
            }
            d => {
                let bits = d as usize;
                let per_byte = 8 / bits;
                let byte = *line.get(i / per_byte).ok_or(Error::Buffers)?;
                let shift = 8 - bits * (i % per_byte + 1);
                Ok(((byte >> shift) as u32) & self.max)
            }
        }
    }

    /// Scale a sample of this file's depth to eight bits.
    ///
    /// By the ratio, not by shifting: at depth 1 a set bit is 255, not 128, and at
    /// depth 4 the top value is 255 rather than 240. Source: PNG spec §12.6 [C]
    fn to8(&self, v: u32) -> u8 {
        match self.hdr.depth {
            8 => v as u8,
            16 => (v >> 8) as u8,
            _ => ((v * 255 + self.max / 2) / self.max) as u8,
        }
    }

    /// Composite `rgb` with alpha `a` out of `amax` onto the background.
    fn over(&self, rgb: [u8; 3], a: u32, amax: u32) -> [u8; 3] {
        if a >= amax {
            return rgb;
        }
        let mut out = [0u8; 3];
        for c in 0..3 {
            let fg = rgb[c] as u32 * a;
            let bg = self.background[c] as u32 * (amax - a);
            out[c] = ((fg + bg + amax / 2) / amax) as u8;
        }
        out
    }
}

/// Undo one scanline's filter, in place, given the line above it.
///
/// `step` is the distance to "the pixel to the left" in bytes, which for depths below
/// eight is one byte rather than one pixel. `prev` is the already-un-filtered row above,
/// and is all zeroes for the first row -- which is what makes the Up, Average and Paeth
/// filters work there without a special case.
///
/// Source: PNG spec §9.2, the five filter types and their reconstruction functions [C]
pub(crate) fn unfilter(kind: u8, line: &mut [u8], prev: &[u8], step: usize) -> Result<(), Error> {
    match kind {
        0 => {}
        1 => {
            for i in step..line.len() {
                line[i] = line[i].wrapping_add(line[i - step]);
            }
        }
        2 => {
            for i in 0..line.len() {
                line[i] = line[i].wrapping_add(prev[i]);
            }
        }
        3 => {
            for i in 0..line.len() {
                let left = if i >= step { line[i - step] as u32 } else { 0 };
                let up = prev[i] as u32;
                line[i] = line[i].wrapping_add(((left + up) / 2) as u8);
            }
        }
        4 => {
            for i in 0..line.len() {
                let (left, upleft) = if i >= step {
                    (line[i - step] as i32, prev[i - step] as i32)
                } else {
                    (0, 0)
                };
                let up = prev[i] as i32;
                line[i] = line[i].wrapping_add(paeth(left, up, upleft));
            }
        }
        _ => return Err(Error::Damaged),
    }
    Ok(())
}

/// The Paeth predictor: whichever of left, above and above-left is closest to their
/// linear combination, ties going to the left one. Source: PNG spec §9.4 [C]
fn paeth(a: i32, b: i32, c: i32) -> u8 {
    let p = a + b - c;
    let (pa, pb, pc) = ((p - a).abs(), (p - b).abs(), (p - c).abs());
    if pa <= pb && pa <= pc {
        a as u8
    } else if pb <= pc {
        b as u8
    } else {
        c as u8
    }
}
