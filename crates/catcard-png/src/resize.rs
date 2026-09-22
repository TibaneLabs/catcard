//! Fitting a picture to a panel, one row at a time.
//!
//! The whole resize runs on two source scanlines and one accumulator row, because of
//! how the weights fall out. Horizontally, each source column overlaps at most two
//! output columns; vertically, each source row overlaps at most two output rows. So a
//! source row can be reduced to output width the moment it is un-filtered, added into
//! the accumulator with its share of the weight, and thrown away -- and an output row
//! is finished, sent, and cleared as soon as the last source row touching it arrives.
//!
//! # The arithmetic is exact
//!
//! Positions are kept in units of `src * dst` so nothing is ever a rounded ratio: the
//! weights along a row sum to exactly the source width, the weights down a column sum
//! to exactly the source height, and the last output row is finished by the last source
//! row rather than by a fudge at the end. Rounding happens twice and only twice: once
//! when a row is reduced to output width (to four fractional bits, which is what keeps
//! the vertical sums inside a `u32`), and once when a finished pixel is quantised to
//! RGB565.

use crate::pixels::{Palette, Reader, unfilter};
use crate::{Error, Header};

/// How a picture is being made to fit.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Scale {
    /// Averaged down: every output pixel is the mean of the source pixels it covers.
    Down,
    /// Repeated up by a whole number of steps, or copied as it is at 1.
    Up(usize),
}

/// The size a picture will be drawn at, and how it gets there.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Plan {
    /// Output width in pixels.
    pub w: usize,
    /// Output height in pixels.
    pub h: usize,
    pub scale: Scale,
}

/// Work out the largest size a picture can be drawn at inside `max_w` x `max_h`,
/// keeping its proportions.
///
/// A picture that already fits is enlarged by whole steps if it can be -- a 27x30 icon
/// on a 320x240 panel goes to 8x rather than sitting in the middle as a stamp -- and
/// left alone if the next step would not fit. A picture that does not fit is averaged
/// down to whichever edge binds first.
pub fn fit(hdr: &Header, max_w: usize, max_h: usize) -> Plan {
    let (sw, sh) = (hdr.width as usize, hdr.height as usize);
    if sw <= max_w && sh <= max_h {
        // At least 1: it fits, so both quotients are at least one.
        let n = (max_w / sw).min(max_h / sh).max(1);
        return Plan {
            w: sw * n,
            h: sh * n,
            scale: Scale::Up(n),
        };
    }
    // Which edge binds: compare the two ratios without dividing.
    let (w, h) = if sw as u64 * max_h as u64 >= sh as u64 * max_w as u64 {
        let h = (sh as u64 * max_w as u64 / sw as u64).max(1) as usize;
        (max_w, h.min(max_h))
    } else {
        let w = (sw as u64 * max_h as u64 / sh as u64).max(1) as usize;
        (w.min(max_w), max_h)
    };
    Plan {
        w,
        h,
        scale: Scale::Down,
    }
}

/// Fractional bits kept when a source row is reduced to output width.
///
/// Four, because the vertical sums have to stay inside a `u32`: a value of up to
/// `255 << 4` times a height of up to 65535 is 267 million, which is comfortable, while
/// eight fractional bits would be four billion and is not.
const FRAC: u32 = 4;

/// The streaming half of the resize: bytes in, finished rows out.
pub(crate) struct Rows<'a, S> {
    hdr: Header,
    plan: Plan,
    reader: Reader,
    /// Two scanlines back to back: the one being built and the one above it.
    lines: &'a mut [u8],
    /// `3*w` vertical accumulators, then `3*w` for the row being reduced.
    acc: &'a mut [u32],
    out: &'a mut [u16],
    sink: &'a mut S,

    /// The filter byte of the scanline being assembled, once it has arrived.
    filter: Option<u8>,
    /// Bytes of the current scanline in hand.
    got: usize,
    /// Whether the current scanline is the first half of `lines`.
    first_half: bool,
    /// Source rows finished.
    y: usize,
    /// Output rows sent.
    sent: usize,
    /// Weight already accumulated into the output row being built.
    filled: u32,
}

impl<'a, S> Rows<'a, S>
where
    S: FnMut(usize, &[u16]) -> Result<(), ()>,
{
    #[allow(clippy::too_many_arguments)] // every one of them is a distinct buffer
    pub(crate) fn new(
        hdr: &Header,
        plan: &Plan,
        lines: &'a mut [u8],
        acc: &'a mut [u32],
        out: &'a mut [u16],
        background: [u8; 3],
        palette: Palette,
        sink: &'a mut S,
    ) -> Self {
        acc.fill(0);
        lines.fill(0);
        Rows {
            hdr: *hdr,
            plan: *plan,
            reader: Reader::new(hdr, palette, background),
            lines,
            acc,
            out,
            sink,
            filter: None,
            got: 0,
            first_half: true,
            y: 0,
            sent: 0,
            filled: 0,
        }
    }

    /// Take the next piece of expanded image data, of any length.
    pub(crate) fn feed(&mut self, mut data: &[u8]) -> Result<(), Error> {
        let stride = self.hdr.stride();
        while !data.is_empty() {
            if self.y >= self.hdr.height as usize {
                // More data than the image has rows. The decompressor is capped at the
                // exact raw length, so this means a file whose header disagrees with
                // its own data.
                return Err(Error::Damaged);
            }
            if self.filter.is_none() {
                self.filter = Some(data[0]);
                data = &data[1..];
                continue;
            }
            let (a, b) = self.lines.split_at_mut(stride);
            let cur = if self.first_half { a } else { b };
            let want = stride - self.got;
            let take = want.min(data.len());
            cur[self.got..self.got + take].copy_from_slice(&data[..take]);
            self.got += take;
            data = &data[take..];
            if self.got == stride {
                self.row_done()?;
            }
        }
        Ok(())
    }

    /// A whole scanline has arrived: un-filter it and put it through the resize.
    fn row_done(&mut self) -> Result<(), Error> {
        let step = self.hdr.filter_step();
        let kind = self.filter.take().unwrap_or(0);
        {
            let stride = self.hdr.stride();
            let (a, b) = self.lines.split_at_mut(stride);
            let (cur, prev) = if self.first_half { (a, b) } else { (b, a) };
            unfilter(kind, cur, prev, step)?;
        }
        match self.plan.scale {
            Scale::Up(n) => self.emit_repeated(n)?,
            Scale::Down => self.accumulate()?,
        }
        self.got = 0;
        self.first_half = !self.first_half;
        self.y += 1;
        Ok(())
    }

    /// Enlarging: each pixel across, each row down, `n` times.
    fn emit_repeated(&mut self, n: usize) -> Result<(), Error> {
        let sw = self.hdr.width as usize;
        {
            let stride = self.hdr.stride();
            let line: &[u8] = if self.first_half {
                &self.lines[..stride]
            } else {
                &self.lines[stride..stride * 2]
            };
            for i in 0..sw {
                let px = rgb565(self.reader.at(line, i)?);
                for k in 0..n {
                    self.out[i * n + k] = px;
                }
            }
        }
        for _ in 0..n {
            let row = self.sent;
            (self.sink)(row, &self.out[..self.plan.w]).map_err(|()| Error::Sink)?;
            self.sent += 1;
        }
        Ok(())
    }

    /// Shrinking: reduce this row to output width, then give it to the one or two
    /// output rows it belongs to.
    fn accumulate(&mut self) -> Result<(), Error> {
        let (sw, sh) = (self.hdr.width as usize, self.hdr.height as usize);
        let (dw, dh) = (self.plan.w, self.plan.h);

        // Across: sum into the second half of `acc`, then scale to `FRAC` fractional
        // bits. The weights over one output column sum to exactly `sw`.
        {
            let (_, horiz) = self.acc.split_at_mut(3 * dw);
            horiz.fill(0);
            let line = if self.first_half {
                &self.lines[..self.hdr.stride()]
            } else {
                &self.lines[self.hdr.stride()..self.hdr.stride() * 2]
            };
            for i in 0..sw {
                let px = self.reader.at(line, i)?;
                let a = i * dw;
                let j = a / sw;
                let edge = (j + 1) * sw;
                let b = a + dw;
                if b <= edge {
                    for c in 0..3 {
                        horiz[j * 3 + c] += dw as u32 * px[c] as u32;
                    }
                } else {
                    let w0 = (edge - a) as u32;
                    let w1 = (b - edge) as u32;
                    for c in 0..3 {
                        horiz[j * 3 + c] += w0 * px[c] as u32;
                        // `j + 1` exists: `b <= sw * dw` and only the last column has
                        // `b == edge`, which took the branch above.
                        horiz[(j + 1) * 3 + c] += w1 * px[c] as u32;
                    }
                }
            }
            let half = sw as u32 / 2;
            for v in horiz.iter_mut() {
                *v = ((*v << FRAC) + half) / sw as u32;
            }
        }

        // Down: this row's share of the output rows it covers. Same arithmetic, and
        // the weights over one output row sum to exactly `sh`.
        let a = self.y * dh;
        let k = a / sh;
        let edge = (k + 1) * sh;
        let b = a + dh;
        if b <= edge {
            self.add_weighted(dh as u32);
            if self.filled == sh as u32 {
                self.emit_accumulated(k)?;
            }
        } else {
            self.add_weighted((edge - a) as u32);
            self.emit_accumulated(k)?;
            self.add_weighted((b - edge) as u32);
        }
        Ok(())
    }

    /// Add the reduced row into the output row being built, with `weight` of it.
    fn add_weighted(&mut self, weight: u32) {
        let (vert, horiz) = self.acc.split_at_mut(3 * self.plan.w);
        for (v, &h) in vert.iter_mut().zip(horiz.iter()) {
            *v += weight * h;
        }
        self.filled += weight;
    }

    /// Finish output row `k`: divide out the weight, quantise, send, clear.
    fn emit_accumulated(&mut self, k: usize) -> Result<(), Error> {
        let sh = self.hdr.height;
        let dw = self.plan.w;
        let total = sh << FRAC;
        let half = total / 2;
        let (vert, _) = self.acc.split_at_mut(3 * dw);
        for j in 0..dw {
            let mut px = [0u8; 3];
            for c in 0..3 {
                px[c] = (((vert[j * 3 + c] + half) / total).min(255)) as u8;
            }
            self.out[j] = rgb565(px);
        }
        vert.fill(0);
        self.filled = 0;
        (self.sink)(k, &self.out[..dw]).map_err(|()| Error::Sink)?;
        self.sent += 1;
        Ok(())
    }

    /// Every row of the picture arrived, and every row of the output went out.
    pub(crate) fn finish(&self) -> Result<(), Error> {
        if self.y != self.hdr.height as usize || self.sent != self.plan.h {
            return Err(Error::Truncated);
        }
        Ok(())
    }
}

/// Eight bits a channel down to what the panel takes: five red, six green, five blue.
pub(crate) fn rgb565(px: [u8; 3]) -> u16 {
    ((px[0] as u16 & 0xF8) << 8) | ((px[1] as u16 & 0xFC) << 3) | (px[2] as u16 >> 3)
}
