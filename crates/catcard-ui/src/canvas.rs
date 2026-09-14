//! Somewhere to draw, of any size and depth.
//!
//! Screens were written against [`Mono128x64`](crate::Mono128x64) with the panel's size in
//! their constants, which tied every layout to the mk4's OLED: a bigger panel could only
//! show the same 128x64 picture scaled up. A [`Canvas`] says how big it is and takes a
//! 4-bit [`Level`] per pixel, so one piece of drawing code fills a 128x64 mono panel or the
//! Q1's 320x240 LCD -- and anti-aliased text, which needs the levels between ink and paper,
//! degrades to a threshold on a panel that only has the two ends.

use crate::framebuffer::Framebuffer;

/// Pixel intensity, from [`PAPER`] (0) to [`INK`] (15).
pub type Level = u8;
/// The background: nothing drawn.
pub const PAPER: Level = 0;
/// Full ink.
pub const INK: Level = 15;

/// A drawing surface.
pub trait Canvas {
    fn width(&self) -> usize;
    fn height(&self) -> usize;

    /// Set one pixel. Out of range is ignored, so drawing code clips by simply drawing;
    /// levels above [`INK`] are clamped.
    fn put(&mut self, x: usize, y: usize, level: Level);

    /// Read one pixel. Out of range reads [`PAPER`].
    fn get(&self, x: usize, y: usize) -> Level;

    /// Fill everything with [`PAPER`].
    fn clear(&mut self) {
        let (w, h) = (self.width(), self.height());
        self.fill_rect(0, 0, w, h, PAPER);
    }

    /// Fill `w` x `h` at `(x, y)`, clipped.
    fn fill_rect(&mut self, x: usize, y: usize, w: usize, h: usize, level: Level) {
        let x1 = x.saturating_add(w).min(self.width());
        let y1 = y.saturating_add(h).min(self.height());
        for yy in y..y1 {
            for xx in x..x1 {
                self.put(xx, yy, level);
            }
        }
    }

    /// Lay `ink` over a pixel at `coverage` (0..=15): 15 replaces what is there, 0 leaves
    /// it, and the levels between mix the two. This is how an anti-aliased glyph edge
    /// lands on whatever is beneath it.
    fn blend(&mut self, x: usize, y: usize, ink: Level, coverage: Level) {
        let cov = coverage.min(INK) as i16;
        if cov == 0 {
            return;
        }
        let under = self.get(x, y) as i16;
        let over = ink.min(INK) as i16;
        self.put(x, y, (under + (over - under) * cov / INK as i16) as Level);
    }
}

/// The mono panel's framebuffer, thresholded: a level of 8 or more is lit.
impl<const W: usize, const P: usize, const N: usize> Canvas for Framebuffer<W, P, N> {
    fn width(&self) -> usize {
        W
    }
    fn height(&self) -> usize {
        P * 8
    }
    fn put(&mut self, x: usize, y: usize, level: Level) {
        self.set(x, y, level >= 8);
    }
    fn get(&self, x: usize, y: usize) -> Level {
        if Framebuffer::get(self, x, y) {
            INK
        } else {
            PAPER
        }
    }
}

/// A 4-bit-per-pixel framebuffer: 16 levels, two pixels per byte, row-major, the left
/// pixel of each pair in the high nibble.
///
/// The Q1's 320x240 is 38.4 KB this way, which fits in SRAM1 beside everything else;
/// RGB565 would be 153.6 KB and would not. Levels become colours when the panel driver
/// flushes, through a palette.
///
/// `N` is `H * W.div_ceil(2)`, passed explicitly because const generic arithmetic in an
/// array length is not stable; [`Gray4::new`] checks it.
pub struct Gray4<const W: usize, const H: usize, const N: usize> {
    buf: [u8; N],
}

/// The Q1's whole panel.
pub type Gray320x240 = Gray4<320, 240, 38400>;

impl<const W: usize, const H: usize, const N: usize> Default for Gray4<W, H, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const W: usize, const H: usize, const N: usize> Gray4<W, H, N> {
    pub const fn new() -> Self {
        assert!(N == H * W.div_ceil(2), "Gray4 N must equal H * ceil(W / 2)");
        Self { buf: [0; N] }
    }

    /// The packed levels, row-major.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    const fn at(x: usize, y: usize) -> (usize, u32) {
        (y * W.div_ceil(2) + x / 2, if x.is_multiple_of(2) { 4 } else { 0 })
    }
}

impl<const W: usize, const H: usize, const N: usize> Canvas for Gray4<W, H, N> {
    fn width(&self) -> usize {
        W
    }
    fn height(&self) -> usize {
        H
    }
    fn put(&mut self, x: usize, y: usize, level: Level) {
        if x >= W || y >= H {
            return;
        }
        let (i, shift) = Self::at(x, y);
        self.buf[i] = (self.buf[i] & !(0x0F << shift)) | (level.min(INK) << shift);
    }
    fn get(&self, x: usize, y: usize) -> Level {
        if x >= W || y >= H {
            return PAPER;
        }
        let (i, shift) = Self::at(x, y);
        (self.buf[i] >> shift) & 0x0F
    }
    fn clear(&mut self) {
        self.buf.fill(0);
    }
}

/// Copy `src` into `dst` at `scale`x, centred and clipped, over whatever `dst` holds.
///
/// How a screen still drawn for a 128x64 panel is shown on a bigger one: copied into the
/// big canvas and flushed with it, so it replaces the whole of the last frame rather than
/// leaving that frame's edges around a scaled window.
pub fn blit_scaled<D: Canvas + ?Sized, S: Canvas + ?Sized>(dst: &mut D, src: &S, scale: usize) {
    let scale = scale.max(1);
    let (w, h) = (src.width() * scale, src.height() * scale);
    let x0 = dst.width().saturating_sub(w) / 2;
    let y0 = dst.height().saturating_sub(h) / 2;
    for sy in 0..src.height() {
        for sx in 0..src.width() {
            let level = src.get(sx, sy);
            if level != PAPER {
                dst.fill_rect(x0 + sx * scale, y0 + sy * scale, scale, scale, level);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framebuffer::Mono128x64;

    #[test]
    fn a_320x240_gray_canvas_is_the_size_that_fits_in_sram1() {
        let c = Gray320x240::new();
        assert_eq!((c.width(), c.height()), (320, 240));
        assert_eq!(c.as_bytes().len(), 38_400);
    }

    #[test]
    fn every_level_round_trips_at_both_nibbles_of_a_byte() {
        let mut c = Gray320x240::new();
        for level in 0..=INK {
            for (x, y) in [(0, 0), (1, 0), (318, 239), (319, 239), (160, 120)] {
                c.put(x, y, level);
                assert_eq!(c.get(x, y), level, "({x},{y}) at level {level}");
            }
        }
        // Neighbours in the same byte do not disturb each other.
        let mut c = Gray320x240::new();
        c.put(10, 5, 9);
        c.put(11, 5, 3);
        assert_eq!((c.get(10, 5), c.get(11, 5)), (9, 3));
        assert_eq!(c.as_bytes()[5 * 160 + 5], 0x93, "left pixel is the high nibble");
    }

    #[test]
    fn out_of_range_is_ignored_and_levels_are_clamped() {
        let mut c = Gray320x240::new();
        c.put(320, 0, INK);
        c.put(0, 240, INK);
        c.put(usize::MAX, usize::MAX, INK);
        assert!(c.as_bytes().iter().all(|&b| b == 0));
        assert_eq!(c.get(320, 0), PAPER);
        c.put(0, 0, 200);
        assert_eq!(c.get(0, 0), INK);
    }

    #[test]
    fn fill_rect_clips_to_the_canvas() {
        let mut c = Gray320x240::new();
        c.fill_rect(310, 230, 100, 100, 7);
        assert_eq!(c.get(319, 239), 7);
        assert_eq!(c.get(309, 239), PAPER);
        let painted = (0..240)
            .flat_map(|y| (0..320).map(move |x| (x, y)))
            .filter(|&(x, y)| c.get(x, y) != 0)
            .count();
        assert_eq!(painted, 100);
    }

    #[test]
    fn blend_mixes_ink_over_what_is_there_by_coverage() {
        let mut c = Gray320x240::new();
        c.blend(0, 0, INK, 0);
        assert_eq!(c.get(0, 0), PAPER, "zero coverage leaves the pixel");
        c.blend(0, 0, INK, INK);
        assert_eq!(c.get(0, 0), INK, "full coverage replaces it");
        c.put(1, 0, PAPER);
        c.blend(1, 0, INK, 8);
        assert_eq!(c.get(1, 0), 8, "half coverage over paper is half ink");
        c.put(2, 0, INK);
        c.blend(2, 0, PAPER, INK);
        assert_eq!(c.get(2, 0), PAPER, "blending towards paper works too");
    }

    #[test]
    fn a_mono_screen_blits_centred_at_twice_its_size() {
        let mut fb = Mono128x64::new();
        fb.set(0, 0, true);
        fb.set(127, 63, true);
        let mut c = Gray320x240::new();
        c.fill_rect(0, 0, 10, 10, 9); // outside the blit: left alone
        blit_scaled(&mut c, &fb, 2);
        // 256x128 centred on 320x240 starts at (32, 56).
        for (x, y) in [(32, 56), (33, 56), (32, 57), (33, 57), (286, 182), (287, 183)] {
            assert_eq!(c.get(x, y), INK, "({x},{y})");
        }
        assert_eq!(c.get(34, 56), PAPER);
        assert_eq!(c.get(0, 0), 9, "blit painted outside its window");
    }

    #[test]
    fn the_mono_framebuffer_thresholds_levels_at_eight() {
        let mut fb = Mono128x64::new();
        assert_eq!((Canvas::width(&fb), Canvas::height(&fb)), (128, 64));
        fb.put(3, 3, 7);
        assert_eq!(Canvas::get(&fb, 3, 3), PAPER);
        fb.put(3, 3, 8);
        assert_eq!(Canvas::get(&fb, 3, 3), INK);
        fb.blend(4, 4, INK, 5);
        assert_eq!(Canvas::get(&fb, 4, 4), PAPER, "a faint edge does not light an OLED pixel");
    }
}
