//! Monochrome framebuffer in SSD1306 page order.
//!
//! The SSD1306 stores one byte per 8 vertical pixels: byte `(page, x)` holds rows
//! `page*8 .. page*8+8` of column `x`, LSB at the top. Keeping the framebuffer in that
//! layout means a flush is one contiguous SPI write with no transposition.

/// `W` = width in pixels, `PAGES` = height / 8, `N` = W * PAGES.
///
/// The three parameters are redundant, but const generic arithmetic in array lengths
/// is not stable, so `N` is passed explicitly and checked.
pub struct Framebuffer<const W: usize, const PAGES: usize, const N: usize> {
    buf: [u8; N],
}

impl<const W: usize, const PAGES: usize, const N: usize> Default for Framebuffer<W, PAGES, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const W: usize, const PAGES: usize, const N: usize> Framebuffer<W, PAGES, N> {
    pub const WIDTH: usize = W;
    pub const HEIGHT: usize = PAGES * 8;

    pub const fn new() -> Self {
        assert!(N == W * PAGES, "framebuffer N must equal W * PAGES");
        Self { buf: [0; N] }
    }

    pub fn clear(&mut self) {
        self.buf.fill(0);
    }

    pub fn fill(&mut self) {
        self.buf.fill(0xFF);
    }

    /// Set or clear one pixel. Out-of-range coordinates are ignored, so drawing code
    /// can clip by simply drawing.
    pub fn set(&mut self, x: usize, y: usize, on: bool) {
        if x >= W || y >= Self::HEIGHT {
            return;
        }
        let idx = (y / 8) * W + x;
        let bit = 1u8 << (y % 8);
        if on {
            self.buf[idx] |= bit;
        } else {
            self.buf[idx] &= !bit;
        }
    }

    pub fn get(&self, x: usize, y: usize) -> bool {
        if x >= W || y >= Self::HEIGHT {
            return false;
        }
        self.buf[(y / 8) * W + x] & (1 << (y % 8)) != 0
    }

    /// Horizontal line, inclusive of `x0`, exclusive of `x1`.
    pub fn hline(&mut self, x0: usize, x1: usize, y: usize, on: bool) {
        for x in x0..x1.min(W) {
            self.set(x, y, on);
        }
    }

    pub fn vline(&mut self, x: usize, y0: usize, y1: usize, on: bool) {
        for y in y0..y1.min(Self::HEIGHT) {
            self.set(x, y, on);
        }
    }

    pub fn rect(&mut self, x0: usize, y0: usize, x1: usize, y1: usize, on: bool) {
        self.hline(x0, x1, y0, on);
        self.hline(x0, x1, y1.saturating_sub(1), on);
        self.vline(x0, y0, y1, on);
        self.vline(x1.saturating_sub(1), y0, y1, on);
    }

    /// The bytes to push to the panel, in the order the controller expects them.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    pub const fn pages(&self) -> usize {
        PAGES
    }
}

/// The mk3/mk4 panel: 128x64.
pub type Mono128x64 = Framebuffer<128, 8, 1024>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dimensions() {
        assert_eq!(Mono128x64::WIDTH, 128);
        assert_eq!(Mono128x64::HEIGHT, 64);
        assert_eq!(Mono128x64::new().as_bytes().len(), 1024);
    }

    #[test]
    fn set_and_get_round_trip() {
        let mut fb = Mono128x64::new();
        for (x, y) in [(0, 0), (127, 63), (64, 32), (1, 7), (1, 8)] {
            assert!(!fb.get(x, y));
            fb.set(x, y, true);
            assert!(fb.get(x, y), "pixel ({x},{y}) did not set");
            fb.set(x, y, false);
            assert!(!fb.get(x, y));
        }
    }

    /// The page-order layout is the part that is easy to get subtly wrong, so pin the
    /// exact byte and bit a pixel lands in.
    #[test]
    fn pixels_land_in_ssd1306_page_order() {
        let mut fb = Mono128x64::new();
        fb.set(0, 0, true);
        assert_eq!(fb.as_bytes()[0], 0x01, "row 0 must be the LSB of page 0");

        let mut fb = Mono128x64::new();
        fb.set(0, 7, true);
        assert_eq!(fb.as_bytes()[0], 0x80, "row 7 must be the MSB of page 0");

        let mut fb = Mono128x64::new();
        fb.set(5, 8, true);
        assert_eq!(fb.as_bytes()[128 + 5], 0x01, "row 8 must start page 1");
    }

    #[test]
    fn out_of_range_coordinates_are_clipped_not_panics() {
        let mut fb = Mono128x64::new();
        fb.set(128, 0, true);
        fb.set(0, 64, true);
        fb.set(usize::MAX, usize::MAX, true);
        assert!(fb.as_bytes().iter().all(|&b| b == 0));
        assert!(!fb.get(128, 0));
    }

    #[test]
    fn clear_and_fill() {
        let mut fb = Mono128x64::new();
        fb.fill();
        assert!(fb.as_bytes().iter().all(|&b| b == 0xFF));
        assert!(fb.get(63, 63));
        fb.clear();
        assert!(fb.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn lines_stay_in_bounds() {
        let mut fb = Mono128x64::new();
        fb.hline(0, 1000, 10, true);
        assert!(fb.get(127, 10));
        fb.vline(10, 0, 1000, true);
        assert!(fb.get(10, 63));
    }

    #[test]
    fn rect_draws_four_edges_and_no_fill() {
        let mut fb = Mono128x64::new();
        fb.rect(2, 2, 10, 10, true);
        assert!(fb.get(2, 2) && fb.get(9, 2) && fb.get(2, 9) && fb.get(9, 9));
        assert!(!fb.get(5, 5), "rect should be an outline, not filled");
    }
}
