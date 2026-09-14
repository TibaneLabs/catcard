//! Indexed-colour artwork: the pixels a renderer produced, and the palette they need.
//!
//! A [`Canvas`](crate::canvas::Canvas) holds 4 bits per pixel and the panel flush maps
//! those through a 16-entry RGB565 palette, so a picture travels as its own palette plus
//! one nibble per pixel. That is how a rasterised SVG -- glow, gradient, anti-aliased
//! edges -- reaches the screen without a 150 KB RGB565 framebuffer nobody has the RAM for.
//!
//! **Index 0 is the background and is never drawn**, so art composes over whatever is
//! already on the canvas instead of carrying a transparency mask. Index 15 is left for
//! white, which is what text and the progress bar draw in.
//!
//! On a mono panel the same indices threshold to ink or paper, so the art degrades to a
//! silhouette rather than needing a second asset -- though a hand-drawn 1-bit picture
//! still reads better there, which is why [`cat`](super::cat) stays.

use crate::canvas::Canvas;

/// A picture as indices into its own palette.
pub struct Indexed {
    pub width: u16,
    pub height: u16,
    /// Colours for indices 0..=15, RGB565. Index 0 is the background.
    pub palette: [u16; 16],
    /// Two pixels per byte, row-major, the left pixel in the high nibble -- the packing a
    /// [`Gray4`](crate::canvas::Gray4) canvas uses.
    pub pixels: &'static [u8],
}

impl Indexed {
    /// Bytes one row occupies.
    pub const fn row_len(&self) -> usize {
        (self.width as usize).div_ceil(2)
    }

    /// The palette index at `(x, y)`. Outside the picture reads 0.
    pub fn index(&self, x: usize, y: usize) -> u8 {
        if x >= self.width as usize || y >= self.height as usize {
            return 0;
        }
        let byte = self.pixels[y * self.row_len() + x / 2];
        if x.is_multiple_of(2) {
            byte >> 4
        } else {
            byte & 0x0F
        }
    }
}

/// Draw `art` with its top-left at `(x, y)`, clipped. Index 0 is not drawn.
///
/// The canvas must be flushed through `art.palette` for the colours to be the ones the
/// renderer chose -- see the firmware's `display::draw_with_palette`.
pub fn draw_indexed<C: Canvas + ?Sized>(canvas: &mut C, art: &Indexed, x: usize, y: usize) {
    for ay in 0..art.height as usize {
        for ax in 0..art.width as usize {
            let index = art.index(ax, ay);
            if index != 0 {
                canvas.put(x.saturating_add(ax), y.saturating_add(ay), index);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canvas::{Gray320x240, PAPER};

    /// 3x2: indices 1, 2, 0 / 0, 15, 3. Odd width, so the last nibble of each row is padding.
    static SMALL_PIXELS: [u8; 4] = [0x12, 0x00, 0x0F, 0x30];
    const SMALL: Indexed = Indexed {
        width: 3,
        height: 2,
        palette: [0; 16],
        pixels: &SMALL_PIXELS,
    };

    #[test]
    fn indices_unpack_from_the_high_nibble_first_and_clip() {
        assert_eq!(SMALL.row_len(), 2);
        assert_eq!(
            [
                SMALL.index(0, 0),
                SMALL.index(1, 0),
                SMALL.index(2, 0),
                SMALL.index(0, 1),
                SMALL.index(1, 1),
                SMALL.index(2, 1)
            ],
            [1, 2, 0, 0, 15, 3]
        );
        assert_eq!(SMALL.index(3, 0), 0, "past the width");
        assert_eq!(SMALL.index(0, 2), 0, "past the height");
        assert_eq!(SMALL.index(usize::MAX, usize::MAX), 0);
    }

    #[test]
    fn drawing_keeps_the_indices_and_leaves_the_background_alone() {
        let mut c = Gray320x240::new();
        c.put(2, 0, 9); // under an index-0 pixel of the art
        draw_indexed(&mut c, &SMALL, 0, 0);
        assert_eq!(c.get(0, 0), 1);
        assert_eq!(c.get(1, 0), 2);
        assert_eq!(c.get(2, 0), 9, "index 0 should not have painted over this");
        assert_eq!(c.get(0, 1), PAPER);
        assert_eq!(c.get(1, 1), 15);
        assert_eq!(c.get(2, 1), 3);
    }

    #[test]
    fn drawing_off_the_canvas_is_clipped_not_a_panic() {
        let mut c = Gray320x240::new();
        draw_indexed(&mut c, &SMALL, 319, 239);
        assert_eq!(c.get(319, 239), 1);
        draw_indexed(&mut c, &SMALL, usize::MAX - 1, usize::MAX - 1);
    }
}
