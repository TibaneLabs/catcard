//! Bitmap artwork.

pub mod cat;

/// A 1-bit image, row-major with the most significant bit leftmost.
///
/// Same layout as a [`Font`](crate::font::Font) glyph, so the two draw the same way —
/// artwork is just a glyph nobody types.
pub struct Bitmap {
    pub width: u16,
    pub height: u16,
    /// Bytes each row occupies; rows are left-aligned, so trailing bits are padding.
    pub bytes_per_row: u16,
    pub pixels: &'static [u8],
}

impl Bitmap {
    /// Whether pixel `(x, y)` is set. Out of range reads as clear.
    pub fn pixel(&self, x: usize, y: usize) -> bool {
        if x >= self.width as usize || y >= self.height as usize {
            return false;
        }
        let byte = self.pixels[y * self.bytes_per_row as usize + x / 8];
        byte & (0x80 >> (x % 8)) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cat_is_the_size_it_says() {
        let c = &cat::CAT;
        assert_eq!(c.pixels.len(), c.height as usize * c.bytes_per_row as usize);
        assert_eq!(c.bytes_per_row, c.width.div_ceil(8));
        // Fits the panel at all. How much room it leaves for the wordmark and the
        // version is the splash's constraint, and splash.rs tests it there.
        //
        // Nothing here asserts what the drawing contains. These check that the table is
        // a faithful encoding of some bitmap, which is a property of the emit; what is
        // in the picture is the artist's call, and a test that pinned it down would only
        // fail every time the art improved.
        assert!(c.width <= 128 && c.height <= 64, "{}x{}", c.width, c.height);
    }

    #[test]
    fn padding_bits_are_clear() {
        let c = &cat::CAT;
        let pad = c.bytes_per_row as usize * 8 - c.width as usize;
        if pad == 0 {
            return;
        }
        let mask = (1u16 << pad) - 1;
        for y in 0..c.height as usize {
            let last = c.pixels[y * c.bytes_per_row as usize + c.bytes_per_row as usize - 1];
            assert_eq!(last as u16 & mask, 0, "ink in row {y}'s padding");
        }
    }
}
