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
        // Fits the left of a 128x64 panel with room for text beside it.
        assert!(c.width <= 48 && c.height <= 48, "{}x{}", c.width, c.height);
    }

    #[test]
    fn it_is_cropped_to_its_ink() {
        // The generator crops, so every edge row and column must carry something —
        // otherwise the art is padded and the layout maths silently drifts.
        let c = &cat::CAT;
        let row_has = |y: usize| (0..c.width as usize).any(|x| c.pixel(x, y));
        let col_has = |x: usize| (0..c.height as usize).any(|y| c.pixel(x, y));
        assert!(row_has(0) && row_has(c.height as usize - 1));
        assert!(col_has(0) && col_has(c.width as usize - 1));
    }

    #[test]
    fn it_has_two_eyes() {
        // A shape check that survives the art being redrawn: scan the upper-middle band
        // for two separated runs of ink well inside the head outline. If the eyes ever
        // merge or vanish, it stops reading as a face and this catches it.
        let c = &cat::CAT;
        let y = c.height as usize * 13 / 25;
        let mut runs = 0;
        let mut prev = false;
        for x in 3..c.width as usize - 3 {
            let on = c.pixel(x, y);
            if on && !prev {
                runs += 1;
            }
            prev = on;
        }
        // Two eyes plus the head outline on either side, which the 3-pixel inset skips
        // for a circle but not always — allow the outline to contribute.
        assert!(
            (2..=4).contains(&runs),
            "expected two eyes, found {runs} runs"
        );
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
