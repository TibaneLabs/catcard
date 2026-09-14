//! What text drawing needs from a typeface, whatever kind of typeface it is.
//!
//! The faces in [`crate::font`] are one kind: 1-bit, fixed cell. An anti-aliased face baked
//! for the Q1's colour panel is another -- 4-bit coverage per pixel, possibly with its own
//! advance per character. Text and the widgets are written against this trait, so they draw
//! with either kind, on either kind of [`Canvas`](crate::canvas::Canvas).
//!
//! Object-safe on purpose: a [`Layout`](crate::widgets::Layout) holds `&dyn Face`, so the
//! choice of face is a value a board picks at run time, not a type parameter threaded
//! through every screen.

use crate::canvas::{INK, Level, PAPER};
use crate::font::Font;

pub trait Face {
    /// Pixels from the top of one line to the top of the next, before any extra spacing.
    fn line_height(&self) -> usize;

    /// How far the pen moves after drawing `c`.
    fn advance(&self, c: u8) -> usize;

    /// Ink coverage of pixel `(x, y)` in `c`'s cell: 0 none, 15 solid, anything between an
    /// anti-aliased edge. Outside the cell reads 0.
    fn coverage(&self, c: u8, x: usize, y: usize) -> Level;

    /// Width of the cell [`coverage`](Self::coverage) is asked about. The advance, unless a
    /// face draws past it.
    fn cell_width(&self, c: u8) -> usize {
        self.advance(c)
    }
}

/// A 1-bit bitmap face: every set pixel is solid ink.
impl Face for Font {
    fn line_height(&self) -> usize {
        self.height as usize
    }

    fn advance(&self, _c: u8) -> usize {
        self.width as usize
    }

    fn coverage(&self, c: u8, x: usize, y: usize) -> Level {
        if self.pixel(self.glyph(c), x, y) {
            INK
        } else {
            PAPER
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::font::{misc4x6, peep7x14, peep10x20};

    #[test]
    fn a_bitmap_face_reports_its_cell_and_solid_coverage() {
        for f in [&misc4x6::FONT, &peep7x14::FONT, &peep10x20::FONT] {
            let face: &dyn Face = f;
            assert_eq!(face.line_height(), f.height as usize);
            assert_eq!(face.advance(b'W'), f.width as usize);
            assert_eq!(face.cell_width(b'W'), f.width as usize);
            let levels: Vec<Level> = (0..f.height as usize)
                .flat_map(|y| (0..f.width as usize).map(move |x| face.coverage(b'#', x, y)))
                .collect();
            assert!(levels.contains(&INK), "'#' has no ink");
            assert!(
                levels.iter().all(|&l| l == INK || l == PAPER),
                "a bitmap has no greys"
            );
            assert_eq!(face.coverage(b'#', 100, 100), PAPER, "outside the cell");
        }
    }
}
