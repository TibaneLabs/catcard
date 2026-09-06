//! Bitmap faces.
//!
//! Three sizes, converted from their upstream BDF sources by
//! `tools/fontgen/bdf2rs.py`. Two are the faces a Coldcard renders with, which is
//! deliberate: they are upstream public fonts, not Coinkite assets, and using them keeps
//! the device visually familiar without taking anything that is not freely licensed.
//!
//! | face | size | licence | use |
//! |---|---|---|---|
//! | [`peep7x14`] | 7x14 | MIT, (c) 2007-2012 Zevv | body, menus |
//! | [`peep10x20`] | 10x20 | MIT, (c) 2007-2012 Zevv | titles |
//! | [`misc4x6`] | 4x6 | public domain (X11 misc-fixed) | dense status text |
//!
//! zevv-peep is **MIT, not public domain** — it carries an attribution requirement, met
//! by `THIRD-PARTY-NOTICES.md` at the repository root. Dropping that notice would make
//! the distribution non-compliant, so it is not optional.

pub mod misc4x6;
pub mod peep10x20;
pub mod peep7x14;

/// A fixed-cell bitmap face, row-major with the most significant bit leftmost.
pub struct Font {
    /// Cell width in pixels. May be narrower than `bytes_per_row * 8`.
    pub width: u8,
    /// Cell height in pixels.
    pub height: u8,
    /// Bytes each row occupies. Rows are left-aligned, so trailing bits are padding.
    pub bytes_per_row: u8,
    pub first: u8,
    pub last: u8,
    pub glyphs: &'static [u8],
}

impl Font {
    /// Bytes one glyph occupies.
    pub const fn glyph_len(&self) -> usize {
        self.bytes_per_row as usize * self.height as usize
    }

    /// The bitmap for `c`, or `?` if it is outside the face.
    ///
    /// Substituting keeps rendering total: a stray byte in a label shows as `?` rather
    /// than aborting a screen draw or, worse, indexing out of the table.
    pub fn glyph(&self, c: u8) -> &'static [u8] {
        let idx = if c >= self.first && c <= self.last {
            (c - self.first) as usize
        } else {
            (b'?' - self.first) as usize
        };
        let at = idx * self.glyph_len();
        &self.glyphs[at..at + self.glyph_len()]
    }

    /// Whether pixel `(x, y)` of `glyph` is set.
    pub fn pixel(&self, glyph: &[u8], x: usize, y: usize) -> bool {
        if x >= self.width as usize || y >= self.height as usize {
            return false;
        }
        let byte = glyph[y * self.bytes_per_row as usize + x / 8];
        byte & (0x80 >> (x % 8)) != 0
    }

    /// Characters that fit across `px` pixels.
    pub const fn columns(&self, px: usize) -> usize {
        px / self.width as usize
    }

    /// Lines that fit down `px` pixels.
    pub const fn rows(&self, px: usize) -> usize {
        px / self.height as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn faces() -> [&'static Font; 3] {
        [&peep7x14::FONT, &peep10x20::FONT, &misc4x6::FONT]
    }

    #[test]
    fn every_face_covers_printable_ascii() {
        for f in faces() {
            assert_eq!(f.first, 0x20);
            assert_eq!(f.last, 0x7E);
            let expect = (f.last - f.first + 1) as usize * f.glyph_len();
            assert_eq!(f.glyphs.len(), expect, "{}x{}", f.width, f.height);
        }
    }

    #[test]
    fn declared_sizes_match_their_sources() {
        assert_eq!((peep7x14::FONT.width, peep7x14::FONT.height), (7, 14));
        assert_eq!((peep10x20::FONT.width, peep10x20::FONT.height), (10, 20));
        assert_eq!((misc4x6::FONT.width, misc4x6::FONT.height), (4, 6));
    }

    #[test]
    fn space_is_blank_and_letters_are_not() {
        for f in faces() {
            assert!(
                f.glyph(b' ').iter().all(|&b| b == 0),
                "space has ink in {}x{}",
                f.width,
                f.height
            );
            for c in *b"Az0#" {
                assert!(
                    f.glyph(c).iter().any(|&b| b != 0),
                    "{:?} is blank in {}x{}",
                    c as char,
                    f.width,
                    f.height
                );
            }
        }
    }

    #[test]
    fn out_of_range_characters_fall_back_to_question_mark() {
        for f in faces() {
            let q = f.glyph(b'?');
            assert_eq!(f.glyph(0x00), q);
            assert_eq!(f.glyph(0x7F), q);
            assert_eq!(f.glyph(0xFF), q);
        }
    }

    #[test]
    fn padding_bits_beyond_the_cell_width_are_clear() {
        // Rows are left-aligned in whole bytes. Ink in the padding would render as a
        // stray column belonging to the next character.
        for f in faces() {
            let pad = f.bytes_per_row as usize * 8 - f.width as usize;
            if pad == 0 {
                continue;
            }
            let mask = (1u16 << pad) - 1;
            for c in f.first..=f.last {
                for (i, &b) in f.glyph(c).iter().enumerate() {
                    if i % f.bytes_per_row as usize == f.bytes_per_row as usize - 1 {
                        assert_eq!(
                            b as u16 & mask,
                            0,
                            "{:?} has ink in the padding of a {}x{} cell",
                            c as char,
                            f.width,
                            f.height
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn glyphs_are_the_right_way_up() {
        // Cheap shape check that the BDF baseline compositing is right. A glyph placed
        // at the wrong vertical offset still has ink, so blank/non-blank would pass
        // while the whole face sat upside down or a row out.
        //
        // 'T' is a bar on top of a stem and 'L' a stem on top of a foot, so the widest
        // row of each is unambiguous and font-independent. (An earlier version of this
        // test guessed that 'A' is widest at its feet — it is not: this face gives it a
        // 4-pixel flat apex and 2-pixel legs.)
        for f in faces() {
            for (c, widest_should_be_first) in [(b'T', true), (b'L', false)] {
                let g = f.glyph(c);
                let width_at =
                    |y: usize| (0..f.width as usize).filter(|&x| f.pixel(g, x, y)).count();
                let inked: Vec<usize> = (0..f.height as usize)
                    .filter(|&y| width_at(y) > 0)
                    .collect();
                let widest = *inked
                    .iter()
                    .max_by_key(|&&y| width_at(y))
                    .expect("glyph has ink");
                let expect = if widest_should_be_first {
                    *inked.first().unwrap()
                } else {
                    *inked.last().unwrap()
                };
                assert_eq!(
                    widest, expect,
                    "{:?} is oriented wrongly in {}x{}",
                    c as char, f.width, f.height
                );
            }
        }
    }

    #[test]
    fn descenders_sit_lower_than_baseline_letters() {
        // The specific thing a flipped baseline offset breaks.
        for f in faces() {
            let lowest = |c: u8| {
                let g = f.glyph(c);
                (0..f.height as usize)
                    .rfind(|&y| (0..f.width as usize).any(|x| f.pixel(g, x, y)))
                    .unwrap_or(0)
            };
            assert!(
                lowest(b'g') > lowest(b'o'),
                "'g' does not descend below 'o' in {}x{}",
                f.width,
                f.height
            );
        }
    }

    #[test]
    fn a_128_pixel_panel_fits_the_expected_line_lengths() {
        assert_eq!(peep7x14::FONT.columns(128), 18);
        assert_eq!(peep10x20::FONT.columns(128), 12);
        assert_eq!(misc4x6::FONT.columns(128), 32);
        assert_eq!(peep7x14::FONT.rows(64), 4);
        assert_eq!(misc4x6::FONT.rows(64), 10);
    }
}
