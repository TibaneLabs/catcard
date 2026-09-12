//! The two symbols printed on the keypad.
//!
//! The `y` and `x` this code calls them are names from a wiring diagram, not from the
//! device. What a person is looking at is a **✓** and a **✗** moulded into the caps, so
//! a screen that says "y continue" is asking them to translate — and the translation is
//! exactly the thing that is unreliable on a board whose key map is still in question.
//!
//! These are bitmaps rather than font glyphs because both faces here are ASCII bitmaps
//! generated from BDF, and `✓` is U+2713. Adding codepoints to a generated face to spell
//! two symbols would be a worse trade than five bytes of pixels each.

use crate::art::Bitmap;

/// ✓ — the key this code calls [`crate::keypad::Key::Confirm`].
pub const CHECK: Bitmap = Bitmap {
    width: 5,
    height: 5,
    bytes_per_row: 1,
    // ....#
    // ...#.
    // #..#.
    // .#.#.
    // ..#..
    pixels: &[0x08, 0x10, 0x90, 0x50, 0x20],
};

/// ✗ — the key this code calls [`crate::keypad::Key::Cancel`].
pub const CROSS: Bitmap = Bitmap {
    width: 5,
    height: 5,
    bytes_per_row: 1,
    // #...#
    // .#.#.
    // ..#..
    // .#.#.
    // #...#
    pixels: &[0x88, 0x50, 0x20, 0x50, 0x88],
};

/// Width of an icon plus the gap before the word after it.
pub const ICON_ADVANCE: usize = 7;

/// Draw `✓ label` or `✗ label`, returning where the text ended.
///
/// The icon is centred against the font's cell rather than sharing its baseline, because
/// a 5-pixel square hung off a 14-pixel face's baseline sits visibly low.
pub fn draw_hint<const W: usize, const P: usize, const N: usize>(
    fb: &mut crate::framebuffer::Framebuffer<W, P, N>,
    icon: &Bitmap,
    font: &crate::font::Font,
    x: usize,
    y: usize,
    label: &str,
) -> usize {
    let drop = (font.height as usize).saturating_sub(icon.height as usize) / 2;
    crate::splash::draw_bitmap(fb, icon, x, y + drop);
    crate::text::draw_text(fb, font, x + ICON_ADVANCE, y, label)
}

/// Width `draw_hint` will occupy, for centring a line before drawing it.
pub fn hint_width(font: &crate::font::Font, label: &str) -> usize {
    ICON_ADVANCE + label.len() * font.width as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both symbols must actually have pixels in them, and be square.
    ///
    /// A bitmap whose bytes are all zero draws nothing at all, and "nothing at all" on a
    /// key hint is indistinguishable from a label that was never written.
    #[test]
    fn both_icons_carry_ink_and_are_the_size_they_claim() {
        for (name, b) in [("check", &CHECK), ("cross", &CROSS)] {
            assert_eq!(b.pixels.len(), b.height as usize, "{name}: wrong row count");
            let ink = b.pixels.iter().filter(|p| **p != 0).count();
            assert_eq!(ink, b.height as usize, "{name}: every row should have ink");
            // Nothing may sit in the padding bits, or it draws outside the cell.
            for (y, row) in b.pixels.iter().enumerate() {
                assert_eq!(
                    row & ((1 << (8 - b.width)) - 1),
                    0,
                    "{name}: row {y} has ink in the padding bits"
                );
            }
        }
    }

    /// The cross is symmetric; the check is not. This is how a flipped or mirrored
    /// bitmap gets caught, which matters because both are drawn at 5x5 where a mistake
    /// reads as "slightly odd" rather than as obviously wrong.
    #[test]
    fn the_cross_is_symmetric_and_the_check_is_not() {
        let mirror = |row: u8, w: u16| {
            let mut out = 0u8;
            for x in 0..w {
                if row & (0x80 >> x) != 0 {
                    out |= 0x80 >> (w - 1 - x);
                }
            }
            out
        };
        for (y, row) in CROSS.pixels.iter().enumerate() {
            assert_eq!(*row, mirror(*row, CROSS.width), "cross row {y} is lopsided");
        }
        assert_eq!(
            CROSS.pixels[0], CROSS.pixels[4],
            "cross is not top-bottom even"
        );
        assert!(
            CHECK
                .pixels
                .iter()
                .enumerate()
                .any(|(y, r)| *r != mirror(*r, CHECK.width)
                    || CHECK.pixels[y] != CHECK.pixels[CHECK.height as usize - 1 - y]),
            "the check should not be symmetric -- it would not read as a tick"
        );
    }

    /// The tick's vertex is its lowest point, with both arms above it.
    #[test]
    fn the_check_has_a_vertex_at_the_bottom() {
        let lowest = CHECK.pixels.len() - 1;
        assert_eq!(
            CHECK.pixels[lowest].count_ones(),
            1,
            "the bottom row should be the single vertex pixel"
        );
        assert!(
            CHECK.pixels[0].count_ones() == 1,
            "the top row should be the tip of the long arm"
        );
    }
}
