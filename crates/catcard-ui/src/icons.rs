//! How a screen names the confirm and cancel keys.
//!
//! The `y` and `x` this code calls them are names from a wiring diagram, not from the
//! device. What a person is looking at differs by board: the mk pads carry a **✓** and a
//! **✗** moulded into the caps, and the Q1's keys are printed ENTER and CANCEL. Either
//! way a screen should show what is under their thumb -- a hint that says something else
//! asks them to translate, which is the thing these marks exist to avoid.
//!
//! So a board picks its [`KeyMark`]s and every hint line draws whichever it has. The
//! symbols are bitmaps rather than font glyphs because both bitmap faces here are ASCII,
//! generated from BDF, and `✓` is U+2713: adding codepoints to a generated face to spell
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

/// What a board's confirm or cancel key is labelled with.
///
/// A fact about the hardware, like the key map: the board layer picks these, not the
/// layout, because it is about the caps rather than the panel.
#[derive(Copy, Clone)]
pub enum KeyMark {
    /// A symbol moulded into the cap, drawn as pixels beside the label.
    Icon(&'static Bitmap),
    /// A word printed on the cap, drawn in the same face as the label.
    Word(&'static str),
}

/// Draw `<mark> label`, returning where the text ended.
pub fn draw_key_hint<C: crate::canvas::Canvas + ?Sized, F: crate::face::Face + ?Sized>(
    fb: &mut C,
    font: &F,
    x: usize,
    y: usize,
    mark: KeyMark,
    label: &str,
) -> usize {
    match mark {
        KeyMark::Icon(icon) => draw_hint(fb, icon, font, x, y, label),
        KeyMark::Word(word) => {
            let at = crate::text::draw_text(fb, font, x, y, word);
            crate::text::draw_text(fb, font, at + font.advance(b' '), y, label)
        }
    }
}

/// Width [`draw_key_hint`] will occupy, for centring a line before drawing it.
pub fn key_hint_width<F: crate::face::Face + ?Sized>(
    font: &F,
    mark: KeyMark,
    label: &str,
) -> usize {
    match mark {
        KeyMark::Icon(_) => hint_width(font, label),
        KeyMark::Word(word) => {
            crate::text::width_of(font, word)
                + font.advance(b' ')
                + crate::text::width_of(font, label)
        }
    }
}

/// Width of an icon plus the gap before the word after it, at 1x.
pub const ICON_ADVANCE: usize = 7;

/// How much to grow a 5x5 icon so it reads beside `font`.
///
/// The icons are drawn as pixels, not as glyphs, so they do not grow with the face on
/// their own: beside the 4x6 status face they are the size they were drawn, and beside a
/// 7x14 one they need doubling. One step per seven pixels of line height, never below 1.
pub fn icon_scale<F: crate::face::Face + ?Sized>(font: &F) -> usize {
    (font.line_height() / 7).max(1)
}

/// Draw `✓ label` or `✗ label`, returning where the text ended.
///
/// The icon is centred against the font's cell rather than sharing its baseline, because
/// a 5-pixel square hung off a 14-pixel face's baseline sits visibly low.
pub fn draw_hint<C: crate::canvas::Canvas + ?Sized, F: crate::face::Face + ?Sized>(
    fb: &mut C,
    icon: &Bitmap,
    font: &F,
    x: usize,
    y: usize,
    label: &str,
) -> usize {
    let scale = icon_scale(font);
    let drop = font
        .line_height()
        .saturating_sub(icon.height as usize * scale)
        / 2;
    crate::splash::draw_bitmap_scaled(fb, icon, x, y + drop, scale);
    crate::text::draw_text(fb, font, x + ICON_ADVANCE * scale, y, label)
}

/// Width `draw_hint` will occupy, for centring a line before drawing it.
pub fn hint_width<F: crate::face::Face + ?Sized>(font: &F, label: &str) -> usize {
    ICON_ADVANCE * icon_scale(font) + crate::text::width_of(font, label)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canvas::{Canvas, Gray320x240, PAPER};
    use crate::font::{misc4x6, peep7x14};

    #[test]
    fn a_word_mark_reads_as_the_cap_does_and_measures_the_same() {
        // The Q1's keys say ENTER and CANCEL; drawing a tick there would name a key the
        // board does not have.
        let f = &peep7x14::FONT;
        let mark = KeyMark::Word("ENTER");
        let mut c = Gray320x240::new();
        let end = draw_key_hint(&mut c, f, 0, 0, mark, "accept");
        assert_eq!(end, ("ENTER".len() + 1 + "accept".len()) * 7);
        assert_eq!(key_hint_width(f, mark, "accept"), end, "width disagrees with the draw");
        assert!((0..14).any(|y| (0..35).any(|x| c.get(x, y) != PAPER)), "no word drawn");
    }

    #[test]
    fn an_icon_mark_measures_the_same_as_the_icon_hint() {
        let f = &peep7x14::FONT;
        let mark = KeyMark::Icon(&CHECK);
        assert_eq!(key_hint_width(f, mark, "yes"), hint_width(f, "yes"));
        let mut a = Gray320x240::new();
        let mut b = Gray320x240::new();
        let ea = draw_key_hint(&mut a, f, 0, 0, mark, "yes");
        let eb = draw_hint(&mut b, &CHECK, f, 0, 0, "yes");
        assert_eq!(ea, eb);
    }

    #[test]
    fn an_icon_grows_with_the_face_beside_it_and_the_label_follows() {
        assert_eq!(icon_scale(&misc4x6::FONT), 1, "4x6 keeps the drawn size");
        assert_eq!(icon_scale(&peep7x14::FONT), 2, "7x14 doubles it");

        // The label starts past the scaled icon, and the reported width covers both.
        let mut c = Gray320x240::new();
        let end = draw_hint(&mut c, &CHECK, &peep7x14::FONT, 0, 0, "yes");
        assert_eq!(end, ICON_ADVANCE * 2 + 3 * 7);
        assert_eq!(hint_width(&peep7x14::FONT, "yes"), end);
        // A 5x5 tick at 2x covers ten rows; at 1x it would stop at five.
        let ink_rows = (0..20)
            .filter(|&y| (0..ICON_ADVANCE * 2).any(|x| c.get(x, y) != PAPER))
            .count();
        assert!(ink_rows >= 9, "the tick did not grow: {ink_rows} rows of ink");
    }

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
