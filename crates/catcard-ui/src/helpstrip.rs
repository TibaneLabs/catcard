//! The help strip: one flat line along the foot of a screen that has help.
//!
//! On the Q1 help is not a row of the menu it explains. A `Help` cell cost a grid a
//! sixth of its first page, and only the three top menus had one -- so the screens a
//! person was most likely to be lost in had nothing. The strip is on every screen that
//! has something to say, in the small face and a dim ink, under the menu rather than in
//! it: the cursor never lands on it, and the arrows, digits and ENTER do exactly what
//! they did before it was there.
//!
//! It is reached by its own keys instead. `TAB` moves the focus onto it, which draws it
//! inverted like a selected row; ENTER then opens the help, and `TAB`, CANCEL or an arrow
//! hands the focus back to the menu where it was. `?` opens the help straight away.
//!
//! This module is the drawing and the key rule; which help a screen opens, and showing
//! it, belong to the firmware.

use crate::canvas::{Canvas, INK, Inset, Level, PAPER};
use crate::face::Face;
use crate::keypad::Key;
use crate::text::{centred, draw_text_in};

/// What the strip says. The `?` is the key that opens it, and the word is what it opens.
pub const LABEL: &str = "? Help";

/// Rows above and below the label: enough that an inverted strip reads as a bar rather
/// than as highlighted text, and no more -- every row here is a row the menu gives up.
const PAD: usize = 1;

/// How tall the strip is, drawn in `face`.
pub fn height(face: &dyn Face) -> usize {
    face.line_height() + 2 * PAD
}

/// The rows the strip occupies at the foot of a canvas `h` tall: `(first row, rows)`.
pub fn rows(h: usize, face: &dyn Face) -> (usize, usize) {
    let n = height(face).min(h);
    (h - n, n)
}

/// How the strip is drawn on one frame.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Strip {
    /// The focus is on the strip: drawn inverted, as a selected row is.
    pub focused: bool,
    /// The label's ink while it does not have the focus. A level, not a colour: which
    /// colour it becomes is the frame's palette -- a grey on a list's ramp, and on the
    /// icon grid whichever entry of the art's palette the caller picks as its dim.
    pub ink: Level,
}

/// Paint the strip into the bottom [`height`] rows of `canvas`, over whatever is there.
pub fn render<C: Canvas + ?Sized>(canvas: &mut C, face: &dyn Face, strip: Strip) {
    let w = canvas.width();
    let (y, h) = rows(canvas.height(), face);
    let (paper, ink) = if strip.focused {
        (INK, PAPER)
    } else {
        (PAPER, strip.ink)
    };
    canvas.fill_rect(0, y, w, h, paper);
    draw_text_in(canvas, face, centred(face, LABEL, w), y + PAD, LABEL, ink);
}

/// Draw a frame with the strip at its foot: `f` gets the band above it, which is all it
/// can see or clear, and the strip goes in under it.
pub fn frame<C: Canvas + ?Sized>(
    canvas: &mut C,
    face: &dyn Face,
    strip: Strip,
    f: impl FnOnce(&mut Inset<'_, C>),
) {
    {
        let mut band = Inset::band(canvas, 0, height(face));
        f(&mut band);
    }
    render(canvas, face, strip);
}

/// What a key does to a screen that has the strip.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Act {
    /// Not the strip's: the screen handles it as it would with no strip there.
    Pass,
    /// The focus moves: onto the strip (`true`) or back to the screen (`false`).
    Focus(bool),
    /// Open the help.
    Open,
    /// The strip has the focus and this key means nothing to it: swallowed, so it does
    /// not act on the menu row nobody is looking at.
    Swallow,
}

/// The Q1's TAB, as the keyboard decodes it.
pub const TAB: Key = Key::Char(b'\t');
/// `?`, typed with SHIFT or SYMBOL.
pub const QUESTION: Key = Key::Char(b'?');

/// What `k` does, with the focus on the strip or not.
///
/// The arrows are digits here (`5` `7` `8` `9`, and `0` for home), as they are everywhere
/// the Q1's keyboard stands in for a numpad; any of them hands the focus back without
/// moving the cursor, so the menu is exactly where it was left.
pub fn key(focused: bool, k: Key) -> Act {
    match (focused, k) {
        (_, QUESTION) => Act::Open,
        (false, TAB) => Act::Focus(true),
        (false, _) => Act::Pass,
        (true, Key::Confirm) => Act::Open,
        (true, TAB | Key::Cancel | Key::Digit(0 | 5 | 7 | 8 | 9)) => Act::Focus(false),
        (true, _) => Act::Swallow,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canvas::{Gray4, Gray320x240};
    use crate::font::peep7x14::FONT;

    /// The Q1's content area under its status bar.
    type Area = Gray4<320, 224, { 320 * 224 / 2 }>;

    const DIM: Level = 8;

    fn drawn_rows(c: &Area) -> impl Iterator<Item = usize> + '_ {
        (0..c.height()).filter(|&y| (0..c.width()).any(|x| c.get(x, y) != PAPER))
    }

    /// One line of the small face and a pixel either side: sixteen rows on the Q1.
    #[test]
    fn the_strip_is_one_small_line_tall() {
        assert_eq!(height(&FONT), FONT.line_height() + 2);
        assert_eq!(height(&FONT), 16);
        assert_eq!(rows(224, &FONT), (208, 16));
        assert_eq!(
            rows(10, &FONT),
            (0, 10),
            "never more rows than the canvas has"
        );
    }

    /// It draws only in its own rows, at the foot, and says what it is.
    #[test]
    fn it_renders_inside_its_rows() {
        let mut c: Box<Area> = Box::default();
        render(
            &mut *c,
            &FONT,
            Strip {
                focused: false,
                ink: DIM,
            },
        );
        let (first, _) = rows(c.height(), &FONT);
        let used: Vec<usize> = drawn_rows(&c).collect();
        assert!(!used.is_empty(), "the label drew nothing");
        assert!(
            used.iter().all(|&y| y >= first),
            "ink above the strip: {used:?}"
        );
        // Dim, not full ink: it is not a menu row.
        for y in first..c.height() {
            for x in 0..c.width() {
                assert!(matches!(c.get(x, y), PAPER | DIM), "{x},{y}");
            }
        }
        // Centred: as much paper left of the label as right of it, to a pixel.
        let xs: Vec<usize> = (0..c.width())
            .filter(|&x| (first..c.height()).any(|y| c.get(x, y) != PAPER))
            .collect();
        let (l, r) = (xs[0], c.width() - 1 - xs[xs.len() - 1]);
        assert!(l.abs_diff(r) <= FONT.width as usize, "left {l}, right {r}");
    }

    /// With the focus it is a bar: every row of it inked, the label cut out of it.
    #[test]
    fn focus_inverts_it() {
        let mut c: Box<Area> = Box::default();
        render(
            &mut *c,
            &FONT,
            Strip {
                focused: true,
                ink: DIM,
            },
        );
        let (first, n) = rows(c.height(), &FONT);
        let ink = (first..first + n)
            .flat_map(|y| (0..c.width()).map(move |x| (x, y)))
            .filter(|&(x, y)| c.get(x, y) == INK)
            .count();
        let paper = (first..first + n)
            .flat_map(|y| (0..c.width()).map(move |x| (x, y)))
            .filter(|&(x, y)| c.get(x, y) == PAPER)
            .count();
        assert!(ink > paper * 4, "not a bar: {ink} ink, {paper} paper");
        assert!(paper > 0, "the label is not cut out of the bar");
        assert!(drawn_rows(&c).all(|y| y >= first), "the bar leaked upwards");
    }

    /// What `frame` hands the screen is the band above the strip: a screen that clears
    /// its canvas, as every widget does, cannot wipe the strip -- and one that fills all
    /// of it stops where the strip starts.
    #[test]
    fn the_screen_above_cannot_reach_the_strip() {
        let mut c: Box<Gray320x240> = Box::default();
        let strip = Strip {
            focused: false,
            ink: DIM,
        };
        let mut seen = 0;
        frame(&mut *c, &FONT, strip, |band| {
            seen = band.height();
            band.fill_rect(0, 0, band.width(), band.height() + 50, INK);
        });
        assert_eq!(seen, 240 - height(&FONT));
        let (first, n) = rows(240, &FONT);
        // The rows of the strip hold only the strip: paper and the dim label.
        for y in first..first + n {
            for x in 0..320 {
                assert!(matches!(c.get(x, y), PAPER | DIM), "{x},{y}");
            }
        }
        assert_eq!(
            c.get(0, first - 1),
            INK,
            "the band did not reach its last row"
        );
    }

    /// Nothing the menu already uses is taken: the arrows, the digits, ENTER and CANCEL
    /// all pass while the strip does not have the focus.
    #[test]
    fn navigation_is_untouched_until_tab() {
        for k in [
            Key::Confirm,
            Key::Cancel,
            Key::Qr,
            Key::Char(b'a'),
            Key::Char(b' '),
        ]
        .into_iter()
        .chain((0..10).map(Key::Digit))
        {
            assert_eq!(key(false, k), Act::Pass, "{k:?}");
        }
        assert_eq!(key(false, TAB), Act::Focus(true));
    }

    /// TAB there, ENTER opens, and every way back returns the focus without acting.
    #[test]
    fn the_focus_goes_and_comes_back() {
        assert_eq!(key(true, Key::Confirm), Act::Open);
        for k in [
            TAB,
            Key::Cancel,
            Key::Digit(5),
            Key::Digit(7),
            Key::Digit(8),
            Key::Digit(9),
            Key::Digit(0),
        ] {
            assert_eq!(key(true, k), Act::Focus(false), "{k:?}");
        }
        // A key that means nothing to the strip does not reach the menu under it either.
        for k in [Key::Digit(1), Key::Char(b'q'), Key::Qr] {
            assert_eq!(key(true, k), Act::Swallow, "{k:?}");
        }
    }

    /// `?` opens the help from anywhere, focus or not.
    #[test]
    fn question_mark_opens_it_directly() {
        assert_eq!(key(false, QUESTION), Act::Open);
        assert_eq!(key(true, QUESTION), Act::Open);
    }
}
