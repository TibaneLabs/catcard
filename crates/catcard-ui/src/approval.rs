//! A question that needs a yes, laid out as a page with a picture: the colour panel's
//! version of "allow this?".
//!
//! The action heads the page, a picture sits under it, and what the question is about --
//! a site, a file, a device -- is the line under the picture, in the body face and wrapped
//! if it is long. Smaller facts follow (the account, which wallet), and the keys that
//! answer it sit along the bottom. Nothing scrolls: what does not fit is left out rather
//! than pushed below the keys, so the answer is always on the screen.
//!
//! Drawn in the icon palette (`art::menuicons::PALETTE`), where text levels and the art's
//! colours share one table, the way the picture pages already draw.

use crate::art::indexed::{Indexed, draw_indexed};
use crate::canvas::Canvas;
use crate::face::Face;
use crate::icons::{KeyMark, draw_answer_row};
use crate::scroll::Fonts;
use crate::text::{centred, draw_text, wrap};

/// What the page says.
pub struct Approval<'a> {
    /// The action, as the heading: "Register", "Sign in".
    pub head: &'a str,
    /// The picture under it, on a panel that can show one.
    pub art: Option<&'a Indexed>,
    /// What the question is about, the page's main line: at most two lines when wrapped,
    /// or three in the small face where the body face would need more.
    pub main: &'a str,
    /// Smaller lines under it, each wrapped to at most two lines, dropped from the end
    /// when they would reach the keys.
    pub small: &'a [&'a str],
    /// The key that says yes, as the board marks it, and what it does: `allow`.
    pub yes: (KeyMark, &'a str),
    /// The key that says no, and what it does: `refuse`.
    pub no: (KeyMark, &'a str),
}

/// Draw `text` centred in `face` from `y`, at most `most` lines (up to two), or in
/// `fallback` -- up to three -- when `face` would need more. Stops above `limit`. Returns where the next line goes.
#[allow(clippy::too_many_arguments)]
fn block<C: Canvas + ?Sized>(
    c: &mut C,
    face: &dyn Face,
    most: usize,
    fallback: &dyn Face,
    fonts: &Fonts<'_>,
    text: &str,
    mut y: usize,
    limit: usize,
) -> usize {
    let width = c.width().saturating_sub(2 * fonts.margin);
    let (two, cut) = wrap::<_, 2>(face, text, width);
    let mut lines: heapless::Vec<&str, 3> = two.iter().copied().collect();
    let mut f = face;
    if cut || lines.len() > most {
        lines = wrap::<_, 3>(fallback, text, width).0;
        f = fallback;
    }
    for l in &lines {
        if y + f.line_height() > limit {
            break;
        }
        draw_text(c, f, centred(f, l, c.width()), y, l);
        y += f.line_height() + fonts.gap;
    }
    y
}

/// Draw `a` over the whole canvas.
pub fn draw<C: Canvas + ?Sized>(c: &mut C, fonts: &Fonts<'_>, a: &Approval<'_>) {
    c.clear();
    let (w, h) = (c.width(), c.height());
    // Spacing follows the panel's own margin: generous on the colour panel, a couple of
    // pixels on the 64-row one.
    let space = fonts.margin + 2;

    // The answers own the bottom line; everything else stops short of it.
    let keys_y = h.saturating_sub(fonts.small.line_height() + space / 2);
    let limit = keys_y.saturating_sub(space / 2);

    // The heading gets one line in its own face: on the 64-row panel a second would take
    // the room the warning under it needs.
    let mut y = block(c, fonts.title, 1, fonts.small, fonts, a.head, space, limit) + space;
    if let Some(art) = a.art {
        let (aw, ah) = (art.width as usize, art.height as usize);
        if y + ah <= limit {
            draw_indexed(c, art, w.saturating_sub(aw) / 2, y);
            y += ah + space;
        }
    }
    if !a.main.is_empty() {
        y = block(c, fonts.body, 2, fonts.small, fonts, a.main, y, limit) + space / 2;
    }
    for s in a.small {
        y = block(c, fonts.small, 2, fonts.small, fonts, s, y, limit);
    }

    draw_answer_row(c, fonts.small, keys_y, a.yes, a.no);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canvas::{Gray320x240, Inset, PAPER};
    use crate::font::{peep7x14, peep10x20};

    const FONTS: Fonts<'static> = Fonts {
        title: &peep10x20::FONT,
        body: &peep10x20::FONT,
        small: &peep7x14::FONT,
        gap: 2,
        margin: 6,
        colour: true,
        scrollbar: 6,
    };

    fn rows_inked<C: Canvas + ?Sized>(c: &C) -> heapless::Vec<usize, 240> {
        let mut v = heapless::Vec::new();
        for y in 0..c.height() {
            if (0..c.width()).any(|x| c.get(x, y) != PAPER) {
                let _ = v.push(y);
            }
        }
        v
    }

    /// Every part lands on the page, top to bottom, and the keys are the last thing drawn
    /// -- nothing overlaps them, however much small print there is.
    #[test]
    fn a_page_with_everything_keeps_the_keys_on_screen() {
        let mut fb = Gray320x240::new();
        let mut c = Inset::new(&mut fb, 16);
        let small = [
            "as someone.with.a.rather.long.name@example.com",
            "Wallet: root 1A2B3C4D",
            "This wallet already has a login here.",
            "and one more line that should be dropped rather than cover the keys",
        ];
        let a = Approval {
            head: "Register",
            art: Some(&crate::art::menuicons::SECURE_KEY),
            main: "accounts.some-very-long-domain.example.com",
            small: &small,
            yes: (KeyMark::Word("ENTER"), "allow"),
            no: (KeyMark::Word("CANCEL"), "refuse"),
        };
        draw(&mut c, &FONTS, &a);
        let rows = rows_inked(&c);
        let last = *rows.last().unwrap();
        let space = FONTS.margin + 2;
        let hint_top = c.height() - (peep7x14::FONT.line_height() + space / 2);
        assert!(last >= hint_top, "the keys are not along the bottom");
        assert!(last < c.height());
        // A band of paper just above the keys: the small print stopped short of them.
        assert!(
            (hint_top.saturating_sub(space / 2)..hint_top).all(|y| !rows.contains(&y)),
            "something runs into the keys"
        );
        // The heading is at the top.
        assert!(rows.first().copied().unwrap() < space + peep10x20::FONT.line_height());
    }

    /// A short page draws what it has and leaves the rest of the canvas blank.
    #[test]
    fn a_short_page_is_short() {
        let mut fb = Gray320x240::new();
        let mut c = Inset::new(&mut fb, 16);
        let a = Approval {
            head: "Sign in",
            art: Some(&crate::art::menuicons::SECURE_KEY),
            main: "example.com",
            small: &[],
            yes: (KeyMark::Word("ENTER"), "allow"),
            no: (KeyMark::Word("CANCEL"), "refuse"),
        };
        draw(&mut c, &FONTS, &a);
        assert!(!rows_inked(&c).is_empty());
    }

    /// On the 128x64 panel, with no picture and the tick/cross marks, a warning whose
    /// sentence is too long for two body lines still says all of it -- in the small face
    /// -- and the keys stay along the bottom.
    #[test]
    fn a_mono_page_keeps_the_whole_warning() {
        use crate::font::misc4x6;
        use crate::framebuffer::Mono128x64;
        let mono = Fonts {
            title: &peep7x14::FONT,
            body: &peep7x14::FONT,
            small: &misc4x6::FONT,
            gap: 1,
            margin: 2,
            colour: false,
            scrollbar: 3,
        };
        let text = "Every site this wallet registered with stops accepting it.";
        let (_, cut) = wrap::<_, 3>(&misc4x6::FONT, text, 128 - 4);
        assert!(!cut, "the small face should fit it in three lines");
        let mut fb = Mono128x64::new();
        let a = Approval {
            head: "Reset security key?",
            art: None,
            main: text,
            small: &["This cannot be undone."],
            yes: (KeyMark::Icon(&crate::icons::CHECK), "reset"),
            no: (KeyMark::Icon(&crate::icons::CROSS), "keep it"),
        };
        draw(&mut fb, &mono, &a);
        let rows = rows_inked(&fb);
        assert!(
            *rows.last().unwrap() >= 64 - 7,
            "the keys are not along the bottom"
        );
    }
}
