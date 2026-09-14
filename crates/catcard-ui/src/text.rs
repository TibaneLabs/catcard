//! Text rendering onto any [`Canvas`], in any [`Face`].
//!
//! Every entry point takes the face explicitly. An earlier version hardcoded an 8x8 cell,
//! which quietly ruled out the faces the device actually wants — a title face and a dense
//! status face are different sizes. The same reasoning now extends to the canvas: nothing
//! here knows how big the panel is except by asking it.

use crate::canvas::{Canvas, INK, Level};
use crate::face::Face;

/// Draw one character in full ink with its top-left at `(x, y)`. Clipped, never panics.
/// Returns the face's advance for it.
pub fn draw_char<C: Canvas + ?Sized, F: Face + ?Sized>(
    canvas: &mut C,
    font: &F,
    x: usize,
    y: usize,
    c: u8,
) -> usize {
    draw_char_in(canvas, font, x, y, c, INK)
}

/// Draw one character at `ink`, blending each pixel by the face's coverage.
pub fn draw_char_in<C: Canvas + ?Sized, F: Face + ?Sized>(
    canvas: &mut C,
    font: &F,
    x: usize,
    y: usize,
    c: u8,
    ink: Level,
) -> usize {
    for gy in 0..font.line_height() {
        for gx in 0..font.cell_width(c) {
            let cov = font.coverage(c, gx, gy);
            if cov != 0 {
                canvas.blend(x.saturating_add(gx), y.saturating_add(gy), ink, cov);
            }
        }
    }
    font.advance(c)
}

/// Draw a string in full ink. Returns the x coordinate just past the last glyph.
///
/// Stops at the right edge rather than wrapping: a truncated address is obviously
/// truncated, whereas a wrapped one can look like a different, complete address.
pub fn draw_text<C: Canvas + ?Sized, F: Face + ?Sized>(
    canvas: &mut C,
    font: &F,
    x: usize,
    y: usize,
    text: &str,
) -> usize {
    draw_text_in(canvas, font, x, y, text, INK)
}

/// [`draw_text`] at a chosen ink level.
pub fn draw_text_in<C: Canvas + ?Sized, F: Face + ?Sized>(
    canvas: &mut C,
    font: &F,
    x: usize,
    y: usize,
    text: &str,
    ink: Level,
) -> usize {
    let mut at = x;
    for &c in text.as_bytes() {
        let adv = font.advance(c);
        if at + adv > canvas.width() {
            break;
        }
        draw_char_in(canvas, font, at, y, c, ink);
        at += adv;
    }
    at
}

/// Draw text wrapped across lines, breaking at the canvas edge.
///
/// Returns the number of lines drawn. For strings that must be shown in full — a
/// mnemonic, an address — where truncating would be worse than wrapping. A character too
/// wide for a line on its own still gets a line of its own, clipped, rather than stalling.
pub fn draw_wrapped<C: Canvas + ?Sized, F: Face + ?Sized>(
    canvas: &mut C,
    font: &F,
    x: usize,
    y: usize,
    text: &str,
) -> usize {
    let lh = font.line_height();
    let (mut at, mut row, mut lines, mut started) = (x, y, 0, false);
    for &c in text.as_bytes() {
        let adv = font.advance(c);
        if started && at + adv > canvas.width() {
            row += lh;
            at = x;
            started = false;
        }
        if row + lh > canvas.height() {
            break;
        }
        if !started {
            lines += 1;
            started = true;
        }
        draw_char_in(canvas, font, at, row, c, INK);
        at += adv;
    }
    lines
}

/// Width in pixels a string would occupy, ignoring clipping.
pub fn width_of<F: Face + ?Sized>(font: &F, text: &str) -> usize {
    text.as_bytes().iter().map(|&c| font.advance(c)).sum()
}

/// The x coordinate that centres `text` across `panel_width` pixels, clamped to 0.
pub fn centred<F: Face + ?Sized>(font: &F, text: &str, panel_width: usize) -> usize {
    panel_width.saturating_sub(width_of(font, text)) / 2
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canvas::{Gray320x240, PAPER};
    use crate::font::{misc4x6, peep7x14, peep10x20};
    use crate::framebuffer::{Framebuffer, Mono128x64};

    fn ink<const W: usize, const P: usize, const N: usize>(fb: &Framebuffer<W, P, N>) -> u32 {
        fb.as_bytes().iter().map(|b| b.count_ones()).sum()
    }

    #[test]
    fn drawing_marks_pixels() {
        for f in [&peep7x14::FONT, &peep10x20::FONT, &misc4x6::FONT] {
            let mut fb = Mono128x64::new();
            assert_eq!(ink(&fb), 0);
            draw_text(&mut fb, f, 0, 0, "CatCard");
            assert!(ink(&fb) > 0, "{}x{} drew nothing", f.width, f.height);
        }
    }

    #[test]
    fn a_space_draws_nothing() {
        let mut fb = Mono128x64::new();
        draw_text(&mut fb, &peep7x14::FONT, 0, 0, "   ");
        assert_eq!(ink(&fb), 0);
    }

    #[test]
    fn text_is_truncated_at_the_edge_not_wrapped() {
        // A wrapped address can look like a complete, different address.
        let f = &peep7x14::FONT;
        let fits = "x".repeat(f.columns(128));
        let mut a = Mono128x64::new();
        draw_text(&mut a, f, 0, 0, &fits);
        let mut b = Mono128x64::new();
        draw_text(&mut b, f, 0, 0, &(fits.clone() + "yyyy"));
        assert_eq!(a.as_bytes(), b.as_bytes(), "extra characters leaked");
    }

    #[test]
    fn draw_text_reports_where_it_stopped() {
        let mut fb = Mono128x64::new();
        assert_eq!(draw_text(&mut fb, &peep7x14::FONT, 0, 0, "abc"), 21);
        assert_eq!(draw_text(&mut fb, &misc4x6::FONT, 0, 0, "abc"), 12);
        assert_eq!(draw_text(&mut fb, &peep7x14::FONT, 8, 0, ""), 8);
    }

    #[test]
    fn drawing_off_screen_is_clipped_not_a_panic() {
        let mut fb = Mono128x64::new();
        draw_char(&mut fb, &peep10x20::FONT, 1000, 1000, b'X');
        draw_char(&mut fb, &peep10x20::FONT, 124, 60, b'X');
        draw_char(&mut fb, &peep10x20::FONT, usize::MAX, usize::MAX, b'X');
        draw_text(&mut fb, &peep7x14::FONT, 120, 0, "long string here");
        assert!(ink(&fb) > 0);
    }

    #[test]
    fn lines_land_where_they_are_placed() {
        // A 14-pixel face straddles pages, so the framebuffer's page arithmetic has to
        // hold for unaligned y. An off-by-one here shifts every line on the device.
        let f = &peep7x14::FONT;
        let mut fb = Mono128x64::new();
        draw_char(&mut fb, f, 0, 0, b'#');
        assert!(fb.as_bytes()[..128].iter().any(|&b| b != 0), "page 0 empty");
        assert!(
            fb.as_bytes()[128..256].iter().any(|&b| b != 0),
            "page 1 empty"
        );
        assert!(
            fb.as_bytes()[256..].iter().all(|&b| b == 0),
            "ink below a 14-pixel glyph drawn at y=0"
        );
    }

    #[test]
    fn wrapping_shows_every_character_and_stops_at_the_bottom() {
        let f = &misc4x6::FONT;
        let mut fb = Mono128x64::new();
        let cols = f.columns(128);
        let lines = draw_wrapped(&mut fb, f, 0, 0, &"a".repeat(cols * 3));
        assert_eq!(lines, 3);

        let mut fb = Mono128x64::new();
        let lines = draw_wrapped(&mut fb, f, 0, 0, &"a".repeat(cols * 50));
        assert_eq!(lines, f.rows(64), "should fill the panel and stop");
    }

    #[test]
    fn centring_is_symmetric_and_never_underflows() {
        let f = &peep7x14::FONT;
        assert_eq!(centred(f, "", 128), 64);
        // 7 chars * 7px = 49; (128-49)/2 = 39
        assert_eq!(centred(f, "CatCard", 128), 39);
        // Longer than the panel clamps rather than wrapping around.
        assert_eq!(centred(f, &"x".repeat(40), 128), 0);
    }

    #[test]
    fn the_same_calls_fill_a_320x240_canvas_to_its_own_edges() {
        let f = &peep7x14::FONT;
        let mut c = Gray320x240::new();
        let cols = f.columns(320);
        assert_eq!(draw_text(&mut c, f, 0, 0, &"x".repeat(cols + 5)), cols * 7);
        let lines = draw_wrapped(&mut c, f, 0, 0, &"a".repeat(cols * 100));
        assert_eq!(lines, f.rows(240));
    }

    #[test]
    fn ink_level_is_what_lands_on_a_gray_canvas() {
        let f = &peep10x20::FONT;
        let mut c = Gray320x240::new();
        draw_text_in(&mut c, f, 0, 0, "#", 6);
        let levels: Vec<Level> = (0..20)
            .flat_map(|y| (0..10).map(move |x| (x, y)))
            .map(|(x, y)| c.get(x, y))
            .collect();
        assert!(levels.contains(&6));
        assert!(levels.iter().all(|&l| l == 6 || l == PAPER));
    }
}
