//! Text rendering onto a framebuffer.
//!
//! Every entry point takes the [`Font`] explicitly. The previous version hardcoded an
//! 8x8 cell, which quietly ruled out the faces the device actually wants — a title face
//! and a dense status face are different sizes, and a renderer that assumes one of them
//! cannot draw the other.

use crate::font::Font;
use crate::framebuffer::Framebuffer;

/// Draw one character with its top-left at `(x, y)`. Clipped, never panics.
pub fn draw_char<const W: usize, const P: usize, const N: usize>(
    fb: &mut Framebuffer<W, P, N>,
    font: &Font,
    x: usize,
    y: usize,
    c: u8,
) {
    let g = font.glyph(c);
    for gy in 0..font.height as usize {
        for gx in 0..font.width as usize {
            if font.pixel(g, gx, gy) {
                fb.set(x + gx, y + gy, true);
            }
        }
    }
}

/// Draw a string. Returns the x coordinate just past the last glyph.
///
/// Stops at the right edge rather than wrapping: a truncated address is obviously
/// truncated, whereas a wrapped one can look like a different, complete address.
pub fn draw_text<const W: usize, const P: usize, const N: usize>(
    fb: &mut Framebuffer<W, P, N>,
    font: &Font,
    x: usize,
    y: usize,
    text: &str,
) -> usize {
    let mut at = x;
    for &c in text.as_bytes() {
        if at + font.width as usize > W {
            break;
        }
        draw_char(fb, font, at, y, c);
        at += font.width as usize;
    }
    at
}

/// Draw text wrapped across lines, breaking at the panel edge.
///
/// Returns the number of lines drawn. For strings that must be shown in full — a
/// mnemonic, an address — where truncating would be worse than wrapping.
pub fn draw_wrapped<const W: usize, const P: usize, const N: usize>(
    fb: &mut Framebuffer<W, P, N>,
    font: &Font,
    x: usize,
    y: usize,
    text: &str,
) -> usize {
    let per_line = font.columns(W - x).max(1);
    let mut lines = 0;
    for (i, chunk) in text.as_bytes().chunks(per_line).enumerate() {
        let row = y + i * font.height as usize;
        if row + font.height as usize > P * 8 {
            break;
        }
        let mut at = x;
        for &c in chunk {
            draw_char(fb, font, at, row, c);
            at += font.width as usize;
        }
        lines += 1;
    }
    lines
}

/// Width in pixels a string would occupy, ignoring clipping.
pub fn width_of(font: &Font, text: &str) -> usize {
    text.len() * font.width as usize
}

/// The x coordinate that centres `text` on a `W`-pixel panel, clamped to 0.
pub fn centred(font: &Font, text: &str, panel_width: usize) -> usize {
    panel_width.saturating_sub(width_of(font, text)) / 2
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::font::{misc4x6, peep10x20, peep7x14};
    use crate::framebuffer::Mono128x64;

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
}
