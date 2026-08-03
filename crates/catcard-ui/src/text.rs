//! Text rendering onto a framebuffer.
//!
//! Glyphs are 8x8 and stored in column order, so drawing a character is a byte copy
//! when it lands on a page boundary. The general path handles arbitrary `y` too, since
//! a wallet needs to place a line under a heading rather than only on multiples of 8.

use crate::font::{glyph, GLYPH_SIZE};
use crate::framebuffer::Framebuffer;

/// A 128-pixel-wide panel fits 16 characters per line.
pub const fn columns(width: usize) -> usize {
    width / GLYPH_SIZE
}

/// Draw one character with its top-left at `(x, y)`. Clipped, never panics.
pub fn draw_char<const W: usize, const P: usize, const N: usize>(
    fb: &mut Framebuffer<W, P, N>,
    x: usize,
    y: usize,
    c: u8,
) {
    let g = glyph(c);
    for (dx, col) in g.iter().enumerate() {
        for dy in 0..GLYPH_SIZE {
            if col & (1 << dy) != 0 {
                fb.set(x + dx, y + dy, true);
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
    x: usize,
    y: usize,
    text: &str,
) -> usize {
    let mut at = x;
    for &c in text.as_bytes() {
        if at + GLYPH_SIZE > W {
            break;
        }
        draw_char(fb, at, y, c);
        at += GLYPH_SIZE;
    }
    at
}

/// Draw text wrapped across lines, breaking at the panel edge.
///
/// Returns the number of lines drawn. Used for long strings that must be shown in full
/// — a mnemonic, an address — where truncation would be worse than wrapping.
pub fn draw_wrapped<const W: usize, const P: usize, const N: usize>(
    fb: &mut Framebuffer<W, P, N>,
    x: usize,
    y: usize,
    text: &str,
) -> usize {
    let per_line = columns(W - x);
    let mut lines = 0;
    for (i, chunk) in text.as_bytes().chunks(per_line.max(1)).enumerate() {
        let row = y + i * GLYPH_SIZE;
        if row + GLYPH_SIZE > P * 8 {
            break;
        }
        let mut at = x;
        for &c in chunk {
            draw_char(fb, at, row, c);
            at += GLYPH_SIZE;
        }
        lines += 1;
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framebuffer::Mono128x64;

    fn ink<const W: usize, const P: usize, const N: usize>(fb: &Framebuffer<W, P, N>) -> u32 {
        fb.as_bytes().iter().map(|b| b.count_ones()).sum()
    }

    #[test]
    fn a_line_fits_sixteen_characters() {
        assert_eq!(columns(128), 16);
    }

    #[test]
    fn drawing_marks_pixels() {
        let mut fb = Mono128x64::new();
        assert_eq!(ink(&fb), 0);
        draw_text(&mut fb, 0, 0, "CatCard");
        assert!(ink(&fb) > 0);
    }

    #[test]
    fn a_space_draws_nothing() {
        let mut fb = Mono128x64::new();
        draw_text(&mut fb, 0, 0, "   ");
        assert_eq!(ink(&fb), 0);
    }

    #[test]
    fn text_is_truncated_at_the_edge_not_wrapped() {
        // A wrapped address can look like a complete, different address.
        let mut a = Mono128x64::new();
        draw_text(&mut a, 0, 0, "0123456789ABCDEF");
        let mut b = Mono128x64::new();
        draw_text(&mut b, 0, 0, "0123456789ABCDEFGHIJ");
        assert_eq!(
            a.as_bytes(),
            b.as_bytes(),
            "extra characters leaked onto the line"
        );
    }

    #[test]
    fn draw_text_reports_where_it_stopped() {
        let mut fb = Mono128x64::new();
        assert_eq!(draw_text(&mut fb, 0, 0, "abc"), 24);
        assert_eq!(draw_text(&mut fb, 8, 0, ""), 8);
    }

    #[test]
    fn drawing_off_screen_is_clipped_not_a_panic() {
        let mut fb = Mono128x64::new();
        draw_char(&mut fb, 1000, 1000, b'X');
        draw_char(&mut fb, 124, 60, b'X'); // partially off both edges
        draw_text(&mut fb, 120, 0, "long string here");
        // No panic; the far-corner glyph is clipped to what fits.
        assert!(ink(&fb) > 0);
    }

    #[test]
    fn glyphs_land_on_the_expected_page() {
        // y=0 writes page 0; y=8 writes page 1. An off-by-one here shifts every line.
        let mut fb = Mono128x64::new();
        draw_char(&mut fb, 0, 0, b'#');
        assert!(fb.as_bytes()[..128].iter().any(|&b| b != 0));
        assert!(fb.as_bytes()[128..].iter().all(|&b| b == 0));

        let mut fb = Mono128x64::new();
        draw_char(&mut fb, 0, 8, b'#');
        assert!(fb.as_bytes()[..128].iter().all(|&b| b == 0));
        assert!(fb.as_bytes()[128..256].iter().any(|&b| b != 0));
    }

    #[test]
    fn unaligned_y_straddles_two_pages() {
        let mut fb = Mono128x64::new();
        draw_char(&mut fb, 0, 4, b'#');
        assert!(
            fb.as_bytes()[..128].iter().any(|&b| b != 0),
            "top half missing"
        );
        assert!(
            fb.as_bytes()[128..256].iter().any(|&b| b != 0),
            "bottom half missing"
        );
    }

    #[test]
    fn wrapping_shows_every_character() {
        let mut fb = Mono128x64::new();
        // 24 characters over a 16-column panel needs two lines.
        let lines = draw_wrapped(&mut fb, 0, 0, "abcdefghijklmnopqrstuvwx");
        assert_eq!(lines, 2);
        assert!(
            fb.as_bytes()[128..256].iter().any(|&b| b != 0),
            "second line empty"
        );
    }

    #[test]
    fn wrapping_stops_at_the_bottom_of_the_panel() {
        let mut fb = Mono128x64::new();
        let long = "x".repeat(16 * 20);
        let lines = draw_wrapped(&mut fb, 0, 0, &long);
        assert_eq!(lines, 8, "should fill exactly the eight pages and stop");
    }
}
