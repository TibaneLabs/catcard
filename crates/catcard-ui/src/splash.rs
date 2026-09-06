//! The boot splash: cat on the left, wordmark on the right, version and progress below.
//!
//! Drawn repeatedly during init with a rising progress value, so the device shows
//! something from the moment the panel is alive rather than staying dark until the
//! entropy pool has finished. On a wallet that matters beyond decoration: a dark screen
//! and a hung screen look identical, and this makes the difference visible.

use crate::art::{cat::CAT, Bitmap};
use crate::font::{misc4x6, peep7x14};
use crate::framebuffer::Framebuffer;
use crate::text::{draw_text, width_of};

/// Left margin before the cat.
const CAT_X: usize = 3;
/// Gap between the art and the text column.
const GUTTER: usize = 6;

/// Draw a bitmap with its top-left at `(x, y)`. Clipped, never panics.
pub fn draw_bitmap<const W: usize, const P: usize, const N: usize>(
    fb: &mut Framebuffer<W, P, N>,
    bmp: &Bitmap,
    x: usize,
    y: usize,
) {
    for by in 0..bmp.height as usize {
        for bx in 0..bmp.width as usize {
            if bmp.pixel(bx, by) {
                fb.set(x + bx, y + by, true);
            }
        }
    }
}

/// Fill the bottom row from the left in proportion to `progress` (0..=100).
///
/// One row, deliberately: it reads as a progress indicator without taking space from
/// the content, and there is nothing to get wrong about its geometry.
pub fn draw_progress<const W: usize, const P: usize, const N: usize>(
    fb: &mut Framebuffer<W, P, N>,
    progress: u8,
) {
    let filled = (W * progress.min(100) as usize) / 100;
    let y = P * 8 - 1;
    for x in 0..filled {
        fb.set(x, y, true);
    }
}

/// Render the whole splash into a cleared framebuffer.
pub fn draw<const W: usize, const P: usize, const N: usize>(
    fb: &mut Framebuffer<W, P, N>,
    version: &str,
    progress: u8,
) {
    fb.clear();

    let height = P * 8;
    // Everything above the progress row.
    let content = height - 1;

    let cat_y = (content.saturating_sub(CAT.height as usize)) / 2;
    draw_bitmap(fb, &CAT, CAT_X, cat_y);

    // The text column is whatever is left to the right of the art.
    let col_x = CAT_X + CAT.width as usize + GUTTER;
    let col_w = W.saturating_sub(col_x);

    let title = &peep7x14::FONT;
    let name = "CatCard";
    let title_w = width_of(title, name);
    let title_x = col_x + col_w.saturating_sub(title_w) / 2;
    let title_y = cat_y + (CAT.height as usize).saturating_sub(title.height as usize) / 2;
    draw_text(fb, title, title_x, title_y, name);

    // Version in the small face, centred under the wordmark, clear of the progress row.
    let small = &misc4x6::FONT;
    let ver_w = width_of(small, version);
    let ver_x = col_x + col_w.saturating_sub(ver_w) / 2;
    let ver_y = content.saturating_sub(small.height as usize + 1);
    draw_text(fb, small, ver_x, ver_y, version);

    draw_progress(fb, progress);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framebuffer::Mono128x64;

    fn row_ink<const W: usize, const P: usize, const N: usize>(
        fb: &Framebuffer<W, P, N>,
        y: usize,
    ) -> usize {
        (0..W).filter(|&x| fb.get(x, y)).count()
    }

    #[test]
    fn the_progress_row_is_the_bottom_row_and_fills_from_the_left() {
        let mut fb = Mono128x64::new();
        draw_progress(&mut fb, 0);
        assert_eq!(row_ink(&fb, 63), 0);

        let mut fb = Mono128x64::new();
        draw_progress(&mut fb, 50);
        assert_eq!(row_ink(&fb, 63), 64);
        assert!(fb.get(0, 63) && fb.get(63, 63));
        assert!(!fb.get(64, 63), "filled past the halfway point");

        let mut fb = Mono128x64::new();
        draw_progress(&mut fb, 100);
        assert_eq!(row_ink(&fb, 63), 128);
    }

    #[test]
    fn progress_saturates_rather_than_overflowing() {
        // A caller reporting 255 should show a full bar, not wrap or panic.
        let mut fb = Mono128x64::new();
        draw_progress(&mut fb, 255);
        assert_eq!(row_ink(&fb, 63), 128);
    }

    #[test]
    fn progress_is_monotonic() {
        let mut last = 0;
        for p in 0..=100u8 {
            let mut fb = Mono128x64::new();
            draw_progress(&mut fb, p);
            let n = row_ink(&fb, 63);
            assert!(
                n >= last,
                "bar shrank between {} and {p}",
                p.saturating_sub(1)
            );
            last = n;
        }
    }

    /// The widest version we will ship: three numeric components, no pre-release or
    /// build suffix, generous on each.
    const LONGEST_VERSION: &str = "12.124.12445";

    #[test]
    fn the_art_leaves_room_for_the_wordmark_and_the_version() {
        // Every position here is computed from CAT.width and CAT.height, so redrawing
        // the cat re-flows the splash without touching this file — right up to the
        // point where it squeezes the text column out, which is silent because
        // draw_text clips at the panel edge. This is that point, stated as the two
        // things that have to survive.
        let col_x = CAT_X + CAT.width as usize + GUTTER;
        let col_w = 128usize.saturating_sub(col_x);
        assert!(
            col_w >= width_of(&peep7x14::FONT, "CatCard"),
            "cat is {} wide; only {col_w} left, and the wordmark needs {}",
            CAT.width,
            width_of(&peep7x14::FONT, "CatCard")
        );
        assert!(
            col_w >= width_of(&misc4x6::FONT, LONGEST_VERSION),
            "cat is {} wide; only {col_w} left, and {LONGEST_VERSION} needs {}",
            CAT.width,
            width_of(&misc4x6::FONT, LONGEST_VERSION)
        );
        // The bottom row is the progress bar's, so the art has the 63 above it.
        assert!(
            (CAT.height as usize) < 64,
            "the art is {} tall and would reach the progress row",
            CAT.height
        );
    }

    #[test]
    fn the_longest_version_is_drawn_in_full() {
        // draw_text clips silently at the panel edge, so "it did not panic" is not the
        // same as "it is all there". Count the version's ink against an unclipped
        // render of the same string.
        let mut fb = Mono128x64::new();
        draw(&mut fb, LONGEST_VERSION, 0);
        let with: usize = (0..64).map(|y| row_ink(&fb, y)).sum();

        let mut blank = Mono128x64::new();
        draw(&mut blank, "", 0);
        let without: usize = (0..64).map(|y| row_ink(&blank, y)).sum();

        let mut unclipped = Mono128x64::new();
        draw_text(&mut unclipped, &misc4x6::FONT, 0, 0, LONGEST_VERSION);
        let expected: usize = (0..64).map(|y| row_ink(&unclipped, y)).sum();

        assert_eq!(
            with - without,
            expected,
            "the version string is being clipped"
        );
    }

    #[test]
    fn the_splash_keeps_the_art_and_the_text_apart() {
        // The wordmark must not land on the cat: they overlap vertically by design, so
        // only the column split keeps them legible.
        let mut fb = Mono128x64::new();
        draw(&mut fb, "0.0.1", 0);

        let boundary = CAT_X + CAT.width as usize;
        let cat_side: usize = (0..boundary)
            .map(|x| (0..63).filter(|&y| fb.get(x, y)).count())
            .sum();
        let text_side: usize = (boundary + GUTTER..128)
            .map(|x| (0..63).filter(|&y| fb.get(x, y)).count())
            .sum();
        assert!(cat_side > 0, "no art drawn");
        assert!(text_side > 0, "no text drawn");
        // The gutter itself is empty.
        for x in boundary..boundary + GUTTER {
            assert_eq!(
                (0..63).filter(|&y| fb.get(x, y)).count(),
                0,
                "ink in the gutter at x={x}"
            );
        }
    }

    #[test]
    fn nothing_but_the_bar_touches_the_bottom_row() {
        // The version sits clear of it; if it crept down, a full bar would look like a
        // rendering fault.
        let mut fb = Mono128x64::new();
        draw(&mut fb, "0.0.1", 0);
        assert_eq!(row_ink(&fb, 63), 0, "content is using the progress row");
    }

    #[test]
    fn the_splash_redraws_identically_for_the_same_inputs() {
        let mut a = Mono128x64::new();
        let mut b = Mono128x64::new();
        draw(&mut a, "0.0.1", 40);
        draw(&mut b, "0.0.1", 40);
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn redrawing_clears_the_previous_frame() {
        // draw() is called repeatedly as progress rises; without the clear, a longer
        // version string or a shorter bar would leave debris behind.
        let mut fb = Mono128x64::new();
        draw(&mut fb, "1.22.333", 100);
        let mut fresh = Mono128x64::new();
        draw(&mut fresh, "0.0.1", 0);
        draw(&mut fb, "0.0.1", 0);
        assert_eq!(
            fb.as_bytes(),
            fresh.as_bytes(),
            "stale pixels survived a redraw"
        );
    }

    #[test]
    fn a_long_version_string_does_not_run_off_the_panel() {
        let mut fb = Mono128x64::new();
        draw(&mut fb, "99.99.99-rc1+build", 0);
        // No panic, and the bottom row is still the bar's alone.
        assert_eq!(row_ink(&fb, 63), 0);
    }
}
