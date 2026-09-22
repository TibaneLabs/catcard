//! The boot splash: cat on the left, wordmark on the right, version and progress below.
//!
//! Drawn repeatedly during init with a rising progress value, so the device shows
//! something from the moment the panel is alive rather than staying dark until the
//! entropy pool has finished. On a wallet that matters beyond decoration: a dark screen
//! and a hung screen look identical, and this makes the difference visible.

use crate::art::{Bitmap, Indexed, cat::CAT, draw_indexed};
use crate::canvas::{Canvas, INK};
use crate::font::{misc4x6, peep7x14};
use crate::text::{centred, draw_text, width_of};
use crate::widgets::Layout;

/// Left margin before the cat.
const CAT_X: usize = 3;
/// Gap between the art and the text column.
const GUTTER: usize = 6;

/// Draw a bitmap with its top-left at `(x, y)`. Clipped, never panics.
pub fn draw_bitmap<C: Canvas + ?Sized>(fb: &mut C, bmp: &Bitmap, x: usize, y: usize) {
    for by in 0..bmp.height as usize {
        for bx in 0..bmp.width as usize {
            if bmp.pixel(bx, by) {
                fb.put(x.saturating_add(bx), y.saturating_add(by), INK);
            }
        }
    }
}

/// Draw a bitmap at `scale`x with its top-left at `(x, y)`. Clipped, never panics.
///
/// For art sized in pixels rather than in points: a 5x5 key icon beside a 4x6 face is the
/// size it was drawn, and beside a 7x14 one it has to grow or it reads as a speck.
pub fn draw_bitmap_scaled<C: Canvas + ?Sized>(
    fb: &mut C,
    bmp: &Bitmap,
    x: usize,
    y: usize,
    scale: usize,
) {
    draw_bitmap_scaled_in(fb, bmp, x, y, scale, INK);
}

/// [`draw_bitmap_scaled`] at a chosen ink level, for art on a light background.
pub fn draw_bitmap_scaled_in<C: Canvas + ?Sized>(
    fb: &mut C,
    bmp: &Bitmap,
    x: usize,
    y: usize,
    scale: usize,
    level: crate::canvas::Level,
) {
    let scale = scale.max(1);
    for by in 0..bmp.height as usize {
        for bx in 0..bmp.width as usize {
            if bmp.pixel(bx, by) {
                fb.fill_rect(
                    x.saturating_add(bx * scale),
                    y.saturating_add(by * scale),
                    scale,
                    scale,
                    level,
                );
            }
        }
    }
}

/// How tall the progress bar is on a canvas this size.
///
/// A single row is most of a millimetre on a 128x64 OLED and almost nothing on the
/// Q1's 320x240, where it is barely visible at all. Stock reserves the bottom **5 px**
/// of that panel for the bar, so the tall panels match it; the mono panels keep one
/// row, since five out of sixty-four would be a twelfth of the screen.
///
/// Source: hw-reference/display.md §"Q1 — colour palette & screen layout" [C]
pub const fn progress_h(height: usize) -> usize {
    if height > 96 { 5 } else { 1 }
}

/// Fill the bottom [`progress_h`] rows from the left, in proportion to `progress`
/// (0..=100).
///
/// Callers that draw content must leave these rows clear — [`draw`] and [`draw_colour`]
/// both subtract the same height, so the bar cannot land on the version line.
pub fn draw_progress<C: Canvas + ?Sized>(fb: &mut C, progress: u8) {
    let filled = (fb.width() * progress.min(100) as usize) / 100;
    let h = progress_h(fb.height());
    let top = fb.height().saturating_sub(h);
    fb.fill_rect(0, top, filled, h, INK);
}

/// Render the whole splash into a cleared framebuffer.
pub fn draw<C: Canvas + ?Sized>(fb: &mut C, version: &str, progress: u8) {
    fb.clear();

    let height = fb.height();
    // Everything above the progress bar, whatever height it is on this panel.
    let content = height.saturating_sub(progress_h(height));

    let cat_y = (content.saturating_sub(CAT.height as usize)) / 2;
    draw_bitmap(fb, &CAT, CAT_X, cat_y);

    // The text column is whatever is left to the right of the art.
    let col_x = CAT_X + CAT.width as usize + GUTTER;
    let col_w = fb.width().saturating_sub(col_x);

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

/// The splash with baked colour art: logo, wordmark, version, progress row.
///
/// For a panel with room and a palette -- the art carries its own, and the canvas must be
/// flushed through it (see the firmware's `display::draw_with_palette`). Text draws in
/// white, which that palette keeps at index 15, so it reads over the art's colours.
///
/// The block is centred as a whole: art, then the wordmark in the layout's title face,
/// then the version in its body face, with the progress row left clear at the bottom.
pub fn draw_colour<C: Canvas + ?Sized>(
    fb: &mut C,
    art: &Indexed,
    version: &str,
    progress: u8,
    l: &Layout<'_>,
) {
    fb.clear();
    let (w, h) = (fb.width(), fb.height());
    // Everything above the progress bar, whatever height it is on this panel.
    let content = h.saturating_sub(progress_h(h));

    let art_h = art.height as usize;
    let block = art_h + l.gap * 2 + l.title.line_height() + l.gap + l.body.line_height();
    let top = content.saturating_sub(block) / 2;

    draw_indexed(fb, art, w.saturating_sub(art.width as usize) / 2, top);

    let name = "CatCard";
    let name_y = top + art_h + l.gap * 2;
    draw_text(fb, l.title, centred(l.title, name, w), name_y, name);

    let ver_y = name_y + l.title.line_height() + l.gap;
    draw_text(fb, l.body, centred(l.body, version, w), ver_y, version);

    draw_progress(fb, progress);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canvas::{Gray320x240, INK, PAPER};
    use crate::framebuffer::{Framebuffer, Mono128x64};

    #[test]
    fn the_colour_splash_shows_the_art_in_its_own_colours_under_white_text() {
        use crate::art::tibane::LOGO;
        let l = Layout::roomy();
        let mut c = Gray320x240::new();
        draw_colour(&mut c, &LOGO, "7.0.0", 50, &l);

        let levels: Vec<u8> = (0..240)
            .flat_map(|y| (0..320).map(move |x| (x, y)))
            .map(|(x, y)| c.get(x, y))
            .collect();
        assert!(
            levels.iter().any(|&v| (1..INK).contains(&v)),
            "no art colours on the canvas"
        );
        assert!(levels.contains(&INK), "no white text or bar");
        assert!(levels.contains(&PAPER), "the whole canvas is painted");

        // The art sits centred above the text, and the bottom row is the bar's.
        let art_x = (320 - LOGO.width as usize) / 2;
        assert!(
            (0..LOGO.height as usize)
                .any(|dy| (0..LOGO.width as usize).any(|dx| c.get(art_x + dx, 20 + dy) != PAPER)),
            "no art where the logo should be"
        );
        assert_eq!((0..320).filter(|&x| c.get(x, 239) != PAPER).count(), 160);
    }

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

    #[test]
    fn the_bar_is_thick_enough_to_see_on_a_tall_panel() {
        // One row out of 240 is barely visible on the glass, which is how this was
        // noticed. Five is what stock reserves.
        let mut c = Gray320x240::new();
        draw_progress(&mut c, 100);
        let rows = (0..240).filter(|&y| c.get(0, y) != PAPER).count();
        assert_eq!(rows, 5);
        assert!(rows >= 4, "too thin to see");
        // And it does not creep further up than that.
        assert_eq!(c.get(0, 240 - 6), PAPER);
    }

    #[test]
    fn the_mono_panels_keep_their_single_row() {
        // Five rows of sixty-four would be a twelfth of the screen.
        assert_eq!(progress_h(64), 1);
        assert_eq!(progress_h(240), 5);
    }

    #[test]
    fn a_partial_bar_is_as_tall_as_a_full_one() {
        // Height is the panel's; only the width tracks progress.
        let mut c = Gray320x240::new();
        draw_progress(&mut c, 25);
        assert_eq!((0..240).filter(|&y| c.get(0, y) != PAPER).count(), 5);
        assert_eq!((0..320).filter(|&x| c.get(x, 239) != PAPER).count(), 80);
    }

    #[test]
    fn the_colour_splash_leaves_the_bar_rows_to_the_bar() {
        // With no progress to show, those rows must be empty -- if content reached into
        // them, a full bar would look like a rendering fault.
        use crate::art::tibane::LOGO;
        let l = Layout::roomy();
        let mut c = Gray320x240::new();
        draw_colour(&mut c, &LOGO, "7.0.0", 0, &l);
        for y in 240 - progress_h(240)..240 {
            assert!(
                (0..320).all(|x| c.get(x, y) == PAPER),
                "content is using the bar's rows at y={y}"
            );
        }
    }
}
