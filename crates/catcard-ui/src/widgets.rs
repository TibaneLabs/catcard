//! Screens that lay themselves out from the canvas they are handed.
//!
//! Every screen placed its text with constants worked out for a 128x64 panel -- a first row
//! at 21, a 7-pixel pitch, six rows, centring across 128 -- so a bigger panel could only show
//! the same screen doubled. These take a [`Layout`], which says which faces to use and how
//! much air to leave, and derive everything else from the canvas: the same [`menu`] gives six
//! rows of 4x6 on an mk4 and a dozen rows of 7x14 across a Q1's whole 320x240.

use crate::canvas::Canvas;
use crate::face::Face;
use crate::font::{misc4x6, peep7x14, peep10x20};
use crate::menu::Scroll;
use crate::text::{centred, draw_text};

/// How a board wants its screens set: which faces, and how much space between things.
#[derive(Copy, Clone)]
pub struct Layout<'a> {
    /// Titles, and anything that must read at arm's length.
    pub title: &'a dyn Face,
    /// Menu items, values and notes.
    pub body: &'a dyn Face,
    /// Extra pixels between lines, and between the title and what follows it.
    pub gap: usize,
    /// Left margin for body text, and the right margin for the scroll arrows.
    pub margin: usize,
}

impl Layout<'static> {
    /// The mk3/mk4/mk5 OLED: a 7x14 title over 4x6 body text. On 128x64 this is exactly the
    /// geometry the screens were first drawn with -- note at 15, rows from 21 every 7.
    pub const fn compact() -> Self {
        Self {
            title: &peep7x14::FONT,
            body: &misc4x6::FONT,
            gap: 1,
            margin: 2,
        }
    }

    /// A panel with room: a 10x20 title over 7x14 body text. On the Q1's 320x240 that is
    /// twelve rows of readable text with nothing scaled.
    pub const fn roomy() -> Self {
        Self {
            title: &peep10x20::FONT,
            body: &peep7x14::FONT,
            gap: 2,
            margin: 6,
        }
    }

    /// [`compact`](Self::compact) with the body one size larger, for reading seed words:
    /// bigger text at the cost of fewer rows -- three or four words on a 128x64 panel
    /// rather than six cramped ones.
    pub const fn compact_words() -> Self {
        Self {
            title: &peep7x14::FONT,
            body: &peep7x14::FONT,
            gap: 1,
            margin: 2,
        }
    }

    /// [`roomy`](Self::roomy) with the body one size larger, the Q1 counterpart of
    /// [`compact_words`](Self::compact_words).
    pub const fn roomy_words() -> Self {
        Self {
            title: &peep10x20::FONT,
            body: &peep10x20::FONT,
            gap: 2,
            margin: 6,
        }
    }
}

impl Layout<'_> {
    /// Distance from one body row to the next.
    pub fn pitch(&self) -> usize {
        self.body.line_height() + self.gap
    }

    /// Where a note line sits: directly under the title.
    pub fn note_y(&self) -> usize {
        self.title.line_height() + self.gap
    }

    /// The first body row: under the title and the note line.
    pub fn body_top(&self) -> usize {
        self.note_y() + self.body.line_height()
    }

    /// Body rows that fit between [`body_top`](Self::body_top) and the bottom of a canvas
    /// `height` pixels tall.
    pub fn rows(&self, height: usize) -> usize {
        height.saturating_sub(self.body_top()) / self.pitch().max(1)
    }

    /// Rows the pager fits. Unlike a menu or info screen it has a title but **no note
    /// line**, so its text starts one line higher -- at [`note_y`](Self::note_y) rather
    /// than [`body_top`](Self::body_top) -- and one more row fits. This is what lets the
    /// mono seed backup show three words instead of two.
    pub fn pager_rows(&self, height: usize) -> usize {
        height.saturating_sub(self.note_y()) / self.pitch().max(1)
    }

    /// Where menu item text starts, leaving room for the cursor marker before it.
    pub fn indent(&self) -> usize {
        self.margin + 2 * self.body.advance(b'>')
    }
}

/// A titled, scrolling list with a `>` at the cursor, and `^` / `v` when there is more
/// above or below. `note` goes under the title in the body face; pass `""` for none.
///
/// Clears the canvas first. The caller keeps `sc` and steps it with
/// [`Scroll::step`] using [`Layout::rows`] for the window, so the cursor moves over exactly
/// the rows this draws.
pub fn menu<C: Canvas + ?Sized>(
    canvas: &mut C,
    l: &Layout<'_>,
    title: &str,
    note: &str,
    items: &[&str],
    sc: Scroll,
) {
    canvas.clear();
    let w = canvas.width();
    draw_text(canvas, l.title, centred(l.title, title, w), 0, title);
    draw_text(canvas, l.body, centred(l.body, note, w), l.note_y(), note);

    let rows = l.rows(canvas.height());
    let (top, end) = sc.window(items.len(), rows);
    for (row, item) in items[top..end].iter().enumerate() {
        let y = l.body_top() + row * l.pitch();
        // A marker rather than inverted pixels: it stays legible in the smallest face.
        if top + row == sc.cursor {
            draw_text(canvas, l.body, l.margin, y, ">");
        }
        draw_text(canvas, l.body, l.indent(), y, item);
    }

    // Say that there is more. Without this a list that scrolls looks exactly like one that
    // has ended.
    let arrow_x = w.saturating_sub(l.body.advance(b'^') + l.margin);
    if top > 0 {
        draw_text(canvas, l.body, arrow_x, l.body_top(), "^");
    }
    if end < items.len() && rows > 0 {
        draw_text(
            canvas,
            l.body,
            arrow_x,
            l.body_top() + (rows - 1) * l.pitch(),
            "v",
        );
    }
}

/// A titled screen of left-aligned lines, as many as fit.
pub fn info<C: Canvas + ?Sized, S: AsRef<str>>(
    canvas: &mut C,
    l: &Layout<'_>,
    title: &str,
    lines: &[S],
) {
    canvas.clear();
    let w = canvas.width();
    draw_text(canvas, l.title, centred(l.title, title, w), 0, title);
    for (i, line) in lines.iter().take(l.rows(canvas.height())).enumerate() {
        draw_text(
            canvas,
            l.body,
            l.margin,
            l.body_top() + i * l.pitch(),
            line.as_ref(),
        );
    }
}

/// A heading and up to two lines under it, the block centred on the canvas: "Installing /
/// do not disconnect". Empty lines take no ink but keep their place.
pub fn message<C: Canvas + ?Sized>(canvas: &mut C, l: &Layout<'_>, head: &str, a: &str, b: &str) {
    canvas.clear();
    let (w, h) = (canvas.width(), canvas.height());
    let under = l.title.line_height() + 2 * l.gap + l.body.line_height();
    let block = under + l.pitch();
    let top = h.saturating_sub(block) / 2;
    draw_text(canvas, l.title, centred(l.title, head, w), top, head);
    let y = top + l.title.line_height() + 2 * l.gap;
    draw_text(canvas, l.body, centred(l.body, a, w), y, a);
    draw_text(canvas, l.body, centred(l.body, b, w), y + l.pitch(), b);
}

/// How tall the busy bar is: the progress bar's rows, but never a single one.
///
/// [`splash::progress_h`](crate::splash::progress_h) gives the mono panels one row, which
/// is enough for a bar whose *position* carries the meaning. Here the meaning is the
/// movement itself, and a one-pixel line sliding along the bottom edge of an OLED reads as
/// a rendering artefact rather than as a device that is working.
pub const fn busy_h(height: usize) -> usize {
    let h = crate::splash::progress_h(height);
    if h < 2 { 2 } else { h }
}

/// A bar that says work is happening, without claiming to know how far along it is.
///
/// A percentage would have to be invented: a key stretch or a derivation has no honest
/// fraction to report, and a bar that crawls to 90% and sits there is worse than none. So a
/// lit segment slides across the bottom rows and wraps -- what matters is that it moves, and
/// that it stops when the work is done.
///
/// `phase` is a free-running counter the caller bumps once per redraw; the segment advances
/// a few pixels each time and re-enters from the left.
pub fn busy_bar<C: Canvas + ?Sized>(canvas: &mut C, phase: u32) {
    use crate::canvas::INK;
    let (w, h) = (canvas.width(), canvas.height());
    let bar = busy_h(h);
    let top = h.saturating_sub(bar);
    let seg = (w / 5).max(4);
    let step = (w / 32).max(2);
    // The segment wraps round the bar rather than sliding off the end: what leaves at the
    // right comes straight back in at the left, so every frame is lit and there is no
    // moment where the screen looks as dead as the one this bar exists to explain.
    //
    // Counting the cycle in *ticks* rather than pixels keeps the multiply small: a phase
    // that has been running for a day cannot overflow into a jump.
    let cycle = w.div_ceil(step).max(1);
    let x = (phase as usize % cycle) * step % w.max(1);
    canvas.fill_rect(x, top, seg.min(w - x), bar, INK);
    if x + seg > w {
        canvas.fill_rect(0, top, x + seg - w, bar, INK);
    }
}

/// [`message`] with a [`busy_bar`] under it: the screen shown while something slow runs.
///
/// The head and note say what is happening; the bar says it is still happening. The message
/// block is centred in the canvas and the bar takes the bottom rows, so the two do not
/// meet on any panel this firmware draws.
pub fn working<C: Canvas + ?Sized>(
    canvas: &mut C,
    l: &Layout<'_>,
    head: &str,
    note: &str,
    phase: u32,
) {
    message(canvas, l, head, note, "");
    busy_bar(canvas, phase);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canvas::{Gray320x240, INK, PAPER};
    use crate::framebuffer::Mono128x64;

    fn inked<C: Canvas>(c: &C, x0: usize, y0: usize, x1: usize, y1: usize) -> bool {
        (y0..y1).any(|y| (x0..x1).any(|x| c.get(x, y) != PAPER))
    }

    fn snapshot<C: Canvas>(c: &C) -> Vec<u8> {
        (0..c.height())
            .flat_map(|y| (0..c.width()).map(move |x| (x, y)))
            .map(|(x, y)| c.get(x, y))
            .collect()
    }

    #[test]
    fn the_compact_layout_is_the_geometry_the_mk4_screens_were_drawn_with() {
        let l = Layout::compact();
        assert_eq!(l.note_y(), 15);
        assert_eq!(l.body_top(), 21);
        assert_eq!(l.pitch(), 7);
        assert_eq!(l.rows(64), 6);
        assert_eq!(l.indent(), 10);
    }

    #[test]
    fn the_seed_words_layout_fits_three_words_on_the_mono_panel() {
        // The pager has a title but no note line, so it fits one more row than a menu --
        // three seed words on the 64px panel rather than two. Regressing this back to two
        // is the kind of change that looks fine until someone is reading a backup.
        let l = Layout::compact_words();
        assert_eq!(l.rows(64), 2, "a note-bearing screen fits two");
        assert_eq!(l.pager_rows(64), 3, "the pager fits three");
        // The third row's text still sits inside the panel.
        assert!(l.note_y() + 3 * l.pitch() <= 64 + l.gap);
    }

    #[test]
    fn the_roomy_layout_uses_the_whole_320x240_without_scaling() {
        let l = Layout::roomy();
        assert_eq!(l.note_y(), 22);
        assert_eq!(l.body_top(), 36);
        assert_eq!(l.pitch(), 16);
        assert_eq!(l.rows(240), 12);
        // Past the last row there is no room for another.
        assert!(l.body_top() + l.rows(240) * l.pitch() <= 240 + l.gap);
    }

    #[test]
    fn the_cursor_marker_is_on_the_cursor_row_and_no_other() {
        let l = Layout::roomy();
        let items = ["USB", "Clocks", "PSRAM", "Boot report"];
        let mut sc = Scroll::new();
        sc = sc.step(items.len(), l.rows(240), true); // cursor on row 1
        let mut c = Gray320x240::new();
        menu(&mut c, &l, "Debug", "", &items, sc);
        let marker = |row: usize| {
            let y = l.body_top() + row * l.pitch();
            inked(&c, l.margin, y, l.indent() - 1, y + l.body.line_height())
        };
        assert!(!marker(0) && marker(1) && !marker(2) && !marker(3));
        for row in 0..items.len() {
            let y = l.body_top() + row * l.pitch();
            assert!(
                inked(&c, l.indent(), y, 320, y + 14),
                "item {row} not drawn"
            );
        }
    }

    #[test]
    fn a_long_list_says_there_is_more_above_and_below() {
        let l = Layout::roomy();
        let items: Vec<String> = (0..40).map(|i| format!("item {i}")).collect();
        let refs: Vec<&str> = items.iter().map(String::as_str).collect();
        let mut sc = Scroll::new();
        for _ in 0..20 {
            sc = sc.step(refs.len(), l.rows(240), true);
        }
        let mut c = Gray320x240::new();
        menu(&mut c, &l, "Long", "", &refs, sc);
        let arrow_x = 320 - 7 - l.margin;
        let first = l.body_top();
        let last = l.body_top() + (l.rows(240) - 1) * l.pitch();
        assert!(
            inked(&c, arrow_x, first, 320, first + 14),
            "no ^ with more above"
        );
        assert!(
            inked(&c, arrow_x, last, 320, last + 14),
            "no v with more below"
        );
    }

    #[test]
    fn the_same_menu_draws_on_the_mono_panel_inside_its_128x64() {
        let l = Layout::compact();
        let items = [
            "USB",
            "Clocks",
            "PSRAM",
            "Boot report",
            "Selftest",
            "Keypad",
            "microSD",
        ];
        let mut fb = Mono128x64::new();
        menu(&mut fb, &l, "Debug", "note", &items, Scroll::new());
        // Title, note, the six rows that fit, and the "more below" arrow.
        assert!(inked(&fb, 0, 0, 128, 14), "no title");
        assert!(inked(&fb, 0, 15, 128, 21), "no note");
        assert!(inked(&fb, 2, 21, 10, 27), "no marker on the first row");
        assert!(
            inked(&fb, 122, 21 + 5 * 7, 128, 64),
            "no v for the seventh item"
        );
    }

    #[test]
    fn info_draws_only_the_lines_that_fit() {
        let l = Layout::compact();
        let many: Vec<String> = (0..20).map(|i| format!("line {i}")).collect();
        let mut a = Mono128x64::new();
        info(&mut a, &l, "Info", &many);
        let mut b = Mono128x64::new();
        info(&mut b, &l, "Info", &many[..l.rows(64)]);
        assert_eq!(
            snapshot(&a),
            snapshot(&b),
            "lines past the panel changed the picture"
        );
    }

    #[test]
    fn a_message_is_centred_and_clears_what_was_there() {
        let l = Layout::roomy();
        let mut c = Gray320x240::new();
        c.fill_rect(0, 0, 320, 240, INK);
        message(&mut c, &l, "Installing", "do not disconnect", "");
        assert!(
            !inked(&c, 0, 0, 320, 60),
            "old ink above the message survived"
        );
        assert!(
            !inked(&c, 0, 180, 320, 240),
            "old ink below the message survived"
        );
        let rows_with_ink: Vec<usize> = (0..240).filter(|&y| inked(&c, 0, y, 320, y + 1)).collect();
        let (top, bottom) = (rows_with_ink[0], *rows_with_ink.last().unwrap());
        let (above, below) = (top, 239 - bottom);
        assert!(
            above.abs_diff(below) <= l.pitch() + 4,
            "block not centred: {above} vs {below}"
        );
    }

    /// The lit columns of the bar rows, which is the whole state the bar has.
    fn segment<C: Canvas>(c: &C) -> Vec<usize> {
        let top = c.height() - busy_h(c.height());
        (0..c.width())
            .filter(|&x| inked(c, x, top, x + 1, c.height()))
            .collect()
    }

    #[test]
    fn the_busy_bar_moves_every_tick_and_comes_back_round() {
        let mut seen: Vec<Vec<usize>> = Vec::new();
        for phase in 0..80 {
            let mut c = Mono128x64::new();
            busy_bar(&mut c, phase);
            seen.push(segment(&c));
        }
        // Something is lit on all but the two ends of a sweep, and it never stands still:
        // a bar that repeats a frame is a bar the owner reads as a frozen device.
        assert!(
            seen.windows(2).all(|w| w[0] != w[1]),
            "the segment did not move between two consecutive ticks"
        );
        assert!(
            seen.iter().all(|s| !s.is_empty()),
            "the bar went dark: it wraps round, it never leaves the screen"
        );
        // And it wraps rather than running off: a later phase repeats an earlier frame.
        assert!(
            seen[40..].contains(&seen[1]),
            "the segment never came back round"
        );
    }

    #[test]
    fn the_busy_bar_keeps_to_the_bottom_rows_and_off_the_message() {
        for phase in [0u32, 3, 9, 17] {
            let mut c = Gray320x240::new();
            working(&mut c, &Layout::roomy(), "Deriving", "Taproot...", phase);
            let top = 240 - busy_h(240);
            assert!(inked(&c, 0, top, 320, 240), "no bar drawn at phase {phase}");
            let mut plain = Gray320x240::new();
            message(&mut plain, &Layout::roomy(), "Deriving", "Taproot...", "");
            // Above the bar rows the busy screen is exactly the message screen: the bar
            // adds movement, it does not push the text around.
            for y in 0..top {
                for x in 0..320 {
                    assert_eq!(
                        c.get(x, y),
                        plain.get(x, y),
                        "row {y} changed at phase {phase}"
                    );
                }
            }
        }
    }

    #[test]
    fn the_busy_bar_is_visible_on_a_mono_panel() {
        // One row is what the determinate bar uses on 128x64; for a moving segment that
        // reads as a glitch on the bottom edge, so this one is thicker by contract.
        assert!(busy_h(64) >= 2);
        assert_eq!(busy_h(240), crate::splash::progress_h(240));
    }
}
