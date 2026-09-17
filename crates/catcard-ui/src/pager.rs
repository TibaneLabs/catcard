//! Showing more text than fits, on whichever panel is attached.
//!
//! Three screens had grown their own version of this: the log viewer scrolled a byte
//! buffer, the seed-word backup paged a list, and menus scrolled with a cursor. They
//! disagreed about what the keys did and about what "the end" looked like, which is a
//! bad thing for a screen someone is copying a wallet backup off.
//!
//! The split here is deliberate. [`Pager`] is arithmetic and is tested on the host;
//! [`paged`] draws and knows nothing about where text came from; [`LineSource`] is how
//! a caller hands over content it may not be able to produce randomly.
//!
//! **Why a windowed fill rather than "give me line `i`".** The log is a wrapped byte
//! buffer with no index: finding line 40 means scanning from the start. Asking for one
//! line at a time would rescan the whole buffer once per visible row, every frame. So a
//! source fills a window in a single pass and reports the total as it goes.
//!
//! Nothing here allocates: [`LineSink`] is a fixed array, which is also why a line
//! longer than [`PAGER_COLS`] is **clipped rather than wrapped**. Wrapping would change
//! the number of lines depending on the panel, and the scroll position would mean
//! something different on each one.

use crate::canvas::Canvas;
use crate::widgets::Layout;

/// Longest line the pager keeps. Beyond this, a line is clipped.
pub const PAGER_COLS: usize = 64;

/// Most rows any panel we drive can show at once. The Q1 shows 12, the mono panels 6.
pub const PAGER_ROWS: usize = 16;

/// Somewhere for a source to put the lines of one window.
///
/// Rows are plain bytes rather than `str` so that filling one cannot fail on a partial
/// UTF-8 write; anything non-ASCII is refused a byte at a time by [`Self::push`].
pub struct LineSink {
    rows: [[u8; PAGER_COLS]; PAGER_ROWS],
    lens: [u8; PAGER_ROWS],
    used: usize,
    cap: usize,
}

impl LineSink {
    /// A sink that will accept `cap` lines, clamped to what it can hold.
    pub const fn new(cap: usize) -> Self {
        Self {
            rows: [[0; PAGER_COLS]; PAGER_ROWS],
            lens: [0; PAGER_ROWS],
            used: 0,
            cap: if cap > PAGER_ROWS { PAGER_ROWS } else { cap },
        }
    }

    /// How many lines it will take in total.
    pub const fn capacity(&self) -> usize {
        self.cap
    }

    /// How many it holds.
    pub const fn len(&self) -> usize {
        self.used
    }

    pub const fn is_empty(&self) -> bool {
        self.used == 0
    }

    /// Whether another [`Self::push`] would be refused.
    pub const fn is_full(&self) -> bool {
        self.used >= self.cap
    }

    pub fn clear(&mut self) {
        self.used = 0;
    }

    /// Add a line, clipped to [`PAGER_COLS`]. False if the sink is full.
    ///
    /// A source uses the return value to stop early: once the window is full there is
    /// no point rendering the rest, only counting it.
    pub fn push(&mut self, s: &str) -> bool {
        if self.is_full() {
            return false;
        }
        let row = &mut self.rows[self.used];
        let mut n = 0;
        for b in s.bytes() {
            if n == PAGER_COLS {
                break;
            }
            // The faces here are ASCII; a stray byte draws as a dot rather than as a
            // gap that looks like the text ended.
            row[n] = if (0x20..0x7f).contains(&b) { b } else { b'.' };
            n += 1;
        }
        self.lens[self.used] = n as u8;
        self.used += 1;
        true
    }

    /// The lines it holds, in order.
    pub fn lines(&self) -> impl Iterator<Item = &str> + '_ {
        (0..self.used).map(move |i| {
            let n = self.lens[i] as usize;
            // SAFETY-free: `push` only ever stores bytes in `0x20..0x7f`, which is
            // valid UTF-8, so this cannot fail. It is written as a fallback rather
            // than an unwrap because a panic here would be a blank screen.
            core::str::from_utf8(&self.rows[i][..n]).unwrap_or("")
        })
    }
}

/// Content the pager can show: fills one window and says how much there is.
pub trait LineSource {
    /// Write lines from `from` onward into `sink`, and return the **total** number of
    /// lines available — not the number written.
    ///
    /// A source must keep counting after the sink is full, or the scroll bar cannot
    /// know where the end is.
    fn fill(&self, from: usize, sink: &mut LineSink) -> usize;
}

/// Where the window sits. No cursor: this is reading, not choosing.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Pager {
    /// Index of the first line shown.
    pub top: usize,
}

impl Pager {
    pub const fn new() -> Self {
        Self { top: 0 }
    }

    /// The last `top` that still fills the screen, so the final line sits at the bottom
    /// rather than scrolling into an empty page.
    pub fn last_top(total: usize, rows: usize) -> usize {
        total.saturating_sub(rows.max(1))
    }

    /// Move one line. Clamps at both ends rather than wrapping — see [`crate::menu`]
    /// for why wrapping makes "am I at the end?" unanswerable.
    pub fn step(self, total: usize, rows: usize, down: bool) -> Self {
        let last = Self::last_top(total, rows);
        let top = if down {
            (self.top + 1).min(last)
        } else {
            self.top.saturating_sub(1)
        };
        Self { top }
    }

    /// Move one screenful, keeping a line of overlap so nothing is read across a jump
    /// without context.
    pub fn page(self, total: usize, rows: usize, down: bool) -> Self {
        let rows = rows.max(1);
        let stride = rows.saturating_sub(1).max(1);
        let last = Self::last_top(total, rows);
        let top = if down {
            (self.top + stride).min(last)
        } else {
            self.top.saturating_sub(stride)
        };
        Self { top }
    }

    /// Whether the last line is on screen.
    ///
    /// The seed backup uses this: it will not accept "done" until every word has been
    /// in front of the reader at least once.
    pub fn at_end(self, total: usize, rows: usize) -> bool {
        self.top >= Self::last_top(total, rows)
    }

    /// Clamp after the content has changed under us.
    pub fn clamped(self, total: usize, rows: usize) -> Self {
        Self {
            top: self.top.min(Self::last_top(total, rows)),
        }
    }
}

/// The sensitive-line marking for a page of secret text (see [`paged`]).
///
/// Next to each secret line it draws a ragged strip in the right margin: for **every
/// pixel-row** of the line, one 1-px horizontal segment that ends at the right edge and
/// runs left by a **random length** (about 2..31 px). Stacked over the line's height the
/// varying lengths form a jagged bar, like a strip of static hugging the right side --
/// the unmistakable "this line is a secret, shield it" cue the Coldcard OLED uses. It is
/// a UX marker, not a cryptographic control. Source: `hw-reference/
/// sensitive-display-marking.md` [C].
///
/// The lengths come from a per-viewing seed mixed with the content-line index and the
/// pixel-row, so a word keeps its own bar and it **scrolls with the text** rather than
/// flickering; a fresh seed each time the screen opens means the pattern never repeats
/// across viewings. The seed is a UI DRBG draw, never the entropy pool -- a scribble must
/// not draw down real entropy.
#[derive(Copy, Clone)]
pub struct Scramble {
    seed: u32,
}

impl Scramble {
    /// Seed from a fresh random word, drawn once when the page opens.
    pub const fn new(seed: u32) -> Self {
        Self { seed }
    }

    /// A random mark length in `2..=max` for pixel-row `row` of content line `idx`, or 0
    /// when there is no room. Keyed to the line so the bar scrolls with its word, and to
    /// the row so each row of the bar has its own length -- the jaggedness.
    pub(crate) fn length(self, idx: usize, row: usize, max: usize) -> usize {
        if max < 2 {
            return 0;
        }
        // A splitmix-style mix of the seed with the line and row indices.
        let mut h = self.seed
            ^ (idx as u32).wrapping_mul(0x9E37_79B9)
            ^ (row as u32).wrapping_mul(0x85EB_CA6B);
        h ^= h >> 16;
        h = h.wrapping_mul(0x7feb_352d);
        h ^= h >> 15;
        h = h.wrapping_mul(0x846c_a68b);
        h ^= h >> 16;
        // `max - 1` values spanning 2..=max.
        2 + (h as usize) % (max - 1)
    }
}

/// Draw one window, with arrows saying whether there is more either way.
///
/// `total` is what the source reported, which is how the arrows can be right even
/// though only the visible lines were rendered. `scramble`, when set, draws a ragged
/// sensitive-line marker in the right margin next to each line -- see [`Scramble`] -- for
/// pages of secret text such as the seed backup.
pub fn paged<C: Canvas + ?Sized>(
    canvas: &mut C,
    l: &Layout<'_>,
    title: &str,
    sink: &LineSink,
    p: Pager,
    total: usize,
    scramble: Option<Scramble>,
) {
    canvas.clear();
    let w = canvas.width();
    crate::text::draw_text(
        canvas,
        l.title,
        crate::text::centred(l.title, title, w),
        0,
        title,
    );

    // Kept clear of this column so the scramble never buries the scroll arrows.
    let arrow_x = w.saturating_sub(l.body.advance(b'^') + l.margin);
    let gap = l.body.advance(b' ');

    // The pager has no note line, so its text starts under the title (one row higher
    // than a menu's body) and fits one more row -- three seed words on the mono panel.
    let body_top = l.note_y();
    let rows = l.pager_rows(canvas.height());
    for (row, line) in sink.lines().take(rows).enumerate() {
        let y = body_top + row * l.pitch();
        crate::text::draw_text(canvas, l.body, l.margin, y, line);

        // Sensitive-line marker: a ragged strip of 1-px horizontal segments hugging the
        // right margin over the whole height of the line, each pixel-row its own random
        // length. Anchored just left of the arrow column so it never buries the scroll
        // bar, and capped so it never reaches the word to its left. Keyed to the content
        // line (`p.top + row`) so a word keeps its own bar and it scrolls with the text.
        if let Some(sc) = scramble {
            let text_w: usize = line.bytes().map(|b| l.body.advance(b)).sum();
            let text_right = l.margin + text_w;
            let right_end = arrow_x.saturating_sub(gap);
            // The longest a segment may run left without touching the word.
            let room = right_end.saturating_sub(text_right + gap).min(31);
            if room >= 2 {
                for r in 0..l.body.line_height() {
                    let ln = sc.length(p.top + row, r, room);
                    if ln >= 2 {
                        canvas.fill_rect(right_end - ln, y + r, ln, 1, crate::canvas::INK);
                    }
                }
            }
        }
    }

    // The same affordance the menus use, so "there is more below" looks the same
    // wherever it appears.
    if p.top > 0 {
        crate::text::draw_text(canvas, l.body, arrow_x, body_top, "^");
    }
    if p.top + sink.len() < total && rows > 0 {
        crate::text::draw_text(
            canvas,
            l.body,
            arrow_x,
            body_top + (rows - 1) * l.pitch(),
            "v",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canvas::{Canvas, Gray320x240, PAPER};

    /// A source of `n` numbered lines.
    struct Counted(usize);

    impl LineSource for Counted {
        fn fill(&self, from: usize, sink: &mut LineSink) -> usize {
            for i in from..self.0 {
                let mut buf = [0u8; 16];
                let mut n = 0;
                for b in b"line " {
                    buf[n] = *b;
                    n += 1;
                }
                let d = i % 10;
                buf[n] = b'0' + d as u8;
                n += 1;
                if !sink.push(core::str::from_utf8(&buf[..n]).unwrap()) {
                    break;
                }
            }
            self.0
        }
    }

    #[test]
    fn a_sink_clips_rather_than_wrapping() {
        // Wrapping would make the line count depend on the panel, and then a scroll
        // position would mean something different on each one.
        let mut s = LineSink::new(4);
        let long = "x".repeat(PAGER_COLS + 20);
        assert!(s.push(&long));
        assert_eq!(s.lines().next().unwrap().len(), PAGER_COLS);
    }

    #[test]
    fn a_sink_refuses_past_its_capacity_and_says_so() {
        let mut s = LineSink::new(2);
        assert!(s.push("a"));
        assert!(s.push("b"));
        assert!(!s.push("c"), "accepted a third line into room for two");
        assert_eq!(s.len(), 2);
        assert_eq!(s.lines().collect::<Vec<_>>(), vec!["a", "b"]);
    }

    #[test]
    fn a_sink_never_holds_more_rows_than_it_can() {
        let s = LineSink::new(PAGER_ROWS + 50);
        assert_eq!(s.capacity(), PAGER_ROWS);
    }

    #[test]
    fn non_ascii_becomes_a_dot_rather_than_a_gap() {
        let mut s = LineSink::new(1);
        s.push("a\u{00ff}b");
        // Two bytes of UTF-8 for the middle character, both replaced.
        assert_eq!(s.lines().next().unwrap(), "a..b");
    }

    #[test]
    fn scrolling_stops_with_the_last_line_on_screen() {
        // Not at `total`: scrolling until the text has left the panel is how a reader
        // loses the end of it.
        let (total, rows) = (20, 6);
        let mut p = Pager::new();
        for _ in 0..100 {
            p = p.step(total, rows, true);
        }
        assert_eq!(p.top, 14);
        assert!(p.at_end(total, rows));
    }

    #[test]
    fn scrolling_up_stops_at_the_first_line() {
        let mut p = Pager { top: 3 };
        for _ in 0..10 {
            p = p.step(20, 6, false);
        }
        assert_eq!(p.top, 0);
    }

    #[test]
    fn a_page_keeps_one_line_of_overlap() {
        // Reading across a jump with no shared line is how a word gets skipped.
        let p = Pager::new().page(100, 6, true);
        assert_eq!(p.top, 5);
    }

    #[test]
    fn content_shorter_than_the_screen_never_scrolls() {
        let p = Pager::new().step(3, 6, true);
        assert_eq!(p.top, 0);
        assert!(p.at_end(3, 6), "a single screenful is already the end");
    }

    #[test]
    fn the_end_is_not_reached_before_the_last_line_is_visible() {
        // What the seed backup gates "done" on.
        let (total, rows) = (24, 11);
        let mut p = Pager::new();
        assert!(!p.at_end(total, rows));
        p = p.page(total, rows, true);
        assert!(!p.at_end(total, rows), "word 24 is not on screen yet");
        p = p.page(total, rows, true);
        assert!(p.at_end(total, rows));
    }

    #[test]
    fn a_shrinking_source_does_not_leave_the_window_past_the_end() {
        let p = Pager { top: 40 }.clamped(10, 6);
        assert_eq!(p.top, 4);
    }

    #[test]
    fn the_arrows_say_which_way_there_is_more() {
        let l = Layout::roomy();
        let src = Counted(100);
        let rows = l.pager_rows(240);

        // At the top: something below, nothing above.
        let mut sink = LineSink::new(rows);
        let total = src.fill(0, &mut sink);
        let mut c = Gray320x240::new();
        paged(&mut c, &l, "Log", &sink, Pager::new(), total, None);
        let arrow_x = 320 - (l.body.advance(b'^') + l.margin);
        let top_row = l.note_y();
        let bottom_row = l.note_y() + (rows - 1) * l.pitch();
        assert!(
            !inked(&c, arrow_x, top_row, top_row + 14),
            "^ drawn at the top of the log"
        );
        assert!(
            inked(&c, arrow_x, bottom_row, bottom_row + 14),
            "no v with more below"
        );

        // Scrolled: something above.
        let p = Pager { top: 20 };
        let mut sink = LineSink::new(rows);
        let total = src.fill(p.top, &mut sink);
        let mut c = Gray320x240::new();
        paged(&mut c, &l, "Log", &sink, p, total, None);
        assert!(
            inked(&c, arrow_x, top_row, top_row + 14),
            "no ^ with more above"
        );
    }

    fn inked(c: &Gray320x240, x0: usize, y0: usize, y1: usize) -> bool {
        (y0..y1.min(240)).any(|y| (x0..320).any(|x| c.get(x, y) != PAPER))
    }

    fn total_ink(c: &Gray320x240) -> usize {
        let mut n = 0;
        for y in 0..240 {
            for x in 0..320 {
                if c.get(x, y) != PAPER {
                    n += 1;
                }
            }
        }
        n
    }

    fn identical(a: &Gray320x240, b: &Gray320x240) -> bool {
        (0..240).all(|y| (0..320).all(|x| a.get(x, y) == b.get(x, y)))
    }

    #[test]
    fn scramble_adds_stable_ink_that_scrolls() {
        let src = Counted(50);
        let l = Layout::roomy();
        let rows = l.pager_rows(240);
        let mut sink = LineSink::new(rows);
        let total = src.fill(0, &mut sink);

        let mut plain = Gray320x240::new();
        paged(&mut plain, &l, "Seed", &sink, Pager::new(), total, None);
        let mut a = Gray320x240::new();
        paged(
            &mut a,
            &l,
            "Seed",
            &sink,
            Pager::new(),
            total,
            Some(Scramble::new(0x00C0_FFEE)),
        );

        // The scramble only ever adds ink, and for this seed it adds some.
        assert!(total_ink(&a) > total_ink(&plain), "scramble laid no ink");

        // Deterministic for a given seed -- which is what lets the noise scroll with the
        // text (a given content line keeps its width) instead of flickering per frame.
        let mut b = Gray320x240::new();
        paged(
            &mut b,
            &l,
            "Seed",
            &sink,
            Pager::new(),
            total,
            Some(Scramble::new(0x00C0_FFEE)),
        );
        assert!(identical(&a, &b), "same seed produced a different scramble");

        // A different seed gives a different pattern, so it is not a fixed decoration.
        let mut c = Gray320x240::new();
        paged(
            &mut c,
            &l,
            "Seed",
            &sink,
            Pager::new(),
            total,
            Some(Scramble::new(0x0000_1234)),
        );
        assert!(
            !identical(&a, &c),
            "different seeds produced the same scramble"
        );
    }

    /// The mark is a right-margin cue: it must hug the right edge and never reach the
    /// word to its left, matching `hw-reference/sensitive-display-marking.md`.
    #[test]
    fn scramble_hugs_the_right_margin_and_spares_the_word() {
        // One long line, so the word's ink extends well to the right and the "never
        // touch the word" bound is actually exercised.
        struct One;
        impl LineSource for One {
            fn fill(&self, _from: usize, sink: &mut LineSink) -> usize {
                sink.push("24  mountain");
                1
            }
        }
        let l = Layout::roomy();
        let rows = l.pager_rows(240);
        let mut sink = LineSink::new(rows);
        let total = One.fill(0, &mut sink);

        let mut plain = Gray320x240::new();
        paged(&mut plain, &l, "Seed", &sink, Pager::new(), total, None);
        let mut marked = Gray320x240::new();
        paged(
            &mut marked,
            &l,
            "Seed",
            &sink,
            Pager::new(),
            total,
            Some(Scramble::new(0xBEEF)),
        );

        // Where the word's own ink ends, on the plain render.
        let word_right = (0..320)
            .rev()
            .find(|&x| (0..240).any(|y| plain.get(x, y) != PAPER))
            .expect("the word drew nothing");

        // Every pixel the mark added is strictly to the right of the word, and left of
        // the panel edge. Pixels shared with the plain render (the word, the arrows) are
        // not the mark's doing, so only the *added* ones are checked.
        let mut added = 0;
        let mut rightmost = 0;
        for y in 0..240 {
            for x in 0..320 {
                if marked.get(x, y) != PAPER && plain.get(x, y) == PAPER {
                    added += 1;
                    rightmost = rightmost.max(x);
                    assert!(x > word_right, "mark pixel at x={x} touches the word");
                }
            }
        }
        assert!(added > 0, "no mark was drawn");
        // Every segment ends at the same right anchor (just clear of the arrow column),
        // so the rightmost mark pixel is exactly one left of it -- the bar hugs the right
        // margin rather than floating in the middle of it.
        let gap = l.body.advance(b' ');
        let arrow_x = 320 - (l.body.advance(b'^') + l.margin);
        let right_end = arrow_x - gap;
        assert_eq!(
            rightmost,
            right_end - 1,
            "mark did not hug the right margin (anchor {right_end})"
        );
    }
}
