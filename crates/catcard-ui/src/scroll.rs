//! One scrollable view for every screen that is a document of lines.
//!
//! The older screens ([`crate::widgets`], [`crate::pager`]) each reserved a title line and
//! a note line and then packed a single body font into what was left. That wasted the note
//! line when unused, allowed only one font size, clipped long lines, and scrolled a whole
//! line at a time. This replaces them with a list of [`Line`]s, each carrying its own font
//! [`Size`], [`Align`], a `sensitive` flag (the ragged right-margin marker), and an
//! optional `menu_item` id. A [`ScrollView`] lays them out top to bottom, scrolls by the
//! pixel so a line can be half-visible at an edge, and -- for menus -- moves a cursor over
//! the selectable lines and draws the selected one as an inverted bar.
//!
//! **Wrapping is a preprocessing pass.** [`wrap`] expands the lines to fit the panel width
//! before any of this: a `wrap`-enabled line too wide for its font is split on word
//! boundaries into a head line and continuation lines, and the continuation lines carry no
//! `menu_item`, so a wrapped menu label still selects as one item.

use crate::canvas::{Canvas, INK, Level, PAPER};
use crate::face::Face;
use crate::pager::Scramble;
use crate::text::{centred, width_of};

/// The three font roles a document can use. A board maps each to a real face in [`Fonts`].
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Size {
    Title,
    Body,
    Small,
}

/// How a line sits across the panel.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Align {
    Left,
    Center,
}

/// The faces and spacing a board draws documents with.
#[derive(Copy, Clone)]
pub struct Fonts<'a> {
    pub title: &'a dyn Face,
    pub body: &'a dyn Face,
    pub small: &'a dyn Face,
    /// Extra pixels between one line and the next.
    pub gap: usize,
    /// Left margin for text, and the base of the right gutter kept for arrows and markers.
    pub margin: usize,
}

impl<'a> Fonts<'a> {
    /// The face for a [`Size`].
    pub fn face(&self, size: Size) -> &'a dyn Face {
        match size {
            Size::Title => self.title,
            Size::Body => self.body,
            Size::Small => self.small,
        }
    }
}

/// One line of a document, before wrapping.
#[derive(Copy, Clone)]
pub struct Line<'a> {
    pub text: &'a str,
    pub size: Size,
    pub align: Align,
    /// Draw the ragged sensitive-line marker over this line (needs a [`Scramble`] on the
    /// view).
    pub sensitive: bool,
    /// `Some(id)` makes the line selectable; the id is what [`ScrollView::selected`]
    /// returns. Titles, prose and wrap continuations are `None`.
    pub menu_item: Option<u32>,
    /// Whether [`wrap`] may split this line to fit the panel.
    pub wrap: bool,
}

impl<'a> Line<'a> {
    /// Left-aligned body text, not selectable, not wrapped.
    pub const fn body(text: &'a str) -> Self {
        Self {
            text,
            size: Size::Body,
            align: Align::Left,
            sensitive: false,
            menu_item: None,
            wrap: false,
        }
    }

    /// A centered title in the title face.
    pub const fn title(text: &'a str) -> Self {
        Self {
            text,
            size: Size::Title,
            align: Align::Center,
            sensitive: false,
            menu_item: None,
            wrap: false,
        }
    }

    /// A selectable menu row carrying `id`.
    pub const fn item(text: &'a str, id: u32) -> Self {
        Self {
            text,
            size: Size::Body,
            align: Align::Left,
            sensitive: false,
            menu_item: Some(id),
            wrap: false,
        }
    }

    /// This line in the small face.
    pub const fn small(mut self) -> Self {
        self.size = Size::Small;
        self
    }

    /// Center this line.
    pub const fn centered(mut self) -> Self {
        self.align = Align::Center;
        self
    }

    /// Let [`wrap`] split this line to fit.
    pub const fn wrapped(mut self) -> Self {
        self.wrap = true;
        self
    }

    /// Mark this line secret, so the view draws its ragged right-margin marker.
    pub const fn secret(mut self) -> Self {
        self.sensitive = true;
        self
    }
}

/// A line after wrapping: exactly what one row on screen draws.
#[derive(Copy, Clone)]
pub struct VisualLine<'a> {
    pub text: &'a str,
    pub size: Size,
    pub align: Align,
    pub sensitive: bool,
    pub menu_item: Option<u32>,
}

/// Most visual lines a document holds after wrapping. Enough for a 24-word seed with a
/// title, or any of the menus; long unbounded content (the log) stays on [`crate::pager`].
pub const MAX_LINES: usize = 64;

/// The wrapped lines of a document.
pub type Lines<'a> = heapless::Vec<VisualLine<'a>, MAX_LINES>;

/// The text width available on a line: the panel less the left margin and the right gutter
/// kept clear for the scroll arrows (and the sensitive marker).
fn text_width(canvas_w: usize, fonts: &Fonts<'_>) -> usize {
    let gutter = fonts.body.advance(b'^') + fonts.margin;
    canvas_w.saturating_sub(fonts.margin + gutter)
}

/// Bytes of `s` that fit in `avail` pixels in `face`, broken at the last word boundary that
/// fits; a single word wider than the line is hard-split so wrapping always makes progress.
/// ASCII faces, so byte offsets are character offsets.
fn fit_prefix(face: &dyn Face, s: &str, avail: usize) -> usize {
    let b = s.as_bytes();
    let (mut w, mut i, mut brk) = (0usize, 0usize, 0usize);
    while i < b.len() {
        let adv = face.advance(b[i]);
        if w + adv > avail {
            return if brk > 0 { brk } else { i.max(1) };
        }
        w += adv;
        i += 1;
        // A space we could break before, having fit everything up to it.
        if i < b.len() && b[i] == b' ' {
            brk = i;
        }
    }
    b.len()
}

/// Expand a document to fit `width`, splitting `wrap`-enabled lines that are too wide.
///
/// Continuation lines inherit size/align/sensitivity but never a `menu_item`, so a wrapped
/// menu label is still one selectable item and a wrapped secret still one marked block.
pub fn wrap<'a>(lines: &[Line<'a>], width: usize, fonts: &Fonts<'_>) -> Lines<'a> {
    let mut out = Lines::new();
    let avail = text_width(width, fonts);
    for line in lines {
        let face = fonts.face(line.size);
        if !line.wrap || avail == 0 || width_of(face, line.text) <= avail {
            let _ = out.push(VisualLine {
                text: line.text,
                size: line.size,
                align: line.align,
                sensitive: line.sensitive,
                menu_item: line.menu_item,
            });
            if out.is_full() {
                break;
            }
            continue;
        }
        let mut rest = line.text;
        let mut first = true;
        while !rest.is_empty() {
            let take = fit_prefix(face, rest, avail);
            let (head, tail) = rest.split_at(take);
            let _ = out.push(VisualLine {
                text: head,
                size: line.size,
                align: line.align,
                sensitive: line.sensitive,
                // Only the head keeps the id: continuation lines are not selectable.
                menu_item: if first { line.menu_item } else { None },
            });
            first = false;
            rest = tail.trim_start_matches(' ');
            if out.is_full() {
                break;
            }
        }
    }
    out
}

/// A document laid out for a viewport, scrolled by the pixel.
pub struct ScrollView<'a> {
    lines: Lines<'a>,
    fonts: Fonts<'a>,
    height: usize,
    /// Top of the window in document pixels.
    off: usize,
    /// Index into `lines` of the selected line, if any is selectable.
    cursor: Option<usize>,
    /// The sensitive-line marker source, when this document shows secrets.
    scramble: Option<Scramble>,
}

impl<'a> ScrollView<'a> {
    /// Build a view over already-wrapped `lines`. The cursor starts on the first selectable
    /// line and is scrolled into view.
    pub fn new(lines: Lines<'a>, fonts: Fonts<'a>, height: usize) -> Self {
        let cursor = lines.iter().position(|l| l.menu_item.is_some());
        let mut v = Self {
            lines,
            fonts,
            height,
            off: 0,
            cursor,
            scramble: None,
        };
        v.ensure_cursor_visible();
        v
    }

    /// Wrap `src` to `width` and build a view -- the usual entry point.
    pub fn build(src: &[Line<'a>], width: usize, height: usize, fonts: Fonts<'a>) -> Self {
        Self::new(wrap(src, width, &fonts), fonts, height)
    }

    /// Turn on the sensitive-line marker with a per-viewing seed.
    pub fn with_scramble(mut self, scramble: Scramble) -> Self {
        self.scramble = Some(scramble);
        self
    }

    /// The height of line `i`'s slot: its face plus the inter-line gap.
    fn slot(&self, i: usize) -> usize {
        self.fonts.face(self.lines[i].size).line_height() + self.fonts.gap
    }

    /// Document pixels above line `i`.
    fn top(&self, i: usize) -> usize {
        (0..i).map(|j| self.slot(j)).sum()
    }

    /// Total document height in pixels.
    pub fn content_height(&self) -> usize {
        (0..self.lines.len()).map(|j| self.slot(j)).sum()
    }

    /// The furthest the window can scroll and still show content at the bottom.
    pub fn max_off(&self) -> usize {
        self.content_height().saturating_sub(self.height)
    }

    /// Whether the bottom of the document is on screen.
    pub fn at_end(&self) -> bool {
        self.off >= self.max_off()
    }

    /// One body line: the natural scroll step for a reading screen.
    pub fn line_step(&self) -> usize {
        self.fonts.body.line_height() + self.fonts.gap
    }

    /// Scroll the window by `step` pixels, clamped to the document.
    pub fn scroll(&mut self, down: bool, step: usize) {
        self.off = if down {
            (self.off + step).min(self.max_off())
        } else {
            self.off.saturating_sub(step)
        };
    }

    /// Whether this document has any selectable line (i.e. is a menu).
    pub fn is_menu(&self) -> bool {
        self.cursor.is_some()
    }

    /// The selected line's `menu_item` id, if any.
    pub fn selected(&self) -> Option<u32> {
        self.cursor.and_then(|i| self.lines[i].menu_item)
    }

    /// Move the cursor to the next/previous selectable line, clamping at the ends, and
    /// scroll it into view.
    pub fn move_cursor(&mut self, down: bool) {
        let Some(cur) = self.cursor else {
            return;
        };
        let next = if down {
            (cur + 1..self.lines.len()).find(|&j| self.lines[j].menu_item.is_some())
        } else {
            (0..cur).rev().find(|&j| self.lines[j].menu_item.is_some())
        };
        if let Some(j) = next {
            self.cursor = Some(j);
            self.ensure_cursor_visible();
        }
    }

    /// Nudge the window so the whole selected line is on screen.
    fn ensure_cursor_visible(&mut self) {
        if let Some(i) = self.cursor {
            let (t, h) = (self.top(i), self.slot(i));
            if t < self.off {
                self.off = t;
            } else if t + h > self.off + self.height {
                self.off = t + h - self.height;
            }
        }
    }
}

/// Draw a string at a signed top, clipping the rows that fall outside `[0, height)` so a
/// line can be partly above or below the viewport. `ink` is the glyph colour -- [`PAPER`]
/// knocks the text out of an inverted bar.
fn draw_clipped<C: Canvas + ?Sized>(
    canvas: &mut C,
    face: &dyn Face,
    x: usize,
    top: isize,
    text: &str,
    ink: Level,
    height: usize,
) {
    let (w, lh) = (canvas.width(), face.line_height());
    let mut at = x;
    for &c in text.as_bytes() {
        let adv = face.advance(c);
        if at + adv > w {
            break;
        }
        for gy in 0..lh {
            let y = top + gy as isize;
            if y < 0 || y >= height as isize {
                continue;
            }
            for gx in 0..face.cell_width(c) {
                let cov = face.coverage(c, gx, gy);
                if cov != 0 {
                    canvas.blend(at + gx, y as usize, ink, cov);
                }
            }
        }
        at += adv;
    }
}

/// Fill a horizontal band `[top, top+lh)` across the panel, clipped to the viewport.
fn fill_band<C: Canvas + ?Sized>(canvas: &mut C, top: isize, lh: usize, height: usize) {
    let y0 = top.max(0) as usize;
    let y1 = (top + lh as isize).max(0) as usize;
    let y1 = y1.min(height);
    if y1 > y0 {
        let w = canvas.width();
        canvas.fill_rect(0, y0, w, y1 - y0, INK);
    }
}

/// Draw the whole view onto `canvas`.
pub fn render<C: Canvas + ?Sized>(canvas: &mut C, view: &ScrollView<'_>) {
    canvas.clear();
    let (w, h) = (canvas.width(), view.height);
    let fonts = &view.fonts;
    let arrow = fonts.body.advance(b'^');
    let arrow_x = w.saturating_sub(arrow + fonts.margin);

    for (i, vl) in view.lines.iter().enumerate() {
        let face = fonts.face(vl.size);
        let lh = face.line_height();
        let top = view.top(i) as isize - view.off as isize;
        if top >= h as isize {
            break; // this line and all below it are past the bottom
        }
        if top + lh as isize <= 0 {
            continue; // fully above the top
        }

        let tx = match vl.align {
            Align::Left => fonts.margin,
            Align::Center => centred(face, vl.text, w),
        };

        if view.cursor == Some(i) {
            // The selected row: an inverted bar with the text knocked out of it.
            fill_band(canvas, top, lh, h);
            draw_clipped(canvas, face, tx, top, vl.text, PAPER, h);
        } else {
            draw_clipped(canvas, face, tx, top, vl.text, INK, h);
        }

        // Sensitive-line marker: a ragged strip in the right gutter over the line's height,
        // never reaching the text. Same geometry and per-row lengths as the pager's.
        if let (true, Some(sc)) = (vl.sensitive, view.scramble) {
            let text_right = fonts.margin + width_of(face, vl.text);
            let gap = face.advance(b' ');
            let right_end = arrow_x.saturating_sub(gap);
            let room = right_end.saturating_sub(text_right + gap).min(31);
            if room >= 2 {
                for r in 0..lh {
                    let y = top + r as isize;
                    if y < 0 || y >= h as isize {
                        continue;
                    }
                    let ln = sc.length(i, r, room);
                    if ln >= 2 {
                        canvas.fill_rect(right_end - ln, y as usize, ln, 1, INK);
                    }
                }
            }
        }
    }

    // Scroll indicators, kept in the arrow gutter clear of everything else.
    if view.off > 0 {
        crate::text::draw_text(canvas, fonts.body, arrow_x, 0, "^");
    }
    if !view.at_end() {
        let y = h.saturating_sub(fonts.body.line_height());
        crate::text::draw_text(canvas, fonts.body, arrow_x, y, "v");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canvas::{Gray320x240, PAPER};
    use crate::font::{misc4x6, peep7x14, peep10x20};

    fn fonts() -> Fonts<'static> {
        Fonts {
            title: &peep10x20::FONT,
            body: &peep7x14::FONT,
            small: &misc4x6::FONT,
            gap: 2,
            margin: 6,
        }
    }

    #[test]
    fn a_short_line_is_not_split() {
        let src = [Line::body("short").wrapped()];
        let v = wrap(&src, 320, &fonts());
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].text, "short");
    }

    #[test]
    fn wrapping_breaks_on_word_boundaries_and_keeps_only_the_head_selectable() {
        // A long selectable label that must span more than one visual line.
        let long = "the quick brown fox jumps over the lazy dog again and again and again";
        let src = [Line::item(long, 7).wrapped()];
        let v = wrap(&src, 320, &fonts());
        assert!(v.len() >= 2, "did not wrap");
        // Reassembling the pieces (a space rejoins word breaks) gives the original text.
        let mut joined = alloc_join(&v);
        assert_eq!(joined.trim_end(), long);
        // Only the first visual line carries the id.
        assert_eq!(v[0].menu_item, Some(7));
        assert!(
            v[1..].iter().all(|l| l.menu_item.is_none()),
            "a continuation line was left selectable"
        );
        joined.clear();
    }

    #[test]
    fn an_overlong_word_is_hard_split_rather_than_looping() {
        let word = "x".repeat(400);
        let src = [Line::body(&word).wrapped()];
        let v = wrap(&src, 320, &fonts());
        assert!(v.len() >= 2);
        // Every piece is non-empty, so wrapping always made progress.
        assert!(v.iter().all(|l| !l.text.is_empty()));
        let total: usize = v.iter().map(|l| l.text.len()).sum();
        assert_eq!(total, 400, "characters were lost or duplicated");
    }

    fn alloc_join(v: &Lines<'_>) -> std::string::String {
        let mut s = std::string::String::new();
        for (i, l) in v.iter().enumerate() {
            if i > 0 {
                s.push(' ');
            }
            s.push_str(l.text);
        }
        s
    }

    #[test]
    fn the_cursor_skips_lines_that_are_not_menu_items() {
        let src = [
            Line::title("Menu"),
            Line::item("first", 1),
            Line::body("a note"),
            Line::item("second", 2),
        ];
        let mut v = ScrollView::build(&src, 320, 240, fonts());
        assert_eq!(v.selected(), Some(1));
        v.move_cursor(true);
        assert_eq!(v.selected(), Some(2), "cursor did not skip the title and note");
        v.move_cursor(true);
        assert_eq!(v.selected(), Some(2), "cursor ran off the end instead of clamping");
        v.move_cursor(false);
        assert_eq!(v.selected(), Some(1));
    }

    #[test]
    fn a_document_with_no_items_is_not_a_menu() {
        let src = [Line::title("Words"), Line::body("12  zoo")];
        let v = ScrollView::build(&src, 320, 240, fonts());
        assert!(!v.is_menu());
        assert_eq!(v.selected(), None);
    }

    #[test]
    fn scrolling_clamps_and_reports_the_end() {
        // A tall document in a short viewport.
        let src: [Line; 20] = core::array::from_fn(|_| Line::body("line"));
        let mut v = ScrollView::build(&src, 320, 64, fonts());
        assert!(!v.at_end());
        for _ in 0..100 {
            v.scroll(true, v.line_step());
        }
        assert!(v.at_end(), "scrolling down never reached the end");
        assert_eq!(v.off, v.max_off());
        for _ in 0..100 {
            v.scroll(false, v.line_step());
        }
        assert_eq!(v.off, 0, "scrolling up did not return to the top");
    }

    fn ink_count(c: &Gray320x240) -> usize {
        (0..240)
            .flat_map(|y| (0..320).map(move |x| (x, y)))
            .filter(|&(x, y)| c.get(x, y) != PAPER)
            .count()
    }

    #[test]
    fn the_selected_row_is_an_inverted_bar() {
        let src = [Line::item("only", 1)];
        let v = ScrollView::build(&src, 320, 240, fonts());
        let mut c = Gray320x240::new();
        render(&mut c, &v);
        // A full-width ink band the height of the body face means far more ink than a few
        // glyphs would leave.
        let band = 320 * peep7x14::FONT.height as usize;
        assert!(ink_count(&c) > band / 2, "selected row was not filled");
    }

    #[test]
    fn a_line_scrolled_past_the_top_still_draws_its_visible_rows() {
        // One tall title, scrolled so only its bottom rows remain on screen.
        let src = [Line::title("Top")];
        let mut v = ScrollView::build(&src, 320, 240, fonts());
        v.off = 5; // push the title partly above the viewport
        let mut c = Gray320x240::new();
        render(&mut c, &v);
        // Its top five rows are gone, but the rest still drew something.
        assert!(ink_count(&c) > 0, "a partially-scrolled line vanished entirely");
    }

    #[test]
    fn the_sensitive_marker_stays_right_of_the_word() {
        let src = [Line::body("24  mountain").secret()];
        let v = ScrollView::build(&src, 320, 240, fonts()).with_scramble(Scramble::new(0xBEEF));
        let mut plain = Gray320x240::new();
        render(&mut plain, &ScrollView::build(&src, 320, 240, fonts()));
        let mut marked = Gray320x240::new();
        render(&mut marked, &v);

        let word_right = (0..320)
            .rev()
            .find(|&x| (0..240).any(|y| plain.get(x, y) != PAPER))
            .expect("word drew nothing");
        for y in 0..240 {
            for x in 0..320 {
                if marked.get(x, y) != PAPER && plain.get(x, y) == PAPER {
                    assert!(x > word_right, "marker at x={x} touched the word");
                }
            }
        }
    }
}
