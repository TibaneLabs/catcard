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

use crate::art::Bitmap;
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

/// Characters of `size` that fit on one left-aligned line without being clipped.
///
/// [`render`] keeps a gutter on the right for the scroll arrows and clips left-aligned text
/// at it, so a caller that has to shorten a string to fit -- eliding an address, say -- must
/// measure against the same width the renderer will honour. Measuring against the panel
/// instead leaves the last glyph chopped down its middle, and half a character at the end of
/// an address is indistinguishable from a different character.
///
/// Assumes the fixed-pitch faces this firmware draws with.
pub fn text_cols(fonts: &Fonts<'_>, size: Size, width: usize) -> usize {
    let gutter = fonts.body.advance(b'^') + fonts.margin;
    width.saturating_sub(fonts.margin + gutter) / fonts.face(size).advance(b'0').max(1)
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
    /// A small icon drawn at the left, ahead of the text. The text is indented past it and
    /// the icon stays put when a selected, un-wrapped line marquees. Used by the file
    /// browser for folder/file/parent glyphs.
    pub icon: Option<&'a Bitmap>,
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
            icon: None,
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
            icon: None,
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
            icon: None,
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

    /// Draw `icon` at the left of this line, ahead of the text.
    pub const fn with_icon(mut self, icon: &'a Bitmap) -> Self {
        self.icon = Some(icon);
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
    pub icon: Option<&'a Bitmap>,
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

/// A character boundary at or near `i`. `str::split_at` panics inside a multi-byte
/// character, and a name off a card is not guaranteed ASCII. Walks down, then up when
/// down would give zero -- which would leave [`wrap`] no progress to make.
fn char_boundary(s: &str, i: usize) -> usize {
    let mut at = i.min(s.len());
    while at > 0 && !s.is_char_boundary(at) {
        at -= 1;
    }
    if at > 0 {
        return at;
    }
    at = i.min(s.len()).max(1);
    while at < s.len() && !s.is_char_boundary(at) {
        at += 1;
    }
    at
}

/// Bytes of `s` that fit in `avail` pixels in `face`, broken at the last word boundary that
/// fits; a single word wider than the line is hard-split so wrapping always makes progress.
///
/// Always returns a character boundary. Widths are still summed per byte, so a multi-byte
/// character costs a little room on the line and never an index.
fn fit_prefix(face: &dyn Face, s: &str, avail: usize) -> usize {
    let b = s.as_bytes();
    let (mut w, mut i, mut brk) = (0usize, 0usize, 0usize);
    while i < b.len() {
        let adv = face.advance(b[i]);
        if w + adv > avail {
            // `brk` indexes a space, already a boundary; only the hard split needs one.
            return if brk > 0 {
                brk
            } else {
                char_boundary(s, i.max(1))
            };
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
                icon: line.icon,
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
                // Only the head keeps the id and icon: continuation lines are neither
                // selectable nor re-iconed.
                menu_item: if first { line.menu_item } else { None },
                icon: if first { line.icon } else { None },
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
    /// Panel width and height in pixels.
    width: usize,
    height: usize,
    /// Top of the window in document pixels.
    off: usize,
    /// Index into `lines` of the selected line, if any is selectable.
    cursor: Option<usize>,
    /// The sensitive-line marker source, when this document shows secrets.
    scramble: Option<Scramble>,
    /// Horizontal marquee phase for the selected line, advanced by [`Self::tick_marquee`].
    marquee: usize,
}

impl<'a> ScrollView<'a> {
    /// Build a view over already-wrapped `lines`. The cursor starts on the first selectable
    /// line and is scrolled into view.
    pub fn new(lines: Lines<'a>, fonts: Fonts<'a>, width: usize, height: usize) -> Self {
        let cursor = lines.iter().position(|l| l.menu_item.is_some());
        let mut v = Self {
            lines,
            fonts,
            width,
            height,
            off: 0,
            cursor,
            scramble: None,
            marquee: 0,
        };
        v.ensure_cursor_visible();
        v
    }

    /// Wrap `src` to `width` and build a view -- the usual entry point.
    pub fn build(src: &[Line<'a>], width: usize, height: usize, fonts: Fonts<'a>) -> Self {
        Self::new(wrap(src, width, &fonts), fonts, width, height)
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

    /// The current pixel scroll offset, for a caller that persists it across redraws.
    pub fn off(&self) -> usize {
        self.off
    }

    /// Restore a scroll offset, clamped to the document.
    pub fn set_off(&mut self, off: usize) {
        self.off = off.min(self.max_off());
    }

    /// Whether this document has any selectable line (i.e. is a menu).
    pub fn is_menu(&self) -> bool {
        self.cursor.is_some()
    }

    /// The selected line's `menu_item` id, if any.
    pub fn selected(&self) -> Option<u32> {
        self.cursor.and_then(|i| self.lines[i].menu_item)
    }

    /// Put the cursor on the line whose `menu_item` is `id`, scrolling it into view. Used
    /// by a caller that tracks the selection itself (the run loop) and rebuilds the view
    /// each frame. No-op if no line carries that id.
    pub fn select(&mut self, id: u32) {
        if let Some(i) = self.lines.iter().position(|l| l.menu_item == Some(id)) {
            if self.cursor != Some(i) {
                self.marquee = 0;
            }
            self.cursor = Some(i);
            self.ensure_cursor_visible();
        }
    }

    /// The icon's horizontal footprint on line `i` -- its scaled width plus a small gap --
    /// or zero when it has no icon. The icon is scaled to about the line height, matching
    /// [`crate::icons`].
    fn icon_advance(&self, i: usize) -> usize {
        match self.lines[i].icon {
            Some(bmp) => {
                let lh = self.fonts.face(self.lines[i].size).line_height();
                bmp.width as usize * (lh / 7).max(1) + 2
            }
            None => 0,
        }
    }

    /// Where line `i`'s text starts: past the left margin and any icon.
    fn text_left(&self, i: usize) -> usize {
        self.fonts.margin + self.icon_advance(i)
    }

    /// The right edge text stops at, kept clear of the arrow gutter.
    fn text_right(&self) -> usize {
        let gutter = self.fonts.body.advance(b'^') + self.fonts.margin;
        self.width.saturating_sub(gutter)
    }

    /// How many pixels line `i`'s text runs past the space it has.
    fn overflow(&self, i: usize) -> usize {
        let text_w = width_of(self.fonts.face(self.lines[i].size), self.lines[i].text);
        let avail = self.text_right().saturating_sub(self.text_left(i));
        text_w.saturating_sub(avail)
    }

    /// The marquee only runs on a selected, left-aligned line whose text overflows; this is
    /// how far it can travel. Wrapped lines fit by construction, so this is zero for them.
    fn marquee_span(&self) -> usize {
        match self.cursor {
            Some(i) if self.lines[i].align == Align::Left => self.overflow(i),
            _ => 0,
        }
    }

    /// Whether the selected line's name is too long to show at once, so it wants a marquee.
    pub fn needs_marquee(&self) -> bool {
        self.marquee_span() > 0
    }

    /// The current horizontal shift of the selected line's text.
    fn marquee_shift(&self) -> usize {
        self.marquee.min(self.marquee_span())
    }

    /// Advance the marquee one step; returns whether anything changed (so the caller knows
    /// to redraw). It ramps to the end, dwells, then snaps back to the start.
    pub fn tick_marquee(&mut self) -> bool {
        let span = self.marquee_span();
        if span == 0 {
            // Nothing to scroll; clear any leftover shift from a previous selection.
            let dirty = self.marquee != 0;
            self.marquee = 0;
            return dirty;
        }
        // Pause at the fully-scrolled end before jumping back, so the tail can be read.
        const DWELL: usize = 12;
        self.marquee += 1;
        if self.marquee > span + DWELL {
            self.marquee = 0;
        }
        true
    }

    /// Move the selection one step.
    ///
    /// If there is another selectable line that way, the cursor moves to it and the view
    /// scrolls the *minimum* needed to keep it on screen -- so the highlight travels within
    /// the panel and only pushes the view once it reaches an edge. If there is no further
    /// selectable line (already the first or last item), the view keeps scrolling that way
    /// while it can, so pressing up past the first item reveals the title and any text
    /// above it, and pressing down past the last reveals trailing content.
    pub fn move_cursor(&mut self, down: bool) {
        let Some(cur) = self.cursor else {
            self.scroll(down, self.line_step());
            return;
        };
        let next = if down {
            (cur + 1..self.lines.len()).find(|&j| self.lines[j].menu_item.is_some())
        } else {
            (0..cur).rev().find(|&j| self.lines[j].menu_item.is_some())
        };
        match next {
            Some(j) => {
                // A new selection starts its name from the left again.
                self.marquee = 0;
                self.cursor = Some(j);
                self.ensure_cursor_visible();
            }
            // Past the last selectable line either way: scroll the view to show whatever
            // sits beyond it (a title, a note) rather than doing nothing.
            None => self.scroll(down, self.line_step()),
        }
    }

    /// Jump straight back to the top: the first selectable line (if any) and the top of
    /// the document. This is what the `0` key does.
    pub fn to_top(&mut self) {
        self.cursor = self.lines.iter().position(|l| l.menu_item.is_some());
        self.off = 0;
        self.marquee = 0;
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

/// Draw a string at a signed origin, clipped to the box `[xmin, xmax) x [0, height)`.
///
/// A signed `x` lets the text start left of `xmin` (how the marquee scrolls a long name
/// under a fixed left edge); the vertical clip lets a line be partly above or below the
/// viewport. `ink` is the glyph colour -- [`PAPER`] knocks the text out of an inverted bar.
#[allow(clippy::too_many_arguments)]
fn draw_clipped<C: Canvas + ?Sized>(
    canvas: &mut C,
    face: &dyn Face,
    x: isize,
    top: isize,
    text: &str,
    ink: Level,
    height: usize,
    xmin: usize,
    xmax: usize,
) {
    let lh = face.line_height();
    let mut at = x;
    for &c in text.as_bytes() {
        let adv = face.advance(c) as isize;
        if at >= xmax as isize {
            break; // this glyph and the rest are past the right edge
        }
        if at + adv > xmin as isize {
            for gy in 0..lh {
                let y = top + gy as isize;
                if y < 0 || y >= height as isize {
                    continue;
                }
                for gx in 0..face.cell_width(c) {
                    let px = at + gx as isize;
                    if px < xmin as isize || px >= xmax as isize {
                        continue;
                    }
                    let cov = face.coverage(c, gx, gy);
                    if cov != 0 {
                        canvas.blend(px as usize, y as usize, ink, cov);
                    }
                }
            }
        }
        at += adv;
    }
}

/// Draw a 1-bpp icon at `(x, top)`, each pixel a `scale`x`scale` block, in `ink`, clipped
/// to the viewport rows.
fn draw_icon<C: Canvas + ?Sized>(
    canvas: &mut C,
    bmp: &Bitmap,
    x: usize,
    top: isize,
    scale: usize,
    ink: Level,
    height: usize,
) {
    for gy in 0..bmp.height as usize {
        for gx in 0..bmp.width as usize {
            if !bmp.pixel(gx, gy) {
                continue;
            }
            for sy in 0..scale {
                let y = top + (gy * scale + sy) as isize;
                if y < 0 || y >= height as isize {
                    continue;
                }
                for sx in 0..scale {
                    canvas.put(x + gx * scale + sx, y as usize, ink);
                }
            }
        }
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

        let selected = view.cursor == Some(i);
        let ink = if selected { PAPER } else { INK };
        if selected {
            // The selected row is an inverted bar with everything knocked out of it.
            fill_band(canvas, top, lh, h);
        }

        // The icon sits at the left margin and stays put while the text marquees.
        let mut tx = fonts.margin;
        if let (Some(bmp), Align::Left) = (vl.icon, vl.align) {
            let scale = (lh / 7).max(1);
            draw_icon(canvas, bmp, fonts.margin, top, scale, ink, h);
            tx = fonts.margin + bmp.width as usize * scale + 2;
        }

        match vl.align {
            Align::Left => {
                // A selected, overflowing name scrolls sideways: the icon and the left edge
                // stay put and the text is clipped to the room right of the icon.
                let shift = if selected { view.marquee_shift() } else { 0 };
                let x = tx as isize - shift as isize;
                draw_clipped(canvas, face, x, top, vl.text, ink, h, tx, arrow_x);
            }
            Align::Center => {
                let x = centred(face, vl.text, w) as isize;
                draw_clipped(canvas, face, x, top, vl.text, ink, h, 0, w);
            }
        }

        // Sensitive-line marker: a ragged strip in the right gutter over the line's height,
        // never reaching the text. Same geometry and per-row lengths as the pager's.
        if let (true, Some(sc)) = (vl.sensitive, view.scramble) {
            let text_right = fonts.margin + width_of(face, vl.text);
            let space = face.advance(b' ');
            let right_end = arrow_x.saturating_sub(space);
            let room = right_end.saturating_sub(text_right + space).min(31);
            // Carry the strip through the inter-line gap when the next line is also
            // secret, so the ragged bar is continuous down a block of words rather than
            // broken by a blank row between each.
            let next_secret = view.lines.get(i + 1).is_some_and(|n| n.sensitive);
            let bleed = if next_secret { fonts.gap } else { 0 };
            if room >= 2 {
                for r in 0..lh + bleed {
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

    /// Mono-panel-shaped fonts (14px title and body), for the scroll-behaviour tests.
    fn compact_fonts() -> Fonts<'static> {
        Fonts {
            title: &peep7x14::FONT,
            body: &peep7x14::FONT,
            small: &misc4x6::FONT,
            gap: 1,
            margin: 2,
        }
    }

    #[test]
    fn a_name_that_is_not_ascii_wraps_instead_of_splitting_a_character() {
        // A card holds whatever it holds, and a hard split on a byte index lands inside
        // a character -- a panic, which on this firmware is a halt.
        let fonts = compact_fonts();
        for pad in 0..40usize {
            for tail in ["", "x", "xxxxxxxxxxxxxxxxxxxx.psbt"] {
                for ch in ['\u{e9}', '\u{20ac}', '\u{1f600}'] {
                    let name = format!("{}{ch}{tail}", "a".repeat(pad));
                    let out = wrap(&[Line::body(&name).wrapped()], 128, &fonts);
                    // No spaces, so nothing is dropped at a break: the pieces must rejoin.
                    let joined: String = out.iter().map(|l| l.text).collect();
                    assert_eq!(joined, name, "{name:?} came apart");
                }
            }
        }
    }

    /// The mono panel, as `catcard_fw::display` configures it. `compact_fonts` matches
    /// its `FONTS`, so these tests answer for the build that ships.
    const MONO_W: usize = 128;
    const MONO_H: usize = 64;

    #[test]
    fn the_file_detail_screen_survives_a_name_that_is_not_ascii() {
        // The document `file_info` builds, through the entry point `show_doc` uses.
        let fonts = compact_fonts();
        for pad in 0..40usize {
            for ch in ['\u{e9}', '\u{20ac}', '\u{1f600}'] {
                let name = format!("{}{ch}xxxxxxxx.psbt", "a".repeat(pad));
                let sz = "4096 bytes";
                let doc = [
                    Line::title("File"),
                    Line::body(&name).wrapped(),
                    Line::body(sz).small(),
                    Line::body("y = select this").centered(),
                ];
                let view = ScrollView::build(&doc, MONO_W, MONO_H, fonts);
                assert!(view.content_height() > 0, "{name:?} laid out to nothing");
            }
        }
    }

    #[test]
    fn a_line_that_is_one_wide_character_still_makes_progress() {
        // Walking down to a boundary gives zero here, and `wrap` would spin.
        let fonts = compact_fonts();
        let out = wrap(
            &[Line::body("\u{1f600}\u{1f600}\u{1f600}").wrapped()],
            24,
            &fonts,
        );
        assert!(!out.is_empty());
        assert!(out.iter().all(|l| !l.text.is_empty()));
    }

    #[test]
    fn a_line_of_text_cols_characters_is_drawn_whole() {
        // The bug this pins: a caller that elides to `(width - margin) / advance` overruns
        // the arrow gutter, and `render` clips the last glyph down its middle. On an
        // address that is a character the owner cannot read and cannot check.
        use crate::canvas::Canvas;
        use crate::framebuffer::Mono128x64;

        let fonts = compact_fonts();
        let cols = text_cols(&fonts, Size::Body, 128);
        assert!(cols > 0);
        let text: String = core::iter::repeat_n('M', cols).collect();
        let doc = [Line::body(&text)];
        let view = ScrollView::build(&doc, 128, 64, fonts);
        let mut c = Mono128x64::new();
        render(&mut c, &view);

        // Same text, drawn with nothing in the way.
        let mut plain = Mono128x64::new();
        crate::text::draw_text(&mut plain, fonts.body, fonts.margin, 0, &text);
        for y in 0..fonts.body.line_height() {
            for x in 0..128 {
                assert_eq!(
                    Canvas::get(&c, x, y),
                    Canvas::get(&plain, x, y),
                    "clipped at {x},{y} with {cols} columns"
                );
            }
        }

        // And one more character would not have fitted: the check is tight, not generous.
        let over: String = core::iter::repeat_n('M', cols + 1).collect();
        let doc = [Line::body(&over)];
        let view = ScrollView::build(&doc, 128, 64, fonts);
        let mut c = Mono128x64::new();
        render(&mut c, &view);
        let mut plain = Mono128x64::new();
        crate::text::draw_text(&mut plain, fonts.body, fonts.margin, 0, &over);
        let same = (0..fonts.body.line_height())
            .all(|y| (0..128).all(|x| Canvas::get(&c, x, y) == Canvas::get(&plain, x, y)));
        assert!(!same, "{} columns should have been clipped", cols + 1);
    }

    fn a_menu() -> [Line<'static>; 6] {
        [
            Line::title("Menu"),
            Line::item("one", 1),
            Line::item("two", 2),
            Line::item("three", 3),
            Line::item("four", 4),
            Line::item("five", 5),
        ]
    }

    #[test]
    fn the_highlight_moves_within_the_screen_before_the_view_scrolls() {
        let src = a_menu();
        // 64px fits the title and three 15px item slots, so an early move stays on screen.
        let mut v = ScrollView::build(&src, 128, 64, compact_fonts());
        assert_eq!(v.off(), 0);
        v.move_cursor(true);
        assert_eq!(
            v.off(),
            0,
            "the view scrolled before the highlight reached an edge"
        );
    }

    #[test]
    fn pressing_up_on_the_first_item_reveals_the_title() {
        let src = a_menu();
        let mut v = ScrollView::build(&src, 128, 64, compact_fonts());
        // Walk to the bottom so the title has left the screen.
        for _ in 0..5 {
            v.move_cursor(true);
        }
        assert!(v.off() > 0, "never scrolled");
        // Back up to the first item; its row ends up against the top with the title still
        // hidden above it.
        for _ in 0..4 {
            v.move_cursor(false);
        }
        assert_eq!(v.selected(), Some(1));
        assert!(v.off() > 0, "first item did not sit against the top");
        // Pressing up again has no earlier item, so it keeps scrolling to show the title.
        v.move_cursor(false);
        assert_eq!(v.off(), 0, "did not scroll up to reveal the title");
    }

    #[test]
    fn to_top_returns_to_the_first_item_and_the_top() {
        let src = a_menu();
        let mut v = ScrollView::build(&src, 128, 64, compact_fonts());
        for _ in 0..5 {
            v.move_cursor(true);
        }
        assert!(v.off() > 0, "never scrolled away from the top");
        v.to_top();
        assert_eq!(v.off(), 0);
        assert_eq!(
            v.selected(),
            Some(1),
            "cursor did not return to the first item"
        );
    }

    #[test]
    fn pressing_down_on_the_last_item_reveals_trailing_content() {
        // A menu with a note after the last item.
        let src = [
            Line::title("Menu"),
            Line::item("one", 1),
            Line::item("two", 2),
            Line::item("three", 3),
            Line::body("a footnote below the last item"),
        ];
        let mut v = ScrollView::build(&src, 128, 64, compact_fonts());
        for _ in 0..5 {
            v.move_cursor(true);
        }
        assert_eq!(v.selected(), Some(3), "cursor left the last item");
        // At the end already? push once more to be sure it clamps rather than looping.
        let end = v.off();
        v.move_cursor(true);
        assert_eq!(
            v.off(),
            end.max(v.off()),
            "scrolling past the end went backwards"
        );
        assert!(v.at_end());
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
        assert_eq!(
            v.selected(),
            Some(2),
            "cursor did not skip the title and note"
        );
        v.move_cursor(true);
        assert_eq!(
            v.selected(),
            Some(2),
            "cursor ran off the end instead of clamping"
        );
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
        assert!(
            ink_count(&c) > 0,
            "a partially-scrolled line vanished entirely"
        );
    }

    #[test]
    fn an_icon_indents_the_text_and_a_long_name_wants_a_marquee() {
        use crate::icons::{FILE, FOLDER};
        // A long file name on a narrow panel: icon at the left, name overflows.
        let long = "a-really-long-file-name-that-will-not-fit.psbt";
        let src = [
            Line::item("dir", 0).with_icon(&FOLDER),
            Line::item(long, 1).with_icon(&FILE),
        ];
        let mut v = ScrollView::build(&src, 128, 64, compact_fonts());
        // Cursor starts on the folder (fits): no marquee.
        assert_eq!(v.selected(), Some(0));
        assert!(!v.needs_marquee());
        // Move to the long file: now it wants to scroll.
        v.move_cursor(true);
        assert_eq!(v.selected(), Some(1));
        assert!(
            v.needs_marquee(),
            "a name wider than the panel did not marquee"
        );
        // Ticking advances the shift and eventually snaps back to the start.
        assert!(v.tick_marquee());
        let mut saw_reset = false;
        for _ in 0..400 {
            v.tick_marquee();
            if v.marquee == 0 {
                saw_reset = true;
                break;
            }
        }
        assert!(saw_reset, "the marquee never cycled back to the start");
        // A short selection clears the marquee.
        v.move_cursor(false);
        assert!(!v.needs_marquee());
    }

    #[test]
    fn the_marker_bridges_the_gap_between_two_sensitive_lines() {
        use crate::framebuffer::Mono128x64;
        let src = [Line::body("aa").secret(), Line::body("bb").secret()];
        let v = ScrollView::build(&src, 128, 64, compact_fonts()).with_scramble(Scramble::new(1));
        let mut c = Mono128x64::new();
        render(&mut c, &v);
        // The blank row between the two lines (y = body line height, the inter-line gap)
        // now carries marker ink on the right, so the ragged strip is unbroken.
        let gap_y = peep7x14::FONT.height as usize;
        // The mono framebuffer's inherent `get` returns whether the pixel is lit.
        assert!(
            (80..128).any(|x| c.get(x, gap_y)),
            "the gap row between two sensitive lines had no marker"
        );
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
