//! A grid of icons with labels under them: the Q1's main menu.
//!
//! Six things a person does, laid out so the one they want is a glance rather than a
//! scroll. A list is the right shape for fifteen settings; it is the wrong shape for the
//! half-dozen places everything else hangs off, where the shape of the menu is itself
//! worth learning.
//!
//! Geometry is derived from the canvas rather than fixed, so the same code lays out
//! whatever height the status bar leaves. What is *not* derived is the icon size: art is
//! drawn at one size and scaling pixel art is how it stops being pixel art, so
//! [`ICON`] is a constant the art is authored against and the rest gives way around it.
//!
//! # One palette for the row
//!
//! The canvas holds an index per pixel and the panel maps those through a 16-entry
//! palette at send time, so everything on one scanline shares one palette. Three icons
//! side by side are on the same scanlines, so **they share a palette**; the two rows are
//! on different scanlines, so they need not share with each other. That is the budget
//! the art is authored to, and why the renderer here draws indices and never colours.

use crate::art::indexed::Indexed;
use crate::canvas::{Canvas, INK, Level, PAPER};
use crate::face::Face;
use crate::text::{draw_text_in, width_of};

/// Columns, and rows: six cells.
pub const COLS: usize = 3;
pub const ROWS: usize = 2;
pub const CELLS: usize = COLS * ROWS;

/// The size every icon is authored at, in pixels, square.
///
/// Fixed rather than fitted: pixel art scaled to fit is pixel art with the decisions
/// blurred out of it. The cell is built around this.
pub const ICON: usize = 64;

/// Space between the icon and its label.
const LABEL_GAP: usize = 4;

/// One cell: what it shows and what it is called.
#[derive(Copy, Clone)]
pub struct Cell<'a> {
    pub label: &'a str,
    /// `None` renders the cell's frame and label with no art, which is what a build
    /// whose icons have not landed yet looks like -- deliberately, rather than
    /// substituting something that would read as the wrong icon.
    pub icon: Option<&'a Indexed>,
}

/// Where a cell sits on the canvas.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Rect {
    pub x: usize,
    pub y: usize,
    pub w: usize,
    pub h: usize,
}

/// The rectangle cell `i` occupies on a canvas `w` x `h`.
///
/// Columns divide the width exactly, remainder spread one pixel at a time from the left,
/// so three columns of a 320-wide panel are 107, 107, 106 rather than 106 and a six-pixel
/// gutter nobody chose.
pub fn cell_rect(i: usize, w: usize, h: usize) -> Rect {
    let (col, row) = (i % COLS, i / COLS);
    let (cw, extra) = (w / COLS, w % COLS);
    let x = col * cw + col.min(extra);
    let width = cw + usize::from(col < extra);
    let (ch, tall) = (h / ROWS, h % ROWS);
    let y = row * ch + row.min(tall);
    let height = ch + usize::from(row < tall);
    Rect {
        x,
        y,
        w: width,
        h: height,
    }
}

/// How many columns a set of cells needs. Never zero: an empty menu is one empty column.
pub fn columns(len: usize) -> usize {
    len.div_ceil(ROWS).max(1)
}

/// How many windows' worth of columns there are, for the dots along the bottom.
pub fn pages(len: usize) -> usize {
    columns(len).div_ceil(COLS).max(1)
}

/// Which of the window's cells a visible index occupies, left to right, top to bottom.
///
/// The window is filled down each column in turn, as the strip is; `cell_rect` counts
/// across. This is the one place the two orders meet.
pub const fn slot(i: usize) -> usize {
    (i % ROWS) * COLS + i / ROWS
}

/// Where a cell sits in the strip: which column, and which row of it.
///
/// **Column-major**, which is what makes the strip continuous. A grid that filled left
/// to right would have to know how many columns there are in total before it could place
/// anything, so adding one item would move every other -- and the window could then only
/// move a whole page at a time, because a partial page would be laid out differently
/// from a full one. Filling downwards first means a cell's place never depends on what
/// is visible, which is what lets the window move one column at a time.
pub const fn place(i: usize) -> (usize, usize) {
    (i / ROWS, i % ROWS)
}

/// The leftmost column to show, given where the cursor is and where the window was.
///
/// **Moves as little as it can**, which is what the list does vertically: the cursor
/// travels inside the window until it reaches an edge, and only then does the window
/// follow it by one column. A grid that jumped a whole page on every crossing would move
/// the picture further than the key asked for, and the eye would lose the cell it was
/// following.
pub fn window(cursor: usize, len: usize, off: usize) -> usize {
    let last = columns(len) - 1;
    let (col, _) = place(cursor.min(len.saturating_sub(1)));
    let off = off.min(last.saturating_sub(COLS - 1).min(off));
    if col < off {
        return col;
    }
    if col >= off + COLS {
        return col + 1 - COLS;
    }
    off
}

/// A movement key, as the grid understands it.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Dir {
    Up,
    Down,
    Left,
    Right,
    /// Back to the first cell of the first page.
    Home,
}

/// Where a movement takes the cursor, over one strip of columns.
///
/// **Sideways moves one column; up and down stay in the one they are in.** The strip is
/// continuous, so there is no page to leave -- right is the next column, whatever is on
/// screen at the time, and the window follows only as far as it must.
///
/// Nothing wraps: at the last column, right stays put. A cursor that jumped back to the
/// start would be a movement nobody asked for, in a direction they did not press.
pub fn step(cursor: usize, len: usize, dir: Dir) -> usize {
    if len == 0 {
        return 0;
    }
    let last = len - 1;
    let (col, row) = place(cursor.min(last));
    // A cell that does not exist is not somewhere the cursor may land, so every landing
    // is clamped to the last one.
    let at = |col: usize, row: usize| (col * ROWS + row).min(last);
    match dir {
        Dir::Home => 0,
        Dir::Down if row + 1 < ROWS => at(col, row + 1),
        Dir::Up if row > 0 => at(col, row - 1),
        Dir::Right if (col + 1) * ROWS <= last => at(col + 1, row),
        Dir::Left if col > 0 => at(col - 1, row),
        _ => cursor.min(last),
    }
}

/// Draw the grid, with `selected` marked.
///
/// `label` is the face the captions use. The caller has already cleared, or not: this
/// paints its own background so a redraw does not need one.
pub fn render<C: Canvas + ?Sized>(
    canvas: &mut C,
    font: &dyn Face,
    small: &dyn Face,
    cells: &[Cell<'_>],
    selected: usize,
) {
    render_page(canvas, font, small, cells, selected, 0, cells.len());
}

/// Draw one page of a strip of pages: the cells given, plus what says there are others.
///
/// `cells` is this page's cells and `selected` is the index within them, or out of range
/// for a page with no cursor on it. `page` and `pages` are where this one is in the
/// strip, which is what the edge hints and the dots are drawn from.
///
/// **The pages are beside each other, not stacked.** Moving off the right of one lands
/// on the left of the next, so the hint that there is more says which way to go: a
/// chevron over a band of background that lifts toward the edge, on whichever sides have
/// a page. The dots along the bottom say how many there are and which this is -- the
/// same thing the `1/2` in the corner used to say, in something the eye reads without
/// stopping on it.
#[allow(clippy::too_many_arguments)] // two faces, the cells, and where in the strip
pub fn render_page<C: Canvas + ?Sized>(
    canvas: &mut C,
    font: &dyn Face,
    small: &dyn Face,
    cells: &[Cell<'_>],
    selected: usize,
    off: usize,
    len: usize,
) {
    let (w, h) = (canvas.width(), canvas.height());
    canvas.fill_rect(0, 0, w, h, PAPER);
    let columns = columns(len);
    let more = columns > COLS;
    // The dots get a strip of their own rather than being laid over the bottom row's
    // labels: a caption with a dot in it is not a caption.
    let body = if more { h - DOTS_H.min(h) } else { h };
    // `cells` is the window: the columns from `off`, laid out down each one in turn,
    // which is the order they are numbered in.
    for (i, cell) in cells.iter().enumerate().take(CELLS) {
        draw_cell(
            canvas,
            font,
            small,
            &cell_rect(slot(i), w, body),
            cell,
            i == selected,
        );
    }
    if more {
        if off > 0 {
            edge_hint(canvas, body, false);
        }
        if off + COLS < columns {
            edge_hint(canvas, body, true);
        }
        // The dots say how far along the strip the window is, in windows' worth --
        // which is what a person counts, rather than columns they cannot see.
        dots(canvas, off / COLS, pages(len));
    }
}

/// The strip along the bottom the page dots live in.
const DOTS_H: usize = 10;

/// How wide the shaded band at an edge is.
const HINT_W: usize = 8;
/// Half the chevron's height, and how far it reaches in from the edge.
const CHEVRON: usize = 10;
/// How thick the chevron's strokes are. Two pixels is a hairline at this size; three
/// reads as a mark somebody drew.
const STROKE: usize = 3;

/// The mark that says the pages carry on this way: a chevron over a shaded band.
///
/// The chevron is the message and the band is what makes it findable -- the eye lands on
/// an edge that is a different shade before it lands on anything drawn at one.
///
/// **Dithered, not shaded.** This screen is drawn through the artwork's palette, whose
/// middle entries are a coin's blue and a cat's orange rather than steps of a ramp --
/// there is no "slightly lighter than the background" to ask for. So the band is ink
/// scattered thinly on the background, which is a shade at any palette, and kept light
/// enough that it reads as a shadow rather than as a dashed border.
fn edge_hint<C: Canvas + ?Sized>(canvas: &mut C, h: usize, right: bool) {
    /// The ordered-dither matrix, 4x4: a pixel is set where the threshold beats it.
    const BAYER: [[u8; 4]; 4] = [[0, 8, 2, 10], [12, 4, 14, 6], [3, 11, 1, 9], [15, 7, 13, 5]];
    let w = canvas.width();
    if w < 2 * HINT_W || h < 4 * CHEVRON {
        return;
    }
    for step in 0..HINT_W {
        // A quarter of the pixels against the edge, none of them by the inner side.
        let density = 4u8.saturating_sub((step * 4 / HINT_W) as u8);
        let x = if right { w - 1 - step } else { step };
        for y in 0..h {
            if BAYER[y % 4][x % 4] < density {
                canvas.put(x, y, INK);
            }
        }
    }
    // The chevron: a tip at the edge and two arms running back from it, so it points
    // the way the next page is.
    let mid = h / 2;
    for k in 0..CHEVRON {
        let dx = 2 + k;
        let x = if right { w - dx - STROKE } else { dx };
        canvas.fill_rect(x, mid - k - STROKE / 2, STROKE, STROKE, INK);
        canvas.fill_rect(x, mid + k - STROKE / 2, STROKE, STROKE, INK);
    }
}

/// One dot per page along the bottom, the current one filled.
fn dots<C: Canvas + ?Sized>(canvas: &mut C, page: usize, pages: usize) {
    const R: usize = 3;
    const GAP: usize = 5;
    let (w, h) = (canvas.width(), canvas.height());
    let span = pages * R + (pages - 1) * GAP;
    if span > w || h < R + 2 {
        return;
    }
    let y = h - R - 1;
    let mut x = (w - span) / 2;
    for i in 0..pages {
        // The page you are on is a filled square; the others are its four corners, which
        // is the same shape with less of it. Ink either way -- the palette here has no
        // dim (see `edge_hint`).
        if i == page {
            canvas.fill_rect(x, y, R, R, INK);
        } else {
            canvas.put(x, y, INK);
            canvas.put(x + R - 1, y, INK);
            canvas.put(x, y + R - 1, INK);
            canvas.put(x + R - 1, y + R - 1, INK);
        }
        x += R + GAP;
    }
}

fn draw_cell<C: Canvas + ?Sized>(
    canvas: &mut C,
    font: &dyn Face,
    small: &dyn Face,
    at: &Rect,
    cell: &Cell<'_>,
    selected: bool,
) {
    // How the label is going to be set, which decides how tall the block is.
    let room = at.w.saturating_sub(2 * LABEL_GAP);
    let label = Label::fit(font, small, cell.label, room);

    // Icon and label as one block, centred in what the cell has. Where the cell is too
    // short for both the label wins: a nameless picture is a guess, a named empty box is
    // a menu entry whose art has not arrived.
    let block = ICON + LABEL_GAP + label.height();
    let top = at.y + at.h.saturating_sub(block) / 2;

    if let Some(art) = cell.icon {
        let ix = at.x + at.w.saturating_sub(art.width as usize) / 2;
        crate::art::indexed::draw_indexed(canvas, art, ix, top);
    }

    let mut y = top + ICON + LABEL_GAP;
    for line in label.lines() {
        if y + label.face.line_height() > at.y + at.h {
            break;
        }
        let tw = width_of(label.face, line);
        let tx = at.x + at.w.saturating_sub(tw) / 2;
        draw_text_in(canvas, label.face, tx, y, line, INK);
        y += label.face.line_height();
    }

    if selected {
        frame(canvas, at);
    }
}

/// A cell's caption, laid out to the width it has.
///
/// Three columns of a 320-wide panel are 106 pixels, which in a 10x20 face is ten
/// characters -- and the menus this now draws were written for a list, where "Browse SD
/// card" had a row to itself. So a caption that does not fit is tried again over two
/// lines, and then in the smaller face, and only then cut. Cutting first is what turned
/// `Analyze RNG` into `Analyze R`.
struct Label<'a> {
    face: &'a dyn Face,
    first: &'a str,
    second: Option<&'a str>,
}

impl<'a> Label<'a> {
    fn fit(font: &'a dyn Face, small: &'a dyn Face, text: &'a str, room: usize) -> Self {
        for face in [font, small] {
            if width_of(face, text) <= room {
                return Label {
                    face,
                    first: text,
                    second: None,
                };
            }
            // At a space, so the break is between words rather than inside one. The
            // last space that leaves both halves fitting wins; a single long word has
            // none and falls through to the next face.
            if let Some((a, b)) = split_to_fit(face, text, room) {
                return Label {
                    face,
                    first: a,
                    second: Some(b),
                };
            }
        }
        Label {
            face: small,
            first: fit_text(small, text, room),
            second: None,
        }
    }

    fn height(&self) -> usize {
        self.face.line_height() * if self.second.is_some() { 2 } else { 1 }
    }

    fn lines(&self) -> impl Iterator<Item = &'a str> {
        [Some(self.first), self.second].into_iter().flatten()
    }
}

/// Split at the space that leaves both halves inside `room`, preferring the latest one.
fn split_to_fit<'a>(font: &dyn Face, text: &'a str, room: usize) -> Option<(&'a str, &'a str)> {
    let mut best = None;
    for (i, _) in text.match_indices(' ') {
        let (a, b) = (&text[..i], &text[i + 1..]);
        if width_of(font, a) <= room && width_of(font, b) <= room {
            best = Some((a, b));
        }
    }
    best
}

/// The longest prefix of `text` that fits in `room` pixels.
///
/// Whole characters, on a character boundary: the faces here are one byte a glyph, but
/// a label is a `&str` and slicing one anywhere else is a panic waiting for the first
/// menu entry somebody writes with an accent in it.
fn fit_text<'a, F: Face + ?Sized>(font: &F, text: &'a str, room: usize) -> &'a str {
    if width_of(font, text) <= room {
        return text;
    }
    let mut used = 0;
    let mut end = 0;
    for (i, c) in text.char_indices() {
        let mut w = 0;
        let mut buf = [0u8; 4];
        for &b in c.encode_utf8(&mut buf).as_bytes() {
            w += font.advance(b);
        }
        if used + w > room {
            break;
        }
        used += w;
        end = i + c.len_utf8();
    }
    &text[..end]
}

/// The selection mark: a frame inset from the cell's edge, with the corners left open.
///
/// A filled highlight would have to invert the icon underneath it, and a border that
/// touched its neighbours would read as a table rather than as one thing being chosen.
fn frame<C: Canvas + ?Sized>(canvas: &mut C, at: &Rect) {
    const INSET: usize = 3;
    /// How far the corner brackets run along each edge.
    const ARM: usize = 10;
    if at.w <= 2 * INSET + 2 * ARM || at.h <= 2 * INSET + 2 * ARM {
        return;
    }
    let (x0, y0) = (at.x + INSET, at.y + INSET);
    let (x1, y1) = (at.x + at.w - INSET - 1, at.y + at.h - INSET - 1);
    let mark: Level = INK;
    for (cx, cy, dx, dy) in [
        (x0, y0, 1isize, 1isize),
        (x1, y0, -1, 1),
        (x0, y1, 1, -1),
        (x1, y1, -1, -1),
    ] {
        for k in 0..ARM {
            let hx = cx.wrapping_add_signed(dx * k as isize);
            let vy = cy.wrapping_add_signed(dy * k as isize);
            canvas.put(hx, cy, mark);
            canvas.put(cx, vy, mark);
        }
    }
}

#[cfg(test)]
mod tests;
