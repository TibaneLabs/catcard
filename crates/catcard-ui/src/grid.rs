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

/// Draw the grid, with `selected` marked.
///
/// `label` is the face the captions use. The caller has already cleared, or not: this
/// paints its own background so a redraw does not need one.
pub fn render<C: Canvas + ?Sized, F: Face + ?Sized>(
    canvas: &mut C,
    font: &F,
    cells: &[Cell<'_>],
    selected: usize,
) {
    let (w, h) = (canvas.width(), canvas.height());
    canvas.fill_rect(0, 0, w, h, PAPER);
    for (i, cell) in cells.iter().enumerate().take(CELLS) {
        draw_cell(canvas, font, &cell_rect(i, w, h), cell, i == selected);
    }
}

fn draw_cell<C: Canvas + ?Sized, F: Face + ?Sized>(
    canvas: &mut C,
    font: &F,
    at: &Rect,
    cell: &Cell<'_>,
    selected: bool,
) {
    let line = font.line_height();
    // Icon and label as one block, centred in what the cell has. Where the cell is too
    // short for both the label wins: a nameless picture is a guess, a named empty box is
    // a menu entry whose art has not arrived.
    let block = ICON + LABEL_GAP + line;
    let top = at.y + at.h.saturating_sub(block) / 2;

    if let Some(art) = cell.icon {
        let ix = at.x + at.w.saturating_sub(art.width as usize) / 2;
        crate::art::indexed::draw_indexed(canvas, art, ix, top);
    }

    let label_y = top + ICON + LABEL_GAP;
    if label_y + line <= at.y + at.h {
        let tw = width_of(font, cell.label);
        let tx = at.x + at.w.saturating_sub(tw) / 2;
        draw_text_in(canvas, font, tx, label_y, cell.label, INK);
    }

    if selected {
        frame(canvas, at);
    }
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
