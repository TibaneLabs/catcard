//! The grid covers the canvas exactly, and stays inside the cell it was given.

use super::*;
use crate::canvas::Gray320x240;
// The face the Q1's grid labels actually use, so the fit test is about the real thing.
use crate::font::peep7x14;
use crate::font::peep10x20::FONT;

/// The Q1's main menu area: the panel less the status bar.
const W: usize = 320;
/// The canvas's own height. It used to be 224 -- the panel's content area under the
/// status bar -- while the canvas under test was 240, so every rect this file computed
/// was eight pixels out from the one the renderer drew into. Nothing caught it while the
/// cells being checked happened to sit where the error did not show.
const H: usize = 240;

/// Every pixel belongs to exactly one cell: no overlap, no gutter nobody chose.
///
/// Three columns do not divide 320, so the remainder has to land somewhere deliberate.
/// A gap would show as a seam down a screen whose whole job is to look like six tiles.
#[test]
fn the_cells_tile_the_canvas_exactly() {
    let mut covered = vec![0u8; W * H];
    for i in 0..CELLS {
        let r = cell_rect(slot(i), W, H);
        for y in r.y..r.y + r.h {
            for x in r.x..r.x + r.w {
                covered[y * W + x] += 1;
            }
        }
    }
    assert!(
        covered.iter().all(|&n| n == 1),
        "cells overlap or leave gaps: {} pixels not covered once",
        covered.iter().filter(|&&n| n != 1).count()
    );
}

/// The two grid rows are separate scanline bands, which is what lets them have their own
/// palettes. If a row's cells ever spanned the same rows as the other's, they could not.
#[test]
fn the_rows_occupy_separate_scanlines() {
    let top: Vec<Rect> = (0..COLS).map(|i| cell_rect(i, W, H)).collect();
    let bottom: Vec<Rect> = (COLS..CELLS).map(|i| cell_rect(i, W, H)).collect();
    let top_end = top.iter().map(|r| r.y + r.h).max().unwrap();
    let bottom_start = bottom.iter().map(|r| r.y).min().unwrap();
    assert!(
        top_end <= bottom_start,
        "the grid rows share scanlines, so they cannot have separate palettes"
    );
    // And every cell in a row starts on the same line, or the band is ragged.
    assert!(top.iter().all(|r| r.y == top[0].y));
    assert!(bottom.iter().all(|r| r.y == bottom[0].y));
}

/// A cell is big enough for the icon the art is authored at, plus its label.
///
/// This is the number the art depends on. If the layout ever stopped fitting it, the
/// choice would be scaling the art -- which is how pixel art stops being pixel art --
/// so it fails here instead.
#[test]
fn a_cell_fits_the_icon_and_a_label() {
    let r = cell_rect(0, W, H);
    assert!(r.w >= ICON, "cell {} wide cannot hold a {ICON}px icon", r.w);
    assert!(
        r.h >= ICON + LABEL_GAP + FONT.line_height(),
        "cell {} tall cannot hold the icon and a label",
        r.h
    );
    // And the longest label we ship fits across it.
    for label in ["Addresses", "Settings", "Logout", "Notes", "Utils", "Sign"] {
        assert!(
            width_of(&FONT, label) <= r.w,
            "{label:?} is wider than a {}px cell",
            r.w
        );
    }
}

fn ink(c: &Gray320x240, r: &Rect) -> u32 {
    let mut n = 0;
    for y in r.y..r.y + r.h {
        for x in r.x..r.x + r.w {
            n += c.get(x, y) as u32;
        }
    }
    n
}

/// Only the selected cell is marked, and the mark stays inside it.
#[test]
fn the_selection_marks_one_cell_and_does_not_leak() {
    let cells = [Cell {
        label: "Sign",
        icon: None,
    }; CELLS];
    let mut plain = Gray320x240::new();
    render(&mut plain, &FONT, &peep7x14::FONT, &cells, usize::MAX);
    let mut picked = Gray320x240::new();
    render(&mut picked, &FONT, &peep7x14::FONT, &cells, 4);

    for i in 0..CELLS {
        let r = cell_rect(slot(i), W, H);
        let before = ink(&plain, &r);
        let after = ink(&picked, &r);
        if i == 4 {
            assert!(after > before, "the selected cell is not marked");
        } else {
            assert_eq!(after, before, "cell {i} changed when cell 4 was selected");
        }
    }
}

/// Labels are drawn for every cell, art or no art.
#[test]
fn a_cell_with_no_icon_still_says_what_it_is() {
    let cells = [
        Cell {
            label: "Sign",
            icon: None,
        },
        Cell {
            label: "Addresses",
            icon: None,
        },
        Cell {
            label: "Notes",
            icon: None,
        },
        Cell {
            label: "Utils",
            icon: None,
        },
        Cell {
            label: "Settings",
            icon: None,
        },
        Cell {
            label: "Logout",
            icon: None,
        },
    ];
    let mut c = Gray320x240::new();
    render(&mut c, &FONT, &peep7x14::FONT, &cells, 0);
    for i in 0..CELLS {
        let r = cell_rect(slot(i), W, H);
        assert!(ink(&c, &r) > 0, "cell {i} drew nothing at all");
    }
}

/// Nothing is drawn outside the area the grid was given.
#[test]
fn the_grid_stays_within_the_canvas_it_was_given() {
    // A canvas taller than the grid area, so an overrun has somewhere to show.
    let cells = [Cell {
        label: "Addresses",
        icon: None,
    }; CELLS];
    /// The rows the status bar keeps, which the grid is drawn below.
    const BAR: usize = 16;
    let mut c = Gray320x240::new();
    {
        let mut view = crate::canvas::Inset::new(&mut c, BAR);
        render(&mut view, &FONT, &peep7x14::FONT, &cells, 0);
    }
    for y in 0..BAR {
        for x in 0..320 {
            assert_eq!(c.get(x, y), PAPER, "the grid drew at ({x}, {y})");
        }
    }
}

/// A label too wide for its cell is set over two lines rather than cut.
///
/// The menus the grid now draws were written for a list, where "Browse SD card" had a
/// row to itself. In three 106-pixel columns it does not fit on one line in the title
/// face, and cutting it gives "Browse SD" -- which is a different card.
#[test]
fn a_long_label_wraps_instead_of_losing_its_end() {
    let cells = [Cell {
        label: "Browse SD card",
        icon: None,
    }];
    let mut c = Gray320x240::new();
    render(&mut c, &FONT, &peep7x14::FONT, &cells, usize::MAX);

    // Ink appears on two separate bands of rows: two lines, not one.
    let inked_rows: Vec<usize> = (0..H)
        .filter(|&y| (0..W).any(|x| crate::canvas::Canvas::get(&c, x, y) != PAPER))
        .collect();
    let bands = inked_rows.windows(2).filter(|w| w[1] != w[0] + 1).count() + 1;
    assert_eq!(bands, 2, "the label did not wrap onto a second line");
}

/// Whatever the caption, it stays inside the cell it belongs to.
#[test]
fn a_label_never_reaches_its_neighbours_cell() {
    // One impossible caption in the middle cell, nothing either side of it.
    let cells = [
        Cell {
            label: "",
            icon: None,
        },
        Cell {
            label: "Supercalifragilistic",
            icon: None,
        },
        Cell {
            label: "",
            icon: None,
        },
    ];
    let mut c = Gray320x240::new();
    render(&mut c, &FONT, &peep7x14::FONT, &cells, usize::MAX);
    let middle = cell_rect(slot(1), W, H);
    for y in 0..H {
        for x in 0..W {
            if crate::canvas::Canvas::get(&c, x, y) != PAPER {
                assert!(
                    x >= middle.x && x < middle.x + middle.w,
                    "a label reached ({x}, {y}), outside its own cell"
                );
            }
        }
    }
}

/// The hint is on the sides that have a page, and nowhere else.
#[test]
fn the_edge_hints_point_only_where_there_is_more() {
    let cells: Vec<Cell> = (0..CELLS)
        .map(|_| Cell {
            label: "x",
            icon: None,
        })
        .collect();
    let ink_in = |c: &Gray320x240, x0: usize, x1: usize| {
        (0..H)
            .flat_map(|y| (x0..x1).map(move |x| (x, y)))
            .filter(|&(x, y)| crate::canvas::Canvas::get(c, x, y) != PAPER)
            .count()
    };

    // No cursor anywhere (`usize::MAX`): the selection frame is inset three pixels and
    // would put its own ink in the columns this is measuring.
    // A strip of nine columns -- three windows' worth -- with the window in the middle.
    const LONG: usize = CELLS * 3;
    let mut mid = Gray320x240::new();
    render_page(
        &mut mid,
        &FONT,
        &peep7x14::FONT,
        &cells,
        usize::MAX,
        3,
        LONG,
    );
    assert!(ink_in(&mid, 0, HINT_W + CHEVRON) > 0, "no hint to the left");
    assert!(
        ink_in(&mid, W - HINT_W - CHEVRON, W) > 0,
        "no hint to the right"
    );

    // The first page of three: nothing on the left.
    let mut first = Gray320x240::new();
    render_page(
        &mut first,
        &FONT,
        &peep7x14::FONT,
        &cells,
        usize::MAX,
        0,
        LONG,
    );
    assert_eq!(
        ink_in(&first, 0, HINT_W),
        0,
        "the first page points back to a page that is not there"
    );

    // A strip that fits the window: neither hint, and no dots.
    let mut only = Gray320x240::new();
    render_page(
        &mut only,
        &FONT,
        &peep7x14::FONT,
        &cells,
        usize::MAX,
        0,
        CELLS,
    );
    assert_eq!(ink_in(&only, 0, HINT_W), 0);
    assert_eq!(ink_in(&only, W - HINT_W, W), 0);
    assert_eq!(
        ink_in(&only, 0, W) - ink_in(&mid, 0, W).min(ink_in(&only, 0, W)),
        0,
        "a single page drew more than the cells"
    );
}

/// Sideways moves the cursor a column; up and down stay in it.
#[test]
fn the_cursor_walks_the_strip_the_way_the_eye_does() {
    // Thirteen cells: seven columns of two, the last of them half empty.
    let len = 13;
    // Right is the next column, at the same row, wherever the window happens to be.
    assert_eq!(step(0, len, Dir::Right), ROWS);
    assert_eq!(step(1, len, Dir::Right), ROWS + 1);
    // ...and back again, to the row it came from.
    assert_eq!(step(ROWS, len, Dir::Left), 0, "left did not come back");
    assert_eq!(step(0, len, Dir::Left), 0, "the first cell moved left");

    // Down and up stay in the column they are in.
    assert_eq!(step(0, len, Dir::Down), 1);
    assert_eq!(step(1, len, Dir::Up), 0);
    assert_eq!(step(1, len, Dir::Down), 1, "down left its column");
    assert_eq!(step(0, len, Dir::Up), 0);

    // Every landing is a cell that exists.
    for from in 0..len {
        for dir in [Dir::Up, Dir::Down, Dir::Left, Dir::Right, Dir::Home] {
            let to = step(from, len, dir);
            assert!(to < len, "{dir:?} from {from} landed on {to} of {len}");
        }
    }
    assert_eq!(step(12, len, Dir::Right), 12, "the last cell moved right");
    assert_eq!(step(7, len, Dir::Home), 0);

    // An empty menu has nowhere to go and must not panic getting there.
    assert_eq!(step(0, 0, Dir::Right), 0);
}

/// The strip is columns, and a cell's place in it never moves.
#[test]
fn the_strip_is_as_long_as_the_menu() {
    assert_eq!(columns(0), 1);
    assert_eq!(columns(1), 1);
    assert_eq!(columns(ROWS), 1);
    assert_eq!(columns(ROWS + 1), 2);
    assert_eq!(pages(CELLS), 1);
    assert_eq!(pages(CELLS + 1), 2);
    // Column-major: the first two cells fill one column, the next two the next.
    assert_eq!(place(0), (0, 0));
    assert_eq!(place(1), (0, 1));
    assert_eq!(place(2), (1, 0));
    // And a cell's place does not depend on how many there are, which is what lets the
    // window move a column at a time.
    assert_eq!(place(7), (3, 1));
}

/// The window follows the cursor by as little as it can.
///
/// The rule the list follows going down, sideways: the cursor travels inside the window
/// until it reaches an edge, and only then does the window move -- by one column, not by
/// a page.
#[test]
fn the_window_moves_only_as_far_as_it_must() {
    // Ten cells: five columns, of which three are on screen.
    let len = 10;
    assert_eq!(columns(len), 5);

    // Inside the window, nothing moves.
    let mut off = 0;
    for cursor in 0..COLS * ROWS {
        off = window(cursor, len, off);
        assert_eq!(off, 0, "cursor {cursor} moved a window it was inside");
    }
    // The fourth column is one past the edge, so the window follows by one.
    off = window(COLS * ROWS, len, off);
    assert_eq!(off, 1);
    // And the fifth by one more.
    off = window((COLS + 1) * ROWS, len, off);
    assert_eq!(off, 2);
    // Coming back leaves it where it is until the cursor passes the left edge.
    off = window((COLS + 1) * ROWS - 1, len, off);
    assert_eq!(off, 2, "the window moved for a cursor still inside it");
    off = window(2, len, off);
    assert_eq!(off, 1, "the window did not follow the cursor left");
    off = window(0, len, off);
    assert_eq!(off, 0);

    // A menu that fits needs no window at all, whatever it is told.
    assert_eq!(window(0, 4, 3), 0);
}
