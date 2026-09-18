//! The grid covers the canvas exactly, and stays inside the cell it was given.

use super::*;
use crate::canvas::Gray320x240;
// The face the Q1's grid labels actually use, so the fit test is about the real thing.
use crate::font::peep10x20::FONT;

/// The Q1's main menu area: the panel less the status bar.
const W: usize = 320;
const H: usize = 224;

/// Every pixel belongs to exactly one cell: no overlap, no gutter nobody chose.
///
/// Three columns do not divide 320, so the remainder has to land somewhere deliberate.
/// A gap would show as a seam down a screen whose whole job is to look like six tiles.
#[test]
fn the_cells_tile_the_canvas_exactly() {
    let mut covered = vec![0u8; W * H];
    for i in 0..CELLS {
        let r = cell_rect(i, W, H);
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
    render(&mut plain, &FONT, &cells, usize::MAX);
    let mut picked = Gray320x240::new();
    render(&mut picked, &FONT, &cells, 4);

    for i in 0..CELLS {
        let r = cell_rect(i, W, H);
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
    render(&mut c, &FONT, &cells, 0);
    for i in 0..CELLS {
        let r = cell_rect(i, W, H);
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
    let mut c = Gray320x240::new();
    {
        let mut view = crate::canvas::Inset::new(&mut c, 240 - H);
        render(&mut view, &FONT, &cells, 0);
    }
    for y in 0..240 - H {
        for x in 0..320 {
            assert_eq!(c.get(x, y), PAPER, "the grid drew at ({x}, {y})");
        }
    }
}
