//! BitCan: a BIP-39 word drawn as eleven lines.
//!
//! Each word's wordlist index (0..=2047) is eleven bits, and a BitCan glyph gives every bit
//! a line of its own in a box two squares tall. A set bit is drawn bold and a clear one
//! light, so a glyph always shows all eleven lines and a missing line is a damaged glyph
//! rather than a zero. The glyph carries no checksum of its own; the phrase's BIP-39
//! checksum covers it.
//!
//! Segment `i` is bit `i` of the index: the top edge is the least significant bit and the
//! bottom edge the most. Reading from the bottom up halves the candidate words with each
//! line, which is the order [`ENTRY_ORDER`] asks them in.
//!
//! Source: https://bitcan.world, format definition (segment table, 50x100 box, line
//! insets 8 and 13.6, bit order) [C]. Implemented from the definition; no code copied.

use crate::canvas::{Canvas, Level};

/// Lines in a glyph, one per bit of a wordlist index.
pub const SEGMENTS: usize = 11;

/// The order an owner reads a glyph in: from the bottom edge (bit 10) to the top (bit 0),
/// so each line halves the words it could be.
pub const ENTRY_ORDER: [usize; SEGMENTS] = [10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0];

/// The two drawings of the same bits. They differ only in the four diagonals.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Shape {
    /// Each square crossed by an X.
    Stack,
    /// The diagonals meet at the middle edge: a V in the top square, an inverted V below.
    Fold,
}

impl Shape {
    /// The other one.
    pub fn toggled(self) -> Self {
        match self {
            Shape::Stack => Shape::Fold,
            Shape::Fold => Shape::Stack,
        }
    }

    /// Its name, for a hint line.
    pub fn name(self) -> &'static str {
        match self {
            Shape::Stack => "Stack",
            Shape::Fold => "Fold",
        }
    }
}

/// Box size, in tenths of the format's units: 50 wide, 100 tall.
const W: i32 = 500;
const H: i32 = 1000;
/// Edge lines stop 8 units short of the corners; diagonals 13.6 units in from them.
const IN: i32 = 80;
const MID: i32 = 136;
/// Where Fold's diagonals meet: the middle of the box's width.
const HALF: i32 = W / 2;

/// One line, `(x0, y0, x1, y1)` in tenths of a unit.
type Seg = (i32, i32, i32, i32);

/// The eleven lines of a shape, indexed by bit.
pub fn segments(shape: Shape) -> [(i32, i32, i32, i32); SEGMENTS] {
    let s: [Seg; SEGMENTS] = [
        (IN, 0, W - IN, 0),               // 0: top edge
        (0, IN, 0, W - IN),               // 1: top square, left edge
        (MID, MID, W - MID, W - MID),     // 2: top square, `\`
        (W - MID, MID, MID, W - MID),     // 3: top square, `/`
        (W, IN, W, W - IN),               // 4: top square, right edge
        (IN, W, W - IN, W),               // 5: the shared middle edge
        (0, W + IN, 0, H - IN),           // 6: bottom square, left edge
        (MID, W + MID, W - MID, H - MID), // 7: bottom square, `\`
        (W - MID, W + MID, MID, H - MID), // 8: bottom square, `/`
        (W, W + IN, W, H - IN),           // 9: bottom square, right edge
        (IN, H, W - IN, H),               // 10: bottom edge
    ];
    match shape {
        Shape::Stack => s,
        Shape::Fold => {
            let mut f = s;
            f[2] = (MID, MID, HALF, W - MID);
            f[3] = (W - MID, MID, HALF, W - MID);
            f[7] = (HALF, W + MID, MID, H - MID);
            f[8] = (HALF, W + MID, W - MID, H - MID);
            f
        }
    }
}

/// Whether segment `seg` of `index`'s glyph is bold.
pub fn bold(index: u16, seg: usize) -> bool {
    seg < SEGMENTS && (index >> seg) & 1 == 1
}

/// What one line of a glyph shows.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Mark {
    /// A set bit: bold.
    On,
    /// A clear bit: light.
    Off,
    /// Not known yet, while a glyph is being entered.
    Unknown,
    /// The line being asked about now.
    Here,
}

/// The marks of a whole word.
pub fn marks_of(index: u16) -> [Mark; SEGMENTS] {
    core::array::from_fn(|i| if bold(index, i) { Mark::On } else { Mark::Off })
}

/// How a line is drawn: its level, its thickness in pixels, and a dash pattern of `(on,
/// off)` pixels along it, `off == 0` for a solid line.
#[derive(Copy, Clone, Debug)]
pub struct Stroke {
    pub level: Level,
    pub width: usize,
    pub dash: (usize, usize),
}

/// One stroke per [`Mark`]. `unknown` is `None` to leave unknown lines undrawn.
#[derive(Copy, Clone, Debug)]
pub struct Pens {
    pub on: Stroke,
    pub off: Stroke,
    pub unknown: Option<Stroke>,
    pub here: Stroke,
}

impl Pens {
    /// For a panel with only ink and paper: light lines are dotted, the line being asked
    /// about is a thick dash.
    pub const MONO: Pens = Pens {
        on: Stroke {
            level: 15,
            width: 2,
            dash: (1, 0),
        },
        off: Stroke {
            level: 15,
            width: 1,
            dash: (1, 2),
        },
        unknown: None,
        here: Stroke {
            level: 15,
            width: 3,
            dash: (2, 2),
        },
    };

    /// For a grey panel: light lines are a dim grey, unknown ones fainter still.
    pub const GRAY: Pens = Pens {
        on: Stroke {
            level: 15,
            width: 3,
            dash: (1, 0),
        },
        off: Stroke {
            level: 6,
            width: 1,
            dash: (1, 0),
        },
        unknown: Some(Stroke {
            level: 2,
            width: 1,
            dash: (1, 0),
        }),
        here: Stroke {
            level: 12,
            width: 3,
            dash: (4, 3),
        },
    };

    fn of(&self, m: Mark) -> Option<Stroke> {
        match m {
            Mark::On => Some(self.on),
            Mark::Off => Some(self.off),
            Mark::Unknown => self.unknown,
            Mark::Here => Some(self.here),
        }
    }

    /// The widest stroke, which is how far a line can reach past the box's edge.
    fn reach(&self) -> usize {
        let u = self.unknown.map_or(0, |s| s.width);
        self.on
            .width
            .max(self.off.width)
            .max(self.here.width)
            .max(u)
    }
}

/// Draw a glyph so that it fills `h` pixels of height, `h / 2` of width, at `(x, y)`.
///
/// The lines are drawn inside that box: a thick stroke is pulled in rather than spilling
/// onto a neighbour.
pub fn draw<C: Canvas + ?Sized>(
    c: &mut C,
    x: usize,
    y: usize,
    h: usize,
    shape: Shape,
    marks: &[Mark; SEGMENTS],
    pens: &Pens,
) {
    let pad = pens.reach().div_ceil(2) as i32;
    let iw = (h as i32 / 2 - 1 - 2 * pad).max(1);
    let ih = (h as i32 - 1 - 2 * pad).max(1);
    let px = |u: i32| x as i32 + pad + u * iw / W;
    let py = |u: i32| y as i32 + pad + u * ih / H;
    // Light lines first, so a bold one crossing them is never broken by a dot.
    for pass in [Mark::Unknown, Mark::Off, Mark::Here, Mark::On] {
        for (i, &(x0, y0, x1, y1)) in segments(shape).iter().enumerate() {
            if marks[i] != pass {
                continue;
            }
            if let Some(s) = pens.of(pass) {
                line(c, px(x0), py(y0), px(x1), py(y1), &s);
            }
        }
    }
}

/// A straight line from `(x0, y0)` to `(x1, y1)` inclusive, in `s`'s stroke.
///
/// Bresenham's walk, with a square brush `s.width` across at each step and the dash
/// counted in steps along the line.
pub fn line<C: Canvas + ?Sized>(c: &mut C, x0: i32, y0: i32, x1: i32, y1: i32, s: &Stroke) {
    let (dx, dy) = ((x1 - x0).abs(), -(y1 - y0).abs());
    let (sx, sy) = (if x0 < x1 { 1 } else { -1 }, if y0 < y1 { 1 } else { -1 });
    let (mut x, mut y, mut err) = (x0, y0, dx + dy);
    let period = (s.dash.0 + s.dash.1).max(1);
    let w = s.width.max(1) as i32;
    let back = (w - 1) / 2;
    let mut step = 0usize;
    loop {
        if step % period < s.dash.0.max(1) {
            for by in 0..w {
                for bx in 0..w {
                    let (px, py) = (x - back + bx, y - back + by);
                    if px >= 0 && py >= 0 {
                        c.put(px as usize, py as usize, s.level);
                    }
                }
            }
        }
        if x == x1 && y == y1 {
            return;
        }
        step += 1;
        let e2 = 2 * err;
        if e2 >= dy {
            err += dy;
            x += sx;
        }
        if e2 <= dx {
            err += dx;
            y += sy;
        }
    }
}

/// The index range a glyph can still be once the lines in [`ENTRY_ORDER`] up to `known`
/// are decided, given those decided bits in `index` (the rest ignored).
pub fn range(index: u16, known: usize) -> (u16, u16) {
    let k = known.min(SEGMENTS);
    let low_bits = SEGMENTS - k;
    let lo = (index >> low_bits) << low_bits;
    (lo, lo | ((1u16 << low_bits) - 1))
}

/// A page of glyphs: `cols` across, `rows` down, each labelled with its word number.
#[derive(Copy, Clone, Debug)]
pub struct Page {
    pub cols: usize,
    pub rows: usize,
    /// Height of each glyph, in pixels.
    pub glyph_h: usize,
}

impl Page {
    /// Glyphs per page.
    pub const fn per_page(&self) -> usize {
        self.cols * self.rows
    }
}

/// Draw `indices` as a page of labelled glyphs, the first numbered `first`.
pub fn draw_page<C: Canvas + ?Sized, F: crate::face::Face + ?Sized>(
    c: &mut C,
    font: &F,
    page: &Page,
    first: usize,
    indices: &[u16],
    shape: Shape,
    pens: &Pens,
) {
    let cell_w = c.width() / page.cols.max(1);
    let label_h = font.line_height() + 1;
    let cell_h = label_h + page.glyph_h + 2;
    for (n, &idx) in indices.iter().take(page.per_page()).enumerate() {
        let (col, row) = (n % page.cols, n / page.cols);
        let cx = col * cell_w;
        let cy = row * cell_h;
        let mut num = [0u8; 3];
        let label = number(first + n, &mut num);
        let lw = crate::text::width_of(font, label);
        crate::text::draw_text(c, font, cx + cell_w.saturating_sub(lw) / 2, cy, label);
        let gx = cx + cell_w.saturating_sub(page.glyph_h / 2) / 2;
        draw(
            c,
            gx,
            cy + label_h,
            page.glyph_h,
            shape,
            &marks_of(idx),
            pens,
        );
    }
}

/// `n` (below 1000) in decimal, without formatting machinery.
fn number(n: usize, buf: &mut [u8; 3]) -> &str {
    let n = n.min(999);
    let mut i = 3;
    let mut v = n;
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 || i == 0 {
            break;
        }
    }
    core::str::from_utf8(&buf[i..]).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canvas::{Gray320x240, INK, PAPER};

    #[test]
    fn bit_i_is_segment_i() {
        // "abandon" is all light; the last word of the list is all bold.
        assert!(marks_of(0).iter().all(|&m| m == Mark::Off));
        assert!(marks_of(2047).iter().all(|&m| m == Mark::On));
        // One bit at a time lights exactly its own line.
        for i in 0..SEGMENTS {
            let m = marks_of(1 << i);
            for (j, &mj) in m.iter().enumerate() {
                assert_eq!(mj == Mark::On, i == j, "bit {i}, segment {j}");
            }
        }
        // The top edge is the least significant bit, the bottom edge the most.
        let s = segments(Shape::Stack);
        assert_eq!(s[0].1, 0);
        assert_eq!(s[0].3, 0);
        assert_eq!(s[10].1, H);
        assert_eq!(s[10].3, H);
    }

    #[test]
    fn the_shapes_differ_only_in_the_diagonals() {
        let (a, b) = (segments(Shape::Stack), segments(Shape::Fold));
        for i in 0..SEGMENTS {
            assert_eq!(a[i] == b[i], ![2, 3, 7, 8].contains(&i), "segment {i}");
        }
        // Fold's diagonals meet in the middle of the shared edge's width, 13.6 units off it.
        assert_eq!((b[2].2, b[2].3), (250, 364));
        assert_eq!((b[3].2, b[3].3), (250, 364));
        assert_eq!((b[7].0, b[7].1), (250, 636));
        assert_eq!((b[8].0, b[8].1), (250, 636));
    }

    #[test]
    fn reading_from_the_bottom_halves_the_range() {
        let idx = 0b101_1001_0110u16;
        let mut width = 2048u32;
        for k in 0..=SEGMENTS {
            let (lo, hi) = range(idx, k);
            assert!(lo <= idx && idx <= hi);
            assert_eq!(u32::from(hi - lo) + 1, width);
            width /= 2;
        }
        assert_eq!(range(idx, SEGMENTS), (idx, idx));
        assert_eq!(ENTRY_ORDER[0], 10);
    }

    #[test]
    fn a_glyph_stays_in_its_box_and_shows_every_line() {
        for shape in [Shape::Stack, Shape::Fold] {
            for idx in [0u16, 2047, 0b100_0000_0001] {
                let mut c = Gray320x240::new();
                let (x, y, h) = (40, 30, 80);
                draw(&mut c, x, y, h, shape, &marks_of(idx), &Pens::GRAY);
                let mut inked = 0;
                for py in 0..240 {
                    for px in 0..320 {
                        let inside = (x..x + h / 2).contains(&px) && (y..y + h).contains(&py);
                        if c.get(px, py) != PAPER {
                            assert!(inside, "{shape:?} {idx}: ink at {px},{py}");
                            inked += 1;
                        }
                    }
                }
                assert!(inked > 0);
                // Bold lines are full ink; light ones never are on a grey panel.
                let full = (0..240)
                    .flat_map(|py| (0..320).map(move |px| (px, py)))
                    .any(|(px, py)| c.get(px, py) == INK);
                assert_eq!(full, idx != 0, "{shape:?} {idx}");
            }
        }
    }

    #[test]
    fn unknown_lines_can_be_left_out() {
        let mut c = Gray320x240::new();
        let marks = [Mark::Unknown; SEGMENTS];
        draw(&mut c, 0, 0, 80, Shape::Stack, &marks, &Pens::MONO);
        assert!((0..80).all(|y| (0..40).all(|x| c.get(x, y) == PAPER)));
    }

    #[test]
    fn numbers_are_decimal() {
        let mut b = [0u8; 3];
        assert_eq!(number(0, &mut b), "0");
        assert_eq!(number(7, &mut b), "7");
        assert_eq!(number(24, &mut b), "24");
        assert_eq!(number(123, &mut b), "123");
    }
}
