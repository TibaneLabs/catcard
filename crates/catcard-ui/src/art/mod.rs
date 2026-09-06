//! Bitmap artwork.

pub mod cat;

/// A 1-bit image, row-major with the most significant bit leftmost.
///
/// Same layout as a [`Font`](crate::font::Font) glyph, so the two draw the same way —
/// artwork is just a glyph nobody types.
pub struct Bitmap {
    pub width: u16,
    pub height: u16,
    /// Bytes each row occupies; rows are left-aligned, so trailing bits are padding.
    pub bytes_per_row: u16,
    pub pixels: &'static [u8],
}

impl Bitmap {
    /// Whether pixel `(x, y)` is set. Out of range reads as clear.
    pub fn pixel(&self, x: usize, y: usize) -> bool {
        if x >= self.width as usize || y >= self.height as usize {
            return false;
        }
        let byte = self.pixels[y * self.bytes_per_row as usize + x / 8];
        byte & (0x80 >> (x % 8)) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four orthogonal neighbours of `(x, y)` that are inside a `w` by `h` grid.
    fn neighbours_of(x: usize, y: usize, w: usize, h: usize) -> Vec<(usize, usize)> {
        let mut v = Vec::with_capacity(4);
        if x > 0 {
            v.push((x - 1, y));
        }
        if y > 0 {
            v.push((x, y - 1));
        }
        if x + 1 < w {
            v.push((x + 1, y));
        }
        if y + 1 < h {
            v.push((x, y + 1));
        }
        v
    }

    #[test]
    fn the_cat_is_the_size_it_says() {
        let c = &cat::CAT;
        assert_eq!(c.pixels.len(), c.height as usize * c.bytes_per_row as usize);
        assert_eq!(c.bytes_per_row, c.width.div_ceil(8));
        // Fits the panel at all. How much room it leaves for the wordmark and the
        // version is the splash's constraint, and splash.rs tests it there.
        assert!(c.width <= 128 && c.height <= 64, "{}x{}", c.width, c.height);
    }

    #[test]
    fn the_cat_is_lit_on_a_dark_panel() {
        // Polarity. An inverted re-emit still passes every size and format check, and
        // the failure is not subtle: on an OLED it lights all 1824 pixels and shows a
        // black cat in a white box. A silhouette does not reach its own corners, so
        // clear corners are a cheap way to say which way round it is.
        let c = &cat::CAT;
        let (w, h) = (c.width as usize - 1, c.height as usize - 1);
        for (x, y) in [(0, 0), (w, 0), (0, h), (w, h)] {
            assert!(
                !c.pixel(x, y),
                "ink in the corner at ({x}, {y}) — inverted?"
            );
        }
        let lit = (0..c.height as usize)
            .flat_map(|y| (0..c.width as usize).map(move |x| (x, y)))
            .filter(|&(x, y)| c.pixel(x, y))
            .count();
        let total = c.width as usize * c.height as usize;
        assert!(lit * 4 < total * 3, "{lit} of {total} lit — inverted?");
    }

    #[test]
    fn the_face_is_cut_out_of_the_silhouette() {
        // The cat is a filled shape and its features are holes in it: two eyes, two ear
        // interiors, six whisker grooves, a nose and a mouth. Twelve enclosed regions.
        //
        // Both defects reported off a real screen were a missing feature, so this counts
        // them. It works on holes rather than on strokes because that is what they are —
        // a test looking for ink where the nose is would pass on a solid blob.
        let c = &cat::CAT;
        let (w, h) = (c.width as usize, c.height as usize);

        // Flood the background inward from the border; whatever dark is left is enclosed.
        let mut outside = vec![false; w * h];
        let mut stack: Vec<(usize, usize)> = (0..w)
            .flat_map(|x| [(x, 0), (x, h - 1)])
            .chain((0..h).flat_map(|y| [(0, y), (w - 1, y)]))
            .filter(|&(x, y)| !c.pixel(x, y))
            .collect();
        for &(x, y) in &stack {
            outside[y * w + x] = true;
        }
        let neighbours = |x: usize, y: usize| {
            let mut v = neighbours_of(x, y, w, h);
            v.retain(|&(nx, ny)| !c.pixel(nx, ny));
            v
        };
        while let Some((x, y)) = stack.pop() {
            for (nx, ny) in neighbours(x, y) {
                if !outside[ny * w + nx] {
                    outside[ny * w + nx] = true;
                    stack.push((nx, ny));
                }
            }
        }

        // (area, leftmost column, rightmost column) of each enclosed region.
        let mut seen = outside.clone();
        let mut holes: Vec<(usize, usize, usize)> = Vec::new();
        for y in 0..h {
            for x in 0..w {
                if c.pixel(x, y) || seen[y * w + x] {
                    continue;
                }
                seen[y * w + x] = true;
                let (mut area, mut lo, mut hi) = (0usize, x, x);
                let mut stack = vec![(x, y)];
                while let Some((a, b)) = stack.pop() {
                    area += 1;
                    lo = lo.min(a);
                    hi = hi.max(a);
                    for (nx, ny) in neighbours(a, b) {
                        if !seen[ny * w + nx] {
                            seen[ny * w + nx] = true;
                            stack.push((nx, ny));
                        }
                    }
                }
                holes.push((area, lo, hi));
            }
        }

        let areas = || {
            let mut v: Vec<usize> = holes.iter().map(|&(a, ..)| a).collect();
            v.sort_unstable_by(|a, b| b.cmp(a));
            v
        };
        assert_eq!(
            holes.len(),
            12,
            "expected twelve cut-outs, found {:?}",
            areas()
        );

        // The eyes are the largest pair, and equal to one another. If one fills in or
        // gets nicked, the art is still a cat-shaped blob and only the sizes say so.
        let sorted = areas();
        assert_eq!(sorted[0], sorted[1], "the eyes differ in size: {sorted:?}");
        assert!(
            sorted[1] > sorted[2],
            "the eyes are not the largest pair: {sorted:?}"
        );

        // Everything but the nose and the mouth comes in a left/right pair, so the two
        // sides carry the same number of cut-outs. That is what notices a whisker lost
        // from one cheek, which counting alone would let through if a stray hole opened
        // somewhere else. The two are not compared by area: the whiskers are drawn to
        // sit on the silhouette and its edge is not symmetric, so their areas differ by
        // a pixel or two.
        let mid = w / 2;
        let left = holes.iter().filter(|&&(_, _, hi)| hi < mid).count();
        let right = holes.iter().filter(|&&(_, lo, _)| lo > mid).count();
        let centred = holes.len() - left - right;
        assert_eq!(
            left, right,
            "{left} cut-outs on the left, {right} on the right"
        );
        assert_eq!(
            centred, 2,
            "expected the nose and the mouth astride the midline"
        );
    }

    #[test]
    fn padding_bits_are_clear() {
        let c = &cat::CAT;
        let pad = c.bytes_per_row as usize * 8 - c.width as usize;
        if pad == 0 {
            return;
        }
        let mask = (1u16 << pad) - 1;
        for y in 0..c.height as usize {
            let last = c.pixels[y * c.bytes_per_row as usize + c.bytes_per_row as usize - 1];
            assert_eq!(last as u16 & mask, 0, "ink in row {y}'s padding");
        }
    }
}
