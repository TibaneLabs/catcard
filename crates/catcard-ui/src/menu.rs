//! Scrolling a list that is longer than the panel.
//!
//! Lives here rather than beside the menu screens because it is the only part of a menu
//! that is arithmetic, and arithmetic is the part that can be wrong without looking
//! wrong. The first version of the debug menu drew a fixed number of rows and dropped
//! the rest, which hid `Enter DFU` — the item that exists to rescue a device nothing
//! else can reach. Nobody noticed, because a menu missing its last row looks exactly
//! like a menu that has no last row.

/// Where the cursor is, and which slice of the list is on screen.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Scroll {
    /// Index of the selected item.
    pub cursor: usize,
    /// Index of the first item drawn.
    pub top: usize,
}

impl Scroll {
    /// Start at the top of the list.
    pub const fn new() -> Self {
        Self { cursor: 0, top: 0 }
    }

    /// Move one step, bringing the window along if the cursor has left it.
    ///
    /// Clamps at both ends rather than wrapping. A list that wraps makes "am I at the
    /// bottom?" unanswerable without counting, and these menus are read by someone who
    /// is already unsure whether the keypad is reporting what they pressed.
    ///
    /// `rows` is how many items fit on the panel; a `rows` of zero is treated as one,
    /// so a caller that miscomputes its layout still gets a usable cursor rather than a
    /// division by zero or a window that can never contain anything.
    pub fn step(self, len: usize, rows: usize, down: bool) -> Self {
        if len == 0 {
            return Self::new();
        }
        let rows = rows.max(1);
        let cursor = if down {
            (self.cursor + 1).min(len - 1)
        } else {
            self.cursor.saturating_sub(1)
        };
        // Follow by the smallest amount that brings the cursor back into view, so a long
        // list moves a row at a time instead of jumping a page.
        let top = if cursor < self.top {
            cursor
        } else if cursor >= self.top + rows {
            cursor + 1 - rows
        } else {
            self.top
        };
        Self { cursor, top }
    }

    /// The half-open range of items to draw, given how many rows fit.
    pub fn window(self, len: usize, rows: usize) -> (usize, usize) {
        let rows = rows.max(1);
        (self.top, (self.top + rows).min(len))
    }
}

impl Default for Scroll {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Walking to the end must reach the last item, whatever the window size.
    ///
    /// This is the property the original bug violated: the list had six items, five
    /// rows, and the sixth was unreachable.
    #[test]
    fn every_item_is_reachable_by_pressing_down() {
        for len in 1..20usize {
            for rows in 1..8usize {
                let mut s = Scroll::new();
                let mut seen = 0;
                for _ in 0..len * 2 {
                    let (from, to) = s.window(len, rows);
                    assert!(
                        (from..to).contains(&s.cursor),
                        "cursor {} outside the drawn window {from}..{to}",
                        s.cursor
                    );
                    seen = seen.max(s.cursor);
                    s = s.step(len, rows, true);
                }
                assert_eq!(
                    seen,
                    len - 1,
                    "len {len} rows {rows}: never reached the end"
                );
            }
        }
    }

    #[test]
    fn the_cursor_stays_inside_the_list_at_both_ends() {
        let s = Scroll::new().step(3, 2, false);
        assert_eq!(s.cursor, 0, "up from the top must not underflow");

        let mut s = Scroll::new();
        for _ in 0..10 {
            s = s.step(3, 2, true);
        }
        assert_eq!(s.cursor, 2, "down past the end must stop on the last item");
        assert_eq!(s.top, 1, "and the window must show it");
    }

    /// A list that fits never scrolls, so no indicator is ever drawn for it.
    #[test]
    fn a_list_that_fits_keeps_its_window_at_zero() {
        let mut s = Scroll::new();
        for _ in 0..5 {
            s = s.step(3, 5, true);
        }
        assert_eq!(s.top, 0);
        assert_eq!(s.window(3, 5), (0, 3));
    }

    /// One row at a time, not one page.
    #[test]
    fn scrolling_follows_the_cursor_by_a_single_row() {
        let mut s = Scroll::new();
        for _ in 0..3 {
            s = s.step(10, 3, true);
        }
        assert_eq!(s.cursor, 3);
        assert_eq!(s.top, 1, "should have moved by one row, not jumped a page");
    }

    /// Coming back up scrolls the other way, and lands where it started.
    #[test]
    fn scrolling_back_up_restores_the_window() {
        let mut s = Scroll::new();
        for _ in 0..6 {
            s = s.step(10, 3, true);
        }
        for _ in 0..6 {
            s = s.step(10, 3, false);
        }
        assert_eq!(s, Scroll::new());
    }

    /// Degenerate inputs must not panic: an empty list, and a panel with no rows.
    #[test]
    fn empty_lists_and_zero_rows_do_not_panic() {
        assert_eq!(Scroll::new().step(0, 4, true), Scroll::new());
        let s = Scroll::new().step(5, 0, true);
        assert_eq!(s.cursor, 1);
        assert_eq!(s.window(5, 0), (1, 2));
    }
}
