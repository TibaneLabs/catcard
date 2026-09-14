//! The Q1's 10x6 QWERTY matrix: scanning, debounce, and mapping onto [`Key`].
//!
//! The same electrical model and the same rules as the numpad in [`crate::keypad`]: rows
//! are open-drain outputs driven low one at a time, columns are pulled-up inputs, and the
//! row and column order are shuffled from the **UI** DRBG on every scan -- never from the
//! seed pool, for the reasons [`crate::keypad`] gives.
//! Source: gpio-peripherals.md §Q/Q1 Keyboard [C]
//!
//! # Only the keys the current screens understand produce events
//!
//! Every screen is still written against the numpad's [`Key`] set, so until there is a
//! native Q1 UI the keyboard is mapped onto it: the number row types digits, ENTER
//! confirms, CANCEL and DELETE cancel (which is backspace in a PIN field), and the four
//! arrows take the numpad's arrow digits -- `5` up, `8` down, `7` left, `9` right -- so the
//! menus move the way the caps say. Every other key is scanned and debounced like the rest
//! but produces no event.
//!
//! The price is that an arrow typed into a PIN field enters its digit, exactly as that
//! digit's key on the numpad would. That is a property of reusing the numpad screens, not
//! of the keyboard, and it goes away with a native UI.

use catcard_entropy::HmacDrbg;

pub use crate::keypad::DEBOUNCE_SAMPLES;
use crate::keypad::{Event, Key};

/// Rows in the matrix. Source: gpio-peripherals.md §Q/Q1 Keyboard [C]
pub const ROWS: usize = 6;
/// Columns in the matrix.
pub const COLS: usize = 10;
/// Matrix positions, `kn = row * COLS + col`.
pub const KEYS: usize = ROWS * COLS;

/// What each matrix position means to the current screens, indexed `row * COLS + col`.
///
/// Positions from the reference's decode table [C]: `kn3..6` are the arrows (left, up,
/// down, right), `kn7` CANCEL, `kn8` ENTER, `kn10..19` the number row `1234567890`, and
/// `kn54` DELETE. `kn9` and `kn55..59` are unused; letters, symbols and the modifiers
/// have no meaning to a numpad screen and map to nothing.
/// Source: gpio-peripherals.md §Q/Q1 "Key decode" [C]
pub const LAYOUT: [Option<Key>; KEYS] = {
    let mut l = [None; KEYS];
    l[3] = Some(Key::Digit(7)); // left
    l[4] = Some(Key::Digit(5)); // up
    l[5] = Some(Key::Digit(8)); // down
    l[6] = Some(Key::Digit(9)); // right
    l[7] = Some(Key::Cancel); // CANCEL
    l[8] = Some(Key::Confirm); // ENTER
    let mut i = 0;
    while i < 9 {
        l[10 + i] = Some(Key::Digit(i as u8 + 1));
        i += 1;
    }
    l[19] = Some(Key::Digit(0));
    l[54] = Some(Key::Cancel); // DELETE
    l
};

/// The electrical half of the keyboard, supplied by the firmware.
pub trait Matrix {
    /// Drive exactly one row low and leave the others released.
    fn select_row(&mut self, row: usize);

    /// Read the columns in the given order. Bit `n` set means column `n` reads **low**,
    /// i.e. a key on the selected row is pressed.
    ///
    /// `order` is a permutation of the column indices; an implementation must sample in
    /// that order and not fold it back to a fixed one.
    fn read_columns(&mut self, order: &[u8; COLS]) -> u16;

    /// Release every row, leaving the matrix idle.
    fn release_rows(&mut self);

    /// Settling delay between driving a row and sampling the columns.
    fn settle(&mut self);
}

/// Debounced keyboard scanner. Named `Keypad` so the firmware can use either scanner
/// behind one name.
pub struct Keypad {
    counters: [u8; KEYS],
    down: [bool; KEYS],
}

impl Default for Keypad {
    fn default() -> Self {
        Self::new()
    }
}

impl Keypad {
    pub const fn new() -> Self {
        Self {
            counters: [0; KEYS],
            down: [false; KEYS],
        }
    }

    /// Scan once and write any mapped state changes into `events`.
    ///
    /// Returns the number written, which never exceeds `events.len()`: changes beyond
    /// that are debounced into the state but not reported, rather than overrunning the
    /// caller's buffer. `drbg` must be a UI-domain generator.
    pub fn scan<M: Matrix>(
        &mut self,
        matrix: &mut M,
        drbg: &mut HmacDrbg,
        events: &mut [Event],
    ) -> usize {
        let mut rows = [0u8; ROWS];
        for (i, r) in rows.iter_mut().enumerate() {
            *r = i as u8;
        }
        // A failed shuffle means the DRBG wants reseeding; a fixed order is the fallback,
        // since a leaky scan order is better than an unusable keyboard.
        let _ = drbg.shuffle(&mut rows);
        let mut cols = [0u8; COLS];
        for (i, c) in cols.iter_mut().enumerate() {
            *c = i as u8;
        }
        let _ = drbg.shuffle(&mut cols);

        let mut raw = [false; KEYS];
        for &row in &rows {
            let row = row as usize;
            matrix.select_row(row);
            matrix.settle();
            let bits = matrix.read_columns(&cols);
            for col in 0..COLS {
                raw[row * COLS + col] = bits & (1 << col) != 0;
            }
        }
        matrix.release_rows();

        let mut n = 0;
        for i in 0..KEYS {
            if raw[i] == self.down[i] {
                self.counters[i] = 0;
                continue;
            }
            self.counters[i] += 1;
            if self.counters[i] < DEBOUNCE_SAMPLES {
                continue;
            }
            self.counters[i] = 0;
            self.down[i] = raw[i];
            if let Some(key) = LAYOUT[i]
                && n < events.len()
            {
                events[n] = if raw[i] {
                    Event::Pressed(key)
                } else {
                    Event::Released(key)
                };
                n += 1;
            }
        }
        n
    }

    /// How many positions are held after debounce, mapped or not.
    pub fn held_count(&self) -> usize {
        self.down.iter().filter(|d| **d).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockMatrix {
        pressed: [[bool; COLS]; ROWS],
        selected: Option<usize>,
        rows_seen: Vec<usize>,
        cols_seen: Vec<[u8; COLS]>,
        releases: usize,
    }

    impl MockMatrix {
        fn new() -> Self {
            Self {
                pressed: [[false; COLS]; ROWS],
                selected: None,
                rows_seen: Vec::new(),
                cols_seen: Vec::new(),
                releases: 0,
            }
        }
        fn hold(&mut self, kn: usize, down: bool) {
            self.pressed[kn / COLS][kn % COLS] = down;
        }
    }

    impl Matrix for MockMatrix {
        fn select_row(&mut self, row: usize) {
            self.selected = Some(row);
            self.rows_seen.push(row);
        }
        fn read_columns(&mut self, order: &[u8; COLS]) -> u16 {
            self.cols_seen.push(*order);
            let row = self.selected.expect("columns read with no row selected");
            let mut bits = 0;
            for &c in order {
                if self.pressed[row][c as usize] {
                    bits |= 1 << c;
                }
            }
            bits
        }
        fn release_rows(&mut self) {
            self.selected = None;
            self.releases += 1;
        }
        fn settle(&mut self) {}
    }

    fn drbg() -> HmacDrbg {
        HmacDrbg::new(&[0x22; 32], &[], catcard_entropy::domain::UI)
    }

    fn scan_n(pad: &mut Keypad, m: &mut MockMatrix, d: &mut HmacDrbg, n: usize) -> Vec<Event> {
        let mut out = Vec::new();
        for _ in 0..n {
            let mut ev = [Event::Pressed(Key::Cancel); 12];
            let k = pad.scan(m, d, &mut ev);
            out.extend_from_slice(&ev[..k]);
        }
        out
    }

    #[test]
    fn the_decode_table_puts_the_keys_the_screens_need_where_the_reference_says() {
        // Source: gpio-peripherals.md §Q/Q1 "Key decode" [C]
        assert_eq!(LAYOUT[8], Some(Key::Confirm), "kn8 is ENTER");
        assert_eq!(LAYOUT[7], Some(Key::Cancel), "kn7 is CANCEL");
        assert_eq!(LAYOUT[54], Some(Key::Cancel), "kn54 is DELETE");
        assert_eq!(LAYOUT[10], Some(Key::Digit(1)));
        assert_eq!(LAYOUT[18], Some(Key::Digit(9)));
        assert_eq!(LAYOUT[19], Some(Key::Digit(0)), "the row ends in 0, not starts");
        assert_eq!(
            [LAYOUT[3], LAYOUT[4], LAYOUT[5], LAYOUT[6]],
            [
                Some(Key::Digit(7)),
                Some(Key::Digit(5)),
                Some(Key::Digit(8)),
                Some(Key::Digit(9))
            ],
            "left, up, down, right take the numpad's arrow digits"
        );
        for kn in [0, 1, 2, 9, 20, 29, 35, 49, 50, 51, 52, 53, 55, 59] {
            assert_eq!(LAYOUT[kn], None, "kn{kn} has no meaning to a numpad screen");
        }
    }

    #[test]
    fn a_press_is_reported_once_after_debounce_and_its_release_likewise() {
        let (mut pad, mut m, mut d) = (Keypad::new(), MockMatrix::new(), drbg());
        m.hold(8, true);
        let ev = scan_n(&mut pad, &mut m, &mut d, DEBOUNCE_SAMPLES as usize - 1);
        assert!(ev.is_empty(), "reported before debounce: {ev:?}");
        let ev = scan_n(&mut pad, &mut m, &mut d, 5);
        assert_eq!(ev, vec![Event::Pressed(Key::Confirm)]);
        m.hold(8, false);
        let ev = scan_n(&mut pad, &mut m, &mut d, 5);
        assert_eq!(ev, vec![Event::Released(Key::Confirm)]);
    }

    #[test]
    fn an_unmapped_key_is_debounced_but_says_nothing() {
        let (mut pad, mut m, mut d) = (Keypad::new(), MockMatrix::new(), drbg());
        m.hold(25, true); // a letter
        assert!(scan_n(&mut pad, &mut m, &mut d, 10).is_empty());
        assert_eq!(pad.held_count(), 1);
    }

    #[test]
    fn every_row_is_driven_once_per_scan_in_a_shuffled_order() {
        let (mut pad, mut m, mut d) = (Keypad::new(), MockMatrix::new(), drbg());
        let mut orders = Vec::new();
        for _ in 0..8 {
            m.rows_seen.clear();
            let mut ev = [Event::Pressed(Key::Cancel); 12];
            pad.scan(&mut m, &mut d, &mut ev);
            let mut sorted = m.rows_seen.clone();
            sorted.sort();
            assert_eq!(sorted, (0..ROWS).collect::<Vec<_>>(), "not a permutation");
            orders.push(m.rows_seen.clone());
        }
        assert!(
            orders.windows(2).any(|w| w[0] != w[1]),
            "eight scans in one fixed row order"
        );
        for o in &m.cols_seen {
            let mut s = *o;
            s.sort();
            assert_eq!(s, core::array::from_fn(|i| i as u8));
        }
        assert!(m.releases >= 8);
    }

    #[test]
    fn more_changes_than_the_buffer_holds_are_capped_not_overrun() {
        let (mut pad, mut m, mut d) = (Keypad::new(), MockMatrix::new(), drbg());
        for kn in (3..9).chain(10..20).chain([54]) {
            m.hold(kn, true); // 17 mapped keys at once
        }
        for _ in 0..DEBOUNCE_SAMPLES {
            let mut ev = [Event::Pressed(Key::Cancel); 12];
            let n = pad.scan(&mut m, &mut d, &mut ev);
            assert!(n <= ev.len());
        }
        assert_eq!(pad.held_count(), 17);
    }
}
