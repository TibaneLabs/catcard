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

// `held_mask` reports one bit per position.
const _: () = assert!(KEYS <= 64, "more positions than a mask can hold");

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

/// Matrix positions that are modifiers or driver-only: they never become an event.
///
/// LAMP is the torch key, and it is **not an MCU pin**: it toggles the QR-scanner
/// module's own illumination LED over the scanner's UART (`S_CMD_03L1` on, `03L2` auto,
/// `03L0` off). So it is never delivered as a character, and it will start working when
/// there is a scanner driver to send that command -- not before, and not via a GPIO.
/// Source: input.md §"Illumination torch / LAMP key" [C], gpio.md §"Indicator LEDs" [C]
pub const KN_LAMP: usize = 50;
/// SHIFT. Held, not latched, and never delivered.
pub const KN_SHIFT: usize = 51;
/// SYMBOL. Held, never delivered.
pub const KN_SYMBOL: usize = 53;

/// What each position types with nothing held. `0` means "produces no character".
///
/// The rows are the reference's positional groups: `kn0..9` specials (only TAB types),
/// `kn10..19` the number row, `kn20..49` the three letter rows, `kn50..59` the modifiers
/// with SPACE among them. Source: input.md §"Key decode" [C]
const BASE_CHARS: [u8; KEYS] = *b"\x00\t\x00\x00\x00\x00\x00\x00\x00\x00\
1234567890\
qwertyuiop\
asdfghjkl'\
zxcvbnm,./\
\x00\x00 \x00\x00\x00\x00\x00\x00\x00";

/// With SHIFT held. Row 0 is dead, the number row gives symbols, letters upper-case.
/// Source: input.md §"Key decode" [C]
const SHIFT_CHARS: [u8; KEYS] = *b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
!@#$%^&*()\
QWERTYUIOP\
ASDFGHJKL\"\
ZXCVBNM<>?\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

/// With SYMBOL held. The number row matches SHIFT ("number+symbol = number+shift"); the
/// letter rows carry the punctuation that is otherwise unreachable, with gaps where the
/// reference marks a key dead. F1-F6 (kn40..45) are context soft keys that do nothing
/// outside one stock screen, so they are left unmapped rather than delivered as controls.
/// Row 0 keeps its arrows here rather than becoming HOME/PGUP/PGDN/END: those have no
/// `Key`, and navigation that stopped working while SYMBOL was held would be worse than
/// four keys that do what their caps say.
/// Source: input.md §"What each key emits, per layer" [C]
const SYMBOL_CHARS: [u8; KEYS] = *b"\x00\t\x00\x00\x00\x00\x00\x00\x00\x00\
!@#$%^&*()\
-_`\x00\x00\x00[]{}\
+\x00\x00=:;~|\\\"\
\x00\x00\x00\x00\x00\x00\x00<>?\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

/// With CAPS latched: the base table with its letters upper-cased, which is what the
/// reference says CAPS is -- not the SHIFT table, whose number row is symbols.
const CAPS_CHARS: [u8; KEYS] = {
    let mut t = BASE_CHARS;
    let mut i = 0;
    while i < KEYS {
        if t[i] >= b'a' && t[i] <= b'z' {
            t[i] -= b'a' - b'A';
        }
        i += 1;
    }
    t
};

/// What a position means with the modifiers currently held.
///
/// Three groups never become characters, whatever is held:
///
/// - the arrows, CANCEL and ENTER (`kn3..8`) and DELETE (`kn54`), which stay the [`Key`]s
///   every screen already navigates with;
/// - the unmodified number row, which stays [`Key::Digit`] -- a PIN field and a menu
///   both need digits, and typing `1` must not become a character there;
/// - the modifiers and the lamp themselves.
///
/// SYMBOL is scanned and tracked but types nothing yet: the reference's symbol rows do
/// not line up unambiguously with ten positions each, and a keyboard that types the wrong
/// punctuation into a passphrase is worse than one that types none.
pub fn decode(kn: usize, shift: bool, symbol: bool, caps: bool) -> Option<Key> {
    if kn >= KEYS {
        return None;
    }
    match kn {
        // Navigation and the two answer keys, unchanged under every modifier.
        3..=8 | 54 => LAYOUT[kn],
        KN_LAMP | KN_SHIFT | KN_SYMBOL => None,
        // Digits, unless a modifier turns the row into symbols. CAPS is not one of them:
        // it upper-cases letters and leaves digits alone, so a PIN still types.
        10..=19 if !shift && !symbol => LAYOUT[kn],
        _ => {
            // Priority CAPS > SYMBOL > SHIFT > base, as the reference states it.
            let c = if caps {
                CAPS_CHARS[kn]
            } else if symbol {
                SYMBOL_CHARS[kn]
            } else if shift {
                SHIFT_CHARS[kn]
            } else {
                BASE_CHARS[kn]
            };
            if c == 0 { None } else { Some(Key::Char(c)) }
        }
    }
}

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
    /// Most recent position to go down, for the keypad tester.
    last_kn: Option<u8>,
    /// CAPS, which latches rather than being held: the reference says it toggles when
    /// SHIFT and SYMBOL are pressed together.
    caps: bool,
    /// Whether SHIFT+SYMBOL were already down together, so holding them toggles CAPS
    /// once rather than on every scan.
    caps_combo: bool,
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
            last_kn: None,
            caps: false,
            caps_combo: false,
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

        // Modifiers are read from the raw scan, not from debounced events: they are held
        // while another key is struck, so they must be current for that key's decode.
        let shift = raw[KN_SHIFT];
        let symbol = raw[KN_SYMBOL];
        if shift && symbol {
            if !self.caps_combo {
                self.caps = !self.caps;
                self.caps_combo = true;
            }
        } else {
            self.caps_combo = false;
        }

        let mut n = 0;
        for (i, &now) in raw.iter().enumerate() {
            if now == self.down[i] {
                self.counters[i] = 0;
                continue;
            }
            self.counters[i] += 1;
            if self.counters[i] < DEBOUNCE_SAMPLES {
                continue;
            }
            self.counters[i] = 0;
            self.down[i] = now;
            if now {
                self.last_kn = Some(i as u8);
            }
            // Decoded with the modifiers as they are now. A key released after its
            // modifier was let go reports the unmodified key; screens act on presses.
            if let Some(key) = decode(i, shift, symbol, self.caps)
                && n < events.len()
            {
                events[n] = if now {
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
    /// The matrix position most recently pressed, mapped or not.
    ///
    /// For the keypad tester. A test screen that only reacted to keys the UI understands
    /// could not prove the matrix works, which is the one thing it exists for -- the
    /// modifiers, the lamp and the two hardware keys decode to nothing and would look
    /// dead on the very screen meant to tell a dead key from an unmapped one.
    pub fn last_pressed(&self) -> Option<usize> {
        self.last_kn.map(usize::from)
    }

    /// Which positions are held, one bit per matrix position.
    pub fn held_mask(&self) -> u64 {
        let mut m = 0u64;
        for (i, &d) in self.down.iter().enumerate() {
            if d {
                m |= 1 << i;
            }
        }
        m
    }

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
        assert_eq!(
            LAYOUT[19],
            Some(Key::Digit(0)),
            "the row ends in 0, not starts"
        );
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
        // kn9 is unused in the reference's decode table. It used to be a letter here,
        // which stopped being unmapped the moment the keyboard learned to type.
        m.hold(9, true);
        assert!(scan_n(&mut pad, &mut m, &mut d, 10).is_empty());
        assert_eq!(pad.held_count(), 1);
    }

    #[test]
    fn the_letter_rows_type_what_the_reference_prints() {
        // The three letter rows, their ends, and the two whitespace keys.
        // Source: input.md §"Key decode" [C]
        assert_eq!(decode(20, false, false, false), Some(Key::Char(b'q')));
        assert_eq!(decode(29, false, false, false), Some(Key::Char(b'p')));
        assert_eq!(decode(30, false, false, false), Some(Key::Char(b'a')));
        assert_eq!(decode(38, false, false, false), Some(Key::Char(b'l')));
        assert_eq!(decode(40, false, false, false), Some(Key::Char(b'z')));
        assert_eq!(decode(46, false, false, false), Some(Key::Char(b'm')));
        assert_eq!(decode(52, false, false, false), Some(Key::Char(b' ')), "kn52 is SPACE");
        assert_eq!(decode(1, false, false, false), Some(Key::Char(b'\t')), "kn1 is TAB");
    }

    #[test]
    fn navigation_never_becomes_a_character() {
        // Whatever is held, the keys the screens steer with stay themselves -- otherwise
        // a menu would stop answering the moment someone rested a thumb on SHIFT.
        for (shift, caps) in [(false, false), (true, false), (false, true), (true, true)] {
            assert_eq!(decode(7, shift, false, caps), Some(Key::Cancel), "kn7 CANCEL");
            assert_eq!(decode(8, shift, false, caps), Some(Key::Confirm), "kn8 ENTER");
            assert_eq!(decode(54, shift, false, caps), Some(Key::Cancel), "kn54 DELETE");
            assert_eq!(decode(4, shift, false, caps), Some(Key::Digit(5)), "kn4 up");
        }
    }

    #[test]
    fn caps_leaves_the_number_row_alone_but_shift_does_not() {
        // A latched CAPS that turned `1` into a character would break PIN entry, which
        // is the one screen with no way to say what went wrong.
        assert_eq!(decode(10, false, false, true), Some(Key::Digit(1)));
        assert_eq!(decode(19, false, false, true), Some(Key::Digit(0)));
        // SHIFT is the documented symbol row.
        assert_eq!(decode(10, true, false, false), Some(Key::Char(b'!')));
        assert_eq!(decode(20, true, false, false), Some(Key::Char(b'Q')));
        // CAPS upper-cases letters, which is what the reference says it is.
        assert_eq!(decode(20, false, false, true), Some(Key::Char(b'Q')));
    }

    #[test]
    fn symbol_types_the_punctuation_the_reference_lists() {
        // Source: input.md §"What each key emits, per layer" [C]
        let sym = |kn| decode(kn, false, true, false);
        assert_eq!(sym(20), Some(Key::Char(b'-')), "q");
        assert_eq!(sym(21), Some(Key::Char(b'_')), "w");
        assert_eq!(sym(22), Some(Key::Char(b'`')), "e");
        assert_eq!(sym(26), Some(Key::Char(b'[')), "u");
        assert_eq!(sym(29), Some(Key::Char(b'}')), "p");
        assert_eq!(sym(30), Some(Key::Char(b'+')), "a");
        assert_eq!(sym(33), Some(Key::Char(b'=')), "f");
        assert_eq!(sym(38), Some(Key::Char(b'\\')), "l");
        assert_eq!(sym(39), Some(Key::Char(b'"')), "'");
        assert_eq!(sym(47), Some(Key::Char(b'<')), ",");
        // The number row is the same as SHIFT: "number+symbol = number+shift".
        assert_eq!(sym(10), Some(Key::Char(b'!')));
        // Dead keys in this layer, and the F-keys we deliberately do not deliver.
        for kn in [23, 24, 25, 31, 32, 40, 45, 46, 52] {
            assert_eq!(sym(kn), None, "kn{kn} should be dead under SYMBOL");
        }
    }

    #[test]
    fn caps_outranks_symbol_as_the_reference_orders_them() {
        // Priority is CAPS > SYMBOL > SHIFT > base, so a latched CAPS wins.
        assert_eq!(decode(20, false, true, true), Some(Key::Char(b'Q')));
    }

    #[test]
    fn the_modifiers_and_the_lamp_deliver_nothing() {
        // The lamp is torch-only in the reference, and we have no pin for it either way.
        for kn in [KN_LAMP, KN_SHIFT, KN_SYMBOL, 9, 55, 59] {
            assert_eq!(decode(kn, false, false, false), None, "kn{kn} produced a key");
        }
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
