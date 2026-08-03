//! 4x3 membrane keypad: scanning, debounce, and event generation.
//!
//! Split from the GPIO the same way the panel driver is split from SPI — the scan
//! logic takes a [`Matrix`], so debounce and edge detection are testable against a mock
//! without a device. Those are exactly the parts that fail subtly: a keypad that
//! double-registers or drops presses is a UX bug that a wallet turns into a wrong PIN.
//!
//! # The scan order is randomised, and where that randomness comes from matters
//!
//! Driving rows in a fixed order leaks which key is pressed through the power trace and
//! through EM emissions — the reason the stock firmware shuffles its scan order too.
//!
//! The shuffle must **not** draw from the wallet-seed generator. In the stock firmware
//! it did, which tied the seed's internal state to the number of key presses and is a
//! large part of why that state was recoverable in practice rather than only in
//! principle. Here the shuffle takes an [`HmacDrbg`](catcard_entropy::HmacDrbg) seeded
//! from `domain::UI`, and [`EntropyPool`](catcard_entropy::EntropyPool) has no API that
//! could serve this purpose even by mistake.

use catcard_entropy::HmacDrbg;

/// Rows in the matrix.
pub const ROWS: usize = 4;
/// Columns in the matrix.
pub const COLS: usize = 3;
/// Keys on the pad.
pub const KEYS: usize = ROWS * COLS;

/// Consecutive agreeing samples before a key's state changes.
///
/// Three at the scan rate below gives roughly 50 ms of settling, comfortably past
/// membrane bounce without being perceptible.
pub const DEBOUNCE_SAMPLES: u8 = 3;

/// What a key means. The pad is digits plus cancel and OK.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Key {
    Digit(u8),
    /// The `x` key.
    Cancel,
    /// The `y` / OK key.
    Confirm,
}

/// Row-major key layout:
///
/// ```text
/// 1 2 3
/// 4 5 6
/// 7 8 9
/// x 0 y
/// ```
pub const LAYOUT: [Key; KEYS] = [
    Key::Digit(1),
    Key::Digit(2),
    Key::Digit(3),
    Key::Digit(4),
    Key::Digit(5),
    Key::Digit(6),
    Key::Digit(7),
    Key::Digit(8),
    Key::Digit(9),
    Key::Cancel,
    Key::Digit(0),
    Key::Confirm,
];

/// A press or release.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Event {
    Pressed(Key),
    Released(Key),
}

/// The electrical half of the keypad, supplied by the firmware.
pub trait Matrix {
    /// Drive exactly one row low and leave the others released.
    ///
    /// Rows are open-drain: driving two low at once shorts them together through a
    /// pressed key, which reads as phantom presses on other rows.
    fn select_row(&mut self, row: usize);

    /// Read the three columns. Bit `n` set means column `n` reads **low**, i.e. a key
    /// on the selected row is pressed. Columns are pulled up, so idle reads as zero
    /// here after inversion.
    fn read_columns(&mut self) -> u8;

    /// Release every row, leaving the matrix idle.
    fn release_rows(&mut self);

    /// Settling delay between driving a row and sampling the columns.
    fn settle(&mut self);
}

/// Debounced keypad scanner.
pub struct Keypad {
    /// Consecutive samples agreeing with the *opposite* of the current state.
    counters: [u8; KEYS],
    /// Debounced state.
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

    /// Scan once and append any state changes to `events`.
    ///
    /// Returns the number of events written. `drbg` supplies the row order; passing a
    /// UI-domain generator is the caller's responsibility and is what keeps this off the
    /// seed generator.
    pub fn scan<M: Matrix>(
        &mut self,
        matrix: &mut M,
        drbg: &mut HmacDrbg,
        events: &mut [Event; KEYS],
    ) -> usize {
        let mut order = [0u8, 1, 2, 3];
        // A failure here means the DRBG needs reseeding; scanning in a fixed order is
        // the safe fallback, since a leaky scan order is better than an unusable keypad.
        let _ = drbg.shuffle(&mut order);

        let mut raw = [false; KEYS];
        for &row in &order {
            let row = row as usize;
            matrix.select_row(row);
            matrix.settle();
            let cols = matrix.read_columns();
            for col in 0..COLS {
                raw[row * COLS + col] = cols & (1 << col) != 0;
            }
        }
        matrix.release_rows();

        let mut n = 0;
        for i in 0..KEYS {
            if raw[i] == self.down[i] {
                // Agrees with the debounced state; nothing pending.
                self.counters[i] = 0;
                continue;
            }
            self.counters[i] += 1;
            if self.counters[i] >= DEBOUNCE_SAMPLES {
                self.counters[i] = 0;
                self.down[i] = raw[i];
                events[n] = if raw[i] {
                    Event::Pressed(LAYOUT[i])
                } else {
                    Event::Released(LAYOUT[i])
                };
                n += 1;
            }
        }
        n
    }

    /// Whether a key is currently held, after debounce.
    pub fn is_down(&self, key: Key) -> bool {
        LAYOUT
            .iter()
            .position(|k| *k == key)
            .is_some_and(|i| self.down[i])
    }

    /// How many keys are held. Used to reject multi-key input during PIN entry, where
    /// an ambiguous read must not be guessed at.
    pub fn held_count(&self) -> usize {
        self.down.iter().filter(|d| **d).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A matrix whose contents the test controls, recording which rows were driven.
    struct MockMatrix {
        /// `pressed[row][col]`.
        pressed: [[bool; COLS]; ROWS],
        selected: Option<usize>,
        order_seen: Vec<usize>,
        settles: usize,
        releases: usize,
        /// Every call in order, so an ordering bug is visible.
        log: Vec<&'static str>,
    }

    impl MockMatrix {
        fn new() -> Self {
            Self {
                pressed: [[false; COLS]; ROWS],
                selected: None,
                order_seen: Vec::new(),
                settles: 0,
                releases: 0,
                log: Vec::new(),
            }
        }
        fn press(&mut self, row: usize, col: usize) {
            self.pressed[row][col] = true;
        }
        fn release(&mut self, row: usize, col: usize) {
            self.pressed[row][col] = false;
        }
    }

    impl Matrix for MockMatrix {
        fn select_row(&mut self, row: usize) {
            // Contract: exactly one row is driven, so selecting implicitly releases the
            // previous one. Modelled as a single value rather than a set, which makes
            // "two rows low at once" unrepresentable here — the firmware's Matrix impl
            // is where that invariant actually has to hold, via one register write.
            assert!(row < ROWS, "row {row} out of range");
            self.selected = Some(row);
            self.order_seen.push(row);
            self.log.push("select");
        }
        fn read_columns(&mut self) -> u8 {
            self.log.push("read");
            let row = self.selected.expect("read without selecting a row");
            let mut bits = 0u8;
            for (c, p) in self.pressed[row].iter().enumerate() {
                if *p {
                    bits |= 1 << c;
                }
            }
            // A real matrix leaves the row driven until the next select; model that.
            self.selected = Some(row);
            bits
        }
        fn release_rows(&mut self) {
            self.selected = None;
            self.releases += 1;
            self.log.push("release");
        }
        fn settle(&mut self) {
            self.settles += 1;
            self.log.push("settle");
        }
    }

    fn drbg() -> HmacDrbg {
        HmacDrbg::new(&[0x11; 32], &[], catcard_entropy::domain::UI)
    }

    fn scan_n(k: &mut Keypad, m: &mut MockMatrix, d: &mut HmacDrbg, n: usize) -> Vec<Event> {
        let mut all = Vec::new();
        let mut buf = [Event::Pressed(Key::Cancel); KEYS];
        for _ in 0..n {
            let c = k.scan(m, d, &mut buf);
            all.extend_from_slice(&buf[..c]);
        }
        all
    }

    #[test]
    fn a_press_is_reported_only_after_debounce() {
        let (mut k, mut m, mut d) = (Keypad::new(), MockMatrix::new(), drbg());
        m.press(0, 0);

        // Fewer than DEBOUNCE_SAMPLES scans: nothing yet.
        let early = scan_n(&mut k, &mut m, &mut d, DEBOUNCE_SAMPLES as usize - 1);
        assert!(early.is_empty(), "reported before debounce: {early:?}");
        assert!(!k.is_down(Key::Digit(1)));

        let now = scan_n(&mut k, &mut m, &mut d, 1);
        assert_eq!(now, vec![Event::Pressed(Key::Digit(1))]);
        assert!(k.is_down(Key::Digit(1)));
    }

    #[test]
    fn contact_bounce_does_not_produce_an_event() {
        // The whole point of debounce: a key that chatters must register once, or not
        // at all — never as several presses.
        let (mut k, mut m, mut d) = (Keypad::new(), MockMatrix::new(), drbg());
        let mut events = Vec::new();
        for i in 0..12 {
            if i % 2 == 0 {
                m.press(1, 1);
            } else {
                m.release(1, 1);
            }
            events.extend(scan_n(&mut k, &mut m, &mut d, 1));
        }
        assert!(events.is_empty(), "bounce produced {events:?}");
    }

    #[test]
    fn a_held_key_reports_once_not_repeatedly() {
        let (mut k, mut m, mut d) = (Keypad::new(), MockMatrix::new(), drbg());
        m.press(0, 0);
        let events = scan_n(&mut k, &mut m, &mut d, 50);
        assert_eq!(events, vec![Event::Pressed(Key::Digit(1))]);
    }

    #[test]
    fn release_is_reported_after_debounce() {
        let (mut k, mut m, mut d) = (Keypad::new(), MockMatrix::new(), drbg());
        m.press(0, 0);
        scan_n(&mut k, &mut m, &mut d, 5);
        m.release(0, 0);
        let events = scan_n(&mut k, &mut m, &mut d, DEBOUNCE_SAMPLES as usize);
        assert_eq!(events, vec![Event::Released(Key::Digit(1))]);
        assert!(!k.is_down(Key::Digit(1)));
    }

    #[test]
    fn every_position_maps_to_its_printed_key() {
        // A transposed layout would make the device silently enter the wrong PIN.
        let cases = [
            (0, 0, Key::Digit(1)),
            (0, 2, Key::Digit(3)),
            (1, 0, Key::Digit(4)),
            (2, 2, Key::Digit(9)),
            (3, 0, Key::Cancel),
            (3, 1, Key::Digit(0)),
            (3, 2, Key::Confirm),
        ];
        for (row, col, want) in cases {
            let (mut k, mut m, mut d) = (Keypad::new(), MockMatrix::new(), drbg());
            m.press(row, col);
            let events = scan_n(&mut k, &mut m, &mut d, DEBOUNCE_SAMPLES as usize);
            assert_eq!(events, vec![Event::Pressed(want)], "row {row} col {col}");
        }
    }

    #[test]
    fn the_layout_covers_every_digit_once_plus_cancel_and_confirm() {
        for digit in 0..=9u8 {
            assert_eq!(
                LAYOUT.iter().filter(|k| **k == Key::Digit(digit)).count(),
                1,
                "digit {digit}"
            );
        }
        assert_eq!(LAYOUT.iter().filter(|k| **k == Key::Cancel).count(), 1);
        assert_eq!(LAYOUT.iter().filter(|k| **k == Key::Confirm).count(), 1);
        assert_eq!(LAYOUT.len(), 12);
    }

    #[test]
    fn columns_are_never_sampled_before_the_row_settles() {
        // Sampling immediately after driving a row reads the previous row's state
        // through the line capacitance, which presents as keys from the wrong row.
        let (mut k, mut m, mut d) = (Keypad::new(), MockMatrix::new(), drbg());
        let mut buf = [Event::Pressed(Key::Cancel); KEYS];
        k.scan(&mut m, &mut d, &mut buf);

        assert_eq!(
            m.log,
            vec![
                "select", "settle", "read", "select", "settle", "read", "select", "settle", "read",
                "select", "settle", "read", "release",
            ],
            "scan sequence is wrong"
        );
    }

    #[test]
    fn all_four_rows_are_scanned_every_pass() {
        let (mut k, mut m, mut d) = (Keypad::new(), MockMatrix::new(), drbg());
        let mut buf = [Event::Pressed(Key::Cancel); KEYS];
        k.scan(&mut m, &mut d, &mut buf);
        let mut seen = m.order_seen.clone();
        seen.sort_unstable();
        assert_eq!(seen, vec![0, 1, 2, 3], "a row was skipped or repeated");
        assert_eq!(m.settles, ROWS, "columns sampled without settling");
        assert_eq!(m.releases, 1, "rows left driven after the scan");
    }

    #[test]
    fn the_scan_order_is_randomised() {
        // A fixed order leaks which key is pressed through power and EM.
        let (mut k, mut m, mut d) = (Keypad::new(), MockMatrix::new(), drbg());
        let mut buf = [Event::Pressed(Key::Cancel); KEYS];
        let mut orders = std::collections::HashSet::new();
        for _ in 0..40 {
            m.order_seen.clear();
            k.scan(&mut m, &mut d, &mut buf);
            orders.insert(m.order_seen.clone());
        }
        assert!(
            orders.len() > 4,
            "scan order barely varies: {} seen",
            orders.len()
        );
    }

    #[test]
    fn simultaneous_presses_are_all_reported_and_counted() {
        let (mut k, mut m, mut d) = (Keypad::new(), MockMatrix::new(), drbg());
        m.press(0, 0);
        m.press(3, 2);
        let mut events = scan_n(&mut k, &mut m, &mut d, DEBOUNCE_SAMPLES as usize);
        events.sort_by_key(|e| format!("{e:?}"));
        assert_eq!(
            events,
            vec![Event::Pressed(Key::Confirm), Event::Pressed(Key::Digit(1)),]
        );
        // PIN entry uses this to refuse an ambiguous read rather than guessing.
        assert_eq!(k.held_count(), 2);
    }

    #[test]
    fn an_idle_pad_produces_nothing() {
        let (mut k, mut m, mut d) = (Keypad::new(), MockMatrix::new(), drbg());
        assert!(scan_n(&mut k, &mut m, &mut d, 100).is_empty());
        assert_eq!(k.held_count(), 0);
    }
}
