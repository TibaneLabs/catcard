//! Binding the keypad scanner to this board's GPIO.
//!
//! One scanner per input type: the 4x3 numpad ([`catcard_ui::keypad`]) on mk3/mk4/mk5 and
//! the 10x6 QWERTY matrix ([`catcard_ui::qwerty`]) on Q1. Both hand the rest of the
//! firmware the same `Key` events through a type named [`Keypad`], so no screen needs to
//! know which one it is reading.

use catcard_board::spec::Input;
use catcard_board::{BOARD, Pin};
use catcard_hal::gpio::{self, Mode, OutputType, Pull, Speed};

#[cfg(not(feature = "board-q1"))]
pub use catcard_ui::keypad::Keypad;
#[cfg(not(feature = "board-q1"))]
use catcard_ui::keypad::{COLS, Matrix, ROWS};
#[cfg(feature = "board-q1")]
pub use catcard_ui::qwerty::Keypad;
#[cfg(feature = "board-q1")]
use catcard_ui::qwerty::{COLS, Matrix, ROWS};

/// Column bits as the scanner's `Matrix` returns them: 3 lanes fit a `u8`, 10 need a `u16`.
#[cfg(not(feature = "board-q1"))]
type Bits = u8;
#[cfg(feature = "board-q1")]
type Bits = u16;

/// Settling time between driving a row and sampling the columns.
///
/// The columns are pulled up by weak internal resistors against the membrane's cable
/// capacitance, so the line takes real time to rise. Sampling too early reads the
/// previous row's state, which presents as keys registering from the wrong row.
const SETTLE_CYCLES: u32 = 200;

/// The keypad as wired on this board.
pub struct GpioMatrix {
    rows: [Pin; ROWS],
    cols: [Pin; COLS],
}

impl GpioMatrix {
    /// Configure the matrix pins.
    ///
    /// Rows are open-drain: a push-pull row driven high would fight a different row
    /// driven low through any pressed key, which at best reads wrong and at worst
    /// sources current through the membrane.
    ///
    /// Returns `None` when this build's scanner does not match the board's input, or when
    /// a column reads low with every row released -- see below.
    ///
    /// # Safety
    /// Call once; takes exclusive ownership of the keypad pins.
    pub unsafe fn init() -> Option<Self> {
        let (rows, cols) = match BOARD.input {
            #[cfg(not(feature = "board-q1"))]
            Input::Numpad4x3 { rows, cols } => (rows, cols),
            #[cfg(feature = "board-q1")]
            Input::Qwerty { rows, cols } => (rows, cols),
            #[allow(unreachable_patterns)]
            _ => return None,
        };

        // SAFETY: these pins belong to the keypad alone, which the board table's
        // pin-conflict test enforces.
        unsafe {
            for r in rows {
                gpio::enable_port(r.port);
                gpio::configure(
                    r,
                    Mode::Output,
                    OutputType::OpenDrain,
                    Pull::None,
                    Speed::Low,
                );
                gpio::write(r, true); // released
            }
            for c in cols {
                gpio::enable_port(c.port);
                gpio::configure(c, Mode::Input, OutputType::PushPull, Pull::Up, Speed::Low);
            }
        }

        // With every row released no key can pull a column low, so a column that reads
        // low now is a short, a missing pull-up, or the wrong pins -- and a matrix like
        // that presses something on every scan, which on a confirmation screen is an
        // answer nobody gave. Refuse it: the session then runs headless, which keeps the
        // device reprogrammable over USB. Nothing is driven, so no scan order can leak.
        catcard_hal::dwt::delay_cycles(SETTLE_CYCLES * 10);
        // SAFETY: configured as inputs just above.
        if cols.iter().any(|&c| !unsafe { gpio::read(c) }) {
            crate::catlog!("keypad: a column reads low with no row driven; matrix refused");
            return None;
        }
        Some(Self { rows, cols })
    }
}

impl Matrix for GpioMatrix {
    fn select_row(&mut self, row: usize) {
        // Release every row, then drive the one wanted. Doing it in this order means
        // two rows are never low simultaneously, even briefly.
        // SAFETY: configured as outputs in `init`.
        unsafe {
            for r in self.rows {
                gpio::write(r, true);
            }
            gpio::write(self.rows[row], false);
        }
    }

    fn read_columns(&mut self, order: &[u8; COLS]) -> Bits {
        let mut bits: Bits = 0;
        for &c in order {
            let ci = c as usize;
            // Read in the caller's randomised order, and accumulate branchlessly: a
            // pressed key (column low) sets its bit, a released one sets nothing, via
            // identical code with no data-dependent branch. So neither which lane is
            // pressed nor which row leaks through the read timing or the EM ordering.
            // Pulled up, so a pressed key pulls the column to the driven row's low.
            // SAFETY: configured as inputs in `init`.
            bits |= Bits::from(!unsafe { gpio::read(self.cols[ci]) }) << ci;
        }
        bits
    }

    fn release_rows(&mut self) {
        // SAFETY: configured as outputs in `init`.
        unsafe {
            for r in self.rows {
                gpio::write(r, true);
            }
        }
    }

    fn settle(&mut self) {
        catcard_hal::dwt::delay_cycles(SETTLE_CYCLES);
    }
}
