//! Binding the keypad scanner to this board's GPIO.

use catcard_board::spec::Input;
use catcard_board::{Pin, BOARD};
use catcard_hal::gpio::{self, Mode, OutputType, Pull, Speed};
use catcard_ui::keypad::{Matrix, COLS, ROWS};

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
    /// # Safety
    /// Call once; takes exclusive ownership of the numpad pins.
    pub unsafe fn init() -> Option<Self> {
        let Input::Numpad4x3 { rows, cols } = BOARD.input else {
            // A Q1 keyboard is a 10x6 matrix and needs its own scanner.
            return None;
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

    fn read_columns(&mut self, order: &[u8; COLS]) -> u8 {
        let mut bits = 0u8;
        for &c in order {
            let ci = c as usize;
            // Read in the caller's randomised order, and accumulate branchlessly: a
            // pressed key (column low) sets its bit, a released one sets nothing, via
            // identical code with no data-dependent branch. So neither which lane is
            // pressed nor which row leaks through the read timing or the EM ordering.
            // Pulled up, so a pressed key pulls the column to the driven row's low.
            // SAFETY: configured as inputs in `init`.
            bits |= u8::from(!unsafe { gpio::read(self.cols[ci]) }) << ci;
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
