//! The keyboard matrix, as the gateware scans it.
//!
//! 9 rows by 10 columns. The gateware drives the columns, samples the rows, debounces
//! (5 ms) and publishes one register per row, `keyboard_rowNdat`, whose bit `c` is set
//! while the key at (row, column `c`) is held. Nothing to scan here: read nine words.
//! Source: betrusted gateware keyboard.py (row/col roles, `rowNdat` per row, debounce) [C];
//! betrusted_soc.py `kbd` pads: 9 rows, 10 columns [C]; csr.csv `keyboard_row0dat..8dat`
//! at consecutive words [C].
//!
//! Which printed key sits at which (row, column), and what it means to the screens, is
//! `catcard_ui::precursorkeys`.

use crate::csr::{self, reg};

pub use catcard_ui::precursorkeys::ROWS;

const _: () = assert!(reg::KEYBOARD_ROW8DAT == reg::KEYBOARD_ROW0DAT + 8 * 4);

/// Column masks, one per row.
pub fn scan() -> [u16; ROWS] {
    core::array::from_fn(|r| (csr::read(reg::KEYBOARD_ROW0DAT + 4 * r) & 0x3FF) as u16)
}
