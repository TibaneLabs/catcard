//! The four things every screen needs, travelling together.
//!
//! A screen draws on the panel, reads the keypad through the matrix, and shuffles its
//! scan order from the UI DRBG. Those four were passed separately to twenty-nine
//! functions, which is what `Session` and `View` already exist to avoid: a call taking
//! eight positional arguments is one transposed pair away from driving the wrong thing,
//! and adding a fifth meant touching every signature in the file.
//!
//! Keeping them in one struct is also what makes an event-driven screen possible: a
//! screen that is handed a `Ui` can be asked to draw or to take a key without the
//! caller knowing which peripherals it happens to need.
//!
//! The fields are borrows rather than owned values because the peripherals are owned by
//! the boot path and outlive every screen. Borrowing the fields individually is what
//! lets a screen hold `ui.panel` and still hand `ui` to a helper on the next line.

use catcard_entropy::HmacDrbg;

use crate::display;
use crate::keypad::{GpioMatrix, Keypad};

/// The panel, the keypad and the randomness a screen draws and reads with.
pub(crate) struct Ui<'a> {
    pub panel: &'a mut display::Panel,
    /// One scanner for the whole session.
    ///
    /// Not one per screen: a fresh [`Keypad`] starts with nothing held, so a key still
    /// down from the previous screen reads as a new press and the screen advances
    /// before anyone let go. That cost a page of seed words once already.
    pub pad: &'a mut Keypad,
    pub matrix: &'a mut GpioMatrix,
    /// The UI DRBG, used to shuffle the scan order. Never the seed pool.
    pub drbg: &'a mut HmacDrbg,
}
