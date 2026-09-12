//! Board-revision straps: telling an mk5 from an mk4 at runtime.
//!
//! mk4 and mk5 are the same board to within a strap, which is why one firmware image can
//! carry both `hw_compat` bits and install on either. The cost of that is identity: a
//! single image built for one of them reports that one on its screen, in `Identify`, and
//! in any log taken off it — so an mk5 would insist it was an mk4.
//!
//! The hardware answers directly. `STRAP_MK5` is `PE0`, left open on mk1-4 and pulled
//! **low** on mk5, which is how the stock firmware derives `mk_num`.
//!
//! Source: `hw-reference/generations-mk2-q-mk5.md` §Mk4 vs Mk5 [C],
//! `hw-reference/gpio-peripherals.md` §Mk4 [C]

use crate::gpio::{self, Mode, OutputType, Pull, Speed};
use catcard_board::{Pin, Port};

/// `STRAP_MK5`, on port E pin 0.
const STRAP_MK5: Pin = Pin::new(Port::E, 0);

/// Whether the mk5 strap is pulled low.
///
/// Reads as an input with our own pull-up, so an open strap — every board before mk5 —
/// reads high and only a board that actively pulls it down reads low. That way a missing
/// connection cannot be mistaken for an mk5.
///
/// # Safety
/// Claims `PE0` and enables port E's clock. Nothing else may be driving that pin.
pub unsafe fn is_mk5() -> bool {
    let pin = STRAP_MK5;
    // SAFETY: as documented.
    unsafe {
        gpio::enable_port(pin.port);
        gpio::configure(pin, Mode::Input, OutputType::PushPull, Pull::Up, Speed::Low);
        // The pull takes a moment to settle on a floating pin; without a pause this can
        // sample the state the pad was left in rather than the one the resistor sets.
        crate::dwt::delay_cycles(1_000);
        !gpio::read(pin)
    }
}
