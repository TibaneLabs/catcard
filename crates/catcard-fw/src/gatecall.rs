//! The one way this firmware calls a callgate that draws or does not come back.
//!
//! The bootloader drives the Q1's panel itself in callgate 2 (DFU and brick screens),
//! 3 (logout, power-off), 4/3 (genuine light) and 23 (wipe), assuming SPI1, the panel's
//! pins and DMA are as it left them.
//! Source: hw-reference/bootloader-callgate-abi.md §"Caveat (exceptional paths only)" and
//! the method table [C]; docs/CALLGATE-DMA.md (2).
//!
//! A waiting screen's sweep (`display::Busy`) streams into that panel by DMA for as long
//! as its work runs, and the calls here can come from anywhere in the meantime -- the
//! power button from the USB task, the idle logout, the fatal guard, a trick-PIN wipe, a
//! host's logout. So each wrapper stops the sweep first ([`display::quiesce`]), then makes
//! the call. `make lint` refuses a direct call of these methods anywhere else
//! (`tools/gatecall-lint.sh`), so a new one cannot bypass the backstop.
//!
//! On the boot path and in the failsafe (`recovery`) no sweep has ever started, and
//! `quiesce` is then a single atomic load: these wrappers add nothing else there.
//!
//! Only the modes this firmware uses are wrapped: gate 4 is only ever read (4/0, which
//! draws nothing), and 24 (brick) is never called.

use catcard_callgate::Callgate;
#[cfg(not(feature = "board-mk3"))]
use catcard_callgate::abi::FastWipe;
use catcard_callgate::abi::{DfuMode, LogoutMode, Method};

use crate::display;

/// Callgate 3: wipe SRAM, then show the logout screen, keep the screen, reboot or power
/// off, as `mode` says. Does not return.
///
/// # Safety
///
/// As [`Callgate::logout`]: everything in SRAM is gone afterwards.
pub(crate) unsafe fn logout(gate: &Callgate, mode: LogoutMode) -> ! {
    display::quiesce();
    // SAFETY: the caller's contract, passed on; the panel is the bootloader's again.
    unsafe { gate.logout(mode) }
}

/// Callgate 3 for a path that must carry on if the bootloader declines -- the panic
/// handler, which then wipes what it can itself. Returns only if the gate did.
///
/// # Safety
///
/// As [`Callgate::call_no_buf`] with [`Method::ShowLogout`]: if it runs, everything in
/// SRAM is gone.
pub(crate) unsafe fn try_logout(
    gate: &Callgate,
    mode: LogoutMode,
) -> Result<i32, catcard_callgate::Error> {
    display::quiesce();
    // SAFETY: the caller's contract, passed on; show_logout takes no buffer.
    unsafe { gate.call_no_buf(Method::ShowLogout, mode as u32) }
}

/// Callgate 2: wipe SRAM, show the bootloader's screen, and go to DFU -- or, for
/// [`DfuMode::Brick`], lock up. Does not return. **`Brick` is irreversible.**
///
/// # Safety
///
/// As [`Callgate::enter_dfu`].
pub(crate) unsafe fn enter_dfu(gate: &Callgate, mode: DfuMode) -> ! {
    display::quiesce();
    // SAFETY: the caller's contract, passed on.
    unsafe { gate.enter_dfu(mode) }
}

/// Callgate 23: wipe the seed and reset. **Irreversible**, and does not return.
///
/// # Safety
///
/// As [`Callgate::fast_wipe`]: destroys the stored wallet.
#[cfg(not(feature = "board-mk3"))]
pub(crate) unsafe fn fast_wipe(gate: &Callgate, mode: FastWipe) -> ! {
    display::quiesce();
    // SAFETY: the caller's contract, passed on.
    unsafe { gate.fast_wipe(mode) }
}
