//! The gateware watchdog.
//!
//! Once enabled it cannot be disabled, and Xous enables it: the bench unit reads back
//! `wdt_state = 0x9` (enabled, disarmed) with Xous running. Its period is 325,000,000
//! cycles of the FPGA's internal CFGMCLK, "approximately 65 MHz" with a +/-50% tolerance
//! by Xilinx's own figure, so anywhere from about 2.5 s to 7.5 s.
//! Source: betrusted gateware wdt.py (period default, enable latch, state bits) [C];
//! state and period read on the bench unit over the USB bridge, 2026-11-05 [C].
//!
//! When it fires it pulses the FPGA's global set/reset, which restarts the SoC into the
//! boot ROM and so back into whatever firmware is in flash. That is the recovery path a
//! hung image falls into, which is why the trap and panic handlers stop feeding it.

use crate::csr::{self, reg};

/// `wdt_watchdog` bit 0, `reset_wdt`: a write of 1 restarts the countdown. Bit 1 is
/// `enable`, which is never written here: this firmware does not arm the watchdog
/// itself, it only keeps an armed one quiet. Writing 0 to bit 1 does not disarm it.
/// Source: wdt.py `CSRField("reset_wdt", pulse=True)`, `CSRField("enable")` [C]; stock
/// usb_update.py `ping_wdt` writes exactly 1 [C].
const RESET_WDT: u32 = 1 << 0;

/// `wdt_state` bit 0, `enabled`. Source: wdt.py `self.state` fields [C].
const STATE_ENABLED: u32 = 1 << 0;

/// Restarts the watchdog countdown. Harmless when the watchdog was never enabled.
pub fn feed() {
    csr::write(reg::WDT_WATCHDOG, RESET_WDT);
}

/// Whether a previous firmware armed the watchdog.
pub fn enabled() -> bool {
    csr::read(reg::WDT_STATE) & STATE_ENABLED != 0
}
