//! DWT cycle counter — a free-running CPU-clock counter.
//!
//! Two uses:
//!
//! - Cheap microsecond-ish timing for driver delays.
//! - **Timing jitter**: sampling `CYCCNT` at the moment a user presses a key captures
//!   a few genuinely unpredictable low bits per press. It is a weak source and is
//!   credited as such by [`catcard_entropy::Source::UserTiming`] — it supplements the
//!   TRNGs, it never substitutes for them.
//!
//! Source: `hw-reference/platform.md §2` [C] for the addresses; ARMv7-M ARM §C1.8 for
//! the register definitions.

use catcard_board::memory::fixed;

use crate::reg;

const DEMCR_TRCENA: u32 = 1 << 24;
const DWT_CTRL_CYCCNTENA: u32 = 1 << 0;

/// Enable the cycle counter.
///
/// # Safety
/// Writes the debug control registers. Harmless, but it does enable the trace unit.
pub unsafe fn enable() {
    unsafe {
        reg::set_bits(fixed::DEMCR, DEMCR_TRCENA);
        reg::write(fixed::DWT_CYCCNT, 0);
        reg::set_bits(fixed::DWT_CTRL, DWT_CTRL_CYCCNTENA);
    }
}

/// Current cycle count. Wraps every 2^32 cycles.
#[inline]
pub fn cycles() -> u32 {
    // SAFETY: DWT_CYCCNT is a read-only counter; reading it has no side effects.
    unsafe { reg::read(fixed::DWT_CYCCNT) }
}

/// Whether the counter is actually running.
///
/// A stopped counter returns a constant, which would make every "timing" sample
/// identical — worth checking before crediting anything to it.
pub fn is_running() -> bool {
    let a = cycles();
    for _ in 0..64 {
        core::hint::spin_loop();
    }
    cycles() != a
}

/// Busy-wait for a number of CPU cycles.
pub fn delay_cycles(n: u32) {
    let start = cycles();
    while cycles().wrapping_sub(start) < n {
        core::hint::spin_loop();
    }
}
