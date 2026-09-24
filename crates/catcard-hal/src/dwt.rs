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

/// Whether `DWT_CTRL.CYCCNTENA` is set: one register read, against [`is_running`]'s
/// sixty-four-turn spin. Cheap enough to ask on every wait.
#[inline]
fn counting() -> bool {
    // SAFETY: DWT_CTRL is readable at any time; reading it has no side effects.
    unsafe { reg::read(fixed::DWT_CTRL) & DWT_CTRL_CYCCNTENA != 0 }
}

/// Fewest cycles one turn of a polling loop can cost, for sizing a turn budget.
///
/// A load, a compare and a branch is more than this on a Cortex-M4, and every wait here
/// has a peripheral read in the loop as well. So `cycles / CYCLES_PER_TURN` turns is
/// never *shorter* than `cycles` of real time, which is what a wait that has lost its
/// clock needs: it still ends, and not early.
const CYCLES_PER_TURN: u32 = 4;

/// Busy-wait for a number of CPU cycles.
///
/// **Bounded whatever the counter does.** With `CYCCNTENA` clear the counter reads a
/// constant and the cycle comparison never becomes true; the wait then spins a counted
/// number of turns instead. And even with the bit set a counter can stand still (`TRCENA`
/// dropped, a debugger holding the core's trace unit), so the cycle loop also carries a
/// turn budget of `n`: each turn is at least one cycle, so a counter that *is* running
/// always ends the wait first, and a stopped one ends it after `n` turns. On a healthy
/// board neither fallback is ever taken.
pub fn delay_cycles(n: u32) {
    if !counting() {
        for _ in 0..n / CYCLES_PER_TURN {
            core::hint::spin_loop();
        }
        return;
    }
    let start = cycles();
    let mut turns = n;
    while cycles().wrapping_sub(start) < n {
        if turns == 0 {
            return;
        }
        turns -= 1;
        core::hint::spin_loop();
    }
}

/// A bounded wait: a point on the cycle counter, plus a poll budget that ends the wait
/// even if the counter has stopped.
///
/// Drivers poll a status register until it says ready or the deadline passes. Written
/// against `cycles()` alone, that loop never ends on a stopped counter -- a dead panel or
/// a dead scanner module then holds the CPU forever instead of reporting a timeout. The
/// budget is the same guard [`delay_cycles`] carries: one poll of the budget per
/// [`expired`](Self::expired), sized so a running counter always fires first.
pub struct Deadline {
    until: u32,
    polls: u32,
}

impl Deadline {
    /// A deadline `cycles` from now.
    pub fn after(cycles_from_now: u32) -> Self {
        // With the counter running, the caller's loop costs more than one cycle a turn,
        // so `cycles_from_now` polls outlast the cycle deadline and never cut it short.
        // Without it, the polls are the whole clock, and each is at least
        // `CYCLES_PER_TURN` long.
        let polls = if counting() {
            cycles_from_now
        } else {
            cycles_from_now / CYCLES_PER_TURN
        };
        Deadline {
            until: cycles().wrapping_add(cycles_from_now),
            polls: polls.max(1),
        }
    }

    /// Whether the wait is over. Ask once per turn of the polling loop: every call spends
    /// one poll of the budget.
    pub fn expired(&mut self) -> bool {
        if self.polls == 0 {
            return true;
        }
        self.polls -= 1;
        cycles().wrapping_sub(self.until) < u32::MAX / 2
    }
}

/// Busy-wait roughly `ms` milliseconds, scaled to the live core clock.
///
/// Unlike a bare cycle count, this is a wall-clock delay whatever the bootloader set the
/// clock to -- the OLED reset needs real milliseconds, and a count calibrated for 4 MHz
/// is 20x too short at the 80 MHz the part actually runs at.
///
/// # Safety
/// Reads RCC to find the clock.
pub unsafe fn delay_ms(ms: u32) {
    // SAFETY: reads RCC.
    let per_ms = unsafe { crate::clock::hclk_hz() } / 1000;
    delay_cycles(ms.saturating_mul(per_ms));
}
