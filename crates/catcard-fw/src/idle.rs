//! Logging out after a while with nobody touching it.
//!
//! The risk this answers is a device left unlocked on a desk. The PIN is in, the seed is
//! in SRAM, and anyone who walks past has a wallet. So after the owner's chosen quiet
//! period the firmware hands back to the bootloader, which wipes SRAM and asks for the
//! PIN again -- the same `logout` [`crate::power`] uses for the power button, with
//! [`LogoutMode::Logout`] rather than `PowerDown`, because this is a lock and not a
//! shutdown.
//!
//! # Where the two halves live
//!
//! **Keys** are noted in [`crate::pinentry::pressed_keys`], the single funnel every
//! screen's keypad read goes through, so there is no screen whose keys fail to count as
//! activity. **Time** is measured in [`tick`], called from [`crate::usbtask::pump`]
//! beside [`crate::power::tick`] and for the same reason: that is the one place that runs
//! whatever screen is up.
//!
//! # Measuring minutes with a 35-second counter
//!
//! `DWT_CYCCNT` wraps about every 35 s at 120 MHz, so a deadline cannot be a cycle count.
//! Each tick takes the gap since the previous one and adds it to a millisecond total.
//!
//! A gap longer than [`MAX_GAP_MS`] is counted as [`MAX_GAP_MS`] and no more. Nothing was
//! watching across it -- the firmware was stretching a seed with interrupts masked, or
//! inside a callgate -- and the counter may have wrapped in the middle, so the true
//! length is not known. **Under-counting is the safe direction**: the device logs out a
//! little late rather than in the middle of the very operation that caused the gap.
//!
//! # It can land anywhere a key wait can
//!
//! Exactly like the power button, which already powers a device down mid-anything. The
//! settings store survives losing power mid-write by construction, and the seed is in the
//! secure element, so the worst case is an operation that has to be started again. A
//! timeout that politely declined to fire while something was in progress would be a
//! timeout an attacker could hold open.

use core::ptr::addr_of_mut;

use catcard_callgate::{Callgate, abi::LogoutMode};
use catcard_hal::dwt;

/// The longest gap between two ticks that is counted at face value, in milliseconds.
///
/// One second: far longer than the natural poll period, far shorter than any timeout on
/// offer, and short enough that a wrapped cycle counter cannot be mistaken for real time.
const MAX_GAP_MS: u32 = 1_000;

/// The callgate, so a tick with no arguments can still reach the bootloader.
static mut GATE: Option<Callgate> = None;
/// CPU cycles in a millisecond, worked out at init. Zero means init never ran, which
/// leaves the timeout inert rather than guessing at the clock.
static mut CYCLES_PER_MS: u32 = 0;
/// The timeout while on external power, in milliseconds; zero is off.
static mut LIMIT_MS: u32 = 0;
/// The timeout while on the battery, in milliseconds; zero means [`LIMIT_MS`] applies
/// there too.
static mut BATTERY_LIMIT_MS: u32 = 0;
/// Milliseconds since the last keypress, as the ticks have added them up.
static mut QUIET_MS: u32 = 0;
/// Cycle count at the previous tick, or `None` when the count is starting fresh.
static mut LAST_TICK: Option<u32> = None;

/// Remember how to log out, and how fast this board's clock runs.
///
/// # Safety
/// Reads RCC. Call once, from the boot path, after the clocks are up.
pub unsafe fn init(gate: &Callgate) {
    // SAFETY: single-threaded boot path; this is the only writer and no tick has run.
    unsafe {
        *addr_of_mut!(CYCLES_PER_MS) = (catcard_hal::clock::hclk_hz() / 1_000).max(1);
        *addr_of_mut!(GATE) = Some(*gate);
    }
}

/// Put a timeout in force, in minutes. `None` for either is off.
///
/// Called by [`crate::prefs`] whenever the preferences change, which includes the load
/// just after login -- so nothing is armed until a wallet's own settings have said so.
pub fn arm(minutes: Option<u32>, battery_minutes: Option<u32>) {
    let ms = |m: Option<u32>| m.unwrap_or(0).saturating_mul(60_000);
    // SAFETY: foreground only, single core; the writes finish within this block.
    unsafe {
        *addr_of_mut!(LIMIT_MS) = ms(minutes);
        *addr_of_mut!(BATTERY_LIMIT_MS) = ms(battery_minutes);
        *addr_of_mut!(QUIET_MS) = 0;
        *addr_of_mut!(LAST_TICK) = None;
    }
    match minutes {
        Some(m) => crate::catlog!(
            "idle: logout after {} min ({:?} on battery)",
            m,
            battery_minutes
        ),
        None => crate::catlog!("idle: logout off"),
    }
}

/// A key was pressed: the quiet period starts again.
pub fn note_key() {
    // SAFETY: foreground only, single core; the writes finish within this block.
    unsafe {
        *addr_of_mut!(QUIET_MS) = 0;
        *addr_of_mut!(LAST_TICK) = Some(dwt::cycles());
    }
}

/// The timeout that applies right now, in milliseconds; zero is off.
///
/// On a board with a battery, a separate battery value takes over whenever the device is
/// running from it -- which is the state where it is most likely to be away from a desk.
/// With no battery value set, the one timeout covers both.
fn limit_ms() -> u32 {
    // SAFETY: foreground only; the reads finish within this statement.
    let (mains, battery) = unsafe { (*addr_of_mut!(LIMIT_MS), *addr_of_mut!(BATTERY_LIMIT_MS)) };
    #[cfg(feature = "board-q1")]
    if battery > 0 && crate::battery::source() == Some(crate::battery::Source::Battery) {
        return battery;
    }
    #[cfg(not(feature = "board-q1"))]
    let _ = battery;
    mains
}

/// Add the time since the last tick, and log out if the quiet period is up.
///
/// Never returns if it fires: the bootloader takes the CPU.
pub fn tick() {
    // SAFETY: foreground only; the read finishes within this statement.
    let per_ms = unsafe { *addr_of_mut!(CYCLES_PER_MS) };
    let limit = limit_ms();
    if per_ms == 0 || limit == 0 {
        return;
    }
    // SAFETY: foreground only, single core; the borrows end with this function.
    let last = unsafe { &mut *addr_of_mut!(LAST_TICK) };
    let quiet = unsafe { &mut *addr_of_mut!(QUIET_MS) };

    let now = dwt::cycles();
    let Some(prev) = *last else {
        // First tick since the timeout was armed or a key was pressed: this reading is
        // the start of the measurement, not a gap to be counted.
        *last = Some(now);
        return;
    };
    *last = Some(now);
    // `wrapping_sub` because DWT_CYCCNT wraps; a gap long enough to have wrapped is
    // indistinguishable from a short one, which is what the clamp is for.
    let gap_ms = (now.wrapping_sub(prev) / per_ms).min(MAX_GAP_MS);
    *quiet = quiet.saturating_add(gap_ms);
    if *quiet < limit {
        return;
    }
    // Do not fire again while the callgate is unreachable: without it nothing here can
    // log out, and re-deciding every tick would fill the log with the same line.
    *quiet = 0;
    // SAFETY: foreground only; the read finishes within this statement.
    let Some(gate) = (unsafe { *addr_of_mut!(GATE) }) else {
        return;
    };
    crate::catlog!("idle: {} ms quiet, logging out", limit);
    // The bootloader wipes all of SRAM on the way out, which is what takes the seed and
    // the cached PIN with it.
    //
    // SAFETY: nothing after this runs; the bootloader takes the CPU and asks for the PIN.
    unsafe { gate.logout(LogoutMode::Logout) }
}
