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
//! # Two tasks, one counter
//!
//! Under the kernel [`note_key`] runs on the UI task and [`tick`] on the USB task,
//! preempted at any instruction, so everything the two of them touch is an atomic.
//! `Relaxed` is enough: on one core every store is visible in program order across a
//! context switch, and there is nothing else to order it against. What a race can cost
//! is bounded and in the safe direction -- a tick that read `LAST_TICK` just before a
//! keypress reset it adds one gap, at most [`MAX_GAP_MS`], to a `QUIET_MS` that was just
//! zeroed. A second, against a timeout measured in minutes, and a reset is never lost:
//! the add is a read-modify-write, so a zero stored on either side of it survives it.
//!
//! # It can land anywhere a key wait can
//!
//! Exactly like the power button, which already powers a device down mid-anything. The
//! settings store survives losing power mid-write by construction, and the seed is in the
//! secure element, so the worst case is an operation that has to be started again. A
//! timeout that politely declined to fire while something was in progress would be a
//! timeout an attacker could hold open.

use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{AtomicU32, Ordering};

use catcard_callgate::{Callgate, abi::LogoutMode};
use catcard_hal::dwt;

/// The longest gap between two ticks that is counted at face value, in milliseconds.
///
/// One second: far longer than the natural poll period, far shorter than any timeout on
/// offer, and short enough that a wrapped cycle counter cannot be mistaken for real time.
const MAX_GAP_MS: u32 = 1_000;

/// The callgate, so a tick with no arguments can still reach the bootloader.
///
/// Written once by [`init`] on the boot path, before any task exists, and only read
/// after -- which is why it and [`CYCLES_PER_MS`] can stay plain statics while the
/// counters below cannot.
static mut GATE: Option<Callgate> = None;
/// CPU cycles in a millisecond, worked out at init. Zero means init never ran, which
/// leaves the timeout inert rather than guessing at the clock. Written once, like
/// [`GATE`].
static mut CYCLES_PER_MS: u32 = 0;
/// The timeout while on external power, in milliseconds; zero is off.
static LIMIT_MS: AtomicU32 = AtomicU32::new(0);
/// The timeout while on the battery, in milliseconds; zero means [`LIMIT_MS`] applies
/// there too.
static BATTERY_LIMIT_MS: AtomicU32 = AtomicU32::new(0);
/// Milliseconds since the last keypress, as the ticks have added them up.
static QUIET_MS: AtomicU32 = AtomicU32::new(0);
/// Cycle count at the previous tick, or [`NO_TICK`] when the count is starting fresh.
static LAST_TICK: AtomicU32 = AtomicU32::new(NO_TICK);
/// The [`LAST_TICK`] value that means "no reading yet". A real reading that happens to
/// equal it is taken as none, which restarts the measurement one tick late -- once in
/// 2^32 ticks, and in the under-counting direction.
const NO_TICK: u32 = u32::MAX;

/// Remember how to log out, and how fast this board's clock runs.
///
/// # Safety
/// Reads RCC. Call once, from the boot path, after the clocks are up and before the
/// kernel starts.
pub unsafe fn init(gate: &Callgate) {
    // SAFETY: the boot path, before any task exists: this is the only writer these two
    // statics ever have, and no tick has run.
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
    // Four separate stores, and a tick on the USB task can land between any two of
    // them; the worst it sees is the old limit against a fresh zero, which fires
    // nothing. See "Two tasks, one counter" above.
    LIMIT_MS.store(ms(minutes), Ordering::Relaxed);
    BATTERY_LIMIT_MS.store(ms(battery_minutes), Ordering::Relaxed);
    QUIET_MS.store(0, Ordering::Relaxed);
    LAST_TICK.store(NO_TICK, Ordering::Relaxed);
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
///
/// Called on the UI task while [`tick`] runs on the USB task. Two relaxed stores: a tick
/// between them measures from the new reading against the old total or the reverse, and
/// either way what it adds is one gap, bounded by [`MAX_GAP_MS`].
pub fn note_key() {
    QUIET_MS.store(0, Ordering::Relaxed);
    LAST_TICK.store(dwt::cycles(), Ordering::Relaxed);
}

/// The timeout that applies right now, in milliseconds; zero is off.
///
/// On a board with a battery, a separate battery value takes over whenever the device is
/// running from it -- which is the state where it is most likely to be away from a desk.
/// With no battery value set, the one timeout covers both.
fn limit_ms() -> u32 {
    let mains = LIMIT_MS.load(Ordering::Relaxed);
    let battery = BATTERY_LIMIT_MS.load(Ordering::Relaxed);
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
    // SAFETY: written once by `init` before any task existed, and only read since.
    let per_ms = unsafe { *addr_of!(CYCLES_PER_MS) };
    let limit = limit_ms();
    if per_ms == 0 || limit == 0 {
        return;
    }

    let now = dwt::cycles();
    let prev = LAST_TICK.swap(now, Ordering::Relaxed);
    if prev == NO_TICK {
        // First tick since the timeout was armed or a key was pressed: this reading is
        // the start of the measurement, not a gap to be counted.
        return;
    }
    // `wrapping_sub` because DWT_CYCCNT wraps; a gap long enough to have wrapped is
    // indistinguishable from a short one, which is what the clamp is for.
    let gap_ms = (now.wrapping_sub(prev) / per_ms).min(MAX_GAP_MS);
    // A read-modify-write, so a keypress's zero on either side of it is kept: stored
    // before, the total is this one gap; stored after, it is zero. Saturating, because
    // a timeout set to the largest value the preferences allow must not wrap to nothing.
    let before = QUIET_MS
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |q| {
            Some(q.saturating_add(gap_ms))
        })
        .unwrap_or_else(|q| q);
    if before.saturating_add(gap_ms) < limit {
        return;
    }
    // Do not fire again while the callgate is unreachable: without it nothing here can
    // log out, and re-deciding every tick would fill the log with the same line.
    QUIET_MS.store(0, Ordering::Relaxed);
    // SAFETY: written once by `init` before any task existed, and only read since.
    let Some(gate) = (unsafe { *addr_of!(GATE) }) else {
        return;
    };
    crate::catlog!("idle: {} ms quiet, logging out", limit);
    // The bootloader wipes all of SRAM on the way out, which is what takes the seed and
    // the cached PIN with it.
    //
    // SAFETY: nothing after this runs; the bootloader takes the CPU and asks for the PIN.
    unsafe { gate.logout(LogoutMode::Logout) }
}
