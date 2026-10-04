//! Logging out after a while with nobody touching it.
//!
//! The risk this answers is a device left unlocked on a desk. The PIN is in, the seed is
//! in SRAM, and anyone who walks past has a wallet. So after the owner's chosen quiet
//! period the firmware hands back to the bootloader, which wipes SRAM and asks for the
//! PIN again -- the same `logout` [`crate::power`] uses for the power button, with
//! [`LogoutMode::Logout`] rather than `PowerDown`, because this is a lock and not a
//! shutdown.
//!
//! # On battery: powering off (Q1)
//!
//! Separately, and as stock does, a Q1 running on its batteries **powers itself off**
//! after its own quiet period -- ten minutes unless the owner chose otherwise, from 30 s
//! to 4 h or never. That one is device-wide and runs **before login too**: the value
//! lives in the pre-login settings ([`catcard_settings::prelogin::BATT_OFF`]), read on
//! the boot path, because a device left at its PIN prompt drains its batteries just as
//! surely as one left at the menu. It goes through the power button's own path,
//! [`crate::power::power_down`]. It holds off while the QR scanner is mid-scan
//! ([`Scanning`]) or while a progress bar has moved in the last minute
//! ([`note_progress`]): a device reading a long animated code, or grinding through a
//! long job, is in use even with no key pressed.
//! Source: hw-reference/power.md §"Battery idle auto-power-off (Q1)" [C]
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
#[cfg(feature = "board-q1")]
use core::sync::atomic::AtomicBool;
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
/// The logout timeout, in milliseconds; zero is off.
static LIMIT_MS: AtomicU32 = AtomicU32::new(0);
/// The on-battery power-off, in milliseconds; zero is never. Stock's default until the
/// pre-login settings say otherwise, so a device whose settings cannot be read still
/// turns itself off rather than draining its cells.
/// Source: hw-reference/power.md §"Battery idle auto-power-off (Q1)" -- "Default
/// `batt_to` = 10 min" [C]
#[cfg(feature = "board-q1")]
static BATTERY_OFF_MS: AtomicU32 =
    AtomicU32::new(catcard_settings::prelogin::BATT_OFF_DEFAULT_SECONDS * 1_000);
/// Milliseconds since a progress bar last moved, as the ticks add them up. Starts past
/// [`PROGRESS_HOLD_MS`]: nothing has moved yet.
#[cfg(feature = "board-q1")]
static PROGRESS_QUIET_MS: AtomicU32 = AtomicU32::new(PROGRESS_HOLD_MS);
/// A progress bar that moved this recently holds the power-off. Source: power.md
/// §"Battery idle auto-power-off (Q1)" -- "a progress bar updated in the last 60 s" [C]
#[cfg(feature = "board-q1")]
const PROGRESS_HOLD_MS: u32 = 60_000;
/// Whether the QR scanner is mid-scan; see [`Scanning`].
#[cfg(feature = "board-q1")]
static SCANNING: AtomicBool = AtomicBool::new(false);
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

/// Put the logout timeout in force, in minutes. `None` is off.
///
/// Called by [`crate::prefs`] whenever the preferences change, which includes the load
/// just after login -- so nothing is armed until a wallet's own settings have said so.
/// The on-battery power-off is [`arm_battery_off`], and is not touched here.
pub fn arm(minutes: Option<u32>) {
    // Three separate stores, and a tick on the USB task can land between any two of
    // them; the worst it sees is the old limit against a fresh zero, which fires
    // nothing. See "Two tasks, one counter" above.
    LIMIT_MS.store(
        minutes.unwrap_or(0).saturating_mul(60_000),
        Ordering::Relaxed,
    );
    QUIET_MS.store(0, Ordering::Relaxed);
    LAST_TICK.store(NO_TICK, Ordering::Relaxed);
    match minutes {
        Some(m) => crate::catlog!("idle: logout after {} min", m),
        None => crate::catlog!("idle: logout off"),
    }
}

/// Put the on-battery power-off in force, in seconds; `None` is never.
///
/// From the pre-login settings on the boot path, and again when the owner changes it.
/// Does not restart the quiet period: choosing a value is itself a keypress.
#[cfg(feature = "board-q1")]
pub fn arm_battery_off(seconds: Option<u32>) {
    BATTERY_OFF_MS.store(
        seconds.unwrap_or(0).saturating_mul(1_000),
        Ordering::Relaxed,
    );
    crate::catlog!("idle: on battery, power off after {:?} s", seconds);
}

/// A progress bar moved: hold the on-battery power-off for the next minute.
///
/// Cheap -- one store -- and harmless on the boards with no battery, so the progress
/// screens call it without asking which board they are on.
pub fn note_progress() {
    #[cfg(feature = "board-q1")]
    PROGRESS_QUIET_MS.store(0, Ordering::Relaxed);
}

/// Held while the QR scanner is mid-scan, so the on-battery power-off waits for it.
///
/// Dropping it ends the hold, however the scan ends -- a code, a cancel, a fault.
#[cfg(feature = "board-q1")]
pub struct Scanning(());

#[cfg(feature = "board-q1")]
impl Scanning {
    /// The scanner is reading from now until this is dropped.
    pub fn begin() -> Self {
        SCANNING.store(true, Ordering::Relaxed);
        Scanning(())
    }
}

#[cfg(feature = "board-q1")]
impl Drop for Scanning {
    fn drop(&mut self) {
        SCANNING.store(false, Ordering::Relaxed);
        // A scan that ended was someone holding a code up, or cancelling: either way,
        // someone is there. Without this a long scan with no key pressed would end
        // straight into a power-off.
        note_key();
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

/// The on-battery power-off that applies right now, in milliseconds; zero is none.
///
/// Zero off battery, while the scanner is mid-scan, and while a progress bar has moved
/// in the last minute.
#[cfg(feature = "board-q1")]
fn battery_off_ms() -> u32 {
    let limit = BATTERY_OFF_MS.load(Ordering::Relaxed);
    if limit == 0
        || SCANNING.load(Ordering::Relaxed)
        || PROGRESS_QUIET_MS.load(Ordering::Relaxed) < PROGRESS_HOLD_MS
        || crate::battery::source() != Some(crate::battery::Source::Battery)
    {
        return 0;
    }
    limit
}

/// Add the time since the last tick, and log out -- or, on battery, power off -- if the
/// quiet period is up.
///
/// Never returns if it fires: the bootloader takes the CPU.
pub fn tick() {
    // SAFETY: written once by `init` before any task existed, and only read since.
    let per_ms = unsafe { *addr_of!(CYCLES_PER_MS) };
    let limit = LIMIT_MS.load(Ordering::Relaxed);
    #[cfg(feature = "board-q1")]
    let off = battery_off_ms();
    #[cfg(not(feature = "board-q1"))]
    let off = 0u32;
    // The progress clock runs whether or not anything is armed, so a bar that moved
    // just before the device went onto its battery still holds the power-off.
    #[cfg(feature = "board-q1")]
    let progress_running = PROGRESS_QUIET_MS.load(Ordering::Relaxed) < PROGRESS_HOLD_MS;
    #[cfg(not(feature = "board-q1"))]
    let progress_running = false;
    if per_ms == 0 || (limit == 0 && off == 0 && !progress_running) {
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
    // `fetch_update` is deprecated from Rust 1.99 in favour of `try_update`, which the
    // 1.89 this workspace supports does not have; the two are the same operation.
    #[cfg(feature = "board-q1")]
    #[allow(deprecated)]
    let _ = PROGRESS_QUIET_MS.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |q| {
        Some(q.saturating_add(gap_ms).min(PROGRESS_HOLD_MS))
    });
    // A read-modify-write, so a keypress's zero on either side of it is kept: stored
    // before, the total is this one gap; stored after, it is zero. Saturating, because
    // a timeout set to the largest value the preferences allow must not wrap to nothing.
    #[allow(deprecated)]
    let before = QUIET_MS
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |q| {
            Some(q.saturating_add(gap_ms))
        })
        .unwrap_or_else(|q| q);
    let quiet = before.saturating_add(gap_ms);
    // On battery, the power-off first when both are due: it is the stronger of the two,
    // and a logout would only bring the device back up at its PIN prompt, on batteries.
    if off > 0 && quiet >= off {
        QUIET_MS.store(0, Ordering::Relaxed);
        crate::catlog!("idle: {} ms quiet on battery, powering off", off);
        crate::power::power_down();
        return;
    }
    if limit == 0 || quiet < limit {
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
    unsafe { crate::gatecall::logout(&gate, LogoutMode::Logout) }
}
