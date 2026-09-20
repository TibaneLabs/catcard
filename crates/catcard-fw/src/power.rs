//! The power button, on the board that has one.
//!
//! `PWR_BTN=PB12` is active-low with a pull-up, so a press reads 0. Stock arms a
//! falling-edge interrupt and schedules a check **500 ms** later: still held means power
//! down, released means it was a tap and nothing happens. This polls instead -- the whole
//! front panel here is polled -- but the rule is the same, and it is why a quick tap does
//! nothing.
//!
//! **Cutting power is the bootloader's job, not ours.** `show_logout(3)` wipes all SRAM
//! and drives `TURN_OFF=PC0` into the board's XC6192 power-management IC. So nothing here
//! touches PC0, and the one thing about that pin we could never confirm -- which level
//! actually cuts power -- stays inside the bootloader where it already lives.
//!
//! Only the Q1 can power itself off; mk3/mk4/mk5 are USB-powered, have no button, and
//! nothing to switch off. That is a board-table pin rather than a `cfg` so the same code
//! is simply inert on them.
//!
//! There is also a hardware failsafe with no firmware involvement: holding the button
//! about 5 s makes the PMIC cut power whatever the firmware is doing. That is what still
//! worked while this was unimplemented, and it keeps working if this ever wedges.
//!
//! Source: hw-reference/power.md §"Power-off / shutdown (Q1)" [C]

use core::ptr::addr_of_mut;

use catcard_board::BOARD;
use catcard_callgate::{Callgate, abi::LogoutMode};
use catcard_hal::dwt;
use catcard_hal::gpio::{self, Mode, OutputType, Pull, Speed};

/// How long the button must be held before it powers the device down.
///
/// Matches stock's 500 ms. Short enough to feel deliberate rather than slow, long enough
/// that brushing the key does not drop a wallet mid-signing.
const HOLD_MS: u32 = 500;

/// The callgate, so a poll with no arguments can still reach the bootloader.
static mut GATE: Option<Callgate> = None;
/// [`HOLD_MS`] converted to CPU cycles at init, since the poll has no clock of its own.
/// Zero means init never ran, which leaves the button inert rather than guessing.
static mut HOLD_CYCLES: u32 = 0;
/// Cycle count when the current press started, or `None` while the button is up.
static mut HELD_SINCE: Option<u32> = None;
/// Cycle count of the previous poll, to tell a held button from an unwatched one.
static mut LAST_POLL: Option<u32> = None;
/// Whether the button has been seen *up* since the firmware started watching it.
///
/// **This is how a Q1 gets switched on.** The button is held to power the device up, so
/// it is still down when the firmware boots -- and a poll that reads a level rather than
/// an edge counts that as a press that began the moment it started looking. The device
/// then switched itself off the instant it reached the PIN prompt, which is simply the
/// first screen that waits long enough to poll.
///
/// Stock arms a *falling-edge* interrupt, which is a transition and cannot fire for a
/// button that was already down. This is the same rule for a poll: nothing counts until
/// the button has been let go once.
static mut SEEN_UP: bool = false;

/// The longest gap between two polls that still counts as continuous observation.
///
/// A hold means the button was down *for* half a second, and the only evidence of that
/// is having looked and found it down throughout. Between two polls far enough apart,
/// nothing was looking, and a press seen at each end could as easily be two taps -- or
/// one tap and one bad reading.
///
/// It matters because the gaps are not all small. Stretching a seed is about 1.7 s of
/// masked hashing with the screen stepped between slices and nothing polling the front
/// panel, and a device that powers itself off in the middle of reading a wallet is what
/// this rule is here to stop. 100 ms is comfortably longer than the poll's natural
/// period and far shorter than any of the long operations.
const CONTINUITY_MS: u32 = 100;
/// [`CONTINUITY_MS`] in cycles, alongside [`HOLD_CYCLES`].
static mut CONTINUITY_CYCLES: u32 = 0;

/// Configure the button and remember how to power down.
///
/// # Safety
/// Claims `BOARD.pwr_btn` and reads RCC. Nothing else drives that pin.
pub unsafe fn init(gate: &Callgate) {
    let Some(pin) = BOARD.pwr_btn else { return };
    // SAFETY: the pin belongs to the power button alone, and the caller is the boot path.
    unsafe {
        gpio::enable_port(pin.port);
        // The board pulls it up; asking for the internal pull-up too costs nothing and
        // means a press is unambiguous even if the external one is ever depopulated.
        gpio::configure(pin, Mode::Input, OutputType::PushPull, Pull::Up, Speed::Low);
        let hz = catcard_hal::clock::hclk_hz();
        *addr_of_mut!(HOLD_CYCLES) = (hz / 1_000).saturating_mul(HOLD_MS);
        *addr_of_mut!(CONTINUITY_CYCLES) = (hz / 1_000).saturating_mul(CONTINUITY_MS);
        *addr_of_mut!(GATE) = Some(*gate);
        // Not armed yet, whatever the pin reads now: see `SEEN_UP`.
        *addr_of_mut!(SEEN_UP) = false;
    }
    crate::catlog!("power: button armed, {} ms hold", HOLD_MS);
}

/// Poll the button. Never returns if it has been held long enough.
///
/// Called from [`crate::usbtask::pump`], which every waiting screen calls -- the same
/// reasoning that puts the USB activity light there. A button that only worked on the
/// main menu would be a button that does not work.
pub fn tick() {
    let Some(pin) = BOARD.pwr_btn else { return };
    // SAFETY: the foreground is single-threaded and every caller is the foreground poll;
    // each read finishes within this statement.
    let (hold, gate, continuity) = unsafe {
        (
            *addr_of_mut!(HOLD_CYCLES),
            *addr_of_mut!(GATE),
            *addr_of_mut!(CONTINUITY_CYCLES),
        )
    };
    // Never initialised, or the clock read gave nothing usable: stay inert. The hardware
    // failsafe still powers the device down on a long hold.
    if hold == 0 {
        return;
    }
    // Active-low with a pull-up: pressed reads 0.
    // SAFETY: reads one GPIO input register.
    let pressed = !unsafe { gpio::read(pin) };

    // The button that turned the device on is still down. Until it has been released
    // once, there is no press here to measure -- only the one that is still ending.
    // SAFETY: foreground only, and the borrow ends with this statement.
    let seen_up = unsafe { &mut *addr_of_mut!(SEEN_UP) };
    if !*seen_up {
        if !pressed {
            *seen_up = true;
            crate::catlog!("power: button released, now live");
        }
        return;
    }
    // SAFETY: as above -- foreground only, and the borrow ends with this function.
    let since = unsafe { &mut *addr_of_mut!(HELD_SINCE) };
    // SAFETY: as above.
    let last = unsafe { &mut *addr_of_mut!(LAST_POLL) };

    // How long since anything last looked at the button. A press cannot be counted as
    // *held* across a gap nobody was watching: the screen may have spent that time
    // stretching a seed with interrupts masked, and the button may have been released
    // and pressed again, or never really pressed at all.
    let now_cycles = dwt::cycles();
    let watched = match *last {
        Some(prev) => now_cycles.wrapping_sub(prev) <= continuity,
        None => false,
    };
    *last = Some(now_cycles);
    if !watched {
        // Start the measurement again from this reading, which is the first one that can
        // be vouched for. A genuine hold simply takes its half second from here.
        *since = None;
    }

    if !pressed {
        // Released: a tap, so forget it. This is the half that makes the hold deliberate.
        *since = None;
        return;
    }
    let now = dwt::cycles();
    match *since {
        None => *since = Some(now),
        Some(started) => {
            // `wrapping_sub` because DWT_CYCCNT wraps every 2^32 cycles -- about 35 s at
            // 120 MHz, far longer than the hold being measured.
            if now.wrapping_sub(started) >= hold {
                if let Some(gate) = gate {
                    crate::catlog!("power: held {} ms, powering down", HOLD_MS);
                    // The bootloader wipes all of SRAM on the way out, which is what
                    // takes any seed and the cached PIN with it.
                    //
                    // SAFETY: nothing after this runs; the bootloader cuts power.
                    unsafe { gate.logout(LogoutMode::PowerDown) }
                }
                // No callgate means nothing can cut power. Forget the press rather than
                // re-deciding on every poll.
                *since = None;
            }
        }
    }
}
