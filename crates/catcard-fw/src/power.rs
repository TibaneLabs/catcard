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
        *addr_of_mut!(GATE) = Some(*gate);
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
    let (hold, gate) = unsafe { (*addr_of_mut!(HOLD_CYCLES), *addr_of_mut!(GATE)) };
    // Never initialised, or the clock read gave nothing usable: stay inert. The hardware
    // failsafe still powers the device down on a long hold.
    if hold == 0 {
        return;
    }
    // Active-low with a pull-up: pressed reads 0.
    // SAFETY: reads one GPIO input register.
    let pressed = !unsafe { gpio::read(pin) };
    // SAFETY: as above -- foreground only, and the borrow ends with this function.
    let since = unsafe { &mut *addr_of_mut!(HELD_SINCE) };

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
                    crate::catlog!("power: held, powering down");
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
