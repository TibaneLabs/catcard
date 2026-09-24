//! Boot-time failsafe reflash, for a dev build whose normal boot is broken.
//!
//! Hold CANCEL at power-on and the device drops straight into the USB recovery loop --
//! the same one [`crate::recovery`] runs, but reached **before** [`crate::boot::bring_up`]
//! has touched entropy, the secure elements or the display. That is exactly where a
//! validly-signed-but-broken image hangs, and on a locked (RDP=2) unit there is otherwise
//! no way back: the bootloader keeps launching the same broken image and offers no
//! recovery of its own. A host then sends the PIN and a new image over USB, as in
//! headless recovery.
//!
//! **Dev builds only** (`dev` + `usb-key-injection`). A shipped image compiles this out,
//! so a host cannot ask a stranger's device to reflash itself; the recovery loop it jumps
//! into already needs `usb-key-injection` to press keys. When CANCEL is not held the code
//! below does nothing but a ~200 ms key read and hands back to the ordinary boot, so a
//! healthy device is untouched.
//!
//! This runs on the boot path, so it must be proven on hardware before it is trusted --
//! but a bug in it can only strike when CANCEL is held: power-cycle without holding it and
//! the normal boot runs, so a failure here costs a power cycle, never a brick. That is the
//! same "cure with a power cycle" property the Debug-menu machinery relies on.

use catcard_callgate::Callgate;
use catcard_entropy::HmacDrbg;
use catcard_ui::keypad::{Event, KEYS, Key};

use crate::{BOARD, display, keypad, usbtask};

/// Is CANCEL held down right now? Read before anything else is brought up.
///
/// A purely polled read: [`GpioMatrix::init_pins`](keypad::GpioMatrix::init_pins)
/// configures the matrix GPIOs but wires **no** keypress interrupt, and
/// [`Keypad::scan`](catcard_ui::keypad::Keypad::scan) only drives rows and reads columns.
/// So this touches no EXTI, no NVIC and no RTC -- the edge path stays exactly as the
/// ordinary boot leaves it (untouched until `session`), and no keypress can raise an
/// interrupt during the bring-up that follows a not-held boot.
///
/// It scans for ~200 ms and asks for a steady hold, not a single sighting, so a glitch
/// cannot trip it and someone meaning it cannot miss it. A throwaway DRBG feeds the
/// scan-order scramble, which carries nothing here: no PIN is being typed, and the pool
/// does not exist yet. `session` re-initialises the matrix from scratch afterwards.
pub fn cancel_held_at_boot() -> bool {
    // SAFETY: single-threaded bring-up; nothing else has claimed the matrix yet, and the
    // ordinary boot below re-initialises it from scratch (edge path and all).
    let Some(mut matrix) = (unsafe { keypad::GpioMatrix::init_pins() }) else {
        return false;
    };
    let mut drbg = HmacDrbg::new(b"failsafe-boot-cancel", &[], &[]);
    let mut pad = keypad::Keypad::new();
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    // SAFETY: reads RCC only.
    let per_ms = (unsafe { catcard_hal::clock::hclk_hz() } / 1000).max(1);
    // Twenty samples at 10 ms, held through at least the last three: several times the
    // debounce, short enough that a deliberate hold never misses it.
    let mut held_for = 0u32;
    for _ in 0..20 {
        pad.scan(&mut matrix, &mut drbg, &mut events);
        held_for = if pad.holds(Key::Cancel) {
            held_for + 1
        } else {
            0
        };
        catcard_hal::dwt::delay_cycles(10 * per_ms);
    }
    held_for >= 3
}

/// Enter the failsafe reflash loop. Never returns except by rebooting into a new image.
///
/// USB comes up first, so the device is reachable even if the panel is the broken thing;
/// the panel message is best effort. Then the proven headless recovery loop takes over,
/// waiting for a host to send the PIN and an image.
pub fn run() -> ! {
    crate::catlog!("failsafe: CANCEL held at boot -- USB reflash, bring-up skipped");

    // SAFETY: single-threaded bring-up; this is the only writer of the USB state and no
    // reader exists until it returns.
    unsafe { usbtask::init(crate::session::serial()) };

    // Best effort on the glass. The panel is brought up exactly as the ordinary boot does
    // it; if it does not start, the log and the USB link still carry the state.
    // SAFETY: nothing else has claimed the panel on this path.
    if let Some(mut panel) = unsafe { display::init() } {
        crate::menu::message(
            &mut panel,
            "Recovery",
            "send firmware over USB",
            "power off to cancel",
        );
    }

    // SAFETY: we are running on BOARD; `discover` validates the published entry address
    // before anything can branch to it.
    match unsafe { Callgate::discover(&BOARD) }.ok() {
        // The full pre-login USB install path: PIN in, offer, approve, `gate 18/7`, reboot.
        Some(gate) => crate::recovery::headless(gate),
        None => {
            // Without the callgate nothing can log in or install. Keep USB serviced so the
            // device is still reachable and its log readable, rather than going dark.
            crate::catlog!("failsafe: no callgate -- USB is up, but nothing can install");
            loop {
                let _ = usbtask::pump();
                catcard_hal::dwt::delay_cycles(usbtask::IDLE_PAUSE_CYCLES);
            }
        }
    }
}
