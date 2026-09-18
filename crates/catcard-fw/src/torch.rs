//! The LAMP key: the scanner's illumination LED, lit while the key is held.
//!
//! The lamp belongs to the QR module and is driven over its UART, not by a GPIO — there
//! is no pin to pull. So this opens the scanner's serial port and says so, which is why
//! a torch lives next to a barcode reader at all.
//!
//! # Why this does not do the scanner's bring-up
//!
//! Scanning needs the module reset, probed and configured: a ten-millisecond pulse, two
//! seconds of recovery and fourteen commands. Lighting the lamp needs none of it — only
//! a module that is awake and listening. So the lamp opens the port and talks, and the
//! two seconds stay where they belong, behind a screen that says what it is waiting for.
//!
//! The rate is the one thing that has to be right, and until a scan has run nothing knows
//! it. So an unlocated module is told twice, once at each rate; one of the two lands.
//! Once [`crate::qrscan`] has found the rate it records it here and this stops guessing.
//!
//! # Held, where stock toggles
//!
//! Stock's LAMP key toggles the lamp: press once for on, again for off. This lights it
//! while the key is down and puts it out when it is released, which is what was asked
//! for and is a deliberate departure -- worth knowing, because it is the one place the
//! key behaves differently from the device people may be used to.
//!
//! Source: hw-reference/qr.md §8 [C]

use catcard_hal::usart::Usart;
use catcard_qr::cmd;

use crate::keypad::Keypad;

/// Loop iterations one byte may take. Short: this runs inside the keypad poll, so it is
/// a budget for "the port is there and idle", not for waiting on a reply. Nothing here
/// waits on a reply at all.
const BYTE_BUDGET: u32 = 20_000;

/// The port, opened the first time the key is pressed.
///
/// Foreground only, like the rest of the UI's state. Held across presses because opening
/// it per press would put a GPIO and clock reconfiguration in the path of a key.
static mut PORT: Option<Usart> = None;
/// Whether the lamp is lit, so the command only goes out when the answer changes.
static mut LIT: bool = false;
/// The rate a scan found the module at, once one has.
static mut KNOWN_RATE: Option<u32> = None;

/// Record the rate a successful probe found, so the lamp stops guessing.
pub(crate) fn note_rate(rate: u32) {
    // SAFETY: foreground only; the write finishes within this statement.
    unsafe { *core::ptr::addr_of_mut!(KNOWN_RATE) = Some(rate) };
}

/// Give up the port, so the scanner screen can take it.
///
/// Two owners of one USART would each reconfigure it under the other. The scan screen
/// needs the port at a rate it chooses and with its own timing, so the lamp stands down
/// for the duration and reopens on the next press.
pub(crate) fn release() {
    // SAFETY: as above.
    unsafe {
        *core::ptr::addr_of_mut!(PORT) = None;
        *core::ptr::addr_of_mut!(LIT) = false;
    }
}

/// Follow the LAMP key: lit while it is held, out when it is let go.
///
/// Called from the keypad poll, which every waiting screen runs — the same place the
/// status bar reads its modifiers — so the key works wherever you are rather than only
/// on the scanner's screen.
pub(crate) fn note(pad: &Keypad) {
    let down = pad.held_mask() & (1 << catcard_ui::qwerty::KN_LAMP) != 0;
    // SAFETY: foreground only, single core.
    let lit = unsafe { *core::ptr::addr_of!(LIT) };
    if down == lit {
        return;
    }
    // SAFETY: as above.
    unsafe { *core::ptr::addr_of_mut!(LIT) = down };
    set(down);
}

/// Send the lamp command, at whichever rate the module might be listening at.
fn set(on: bool) {
    let Some(scanner) = catcard_board::BOARD.qr else {
        return;
    };
    // SAFETY: foreground only. The scanner's pins and USART2 are this firmware's, and
    // the scan screen releases them before it takes them.
    let port = unsafe { &mut *core::ptr::addr_of_mut!(PORT) };
    if port.is_none() {
        // No reset and no configuration: see the module docs. Opening the port does not
        // disturb a module that is asleep or mid-scan.
        // SAFETY: as above.
        *port = Some(unsafe { Usart::init(scanner.tx, scanner.rx, catcard_qr::BAUDS[0]) });
    }
    let Some(port) = port.as_mut() else { return };

    let body = if on { cmd::TORCH_ON } else { cmd::TORCH_OFF };
    let mut framed = [0u8; 32];
    let Ok(frame) = catcard_qr::wrap(catcard_qr::FID_COMMAND, body, &mut framed) else {
        return;
    };

    // SAFETY: reads a static that only the foreground writes.
    let rates = match unsafe { *core::ptr::addr_of!(KNOWN_RATE) } {
        Some(rate) => [rate, rate],
        None => catcard_qr::BAUDS,
    };
    let mut last = 0;
    for rate in rates {
        if rate != last {
            port.set_baud(rate);
            last = rate;
        }
        // Wake first: a module that has put itself to sleep hears nothing else. Bare,
        // and not waited on -- waking is near-instant and this is in a key's path.
        let _ = port.write(cmd::WAKE, BYTE_BUDGET);
        let _ = port.write(frame, BYTE_BUDGET);
        // Whatever it says back, including the bare acknowledgement, is not for us.
        port.drain(64, BYTE_BUDGET / 16);
    }
}
