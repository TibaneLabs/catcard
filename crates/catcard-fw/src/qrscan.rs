//! Reading a QR code with the Q1's scanner.
//!
//! The module is a decoded-barcode engine on USART2, not a camera: it images and decodes
//! on its own and hands back plain text. [`catcard_qr`] holds the wire format, tested
//! against the reference's own worked example; [`catcard_hal::usart`] holds the port.
//! This is the sequence between them, and the screen.
//!
//! # Why it probes
//!
//! The module's baud rate is whatever it was left at, and nothing on the board says
//! which. So a version query goes out at each rate in turn until one answers, and then
//! the link is locked to 57600. Stock does the same, and bounds its attempts; an
//! unbounded probe on a module that is unplugged or asleep is a device that stops.
//!
//! Source: hw-reference/input.md §"QR scanner (Q1)" [C]

use catcard_hal::usart::Usart;
use catcard_qr::{cmd, wrap};

use crate::menu;
use crate::ui::Ui;

/// Loop iterations a single byte may take. At 9600 baud a byte is about a millisecond,
/// and this is generous against that rather than tuned to it: the cost of being wrong
/// high is a slower failure, and of being wrong low is a working scanner called broken.
const BYTE_BUDGET: u32 = 400_000;

/// How long the reset line is held low: 10 ms, per the reference.
const RESET_MS: u32 = 10;
/// And how long the module needs afterwards before it will answer: two seconds.
const RECOVERY_MS: u32 = 2_000;

/// Attempts at finding the baud rate. Stock uses five; past that the module is not
/// there, and trying forever would be a screen that never comes back.
const PROBE_TRIES: usize = 5;

/// The longest decoded QR this will hand back.
///
/// The module can produce a version-40 code, which is more than any screen can show and
/// more than the 8 KB stack a screen gets. What arrives past this is dropped, and the
/// screen says the code was too long rather than showing a truncated prefix of it --
/// half an address is not an address.
pub const MAX_TEXT: usize = 512;

/// Why a scan did not produce anything.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Fault {
    /// This board has no scanner in its table.
    NoScanner,
    /// No rate answered the version query, so nothing is listening.
    NotFound,
    /// It answered, but would not take the setup.
    SetupRefused,
    /// Nothing was read before the owner gave up.
    Cancelled,
    /// A code was read that is longer than [`MAX_TEXT`].
    TooLong,
}

/// Send one framed command and wait for its acknowledgement.
///
/// **Silence is the negative.** There is no NACK on this wire, so not hearing back is
/// the failure, and the budget is what turns that into an answer.
fn command(port: &mut Usart, body: &[u8]) -> bool {
    let mut out = [0u8; 64];
    let Ok(frame) = wrap(catcard_qr::FID_COMMAND, body, &mut out) else {
        return false;
    };
    port.flush_input();
    if port.write(frame, BYTE_BUDGET).is_err() {
        return false;
    }
    let mut reply = [0u8; 32];
    let n = port.read(&mut reply, BYTE_BUDGET);
    matches!(catcard_qr::unwrap(&reply[..n]), Ok(f) if catcard_qr::is_ack(&f))
}

/// Find the rate the module is listening at, and lock the link to 57600.
fn find(port: &mut Usart) -> Result<(), Fault> {
    for _ in 0..PROBE_TRIES {
        for rate in catcard_qr::BAUDS {
            port.set_baud(rate);
            if command(port, cmd::VERSION) {
                // Found it. Ask for the fast rate and follow it there; if the module
                // does not take the change, carry on at the rate that answered rather
                // than moving to one nothing is listening at.
                if rate != 57_600 && command(port, cmd::BAUD_57600) {
                    port.set_baud(57_600);
                }
                return Ok(());
            }
        }
    }
    Err(Fault::NotFound)
}

/// Put the module into a known state, then ask it to scan.
fn setup(port: &mut Usart) -> Result<(), Fault> {
    // Factory reset first, so this does not inherit whatever it was left configured as.
    // CRLF is what marks the end of a decoded code, so it is the one that must land.
    for body in [
        cmd::FACTORY_RESET,
        cmd::APPEND_CRLF,
        cmd::STATUS_LED,
        cmd::SAVE,
    ] {
        if !command(port, body) {
            return Err(Fault::SetupRefused);
        }
    }
    Ok(())
}

/// Read one decoded code, or stop when the owner cancels.
///
/// A decoded QR does not arrive framed: setup asked for plain text ending in CRLF, so
/// this reads bytes until that terminator. Anything the module cannot express as text
/// arrives as its own message, which is a *decoded answer* and not the code's contents.
fn read_code(port: &mut Usart, ui: &mut Ui<'_>, out: &mut [u8]) -> Result<usize, Fault> {
    let mut n = 0;
    let mut overflowed = false;
    loop {
        let mut byte = [0u8; 1];
        if port.read(&mut byte, BYTE_BUDGET / 8) == 1 {
            match byte[0] {
                b'\r' => {}
                b'\n' if n > 0 || overflowed => {
                    return if overflowed {
                        Err(Fault::TooLong)
                    } else {
                        Ok(n)
                    };
                }
                b'\n' => {}
                b => {
                    if n < out.len() {
                        out[n] = b;
                        n += 1;
                    } else {
                        overflowed = true;
                    }
                }
            }
            continue;
        }
        // Nothing arrived this time round: give the owner a chance to leave. The scan is
        // continuous, so without this the only way out would be the power button.
        if menu::cancel_pressed(ui) {
            return Err(Fault::Cancelled);
        }
    }
}

/// Bring the scanner up, read one code, and put it back to sleep.
fn scan(ui: &mut Ui<'_>, out: &mut [u8]) -> Result<usize, Fault> {
    let scanner = catcard_board::BOARD.qr.ok_or(Fault::NoScanner)?;

    menu::blocking_screen(ui.panel, "Scan QR", "waking the scanner");
    // SAFETY: the board table's scanner pins, and USART2, belong to this screen: nothing
    // else in the firmware touches either, and the menu waits for this to return.
    let mut port = unsafe {
        catcard_hal::usart::pulse_reset(scanner.reset, ms_cycles(RESET_MS));
        catcard_hal::dwt::delay_cycles(ms_cycles(RECOVERY_MS));
        Usart::init(scanner.tx, scanner.rx, catcard_qr::BAUDS[0])
    };

    find(&mut port)?;
    setup(&mut port)?;

    menu::blocking_screen(ui.panel, "Scan QR", "point it at a code");
    if !command(&mut port, cmd::SCAN_START) {
        return Err(Fault::SetupRefused);
    }
    let read = read_code(&mut port, ui, out);
    // Stop scanning and put the illumination out whatever happened, so a cancelled scan
    // does not leave the module running and the lamp on.
    let _ = command(&mut port, cmd::SCAN_STOP);
    let _ = command(&mut port, cmd::TORCH_OFF);
    read
}

/// Milliseconds as CPU cycles.
fn ms_cycles(ms: u32) -> u32 {
    // SAFETY: reads RCC only.
    let hz = unsafe { catcard_hal::clock::hclk_hz() };
    (hz / 1_000).saturating_mul(ms)
}

/// The Scan QR screen: read a code and show what it said.
pub(crate) fn screen(ui: &mut Ui<'_>) {
    let mut text = [0u8; MAX_TEXT];
    match scan(ui, &mut text) {
        Ok(n) => show(ui, &text[..n]),
        Err(Fault::Cancelled) => {}
        Err(why) => {
            menu::message(ui.panel, "Scan QR", describe(why), "any key to go back");
            menu::wait_for_any_key(ui);
        }
    }
}

/// Show what was read.
///
/// Only shown, for now: nothing here decides that a string is an address or a PSBT and
/// acts on it. Reading a code and acting on one are different features, and the second
/// is where a wrong guess sends money somewhere.
fn show(ui: &mut Ui<'_>, raw: &[u8]) {
    use catcard_ui::scroll::Line as Row;

    let text = core::str::from_utf8(raw).unwrap_or("(not text)");
    let text = if raw == catcard_qr::UNSUPPORTED {
        // The module's way of saying it read a code that held bytes rather than
        // characters. Passing it on as the contents would be a lie about what is there.
        "the code was not text"
    } else {
        text
    };
    let mut rows: heapless::Vec<Row, 4> = heapless::Vec::new();
    let _ = rows.push(Row::title("Scanned"));
    let _ = rows.push(Row::body(text).small());
    let _ = menu::show_doc(ui, &rows, false, false);
}

fn describe(why: Fault) -> &'static str {
    match why {
        Fault::NoScanner => "this board has no scanner",
        Fault::NotFound => "the scanner did not answer",
        Fault::SetupRefused => "the scanner refused setup",
        Fault::Cancelled => "cancelled",
        Fault::TooLong => "that code is too long to show",
    }
}
