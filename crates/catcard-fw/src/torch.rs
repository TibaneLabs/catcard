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
//! # Hold to light, as stock does when idle
//!
//! Stock brackets the whole thing wake -> `S_CMD_03L1` -> (key released) `S_CMD_03L0`
//! -> sleep, and **does not start a scan**: the illumination is a flashlight in its own
//! right, not a side effect of imaging. Only *during* a scan does the key toggle
//! instead, between auto (`L2`) and off, so a hand is free to hold the device.
//!
//! Source: hw-reference/qr.md §8 [C]

use catcard_hal::usart::Usart;
use catcard_qr::cmd;

use crate::keypad::Keypad;

/// Loop iterations one byte may take. Short: this runs inside the keypad poll, so it is
/// a budget for "the port is there and idle", not for waiting on a reply.
const BYTE_BUDGET: u32 = 20_000;

/// Attempts at waking. The first is expected to be swallowed, so one is none.
const WAKE_TRIES: usize = 5;

/// How often the lamp is told again while the key is held.
///
/// **The module sleeps itself.** Its configuration sets automatic sleep after 500 ms of
/// idle (`S_CMD_MT20`, `S_CMD_MTRF500`), and a sleeping module puts its lamp out -- so
/// one command on the way down lights it for half a second and no longer. Saying it
/// again inside that window is what makes "while the key is held" mean anything.
///
/// Source: hw-reference/qr.md §5 [C]
const REASSERT_MS: u32 = 250;
/// Between the two sleep commands, for the module's second sleep layer.
const SLEEP_GAP_MS: u32 = 150;

/// How long to leave between wake attempts: **50 ms**, as the reference specifies.
///
/// A real delay and not a loop budget. The budget this replaced came to something like
/// eight milliseconds, so all five attempts landed inside the window where the module is
/// still coming up -- which reads exactly like a module that is not there.
const WAKE_GAP_MS: u32 = 50;

/// The port, opened the first time the key is pressed.
///
/// Foreground only, like the rest of the UI's state. Held across presses because opening
/// it per press would put a GPIO and clock reconfiguration in the path of a key.
static mut PORT: Option<Usart> = None;
/// Whether the lamp is lit, so the command only goes out when the answer changes.
static mut LIT: bool = false;
/// The rate a scan found the module at, once one has.
static mut KNOWN_RATE: Option<u32> = None;
/// When the lamp was last told to be on, so it can be told again before the module
/// decides it has been idle long enough to sleep.
static mut LAST_SENT: u32 = 0;

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
        // Held: say it again before the module's idle timer puts it out. Nothing is sent
        // while the lamp is off, so an untouched key costs one comparison.
        if down && elapsed_ms() >= REASSERT_MS {
            set(true);
        }
        return;
    }
    // SAFETY: as above.
    unsafe { *core::ptr::addr_of_mut!(LIT) = down };
    set(down);
}

/// Milliseconds since the lamp was last told anything.
fn elapsed_ms() -> u32 {
    // SAFETY: reads RCC and the cycle counter.
    let per_ms = (unsafe { catcard_hal::clock::hclk_hz() } / 1_000).max(1);
    let now = catcard_hal::dwt::cycles();
    // SAFETY: foreground only.
    let then = unsafe { *core::ptr::addr_of!(LAST_SENT) };
    now.wrapping_sub(then) / per_ms
}

/// Light the lamp, or put it out.
///
/// Exactly stock's idle sequence: wake, then always-on; on release, off, then sleep.
/// **No scan is started.** The illumination is a flashlight in its own right -- the
/// reference is explicit that turning it on issues no `S_CMD_020E` -- so holding a scan
/// open to keep it lit would be lighting it by side effect and leaving the module
/// reading codes nobody pointed it at.
///
/// Source: hw-reference/qr.md §8 [C]
fn set(on: bool) {
    let Some(scanner) = catcard_board::BOARD.qr else {
        return;
    };
    // SAFETY: foreground only. The scanner's pins and USART2 are this firmware's, and
    // the scan screen releases them before it takes them.
    let port = unsafe { &mut *core::ptr::addr_of_mut!(PORT) };
    if port.is_none() {
        // SAFETY: as above.
        *port = Some(unsafe { Usart::init(scanner.tx, scanner.rx, catcard_qr::BAUDS[0]) });
    }
    let Some(port) = port.as_mut() else { return };

    // SAFETY: reads a static that only the foreground writes.
    let rates = match unsafe { *core::ptr::addr_of!(KNOWN_RATE) } {
        Some(rate) => [rate, 0],
        None => catcard_qr::BAUDS,
    };
    let mut woke = 0u32;
    let mut answered = "silence";
    for rate in rates {
        if rate == 0 {
            continue;
        }
        port.set_baud(rate);
        if on && wake(port) {
            woke = rate;
        }
        // Framed, and framed only: bare is for the sleep and wake pokes, and raw ASCII
        // at a module expecting a frame is as likely to desynchronise its parser as to
        // be understood.
        let body = if on { cmd::TORCH_ON } else { cmd::TORCH_OFF };
        let mut framed = [0u8; 32];
        let Ok(frame) = catcard_qr::wrap(catcard_qr::FID_COMMAND, body, &mut framed) else {
            return;
        };
        port.flush_input();
        let _ = port.write(frame, BYTE_BUDGET);
        // What comes back is the whole diagnosis: an acknowledgement means the command
        // landed and an unlit lamp is the module's business, silence means it did not.
        let mut reply = [0u8; 16];
        let n = port.read(&mut reply, BYTE_BUDGET);
        answered = match catcard_qr::unwrap(&reply[..n]) {
            Ok(f) if catcard_qr::is_ack(&f) => "ack",
            Ok(_) => "a frame, but not an ack",
            Err(_) if n > 0 => "bytes, but not a frame",
            Err(_) => "silence",
        };
    }
    if !on {
        // Stock re-sleeps here, and an idle state that is not the one the rest of the
        // firmware assumes is a battery draining quietly. Twice, 150 ms apart: the
        // module has two sleep layers and one command only reaches the first.
        let _ = port.write(cmd::SLEEP, BYTE_BUDGET);
        catcard_hal::dwt::delay_cycles(ms_cycles(SLEEP_GAP_MS));
        let _ = port.write(cmd::SLEEP, BYTE_BUDGET);
    }
    // SAFETY: foreground only.
    unsafe { *core::ptr::addr_of_mut!(LAST_SENT) = catcard_hal::dwt::cycles() };
    crate::catlog!(
        "torch: {} -> {} (woke at {})",
        if on { "on" } else { "off" },
        answered,
        woke
    );
}

/// Wake the module, retrying as the reference says to.
///
/// **The first send is expected to be ignored.** It arrives while the module is still
/// down, so a single attempt is no attempt at all -- which is why the lamp did nothing
/// at first. Bounded at [`WAKE_TRIES`], with a gap between each so the module has time
/// to come up and answer; it answers with a bare acknowledgement, so any byte back is
/// the signal.
///
/// Source: hw-reference/qr.md §7 [C]
fn wake(port: &mut Usart) -> bool {
    for _ in 0..WAKE_TRIES {
        port.flush_input();
        let _ = port.write(cmd::WAKE, BYTE_BUDGET);
        catcard_hal::dwt::delay_cycles(ms_cycles(WAKE_GAP_MS));
        let mut got = [0u8; 8];
        if port.read(&mut got, BYTE_BUDGET) > 0 {
            return true;
        }
    }
    false
}

/// Milliseconds as CPU cycles.
fn ms_cycles(ms: u32) -> u32 {
    // SAFETY: reads RCC only.
    let hz = unsafe { catcard_hal::clock::hclk_hz() };
    (hz / 1_000).saturating_mul(ms)
}
