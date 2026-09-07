//! The PIN unlock screens.
//!
//! [`catcard_pin::Login`] decides what happens; this draws it and feeds it keys. The
//! split matters because the sequencing is testable on the host and the drawing is not.
//!
//! Key meanings are the same on every screen, which is the only thing that makes a
//! twelve-key pad usable without a legend:
//!
//! ```text
//! 0-9   a digit
//! x     delete a digit; on an empty field, go back a step
//! y     accept this field
//! ```

use catcard_callgate::abi::{DfuMode, LogoutMode, PinOp};
use catcard_callgate::pin::PinAttempt;
use catcard_callgate::{Callgate, Error as GateError};
use catcard_entropy::HmacDrbg;
use catcard_pin::{Login, PinGate, Step, MAX_ATTEMPTS, MAX_PART_LEN};
use catcard_ui::font::{misc4x6, peep7x14};
use catcard_ui::keypad::{Event, Key, Keypad, KEYS};
use catcard_ui::pinentry::PinBuffer;
use catcard_ui::text::{centred, draw_text};
use catcard_ui::Mono128x64;

use crate::{display, keypad::GpioMatrix};

/// Scan interval, matching the selftest loop: roughly 60 Hz at the reset-default clock.
const SCAN_CYCLES: u32 = 66_000;

/// [`PinGate`] over the real bootloader.
///
/// Exists so [`Login`] can be driven by a model on the host and by the callgate here,
/// with the same sequencing code in both.
pub struct BootloaderGate<'a> {
    gate: &'a Callgate,
}

impl PinGate for BootloaderGate<'_> {
    fn pin_attempt(&self, op: PinOp, attempt: &mut PinAttempt) -> Result<i32, GateError> {
        // SAFETY: `attempt` is on our stack, which the linker places in SRAM1 — the
        // region the gate requires — and `call` range-checks it regardless. The struct
        // is the bootloader's own layout and, except for Setup, carries the HMAC it
        // signed on the previous call.
        unsafe { self.gate.pin_attempt(op, attempt) }
    }

    fn anti_phishing(&self, prefix: &[u8]) -> Result<u32, GateError> {
        // SAFETY: the wrapper builds and bounds its own MAX_PIN_LEN buffer.
        unsafe { self.gate.anti_phishing_words(prefix) }
    }
}

/// One line of 7x14, centred.
fn title(fb: &mut Mono128x64, y: usize, s: &str) {
    let f = &peep7x14::FONT;
    draw_text(fb, f, centred(f, s, 128), y, s);
}

/// One line of 4x6, centred.
fn small(fb: &mut Mono128x64, y: usize, s: &str) {
    let f = &misc4x6::FONT;
    draw_text(fb, f, centred(f, s, 128), y, s);
}

/// Render a small unsigned number into `buf`, returning it as a `str`.
///
/// `core::fmt` is not available here — it is the single largest thing that would pull
/// formatting machinery into a firmware image that otherwise has none.
fn num(buf: &mut [u8; 3], mut v: u32) -> &str {
    if v > 99 {
        v = 99;
    }
    let (a, b) = ((v / 10) as u8, (v % 10) as u8);
    let s: &[u8] = if a > 0 {
        buf[0] = b'0' + a;
        buf[1] = b'0' + b;
        &buf[..2]
    } else {
        buf[0] = b'0' + b;
        &buf[..1]
    };
    core::str::from_utf8(s).unwrap_or("?")
}

/// Draw "N of 13 tries left" on the bottom line, or nothing while the count is full.
///
/// Hidden at full count deliberately: a permanent attempt counter reads as a threat on
/// a device that is working normally. It appears the moment one is spent.
fn tries_left(fb: &mut Mono128x64, left: u32) {
    if left >= MAX_ATTEMPTS {
        return;
    }
    let f = &misc4x6::FONT;
    let mut n = [0u8; 3];
    let s = num(&mut n, left);
    // "<n> of 13 tries left", assembled without a formatter.
    let mut x = centred(f, "00 of 13 tries left", 128);
    for part in [s, " of 13 tries left"] {
        draw_text(fb, f, x, 56, part);
        x += part.len() * f.width as usize;
    }
}

fn screen_field(
    panel: &mut display::Panel,
    heading: &str,
    buf: &PinBuffer<MAX_PART_LEN>,
    left: u32,
) {
    let mut fb = Mono128x64::new();
    title(&mut fb, 2, heading);
    let mut mask = [0u8; MAX_PART_LEN];
    title(&mut fb, 24, buf.masked(&mut mask));
    small(
        &mut fb,
        46,
        if buf.is_empty() {
            "0-9 to enter"
        } else {
            "y accept   x delete"
        },
    );
    tries_left(&mut fb, left);
    let _ = panel.flush(&fb);
}

fn screen_words(panel: &mut display::Panel, w: [&str; 2]) {
    let mut fb = Mono128x64::new();
    small(&mut fb, 1, "these two words must be");
    small(&mut fb, 8, "the ones you know");
    title(&mut fb, 18, w[0]);
    title(&mut fb, 34, w[1]);
    small(&mut fb, 52, "y yes   x no, stop");
    let _ = panel.flush(&fb);
}

fn screen_message(panel: &mut display::Panel, head: &str, a: &str, b: &str) {
    let mut fb = Mono128x64::new();
    title(&mut fb, 6, head);
    small(&mut fb, 28, a);
    small(&mut fb, 36, b);
    let _ = panel.flush(&fb);
}

/// Where the unlock ended.
pub enum Unlocked {
    /// Logged in. `zero_secret` means there is no seed stored yet.
    In { zero_secret: bool },
    /// No PIN has ever been set; the device needs first-time setup.
    Blank,
}

/// Run the unlock loop until the device is in, or until it cannot be.
///
/// Does not return on the terminal outcomes: a bricked device goes to the bootloader's
/// DFU screen, and a user who rejects the anti-phishing words gets a logout, because in
/// both cases carrying on would be worse than stopping.
pub fn unlock(
    gate: &Callgate,
    panel: &mut display::Panel,
    matrix: &mut GpioMatrix,
    drbg: &mut HmacDrbg,
) -> Unlocked {
    let g = BootloaderGate { gate };
    let mut login = Login::new(&g);
    let mut field = PinBuffer::<MAX_PART_LEN>::new();
    let mut pad = Keypad::new();
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut redraw = true;

    loop {
        if redraw {
            match login.step() {
                Step::Prefix => screen_field(panel, "PIN prefix", &field, login.attempts_left()),
                Step::ConfirmWords(w) => screen_words(panel, w.as_str()),
                Step::Suffix => screen_field(panel, "PIN suffix", &field, login.attempts_left()),
                Step::Wrong { attempts_left, .. } => {
                    let mut n = [0u8; 3];
                    screen_message(panel, "Wrong PIN", num(&mut n, attempts_left), "tries left");
                }
                Step::Blank => {
                    screen_message(panel, "No PIN set", "this device has no", "wallet yet")
                }
                Step::In { .. } => screen_message(panel, "Unlocked", "", ""),
                // Terminal: the pairing secret is gone and no PIN will ever work again.
                // Saying so and stopping is the only honest thing left.
                Step::Bricked => {
                    screen_message(
                        panel,
                        "BRICKED",
                        "secure element lost",
                        "its pairing secret",
                    );
                    // SAFETY: nothing after this runs; the bootloader wipes SRAM.
                    unsafe { gate.enter_dfu(DfuMode::Brick) }
                }
                Step::Failed(_) => {
                    screen_message(panel, "PIN error", "restarting the", "unlock sequence")
                }
            }
            redraw = false;
        }

        // A failure that is not about this PIN is recoverable only by re-running setup,
        // which is what `Login::new` does. Doing it here rather than leaving the screen
        // up means a transient gate error does not strand the device.
        if matches!(login.step(), Step::Failed(_)) {
            catcard_hal::dwt::delay_cycles(SCAN_CYCLES * 60);
            login = Login::new(&g);
            field.clear();
            redraw = true;
            continue;
        }

        match login.step() {
            Step::In { zero_secret } => return Unlocked::In { zero_secret },
            Step::Blank => return Unlocked::Blank,
            _ => {}
        }

        crate::usbtask::pump();

        let n = pad.scan(matrix, drbg, &mut events);
        for e in &events[..n] {
            let Event::Pressed(key) = e else { continue };
            redraw = true;
            match (login.step(), key) {
                (Step::ConfirmWords(_), Key::Confirm) => {
                    login.words_confirmed();
                    field.clear();
                }
                // The user does not recognise the words. That is the signal this whole
                // step exists for: it means the device may not be theirs, so the suffix
                // must not be typed into it. Wipe and stop rather than offering a retry.
                (Step::ConfirmWords(_), Key::Cancel) => {
                    screen_message(panel, "Stopped", "words not recognised", "powering down");
                    // SAFETY: nothing after this runs; the bootloader wipes all SRAM.
                    unsafe { gate.logout(LogoutMode::Logout) }
                }
                (Step::ConfirmWords(_), Key::Digit(_)) => {}

                (Step::Prefix | Step::Suffix, Key::Digit(d)) => {
                    field.push(*d);
                }
                (Step::Prefix | Step::Suffix, Key::Cancel) => {
                    if !field.pop() {
                        // Empty field: back out of the step rather than doing nothing.
                        // From the suffix that means re-checking the words, which is
                        // also how a user reaches them again after a wrong PIN.
                        login = Login::new(&g);
                    }
                }
                (Step::Prefix, Key::Confirm) => {
                    if !field.is_empty() {
                        let _ = login.prefix_entered(&g, field.as_bytes());
                        field.clear();
                    }
                }
                (Step::Suffix, Key::Confirm) => {
                    if !field.is_empty() {
                        let _ = login.attempt(&g, field.as_bytes());
                        field.clear();
                    }
                }

                // Any key acknowledges the wrong-PIN screen and starts over. The
                // attempt is already spent; there is nothing to confirm.
                (Step::Wrong { .. }, _) => {
                    login = Login::new(&g);
                    field.clear();
                }
                _ => {}
            }
        }

        catcard_hal::dwt::delay_cycles(SCAN_CYCLES);
    }
}
