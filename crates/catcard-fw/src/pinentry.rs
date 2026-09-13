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
use catcard_pin::{Failure, Login, MAX_ATTEMPTS, MAX_PART_LEN, PinGate, Step};
use catcard_ui::Mono128x64;
use catcard_ui::font::{misc4x6, peep7x14};
use catcard_ui::keypad::{Event, KEYS, Key, Keypad};
use catcard_ui::pinentry::PinBuffer;
use catcard_ui::text::{centred, draw_text};

use crate::{display, keypad::GpioMatrix};

/// Every key this iteration produced, from the pad and from a host.
///
/// The two are merged here rather than at each call site so no screen can honour one
/// source and forget the other — which would show up as a device that answers the
/// keypad but ignores a host, or worse, the reverse.
pub(crate) fn pressed_keys(
    pad: &mut Keypad,
    matrix: &mut GpioMatrix,
    drbg: &mut HmacDrbg,
    events: &mut [Event; KEYS],
    out: &mut heapless::Vec<Key, { KEYS + 1 }>,
) {
    out.clear();
    let n = pad.scan(matrix, drbg, events);
    for e in &events[..n] {
        if let Event::Pressed(k) = e {
            let _ = out.push(*k);
        }
    }
    if let Some(k) = crate::usbtask::take_injected_key() {
        let _ = out.push(k);
    }
}

/// Scan interval, matching the selftest loop: roughly 60 Hz at the reset-default clock.
const SCAN_CYCLES: u32 = 66_000;

/// [`PinGate`] over the real bootloader.
///
/// Exists so [`Login`] can be driven by a model on the host and by the callgate here,
/// with the same sequencing code in both.
impl<'a> BootloaderGate<'a> {
    /// Wrap a callgate so `catcard_pin` can drive it.
    pub fn new(gate: &'a Callgate) -> Self {
        Self { gate }
    }
}

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

/// Look up the anti-phishing indices in the BIP-39 English list.
///
/// `catcard-pin` deliberately hands back positions rather than words: holding the list
/// would let the PIN gate reach wallet code. The lookup belongs here, where a screen is
/// being drawn anyway.
fn anti_phishing_words(w: catcard_pin::words::Words) -> [&'static str; 2] {
    use catcard_wallet::bip39::wordlist::ENGLISH;
    [ENGLISH[w.index[0] as usize], ENGLISH[w.index[1] as usize]]
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
    if buf.is_empty() {
        small(&mut fb, 46, "0-9 to enter");
    } else {
        two_key_hint(&mut fb, 46, "accept", "delete");
    }
    tries_left(&mut fb, left);
    let _ = panel.flush(&fb);
}

/// `✓ <yes>   ✗ <no>`, centred, using the symbols moulded into the keys.
///
/// The pad is labelled with a tick and a cross. Writing "y" and "x" asked the reader to
/// translate our wiring names into what is under their thumb, which is one more thing to
/// get wrong on a device where the key map is the thing in doubt.
fn two_key_hint(fb: &mut Mono128x64, y: usize, yes: &str, no: &str) {
    use catcard_ui::icons;
    let f = &misc4x6::FONT;
    let gap = 3 * f.width as usize;
    let total = icons::hint_width(f, yes) + gap + icons::hint_width(f, no);
    let mut x = (128usize).saturating_sub(total) / 2;
    x = icons::draw_hint(fb, &icons::CHECK, f, x, y, yes) + gap;
    icons::draw_hint(fb, &icons::CROSS, f, x, y, no);
}

fn screen_words(panel: &mut display::Panel, w: [&str; 2]) {
    let mut fb = Mono128x64::new();
    small(&mut fb, 1, "these two words must be");
    small(&mut fb, 8, "the ones you know");
    title(&mut fb, 18, w[0]);
    title(&mut fb, 34, w[1]);
    two_key_hint(&mut fb, 52, "yes", "no, stop");
    let _ = panel.flush(&fb);
}

fn screen_message(panel: &mut display::Panel, head: &str, a: &str, b: &str) {
    let mut fb = Mono128x64::new();
    title(&mut fb, 6, head);
    small(&mut fb, 28, a);
    small(&mut fb, 36, b);
    let _ = panel.flush(&fb);
}

/// Choose the first PIN on a blank device.
///
/// The prefix is taken, its anti-phishing words are shown — which is where a user learns
/// the words they will be checking on every later unlock — and then the suffix. Returns
/// true when a PIN was set.
///
/// **Not reversible.** After this the device is PIN-gated, and there is no path back to
/// blank that does not go through knowing the PIN. So the words screen is not a
/// formality here: it is the only time the user sees them without already being the
/// person who set them.
fn setup_first_pin(
    g: &BootloaderGate<'_>,
    panel: &mut display::Panel,
    matrix: &mut GpioMatrix,
    drbg: &mut HmacDrbg,
    login: &mut Login,
) -> bool {
    let Some(prefix) = collect(panel, matrix, drbg, "New PIN prefix") else {
        return false;
    };
    // A query, not the login path: `set_first_pin` only acts while the device is still
    // blank, and walking the login state machine here would take it out of that state.
    working(panel, "Checking");
    if let Some(w) = login.words_for(g, prefix.as_bytes()) {
        screen_words(panel, anti_phishing_words(w));
        if !wait_for_confirm(matrix, drbg) {
            return false;
        }
    }
    let Some(suffix) = collect(panel, matrix, drbg, "New PIN suffix") else {
        return false;
    };

    screen_message(panel, "Setting PIN", "do not disconnect", "");
    matches!(
        login.set_first_pin(g, prefix.as_bytes(), suffix.as_bytes()),
        Ok(Step::Prefix)
    )
}

/// "No PIN set", with the tick drawn rather than named.
fn screen_blank(panel: &mut display::Panel) {
    use catcard_ui::icons;
    let mut fb = Mono128x64::new();
    title(&mut fb, 10, "No PIN set");
    let f = &misc4x6::FONT;
    let label = "choose a PIN";
    let x = (128usize).saturating_sub(icons::hint_width(f, label)) / 2;
    icons::draw_hint(&mut fb, &icons::CHECK, f, x, 34, label);
    let _ = panel.flush(&fb);
}

/// "Working on it" — drawn before anything that blocks on the secure element.
///
/// Deliberately says what is happening rather than showing a spinner: there is no timer
/// driving one, and a frozen spinner is worse than a still screen because it claims
/// progress that is not being made.
fn working(panel: &mut display::Panel, what: &str) {
    screen_message(panel, what, "please wait", "");
}

/// Collect one PIN part. `None` if the user backs out.
fn collect(
    panel: &mut display::Panel,
    matrix: &mut GpioMatrix,
    drbg: &mut HmacDrbg,
    heading: &str,
) -> Option<PinBuffer<MAX_PART_LEN>> {
    let mut field = PinBuffer::<MAX_PART_LEN>::new();
    let mut pad = Keypad::new();
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    screen_field(panel, heading, &field, MAX_ATTEMPTS);

    loop {
        crate::usbtask::pump();
        pressed_keys(&mut pad, matrix, drbg, &mut events, &mut keys);
        let mut changed = false;
        for k in keys.iter() {
            match k {
                Key::Digit(d) => {
                    field.push(*d);
                    changed = true;
                }
                Key::Cancel => {
                    if !field.pop() {
                        return None;
                    }
                    changed = true;
                }
                Key::Confirm => {
                    if !field.is_empty() {
                        return Some(field);
                    }
                }
            }
        }
        if changed {
            screen_field(panel, heading, &field, MAX_ATTEMPTS);
        }
        catcard_hal::dwt::delay_cycles(SCAN_CYCLES);
    }
}

/// Wait for `y`. False if the user pressed `x` instead.
fn wait_for_confirm(matrix: &mut GpioMatrix, drbg: &mut HmacDrbg) -> bool {
    let mut pad = Keypad::new();
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        crate::usbtask::pump();
        pressed_keys(&mut pad, matrix, drbg, &mut events, &mut keys);
        for k in keys.iter() {
            match k {
                Key::Confirm => return true,
                Key::Cancel => return false,
                _ => {}
            }
        }
        catcard_hal::dwt::delay_cycles(SCAN_CYCLES);
    }
}

/// Where the unlock ended.
pub enum Unlocked {
    /// Logged in. `zero_secret` means there is no seed stored yet.
    In { zero_secret: bool },
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
) -> (Unlocked, Login) {
    let g = BootloaderGate { gate };
    let mut login = Login::new(&g);
    let mut field = PinBuffer::<MAX_PART_LEN>::new();
    let mut pad = Keypad::new();
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    let mut redraw = true;

    loop {
        // A host driving this device needs to know which screen it is looking at.
        crate::usbtask::set_blank(matches!(login.step(), Step::Blank));

        if redraw {
            match login.step() {
                Step::Prefix => screen_field(panel, "PIN prefix", &field, login.attempts_left()),
                Step::ConfirmWords(w) => screen_words(panel, anti_phishing_words(w)),
                Step::Suffix => screen_field(panel, "PIN suffix", &field, login.attempts_left()),
                Step::Wrong { attempts_left, .. } => {
                    let mut n = [0u8; 3];
                    let mut m = [0u8; 3];
                    // The length of what was submitted, never the digits. Distinguishes
                    // "the wrong digits went in" from "nothing went in", which look the
                    // same from a wrong-PIN answer.
                    let left = num(&mut n, attempts_left);
                    let sent = num(&mut m, login.last_pin_len() as u32);
                    let mut fb = Mono128x64::new();
                    let t = &peep7x14::FONT;
                    let f = &misc4x6::FONT;
                    draw_text(&mut fb, t, centred(t, "Wrong PIN", 128), 6, "Wrong PIN");
                    let mut x = 8;
                    for part in [left, " tries left, sent ", sent] {
                        draw_text(&mut fb, f, x, 30, part);
                        x += part.len() * f.width as usize;
                    }
                    let _ = panel.flush(&fb);
                }
                Step::Blank => screen_blank(panel),
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
                // Name the reason. "PIN error" alone sent me guessing at which of
                // fourteen documented codes it was; the code is what says.
                Step::Failed(f) => {
                    let mut n = [0u8; 3];
                    let (what, detail) = match f {
                        Failure::NeedsSetup => ("hmac / stale struct", ""),
                        // Only from an upgrade authorisation, which does not run from
                        // this screen -- listed so adding one cannot be forgotten.
                        Failure::ImageRefused => ("image refused", ""),
                        Failure::MustWait => ("rate limited", ""),
                        Failure::Gate(_) => ("callgate", "unreachable"),
                        Failure::Code(c) => ("gate said -1", num(&mut n, c.unsigned_abs() % 100)),
                    };
                    screen_message(panel, "PIN error", what, detail)
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

        if let Step::In { zero_secret } = login.step() {
            // The login travels back out with the result. On mk4 and later an upgrade is
            // authorised through this same struct, and only a logged-in one carries the
            // bootloader's signature that `gate 18/7` demands -- so throwing it away
            // here would mean no install could ever happen.
            return (Unlocked::In { zero_secret }, login);
        }

        let _ = crate::usbtask::pump();

        pressed_keys(&mut pad, matrix, drbg, &mut events, &mut keys);
        for key in keys.iter() {
            redraw = true;
            match (login.step(), key) {
                // A blank device: offer to set the first PIN rather than stopping.
                // Until this existed the device simply said "no wallet yet" and there
                // was no way forward from the front panel at all.
                (Step::Blank, Key::Confirm) => {
                    if !setup_first_pin(&g, panel, matrix, drbg, &mut login) {
                        redraw = true;
                    }
                    field.clear();
                }
                (Step::Blank, _) => {}

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
                        // Both of these block for as long as the secure element takes,
                        // with no display update and no USB polling in between. Without
                        // a screen first, the device looks like it ignored the key --
                        // and the natural response to that is to press it again, which
                        // on the suffix means spending a second PIN attempt.
                        working(panel, "Checking");
                        let _ = login.prefix_entered(&g, field.as_bytes());
                        field.clear();
                    }
                }
                (Step::Suffix, Key::Confirm) => {
                    if !field.is_empty() {
                        working(panel, "Checking PIN");
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
