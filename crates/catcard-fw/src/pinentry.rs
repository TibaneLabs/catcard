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
use catcard_ui::canvas::Canvas;
use catcard_ui::keypad::{Event, KEYS, Key};

use crate::keypad::Keypad;
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
    // Mask the column EXTI lines while the scan toggles rows, or a scan would raise the
    // very interrupt this uses to time a real press. Re-armed at the end for the idle gap.
    matrix.disarm_edge_detect();
    let n = pad.scan(matrix, drbg, events);
    let mut physical = false;
    for e in &events[..n] {
        if let Event::Pressed(k) = e {
            let _ = out.push(*k);
            physical = true;
        }
    }

    // Every physical keypress carries timing no polling schedule can predict, so mix it
    // into the UI DRBG as extra entropy. The best sample is the one the column-edge
    // interrupt latched at the instant of contact -- CPU-cycle resolution, independent of
    // the 60 Hz scan. If none was caught (a key that went down exactly at scan time), fall
    // back to sampling the timers now. This only tops up a generator already seeded from
    // the entropy pool; it is never a precondition, and a stopped RTC contributing a
    // constant is harmless. (Injected keys carry no such timing and are skipped.)
    if physical {
        let sample = crate::keypad::take_edge_sample().unwrap_or_else(|| {
            let cycles = catcard_hal::dwt::cycles();
            // SAFETY: single-threaded UI context; `snapshot` only opens an APB gate and reads.
            let rtc = unsafe { catcard_hal::rtc::snapshot() };
            let mut s = [0u8; 16];
            s[0..4].copy_from_slice(&cycles.to_le_bytes());
            s[4..8].copy_from_slice(&rtc[0].to_le_bytes());
            s[8..12].copy_from_slice(&rtc[1].to_le_bytes());
            s[12..16].copy_from_slice(&rtc[2].to_le_bytes());
            s
        });
        drbg.reseed(&sample, &[]);
    }

    // Idle the matrix for edge detection during the caller's wait before the next scan.
    matrix.arm_edge_detect();

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

/// Rows the PIN screens were first laid out on.
///
/// Every `y` below is a position on that 64-row design, spread in proportion over the real
/// canvas: the mk OLED keeps its exact placement, and the Q1's 240 rows are filled in the
/// layout's larger faces instead of holding a small picture in the middle.
const DESIGN_ROWS: usize = 64;

/// Design row `y`, on this canvas.
fn at(c: &display::Screen, y: usize) -> usize {
    y * c.height() / DESIGN_ROWS
}

/// One line of the layout's title face, centred, at design row `y`.
fn title(c: &mut display::Screen, y: usize, s: &str) {
    let f = display::LAYOUT.title;
    let (x, y) = (centred(f, s, c.width()), at(c, y));
    draw_text(c, f, x, y, s);
}

/// One line of the layout's body face, centred, at design row `y`.
fn small(c: &mut display::Screen, y: usize, s: &str) {
    let f = display::LAYOUT.body;
    let (x, y) = (centred(f, s, c.width()), at(c, y));
    draw_text(c, f, x, y, s);
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
fn tries_left(c: &mut display::Screen, left: u32) {
    if left >= MAX_ATTEMPTS {
        return;
    }
    let f = display::LAYOUT.body;
    let mut n = [0u8; 3];
    let s = num(&mut n, left);
    // "<n> of 13 tries left", assembled without a formatter.
    let (mut x, y) = (centred(f, "00 of 13 tries left", c.width()), at(c, 56));
    for part in [s, " of 13 tries left"] {
        x = draw_text(c, f, x, y, part);
    }
}

fn screen_field(
    panel: &mut display::Panel,
    heading: &str,
    buf: &PinBuffer<MAX_PART_LEN>,
    left: u32,
) {
    display::draw(panel, |c| {
        c.clear();
        title(c, 2, heading);
        let mut mask = [0u8; MAX_PART_LEN];
        title(c, 24, buf.masked(&mut mask));
        if buf.is_empty() {
            small(c, 46, "0-9 to enter");
        } else {
            two_key_hint(c, 46, "accept", "delete");
        }
        tries_left(c, left);
    });
}

/// The two keys and what they do here, centred: `✓ <yes>   ✗ <no>` where those symbols are
/// moulded into the caps, `ENTER <yes>   CANCEL <no>` where the keys are printed with words.
///
/// Writing "y" and "x" asked the reader to translate our wiring names into what is under
/// their thumb, which is one more thing to get wrong on a device where the key map is the
/// thing in doubt. Naming a mark the board does not carry would be the same mistake.
fn two_key_hint(c: &mut display::Screen, y: usize, yes: &str, no: &str) {
    use catcard_ui::icons;
    let f = display::LAYOUT.body;
    let gap = 3 * f.advance(b' ');
    let total = icons::key_hint_width(f, display::CONFIRM, yes)
        + gap
        + icons::key_hint_width(f, display::CANCEL, no);
    let (mut x, y) = (c.width().saturating_sub(total) / 2, at(c, y));
    x = icons::draw_key_hint(c, f, x, y, display::CONFIRM, yes) + gap;
    icons::draw_key_hint(c, f, x, y, display::CANCEL, no);
}

fn screen_words(panel: &mut display::Panel, w: [&str; 2]) {
    display::draw(panel, |c| {
        c.clear();
        small(c, 1, "these two words must be");
        small(c, 8, "the ones you know");
        title(c, 18, w[0]);
        title(c, 34, w[1]);
        two_key_hint(c, 52, "yes", "no, stop");
    });
}

fn screen_message(panel: &mut display::Panel, head: &str, a: &str, b: &str) {
    display::draw(panel, |c| {
        c.clear();
        title(c, 6, head);
        small(c, 28, a);
        small(c, 36, b);
    });
}

/// "Wrong PIN", with the tries left and how long the submitted PIN was.
fn screen_wrong(panel: &mut display::Panel, left: &str, sent: &str) {
    display::draw(panel, |c| {
        c.clear();
        title(c, 6, "Wrong PIN");
        let f = display::LAYOUT.body;
        let (mut x, y) = (8, at(c, 30));
        for part in [left, " tries left, sent ", sent] {
            x = draw_text(c, f, x, y, part);
        }
    });
}

/// Choose the first PIN on a blank device.
///
/// The prefix is taken, its anti-phishing words are shown — which is where a user learns
/// the words they will be checking on every later unlock — then the suffix, then the whole
/// PIN once more so a typo cannot slip through. Only when the two entries match is the PIN
/// set. Returns true when a PIN was set.
///
/// **Not reversible.** After this the device is PIN-gated, and there is no path back to
/// blank that does not go through knowing the PIN. That is exactly why the PIN is entered
/// twice here: a mistyped first PIN would lock the device out of both login and Factory
/// Reset. The words screen matters for the same reason — it is the only time the user sees
/// them without already being the person who set them.
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

    // Entered again and compared, exactly as a PIN change is, so a typo cannot set a first
    // PIN the owner does not know -- which on a blank device would be unrecoverable, since
    // both login and Factory Reset need the PIN nobody typed on purpose.
    let Some(again_prefix) = collect(panel, matrix, drbg, "Repeat prefix") else {
        return false;
    };
    let Some(again_suffix) = collect(panel, matrix, drbg, "Repeat suffix") else {
        return false;
    };
    if again_prefix.as_bytes() != prefix.as_bytes() || again_suffix.as_bytes() != suffix.as_bytes()
    {
        screen_message(panel, "PIN not set", "the two entries", "did not match");
        // Acknowledge, then fall back to the blank screen so the owner can start over.
        let _ = wait_for_confirm(matrix, drbg);
        return false;
    }

    screen_message(panel, "Setting PIN", "do not disconnect", "");
    matches!(
        login.set_first_pin(g, prefix.as_bytes(), suffix.as_bytes()),
        Ok(Step::Prefix)
    )
}

/// "No PIN set", with the tick drawn rather than named.
fn screen_blank(panel: &mut display::Panel) {
    use catcard_ui::icons;
    display::draw(panel, |c| {
        c.clear();
        title(c, 10, "No PIN set");
        let f = display::LAYOUT.body;
        let label = "choose a PIN";
        let width = icons::key_hint_width(f, display::CONFIRM, label);
        let (x, y) = (c.width().saturating_sub(width) / 2, at(c, 34));
        icons::draw_key_hint(c, f, x, y, display::CONFIRM, label);
    });
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

/// Split a `prefix-suffix` PIN payload into its two parts.
///
/// Returns `None` unless both parts are non-empty, all ASCII digits, and within
/// [`MAX_PART_LEN`] -- the same shape [`PinBuffer`] would have produced from the keypad,
/// so the gate hashes exactly what a typed PIN would.
pub(crate) fn split_pin(pin: &[u8]) -> Option<(&[u8], &[u8])> {
    let sep = pin.iter().position(|&b| b == catcard_pin::SEPARATOR)?;
    let (prefix, rest) = pin.split_at(sep);
    let suffix = &rest[1..];
    let ok = |part: &[u8]| {
        !part.is_empty() && part.len() <= MAX_PART_LEN && part.iter().all(u8::is_ascii_digit)
    };
    (ok(prefix) && ok(suffix)).then_some((prefix, suffix))
}

/// Log in with a whole PIN a host submitted: the prefix, the anti-phishing words
/// auto-confirmed -- the host has chosen to trust the device it is talking to -- then the
/// suffix. Shared by the keypad screen and the headless recovery loop, so both walk the
/// state machine the same way.
pub(crate) fn login_with(g: &BootloaderGate<'_>, login: &mut Login, prefix: &[u8], suffix: &[u8]) {
    let _ = login.prefix_entered(g, prefix);
    if matches!(login.step(), Step::ConfirmWords(_)) {
        login.words_confirmed();
    }
    if matches!(login.step(), Step::Suffix) {
        let _ = login.attempt(g, suffix);
    }
}

/// How a Change-PIN attempt ended.
pub enum ChangePin {
    /// The PIN was changed and the new one logged back in; the session continues.
    Changed,
    /// The owner backed out before anything was written.
    Cancelled,
    /// The two entries of the new PIN did not match; nothing was written.
    Mismatch,
    /// The bootloader refused -- a wrong current PIN, or another failure. The session is no
    /// longer valid and the caller should reboot to a fresh login.
    Refused,
}

/// Change the wallet PIN from a logged-in session.
///
/// Collects the current PIN, then the new one twice, then writes it and logs back in with
/// the new PIN so the menu keeps a valid session -- "Saving" while the change is written,
/// "Verifying" while it logs in again, the words the stock firmware uses. The new PIN is
/// entered twice because a typo here would set a PIN the owner does not know; a mismatch
/// writes nothing. A refusal (usually a wrong current PIN) leaves the session invalid, so
/// the caller reboots.
pub(crate) fn change_pin(
    gate: &Callgate,
    panel: &mut display::Panel,
    matrix: &mut GpioMatrix,
    drbg: &mut HmacDrbg,
    login: &mut Login,
) -> ChangePin {
    let g = BootloaderGate::new(gate);

    // The current PIN, with its anti-phishing words, as a login would show them.
    let Some(old_prefix) = collect(panel, matrix, drbg, "Current prefix") else {
        return ChangePin::Cancelled;
    };
    working(panel, "Checking");
    if let Some(w) = login.words_for(&g, old_prefix.as_bytes()) {
        screen_words(panel, anti_phishing_words(w));
        if !wait_for_confirm(matrix, drbg) {
            return ChangePin::Cancelled;
        }
    }
    let Some(old_suffix) = collect(panel, matrix, drbg, "Current suffix") else {
        return ChangePin::Cancelled;
    };

    // The new PIN, its words shown once so the owner can learn them.
    let Some(new_prefix) = collect(panel, matrix, drbg, "New prefix") else {
        return ChangePin::Cancelled;
    };
    working(panel, "Checking");
    if let Some(w) = login.words_for(&g, new_prefix.as_bytes()) {
        screen_words(panel, anti_phishing_words(w));
        if !wait_for_confirm(matrix, drbg) {
            return ChangePin::Cancelled;
        }
    }
    let Some(new_suffix) = collect(panel, matrix, drbg, "New suffix") else {
        return ChangePin::Cancelled;
    };

    // Entered again, and compared, so a typo cannot set an unknown PIN.
    let Some(again_prefix) = collect(panel, matrix, drbg, "Repeat prefix") else {
        return ChangePin::Cancelled;
    };
    let Some(again_suffix) = collect(panel, matrix, drbg, "Repeat suffix") else {
        return ChangePin::Cancelled;
    };
    if again_prefix.as_bytes() != new_prefix.as_bytes()
        || again_suffix.as_bytes() != new_suffix.as_bytes()
    {
        return ChangePin::Mismatch;
    }

    working(panel, "Saving");
    let step = login.change_pin(
        &g,
        old_prefix.as_bytes(),
        old_suffix.as_bytes(),
        new_prefix.as_bytes(),
        new_suffix.as_bytes(),
    );
    if !matches!(step, Ok(Step::Prefix)) {
        return ChangePin::Refused;
    }

    working(panel, "Verifying");
    login_with(&g, login, new_prefix.as_bytes(), new_suffix.as_bytes());
    if matches!(login.step(), Step::In { .. }) {
        ChangePin::Changed
    } else {
        ChangePin::Refused
    }
}

/// How a factory reset ended.
pub enum FactoryReset {
    /// The PIN was cleared: the device is blank now, and the caller must reboot into the
    /// first-run flow rather than carry on with an invalid session.
    Wiped,
    /// The owner backed out before the PIN was cleared; nothing changed.
    Cancelled,
    /// The bootloader refused — a wrong current PIN, or another failure. Either way the
    /// session is no longer valid, so the caller reboots.
    Refused,
}

/// Factory reset: clear the wallet PIN to a zero-length value, returning the device to
/// blank. The current PIN is collected first and passed as `old_pin` — the bootloader
/// takes the change only from someone who proves they hold the PIN, so this cannot wipe a
/// device that was not actually unlocked with the right PIN (and a wrong entry counts
/// toward the brick limit, exactly as a wrong login does). The caller has already
/// confirmed the intent; on any terminal outcome here the device must reboot.
pub(crate) fn factory_reset(
    gate: &Callgate,
    panel: &mut display::Panel,
    matrix: &mut GpioMatrix,
    drbg: &mut HmacDrbg,
    login: &mut Login,
) -> FactoryReset {
    let g = BootloaderGate::new(gate);

    // The current PIN, with its anti-phishing words, exactly as a login or a PIN change
    // shows them -- this is a PIN change (to nothing), so it needs the current PIN.
    let Some(old_prefix) = collect(panel, matrix, drbg, "Current prefix") else {
        return FactoryReset::Cancelled;
    };
    working(panel, "Checking");
    if let Some(w) = login.words_for(&g, old_prefix.as_bytes()) {
        screen_words(panel, anti_phishing_words(w));
        if !wait_for_confirm(matrix, drbg) {
            return FactoryReset::Cancelled;
        }
    }
    let Some(old_suffix) = collect(panel, matrix, drbg, "Current suffix") else {
        return FactoryReset::Cancelled;
    };

    working(panel, "Resetting");
    match login.clear_pin(&g, old_prefix.as_bytes(), old_suffix.as_bytes()) {
        Ok(Step::Blank) => FactoryReset::Wiped,
        _ => FactoryReset::Refused,
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
    // Attach USB only now, after `Login::new`'s callgate has returned and we are about to
    // enter the polling loop below. Presenting the device to the host any earlier -- while
    // that callgate held the CPU -- let the host start enumerating into a core nothing was
    // servicing, which wedged it. From here every enumeration packet is answered promptly.
    crate::usbtask::attach();
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
                    screen_wrong(panel, left, sent);
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

        // A host may submit the whole PIN over USB instead of typing it key by key
        // (bring-up only; see `Opcode::UnlockPin`). Drive it through the same state
        // machine a person does, auto-confirming the anti-phishing words -- the host
        // has chosen to trust the device it is talking to. A blank device needs setup,
        // not this, and one already in is left alone.
        if let Some(pin) = crate::usbtask::take_unlock_pin()
            && !matches!(login.step(), Step::Blank | Step::In { .. })
        {
            // From a wrong-PIN screen, reset to a fresh prefix before applying.
            if !matches!(login.step(), Step::Prefix) {
                login = Login::new(&g);
            }
            if let (Step::Prefix, Some((prefix, suffix))) = (login.step(), split_pin(&pin)) {
                working(panel, "USB unlock");
                login_with(&g, &mut login, prefix, suffix);
                field.clear();
            }
            redraw = true;
            continue;
        }

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
