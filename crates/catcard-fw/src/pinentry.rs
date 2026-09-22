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
use catcard_pin::{Failure, Login, MAX_ATTEMPTS, MAX_PART_LEN, MIN_PART_LEN, PinGate, Step};
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
    // The modifiers and the lamp key decode to no key, so this is the only place either
    // is ever seen.
    #[cfg(feature = "board-q1")]
    crate::statusbar::note(pad);
    #[cfg(feature = "board-q1")]
    crate::torch::note(pad);
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
fn at<C: Canvas + ?Sized>(c: &C, y: usize) -> usize {
    y * c.height() / DESIGN_ROWS
}

/// One line of the layout's title face, centred, at design row `y`.
fn title<C: Canvas + ?Sized>(c: &mut C, y: usize, s: &str) {
    let f = display::LAYOUT.title;
    let (x, y) = (centred(f, s, c.width()), at(c, y));
    draw_text(c, f, x, y, s);
}

/// One line of the layout's body face, centred, at design row `y`.
fn small<C: Canvas + ?Sized>(c: &mut C, y: usize, s: &str) {
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
fn tries_left<C: Canvas + ?Sized>(c: &mut C, left: u32) {
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

/// The PIN prompt on the Q1: one field in two halves, the words appearing in the first.
///
/// # Why one screen instead of three
///
/// The prompt used to be a field, then a separate screen for the anti-phishing words
/// with its own confirm, then a second field. That is two presses of the accept key for
/// one PIN, and the words -- the thing the owner is meant to *check* -- were on a screen
/// that had gone by the time the half that matters was typed.
///
/// Here the top half holds the prefix, and the moment it is accepted the words take its
/// place with the caret in the bottom half. One press, and the words stay in front of
/// the owner for as long as they are typing the half that would be given away if the
/// device were not theirs.
///
/// # It is the same card every other typing screen draws
///
/// Two rows of [`catcard_ui::field`], sharing an edge: marks for the digits, text for
/// the words. This screen used to lay out its own boxes, its own prints and its own
/// caret, and then the passphrase and the BIP-85 index each invented something else. The
/// geometry lives in the widget now, and what is left here is which rows there are.
///
/// `caret` is the blink, which belongs to the loop that polls the keypad -- see
/// [`unlock`].
#[cfg(feature = "board-q1")]
fn screen_pin(
    panel: &mut display::Panel,
    prefix: usize,
    words: Option<[&str; 2]>,
    suffix: usize,
    caret: bool,
    busy: bool,
    left: u32,
) {
    use catcard_ui::canvas::Canvas as _;
    use catcard_ui::field::{self, Field};

    /// What the row just accepted says while the secure element is working on it.
    const CHECKING: &[&str] = &["Checking", "please wait"];

    /// Stand-ins for the digits: the widget draws one print per character and never
    /// looks at them, so the marks row is handed a count and not a PIN.
    const DOTS: &str = "......";

    let body = display::LAYOUT.body;
    let filled = words.is_some();

    // Both rows are six-print rows the whole time. Once the prefix is accepted the top
    // one shows the two words, one per line, as its placeholder -- keeping its size, so
    // the card does not jump at the moment the owner is meant to be reading it.
    let said: [&str; 2] = words.unwrap_or(["", ""]);
    let top = Field::marks(&DOTS[..prefix.min(MAX_PART_LEN)], MAX_PART_LEN).live(!filled);
    let top = match (filled, busy) {
        (true, _) => top.placeholder(&said),
        // The prefix was just accepted and its words are being fetched: this row says
        // so, in place, rather than the whole screen going away for a second.
        (false, true) => top.placeholder(CHECKING).live(false),
        (false, false) => top,
    };
    let bottom = Field::marks(&DOTS[..suffix.min(MAX_PART_LEN)], MAX_PART_LEN).live(filled);
    // The same for the suffix, while the PIN itself is being tried.
    let bottom = if filled && busy {
        bottom.placeholder(CHECKING).live(false)
    } else {
        bottom
    };
    let fields = [top, bottom];

    display::draw_field_page(panel, |c| {
        c.clear();
        let below = field::stack(
            c,
            &display::LAYOUT,
            display::FIELD_TOP,
            &fields,
            display::FIELD_SKIN,
            caret,
        );

        // What the two halves are, and what the keys do, in the space around them.
        let head = if filled {
            "these words must be yours"
        } else {
            "PIN prefix"
        };
        let hx = centred(body, head, c.width());
        draw_text(
            c,
            body,
            hx,
            display::FIELD_TOP.saturating_sub(body.line_height() + 6),
            head,
        );

        let typed = if filled { suffix } else { prefix };
        let foot = if busy {
            ""
        } else if typed < MIN_PART_LEN {
            "2 to 6 digits"
        } else if filled {
            "accept to log in"
        } else {
            "accept for the words"
        };
        let fx = centred(body, foot, c.width());
        draw_text(c, body, fx, below + 6, foot);
        tries_left(c, left);
    });
}

/// The PIN screen, with the row just accepted saying it is being checked, and the
/// co-processor's bar moving under it.
///
/// Drawn **before** the callgate, which holds the CPU for a second or more with nothing
/// able to repaint: a device that shows no reaction to the accept key invites a second
/// press, and on the suffix a second press is a second attempt spent. This used to be a
/// separate "Checking" screen; it is the same screen now, so the words stay in view.
#[cfg(feature = "board-q1")]
fn checking(panel: &mut display::Panel, login: &Login, prefix: usize, suffix: usize) {
    let words = login.words().map(anti_phishing_words);
    let words = if matches!(login.step(), Step::Suffix) {
        words
    } else {
        None
    };
    screen_pin(
        panel,
        prefix,
        words,
        suffix,
        false,
        true,
        login.attempts_left(),
    );
    if display::GPU_BAR_ON_BLOCKING {
        display::scroll_busy_bar(panel);
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
        // A paw print per digit instead of a `*`. The trail is placed for the longest part
        // a PIN can have and filled from its left, so each digit adds a print ahead of the
        // last and nothing already drawn moves: a cat walking in, not a row that re-centres
        // itself on every key. One print per digit, so it gives away exactly what the stars
        // did -- how many -- and nothing about which.
        use catcard_ui::icons::{draw_paw_trail, paw_trail_size};
        let scale = (c.height() / DESIGN_ROWS).max(1);
        let (trail_w, _) = paw_trail_size(MAX_PART_LEN, scale);
        let x = c.width().saturating_sub(trail_w) / 2;
        draw_paw_trail(c, buf.len(), x, at(c, 22), scale);
        if buf.len() < MIN_PART_LEN {
            small(c, 46, "2 to 6 digits");
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
fn two_key_hint<C: Canvas + ?Sized>(c: &mut C, y: usize, yes: &str, no: &str) {
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

/// The owner's nickname, before the PIN prompt, as stock shows it.
///
/// Its whole purpose is to be seen *before* a PIN is typed: it is how the owner tells their
/// device from a substituted one. So it is drawn on its own screen rather than tucked into a
/// corner of the prompt, and it **waits for a key** rather than passing on its own -- a
/// message that disappears while you are reading it is no use as a check.
///
/// USB is pumped while it waits, and it is shown *after* the device has attached, so a host
/// can still reach a device sitting on this screen: the wait is indefinite from the owner's
/// side, and the recovery path must not depend on someone being in the room. A key from the
/// host dismisses it exactly as a key on the keypad does.
#[cfg(not(feature = "board-mk3"))]
pub fn show_nickname(
    panel: &mut display::Panel,
    matrix: &mut GpioMatrix,
    drbg: &mut HmacDrbg,
    nick: &str,
) {
    use catcard_ui::keypad::{Event, KEYS, Key};
    // Wrapped, not a title: a nickname is whatever its owner typed, and one of them turned
    // out to be a paragraph. A title would draw it off both edges of the screen.
    use catcard_ui::scroll::{Line, ScrollView, render};
    let mut hint = heapless::String::<32>::new();
    let _ = core::fmt::Write::write_fmt(
        &mut hint,
        format_args!("{} to continue", display::CONFIRM_KEY),
    );
    let mut doc: heapless::Vec<Line, 4> = heapless::Vec::new();
    let _ = doc.push(Line::body(nick).wrapped());
    let _ = doc.push(Line::body(hint.as_str()).small());
    let view = ScrollView::build(&doc, display::SCREEN_W, display::SCREEN_H, display::FONTS);
    display::draw(panel, |c| render(c, &view));
    crate::catlog!("nick: drawn, {} px of content", view.content_height());

    let mut pad = Keypad::new();
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    // SAFETY: reads RCC only.
    let per_ms = (unsafe { catcard_hal::clock::hclk_hz() } / 1000).max(1);

    // Throw away the first sample. A fresh scanner reports a key that is already down as a
    // new press, and a host that has just installed firmware has injected one -- so without
    // this the screen is dismissed by the keypress that caused the reboot.
    pressed_keys(&mut pad, matrix, drbg, &mut events, &mut keys);
    keys.clear();

    // Bounded, as every wait here is: five minutes is far longer than anyone stands in
    // front of a device, and a keypad that has failed must cost the screen, not the boot.
    let mut waited = 0u32;
    for _ in 0..30_000 {
        let _ = crate::usbtask::pump();
        pressed_keys(&mut pad, matrix, drbg, &mut events, &mut keys);
        if !keys.is_empty() {
            break;
        }
        waited += 1;
        catcard_hal::dwt::delay_cycles(10 * per_ms);
    }
    crate::catlog!("nick: dismissed after {} ms", waited * 10);
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

/// Record what the bootloader said, every time the login state machine moves.
///
/// Never the PIN, and never its digits: the step, the two counters the gate reports, and
/// the refusal code if there was one. That is the whole of what a bootloader we cannot see
/// inside tells us, and without it a device that will not log in says nothing at all to
/// anyone holding it over USB -- which is exactly the situation where the screen is not the
/// thing you can read.
fn log_state(login: &Login, what: &str) {
    match login.step() {
        Step::Blank => crate::catlog!("pin: {} -> blank, no PIN set", what),
        Step::Prefix => crate::catlog!(
            "pin: {} -> prefix, {} left, {} fails",
            what,
            login.attempts_left(),
            login.num_fails()
        ),
        Step::ConfirmWords(_) => crate::catlog!("pin: {} -> words", what),
        Step::Suffix => crate::catlog!("pin: {} -> suffix", what),
        Step::In { zero_secret } => crate::catlog!(
            "pin: {} -> in, secret slot {}",
            what,
            if zero_secret { "EMPTY" } else { "in use" }
        ),
        Step::Wrong {
            attempts_left,
            num_fails,
        } => crate::catlog!(
            "pin: {} -> WRONG, {} left, {} fails",
            what,
            attempts_left,
            num_fails
        ),
        Step::Bricked => crate::catlog!("pin: {} -> BRICKED", what),
        Step::Failed(f) => match f {
            catcard_pin::Failure::Code(c) => {
                crate::catlog!("pin: {} -> refused, gate code {}", what, c)
            }
            catcard_pin::Failure::Gate(_) => {
                crate::catlog!("pin: {} -> callgate unreachable", what)
            }
            catcard_pin::Failure::NeedsSetup => crate::catlog!("pin: {} -> needs setup", what),
            catcard_pin::Failure::MustWait => crate::catlog!("pin: {} -> must wait", what),
            catcard_pin::Failure::ImageRefused => {
                crate::catlog!("pin: {} -> image refused", what)
            }
        },
    }
}

/// "Working on it" — drawn before anything that blocks on the secure element.
///
/// Every one of these waits is a callgate call: interrupts masked, the CPU inside the
/// bootloader's firewall, nothing the firmware can do until it returns. So the movement is
/// handed to the panel, which scrolls the bar from its own frame counter and does not care
/// that the CPU is busy. Where the controller cannot do that, the screen stays a plain
/// message rather than a bar frozen mid-sweep — see
/// [`menu::blocking_screen`](crate::menu::blocking_screen).
fn working(panel: &mut display::Panel, what: &str) {
    crate::menu::blocking_screen(panel, what, "please wait");
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
                // Accepting fewer than MIN_PART_LEN digits would set a PIN part that
                // stock firmware cannot type, so the key simply waits for another digit.
                Key::Confirm => {
                    if field.len() >= MIN_PART_LEN {
                        return Some(field);
                    }
                }
                Key::Char(_) => {}
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
/// Returns `None` unless both parts are all ASCII digits and [`MIN_PART_LEN`] to
/// [`MAX_PART_LEN`] long -- the same shape [`PinBuffer`] would have produced from the
/// keypad, so the gate hashes exactly what a typed PIN would, and no host can hand this
/// device a PIN part stock firmware could not type.
pub(crate) fn split_pin(pin: &[u8]) -> Option<(&[u8], &[u8])> {
    let sep = pin.iter().position(|&b| b == catcard_pin::SEPARATOR)?;
    let (prefix, rest) = pin.split_at(sep);
    let suffix = &rest[1..];
    let ok = |part: &[u8]| catcard_pin::part_len_ok(part) && part.iter().all(u8::is_ascii_digit);
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
    // The owner's nickname, shown once the device has attached to USB. Always `None` on the
    // mk3, whose settings medium is not wired up -- hence the underscore there.
    #[cfg_attr(feature = "board-mk3", allow(unused_variables))] nick: Option<&str>,
) -> (Unlocked, Login) {
    let g = BootloaderGate { gate };
    let mut login = Login::new(&g);
    log_state(&login, "setup");
    // Attach USB only now, after `Login::new`'s callgate has returned and we are about to
    // enter the polling loop below. Presenting the device to the host any earlier -- while
    // that callgate held the CPU -- let the host start enumerating into a core nothing was
    // servicing, which wedged it. From here every enumeration packet is answered promptly.
    crate::usbtask::attach();

    // The nickname, if the owner set one, before anything is typed -- and after `attach`,
    // so a host can reach a device that is sitting on it.
    #[cfg(not(feature = "board-mk3"))]
    if let Some(nick) = nick {
        show_nickname(panel, matrix, drbg, nick);
    }

    let mut field = PinBuffer::<MAX_PART_LEN>::new();
    let mut pad = Keypad::new();
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    let mut redraw = true;

    // The caret blinks from here rather than from the co-processor: half a second on,
    // half a second off, toggled below. A redraw for each toggle is affordable because
    // the panel is flushed row by row against what it already shows, so what reaches
    // the wire is the few rows the caret sits in.
    #[cfg(feature = "board-q1")]
    let (mut caret, mut caret_at) = (true, catcard_hal::dwt::cycles());
    // SAFETY: reads RCC only.
    #[cfg(feature = "board-q1")]
    let blink = (unsafe { catcard_hal::clock::hclk_hz() } / 2).max(1);

    loop {
        // A host driving this device needs to know which screen it is looking at.
        crate::usbtask::set_blank(matches!(login.step(), Step::Blank));

        // Only where there is a caret to blink: anywhere else this would repaint a
        // static screen twice a second for nothing.
        #[cfg(feature = "board-q1")]
        if matches!(login.step(), Step::Prefix | Step::Suffix) {
            let now = catcard_hal::dwt::cycles();
            if now.wrapping_sub(caret_at) >= blink {
                caret_at = now;
                caret = !caret;
                redraw = true;
            }
        }

        if redraw {
            match login.step() {
                // One screen for the whole PIN on the Q1: the prefix half, then the
                // words in its place with the caret in the second. The words the owner
                // is meant to check stay in front of them while the half that matters
                // is typed, and it costs one press of the accept key rather than two.
                #[cfg(feature = "board-q1")]
                Step::Prefix => screen_pin(
                    panel,
                    field.len(),
                    None,
                    0,
                    caret,
                    false,
                    login.attempts_left(),
                ),
                // Not normally drawn: the accept key that submits the prefix also
                // passes this step, because the screen it would show is the screen
                // already on its way. Kept so a path that does stop here has a picture.
                #[cfg(feature = "board-q1")]
                Step::ConfirmWords(w) => screen_pin(
                    panel,
                    0,
                    Some(anti_phishing_words(w)),
                    0,
                    caret,
                    false,
                    login.attempts_left(),
                ),
                #[cfg(feature = "board-q1")]
                Step::Suffix => screen_pin(
                    panel,
                    0,
                    login.words().map(anti_phishing_words),
                    field.len(),
                    caret,
                    false,
                    login.attempts_left(),
                ),
                #[cfg(not(feature = "board-q1"))]
                Step::Prefix => screen_field(panel, "PIN prefix", &field, login.attempts_left()),
                #[cfg(not(feature = "board-q1"))]
                Step::ConfirmWords(w) => screen_words(panel, anti_phishing_words(w)),
                #[cfg(not(feature = "board-q1"))]
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
        // Solid again from the moment a key goes in: a caret that happened to be
        // blinked out as a digit landed reads as a key the device did not take.
        #[cfg(feature = "board-q1")]
        if !keys.is_empty() {
            caret = true;
            caret_at = catcard_hal::dwt::cycles();
        }
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
                // Not before MIN_PART_LEN digits: no PIN has a shorter part, so a
                // shorter one could only spend an attempt.
                (Step::Prefix, Key::Confirm) => {
                    if field.len() >= MIN_PART_LEN {
                        // Both of these block for as long as the secure element takes,
                        // with no display update and no USB polling in between. Without
                        // a screen first, the device looks like it ignored the key --
                        // and the natural response to that is to press it again, which
                        // on the suffix means spending a second PIN attempt.
                        #[cfg(feature = "board-q1")]
                        checking(panel, &login, field.len(), 0);
                        #[cfg(not(feature = "board-q1"))]
                        working(panel, "Checking");
                        let _ = login.prefix_entered(&g, field.as_bytes());
                        log_state(&login, "prefix");
                        field.clear();
                        // On the Q1 the words take the prefix's own box on the next
                        // redraw and stay there for the whole suffix, so a screen whose
                        // only job is to show them has nothing left to say -- and the
                        // owner presses accept once for a PIN instead of twice. A no-op
                        // on any other step, so a gate that gave no words is unaffected.
                        #[cfg(feature = "board-q1")]
                        login.words_confirmed();
                    }
                }
                (Step::Suffix, Key::Confirm) => {
                    if field.len() >= MIN_PART_LEN {
                        #[cfg(feature = "board-q1")]
                        checking(panel, &login, 0, field.len());
                        #[cfg(not(feature = "board-q1"))]
                        working(panel, "Checking PIN");
                        let _ = login.attempt(&g, field.as_bytes());
                        log_state(&login, "attempt");
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
