//! Typing into the host as a USB keyboard.
//!
//! The one thing the device can do *to* a host rather than for it: with `Keyboard EMU`
//! on (Settings → Hardware On/Off), it enumerates a boot-protocol keyboard beside the
//! wallet interface, and [`type_text`] sends a string as keystrokes into whatever
//! window the host has focused. That is how a BIP-85 password or a stored note reaches
//! a login form without going through a clipboard the host's other software can read.
//!
//! What this module owns is *when* the reports go out and what happens when they do
//! not. The keycodes, the report bytes and the descriptors are [`catcard_usb::kbd`],
//! tested on the host; the endpoint registers are the HAL's.
//!
//! # Rules
//!
//! - **Nothing is typed unless all of it can be.** A string with a character the US
//!   table has no key for is refused whole, before the first report, rather than typed
//!   up to the character and then abandoned half-way into a password field.
//! - **Every wait is bounded.** A host that stops taking reports -- the window lost
//!   focus on a locked screen, the OS suspended the port -- costs the caller
//!   [`REPORT_MS`] and an error, never a hang. A whole string is bounded again by
//!   [`TOTAL_MS`].
//! - **Nothing is logged.** Not the text, not its length. The log is readable by any
//!   host that can open the port, and a password's length is a fact about the password.
//! - **No Enter unless asked.** [`type_text`] ends with the last character released;
//!   [`Options::enter`] adds the keystroke for callers that mean "and submit".
//!
//! The device's screen, not this module, is what says the text is about to go out --
//! the caller confirms with the owner first, then calls in.

use catcard_usb::kbd::{self, Report};

use crate::usbtask::{self, KbdSend};

/// Why a string was not typed, or not typed whole.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// `Keyboard EMU` is switched off, so the host has no keyboard to type into.
    Off,
    /// The port is off, the device is a disk right now, or no host has configured it.
    NoHost,
    /// This character has no key on the US layout. Nothing was sent.
    Untypeable(char),
    /// Longer than [`MAX_CHARS`]. Nothing was sent.
    TooLong,
    /// The host stopped taking reports. Some of the text may have been typed; the last
    /// report sent was a release, or is one the host never took, so no key is left down.
    HostNotReading,
}

impl Error {
    /// A line for the screen.
    pub fn describe(&self) -> &'static str {
        match self {
            Error::Off => "Keyboard EMU is off",
            Error::NoHost => "no host is listening",
            Error::Untypeable(_) => "a character has no key",
            Error::TooLong => "too long to type",
            Error::HostNotReading => "the host stopped reading",
        }
    }
}

/// Longest string [`type_text`] will send. A password or a note line, not a document;
/// with [`TOTAL_MS`] this bounds the whole call.
pub const MAX_CHARS: usize = 256;

/// Gap left between two reports, in milliseconds. A press and its release two reports
/// apart with nothing between would be a key down for one host polling interval, which
/// some hosts debounce away; a few milliseconds is what a fast typist's key takes.
const PACE_MS: u32 = 5;

/// How long one report may wait for the host to take the previous one, in
/// milliseconds. Well under a second, so a host that has stopped reading is reported
/// as such within one -- the pace and the check both count against it.
const REPORT_MS: u32 = 800;

/// How long a whole call may take, in milliseconds, pacing and waiting included. At
/// [`PACE_MS`] a full [`MAX_CHARS`] string takes about three seconds on a host that is
/// reading; the rest is slack for one that is slow, not one that has stopped.
const TOTAL_MS: u32 = 20_000;

const _: () = assert!(PACE_MS < REPORT_MS && REPORT_MS < 1000);
const _: () = assert!((MAX_CHARS as u32 + 1) * 2 * PACE_MS < TOTAL_MS);

/// What to do after the last character.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Options {
    /// Press Enter after the text, as a form's submit. Off unless asked: a password
    /// typed into the wrong field is recoverable, one that was also submitted is not.
    pub enter: bool,
}

/// Type `text` into the host, character by character, and press nothing after it.
///
/// Each character is one press report and one release report, paced [`PACE_MS`] apart.
/// Returns once the host has taken the final release, so on `Ok` no key is left down.
pub fn type_text(text: &str) -> Result<(), Error> {
    type_text_with(text, Options::default())
}

/// [`type_text`], with a say in what follows the text.
pub fn type_text_with(text: &str, opt: Options) -> Result<(), Error> {
    check(text)?;
    let mut budget = Budget::new(TOTAL_MS);
    for c in text.chars() {
        // Checked just above; a `None` here would be a table that changed under us.
        let Some(stroke) = kbd::keycode(c) else {
            return Err(Error::Untypeable(c));
        };
        send(&Report::press(stroke), &mut budget)?;
        send(&Report::RELEASE, &mut budget)?;
    }
    if opt.enter {
        let Some(enter) = kbd::keycode('\n') else {
            return Err(Error::Untypeable('\n'));
        };
        send(&Report::press(enter), &mut budget)?;
        send(&Report::RELEASE, &mut budget)?;
    }
    // The last release is in the FIFO; wait for the host to take it, so "typed" means
    // typed and not "queued on a device the host may have stopped polling".
    wait_taken(&mut budget)
}

/// Whether `text` can be typed at all: the switch is on, it is not too long, and every
/// character has a key. All or nothing, checked before anything goes out -- and by the
/// screen before it asks, so "type it?" is never asked about something that cannot be.
pub fn check(text: &str) -> Result<(), Error> {
    if !usbtask::keyboard_on() {
        return Err(Error::Off);
    }
    if text.chars().count() > MAX_CHARS {
        return Err(Error::TooLong);
    }
    kbd::typeable(text).map_err(Error::Untypeable)
}

/// Whether the host would take a keystroke right now: the switch is on, the port is
/// up, and a host has configured the composite device. For a screen to say "no host"
/// before asking the owner to confirm, rather than after.
pub fn ready() -> bool {
    usbtask::keyboard_on() && usbtask::kbd_ready()
}

/// The screen every sender goes through -- a note's password, a BIP-85 child -- and
/// the one place the owner is asked.
///
/// Says why not if the keyboard is off, the text cannot be typed or no host is
/// listening; offers Enter after the text, as stock does; then asks, because the cursor
/// has to be in the right field on the host before a keystroke goes out. `note` is what
/// the question names -- a title, a path -- never the text. True once the host has taken
/// the whole of it.
///
/// Nothing about the text is logged, not even why it was refused: "a character has no
/// key" is a fact about the text, and the log is a host's to read.
///
/// Source: help-and-warning-screens.md "Send BIP-85 password as USB keystrokes" and
/// §16 "View / send password" [C]
pub fn send_screen(ui: &mut crate::ui::Ui<'_>, head: &str, note: &str, text: &str) -> bool {
    use crate::menu;
    if let Err(why) = check(text) {
        let (a, b) = match why {
            Error::Off => ("Keyboard EMU is off", "Settings > Hardware On/Off"),
            other => (other.describe(), "cannot be typed"),
        };
        menu::message(ui.panel, head, a, b);
        menu::wait_for_any_key(ui);
        return false;
    }
    if !ready() {
        menu::message(
            ui.panel,
            head,
            "no host is listening",
            "plug in, then retry",
        );
        menu::wait_for_any_key(ui);
        return false;
    }
    let Some(row) = menu::pick_row(ui, head, "after the text", &["Nothing", "Press Enter"]) else {
        return false;
    };
    let opt = Options { enter: row == 1 };
    menu::ask(ui.panel, head, note, "type into the host now?");
    if !menu::confirmed(ui) {
        return false;
    }
    menu::message(ui.panel, head, "typing", "cursor in the host's field");
    match type_text_with(text, opt) {
        Ok(()) => {
            crate::catlog!("kbd: text typed");
            menu::message(ui.panel, head, "typed", "any key to go back");
            menu::wait_for_any_key(ui);
            true
        }
        Err(why) => {
            crate::catlog!("kbd: text not typed");
            menu::message(ui.panel, head, why.describe(), "any key to go back");
            menu::wait_for_any_key(ui);
            false
        }
    }
}

/// Milliseconds left for the whole call, spent one at a time.
struct Budget {
    left: u32,
}

impl Budget {
    fn new(ms: u32) -> Self {
        Self { left: ms }
    }

    /// Pause a millisecond, servicing USB, and charge it. `false` when the budget is
    /// gone.
    fn tick(&mut self) -> bool {
        if self.left == 0 {
            return false;
        }
        self.left -= 1;
        // The service task polls the core under the kernel; before it starts, `pump`
        // is what does. Either way the wait is a millisecond of wall clock.
        let _ = usbtask::pump();
        // SAFETY: reads RCC to scale the delay to the live clock.
        unsafe { catcard_hal::dwt::delay_ms(1) };
        true
    }
}

/// Pace, then send one report, retrying while the host is still taking the previous
/// one. Bounded by [`REPORT_MS`] for this report and by the budget for the call.
fn send(report: &Report, budget: &mut Budget) -> Result<(), Error> {
    for _ in 0..PACE_MS {
        if !budget.tick() {
            return Err(Error::HostNotReading);
        }
    }
    for _ in 0..REPORT_MS {
        match usbtask::kbd_send(report) {
            KbdSend::Sent => return Ok(()),
            KbdSend::Unavailable => return Err(Error::NoHost),
            KbdSend::Busy => {}
        }
        if !budget.tick() {
            return Err(Error::HostNotReading);
        }
    }
    Err(Error::HostNotReading)
}

/// Wait for the host to take the report last sent. Bounded like [`send`].
fn wait_taken(budget: &mut Budget) -> Result<(), Error> {
    for _ in 0..REPORT_MS {
        if !usbtask::kbd_busy() {
            return Ok(());
        }
        if !budget.tick() {
            return Err(Error::HostNotReading);
        }
    }
    Err(Error::HostNotReading)
}

/// Debug → Keyboard EMU test: type a fixed, harmless line into the host.
///
/// The way the feature is proven on hardware: switch it on, open a text editor on the
/// host, run this, and read the line. The text is a constant, so it is safe to name on
/// the screen and in the log, which a real use of [`type_text`] never is.
pub fn self_test(ui: &mut crate::ui::Ui<'_>) {
    use crate::menu;
    const HEAD: &str = "Keyboard EMU test";
    const LINE: &str = "catcard keyboard ok";

    if !usbtask::keyboard_on() {
        menu::message(ui.panel, HEAD, "Keyboard EMU is off", "Settings > Hardware");
        menu::wait_for_any_key(ui);
        return;
    }
    if !ready() {
        menu::message(
            ui.panel,
            HEAD,
            "no host is listening",
            "plug in, then retry",
        );
        menu::wait_for_any_key(ui);
        return;
    }
    menu::ask(
        ui.panel,
        HEAD,
        "types a test line",
        "into the host's window",
    );
    if !menu::confirmed(ui) {
        return;
    }
    menu::message(ui.panel, HEAD, "typing", "");
    match type_text(LINE) {
        Ok(()) => {
            crate::catlog!("kbd: self-test line typed");
            menu::message(
                ui.panel,
                HEAD,
                "typed: check the host",
                "any key to go back",
            );
        }
        Err(why) => {
            crate::catlog!("kbd: self-test failed: {}", why.describe());
            menu::message(ui.panel, HEAD, why.describe(), "any key to go back");
        }
    }
    menu::wait_for_any_key(ui);
}
