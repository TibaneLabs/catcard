//! *Debug -> Self-tests*: an extensible harness for the risky low-level checks that can
//! break the device, each run on demand behind a confirmation.
//!
//! The device's other "Selftest" (singular) is the boot POST report; this is a separate
//! thing -- a menu of *deliberate* fault injections, so a low-level defence that would
//! otherwise only be exercised by a real crash can be proven on the bench. Each entry
//! arms something, shows its state, and offers a confirmed probe that trips it; a working
//! defence wipes and resets, a broken one returns and the screen says so.
//!
//! Adding a future risky feature is one row in [`TESTS`], not a bespoke screen: give it a
//! name and a `run` function that owns the panel until the owner presses Cancel.
//!
//! Compiled out of a ship build: the whole harness lives behind `usb-debug-mem`, the same
//! gate the peek/poke tools use.

use catcard_ui::keypad::{Event, KEYS, Key};

use crate::display;
use crate::ui::Ui;

/// One named self-test. `run` takes the panel and drives its own arm/observe/probe flow,
/// returning when the owner presses Cancel.
struct SelfTest {
    name: &'static str,
    run: fn(&mut Ui<'_>),
}

/// The self-tests, in the order shown. Digit `n` runs row `n`.
static TESTS: &[SelfTest] = &[
    SelfTest {
        name: "Stack fence (MPU)",
        run: crate::stackguard::fence_test,
    },
    SelfTest {
        name: "Switch canary",
        run: crate::stackguard::canary_test,
    },
];

type Line = heapless::String<48>;

/// The harness screen: a numbered list, a digit to run one, Cancel to leave.
pub(crate) fn screen(ui: &mut Ui<'_>) {
    loop {
        draw(ui.panel);
        match wait_key(ui) {
            Key::Cancel => return,
            Key::Digit(d) => {
                let idx = (d as usize).wrapping_sub(1);
                if let Some(t) = TESTS.get(idx) {
                    crate::catlog!("selftest: entering {}", t.name);
                    (t.run)(ui);
                }
            }
            _ => {}
        }
    }
}

/// List the tests with their digit, plus the boot invariant so the owner knows nothing
/// here is armed until they arm it.
fn draw(panel: &mut display::Panel) {
    use core::fmt::Write as _;

    let mut lines: heapless::Vec<Line, 6> = heapless::Vec::new();
    for (i, t) in TESTS.iter().enumerate() {
        let mut l = Line::new();
        let _ = write!(l, "{} {}", i + 1, t.name);
        let _ = lines.push(l);
    }
    let mut l = Line::new();
    let _ = l.push_str("off until armed; CANCEL");
    let _ = lines.push(l);

    crate::menu::info(panel, "Self-tests", &lines);
}

/// Block until a key is pressed, servicing USB meanwhile. Cancel wins over anything
/// pressed with it.
fn wait_key(ui: &mut Ui<'_>) -> Key {
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        let _ = crate::usbtask::pump();
        crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
        if let Some(k) = keys
            .iter()
            .copied()
            .find(|&k| k == Key::Cancel)
            .or(keys.first().copied())
        {
            return k;
        }
        display::idle(ui.panel);
    }
}
