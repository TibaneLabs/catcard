//! What the Q1's status bar is showing, gathered from the rest of the firmware.
//!
//! [`catcard_ui::statusbar`] draws; this decides what. The split matters because the bar
//! is painted on **every frame**: anything expensive, or anything that could prompt, must
//! not be reachable from here. In particular the master fingerprint is taken only if some
//! other screen has already paid for it -- the bar must never be the reason a seed is
//! stretched.
//!
//! The modifier keys are the one piece that cannot simply be read at paint time. They are
//! scanned by the keypad and decode to no key at all, so holding SHIFT produces no event
//! and nothing would repaint. [`note`] records them from the scan that every idle poll
//! already runs, and [`take_dirty`] tells that poll when the bar is stale.

use crate::keypad::Keypad;
use catcard_ui::statusbar::{Power, Status};

/// The modifiers as the last scan saw them, packed so a change is one comparison.
static mut MODIFIERS: u8 = 0;
/// Set when a poll sees a change the panel has not been shown yet.
static mut DIRTY: bool = false;
/// The power source as the last poll saw it.
///
/// Unlike the modifiers this changes with a *cable*, so there is no keypress and no scan
/// to hang the notice off -- without sampling it, the icon would sit wrong until some
/// unrelated thing happened to repaint the screen.
static mut POWER: Option<crate::battery::Source> = None;

const SHIFT: u8 = 1;
const SYMBOL: u8 = 2;
const CAPS: u8 = 4;

/// Record the modifier state from a keypad that has just been scanned.
///
/// Called from the keypad poll, which every waiting screen runs -- the same reasoning
/// that puts the power button and the USB light there. A bar that only tracked the
/// keyboard on one screen would be a bar nobody could trust on the others.
pub(crate) fn note(pad: &Keypad) {
    let held = pad.held_mask();
    let mut now = 0u8;
    if held & (1 << catcard_ui::qwerty::KN_SHIFT) != 0 {
        now |= SHIFT;
    }
    if held & (1 << catcard_ui::qwerty::KN_SYMBOL) != 0 {
        now |= SYMBOL;
    }
    if pad.caps() {
        now |= CAPS;
    }
    // SAFETY: foreground only, single core; the borrows end within this function.
    unsafe {
        if *core::ptr::addr_of!(MODIFIERS) != now {
            *core::ptr::addr_of_mut!(MODIFIERS) = now;
            *core::ptr::addr_of_mut!(DIRTY) = true;
        }
    }
}

/// Whether the bar has changed since it was last painted, clearing the flag.
pub(crate) fn take_dirty() -> bool {
    // SAFETY: as in `note`.
    unsafe { core::mem::replace(&mut *core::ptr::addr_of_mut!(DIRTY), false) }
}

/// Everything the bar shows, as it stands right now.
pub(crate) fn status() -> Status {
    // SAFETY: as in `note`.
    let mods = unsafe { *core::ptr::addr_of!(MODIFIERS) };
    Status {
        shift: mods & SHIFT != 0,
        symbol: mods & SYMBOL != 0,
        caps: mods & CAPS != 0,
        key: crate::key::label(),
        key_set: !crate::key::is_root(),
        // Only if a screen has already derived it. Never an unlock from here.
        fingerprint: crate::pubkeys::known_fingerprint(),
        power: crate::battery::source().map(|s| match s {
            crate::battery::Source::External => Power::External,
            crate::battery::Source::Battery => Power::Battery,
        }),
    }
}

/// Repaint the bar if anything on it moved since the last frame.
///
/// For the idle poll of a screen that is waiting on a key. Two register reads and a
/// comparison when nothing changed, which is almost always.
///
/// The modifiers arrive through [`note`], off the keypad scan. The power source has no
/// such hook -- it changes when someone moves a cable -- so it is sampled here. Stock
/// arms an edge interrupt on rev-D+ boards and polls as a backstop; polling alone is
/// enough while a screen is waiting, which is whenever anyone is looking at the bar.
///
/// Source: hw-reference/power.md §"Power source: battery vs USB" [C]
#[cfg(feature = "board-q1")]
pub(crate) fn poll(panel: &mut crate::display::Panel) {
    let now = crate::battery::source();
    // SAFETY: foreground only, single core; the borrows end within this block.
    unsafe {
        if *core::ptr::addr_of!(POWER) != now {
            *core::ptr::addr_of_mut!(POWER) = now;
            *core::ptr::addr_of_mut!(DIRTY) = true;
        }
    }
    if take_dirty() {
        crate::display::refresh_bar(panel);
    }
}
