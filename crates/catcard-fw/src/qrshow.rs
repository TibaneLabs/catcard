//! Showing a file as animated QR, so it can be read without a card or a cable.
//!
//! One QR code holds a few hundred bytes at a size a camera can read off this panel, and
//! a wallet export is a few thousand. So the file is split into BBQr parts and shown in
//! turn, over and over: the reader collects whichever it catches, in any order, until it
//! has them all. Nothing has to be caught in sequence, which is what makes it work at
//! all with a hand-held phone.
//!
//! # The part size is chosen by what the screen can draw, not by what a symbol can hold
//!
//! A version-40 symbol holds 4,296 alphanumeric characters, and on a 320-pixel panel
//! that is 177 modules at one pixel each -- a grey square as far as a camera is
//! concerned. What matters is modules-per-pixel, so the part size is derived downwards
//! from the largest symbol that still gets three pixels a module, and
//! [`catcard_bbqr::encode::fits`] turns that back into bytes.

use catcard_bbqr::FileType;
use catcard_bbqr::encode;

use core::fmt::Write as _;

use catcard_ui::keypad::{Event, KEYS, Key};

use crate::display;
use crate::menu;
use crate::ui::Ui;

/// The largest symbol drawn. Version 12 is 65 modules, which is three pixels a module on
/// a 320-wide panel with its quiet zone -- about the smallest a phone reads reliably at
/// arm's length.
const VERSION: u8 = 12;
/// Characters a version-12 symbol holds in alphanumeric mode at error-correction L.
///
/// From the QR specification's capacity table. L rather than M because every part is
/// shown repeatedly: a symbol misread once comes round again, so correction that costs
/// capacity buys less here than it does on an address shown once.
const CHARS: usize = 535;

/// Milliseconds each part is shown for.
///
/// Slow enough that a phone's camera gets a whole frame and a decode attempt, fast
/// enough that a hundred parts do not take all afternoon. Stock uses a comparable rate.
const FRAME_MS: u32 = 250;

/// Show `payload` as an animated BBQr, until a key is pressed.
///
/// Returns when the user leaves. There is nothing to report: a QR that was shown may or
/// may not have been read, and only the thing reading it knows.
pub(crate) fn animate(ui: &mut Ui<'_>, head: &str, payload: &[u8], filetype: FileType) {
    use anyd::codes::qr::{EcLevel, QrEncoder, Version};

    const MAX_VERSION: Version = match Version::new(VERSION) {
        Some(v) => v,
        None => unreachable!(),
    };
    const BUF: usize = QrEncoder::buffer_len(MAX_VERSION);

    let per = encode::fits(CHARS);
    let total = encode::parts_needed(payload.len(), per);
    if total == 0 || total > 36 * 36 {
        menu::message(ui.panel, head, "too large to show", "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    }

    // The line, the encoder's scratch, and the module grid. All from the heap: three
    // kilobytes is more than a screen's stack should carry, and this screen is one of
    // the few that can ask for memory and be told no.
    let (Some(mut line_mem), Some(mut scratch_mem), Some(mut store_mem)) = (
        crate::heap::take(encode::encoded_len(per)),
        crate::heap::take(BUF),
        crate::heap::take(BUF),
    ) else {
        menu::message(ui.panel, head, "not enough memory", "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    };

    let encoder = QrEncoder::new();
    let mut at = 0usize;
    let mut note: heapless::String<24> = heapless::String::new();

    loop {
        let start = at * per;
        let chunk = &payload[start..(start + per).min(payload.len())];
        let Ok(n) = encode::part(chunk, filetype, total as u16, at as u16, line_mem.bytes()) else {
            menu::message(ui.panel, head, "could not encode", "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        };

        note.clear();
        let _ = write!(note, "{} of {total}", at + 1);
        // Three separate blocks, so all three can be borrowed at once.
        let text = &line_mem.bytes()[..n];
        let (scratch, storage) = (scratch_mem.bytes(), store_mem.bytes());
        let Ok((grid, _)) = encoder.encode_text_into(text, EcLevel::L, scratch, storage) else {
            menu::message(ui.panel, head, "could not encode", "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        };

        display::draw(ui.panel, |c| {
            // The counter beside the symbol says whether this is going anywhere: a
            // reader that has stalled looks exactly like one that is working, and the
            // only visible difference is the frame number still moving.
            if catcard_ui::widgets::qr_with_text(
                c,
                menu::qr_faces(),
                display::FONTS.gap,
                grid.width(),
                |x, y| grid.get(x, y),
                note.as_str(),
            )
            .is_none()
            {
                // No arrangement fits the text; the symbol alone is what matters.
                catcard_ui::widgets::qr(c, grid.width(), |x, y| grid.get(x, y));
            }
        });

        // A key leaves, checked while this frame is up rather than between cycles.
        if key_within(ui, FRAME_MS) {
            return;
        }
        at = (at + 1) % total;
    }
}

/// Wait up to `ms`, returning true if a key was pressed in that time.
///
/// The animation's clock. USB is pumped while it waits, for the same reason every other
/// waiting screen pumps it: a polled bus nobody services is a device the host cannot
/// reach, and this screen can be up for minutes.
fn key_within(ui: &mut Ui<'_>, ms: u32) -> bool {
    use catcard_hal::dwt;

    let hz = unsafe { catcard_hal::clock::hclk_hz() };
    let until = dwt::cycles().wrapping_add((hz / 1_000).saturating_mul(ms));
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        let _ = crate::usbtask::pump();
        crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
        if !keys.is_empty() {
            return true;
        }
        if dwt::cycles().wrapping_sub(until) < u32::MAX / 2 {
            return false;
        }
    }
}
