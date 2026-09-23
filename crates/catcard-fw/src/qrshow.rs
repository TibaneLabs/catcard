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

#[cfg(feature = "board-q1")]
use catcard_bbqr::{Encoding, FileType, Header};

use catcard_ui::keypad::{Event, KEYS, Key};

use crate::display;
#[cfg_attr(not(feature = "multichain"), allow(unused_imports))]
use crate::menu;
use crate::ui::Ui;

/// The symbol drawn. **Version 7: 45 modules.**
///
/// Sized from the pixels, not from the capacity. The content area is 224 rows, and a
/// symbol needs its four-module quiet zone, so 45 modules get `224 / 53 = 4` pixels
/// each. Version 12 would hold two and a half times as much and get three pixels, and
/// with the frame counter beside it only two -- which is what made the codes hard to
/// read. Four pixels a module is twice the linear size and four times the area.
///
/// The cost is more codes: 135 bytes a part against 330, so a two-kilobyte export is
/// about sixteen frames instead of seven. A code that scans first time beats a shorter
/// animation that does not.
const VERSION: u8 = 7;
/// Characters a version-7 symbol holds in alphanumeric mode at error-correction L.
///
/// From the QR specification's capacity table. L rather than M because every part is
/// shown repeatedly: a symbol misread once comes round again, so correction that costs
/// capacity buys less here than it does on an address shown once.
const CHARS: usize = 224;

/// How a part's bytes are written.
///
/// Base32 rather than hex: five bits a character against four, so the same file takes a
/// fifth fewer codes and every character still sits in QR's alphanumeric mode. `Z` would
/// be denser still, but the device on the other side cannot inflate a stream it is
/// staging in place -- see [`catcard_bbqr::Error::Compressed`].
#[cfg(feature = "board-q1")]
const ENCODING: Encoding = Encoding::Base32;

/// Milliseconds each part is shown for.
///
/// Slow enough that a phone's camera gets a whole frame and a decode attempt, fast
/// enough that a hundred parts do not take all afternoon. Stock uses a comparable rate.
const FRAME_MS: u32 = 250;

/// Show `payload` as animated BBQr.
///
/// The denser of the two and the right choice for anything Bitcoin: base32 is five bits
/// a character against BC-UR's four, so the same file is about a quarter fewer codes.
///
/// `filetype` is not decoration. A reader dispatches on it to decide what it has been
/// handed, and sending a wallet export as `BINARY` gets it refused by software that
/// would have taken the same bytes as `JSON`.
#[cfg(feature = "board-q1")]
pub(crate) fn animate_bbqr(ui: &mut Ui<'_>, head: &str, payload: &[u8], filetype: FileType) {
    animate(ui, head, payload, filetype)
}

/// Show an opaque payload as `ur:bytes`.
///
/// **The payload is wrapped, not sent bare.** A UR's body is the registry item's CBOR,
/// and the `bytes` item is a CBOR byte string -- so a reader takes the header off
/// before it sees the first character of what was exported. [C] BCR-2020-006
/// §"Registry". Handing the raw bytes over instead produced a UR that decoded to
/// something no reader could make sense of, which is why this exists rather than the
/// caller passing its buffer straight through.
#[cfg(feature = "board-q1")]
#[cfg(feature = "multichain")]
pub(crate) fn animate_bytes_ur(ui: &mut Ui<'_>, head: &str, payload: &[u8]) {
    use catcard_bcur::registry::{Kind, bytestring};

    let Some(mut mem) = crate::heap::take(bytestring::encoded_len(payload.len())) else {
        menu::message(ui.panel, head, "not enough memory", "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    };
    let Ok(n) = bytestring::encode(payload, mem.bytes()) else {
        menu::message(ui.panel, head, "could not encode", "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    };
    let message = &mem.bytes()[..n];
    animate_bcur(ui, head, Kind::Bytes.written_as(), message);
}

/// Show a signed transaction as `ur:crypto-psbt`.
///
/// # Which format, and when
///
/// BBQr is the default everywhere and stays the default here: base32 is five bits a
/// character against bytewords' four, so the same transaction is about a quarter fewer
/// codes, and `FileType::PSBT` says exactly what it is. BC-UR is the one to pick when
/// the thing holding the camera reads URs and not BBQr, which is most software that is
/// not Coldcard-aware. So both are offered and neither is guessed at: the owner knows
/// which wallet they are pointing at the screen, and this device does not.
///
/// # Why `crypto-psbt` and not `bytes`
///
/// `ur:bytes` is an opaque payload: a receiver has to guess what is inside, and most
/// simply refuse. `crypto-psbt` says what it is, and is the type BCR-2020-006 defines
/// for exactly this. [C] BCR-2020-006 §"Partially Signed Bitcoin Transaction (PSBT)"
///
/// The wrapper is a CBOR byte string around the transaction, which is what `scratch`
/// is for: a few bytes longer than the PSBT, and the signer already holds a
/// same-sized second buffer.
#[cfg(feature = "board-q1")]
#[cfg(feature = "multichain")]
pub(crate) fn animate_psbt_ur(ui: &mut Ui<'_>, head: &str, psbt: &[u8], scratch: &mut [u8]) {
    use catcard_bcur::registry::{Kind, bytestring};

    if bytestring::encoded_len(psbt.len()) > scratch.len() {
        menu::message(ui.panel, head, "no room to wrap it", "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    }
    let Ok(n) = bytestring::encode(psbt, scratch) else {
        menu::message(ui.panel, head, "could not encode", "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    };
    animate_bcur(ui, head, Kind::Psbt.written_as(), &scratch[..n]);
}

/// Show `message` as an animated BC-UR of type `ty`.
///
/// `message` is the registry item's CBOR, not the payload inside it: what the wrapper
/// is depends on the type, so the caller wraps. For an opaque payload that is
/// [`catcard_bcur::registry::Kind::Bytes`] and a byte string; for a transaction it is
/// `crypto-psbt`, which [`animate_psbt_ur`] does.
///
/// Less dense than BBQr, and the one to use where BBQr has no file type for what is
/// being sent -- which is everything that is not Bitcoin, and anything whose receiver
/// speaks URs.
///
/// A message small enough for one symbol is shown as a **single-part** UR,
/// `ur:<type>/<bytewords>`, with no sequence field at all. Not a nicety: a static code
/// is read at a glance rather than waited on through an animation, and it is shorter
/// than the same message numbered `1-1`, because the five-element part header and its
/// padding are gone. [C] BCR-2020-005 §"Types"
#[cfg(feature = "multichain")]
pub(crate) fn animate_bcur(ui: &mut Ui<'_>, head: &str, ty: &str, message: &[u8]) {
    use anyd::codes::qr::{EcLevel, QrEncoder, Version};
    use catcard_bcur::encode as ur;

    const MAX_VERSION: Version = match Version::new(VERSION) {
        Some(v) => v,
        None => unreachable!(),
    };
    const BUF: usize = QrEncoder::buffer_len(MAX_VERSION);

    // One symbol, if the whole message fits in one symbol.
    let lone = ur::single_len(ty, message.len()) <= CHARS;

    // The fragment size depends on how many parts there are, and the number of parts
    // depends on the fragment size. Two passes settle it: guess from a one-part header,
    // then re-solve knowing how wide the sequence numbers will be.
    let mut per = ur::fits(ty, CHARS, 1);
    let mut total = message.len().div_ceil(per.max(1)) as u32;
    per = ur::fits(ty, CHARS, total.max(1));
    if !lone && per == 0 {
        menu::message(ui.panel, head, "too large to show", "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    }
    total = if lone {
        1
    } else {
        message.len().div_ceil(per) as u32
    };

    let (Some(mut line_mem), Some(mut scratch_mem), Some(mut store_mem)) = (
        crate::heap::take(CHARS + 64),
        crate::heap::take(BUF),
        crate::heap::take(BUF),
    ) else {
        menu::message(ui.panel, head, "not enough memory", "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    };

    let encoder = QrEncoder::new();
    let mut at = 1u32;
    loop {
        let written = if lone {
            ur::single(ty, message, line_mem.bytes())
        } else {
            ur::part(ty, message, at, total, line_mem.bytes())
        };
        let Ok(n) = written else {
            menu::message(ui.panel, head, "could not encode", "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        };
        let text = &line_mem.bytes()[..n];
        let (scratch, storage) = (scratch_mem.bytes(), store_mem.bytes());
        let Ok((grid, _)) = encoder.encode_text_into(text, EcLevel::L, scratch, storage) else {
            menu::message(ui.panel, head, "could not encode", "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        };
        // **No bar.** Past the pure parts these are fountain mixtures, numbered upwards
        // for as long as the screen is shown, so there is nothing for a fraction to be
        // of: the animation does not end and does not come round. A bar that filled and
        // then sat full -- or worse, kept filling -- would be answering "how far through
        // is this?" with a number that means nothing. What a reader has caught is on the
        // reader's screen, which is where that question belongs.
        show(ui, grid.width(), |x, y| grid.get(x, y), None);
        if lone {
            // Nothing to animate. Redrawing the one code four times a second would
            // only make it flicker at the camera trying to read it -- but the wait
            // still goes through `key_within`, which is what keeps USB pumped.
            while !key_within(ui, FRAME_MS) {}
            return;
        }
        if key_within(ui, FRAME_MS) {
            return;
        }
        // **Onwards, not back to one.** Past `total` the parts are fountain mixtures,
        // and a reader that missed one fills the gap from the next mixture that covers
        // it rather than waiting for the cycle to come round. Looping would make every
        // missed part cost a whole animation.
        at = at.checked_add(1).unwrap_or(1);
    }
}

/// Show `payload` as an animated BBQr, until a key is pressed.
///
/// Returns when the user leaves. There is nothing to report: a QR that was shown may or
/// may not have been read, and only the thing reading it knows.
#[cfg(feature = "board-q1")]
fn animate(ui: &mut Ui<'_>, head: &str, payload: &[u8], filetype: FileType) {
    use anyd::codes::qr::{EcLevel, QrEncoder, Version};

    const MAX_VERSION: Version = match Version::new(VERSION) {
        Some(v) => v,
        None => unreachable!(),
    };
    const BUF: usize = QrEncoder::buffer_len(MAX_VERSION);

    let per = catcard_bbqr::fits(ENCODING, CHARS);
    let total = catcard_bbqr::parts_needed(payload.len(), per);
    if total == 0 || total > 36 * 36 {
        menu::message(ui.panel, head, "too large to show", "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    }

    // The line, the encoder's scratch, and the module grid. All from the heap: three
    // kilobytes is more than a screen's stack should carry, and this screen is one of
    // the few that can ask for memory and be told no.
    let (Some(mut line_mem), Some(mut scratch_mem), Some(mut store_mem)) = (
        crate::heap::take(catcard_bbqr::part_len(ENCODING, per)),
        crate::heap::take(BUF),
        crate::heap::take(BUF),
    ) else {
        menu::message(ui.panel, head, "not enough memory", "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    };

    let encoder = QrEncoder::new();
    let mut at = 0usize;

    loop {
        let start = at * per;
        let chunk = &payload[start..(start + per).min(payload.len())];
        let header = Header {
            encoding: ENCODING,
            file_type: filetype,
            num_parts: total as u16,
            index: at as u16,
        };
        let Ok(n) = catcard_bbqr::encode_part_to_slice(&header, chunk, line_mem.bytes()) else {
            menu::message(ui.panel, head, "could not encode", "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        };

        // Three separate blocks, so all three can be borrowed at once.
        let text = &line_mem.bytes()[..n];
        let (scratch, storage) = (scratch_mem.bytes(), store_mem.bytes());
        let Ok((grid, _)) = encoder.encode_text_into(text, EcLevel::L, scratch, storage) else {
            menu::message(ui.panel, head, "could not encode", "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        };

        // BBQr keeps the bar: its parts are numbered and the animation cycles, so the
        // bar says where in the cycle this frame is and it comes round again.
        show(
            ui,
            grid.width(),
            |x, y| grid.get(x, y),
            Some((at as u32 + 1, total as u32)),
        );

        // A key leaves, checked while this frame is up rather than between cycles.
        if key_within(ui, FRAME_MS) {
            return;
        }
        at = (at + 1) % total;
    }
}

/// Draw one symbol as large as the screen allows, with a progress bar beside it.
///
/// **White, not amber.** Every other screen here is the Coldcard amber, but a QR is read
/// by a camera rather than a person: scanners expect dark modules on a light field, and
/// the closer that field is to white the more contrast there is to work with. The greys
/// palette puts white at the top of its ramp, so the symbol is drawn through that rather
/// than through the amber one.
///
/// **A bar, not a counter.** The text counter had to sit beside the symbol, which cost
/// it a third of the width and was the main reason the codes were too small. The bar
/// goes in the margin the square symbol leaves on a wide screen, so it costs nothing --
/// and it answers the only question anyone has while holding a phone at the screen,
/// which is whether this is going anywhere at all.
fn show(
    ui: &mut Ui<'_>,
    modules: usize,
    get: impl Fn(usize, usize) -> bool,
    progress: Option<(u32, u32)>,
) {
    use catcard_ui::canvas::{Canvas, INK, PAPER};

    display::draw_with(ui.panel, &catcard_ui::st7789::GREYS, |c| {
        catcard_ui::widgets::qr(c, modules, &get);

        // The symbol is square and centred, so on a 320-wide panel showing 224 rows it
        // leaves about fifty pixels each side. The bar lives in the right-hand one and
        // never touches the code.
        // Only where there is something to be a fraction of.
        let Some((at, total)) = progress.filter(|&(_, total)| total > 0) else {
            return;
        };
        let (w, h) = (c.width(), c.height());
        let side = h.min(w);
        let gutter = w.saturating_sub(side) / 2;
        if gutter < 8 {
            return;
        }
        let bar_w = (gutter / 3).clamp(3, 10);
        let x = w - gutter / 2 - bar_w / 2;
        let top = h / 8;
        let span = h - 2 * top;
        // The whole track faintly, then the part done brightly: an empty bar and a
        // missing bar look the same, and only one of them means something is wrong.
        c.fill_rect(x, top, bar_w, span, PAPER + 4);
        let done = (span * at as usize / total as usize).clamp(1, span);
        c.fill_rect(x, top, bar_w, done, INK);
    });
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
