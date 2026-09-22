//! The strip along the top of the Q1's screen.
//!
//! It answers, without being asked, the questions whose wrong answer is expensive:
//!
//! - **Which modifiers are down.** The Q1 has a real keyboard, and a passphrase typed
//!   with SHIFT held is a different passphrase -- one that opens a different, empty
//!   wallet with no error to say so. The indicators are dim when the modifier is up and
//!   full ink while it is held, so a person can see what they are about to type.
//! - **Whether a passphrase is in force**, which decides which wallet everything else on
//!   the screen belongs to.
//! - **Which wallet that is**, as the master fingerprint -- the same four bytes a
//!   coordinator, a watch-only wallet or a cosigner list names it by.
//! - **Where the power is coming from**, because a device that is about to lose its
//!   batteries mid-signing should say so first.
//!
//! Nothing here reads hardware or derives anything; it is handed a [`Status`] and draws
//! it. That keeps the whole thing testable on a host, and keeps the rule that the bar is
//! *passive*: it is painted on every frame, so anything it needed to compute would be
//! computed on every frame.

use crate::canvas::{Canvas, INK, Level, PAPER};
use crate::face::Face;
use crate::text::{draw_text_in, width_of};

/// Ink for a modifier that is not held, or a state that is off.
///
/// Present but plainly inactive. Stock greys them the same way, and the alternative --
/// hiding them until they matter -- makes the bar's width jump around and gives a person
/// nothing to learn the layout from.
pub const DIM: Level = 6;

/// Where the device's power is coming from.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Power {
    /// External or USB power.
    External,
    /// The batteries.
    Battery,
}

/// What the bar shows. Everything is already known by the time this is built.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Status {
    pub shift: bool,
    pub symbol: bool,
    /// CAPS latches rather than being held, so this can be on with no key down.
    pub caps: bool,
    /// One word for the wallet in force: the root, a passphrase, a BIP-85 child.
    ///
    /// A word rather than a flag, because "passphrase: off" says nothing about whether
    /// the device is somewhere other than the wallet whose words are written down --
    /// and that is the only question this space is worth spending on.
    pub key: &'static str,
    /// Whether that word means something other than the root, and should stand out.
    pub key_set: bool,
    /// The master fingerprint, if it is already known.
    ///
    /// `None` leaves the space empty. The bar must never be the reason a seed is
    /// unlocked: it is drawn on every frame, and a screen that stretches the seed to
    /// decorate itself would be unusable.
    pub fingerprint: Option<[u8; 4]>,
    /// `None` on a board with no battery, which draws no icon rather than a guessed one.
    pub power: Option<Power>,
}

/// Space between the modifier words.
const GAP: usize = 6;
/// Space before the key word, which is a separate group.
const GROUP_GAP: usize = 14;
/// Space either side of the bar's contents.
const MARGIN: usize = 4;
/// Width the power icon is given, including the space before it.
const ICON_W: usize = 14;

/// How tall a bar in `font` is, the rule underneath included.
///
/// One row of padding above the text and the rule immediately below it. A second blank
/// row read as a gap rather than as a border on hardware.
pub fn height<F: Face + ?Sized>(font: &F) -> usize {
    font.line_height() + 2
}

/// Draw the bar across the top of `canvas`.
///
/// Paints its own background, so it can be laid over a frame a screen has already drawn.
pub fn render<C: Canvas + ?Sized, F: Face + ?Sized>(canvas: &mut C, font: &F, status: &Status) {
    let w = canvas.width();
    let h = height(font);
    canvas.fill_rect(0, 0, w, h, PAPER);
    // A rule along the bottom, so the bar reads as a frame around the screen rather than
    // as the first line of whatever is below it.
    canvas.fill_rect(0, h - 1, w, 1, DIM);

    let level = |on: bool| if on { INK } else { DIM };
    let y = 1;

    let mut x = MARGIN;
    for (text, on) in [
        ("SHIFT", status.shift),
        ("SYM", status.symbol),
        ("CAPS", status.caps),
    ] {
        x = draw_text_in(canvas, font, x, y, text, level(on)) + GAP;
    }
    let _ = draw_text_in(
        canvas,
        font,
        x + GROUP_GAP - GAP,
        y,
        status.key,
        level(status.key_set),
    );

    // The right-hand group, laid out from the edge inwards so it stays put as the left
    // side changes width.
    let mut right = w.saturating_sub(MARGIN);
    if let Some(power) = status.power {
        right = right.saturating_sub(ICON_W);
        power_icon(canvas, right + 2, y, font.line_height(), power);
    }
    if let Some(fp) = status.fingerprint {
        let mut text = [0u8; 8];
        hex(fp, &mut text);
        let text = core::str::from_utf8(&text).unwrap_or("");
        let at = right.saturating_sub(width_of(font, text));
        let _ = draw_text_in(canvas, font, at, y, text, INK);
    }
}

/// The fingerprint as eight upper-case hex digits, the way every other wallet writes it.
fn hex(bytes: [u8; 4], out: &mut [u8; 8]) {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    for (i, b) in bytes.iter().enumerate() {
        out[i * 2] = DIGITS[(b >> 4) as usize];
        out[i * 2 + 1] = DIGITS[(b & 0x0F) as usize];
    }
}

/// A plug on external power, a battery on its own.
///
/// Drawn rather than drawn *from art*: at this size it is a handful of rectangles, and a
/// glyph sheet for two icons would be more to keep in step than to write.
fn power_icon<C: Canvas + ?Sized>(canvas: &mut C, x: usize, y: usize, h: usize, power: Power) {
    /// Both icons are drawn in a box this tall, centred on the text line.
    const ICON_H: usize = 10;
    let top = y + h.saturating_sub(ICON_H) / 2;
    match power {
        Power::Battery => {
            // Upright, with its terminal on top. Drawn empty: nothing here has read the
            // level, and a part-filled cell would be claiming to know it.
            outline(canvas, x + 1, top + 2, 8, 8);
            canvas.fill_rect(x + 3, top, 4, 2, INK);
        }
        Power::External => {
            // A plug: two pins above a body, with the lead leaving the bottom.
            canvas.fill_rect(x + 2, top, 2, 3, INK);
            canvas.fill_rect(x + 6, top, 2, 3, INK);
            outline(canvas, x + 1, top + 3, 8, 5);
            canvas.fill_rect(x + 4, top + 8, 2, 2, INK);
        }
    }
}

/// An outlined rectangle, which both power icons are built from.
fn outline<C: Canvas + ?Sized>(canvas: &mut C, x: usize, y: usize, w: usize, h: usize) {
    canvas.fill_rect(x, y, w, 1, INK);
    canvas.fill_rect(x, y + h - 1, w, 1, INK);
    canvas.fill_rect(x, y, 1, h, INK);
    canvas.fill_rect(x + w - 1, y, 1, h, INK);
}

#[cfg(test)]
mod tests;
