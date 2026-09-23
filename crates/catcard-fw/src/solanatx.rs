//! What a Solana transaction says, in the words a screen uses.
//!
//! The reading is [`catcard_solana`]; this is the firmware's side of it. For now that is
//! one line -- what the transaction mostly does, and how far through signing it is --
//! the same honest placeholder the EVM path carries in [`crate::evmtx`], until the
//! screen that lays the whole of it out and the signing behind it are built.

use catcard_solana::{Action, Tx};
use core::fmt::Write as _;

/// One line for what a transaction does.
///
/// A Solana transaction is a list of instructions rather than one call, so there is no
/// single thing it "is". What gets named here is the first instruction that is about
/// value: a compute-budget setting is a price, not an act, and a transaction that led
/// with "sets a compute limit" would tell a person nothing about what they are signing.
/// The count that follows says how much else is in there.
fn what_it_does(tx: &Tx<'_>) -> &'static str {
    let mut fallback = "does nothing this build can name";
    for i in 0..tx.instruction_count() {
        let Some(action) = tx.action(i) else {
            continue;
        };
        match action {
            Action::TransferSol { .. } => return "sends SOL",
            Action::TransferToken { .. } => return "sends a token",
            Action::ApproveToken { .. } => return "approves spending",
            Action::CreateTokenAccount { .. } => return "opens a token account",
            // Neither of these is the point of a transaction, but an unnamed program is
            // worth saying if it turns out to be all there is.
            Action::ComputeBudget => {}
            Action::Unknown { .. } => fallback = "calls a program this build cannot name",
        }
    }
    fallback
}

/// The line a review screen shows before anything else.
///
/// Three things, in the order they change a decision: what it does, how many
/// instructions that was one of, and whether somebody has already signed. The last
/// matters most -- a partly signed transaction is one this device is being asked to
/// join, not one it is starting.
///
/// Unused on mk3 for now, which has neither a scanner nor a tag: a transaction reaches
/// that board by card or by USB, and neither path sniffs yet.
#[cfg_attr(feature = "board-mk3", allow(dead_code))]
pub(crate) fn headline(tx: &Tx<'_>, out: &mut heapless::String<80>) {
    let signing = tx.signing();
    let n = tx.instruction_count();
    let _ = write!(out, "{}", what_it_does(tx));
    if n > 1 {
        let _ = write!(out, ", 1 of {n} instructions");
    }
    if signing.present > 0 {
        let _ = write!(out, "; {} of {} signed", signing.present, signing.required);
    }
    // What a lookup table lends is named here rather than left out: those accounts are
    // fetched from the chain at execution and this device never sees them, so an
    // instruction touching one is an instruction it cannot fully read.
    let (w, r) = tx.lookups();
    if w + r > 0 {
        let _ = write!(out, "; {} accounts not shown", w + r);
    }
}

/// Show what a transaction does, and offer to hand it on.
///
/// `payload` is what arrived and `base64` says where the transaction is inside it: a
/// range when it came written down -- a broadcast link, or the base64 on its own -- and
/// `None` when the payload is the transaction itself. Both the scanner and the tag come
/// through here, because what a person needs to see does not depend on which way it
/// arrived.
///
/// The review screen that lays a transaction out line by line, and the signing behind
/// it, are the next pieces. What this can already do is the other half of the journey:
/// put the transaction back on the tag as a link, which is how it reaches a phone that
/// can send it -- or the next signer, when it is still short of signatures.
#[cfg(not(feature = "board-mk3"))]
pub(crate) fn screen(ui: &mut crate::ui::Ui<'_>, payload: &[u8], base64: Option<(usize, usize)>) {
    use catcard_solana::link;

    const HEAD: &str = "Solana transaction";

    // Held here so that a decoded transaction outlives the borrow taken from it, and so
    // that a transaction which arrived as bytes costs no memory at all.
    let mut block;
    let raw: &[u8] = match base64 {
        None => payload,
        Some((at, len)) => {
            let Some(text) = payload
                .get(at..at + len)
                .and_then(|b| core::str::from_utf8(b).ok())
            else {
                return;
            };
            let Some(got) = crate::heap::take(link::PACKET_MAX) else {
                crate::menu::message(ui.panel, HEAD, "not enough memory", "any key to go back");
                crate::menu::wait_for_any_key(ui);
                return;
            };
            block = got;
            let Ok(n) = outscript::base64::decode_to_slice(text, block.bytes()) else {
                return;
            };
            &block.bytes()[..n]
        }
    };

    let Ok(tx) = catcard_solana::parse(raw) else {
        crate::menu::message(
            ui.panel,
            HEAD,
            "this is not a transaction",
            "any key to go back",
        );
        crate::menu::wait_for_any_key(ui);
        return;
    };
    let mut said: heapless::String<80> = heapless::String::new();
    headline(&tx, &mut said);
    let missing = tx.signing().missing();
    crate::menu::message(ui.panel, HEAD, &said, "any key to go back");
    crate::menu::wait_for_any_key(ui);
    crate::nfc::offer_solana_link(ui, raw, missing);
}
