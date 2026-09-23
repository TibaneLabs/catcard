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
