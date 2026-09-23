//! What an EVM transaction says, in the words a screen uses.
//!
//! The reading is [`catcard_evm`]; this is the firmware's side of it. For now that is
//! one line per kind of action -- the screen that lays out the whole of a transaction,
//! and the signing behind it, are the next pieces.

use catcard_evm::summary::Action;

/// One line for what a transaction does.
///
/// Unused on mk3 for now, which has neither a scanner nor a tag: a transaction reaches
/// that board by card or by USB, and neither path sniffs yet.
#[cfg_attr(feature = "board-mk3", allow(dead_code))]
pub(crate) fn headline(action: &Action) -> &'static str {
    match action {
        Action::Send { .. } => "sends coin",
        Action::TokenSend { .. } => "sends a token",
        Action::TokenSendFrom { .. } => "moves a token under an allowance",
        Action::Approve { amount, .. } if amount.unlimited() => "approves unlimited spending",
        Action::Approve { .. } => "approves spending",
        Action::Call { method, .. } => method,
        Action::UnknownCall { .. } => "calls a contract this build cannot name",
        Action::CreateContract { .. } => "deploys a contract",
    }
}
