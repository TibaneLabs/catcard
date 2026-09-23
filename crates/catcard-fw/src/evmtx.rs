//! What an EVM transaction says, in the words and shapes a screen uses.
//!
//! The reading is [`catcard_evm`] and the screen is [`crate::txreview`]; this is what
//! joins them. The same three steps as [`crate::solanatx`], which shares the screen:
//! read, lay out, sign -- and what differs between the two chains is only what the cards
//! say.
//!
//! # What an EVM transaction hides that a Solana one does not
//!
//! One call, not a list, so there is less to lay out -- and more to be wrong about. The
//! whole of what a call does is in four bytes of selector and some arguments, and this
//! build can name a few thousand selectors out of millions. So the cards are careful
//! about the difference between *knowing what a call is* and *having seen its name
//! somewhere*: a named selector is shown as a name, and everything else is a red card.

use catcard_evm::summary::{Action, Amount};

use crate::txreview::Review;

/// Room for an address as EIP-55 writes it: `0x` and forty hex digits.
const ADDRESS: usize = 42;

/// An address, checksummed the way every explorer shows one.
///
/// EIP-55 rather than plain hex: the capitalisation is a checksum, so an address a
/// person compares against a screen somewhere else matches character for character or
/// does not match at all.
fn address<'o>(a: &[u8; 20], out: &'o mut [u8; ADDRESS]) -> &'o str {
    match outscript::address::eip55_to_slice(a, out) {
        Some(n) => core::str::from_utf8(&out[..n]).unwrap_or("(bad address)"),
        None => "(bad address)",
    }
}

/// A 256-bit amount at `decimals`, as people write it.
fn scaled<'o>(
    raw: &[u8; 32],
    decimals: u8,
    out: &'o mut [u8; catcard_evm::summary::DECIMAL_MAX],
) -> &'o str {
    catcard_evm::summary::decimal(raw, decimals, out)
}

/// A token amount as one row, with its ticker when the table has one.
fn token_row(out: &mut Review, lead: &str, amount: &Amount) {
    let mut num = [0u8; catcard_evm::summary::DECIMAL_MAX];
    match amount.token {
        Some(t) if amount.unlimited() => {
            out.element(false, format_args!("{lead} unlimited {}", t.symbol));
        }
        Some(t) => {
            let n = scaled(&amount.raw, t.decimals, &mut num);
            out.element(false, format_args!("{lead} {n} {}", t.symbol));
        }
        // Unnamed: the raw number and the contract, which is everything actually known.
        // Scaling it by a guessed decimal count would be inventing the amount.
        None if amount.unlimited() => out.element(false, format_args!("{lead} unlimited")),
        None => {
            let n = scaled(&amount.raw, 0, &mut num);
            out.element(false, format_args!("{lead} {n} raw units"));
            out.note(format_args!("of a token this build cannot name"));
        }
    }
    let mut addr = [0u8; ADDRESS];
    out.address("token", address(&amount.contract, &mut addr));
}

/// Lay a transaction out: which chain, what it costs, and what it does.
pub(crate) fn describe(tx: &catcard_evm::Tx<'_>, out: &mut Review) {
    let mut addr = [0u8; ADDRESS];
    let mut num = [0u8; catcard_evm::summary::DECIMAL_MAX];

    // Which chain, first. The same calldata on the wrong chain is a different
    // transaction, and one naming no chain is valid on every chain at once -- which is a
    // red row rather than a blank.
    match tx.chain_id {
        Some(id) => match catcard_evm::tokens::chain_name(id) {
            Some(name) => out.element(false, format_args!("On {name}")),
            None => out.element(false, format_args!("On chain {id}")),
        },
        None => {
            out.cannot_read(format_args!("This names no chain"));
            out.note(format_args!("so it is valid on every chain at once"));
        }
    }
    out.field("nonce", format_args!("{}", tx.nonce));

    // What the gas can cost at most: the limit times the price, which is what the sender
    // is committing to rather than what they will probably pay.
    let mut fee = [0u8; 32];
    let mut carry = 0u128;
    for i in (0..32).rev() {
        let v = u128::from(tx.max_fee[i]) * u128::from(tx.gas_limit) + carry;
        fee[i] = v as u8;
        carry = v >> 8;
    }
    if carry == 0 {
        out.field("gas up to", format_args!("{}", scaled(&fee, 18, &mut num)));
    }

    match catcard_evm::summary::summarise(tx) {
        Action::Send { to, wei } => {
            out.element(false, format_args!("Send {}", scaled(&wei, 18, &mut num)));
            out.note(format_args!("of the chain's own coin"));
            out.address("to", address(&to, &mut addr));
        }
        Action::TokenSend { to, amount } => {
            token_row(out, "Send", &amount);
            out.address("to", address(&to, &mut addr));
        }
        Action::TokenSendFrom { from, to, amount } => {
            token_row(out, "Move", &amount);
            out.address("from", address(&from, &mut addr));
            out.address("to", address(&to, &mut addr));
            out.note(format_args!("under an allowance already given"));
        }
        Action::Approve { spender, amount } => {
            token_row(out, "Approve", &amount);
            out.address("to", address(&spender, &mut addr));
            out.note(format_args!("an approval outlives this transaction"));
        }
        // A selector this build can name. Named is not decoded: what the arguments say
        // is not read, so the amount inside a swap is not on this screen.
        Action::Call {
            to,
            method,
            data_len,
            wei,
        } => {
            out.cannot_read(format_args!("Calls {method}"));
            out.note(format_args!("the name is known, the arguments are not"));
            out.field("calldata", format_args!("{data_len} bytes"));
            out.address("contract", address(&to, &mut addr));
            if wei.iter().any(|&b| b != 0) {
                out.field("sending", format_args!("{}", scaled(&wei, 18, &mut num)));
            }
        }
        Action::UnknownCall {
            to,
            selector,
            data_len,
            wei,
        } => {
            out.cannot_read(format_args!("Calls a contract"));
            out.field(
                "selector",
                format_args!(
                    "{:02x}{:02x}{:02x}{:02x}",
                    selector[0], selector[1], selector[2], selector[3]
                ),
            );
            out.field("calldata", format_args!("{data_len} bytes"));
            out.address("contract", address(&to, &mut addr));
            if wei.iter().any(|&b| b != 0) {
                out.field("sending", format_args!("{}", scaled(&wei, 18, &mut num)));
            }
        }
        Action::CreateContract { data_len, wei } => {
            out.cannot_read(format_args!("Deploys a contract"));
            out.field("code", format_args!("{data_len} bytes"));
            if wei.iter().any(|&b| b != 0) {
                out.field("with", format_args!("{}", scaled(&wei, 18, &mut num)));
            }
        }
    }

    if tx.access_list_len > 0 {
        out.field(
            "access list",
            format_args!("{} entries", tx.access_list_len),
        );
    }
    if tx.signature.is_some() {
        out.note(format_args!("this already carries a signature"));
    }
}

/// Read a transaction out and offer to do the one thing that can be done with it.
///
/// Signing is not built for EVM yet, so the row is not offered: what this gives is the
/// whole transaction on a screen, which is the half that has to be right before a
/// signature over it means anything.
#[cfg(not(feature = "board-mk3"))]
pub(crate) fn screen(ui: &mut crate::ui::Ui<'_>, bytes: &[u8]) {
    const HEAD: &str = "EVM transaction";

    let Ok(tx) = catcard_evm::parse(bytes) else {
        crate::menu::message(
            ui.panel,
            HEAD,
            "this is not a transaction",
            "any key to go back",
        );
        crate::menu::wait_for_any_key(ui);
        return;
    };
    let Some(mut review) = Review::new() else {
        crate::menu::message(ui.panel, HEAD, "not enough memory", "any key to go back");
        crate::menu::wait_for_any_key(ui);
        return;
    };
    describe(&tx, &mut review);
    review.show(ui, HEAD, &["Signing is not built yet"]);
}
