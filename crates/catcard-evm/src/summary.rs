//! What a transaction *does*, in the terms a person deciding whether to sign it uses.
//!
//! The parse gives fields; this gives a sentence. "Send 12.5 USDC to 0x1234…5678" is a
//! different object from "call 0xa0b8…eb48 with 68 bytes of calldata", and only one of
//! them can be checked against what somebody meant to do.
//!
//! # Three levels of confidence, and they are never blurred
//!
//! 1. **What the transaction says.** The destination, the value, the chain id. These are
//!    fields; they are as true as the bytes.
//! 2. **What the calldata claims.** A selector of `a9059cbb` and two 32-byte words is an
//!    ERC-20 `transfer` *as far as anything off-chain can tell*. The four-byte selector
//!    is a hash prefix, it collides by construction, and the contract at that address is
//!    free to implement something else entirely. So this is reported as a claim.
//! 3. **What this firmware has been told.** That `0x2791…4174` is called USDC and has six
//!    decimals comes from a baked table (see [`crate::tokens`]), not from the chain. It
//!    is a label, and the screens show the address whether or not it is labelled.
//!
//! The reason for the fuss: every one of those levels is a place where a hostile
//! transaction would like to be mistaken for a friendly one, and the mistake has to cost
//! something visible. A name this firmware cannot vouch for is not shown as a name.

use crate::tokens::{self, Token};
use crate::{Address, Tx};

/// ERC-20 `transfer(address,uint256)`.
pub const TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
/// ERC-20 `approve(address,uint256)`.
pub const APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];
/// ERC-20 `transferFrom(address,address,uint256)`.
pub const TRANSFER_FROM: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd];

/// An amount of some token, with whatever this firmware knows about that token.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Amount {
    /// The contract the amount is denominated in.
    pub contract: Address,
    /// Its name and decimals, when the table has them. `None` means "show the address
    /// and the raw number", which is honest rather than unhelpful.
    pub token: Option<Token>,
    /// The raw on-chain amount, before decimals are applied.
    pub raw: [u8; 32],
}

impl Amount {
    /// Whether this is the "infinite" allowance an approval usually asks for.
    ///
    /// `2^256 - 1`, which is not a quantity anybody holds -- it is the number a spender
    /// asks for when it wants permission to take everything, now and later. Worth its
    /// own word on a screen, because the difference between approving 50 USDC and
    /// approving all of them forever is the whole of the decision.
    pub fn unlimited(&self) -> bool {
        self.raw == [0xFF; 32]
    }
}

/// What the transaction amounts to.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Action {
    /// The chain's own coin, moved. No contract involved.
    Send { to: Address, wei: [u8; 32] },
    /// An ERC-20 transfer, as the calldata claims.
    TokenSend { to: Address, amount: Amount },
    /// An ERC-20 `transferFrom`: moving somebody else's tokens under an allowance.
    TokenSendFrom {
        from: Address,
        to: Address,
        amount: Amount,
    },
    /// An allowance, as the calldata claims. The one that empties wallets.
    Approve { spender: Address, amount: Amount },
    /// Calldata whose selector this build can name, and nothing more specific.
    Call {
        to: Address,
        /// The signature as `evmabiless` has it, e.g. `swapExactTokensForTokens(...)`.
        method: &'static str,
        data_len: usize,
        /// Any coin sent along with the call.
        wei: [u8; 32],
    },
    /// Calldata this build cannot name at all.
    UnknownCall {
        to: Address,
        selector: [u8; 4],
        data_len: usize,
        wei: [u8; 32],
    },
    /// No destination: this deploys code.
    CreateContract { data_len: usize, wei: [u8; 32] },
}

/// Read what a transaction does.
///
/// `chain_id` is taken from the transaction where it has one; a transaction that names
/// no chain is looked up against nothing, so its contracts stay unnamed -- which is the
/// right answer for a transaction that is valid on every chain at once.
pub fn summarise(tx: &Tx<'_>) -> Action {
    let chain = tx.chain_id.unwrap_or(0);
    let Some(to) = tx.to else {
        return Action::CreateContract {
            data_len: tx.data.len(),
            wei: tx.value,
        };
    };
    let Some(selector) = tx.selector() else {
        // No calldata to speak of: a plain send, whatever else is attached.
        return Action::Send { to, wei: tx.value };
    };
    let args = &tx.data[4..];
    let named = |contract: Address, raw: [u8; 32]| Amount {
        contract,
        token: tokens::lookup(chain, &contract),
        raw,
    };

    match selector {
        TRANSFER if args.len() >= 64 => Action::TokenSend {
            to: word_address(args, 0),
            amount: named(to, word(args, 1)),
        },
        APPROVE if args.len() >= 64 => Action::Approve {
            spender: word_address(args, 0),
            amount: named(to, word(args, 1)),
        },
        TRANSFER_FROM if args.len() >= 96 => Action::TokenSendFrom {
            from: word_address(args, 0),
            to: word_address(args, 1),
            amount: named(to, word(args, 2)),
        },
        _ => match lookup(selector) {
            Some(method) => Action::Call {
                to,
                method,
                data_len: tx.data.len(),
                wei: tx.value,
            },
            None => Action::UnknownCall {
                to,
                selector,
                data_len: tx.data.len(),
                wei: tx.value,
            },
        },
    }
}

/// The signature for a selector, from whichever table this build carries.
///
/// A build may carry none at all, and then nothing is ever named -- which is a smaller
/// firmware that says "a call this build cannot name" more often, not one that guesses.
#[cfg(any(feature = "common-signatures", feature = "full-signatures"))]
fn lookup(selector: [u8; 4]) -> Option<&'static str> {
    evmabiless::lookup_abi(evmabiless::MethodPrefix(selector)).map(|abi| abi.compact)
}

#[cfg(not(any(feature = "common-signatures", feature = "full-signatures")))]
fn lookup(_selector: [u8; 4]) -> Option<&'static str> {
    None
}

/// Word `n` of the arguments, as 256 bits. Short arguments read as zero, which only
/// happens on calldata the caller has already length-checked.
fn word(args: &[u8], n: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    if let Some(slice) = args.get(n * 32..n * 32 + 32) {
        out.copy_from_slice(slice);
    }
    out
}

/// Word `n` read as an address: the low twenty bytes of it.
///
/// The high twelve bytes are supposed to be zero. They are **not checked**, and that is
/// deliberate: a non-zero prefix would be a malformed argument, and the contract will
/// read the same low twenty bytes this does. Showing a different address from the one
/// that will be used would be the more dangerous mistake.
fn word_address(args: &[u8], n: usize) -> Address {
    let w = word(args, n);
    let mut out = [0u8; 20];
    out.copy_from_slice(&w[12..]);
    out
}

/// The longest a decimal amount can be: 78 digits of `u256`, a point, and a sign of
/// nothing.
pub const DECIMAL_MAX: usize = 80;

/// Write `raw` as a decimal number with `decimals` places, trimmed.
///
/// `1_250_000` at six decimals is `1.25`, not `1.250000` -- trailing zeros in a money
/// amount are noise, and noise is what a person's eye skips over on the screen where
/// they are supposed to be checking a number.
///
/// Returns the text, which borrows `out`.
pub fn decimal<'o>(raw: &[u8; 32], decimals: u8, out: &'o mut [u8; DECIMAL_MAX]) -> &'o str {
    // Digits of the whole 256-bit value, least significant first.
    let mut digits = [0u8; 78];
    let mut n = 0;
    let mut v = *raw;
    while v.iter().any(|&b| b != 0) {
        let mut rem = 0u32;
        for b in v.iter_mut() {
            let cur = (rem << 8) | *b as u32;
            *b = (cur / 10) as u8;
            rem = cur % 10;
        }
        digits[n] = rem as u8;
        n += 1;
    }
    if n == 0 {
        digits[0] = 0;
        n = 1;
    }

    let places = decimals as usize;
    // Drop the trailing zeros of the fraction, but never a digit of the whole part.
    //
    // A position the value does not reach is a zero as much as a stored one is: the
    // digits run out at `n`, and everything above that is zero all the way up. Stopping
    // the trim at `n` was why nothing at eighteen decimals printed as `0.00000000000000000`
    // instead of `0`.
    let mut skip = 0;
    while skip < places && (skip >= n || digits[skip] == 0) {
        skip += 1;
    }
    let fraction = places - skip;

    let mut at = 0;
    let mut put = |c: u8, at: &mut usize| {
        if *at < out.len() {
            out[*at] = c;
            *at += 1;
        }
    };
    // The whole part: everything above `places`, or a single zero.
    if n > places {
        for i in (places..n).rev() {
            put(b'0' + digits[i], &mut at);
        }
    } else {
        put(b'0', &mut at);
    }
    if fraction > 0 {
        put(b'.', &mut at);
        // Most significant digit of the fraction first. Positions above what the value
        // has are zeros: `1` at 18 decimals is `0.000000000000000001`.
        for i in (skip..places).rev() {
            let d = if i < n { digits[i] } else { 0 };
            put(b'0' + d, &mut at);
        }
    }
    core::str::from_utf8(&out[..at]).unwrap_or("?")
}
