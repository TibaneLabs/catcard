//! What a transaction comes to, for the keys this device holds.
//!
//! The question a person actually has -- "what does signing this cost me?" -- and the one
//! no single instruction answers. A transaction can take SOL in one instruction and give
//! it back in another; the fee is not an instruction at all; and a token amount is
//! denominated in a mint that the instruction moving it may not name.
//!
//! **Here rather than in a screen**, because it is arithmetic and arithmetic is the part
//! worth testing. A total is the number somebody reads instead of reading the rows, so it
//! is the number that must not be wrong -- and a self-transfer, where the same account is
//! on both sides, is exactly the case a per-instruction reading gets wrong and a total
//! gets right.
//!
//! # What is counted
//!
//! Only what can be attributed. A token account this build cannot tie to a key of its own
//! is somebody else's as far as this is concerned, and an amount arriving there is not
//! added to a total that says "yours". Under-counting shows up as rows that do not add to
//! the total; over-counting would be a number that is simply wrong.

use crate::{Action, LAMPORTS_PER_SOL, SolanaKey, TokenProgram, Tx, associated_account, mints};

/// How many assets a total can name.
///
/// A transaction that moves more kinds of thing than this is one whose summary would not
/// fit a screen anyway; what does not fit is said rather than dropped.
pub const ASSETS: usize = 6;

/// SOL's decimal places: a lamport is a billionth.
pub const SOL_DECIMALS: u8 = LAMPORTS_PER_SOL.ilog10() as u8;

/// One asset, and how much of it moves.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Entry {
    /// `None` is SOL itself.
    pub mint: Option<SolanaKey>,
    /// What the mint table calls it, when the mint is one this build knows.
    pub named: Option<mints::Mint>,
    /// Signed: a transaction can move the same asset both ways.
    pub delta: i128,
}

impl Entry {
    /// The decimal places to write this amount with, where they are known.
    pub fn decimals(&self) -> Option<u8> {
        match self.mint {
            None => Some(SOL_DECIMALS),
            Some(_) => self.named.map(|m| m.decimals),
        }
    }
}

/// The totals, and whether they are all of them.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Effects {
    entries: heapless::Vec<Entry, ASSETS>,
    lost: bool,
}

impl Effects {
    /// Everything that moves, in the order it was first seen. Entries that net to zero
    /// are kept: "this nets out" is a fact worth having, and a caller that only wants
    /// what moved can filter.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Whether there were more assets than there is room for, so a partial total never
    /// reads as a whole one.
    pub fn lost(&self) -> bool {
        self.lost
    }

    /// What moves, per asset.
    pub fn moving(&self) -> impl Iterator<Item = &Entry> {
        self.entries.iter().filter(|e| e.delta != 0)
    }

    fn add(&mut self, mint: Option<SolanaKey>, named: Option<mints::Mint>, delta: i128) {
        if let Some(e) = self.entries.iter_mut().find(|e| e.mint == mint) {
            e.delta += delta;
            // A later instruction may name a mint an earlier one could not.
            e.named = e.named.or(named);
            return;
        }
        if self.entries.push(Entry { mint, named, delta }).is_err() {
            self.lost = true;
        }
    }
}

/// Add up what `tx` does to the keys in `mine`.
///
/// `mine` is public keys -- the wallet addresses this device can sign for. A token
/// account is not one of those, so an SPL transfer is attributed by deriving the
/// associated account for each key and mint and comparing; see [`ours`].
pub fn of(tx: &Tx<'_>, mine: &[[u8; 32]]) -> Effects {
    let mut out = Effects::default();

    // The fee, which no instruction carries. It is the payer's whatever else happens.
    let fee = tx.fee();
    if is_mine(tx.fee_payer(), mine) {
        let paid = fee.base.saturating_add(fee.priority.unwrap_or(0));
        out.add(None, None, -(paid as i128));
    }

    for i in 0..tx.instruction_count() {
        match tx.action(i) {
            Some(Action::TransferSol { from, to, lamports }) => {
                // Both, and in that order: an account that is on both sides nets to
                // nothing, which is what a self-transfer is and what a reading that
                // stopped at the first match would get wrong.
                if is_mine(from, mine) {
                    out.add(None, None, -(lamports as i128));
                }
                if is_mine(to, mine) {
                    out.add(None, None, lamports as i128);
                }
            }
            Some(Action::TransferToken {
                program,
                from,
                to,
                owner,
                amount,
                mint,
                named,
                ..
            }) => {
                // Out when the authority is ours or the account it leaves is; in when
                // the account it arrives at is one of ours. Again both, for the same
                // reason.
                if is_mine(owner, mine) || ours(from, mint, program, mine) {
                    out.add(mint, named, -(amount as i128));
                }
                if ours(to, mint, program, mine) {
                    out.add(mint, named, amount as i128);
                }
            }
            _ => {}
        }
    }
    out
}

/// Whether `key` is one this device holds.
fn is_mine(key: Option<SolanaKey>, mine: &[[u8; 32]]) -> bool {
    key.is_some_and(|k| mine.contains(&k.0))
}

/// Whether `account` is the associated token account of one of our keys for `mint`
/// under `program`.
///
/// The addresses inside an SPL transfer are token accounts, not wallets, so "is this
/// mine?" cannot be answered by comparing against our own keys. It is answered by
/// deriving what our account for that mint *would* be, which is arithmetic over public
/// keys and needs no seed and no trust. The token program is one of the seeds, so it has
/// to be the one the instruction called: deriving a Token-2022 account with the SPL
/// Token program's id gives an address that is nobody's.
pub fn ours(
    account: Option<SolanaKey>,
    mint: Option<SolanaKey>,
    program: TokenProgram,
    mine: &[[u8; 32]],
) -> bool {
    let (Some(account), Some(mint)) = (account, mint) else {
        return false;
    };
    mine.iter()
        .any(|k| associated_account(SolanaKey(*k), program, mint) == Some(account))
}
