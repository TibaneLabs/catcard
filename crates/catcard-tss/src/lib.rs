//! Threshold signing for CatCard: the protocol layer of docs/TSS.md.
//!
//! A TSS wallet's key is held in shares by `n` CatCards; any `t` of them sign together
//! (DKLs23 threshold ECDSA, tsslib's `dklstss`), and `t` can restore it. This crate is
//! everything about that which is not a screen or a file:
//!
//! - [`Session`] runs one protocol among numbered members: create together (DKG) or
//!   sign. It takes and produces **byte buffers** -- signed [`envelope`]s -- and never
//!   touches a card or a camera; the firmware moves them by SD (named by
//!   [`envelope::file_name`]) or QR.
//! - Round 0 of every session authenticates the members: per-session identity keys and
//!   a [`SessionCode`] the user compares across devices. After it every message is
//!   signed, unicasts are encrypted, and a message out of place is [`Refused`].
//! - [`ShareRecord`] is what a member stores; [`export`] splits a wallet the device holds
//!   into [`ShareBundle`]s (Codex32 for restoring, DKLs for signing);
//!   [`restore_entropy`] and [`combine`] put a wallet back together.
//!
//! # Members and thresholds
//!
//! Members are numbered `1..=n`, `2 <= t <= n <= 9`. `t` is the number of members that
//! sign or restore -- tsslib's own threshold is one less (its `t`-of-`n` key needs `t +
//! 1` signers), which this crate converts at its edge. Nine is Codex32's limit, and with
//! single-digit member numbers every message file name fits 8.3.
//!
//! The member number is also the party key tsslib shares at: member `i`'s Shamir share is
//! the polynomial at `x = i`.
//!
//! # Rounds
//!
//! | protocol        | round 0    | rounds               | after          |
//! |-----------------|------------|----------------------|----------------|
//! | create together | identities | 3 (shares, echo, OT) | a share record |
//! | sign            | identities | 6                    | signatures     |
//!
//! A signing session signs any number of sighashes at once, each its own tsslib party,
//! with all their messages for a round in one envelope: a PSBT of ten inputs takes the
//! same six passes of the cards as one input.
//!
//! # Randomness
//!
//! From the caller, through [`Entropy`], and never from anything else; see [`rng`] for
//! how tsslib's own generator is fed and what the firmware must do about it.
//!
//! # Private-key work
//!
//! Everything that touches a share, an identity key or a wallet secret takes a
//! [`KeyWork`](catcard_wallet::KeyWork), so on the device it runs inside `keywork::run`
//! with interrupts masked. A DKLs round is not sliced here: its duration depends on `n`
//! and the round, never on a secret.
//!
//! # Known limitations, from tsslib
//!
//! - **Key generation with `n <= 2t - 2`** (tsslib's `n <= 2t'` for its `t' = t - 1`):
//!   2-of-2, 3-of-3, 3-of-4 and so on. tsslib's round 1 has no commit-then-reveal, so
//!   colluding members who move last can bias the joint key to one they know. Export
//!   does not run a DKG and is not affected.
//! - **Selective-failure aborts in signing.** A malicious co-signer can make a signing
//!   session fail depending on one bit of another member's share. [`SignMode::Checked`]
//!   catches the inconsistent form of the attack and names the culprit; neither mode
//!   closes it fully. Repeated unexplained failures with the same co-signers are to be
//!   treated as an attack.
//! - tsslib copies key material into `serde_json` values and its own state that it does
//!   not wipe; this crate wipes every buffer it owns.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use tsslib::tss::PartyId;

mod bjson;
mod broker;
mod code;
pub mod envelope;
mod export;
mod identity;
pub mod rng;
mod session;
mod share;

pub use code::{SessionCode, WORDS as SESSION_CODE_WORDS};
pub use envelope::{Protocol, Refused, SESSION_ID_LEN, file_name, parse_file_name, session_dir};
pub use export::{AccountKey, export, restore_entropy, restore_entropy_from_codex32};
pub use rng::{Entropy, NoEntropy};
pub use session::{
    EcdsaSignature, MAX_REQUESTS, Outgoing, Session, SignMode, SignRequest, Status, new_session_id,
};
pub use share::{JointSecret, MAX_PATH, Origin, ShareBundle, ShareRecord, combine};

/// Most members a TSS wallet has: Codex32's nine share indices.
pub const MAX_MEMBERS: u8 = 9;

/// A compressed secp256k1 public key.
pub const PUBKEY_LEN: usize = 33;

/// Why an operation did not complete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// `n`, `t`, a member number, a signer set or a path out of range.
    Parameters,
    /// The caller's [`Entropy`] refused, or tsslib draws from a source this crate did
    /// not install ([`rng::install`]).
    Randomness,
    /// A message was not taken; the session is unchanged.
    Refused(Refused),
    /// A record, bundle or payload that does not parse.
    Format(&'static str),
    /// A call out of order (confirming before every identity is in, receiving after
    /// the end...).
    State(&'static str),
    /// The protocol failed: tsslib refused a peer's message or could not finish. The
    /// session is over.
    Protocol(String),
    /// A Codex32 share was refused.
    Codex32(catcard_wallet::codex32::Error),
    /// Fewer shares than the threshold.
    NotEnoughShares,
    /// Shares of different wallets or splits, or a combination that does not give the
    /// wallet's public key.
    Mismatch,
}

impl From<Refused> for Error {
    fn from(r: Refused) -> Self {
        Error::Refused(r)
    }
}

/// tsslib's party id for member `m`: key `[m]`, so it shares at `x = m`.
pub(crate) fn member_id(m: u8) -> PartyId {
    PartyId::new(m.to_string(), "", alloc::vec![m])
}

/// Members `1..=n` as tsslib's sorted party set.
pub(crate) fn member_ids(n: u8) -> Vec<PartyId> {
    PartyId::sort((1..=n).map(member_id).collect(), 0)
}
