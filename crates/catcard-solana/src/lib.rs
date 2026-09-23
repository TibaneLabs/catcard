//! What a Solana transaction does, in the terms a person signing it uses.
//!
//! The pieces that are facts about the format -- base58 keys, compact-u16, and the
//! well-known program addresses -- come from [`outscript::solana`], which is ours and
//! already carries them as compile-time constants. The message walk is here because
//! outscript's owns its result: `Vec`s of `Vec`s behind that crate's `alloc` feature,
//! which also drags in `serde_json`. A wallet reads one transaction out of a buffer it
//! already holds, so this borrows from that buffer and allocates nothing.
//!
//! The tests build their fixtures with outscript's encoder, which *is* worth the
//! serde_json on a host: what this reads is then checked against what an implementation
//! sharing none of this code wrote.
//!
//! # Partly signed is a state, not an error
//!
//! A Solana transaction carries one signature slot per required signer, and slots are
//! filled independently -- a multisig, or a fee payer who signs after you do. A slot
//! that is empty is a slot waiting for somebody, so [`Signing::missing`] is a number to
//! show rather than a reason to refuse. What matters for safety is the opposite
//! direction: a transaction arriving with signatures already on it is one whose message
//! **must not change**, or those signatures stop matching it.
//!
//! # What is decoded, and what is only named
//!
//! Decoded, because the instruction is fixed-shape and the program is identified by an
//! address this build carries: the System program's transfer, the SPL Token program's
//! transfer, checked transfer and approve, an associated-token-account creation, and the
//! compute-budget settings that ride along with almost everything.
//!
//! Everything else is **named and counted, never guessed**: the program's address, how
//! many accounts it touches and how many bytes of data it carries. A program this build
//! does not know is a program whose instruction this build cannot read, and saying so is
//! the honest screen.

#![no_std]
#![forbid(unsafe_code)]

pub mod link;
pub mod literal;
pub mod mints;

#[cfg(test)]
mod tests;

pub use outscript::solana::SolanaKey;

use outscript::solana::{
    ata_program, compute_budget_program, decode_compact_u16, system_program, token_program,
};

/// How many lamports make one SOL.
pub const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

/// Why a transaction could not be read.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// The bytes are not a Solana transaction.
    NotATransaction,
    /// It parsed, but its message refers to accounts it does not carry -- an index past
    /// the end of the key array. Refused rather than shown with a gap, because every
    /// account in an instruction is part of what it does.
    BadAccountIndex,
    /// A message version this build has not been written against.
    UnsupportedVersion(u8),
}

impl Error {
    /// The few words a screen has for it.
    pub fn why(self) -> &'static str {
        match self {
            Error::NotATransaction => "this is not a Solana transaction",
            Error::BadAccountIndex => "it refers to accounts it does not carry",
            Error::UnsupportedVersion(_) => "a message version this firmware cannot read",
        }
    }
}

/// Which message format a transaction arrived in.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Version {
    /// The original format.
    Legacy,
    /// Versioned, with address table lookups.
    V0,
    /// SIMD-0385.
    V1,
}

impl Version {
    /// A word for a screen.
    pub const fn name(self) -> &'static str {
        match self {
            Version::Legacy => "legacy",
            Version::V0 => "v0",
            Version::V1 => "v1",
        }
    }
}

/// How far through signing a transaction is.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Signing {
    /// Signatures the message requires.
    pub required: usize,
    /// Slots already filled.
    pub present: usize,
}

impl Signing {
    /// Slots still waiting for somebody.
    pub fn missing(self) -> usize {
        self.required.saturating_sub(self.present)
    }

    /// Whether anybody has signed this yet.
    ///
    /// The question worth asking before a screen offers to change anything: a message
    /// with a signature on it is a message that cannot be edited without throwing that
    /// signature away.
    pub fn partly_signed(self) -> bool {
        self.present > 0 && self.missing() > 0
    }
}

/// A transaction, borrowed from the bytes it arrived in.
#[derive(Copy, Clone)]
pub struct Tx<'a> {
    version: Version,
    /// The signature slots, 64 bytes each.
    signatures: &'a [u8],
    /// Everything a signature is over: the message, which is the rest of the bytes.
    message: &'a [u8],
    header: [u8; 3],
    /// The account keys, 32 bytes each.
    keys: &'a [u8],
    /// The instruction region, walked on demand.
    instructions: &'a [u8],
    instruction_count: usize,
    lookup_tables: usize,
    lookup_accounts: usize,
}

/// A cursor with the bounds checks in one place.
struct Cursor<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let out = self
            .data
            .get(self.at..self.at + n)
            .ok_or(Error::NotATransaction)?;
        self.at += n;
        Ok(out)
    }

    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    /// A compact-u16 length, as the format writes every count.
    fn len(&mut self) -> Result<usize, Error> {
        decode_compact_u16(self.data, &mut self.at).map_err(|_| Error::NotATransaction)
    }
}

/// Parse a transaction, signed, partly signed or not at all.
///
/// Legacy and v0. **A v1 transaction is refused by name**: its layout is SIMD-0385's and
/// this has not been written against it, and a reader that guessed at a format would be
/// guessing about what somebody is signing.
pub fn parse(bytes: &[u8]) -> Result<Tx<'_>, Error> {
    let mut c = Cursor { data: bytes, at: 0 };
    let sig_count = c.len()?;
    let signatures = c.take(sig_count.checked_mul(64).ok_or(Error::NotATransaction)?)?;
    // What a signature is over starts here -- at the version byte, for a message that
    // has one. The end is the end of the transaction, which the full-consumption check
    // at the bottom of `walk` is what makes true.
    let message = &bytes[c.at..];
    walk(c, signatures, message)
}

/// Parse a message on its own: a transaction with its signature slots taken off.
///
/// This is what an air-gapped signing request carries -- `sol-sign-request` asks for a
/// signature over exactly these bytes -- and it is the same object as a transaction in
/// every way that matters to a person reading it. What comes back reports no signatures,
/// because a message has nowhere to keep one, and [`Tx::to_transaction`] is how it
/// becomes something that can hold them.
pub fn parse_message(bytes: &[u8]) -> Result<Tx<'_>, Error> {
    let c = Cursor { data: bytes, at: 0 };
    walk(c, &[], bytes)
}

/// The message walk, shared by both entry points.
fn walk<'a>(mut c: Cursor<'a>, signatures: &'a [u8], message: &'a [u8]) -> Result<Tx<'a>, Error> {
    let bytes = c.data;

    // A versioned message opens with a byte that cannot be a header: the top bit is set,
    // and a legacy header's first byte is a signature count that never reaches 0x80.
    let first = *bytes.get(c.at).ok_or(Error::NotATransaction)?;
    let version = if first & 0x80 == 0 {
        Version::Legacy
    } else {
        c.at += 1;
        match first & 0x7f {
            0 => Version::V0,
            1 => return Err(Error::UnsupportedVersion(1)),
            other => return Err(Error::UnsupportedVersion(other)),
        }
    };

    let header = [c.byte()?, c.byte()?, c.byte()?];
    let key_count = c.len()?;
    let keys = c.take(key_count.checked_mul(32).ok_or(Error::NotATransaction)?)?;
    // The recent blockhash: read past, because what it commits to is freshness rather
    // than anything a person checks.
    let _ = c.take(32)?;

    let instruction_count = c.len()?;
    let from = c.at;
    // Walk them once here so every later read is inside bytes already checked.
    for _ in 0..instruction_count {
        let program = c.byte()?;
        if program as usize >= key_count {
            return Err(Error::BadAccountIndex);
        }
        let accounts = c.len()?;
        for &a in c.take(accounts)? {
            if a as usize >= key_count {
                return Err(Error::BadAccountIndex);
            }
        }
        let data = c.len()?;
        let _ = c.take(data)?;
    }
    let instructions = &bytes[from..c.at];

    // The address table lookups, which only a versioned message has.
    //
    // **Read, not skipped.** They are part of the message and therefore part of what a
    // signature covers, so a reader that stopped before them would be reporting on less
    // than it signs. They also say something worth showing: each index is an account the
    // instructions use and this device cannot see, because it lives in a table on-chain.
    let mut lookup_tables = 0;
    let mut lookup_accounts = 0;
    if matches!(version, Version::V0) {
        lookup_tables = c.len()?;
        for _ in 0..lookup_tables {
            let _table = c.take(32)?;
            let writable = c.len()?;
            let _ = c.take(writable)?;
            let readonly = c.len()?;
            let _ = c.take(readonly)?;
            lookup_accounts += writable + readonly;
        }
    }

    // Nothing left over. A transaction is a whole object, and bytes after the end of one
    // mean this is not a transaction -- or is one with something appended, which is the
    // same thing for a device deciding what it is about to sign. It is also what makes
    // the parse usable as a test of "are these bytes a Solana transaction at all":
    // without it, anything that merely *starts* like one would pass.
    if c.at != bytes.len() {
        return Err(Error::NotATransaction);
    }

    Ok(Tx {
        version,
        signatures,
        message,
        header,
        keys,
        instructions,
        instruction_count,
        lookup_tables,
        lookup_accounts,
    })
}

/// Put `signature` in slot `index` of the transaction in `bytes`.
///
/// Separate from [`Tx`] because a transaction is read through a shared borrow and signed
/// through an exclusive one, and because this is the one operation that changes the
/// bytes: keeping it apart means every other path is visibly read-only.
///
/// **The message is not touched, and cannot be.** Only a 64-byte slot is written, so
/// signatures already in the transaction stay valid -- which is the whole reason a
/// partly signed transaction can be passed from signer to signer. `false` means nothing
/// was written: not a transaction, or a slot it does not have.
pub fn place_signature(bytes: &mut [u8], index: usize, signature: &[u8; 64]) -> bool {
    let mut at = 0;
    let Ok(count) = decode_compact_u16(bytes, &mut at) else {
        return false;
    };
    if index >= count {
        return false;
    }
    let from = at + index * 64;
    let Some(slot) = bytes.get_mut(from..from + 64) else {
        return false;
    };
    slot.copy_from_slice(signature);
    true
}

impl<'a> Tx<'a> {
    /// The bytes a signature is over.
    ///
    /// The message: the header, the account keys, the blockhash, the instructions and --
    /// for a versioned transaction -- the version byte in front and the address table
    /// lookups behind. Everything except the signature slots, which is why signing one
    /// never invalidates another.
    pub fn message(&self) -> &'a [u8] {
        self.message
    }

    /// Which slot `key` signs, if it signs at all.
    ///
    /// The signers are the first `required` account keys, in order, and slot `i` belongs
    /// to key `i`. A key further down the list is an account the transaction touches
    /// rather than one that authorises it, and gets `None` -- a device that signed for
    /// one of those would be producing a signature the network has no slot for.
    pub fn signer_index(&self, key: &[u8; 32]) -> Option<usize> {
        (0..self.signing().required).find(|&i| self.keys.get(i * 32..i * 32 + 32) == Some(&key[..]))
    }

    /// Write this out as a transaction: the signature slots, then the message.
    ///
    /// For the one that arrived as a message alone. A signing request carries no slots,
    /// and a transaction cannot be broadcast without them, so they are put in front --
    /// empty, in the number the header says are required, ready for
    /// [`place_signature`].
    ///
    /// A transaction that arrived as one is written back as it came, signatures and all.
    /// `None` means `out` is too small; nothing is written in that case.
    pub fn to_transaction(&self, out: &mut [u8]) -> Option<usize> {
        let count = if self.signatures.is_empty() {
            self.signing().required
        } else {
            self.signatures.len() / 64
        };
        // A compact-u16: seven bits a byte, high bit meaning "another follows". The same
        // encoding every count in the format uses, and a signature count never needs
        // more than two bytes because an account index is a byte.
        let mut head = [0u8; 2];
        let head = if count < 0x80 {
            head[0] = count as u8;
            &head[..1]
        } else {
            head[0] = (count as u8 & 0x7f) | 0x80;
            head[1] = (count >> 7) as u8;
            &head[..2]
        };
        let slots = count * 64;
        let total = head.len() + slots + self.message.len();
        if out.len() < total || count > 0x3fff {
            return None;
        }
        out[..head.len()].copy_from_slice(head);
        let mut at = head.len();
        if self.signatures.is_empty() {
            out[at..at + slots].fill(0);
        } else {
            out[at..at + slots].copy_from_slice(self.signatures);
        }
        at += slots;
        out[at..at + self.message.len()].copy_from_slice(self.message);
        Some(total)
    }

    /// What this transaction will cost its fee payer.
    ///
    /// Two parts, and the device can be sure of only one. The signature fee is the
    /// network's rate times the signatures required, and is a few thousand lamports. The
    /// priority fee is the compute limit times the price per unit, both set by
    /// instructions in the transaction -- so a transaction can ask its payer for an
    /// arbitrary amount without a transfer anywhere in it, which is worth a line on a
    /// screen rather than a shrug.
    ///
    /// A price set without a limit is reported as unknown rather than estimated: the
    /// runtime's default depends on the instructions, and a number this device made up
    /// would be read as one the transaction contained.
    pub fn fee(&self) -> Fee {
        let mut limit = None;
        let mut price = None;
        for i in 0..self.instruction_count() {
            if let Some(Action::ComputeBudget(b)) = self.action(i) {
                match b {
                    Budget::Limit { units } => limit = Some(u64::from(units)),
                    Budget::Price { micro_lamports } => price = Some(micro_lamports),
                    _ => {}
                }
            }
        }
        let base = LAMPORTS_PER_SIGNATURE.saturating_mul(self.signing().required as u64);
        match (limit, price) {
            // Rounded up, because the fee is: a fraction of a lamport is charged as one.
            (Some(l), Some(p)) => Fee {
                base,
                priority: Some(l.saturating_mul(p).div_ceil(1_000_000)),
                priority_unknown: false,
            },
            (None, Some(_)) => Fee {
                base,
                priority: None,
                priority_unknown: true,
            },
            _ => Fee {
                base,
                priority: Some(0),
                priority_unknown: false,
            },
        }
    }

    /// Whether slot `i` has been filled.
    ///
    /// An empty slot is sixty-four zeros, which is what an unsigned transaction carries
    /// and what no real signature is.
    pub fn signed(&self, i: usize) -> bool {
        self.signatures
            .get(i * 64..i * 64 + 64)
            .is_some_and(|s| s.iter().any(|&b| b != 0))
    }

    /// Which format it arrived in.
    pub fn version(&self) -> Version {
        self.version
    }

    /// Account key `i`, if the message carries it.
    ///
    /// **A v0 transaction can refer to accounts it does not carry**: an address table
    /// lookup names them by index into a table that lives on-chain, which a device
    /// holding only the transaction cannot read. Those are out of range here, come back
    /// `None`, and the screens say "an address from a lookup table" rather than showing
    /// the wrong key.
    pub fn key(&self, i: usize) -> Option<SolanaKey> {
        let bytes = self.keys.get(i * 32..i * 32 + 32)?;
        let mut k = [0u8; 32];
        k.copy_from_slice(bytes);
        Some(SolanaKey(k))
    }

    /// How many account keys it carries.
    pub fn key_count(&self) -> usize {
        self.keys.len() / 32
    }

    /// Who pays, which is the first account and the first signer.
    pub fn fee_payer(&self) -> Option<SolanaKey> {
        self.key(0)
    }

    /// How far through signing it is.
    pub fn signing(&self) -> Signing {
        Signing {
            required: self.header[0] as usize,
            // An empty slot is 64 zero bytes: the format keeps the room whether or not
            // anybody has filled it, which is what makes the count mean something.
            present: self
                .signatures
                .as_chunks::<64>()
                .0
                .iter()
                .filter(|s| s.iter().any(|&b| b != 0))
                .count(),
        }
    }

    /// How many instructions it will run.
    pub fn instruction_count(&self) -> usize {
        self.instruction_count
    }

    /// How many address lookup tables it draws accounts from, and how many accounts
    /// those are.
    ///
    /// Both are zero for a legacy transaction, which carries every account it uses. For a
    /// versioned one they are the size of what this device **cannot see**: the accounts
    /// live in a table on-chain, the transaction names them by index, and a screen that
    /// did not say so would be showing a complete-looking list of accounts that is not
    /// the whole list.
    pub fn lookups(&self) -> (usize, usize) {
        (self.lookup_tables, self.lookup_accounts)
    }

    /// What instruction `i` does.
    pub fn action(&self, i: usize) -> Option<Action> {
        let mut c = Cursor {
            data: self.instructions,
            at: 0,
        };
        for n in 0..=i {
            let program = c.byte().ok()?;
            let accounts = c.len().ok()?;
            let account_indices = c.take(accounts).ok()?;
            let data_len = c.len().ok()?;
            let data = c.take(data_len).ok()?;
            if n == i {
                let program = self.key(program as usize)?;
                let account = |n: usize| account_indices.get(n).and_then(|&a| self.key(a as usize));
                return Some(decode(program, data, account_indices.len(), &account));
            }
        }
        None
    }
}

/// One setting from the compute budget program.
///
/// Discriminants and their little-endian payloads. [C] `solana-sdk`,
/// `compute-budget-interface`: `ComputeBudgetInstruction`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Budget {
    /// A heap size for every program in the transaction, in bytes. Discriminant 1.
    Heap { bytes: u32 },
    /// The compute units this transaction may use. Discriminant 2.
    Limit { units: u32 },
    /// What each of those units costs, in millionths of a lamport. Discriminant 3. The
    /// priority fee is this times the limit, which is why neither number means much
    /// without the other.
    Price { micro_lamports: u64 },
    /// A cap on the account data this transaction may load, in bytes. Discriminant 4.
    DataSize { bytes: u32 },
    /// A setting this build does not decode, or one whose payload is the wrong length.
    Other,
}

/// What a transaction will cost its fee payer, in lamports.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Fee {
    /// The signature fee: the network's rate times the signatures required.
    pub base: u64,
    /// The priority fee, when the transaction sets both numbers that decide it.
    pub priority: Option<u64>,
    /// A price was set with no limit beside it. The runtime then applies a default that
    /// depends on the instructions, and this build does not compute it -- so the fee is
    /// higher than [`Fee::base`] by an amount named nowhere in these bytes.
    pub priority_unknown: bool,
}

/// Lamports per signature, the rate every cluster has run at.
///
/// A cluster's fee governor could in principle set another, so this is the default
/// rather than a promise. [C] `solana-sdk`: `DEFAULT_LAMPORTS_PER_SIGNATURE`.
pub const LAMPORTS_PER_SIGNATURE: u64 = 5_000;

/// What one instruction amounts to.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Action {
    /// The System program moving SOL.
    TransferSol {
        from: Option<SolanaKey>,
        to: Option<SolanaKey>,
        lamports: u64,
    },
    /// An SPL token moving, as the instruction claims.
    ///
    /// `decimals` and `mint` are present only for the *checked* form, which is the one
    /// that carries them -- and the one a person can therefore be shown a scaled amount
    /// for. The unchecked form gives a raw number and the token account it comes from,
    /// and that is all anybody off-chain can know about it.
    TransferToken {
        from: Option<SolanaKey>,
        to: Option<SolanaKey>,
        owner: Option<SolanaKey>,
        amount: u64,
        decimals: Option<u8>,
        mint: Option<SolanaKey>,
        /// What the mint table calls it, when it carries that mint.
        named: Option<mints::Mint>,
    },
    /// A delegation: somebody else may move this many tokens.
    ApproveToken {
        account: Option<SolanaKey>,
        delegate: Option<SolanaKey>,
        owner: Option<SolanaKey>,
        amount: u64,
    },
    /// Creating the associated token account for a wallet and mint.
    CreateTokenAccount {
        owner: Option<SolanaKey>,
        mint: Option<SolanaKey>,
    },
    /// A compute-budget setting: what the transaction costs, not what it does.
    ///
    /// Worth decoding rather than naming, because the priority fee is set here and the
    /// payer pays whatever it says. A price nobody looked at is the one number in a
    /// transaction that can empty an account without a transfer in sight.
    ComputeBudget(Budget),
    /// A durable nonce being consumed and replaced.
    ///
    /// What makes a transaction that will be signed later still valid: instead of a
    /// blockhash that expires in about a minute, the message commits to a nonce held in
    /// an account, and advancing it is what spends that nonce. An air-gapped signature
    /// is the reason anybody uses one, so a device that called it "a program this build
    /// cannot read" would be warning about the very thing that waited for it.
    AdvanceNonce {
        account: Option<SolanaKey>,
        authority: Option<SolanaKey>,
    },
    /// A program this build does not decode, named and counted.
    Unknown {
        program: SolanaKey,
        /// What the program is called, where the address is one this build knows. A
        /// name is not a decoding: it says whose instruction this is, not what it does.
        named: Option<&'static str>,
        /// The instruction's number, for a program whose instructions are numbered.
        /// Shown so that an instruction nobody here has written a reader for can at
        /// least be looked up by somebody who has.
        tag: Option<u32>,
        accounts: usize,
        data_len: usize,
    },
}

impl Action {
    /// Whether a checked transfer's decimals disagree with the mint this build knows.
    ///
    /// Both numbers describe the same mint and the program enforces that its own copy is
    /// right, so a disagreement means **this firmware's table is wrong about that mint**
    /// -- stale, or naming an address that is not what it was when the row was written.
    /// Either way the amount on screen would be scaled by the wrong power of ten, which
    /// is the difference between sending one token and a thousand. Worth its own answer
    /// rather than a silent preference for one source.
    pub fn decimals_disagree(&self) -> bool {
        match self {
            Action::TransferToken {
                decimals: Some(d),
                named: Some(m),
                ..
            } => *d != m.decimals,
            _ => false,
        }
    }
}

/// SPL Token instruction tags, from the program's own layout.
const TOKEN_TRANSFER: u8 = 3;
const TOKEN_APPROVE: u8 = 4;
const TOKEN_TRANSFER_CHECKED: u8 = 12;
fn decode(
    program: SolanaKey,
    data: &[u8],
    accounts: usize,
    account: &dyn Fn(usize) -> Option<SolanaKey>,
) -> Action {
    // The fallback, for a program this build has no reader for. Named where the address
    // is one it knows, and carrying the instruction's number where the program numbers
    // them -- neither of which is a decoding, and the screens say so.
    let named = if program == token_program() {
        Some("SPL Token")
    } else if program == ata_program() {
        Some("Associated Token Account")
    } else if program == compute_budget_program() {
        Some("Compute Budget")
    } else {
        None
    };
    let unknown = Action::Unknown {
        program,
        named,
        tag: data.first().map(|&b| u32::from(b)),
        accounts,
        data_len: data.len(),
    };

    if program == system_program() {
        // Every System instruction opens with a little-endian `u32` discriminant.
        // [C] `solana-sdk`, `system-interface`: `SystemInstruction`.
        let tag = (data.len() >= 4).then(|| u32_le(&data[..4]));
        match (tag, data.len()) {
            // Transfer: the tag and a little-endian `u64` of lamports.
            (Some(2), 12) => {
                return Action::TransferSol {
                    from: account(0),
                    to: account(1),
                    lamports: u64_le(&data[4..12]),
                };
            }
            // AdvanceNonceAccount: no parameters at all. The accounts are the nonce
            // account, the recent-blockhashes sysvar, and the authority that signs.
            (Some(4), 4) => {
                return Action::AdvanceNonce {
                    account: account(0),
                    authority: account(2),
                };
            }
            _ => {}
        }
        return Action::Unknown {
            program,
            named: Some("System"),
            tag,
            accounts,
            data_len: data.len(),
        };
    }

    if program == token_program() {
        return match data.first().copied() {
            // transfer: tag, amount. Accounts: source, destination, owner.
            Some(TOKEN_TRANSFER) if data.len() == 9 => Action::TransferToken {
                from: account(0),
                to: account(1),
                owner: account(2),
                amount: u64_le(&data[1..9]),
                // The unchecked form names no mint, so there is nothing to look up:
                // the amount stays in whatever the smallest unit of an unnamed token
                // is, which is the whole of what anybody off-chain knows about it.
                decimals: None,
                mint: None,
                named: None,
            },
            // transferChecked: tag, amount, decimals. Accounts: source, mint,
            // destination, owner -- the mint is in the middle, which is the whole point
            // of the checked form.
            Some(TOKEN_TRANSFER_CHECKED) if data.len() == 10 => {
                let mint = account(1);
                Action::TransferToken {
                    from: account(0),
                    to: account(2),
                    owner: account(3),
                    amount: u64_le(&data[1..9]),
                    decimals: Some(data[9]),
                    mint,
                    named: mint.and_then(|m| mints::lookup(&m.0)),
                }
            }
            // approve: tag, amount. Accounts: source, delegate, owner.
            Some(TOKEN_APPROVE) if data.len() == 9 => Action::ApproveToken {
                account: account(0),
                delegate: account(1),
                owner: account(2),
                amount: u64_le(&data[1..9]),
            },
            _ => unknown,
        };
    }

    if program == ata_program() {
        // Create: payer, the new account, its owner, the mint, then the two programs.
        return Action::CreateTokenAccount {
            owner: account(2),
            mint: account(3),
        };
    }

    if program == compute_budget_program() {
        return Action::ComputeBudget(match (data.first(), data.len()) {
            (Some(1), 5) => Budget::Heap {
                bytes: u32_le(&data[1..]),
            },
            (Some(2), 5) => Budget::Limit {
                units: u32_le(&data[1..]),
            },
            (Some(3), 9) => Budget::Price {
                micro_lamports: u64_le(&data[1..]),
            },
            (Some(4), 5) => Budget::DataSize {
                bytes: u32_le(&data[1..]),
            },
            _ => Budget::Other,
        });
    }

    unknown
}

fn u32_le(b: &[u8]) -> u32 {
    let mut v = [0u8; 4];
    v.copy_from_slice(&b[..4]);
    u32::from_le_bytes(v)
}

fn u64_le(b: &[u8]) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[..8]);
    u64::from_le_bytes(v)
}

/// The longest base58 an address takes, plus room.
pub const ADDRESS_MAX: usize = 44;

/// Write `key` as base58, which is how Solana addresses are read and compared.
pub fn address<'o>(key: &SolanaKey, out: &'o mut [u8; ADDRESS_MAX]) -> &'o str {
    match key.to_base58_slice(out) {
        Ok(n) => core::str::from_utf8(&out[..n]).unwrap_or("?"),
        Err(_) => "?",
    }
}
