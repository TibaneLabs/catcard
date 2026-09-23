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

pub mod literal;
pub mod mints;

#[cfg(test)]
mod tests;

use outscript::solana::{
    SolanaKey, ata_program, compute_budget_program, decode_compact_u16, system_program,
    token_program,
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
    header: [u8; 3],
    /// The account keys, 32 bytes each.
    keys: &'a [u8],
    /// The instruction region, walked on demand.
    instructions: &'a [u8],
    instruction_count: usize,
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

    Ok(Tx {
        version,
        signatures,
        header,
        keys,
        instructions,
        instruction_count,
    })
}

impl<'a> Tx<'a> {
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
    /// A compute-budget setting: what it costs, not what it does.
    ComputeBudget,
    /// A program this build does not decode, named and counted.
    Unknown {
        program: SolanaKey,
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
/// The System program's instruction tags are four bytes, little-endian.
const SYSTEM_TRANSFER: [u8; 4] = [2, 0, 0, 0];

fn decode(
    program: SolanaKey,
    data: &[u8],
    accounts: usize,
    account: &dyn Fn(usize) -> Option<SolanaKey>,
) -> Action {
    let unknown = Action::Unknown {
        program,
        accounts,
        data_len: data.len(),
    };

    if program == system_program() {
        // transfer: a four-byte tag and a little-endian `u64`.
        if data.len() == 12 && data[..4] == SYSTEM_TRANSFER {
            return Action::TransferSol {
                from: account(0),
                to: account(1),
                lamports: u64_le(&data[4..12]),
            };
        }
        return unknown;
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
        return Action::ComputeBudget;
    }

    unknown
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
