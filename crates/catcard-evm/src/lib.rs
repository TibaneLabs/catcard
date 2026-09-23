//! Reading an Ethereum transaction, signed or not, and saying what it does.
//!
//! A hardware wallet's job with a transaction is not to send it. It is to answer, out
//! loud, the question the person holding the device is actually asking: *what am I
//! agreeing to?* Everything here serves that. The parse exists so the fields can be
//! named; the chain id exists so "on Polygon" can be said; the calldata decode exists so
//! a transfer can be called a transfer rather than "68 bytes of data".
//!
//! # What arrives
//!
//! Both forms, because both are offered in practice:
//!
//! - **Unsigned** -- the usual thing a watch-only wallet hands over. Legacy transactions
//!   arrive in their EIP-155 form, with the chain id where the signature goes.
//! - **Signed** -- a transaction somebody else already signed, offered for inspection,
//!   or one of ours coming back. Its signature is read and reported; re-signing it means
//!   re-encoding it without that signature, which [`Tx::signing_bytes`] does.
//!
//! Four envelopes: legacy, and the typed ones from EIP-2930, EIP-1559 and EIP-4844.
//! Typed transactions are a type byte followed by an RLP list (EIP-2718), and a type
//! this does not know is refused by number rather than guessed at.
//!
//! # What it deliberately does not do
//!
//! **It does not execute anything.** A decoded `transfer(address,uint256)` is what the
//! calldata *says*; whether the contract at that address implements ERC-20 or something
//! that merely shares a selector is not knowable here, and the screens that show this
//! say which parts are claims. The four-byte selector is a hash prefix and collides by
//! design; [`evmabiless`] answering with a name is evidence, not proof.
//!
//! Source: EIP-155 (chain id in the signature), EIP-2718 (typed envelopes), EIP-2930
//! (access lists), EIP-1559 (fee market), EIP-4844 (blobs). Public standards.

#![no_std]
#![forbid(unsafe_code)]

pub mod rlp;
pub mod summary;
pub mod tokens;

#[cfg(test)]
mod tests;

/// An address, as twenty bytes.
pub type Address = [u8; 20];

/// Why a transaction could not be read.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Not RLP, or not the RLP it claimed.
    Rlp(rlp::Error),
    /// An EIP-2718 type byte this does not know.
    UnknownType(u8),
    /// The right number of fields for no known form.
    NotATransaction,
    /// A field was wider than the protocol allows -- a 33-byte "u256", a 9-byte gas
    /// limit. Refused rather than truncated: a value that does not fit is a value this
    /// would otherwise show wrongly.
    FieldTooWide,
    /// The `to` field was neither empty (a contract creation) nor twenty bytes.
    BadAddress,
    /// There was no room to re-encode it for hashing.
    NoRoom,
}

impl From<rlp::Error> for Error {
    fn from(e: rlp::Error) -> Self {
        Error::Rlp(e)
    }
}

impl Error {
    /// The few words a screen has for it.
    pub fn why(self) -> &'static str {
        match self {
            Error::Rlp(_) => "this is not a transaction",
            Error::UnknownType(_) => "a transaction type this firmware does not know",
            Error::NotATransaction => "this is not a transaction",
            Error::FieldTooWide => "a field in it is out of range",
            Error::BadAddress => "its destination is malformed",
            Error::NoRoom => "not enough memory to check it",
        }
    }
}

/// Which envelope a transaction came in.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Kind {
    /// The original form. Carries its chain id inside the signature (EIP-155), or not at
    /// all on a pre-155 transaction.
    Legacy,
    /// EIP-2930: an access list, and a chain id of its own.
    AccessList,
    /// EIP-1559: a base fee and a tip, which is what almost everything is today.
    FeeMarket,
    /// EIP-4844: fee market plus blob hashes.
    Blob,
}

impl Kind {
    /// The EIP-2718 type byte, or `None` for the legacy form which has none.
    pub const fn type_byte(self) -> Option<u8> {
        match self {
            Kind::Legacy => None,
            Kind::AccessList => Some(0x01),
            Kind::FeeMarket => Some(0x02),
            Kind::Blob => Some(0x03),
        }
    }

    /// A word for a screen.
    pub const fn name(self) -> &'static str {
        match self {
            Kind::Legacy => "legacy",
            Kind::AccessList => "access list",
            Kind::FeeMarket => "fee market",
            Kind::Blob => "blob",
        }
    }
}

/// What a signature on a transaction is, as it arrived.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Signature {
    /// Legacy `v` (27/28, or `chain_id * 2 + 35/36`), or the parity bit on a typed one.
    pub v: u64,
    pub r: [u8; 32],
    pub s: [u8; 32],
}

/// A transaction, borrowed from the bytes it arrived in.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Tx<'a> {
    pub kind: Kind,
    /// `None` only for a pre-EIP-155 legacy transaction, which names no chain -- and is
    /// therefore valid on every chain at once, which is worth saying out loud.
    pub chain_id: Option<u64>,
    pub nonce: u64,
    /// `None` is a contract creation.
    pub to: Option<Address>,
    /// Wei, as 256 bits.
    pub value: [u8; 32],
    pub data: &'a [u8],
    pub gas_limit: u64,
    /// What the sender will pay per unit of gas, at most: `gas_price` on the older
    /// forms, `max_fee_per_gas` on the fee-market ones.
    pub max_fee: [u8; 32],
    /// The tip, on the fee-market forms only.
    pub max_priority_fee: Option<[u8; 32]>,
    /// How many entries the access list has. The contents do not change what the
    /// transaction *does*, only what it costs, so the count is all that is kept.
    pub access_list_len: usize,
    /// Present when the transaction arrived signed.
    pub signature: Option<Signature>,
    /// Exactly the bytes this was parsed from, for hashing.
    raw: &'a [u8],
}

/// Parse a transaction, signed or unsigned.
pub fn parse(bytes: &[u8]) -> Result<Tx<'_>, Error> {
    match bytes.first().copied() {
        None => Err(Error::Rlp(rlp::Error::Truncated)),
        // An EIP-2718 envelope: a type byte below 0x80, then an RLP list. The legacy
        // form always starts with a list header, which is 0xc0 or above, so the two can
        // never be confused.
        Some(t) if t < 0x80 => typed(t, &bytes[1..]),
        Some(_) => legacy(bytes),
    }
}

/// The legacy form, in both its shapes.
///
/// Nine fields either way. What distinguishes an unsigned EIP-155 transaction from a
/// signed one is what the last three hold: `chain_id, 0, 0` before signing, and `v, r, s`
/// after. A pre-155 unsigned transaction has six.
fn legacy(bytes: &[u8]) -> Result<Tx<'_>, Error> {
    let mut l = rlp::List::open(bytes)?;
    let nonce = u64_of(l.uint()?)?;
    let gas_price = u256_of(l.uint()?)?;
    let gas_limit = u64_of(l.uint()?)?;
    let to = address_of(l.bytes()?)?;
    let value = u256_of(l.uint()?)?;
    let data = l.bytes()?;

    let mut tx = Tx {
        raw: bytes,
        kind: Kind::Legacy,
        chain_id: None,
        nonce,
        to,
        value,
        data,
        gas_limit,
        max_fee: gas_price,
        max_priority_fee: None,
        access_list_len: 0,
        signature: None,
    };
    if l.done() {
        // Pre-EIP-155 and unsigned: no chain named at all.
        return Ok(tx);
    }
    let v = l.uint()?;
    let r = l.uint()?;
    let s = l.uint()?;
    if !l.done() {
        return Err(Error::NotATransaction);
    }
    let v = u64_of(v)?;
    if r.is_empty() && s.is_empty() {
        // The EIP-155 unsigned form: the chain id sits where `v` goes, with two zeros
        // behind it.
        tx.chain_id = Some(v);
        return Ok(tx);
    }
    // Signed. The chain id is folded into `v`, for anything since EIP-155.
    tx.chain_id = match v {
        27 | 28 => None,
        v if v >= 35 => Some((v - 35) / 2),
        _ => return Err(Error::NotATransaction),
    };
    tx.signature = Some(Signature {
        v,
        r: u256_of(r)?,
        s: u256_of(s)?,
    });
    Ok(tx)
}

/// The typed forms. `body` is everything after the type byte.
fn typed(t: u8, body: &[u8]) -> Result<Tx<'_>, Error> {
    let kind = match t {
        0x01 => Kind::AccessList,
        0x02 => Kind::FeeMarket,
        0x03 => Kind::Blob,
        other => return Err(Error::UnknownType(other)),
    };
    let mut l = rlp::List::open(body)?;
    let chain_id = u64_of(l.uint()?)?;
    let nonce = u64_of(l.uint()?)?;
    // 2930 has one fee field; 1559 and 4844 have a tip and a cap, in that order.
    let (max_priority_fee, max_fee) = if matches!(kind, Kind::AccessList) {
        (None, u256_of(l.uint()?)?)
    } else {
        let tip = u256_of(l.uint()?)?;
        (Some(tip), u256_of(l.uint()?)?)
    };
    let gas_limit = u64_of(l.uint()?)?;
    let to = address_of(l.bytes()?)?;
    let value = u256_of(l.uint()?)?;
    let data = l.bytes()?;
    let mut access = l.list()?;
    let mut access_list_len = 0;
    while !access.done() {
        let _ = access.next_item()?;
        access_list_len += 1;
    }
    if matches!(kind, Kind::Blob) {
        // max_fee_per_blob_gas, then the versioned hashes. Neither changes what the
        // transaction does to anybody's balance, so they are stepped over.
        let _ = l.uint()?;
        let _ = l.list()?;
    }

    let mut tx = Tx {
        // The type byte belongs to the transaction, and the hash is taken over it too.
        raw: body,
        kind,
        chain_id: Some(chain_id),
        nonce,
        to,
        value,
        data,
        gas_limit,
        max_fee,
        max_priority_fee,
        access_list_len,
        signature: None,
    };
    if l.done() {
        return Ok(tx);
    }
    let v = u64_of(l.uint()?)?;
    let r = u256_of(l.uint()?)?;
    let s = u256_of(l.uint()?)?;
    if !l.done() {
        return Err(Error::NotATransaction);
    }
    tx.signature = Some(Signature { v, r, s });
    Ok(tx)
}

impl<'a> Tx<'a> {
    /// The bytes a signature is made over, when this arrived unsigned.
    ///
    /// Which is **exactly what arrived**, for the typed forms with their type byte back
    /// in front. That is not a shortcut: signing anything else would be signing
    /// something the person was not shown, and the whole point of the screen before this
    /// is that the two are the same object.
    ///
    /// `None` for a transaction that came in signed. Re-signing one means re-encoding it
    /// without its signature, and this does not keep the raw access list needed to do
    /// that faithfully -- so it says so rather than hashing something close.
    pub fn signing_bytes(&self, out: &'a mut [u8]) -> Result<&'a [u8], Error> {
        if self.signed() {
            return Err(Error::NotATransaction);
        }
        let (extra, body) = match self.kind.type_byte() {
            Some(t) => (Some(t), self.raw),
            None => (None, self.raw),
        };
        let total = usize::from(extra.is_some()) + body.len();
        let out = out.get_mut(..total).ok_or(Error::NoRoom)?;
        if let Some(t) = extra {
            out[0] = t;
            out[1..].copy_from_slice(body);
        } else {
            out.copy_from_slice(body);
        }
        Ok(out)
    }

    /// Keccak-256 of [`signing_bytes`](Self::signing_bytes).
    pub fn signing_hash(&self, scratch: &'a mut [u8]) -> Result<[u8; 32], Error> {
        let bytes = self.signing_bytes(scratch)?;
        Ok(outscript::hash::keccak256_once(bytes))
    }

    /// Whether this arrived already signed.
    pub fn signed(&self) -> bool {
        self.signature.is_some()
    }

    /// Whether it creates a contract rather than calling one.
    pub fn creates_contract(&self) -> bool {
        self.to.is_none()
    }

    /// The first four bytes of the calldata: the method selector, where there is one.
    ///
    /// Calldata shorter than four bytes selects nothing -- that is a plain value
    /// transfer with a note attached, or a mistake.
    pub fn selector(&self) -> Option<[u8; 4]> {
        self.data.get(..4)?.try_into().ok()
    }

    /// The most gas this can spend, in wei: `gas_limit * max_fee`.
    ///
    /// The *most*, not the cost: a fee-market transaction pays the base fee plus the tip
    /// and refunds the rest, and the base fee is not known here. What a person needs
    /// before signing is the worst case, which is this.
    pub fn max_fee_wei(&self) -> [u8; 32] {
        mul_u64(self.max_fee, self.gas_limit)
    }
}

/// The 256-bit product of a 256-bit value and a `u64`, saturating.
///
/// Saturating rather than wrapping: a fee that overflowed 256 bits is not a small fee,
/// and showing it as one would be the worst possible rounding.
fn mul_u64(a: [u8; 32], b: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u128;
    for i in (0..32).rev() {
        let p = a[i] as u128 * b as u128 + carry;
        out[i] = p as u8;
        carry = p >> 8;
    }
    if carry != 0 {
        return [0xFF; 32];
    }
    out
}

fn u64_of(bytes: &[u8]) -> Result<u64, Error> {
    rlp::as_u64(bytes).ok_or(Error::FieldTooWide)
}

fn u256_of(bytes: &[u8]) -> Result<[u8; 32], Error> {
    rlp::as_u256(bytes).ok_or(Error::FieldTooWide)
}

fn address_of(bytes: &[u8]) -> Result<Option<Address>, Error> {
    match bytes.len() {
        0 => Ok(None),
        20 => Ok(Some(bytes.try_into().map_err(|_| Error::BadAddress)?)),
        _ => Err(Error::BadAddress),
    }
}
