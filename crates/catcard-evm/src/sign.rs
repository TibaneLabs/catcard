//! Putting a signature onto a transaction.
//!
//! The reading half of this crate never has to write anything: what gets hashed is the
//! bytes exactly as they arrived. Signing is the one place a transaction has to be built,
//! and the danger there is well known -- a signer that rebuilds a transaction from the
//! fields it understood signs a *different* transaction from the one it showed somebody.
//!
//! So nothing is rebuilt. The unsigned payload is copied verbatim and the three signature
//! items are appended to it, which means an access list, a blob's versioned hashes, and
//! anything a later fork adds all go back out byte for byte, decoded or not.
//!
//! # What changes between forms
//!
//! - **Typed** (2930, 1559, 4844): the signed payload is the unsigned payload plus
//!   `yParity`, `r`, `s`. The type byte goes back in front. [C] EIP-2718
//! - **Legacy, EIP-155**: the unsigned form ends with `chainId, 0, 0`, and those three
//!   are *replaced* by `v, r, s` with `v = chainId * 2 + 35 + parity`. [C] EIP-155
//! - **Legacy, pre-EIP-155**: nothing to replace; `v = 27 + parity`. [C] Homestead

use crate::rlp;
use crate::{Error, Kind, Tx};

/// The most a signature adds: three items, each with a one-byte header, `v` up to nine
/// bytes and `r` and `s` up to thirty-two.
pub const OVERHEAD: usize = 3 + 9 + 32 + 32;

/// Write `tx` with this signature on it, and say how long it is.
///
/// `recid` is the recovery id as [`outscript::crypto::secp256k1`] returns it. Only 0 and
/// 1 can be written: Ethereum's `v` carries one parity bit, and the values above that --
/// which mean the signature's `r` overflowed the curve order -- have no room in it.
/// RFC6979 makes them vanishingly rare and refusing is the only honest answer, since a
/// `v` that dropped the high bit would recover somebody else's address.
pub fn encode_signed(
    tx: &Tx<'_>,
    r: &[u8; 32],
    s: &[u8; 32],
    recid: u8,
    out: &mut [u8],
) -> Result<usize, Error> {
    if tx.signed() {
        return Err(Error::NotATransaction);
    }
    if recid > 1 {
        return Err(Error::NotATransaction);
    }
    let parity = u64::from(recid & 1);

    // The payload of the unsigned list, and how much of it survives.
    let whole = rlp::item(tx.raw())?;
    if !whole.list {
        return Err(Error::NotATransaction);
    }
    let payload = whole.payload;
    let keep = match tx.kind {
        // Everything: a typed transaction's unsigned form is its signed form without
        // the last three items.
        Kind::AccessList | Kind::FeeMarket | Kind::Blob => payload,
        Kind::Legacy => {
            // The six fields every legacy transaction has. What follows them is either
            // nothing (pre-EIP-155) or the `chainId, 0, 0` that the signature replaces.
            let mut l = rlp::List::open(tx.raw())?;
            for _ in 0..6 {
                let _ = l.next_item()?;
            }
            let left = l.remainder().len();
            payload.get(..payload.len() - left).ok_or(Error::NoRoom)?
        }
    };

    let v = match tx.kind {
        Kind::Legacy => match tx.chain_id {
            Some(chain) => chain
                .checked_mul(2)
                .and_then(|c| c.checked_add(35 + parity))
                .ok_or(Error::NotATransaction)?,
            None => 27 + parity,
        },
        _ => parity,
    };

    // RLP writes an integer big-endian with no leading zeros, and zero as an empty
    // string -- which is what `yParity = 0` becomes on a typed transaction.
    let v_be = v.to_be_bytes();
    let v_item = trim(&v_be);
    let items: [&[u8]; 3] = [v_item, trim(r), trim(s)];

    let type_byte = tx.kind.type_byte();
    let at = usize::from(type_byte.is_some());
    if let Some(t) = type_byte {
        *out.first_mut().ok_or(Error::NoRoom)? = t;
    }
    let body = out.get_mut(at..).ok_or(Error::NoRoom)?;
    let written = rlp::list_from(keep, &items, body).ok_or(Error::NoRoom)?;
    Ok(at + written.len())
}

/// A big-endian number with its leading zeros off, as RLP writes one.
fn trim(bytes: &[u8]) -> &[u8] {
    let at = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[at..]
}
