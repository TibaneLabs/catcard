//! `crypto-multi-accounts`: every account this device holds, in one code.
//!
//! Keystone's extension rather than a BCR, and the thing a wallet reads when it says
//! "sync with your hardware wallet". One message carries a key per chain, each with the
//! path it came from, so a wallet learns every account at once instead of being told
//! about one chain and having to ask again for the next.
//!
//! Source: `@keystonehq/bc-ur-registry`, `CryptoMultiAccounts.ts`. Tag 1103, map keys
//! `masterFingerprint`, `keys`, `device`, `deviceId`, `version`. [C]
//!
//! # The keys are `crypto-hdkey`, and two curves go in them
//!
//! For secp256k1 the entry is what the specification describes: a compressed public key
//! and a chain code, at the account node, so the wallet derives addresses under it.
//!
//! For ed25519 there is no such thing -- SLIP-0010 has no public derivation, so a node
//! somebody else can derive from does not exist. Keystone writes the account's own
//! 32-byte public key and the wallets base58 it into the address `[C]`
//! (`@keystonehq/sol-keyring`: `bs58.encode(each.getKey())`). That is what this writes
//! too: one key per account rather than a node, and no chain code, because there is
//! nothing further to derive.

use super::{Error, TAG_HDKEY_V1, hdkey::HdKey};
use crate::cbor::Writer;

/// `crypto-multi-accounts`. [C] `@keystonehq/bc-ur-registry`
pub const TAG_MULTI_ACCOUNTS: u64 = 1103;

// Map keys. [C] `CryptoMultiAccounts.ts`, `enum Keys`.
const MASTER_FINGERPRINT: u64 = 1;
const KEYS: u64 = 2;
const DEVICE: u64 = 3;
/// `deviceId` (4) and `version` (5) are not written. A device id is an identifier for
/// one physical device, which is exactly the sort of thing a wallet has no need of and
/// this device has no business volunteering; the version says what firmware somebody is
/// running, which is the same.
const _RESERVED: u64 = 4;

/// Write the accounts as one `crypto-multi-accounts` message.
///
/// `fingerprint` is the master key's, which is how a wallet recognises the same device
/// again. `device` is the name it will show in its own list.
pub fn encode(
    fingerprint: u32,
    keys: &[HdKey],
    device: &str,
    out: &mut [u8],
) -> Result<usize, Error> {
    let mut w = Writer::new(out);
    w.map(3)?;
    w.uint(MASTER_FINGERPRINT)?;
    w.uint(u64::from(fingerprint))?;
    w.uint(KEYS)?;
    w.array(keys.len() as u64)?;
    for key in keys {
        // Tagged, unlike a `crypto-hdkey` sent on its own: inside another item the tag
        // is what says which item it is. [C] `CryptoMultiAccounts.ts` sets it explicitly.
        w.tag(TAG_HDKEY_V1)?;
        key.write(super::hdkey::Tags::V1, &mut w)?;
    }
    w.uint(DEVICE)?;
    w.text(device)?;
    Ok(w.len())
}

/// Bytes the encoded form will take, generously.
///
/// For a caller sizing a buffer before it has the keys: each entry is a small map with a
/// key, a chain code, a path of a few components and a name.
pub const fn encoded_len(keys: usize, device: usize) -> usize {
    const PER_KEY: usize = 160;
    16 + keys * PER_KEY + device
}
