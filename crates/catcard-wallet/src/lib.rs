//! Wallet logic: encodings, key derivation, addresses, transactions, and which chains
//! this build carries.
//!
//! One crate rather than six. These modules are only ever used together, by one binary,
//! and the boundaries between them were filing rather than architecture: six manifests
//! and six sets of feature flags to keep in step, and `pub` on everything that crossed a
//! line that had no reason to exist.
//!
//! The boundaries that remain in this tree are the ones that carry a property the
//! compiler can check. `catcard-entropy` cannot reach the display because it does not
//! depend on it; `catcard-pin` cannot reach the wallet; `catcard-sign` stays outside
//! this crate because `catcard-upgrade` needs to verify a firmware signature and has no
//! business being able to parse a transaction. Those are worth a manifest each. Whether
//! Base58 lives beside BIP-32 is not.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod address;
pub mod bip32;
pub mod bip39;
pub mod chain;
pub mod encoding;
pub mod tx;
