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

/// Proof that the caller is doing private-key work where a host cannot time it.
///
/// Arithmetic on a private key must not be observable part-way through. On a device that
/// means interrupts masked for the whole operation: no USB reply, no scheduled task and no
/// interrupt handler runs inside it, so a host can see when the work starts and when it
/// ends, and nothing in between. What masking cannot hide is the total duration -- that is
/// what the operations being constant-time is for. The two are separate defences against
/// the same measurement, and neither replaces the other.
///
/// Every function in this crate that computes from a private key or a seed takes a
/// `&KeyWork`: BIP-39 entropy, phrase parsing and seed stretching; BIP-32 master and child
/// derivation, the public key and fingerprint of a private key, and the `xprv` encoding.
/// Functions on public data -- `ExtendedPubKey`, address encoding -- do not.
///
/// This crate is portable and cannot mask anything itself, so it cannot make one of these
/// safely either. The firmware makes one inside its critical section and lends it to a
/// closure, so the borrow cannot outlive the masked region. Host builds, where nothing can
/// interrupt the work, use [`KeyWork::host`].
///
/// Deliberately neither `Clone` nor `Copy`, so it cannot be duplicated out of the region
/// that made it.
pub struct KeyWork {
    _private: (),
}

impl KeyWork {
    /// A token for code that has masked interrupts itself.
    ///
    /// # Safety
    /// Interrupts must stay masked for as long as the returned value, and every borrow of
    /// it, is alive.
    pub const unsafe fn assume_masked() -> Self {
        Self { _private: () }
    }

    /// A token for host code and tests, where there are no interrupts to mask.
    #[cfg(any(test, feature = "std"))]
    pub const fn host() -> Self {
        Self { _private: () }
    }
}

pub mod address;
pub mod bip32;
pub mod bip39;
pub mod chain;
pub mod descriptor;
pub mod encoding;
pub mod psbt;
pub mod tx;
