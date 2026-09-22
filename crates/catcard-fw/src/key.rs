//! Which wallet the device is working in.
//!
//! A Coldcard is not one wallet. The seed in the secure element is the root, and from it
//! the owner can reach others: a BIP-39 passphrase gives a different wallet from the same
//! words, and BIP-85 gives a whole separate seed derived from the same backup. Stock calls
//! the one in force the *current key*, and everything follows it -- the addresses the
//! explorer shows, the descriptors an export writes, the keys a PSBT is signed with.
//!
//! So it is held here rather than at the screens that set it. A screen that derived its
//! own idea of the wallet would be a screen that disagrees with the one next to it, and
//! the disagreement would show up as an export for a wallet the owner is not in.
//!
//! # Nothing here is stored
//!
//! The selection lives in RAM for the session and is gone on reboot, exactly as the
//! passphrase is. That is deliberate and matches stock: the device comes up in the root
//! wallet, which is the one whose backup the owner has.
//!
//! # A temporary seed is one of them
//!
//! [`Source::Temporary`] is a seed the owner brought in for this session -- today, the
//! result of joining Seed XOR parts -- used as if it were the master. Unlike the other
//! two it is not derived from the root at all, so the bytes have to live somewhere: they
//! are here, beside the selection, and [`crate::menu::seed_entropy`] returns them instead
//! of reading the secure element.
//!
//! What is still missing from stock's version is a *vault*: somewhere to keep several and
//! choose between them, and the option to make one permanent. This holds exactly one, and
//! forgets it on reboot like everything else here.
//!
//! Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §B3, §S1 [C]

use zeroize::Zeroize as _;

/// Where the wallet in force comes from.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum Source {
    /// The seed the secure element holds: the wallet whose words are backed up.
    Root,
    /// A BIP-85 child of it -- a separate seed, from the same backup, at this index.
    ///
    /// `words` is how many the child has: any length BIP-39 defines. A word count
    /// rather than a menu row's kind, because the menu offers five and `derive::Kind`
    /// can only say two -- and what identifies this wallet is the number in the
    /// derivation path, not which row was pressed to get here.
    Bip85 { words: u32, index: u32 },
    /// A seed from outside, in force for this session only.
    ///
    /// The entropy is in [`TEMP`] rather than in the variant: it is up to 32 bytes of
    /// wallet, which has no business being `Copy`, being compared with `==`, or being
    /// returned by value from [`in_force`] to whoever asks what wallet this is.
    Temporary,
}

/// The temporary seed's entropy, and how much of it is real.
///
/// Foreground only, single core, and wiped whenever the selection leaves it.
static mut TEMP: [u8; catcard_wallet::bip39::MAX_ENTROPY_LEN] =
    [0; catcard_wallet::bip39::MAX_ENTROPY_LEN];
static mut TEMP_LEN: usize = 0;

/// How the temporary seed was made -- `XOR`, `BIP85`, whatever the vault recorded.
///
/// The *kind* only. It is what the Seed Vault writes beside an entry, so an owner can
/// tell two keys apart without the parameters that would make the entry a second copy
/// of the key itself.
static mut TEMP_METHOD: heapless::String<16> = heapless::String::new();

/// The selection in force. Foreground only, single core.
static mut SOURCE: Source = Source::Root;

/// What the device is working in.
pub(crate) fn in_force() -> Source {
    // SAFETY: foreground only; the menu is the sole writer and holds no borrow across it.
    unsafe { *core::ptr::addr_of!(SOURCE) }
}

/// Whether this is the plain root wallet -- no derivation and no passphrase.
///
/// The passphrase counts: a passphrase wallet is as separate from the root as a BIP-85
/// child is, and an owner who has one set is not in the wallet they backed up.
pub(crate) fn is_root() -> bool {
    in_force() == Source::Root && !crate::passphrase::is_set()
}

/// The temporary seed's entropy, if one is in force.
pub(crate) fn temporary() -> Option<&'static [u8]> {
    if in_force() != Source::Temporary {
        return None;
    }
    // SAFETY: foreground only; the only writer is `set_temporary`, which holds no
    // borrow across the write, and the length is never longer than the array.
    unsafe {
        let len = *core::ptr::addr_of!(TEMP_LEN);
        let all: &'static [u8; catcard_wallet::bip39::MAX_ENTROPY_LEN] =
            &*core::ptr::addr_of!(TEMP);
        Some(&all[..len])
    }
}

/// Work from `entropy` as if it were the stored seed, for this session.
///
/// Refuses a length BIP-39 has no words for: everything downstream turns this back into
/// a phrase, and a seed that cannot be written down is not one anybody can keep.
pub(crate) fn set_temporary(entropy: &[u8], method: &str) -> bool {
    if catcard_wallet::bip39::words_for_entropy(entropy.len()).is_none() {
        return false;
    }
    // SAFETY: as in `temporary`.
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(TEMP);
        slot.zeroize();
        slot[..entropy.len()].copy_from_slice(entropy);
        *core::ptr::addr_of_mut!(TEMP_LEN) = entropy.len();
        let m = &mut *core::ptr::addr_of_mut!(TEMP_METHOD);
        m.clear();
        let _ = m.push_str(&method[..method.len().min(m.capacity())]);
    }
    set(Source::Temporary);
    true
}

/// How the wallet in force came to be, as the Seed Vault records it.
///
/// The mk3 has no settings store and so no vault; the string is still defined there
/// rather than cfg'd away, because what a key *is* does not depend on the panel.
#[cfg_attr(feature = "board-mk3", allow(dead_code))]
pub(crate) fn method() -> &'static str {
    match in_force() {
        // Nothing here made the stored seed, and nothing here can ask. It is also the
        // one wallet the vault has no reason to hold.
        Source::Root => "Master",
        Source::Bip85 { .. } => "BIP85",
        // SAFETY: as in `temporary`; the only writer is `set_temporary`.
        Source::Temporary => {
            let m: &'static heapless::String<16> = unsafe { &*core::ptr::addr_of!(TEMP_METHOD) };
            if m.is_empty() { "Imported" } else { m.as_str() }
        }
    }
}

/// Work in `source` from now on.
pub(crate) fn set(source: Source) {
    // Leaving the temporary seed is the only chance to wipe it: nothing else holds a
    // copy, and a seed that outlived its selection would be a wallet in force that no
    // screen names.
    if source != Source::Temporary {
        // SAFETY: as in `temporary`.
        unsafe {
            (*core::ptr::addr_of_mut!(TEMP)).zeroize();
            *core::ptr::addr_of_mut!(TEMP_LEN) = 0;
        }
    }
    // SAFETY: as in `in_force`.
    unsafe { *core::ptr::addr_of_mut!(SOURCE) = source };
    // Everything cached belongs to the wallet that was in force a moment ago -- the
    // derived keys, and the settings file, which is a different file per wallet.
    crate::pubkeys::forget();
    #[cfg(not(feature = "board-mk3"))]
    crate::settings::forget_key();
}

/// Go back to the root wallet, dropping any passphrase with it.
///
/// Both at once, because "return to the root" means the wallet whose words are written
/// down, and leaving a passphrase in force would land somewhere else that merely looks
/// like it on the way past.
pub(crate) fn to_root() {
    crate::passphrase::clear();
    set(Source::Root);
}

/// The word the status bar shows for what is in force.
///
/// One word, because the bar has room for one. It names the *strongest* thing about the
/// current key: a BIP-85 child with a passphrase on top is still, first, a child.
pub(crate) fn label() -> &'static str {
    match (in_force(), crate::passphrase::is_set()) {
        (Source::Root, false) => "MASTER",
        (Source::Root, true) => "PASSPHRASE",
        (Source::Bip85 { .. }, false) => "BIP85",
        (Source::Bip85 { .. }, true) => "BIP85+PP",
        (Source::Temporary, false) => "TEMP",
        (Source::Temporary, true) => "TEMP+PP",
    }
}
