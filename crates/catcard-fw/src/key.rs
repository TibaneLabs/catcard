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
//! # What it is not
//!
//! Not a *temporary seed* in stock's fuller sense -- words imported from a card or a QR
//! and used as if they were the master. That needs somewhere to hold the seed itself and
//! a vault to keep several; this holds a derivation *path* from a root that is already
//! there. The two meet later: a temporary seed would be another variant here, and every
//! consumer of [`in_force`] already asks the right question.
//!
//! Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §B3, §S1 [C]

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
}

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

/// Work in `source` from now on.
pub(crate) fn set(source: Source) {
    // SAFETY: as in `in_force`.
    unsafe { *core::ptr::addr_of_mut!(SOURCE) = source };
    // Everything cached belongs to the wallet that was in force a moment ago.
    crate::pubkeys::forget();
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
    }
}
