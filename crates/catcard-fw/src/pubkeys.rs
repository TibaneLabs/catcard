//! Account public keys this session has already paid for.
//!
//! Reaching the seed is expensive and the cost is paid per screen: the bootloader's
//! `fetch_secret` runs the PIN key-stretch inside the secure element (about 1.6 s on an
//! mk4, and the firewall resets the CPU if an interrupt lands in it, so nothing can even
//! repaint across it), then BIP-39's 2048 PBKDF2 rounds are about a second more. Screens
//! that only ever show *public* data -- the address explorer, verify address, the wallet
//! export -- were paying all of it again on every entry.
//!
//! So an account key, once derived, is kept for the session. Below the account level
//! everything is unhardened, so the chain and the address index come out of it with no
//! private key anywhere near them.
//!
//! # Why the account level, and not the master
//!
//! A master xpub cannot derive any of this. BIP-44 paths are hardened for their first
//! three levels (`m/84h/0h/0h`), and hardened derivation needs the private key by
//! definition. Caching `m` would speed up nothing but the fingerprint. The account key is
//! the highest point that public derivation can descend from, which is why it is the unit
//! here.
//!
//! # Why not the `xpub` in the settings
//!
//! Stock caches `xfp`/`xpub` in the settings blob and we can read them, but nothing is
//! derived from them here. That blob is encrypted, not authenticated: a slot is
//! `AES256CTR(plaintext ‖ SHA256(plaintext))` -- an unkeyed hash inside the same malleable
//! stream -- and the counter, `pack('<4I',4,3,2,pos)`, is fixed per slot, so every rewrite
//! of a slot reuses the keystream and the zero padding hands over a large window of it.
//! Anyone able to write that flash region can substitute an xpub along with a digest that
//! verifies.
//!
//! Which would matter here more than anywhere else. The screens this serves exist to
//! answer "is this address really mine?", and an answer derived from flash rather than
//! from the seed is worthless in exactly the case it is asked: a person reads an address
//! off the device, hands it out, and receives coins only the forger can spend. What is
//! cached here was derived from the seed, in this session.
//!
//! Those keys are therefore **ignored outright** -- not read, and not compared against
//! what we derive. A comparison would have no correct response: the stored value is not
//! evidence, so a mismatch could only mean "ignore the stored value", which is what
//! ignoring it does already, without a warning that invites someone to doubt a correct
//! address. It would also cry wolf by design -- with a BIP-39 passphrase in force the
//! wallet legitimately differs from the one stock cached, so every passphrase wallet
//! would carry a permanent alarm -- and it would hand anyone who can write that flash a
//! way to raise one at will.
//!
//! Ignoring does mean *leaving alone*, not discarding: `store::set` edits in place, so
//! stock's keys keep their exact bytes through our writes and a device that goes back to
//! stock finds them intact.
//!
//! Source: hw-reference/settings-nvstore-format.md §2-3 [C]
//!
//! # Lifetime
//!
//! Until the device reboots, or the BIP-39 passphrase changes. The passphrase is part of
//! the seed, so a key derived under one is a *different wallet's* key under another --
//! [`crate::passphrase::set`] and [`crate::passphrase::clear`] call [`forget`] for that
//! reason, and forgetting to would make this screen confidently show the wrong wallet's
//! addresses. Secure Logout needs no such call: it wipes all of SRAM and reboots.
//!
//! An extended *public* key is not secret, but it is not nothing either -- it links every
//! address of that account -- so this is a deliberate trade of a little residency for not
//! re-deriving from the seed five times in a row.

use catcard_wallet::address::AddressKind;
use catcard_wallet::bip32::{ChildNumber, ExtendedPubKey};

use crate::menu;
use crate::ui::Ui;

/// Account keys held at once.
///
/// Four address types across two accounts, which is more than a person walks in one
/// sitting. Past this the oldest is dropped: the cost of a miss is the derivation that
/// would have happened anyway.
const MAX: usize = 8;

/// One account key and the path it sits at: `m/{purpose}h/{coin}h/{account}h`.
#[derive(Clone, Copy)]
struct Cached {
    purpose: u32,
    /// The SLIP-44 coin type -- 0 for Bitcoin. Part of the key: Litecoin's account 0
    /// under purpose 84 is not Bitcoin's.
    coin: u32,
    account: u32,
    key: ExtendedPubKey,
}

/// Foreground only, single core -- as with [`crate::passphrase`].
static mut ACCOUNTS: heapless::Vec<Cached, MAX> = heapless::Vec::new();
/// This wallet's master fingerprint, which costs the same unlock to learn.
static mut FINGERPRINT: Option<[u8; 4]> = None;

/// Drop everything derived for the wallet that was in force.
///
/// Called when the passphrase changes: what is cached describes the old wallet, and
/// showing it under the new one would be a lie the owner has no way to catch.
pub(crate) fn forget() {
    // SAFETY: foreground only; the menu is the sole writer and holds no borrow across it.
    unsafe {
        (*core::ptr::addr_of_mut!(ACCOUNTS)).clear();
        *core::ptr::addr_of_mut!(FINGERPRINT) = None;
    }
}

/// The cached account key at `m/{purpose}h/{coin}h/{account}h`, if this session has it.
fn cached(purpose: u32, coin: u32, account: u32) -> Option<ExtendedPubKey> {
    // SAFETY: as in `forget`.
    let all = unsafe { &*core::ptr::addr_of!(ACCOUNTS) };
    all.iter()
        .find(|c| (c.purpose, c.coin, c.account) == (purpose, coin, account))
        .map(|c| c.key)
}

/// Remember an account key, evicting the oldest if there is no room.
fn remember(purpose: u32, coin: u32, account: u32, key: ExtendedPubKey) {
    // SAFETY: as in `forget`.
    let all = unsafe { &mut *core::ptr::addr_of_mut!(ACCOUNTS) };
    if all.is_full() {
        all.remove(0);
    }
    let _ = all.push(Cached {
        purpose,
        coin,
        account,
        key,
    });
}

/// The Bitcoin account key at `m/{purpose}h/{coin}h/{account}h` for `kind`, from this
/// session or the seed. The coin type follows the network in force -- 0 on mainnet, 1 on
/// testnet and regtest -- so testnet mode moves the whole account. See [`account_key_at`].
pub(crate) fn account_key(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    head: &str,
    kind: AddressKind,
    account: u32,
) -> Option<ExtendedPubKey> {
    let coin = crate::prefs::network().coin_type();
    account_key_at(gate, login, ui, head, kind.bip44_purpose(), coin, account)
}

/// The account key at `m/{purpose}h/{coin}h/{account}h`, from this session or the seed --
/// any secp256k1 chain, by its SLIP-44 coin type.
///
/// A hit costs nothing. A miss unlocks the seed, which shows its own screens and may be
/// refused -- `None` once the owner has been told why.
pub(crate) fn account_key_at(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    head: &str,
    purpose: u32,
    coin: u32,
    account: u32,
) -> Option<ExtendedPubKey> {
    if let Some(key) = cached(purpose, coin, account) {
        return Some(key);
    }

    let master = menu::unlock_master(gate, login, ui, head)?;
    // The fingerprint comes free with the unlock; taking it now saves a later one.
    let fp = crate::keywork::run(|kw| master.fingerprint(kw));
    // SAFETY: as in `forget`.
    unsafe { *core::ptr::addr_of_mut!(FINGERPRINT) = Some(fp) };

    let steps = [
        ChildNumber::hardened(purpose).ok()?,
        ChildNumber::hardened(coin).ok()?,
        ChildNumber::hardened(account).ok()?,
    ];
    let mut busy = menu::Working::new(ui.panel, head, "deriving account");
    let key = menu::public_at(&master, &steps, &mut busy, ui.panel);
    drop(master);
    let key = key?;
    remember(purpose, coin, account, key);
    Some(key)
}

/// Record the fingerprint of the wallet now in force.
///
/// For a screen that derived one as part of its own work, so the status bar gets it
/// without a second stretch -- and for putting back the one that was in force when a
/// passphrase is typed and then declined.
#[cfg(feature = "board-q1")]
pub(crate) fn note_fingerprint(fp: Option<[u8; 4]>) {
    // SAFETY: foreground only; the write finishes within this statement.
    unsafe { *core::ptr::addr_of_mut!(FINGERPRINT) = fp };
}

/// Derive the fingerprint now, if this session does not have it, so the status bar can
/// name the wallet from the moment the menu appears.
///
/// Quiet by construction: no dialogs, no key waits. A device with no wallet, or one
/// holding a secret this build cannot read, simply leaves the bar's fingerprint blank --
/// a boot that stopped to complain about something the owner never asked for would be
/// worse than a blank space.
///
/// Costs one seed stretch, once, at the point the owner has just entered their PIN and
/// is waiting for the menu anyway. Everything derived from it afterwards is free.
#[cfg(feature = "board-q1")]
pub(crate) fn warm_fingerprint(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    panel: &mut crate::display::Panel,
) {
    if known_fingerprint().is_some() {
        return;
    }
    match menu::master_quietly(gate, login, panel, "Wallet") {
        Ok(master) => {
            let fp = crate::keywork::run(|kw| master.fingerprint(kw));
            drop(master);
            note_fingerprint(Some(fp));
            crate::catlog!("wallet: fingerprint derived for the status bar");
        }
        Err(why) => crate::catlog!("wallet: no fingerprint for the status bar: {}", why),
    }
}

/// This wallet's master fingerprint **only if this session already knows it**.
///
/// Never unlocks. For the status bar, which is painted on every frame: a bar that could
/// stretch a seed to decorate itself would make the device unusable, and an empty space
/// is the honest answer until a screen that needed the seed anyway has paid for it.
///
/// The Q1 paints it in the status bar; the boards without one name the wallet in the
/// menu's own header row instead, and want the same "only if free" rule there.
pub(crate) fn known_fingerprint() -> Option<[u8; 4]> {
    // SAFETY: foreground only; the read finishes within this statement.
    unsafe { *core::ptr::addr_of!(FINGERPRINT) }
}

/// This wallet's master fingerprint, from this session or the seed.
///
/// The same unlock that derives an account key learns this, so a screen that has already
/// shown an address pays nothing for it.
///
/// Only the multisig import asks.
pub(crate) fn fingerprint(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    head: &str,
) -> Option<[u8; 4]> {
    // SAFETY: as in `forget`.
    if let Some(fp) = unsafe { *core::ptr::addr_of!(FINGERPRINT) } {
        return Some(fp);
    }
    let master = menu::unlock_master(gate, login, ui, head)?;
    let fp = crate::keywork::run(|kw| master.fingerprint(kw));
    drop(master);
    // SAFETY: as in `forget`.
    unsafe { *core::ptr::addr_of_mut!(FINGERPRINT) = Some(fp) };
    Some(fp)
}
