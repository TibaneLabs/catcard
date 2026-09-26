//! Device-bound, whole-card SD encryption: unlock state for the session, and the
//! Encrypt / Unlock / Remove operations.
//!
//! # What this does
//!
//! A card can be encrypted in place with AES-128-XTS ([`catcard_sd::SectorCrypto`]), every
//! 512-byte sector enciphered under a key derived from a password (or the wallet's BIP-39
//! passphrase) with PBKDF2-HMAC-SHA256. A computer cannot read the card; this device
//! decrypts it transparently once it is unlocked, because both the filesystem path
//! ([`catcard_sd::Sectors`]) and the USB Drive path ([`crate::msc_drive`]) bottom out in
//! [`catcard_sd::read_block`]/[`catcard_sd::write_block`], which honour
//! [`catcard_sd::Card::crypto`]. The PSRAM Virtual Disk uses a different block path and is
//! untouched by any of this.
//!
//! # Device-bound
//!
//! The per-card parameters -- salt, iteration count, verifier, keyed by the card's serial
//! ([`catcard_sd::Card::serial`]) -- live in this device's settings on internal flash
//! ([`catcard_settings::ccenc`]). The key is never stored. So an encrypted card decrypts
//! only on the device that encrypted it, and only for someone who knows the password.
//!
//! # Session key
//!
//! The derived key lives in RAM only while unlocked, in [`UNLOCKED`], wiped when it is
//! replaced or when [`logout`] runs. Each time a card is mounted, [`apply_to`] injects the
//! session key into the fresh [`catcard_sd::Card`] if it is the unlocked card.
//!
//! mk4 / mk5 / Q1 only: the mk3 has no settings store to hold the parameters, so the whole
//! module is compiled out there (see `main.rs`).

use catcard_callgate::Callgate;
use catcard_pin::Login;
use catcard_settings::ccenc::{self, DerivedKey, Params};
use catcard_ui::textentry::MAX_LEN;
use zeroize::Zeroizing;

use catcard_hal::sdmmc::Sdmmc;
use catcard_sd::{BLOCK_LEN, Card, SectorCrypto};

use crate::menu;
use crate::ui::Ui;

const HEAD: &str = "SD encryption";

/// The card unlocked for this session, if any: its serial and the derived XTS key.
struct Unlocked {
    serial: u32,
    key: DerivedKey,
}

/// The session's unlocked card. `DerivedKey` is `ZeroizeOnDrop`, so replacing or clearing
/// this wipes the key it held.
static mut UNLOCKED: Option<Unlocked> = None;

/// Forget any session key, wiping it. Called at logout, and whenever encryption is removed.
pub(crate) fn logout() {
    // SAFETY: foreground only, single core; the write completes within this statement, and
    // dropping the previous `Unlocked` wipes its key.
    unsafe { *core::ptr::addr_of_mut!(UNLOCKED) = None };
}

/// If `card` is the card unlocked this session, turn on transparent decryption for it.
///
/// Called at every mount ([`crate::menu::mount_card`], the USB Drive, the signing paths),
/// so that once a card is unlocked, all later access to it decrypts without the caller
/// knowing encryption is in play. A no-op for a plaintext card or a different card.
pub(crate) fn apply_to(card: &mut Card) {
    let serial = card.serial();
    // SAFETY: foreground only, single core; mounts are serialised by the menu/USB task.
    let session = unsafe { &*core::ptr::addr_of!(UNLOCKED) };
    let Some(s) = session else { return };
    if s.serial != serial {
        return;
    }
    let mut key = Zeroizing::new([0u8; ccenc::XTS_KEY_LEN]);
    key[..16].copy_from_slice(&s.key.k1);
    key[16..].copy_from_slice(&s.key.k2);
    if card.unlock(&key).is_err() {
        // Equal halves -- cannot happen for a PBKDF2-derived key, but never half-arm.
        crate::catlog!("ccenc: session key rejected for card {:08x}", serial);
    }
}

/// Install the session key for `serial`, replacing (and wiping) any previous one.
fn install(serial: u32, key: DerivedKey) {
    // SAFETY: foreground only; the assignment drops the old `Unlocked`, wiping its key.
    unsafe { *core::ptr::addr_of_mut!(UNLOCKED) = Some(Unlocked { serial, key }) };
}

/// Whether `serial` is the card currently unlocked.
fn is_unlocked(serial: u32) -> bool {
    // SAFETY: foreground only, single core.
    let session = unsafe { &*core::ptr::addr_of!(UNLOCKED) };
    session.as_ref().is_some_and(|s| s.serial == serial)
}

/// The Encrypt / Unlock / Remove menu.
pub(crate) fn screen(gate: &Callgate, login: &mut Login, ui: &mut Ui<'_>) {
    // Bring the card up first: a serial is needed for everything below, and a locked or
    // encrypted card still identifies (only its *data* is ciphertext), so init succeeds.
    // SAFETY: nothing else has claimed SDMMC1 or its pins; this screen is its only user and
    // the menu waits for it to return before it can be chosen again.
    let mut dev = match unsafe { Sdmmc::init(&catcard_board::BOARD) } {
        Ok(d) => d,
        Err(_) => return say(ui, "no SD controller"),
    };
    let card = match catcard_sd::init(&mut dev) {
        Ok(c) => c,
        Err(catcard_sd::Error::NoCard) => return say(ui, "no card in slot"),
        Err(e) => {
            crate::catlog!("sd: card would not start: {:?}", e);
            return say(ui, "card would not start");
        }
    };
    let serial = card.serial();

    // Does this device already hold parameters for this card?
    let params = match read_params(gate, login, ui.panel, serial) {
        Ok(p) => p,
        Err(why) => return say(ui, why),
    };
    let encrypted_here = params.is_some();

    // Offer only what makes sense: encrypt a card with no parameters, or unlock/remove one
    // that has them.
    let mut labels: heapless::Vec<&str, 3> = heapless::Vec::new();
    let mut acts: heapless::Vec<u8, 3> = heapless::Vec::new();
    const ENCRYPT: u8 = 0;
    const UNLOCK: u8 = 1;
    const REMOVE: u8 = 2;
    if encrypted_here {
        let _ = labels.push("Unlock card");
        let _ = acts.push(UNLOCK);
        let _ = labels.push("Remove encryption");
        let _ = acts.push(REMOVE);
    } else {
        let _ = labels.push("Encrypt this card");
        let _ = acts.push(ENCRYPT);
    }

    let note = if encrypted_here {
        "encrypted on this device"
    } else if is_unlocked(serial) {
        "unlocked this session"
    } else {
        "not encrypted here"
    };
    let Some(pick) = menu::choose(ui, HEAD, note, &labels) else {
        return;
    };

    match acts[pick] {
        ENCRYPT => do_encrypt(gate, login, ui, &mut dev, card, serial),
        UNLOCK => do_unlock(ui, serial, params),
        REMOVE => do_remove(gate, login, ui, &mut dev, card, serial, params),
        _ => {}
    }
}

/// Encrypt the whole card in place.
fn do_encrypt(
    gate: &Callgate,
    login: &mut Login,
    ui: &mut Ui<'_>,
    dev: &mut Sdmmc,
    mut card: Card,
    serial: u32,
) {
    menu::ask(
        ui.panel,
        "Encrypt SD card?",
        "locks card to this device",
        "computers can't read it",
    );
    if !menu::confirmed(ui) {
        return;
    }
    // Destructive of readability elsewhere, and slow: a second, plainer question.
    menu::ask(
        ui.panel,
        "Rewrites every sector",
        "do not remove the card",
        "this can take a while",
    );
    if !menu::confirmed(ui) {
        return;
    }

    let Some(password) = get_password(ui, "Encryption password") else {
        return;
    };

    // A fresh per-card salt from the UI DRBG. A salt is public, not key material, so this
    // source is right for it; the key's strength is the password and the iteration count.
    let mut salt = [0u8; ccenc::SALT_LEN];
    if ui.drbg.generate(&mut salt).is_err() {
        return say(ui, "no randomness for a salt");
    }

    menu::blocking_screen(ui.panel, HEAD, "deriving key");
    let (params, key) =
        match ccenc::new_params(password.as_bytes(), salt, ccenc::DEFAULT_ITERATIONS) {
            Ok(pair) => pair,
            Err(_) => return say(ui, "could not derive a key"),
        };

    // The cipher that rewrites the card, built before the parameters are saved so a save
    // that half-works cannot leave a card claimed-encrypted with no way to rewrite it.
    let sc = match SectorCrypto::from_halves(&key.k1, &key.k2) {
        Ok(sc) => sc,
        Err(_) => return say(ui, "bad derived key"),
    };

    // Record the parameters first: if the rewrite is interrupted the card is corrupt either
    // way, but at least the key can be re-derived to finish or investigate.
    if let Err(why) = save_params(gate, login, ui, serial, Some(&params)) {
        return say(ui, why);
    }

    // Rewrite every sector: plaintext in, ciphertext out. `card` is plaintext-mode
    // (`crypto == None`), so the raw bytes are read and the transform is explicit.
    card.relock();
    if let Err(why) = rewrite(dev, &card, &sc, Mode::Encrypt, ui) {
        return say(ui, why);
    }

    // Unlock it for the rest of the session so it is immediately usable.
    install(serial, key);
    crate::catlog!(
        "ccenc: card {:08x} encrypted, {} sectors",
        serial,
        card.blocks
    );
    say(ui, "encrypted and unlocked");
}

/// Unlock an encrypted card for the session.
fn do_unlock(ui: &mut Ui<'_>, serial: u32, params: Option<Params>) {
    let Some(params) = params else {
        return say(ui, "not encrypted on this device");
    };
    let Some(password) = get_password(ui, "Unlock password") else {
        return;
    };
    menu::blocking_screen(ui.panel, HEAD, "checking password");
    match ccenc::verify(&params, password.as_bytes()) {
        Some(key) => {
            install(serial, key);
            crate::catlog!("ccenc: card {:08x} unlocked", serial);
            say(ui, "unlocked for this session");
        }
        None => say(ui, "wrong password"),
    }
}

/// Remove encryption: rewrite the card back to plaintext and forget its parameters.
fn do_remove(
    gate: &Callgate,
    login: &mut Login,
    ui: &mut Ui<'_>,
    dev: &mut Sdmmc,
    mut card: Card,
    serial: u32,
    params: Option<Params>,
) {
    let Some(params) = params else {
        return say(ui, "not encrypted on this device");
    };

    // The key must be in hand to turn ciphertext back into plaintext. Prefer the session
    // key; otherwise ask for the password and verify it.
    let key = if let Some(k) = session_key(serial) {
        k
    } else {
        let Some(password) = get_password(ui, "Password to remove") else {
            return;
        };
        menu::blocking_screen(ui.panel, HEAD, "checking password");
        match ccenc::verify(&params, password.as_bytes()) {
            Some(k) => k,
            None => return say(ui, "wrong password"),
        }
    };

    menu::ask(
        ui.panel,
        "Remove encryption?",
        "rewrites every sector",
        "do not remove the card",
    );
    if !menu::confirmed(ui) {
        return;
    }

    let sc = match SectorCrypto::from_halves(&key.k1, &key.k2) {
        Ok(sc) => sc,
        Err(_) => return say(ui, "bad derived key"),
    };

    // Ciphertext in (raw read), plaintext out (raw write).
    card.relock();
    if let Err(why) = rewrite(dev, &card, &sc, Mode::Decrypt, ui) {
        return say(ui, why);
    }

    // Only after the card is plaintext again: drop the parameters and the session key.
    if let Err(why) = save_params(gate, login, ui, serial, None) {
        // The card is already plaintext; the stale parameters are harmless but confusing.
        crate::catlog!("ccenc: card rewritten but parameters not cleared: {}", why);
    }
    logout();
    crate::catlog!(
        "ccenc: card {:08x} decrypted and parameters removed",
        serial
    );
    say(ui, "encryption removed");
}

/// The session key for `serial`, cloned out for a rewrite. `None` if not unlocked.
fn session_key(serial: u32) -> Option<DerivedKey> {
    // SAFETY: foreground only, single core.
    let session = unsafe { &*core::ptr::addr_of!(UNLOCKED) };
    session.as_ref().filter(|s| s.serial == serial).map(|s| {
        // A fresh holder so the rewrite does not borrow the static; both wipe on drop.
        let mut k = DerivedKey {
            k1: [0u8; 16],
            k2: [0u8; 16],
        };
        k.k1.copy_from_slice(&s.key.k1);
        k.k2.copy_from_slice(&s.key.k2);
        k
    })
}

/// Which way [`rewrite`] transforms each sector.
#[derive(Copy, Clone)]
enum Mode {
    /// Plaintext on the card now, ciphertext after.
    Encrypt,
    /// Ciphertext on the card now, plaintext after.
    Decrypt,
}

/// How often the rewrite redraws its progress and services USB: every this many sectors
/// (2048 × 512 B = 1 MiB), so a long rewrite still answers the host and shows it is alive.
const PROGRESS_EVERY: u32 = 2048;

/// Rewrite every sector of `card` through `sc`. `card` must be plaintext-mode so the reads
/// and writes here are raw; the transform is applied explicitly per the [`Mode`].
///
/// Bounded by the card's block count -- a finite, known loop, never an open wait.
fn rewrite(
    dev: &mut Sdmmc,
    card: &Card,
    sc: &SectorCrypto,
    mode: Mode,
    ui: &mut Ui<'_>,
) -> Result<(), &'static str> {
    use core::fmt::Write as _;

    let total = card.blocks;
    let mut buf = [0u8; BLOCK_LEN];
    for lba in 0..total {
        catcard_sd::read_block(dev, card, lba, &mut buf).map_err(|_| "card read failed")?;
        match mode {
            Mode::Encrypt => sc.encrypt_sector(lba, &mut buf),
            Mode::Decrypt => sc.decrypt_sector(lba, &mut buf),
        }
        catcard_sd::write_block(dev, card, lba, &buf).map_err(|_| "card write failed")?;

        if lba.is_multiple_of(PROGRESS_EVERY) {
            let pct = ((lba as u64) * 100 / (total.max(1) as u64)) as u32;
            let mut note: heapless::String<24> = heapless::String::new();
            let _ = write!(note, "{pct}% of {} MiB", card.blocks / 2048);
            menu::message(ui.panel, HEAD, note.as_str(), "do not remove card");
            // Keep the host serviced through a long rewrite; nothing here reads its reply.
            let _ = crate::usbtask::pump();
        }
    }
    Ok(())
}

/// Choose a password source and return the password, wiped on drop.
///
/// Either the BIP-39 passphrase in force (offered only when one is set), or a
/// separately-typed password. The returned string is `Zeroizing`, and a typed [`Entry`] is
/// cleared here, so the plaintext password does not outlive this call's result.
///
/// [`Entry`]: catcard_ui::textentry::Entry
fn get_password(ui: &mut Ui<'_>, prompt: &str) -> Option<Zeroizing<heapless::String<MAX_LEN>>> {
    // The passphrase path is available through the module accessor. [C]
    let use_passphrase = if crate::passphrase::is_set() {
        match menu::choose(
            ui,
            HEAD,
            "password source",
            &["Wallet passphrase", "Enter a password"],
        ) {
            Some(0) => true,
            Some(_) => false,
            None => return None,
        }
    } else {
        false
    };

    let mut out: Zeroizing<heapless::String<MAX_LEN>> = Zeroizing::new(heapless::String::new());
    if use_passphrase {
        // The in-force passphrase, copied out of its own module's store.
        if out.push_str(crate::passphrase::active()).is_err() {
            return None;
        }
        if out.is_empty() {
            say(ui, "no passphrase in force");
            return None;
        }
    } else {
        let mut entry = crate::passphrase::read(ui, prompt)?;
        let ok = !entry.is_empty() && out.push_str(entry.as_str()).is_ok();
        entry.clear();
        if !ok {
            say(ui, "password cannot be empty");
            return None;
        }
    }
    Some(out)
}

/// Read this card's stored parameters, if any. Read-only: it never writes the settings.
fn read_params(
    gate: &Callgate,
    login: &mut Login,
    panel: &mut crate::display::Panel,
    serial: u32,
) -> Result<Option<Params>, &'static str> {
    use catcard_settings::json::Doc;
    use catcard_settings::store::{self, SCRATCH};

    let key = crate::settings::wallet_key(gate, login, panel, HEAD)?;
    let Some(mut held) = crate::heap::take(SCRATCH) else {
        return Err("not enough memory");
    };
    let buf = held.bytes();
    // SAFETY: the region is mapped and readable; nothing is written through this.
    let mut files =
        unsafe { crate::settings::Files::mount_read_only() }.map_err(|_| "no settings store")?;
    let n = store::read(&mut files, &key, buf).unwrap_or(0);
    let doc = Doc::parse(&buf[..n]).unwrap_or_default();
    ccenc::get(&doc, serial).map_err(|_| "stored parameters are corrupt")
}

/// Save (or, with `params == None`, remove) this card's parameters in the settings.
fn save_params(
    gate: &Callgate,
    login: &mut Login,
    ui: &mut Ui<'_>,
    serial: u32,
    params: Option<&Params>,
) -> Result<(), &'static str> {
    use catcard_settings::json::Doc;
    use catcard_settings::store::{self, SCRATCH};

    menu::blocking_screen(ui.panel, HEAD, "saving parameters");
    let key = crate::settings::wallet_key(gate, login, ui.panel, HEAD)?;

    let (Some(mut doc_held), Some(mut map_held), Some(mut seal_held)) = (
        crate::heap::take(SCRATCH),
        crate::heap::take(SCRATCH),
        crate::heap::take(SCRATCH),
    ) else {
        return Err("not enough memory");
    };
    let doc_buf = doc_held.bytes();
    let map_buf = map_held.bytes();

    // Render the new map into `map_buf`. The existing map borrows `doc_buf`; that borrow
    // ends before `save_wallet` reuses `doc_buf` as its own scratch.
    let len = {
        // SAFETY: the region is mapped and readable; nothing is written through this.
        let mut files = unsafe { crate::settings::Files::mount_read_only() }
            .map_err(|_| "no settings store")?;
        let n = store::read(&mut files, &key, doc_buf).unwrap_or(0);
        let existing = Doc::parse(&doc_buf[..n]).unwrap_or_default();
        let current = existing.get(ccenc::KEY);
        let r = match params {
            Some(p) => ccenc::with_set(current, serial, p, map_buf),
            None => ccenc::without(current, serial, map_buf),
        };
        r.map_err(|e| match e {
            ccenc::Error::TooMany => "too many cards stored",
            _ => "could not update parameters",
        })?
    };

    let text = core::str::from_utf8(&map_buf[..len]).map_err(|_| "not text")?;
    crate::settings::save_wallet(
        gate,
        login,
        ui,
        HEAD,
        (ccenc::KEY, text),
        doc_buf,
        seal_held.bytes(),
    )
}

/// A one-line message screen that waits for a key.
fn say(ui: &mut Ui<'_>, what: &str) {
    menu::message(ui.panel, HEAD, what, "any key to go back");
    menu::wait_for_any_key(ui);
}
