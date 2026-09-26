//! Import a TAPSIGNER card backup: as this device's seed, or for this session only.
//!
//! A TAPSIGNER hands its owner an encrypted `.aes` backup and a one-time **backup key**.
//! This reads the file off the card, asks for the key, and -- if the key is right --
//! recovers the BIP-32 master inside it. The decrypt and the parse are
//! [`catcard_backup::tapsigner`]; what is here is the screens around them.
//!
//! # Two outcomes
//!
//! From a blank device's Import menu the master is offered two ways, as stock offers
//! it under Import Existing and again under Temporary Seed: **stored** as the wallet,
//! or **in force for this session** -- a temporary key like one typed in under Derive
//! -> Import key, gone at reboot unless it is locked down. From Derive it is only ever
//! the second.
//! Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §B1 "Tapsigner Backup", §S1 [C]
//!
//! # Storing replaces the wallet, so it warns first
//!
//! Storing a seed over an existing one is destructive and irreversible. Like every other
//! import, this asks before it touches the slot, and on a device that already holds a
//! wallet that warning is the only thing standing between a mistyped menu and a lost key.
//! The session outcome touches the slot not at all, so it does not warn.
//!
//! # The decrypt is private-key work
//!
//! The decrypted backup is a private key, so the whole decrypt-and-parse runs inside
//! [`crate::keywork::run`] -- interrupts masked, nothing timing it -- and every buffer
//! that held the plaintext is wiped on the way out.

use catcard_backup::tapsigner;
use catcard_callgate::Callgate;
use catcard_callgate::pin::encode_xprv;
use catcard_wallet::bip32::ExtendedPrivKey;
use zeroize::{Zeroize as _, Zeroizing};

use crate::menu;
use crate::ui::Ui;

const HEAD: &str = "TAPSIGNER";

/// Room for the encrypted file and, separately, its plaintext. A TAPSIGNER backup is a
/// few hundred bytes; a whole kilobyte is comfortable headroom, and a file larger than it
/// is refused by the card reader rather than read in part.
const BUF: usize = 1024;

/// A buffer that wipes itself, so every path out goes through one `Drop` -- the file and
/// its decrypted plaintext both pass through here and both are key material.
struct Scratch([u8; BUF]);

impl Drop for Scratch {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Scratch {
    fn new() -> Self {
        Scratch([0u8; BUF])
    }
}

/// The node a backup held: the chain code, then the key. Wiped when dropped.
type Node = Zeroizing<([u8; 32], [u8; 32])>;

/// Import -> TAPSIGNER: read a backup off the card, decrypt it, and store its master --
/// or, if the owner chooses, work in it for this session only.
pub(crate) fn import(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    let Some(node) = decrypt(ui) else {
        return;
    };
    let Some(row) = menu::pick_row(
        ui,
        HEAD,
        "use the backup",
        &["Store as the wallet", "This session only"],
    ) else {
        say(ui, "Import cancelled", "nothing was stored");
        return;
    };
    match row {
        0 => store(gate, login, ui, &node),
        _ => {
            let was = crate::key::in_force();
            if load_session(ui, &node) {
                menu::announce_key(gate, login, ui, HEAD, was);
            }
        }
    }
}

/// Derive -> Import key -> TAPSIGNER: the same backup, in force for this session and
/// never stored. Returns whether a key is now in force; the Derive menu names it.
pub(crate) fn import_temporary(ui: &mut Ui<'_>) -> bool {
    let Some(node) = decrypt(ui) else {
        return false;
    };
    load_session(ui, &node)
}

/// Write the master to the secure element, after the destructive-case warning.
fn store(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>, node: &Node) {
    // The destructive case, warned once -- as `import_seed` and `restore` do.
    if crate::key::stored_wallet(login) {
        menu::ask(
            ui.panel,
            "Wallet exists",
            "an import DESTROYS",
            "the one stored now",
        );
        if !menu::confirmed(ui) {
            return say(ui, "Import cancelled", "nothing was stored");
        }
    }
    // Packed inside the masked region: the stash is the private key in another spelling.
    let (chain_code, key) = &**node;
    let mut secret = crate::keywork::run(|_kw| encode_xprv(chain_code, key));
    let res = crate::backup::store_secret(gate, login, ui, &secret);
    secret.zeroize();
    match res {
        Ok(()) => {
            crate::key::to_root();
            crate::catlog!("tapsigner: imported master");
            menu::message(ui.panel, "Wallet imported", "from the TAPSIGNER", "backup");
        }
        Err(why) => menu::message(ui.panel, "Not imported", why, "any key to go back"),
    }
    menu::wait_for_any_key(ui);
}

/// Put the master in force for this session. True if it is; a key outside the curve
/// order is refused and said.
fn load_session(ui: &mut Ui<'_>, node: &Node) -> bool {
    let (chain_code, key) = &**node;
    if !crate::key::set_temporary_xprv(chain_code, key, "TAPSIGNER") {
        say(ui, "Cannot use it", "that key is not usable");
        return false;
    }
    crate::catlog!("tapsigner: master in force for this session");
    true
}

/// Pick the `.aes` file, take the backup key, and decrypt: the node inside, if the key
/// opened it. Every refusal is said here; `None` means the owner has already been told.
fn decrypt(ui: &mut Ui<'_>) -> Option<Node> {
    let path = menu::browse_sd(ui, "Pick .aes backup", Some("aes"), menu::Browse::File)?;

    let mut cipher = Scratch::new();
    menu::card_wait(ui.panel, HEAD, "reading the card");
    let len = match crate::signtx::read_card_file(&path, &mut cipher.0) {
        Ok(n) => n,
        Err(why) => {
            say(ui, "Cannot read", why);
            return None;
        }
    };

    menu::message(
        ui.panel,
        "Backup key",
        "enter the 32-hex key,",
        "then y to finish",
    );
    menu::wait_for_any_key(ui);
    let Some(entry) = crate::passphrase::read(ui, "Backup key") else {
        say(ui, "Import cancelled", "nothing was changed");
        return None;
    };

    let mut key = [0u8; tapsigner::KEY_LEN];
    if let Err(e) = tapsigner::parse_key(entry.as_str(), &mut key) {
        key.zeroize();
        say(ui, "Bad backup key", describe(e));
        return None;
    }

    // Decrypt and parse inside the masked region: the plaintext and the parsed node are
    // private-key material, computed where a host cannot time them.
    let mut plain = Scratch::new();
    let node = crate::keywork::run(|kw| {
        tapsigner::decrypt(&cipher.0[..len], &key, &mut plain.0)
            .ok()
            .and_then(|xprv| ExtendedPrivKey::from_base58(xprv.trim(), kw).ok())
            .map(|node| Zeroizing::new((node.chain_code, *node.secret_bytes())))
    });
    key.zeroize();
    // `cipher` and `plain` wipe themselves on drop.

    if node.is_none() {
        say(ui, "Cannot import", "wrong key, or not a TAPSIGNER backup");
    }
    node
}

fn say(ui: &mut Ui<'_>, head: &str, why: &str) {
    menu::message(ui.panel, head, why, "any key to go back");
    menu::wait_for_any_key(ui);
}

/// The few words a screen has for a key-entry error.
fn describe(e: catcard_backup::Error) -> &'static str {
    use catcard_backup::Error as E;
    match e {
        E::BadBackupKey => "it must be 32 hex characters",
        E::NotHex => "only 0-9 and a-f are hex",
        _ => "that key cannot be used",
    }
}
