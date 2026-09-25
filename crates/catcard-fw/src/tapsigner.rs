//! Import a TAPSIGNER card backup as this device's seed.
//!
//! A TAPSIGNER hands its owner an encrypted `.aes` backup and a one-time **backup key**.
//! This reads the file off the card, asks for the key, and -- if the key is right --
//! recovers the BIP-32 master inside it and stores it as the wallet. The decrypt and the
//! parse are [`catcard_backup::tapsigner`]; what is here is the screens around them.
//!
//! # It replaces the wallet, so it warns first
//!
//! Storing a seed over an existing one is destructive and irreversible. Like every other
//! import, this asks before it touches the slot, and on a device that already holds a
//! wallet that warning is the only thing standing between a mistyped menu and a lost key.
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
use zeroize::Zeroize as _;

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

/// Read a TAPSIGNER `.aes` backup off the card, decrypt it, and store the master it holds.
pub(crate) fn import(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    // The destructive case, warned once -- as `import_seed` and `restore` do.
    if crate::key::stored_wallet(login) {
        menu::ask(
            ui.panel,
            "Wallet exists",
            "an import DESTROYS",
            "the one stored now",
        );
        if !menu::confirmed(ui) {
            return;
        }
    }

    let Some(path) = menu::browse_sd(ui, "Pick .aes backup", Some("aes"), menu::Browse::File)
    else {
        return;
    };

    let mut cipher = Scratch::new();
    menu::card_wait(ui.panel, HEAD, "reading the card");
    let len = match crate::signtx::read_card_file(&path, &mut cipher.0) {
        Ok(n) => n,
        Err(why) => return say(ui, "Cannot read", why),
    };

    menu::message(
        ui.panel,
        "Backup key",
        "enter the 32-hex key,",
        "then y to finish",
    );
    menu::wait_for_any_key(ui);
    let Some(entry) = crate::passphrase::read(ui, "Backup key") else {
        return say(ui, "Import cancelled", "nothing was stored");
    };

    let mut key = [0u8; tapsigner::KEY_LEN];
    if let Err(e) = tapsigner::parse_key(entry.as_str(), &mut key) {
        key.zeroize();
        return say(ui, "Bad backup key", describe(e));
    }

    // Decrypt and parse inside the masked region: the plaintext, the parsed node and the
    // packed stash are all private-key material, computed where a host cannot time them.
    let mut plain = Scratch::new();
    let encoded = crate::keywork::run(|kw| {
        tapsigner::decrypt(&cipher.0[..len], &key, &mut plain.0)
            .ok()
            .and_then(|xprv| ExtendedPrivKey::from_base58(xprv.trim(), kw).ok())
            .map(|node| encode_xprv(&node.chain_code, node.secret_bytes()))
    });
    key.zeroize();
    // `cipher` and `plain` wipe themselves on drop.

    let Some(mut secret) = encoded else {
        return say(ui, "Cannot import", "wrong key, or not a TAPSIGNER backup");
    };

    let res = crate::backup::store_secret(gate, login, ui, &secret);
    secret.zeroize();
    match res {
        Ok(()) => {
            crate::catlog!("tapsigner: imported master");
            menu::message(ui.panel, "Wallet imported", "from the TAPSIGNER", "backup");
        }
        Err(why) => menu::message(ui.panel, "Not imported", why, "any key to go back"),
    }
    menu::wait_for_any_key(ui);
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
