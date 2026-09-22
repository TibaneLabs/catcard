//! Everything this device keeps, written to a card in one file.
//!
//! For the case where a device has to be understood rather than used: a firmware bug ate
//! a setting, a wallet will not derive what it derived yesterday, a store written by one
//! version has to be read by another. The alternative is reading it off the flash with a
//! debugger, which these parts do not allow -- they are RDP=2.
//!
//! # This writes the seed in the clear
//!
//! Not encrypted, not wrapped, not behind a password: the secret stash exactly as the
//! secure element returns it. **Whoever holds the card holds the wallet.** That is the
//! point -- a dump that needed this firmware to read it would be useless for diagnosing
//! this firmware -- but it makes the card a hardware wallet with no PIN on it, and the
//! screen says so before it writes anything.
//!
//! It is therefore a development and recovery tool and lives in Debug, not a backup.
//! A backup is the same bytes under a key the owner keeps, which is a different feature
//! and wants a decryption tool to go with it.
//!
//! # What is in it
//!
//! | section | what |
//! |---|---|
//! | `secret` | the secret stash from the secure element: marker byte and entropy |
//! | `settings` | the settings region, byte for byte -- a LittleFS2 volume image |
//!
//! The settings slots stay encrypted, because that is how they sit in flash and
//! decrypting them here would be inventing a second format to get wrong. They are
//! readable with the seed, which is in the same file.
//!
//! **Not** in it: the secure element's long secret. Nothing in this firmware reads it
//! yet, and a section that silently held nothing would be worse than an absent one.
//!
//! # The format
//!
//! A text manifest, then sections, each `section <name> <len>\n` followed by exactly
//! that many raw bytes and nothing between them. So `head -c 200` says what a file is
//! and a dozen lines of Python takes it apart, which is the whole requirement for
//! something whose reader has not been written yet.

use core::fmt::Write as _;

use catcard_callgate::Callgate;
use zeroize::Zeroize as _;

use crate::menu;
use crate::ui::Ui;

const HEAD: &str = "Dump state";

/// Room for the manifest and the section headers.
const TEXT_MAX: usize = 256;

/// Write the dump, after saying what it is.
pub(crate) fn screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    let catcard_board::spec::SettingsArea::InternalFlash { start, len } =
        catcard_board::BOARD.settings
    else {
        menu::message(ui.panel, HEAD, "not this board", "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    };

    // Said before the PIN, not after: agreeing to this should not cost an unlock, and
    // what is being agreed to is the part people skip. A yes/no, not "any key" -- a key
    // press is not consent to writing a wallet onto removable media.
    menu::ask(
        ui.panel,
        HEAD,
        "writes the SEED unencrypted",
        "anyone with the card has the wallet",
    );
    if !menu::confirmed(ui) {
        return;
    }

    // The stash exactly as the secure element returns it, marker byte and all. Not the
    // derived master: a dump is for seeing what is *stored*, and the master is a
    // function of this plus whatever passphrase was in force.
    menu::reading_seed(ui.panel, HEAD);
    let pin_gate = crate::pinentry::BootloaderGate::new(gate);
    let mut secret = match login.fetch_secret(&pin_gate) {
        Ok(s) => s,
        Err(_) => {
            menu::message(ui.panel, HEAD, "could not read seed", "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        }
    };

    // Named for the wallet it belongs to, so a card with several on it can be told
    // apart; the fingerprint is cheap here because the master is already in hand.
    let xfp = crate::menu::master_quietly(gate, login, ui.panel, HEAD)
        .map(|m| crate::keywork::run(|kw| m.fingerprint(kw)))
        .unwrap_or([0; 4]);
    let [a, b, c, d] = xfp;

    let mut manifest: heapless::String<TEXT_MAX> = heapless::String::new();
    let _ = write!(
        manifest,
        "CATCARD-STATE 1\n\
         board {}\n\
         version {}\n\
         xfp {a:02X}{b:02X}{c:02X}{d:02X}\n",
        catcard_board::BOARD.name,
        crate::VERSION,
    );
    let mut secret_head: heapless::String<32> = heapless::String::new();
    let _ = writeln!(secret_head, "section secret {}", secret.len());
    let mut settings_head: heapless::String<32> = heapless::String::new();
    let _ = writeln!(settings_head, "section settings {len}");

    // SAFETY: internal flash is memory-mapped and readable; the region is the board
    // table's and this only reads it. A slice rather than a copy, because half a
    // megabyte is more than this device has anywhere to put.
    let settings = unsafe { core::slice::from_raw_parts(start as *const u8, len as usize) };

    menu::card_wait(ui.panel, HEAD, "writing to the card");
    let mut path: heapless::String<24> = heapless::String::new();
    let _ = write!(path, "/{a:02X}{b:02X}{c:02X}{d:02X}-STATE.BIN");
    let written = menu::write_card_parts(
        &path,
        &[
            manifest.as_bytes(),
            secret_head.as_bytes(),
            &secret,
            settings_head.as_bytes(),
            settings,
        ],
    );
    // The card has it now; this copy has no further use.
    secret.zeroize();

    match written {
        Ok(name) => {
            crate::catlog!("state: dumped to {}", name.as_str());
            let mut note: heapless::String<32> = heapless::String::new();
            let _ = write!(note, "{} KB, seed in the clear", (len as usize) / 1024);
            menu::message(ui.panel, "Dumped", &name[1..], &note);
        }
        Err(why) => {
            crate::catlog!("state: dump failed: {}", why);
            menu::message(ui.panel, HEAD, why, "nothing written");
        }
    }
    menu::wait_for_any_key(ui);
}
