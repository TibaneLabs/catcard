//! The `Help` rows: one short screen per drawer saying what the drawer holds.
//!
//! Stock puts a `Help` row on its top menus for the boards without a keyboard; ours is
//! on every board, and on the main, Settings and Utils menus. Each is a scrolling
//! document in this firmware's own words -- the reference catalogues stock's screens by
//! gist and this says the same kind of thing about *our* rows, which are not stock's.
//!
//! Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §B1/B2 "Help" [C];
//! help-and-warning-screens.md (purpose: equivalent guidance, not stock's prose) [C].

use catcard_ui::scroll::Line as DLine;

use crate::menu;
use crate::ui::Ui;

/// Show `body` under `head` as a document, and wait until it is dismissed.
fn show(ui: &mut Ui<'_>, head: &str, body: &[&str]) {
    let mut lines: heapless::Vec<DLine<'_>, 24> = heapless::Vec::new();
    let _ = lines.push(DLine::title(head));
    for b in body {
        let _ = lines.push(DLine::body(b).small().wrapped());
    }
    let _ = menu::show_doc(ui, &lines, false, false);
}

/// The main menu: what each cell is for.
pub(crate) fn main(ui: &mut Ui<'_>) {
    show(
        ui,
        "Help",
        &[
            "Sign: approve a transaction from the card, disk, QR or NFC; sign or verify a message or a text file.",
            "Addresses: list this wallet's addresses and verify one you were given.",
            "Derive: which wallet is in force -- root, passphrase, BIP-85 child, XOR, vault.",
            "Utils: exports, backup, files on the card and disk, USB drive, firmware upgrade.",
            "Settings: login, preferences, multisig, the danger zone, About.",
            "A wallet's fingerprint is shown when another key than the root is in force.",
            "Nothing here sends a transaction: a signed file still has to be broadcast elsewhere.",
        ],
    );
}

/// Settings: what each row changes, and which ones bite.
pub(crate) fn settings(ui: &mut Ui<'_>) {
    show(
        ui,
        "Settings help",
        &[
            "Login: change or test the PIN, nickname, scrambled keys, countdown, calculator login.",
            "Passphrase: a BIP-39 passphrase opens a different wallet from the same words.",
            "Multisig: the wallets this device co-signs for.",
            "Idle timeout, display units, max fee, hardware switches, menu wrapping: preferences kept per wallet.",
            "Danger zone: the seed words, network, and the bootloader rows -- Set High-Water is irreversible.",
            "About: version, chip, and this device's identity as the bootloader reports it.",
            "Debug: diagnostics for a bench; Warm Reset restarts the device.",
        ],
    );
}

/// Utils: the tool drawer.
pub(crate) fn utils(ui: &mut Ui<'_>) {
    show(
        ui,
        "Utils help",
        &[
            "Export wallet: public keys and descriptors for wallet software. Never the seed.",
            "Backup: the whole wallet in one encrypted file, and restoring one.",
            "Browse, Card details, Format SD card, Card password, Encrypt card: the microSD.",
            "Format RAM disk: blank and re-create the Virtual Disk in PSRAM.",
            "Delete PSBTs: blank and remove spent transactions from the card or disk.",
            "USB Drive: share the card or the Virtual Disk with the computer; a firmware left on the disk is offered on eject.",
            "Upgrade Firmware: install a signed image from the card or the Virtual Disk.",
            "Paper wallet, WIF Store: single keys outside the seed. Analyze RNG: the entropy sources.",
        ],
    );
}
