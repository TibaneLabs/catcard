//! SeedQR on the device: the seed shown as a code, and a code read back as the seed.
//!
//! The format is [`catcard_wallet::seedqr`], where both shapes are tested against the
//! published vectors. This is the part that needs a person and a panel: the warning
//! before the symbol goes up, which shape to draw, and what to do with a seed that has
//! just come in through the scanner.
//!
//! Q1 only. It is the board with the colour panel a camera can read off and the scanner
//! that reads one back; on a 64-row mono panel a 29-module symbol has two pixels a
//! module and a seed nobody can photograph reliably is worse than no offer at all.
//!
//! # Showing one is the whole wallet on the glass
//!
//! The same secret as View words, in a form a camera across the room reads in a quarter
//! of a second and a person cannot read at all. So it sits beside View words, behind the
//! same warning, and says what a passphrase wallet's owner needs to hear: the passphrase
//! is not in the code.
//!
//! Nothing is written to a card and nothing is stored. The symbol is drawn from a buffer
//! that is wiped before this returns.
//!
//! # Reading one is a temporary seed
//!
//! Exactly as a joined Seed XOR is ([`crate::seedxor`]): the scanned wallet is in force
//! for the session, named in the status bar, and gone on reboot. The stored seed is not
//! touched -- except on a device that has none, where storing it is the only thing that
//! makes the device useful and is offered explicitly.
//!
//! # What the scanner can and cannot hand over
//!
//! A **Standard** code is digits, which is text, and arrives as text.
//!
//! A **Compact** code is raw entropy in byte mode, and the module decides for itself
//! whether a byte-mode symbol is representable: one that is not comes back as the fixed
//! string `(unsupported binary QR)` rather than as its bytes, and a payload with a `0x0a`
//! in it ends the line early. So Compact import works when the module passes the bytes
//! through and is refused cleanly when it does not -- there is nothing this end can do
//! about a decode that never left the module. Standard is the shape to transcribe if it
//! has to come back through this scanner.
//!
//! Source: hw-reference/qr.md §3 [C] -- "an undecodable/binary symbol yields
//! `'(unsupported binary QR)'`".

use catcard_callgate::Callgate;
use catcard_wallet::bip39::{MAX_ENTROPY_LEN, Mnemonic};
use catcard_wallet::seedqr::{self, Kind, MAX_DIGITS};
use core::fmt::Write as _;
use zeroize::{Zeroize as _, Zeroizing};

use crate::menu::{self, pick_row};
use crate::ui::Ui;

/// The title on every screen here, in both directions. One name, because from where the
/// owner is standing showing a code and reading one are the same feature.
const HEAD: &str = "SeedQR";

/// The two shapes, in the order they are offered.
///
/// Standard first: it is the one any phone can read back, and the one to transcribe onto
/// a plate. Compact buys one QR version of transcription work and costs the ability to
/// check the code was read correctly.
const SHAPES: &[&str] = &["Standard", "Compact"];
const KINDS: [Kind; 2] = [Kind::Standard, Kind::Compact];
const _: () = assert!(SHAPES.len() == KINDS.len());

/// Danger zone → Seed tools → SeedQR: the wallet in force, as a code.
pub(crate) fn export(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    menu::ask(
        ui.panel,
        HEAD,
        "shows your whole seed",
        "check nobody can see",
    );
    if !menu::confirmed(ui) {
        return;
    }

    // A passphrase is not in the words, so it is not in the code. Someone who photographs
    // this and keeps only the photograph has kept a different wallet.
    if crate::passphrase::is_set() {
        menu::ask(
            ui.panel,
            HEAD,
            "the WORDS only",
            "your passphrase is not in it",
        );
        if !menu::confirmed(ui) {
            return;
        }
    }

    let Some(row) = pick_row(ui, HEAD, "which shape", SHAPES) else {
        return;
    };
    let kind = KINDS[row];

    let (mut ent, len) = match menu::seed_entropy(gate, login, ui.panel, HEAD) {
        Ok(got) => got,
        Err(why) => {
            // A loaded XPRV or WIF key, or a stored node: a wallet with no words, and
            // SeedQR is a phrase format. `seed_entropy` names which.
            menu::message(ui.panel, HEAD, why, "nothing was shown");
            menu::wait_for_any_key(ui);
            return;
        }
    };

    // The payload is the seed in another alphabet, so it is built where a host cannot
    // time the building and lives in a buffer that wipes itself.
    let mut payload = Zeroizing::new([0u8; MAX_DIGITS]);
    let built = crate::keywork::run(|kw| {
        let m = Mnemonic::from_entropy(&ent[..len], kw).ok()?;
        let words = m.word_count();
        let n = match kind {
            Kind::Standard => seedqr::digits(&m, &mut payload, kw),
            Kind::Compact => {
                let bytes = seedqr::compact(&m, kw);
                payload[..bytes.len()].copy_from_slice(bytes);
                bytes.len()
            }
        };
        Some((n, words))
    });
    ent.zeroize();

    let Some((n, words)) = built else {
        menu::message(ui.panel, HEAD, "seed did not decode", "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    };

    // What is about to be on screen, before it is. The word count and the shape are
    // what a reader on the other side has to agree with; neither is the secret.
    let mut said: heapless::String<32> = heapless::String::new();
    let _ = write!(said, "{words} words, {}", kind.name());
    menu::message(ui.panel, HEAD, &said, "any key to show it");
    menu::wait_for_any_key(ui);

    crate::catlog!("seedqr: showed {} words, {}", words, kind.name());
    // The symbol alone, as large as the panel allows: no text column beside it, because
    // the only text that could go there is the seed.
    menu::qr_screen_bytes(ui, &payload[..n], "");

    menu::message(ui.panel, HEAD, "nothing was stored", "or written to a card");
    menu::wait_for_any_key(ui);
}

/// A scanned code that [`catcard_wallet::seedqr::kind_of`] claimed as a SeedQR.
///
/// Called from the scanner's offer screen with the payload copied out of the staging
/// area, which the caller has already wiped. Everything from here works on the copy.
pub(crate) fn received(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    payload: &[u8],
    kind: Kind,
) {
    // Parsing is what turns the payload into a wallet -- indices into words, the
    // checksum checked, the entropy rebuilt -- so it happens masked.
    let parsed = crate::keywork::run(|kw| {
        seedqr::parse(payload, kw).map(|m| {
            let mut ent = [0u8; MAX_ENTROPY_LEN];
            let e = m.entropy();
            ent[..e.len()].copy_from_slice(e);
            (ent, e.len(), m.word_count())
        })
    });

    let (mut ent, len, words) = match parsed {
        Ok(got) => got,
        Err(why) => {
            crate::catlog!("seedqr: refused a scanned code: {:?}", why);
            menu::message(ui.panel, HEAD, refusal(why), "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        }
    };

    let mut what: heapless::String<32> = heapless::String::new();
    let _ = write!(what, "{words} words, {}", kind.name());
    menu::ask(ui.panel, "Work in this?", &what, "the stored seed stays");
    if !menu::confirmed(ui) {
        ent.zeroize();
        return;
    }

    let was = crate::key::in_force();
    if !crate::key::set_temporary(&ent[..len], "SeedQR") {
        ent.zeroize();
        menu::message(ui.panel, HEAD, "that seed length", "is not usable");
        menu::wait_for_any_key(ui);
        return;
    }

    // Name the wallet that is now in force before anything uses it. Any code of the
    // right shape gives *some* valid wallet, so the fingerprint is the only thing that
    // says whether it is the one that was meant.
    match menu::master_quietly(gate, login, ui.panel, HEAD) {
        Ok(master) => {
            let [a, b, c, d] = crate::keywork::run(|kw| master.fingerprint(kw));
            drop(master);
            let mut said: heapless::String<24> = heapless::String::new();
            let _ = write!(said, "{a:02X}{b:02X}{c:02X}{d:02X}");
            crate::catlog!("seedqr: scanned {} words -> {}", words, said.as_str());
            crate::settings::open_wallet(gate, login, ui.panel, HEAD, [a, b, c, d]);
            menu::message(ui.panel, "Loaded", &said, "in force until reboot");
            menu::wait_for_any_key(ui);
        }
        Err(why) => {
            crate::key::set(was);
            ent.zeroize();
            menu::message(ui.panel, HEAD, why, "unchanged");
            menu::wait_for_any_key(ui);
            return;
        }
    }

    // On a device with no seed of its own this is a restore rather than a session, and
    // keeping it is the only thing that makes the device useful. Anywhere else the
    // stored seed is somebody's wallet and a scanner is not where it gets replaced --
    // Import seed is, with its own warning, and Lock down seed is the deliberate second
    // step for a key that came in this way.
    if !crate::key::stored_wallet(login) {
        menu::ask(
            ui.panel,
            "Keep this seed?",
            "no wallet is stored yet",
            "y to store it for good",
        );
        if menu::confirmed(ui) && menu::store_seed(gate, login, ui, &ent[..len]) {
            // Stored, so it *is* the root now: leaving the temporary selection in force
            // would name one wallet twice.
            crate::key::to_root();
            crate::catlog!("seedqr: scanned seed stored");
            menu::message(ui.panel, "Stored", "this is the wallet", "now");
            menu::wait_for_any_key(ui);
        }
    }
    ent.zeroize();
}

/// What to put on screen for a payload that did not decode.
///
/// Short lines, and none of them says what the payload was: a refusal that echoed the
/// digits back would put most of a seed on the glass to explain why it was not one.
fn refusal(why: seedqr::Error) -> &'static str {
    use catcard_wallet::bip39::Error as Bip39;
    match why {
        seedqr::Error::BadLength { .. } => "not a SeedQR length",
        seedqr::Error::NotDigits { .. } => "not all digits",
        seedqr::Error::NoSuchWord { .. } => "a group is not a word",
        seedqr::Error::Phrase(Bip39::BadChecksum) => "checksum is wrong",
        seedqr::Error::Phrase(_) => "not a valid seed",
    }
}
