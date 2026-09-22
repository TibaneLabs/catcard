//! Login protections that erase the seed on their own: the kill key and microSD 2FA.
//!
//! **Release builds only, and mk4 or later.** A development build (the `dev` feature, on in
//! every default build) compiles this module out, so no bench unit -- all of them RDP=2,
//! with no recovery -- can be erased by one. The settings they read stay on flash either
//! way; a dev build simply does not act on them.
//!
//! Both are stock features (hw-reference/firmware-features.md §"PIN & login" [C]) with
//! stock's pre-login keys (`kbtn`, `sd2fa`) whose value formats the reference does not give
//! [?]. So they are kept under our own keys -- see `catcard_settings::prelogin` -- which
//! stock ignores, and which cannot be misread into erasing a device.
//!
//! # How each erases
//!
//! - The **kill key** fires at the PIN prompt, before any login, so the wallet API that
//!   needs one is out of reach. It uses the bootloader's fast wipe (callgate 23), which
//!   needs none and does not return.
//! - **microSD 2FA** is checked after a correct PIN, logged in, so it erases through the
//!   same write-and-read-back path as Destroy seed, then reboots.

use catcard_callgate::Callgate;
use catcard_settings::prelogin::{self, Sd2fa};
use core::fmt::Write as _;
use zeroize::Zeroize as _;

use crate::menu;
use crate::ui::Ui;

/// The kill key was typed: erase the seed and reset, now.
///
/// Silent, so a person made to log in sees a device reset rather than a message that says
/// what just happened.
pub(crate) fn kill(gate: &Callgate) -> ! {
    // SAFETY: the owner armed this key for exactly this; nothing after it runs.
    unsafe { gate.fast_wipe(catcard_callgate::abi::FastWipe::Silent) }
}

/// After a correct PIN: if cards are enrolled, the inserted card must be one of them, or the
/// seed is erased and the device reboots.
///
/// Read more than once before concluding it is absent, so a card that is slow to answer is
/// not taken for a missing one. A list that is present but will not read matches no card:
/// failing open there would be the feature not working.
pub(crate) fn check_card(gate: &Callgate, login: &mut catcard_pin::Login) {
    let (state, digests) = crate::settings::sd2fa();
    let enrolled = match state {
        Sd2fa::Off => return,
        Sd2fa::Cards(n) => &digests[..n],
        Sd2fa::Damaged => &[][..],
    };

    let mut token = [0u8; prelogin::SD2FA_TOKEN_LEN + 1];
    let mut matched = false;
    for attempt in 0..3 {
        match crate::signtx::read_card_file(prelogin::SD2FA_FILE, &mut token) {
            Ok(n) if n == prelogin::SD2FA_TOKEN_LEN => {
                let d = prelogin::card_digest(&token[..n]);
                matched = enrolled.contains(&d);
                break;
            }
            Ok(_) => break,
            Err(why) => {
                crate::catlog!("2fa: read {}: {}", attempt, why);
                // SAFETY: reads RCC only.
                unsafe { catcard_hal::dwt::delay_ms(200) };
            }
        }
    }
    token.zeroize();
    if matched {
        crate::catlog!("2fa: card accepted");
        return;
    }

    crate::catlog!("2fa: no enrolled card; erasing the seed");
    let pin_gate = crate::pinentry::BootloaderGate::new(gate);
    let empty = [0u8; catcard_callgate::pin::SECRET_LEN];
    // The erase Destroy seed uses, read back. If it did not take, the fast wipe instead:
    // a reboot with the seed still there would be this check doing nothing.
    let erased = login.set_secret(&pin_gate, &empty).is_ok()
        && login.verify_secret(&pin_gate, &empty).unwrap_or(false);
    if !erased {
        kill(gate);
    }
    // SAFETY: a reboot, from the boot path, with nothing to keep.
    unsafe { gate.logout(catcard_callgate::abi::LogoutMode::LogoutAndReboot) }
}

/// Settings → Login → Kill key.
///
/// The digit must not be in the PIN, or the owner would erase their own seed at the next
/// login -- so it is armed only after a test login shows it is not, on this device, typed
/// the way login types it.
pub(crate) fn kill_key_screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    use crate::pinentry::TestLogin;
    const HEAD: &str = "Kill key";
    const ROWS: &[&str] = &[
        "Off", "Digit 0", "Digit 1", "Digit 2", "Digit 3", "Digit 4", "Digit 5", "Digit 6",
        "Digit 7", "Digit 8", "Digit 9",
    ];
    let mut note: heapless::String<24> = heapless::String::new();
    let _ = match crate::settings::kill_key() {
        Some(d) => write!(note, "now digit {d}"),
        None => write!(note, "now off"),
    };
    let Some(row) = menu::pick_row(ui, HEAD, &note, ROWS) else {
        return;
    };
    if row == 0 {
        let said = if crate::settings::save_kill_key(ui, None) {
            "off"
        } else {
            "could not save"
        };
        menu::message(ui.panel, HEAD, said, "");
        menu::wait_for_any_key(ui);
        return;
    }
    let digit = (row - 1) as u8;
    let mut typed: heapless::String<24> = heapless::String::new();
    let _ = write!(typed, "typing {digit} at login");
    menu::ask(ui.panel, HEAD, &typed, "ERASES the seed");
    if !menu::confirmed(ui) {
        return;
    }
    menu::ask(
        ui.panel,
        HEAD,
        "log in once to check",
        "your PIN has no such digit",
    );
    if !menu::confirmed(ui) {
        return;
    }
    let scramble = crate::settings::scramble_keys();
    let outcome = crate::pinentry::test_login(gate, ui.panel, ui.matrix, ui.drbg, login, scramble);
    match outcome {
        TestLogin::Correct { digits } if digits & (1 << digit) != 0 => {
            menu::message(ui.panel, HEAD, "your PIN uses it", "pick another digit");
        }
        TestLogin::Correct { .. } => {
            if crate::settings::save_kill_key(ui, Some(digit)) {
                crate::catlog!("kill key: armed");
                menu::message(ui.panel, HEAD, "armed", "from the next login");
            } else {
                menu::message(ui.panel, HEAD, "could not save", "not armed");
            }
        }
        other => {
            menu::say_test(ui, HEAD, other);
            menu::message(ui.panel, HEAD, "not armed", "");
        }
    }
    menu::wait_for_any_key(ui);
}

/// Settings → Login → MicroSD 2FA: enrol the card in the slot, check one, or stop.
pub(crate) fn sd2fa_screen(ui: &mut Ui<'_>) {
    const HEAD: &str = "MicroSD 2FA";
    let (state, digests) = crate::settings::sd2fa();
    let mut note: heapless::String<24> = heapless::String::new();
    let _ = match state {
        Sd2fa::Off => write!(note, "off"),
        Sd2fa::Cards(n) => write!(note, "{n} card(s) enrolled"),
        Sd2fa::Damaged => write!(note, "list damaged"),
    };
    let Some(row) = menu::pick_row(
        ui,
        HEAD,
        &note,
        &["Add this card", "Check this card", "Turn off"],
    ) else {
        return;
    };
    let enrolled = match state {
        Sd2fa::Cards(n) => &digests[..n],
        _ => &[][..],
    };
    match row {
        0 => add_card(ui, enrolled),
        1 => {
            let mut token = [0u8; prelogin::SD2FA_TOKEN_LEN + 1];
            let ok = matches!(
                crate::signtx::read_card_file(prelogin::SD2FA_FILE, &mut token),
                Ok(n) if n == prelogin::SD2FA_TOKEN_LEN
                    && enrolled.contains(&prelogin::card_digest(&token[..n]))
            );
            token.zeroize();
            let said = if ok { "enrolled" } else { "NOT enrolled" };
            menu::message(ui.panel, HEAD, "this card is", said);
            menu::wait_for_any_key(ui);
        }
        _ => {
            let said = if crate::settings::save_sd2fa(ui, &[]) {
                "off"
            } else {
                "could not save"
            };
            menu::message(ui.panel, HEAD, said, "");
            menu::wait_for_any_key(ui);
        }
    }
}

/// Write a fresh token to the card in the slot, read it back, and enrol its digest.
fn add_card(ui: &mut Ui<'_>, enrolled: &[[u8; 32]]) {
    const HEAD: &str = "MicroSD 2FA";
    if enrolled.len() >= prelogin::SD2FA_MAX {
        menu::message(
            ui.panel,
            HEAD,
            "four cards already",
            "turn off to start over",
        );
        menu::wait_for_any_key(ui);
        return;
    }
    if enrolled.is_empty() {
        menu::ask(ui.panel, HEAD, "login without a card", "ERASES the seed");
        if !menu::confirmed(ui) {
            return;
        }
        menu::ask(ui.panel, HEAD, "keep your words:", "they are the way back");
        if !menu::confirmed(ui) {
            return;
        }
    }

    // A secret token, so from the DRBG the pool seeded -- the one source of randomness
    // for anything that is not a seed. Refusing is the answer if it will not give one.
    let mut token = [0u8; prelogin::SD2FA_TOKEN_LEN];
    if ui.drbg.generate(&mut token).is_err() {
        menu::message(ui.panel, HEAD, "no randomness", "nothing enrolled");
        menu::wait_for_any_key(ui);
        return;
    }
    menu::card_wait(ui.panel, HEAD, "writing to the card");
    let written = menu::write_card_file(prelogin::SD2FA_FILE, &token);
    // Read back before enrolling: a card that did not keep the token would erase the seed
    // at the next login.
    let mut back = [0u8; prelogin::SD2FA_TOKEN_LEN + 1];
    let kept = written.is_ok()
        && matches!(
            crate::signtx::read_card_file(prelogin::SD2FA_FILE, &mut back),
            Ok(n) if back[..n] == token[..]
        );
    back.zeroize();
    let digest = prelogin::card_digest(&token);
    token.zeroize();
    if !kept {
        crate::catlog!("2fa: card did not keep its token: {:?}", written.err());
        menu::message(ui.panel, HEAD, "the card did not", "keep it; not enrolled");
        menu::wait_for_any_key(ui);
        return;
    }

    let mut all: heapless::Vec<[u8; 32], { prelogin::SD2FA_MAX }> = heapless::Vec::new();
    let _ = all.extend_from_slice(enrolled);
    let _ = all.push(digest);
    let said = if crate::settings::save_sd2fa(ui, &all) {
        crate::catlog!("2fa: {} card(s) enrolled", all.len());
        "enrolled"
    } else {
        "could not save"
    };
    menu::message(ui.panel, HEAD, "this card is", said);
    menu::wait_for_any_key(ui);
}
