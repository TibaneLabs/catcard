//! Factory reset: the PIN back to blank, the settings store destroyed and formatted
//! fresh, and optionally a different firmware installed at the end.
//!
//! # The order
//!
//! 1. Say what is lost, twice.
//! 2. Keep this firmware, or install another -- and if another, pick its `.dfu` now,
//!    while the card and the screens are all still there.
//! 3. The current PIN, then the PIN is cleared to blank (gate 18 method 3, empty new PIN).
//!    A wrong PIN stops here, having changed nothing, and reboots as a failed change does.
//! 4. The chosen image is read into the staging area and checked (PSRAM boards).
//! 5. The settings store is overwritten with DRBG output and formatted empty
//!    ([`crate::settings::factory_wipe`]).
//! 6. The image is installed, which reboots -- or, with no image, the device powers off
//!    (Q1) or logs out (the boards with no power switch).
//!
//! On the mk3 steps 4 and 5 swap: its staging area and its settings share the SPI-NOR,
//! and re-opening a staged image there erases it, so the settings go first and the image
//! is read in after. The install is still last.
//!
//! **Irreversible from step 3 on.** Every screen before it says so, and every path after
//! it ends in a reboot or a power-off: nothing returns to a menu whose settings are gone.
//!
//! # The install after the PIN is cleared `[?]`
//!
//! On mk4/mk5/Q1 the install is gate 18 method 7, which the bootloader takes only from a
//! logged-in struct (install-and-usb-transport.md §2b). Whether the struct a PIN change
//! hands back is still logged in is not documented, and stock offers no install on a blank
//! device. So the change is asked to keep the login
//! ([`catcard_pin::Login::clear_pin_keeping_login`]) and the install is tried; if it is
//! refused, the reset has still happened and the screen says the firmware was not
//! installed. The mk3 needs no gate call: its staged image installs on the next boot.
//! Listed in `docs/HARDWARE-OPEN-ITEMS.md`.

use catcard_callgate::Callgate;
use catcard_callgate::abi::LogoutMode;
use core::fmt::Write as _;

use crate::display;
use crate::menu::{self, Browse, Storage};
use crate::ui::Ui;

const HEAD: &str = "Factory reset";

/// A staged, checked image and what it said about itself.
type Ready = (
    catcard_upgrade::Staged<'static, crate::staging::Area>,
    catcard_upgrade::Approval,
);

/// Settings → Debug → Factory Reset.
pub(crate) fn run(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    menu::ask(
        ui.panel,
        "Factory reset?",
        "PIN and ALL settings",
        "are ERASED",
    );
    if !menu::confirmed(ui) {
        return;
    }
    menu::ask(ui.panel, "Really reset?", "this cannot be", "undone");
    if !menu::confirmed(ui) {
        return;
    }

    // Chosen now, installed last: the file is picked while nothing is lost yet.
    let Some(pick) = menu::choose(
        ui,
        HEAD,
        "and the firmware?",
        &["Keep this firmware", "Install another"],
    ) else {
        return;
    };
    let chosen = if pick == 1 {
        let Some(storage) = menu::pick_storage(ui, HEAD) else {
            return;
        };
        let Some(path) =
            menu::browse_storage(ui, storage, "Pick a .dfu", Some("dfu"), Browse::File)
        else {
            return;
        };
        Some((storage, path))
    } else {
        None
    };

    use crate::pinentry::FactoryReset;
    match crate::pinentry::factory_reset(
        gate,
        ui.panel,
        ui.matrix,
        ui.drbg,
        login,
        chosen.is_some(),
    ) {
        FactoryReset::Wiped => crate::catlog!("reset: PIN cleared"),
        FactoryReset::Refused => {
            crate::catlog!("reset: PIN change refused, nothing erased, rebooting");
            menu::message(ui.panel, "Not reset", "rebooting", "");
            // SAFETY: nothing after this runs.
            unsafe { gate.logout(LogoutMode::LogoutAndReboot) }
        }
        FactoryReset::Cancelled => return,
    }

    // From here on the reset has happened. Every path below ends the session.
    #[cfg(not(feature = "board-mk3"))]
    {
        let ready = chosen.and_then(|(storage, path)| stage(gate, ui, storage, &path));
        if !wipe(ui) {
            end(gate, ui, "settings NOT erased");
        }
        if let Some((staged, approval)) = ready {
            install(gate, login, ui, staged, approval);
        }
        end(gate, ui, "done");
    }
    #[cfg(feature = "board-mk3")]
    {
        if !wipe(ui) {
            end(gate, ui, "settings NOT erased");
        }
        if let Some((staged, approval)) =
            chosen.and_then(|(storage, path)| stage(gate, ui, storage, &path))
        {
            install(gate, login, ui, staged, approval);
        }
        end(gate, ui, "done");
    }
}

/// Read `path` into the staging area and check it, then show what it is and ask.
///
/// `None` when it would not load, failed its check, or the owner turned it down: the
/// reset goes on without it, and the screen has said why.
fn stage(gate: &Callgate, ui: &mut Ui<'_>, storage: Storage, path: &str) -> Option<Ready> {
    use crate::sdupgrade::Outcome;
    let mut shown = u8::MAX;
    let mut tick = |done: u32, total: u32| {
        let pct = percent(done, total);
        if pct != shown {
            shown = pct;
            bar(ui.panel, "reading the firmware", pct);
        }
    };
    let outcome = match storage {
        Storage::Sd => {
            crate::sdupgrade::stage_from_card(catcard_hal::sdmmc::Slot::A, Some(path), &mut tick)
        }
        #[cfg(not(feature = "board-mk3"))]
        Storage::Vdisk => crate::sdupgrade::stage_from_vdisk(Some(path), &mut tick),
    };
    match outcome {
        Outcome::Offered(staged, approval) => {
            crate::session::show_offer(gate, ui.panel, &approval);
            if !menu::confirmed(ui) {
                crate::catlog!("reset: firmware declined");
                return None;
            }
            if crate::session::sets_high_water(&approval) {
                menu::ask(
                    ui.panel,
                    "Really install?",
                    "sets anti-downgrade",
                    "mark: no way back",
                );
                if !menu::confirmed(ui) {
                    return None;
                }
            }
            Some((staged, approval))
        }
        Outcome::Failed(why) => {
            crate::catlog!("reset: firmware not loaded: {}", why);
            menu::message(
                ui.panel,
                "Firmware not loaded",
                why,
                "reset goes on without it",
            );
            menu::wait_for_any_key(ui);
            None
        }
    }
}

/// Overwrite the settings store with DRBG output and format it. Says whether it worked.
fn wipe(ui: &mut Ui<'_>) -> bool {
    let mut shown = u8::MAX;
    let mut rng_failed = false;
    let drbg = &mut *ui.drbg;
    let panel = &mut *ui.panel;
    let fill = |buf: &mut [u8]| {
        // The DRBG caps one request well above this; a refusal leaves zeros, which still
        // overwrite what was there, and is logged.
        for chunk in buf.chunks_mut(1024) {
            if drbg.generate(chunk).is_err() {
                chunk.fill(0);
                rng_failed = true;
            }
        }
    };
    let progress = |done: u32, total: u32| {
        let pct = percent(done, total);
        if pct != shown {
            shown = pct;
            bar(panel, "erasing settings", pct);
        }
    };
    // SAFETY: this screen is the only user of the settings medium, and nothing it calls
    // mounts it while the wipe runs.
    let result = unsafe { crate::settings::factory_wipe(fill, progress) };
    if rng_failed {
        crate::catlog!("reset: the DRBG refused; some blocks were overwritten with zeros");
    }
    match result {
        Ok(()) => {
            crate::catlog!("reset: settings overwritten and formatted");
            true
        }
        Err(why) => {
            crate::catlog!("reset: settings wipe failed: {}", why);
            menu::message(ui.panel, "Settings not erased", why, "any key");
            menu::wait_for_any_key(ui);
            false
        }
    }
}

/// Publish the staged image and have the bootloader install it. Returns only if it was
/// refused, having said so.
fn install(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    staged: catcard_upgrade::Staged<'static, crate::staging::Area>,
    approval: catcard_upgrade::Approval,
) {
    match staged.commit(approval) {
        Ok(region) => {
            menu::message(ui.panel, "Installing", "do not disconnect", "");
            crate::staging::install(gate, login, ui.panel, region);
            // Back here only on a refusal, which `install` has put on the screen.
            crate::catlog!("reset: firmware not installed; the reset itself is done");
        }
        Err(why) => {
            crate::catlog!("reset: commit refused: {:?}", why);
            menu::message(
                ui.panel,
                "Not installed",
                crate::sdupgrade::describe(why),
                "",
            );
        }
    }
    menu::wait_for_any_key(ui);
}

/// The end of every path after the PIN is cleared: say how it went, then power off where
/// the board can, and log out where it cannot -- pulling the cable is the power switch.
fn end(gate: &Callgate, ui: &mut Ui<'_>, how: &str) -> ! {
    #[cfg(feature = "board-q1")]
    let (mode, then) = (LogoutMode::PowerDown, "powering off");
    #[cfg(not(feature = "board-q1"))]
    let (mode, then) = (LogoutMode::Logout, "unplug to finish");
    menu::message(ui.panel, "Reset", how, then);
    crate::catlog!("reset: {}, {}", how, then);
    // SAFETY: nothing after this runs; the bootloader wipes SRAM on the way out.
    unsafe { gate.logout(mode) }
}

fn percent(done: u32, total: u32) -> u8 {
    if total == 0 {
        100
    } else {
        ((done as u64 * 100) / total as u64) as u8
    }
}

/// A progress bar under one line of caption.
fn bar(panel: &mut display::Panel, caption: &str, pct: u8) {
    let mut note: heapless::String<16> = heapless::String::new();
    let _ = write!(note, "{pct}%");
    display::draw(panel, |c| {
        let lines = [caption, note.as_str()];
        catcard_ui::widgets::info(c, &display::LAYOUT, HEAD, &lines);
        catcard_ui::splash::draw_progress(c, pct);
        crate::idle::note_progress();
    });
}
