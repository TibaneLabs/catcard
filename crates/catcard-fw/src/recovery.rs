//! Headless recovery: a device that boots but cannot show a prompt or read a key.
//!
//! The session used to park such a device, and a parked device never unlocks -- so it
//! refuses every firmware offer, and the menu that installs from a card is out of reach
//! as well. On a board whose firmware simply lacks the drivers that is every boot (Q1
//! today: no ST7789 driver, no 10x6 keyboard scanner), and it is the trap the mk5 fell
//! into: a validly-signed image that runs, and that nothing can replace.
//!
//! So on a bench build this loop takes the park's place. What a person would do at the
//! glass arrives over USB instead, and every step is written to the log a host pages out:
//!
//! - `UnlockPin` logs in. On a blank device that PIN is set first, then logged in with.
//! - Once in, `UpgradeOffer` is accepted as on any unlocked device. An injected `y`
//!   installs the offered image; `x` declines it.
//! - An injected `1` or `2` stages `catcard.dfu` from SD slot A or B, answered the same
//!   way with `y` or `x`.
//!
//! **Bench builds only.** It needs `usb-key-injection`, which already removes physical
//! presence. Without that feature this is exactly the park it replaced: a shipped device
//! must not install firmware because a host asked.

use catcard_callgate::Callgate;
#[cfg(feature = "usb-key-injection")]
use catcard_pin::{Failure, Login, Step};

use crate::{BootReport, display};

/// Take over from the session on a device that cannot run the front panel. Never returns.
pub fn run(report: BootReport, panel: Option<display::Panel>, gate: Callgate) -> ! {
    #[cfg(feature = "usb-key-injection")]
    {
        // Nothing past this point draws, so leave the reason on the glass while there is
        // glass: a device with a panel but a failed keypad or entropy check shows the same
        // selftest screen it used to park on, and only then goes headless.
        if let Some(mut p) = panel {
            crate::selftest::screen(&report, &mut p);
        }
        headless(gate)
    }
    #[cfg(not(feature = "usb-key-injection"))]
    {
        let _ = gate;
        crate::catlog!("recovery: build has no usb-key-injection; parked");
        crate::selftest::park(report, panel)
    }
}

#[cfg(feature = "usb-key-injection")]
fn headless(gate: Callgate) -> ! {
    use catcard_hal::sdmmc::Slot;
    use catcard_ui::keypad::Key;

    use crate::pinentry::BootloaderGate;
    use crate::sdupgrade::{Outcome, stage_from_card};
    use crate::usbtask;

    let g = BootloaderGate::new(&gate);
    let mut login = Login::new(&g);
    // Only after `Login::new`'s callgate has returned, for the reason `pinentry::unlock`
    // gives: a host that enumerates into a core nobody is servicing wedges.
    usbtask::attach();
    crate::catlog!("recovery: headless -- send the PIN over USB");

    let mut said_in = false;
    let mut said_bricked = false;
    // An image staged from a card, waiting for `y`. USB offers are held by `usbtask`.
    let mut from_card: Option<(
        catcard_upgrade::Staged<'static, crate::staging::Area>,
        catcard_upgrade::Approval,
    )> = None;

    loop {
        let _ = usbtask::pump();
        usbtask::set_blank(matches!(login.step(), Step::Blank));

        match login.step() {
            Step::In { .. } => {
                if !said_in {
                    usbtask::unlocked();
                    crate::catlog!("pin: unlocked (usb)");
                    crate::catlog!("recovery: offer an image, or key 1/2 for SD slot A/B");
                    said_in = true;
                }
            }
            Step::Bricked => {
                // Nothing will log in again. Say so once and keep answering USB.
                if !said_bricked {
                    crate::catlog!("pin: BRICKED -- the pairing secret is gone");
                    said_bricked = true;
                }
            }
            Step::Wrong { attempts_left, .. } => {
                crate::catlog!("pin: wrong PIN, {} tries left", attempts_left);
                login = Login::new(&g);
            }
            Step::Failed(f) => {
                crate::catlog!("pin: gate refused ({}); starting over", failure_name(f));
                catcard_hal::dwt::delay_cycles(usbtask::IDLE_PAUSE_CYCLES * 60);
                login = Login::new(&g);
            }
            Step::Blank | Step::Prefix | Step::ConfirmWords(_) | Step::Suffix => {
                if let Some(pin) = usbtask::take_unlock_pin() {
                    usb_login(&g, &mut login, &pin);
                }
            }
        }

        if matches!(login.step(), Step::In { .. }) {
            // A USB offer is staged into the same PSRAM a card image sits in, so the card
            // image is gone the moment one arrives.
            if usbtask::pending().is_some() && from_card.take().is_some() {
                crate::catlog!("sd: staged image replaced by a USB offer");
            }
            if let Some(key) = usbtask::take_injected_key() {
                match (key, usbtask::pending().is_some(), from_card.is_some()) {
                    (Key::Confirm, true, _) => match usbtask::approve() {
                        #[cfg(not(feature = "board-mk3"))]
                        Ok(region) => install(&g, &mut login, region),
                        // Unreachable on mk3 (USB staging is PSRAM-only, refused there), but
                        // the arm must compile. SAFETY: nothing after this runs.
                        #[cfg(feature = "board-mk3")]
                        Ok(_region) => unsafe {
                            gate.logout(catcard_callgate::abi::LogoutMode::LogoutAndReboot)
                        },
                        Err(_) => crate::catlog!("upgrade: could not stage the offered image"),
                    },
                    (Key::Cancel, true, _) => {
                        usbtask::decline();
                        crate::catlog!("upgrade: declined");
                    }
                    (Key::Confirm, false, true) => {
                        if let Some((staged, approval)) = from_card.take() {
                            match staged.commit(approval) {
                                #[cfg(not(feature = "board-mk3"))]
                                Ok(region) => install(&g, &mut login, region),
                                // mk3 has no gate 18/7: `commit` wrote the SPI-NOR "done"
                                // header, so installing is rebooting -- the bootloader
                                // finds it. SAFETY: nothing after this runs.
                                #[cfg(feature = "board-mk3")]
                                Ok(_region) => unsafe {
                                    crate::catlog!("sd: mk3 SPI-NOR staged, rebooting");
                                    gate.logout(catcard_callgate::abi::LogoutMode::LogoutAndReboot)
                                },
                                Err(_) => crate::catlog!("sd: could not stage the image"),
                            }
                        }
                    }
                    (Key::Cancel, false, true) => {
                        from_card = None;
                        crate::catlog!("sd: declined");
                    }
                    (Key::Digit(d @ (1 | 2)), false, _) => {
                        let (slot, name) = if d == 1 {
                            (Slot::A, "A")
                        } else {
                            (Slot::B, "B")
                        };
                        from_card = None;
                        crate::catlog!("sd: slot {}: looking for a firmware", name);
                        match stage_from_card(slot, None) {
                            Outcome::Offered(staged, approval) => {
                                crate::catlog!(
                                    "sd: staged {}, {} -- key y installs, x declines",
                                    approval.header.version_str().unwrap_or("unknown version"),
                                    crate::session::signature_status(&approval)
                                );
                                from_card = Some((staged, approval));
                            }
                            Outcome::Failed(why) => crate::catlog!("sd: {}", why),
                        }
                    }
                    _ => {}
                }
            }
        }

        catcard_hal::dwt::delay_cycles(usbtask::IDLE_PAUSE_CYCLES);
    }
}

/// Log in with a PIN that arrived over USB, setting it first on a blank device.
#[cfg(feature = "usb-key-injection")]
fn usb_login(g: &crate::pinentry::BootloaderGate<'_>, login: &mut Login, pin: &[u8]) {
    use crate::pinentry::{login_with, split_pin};

    let Some((prefix, suffix)) = split_pin(pin) else {
        crate::catlog!("pin: not PREFIX-SUFFIX digits; ignored");
        return;
    };
    match login.step() {
        Step::Blank => {
            // Not reversible: from here the device is PIN-gated. It is what a person at
            // the setup screen would do, arriving over the channel this build already
            // trusts to press keys.
            crate::catlog!("pin: device is blank -- setting this as its first PIN");
            match login.set_first_pin(g, prefix, suffix) {
                Ok(Step::Prefix) => login_with(g, login, prefix, suffix),
                _ => crate::catlog!("pin: could not set a first PIN"),
            }
        }
        Step::Prefix => login_with(g, login, prefix, suffix),
        _ => {
            // Mid-entry from an earlier attempt: start from a fresh prefix.
            *login = Login::new(g);
            if matches!(login.step(), Step::Prefix) {
                login_with(g, login, prefix, suffix);
            }
        }
    }
}

/// Ask the bootloader to install a staged region. Only returns if it refused.
///
/// mk4/mk5/Q1 only: `gate 18/7` authorises a PSRAM region. mk3 installs by rebooting after
/// `commit` (see the call site), so this is not built there.
#[cfg(all(feature = "usb-key-injection", not(feature = "board-mk3")))]
fn install(
    g: &crate::pinentry::BootloaderGate<'_>,
    login: &mut Login,
    region: catcard_upgrade::Region,
) {
    crate::catlog!(
        "upgrade: installing, gate 18/7 +{:#x} len {}",
        region.start,
        region.len
    );
    match login.authorize_firmware(g, region.start, region.len) {
        Ok(never) => match never {},
        Err(f) => crate::catlog!("upgrade: NOT installed: {}", failure_name(f)),
    }
}

#[cfg(feature = "usb-key-injection")]
fn failure_name(f: Failure) -> &'static str {
    match f {
        // The bootloader's own verification refused the staged image -- a better answer
        // than ours, because it is the check that gates the install.
        Failure::ImageRefused => "bootloader refused the image",
        Failure::NeedsSetup => "login went stale",
        Failure::MustWait => "rate limited",
        Failure::Gate(_) => "callgate unreachable",
        Failure::Code(_) => "refused",
    }
}
