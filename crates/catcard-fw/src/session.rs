//! What happens after bring-up: acknowledge the selftest, then unlock.
//!
//! Everything here is conditional on the device being able to do it at all. A wallet
//! that cannot show a prompt must not pretend to take a PIN, and one whose entropy pool
//! never met its policy has no UI DRBG — so rather than degrade to a weaker source or a
//! fixed scan order, those devices stop at the selftest screen where the fault is
//! legible. That is the whole reason this function is a pile of `Option`s.

use catcard_board::BOARD;
use catcard_callgate::abi::LogoutMode;
use catcard_callgate::Callgate;
use catcard_entropy::{domain, spawn_drbg};
use catcard_ui::keypad::{Event, Key, Keypad, KEYS};

use crate::{display, keypad, pinentry, selftest, usbtask, BootReport};

/// Run the post-boot sequence. Never returns.
pub fn run(mut report: BootReport, panel: Option<display::Panel>) -> ! {
    // First, unconditionally: the only report a device with a dead panel can make.
    selftest::publish(&report);

    // SAFETY: bring-up is complete and nothing else has claimed the keypad pins.
    let matrix = unsafe { keypad::GpioMatrix::init() };

    // The scan-order shuffle draws from the UI domain, never from the seed pool.
    let drbg = report
        .pool
        .as_mut()
        .and_then(|pool| spawn_drbg(pool, domain::UI, &[]).ok());

    // SAFETY: we are running on BOARD; `discover` validates the published entry address
    // before anything can branch to it.
    let gate = unsafe { Callgate::discover(&BOARD) }.ok();

    // Taken one at a time so a device with a working panel but no keypad still shows
    // the selftest screen -- which is exactly the device most likely to have one of
    // these missing, and the one where a blank display would be least diagnosable.
    let Some(mut panel) = panel else {
        selftest::park(report, None)
    };
    let (Some(mut matrix), Some(mut drbg), Some(gate)) = (matrix, drbg, gate) else {
        selftest::park(report, Some(panel))
    };

    // USB before anything a person has to do. A host presents the cable and enumerates
    // within milliseconds; a device that only appears after a PIN looks broken. What the
    // PIN gates is the upgrade, not the enumeration -- see `usbtask`.
    //
    // SAFETY: nothing else has claimed OTG_FS or the USB pins, and HSI48 was started
    // during bring-up.
    unsafe { usbtask::init(serial()) };

    selftest::show(&mut report, &mut panel, &mut matrix, &mut drbg);

    let unlocked = pinentry::unlock(&gate, &mut panel, &mut matrix, &mut drbg);

    // The PIN is in. Upgrades are allowed from here; a blank device reaches this too,
    // which is what keeps a unit with no PIN set recoverable.
    usbtask::unlocked();

    let (head, note) = match unlocked {
        pinentry::Unlocked::In { zero_secret: true } => ("Unlocked", "no seed stored yet"),
        pinentry::Unlocked::In { .. } => ("Unlocked", "wallet is not built yet"),
        pinentry::Unlocked::Blank => ("Blank device", "set a PIN to begin"),
    };
    idle(&gate, &mut panel, &mut matrix, &mut drbg, head, note)
}

/// The resting state: show where we got to, and serve USB.
///
/// Not a `wfi` loop, because USB is polled. The host retries a NAK, so a late poll is
/// slow rather than broken -- but a poll that never happens is a device that enumerates
/// and then goes quiet.
fn idle(
    gate: &Callgate,
    panel: &mut display::Panel,
    matrix: &mut keypad::GpioMatrix,
    drbg: &mut catcard_entropy::HmacDrbg,
    head: &str,
    note: &str,
) -> ! {
    message(panel, head, note, "");
    let mut showing_offer = false;

    let mut pad = Keypad::new();
    let mut events = [Event::Pressed(Key::Cancel); KEYS];

    loop {
        usbtask::pump();

        // An upgrade that passed inspection is waiting on a person. Ask.
        if let Some(a) = usbtask::pending() {
            if !showing_offer {
                show_offer(panel, &a);
                showing_offer = true;
            }
            let n = pad.scan(matrix, drbg, &mut events);
            for e in &events[..n] {
                let Event::Pressed(k) = e else { continue };
                match k {
                    Key::Confirm => {
                        match usbtask::approve() {
                            Ok(()) => {
                                message(panel, "Installing", "do not disconnect", "");
                                // SAFETY: the marker is published; the bootloader
                                // installs on the next boot. Nothing after this runs.
                                unsafe { gate.logout(LogoutMode::LogoutAndReboot) }
                            }
                            Err(_) => {
                                message(panel, "Failed", "could not stage", "the image");
                                showing_offer = false;
                            }
                        }
                    }
                    Key::Cancel => {
                        usbtask::decline();
                        showing_offer = false;
                        message(panel, head, note, "");
                    }
                    Key::Digit(_) => {}
                }
            }
        } else if showing_offer {
            showing_offer = false;
            message(panel, head, note, "");
        }
    }
}

/// Ask about a staged firmware image.
///
/// Says whether the signature was checked, in those words. "Unverified" here does not
/// mean "bad" -- the five factory keys are not published, so an official image cannot be
/// checked on-device at all -- but it is the difference between a claim we can stand
/// behind and one we cannot, and the person about to overwrite their firmware is the one
/// who should weigh it.
fn show_offer(panel: &mut display::Panel, a: &catcard_upgrade::Approval) {
    message(
        panel,
        "Install firmware?",
        a.header.version_str().unwrap_or("unknown version"),
        if a.is_verified() {
            "signature checked"
        } else {
            "SIGNATURE NOT CHECKED"
        },
    );
}

/// The device's USB serial number: its unique ID, in hex.
fn serial() -> &'static str {
    static mut SERIAL: [u8; catcard_board::memory::fixed::UNIQUE_ID_LEN * 2] = [b'0'; 24];
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    // SAFETY: written once, before USB is initialised, from the only caller; the boot
    // path is single-threaded and no interrupt reads it.
    unsafe {
        let uid = catcard_hal::uid::read();
        let out = &mut *core::ptr::addr_of_mut!(SERIAL);
        for (i, b) in uid.iter().enumerate() {
            out[i * 2] = HEX[(b >> 4) as usize];
            out[i * 2 + 1] = HEX[(b & 0xF) as usize];
        }
        core::str::from_utf8(out).unwrap_or("CATCARD")
    }
}

/// Draw up to three lines and return.
fn message(panel: &mut display::Panel, head: &str, a: &str, b: &str) {
    use catcard_ui::font::{misc4x6, peep7x14};
    use catcard_ui::text::{centred, draw_text};
    use catcard_ui::Mono128x64;

    let mut fb = Mono128x64::new();
    let t = &peep7x14::FONT;
    let s = &misc4x6::FONT;
    draw_text(&mut fb, t, centred(t, head, 128), 8, head);
    draw_text(&mut fb, s, centred(s, a, 128), 30, a);
    draw_text(&mut fb, s, centred(s, b, 128), 40, b);
    let _ = panel.flush(&fb);
}
