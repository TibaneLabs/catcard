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

    // USB before anything a person has to do, and before the checks below that can park
    // the device. A host presents the cable and enumerates within milliseconds; a device
    // that only appears after a PIN looks broken. What the PIN gates is the upgrade, not
    // the enumeration -- see `usbtask`.
    //
    // Before the park branches specifically, because those fire on a dead panel, a
    // keypad that would not initialise, an entropy pool that missed its policy, or an
    // unreachable callgate -- the exact failures where a host is the only way to reach
    // the device, and where it used to park with USB never started at all.
    //
    // SAFETY: nothing else has claimed OTG_FS or the USB pins, and HSI48 was started
    // during bring-up.
    unsafe { usbtask::init(serial()) };

    // Taken one at a time so a device with a working panel but no keypad still shows
    // the selftest screen -- which is exactly the device most likely to have one of
    // these missing, and the one where a blank display would be least diagnosable.
    let Some(mut panel) = panel else {
        selftest::park(report, None)
    };
    let (Some(mut matrix), Some(mut drbg), Some(gate)) = (matrix, drbg, gate) else {
        selftest::park(report, Some(panel))
    };

    selftest::show(&mut report, &mut panel, &mut matrix, &mut drbg);

    let unlocked = pinentry::unlock(&gate, &mut panel, &mut matrix, &mut drbg);

    // The PIN is in. Upgrades are allowed from here; a blank device reaches this too,
    // which is what keeps a unit with no PIN set recoverable.
    usbtask::unlocked();

    // `unlock` only returns once the PIN is in -- a blank device is offered setup
    // rather than being turned away, so there is no longer a state where the front
    // panel has nothing to offer.
    let (head, note) = match unlocked {
        pinentry::Unlocked::In { zero_secret: true } => ("Unlocked", "no seed stored yet"),
        pinentry::Unlocked::In { .. } => ("Unlocked", "wallet is not built yet"),
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
    let mut showing_offer = false;
    let mut shown_stats = (false, u32::MAX, 0, false);
    draw_usb(panel, head, note, usbtask::stats());

    let mut pad = Keypad::new();
    let mut events = [Event::Pressed(Key::Cancel); KEYS];

    loop {
        // Poll, then pause. The pause is not optional: with nothing between the polls
        // the core delivers no reports at all. See `usbtask::IDLE_PAUSE_CYCLES`.
        let _ = usbtask::pump();
        catcard_hal::dwt::delay_cycles(usbtask::IDLE_PAUSE_CYCLES);

        // Redraw when the USB counters move. The emulator reads this screen back as
        // text, so it is where a stuck transfer becomes visible without a debugger.
        let stats = usbtask::stats();
        if stats != shown_stats && !showing_offer {
            shown_stats = stats;
            // One draw, not two. Drawing the plain screen and then the counters meant
            // the panel never held still, and the emulator only journals a screen once
            // it settles -- so the diagnostic hid itself.
            draw_usb(panel, head, note, stats);
        }

        // An upgrade that passed inspection is waiting on a person. Ask.
        if let Some(a) = usbtask::pending() {
            if !showing_offer {
                show_offer(panel, &a);
                showing_offer = true;
            }
            let n = pad.scan(matrix, drbg, &mut events);
            let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
            for e in &events[..n] {
                if let Event::Pressed(k) = e {
                    let _ = keys.push(*k);
                }
            }
            // A host can press this too. On the first hardware run the panel and the
            // key map are both unconfirmed, and this is the approval that installs a
            // firmware -- so it must not be reachable only through them.
            if let Some(k) = usbtask::take_injected_key() {
                let _ = keys.push(k);
            }
            for k in keys.iter() {
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

/// Redraw the idle screen with the USB counters underneath.
fn draw_usb(panel: &mut display::Panel, head: &str, note: &str, s: (bool, u32, u32, bool)) {
    use catcard_ui::font::{misc4x6, peep7x14};
    use catcard_ui::text::{centred, draw_text};
    use catcard_ui::Mono128x64;

    let mut fb = Mono128x64::new();
    let t = &peep7x14::FONT;
    let f = &misc4x6::FONT;
    draw_text(&mut fb, t, centred(t, head, 128), 4, head);
    draw_text(&mut fb, f, centred(f, note, 128), 24, note);

    // "usb <state> in <n> out <n>", assembled without a formatter.
    let mut x = 4;
    for part in [
        "usb ",
        if s.0 { "up" } else { "down" },
        " in ",
        num3(s.1),
        " out ",
        num3(s.2),
        if s.3 { " q" } else { "" },
    ] {
        draw_text(&mut fb, f, x, 44, part);
        x += part.len() * f.width as usize;
    }
    let _ = panel.flush(&fb);
}

/// Up to three digits, into a fixed table so no formatter and no buffer is needed.
fn num3(v: u32) -> &'static str {
    const D: [&str; 10] = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"];
    // Only the shape of the number matters here: exact counts past nine are read from
    // the emulator's own tally, not from a 128-pixel screen.
    match v {
        0..=9 => D[v as usize],
        10..=99 => "..",
        _ => "many",
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
    // Two facts, in the order they matter. Whether we could check the signature comes
    // first: an image signed by one of the five unpublished factory keys cannot be
    // verified here at all, and that is different from one that failed. Whether it is
    // older than what is running comes second -- going back to stock firmware is a
    // legitimate thing to want, and the bootloader still holds the final say through its
    // high-water mark, so this is a warning and not a refusal.
    message(
        panel,
        "Install firmware?",
        a.header.version_str().unwrap_or("unknown version"),
        match (a.is_verified(), a.older_than_running) {
            (true, false) => "signature checked",
            (true, true) => "checked, but OLDER",
            (false, false) => "SIGNATURE NOT CHECKED",
            (false, true) => "NOT CHECKED, and OLDER",
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
