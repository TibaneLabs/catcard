//! What happens after bring-up: acknowledge the selftest, then unlock.
//!
//! Everything here is conditional on the device being able to do it at all. A wallet
//! that cannot show a prompt must not pretend to take a PIN, and one whose entropy pool
//! never met its policy has no UI DRBG — so rather than degrade to a weaker source or a
//! fixed scan order, those devices stop at the selftest screen where the fault is
//! legible. That is the whole reason this function is a pile of `Option`s.

use catcard_board::BOARD;
use catcard_callgate::Callgate;
use catcard_entropy::{domain, spawn_drbg};

use crate::{display, keypad, menu, pinentry, selftest, usbtask, BootReport};

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

    let (unlocked, mut login) = pinentry::unlock(&gate, &mut panel, &mut matrix, &mut drbg);

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
    menu::run(menu::Session {
        gate: &gate,
        login: &mut login,
        panel: &mut panel,
        matrix: &mut matrix,
        drbg: &mut drbg,
        report: &report,
        head,
        note,
    })
}

/// Ask about a staged firmware image.
///
/// Says whether the signature was checked, in those words. "Unverified" here does not
/// mean "bad" -- the five factory keys are not published, so an official image cannot be
/// checked on-device at all -- but it is the difference between a claim we can stand
/// behind and one we cannot, and the person about to overwrite their firmware is the one
/// who should weigh it.
pub(crate) fn show_offer(panel: &mut display::Panel, a: &catcard_upgrade::Approval) {
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
