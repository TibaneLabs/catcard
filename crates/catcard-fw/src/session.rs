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

use crate::{display, keypad, pinentry, selftest, BootReport};

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

    selftest::show(&mut report, &mut panel, &mut matrix, &mut drbg);

    match pinentry::unlock(&gate, &mut panel, &mut matrix, &mut drbg) {
        // Logged in, but nothing is built on top of it yet. Held here rather than
        // dropped back to the selftest screen so that a successful unlock is visibly
        // different from a failed one.
        pinentry::Unlocked::In { zero_secret } => hold(
            &mut panel,
            "Unlocked",
            if zero_secret {
                "no seed stored yet"
            } else {
                "wallet is not built yet"
            },
        ),
        pinentry::Unlocked::Blank => hold(&mut panel, "Blank device", "set a PIN to begin"),
    }
}

/// Draw a final screen and stop.
fn hold(panel: &mut display::Panel, head: &str, note: &str) -> ! {
    use catcard_ui::font::{misc4x6, peep7x14};
    use catcard_ui::text::{centred, draw_text};
    use catcard_ui::Mono128x64;

    let mut fb = Mono128x64::new();
    let t = &peep7x14::FONT;
    let b = &misc4x6::FONT;
    draw_text(&mut fb, t, centred(t, head, 128), 12, head);
    draw_text(&mut fb, b, centred(b, note, 128), 36, note);
    let _ = panel.flush(&fb);

    loop {
        cortex_m::asm::wfi();
    }
}
