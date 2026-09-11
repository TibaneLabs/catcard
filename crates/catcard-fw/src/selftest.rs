//! Where boot ends until there is a display to report on.

use catcard_ui::font::{misc4x6, peep7x14};
use catcard_ui::keypad::{Event, Key, Keypad, KEYS};
use catcard_ui::text::{centred, draw_text, draw_wrapped};
use catcard_ui::Mono128x64;

use crate::{display, keypad, BootReport, BOARD_NAME, VERSION};

/// Observable state, laid out so a debugger (or, later, the selftest screen) can read
/// the outcome of bring-up without a protocol.
///
/// `#[used]` and `#[no_mangle]` keep it in the image and findable by name in the map
/// file even at `opt-level = "s"` with LTO.
#[no_mangle]
#[used]
pub static mut CATCARD_BOOT_STATUS: BootStatus = BootStatus {
    magic: BOOT_STATUS_MAGIC,
    hal_ok: 0,
    entropy_ok: 0,
    credited_bits: 0,
    dwt_running: 0,
};

pub const BOOT_STATUS_MAGIC: u32 = 0xCA7C_A2D0;

#[repr(C)]
pub struct BootStatus {
    pub magic: u32,
    pub hal_ok: u32,
    pub entropy_ok: u32,
    pub credited_bits: u32,
    pub dwt_running: u32,
}

/// Draw what bring-up found, then stop.
///
/// This is the first thing anyone sees on hardware, so it reports the two facts that
/// decide whether the device is usable at all: did the TRNG come up, and did the
/// entropy pool meet its policy. A wallet that cannot answer both must not proceed to
/// generating a seed.
fn render(report: &BootReport, last_key: Option<Key>, waiting: bool, panel: &mut display::Panel) {
    let mut fb = Mono128x64::new();

    // Title in the 7x14 face, status in the dense 4x6 — the same split a Coldcard
    // uses, and what makes six status lines fit under a legible heading.
    let title = &peep7x14::FONT;
    let body = &misc4x6::FONT;
    draw_text(&mut fb, title, centred(title, "CatCard", 128), 0, "CatCard");
    draw_text(&mut fb, body, 0, 16, BOARD_NAME);
    draw_text(&mut fb, body, 20, 16, VERSION);

    draw_text(
        &mut fb,
        body,
        0,
        22,
        match report.hal {
            Ok(()) => "HAL   ok",
            Err(_) => "HAL   FAIL",
        },
    );
    draw_text(
        &mut fb,
        body,
        0,
        28,
        if report.dwt_running {
            "DWT   ok"
        } else {
            "DWT   FAIL"
        },
    );

    match report.entropy {
        Ok(bits) => {
            draw_text(&mut fb, body, 0, 34, "RNG   ok");
            // Rendered without a formatter: core::fmt pulls in a large amount of code
            // for what is three digits.
            let mut buf = [b' '; 4];
            let mut n = bits.min(9999);
            for slot in buf.iter_mut().rev() {
                *slot = b'0' + (n % 10) as u8;
                n /= 10;
                if n == 0 {
                    break;
                }
            }
            draw_text(
                &mut fb,
                body,
                36,
                34,
                core::str::from_utf8(&buf).unwrap_or("????"),
            );
            draw_text(&mut fb, body, 56, 34, "bit");
        }
        Err(_) => {
            draw_text(&mut fb, body, 0, 34, "RNG   FAIL");
            draw_wrapped(&mut fb, body, 0, 40, "entropy policy not met");
        }
    }

    // Last key pressed, so the keypad can be validated without a debugger.
    if let Some(k) = last_key {
        draw_text(&mut fb, body, 0, 46, "KEY");
        let label: [u8; 1] = match k {
            Key::Digit(d) => [b'0' + d],
            Key::Cancel => *b"x",
            Key::Confirm => *b"y",
        };
        draw_text(
            &mut fb,
            body,
            48,
            56,
            core::str::from_utf8(&label).unwrap_or("?"),
        );
    }

    // Whether this screen is live. A parked device and one waiting for a key were
    // pixel-identical before this line, so "nothing happens when I press y" had two
    // very different causes and no way to tell them apart without a debugger.
    draw_text(
        &mut fb,
        body,
        0,
        52,
        match (waiting, crate::usbtask::KEY_INJECTION) {
            // Stated on the device itself: a build that accepts keys from a host is not
            // a build to hand to anyone, and this is the screen that always gets looked
            // at first.
            (true, true) => "y  continue   [USB KEYS]",
            (true, false) => "y  continue",
            (false, true) => "stopped: no input   [USB KEYS]",
            (false, false) => "stopped: no input",
        },
    );

    let _ = panel.flush(&fb);
}

/// Write the boot result where a debugger can find it.
///
/// Separate from any screen because it is the only report a device with a dead panel
/// can make, and it must happen whether or not the display came up.
pub fn publish(report: &BootReport) {
    let status = BootStatus {
        magic: BOOT_STATUS_MAGIC,
        hal_ok: report.hal.is_ok() as u32,
        entropy_ok: report.entropy.is_ok() as u32,
        credited_bits: *report.entropy.as_ref().unwrap_or(&0),
        dwt_running: report.dwt_running as u32,
    };
    // SAFETY: single-threaded, interrupts are not enabled yet, and this is the only
    // writer of this static.
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(CATCARD_BOOT_STATUS), status);
    }
}

/// Show the bring-up result and echo key presses until `y` is pressed.
///
/// The echo is not decoration: it is the only way to confirm the keypad map and the
/// debounce on hardware without a debugger, and it exercises the display refresh path
/// at the same time. It also feeds press timing into the entropy pool, which is where
/// user-interaction jitter is meant to come from.
///
/// Returns once the user acknowledges, so that boot can carry on to the PIN prompt.
pub fn show(
    report: &mut BootReport,
    panel: &mut display::Panel,
    matrix: &mut keypad::GpioMatrix,
    drbg: &mut catcard_entropy::HmacDrbg,
) {
    render(report, None, true, panel);

    let mut pad = Keypad::new();
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut last: Option<Key> = None;

    loop {
        // The host starts enumerating within milliseconds of the cable and will not wait
        // for this screen to be dismissed.
        let _ = crate::usbtask::pump();

        let n = pad.scan(matrix, drbg, &mut events);
        let mut changed = false;
        let mut seen: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
        for e in &events[..n] {
            if let Event::Pressed(k) = e {
                let _ = seen.push(*k);
            }
        }
        // Without this a host cannot get past the first screen, which would make the
        // rest of the injected-key path unreachable on a device whose pad is mirrored.
        if let Some(k) = crate::usbtask::take_injected_key() {
            let _ = seen.push(k);
        }
        for k in seen.iter() {
            if *k == Key::Confirm {
                return;
            }
            last = Some(*k);
            changed = true;
            // Press timing is genuine, if weak, entropy; credited 1 bit/byte.
            if let Some(pool) = report.pool.as_mut() {
                pool.add_timing(catcard_hal::dwt::cycles());
            }
        }
        if changed {
            render(report, last, true, panel);
        }
        // Roughly 60 Hz at the reset-default clock; three samples then give about
        // 50 ms of debounce.
        catcard_hal::dwt::delay_cycles(66_000);
    }
}

/// Stop, with whatever we could report.
///
/// The path for a device that cannot offer a PIN prompt at all: no panel, no keypad, or
/// an entropy pool that never met its policy so there is no UI DRBG to shuffle the scan
/// order with. Seeding UI randomness from something weaker instead is the habit this
/// project exists to break, so the keypad simply is not scanned.
pub fn park(report: BootReport, panel: Option<display::Panel>) -> ! {
    publish(&report);
    let mut panel = panel;
    if let Some(p) = panel.as_mut() {
        render(&report, None, false, p);
    }
    loop {
        cortex_m::asm::wfi();
    }
}
