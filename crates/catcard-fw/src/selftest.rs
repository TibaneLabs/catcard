//! Where boot ends until there is a display to report on.

use catcard_ui::text::{draw_text, draw_wrapped};
use catcard_ui::Mono128x64;

use crate::{display, BootReport, BOARD_NAME, VERSION};

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
fn render(report: &BootReport, panel: &mut display::Panel) {
    let mut fb = Mono128x64::new();

    draw_text(&mut fb, 0, 0, "CatCard");
    draw_text(&mut fb, 64, 0, BOARD_NAME);
    draw_text(&mut fb, 0, 8, VERSION);

    draw_text(
        &mut fb,
        0,
        24,
        match report.hal {
            Ok(()) => "HAL   ok",
            Err(_) => "HAL   FAIL",
        },
    );
    draw_text(
        &mut fb,
        0,
        32,
        if report.dwt_running {
            "DWT   ok"
        } else {
            "DWT   FAIL"
        },
    );

    match report.entropy {
        Ok(bits) => {
            draw_text(&mut fb, 0, 40, "RNG   ok");
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
                64,
                40,
                core::str::from_utf8(&buf).unwrap_or("????"),
            );
            draw_text(&mut fb, 96, 40, "bit");
        }
        Err(_) => {
            draw_text(&mut fb, 0, 40, "RNG   FAIL");
            draw_wrapped(&mut fb, 0, 48, "entropy policy not met");
        }
    }

    let _ = panel.flush(&fb);
}

/// Publish the boot result and stop.
pub fn park(report: &BootReport) -> ! {
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

    // SAFETY: bring-up is complete and nothing else has claimed the panel.
    if let Some(mut panel) = unsafe { display::init() } {
        render(report, &mut panel);
    }

    loop {
        cortex_m::asm::wfi();
    }
}
