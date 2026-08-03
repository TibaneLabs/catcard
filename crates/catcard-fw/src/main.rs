//! CatCard firmware entry point.
//!
//! What runs today is the **entropy bring-up path**: enable the cycle counter, start
//! the 48 MHz clock, start the hardware TRNG, and build an entropy pool that meets its
//! policy before anything could ask it for a seed. That order is deliberate — it is
//! the part the original firmware got wrong, so it is the part that exists first.
//!
//! Not yet implemented: display, keypad, SPI-NOR, microSD, USB, and every wallet
//! operation. See `docs/ROADMAP.md`.

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]
// The panic handler needs raw asm and linker symbols; everything else stays safe.
#![allow(clippy::missing_safety_doc)]

use catcard_board::BOARD;
use catcard_entropy::{EntropyPool, Policy};
use cortex_m_rt::entry;

mod boot;
mod display;
mod keypad;
mod panic;
mod selftest;

/// Board this image was built for, from `build.rs`.
pub const BOARD_NAME: &str = env!("CATCARD_BOARD");

/// Version reported to the host and written into the signed header.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[entry]
fn main() -> ! {
    let report = boot::bring_up();

    // Nothing to display on yet, so hold the result where a debugger can read it and
    // stop. Once the panel driver lands this becomes the selftest screen.
    selftest::park(report)
}

/// Where our own signed header sits in flash, for self-inspection.
///
/// The bootloader has already verified this image before we ran, so reading it back
/// is for reporting (version, build timestamp), not for trust decisions.
pub fn own_header() -> Option<catcard_fwhdr::FirmwareHeader> {
    let addr = BOARD.memory.header_addr() as *const u8;
    let mut raw = [0u8; catcard_fwhdr::HEADER_LEN];
    for (i, b) in raw.iter_mut().enumerate() {
        // SAFETY: `header_addr()` is inside our own installed image in main flash,
        // which is mapped and readable for the whole run.
        *b = unsafe { core::ptr::read_volatile(addr.add(i)) };
    }
    let h = catcard_fwhdr::FirmwareHeader::from_bytes(&raw);
    (h.magic == catcard_fwhdr::MAGIC).then_some(h)
}

/// The entropy policy for this board.
///
/// mk4 and Q reach three independent TRNGs (STM32 + SE1 + SE2) and must use at least
/// two. mk3 can only reach the STM32 TRNG, so it uses the single-source policy — which
/// still demands a full 256 credited bits from it.
pub const fn entropy_policy() -> Policy {
    if BOARD.has_callgate_se_rng {
        Policy::STRICT
    } else {
        Policy::single_trng()
    }
}

/// Result of early bring-up, kept for the selftest screen.
pub struct BootReport {
    pub hal: Result<(), catcard_hal::InitError>,
    pub entropy: Result<u32, catcard_entropy::Insufficient>,
    pub dwt_running: bool,
    pub pool: Option<EntropyPool>,
}
