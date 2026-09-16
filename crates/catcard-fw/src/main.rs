//! CatCard firmware entry point.
//!
//! What runs today is the **entropy bring-up path**: enable the cycle counter, start
//! the 48 MHz clock, start the hardware TRNG, and build an entropy pool that meets its
//! policy before anything could ask it for a seed. That order is deliberate — it is
//! the part the original firmware got wrong, so it is the part that exists first.
//!
//! After bring-up it shows the selftest screen and then asks for the PIN, which the
//! bootloader checks -- see [`catcard_pin`] for the sequencing and why it refuses a
//! suffix before the anti-phishing words have been shown.
//!
//! Not yet implemented: SPI-NOR, microSD, USB, and every wallet operation. See
//! `docs/ROADMAP.md`.

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
#[cfg(feature = "games")]
mod game;
mod keypad;
#[macro_use]
mod logbuf;
#[cfg(feature = "usb-debug-mem")]
mod debug_mem;
mod interrupts;
mod menu;
mod msc_drive;
mod nor;
mod panic;
mod pinentry;
mod power;
mod recovery;
mod sdupgrade;
mod selftest;
mod session;
mod staging;
mod splash;
mod ui;
mod usbtask;

/// Board this image was built for, from `build.rs`.
/// The board this was *built* for, from the selected feature.
pub const BOARD_NAME: &str = env!("CATCARD_BOARD");

/// The board this is *running* on.
///
/// One image can carry both the mk4 and mk5 `hw_compat` bits and install on either, so
/// the build-time name is not always the truth. mk5 pulls `STRAP_MK5` low; reading it
/// means a combined image identifies itself correctly on screen, over USB, and in any
/// log taken off it, rather than insisting it is whichever board it was compiled for.
///
/// Only meaningful between mk4 and mk5, which are the same board to within this strap.
/// Every other board returns its own name unread: mk3 is a different MCU, and Q1
/// differs in ways no strap covers.
pub fn running_board() -> &'static str {
    if !matches!(BOARD_NAME, "mk4" | "mk5") {
        return BOARD_NAME;
    }
    // SAFETY: PE0 is not claimed by anything else on these boards -- the reference
    // lists the straps as unused by firmware -- and this only reads.
    if unsafe { catcard_hal::strap::is_mk5() } {
        "mk5"
    } else {
        "mk4"
    }
}

/// Version reported to the host and written into the signed header.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[entry]
fn main() -> ! {
    // SAFETY: this is the reset path; nothing else has touched these peripherals. The
    // core comes up first because the panel's reset pulse is timed with the cycle
    // counter.
    let hal = unsafe { catcard_hal::init_core() };

    // SAFETY: bring-up is single-threaded and nothing else has claimed the panel.
    let mut panel = unsafe { display::init() };

    let report = boot::bring_up(hal, panel.as_mut());

    // Everything above ran on the main stack. From here the firmware is a task: the
    // session becomes the UI task, and the kernel takes the CPU.
    //
    // SAFETY: the boot path is single-threaded and nothing is scheduling yet; the UI
    // task is the only reader of these, and the stacks are not shared.
    unsafe {
        *(core::ptr::addr_of_mut!(BOOT_ARGS)) = Some((report, panel));
        // Built straight from the raw pointers: taking a reference to the array first
        // would be an aliasing claim over a static this task is about to run on.
        let ui = core::slice::from_raw_parts_mut((core::ptr::addr_of_mut!(UI_STACK)).cast::<u32>(), UI_WORDS);
        let beat =
            core::slice::from_raw_parts_mut((core::ptr::addr_of_mut!(BEAT_STACK)).cast::<u32>(), BEAT_WORDS);
        // A full table is a build-time mistake, not a runtime condition worth reporting
        // to a screen that does not exist yet.
        let _ = catcard_kernel::spawn("ui", ui, ui_task);
        let _ = catcard_kernel::spawn("beat", beat, beat_task);
    }

    // SAFETY: reads RCC; the tick must match the clock the core actually runs at.
    let hclk = unsafe { catcard_hal::clock::hclk_hz() };
    // SAFETY: stealing the core peripherals on the boot path, where nothing else holds
    // them, purely to arm SysTick.
    let mut cp = unsafe { cortex_m::Peripherals::steal() };
    // SAFETY: both tasks are spawned and their entries never return.
    unsafe { catcard_kernel::start(&mut cp.SYST, hclk) }
}

/// The UI task's stack.
///
/// Generous on purpose. The deepest screens put kilobytes on it -- the log viewer reads
/// 2 KB of buffer, the seed-word list builds about 1.1 KB of lines, the SD browser holds
/// 48 entries -- and an overflow does not stop politely: it walks into whatever RAM sits
/// below, which on this device can be seed material. The kernel paints and guards every
/// stack so that is detectable, but the first defence is having enough.
const UI_WORDS: usize = 8192;
static mut UI_STACK: [u32; UI_WORDS] = [0; UI_WORDS];

/// The heartbeat's stack. It counts and yields; it needs almost nothing.
const BEAT_WORDS: usize = 256;
static mut BEAT_STACK: [u32; BEAT_WORDS] = [0; BEAT_WORDS];

/// What the session needs, handed across the boundary where the main stack ends and the
/// UI task's begins.
static mut BOOT_ARGS: Option<(BootReport, Option<display::Panel>)> = None;

/// Ticks the heartbeat task has observed.
///
/// The point of it: if this keeps climbing while a blocking screen is up, preemption is
/// real. If it stops, the scheduler stopped -- and that is worth seeing on a screen
/// rather than inferring.
static BEATS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Ticks the heartbeat has counted, for the kernel debug screen.
pub fn beats() -> u32 {
    BEATS.load(core::sync::atomic::Ordering::Relaxed)
}

/// The firmware as it was, now with a stack of its own.
extern "C" fn ui_task() -> ! {
    // SAFETY: written once in `main` before the kernel started; this is the only reader.
    let Some((report, panel)) = (unsafe { (*(core::ptr::addr_of_mut!(BOOT_ARGS))).take() }) else {
        // Cannot happen -- `main` fills this before spawning. Park rather than invent a
        // session out of nothing.
        loop {
            cortex_m::asm::wfi();
        }
    };
    session::run(report, panel)
}

/// Counts kernel ticks and gives the CPU straight back.
///
/// Deliberately not a busy loop: it yields as soon as it has looked, so the UI keeps
/// essentially all of the CPU and the number still tells the truth.
extern "C" fn beat_task() -> ! {
    let mut last = catcard_kernel::ticks();
    loop {
        let now = catcard_kernel::ticks();
        if now != last {
            last = now;
            BEATS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
        catcard_kernel::yield_now();
    }
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
