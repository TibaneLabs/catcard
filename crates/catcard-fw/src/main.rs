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

/// Battery sensing exists only on the Q1; the other boards are USB-powered.
#[cfg(feature = "board-q1")]
mod battery;
mod boot;
mod derive;
mod display;
/// Wallet-export file formats.
mod export;
#[cfg(all(feature = "games", feature = "board-q1"))]
mod flappy;
#[cfg(feature = "games")]
mod game;
#[cfg(feature = "board-q1")]
mod gpu;
/// The heap: one region, lent out a block at a time.
mod heap;
mod key;
mod keypad;
mod keywork;
#[macro_use]
mod logbuf;
#[cfg(feature = "usb-debug-mem")]
mod debug_mem;
/// Expanding a deflate stream that is already in the staging area.
#[cfg(feature = "board-q1")]
mod inflate;
mod interrupts;
mod ktest;
mod menu;
mod msc_drive;
/// Registering a multisig wallet from a descriptor on the card.
#[cfg(not(feature = "board-mk3"))]
mod msimport;
mod nor;
/// Secure Notes & Passwords, read out of the settings blob.
///
/// Q1 only, as the feature is: stock offers it where there is a keyboard to type a note on,
/// so a viewer on an mk4 or mk5 would only ever show an empty list.
#[cfg(feature = "board-q1")]
mod notes;
/// The settings medium on a board whose settings live in internal flash (mk4/mk5/Q1).
#[cfg(not(feature = "board-mk3"))]
mod nvram;
mod panic;
mod passphrase;
mod pinentry;
mod power;
/// PSRAM, and who is using it. mk3 has none.
#[cfg(not(feature = "board-mk3"))]
mod psram;
mod pubkeys;
/// Reading a file that arrived as animated QR.
#[cfg(feature = "board-q1")]
mod qrload;
/// The QR scanner is the Q1's alone.
#[cfg(feature = "board-q1")]
mod qrscan;
/// Showing a file as animated QR.
#[cfg(feature = "board-q1")]
mod qrshow;
mod recovery;
mod sdupgrade;
mod seedxor;
mod selftest;
mod session;
/// The settings store itself: slots, keys, and the screen that reads them.
#[cfg(not(feature = "board-mk3"))]
mod settings;
mod signmsg;
mod signtx;
mod splash;
mod staging;
/// Everything this device keeps, written to a card in one file.
#[cfg(not(feature = "board-mk3"))]
mod statedump;
/// The Q1's status bar has no counterpart on the mono boards, whose 64 rows cannot spare
/// any and whose keypad has no modifiers to report.
#[cfg(feature = "board-q1")]
mod statusbar;
/// The lamp belongs to the scanner, so it is the Q1's too.
#[cfg(feature = "board-q1")]
mod torch;
mod trng;
mod ui;
/// Deflated firmware images arriving over USB.
mod unpack;
mod usbtask;
/// The Seed Vault: keys kept in the settings store, which the mk3 has none of.
#[cfg(not(feature = "board-mk3"))]
mod vault;
mod verify;

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
    // The bootloader hands off by a plain jump, not a reset, so the vector table in use
    // is whatever it left behind. Point it at ours explicitly rather than inferring it
    // from the fact that interrupts happen to work: every exception this image handles --
    // the keypad's edge timestamp, the USB transport, and anything the kernel installs --
    // lives in this image's table, not the loader's.
    //
    // Source: hw-reference/platform.md §"Concrete handoff value" [C]
    //
    // SAFETY: the reset path, writing SCB->VTOR to this image's own vector table.
    unsafe {
        let cp = cortex_m::Peripherals::steal();
        cp.SCB.vtor.write(BOARD.memory.firmware_base);
    }

    // Before anything can allocate, which on this device means before anything at all:
    // the global allocator is registered, so a stray `Vec` anywhere in the image would
    // otherwise reach a heap with no region and be told no.
    // SAFETY: the reset path, once, before any allocation.
    unsafe { heap::init() };

    // The bootloader hands off with interrupts **masked**, and nothing on the way in
    // turns them back on: cortex-m-rt's reset path does not, `#[entry]` does not, and the
    // callgate's `with_interrupts_masked` deliberately preserves whatever it found ("set
    // on entry means leave them so"). So until this line the firmware ran with PRIMASK
    // set and *no interrupt had ever fired on this device*.
    //
    // Everything polled worked, which is why it went unnoticed: USB, the keypad scan, the
    // display. The two things that need an interrupt did not -- the keypad's EXTI edge
    // timestamp, which is the fine-grained entropy a keypress contributes, and
    // interrupt-mode mass storage, whose failure was recorded as an EP0 problem.
    //
    // Proven on hardware: with PRIMASK set the edge handler never ran (its latch stayed
    // zero across a boot and many keypresses); opening a single `cpsie i` window made it
    // fire immediately from the pending line.
    //
    // Before opening the global mask, close every NVIC line, whatever the bootloader left
    // enabled or pending. Our own code enables exactly the lines it services later -- the
    // keypad's column EXTIs during bring-up, OTG only for mass storage -- and
    // `DefaultHandler` parks the CPU on any IRQ it does not recognise. So a line the loader
    // left enabled would fire the moment the mask opened and hang the boot, which on an
    // RDP=2 unit is a brick. On the Q1 the loader turned out to leave none; that was
    // learned by booting, which is not a method to repeat on a board with a seed on it.
    // Clearing them makes the question irrelevant on every board.
    //
    // What the loader left is recorded first, so each board reports it instead of it being
    // inferred from whether the boot survived.
    //
    // SAFETY: the reset path, before any line is enabled by this firmware. NVIC_ICER and
    // NVIC_ICPR are write-one-to-clear; writing all ones disables and un-pends every
    // implemented line and is ignored for unimplemented ones.
    let loader_iser = unsafe {
        let nvic = &*cortex_m::peripheral::NVIC::PTR;
        let mut left = [0u32; 3];
        for (i, slot) in left.iter_mut().enumerate() {
            *slot = nvic.iser[i].read();
        }
        for i in 0..nvic.icer.len() {
            nvic.icer[i].write(u32::MAX);
            nvic.icpr[i].write(u32::MAX);
        }
        left
    };

    // SAFETY: the reset path, with every NVIC line now disabled and un-pended, so this opens
    // the core's global mask without enabling any source.
    unsafe { cortex_m::interrupt::enable() };
    crate::catlog!(
        "boot: loader left NVIC {:#010x} {:#010x} {:#010x}; cleared, interrupts on",
        loader_iser[0],
        loader_iser[1],
        loader_iser[2]
    );

    // SAFETY: this is the reset path; nothing else has touched these peripherals. The
    // core comes up first because the panel's reset pulse is timed with the cycle
    // counter.
    let hal = unsafe { catcard_hal::init_core() };

    // SAFETY: bring-up is single-threaded and nothing else has claimed the panel.
    let mut panel = unsafe { display::init() };

    let report = boot::bring_up(hal, panel.as_mut());

    // Selftest screen, then the PIN prompt. A device missing anything that needs --
    // panel, keypad, UI DRBG or callgate -- stops at the selftest screen instead.
    //
    // The kernel is deliberately *not* started here. On an RDP=2 unit a validly-signed
    // image that boots and then hangs has no bootrom recovery, and a wrong context switch
    // is exactly that image. The scheduler starts only when someone chooses it from
    // Debug, so a failed test is cured by a power cycle.
    session::run(report, panel)
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
