//! Panic handling.
//!
//! A panic in a wallet is not just a crash. Whatever was in RAM at the time — a seed
//! fetched from the secure element, a mnemonic mid-entry, a signing scalar — is still
//! there afterwards, and the device may be sitting on a desk unlocked. `panic-halt`
//! stops the CPU with all of it intact.
//!
//! # What this does instead
//!
//! The bootloader already provides exactly the right primitive: callgate 3
//! (`show_logout`) wipes **all** SRAM and locks the device up, from inside the firewall
//! where it can clear memory it is not itself running out of. So the panic path hands
//! over to it.
//!
//! That is better than anything we could do ourselves. Wiping SRAM from code that is
//! *running in* SRAM means the wiper has to survive erasing its own stack; the
//! bootloader does not have that problem.
//!
//! If the callgate is unreachable — an unrecognised bootloader, or a panic so early
//! that discovery fails — we fall back to clearing what we can reach and halting. That
//! fallback is strictly worse and is not the expected path.

use core::panic::PanicInfo;
use core::sync::atomic::{Ordering, compiler_fence};

use catcard_board::BOARD;
use catcard_callgate::Callgate;
use catcard_callgate::abi::{LogoutMode, Method};

unsafe extern "C" {
    // Provided by cortex-m-rt's linker script. `.data` and `.bss` are where a cached
    // secret would live if it were not on the stack.
    static mut __sdata: u32;
    static mut __edata: u32;
    static mut __sbss: u32;
    static mut __ebss: u32;
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // Deliberately not printed or stored: a panic message can embed key material
    // through a formatted value, and there is no screen to show it on yet.
    wipe_and_stop()
}

/// Clear every secret we can reach, then stop the device.
pub fn wipe_and_stop() -> ! {
    // SAFETY: interrupts off first, so nothing runs on a half-wiped heap.
    unsafe {
        core::arch::asm!("cpsid i", options(nomem, nostack, preserves_flags));
    }

    // Hand over to the bootloader, which can wipe all of SRAM including our stack.
    // SAFETY: we are running on BOARD; `discover` validates the published entry
    // address before it can be branched to.
    if let Ok(gate) = unsafe { Callgate::discover(&BOARD) } {
        // SAFETY: `show_logout` takes no buffer. It does not return.
        let _ = unsafe { gate.call_no_buf(Method::ShowLogout, LogoutMode::Logout as u32) };
        // Reaching here means the bootloader declined; fall through to the local wipe.
    }

    local_wipe();

    loop {
        // SAFETY: halting the core.
        unsafe {
            core::arch::asm!("wfi", options(nomem, nostack, preserves_flags));
        }
    }
}

/// Clear what we can reach, then reset the core: the path for **handler mode**.
///
/// A hard fault, or an interrupt nothing enabled, arrives with the CPU in handler mode.
/// The callgate is only known to work from thread mode: every documented call is made
/// from the firmware's foreground with interrupts masked, and the reference says nothing
/// about entering the firewall from an exception (hw-reference/bootloader-callgate-abi.md
/// §0 describes the entry; nothing describes it from a handler). A branch into it from a
/// fault handler could close the firewall and reset the CPU with SRAM intact, which is
/// the outcome this exists to prevent. So gate 3 is **not** called here.
///
/// Instead: mask, wipe `.data`, `.bss` and the claimed spare bank, then `SYSRESETREQ`. The
/// reset runs the bootloader's own start-up path -- the one a power cycle runs -- and the
/// seed is asked for again through the PIN. What the local wipe cannot reach is the stack,
/// and the fault frame on it; the frame is never formatted or stored, and a reset is the
/// surest way to stop anything reading it.
///
/// `SYSRESETREQ` is `AIRCR` bit 2, written with `VECTKEY`. Source: ARMv7-M ARM §B3.2.6 [C];
/// `cortex_m::peripheral::SCB::sys_reset` does exactly that write and spins.
pub fn wipe_and_reset() -> ! {
    // SAFETY: interrupts off first, so nothing runs on a half-wiped heap. Already the case
    // at a fault's own priority, but this is also reached from an ordinary interrupt.
    unsafe {
        core::arch::asm!("cpsid i", options(nomem, nostack, preserves_flags));
    }
    // The MPU fence under the main stack (`stackguard`) comes down before anything else:
    // this may *be* the fence's fault, with the stack already at the floor, and a wipe
    // that pushed one frame further would fault again inside the fault handler -- the
    // loop that ends with nothing wiped. Off, the wipe and the reset cannot trip it.
    // SAFETY: one store to `MPU_CTRL`; nothing can fault from unfencing memory.
    unsafe { catcard_hal::mpu::disarm() };
    local_wipe();
    cortex_m::peripheral::SCB::sys_reset()
}

/// Zero `.data`, `.bss`, and the spare RAM bank if the heap had claimed it.
///
/// Does **not** clear the stack: we are running on it. That gap is the reason the
/// callgate path above is preferred — anything spilled to the stack survives this.
///
/// # What gate 3 is asserted to wipe, and why this still matters
///
/// `show_logout` "wipe[s] all SRAM, then lock[s] up" -- every bank, the bootloader's own
/// 8 KB included, from code that does not run out of any of it.
/// Source: hw-reference/bootloader-callgate-abi.md §"Method table", method 3, and
/// hw-reference/power.md §"Power-off / shutdown (Q1)" ("It wipes all SRAM") [C]. This function is the
/// fallback for when that gate is unreachable or not known to be callable (handler mode),
/// so it has to cover the same ground as far as it can: the linked statics, and the
/// unlinked bank above SRAM1 that the allocator hands out on the L4+ boards
/// (`BOARD.memory.spare_ram`, 0x2003_0000..0x2009_E000), which holds whatever any heap
/// block held. It stops where the bootloader's window begins (`bl_sram_base`), which
/// the callgate wipes itself on every entry and exit (docs/CALLGATE-DMA.md §5), and
/// which is not this firmware's to write.
///
/// The bank is only zeroed if the heap claimed it. Claiming is what proved it is memory
/// (`heap::claim_spare`), and this runs from the hard fault handler: a bus fault here
/// would be a fault inside the fault handler, a lockup with nothing wiped. On mk3 there
/// is no bank and nothing extra is done.
fn local_wipe() {
    // Ask before the statics go: the flag lives in `.bss`.
    let spare = if crate::heap::spare_claimed() {
        BOARD.memory.spare_ram
    } else {
        None
    };
    // SAFETY: the linker symbols bound the statics region, and interrupts are masked,
    // so nothing else observes these while they are being cleared. Volatile writes stop
    // the compiler from eliding stores to memory it can prove is never read again.
    unsafe {
        zero_range(&raw mut __sdata, &raw mut __edata);
        zero_range(&raw mut __sbss, &raw mut __ebss);
    }
    if let Some(bank) = spare {
        // Never into the bootloader's window, however the table is edited later: the
        // board test asserts the two are disjoint, and this clamps regardless.
        let end = if bank.base < BOARD.memory.bl_sram_base {
            bank.end().min(BOARD.memory.bl_sram_base)
        } else {
            bank.end()
        };
        // SAFETY: the bank was probed and handed to the allocator, so it is real,
        // word-aligned RAM that no linked section lives in; interrupts are masked and
        // nothing allocates again on this path.
        unsafe { zero_range(bank.base as *mut u32, end as *mut u32) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// # Safety
/// `start` and `end` must bound a single, writable, word-aligned object range.
unsafe fn zero_range(start: *mut u32, end: *mut u32) {
    let mut p = start;
    while p < end {
        // SAFETY: `p` is inside the caller-asserted range and word-aligned.
        unsafe {
            core::ptr::write_volatile(p, 0);
            p = p.add(1);
        }
    }
}
