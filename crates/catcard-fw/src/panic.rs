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
use core::sync::atomic::{compiler_fence, Ordering};

use catcard_board::BOARD;
use catcard_callgate::abi::{LogoutMode, Method};
use catcard_callgate::Callgate;

extern "C" {
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

/// Zero `.data` and `.bss`.
///
/// Does **not** clear the stack: we are running on it. That gap is the reason the
/// callgate path above is preferred — anything spilled to the stack survives this.
fn local_wipe() {
    // SAFETY: the linker symbols bound the statics region, and interrupts are masked,
    // so nothing else observes these while they are being cleared. Volatile writes stop
    // the compiler from eliding stores to memory it can prove is never read again.
    unsafe {
        zero_range(&raw mut __sdata, &raw mut __edata);
        zero_range(&raw mut __sbss, &raw mut __ebss);
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
