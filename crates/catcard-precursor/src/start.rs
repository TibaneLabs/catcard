//! Entry, trap and panic.
//!
//! The runner resets the CPU through the VexRiscv debug port and jumps here, so the hart
//! starts in machine mode with the MMU off and interrupts disabled -- but the peripherals
//! are as Xous left them, including any interrupt enables. Interrupts are therefore
//! masked at the CPU (`mie = 0`, `mstatus.MIE = 0`) and stay masked: milestone 1 polls.
//!
//! A trap or a panic prints what it can and then stops feeding the watchdog, which
//! resets the SoC back into the firmware in flash. That is the intended recovery: a
//! wedged bench image should give the device back, not hold it.

use core::arch::global_asm;
use core::fmt::Write as _;

global_asm!(
    r#"
    .section .text.start, "ax"
    .global _start
_start:
    csrw    mie, zero
    csrci   mstatus, 8
    .option push
    .option norelax
    la      gp, __global_pointer$
    .option pop
    la      sp, _stack_top
    la      t0, _trap
    csrw    mtvec, t0
    // The image is loaded straight into SRAM, so .data is already in place; only
    // .bss needs zeroing.
    la      t0, _sbss
    la      t1, _ebss
1:  bgeu    t0, t1, 2f
    sw      zero, 0(t0)
    addi    t0, t0, 4
    j       1b
2:  call    rust_main
3:  j       3b

    .section .text.trap, "ax"
    .balign 4
_trap:
    csrr    a0, mcause
    csrr    a1, mepc
    csrr    a2, mtval
    la      sp, _stack_top
    call    trap_handler
4:  j       4b
"#
);

#[unsafe(no_mangle)]
extern "C" fn trap_handler(mcause: u32, mepc: u32, mtval: u32) -> ! {
    let mut out = crate::uart::Uart::take();
    let _ = writeln!(
        out,
        "\nTRAP mcause={mcause:#010x} mepc={mepc:#010x} mtval={mtval:#010x}"
    );
    let _ = writeln!(
        out,
        "no longer feeding the watchdog: expect a reset into stock firmware"
    );
    halt()
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    let mut out = crate::uart::Uart::take();
    let _ = writeln!(out, "\nPANIC: {info}");
    let _ = writeln!(
        out,
        "no longer feeding the watchdog: expect a reset into stock firmware"
    );
    halt()
}

fn halt() -> ! {
    loop {
        core::hint::spin_loop();
    }
}
