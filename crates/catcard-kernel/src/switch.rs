//! The context switch: PendSV, SysTick, and the very first hand-off.

use core::arch::naked_asm;

/// PendSV: save the running task, ask the scheduler for the next, restore it.
///
/// Named rather than attributed because `cortex_m_rt`'s exception macro wraps the
/// function body, and a naked function cannot be wrapped. The vector table's entry is a
/// weak symbol, so defining this one overrides it.
///
/// The handler runs on MSP while the task's context lives on PSP, so `r0` is only ever a
/// pointer into the task's stack -- SP itself is never moved here.
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PendSV() {
    naked_asm!(
        // The inline assembler does not inherit the target's FPU, and without this the
        // `vstmdb`/`vldmia` below will not assemble -- which then cascades into a
        // complaint about the IT block, because the instruction it was guarding vanished.
        ".fpu fpv4-sp-d16",
        "mrs   r0, psp",
        // EXC_RETURN bit 4 clear means this task has an extended frame -- it used the
        // FPU -- so its callee-saved FP registers must be saved too. Skipping this is a
        // corruption that only shows up in whichever task did floating point.
        "tst   lr, #0x10",
        "it    eq",
        "vstmdbeq r0!, {{s16-s31}}",
        // Callee-saved core registers, with EXC_RETURN among them: the *next* task's
        // EXC_RETURN is restored from its own frame below, which is what lets tasks with
        // and without FP context coexist.
        "stmdb r0!, {{r4-r11, lr}}",
        // r0 in: the outgoing stack pointer. r0 out: the incoming one. `bl` clobbers lr,
        // which is exactly why it was pushed a moment ago.
        "bl    {sched}",
        "ldmia r0!, {{r4-r11, lr}}",
        "tst   lr, #0x10",
        "it    eq",
        "vldmiaeq r0!, {{s16-s31}}",
        "msr   psp, r0",
        "bx    lr",
        sched = sym sched_entry,
    )
}

/// The Rust half of the switch, kept out of the naked function so the scheduler can be
/// ordinary safe code.
extern "C" fn sched_entry(sp: u32) -> u32 {
    crate::task::switch(sp)
}

/// SysTick: count the tick, then ask for a switch.
///
/// The switch is *requested*, not performed here: PendSV is the lowest priority in the
/// system, so the swap happens only once every device handler has finished.
#[unsafe(no_mangle)]
pub extern "C" fn SysTick() {
    crate::count_tick();
    cortex_m::peripheral::SCB::set_pendsv();
}

/// Somewhere harmless for the first context save to land.
///
/// PendSV saves unconditionally, so PSP must already point at writable memory the first
/// time it fires -- otherwise the very first switch writes seventeen words through
/// whatever PSP happened to contain at reset.
static mut BOOTSTRAP_STACK: [u32; 40] = [0; 40];

/// Hand the CPU to the first task. Never returns.
///
/// # Safety
/// Call once, from [`crate::start`], with at least one task spawned.
pub(crate) unsafe fn bootstrap() -> ! {
    // SAFETY: the scratch is ours alone and is only ever written by the discarded first
    // save; `psp` is not in use yet because nothing has run in thread mode on it.
    unsafe {
        let top = (core::ptr::addr_of_mut!(BOOTSTRAP_STACK)).cast::<u32>().add(40) as u32 & !7;
        cortex_m::register::psp::write(top);
    }
    // Mark "no current task", so that first save is dropped rather than written over a
    // real task's pointer.
    crate::task::begin();
    cortex_m::peripheral::SCB::set_pendsv();
    // SAFETY: every task is spawned and both exceptions are armed; the pending PendSV
    // takes the CPU into the first task and never comes back here.
    unsafe { cortex_m::interrupt::enable() };
    loop {
        cortex_m::asm::wfi();
    }
}
