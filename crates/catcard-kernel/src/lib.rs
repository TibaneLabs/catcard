//! A small preemptive kernel: real tasks, real stacks, a real context switch.
//!
//! # Why preemptive, and what that costs
//!
//! The firmware grew as cooperative multitasking *by convention*: every waiting loop had
//! to remember to call `usbtask::pump`, and twenty-six of them did. Forgetting meant a
//! device the host could not reach, and nothing but review enforced it. Worse, a screen
//! that blocked owned the panel and the keypad until it returned, so an upgrade offered
//! over USB sat unseen behind a seed backup that waits on a person writing down words.
//!
//! Preemption fixes that by construction rather than by discipline. It is not free, and
//! on a wallet the costs are specific:
//!
//! - **Every task stack is somewhere a secret can sit.** Stacks are painted and guarded
//!   here so an overflow is detectable rather than silent corruption of whatever is next
//!   in RAM -- and on this device, what is next in RAM may be a seed.
//! - **The callgate must not be preempted.** `catcard-callgate` requires interrupts
//!   masked across a gate call or the firewall resets the CPU, so gate callers take a
//!   critical section and are deliberately non-preemptible for its duration.
//! - **Context switches must never preempt the drivers.** The keypad's EXTI handler
//!   timestamps a keypress at the electrical edge for entropy, and the USB transport runs
//!   from OTG_FS; both sit at NVIC priority 0. [`PENDSV_PRIORITY`] keeps the switch below
//!   them, so a task swap can never delay either.
//!
//! # Shape
//!
//! Round-robin over ready tasks, driven by SysTick, switched in PendSV. One stack per
//! task, provided by the caller as a `&'static mut [u32]` so the linker places it and its
//! size is visible at the call site rather than buried here. No allocator, no priorities
//! yet: a wallet's tasks are few and none of them is hard-real-time.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

mod switch;
mod task;

pub use task::{Full, TaskId, count, high_water, name, spawn, stack_ok};

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Most tasks the kernel will hold. Small on purpose: a wallet has a handful of jobs, and
/// a fixed table means the scheduler never allocates and never fails late.
pub const MAX_TASKS: usize = 8;

/// PendSV runs at the lowest possible priority so a context switch never preempts a
/// device handler. The keypad's edge timestamp and the USB transport both sit at the
/// default priority 0; a switch that could interrupt either would add jitter to an
/// entropy sample and stalls to a bulk transfer.
pub const PENDSV_PRIORITY: u8 = 0xFF;

/// SysTick sits below the device handlers but above the switch it triggers.
pub const SYSTICK_PRIORITY: u8 = 0x80;

/// Ticks since the kernel started, kept in step with real time.
///
/// 32 bits, not 64: this core has no 64-bit atomic, and a `u32` of milliseconds wraps
/// after about seven weeks of continuous power -- longer than this device is ever up.
///
/// **Not simply a count of SysTick interrupts.** Every callgate call masks interrupts for
/// its whole duration -- it must, or the firewall closes -- and while they are masked the
/// SysTick interrupts that fall due collapse into a single pending one. Counting
/// interrupts, the clock ran about three times slow in the kernel test: an SE1 TRNG read
/// holds interrupts for ~99 ms, and those ticks were simply gone. So [`advance_ticks`]
/// measures how many CPU cycles really passed since the last tick, from the DWT cycle
/// counter, which keeps counting while interrupts are masked.
static TICKS: AtomicU32 = AtomicU32::new(0);

/// Ticks added beyond one per interrupt: the time recovered after masked windows.
static RECOVERED: AtomicU32 = AtomicU32::new(0);

/// Whether the DWT cycle counter is running, decided once in [`start`]. If it is not,
/// the clock falls back to one tick per interrupt rather than freezing at zero.
static DWT_CLOCK: AtomicBool = AtomicBool::new(false);
/// CPU cycles per tick, from the clock the core actually runs at.
static CYCLES_PER_TICK: AtomicU32 = AtomicU32::new(1);
/// The cycle count at the previous tick.
static LAST_CYCLES: AtomicU32 = AtomicU32::new(0);
/// Cycles left over from the previous tick that did not make up a whole tick, so the
/// clock does not drift by rounding down on every interrupt.
static CYCLE_REM: AtomicU32 = AtomicU32::new(0);

/// How many times the scheduler has actually changed task, for the debug screen. A
/// counter that never moves is the first symptom of a switch that is not happening.
static SWITCHES: AtomicU32 = AtomicU32::new(0);

/// Switches whose outgoing task had floating-point state to save.
///
/// The FPU path in the switch only runs for a task that has touched the FPU, so a test
/// that never sees this move has not exercised it -- however many switches it counted.
static FP_SAVES: AtomicU32 = AtomicU32::new(0);

/// Milliseconds per tick.
pub const TICK_MS: u32 = 1;

/// Milliseconds since [`start`], kept in step with real time across masked windows.
///
/// **One limit.** The DWT counter is 32 bits and wraps every 2^32 cycles -- about 35.8 s
/// at 120 MHz, 53.7 s at 80 MHz. Catch-up measures the gap between two ticks, so a single
/// window with interrupts masked for longer than that undercounts by whole wraps. No
/// callgate call measured so far comes close (an SE1 TRNG read is ~99 ms), but a clock
/// that has to be right across a longer blackout needs the RTC, not this.
pub fn ticks() -> u32 {
    TICKS.load(Ordering::Relaxed)
}

/// Ticks recovered after masked windows since [`start`] -- how much time the clock would
/// have lost counting interrupts alone.
pub fn recovered() -> u32 {
    RECOVERED.load(Ordering::Relaxed)
}

/// Context switches since [`start`].
pub fn switches() -> u32 {
    SWITCHES.load(Ordering::Relaxed)
}

/// Switches that saved floating-point state, since [`start`].
pub fn fp_saves() -> u32 {
    FP_SAVES.load(Ordering::Relaxed)
}

pub(crate) fn count_fp_save() {
    FP_SAVES.fetch_add(1, Ordering::Relaxed);
}

/// The DWT cycle counter. A core register, read directly so the kernel does not depend on
/// the board HAL.
fn dwt_cycles() -> u32 {
    // SAFETY: CYCCNT is a read-only view of a free-running counter; reading it has no
    // side effects.
    unsafe { (*cortex_m::peripheral::DWT::PTR).cyccnt.read() }
}

/// Advance the clock, from SysTick.
///
/// Runs only in the SysTick handler, so there is one writer and the plain load/store
/// pairs below cannot interleave with each other.
pub(crate) fn advance_ticks() {
    if !DWT_CLOCK.load(Ordering::Relaxed) {
        TICKS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let now = dwt_cycles();
    let last = LAST_CYCLES.swap(now, Ordering::Relaxed);
    let per = CYCLES_PER_TICK.load(Ordering::Relaxed).max(1) as u64;
    // `wrapping_sub` because CYCCNT wraps; correct as long as a tick is serviced at least
    // once per wrap -- the limit documented on `ticks`.
    let total = CYCLE_REM.load(Ordering::Relaxed) as u64 + now.wrapping_sub(last) as u64;
    let add = (total / per) as u32;
    CYCLE_REM.store((total % per) as u32, Ordering::Relaxed);
    TICKS.fetch_add(add, Ordering::Relaxed);
    if add > 1 {
        RECOVERED.fetch_add(add - 1, Ordering::Relaxed);
    }
}

pub(crate) fn count_switch() {
    SWITCHES.fetch_add(1, Ordering::Relaxed);
}

/// Hand the CPU to another ready task, now, without waiting for the tick.
pub fn yield_now() {
    cortex_m::peripheral::SCB::set_pendsv();
}

/// Run something with interrupts masked.
///
/// The kernel's own critical section, and the one a callgate call must hold: the gate
/// resets the CPU if an interrupt lands mid-call.
pub fn critical<R>(f: impl FnOnce() -> R) -> R {
    cortex_m::interrupt::free(|_| f())
}

/// Begin scheduling. Never returns; the first task takes the CPU.
///
/// # Safety
/// Call once, from the reset path, after every task is spawned. Nothing may rely on
/// running on the main stack afterwards -- tasks run on their own.
pub unsafe fn start(syst: &mut cortex_m::peripheral::SYST, hclk_hz: u32) -> ! {
    use cortex_m::peripheral::syst::SystClkSource;

    // SAFETY: setting the priority of two core exceptions, before either can fire.
    unsafe {
        let mut scb = cortex_m::Peripherals::steal().SCB;
        scb.set_priority(cortex_m::peripheral::scb::SystemHandler::PendSV, PENDSV_PRIORITY);
        scb.set_priority(cortex_m::peripheral::scb::SystemHandler::SysTick, SYSTICK_PRIORITY);
    }

    let per_tick = hclk_hz / 1000 * TICK_MS;
    CYCLES_PER_TICK.store(per_tick, Ordering::Relaxed);

    // Is the DWT counter running? A stopped counter reads the same value twice, and a
    // clock driven by it would never advance -- so it is checked here, once, rather than
    // trusted.
    let first = dwt_cycles();
    for _ in 0..10_000 {
        core::hint::spin_loop();
    }
    let second = dwt_cycles();
    DWT_CLOCK.store(first != second, Ordering::Relaxed);
    LAST_CYCLES.store(second, Ordering::Relaxed);

    syst.set_clock_source(SystClkSource::Core);
    syst.set_reload(per_tick - 1);
    syst.clear_current();
    syst.enable_counter();
    syst.enable_interrupt();

    // SAFETY: the scheduler has tasks and the exceptions are armed.
    unsafe { switch::bootstrap() }
}
