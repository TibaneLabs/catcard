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

use core::sync::atomic::{AtomicU32, Ordering};

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

/// Ticks since the kernel started.
///
/// 32 bits, not 64: this core has no 64-bit atomic, and a `u32` of milliseconds wraps
/// after about seven weeks of continuous power -- longer than this device is ever up.
static TICKS: AtomicU32 = AtomicU32::new(0);

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

/// Ticks since [`start`].
pub fn ticks() -> u32 {
    TICKS.load(Ordering::Relaxed)
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

pub(crate) fn count_tick() {
    TICKS.fetch_add(1, Ordering::Relaxed);
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

    syst.set_clock_source(SystClkSource::Core);
    syst.set_reload(hclk_hz / 1000 * TICK_MS - 1);
    syst.clear_current();
    syst.enable_counter();
    syst.enable_interrupt();

    // SAFETY: the scheduler has tasks and the exceptions are armed.
    unsafe { switch::bootstrap() }
}
