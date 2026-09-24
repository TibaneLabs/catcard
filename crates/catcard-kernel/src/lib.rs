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

pub use task::{
    SpawnError, TaskId, corrupt_own_guard_for_test, count, high_water, name, spawn, stack_len,
    stack_ok,
};

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

/// Set once [`start`] has armed the scheduler. There is no way to stop it, so this never
/// clears -- which is what makes it safe to refuse a second start on.
static RUNNING: AtomicBool = AtomicBool::new(false);

/// Whether every context switch reads both guard words -- the outgoing task's before its
/// stack pointer is saved, the incoming task's before its is restored -- and hands an
/// overflow to [`overflow`] instead of switching.
///
/// **Off by default, and off on every boot.** The guard words are otherwise read only
/// when the heartbeat asks (`stack_ok`), which is a report, not a defence: a task that has
/// walked off its stack keeps running until someone looks. Checking at the switch is two
/// volatile loads per switch, but it is also a new way for the scheduler to end the
/// program, and every bench unit is RDP=2 with no recovery. So it is turned on from the
/// Debug self-tests, proven by its probe there, and stays a Debug action until it has been
/// proven on every board (docs/KERNEL.md §5).
static GUARD_CHECKS: AtomicBool = AtomicBool::new(false);

/// Turn the per-switch guard checks on or off. Takes effect at the next switch.
pub fn set_guard_checks(on: bool) {
    GUARD_CHECKS.store(on, Ordering::Relaxed);
}

/// Whether the per-switch guard checks are on.
pub fn guard_checks() -> bool {
    GUARD_CHECKS.load(Ordering::Relaxed)
}

/// Where a tripped guard goes. Given to [`start`] by the firmware -- its wipe-and-reset --
/// so this crate never has to know how the device is cleared, and so nothing here calls
/// `panic!` from PendSV: the panic handler calls bootloader gate 3, which is not proven
/// from handler mode.
static mut ON_OVERFLOW: Option<fn() -> !> = None;

/// A task's stack has walked over its guard word. Never returns.
///
/// Runs inside PendSV, at the lowest priority in the system, with whatever the stack
/// held still in RAM -- the hook's job is to make sure it does not stay there.
pub(crate) fn overflow() -> ! {
    // SAFETY: written once in `start`, before the first switch; this is the only reader.
    match unsafe { *core::ptr::addr_of!(ON_OVERFLOW) } {
        Some(hook) => hook(),
        // Unreachable -- `start` sets the hook before it arms anything -- but a switch
        // that has found an overflow must not resume either task. A reset without a wipe
        // is the weakest answer, and still better than running on a stack that has
        // already written over something else.
        None => cortex_m::peripheral::SCB::sys_reset(),
    }
}

/// Whether the scheduler is running. Starting it twice would re-arm SysTick and run the
/// bootstrap again underneath live tasks.
pub fn running() -> bool {
    RUNNING.load(Ordering::Relaxed)
}

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

/// Nesting depth of [`without_preemption`]. Global rather than per task: while any task
/// holds it no other task runs, so no other task can be the one to change it.
static PREEMPT_LOCK: AtomicU32 = AtomicU32::new(0);
/// A switch fell due while the lock was held, and is owed at release.
static SWITCH_DEFERRED: AtomicBool = AtomicBool::new(false);

/// Run `f` without being switched out.
///
/// For state shared between **tasks** -- the USB service state, for one -- where two tasks
/// holding `&mut` to it at once would be the bug. Interrupts stay enabled, deliberately:
/// the contention is task against task, and masking would turn every hold into a blackout
/// that stalls the keypad edge timestamp and the clock for nothing. It does **not** exclude
/// interrupt handlers; state an ISR also touches still needs a critical section.
///
/// A switch that falls due while this is held is deferred, not dropped: it is pended again
/// on release. Nests. Without a running scheduler it is just a call to `f`, so code that
/// uses it works the same on the normal boot path.
pub fn without_preemption<R>(f: impl FnOnce() -> R) -> R {
    PREEMPT_LOCK.fetch_add(1, Ordering::Relaxed);
    let r = f();
    // If PendSV runs between these two lines it sees the lock free and switches normally;
    // the deferred flag then only causes one harmless extra switch.
    if PREEMPT_LOCK.fetch_sub(1, Ordering::Relaxed) == 1
        && SWITCH_DEFERRED.swap(false, Ordering::Relaxed)
    {
        cortex_m::peripheral::SCB::set_pendsv();
    }
    r
}

/// Whether a task currently holds [`without_preemption`].
pub(crate) fn preemption_locked() -> bool {
    PREEMPT_LOCK.load(Ordering::Relaxed) != 0
}

/// Record that a switch was refused, so release can make it happen.
pub(crate) fn defer_switch() {
    SWITCH_DEFERRED.store(true, Ordering::Relaxed);
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
/// `on_overflow` is where a switch goes when [`guard_checks`] are on and a guard word is
/// wrong. It runs in PendSV and must not return; the firmware passes its wipe-and-reset.
///
/// # Safety
/// Call once, from the reset path, after every task is spawned. Nothing may rely on
/// running on the main stack afterwards -- tasks run on their own.
pub unsafe fn start(
    syst: &mut cortex_m::peripheral::SYST,
    hclk_hz: u32,
    on_overflow: fn() -> !,
) -> ! {
    use cortex_m::peripheral::syst::SystClkSource;

    // Before anything is armed, so no switch can ever find it unset.
    // SAFETY: the only write, before the first switch and with nothing else running.
    unsafe { *core::ptr::addr_of_mut!(ON_OVERFLOW) = Some(on_overflow) };

    // SAFETY: setting the priority of two core exceptions, before either can fire.
    unsafe {
        let mut scb = cortex_m::Peripherals::steal().SCB;
        scb.set_priority(
            cortex_m::peripheral::scb::SystemHandler::PendSV,
            PENDSV_PRIORITY,
        );
        scb.set_priority(
            cortex_m::peripheral::scb::SystemHandler::SysTick,
            SYSTICK_PRIORITY,
        );
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

    RUNNING.store(true, Ordering::Relaxed);
    // SAFETY: the scheduler has tasks and the exceptions are armed.
    unsafe { switch::bootstrap() }
}
