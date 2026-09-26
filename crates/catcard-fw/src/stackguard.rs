//! Two stack-overflow defences: armed on the normal boot-into-menu path, and proven from
//! *Debug -> Self-tests*.
//!
//! # What is being defended
//!
//! The main (MSP) stack starts at the top of linked RAM -- cortex-m-rt's default -- and
//! grows down into `.bss` with nothing between them. It has already overflowed once, into
//! the kernel's task table (`heap.rs`). Each *task* stack has a guard word under it, but
//! until now that word was read only when the heartbeat asked. On this device what sits
//! under a stack can be seed material, and an overflow that nobody notices is the worst
//! failure the design can produce (docs/KERNEL.md §5).
//!
//! # The two defences
//!
//! 1. **The MPU fence.** One no-access region, 32 bytes, at the main stack's floor -- the
//!    higher of `__ebss` and `__euninit`, rounded up. A push that reaches it faults, and
//!    the fault ends in [`panic::wipe_and_reset`](crate::panic::wipe_and_reset). The
//!    register work is `catcard_hal::mpu`; this module decides where and whether.
//! 2. **Per-switch canary checks.** The kernel reads both guard words at every context
//!    switch (`catcard_kernel::set_guard_checks`), and a wrong one goes to the same
//!    wipe-and-reset.
//!
//! # Where they are armed
//!
//! Both are turned on by [`session::run`](crate::session) on the normal boot-into-menu
//! path, immediately before the kernel menu starts -- which is strictly *after* the
//! failsafe CANCEL check in `main`. Holding CANCEL at power-on therefore always reaches the
//! USB recovery reflash before the fence or the canary is live, so a bad interaction with
//! either stays recoverable on a dev unit. Arming is best-effort: if the fence cannot be
//! programmed (no MPU, or the stack already sits within [`ARM_MARGIN`] of the floor) the
//! boot logs it and continues rather than blocking or panicking.
//!
//! This was reversed from an earlier design where both stayed off at boot on every board,
//! armed only from the self-test screen: the defences are proven on hardware now (mk4,
//! mk5, Q1), so they default on. The floor/arm machinery is compiled into every build,
//! including a `--no-default-features` ship build; only the Debug *Self-tests* screens and
//! the deliberate-trip probes below live behind `usb-debug-mem`, the same gate the
//! peek/poke tools use.

use catcard_hal::mpu;

unsafe extern "C" {
    // Provided by cortex-m-rt's linker script (`link.x`): the end of `.bss`, and of
    // `.uninit` which it lays out above `.bss`. Only their addresses are used.
    static mut __ebss: u32;
    static mut __euninit: u32;
}

/// How much main stack must lie between the floor and the current MSP before the fence
/// is armed. A stack already this close to the floor would trip the moment a screen
/// opened, which would be a true report of a real problem -- but not one the owner asked
/// for by pressing a key on a diagnostic screen.
const ARM_MARGIN: u32 = 256;

/// The main stack's floor: the higher section end, rounded up to the fence size.
///
/// Computed from the linker symbols, never hardcoded: the map moves with every build.
pub fn floor() -> u32 {
    // Only the addresses of the two linker symbols are taken; neither is read.
    let ebss = core::ptr::addr_of!(__ebss) as u32;
    let euninit = core::ptr::addr_of!(__euninit) as u32;
    mpu::guard_floor(ebss, euninit)
}

/// The main stack pointer, now.
///
/// From a kernel task this is the *handler* stack's resting point rather than the caller's
/// frame -- tasks run on PSP -- and everything below it is still dead memory, which is
/// all the callers here rely on.
pub fn msp() -> u32 {
    cortex_m::register::msp::read()
}

/// Why the fence could not be armed. Each is shown on the screen.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ArmError {
    /// `MPU_TYPE.DREGION` is zero.
    NoMpu,
    /// The stack is already within [`ARM_MARGIN`] of the floor, or below it.
    TooClose,
}

/// Fence the floor and turn the MPU on. Stays armed until a power cycle.
///
/// Refuses, rather than arming, if there is no MPU to program or the stack is already too
/// close to the floor. Interrupts are masked across the register writes so no handler
/// runs on a half-programmed map.
pub fn arm() -> Result<(), ArmError> {
    let floor = floor();
    if mpu::region_count() == 0 {
        return Err(ArmError::NoMpu);
    }
    if msp() < floor.saturating_add(ARM_MARGIN) {
        return Err(ArmError::TooClose);
    }
    cortex_m::interrupt::free(|_| {
        // SAFETY: `floor` is above every static (both section ends, rounded up) and at
        // least `ARM_MARGIN` below the live stack -- checked just above -- so nothing
        // uses the 32 bytes fenced. `MemoryManagement` is defined in `interrupts.rs`
        // and never returns.
        unsafe {
            match mpu::arm_guard(floor) {
                Ok(()) => {}
                Err(mpu::Error::NoRegions) => return Err(ArmError::NoMpu),
                // Cannot happen: `guard_floor` rounds to the region size.
                Err(mpu::Error::Misaligned) => return Err(ArmError::TooClose),
            }
            mpu::enable_memfault();
        }
        Ok(())
    })
}
