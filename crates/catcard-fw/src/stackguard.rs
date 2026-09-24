//! Two stack-overflow defences, armed from *Debug -> Stack guard* and proven there.
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
//! # Why neither is on at boot
//!
//! Every bench unit is RDP=2 with no recovery. A fence programmed one region-size wrong
//! faults on the first push after it; a check that trips on a healthy stack ends the
//! program at the first switch. Either, on the boot path, is a device that never reaches
//! USB again. So both start **off**, are armed from a screen, and are cured by a power
//! cycle; the screen also carries a deliberate-trip probe for each, so the owner can see
//! it fire -- the device wipes and resets -- before anything is trusted to it. They stay
//! Debug actions until proven on every board.
//!
//! # What the screen costs
//!
//! One `AtomicBool` here. The high-water paint is written into the free stack itself, and
//! the armed state is read back from `MPU_CTRL`; nothing else is stored.

use core::sync::atomic::{AtomicBool, Ordering};

use catcard_hal::mpu;
use catcard_ui::keypad::{Event, KEYS, Key};

use crate::display;
use crate::menu::{ask, confirmed, message, wait_for_any_key};
use crate::ui::Ui;

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

/// Bytes under the current MSP left unpainted: room for an exception frame with FP state
/// (104 bytes) is not needed -- a handler runs to completion before the paint loop
/// resumes -- but the margin keeps the loop clear of anything this frame itself spills.
const PAINT_MARGIN: u32 = 64;

/// What the free stack is painted with. Not the kernel's `0xAAAA_AAAA`, so a main-stack
/// word cannot be mistaken for task-stack paint in a memory dump.
const PAINT: u32 = 0x5AFE_57AC;

/// Whether [`paint`] has run. The only state this module keeps.
static PAINTED: AtomicBool = AtomicBool::new(false);

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

/// Fence the floor and turn the MPU on. Stays armed until [`disarm`] or a power cycle.
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

/// Turn the MPU off. The fence does nothing until [`arm`] is called again.
pub fn disarm() {
    // SAFETY: one store to `MPU_CTRL`; unfencing memory cannot fault.
    unsafe { mpu::disarm() };
}

/// Whether the fence is armed. Read from the hardware, so it is right even if the
/// callgate wrapper has just restored it.
pub fn is_armed() -> bool {
    mpu::is_enabled()
}

/// Paint the free main stack, from just above the fence to just under the current MSP.
///
/// Returns the number of words painted, or `None` if there was nothing to paint. Later
/// visits to the screen report the first unpainted word up from the fence -- the deepest
/// the stack has been since -- through [`high_water`].
///
/// Skips the fenced 32 bytes whether or not the fence is armed, so painting and scanning
/// never touch a region that may fault.
pub fn paint() -> Option<u32> {
    let bottom = floor().saturating_add(mpu::GUARD_BYTES);
    let top = msp().saturating_sub(PAINT_MARGIN) & !3;
    if top <= bottom {
        return None;
    }
    let mut p = bottom as *mut u32;
    // SAFETY: every word written lies in `bottom..top`, which is linked RAM (above the
    // last static, and above the fence) and below the live stack: `top` is 64 bytes under
    // this frame's own SP, and nothing runs on the main stack beneath its SP except
    // exception handlers, which run to completion before this loop resumes -- so no store
    // here lands on a frame that is live at the time of the store. Volatile so the writes
    // happen and in order.
    unsafe {
        while (p as u32) < top {
            core::ptr::write_volatile(p, PAINT);
            p = p.add(1);
        }
    }
    PAINTED.store(true, Ordering::Relaxed);
    Some((top - bottom) / 4)
}

/// The deepest address the main stack has reached since [`paint`], and the bytes still
/// unpainted above the fence at that point. `None` until something has been painted.
pub fn high_water() -> Option<(u32, u32)> {
    if !PAINTED.load(Ordering::Relaxed) {
        return None;
    }
    let bottom = floor().saturating_add(mpu::GUARD_BYTES);
    let top = msp();
    let mut p = bottom;
    // SAFETY: reads only, inside `bottom..top`, the same range `paint` wrote.
    unsafe {
        while p < top && core::ptr::read_volatile(p as *const u32) == PAINT {
            p += 4;
        }
    }
    Some((p, p - bottom))
}

/// **Probe.** Read one word at the floor, inside the fence.
///
/// With the fence armed this never returns: the load faults, `MemoryManagement` wipes
/// and resets. Returning at all is the failure the screen reports. The word read is
/// returned so nothing can decide the load was unneeded.
pub fn probe_mpu() -> u32 {
    let floor = floor();
    // SAFETY: `floor` is linked RAM just above the last static; reading it is harmless
    // unless the fence is armed, and faulting then is the point.
    unsafe { core::ptr::read_volatile(floor as *const u32) }
}

/// **Probe.** Corrupt the running task's guard word and ask for a switch.
///
/// With the kernel running and the checks on, the switch finds the wrong word and never
/// comes back. Returning is the failure the screen reports. The wait after the yield is
/// bounded: a few ticks, in case the switch was deferred under a preemption lock.
pub fn probe_canary() {
    catcard_kernel::corrupt_own_guard_for_test();
    catcard_kernel::yield_now();
    let start = catcard_kernel::ticks();
    let mut turns = 1_000_000u32;
    while catcard_kernel::ticks().wrapping_sub(start) < 5 && turns > 0 {
        turns -= 1;
        core::hint::spin_loop();
    }
}

type Line = heapless::String<48>;

/// The screen: the numbers, and the keys that act on them.
///
/// Every action is logged before it happens, so a `ReadLog` taken *before* a probe shows
/// the arm; after a successful probe the log is gone with the rest of RAM, which is what
/// a pass looks like from the host.
pub(crate) fn screen(ui: &mut Ui<'_>) {
    loop {
        draw(ui.panel);
        match wait_key(ui) {
            Key::Cancel => return,
            Key::Digit(1) => match arm() {
                Ok(()) => crate::catlog!("stackguard: MPU fence armed at {:#010x}", floor()),
                Err(e) => {
                    let why = match e {
                        ArmError::NoMpu => "no MPU regions",
                        ArmError::TooClose => "stack too near floor",
                    };
                    crate::catlog!("stackguard: not armed: {}", why);
                    message(ui.panel, "Not armed", why, "any key to go back");
                    wait_for_any_key(ui);
                }
            },
            Key::Digit(6) => {
                disarm();
                crate::catlog!("stackguard: MPU fence disarmed");
            }
            Key::Digit(2) => {
                if !catcard_kernel::running() {
                    message(
                        ui.panel,
                        "No kernel",
                        "start Kernel UI first",
                        "any key to go back",
                    );
                    wait_for_any_key(ui);
                    continue;
                }
                let on = !catcard_kernel::guard_checks();
                catcard_kernel::set_guard_checks(on);
                crate::catlog!(
                    "stackguard: switch checks {}",
                    if on { "on" } else { "off" }
                );
            }
            Key::Digit(3) => match paint() {
                Some(words) => crate::catlog!("stackguard: painted {} words", words),
                None => {
                    message(
                        ui.panel,
                        "Not painted",
                        "no free stack",
                        "any key to go back",
                    );
                    wait_for_any_key(ui);
                }
            },
            Key::Digit(4) => {
                if !is_armed() {
                    message(ui.panel, "Not armed", "press 1 first", "any key to go back");
                    wait_for_any_key(ui);
                    continue;
                }
                ask(
                    ui.panel,
                    "Probe MPU fence?",
                    "device will wipe",
                    "and reset",
                );
                if !confirmed(ui) {
                    continue;
                }
                crate::catlog!("stackguard: probing MPU fence");
                let v = probe_mpu();
                // Only a fence that did not fire gets here.
                crate::catlog!("stackguard: MPU fence did NOT fire ({:#010x})", v);
                message(ui.panel, "FAIL", "fence did not fire", "any key to go back");
                wait_for_any_key(ui);
            }
            Key::Digit(5) => {
                if !catcard_kernel::running() || !catcard_kernel::guard_checks() {
                    message(
                        ui.panel,
                        "Not checking",
                        "needs Kernel UI",
                        "and checks on (2)",
                    );
                    wait_for_any_key(ui);
                    continue;
                }
                ask(ui.panel, "Probe canary?", "device will wipe", "and reset");
                if !confirmed(ui) {
                    continue;
                }
                crate::catlog!("stackguard: probing canary");
                probe_canary();
                // Only a check that did not trip gets here.
                crate::catlog!("stackguard: canary did NOT fire");
                message(
                    ui.panel,
                    "FAIL",
                    "canary did not fire",
                    "any key to go back",
                );
                wait_for_any_key(ui);
            }
            _ => {}
        }
    }
}

/// Six lines, so it fits the 128x64 panels as well as the Q1's.
fn draw(panel: &mut display::Panel) {
    use core::fmt::Write as _;

    let floor = floor();
    let sp = msp();
    let mut lines: heapless::Vec<Line, 6> = heapless::Vec::new();

    let mut l = Line::new();
    let _ = write!(
        l,
        "floor {:04x}_{:04x} mpu {}",
        floor >> 16,
        floor & 0xFFFF,
        mpu::region_count()
    );
    let _ = lines.push(l);

    let mut l = Line::new();
    let _ = write!(
        l,
        "msp {:04x}_{:04x} hd {}",
        sp >> 16,
        sp & 0xFFFF,
        sp.saturating_sub(floor)
    );
    let _ = lines.push(l);

    let mut l = Line::new();
    let _ = write!(
        l,
        "armed {} checks {}{}",
        if is_armed() { "yes" } else { "no" },
        if catcard_kernel::guard_checks() {
            "on"
        } else {
            "off"
        },
        if catcard_kernel::running() {
            ""
        } else {
            " no kernel"
        }
    );
    let _ = lines.push(l);

    let mut l = Line::new();
    match high_water() {
        Some((deepest, free)) => {
            let _ = write!(
                l,
                "hw {:04x}_{:04x} free {}",
                deepest >> 16,
                deepest & 0xFFFF,
                free
            );
        }
        None => {
            let _ = l.push_str("hw: not painted (3)");
        }
    }
    let _ = lines.push(l);

    let mut l = Line::new();
    let _ = l.push_str("1arm 6off 2chk 3paint");
    let _ = lines.push(l);
    let mut l = Line::new();
    let _ = l.push_str("4probe mpu 5probe canary");
    let _ = lines.push(l);

    crate::menu::info(panel, "Stack guard", &lines);
}

/// Block until a key is pressed, servicing USB meanwhile. Cancel wins over anything
/// pressed with it.
fn wait_key(ui: &mut Ui<'_>) -> Key {
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        let _ = crate::usbtask::pump();
        crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
        if let Some(k) = keys
            .iter()
            .copied()
            .find(|&k| k == Key::Cancel)
            .or(keys.first().copied())
        {
            return k;
        }
        display::idle(ui.panel);
    }
}
