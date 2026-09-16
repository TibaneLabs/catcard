//! A self-test for the preemptive kernel, run from Debug and never from boot.
//!
//! # Why it is not on the boot path
//!
//! This unit is RDP=2, and `hw-reference/install-and-usb-transport.md` is explicit that a
//! locked unit running a **validly-signed but broken** image -- one that "boots, but e.g.
//! no USB" -- has no bootrom recovery: SD recovery only completes a *pending* install,
//! which needs a working firmware to have authorised it. A wrong context switch produces
//! exactly that image, because our USB is polled from the foreground and a hung
//! foreground never enumerates.
//!
//! So the scheduler starts only when someone asks for it. A failure is then cured by a
//! power cycle: the next boot runs the same firmware, which does not start it.
//!
//! # How to read the result
//!
//! The test does not draw its results. One of its tasks pumps USB and writes the counters
//! into the log every half second, so the numbers are read from the host with the same
//! debug channel everything else uses -- while the scheduler is running. What to look for:
//!
//! - `sw` climbing: context switches are happening at all.
//! - `a` and `b` both climbing: two tasks are sharing the CPU, which is the whole claim.
//! - `hw` well under each stack's size, and `ok` rather than `OVERFLOW`.
//!
//! A log that stops updating means the switch broke the task that was writing it.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::display;

/// Counter tasks need almost nothing: they increment and yield.
const SMALL_WORDS: usize = 256;
/// The reporting task formats into the log and drives USB, so it gets room.
const REPORT_WORDS: usize = 1024;

static mut A_STACK: [u32; SMALL_WORDS] = [0; SMALL_WORDS];
static mut B_STACK: [u32; SMALL_WORDS] = [0; SMALL_WORDS];
static mut REPORT_STACK: [u32; REPORT_WORDS] = [0; REPORT_WORDS];

static A_COUNT: AtomicU32 = AtomicU32::new(0);
static B_COUNT: AtomicU32 = AtomicU32::new(0);

/// Two tasks that do nothing but prove they are both running.
extern "C" fn task_a() -> ! {
    loop {
        A_COUNT.fetch_add(1, Ordering::Relaxed);
        catcard_kernel::yield_now();
    }
}

extern "C" fn task_b() -> ! {
    loop {
        B_COUNT.fetch_add(1, Ordering::Relaxed);
        catcard_kernel::yield_now();
    }
}

/// Keeps USB alive and writes the scoreboard to the log.
///
/// USB matters more than the numbers: while this task runs, the host can still reach the
/// device, which is the difference between "the test failed" and "the device is gone".
extern "C" fn task_report() -> ! {
    let mut last = 0u32;
    loop {
        let now = catcard_kernel::ticks();
        if now.wrapping_sub(last) >= 500 {
            last = now;
            crate::catlog!(
                "ktest t={} sw={} a={} b={}",
                now,
                catcard_kernel::switches(),
                A_COUNT.load(Ordering::Relaxed),
                B_COUNT.load(Ordering::Relaxed)
            );
            for i in 0..catcard_kernel::count() {
                let id = catcard_kernel::TaskId(i);
                crate::catlog!(
                    "ktest {} hw={} {}",
                    catcard_kernel::name(id),
                    catcard_kernel::high_water(id),
                    if catcard_kernel::stack_ok(id) {
                        "ok"
                    } else {
                        "OVERFLOW"
                    }
                );
            }
        }
        let _ = crate::usbtask::pump();
    }
}

/// Start the scheduler with three test tasks. Never returns.
///
/// The screen says how to get out, because there is no other way: nothing here stops the
/// kernel. That is deliberate -- a "stop" path would be more code to get wrong than the
/// thing being tested, and a power cycle is already a complete answer.
pub fn run(ui: &mut crate::ui::Ui<'_>) -> ! {
    display::draw(ui.panel, |c| {
        catcard_ui::widgets::message(
            c,
            &display::LAYOUT,
            "Kernel test",
            "running: read over USB",
            "power-cycle to exit",
        );
    });
    crate::catlog!("ktest: starting the scheduler");

    // SAFETY: each stack is this module's alone and is used by exactly one task; the
    // entries never return.
    unsafe {
        let a = core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(A_STACK).cast::<u32>(),
            SMALL_WORDS,
        );
        let b = core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(B_STACK).cast::<u32>(),
            SMALL_WORDS,
        );
        let r = core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(REPORT_STACK).cast::<u32>(),
            REPORT_WORDS,
        );
        let _ = catcard_kernel::spawn("a", a, task_a);
        let _ = catcard_kernel::spawn("b", b, task_b);
        let _ = catcard_kernel::spawn("rep", r, task_report);
    }

    // SAFETY: reads RCC. The tick must be derived from the clock the core actually runs
    // at -- the bootloader hands over at 120 MHz on mk4+ and 80 MHz on mk3, and assuming
    // either one is how a prescaler ends up thirty times wrong.
    let hclk = unsafe { catcard_hal::clock::hclk_hz() };
    // SAFETY: stealing the core peripherals to arm SysTick; the UI is about to stop
    // existing as a context, so nothing else will use them.
    let mut cp = unsafe { cortex_m::Peripherals::steal() };
    // SAFETY: three tasks are spawned and none of their entries returns.
    unsafe { catcard_kernel::start(&mut cp.SYST, hclk) }
}
