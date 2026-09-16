//! A self-test for the preemptive kernel, run from Debug and never from boot.
//!
//! # Why it is not on the boot path
//!
//! This unit is RDP=2, and `hw-reference/install-and-usb-transport.md` is explicit that a
//! locked unit running a **validly-signed but broken** image -- one that "boots, but e.g.
//! no USB" -- has no bootrom recovery. A wrong context switch produces exactly that image,
//! because our USB is polled from the foreground and a hung foreground never enumerates.
//! So the scheduler starts only when someone asks for it, and a failure is cured by a
//! power cycle: the next boot does not start it.
//!
//! # What it proves
//!
//! The first version showed preemption, yielding and stack integrity. This one goes after
//! the three things that did not exercise:
//!
//! - **Floating-point context.** Two tasks hold float values across switches, in disjoint
//!   ranges, and check them every round; `fp_saves` proves the switch's FPU path actually
//!   ran rather than being skipped because nobody touched the FPU.
//! - **A callgate call under the scheduler.** A task reads SE1's TRNG through the gate,
//!   which masks interrupts for the duration. The kernel recovers the ticks that fall
//!   inside from the DWT cycle counter, so `t` should track `ms` (real time, measured
//!   independently here) and `rec` shows how much was recovered.
//! - **A device interrupt preempting a task.** `edge` is the keypad's edge latch; press a
//!   key during the test and it changes, which only the EXTI handler can do.
//!
//! # Reading the log
//!
//! ```text
//! kt t=<ticks> ms=<real> rec=<ticks recovered> sw=<switches> fp=<fp saves> edge=<latch>
//! kf a=<rounds>/<bad> b=<rounds>/<bad>
//! kg ok=<gate calls> err=<gate errors>  hw fa=.. fb=.. g=.. r=.. <ok|OVERFLOW>
//! ```
//!
//! Pass: `fp` climbing, both `bad` counts zero, `ok` climbing with `err` zero, `t` within
//! a few ticks of `ms` with `rec` climbing, and every stack under its size. A log that stops updating means a switch broke the reporting task.

use core::sync::atomic::{AtomicU32, Ordering};

use catcard_callgate::Callgate;
use catcard_callgate::abi::RngSource;

use crate::display;

/// Float tasks keep a few frames of locals; room to spare.
const FLOAT_WORDS: usize = 512;
/// The gate task holds a 33-byte buffer and makes the call.
const GATE_WORDS: usize = 512;
/// The reporting task formats into the log and drives USB.
const REPORT_WORDS: usize = 1024;

static mut FA_STACK: [u32; FLOAT_WORDS] = [0; FLOAT_WORDS];
static mut FB_STACK: [u32; FLOAT_WORDS] = [0; FLOAT_WORDS];
static mut GATE_STACK: [u32; GATE_WORDS] = [0; GATE_WORDS];
static mut REPORT_STACK: [u32; REPORT_WORDS] = [0; REPORT_WORDS];

static FA_ROUNDS: AtomicU32 = AtomicU32::new(0);
static FA_BAD: AtomicU32 = AtomicU32::new(0);
static FB_ROUNDS: AtomicU32 = AtomicU32::new(0);
static FB_BAD: AtomicU32 = AtomicU32::new(0);
static GATE_OK: AtomicU32 = AtomicU32::new(0);
static GATE_ERR: AtomicU32 = AtomicU32::new(0);

/// The gate, handed across to its task.
static mut GATE: Option<Callgate> = None;
/// HCLK in Hz, for turning cycle counts into milliseconds.
static mut HCLK: u32 = 0;

/// A call the optimiser cannot see through, so values live across it must survive in the
/// registers the ABI makes callee-saved -- `s16-s31` for floats -- or on the stack.
#[inline(never)]
fn switch_point() {
    catcard_kernel::yield_now();
}

/// Busy float arithmetic long enough to be preempted by SysTick mid-loop. Every term is a
/// half-integer below 2^23, so the sum is exact and has one right answer.
#[inline(never)]
fn busy_sum() -> f32 {
    let mut acc = 0.0f32;
    for i in 0..2000u32 {
        acc += i as f32 * 0.5;
    }
    acc
}

/// One round: carry eight float values through sixteen switches, then check them.
///
/// **The switch is inside the loop, on purpose.** A first version built the values and
/// then switched once, and the disassembly showed the optimiser had hoisted every
/// comparison ahead of the call -- the comparisons are pure, so it evaluated them first and
/// carried only a boolean across the switch. That tested almost nothing. With the switch
/// in the loop, each iteration's addition depends on values that had to survive the
/// previous switch, so they are loop-carried across the call and must live in the
/// callee-saved `s16-s31` (or the task's stack) -- exactly the registers the switch saves.
///
/// Every step is an exact float operation, so any difference is corruption, not rounding.
#[inline(never)]
fn float_round(base: f32) -> bool {
    let mut v = (base, base, base, base, base, base, base, base);
    for _ in 0..16 {
        v.0 += 1.0;
        v.1 += 2.0;
        v.2 += 3.0;
        v.3 += 4.0;
        v.4 += 5.0;
        v.5 += 6.0;
        v.6 += 7.0;
        v.7 += 8.0;
        switch_point();
    }
    let sum = busy_sum();
    let at = |k: f32| base + 16.0 * k;
    v.0 == at(1.0)
        && v.1 == at(2.0)
        && v.2 == at(3.0)
        && v.3 == at(4.0)
        && v.4 == at(5.0)
        && v.5 == at(6.0)
        && v.6 == at(7.0)
        && v.7 == at(8.0)
        && sum == 999_500.0
}

/// Float task A: positive range, so a value leaking in from B is obviously wrong.
extern "C" fn task_fa() -> ! {
    let mut n = 0u32;
    loop {
        let base = 1000.0 + (n % 1000) as f32;
        if !float_round(base) {
            FA_BAD.fetch_add(1, Ordering::Relaxed);
        }
        FA_ROUNDS.fetch_add(1, Ordering::Relaxed);
        n = n.wrapping_add(1);
    }
}

/// Float task B: negative range.
extern "C" fn task_fb() -> ! {
    let mut n = 0u32;
    loop {
        let base = -5000.0 - (n % 1000) as f32;
        if !float_round(base) {
            FB_BAD.fetch_add(1, Ordering::Relaxed);
        }
        FB_ROUNDS.fetch_add(1, Ordering::Relaxed);
        n = n.wrapping_add(1);
    }
}

/// Calls the bootloader every 50 ticks while the scheduler runs.
///
/// The gate masks interrupts for the whole call, so SysTick cannot preempt it -- which is
/// the rule, since an interrupt inside firewall code resets the CPU. The ticks that fall
/// due inside are recovered afterwards from the cycle counter; `t` against `ms` in the log
/// is the check that they were.
extern "C" fn task_gate() -> ! {
    // SAFETY: written once in `run` before the scheduler started; this task only reads.
    let gate = unsafe { *core::ptr::addr_of!(GATE) };
    let mut last = 0u32;
    loop {
        let now = catcard_kernel::ticks();
        if let Some(gate) = gate
            && catcard_board::BOARD.has_callgate_se_rng
            && now.wrapping_sub(last) >= 50
        {
            // On this task's stack, which is a static inside SRAM1 -- where the gate
            // requires its buffer to be.
            let mut buf = [0u8; 33];
            // SAFETY: a TRNG read with a buffer the gate range-checks.
            match unsafe { gate.se_rng(RngSource::Se1, &mut buf) } {
                Ok(_) => GATE_OK.fetch_add(1, Ordering::Relaxed),
                Err(_) => GATE_ERR.fetch_add(1, Ordering::Relaxed),
            };
            // The period runs from when the call *ended*, not when it began. Each call
            // holds interrupts for ~99 ms, longer than the 50-tick period, and once the
            // kernel clock learned to count through masked windows a period measured
            // from the start was already over when the call returned. The task then
            // called back to back and kept interrupts masked ~97% of the time -- only
            // ~600 of 20 000 ticks arrived as interrupts, and the float tasks were
            // starved to a tenth of their rounds. Measuring from the end guarantees the
            // rest of the system 50 ticks between calls, however long a call takes.
            last = catcard_kernel::ticks();
        }
        catcard_kernel::yield_now();
    }
}

/// Keeps USB alive and writes the scoreboard to the log.
///
/// USB matters more than the numbers: while this runs, the host can still reach the
/// device, which is the difference between "the test failed" and "the device is gone".
extern "C" fn task_report() -> ! {
    // SAFETY: written once in `run` before the scheduler started.
    let per_ms = (unsafe { *core::ptr::addr_of!(HCLK) } / 1000).max(1);
    let mut last_tick = 0u32;
    let mut last_cycles = catcard_hal::dwt::cycles();
    let mut real_ms = 0u32;
    loop {
        let now = catcard_kernel::ticks();
        if now.wrapping_sub(last_tick) >= 500 {
            last_tick = now;
            // Accumulated per report so the cycle counter's 35-second wrap never matters.
            let cycles = catcard_hal::dwt::cycles();
            real_ms = real_ms.wrapping_add(cycles.wrapping_sub(last_cycles) / per_ms);
            last_cycles = cycles;

            crate::catlog!(
                "kt t={} ms={} rec={} sw={} fp={} edge={:#x}",
                now,
                real_ms,
                catcard_kernel::recovered(),
                catcard_kernel::switches(),
                catcard_kernel::fp_saves(),
                crate::keypad::edge_latch()
            );
            crate::catlog!(
                "kf a={}/{} b={}/{}",
                FA_ROUNDS.load(Ordering::Relaxed),
                FA_BAD.load(Ordering::Relaxed),
                FB_ROUNDS.load(Ordering::Relaxed),
                FB_BAD.load(Ordering::Relaxed)
            );
            let hw = |i| catcard_kernel::high_water(catcard_kernel::TaskId(i));
            let all_ok = (0..catcard_kernel::count())
                .all(|i| catcard_kernel::stack_ok(catcard_kernel::TaskId(i)));
            crate::catlog!(
                "kg ok={} err={}  hw fa={} fb={} g={} r={} {}",
                GATE_OK.load(Ordering::Relaxed),
                GATE_ERR.load(Ordering::Relaxed),
                hw(0),
                hw(1),
                hw(2),
                hw(3),
                if all_ok { "ok" } else { "OVERFLOW" }
            );
        }
        let _ = crate::usbtask::pump();
    }
}

/// Start the scheduler with the test tasks. Never returns.
///
/// Nothing here stops the kernel, deliberately: a "stop" path would be more code to get
/// wrong than the thing being tested, and a power cycle is already a complete answer.
pub fn run(gate: &Callgate, ui: &mut crate::ui::Ui<'_>) {
    if refuse_second_start(ui) {
        return;
    }
    display::draw(ui.panel, |c| {
        catcard_ui::widgets::message(
            c,
            &display::LAYOUT,
            "Kernel test",
            "running: read over USB",
            "power-cycle to exit",
        );
    });
    crate::catlog!("ktest: starting the scheduler (fpu, gate, edge)");

    // SAFETY: reads RCC. The tick must come from the clock the core actually runs at.
    let hclk = unsafe { catcard_hal::clock::hclk_hz() };

    // SAFETY: the boot-path equivalent for this test: nothing is scheduling yet, each
    // stack is used by exactly one task, and no entry returns.
    unsafe {
        *core::ptr::addr_of_mut!(GATE) = Some(*gate);
        *core::ptr::addr_of_mut!(HCLK) = hclk;
        let fa = core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(FA_STACK).cast::<u32>(),
            FLOAT_WORDS,
        );
        let fb = core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(FB_STACK).cast::<u32>(),
            FLOAT_WORDS,
        );
        let g = core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(GATE_STACK).cast::<u32>(),
            GATE_WORDS,
        );
        let r = core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(REPORT_STACK).cast::<u32>(),
            REPORT_WORDS,
        );
        // Order matters for the log: the report names stacks by these indices.
        let _ = catcard_kernel::spawn("fa", fa, task_fa);
        let _ = catcard_kernel::spawn("fb", fb, task_fb);
        let _ = catcard_kernel::spawn("gate", g, task_gate);
        let _ = catcard_kernel::spawn("rep", r, task_report);
    }

    // SAFETY: stealing the core peripherals to arm SysTick; the UI is about to stop
    // existing as a context, so nothing else will use them.
    let mut cp = unsafe { cortex_m::Peripherals::steal() };
    // SAFETY: every task is spawned and none of their entries returns.
    unsafe { catcard_kernel::start(&mut cp.SYST, hclk) }
}

/// Say no if the scheduler is already running, and report whether it did.
///
/// Only reachable from the menu running *as* a kernel task: choosing a kernel action from
/// there would re-arm SysTick and run the bootstrap again underneath live tasks.
fn refuse_second_start(ui: &mut crate::ui::Ui<'_>) -> bool {
    if !catcard_kernel::running() {
        return false;
    }
    display::draw(ui.panel, |c| {
        catcard_ui::widgets::message(
            c,
            &display::LAYOUT,
            "Kernel",
            "already running",
            "any key to go back",
        );
    });
    crate::menu::wait_for_any_key(ui);
    true
}

// ---------------------------------------------------------------------------------------
// The menu as a kernel task
// ---------------------------------------------------------------------------------------

/// The menu task's stack. The deepest screens put kilobytes on it -- the log viewer's 2 KB
/// buffer, ~1.1 KB of seed-word lines, 48 SD browser entries -- so it is sized well past
/// that, and Debug -> Kernel shows how deep it has really been.
const UI_WORDS: usize = 8192;
/// The heartbeat formats a log line on its stack every few seconds.
const BEAT_WORDS: usize = 512;
/// The USB service task handles every host request, including a staged upgrade's
/// signature check at the end -- elliptic-curve arithmetic, the likeliest deep path here.
/// Sized generously and reported in the heartbeat until it has been measured.
const USB_WORDS: usize = 4096;

static mut UI_STACK: [u32; UI_WORDS] = [0; UI_WORDS];
static mut BEAT_STACK: [u32; BEAT_WORDS] = [0; BEAT_WORDS];
static mut USB_STACK: [u32; USB_WORDS] = [0; USB_WORDS];

/// The gate, held by value so the menu task can borrow it for the rest of the program.
static mut UI_GATE: Option<Callgate> = None;

/// What the running menu hands to its replacement.
///
/// Raw pointers because these objects live in stack frames of the session that is about
/// to stop running -- see [`run_ui`] for why they stay valid.
struct UiHandles {
    login: *mut catcard_pin::Login,
    panel: *mut display::Panel,
    matrix: *mut crate::keypad::GpioMatrix,
    drbg: *mut catcard_entropy::HmacDrbg,
    report: *const crate::BootReport,
    pool: Option<*mut catcard_entropy::EntropyPool>,
}

static mut UI_HANDLES: Option<UiHandles> = None;

/// Run the menu as a kernel task, beside a heartbeat. Does not return once it starts.
///
/// The menu is restarted, not migrated: a fresh `menu::run` in its own task, on the same
/// peripherals and login the current one holds. The old loop simply never runs again.
///
/// **Why the handed-over pointers stay valid.** The login, panel, matrix, DRBG, boot report
/// and pool live in `session::run`'s frame on the main stack. Once the kernel starts, tasks
/// run on their own stacks and only exception handlers use the main stack -- and they grow
/// it downward from where `start` left it, which is *below* those frames. Nothing unwinds
/// the main stack either, because `start` never returns. So those frames are abandoned but
/// intact for the life of the program.
pub fn run_ui(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut crate::ui::Ui<'_>,
    report: &crate::BootReport,
    pool: Option<&mut catcard_entropy::EntropyPool>,
) {
    if refuse_second_start(ui) {
        return;
    }
    display::draw(ui.panel, |c| {
        catcard_ui::widgets::message(
            c,
            &display::LAYOUT,
            "Kernel UI",
            "menu as a kernel task",
            "power-cycle to exit",
        );
    });
    // The restarted menu gets a fresh keypad scanner, which would read the key still held
    // from choosing this item as a brand-new press on the main menu.
    crate::menu::wait_for_release(ui);
    crate::catlog!("ktest: the menu as a kernel task");

    // SAFETY: reads RCC.
    let hclk = unsafe { catcard_hal::clock::hclk_hz() };

    // SAFETY: nothing is scheduling yet; each stack belongs to one task and no entry
    // returns. The handles outlive the program for the reason given above.
    unsafe {
        *core::ptr::addr_of_mut!(UI_GATE) = Some(*gate);
        *core::ptr::addr_of_mut!(UI_HANDLES) = Some(UiHandles {
            login: core::ptr::from_mut(login),
            panel: core::ptr::from_mut(&mut *ui.panel),
            matrix: core::ptr::from_mut(&mut *ui.matrix),
            drbg: core::ptr::from_mut(&mut *ui.drbg),
            report: core::ptr::from_ref(report),
            pool: pool.map(core::ptr::from_mut),
        });
        let u = core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(UI_STACK).cast::<u32>(),
            UI_WORDS,
        );
        let b = core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(BEAT_STACK).cast::<u32>(),
            BEAT_WORDS,
        );
        let usb = core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(USB_STACK).cast::<u32>(),
            USB_WORDS,
        );
        // Order matters: the heartbeat names stacks by these indices.
        let _ = catcard_kernel::spawn("ui", u, ui_task);
        let _ = catcard_kernel::spawn("beat", b, beat_task);
        let _ = catcard_kernel::spawn("usb", usb, usb_task);
    }

    // From here every `usbtask::pump()` in the menu's waiting loops is a no-op, and only
    // the USB task polls. Set before `start` so there is no moment where both do.
    crate::usbtask::start_service();

    // SAFETY: stealing the core peripherals to arm SysTick.
    let mut cp = unsafe { cortex_m::Peripherals::steal() };
    // SAFETY: every task is spawned and no entry returns.
    unsafe { catcard_kernel::start(&mut cp.SYST, hclk) }
}

/// Services USB -- and with it the activity light and the power button -- every
/// scheduling round, whatever the menu is doing.
///
/// Polls once and yields. The menu's busy loops run for a whole tick before being
/// preempted, so this is reached about once a millisecond, which is as often as the
/// menu's own waiting loops used to poll.
extern "C" fn usb_task() -> ! {
    loop {
        let _ = crate::usbtask::service();
        catcard_kernel::yield_now();
    }
}

/// The ordinary menu, on a stack of its own.
extern "C" fn ui_task() -> ! {
    // SAFETY: written once in `run_ui` before the scheduler started; this is the only
    // reader, and the pointers are valid for the reason given on `run_ui`.
    unsafe {
        let gate = (*core::ptr::addr_of!(UI_GATE)).as_ref();
        let handles = (*core::ptr::addr_of_mut!(UI_HANDLES)).take();
        let (Some(gate), Some(h)) = (gate, handles) else {
            // Cannot happen: `run_ui` fills both before spawning.
            loop {
                cortex_m::asm::wfi();
            }
        };
        let login = &mut *h.login;
        let no_seed = matches!(login.step(), catcard_pin::Step::In { zero_secret: true });
        crate::menu::run(crate::menu::Session {
            gate,
            login,
            panel: &mut *h.panel,
            matrix: &mut *h.matrix,
            drbg: &mut *h.drbg,
            report: &*h.report,
            no_seed,
            pool: h.pool.map(|p| &mut *p),
        })
    }
}

/// Logs the scheduler's health every five seconds and otherwise gives the CPU straight back.
///
/// A second task that logs is also the test of the log itself: the menu logs constantly, and
/// before `write_fmt` masked its copy into the ring, two tasks logging could interleave.
extern "C" fn beat_task() -> ! {
    let mut last = 0u32;
    loop {
        let now = catcard_kernel::ticks();
        if now.wrapping_sub(last) >= 5000 {
            last = now;
            let id = catcard_kernel::TaskId;
            let all_ok =
                (0..catcard_kernel::count()).all(|i| catcard_kernel::stack_ok(id(i)));
            crate::catlog!(
                "kui t={} sw={} rec={} ui={}/{} beat={}/{} usb={}/{} {}",
                now,
                catcard_kernel::switches(),
                catcard_kernel::recovered(),
                catcard_kernel::high_water(id(0)),
                catcard_kernel::stack_len(id(0)),
                catcard_kernel::high_water(id(1)),
                catcard_kernel::stack_len(id(1)),
                catcard_kernel::high_water(id(2)),
                catcard_kernel::stack_len(id(2)),
                if all_ok { "ok" } else { "OVERFLOW" }
            );
        }
        catcard_kernel::yield_now();
    }
}
