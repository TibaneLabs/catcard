//! The menu running as a kernel task, beside a USB service task and a heartbeat.
//!
//! This is the boot path. Once the PIN is in, `session::run` calls [`start_menu`], which
//! starts the preemptive kernel and never returns. The menu, the USB service and the
//! heartbeat each run on their own stack, so a long screen no longer stalls USB and a
//! stack overflow is caught by the switch guard rather than silently corrupting a
//! neighbour.
//!
//! # Why the scheduler starts here and not earlier
//!
//! This unit is RDP=2, and `hw-reference/install-and-usb-transport.md` is explicit that a
//! locked unit running a validly-signed but broken image -- one that "boots, but e.g. no
//! USB" -- has no bootrom recovery. So the scheduler starts only after login, and the
//! failsafe CANCEL check in `main` (held-CANCEL at power-on -> USB recovery) runs first,
//! before any of this: a bad interaction stays recoverable on a dev unit.
//!
//! # The heartbeat log
//!
//! ```text
//! kui t=<ticks> sw=<switches> rec=<recovered> ui=<used>/<size> beat=../.. usb=../.. heap=../.. peak=.. <ok|OVERFLOW>
//! ```
//!
//! Every task's stack use against its size; `Debug -> Kernel` shows the same live. A log
//! that stops updating means a switch broke the reporting task.

use catcard_callgate::Callgate;

use crate::display;

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

/// What `session::run` hands into the menu's kernel task.
///
/// Raw pointers because these objects live in `session::run`'s frame on the main stack,
/// which is abandoned once the kernel starts -- see [`start_menu`] for why they stay valid.
struct UiHandles {
    login: *mut catcard_pin::Login,
    panel: *mut display::Panel,
    matrix: *mut crate::keypad::GpioMatrix,
    drbg: *mut catcard_entropy::HmacDrbg,
    protocol: *mut catcard_entropy::HmacDrbg,
    report: *const crate::BootReport,
    pool: Option<*mut catcard_entropy::EntropyPool>,
}

static mut UI_HANDLES: Option<UiHandles> = None;

/// Start the kernel with the menu, USB and a heartbeat as its tasks. Never returns.
///
/// Called once, from `session::run`, after the PIN is in. The caller's frame is abandoned,
/// not unwound: the login, panel, matrix, DRBGs, boot report and pool live in that frame on
/// the main stack, and once the kernel starts, tasks run on their own stacks while only
/// exception handlers touch the main stack -- growing it downward from where `start` left
/// it, below those frames. `start` never returns, so nothing unwinds them; they are
/// abandoned but intact for the life of the program.
///
/// Eight arguments, one per object handed over: the two generators travel separately
/// because they are separate on purpose (see `Ui::protocol`), and a struct here would be
/// `menu::Session` minus the field this computes itself.
#[allow(clippy::too_many_arguments)]
pub fn start_menu(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    panel: &mut display::Panel,
    matrix: &mut crate::keypad::GpioMatrix,
    drbg: &mut catcard_entropy::HmacDrbg,
    protocol: &mut catcard_entropy::HmacDrbg,
    report: &crate::BootReport,
    pool: Option<&mut catcard_entropy::EntropyPool>,
) -> ! {
    // SAFETY: reads RCC.
    let hclk = unsafe { catcard_hal::clock::hclk_hz() };

    // SAFETY: nothing is scheduling yet; each stack belongs to one task and no entry
    // returns. The handles outlive the program for the reason given on `start_menu`.
    unsafe {
        *core::ptr::addr_of_mut!(UI_GATE) = Some(*gate);
        *core::ptr::addr_of_mut!(UI_HANDLES) = Some(UiHandles {
            login: core::ptr::from_mut(login),
            panel: core::ptr::from_mut(panel),
            matrix: core::ptr::from_mut(matrix),
            drbg: core::ptr::from_mut(drbg),
            protocol: core::ptr::from_mut(protocol),
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
    // A tripped stack guard (the switch checks armed at boot) lands in the
    // same wipe-and-reset a fault does: PendSV is handler mode, where gate 3 is not proven.
    unsafe { catcard_kernel::start(&mut cp.SYST, hclk, crate::panic::wipe_and_reset) }
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
    // SAFETY: written once in `start_menu` before the scheduler started; this is the only
    // reader, and the pointers are valid for the reason given on `start_menu`.
    unsafe {
        let gate = (*core::ptr::addr_of!(UI_GATE)).as_ref();
        let handles = (*core::ptr::addr_of_mut!(UI_HANDLES)).take();
        let (Some(gate), Some(h)) = (gate, handles) else {
            // Cannot happen: `start_menu` fills both before spawning.
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
            protocol: &mut *h.protocol,
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
    // Once five seconds in, then every five minutes -- and at once if a stack overflows.
    // Every five seconds was right for proving the kernel under Debug, but with the kernel
    // running from boot it filled the 2 KB log ring in a few minutes and pushed out the
    // lines anyone reading the log was after.
    const FIRST_MS: u32 = 5_000;
    const EVERY_MS: u32 = 300_000;
    let mut last = 0u32;
    let mut due = FIRST_MS;
    let mut overflow_logged = false;
    loop {
        let now = catcard_kernel::ticks();
        let id = catcard_kernel::TaskId;
        let all_ok = (0..catcard_kernel::count()).all(|i| catcard_kernel::stack_ok(id(i)));
        if now.wrapping_sub(last) >= due || (!all_ok && !overflow_logged) {
            last = now;
            due = EVERY_MS;
            overflow_logged = !all_ok;
            // The heap goes in the same line as the stacks, because they are the same
            // question asked twice: how much of what was reserved is actually used.
            // Reserving the worst case for everything at once is what left the boot
            // stack too small to read a wallet, and these are the numbers that say
            // whether the sizes chosen since are right.
            let (used, peak, total) = crate::heap::stats();
            crate::catlog!(
                "kui t={} sw={} rec={} ui={}/{} beat={}/{} usb={}/{} heap={}/{} peak={} {}",
                now,
                catcard_kernel::switches(),
                catcard_kernel::recovered(),
                catcard_kernel::high_water(id(0)),
                catcard_kernel::stack_len(id(0)),
                catcard_kernel::high_water(id(1)),
                catcard_kernel::stack_len(id(1)),
                catcard_kernel::high_water(id(2)),
                catcard_kernel::stack_len(id(2)),
                used,
                total,
                peak,
                if all_ok { "ok" } else { "OVERFLOW" }
            );
        }
        catcard_kernel::yield_now();
    }
}
