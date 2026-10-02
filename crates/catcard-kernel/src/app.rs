//! Running an app: unprivileged code in its own memory, entered and left through `SVC`.
//!
//! See docs/APPS.md for the design. In short:
//!
//! - [`run`] is called by a privileged task (the UI task). It saves that task's
//!   callee-saved registers, then `SVC ENTER` switches the same task to the app: a fresh
//!   exception frame on the app's own stack, `CONTROL.nPRIV` set, and an exception return
//!   into the app's entry point.
//! - The app asks for things with `SVC CALL`. The handler does not run the service -- `SVC`
//!   sits at the top of the priority order, and a service that drew a frame there would stall
//!   every interrupt. It drops privilege back, points the task at a trampoline on the task's
//!   own stack, and returns; the trampoline runs the firmware's dispatcher as ordinary,
//!   preemptible task code, then `SVC RETURN` puts the result in the app's `r0` and resumes
//!   it unprivileged.
//! - `SVC EXIT`, or a fault taken while the app (not a service) was running, puts the task
//!   back exactly where [`run`] left it, and [`run`] returns how the app ended.
//!
//! What the app may touch is the firmware's business (the MPU regions it programs before
//! [`run`]); this module only moves the CPU between the two privilege levels.
//!
//! **Nothing here runs until the first [`run`].** The context switch saves and restores the
//! privilege bit per task only once [`seen`] is true, so until an app has been entered the
//! whole change to the boot path is one atomic load per switch. The `SVC` and fault entries
//! are only reached by an `SVC` instruction or by a fault the firmware has enabled.
//!
//! Sources, all ARMv7-M ARM (DDI 0403E) [C]:
//! - exception entry and return, the basic and extended frames, `EXC_RETURN` values:
//!   §B1.5.6–§B1.5.8;
//! - `CONTROL.nPRIV` (bit 0), written only when privileged, `ISB` after: §B1.4.4;
//! - lazy floating-point state preservation (`FPCCR.LSPACT`, `FPCAR`), and that any
//!   floating-point instruction completes a pending one: §B1.5.7, §A2.5;
//! - the `SVC` immediate is the low byte of the 16-bit `SVC` encoding at `PC - 2`: §A7.7.175.

use core::arch::naked_asm;
use core::sync::atomic::{AtomicBool, Ordering};

/// `SVC` numbers. The first and last are only accepted from privileged code, the middle
/// two only from an app that is running and not inside a service.
pub const SVC_ENTER: u8 = 0;
/// From the app: finished, `r0` is its exit code.
pub const SVC_EXIT: u8 = 1;
/// From the app: run service `r0` with arguments `r1`-`r3`; the result comes back in `r0`.
pub const SVC_CALL: u8 = 2;
/// From the trampoline: the service is done, `r0` is its result.
pub const SVC_RETURN: u8 = 3;

/// Thread mode, process stack, basic frame. Source: §B1.5.8 Table B1-8 [C]
const EXC_RETURN_THREAD_PSP: u32 = 0xFFFF_FFFD;
/// `xPSR` with only the Thumb bit set: what a fresh frame starts with. §B1.4.2 [C]
const XPSR_THUMB: u32 = 0x0100_0000;
/// Words in a basic exception frame: r0-r3, r12, LR, PC, xPSR.
const FRAME: u32 = 8;

/// Whether an app has ever been entered. Read by the context switch, which only then
/// saves and restores the privilege bit per task. Never cleared: once a task has run
/// unprivileged, every switch has to know whose privilege it is restoring.
static SEEN: AtomicBool = AtomicBool::new(false);

/// Whether any app has been entered since boot (see [`SEEN`]).
#[inline(always)]
pub(crate) fn seen() -> bool {
    SEEN.load(Ordering::Relaxed)
}

/// How an app ended.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Exit {
    /// It called `SVC EXIT` with this code.
    Code(i32),
    /// It faulted, or broke the `SVC` rules. `pc` is where it was, `cfsr` the fault status,
    /// `addr` the faulting data address when the status says it is valid (else 0).
    Fault { pc: u32, cfsr: u32, addr: u32 },
}

/// The service dispatcher, given by the firmware: `(service, a, b, c) -> result`.
///
/// Runs in thread mode, privileged, on the launching task's stack, preemptible like any
/// other task code. It is the firmware's job to treat every argument as hostile: an
/// address from the app must be checked against the app's own memory before it is used.
pub type Dispatch = extern "C" fn(u32, u32, u32, u32) -> u32;

/// Everything the handlers share. Touched only from the `SVC` and fault handlers, which do
/// not preempt one another (both run above every other priority), and by [`run`] before
/// it enters and after it returns, when no app is running.
struct State {
    /// An app has been entered and has not ended.
    active: bool,
    /// The app is waiting on a service: the trampoline is running privileged.
    in_service: bool,
    /// The launcher's exception frame at `SVC ENTER`, and the `EXC_RETURN` it came with:
    /// where [`run`] is resumed when the app ends.
    launch_frame: u32,
    launch_exc: u32,
    /// The app's frame and `EXC_RETURN` at `SVC CALL`: where it resumes after a service.
    app_frame: u32,
    app_exc: u32,
    /// How it ended, read by [`run`] after the launcher is resumed.
    exit: Exit,
    dispatch: Option<Dispatch>,
}

static mut STATE: State = State {
    active: false,
    in_service: false,
    launch_frame: 0,
    launch_exc: 0,
    app_frame: 0,
    app_exc: 0,
    exit: Exit::Code(0),
    dispatch: None,
};

/// Run an app until it exits or faults.
///
/// `entry` is its first instruction (Thumb bit optional), `stack_top` the top of its
/// stack (aligned down to 8 here), `arg` arrives in its `r0`. `dispatch` serves its
/// `SVC CALL`s.
///
/// # Safety
///
/// - Called from thread mode, privileged, with interrupts enabled (an `SVC` with them
///   masked escalates to HardFault), on a task stack -- not before the scheduler starts.
/// - `entry` and the stack must be in memory the firmware has made reachable to
///   unprivileged code, and nothing the app can reach may hold a secret.
/// - The firmware's MemManage, BusFault, UsageFault and HardFault handlers must hand an
///   app's faults to [`fault_entry`], or a fault ends the device instead of the app.
pub unsafe fn run(entry: u32, stack_top: u32, arg: u32, dispatch: Dispatch) -> Exit {
    // SAFETY: no app is running, so no handler is reading this.
    unsafe {
        let s = &mut *core::ptr::addr_of_mut!(STATE);
        s.dispatch = Some(dispatch);
        s.exit = Exit::Code(0);
    }
    // SAFETY: the caller's contract; `enter` restores every callee-saved register itself.
    unsafe { enter(entry | 1, stack_top & !7, arg) };
    // SAFETY: the app has ended, so no handler is touching this.
    unsafe { (*core::ptr::addr_of!(STATE)).exit }
}

/// Save what the app will overwrite, then `SVC ENTER`. Returns when the app has ended.
///
/// The app runs on this task, so it is free to use every register; `r4`-`r11` and
/// `s16`-`s31` are this caller's, and are pushed here and popped after.
#[unsafe(naked)]
unsafe extern "C" fn enter(entry: u32, stack_top: u32, arg: u32) {
    naked_asm!(
        ".fpu fpv4-sp-d16",
        "push  {{r4-r11, lr}}",
        "vpush {{s16-s31}}",
        "svc   #0",
        "vpop  {{s16-s31}}",
        "pop   {{r4-r11, pc}}",
    )
}

/// Where a service runs: privileged thread mode, on the launching task's stack.
///
/// The arguments arrive in `r0`-`r3` from the frame the `SVC CALL` handler built. The
/// dispatcher preserves `r4`-`r11` and `s16`-`s31` as any AAPCS function does, so the app
/// finds its own when it resumes.
#[unsafe(naked)]
unsafe extern "C" fn trampoline() {
    naked_asm!(
        "bl    {dispatch}",
        "svc   #3",
        // Never reached: `SVC RETURN` does not come back here.
        "udf   #0",
        dispatch = sym dispatch_entry,
    )
}

extern "C" fn dispatch_entry(id: u32, a: u32, b: u32, c: u32) -> u32 {
    // SAFETY: written by `run` before the app was entered; nothing writes it meanwhile.
    match unsafe { (*core::ptr::addr_of!(STATE)).dispatch } {
        Some(f) => f(id, a, b, c),
        None => u32::MAX,
    }
}

/// `SVCall`. Finishes any pending lazy floating-point save -- the frame it targets may be
/// about to be left behind -- then hands the frame to [`svc_rust`] and returns with the
/// `EXC_RETURN` that chose.
///
/// Named rather than attributed, like `PendSV`, because a naked function cannot be wrapped;
/// the vector table's entry is weak, so this overrides it.
///
/// # Safety
/// Only the hardware calls this, as the `SVCall` exception.
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SVCall() {
    naked_asm!(
        ".fpu fpv4-sp-d16",
        // Extended frame (EXC_RETURN bit 4 clear): a floating-point instruction completes
        // the lazy save into it before anything moves PSP. §B1.5.7 [C]
        "tst   lr, #0x10",
        "it    eq",
        "vmoveq.f32 s0, s0",
        "tst   lr, #4",
        "ite   eq",
        "mrseq r0, msp",
        "mrsne r0, psp",
        "mov   r1, lr",
        "bl    {rust}",
        "bx    r0",
        rust = sym svc_rust,
    )
}

/// Read `CONTROL.nPRIV` for thread mode. Handler mode is always privileged; the bit is
/// what thread mode will run as.
#[inline(always)]
fn thread_unprivileged() -> bool {
    cortex_m::register::control::read().npriv() == cortex_m::register::control::Npriv::Unprivileged
}

/// Called whenever thread mode is about to run at a different privilege -- entering or
/// leaving an app, a service, or switching to or from the app's task -- with whether it
/// will be unprivileged. The firmware turns the app's MPU regions on for `true` and off for
/// `false`, so services, other tasks and callgate calls run with the MPU as they always
/// have. Runs in handler mode.
static mut ON_PRIVILEGE: Option<fn(bool)> = None;

/// Install the privilege hook (see [`ON_PRIVILEGE`]). Before the first [`run`].
///
/// # Safety
/// No app may be running.
pub unsafe fn set_privilege_hook(f: fn(bool)) {
    // SAFETY: the caller's contract: nothing reads it concurrently.
    unsafe { *core::ptr::addr_of_mut!(ON_PRIVILEGE) = Some(f) };
}

/// Set `CONTROL.nPRIV` for thread mode, with the `ISB` the architecture asks for, after
/// telling the firmware's hook.
#[inline(always)]
pub(crate) fn set_thread_unprivileged(on: bool) {
    use cortex_m::register::control::{self, Npriv};
    // SAFETY: written before any app runs, read only from handler mode.
    if let Some(hook) = unsafe { *core::ptr::addr_of!(ON_PRIVILEGE) } {
        hook(on);
    }
    let mut c = control::read();
    c.set_npriv(if on {
        Npriv::Unprivileged
    } else {
        Npriv::Privileged
    });
    // SAFETY: called from handler mode, which is privileged; only `nPRIV` changes, so the
    // stack selection and FP state bits are written back as they were read.
    unsafe { control::write(c) };
    cortex_m::asm::isb();
}

/// Word `i` of the exception frame at `frame`.
///
/// # Safety
/// `frame` is a stacked exception frame.
#[inline(always)]
unsafe fn word(frame: u32, i: u32) -> u32 {
    // SAFETY: the caller's contract.
    unsafe { ((frame + 4 * i) as *const u32).read_volatile() }
}

#[inline(always)]
unsafe fn set_word(frame: u32, i: u32, v: u32) {
    // SAFETY: as `word`.
    unsafe { ((frame + 4 * i) as *mut u32).write_volatile(v) }
}

/// Lay a fresh basic frame just under `top` that returns to `pc` with `r0`-`r3` set, and
/// return its address.
///
/// # Safety
/// The 32 bytes under `top & !7` are free and writable from handler mode.
unsafe fn fresh_frame(top: u32, pc: u32, r: [u32; 4]) -> u32 {
    let f = (top & !7) - FRAME * 4;
    // SAFETY: the caller's contract.
    unsafe {
        for (i, v) in r.iter().enumerate() {
            set_word(f, i as u32, *v);
        }
        set_word(f, 4, 0); // r12
        // LR: a frame that returns has nowhere to go. Zero is outside anything an app can
        // execute, so returning faults and the fault ends the app.
        set_word(f, 5, 0);
        set_word(f, 6, pc & !1);
        set_word(f, 7, XPSR_THUMB);
    }
    f
}

/// The app has ended, one way or another: put the launcher back. Returns its
/// `EXC_RETURN`.
///
/// # Safety
/// From the `SVC` or fault handler, with `s.active`.
unsafe fn finish(s: &mut State, exit: Exit) -> u32 {
    s.exit = exit;
    s.active = false;
    s.in_service = false;
    set_thread_unprivileged(false);
    // SAFETY: `launch_frame` is the launcher's frame, untouched since `SVC ENTER`: it sits
    // on the launching task's stack, which the app cannot reach.
    unsafe { cortex_m::register::psp::write(s.launch_frame) };
    s.launch_exc
}

/// The `SVC` logic. `frame` is the caller's exception frame, `exc` its `EXC_RETURN`;
/// returns the `EXC_RETURN` to leave with (and may have moved PSP).
extern "C" fn svc_rust(frame: u32, exc: u32) -> u32 {
    // SAFETY: the SVC handler runs above every other priority but the fault handlers, and
    // those only touch `STATE` for a fault in an app, which cannot be raised while this
    // handler runs.
    let s = unsafe { &mut *core::ptr::addr_of_mut!(STATE) };
    // An SVC from handler mode, or on the main stack, is nothing this protocol knows.
    if exc != EXC_RETURN_THREAD_PSP && exc != (EXC_RETURN_THREAD_PSP & !0x10) {
        return exc;
    }
    // SAFETY: a thread-mode caller's frame, on its process stack.
    let pc = unsafe { word(frame, 6) };
    // The SVC instruction is the halfword before the stacked PC; its low byte is the
    // number. The caller's memory, read privileged.
    // SAFETY: `pc - 2` is the instruction the caller just executed.
    let imm = unsafe { ((pc - 2) as *const u16).read_volatile() } as u8;
    let unpriv = thread_unprivileged();

    match (imm, unpriv) {
        (SVC_ENTER, false) if !s.active => {
            // SAFETY: the launcher's frame, from `enter`: r0 entry, r1 stack top, r2 arg.
            let (entry, top, arg) = unsafe { (word(frame, 0), word(frame, 1), word(frame, 2)) };
            s.launch_frame = frame;
            s.launch_exc = exc;
            // SAFETY: the app's stack, made writable by the firmware before `run`.
            let app = unsafe { fresh_frame(top, entry, [arg, 0, 0, 0]) };
            SEEN.store(true, Ordering::Relaxed);
            s.active = true;
            s.in_service = false;
            // SAFETY: points thread mode at the frame just laid.
            unsafe { cortex_m::register::psp::write(app) };
            set_thread_unprivileged(true);
            EXC_RETURN_THREAD_PSP
        }
        (SVC_EXIT, true) if s.active && !s.in_service => {
            // SAFETY: the app's frame: r0 is its code.
            let code = unsafe { word(frame, 0) } as i32;
            // SAFETY: `active`.
            unsafe { finish(s, Exit::Code(code)) }
        }
        (SVC_CALL, true) if s.active && !s.in_service => {
            s.app_frame = frame;
            s.app_exc = exc;
            s.in_service = true;
            // SAFETY: the app's frame carries the call in r0-r3.
            let args = unsafe {
                [
                    word(frame, 0),
                    word(frame, 1),
                    word(frame, 2),
                    word(frame, 3),
                ]
            };
            // The trampoline runs on the launching task's stack, under the launcher's own
            // frame, which stays where it is. A margin keeps an extended frame's tail clear.
            // SAFETY: that stretch of the task's stack is unused while the app runs.
            let k =
                unsafe { fresh_frame(s.launch_frame - 128, trampoline as *const () as u32, args) };
            // SAFETY: as above.
            unsafe { cortex_m::register::psp::write(k) };
            set_thread_unprivileged(false);
            EXC_RETURN_THREAD_PSP
        }
        (SVC_RETURN, false) if s.active && s.in_service => {
            // SAFETY: the trampoline's frame: r0 is the result; the app's frame is where
            // `SVC CALL` left it.
            unsafe { set_word(s.app_frame, 0, word(frame, 0)) };
            s.in_service = false;
            // SAFETY: back onto the app's stack, at its own frame.
            unsafe { cortex_m::register::psp::write(s.app_frame) };
            set_thread_unprivileged(true);
            s.app_exc
        }
        // An app breaking the rules ends the app.
        (_, true) if s.active => {
            // SAFETY: `active`.
            unsafe {
                finish(
                    s,
                    Exit::Fault {
                        pc,
                        cfsr: 0,
                        addr: 0,
                    },
                )
            }
        }
        // Privileged code using a number out of turn: refuse, visibly, and carry on.
        _ => {
            // SAFETY: the caller's frame.
            unsafe { set_word(frame, 0, u32::MAX) };
            exc
        }
    }
}

/// `CFSR` (MemManage, BusFault and UsageFault status), `MMFAR`, `BFAR`.
/// Source: ARMv7-M ARM §B3.2.15–§B3.2.18 [C]
const CFSR: u32 = 0xE000_ED28;
const MMFAR: u32 = 0xE000_ED34;
const BFAR: u32 = 0xE000_ED38;
/// `CFSR.MMARVALID` (bit 7) and `CFSR.BFARVALID` (bit 15).
const MMARVALID: u32 = 1 << 7;
const BFARVALID: u32 = 1 << 15;

/// A fault: if the app was running (not a service, not some other task), end the app and
/// return the launcher's `EXC_RETURN`; otherwise return 0 and the firmware's own handling
/// runs.
///
/// The firmware's fault handlers call this first, from a naked entry like [`SVCall`]'s
/// that passes the frame and `EXC_RETURN` and branches to the result when it is non-zero.
///
/// The test for "the app" is that thread mode is unprivileged: only the app ever runs
/// that way, and while a service runs the bit is clear. A fault in a service is a fault in
/// the firmware.
///
/// # Safety
/// From a fault handler, with `frame` and `exc` as the exception entry left them.
pub unsafe extern "C" fn fault_entry(frame: u32, exc: u32) -> u32 {
    // SAFETY: fault handlers do not preempt the SVC handler mid-update (see svc_rust).
    let s = unsafe { &mut *core::ptr::addr_of_mut!(STATE) };
    let from_thread_psp = exc & 0xC == 0xC;
    if !(s.active && !s.in_service && from_thread_psp && thread_unprivileged()) {
        return 0;
    }
    // SAFETY: fixed SCB registers; reading them has no side effect, and CFSR is cleared by
    // writing back what was read (write-one-to-clear) so the next fault starts clean.
    let (cfsr, addr) = unsafe {
        let cfsr = (CFSR as *const u32).read_volatile();
        let addr = if cfsr & MMARVALID != 0 {
            (MMFAR as *const u32).read_volatile()
        } else if cfsr & BFARVALID != 0 {
            (BFAR as *const u32).read_volatile()
        } else {
            0
        };
        (CFSR as *mut u32).write_volatile(cfsr);
        (cfsr, addr)
    };
    // SAFETY: the app's frame, on its own stack.
    let pc = unsafe { word(frame, 6) };
    // SAFETY: `active`.
    unsafe { finish(s, Exit::Fault { pc, cfsr, addr }) }
}

/// A naked fault entry for the firmware to install as its MemManage / BusFault /
/// UsageFault / HardFault handler body: completes any lazy FP save, asks [`fault_entry`],
/// and either returns into the launcher or falls through to `otherwise` -- the firmware's
/// usual handling -- with nothing changed.
#[macro_export]
macro_rules! app_fault_handler {
    ($(#[$m:meta])* $name:ident, $otherwise:path) => {
        $(#[$m])*
        ///
        /// # Safety
        /// Only the hardware calls this, as its fault exception.
        #[unsafe(naked)]
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name() {
            core::arch::naked_asm!(
                ".fpu fpv4-sp-d16",
                "tst   lr, #0x10",
                "it    eq",
                "vmoveq.f32 s0, s0",
                "tst   lr, #4",
                "ite   eq",
                "mrseq r0, msp",
                "mrsne r0, psp",
                "mov   r1, lr",
                "push  {{r1, lr}}",
                "bl    {fault}",
                "pop   {{r1, lr}}",
                "cmp   r0, #0",
                "it    ne",
                "bxne  r0",
                "b     {otherwise}",
                fault = sym $crate::app::fault_entry,
                otherwise = sym $otherwise,
            )
        }
    };
}
