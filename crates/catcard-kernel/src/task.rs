//! Tasks, their stacks, and the round-robin that picks the next one.

use crate::MAX_TASKS;

/// A spawned task.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct TaskId(pub usize);

/// The table is full.
#[derive(Copy, Clone, Debug)]
pub struct Full;

/// Written to the lowest word of every stack. If it is ever anything else, the task ran
/// off the bottom -- and on this device what lies below a stack may be seed material, so
/// this is checked and reported rather than trusted.
const GUARD: u32 = 0xDEAD_BEEF;

/// Every other stack word starts as this, so the unused depth can be measured: the
/// high-water mark is the first word from the bottom that is no longer painted.
const PAINT: u32 = 0xAAAA_AAAA;

/// Words a context occupies: `r4-r11` and `EXC_RETURN` saved by [`crate::switch`], then
/// the eight the hardware stacks on exception entry.
const FRAME_WORDS: usize = 9 + 8;

struct Tcb {
    /// Stack pointer where this task's saved context begins.
    sp: u32,
    /// The stack itself, so the guard and the paint can be checked later.
    lo: *mut u32,
    len: usize,
    name: &'static str,
}

static mut TASKS: [Option<Tcb>; MAX_TASKS] = [const { None }; MAX_TASKS];
static mut COUNT: usize = 0;
/// Index of the running task, or `usize::MAX` before the first switch -- which is how the
/// bootstrap's throwaway context is discarded instead of being saved over a real one.
static mut CURRENT: usize = usize::MAX;

/// Add a task. It becomes runnable at the next switch.
///
/// `stack` is the caller's, so its size is visible where the task is created rather than
/// hidden in the kernel, and the linker places it.
///
/// # Safety
/// `stack` must be exclusively this task's for the life of the program, and `entry` must
/// never return -- there is nowhere for it to go.
pub unsafe fn spawn(
    name: &'static str,
    stack: &'static mut [u32],
    entry: extern "C" fn() -> !,
) -> Result<TaskId, Full> {
    assert!(stack.len() > FRAME_WORDS + 8, "stack too small for a context");

    // SAFETY: spawning happens on the boot path, before `start`, so nothing is scheduling.
    let tasks = unsafe { &mut *(core::ptr::addr_of_mut!(TASKS)) };
    let count = unsafe { &mut *(core::ptr::addr_of_mut!(COUNT)) };
    if *count == MAX_TASKS {
        return Err(Full);
    }

    // Paint the whole stack, then plant the guard under it.
    stack.fill(PAINT);
    stack[0] = GUARD;

    let lo = stack.as_mut_ptr();
    let len = stack.len();
    // The frame sits at the top, eight-byte aligned as AAPCS wants.
    let top = (lo as usize + len * 4) & !7;
    let sp = top - FRAME_WORDS * 4;
    let f = sp as *mut u32;

    // SAFETY: `f` is inside the stack we were just handed, and the frame is the exact
    // layout an exception return expects to pop.
    unsafe {
        // Ours, popped by the switch: r4-r11 then EXC_RETURN.
        for i in 0..8 {
            f.add(i).write(0);
        }
        // Thread mode, PSP, no FP context yet.
        f.add(8).write(0xFFFF_FFFD);
        // The hardware's: r0-r3, r12, LR, PC, xPSR.
        for i in 9..14 {
            f.add(i).write(0);
        }
        // A task that returns has nowhere to go, so LR traps rather than wandering.
        f.add(14).write(task_returned as *const () as usize as u32 | 1);
        f.add(15).write(entry as *const () as usize as u32 & !1);
        // Thumb bit. Clearing it faults on the first instruction instead of running.
        f.add(16).write(0x0100_0000);
    }

    let id = *count;
    tasks[id] = Some(Tcb {
        sp: sp as u32,
        lo,
        len,
        name,
    });
    *count += 1;
    Ok(TaskId(id))
}

/// A task's entry function returned. There is no caller to go back to.
extern "C" fn task_returned() -> ! {
    loop {
        cortex_m::asm::bkpt();
    }
}

/// Arm the scheduler: the next save is discarded rather than written over a real task.
pub(crate) fn begin() {
    // SAFETY: called once from `start`, before the first switch.
    unsafe { *(core::ptr::addr_of_mut!(CURRENT)) = usize::MAX };
}

/// Save the outgoing stack pointer, choose the next task, return its stack pointer.
///
/// Called from PendSV with interrupts at the switch's own priority, so nothing here can
/// be re-entered.
pub(crate) fn switch(sp: u32) -> u32 {
    // SAFETY: only the switch touches these, and the switch cannot preempt itself.
    let tasks = unsafe { &mut *(core::ptr::addr_of_mut!(TASKS)) };
    let count = unsafe { *(core::ptr::addr_of!(COUNT)) };
    let cur = unsafe { *(core::ptr::addr_of!(CURRENT)) };

    if cur != usize::MAX
        && let Some(t) = tasks[cur].as_mut()
    {
        t.sp = sp;
        // The switch pushed r4-r11 then EXC_RETURN, so EXC_RETURN sits eight words above
        // `sp` whether or not FP registers were stacked beneath it. Bit 4 clear means
        // this task had an extended frame and `s16-s31` were just saved.
        // SAFETY: `sp` is the frame the switch has just written.
        let exc_return = unsafe { ((sp + 32) as *const u32).read() };
        if exc_return & 0x10 == 0 {
            crate::count_fp_save();
        }
    }

    // Round robin. Every spawned task is runnable: sleeping and blocking come with the
    // synchronisation primitives, not with the first switch.
    let next = if cur == usize::MAX {
        0
    } else {
        (cur + 1) % count
    };
    // SAFETY: as above.
    unsafe { *(core::ptr::addr_of_mut!(CURRENT)) = next };
    crate::count_switch();
    match &tasks[next] {
        Some(t) => t.sp,
        // Cannot happen: ids below `count` are always populated. Returning the incoming
        // pointer keeps the current task running rather than jumping somewhere unknown.
        None => sp,
    }
}

/// Deepest the task's stack has ever been, in words.
pub fn high_water(id: TaskId) -> usize {
    // SAFETY: read-only walk of a stack this task owns.
    unsafe {
        let tasks = &*(core::ptr::addr_of!(TASKS));
        let Some(t) = tasks.get(id.0).and_then(|t| t.as_ref()) else {
            return 0;
        };
        let mut untouched = 0;
        // Word 0 is the guard; paint starts above it.
        for i in 1..t.len {
            if t.lo.add(i).read_volatile() != PAINT {
                break;
            }
            untouched += 1;
        }
        t.len - untouched - 1
    }
}

/// A task's stack size in words, so a high-water mark can be read against it.
pub fn stack_len(id: TaskId) -> usize {
    // SAFETY: read-only.
    unsafe {
        let tasks = &*core::ptr::addr_of!(TASKS);
        tasks.get(id.0).and_then(|t| t.as_ref()).map_or(0, |t| t.len)
    }
}

/// Whether the task's stack guard is intact. False means it overflowed.
pub fn stack_ok(id: TaskId) -> bool {
    // SAFETY: one read of the guard word.
    unsafe {
        let tasks = &*(core::ptr::addr_of!(TASKS));
        match tasks.get(id.0).and_then(|t| t.as_ref()) {
            Some(t) => t.lo.read_volatile() == GUARD,
            None => true,
        }
    }
}

/// A task's name, for the debug screen.
pub fn name(id: TaskId) -> &'static str {
    // SAFETY: read-only.
    unsafe {
        let tasks = &*(core::ptr::addr_of!(TASKS));
        tasks
            .get(id.0)
            .and_then(|t| t.as_ref())
            .map(|t| t.name)
            .unwrap_or("?")
    }
}

/// How many tasks are spawned.
pub fn count() -> usize {
    // SAFETY: read-only.
    unsafe { *(core::ptr::addr_of!(COUNT)) }
}
