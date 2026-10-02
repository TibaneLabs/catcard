//! Apps: the firmware's half of running unprivileged code (docs/APPS.md).
//!
//! The kernel moves the CPU between privilege levels (`catcard_kernel::app`); this module
//! decides what an app may touch and what it may ask for:
//!
//! - **the app area**, the largest naturally aligned power-of-two block of the RAM the
//!   image does not link (256 KiB at 0x2004_0000 on mk4/mk5/Q1). The heap gives it up --
//!   [`heap_parts`] -- and an app gets all of it: code, data, `.bss` and stack;
//! - **the MPU layout**: the app's code read-only and executable, the rest of the area
//!   read-write and never executed, everything else unreachable. Live only while thread mode
//!   is unprivileged ([`on_privilege`]), so services, other tasks and callgate calls run
//!   with the MPU exactly as they do without apps;
//! - **the services**, [`dispatch`], which treat every argument as hostile.
//!
//! Phase 1 takes an app only over USB, on debug builds (`DebugAppWrite` / `DebugAppRun` /
//! `DebugAppStatus`): the image is written into the area, then run by the menu loop on the
//! UI task. Nothing here runs at boot; the area is claimed the first time it is written.

// Phase 1 loads apps only over USB on bench builds, so without `usb-debug-mem` the loader
// has no caller yet; the area's carve-out (`heap_parts`) is used by every build. Phase 2's
// packaged apps give the rest a caller and this goes.
#![cfg_attr(not(feature = "usb-debug-mem"), allow(dead_code))]

use core::sync::atomic::{AtomicU8, Ordering};

use catcard_kernel::app::Exit;

/// Where apps run, if this board has the RAM for it: the largest power-of-two block,
/// aligned to its own size, inside `spare_ram`. Power of two and aligned, because the MPU
/// region that covers it must be. Source: ARMv7-M ARM §B3.5.9 (SIZE, base alignment) [C]
pub const ARENA: Option<(u32, u32)> = arena(catcard_board::BOARD.memory.spare_ram);

const fn arena(spare: Option<catcard_board::memory::SpareRam>) -> Option<(u32, u32)> {
    let Some(spare) = spare else {
        return None;
    };
    // From the largest candidate down: the first size with an aligned block inside.
    let mut size: u32 = 1 << 20;
    while size >= 64 * 1024 {
        let base = spare.base.next_multiple_of(size);
        if base + size <= spare.end() {
            return Some((base, size));
        }
        size >>= 1;
    }
    None
}

/// The parts of `spare` the heap may have: everything but [`ARENA`].
pub const fn heap_parts(
    spare: catcard_board::memory::SpareRam,
) -> [catcard_board::memory::SpareRam; 2] {
    use catcard_board::memory::SpareRam;
    match ARENA {
        Some((base, len)) => [
            SpareRam {
                base: spare.base,
                len: base - spare.base,
            },
            SpareRam {
                base: base + len,
                len: spare.end() - (base + len),
            },
        ],
        None => [spare, SpareRam { base: 0, len: 0 }],
    }
}

/// `CAPP`, little-endian: the first word of every app image.
pub const MAGIC: u32 = u32::from_le_bytes(*b"CAPP");
/// The header format this loader reads.
pub const VERSION: u32 = 1;
/// Words in the header at the start of the image (see docs/APPS.md).
const HEADER_WORDS: usize = 8;
/// Least stack an app is started with, above its `.bss`.
const MIN_STACK: u32 = 4 * 1024;

/// What the header says, after checking it against the area.
#[derive(Copy, Clone, Debug)]
struct Layout {
    entry: u32,
    /// Bytes of the code region: a power of two, at least `code_end - base`.
    code_region: u32,
    data_end: u32,
    bss_end: u32,
}

/// Why an image was refused before it ran.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Refused {
    NoArena,
    BadMagic,
    BadVersion,
    BadLayout,
    WrongBuild,
    Mpu,
}

/// Read and check the header of the image at `base`. Every address in it must be inside the
/// area, in order, with the code region a power of two that data starts at or after.
fn layout(base: u32, len: u32) -> Result<Layout, Refused> {
    let mut h = [0u32; HEADER_WORDS];
    for (i, w) in h.iter_mut().enumerate() {
        // SAFETY: the first 32 bytes of the area, which [`claim`] has proven to be memory.
        *w = unsafe { ((base + 4 * i as u32) as *const u32).read_volatile() };
    }
    let [
        magic,
        version,
        entry,
        code_end,
        data_start,
        data_end,
        bss_end,
        build,
    ] = h;
    if magic != MAGIC {
        return Err(Refused::BadMagic);
    }
    if version != VERSION {
        return Err(Refused::BadVersion);
    }
    // Phase 2 checks this against the kernel's own build ID; until then, apps say 0.
    if build != 0 {
        return Err(Refused::WrongBuild);
    }
    let end = base + len;
    let header_end = base + 4 * HEADER_WORDS as u32;
    let code_len = code_end.wrapping_sub(base);
    let code_region = code_len.max(32).next_power_of_two();
    let ordered = header_end <= entry
        && entry < code_end
        && code_end <= end
        && base + code_region <= data_start
        && data_start <= data_end
        && data_end <= bss_end
        && bss_end.saturating_add(MIN_STACK) <= end;
    if !ordered || code_region > len {
        return Err(Refused::BadLayout);
    }
    Ok(Layout {
        entry,
        code_region,
        data_end,
        bss_end,
    })
}

/// Whether the area has been probed and handed over. 0 untried, 1 claimed, 2 not memory.
static CLAIMED: AtomicU8 = AtomicU8::new(0);

/// Probe the area once and keep it. False on a board with none, or if it did not answer.
pub fn claim() -> bool {
    match CLAIMED.load(Ordering::Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    let ok = match ARENA {
        Some((base, len)) => {
            crate::heap::looks_like_memory(catcard_board::memory::SpareRam { base, len })
        }
        None => false,
    };
    crate::catlog!(
        "apps: area {:?} {}",
        ARENA,
        if ok { "claimed" } else { "unusable" }
    );
    CLAIMED.store(if ok { 1 } else { 2 }, Ordering::Relaxed);
    ok
}

/// Copy `bytes` into the area at `offset`. False if the area is not there, the bytes do
/// not fit, or an app is running or waiting to.
pub fn write(offset: u32, bytes: &[u8]) -> bool {
    let busy = matches!(state(), State::Pending | State::Running);
    let Some((base, len)) = ARENA else {
        return false;
    };
    if busy
        || !claim()
        || offset
            .checked_add(bytes.len() as u32)
            .is_none_or(|e| e > len)
    {
        return false;
    }
    for (i, b) in bytes.iter().enumerate() {
        // SAFETY: inside the area, which nothing else uses while no app runs.
        unsafe { ((base + offset + i as u32) as *mut u8).write_volatile(*b) };
    }
    true
}

/// Where a USB-loaded app is.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum State {
    Idle = 0,
    Pending = 1,
    Running = 2,
    Done = 3,
}

static STATE: AtomicU8 = AtomicU8::new(State::Idle as u8);
/// The argument for the pending run, and how the last one ended.
static mut ARG: u32 = 0;
static mut LAST: Result<Exit, Refused> = Ok(Exit::Code(0));

pub fn state() -> State {
    match STATE.load(Ordering::Acquire) {
        1 => State::Pending,
        2 => State::Running,
        3 => State::Done,
        _ => State::Idle,
    }
}

/// Ask the menu loop to run what is in the area. False if one is already waiting or running.
pub fn request(arg: u32) -> bool {
    if matches!(state(), State::Pending | State::Running) || ARENA.is_none() {
        return false;
    }
    // SAFETY: no run is pending or running, so the menu loop is not reading it.
    unsafe { *core::ptr::addr_of_mut!(ARG) = arg };
    STATE.store(State::Pending as u8, Ordering::Release);
    true
}

/// How the last run ended, once [`state`] is `Done`.
pub fn last() -> Result<Exit, Refused> {
    // SAFETY: written by the menu loop before it publishes `Done`.
    unsafe { *core::ptr::addr_of!(LAST) }
}

/// From the menu loop: run the pending app, if there is one.
pub fn serve() {
    if state() != State::Pending {
        return;
    }
    STATE.store(State::Running as u8, Ordering::Release);
    // SAFETY: written by `request` before it published `Pending`.
    let arg = unsafe { *core::ptr::addr_of!(ARG) };
    let outcome = run(arg);
    match outcome {
        Ok(Exit::Code(c)) => crate::catlog!("apps: exited {}", c),
        Ok(Exit::Fault { pc, cfsr, addr }) => crate::catlog!(
            "apps: FAULT pc {:#010x} cfsr {:#010x} addr {:#010x}",
            pc,
            cfsr,
            addr
        ),
        Err(why) => crate::catlog!("apps: refused {:?}", why),
    }
    // SAFETY: `Running`, so nobody else reads or writes it.
    unsafe { *core::ptr::addr_of_mut!(LAST) = outcome };
    STATE.store(State::Done as u8, Ordering::Release);
}

/// Check the image in the area, lay out its memory, and run it.
fn run(arg: u32) -> Result<Exit, Refused> {
    let Some((base, len)) = ARENA else {
        return Err(Refused::NoArena);
    };
    if !claim() {
        return Err(Refused::NoArena);
    }
    let l = layout(base, len)?;
    // `.bss` and the stack start zeroed, as they would after a reset; the image's own
    // bytes stop at `data_end`.
    let mut at = l.data_end;
    while at < base + len {
        // SAFETY: inside the area, past the image.
        unsafe { (at as *mut u8).write_volatile(0) };
        at += 1;
    }
    // SAFETY: the area is the app's and no app is running; the regions take effect only
    // once `on_privilege(true)` turns the MPU on for it.
    unsafe {
        catcard_hal::mpu::set_app_regions(base, l.code_region, len).map_err(|_| Refused::Mpu)?;
        catcard_kernel::app::set_privilege_hook(on_privilege);
        catcard_hal::mpu::enable_app_faults();
    }
    crate::catlog!(
        "apps: run entry {:#010x} code {} data {}..{} arg {:#x}",
        l.entry,
        l.code_region,
        l.data_end,
        l.bss_end,
        arg
    );
    // SAFETY: from the UI task, privileged, interrupts enabled; the entry and stack are in
    // the area the MPU makes the app's; the fault handlers in `interrupts.rs` hand an app's
    // faults to the kernel.
    let exit = unsafe { catcard_kernel::app::run(l.entry, base + len, arg, dispatch) };
    Ok(exit)
}

/// The kernel's privilege hook: the app's MPU layout is on exactly while thread mode is
/// unprivileged.
fn on_privilege(unprivileged: bool) {
    // SAFETY: `run` programmed the regions before the first unprivileged instruction.
    unsafe { catcard_hal::mpu::app_mode(unprivileged) };
}

/// Services an app may ask for. The numbers are the ABI; never renumber one.
pub mod service {
    /// `log(ptr, len)`: one line in the device log, at most [`super::LOG_MAX`] bytes.
    pub const LOG: u32 = 0;
    /// `ticks() -> ms` since boot.
    pub const TICKS: u32 = 1;
    /// `yield()`: let other tasks run.
    pub const YIELD: u32 = 2;
    /// `sleep(ms)`: at most [`super::SLEEP_MAX_MS`].
    pub const SLEEP: u32 = 3;
}

const LOG_MAX: usize = 96;
const SLEEP_MAX_MS: u32 = 10_000;

/// Whether `ptr..ptr+len` lies inside the area: the only memory an app may name.
fn in_arena(ptr: u32, len: u32) -> bool {
    match ARENA {
        Some((base, size)) => {
            ptr >= base && ptr.checked_add(len).is_some_and(|end| end <= base + size)
        }
        None => false,
    }
}

/// Serve one `SVC CALL`. Runs privileged, on the UI task's stack, preemptible.
extern "C" fn dispatch(id: u32, a: u32, b: u32, _c: u32) -> u32 {
    match id {
        service::LOG => {
            let len = (b as usize).min(LOG_MAX);
            if !in_arena(a, len as u32) {
                return u32::MAX;
            }
            let mut line = [0u8; LOG_MAX];
            for (i, byte) in line[..len].iter_mut().enumerate() {
                // SAFETY: checked to be inside the area just above.
                *byte = unsafe { ((a + i as u32) as *const u8).read_volatile() };
            }
            match core::str::from_utf8(&line[..len]) {
                Ok(s) => crate::catlog!("app: {}", s),
                Err(_) => crate::catlog!("app: ({} bytes, not text)", len),
            }
            0
        }
        service::TICKS => catcard_kernel::ticks(),
        service::YIELD => {
            let _ = crate::usbtask::pump();
            catcard_kernel::yield_now();
            0
        }
        service::SLEEP => {
            let start = catcard_kernel::ticks();
            let ms = a.min(SLEEP_MAX_MS);
            while catcard_kernel::ticks().wrapping_sub(start) < ms {
                let _ = crate::usbtask::pump();
                catcard_kernel::yield_now();
            }
            0
        }
        _ => u32::MAX,
    }
}
