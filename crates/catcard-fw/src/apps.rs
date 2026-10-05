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

// The loader's callers are the bench's USB opcodes (`usb-debug-mem`) and the apps this
// board's menu launches (the games, on every board but the mk3, which links them). A build
// with neither still links the area's carve-out (`heap_parts`), which every build uses.
#![cfg_attr(
    not(all(
        feature = "usb-debug-mem",
        feature = "games",
        not(feature = "board-mk3")
    )),
    allow(dead_code)
)]

use core::sync::atomic::{AtomicU8, Ordering};

use catcard_kernel::app::Exit;

use crate::ui::Ui;

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
/// The services ABI this firmware serves (`catcard_app::ABI`, the header's last word). An
/// app made for another one is refused: its service numbers may mean something else here.
pub const ABI: u32 = 1;
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
    WrongAbi,
    Mpu,
    NotFound,
    Damaged,
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
        abi,
    ] = h;
    if magic != MAGIC {
        return Err(Refused::BadMagic);
    }
    if version != VERSION {
        return Err(Refused::BadVersion);
    }
    if abi != ABI {
        return Err(Refused::WrongAbi);
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

/// Whether the area is lent to the heap (`crate::heap::borrow_app_area`). While it is,
/// [`claim`] says no, and with it every way an app gets into the area: an upload, an
/// unpack, a run.
#[cfg(all(feature = "tss", not(feature = "board-mk3")))]
static LENT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Lend the area to the heap. False if an app is running or waiting to, the area is
/// already lent, or it is not memory.
#[cfg(all(feature = "tss", not(feature = "board-mk3")))]
pub fn lend() -> bool {
    if matches!(state(), State::Pending | State::Running) || !claim() {
        return false;
    }
    !LENT.swap(true, Ordering::AcqRel)
}

/// The heap has the area back: apps may use it again.
#[cfg(all(feature = "tss", not(feature = "board-mk3")))]
pub fn give_back() {
    LENT.store(false, Ordering::Release);
}

/// Probe the area once and keep it. False on a board with none, or if it did not answer.
pub fn claim() -> bool {
    #[cfg(all(feature = "tss", not(feature = "board-mk3")))]
    if LENT.load(Ordering::Acquire) {
        return false;
    }
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
        || offset
            .checked_add(bytes.len() as u32)
            .is_none_or(|e| e > len)
    {
        return false;
    }
    // Checked and written with interrupts masked, so the area cannot be lent to the heap
    // (`lend`, on the UI task) between the check and the last byte.
    cortex_m::interrupt::free(|_| {
        if !claim() {
            return false;
        }
        for (i, b) in bytes.iter().enumerate() {
            // SAFETY: inside the area, which nothing else uses while no app runs and it
            // is not lent.
            unsafe { ((base + offset + i as u32) as *mut u8).write_volatile(*b) };
        }
        true
    })
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

/// From the menu loop: run the pending app, if there is one. True if one ran, so the
/// caller redraws what the app may have drawn over.
pub fn serve(ui: &mut Ui<'_>) -> bool {
    if state() != State::Pending {
        return false;
    }
    STATE.store(State::Running as u8, Ordering::Release);
    // SAFETY: written by `request` before it published `Pending`.
    let arg = unsafe { *core::ptr::addr_of!(ARG) };
    let outcome = run(arg, ui);
    report(&outcome);
    // SAFETY: `Running`, so nobody else reads or writes it.
    unsafe { *core::ptr::addr_of_mut!(LAST) = outcome };
    STATE.store(State::Done as u8, Ordering::Release);
    true
}

/// One log line for how a run ended.
fn report(outcome: &Result<Exit, Refused>) {
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
}

/// The launching screen's `Ui`, for the services, while an app runs. The launcher is
/// suspended inside [`run`] meanwhile, so the services are its only user.
static mut UI: *mut () = core::ptr::null_mut();

/// Check the image in the area, lay out its memory, and run it.
fn run(arg: u32, ui: &mut Ui<'_>) -> Result<Exit, Refused> {
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
    // SAFETY: UI task only; cleared again below, before `ui` is used by anyone else.
    unsafe { *core::ptr::addr_of_mut!(UI) = (ui as *mut Ui<'_>).cast() };
    // SAFETY: from the UI task, privileged, interrupts enabled; the entry and stack are in
    // the area the MPU makes the app's; the fault handlers in `interrupts.rs` hand an app's
    // faults to the kernel.
    let exit = unsafe { catcard_kernel::app::run(l.entry, base + len, arg, dispatch) };
    // SAFETY: UI task only; the app has ended, so no service can be reading it.
    unsafe { *core::ptr::addr_of_mut!(UI) = core::ptr::null_mut() };
    // An app that took the panel and did not give it back -- it faulted, or forgot -- must
    // not leave the rest of the firmware drawing into a scrolled panel.
    #[cfg(feature = "board-q1")]
    if PANEL_TAKEN.swap(false, Ordering::Relaxed) {
        crate::display::end_scroll(ui.panel);
    }
    Ok(exit)
}

/// The kernel's privilege hook: the app's MPU layout is on exactly while thread mode is
/// unprivileged.
fn on_privilege(unprivileged: bool) {
    // SAFETY: `run` programmed the regions before the first unprivileged instruction.
    unsafe { catcard_hal::mpu::app_mode(unprivileged) };
}

/// Services an app may ask for. The numbers are the ABI; never renumber one.
// The panel's numbers are only served on the Q1.
#[cfg_attr(not(feature = "board-q1"), allow(dead_code))]
pub mod service {
    /// `log(ptr, len)`: one line in the device log, at most [`super::LOG_MAX`] bytes.
    pub const LOG: u32 = 0;
    /// `ticks() -> ms` since boot.
    pub const TICKS: u32 = 1;
    /// `yield()`: let other tasks run.
    pub const YIELD: u32 = 2;
    /// `sleep(ms)`: at most [`super::SLEEP_MAX_MS`].
    pub const SLEEP: u32 = 3;
    /// `panel_begin() -> 0`: raw panel, no origin, scrolling at raw lines (Q1 only).
    pub const PANEL_BEGIN: u32 = 4;
    /// `panel_end()`: scrolling back as the firmware expects it.
    pub const PANEL_END: u32 = 5;
    /// `scroll_start(line)`.
    pub const SCROLL_START: u32 = 6;
    /// `wait_tear() -> 1 on time, 0 late`.
    pub const WAIT_TEAR: u32 = 7;
    /// `paint(x | y << 16, w | h << 16, ptr)`: `w * h` RGB565 pixels from the app.
    pub const PAINT: u32 = 8;
    /// `key() -> 0 none, 1 cancel, 2 confirm, 3 qr, 0x100|digit, 0x200|char`.
    pub const KEY: u32 = 9;
    /// `random(ptr, len)`: at most 256 bytes from the UI's DRBG, never a key source.
    pub const RANDOM: u32 = 10;
    /// `message(ptr, len)`: "title\na\nb" on a plain screen.
    pub const MESSAGE: u32 = 11;
    /// `wait_any_key()`.
    pub const WAIT_ANY_KEY: u32 = 12;
    /// `cycles() -> DWT cycle counter`.
    pub const CYCLES: u32 = 13;
    /// `clock_hz() -> HCLK`.
    pub const CLOCK_HZ: u32 = 14;
    /// `kv_get(i) -> word`: one of eight words kept for the life of the power-up.
    pub const KV_GET: u32 = 15;
    /// `kv_set(i, word)`.
    pub const KV_SET: u32 = 16;
    /// `present(ptr, len)`: the app's canvas, in the firmware's own layout, onto the panel.
    pub const PRESENT: u32 = 17;
    /// `keys_held() -> count`.
    pub const KEYS_HELD: u32 = 18;
    /// `text(args)`: draw a string into the app's canvas with the firmware's fonts.
    /// `args` is eight words in the app's memory: canvas, canvas length, x, y, font, ink
    /// level, text, text length. Returns the x just past the last glyph.
    pub const TEXT: u32 = 19;
    /// `text_width(font, ptr, len) -> pixels`.
    pub const TEXT_WIDTH: u32 = 20;
    /// `line_height(font) -> pixels`.
    pub const LINE_HEIGHT: u32 = 21;
}

/// The faces an app names by role: 0 tiny (4x6 everywhere), 1 small, 2 body, 3 title --
/// the board's own choices (`display::FONTS`), so an app's text reads like the firmware's.
pub fn face(id: u32) -> Option<&'static dyn catcard_ui::face::Face> {
    let f = crate::display::FONTS;
    Some(match id {
        0 => &catcard_ui::font::misc4x6::FONT,
        1 => f.small,
        2 => f.body,
        3 => f.title,
        _ => return None,
    })
}

/// The SDK's font lookup, linked in.
#[unsafe(no_mangle)]
pub fn catcard_linked_face(id: u32) -> Option<&'static dyn catcard_ui::face::Face> {
    face(id)
}

/// Bytes of the firmware's canvas: what an app's canvas must be too.
#[cfg(feature = "board-q1")]
const SCREEN_BYTES: u32 = 320 * 240 / 2;
#[cfg(not(feature = "board-q1"))]
const SCREEN_BYTES: u32 = 128 * 64 / 8;

/// Up to this many bytes of text a call.
const TEXT_MAX: u32 = 256;

/// Draw text into an app's canvas, after checking every pointer in the request.
fn text_service(args: u32) -> u32 {
    if !in_arena(args, 32) {
        return u32::MAX;
    }
    // SAFETY: inside the area, checked just above.
    let w = |i: u32| unsafe { ((args + 4 * i) as *const u32).read_volatile() };
    let (canvas, canvas_len, x, y, font, level, text, text_len) =
        (w(0), w(1), w(2), w(3), w(4), w(5), w(6), w(7));
    let Some(face) = face(font) else {
        return u32::MAX;
    };
    if canvas_len != SCREEN_BYTES
        || !in_arena(canvas, canvas_len)
        || text_len > TEXT_MAX
        || !in_arena(text, text_len)
    {
        return u32::MAX;
    }
    let mut buf = [0u8; TEXT_MAX as usize];
    for (i, b) in buf[..text_len as usize].iter_mut().enumerate() {
        // SAFETY: inside the area, checked just above.
        *b = unsafe { ((text + i as u32) as *const u8).read_volatile() };
    }
    let s = core::str::from_utf8(&buf[..text_len as usize]).unwrap_or("");
    // SAFETY: `canvas` is `SCREEN_BYTES` inside the app's own area, and the canvas types
    // are `repr(transparent)` over exactly that many bytes; nothing else holds it while
    // the app waits on this call.
    let screen = unsafe { &mut *(canvas as *mut crate::display::Screen) };
    let level = (level as u8).min(catcard_ui::canvas::INK);
    // The same view the app draws through: the Q1's area below the status bar.
    #[cfg(feature = "board-q1")]
    let end = {
        let mut v = catcard_ui::canvas::Inset::new(screen, crate::display::BAR_H);
        catcard_ui::text::draw_text_in(&mut v, face, x as usize, y as usize, s, level)
    };
    #[cfg(not(feature = "board-q1"))]
    let end = catcard_ui::text::draw_text_in(screen, face, x as usize, y as usize, s, level);
    end as u32
}

/// `text_width`: the sum of the advances, as `draw_text` moves the pen.
fn text_width_service(font: u32, ptr: u32, len: u32) -> u32 {
    let Some(face) = face(font) else {
        return u32::MAX;
    };
    if len > TEXT_MAX || !in_arena(ptr, len) {
        return u32::MAX;
    }
    (0..len)
        // SAFETY: inside the area, checked just above.
        .map(|i| face.advance(unsafe { ((ptr + i) as *const u8).read_volatile() }) as u32)
        .sum()
}

/// A feature linked into the firmware is running through the same services (docs/APPS.md,
/// "One source, two builds"). Its pointers are the firmware's own memory, not the app
/// area's, and it is the firmware's own code: the checks that guard an app's arguments
/// pass it through.
static LINKED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Run `f` -- a feature built against `catcard-app` and linked in -- with the services
/// pointed at `ui`, as [`run`] does for an app. Only the mk3 links features in today.
#[cfg(feature = "board-mk3")]
pub fn run_linked<R>(ui: &mut Ui<'_>, f: impl FnOnce() -> R) -> R {
    // SAFETY: UI task only; cleared again below, before `ui` is used by anyone else.
    unsafe { *core::ptr::addr_of_mut!(UI) = (ui as *mut Ui<'_>).cast() };
    LINKED.store(true, Ordering::Relaxed);
    let r = f();
    LINKED.store(false, Ordering::Relaxed);
    // SAFETY: as above.
    unsafe { *core::ptr::addr_of_mut!(UI) = core::ptr::null_mut() };
    r
}

/// The SDK's service call, linked in: the same dispatcher an app's `SVC` reaches.
#[unsafe(no_mangle)]
pub fn catcard_linked_service(id: u32, a: u32, b: u32, c: u32) -> u32 {
    dispatch(id, a, b, c)
}

/// The SDK's `screen::draw`, linked in: a frame of the firmware's own, drawn in place.
#[unsafe(no_mangle)]
pub fn catcard_linked_draw(f: &mut dyn FnMut(&mut dyn catcard_ui::canvas::Canvas)) {
    // SAFETY: inside `run_linked`, on the UI task.
    if let Some(ui) = unsafe { ui() } {
        crate::display::draw(ui.panel, |c| f(c));
    }
}

/// The panel is the app's: `panel_begin` without `panel_end` yet.
#[cfg(feature = "board-q1")]
static PANEL_TAKEN: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// The eight words [`service::KV_GET`] serves.
static mut KV: [u32; 8] = [0; 8];

/// The launching screen's `Ui`. Only from a service, while an app runs.
///
/// # Safety
/// From [`dispatch`]: on the UI task, while [`run`] has `UI` set.
unsafe fn ui<'a>() -> Option<&'a mut Ui<'a>> {
    // SAFETY: the caller's contract; the launcher is suspended in `run`.
    unsafe { (*core::ptr::addr_of!(UI)).cast::<Ui<'a>>().as_mut() }
}

const LOG_MAX: usize = 96;
const SLEEP_MAX_MS: u32 = 10_000;

/// Whether `ptr..ptr+len` lies inside the area: the only memory an app may name. A
/// linked-in feature names the firmware's own memory and passes ([`LINKED`]).
fn in_arena(ptr: u32, len: u32) -> bool {
    if LINKED.load(Ordering::Relaxed) {
        return true;
    }
    match ARENA {
        Some((base, size)) => {
            ptr >= base && ptr.checked_add(len).is_some_and(|end| end <= base + size)
        }
        None => false,
    }
}

/// Serve one `SVC CALL`. Runs privileged, on the UI task's stack, preemptible.
extern "C" fn dispatch(id: u32, a: u32, b: u32, c: u32) -> u32 {
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
        service::KEY => {
            // SAFETY: a service, on the UI task, while the app runs.
            let Some(ui) = (unsafe { ui() }) else {
                return 0;
            };
            use catcard_ui::keypad::{Event, KEYS, Key};
            let mut events = [Event::Pressed(Key::Cancel); KEYS];
            let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
            let _ = crate::usbtask::pump();
            crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
            // Cancel wins over anything pressed with it.
            let k = keys
                .iter()
                .copied()
                .find(|&k| k == Key::Cancel)
                .or(keys.first().copied());
            match k {
                None => 0,
                Some(Key::Cancel) => 1,
                Some(Key::Confirm) => 2,
                Some(Key::Qr) => 3,
                Some(Key::Digit(d)) => 0x100 | d as u32,
                Some(Key::Char(ch)) => 0x200 | ch as u32,
            }
        }
        service::RANDOM => {
            let len = b.min(256);
            if !in_arena(a, len) {
                return u32::MAX;
            }
            // SAFETY: a service, on the UI task, while the app runs.
            let Some(ui) = (unsafe { ui() }) else {
                return u32::MAX;
            };
            let mut buf = [0u8; 256];
            let _ = ui.drbg.generate(&mut buf[..len as usize]);
            for (i, byte) in buf[..len as usize].iter().enumerate() {
                // SAFETY: checked to be inside the area just above.
                unsafe { ((a + i as u32) as *mut u8).write_volatile(*byte) };
            }
            0
        }
        service::MESSAGE => {
            let len = b.min(128);
            if !in_arena(a, len) {
                return u32::MAX;
            }
            let mut text = [0u8; 128];
            for (i, byte) in text[..len as usize].iter_mut().enumerate() {
                // SAFETY: checked to be inside the area just above.
                *byte = unsafe { ((a + i as u32) as *const u8).read_volatile() };
            }
            let text = core::str::from_utf8(&text[..len as usize]).unwrap_or("");
            let mut parts = text.splitn(3, '\n');
            let (t, x, y) = (
                parts.next().unwrap_or(""),
                parts.next().unwrap_or(""),
                parts.next().unwrap_or(""),
            );
            // SAFETY: a service, on the UI task, while the app runs.
            if let Some(ui) = unsafe { ui() } {
                crate::menu::message(ui.panel, t, x, y);
            }
            0
        }
        service::WAIT_ANY_KEY => {
            // SAFETY: a service, on the UI task, while the app runs.
            if let Some(ui) = unsafe { ui() } {
                crate::menu::wait_for_any_key(ui);
            }
            0
        }
        service::KEYS_HELD => {
            // SAFETY: a service, on the UI task, while the app runs.
            match unsafe { ui() } {
                Some(ui) => ui.pad.held_count() as u32,
                None => 0,
            }
        }
        service::PRESENT => present(a, b),
        service::TEXT => text_service(a),
        service::TEXT_WIDTH => text_width_service(a, b, c),
        service::LINE_HEIGHT => face(a).map_or(u32::MAX, |f| f.line_height() as u32),
        service::CYCLES => catcard_hal::dwt::cycles(),
        // SAFETY: reads RCC.
        service::CLOCK_HZ => unsafe { catcard_hal::clock::hclk_hz() },
        // SAFETY: services run one at a time, on the UI task.
        service::KV_GET if a < 8 => unsafe { (*core::ptr::addr_of!(KV))[a as usize] },
        service::KV_SET if a < 8 => {
            // SAFETY: as above.
            unsafe { (*core::ptr::addr_of_mut!(KV))[a as usize] = b };
            0
        }
        #[cfg(feature = "board-q1")]
        service::PANEL_BEGIN
        | service::PANEL_END
        | service::SCROLL_START
        | service::WAIT_TEAR
        | service::PAINT => panel_service(id, a, b, c),
        _ => u32::MAX,
    }
}

/// Copy the app's canvas -- `len` bytes at `ptr`, in the layout of the firmware's own
/// [`display::Screen`](crate::display) -- into a frame and show it.
fn present(ptr: u32, len: u32) -> u32 {
    use catcard_ui::canvas::Canvas as _;
    if len != SCREEN_BYTES || !in_arena(ptr, len) {
        return u32::MAX;
    }
    // SAFETY: a service, on the UI task, while the app runs.
    let Some(ui) = (unsafe { ui() }) else {
        return u32::MAX;
    };
    // SAFETY: checked to be inside the area just above; read only.
    let px = unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) };
    crate::display::draw(ui.panel, |c| {
        #[cfg(feature = "board-q1")]
        for y in 0..c.height() {
            // The surface starts below the status bar; the app's canvas is the whole panel,
            // so its rows are read from the same place the firmware's would be.
            let row = &px[(y + crate::display::BAR_H) * 160..][..160];
            for x in 0..c.width().min(320) {
                let b = row[x / 2];
                c.put(x, y, if x % 2 == 0 { b >> 4 } else { b & 0x0F });
            }
        }
        #[cfg(not(feature = "board-q1"))]
        for y in 0..c.height().min(64) {
            for x in 0..c.width().min(128) {
                let on = px[(y / 8) * 128 + x] & (1 << (y % 8)) != 0;
                c.put(
                    x,
                    y,
                    if on {
                        catcard_ui::canvas::INK
                    } else {
                        catcard_ui::canvas::PAPER
                    },
                );
            }
        }
    });
    0
}

/// The colour panel's services (Q1).
#[cfg(feature = "board-q1")]
fn panel_service(id: u32, a: u32, b: u32, c: u32) -> u32 {
    // SAFETY: a service, on the UI task, while the app runs.
    let Some(ui) = (unsafe { ui() }) else {
        return u32::MAX;
    };
    match id {
        service::PANEL_BEGIN => {
            crate::display::reset_origin(ui.panel);
            let _ = ui.panel.set_scroll_area(0, 0);
            PANEL_TAKEN.store(true, Ordering::Relaxed);
            0
        }
        service::PANEL_END => {
            if PANEL_TAKEN.swap(false, Ordering::Relaxed) {
                crate::display::end_scroll(ui.panel);
            }
            0
        }
        service::SCROLL_START => {
            let _ = ui.panel.set_scroll_start(a as usize);
            0
        }
        service::WAIT_TEAR => crate::display::wait_tear() as u32,
        service::PAINT => {
            let (x, y) = ((a & 0xFFFF) as usize, (a >> 16) as usize);
            let (w, h) = ((b & 0xFFFF) as usize, (b >> 16) as usize);
            let bytes = (w * h * 2) as u32;
            if !PANEL_TAKEN.load(Ordering::Relaxed) || !c.is_multiple_of(2) || !in_arena(c, bytes) {
                return u32::MAX;
            }
            // SAFETY: `c` is 2-aligned and `w * h` pixels from it lie inside the app's
            // area, both checked just above; the app is stopped while its service runs,
            // so nothing writes them while this slice is alive.
            let px = unsafe { core::slice::from_raw_parts(c as *const u16, w * h) };
            match ui.panel.paint_pixels(x, y, w, h, px) {
                Ok(()) => 0,
                Err(_) => u32::MAX,
            }
        }
        _ => u32::MAX,
    }
}

// --- apps carried in the image ---------------------------------------------------------

/// Where `catcard-image` records the apps bundle: `[BUNDLE_SET, flash address]` once it has
/// appended one, `[BUNDLE_UNSET, 0]` as linked. Patched by name, so it keeps its name; read
/// volatile, so the compiler cannot fold the linked value.
#[used]
#[unsafe(no_mangle)]
static CATCARD_APPS_BUNDLE: [u32; 2] = [BUNDLE_UNSET, 0];
const BUNDLE_UNSET: u32 = 0xFFFF_FFFF;
/// `CAPB`: both the patched marker and the bundle's own first word.
const BUNDLE_SET: u32 = u32::from_le_bytes(*b"CAPB");
/// The bundle's header (magic, version, count, total length) and one entry (16-byte name,
/// offset from the bundle, packed length, unpacked length, reserved), in bytes.
const BUNDLE_HEADER: u32 = 16;
const ENTRY: u32 = 32;

/// The bundle's flash address and entry count, if this image carries one.
fn bundle() -> Option<(u32, u32)> {
    // SAFETY: a static in flash; volatile so the linked value is not folded in.
    let [tag, at] = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CATCARD_APPS_BUNDLE)) };
    if tag != BUNDLE_SET {
        return None;
    }
    let lo = catcard_board::BOARD.memory.firmware_base;
    let hi = lo + catcard_board::BOARD.image_ceiling();
    if at < lo || at.saturating_add(BUNDLE_HEADER) > hi {
        return None;
    }
    // SAFETY: inside the image, as just checked.
    let w = |i: u32| unsafe { ((at + 4 * i) as *const u32).read_volatile() };
    let (magic, version, count) = (w(0), w(1), w(2));
    if magic != BUNDLE_SET || version != 1 || count > 64 {
        return None;
    }
    if at + BUNDLE_HEADER + count * ENTRY > hi {
        return None;
    }
    Some((at, count))
}

/// Unpack the app called `name` from the image into the area, check it, and run it.
pub fn launch(name: &str, arg: u32, ui: &mut Ui<'_>) -> Result<Exit, Refused> {
    let outcome = unpack(name).and_then(|()| run(arg, ui));
    report(&outcome);
    outcome
}

/// Inflate `name`'s image from the bundle into the area.
fn unpack(name: &str) -> Result<(), Refused> {
    let Some((at, count)) = bundle() else {
        return Err(Refused::NotFound);
    };
    let Some((base, len)) = ARENA else {
        return Err(Refused::NoArena);
    };
    if matches!(state(), State::Pending | State::Running) || !claim() {
        return Err(Refused::NoArena);
    }
    let hi = catcard_board::BOARD.memory.firmware_base + catcard_board::BOARD.image_ceiling();
    for i in 0..count {
        let e = at + BUNDLE_HEADER + i * ENTRY;
        // SAFETY: inside the bundle, bounded by `bundle`.
        let entry_name = unsafe { core::slice::from_raw_parts(e as *const u8, 16) };
        let n = entry_name.iter().position(|&b| b == 0).unwrap_or(16);
        if &entry_name[..n] != name.as_bytes() {
            continue;
        }
        // SAFETY: as above.
        let w = |k: u32| unsafe { ((e + 16 + 4 * k) as *const u32).read_volatile() };
        let (offset, packed, unpacked) = (w(0), w(1), w(2));
        let src = at.saturating_add(offset);
        if src.saturating_add(packed) > hi || unpacked > len {
            return Err(Refused::Damaged);
        }
        let t0 = catcard_hal::dwt::cycles();
        // SAFETY: the packed bytes are inside the image (checked); the area is the app's and
        // no app runs.
        let (input, out) = unsafe {
            (
                core::slice::from_raw_parts(src as *const u8, packed as usize),
                core::slice::from_raw_parts_mut(base as *mut u8, len as usize),
            )
        };
        let got = compcol::embed::flate::unzlib(input, compcol::embed::flate::Buffer::new(out));
        // SAFETY: reads RCC.
        let per_us = (unsafe { catcard_hal::clock::hclk_hz() } / 1_000_000).max(1);
        let us = catcard_hal::dwt::cycles().wrapping_sub(t0) / per_us;
        return match got {
            Ok(n) if n == unpacked as u64 => {
                crate::catlog!("apps: {} unpacked {} -> {} B in {} us", name, packed, n, us);
                Ok(())
            }
            other => {
                crate::catlog!(
                    "apps: {} did not unpack: {:?}",
                    name,
                    other.map(|n| n as u32)
                );
                Err(Refused::Damaged)
            }
        };
    }
    Err(Refused::NotFound)
}
