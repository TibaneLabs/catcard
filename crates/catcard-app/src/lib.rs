//! The app side of CatCard's kernel/app split (docs/APPS.md).
//!
//! An app is a `no_std` binary that links this crate, defines
//!
//! ```ignore
//! #[unsafe(no_mangle)]
//! pub extern "C" fn app_main(arg: u32) -> i32 { ... }
//! ```
//!
//! and is built with `-Tlink.x` for `thumbv7em-none-eabihf`. It runs unprivileged: the only
//! memory it can reach is its own, and everything else goes through [`sys`].
//!
//! On a host build (the workspace's tests and lints) the services are stubs that panic, so
//! the crate compiles everywhere and is only meaningful on the device.

#![cfg_attr(target_os = "none", no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

/// The services ABI this crate speaks: the last word of the image header (link.x writes
/// it), checked by the loader. Bump it whenever a service changes meaning; adding one does
/// not need a bump.
pub const ABI: u32 = 1;

/// A key, as [`sys::key`] reports it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Key {
    Cancel,
    Confirm,
    Qr,
    Digit(u8),
    Char(u8),
    Other,
}

impl Key {
    fn decode(v: u32) -> Option<Key> {
        Some(match v {
            0 => return None,
            1 => Key::Cancel,
            2 => Key::Confirm,
            3 => Key::Qr,
            v if v & 0xFF00 == 0x100 => Key::Digit(v as u8),
            v if v & 0xFF00 == 0x200 => Key::Char(v as u8),
            _ => Key::Other,
        })
    }
}

/// The services. Numbers match `catcard-fw`'s `apps::service`; never renumber one.
pub mod sys {
    use super::Key;

    const LOG: u32 = 0;
    const TICKS: u32 = 1;
    const YIELD: u32 = 2;
    const SLEEP: u32 = 3;
    const PANEL_BEGIN: u32 = 4;
    const PANEL_END: u32 = 5;
    const SCROLL_START: u32 = 6;
    const WAIT_TEAR: u32 = 7;
    const PAINT: u32 = 8;
    const KEY: u32 = 9;
    const RANDOM: u32 = 10;
    const MESSAGE: u32 = 11;
    const WAIT_ANY_KEY: u32 = 12;
    const CYCLES: u32 = 13;
    const CLOCK_HZ: u32 = 14;
    const KV_GET: u32 = 15;
    const KV_SET: u32 = 16;

    /// `SVC CALL`: service `id` with three arguments, one result.
    #[cfg(target_arch = "arm")]
    #[inline(always)]
    fn call(id: u32, a: u32, b: u32, c: u32) -> u32 {
        let r: u32;
        // SAFETY: `SVC #2` is the kernel's service call (catcard-kernel `app::SVC_CALL`):
        // arguments in r0-r3, the result in r0, and the kernel preserves r4-r11 and
        // s16-s31. Everything a C call may clobber is declared clobbered below.
        unsafe {
            core::arch::asm!(
                "svc #2",
                inlateout("r0") id => r,
                in("r1") a,
                in("r2") b,
                in("r3") c,
                // What a C call may clobber, spelled out: `clobber_abi("C")` would also
                // name d16-d31, which this FPU (fpv4-sp-d16) does not have.
                out("r12") _,
                out("lr") _,
                out("d0") _,
                out("d1") _,
                out("d2") _,
                out("d3") _,
                out("d4") _,
                out("d5") _,
                out("d6") _,
                out("d7") _,
            )
        };
        r
    }

    #[cfg(not(target_arch = "arm"))]
    fn call(_id: u32, _a: u32, _b: u32, _c: u32) -> u32 {
        unimplemented!("CatCard services exist only on the device")
    }

    /// One line in the device log (at most 96 bytes are kept).
    pub fn log(s: &str) {
        call(LOG, s.as_ptr() as u32, s.len() as u32, 0);
    }

    /// Milliseconds since the device started.
    pub fn ticks() -> u32 {
        call(TICKS, 0, 0, 0)
    }

    /// Let the rest of the device run.
    pub fn yield_now() {
        call(YIELD, 0, 0, 0);
    }

    /// Wait `ms` milliseconds (at most ten seconds a call), letting the device run.
    pub fn sleep_ms(ms: u32) {
        call(SLEEP, ms, 0, 0);
    }

    /// Take the panel for raw drawing: no status bar, no origin, hardware scrolling at
    /// raw lines. False on a board without a colour panel.
    pub fn panel_begin() -> bool {
        call(PANEL_BEGIN, 0, 0, 0) == 0
    }

    /// Give the panel back as the firmware expects it. The firmware redraws after the app
    /// ends whether or not this was called.
    pub fn panel_end() {
        call(PANEL_END, 0, 0, 0);
    }

    /// Show frame-memory line `line` first (the panel's hardware scroll).
    pub fn scroll_start(line: u32) {
        call(SCROLL_START, line, 0, 0);
    }

    /// Wait for the panel's next tear pulse. False if it was missed (the frame is late).
    pub fn wait_tear() -> bool {
        call(WAIT_TEAR, 0, 0, 0) != 0
    }

    /// Send `w` x `h` RGB565 pixels, row by row, to frame memory at column `x`, row `y`
    /// (raw, as after [`panel_begin`]). `px` must hold at least `w * h` pixels; it is
    /// refused otherwise.
    pub fn paint(x: u32, y: u32, w: u32, h: u32, px: &[u16]) -> bool {
        if px.len() < (w * h) as usize {
            return false;
        }
        call(
            PAINT,
            (x & 0xFFFF) | (y << 16),
            (w & 0xFFFF) | (h << 16),
            px.as_ptr() as u32,
        ) == 0
    }

    /// A key pressed since the last call, if any. Cancel wins over anything pressed with it.
    pub fn key() -> Option<Key> {
        Key::decode(call(KEY, 0, 0, 0))
    }

    /// Fill `out` from the device's general-purpose random generator (not a key source).
    pub fn random(out: &mut [u8]) {
        for chunk in out.chunks_mut(256) {
            call(RANDOM, chunk.as_mut_ptr() as u32, chunk.len() as u32, 0);
        }
    }

    /// A plain three-line screen: title, then two lines.
    pub fn message(title: &str, a: &str, b: &str) {
        let mut buf = [0u8; 128];
        let mut n = 0;
        for (i, part) in [title, a, b].iter().enumerate() {
            if i > 0 && n < buf.len() {
                buf[n] = b'\n';
                n += 1;
            }
            let take = part.len().min(buf.len() - n);
            buf[n..n + take].copy_from_slice(&part.as_bytes()[..take]);
            n += take;
        }
        call(MESSAGE, buf.as_ptr() as u32, n as u32, 0);
    }

    /// Wait for any key, letting the device run meanwhile.
    pub fn wait_any_key() {
        call(WAIT_ANY_KEY, 0, 0, 0);
    }

    /// The CPU cycle counter.
    pub fn cycles() -> u32 {
        call(CYCLES, 0, 0, 0)
    }

    /// The CPU clock, in Hz.
    pub fn clock_hz() -> u32 {
        call(CLOCK_HZ, 0, 0, 0)
    }

    /// One of eight words that live as long as the device is on, shared by every app.
    pub fn kv_get(i: u32) -> u32 {
        call(KV_GET, i, 0, 0)
    }

    /// Set one of the eight words.
    pub fn kv_set(i: u32, v: u32) {
        call(KV_SET, i, v, 0);
    }

    /// End the app with `code`. Never returns.
    #[cfg(target_arch = "arm")]
    pub fn exit(code: i32) -> ! {
        // SAFETY: `SVC #1` is the kernel's exit (catcard-kernel `app::SVC_EXIT`); it does
        // not come back.
        unsafe { core::arch::asm!("svc #1", in("r0") code, options(noreturn)) }
    }

    #[cfg(not(target_arch = "arm"))]
    pub fn exit(_code: i32) -> ! {
        unimplemented!("CatCard services exist only on the device")
    }
}

/// A small `core::fmt::Write` buffer, for formatting a log line without an allocator.
pub struct Line {
    buf: [u8; 96],
    len: usize,
}

impl Line {
    pub const fn new() -> Self {
        Self {
            buf: [0; 96],
            len: 0,
        }
    }

    pub fn as_str(&self) -> &str {
        // Only ever filled by `write_str` with whole `str`s, cut at a char boundary.
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }

    /// Log it, then empty it.
    pub fn log(&mut self) {
        sys::log(self.as_str());
        self.len = 0;
    }
}

impl Default for Line {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Write for Line {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let room = self.buf.len() - self.len;
        let mut n = s.len().min(room);
        while !s.is_char_boundary(n) {
            n -= 1;
        }
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

#[cfg(target_os = "none")]
mod start {
    unsafe extern "C" {
        /// The app's own entry, defined by the app.
        fn app_main(arg: u32) -> i32;
    }

    /// Where the kernel enters (the header's entry word): `arg` in r0, the stack already
    /// set. Runs the app and exits with what it returned.
    #[unsafe(no_mangle)]
    pub extern "C" fn _start(arg: u32) -> ! {
        // SAFETY: the app defines `app_main` with this signature; that is the contract of
        // linking this crate.
        let code = unsafe { app_main(arg) };
        super::sys::exit(code)
    }

    #[panic_handler]
    fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
        use core::fmt::Write as _;
        let mut l = super::Line::new();
        let _ = write!(l, "panic: {}", info.message());
        l.log();
        super::sys::exit(-1)
    }
}
