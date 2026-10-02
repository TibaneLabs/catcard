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

/// The services. Numbers match `catcard-fw`'s `apps::service`; never renumber one.
pub mod sys {
    const LOG: u32 = 0;
    const TICKS: u32 = 1;
    const YIELD: u32 = 2;
    const SLEEP: u32 = 3;

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
