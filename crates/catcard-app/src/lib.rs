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
    #[cfg_attr(feature = "linked", allow(dead_code))]
    pub(crate) const PRESENT: u32 = 17;
    const KEYS_HELD: u32 = 18;

    /// Linked into the firmware: the service is a plain call (the firmware's
    /// `apps::catcard_linked_service`), with no privilege change.
    #[cfg(feature = "linked")]
    #[inline(always)]
    pub(crate) fn call(id: u32, a: u32, b: u32, c: u32) -> u32 {
        unsafe extern "Rust" {
            fn catcard_linked_service(id: u32, a: u32, b: u32, c: u32) -> u32;
        }
        // SAFETY: the firmware defines it whenever it links an app in; arguments are
        // checked there exactly as an app's would be.
        unsafe { catcard_linked_service(id, a, b, c) }
    }

    /// `SVC CALL`: service `id` with three arguments, one result.
    #[cfg(all(target_arch = "arm", not(feature = "linked")))]
    #[inline(always)]
    pub(crate) fn call(id: u32, a: u32, b: u32, c: u32) -> u32 {
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

    #[cfg(all(not(target_arch = "arm"), not(feature = "linked")))]
    pub(crate) fn call(_id: u32, _a: u32, _b: u32, _c: u32) -> u32 {
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

    /// How many keys are held down right now.
    pub fn keys_held() -> u32 {
        call(KEYS_HELD, 0, 0, 0)
    }

    /// A number in `0..n`, uniform, from [`random`]. `n` of 0 gives 0.
    pub fn below(n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        // Rejection sampling: drop the top partial range so every value is equally likely.
        let zone = u32::MAX - (u32::MAX % n);
        loop {
            let mut b = [0u8; 4];
            random(&mut b);
            let v = u32::from_le_bytes(b);
            if v < zone {
                return v % n;
            }
        }
    }

    /// End the app with `code`. Never returns.
    #[cfg(all(target_arch = "arm", not(feature = "linked")))]
    pub fn exit(code: i32) -> ! {
        // SAFETY: `SVC #1` is the kernel's exit (catcard-kernel `app::SVC_EXIT`); it does
        // not come back.
        unsafe { core::arch::asm!("svc #1", in("r0") code, options(noreturn)) }
    }

    #[cfg(any(not(target_arch = "arm"), feature = "linked"))]
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

/// The screen an app draws on, the same canvas the firmware draws on.
///
/// [`screen::draw`] hands the app a [`screen::Frame`]: a [`Canvas`] in the firmware's own
/// coordinates, plus text in the firmware's own fonts ([`screen::Frame::text`]). The fonts
/// and the text drawing stay in the firmware, so an app does not carry its own copy. As
/// an app the canvas lives in the app's memory and the kernel draws text into it and
/// copies it to the panel (`present`); linked in, it is the firmware's frame, drawn in
/// place.
///
/// [`Canvas`]: catcard_ui::canvas::Canvas
pub mod screen {
    use catcard_ui::canvas::{Canvas, INK, Level};

    /// A face, named by its role: the firmware picks the board's own font for each.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub enum Font {
        /// 4x6 on every board.
        Tiny = 0,
        /// Notes and dense values.
        Small = 1,
        /// Readable text.
        Body = 2,
        /// Headings.
        Title = 3,
    }

    #[cfg(not(feature = "linked"))]
    use super::sys::call;
    #[cfg(not(feature = "linked"))]
    const TEXT: u32 = 19;
    #[cfg(not(feature = "linked"))]
    const TEXT_WIDTH: u32 = 20;
    #[cfg(not(feature = "linked"))]
    const LINE_HEIGHT: u32 = 21;

    #[cfg(feature = "linked")]
    fn face(font: Font) -> Option<&'static dyn catcard_ui::face::Face> {
        unsafe extern "Rust" {
            fn catcard_linked_face(id: u32) -> Option<&'static dyn catcard_ui::face::Face>;
        }
        // SAFETY: the firmware defines it whenever it links an app in.
        unsafe { catcard_linked_face(font as u32) }
    }

    /// How wide `s` is in `font`, in pixels.
    pub fn text_width(font: Font, s: &str) -> usize {
        #[cfg(feature = "linked")]
        {
            face(font).map_or(0, |f| s.bytes().map(|c| f.advance(c)).sum())
        }
        #[cfg(not(feature = "linked"))]
        {
            call(TEXT_WIDTH, font as u32, s.as_ptr() as u32, s.len() as u32) as usize
        }
    }

    /// One line of `font`, in pixels.
    pub fn line_height(font: Font) -> usize {
        #[cfg(feature = "linked")]
        {
            face(font).map_or(0, |f| f.line_height())
        }
        #[cfg(not(feature = "linked"))]
        {
            call(LINE_HEIGHT, font as u32, 0, 0) as usize
        }
    }

    /// The Q1's content area: the 4-bit 320x240 canvas below the 16-row status bar, as
    /// the firmware's `display::Surface` is.
    #[cfg(all(feature = "board-q1", not(feature = "linked")))]
    mod board {
        pub type Screen = catcard_ui::canvas::Gray4<320, 240, 38400>;
        pub const TOP: usize = 16;
    }

    /// The mono boards: the 128x64 framebuffer, all of it.
    #[cfg(all(not(feature = "board-q1"), not(feature = "linked")))]
    mod board {
        pub type Screen = catcard_ui::framebuffer::Framebuffer<128, 8, 1024>;
        pub const TOP: usize = 0;
    }

    /// One frame being drawn. A [`Canvas`], plus text.
    pub struct Frame<'a> {
        #[cfg(not(feature = "linked"))]
        screen: &'a mut board::Screen,
        #[cfg(feature = "linked")]
        canvas: &'a mut dyn Canvas,
    }

    impl Frame<'_> {
        /// Draw `s` in `font` with its top-left at `(x, y)`, in full ink. Returns the x
        /// just past the last glyph; stops at the right edge rather than wrapping.
        pub fn text(&mut self, font: Font, x: usize, y: usize, s: &str) -> usize {
            self.text_in(font, x, y, s, INK)
        }

        /// [`text`](Self::text) at a chosen ink level.
        pub fn text_in(&mut self, font: Font, x: usize, y: usize, s: &str, level: Level) -> usize {
            #[cfg(feature = "linked")]
            {
                match face(font) {
                    Some(f) => catcard_ui::text::draw_text_in(self.canvas, f, x, y, s, level),
                    None => x,
                }
            }
            #[cfg(not(feature = "linked"))]
            {
                let bytes: *mut board::Screen = self.screen;
                let args: [u32; 8] = [
                    bytes as u32,
                    core::mem::size_of::<board::Screen>() as u32,
                    x as u32,
                    y as u32,
                    font as u32,
                    level as u32,
                    s.as_ptr() as u32,
                    s.len() as u32,
                ];
                call(TEXT, args.as_ptr() as u32, 0, 0) as usize
            }
        }
    }

    impl Canvas for Frame<'_> {
        #[cfg(not(feature = "linked"))]
        fn width(&self) -> usize {
            Canvas::width(&*self.screen)
        }
        #[cfg(not(feature = "linked"))]
        fn height(&self) -> usize {
            Canvas::height(&*self.screen) - board::TOP
        }
        #[cfg(not(feature = "linked"))]
        #[inline(always)]
        fn put(&mut self, x: usize, y: usize, level: Level) {
            Canvas::put(&mut *self.screen, x, y + board::TOP, level)
        }
        #[cfg(not(feature = "linked"))]
        #[inline(always)]
        fn get(&self, x: usize, y: usize) -> Level {
            Canvas::get(&*self.screen, x, y + board::TOP)
        }

        #[cfg(feature = "linked")]
        fn width(&self) -> usize {
            self.canvas.width()
        }
        #[cfg(feature = "linked")]
        fn height(&self) -> usize {
            self.canvas.height()
        }
        #[cfg(feature = "linked")]
        fn put(&mut self, x: usize, y: usize, level: Level) {
            self.canvas.put(x, y, level)
        }
        #[cfg(feature = "linked")]
        fn get(&self, x: usize, y: usize) -> Level {
            self.canvas.get(x, y)
        }
    }

    /// Draw a frame with `f` and show it. The canvas keeps what the last frame drew, as
    /// the firmware's does: clear it first for a fresh one.
    #[cfg(feature = "linked")]
    pub fn draw(f: impl FnOnce(&mut Frame<'_>)) {
        unsafe extern "Rust" {
            fn catcard_linked_draw(f: &mut dyn FnMut(&mut dyn Canvas));
        }
        let mut f = Some(f);
        let mut once = |c: &mut dyn Canvas| {
            if let Some(f) = f.take() {
                f(&mut Frame { canvas: c })
            }
        };
        // SAFETY: the firmware defines it whenever it links an app in.
        unsafe { catcard_linked_draw(&mut once) }
    }

    #[cfg(not(feature = "linked"))]
    static mut SCREEN: board::Screen = board::Screen::new();

    #[cfg(not(feature = "linked"))]
    pub fn draw(f: impl FnOnce(&mut Frame<'_>)) {
        // SAFETY: one thread of execution in an app.
        let screen = unsafe { &mut *core::ptr::addr_of_mut!(SCREEN) };
        f(&mut Frame {
            screen: &mut *screen,
        });
        let bytes = screen.as_bytes();
        super::sys::call(
            super::sys::PRESENT,
            bytes.as_ptr() as u32,
            bytes.len() as u32,
            0,
        );
    }
}

#[cfg(all(target_os = "none", not(feature = "linked")))]
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
