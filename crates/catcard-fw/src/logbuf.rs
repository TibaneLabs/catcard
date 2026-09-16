//! The device's log: a ring in RAM, fetchable over USB or out of a dump.
//!
//! Every diagnostic this firmware had ended on a screen. That was fine until an mk5 came
//! up with a dark panel — it enumerated, took a PIN typed blind, and refused an upgrade
//! for a reason drawn where nobody could read it. This is the channel that does not
//! depend on the part that is broken.
//!
//! Two readers, one buffer. `#[no_mangle]` and `#[used]` keep it in the image and
//! findable by name, so the emulator's `--dump-ram` can read it exactly as
//! `CATCARD_BOOT_STATUS` is read; and [`Opcode::ReadLog`] pages it out over USB.
//!
//! **Nothing secret goes in here.** Anything that can open the USB port can read it,
//! including a host that has not proved it knows the PIN, and it outlives a logout. The
//! rule for a line is that it must be safe to read aloud to a stranger holding the
//! device: no PIN digits, no seed, no secret material, no anti-phishing words.

use core::fmt::{self, Write};

use catcard_log::Ring;

/// Bytes of history. Two kilobytes holds a boot and a few operations after it, which is
/// the span that has mattered every time so far.
pub const LOG_LEN: usize = 2048;

/// Marks the buffer in a RAM dump. Same idea as `CATCARD_BOOT_STATUS`'s magic: a dump is
/// a few hundred kilobytes of noise, and this is how a reader finds the log in it.
pub const LOG_MAGIC: u32 = 0xCA7C_106C;

/// The log itself.
///
/// `#[used]` and `#[no_mangle]` so it survives LTO at `opt-level = "s"` and can be found
/// by name in a dump.
#[unsafe(no_mangle)]
#[used]
pub static mut CATCARD_LOG: LogBuf = LogBuf {
    magic: LOG_MAGIC,
    ring: Ring::new(),
};

/// The buffer, with its marker.
pub struct LogBuf {
    /// Never read by this firmware -- it is here for whoever searches a RAM dump for
    /// the log, which is the reader that cannot ask where it is.
    #[allow(dead_code)]
    pub magic: u32,
    pub ring: Ring<LOG_LEN>,
}

/// Append a formatted line.
///
/// Never fails and never blocks: a log that can refuse is one more thing to check on a
/// path that is already going wrong.
///
/// **Safe to call from any task.** With the kernel running, a task can be preempted in
/// the middle of a write and another task can log in between, which would interleave two
/// lines inside the ring or corrupt its indices. So the line is formatted first, into a
/// buffer on the caller's own stack with interrupts on, and only the copy into the ring
/// happens with them masked. Formatting inside the critical section would have made every
/// log call a blackout of its own.
pub fn write_fmt(args: fmt::Arguments<'_>) {
    let mut line = Line::new();
    let _ = line.write_fmt(args);
    line.finish();
    cortex_m::interrupt::free(|_| {
        // SAFETY: the only mutable reference, taken with interrupts masked, so no other
        // task or handler can hold one while this is live.
        let buf = unsafe { &mut *core::ptr::addr_of_mut!(CATCARD_LOG) };
        buf.ring.write(line.as_bytes());
    });
}

/// Copy out from `offset`, counting from the oldest byte.
///
/// Masked for the same reason as [`write_fmt`]: a read preempted by a write would copy
/// half of one line and half of the next.
pub fn read(offset: usize, out: &mut [u8]) -> usize {
    cortex_m::interrupt::free(|_| {
        // SAFETY: interrupts are masked, so no write can be in progress.
        let buf = unsafe { &*core::ptr::addr_of!(CATCARD_LOG) };
        buf.ring.read(offset, out)
    })
}

/// How many bytes the log currently holds.
pub fn len() -> usize {
    cortex_m::interrupt::free(|_| {
        // SAFETY: as in `read`.
        let buf = unsafe { &*core::ptr::addr_of!(CATCARD_LOG) };
        buf.ring.len()
    })
}

/// Whether anything has been dropped off the back.
pub fn wrapped() -> bool {
    cortex_m::interrupt::free(|_| {
        // SAFETY: as in `read`.
        let buf = unsafe { &*core::ptr::addr_of!(CATCARD_LOG) };
        buf.ring.wrapped()
    })
}

/// Longest line kept whole. Longer ones are cut and marked, never silently shortened.
const LINE_MAX: usize = 192;

/// One formatted line, built on the caller's stack before it touches the shared ring.
struct Line {
    bytes: [u8; LINE_MAX],
    len: usize,
    cut: bool,
}

impl Line {
    const fn new() -> Self {
        Self {
            bytes: [0; LINE_MAX],
            len: 0,
            cut: false,
        }
    }

    /// End the line, marking it if the text did not fit.
    fn finish(&mut self) {
        // Always room for the newline, and for `~` before it when the line was cut.
        let room = LINE_MAX - 1 - usize::from(self.cut);
        self.len = self.len.min(room);
        if self.cut {
            self.bytes[self.len] = b'~';
            self.len += 1;
        }
        self.bytes[self.len] = b'\n';
        self.len += 1;
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl Write for Line {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        // Leave two bytes for `finish`'s marker and newline.
        let room = (LINE_MAX - 2).saturating_sub(self.len);
        let take = s.len().min(room);
        self.bytes[self.len..self.len + take].copy_from_slice(&s.as_bytes()[..take]);
        self.len += take;
        if take < s.len() {
            self.cut = true;
        }
        Ok(())
    }
}

/// Log a line. Same shape as `write!`, minus the destination.
///
/// Read the module docs before adding a call: this buffer is readable by any host.
#[macro_export]
macro_rules! catlog {
    ($($arg:tt)*) => {
        $crate::logbuf::write_fmt(format_args!($($arg)*))
    };
}
