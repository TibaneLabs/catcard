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
#[no_mangle]
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
pub fn write_fmt(args: fmt::Arguments<'_>) {
    // SAFETY: the boot path is single-threaded and nothing here runs in interrupt
    // context, so no two references are live at once.
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(CATCARD_LOG) };
    let mut w = Sink(&mut buf.ring);
    let _ = w.write_fmt(args);
    let _ = w.write_str("\n");
}

/// Copy out from `offset`, counting from the oldest byte.
pub fn read(offset: usize, out: &mut [u8]) -> usize {
    // SAFETY: as above; this only reads.
    let buf = unsafe { &*core::ptr::addr_of!(CATCARD_LOG) };
    buf.ring.read(offset, out)
}

/// How many bytes the log currently holds.
pub fn len() -> usize {
    // SAFETY: as above.
    let buf = unsafe { &*core::ptr::addr_of!(CATCARD_LOG) };
    buf.ring.len()
}

/// Whether anything has been dropped off the back.
pub fn wrapped() -> bool {
    // SAFETY: as above.
    let buf = unsafe { &*core::ptr::addr_of!(CATCARD_LOG) };
    buf.ring.wrapped()
}

struct Sink<'a>(&'a mut Ring<LOG_LEN>);

impl Write for Sink<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.write(s.as_bytes());
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
