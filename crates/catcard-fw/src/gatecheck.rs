//! Debug -> Bootloader replies: the raw return value of every read-only callgate this
//! firmware treats as "0 is success", called harmlessly and logged.
//!
//! The bootloader refuses a call with a **positive** code -- `EPERM` for a buffer outside
//! its window, `ERANGE` for a bad length or `arg2`, `ENOENT` for a method it does not
//! have -- and leaves the buffer untouched. For a method whose success value is 0, every
//! nonzero return is a failure.
//! Source: hw-reference/bootloader-callgate-abi.md §0.1 "Refusal codes", §"RNG gates" [C]
//!
//! `Callgate::decode` lets every non-negative value through, because gate 0 returns a
//! length. So a refused gate 16, 19/0 or 26 reads today as a success over a buffer
//! nobody wrote: gate 16 would turn the PIN prefix itself into the two words, and gate 26
//! would hand back a zero length. Only gate 18 checks for exactly 0.
//!
//! Tightening those wrappers changes the login path (gate 16) and boot's entropy reads
//! (gate 26) on locked units, so it is only made once this screen has shown what the
//! bench units actually return. Nothing here changes state: gate 0 reads a string, 16
//! HMACs a fixed two-digit prefix, 19/0 reads the bag number, 21/0 reads the
//! anti-downgrade mark and 26 reads randomness, which is discarded.

use core::fmt::Write as _;

use catcard_callgate::abi::{BagOp, Method, OtpOp, RngSource};
use catcard_callgate::{Callgate, Error};
use catcard_ui::scroll::Line as Row;
use zeroize::Zeroize as _;

use crate::menu;
use crate::ui::Ui;

type Text = heapless::String<48>;

/// Calls made to each secure element's randomness: enough to see whether refusals are
/// occasional or the rule.
pub const SE_CALLS: usize = 8;

/// The value the bootloader returned, whichever way `decode` sorted it. `None` when the
/// call never reached the bootloader (refused on our side before the jump).
fn raw(r: Result<i32, Error>) -> Option<i32> {
    match r {
        Ok(rv) | Err(Error::Pin(rv)) | Err(Error::Failed(rv)) => Some(rv),
        Err(_) => None,
    }
}

fn put(t: &mut Text, rv: Option<i32>) {
    let _ = match rv {
        Some(rv) => write!(t, " {rv}"),
        None => t.push_str(" -").map_err(|_| core::fmt::Error),
    };
}

/// One gate read into `buf`, logged and listed as `label: rv N`.
fn one(texts: &mut heapless::Vec<Text, 8>, label: &str, rv: Option<i32>) {
    let mut t = Text::new();
    let _ = t.push_str(label);
    let _ = t.push_str(": rv");
    put(&mut t, rv);
    crate::catlog!("gatecheck: {}", t.as_str());
    let _ = texts.push(t);
}

/// Every raw return [`collect`] gathers. `None` where the call never reached the
/// bootloader.
pub struct Replies {
    pub version: Option<i32>,
    pub words: Option<i32>,
    pub bag: Option<i32>,
    pub min_version: Option<i32>,
    /// Gate 26 per call: the return and the length byte, SE1 then SE2.
    pub se: [[(Option<i32>, u8); SE_CALLS]; 2],
}

/// Call each "0 is success" gate harmlessly and keep what it returned.
pub fn collect(gate: &Callgate) -> Replies {
    // Gate 0: the one method here whose return is a length, for comparison.
    let mut buf = [0u8; 64];
    // SAFETY: the documented >=64-byte output buffer; a read.
    let version = raw(unsafe { gate.call(Method::GetBootloaderVersion, &mut buf, 0) });

    // Gate 16 over a fixed prefix that is nobody's PIN.
    let mut buf = [0u8; catcard_callgate::pin::MAX_PIN_LEN];
    buf[..2].copy_from_slice(b"12");
    // SAFETY: `arg2` is the prefix length and the buffer is MAX_PIN_LEN, as documented.
    let words = raw(unsafe { gate.call(Method::AntiPhishingWords, &mut buf, 2) });
    buf.zeroize();

    let mut buf = [0u8; 32];
    // SAFETY: the documented 32-byte buffer; 19/0 only reads.
    let bag = raw(unsafe { gate.call(Method::BagNumber, &mut buf, BagOp::Read as u32) });

    let mut buf = [0u8; 8];
    // SAFETY: the documented 8-byte buffer; 21/0 only reads the mark.
    let min_version =
        raw(unsafe { gate.call(Method::Downgrade, &mut buf, OtpOp::ReadMinVersion as u32) });

    // Gate 26: the return and the length byte of each call. On the mk3 the method does not
    // exist, which is itself worth seeing (ENOENT, by the reference).
    let mut se = [[(None, 0u8); SE_CALLS]; 2];
    for (i, src) in [RngSource::Se1, RngSource::Se2].into_iter().enumerate() {
        for call in se[i].iter_mut() {
            let mut buf = [0u8; 33];
            // SAFETY: the documented 33-byte output buffer.
            let rv = raw(unsafe { gate.call(Method::ReadSeRng, &mut buf, src as u32) });
            *call = (rv, buf[0]);
            buf.zeroize();
        }
    }
    Replies {
        version,
        words,
        bag,
        min_version,
        se,
    }
}

/// Only the bench's `DebugGateCheck` sends this.
#[cfg(feature = "usb-debug-mem")]
/// [`collect`]'s result for USB: four `i32` returns (0, 16, 19/0, 21/0), then for SE1 and
/// SE2 [`SE_CALLS`] pairs of `i32` return and `u8` length. `i32::MIN` stands for a call
/// that never reached the bootloader. Returns the bytes written.
pub fn encode(r: &Replies, out: &mut [u8]) -> usize {
    let v = |rv: Option<i32>| rv.unwrap_or(i32::MIN).to_le_bytes();
    let mut at = 0;
    let mut put = |bytes: &[u8]| {
        if let Some(dst) = out.get_mut(at..at + bytes.len()) {
            dst.copy_from_slice(bytes);
        }
        at += bytes.len();
    };
    for rv in [r.version, r.words, r.bag, r.min_version] {
        put(&v(rv));
    }
    for source in &r.se {
        for (rv, len) in source {
            put(&v(*rv));
            put(&[*len]);
        }
    }
    at
}

pub fn screen(gate: &Callgate, ui: &mut Ui<'_>) {
    let r = collect(gate);
    let mut texts: heapless::Vec<Text, 8> = heapless::Vec::new();
    one(&mut texts, "0 version", r.version);
    one(&mut texts, "16 words", r.words);
    one(&mut texts, "19/0 bag", r.bag);
    one(&mut texts, "21/0 min version", r.min_version);
    for (source, label) in r.se.iter().zip(["26/1", "26/2"]) {
        let mut t = Text::new();
        let mut lens = Text::new();
        let _ = write!(t, "{label} rv");
        let _ = lens.push_str(" len");
        for (rv, len) in source {
            put(&mut t, *rv);
            let _ = write!(lens, " {len}");
        }
        crate::catlog!("gatecheck: {}{}", t.as_str(), lens.as_str());
        let _ = texts.push(t);
        let _ = texts.push(lens);
    }

    let mut rows: heapless::Vec<Row<'_>, 10> = heapless::Vec::new();
    let _ = rows.push(Row::title("Bootloader replies"));
    for t in &texts {
        let _ = rows.push(Row::body(t.as_str()).wrapped());
    }
    let _ = menu::show_doc(ui, &rows, false, false);
}
