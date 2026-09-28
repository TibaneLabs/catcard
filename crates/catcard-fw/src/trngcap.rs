//! Raw TRNG capture over USB (`DebugTrng`), for measuring the sources offline.
//!
//! The entropy pool credits each hardware source at a fixed rate (`docs/ENTROPY.md`). That
//! rate is a policy until somebody has run the NIST SP 800-90B estimators over a long
//! capture of each source, and this is how the capture gets off the device: exactly the
//! bytes [`Trngs::read`] returns -- the bytes New wallet passes to `pool.add` -- before any
//! mixing. `tools/trng_capture.py` drives it; `tools/trng_assess.py` runs the estimators.
//!
//! **Bench builds only** (`usb-trng-capture`, a default feature that `SHIP=1` strips, and
//! CI checks a published image for the `trngcap:` marker this module logs). A release has
//! no business handing out raw noise, however harmless it is on its own.
//!
//! What keeps it away from secrets, by construction rather than by care:
//!
//! - **It never touches the pool.** Nothing here names `EntropyPool`: the bytes come from
//!   the same readers the pool is fed from, on their own, and go to the host. A byte read
//!   for a capture is never also fed to the pool, and the reverse.
//! - **It never runs during a seed operation.** The USB side only records what the host
//!   asked for. The reads happen in [`serve`], which only the main menu loop calls, on the
//!   UI task -- the same task every seed flow runs on, synchronously, from that loop. While
//!   New wallet (or any flow) is running, the menu loop is not, so neither is a capture.
//!   The same holds for the chip TRNG's registers: one task reads them at a time.
//! - **It is bounded.** One chunk of at most [`CHUNK_MAX`] bytes per request, with a
//!   bounded number of reads per chunk, so a silent source ends a chunk short instead of
//!   holding the menu.

use catcard_callgate::Callgate;
use catcard_usb::Status;
use zeroize::Zeroize;

use crate::trng::{Kind, Trngs};

/// Largest chunk one request returns: fourteen of the secure elements' 32-byte answers,
/// which keeps the reply (with its 8-byte header) inside the USB task's 512-byte reply.
pub const CHUNK_MAX: usize = 448;

/// Bytes ahead of the data in an `Ok` reply: `[u8 source][u8 flags][u16 n][u32 chunk]`.
pub const HEADER: usize = 8;

/// The largest body [`request`] writes.
pub const REPLY_LEN: usize = HEADER + CHUNK_MAX;

/// Bits in the flags byte of a chunk.
pub mod flags {
    /// The source produced fewer bytes than asked within the read bound.
    pub const SHORT: u8 = 1 << 0;
    /// The source refused a read (a callgate error, a dead bus). The chunk ends there.
    pub const REFUSED: u8 = 1 << 1;
}

/// The wire number of a source. Fixed: a host keeps captures by it. 4 was the
/// bootloader's read (callgate 17), which is no longer read; the number stays retired
/// rather than reused, so an old capture file is never mistaken for a new source.
const fn wire_id(kind: Kind) -> u8 {
    match kind {
        Kind::Chip => 1,
        Kind::Se1 => 2,
        Kind::Se2 => 3,
        Kind::Se1Wire => 5,
    }
}

/// The source a wire number names, if this board has it.
fn kind_of(id: u8) -> Option<Kind> {
    crate::trng::kinds().into_iter().find(|&k| wire_id(k) == id)
}

#[derive(Copy, Clone, PartialEq, Eq)]
struct Want {
    kind: Kind,
    len: u16,
}

#[derive(Copy, Clone)]
struct Ready {
    want: Want,
    n: u16,
    flags: u8,
    chunk: u32,
}

/// What the USB task and the menu loop share: the request waiting to be read, and the
/// chunk waiting to be collected.
struct Shared {
    want: Option<Want>,
    ready: Option<Ready>,
    chunks: u32,
}

static mut SHARED: Shared = Shared {
    want: None,
    ready: None,
    chunks: 0,
};

/// The chunk itself, apart from `SHARED` so it is zero-initialised (`.bss`) rather than
/// carried in the image as `.data`.
static mut BUF: [u8; CHUNK_MAX] = [0; CHUNK_MAX];

fn with<R>(f: impl FnOnce(&mut Shared, &mut [u8; CHUNK_MAX]) -> R) -> R {
    cortex_m::interrupt::free(|_| {
        // SAFETY: the only references to `SHARED` and `BUF`, taken with interrupts masked
        // on a single core, so neither the USB task nor the menu loop can hold one at the
        // same time.
        let (s, b) = unsafe {
            (
                &mut *core::ptr::addr_of_mut!(SHARED),
                &mut *core::ptr::addr_of_mut!(BUF),
            )
        };
        f(s, b)
    })
}

/// Answer a `DebugTrng` request (USB task). Writes the reply body into `out` (at least
/// [`REPLY_LEN`] bytes) and returns the status and the body's length.
///
/// Reads nothing itself: a new request is recorded for [`serve`] and answered `NotNow`;
/// the same request asked again collects the chunk once it is ready, and queues the next.
pub fn request(p: &[u8], out: &mut [u8]) -> (Status, usize) {
    if out.len() < REPLY_LEN {
        return (Status::Busy, 0);
    }
    if p.is_empty() {
        // What this board can capture, and how much at a time.
        out[..2].copy_from_slice(&(CHUNK_MAX as u16).to_le_bytes());
        let kinds = crate::trng::kinds();
        out[2] = kinds.len() as u8;
        for (i, &k) in kinds.iter().enumerate() {
            out[3 + i] = wire_id(k);
        }
        return (Status::Ok, 3 + kinds.len());
    }
    if p.len() != 3 {
        return (Status::BadRequest, 0);
    }
    let len = u16::from_le_bytes([p[1], p[2]]);
    if len == 0 || len as usize > CHUNK_MAX {
        return (Status::BadRequest, 0);
    }
    let Some(kind) = kind_of(p[0]) else {
        return (Status::Refused, 0);
    };
    let asked = Want { kind, len };
    with(|s, buf| {
        if let Some(r) = s.ready
            && r.want == asked
        {
            let n = r.n as usize;
            out[0] = wire_id(kind);
            out[1] = r.flags;
            out[2..4].copy_from_slice(&r.n.to_le_bytes());
            out[4..8].copy_from_slice(&r.chunk.to_le_bytes());
            out[HEADER..HEADER + n].copy_from_slice(&buf[..n]);
            buf.zeroize();
            s.ready = None;
            // Start the next one now, so a host that keeps asking is not waiting on a
            // round trip per chunk -- unless the source has just refused.
            s.want = (r.flags & flags::REFUSED == 0).then_some(asked);
            return (Status::Ok, HEADER + n);
        }
        if s.want != Some(asked) {
            // A different request replaces whatever was waiting, collected or not.
            s.ready = None;
            buf.zeroize();
            s.want = Some(asked);
        }
        (Status::NotNow, 0)
    })
}

/// Read the waiting request's chunk, if there is one (menu loop, UI task).
///
/// Only the main menu loop calls this -- see the module note for why that is what keeps
/// a capture out of every seed operation.
#[inline(never)]
pub fn serve(gate: &Callgate) {
    let Some(want) = with(|s, _| if s.ready.is_none() { s.want } else { None }) else {
        return;
    };
    let len = want.len as usize;
    let mut buf = [0u8; CHUNK_MAX];
    let mut trngs = Trngs::new(Some(gate));
    let mut n = 0usize;
    let mut fl = 0u8;
    // Bounded: a secure element answers 32 bytes a call when it answers at all, and the
    // slower one declines about three calls in four. Eight tries per 32 bytes covers that
    // and still ends when a source goes quiet.
    let max_tries = 8 * len.div_ceil(32) + 8;
    for _ in 0..max_tries {
        if n >= len {
            break;
        }
        let _ = crate::usbtask::pump();
        match trngs.read(want.kind, &mut buf[n..len]) {
            Some(got) => n += got,
            None => {
                fl |= flags::REFUSED;
                break;
            }
        }
    }
    if n < len {
        fl |= flags::SHORT;
    }
    let chunk = with(|s, shared| {
        // The host may have moved on to another request while this one was being read.
        if s.want != Some(want) || s.ready.is_some() {
            return None;
        }
        s.chunks = s.chunks.wrapping_add(1);
        shared[..n].copy_from_slice(&buf[..n]);
        s.ready = Some(Ready {
            want,
            n: n as u16,
            flags: fl,
            chunk: s.chunks,
        });
        s.want = None;
        Some(s.chunks)
    });
    buf.zeroize();
    // One line for the first chunk and then every 256th, and every short one: a million
    // bytes is two thousand chunks, and the log is a ring.
    if let Some(c) = chunk
        && (c % 256 == 1 || fl != 0)
    {
        crate::catlog!(
            "trngcap: {} chunk {} {}B flags {}",
            want.kind.label(),
            c,
            n,
            fl
        );
    }
}
