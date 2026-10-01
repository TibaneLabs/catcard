//! Raw TRNG samples over USB: the one reader, for both ways a computer asks.
//!
//! The entropy pool credits each hardware source at a fixed rate (`docs/ENTROPY.md`). That
//! rate is a policy until somebody has run the NIST SP 800-90B estimators over a long
//! capture of each source, and this is how the samples get off the device: exactly the
//! bytes [`Trngs::read`] returns -- the bytes New wallet passes to `pool.add` -- before any
//! mixing. `tools/trng_capture.py` drives it; `tools/trng_assess.py` runs the estimators.
//!
//! Two front ends share this reader and add nothing to how it reads:
//!
//! - **`DebugTrng`**, plaintext, **bench builds only** (`trngcap`, behind
//!   `usb-trng-capture`, a default feature that `SHIP=1` strips; CI checks a published
//!   image for its `trngcap:` marker -- which is why this reader has another name).
//!   Unlimited, for the long captures a credit rate rests on.
//! - **`RngSample`**, sealed inside a paired session, in every build ([`crate::rngshare`]):
//!   the person at the device says yes once per session, and the secure elements are read
//!   only so often ([`catcard_usb::rng::SeBudget`]).
//!
//! What keeps it away from secrets, by construction rather than by care:
//!
//! - **It never touches the pool.** Nothing here names `EntropyPool`: the bytes come from
//!   the same readers the pool is fed from, on their own, and go to the host. A byte read
//!   for a sample is never also fed to the pool, nor used for anything else, and the
//!   reverse.
//! - **It never runs during a seed operation.** The USB side only records what the host
//!   asked for. The reads happen in [`serve`], which only the main menu loop calls, on the
//!   UI task -- the same task every seed flow runs on, synchronously, from that loop. While
//!   New wallet (or any flow) is running, the menu loop is not, so neither is a read.
//!   The same holds for the chip TRNG's registers: one task reads them at a time.
//! - **It is bounded.** One chunk of at most [`CHUNK_MAX`] bytes per request, with a
//!   bounded number of reads per chunk, so a silent source ends a chunk short instead of
//!   holding the menu. A paired chunk from a secure element is read a few calls at a
//!   time ([`PAIRED_SE_CALLS`]), so the menu loop gets back to the keys between them.

use catcard_callgate::Callgate;
use catcard_usb::Status;
use catcard_usb::rng::{self, Chunk, SeBudget, flags};
use zeroize::Zeroize;

use crate::trng::{Kind, Trngs};

pub use catcard_usb::rng::{CHUNK_MAX, REPLY_LEN};

/// Secure-element calls one paired chunk may make. A call is about 20-30 ms on the
/// mk3's own bus and a callgate round trip on the others; four keep a chunk well under a
/// frame's worth of key latency the person would notice, and the host simply asks again.
pub const PAIRED_SE_CALLS: u16 = 4;

/// The wire number of a source. Fixed: a host keeps captures by it. 4 was the
/// bootloader's read (callgate 17), which is no longer read; the number stays retired
/// rather than reused, so an old capture file is never mistaken for a new source.
pub(crate) const fn wire_id(kind: Kind) -> u8 {
    match kind {
        Kind::Chip => rng::source::CHIP,
        Kind::Se1 => rng::source::SE1,
        Kind::Se2 => rng::source::SE2,
        Kind::Se1Wire => rng::source::SE1_WIRE,
    }
}

/// The source a wire number names, if this board has it.
fn kind_of(id: u8) -> Option<Kind> {
    crate::trng::kinds().into_iter().find(|&k| wire_id(k) == id)
}

/// Which secure element a source reads, as the allowance counts them: SE1 by either
/// path is one chip.
const fn se_slot(kind: Kind) -> Option<usize> {
    match kind {
        Kind::Se1 | Kind::Se1Wire => Some(0),
        Kind::Se2 => Some(1),
        Kind::Chip => None,
    }
}

/// Who asked: the bench's plaintext command, or a paired session (by its number).
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Origin {
    Bench,
    Paired(u32),
}

#[derive(Copy, Clone, PartialEq, Eq)]
struct Want {
    kind: Kind,
    len: u16,
    origin: Origin,
}

#[derive(Copy, Clone)]
struct Ready {
    want: Want,
    n: u16,
    flags: u8,
    chunk: u32,
}

/// What the USB task and the menu loop share: the request waiting to be read, the chunk
/// waiting to be collected, and what the secure elements have been read.
struct Shared {
    want: Option<Want>,
    ready: Option<Ready>,
    chunks: u32,
    budget: SeBudget,
}

static mut SHARED: Shared = Shared {
    want: None,
    ready: None,
    chunks: 0,
    budget: SeBudget::new(),
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

/// The list reply: what this board can sample, and how much at a time.
pub fn list(out: &mut [u8]) -> usize {
    let mut ids: heapless::Vec<u8, 4> = heapless::Vec::new();
    for k in crate::trng::kinds() {
        let _ = ids.push(wire_id(k));
    }
    rng::list_body(&ids, out)
}

/// A request for one chunk, from either front end (USB task). Writes the reply body into
/// `out` (at least [`REPLY_LEN`] bytes) and returns the status and the body's length.
///
/// Reads nothing itself: a new request is recorded for [`serve`] and answered `NotNow`;
/// the same request asked again collects the chunk once it is ready, and queues the next.
/// A paired `NotNow` carries [`rng::wait::READING`]; a paired request for a secure element
/// whose allowance is spent is `Refused` + the [`rng::limit`] reason.
pub fn request(origin: Origin, source: u8, len: u16, out: &mut [u8]) -> (Status, usize) {
    if out.len() < REPLY_LEN || len == 0 || len as usize > CHUNK_MAX {
        return (Status::BadRequest, 0);
    }
    let Some(kind) = kind_of(source) else {
        return (Status::Refused, 0);
    };
    let asked = Want { kind, len, origin };
    let reading = |out: &mut [u8]| match origin {
        Origin::Bench => (Status::NotNow, 0),
        Origin::Paired(_) => {
            out[0] = rng::wait::READING;
            (Status::NotNow, 1)
        }
    };
    with(|s, buf| {
        if let Some(r) = s.ready
            && r.want == asked
        {
            let n = r.n as usize;
            Chunk {
                source,
                flags: r.flags,
                n: r.n,
                number: r.chunk,
            }
            .write(out);
            out[rng::HEADER..rng::HEADER + n].copy_from_slice(&buf[..n]);
            buf.zeroize();
            s.ready = None;
            // Start the next one now, so a host that keeps asking is not waiting on a
            // round trip per chunk -- unless the source has just refused, or the
            // allowance has just run out. Never for a paired secure-element read: each
            // one is a call that may wear the chip, made only when a host asked for it.
            let spends = matches!(origin, Origin::Paired(_)) && se_slot(kind).is_some();
            s.want = (r.flags & (flags::REFUSED | flags::LIMIT) == 0 && !spends).then_some(asked);
            return (Status::Ok, rng::HEADER + n);
        }
        if s.want != Some(asked) {
            // A paired request for a secure element needs some of its allowance left.
            if let (Origin::Paired(id), Some(se)) = (origin, se_slot(kind))
                && let Err(why) = s.budget.allowance(id, se)
            {
                out[0] = why;
                return (Status::Refused, 1);
            }
            // A different request replaces whatever was waiting, collected or not.
            s.ready = None;
            buf.zeroize();
            s.want = Some(asked);
        }
        reading(out)
    })
}

/// A paired session ended: drop what it asked for and what was read for it, so nothing
/// is read for a computer that is no longer there. A bench request is left alone.
pub fn session_ended() {
    with(|s, buf| {
        if matches!(s.want, Some(w) if w.origin != Origin::Bench) {
            s.want = None;
        }
        if matches!(s.ready, Some(r) if r.want.origin != Origin::Bench) {
            s.ready = None;
            buf.zeroize();
        }
    });
}

/// Read the waiting request's chunk, if there is one (menu loop, UI task).
///
/// Only the main menu loop calls this -- see the module note for why that is what keeps
/// a sample out of every seed operation.
#[inline(never)]
pub fn serve(gate: &Callgate) {
    let Some((want, allowed)) = with(|s, _| {
        let want = if s.ready.is_none() { s.want } else { None }?;
        let allowed = match (want.origin, se_slot(want.kind)) {
            (Origin::Paired(id), Some(se)) => match s.budget.allowance(id, se) {
                Ok(left) => Some(left.min(PAIRED_SE_CALLS)),
                // Spent since it was asked for (another session read it): nothing to read.
                Err(_) => Some(0),
            },
            _ => None,
        };
        Some((want, allowed))
    }) else {
        return;
    };
    let len = want.len as usize;
    let mut buf = [0u8; CHUNK_MAX];
    let mut trngs = Trngs::new(Some(gate));
    let mut n = 0usize;
    let mut fl = 0u8;
    // Bounded: SE1 answers 32 bytes a call and SE2 8 (hw-reference/bootloader-callgate-abi.md
    // §"RNG gates" [C]), so 32 bytes take at most four calls. Eight tries per 32 bytes
    // covers that twice over and still ends when a source goes quiet. A paired secure-element chunk is bounded
    // tighter, by what its allowance and [`PAIRED_SE_CALLS`] leave.
    let max_tries = match allowed {
        Some(a) => a as usize,
        None => 8 * len.div_ceil(32) + 8,
    };
    let mut calls = 0u16;
    for _ in 0..max_tries {
        if n >= len {
            break;
        }
        let _ = crate::usbtask::pump();
        calls += 1;
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
        if let (Origin::Paired(id), Some(se)) = (want.origin, se_slot(want.kind)) {
            // Counted whether or not the host is still there to collect them.
            s.budget.spend(id, se, calls);
            if s.budget.allowance(id, se).is_err() {
                fl |= flags::LIMIT;
            }
        }
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
    // One line for the first chunk and then every 256th, and every refused or limited
    // one: a million bytes is two thousand chunks, and the log is a ring. A paired
    // secure element's chunk is short by design, so short alone is not worth a line.
    if let Some(c) = chunk
        && (c % 256 == 1
            || fl & (flags::REFUSED | flags::LIMIT) != 0
            || (want.origin == Origin::Bench && fl != 0))
    {
        crate::catlog!(
            "rng sample: {} chunk {} {}B flags {}",
            want.kind.label(),
            c,
            n,
            fl
        );
    }
}
