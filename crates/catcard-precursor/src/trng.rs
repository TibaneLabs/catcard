//! The gateware TRNG, one noise source at a time.
//!
//! The Precursor has two physical noise sources: an avalanche diode sampled by the
//! FPGA's XADC, and a bank of ring oscillators inside the FPGA. The gateware folds each
//! into 32-bit words (32 ADC samples per avalanche word; oversampled rings), runs NIST
//! SP 800-90B repetition-count and adaptive-proportion tests on both, and fills a FIFO.
//! Source: betrusted gateware trng_managed.py (TrngManaged, TrngManagedServer) [C].
//!
//! Its default output is `avalanche ^ ring_osc`, and the FIFO is refilled whenever
//! *either* source passes its tests -- so a dead source is carried silently by the
//! other. This driver therefore reads the sources **apart**, using the control bits that
//! disable one or the other, and hands each to `catcard-entropy` under its own `Source`,
//! where it is health-tested and credited on its own and the policy can demand both.
//! Source: trng_managed.py `merged_trng` selection on `ro_dis` / `av_dis` [C].
//!
//! It reads the *server* FIFO (`trng_server_data`). The kernel-side raw port is
//! documented as racing the ChaCha reseeder; the server port is not. `urandom` (the
//! ChaCha conditioner's output) is deliberately not used: it is a DRBG, and the pool
//! wants the noise.

use crate::csr::{self, reg};

// trng_server_control. Source: trng_managed.py TrngManagedServer.control [C]
const CTL_ENABLE: u32 = 1 << 0;
const CTL_RO_DIS: u32 = 1 << 1;
const CTL_AV_DIS: u32 = 1 << 2;
/// Set: the sources power down between refills (the avalanche one then needs its 50 ms
/// power-on delay again). Cleared while we read, so the read is not a series of waits.
const CTL_POWERSAVE: u32 = 1 << 3;
const CTL_CLR_ERR: u32 = 1 << 4;

// trng_server_status: bit 0 `avail`. Source: TrngManagedServer.status [C]
const ST_AVAIL: u32 = 1 << 0;

// trng_server_ready: av_excursion[1:0], av_adaprop[3:2], ro_adaprop[7:4] -- set once each
// test's window has filled. Source: TrngManagedServer.ready [C]
const READY_AV_MASK: u32 = 0x0F;
const READY_RO_MASK: u32 = 0xF0;

// trng_server_nist_errors: av_repcount[1:0], av_adaptive[3:2], ro_repcount[7:4],
// ro_adaptive[11:8], ro_miniruns[15:12]. Source: TrngManagedServer.nist_errors [C]
const NIST_AV_MASK: u32 = 0x000F;
const NIST_RO_MASK: u32 = 0xFFF0;

/// The FIFO holds at most 1024 words (10-bit pointers); draining more than that means
/// it is refilling as fast as we read, i.e. the drain itself is not the bound.
/// Source: TrngManagedServer.status `rdcount`/`wrcount` field widths [C].
const FIFO_MAX_WORDS: u32 = 1024;
/// Words read and dropped after the drain, for any produced under the old selection
/// that were still in the pipeline. Generous: the pipeline is a handful of registers.
const PIPELINE_FLUSH_WORDS: u32 = 16;
/// Once words are flowing, one arrives every few tens of microseconds (avalanche ~15 KB/s,
/// rings ~75 KB/s on the bench unit). Half a second without one means the source has
/// stopped.
const WORD_TIMEOUT_MS: u64 = 500;
/// The first word after selecting a source can take much longer: a powered-down
/// avalanche source needs its 50 ms power-on delay, and the gateware then holds the FIFO
/// until its health tests' windows have filled and pass. Bounded all the same.
/// Source: trng_managed.py `powerdelay` reset 50000 us; FIFO write gated on test
/// readiness (`av_noiseout_ready`, `av_pass | ro_pass`) [C]. Measured: see `read`'s
/// return value, printed by the boot check.
const WARMUP_TIMEOUT_MS: u64 = 5000;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Which {
    Avalanche,
    RingOsc,
}

impl Which {
    pub const fn source(self) -> catcard_entropy::Source {
        match self {
            Which::Avalanche => catcard_entropy::Source::PrecursorAvalanche,
            Which::RingOsc => catcard_entropy::Source::PrecursorRingOsc,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Which::Avalanche => "avalanche",
            Which::RingOsc => "ring-osc",
        }
    }

    const fn disable_other(self) -> u32 {
        match self {
            Which::Avalanche => CTL_RO_DIS,
            Which::RingOsc => CTL_AV_DIS,
        }
    }

    const fn ready_mask(self) -> u32 {
        match self {
            Which::Avalanche => READY_AV_MASK,
            Which::RingOsc => READY_RO_MASK,
        }
    }

    const fn nist_mask(self) -> u32 {
        match self {
            Which::Avalanche => NIST_AV_MASK,
            Which::RingOsc => NIST_RO_MASK,
        }
    }
}

/// The TRNG's own view when a read stalled: health latches, test readiness, FIFO state.
/// None of it is derived from a sample's value.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Snapshot {
    /// Bytes of `out` filled before the stall (0 = stalled in warm-up or flush).
    pub bytes: usize,
    pub nist_errors: u32,
    pub ready: u32,
    pub status: u32,
    pub underruns: u32,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// No word arrived in time (`WARMUP_TIMEOUT_MS` for the first, then
    /// `WORD_TIMEOUT_MS`). Carries what the TRNG reported at that moment.
    Timeout(Snapshot),
    /// The FIFO did not drain: it refilled as fast as it was read.
    NoDrain,
    /// The gateware's own NIST tests flagged this source during the read. The value is
    /// the source's bits of `nist_errors`.
    GatewareHealth(u32),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Timeout(s) => write!(
                f,
                "no word after {} bytes: nist_errors={:#06x} ready={:#04x} status={:#010x} underruns={:#010x}",
                s.bytes, s.nist_errors, s.ready, s.status, s.underruns
            ),
            Error::NoDrain => write!(f, "FIFO did not drain"),
            Error::GatewareHealth(bits) => write!(f, "gateware health test failed ({bits:#06x})"),
        }
    }
}

/// Fills `out` with words from one source alone, then puts the TRNG back the way it
/// found it. `out.len()` should be a multiple of 4; a tail is filled from one more word.
/// Returns how long the source took to produce its first word after being selected.
///
/// The bytes are raw source output for the entropy pool -- treat them as secret: the
/// caller zeroizes its buffer once it has been absorbed.
pub fn read(which: Which, out: &mut [u8]) -> Result<u64, Error> {
    let saved = csr::read(reg::TRNG_SERVER_CONTROL) & !CTL_CLR_ERR;
    let result = read_inner(which, out);
    csr::write(reg::TRNG_SERVER_CONTROL, saved);
    result
}

fn read_inner(which: Which, out: &mut [u8]) -> Result<u64, Error> {
    let t0 = crate::timer::now_ms();

    // Warm up with both sources on, and clear the gateware's error latches *here*, never
    // with one source selected.
    //
    // The gateware refills the FIFO only once a source passes its tests (`av_pass |
    // ro_pass`), a test only passes once its window has filled, and the avalanche tests
    // only sample while words are being consumed -- by a refill. `clr_err` also resets the
    // tests' readiness. So with one source selected alone, a `clr_err` (or a power-down,
    // which also drops readiness) leaves nothing that can start a refill: the other
    // source is disabled and cannot carry it. Measured on the bench unit at CPU speed:
    // avalanche-only + `clr_err` gave 82 words and then none, ever, `ready = 0x03`; the
    // same with both sources on recovered within 250 ms, the ring oscillator carrying the
    // refills while the avalanche tests filled.
    // Source: trng_managed.py refill FSM (SELFTEST/REFILL gated on `av_pass | ro_pass`),
    // AdaptivePropTest `reset`/`enabled` clearing `ready` [C]; bench unit 2026-11-06 [C].
    csr::write(reg::TRNG_SERVER_CONTROL, CTL_ENABLE | CTL_CLR_ERR);
    let deadline = t0 + WARMUP_TIMEOUT_MS;
    while csr::read(reg::TRNG_SERVER_READY) & which.ready_mask() != which.ready_mask() {
        if csr::read(reg::TRNG_SERVER_STATUS) & ST_AVAIL != 0 {
            let _ = csr::read(reg::TRNG_SERVER_DATA);
        }
        crate::wdt::feed();
        if crate::timer::now_ms() >= deadline {
            return Err(Error::Timeout(snapshot(0)));
        }
    }

    // Now select the one source, kept powered so its tests stay ready. No `clr_err`: see
    // above. The latches were cleared at the start of the warm-up, so what they say after
    // the read covers it.
    let ctl = (CTL_ENABLE | which.disable_other()) & !CTL_POWERSAVE;
    csr::write(reg::TRNG_SERVER_CONTROL, ctl);

    // Whatever is in the FIFO was made under the previous selection -- likely the XOR of
    // both sources. Drop it, then a few more for the pipeline.
    let mut drained = 0;
    while csr::read(reg::TRNG_SERVER_STATUS) & ST_AVAIL != 0 {
        let _ = csr::read(reg::TRNG_SERVER_DATA);
        drained += 1;
        if drained > FIFO_MAX_WORDS {
            return Err(Error::NoDrain);
        }
    }
    next_word(WARMUP_TIMEOUT_MS, 0)?;
    let warmup_ms = crate::timer::now_ms() - t0;
    for _ in 1..PIPELINE_FLUSH_WORDS {
        next_word(WORD_TIMEOUT_MS, 0)?;
    }

    for (i, chunk) in out.chunks_mut(4).enumerate() {
        let w = next_word(WORD_TIMEOUT_MS, i * 4)?.to_le_bytes();
        chunk.copy_from_slice(&w[..chunk.len()]);
    }

    let flagged = csr::read(reg::TRNG_SERVER_NIST_ERRORS) & which.nist_mask();
    if flagged != 0 {
        return Err(Error::GatewareHealth(flagged));
    }
    Ok(warmup_ms)
}

fn next_word(timeout_ms: u64, bytes: usize) -> Result<u32, Error> {
    let deadline = crate::timer::now_ms() + timeout_ms;
    while csr::read(reg::TRNG_SERVER_STATUS) & ST_AVAIL == 0 {
        crate::wdt::feed();
        if crate::timer::now_ms() >= deadline {
            return Err(Error::Timeout(snapshot(bytes)));
        }
    }
    // `data` is only valid while `avail` is set, which was just checked; reading it pops
    // the word. Source: TrngManagedServer.data description [C].
    Ok(csr::read(reg::TRNG_SERVER_DATA))
}

fn snapshot(bytes: usize) -> Snapshot {
    Snapshot {
        bytes,
        nist_errors: csr::read(reg::TRNG_SERVER_NIST_ERRORS),
        ready: csr::read(reg::TRNG_SERVER_READY),
        status: csr::read(reg::TRNG_SERVER_STATUS),
        underruns: csr::read(reg::TRNG_SERVER_UNDERRUNS),
    }
}
