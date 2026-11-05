//! Boot-time check of both noise sources through the entropy pool, reported on the UART.
//!
//! Two kinds of numbers come out, kept strictly apart:
//!
//! - **Verdicts** from `catcard-entropy` on the bytes it absorbed: start-up test state,
//!   continuous-test trips, credited bits, whether a seed draw would be granted. These
//!   say nothing about any byte's value and are safe to print (the pool's own rule for
//!   `status`).
//! - **Statistics** -- bit bias, a byte chi-square, the longest run of a repeated byte
//!   -- computed on a *separate* test sample per source that is never absorbed, so
//!   printing them gives away nothing that went into the pool.
//!
//! A granted draw is wiped unread: this is a self-test, not seed generation.

use core::fmt::Write;

use catcard_entropy::{EntropyPool, Policy};
use zeroize::Zeroize;

use crate::trng::{self, Which};

/// Bytes absorbed per source: the 1024-byte SP 800-90B start-up window plus a margin.
const POOL_BYTES: usize = 1280;
/// Absorbed in pieces this size, each a continuous-test sample.
const CHUNK: usize = 256;
/// The throwaway sample the statistics are computed on.
const TEST_BYTES: usize = 4096;

pub fn run(out: &mut impl Write) {
    let mut pool = EntropyPool::new(Policy::precursor());
    pool.enforce_startup();

    for which in [Which::Avalanche, Which::RingOsc] {
        let mut buf = [0u8; POOL_BYTES];
        let t0 = crate::timer::now_ms();
        let read = trng::read(which, &mut buf);
        let ms = crate::timer::now_ms() - t0;
        match read {
            Ok(warmup) => {
                for chunk in buf.chunks(CHUNK) {
                    pool.add(which.source(), chunk);
                }
                let _ = writeln!(
                    out,
                    "rng {:9}: {} bytes in {} ms ({} B/s after {} ms warm-up) absorbed",
                    which.label(),
                    POOL_BYTES,
                    ms,
                    rate(POOL_BYTES, ms.saturating_sub(warmup)),
                    warmup
                );
            }
            Err(e) => {
                let _ = writeln!(out, "rng {:9}: read failed: {e}", which.label());
            }
        }
        buf.zeroize();

        if let Some(st) = pool.status(which.source()) {
            let _ = writeln!(
                out,
                "rng {:9}: start-up {:?}, last read ok {:?}, trips {}",
                which.label(),
                st.startup,
                st.last_ok,
                st.trips
            );
        }

        let mut test = [0u8; TEST_BYTES];
        match trng::read(which, &mut test) {
            Ok(warmup) => {
                let _ = writeln!(
                    out,
                    "rng {:9}: test sample warm-up {} ms",
                    which.label(),
                    warmup
                );
                print_stats(out, which, &test)
            }
            Err(e) => {
                let _ = writeln!(out, "rng {:9}: test sample failed: {e}", which.label());
            }
        }
    }

    let _ = writeln!(
        out,
        "rng pool: {} credited bits, {} hardware sources",
        pool.credited_bits(),
        pool.hardware_sources()
    );
    match pool.draw_seed() {
        Ok(mut seed) => {
            seed.zeroize();
            let _ = writeln!(out, "rng pool: seed draw GRANTED (self-test; wiped unread)");
        }
        Err(e) => {
            let _ = writeln!(out, "rng pool: seed draw REFUSED: {e}");
        }
    }
}

fn rate(bytes: usize, ms: u64) -> u64 {
    (bytes as u64 * 1000).checked_div(ms).unwrap_or(0)
}

fn print_stats(out: &mut impl Write, which: Which, s: &[u8]) {
    let ones: u32 = s.iter().map(|b| b.count_ones()).sum();
    let bits = (s.len() * 8) as u32;

    let mut hist = [0u32; 256];
    for &b in s {
        hist[b as usize] += 1;
    }
    // Chi-square against uniform, scaled by 100 to stay in integers. 255 degrees of
    // freedom: about 255 expected, 99% of fair samples fall under ~310.
    let expect = s.len() as u64; // times 256 / 256
    let chi100: u64 = hist
        .iter()
        .map(|&c| {
            let d = (c as i64) * 256 - expect as i64;
            (d * d) as u64
        })
        .sum::<u64>()
        * 100
        / (expect * 256);

    let mut longest = 1;
    let mut run = 1;
    for w in s.windows(2) {
        run = if w[0] == w[1] { run + 1 } else { 1 };
        longest = longest.max(run);
    }

    let _ = writeln!(
        out,
        "rng {:9}: test sample {} B (not absorbed): ones {}.{:02}%, chi2 {}.{:02} (df 255), longest repeat {}",
        which.label(),
        s.len(),
        ones * 100 / bits,
        (ones * 10000 / bits) % 100,
        chi100 / 100,
        chi100 % 100,
        longest
    );
}
