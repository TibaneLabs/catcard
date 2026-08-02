//! Early bring-up.
//!
//! The ordering here is the security-critical part: the entropy pool is filled from
//! every hardware noise source the board has, and its policy is checked, before any
//! code path could ask it for seed material. A pool that cannot meet its policy stays
//! unusable rather than degrading to something weaker.

use catcard_board::BOARD;
use catcard_callgate::{abi::RngSource, Callgate};
use catcard_entropy::{EntropyPool, Source};
use catcard_hal::{dwt, uid};

use crate::{entropy_policy, BootReport};

/// Bytes to draw from each hardware TRNG.
///
/// 64 bytes is credited 256 bits at the pool's deliberately halved rate, so a single
/// source can satisfy the mk3 policy on its own while mk4 still needs two chips to
/// agree that they are alive.
const TRNG_BYTES: usize = 64;

pub fn bring_up() -> BootReport {
    // SAFETY: this is the reset path; nothing else has touched these peripherals.
    let hal = unsafe { catcard_hal::init_core() };
    let dwt_running = dwt::is_running();

    let mut pool = EntropyPool::new(entropy_policy());

    // Domain separation only. The UID is public (it is the USB serial number) and is
    // credited zero bits -- mixing it makes two devices' pools differ, nothing more.
    // SAFETY: reads the factory UID region, which is always mapped.
    unsafe { uid::feed_pool(&mut pool) };

    // The chip TRNG: the source the stock firmware never used for the seed.
    if let Ok(rng) = &hal {
        let _ = rng.feed_pool(&mut pool, TRNG_BYTES);
    }

    // The secure-element TRNGs, where the bootloader exposes them. Both are optional:
    // a missing callgate must not stop the pool from reaching its policy on a board
    // whose policy does not require them.
    feed_secure_elements(&mut pool);

    // A little startup timing jitter. Credited 1 bit per byte, so this cannot
    // meaningfully substitute for a TRNG -- it only ever tops up.
    if dwt_running {
        for _ in 0..16 {
            pool.add_timing(dwt::cycles());
            dwt::delay_cycles(97);
        }
    }

    let entropy = pool.check().map(|()| pool.credited_bits());

    BootReport {
        hal: hal.map(|_| ()),
        entropy,
        dwt_running,
        pool: Some(pool),
    }
}

/// Draw from SE1 and SE2 through bootloader callgate 26.
///
/// Does nothing today: the callgate entry address is not yet known for any board, so
/// [`Callgate::from_board`] returns `None`. The code path exists and is wired up so
/// that filling in one address in `catcard-board` is the whole change.
fn feed_secure_elements(pool: &mut EntropyPool) {
    if !BOARD.has_callgate_se_rng {
        return;
    }
    // SAFETY: `from_board` only produces a handle if the board spec carries an address
    // asserted to be correct for this hardware; today it always returns `None`.
    let Some(gate) = (unsafe { Callgate::from_board(&BOARD) }) else {
        return;
    };

    for (src, tag) in [
        (RngSource::Se1, Source::Se1Trng),
        (RngSource::Se2, Source::Se2Trng),
    ] {
        // Callgate 26 returns at most 32 bytes per call, so draw repeatedly.
        let mut got = 0usize;
        while got < TRNG_BYTES {
            let mut buf = [0u8; 33];
            // SAFETY: exactly the documented 33-byte output buffer for callgate 26.
            // `buf` is on the stack, which is in SRAM1; `call` range-checks it anyway.
            match unsafe { gate.se_rng(src, &mut buf) } {
                Ok(n) if n > 0 => {
                    pool.add(tag, &buf[1..1 + n]);
                    got += n;
                }
                // A secure element that will not produce entropy is not a reason to
                // fall back to something weaker; the policy check decides what happens.
                _ => break,
            }
        }
    }
}
