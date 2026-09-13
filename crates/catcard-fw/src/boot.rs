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

use crate::{display, entropy_policy, splash, BootReport};

/// Bytes to draw from each hardware TRNG.
///
/// 64 bytes is credited 256 bits at the pool's deliberately halved rate, so a single
/// source can satisfy the mk3 policy on its own while mk4 still needs two chips to
/// agree that they are alive.
const TRNG_BYTES: usize = 64;

/// How long the finished splash stays up before the next screen replaces it.
///
/// Bring-up takes a few milliseconds on real hardware, so the splash was drawn and
/// overwritten faster than anyone could read it -- it only ever looked right under the
/// emulator, which is slow enough to hide the problem. The delay is deliberate and goes
/// here rather than in the drawing code, because it is about the boot sequence being
/// too fast to watch, not about how the screen is painted.
///
/// The core runs on the MSI reset default of 4 MHz (RM0351 §6.2.2 [C]), which makes this
/// about 1.5 seconds. It is a cycle count, so programming the PLL changes what it means
/// -- see `docs/HARDWARE-OPEN-ITEMS.md`.
/// How long the finished splash stays up, in milliseconds.
///
/// A wall-clock time, not a cycle count: the part runs at the bootloader's 80 MHz, so a
/// count calibrated for 4 MHz held the splash ~20x too briefly to see.
const SPLASH_MIN_MS: u32 = 500;

/// Bring the machine up, showing the splash as it goes.
///
/// `hal` comes in already initialised because the panel's reset pulse needs the cycle
/// counter, so the display cannot be brought up before the core is. `panel` is optional
/// throughout: a device whose display did not start must still finish booting and reach
/// a state where the fault can be read out over SWD.
pub fn bring_up(
    hal: Result<catcard_hal::rng::Rng, catcard_hal::InitError>,
    mut panel: Option<&mut display::Panel>,
) -> BootReport {
    let dwt_running = dwt::is_running();
    let splash_started = dwt::cycles();
    let step = |panel: &mut Option<&mut display::Panel>, pct: u8| {
        if let Some(p) = panel.as_deref_mut() {
            splash::show(p, pct);
        }
    };

    step(&mut panel, 10);
    let mut pool = EntropyPool::new(entropy_policy());

    // Domain separation only. The UID is public (it is the USB serial number) and is
    // credited zero bits -- mixing it makes two devices' pools differ, nothing more.
    // SAFETY: reads the factory UID region, which is always mapped.
    unsafe { uid::feed_pool(&mut pool) };
    step(&mut panel, 25);

    // The chip TRNG: the source the stock firmware never used for the seed.
    if let Ok(rng) = &hal {
        let _ = rng.feed_pool(&mut pool, TRNG_BYTES);
    }
    step(&mut panel, 50);

    // The secure-element TRNGs, where the bootloader exposes them. Both are optional:
    // a missing callgate must not stop the pool from reaching its policy on a board
    // whose policy does not require them.
    feed_secure_elements(&mut pool);
    step(&mut panel, 80);

    // A little startup timing jitter. Credited 1 bit per byte, so this cannot
    // meaningfully substitute for a TRNG -- it only ever tops up.
    if dwt_running {
        for _ in 0..16 {
            pool.add_timing(dwt::cycles());
            dwt::delay_cycles(97);
        }
    }

    step(&mut panel, 95);
    let entropy = pool.check().map(|()| pool.credited_bits());
    step(&mut panel, 100);

    // Hold the finished splash, measured from when the first one was drawn rather than
    // slept for outright: bring-up has already used some of that time, and on a slower
    // board or a longer boot it may have used all of it, in which case this waits for
    // nothing. Skipped when there is no panel to look at, or no cycle counter to
    // measure with.
    if panel.is_some() && dwt_running {
        // SAFETY: reads RCC to scale the delay to the live clock.
        let min_cycles = unsafe { catcard_hal::clock::hclk_hz() } / 1000 * SPLASH_MIN_MS;
        let elapsed = dwt::cycles().wrapping_sub(splash_started);
        if let Some(remaining) = min_cycles.checked_sub(elapsed) {
            dwt::delay_cycles(remaining);
        }
    }

    BootReport {
        hal: hal.map(|_| ()),
        entropy,
        dwt_running,
        pool: Some(pool),
    }
}

/// Draw from SE1 and SE2 through bootloader callgate 26.
///
/// The entry address comes from the table the bootloader publishes at `0x0800_0040`,
/// validated before use. A board whose bootloader does not publish a usable entry
/// simply contributes nothing here — the entropy policy then decides whether boot can
/// continue, rather than this silently falling back to something weaker.
fn feed_secure_elements(pool: &mut EntropyPool) {
    if !BOARD.has_callgate_se_rng {
        return;
    }
    // SAFETY: we are running on BOARD; `discover` validates the published address
    // before it can be branched to.
    let Ok(gate) = (unsafe { Callgate::discover(&BOARD) }) else {
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
