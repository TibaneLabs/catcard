//! Early bring-up.
//!
//! The ordering here is the security-critical part: the entropy pool is filled from
//! every hardware noise source the board has, and its policy is checked, before any
//! code path could ask it for seed material. A pool that cannot meet its policy stays
//! unusable rather than degrading to something weaker.

use catcard_board::BOARD;
use catcard_callgate::Callgate;
use catcard_entropy::{EntropyPool, Source};
use catcard_hal::{dwt, uid};

use crate::{BootReport, display, entropy_policy, splash};

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

    // A little startup timing jitter, credited **nothing**. These are cycle counts on a
    // fixed instruction path before anyone has touched the device: the same boot on the
    // same board lands within a few cycles of the same values, which is a pattern, not
    // entropy. They go in as `Auxiliary` -- mixed, so two boots differ where they do
    // differ, and counted zero, like every other value nobody chose. `UserTiming` and
    // its credit are for keypress edges, where a human decides the moment.
    if dwt_running {
        for _ in 0..16 {
            pool.add(Source::Auxiliary, &dwt::cycles().to_le_bytes());
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

/// Draw from every generator the board has besides the chip, which boot has already read.
///
/// The list is [`crate::trng::kinds`], the same one New wallet and the RNG screens use.
/// The entry address comes from the table the bootloader publishes at `0x0800_0040`,
/// validated before use; a board whose bootloader does not publish a usable entry simply
/// contributes nothing here -- the entropy policy then decides whether boot can continue,
/// rather than this silently falling back to something weaker.
fn feed_secure_elements(pool: &mut EntropyPool) {
    use crate::trng::Kind;
    // SAFETY: we are running on BOARD; `discover` validates the published address
    // before it can be branched to.
    let Ok(gate) = (unsafe { Callgate::discover(&BOARD) }) else {
        return;
    };
    let mut trngs = crate::trng::Trngs::new(Some(&gate));
    for kind in crate::trng::kinds() {
        // The chip was read above. SE1's raw bus is left out of boot for now: it borrows
        // the bus the bootloader's PIN checks run over, and a mistake there on the boot
        // path would leave a locked board unable to log in. It is used after login, and
        // earns its place here once that has been watched working.
        if kind == Kind::Chip || kind == Kind::Se1Wire {
            continue;
        }
        // The elements return at most 32 bytes a call, so draw repeatedly.
        let mut got = 0usize;
        while got < TRNG_BYTES {
            let mut buf = [0u8; 32];
            match trngs.read(kind, &mut buf) {
                Some(n) if n > 0 => {
                    pool.add(kind.source(), &buf[..n]);
                    got += n;
                }
                // A source that will not produce is not a reason to fall back to something
                // weaker; the policy check decides what happens.
                _ => break,
            }
        }
    }
}
