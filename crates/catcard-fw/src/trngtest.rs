//! Debug -> TRNG startup test: the SP 800-90B §4.3 start-up test, run on demand.
//!
//! The pool can hold a hardware source's credit until that source has passed a start-up
//! test over [`STARTUP_SAMPLES`] consecutive bytes (`EntropyPool::enforce_startup`). New
//! wallet enforces it; boot does not yet, because boot reads 64 bytes a source and a
//! change to the boot path is only put there once the same code has been watched working
//! after boot (every bench unit is locked: a boot that hangs cannot be recovered).
//!
//! This screen is that proof. It runs exactly what boot would run -- a fresh pool with the
//! start-up test enforced, fed [`STARTUP_SAMPLES`] bytes from every source through the same
//! readers ([`Trngs::read`]) and the same `pool.add` -- and reports, per source, whether
//! the test passed, what tripped if it did not, whether the board's policy would be met,
//! and how long the reads took (the boot-time cost of moving it there).
//!
//! The pool is a throwaway: nothing is drawn from it, it is not the session's pool, and it
//! is wiped when this returns. Sources the pool does not test (the bootloader's read, SE1's
//! raw bus) run the same test on the side, reported as "mixed" -- they are never credited.

use core::fmt::Write as _;

use catcard_callgate::Callgate;
use catcard_entropy::{EntropyPool, HealthError, STARTUP_SAMPLES, Startup, StartupTest};
use catcard_ui::scroll::Line as Row;
use zeroize::Zeroize as _;

use crate::display;
use crate::menu;
use crate::trng::Trngs;
use crate::ui::Ui;

type Text = heapless::String<48>;

/// Passes over the sources before giving up on one that is too slow or silent. Every
/// source answers at most 64 bytes a pass and SE2 declines about three in four, so 1,024
/// bytes wants about 130 passes from it; this leaves room and still ends.
const MAX_PASSES: usize = 320;

/// Most sources a board has (`trng::kinds`).
const SOURCES: usize = 4;

/// Run the test on every source and show the verdicts.
#[inline(never)]
pub fn screen(gate: &Callgate, ui: &mut Ui<'_>) {
    let kinds = crate::trng::kinds();
    let mut pool = EntropyPool::new(crate::entropy_policy());
    pool.enforce_startup();
    // The same test for the sources the pool does not test, so they get a verdict too.
    let mut side: [StartupTest; SOURCES] = core::array::from_fn(|_| StartupTest::new());
    let mut got = [0usize; SOURCES];
    let mut refused = [false; SOURCES];
    let mut trngs = Trngs::new(Some(gate));

    // SAFETY: reads RCC.
    let per_ms = (unsafe { catcard_hal::clock::hclk_hz() } / 1000).max(1) as u64;
    let mut read_cycles = 0u64;
    crate::catlog!("trngtest: start, {} bytes a source", STARTUP_SAMPLES);

    for _ in 0..MAX_PASSES {
        let done =
            |got: &[usize], refused: &[bool], i: usize| got[i] >= STARTUP_SAMPLES || refused[i];
        if (0..kinds.len()).all(|i| done(&got, &refused, i)) {
            break;
        }
        for (i, &kind) in kinds.iter().enumerate() {
            if done(&got, &refused, i) {
                continue;
            }
            let _ = crate::usbtask::pump();
            let mut buf = [0u8; 64];
            let t0 = catcard_hal::dwt::cycles();
            let r = trngs.read(kind, &mut buf);
            read_cycles += catcard_hal::dwt::cycles().wrapping_sub(t0) as u64;
            match r {
                Some(n) if n > 0 => {
                    if kind.credited() {
                        pool.add(kind.source(), &buf[..n]);
                    } else {
                        let _ = side[i].feed(&buf[..n]);
                    }
                    got[i] += n;
                }
                Some(_) => {}
                None => refused[i] = true,
            }
            buf.zeroize();
        }
        let total: usize = got.iter().map(|&n| n.min(STARTUP_SAMPLES)).sum();
        let pct = total * 100 / (STARTUP_SAMPLES * kinds.len().max(1));
        progress(ui.panel, &kinds, &got, pct.min(100) as u8);
    }

    let mut texts: heapless::Vec<Text, { SOURCES + 3 }> = heapless::Vec::new();
    let mut all_passed = true;
    for (i, &kind) in kinds.iter().enumerate() {
        let state = if kind.credited() {
            pool.startup(kind.source())
                .unwrap_or(Startup::Pending { tested: 0 })
        } else {
            side[i].state()
        };
        if kind.credited() && state != Startup::Passed {
            all_passed = false;
        }
        let mut t = Text::new();
        let _ = write!(t, "{}: ", kind.label());
        verdict(&mut t, state, refused[i]);
        if !kind.credited() {
            let _ = t.push_str(" (mixed)");
        }
        crate::catlog!("trngtest: {} ({} bytes read)", t.as_str(), got[i]);
        let _ = texts.push(t);
    }

    let mut t = Text::new();
    match pool.check() {
        Ok(()) => {
            let _ = write!(t, "Policy met: {} bits", pool.credited_bits());
        }
        Err(e) => {
            let _ = write!(t, "Policy NOT met: {e}");
        }
    }
    crate::catlog!("trngtest: {}", t.as_str());
    let _ = texts.push(t);

    let mut t = Text::new();
    let _ = write!(t, "Reads took {} ms", read_cycles / per_ms);
    crate::catlog!(
        "trngtest: {}, all hardware passed: {}",
        t.as_str(),
        all_passed
    );
    let _ = texts.push(t);
    drop(pool);

    let mut rows: heapless::Vec<Row<'_>, { SOURCES + 4 }> = heapless::Vec::new();
    let _ = rows.push(Row::title("TRNG startup test"));
    for t in &texts {
        let _ = rows.push(Row::body(t.as_str()).wrapped());
    }
    let _ = menu::show_doc(ui, &rows, false, false);
}

/// One source's verdict, in words.
fn verdict(t: &mut Text, state: Startup, refused: bool) {
    let _ = match state {
        Startup::Passed => t.push_str("passed").map_err(|_| core::fmt::Error),
        Startup::Pending { tested } => write!(
            t,
            "incomplete, {tested} of {STARTUP_SAMPLES}{}",
            if refused { ", no answer" } else { "" }
        ),
        Startup::Failed(e) => {
            let _ = t.push_str("FAILED, ");
            // The byte value and how often it came: what a stuck or biased source says.
            match e {
                HealthError::Repetition { value, run } => write!(t, "{value:02x} x{run} in a row"),
                HealthError::AdaptiveProportion { value, count } => {
                    write!(t, "{value:02x} {count} times in 512")
                }
                HealthError::Constant { value } => write!(t, "all {value:02x}"),
                HealthError::TooShort { len } => write!(t, "{len} bytes"),
            }
        }
    };
}

fn progress(
    panel: &mut display::Panel,
    kinds: &heapless::Vec<crate::trng::Kind, 4>,
    got: &[usize; SOURCES],
    pct: u8,
) {
    let mut lines: heapless::Vec<Text, SOURCES> = heapless::Vec::new();
    for (i, k) in kinds.iter().enumerate() {
        let mut l = Text::new();
        let _ = write!(
            l,
            "{:<3} {:5} of {}",
            k.label(),
            got[i].min(STARTUP_SAMPLES),
            STARTUP_SAMPLES
        );
        let _ = lines.push(l);
    }
    display::draw(panel, |c| {
        catcard_ui::widgets::info(c, &display::LAYOUT, "Startup test", &lines);
        catcard_ui::splash::draw_progress(c, pct);
        crate::idle::note_progress();
    });
}
