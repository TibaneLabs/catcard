//! How much recovery delay does a memory-mapped PSRAM write actually need?
//!
//! `hw-reference/storage.md` §PSRAM says writes must be word-aligned "(+ a NOP recovery
//! delay after writes)" [C] but not how long. Guessing it wrong is invisible: too short and
//! about one store in sixty thousand is mis-issued, which shows up as a firmware image that
//! fails its signature check for no stated reason, once you have staged a megabyte.
//!
//! So it is measured here instead. The sweep writes a position-derived pattern over a
//! region of PSRAM nothing is using, with a different delay each pass, and counts the words
//! that did not stick. One run prints the curve, and [`catcard_upgrade::psram::RECOVERY_NOPS`]
//! is set from it rather than from taste.
//!
//! Nothing here touches the staging area an image would be in, the scratch filesystem's
//! half, or the recovery header.

use catcard_board::BOARD;

/// Delays to try, in NOPs after each store.
const SWEEP: [u32; 7] = [0, 1, 2, 4, 8, 16, 32];

/// Words written per pass: 64 K words is 256 KB, enough to see a fault rate of one in tens
/// of thousands, and quick enough that seven passes are not a wait.
const WORDS: u32 = 64 * 1024;

/// Where to write. The upper half of PSRAM is the staging area, and an image occupies its
/// first megabyte or so; this sits well above that and below the recovery header.
const OFFSET: u32 = 6 * 1024 * 1024;

/// The value a given word should hold: position-derived, so a word that arrives at the
/// wrong offset is wrong rather than coincidentally right.
fn expected(i: u32) -> u32 {
    (i.wrapping_mul(0x9E37_79B9)) ^ 0x5A5A_0F0F
}

/// A store with `nops` NOPs after it.
///
/// # Safety
/// `at` is a mapped, 4-aligned address in the region being swept.
#[inline(always)]
unsafe fn store(at: *mut u32, value: u32, nops: u32) {
    // SAFETY: the caller's guarantee.
    unsafe { core::ptr::write_volatile(at, value) };
    for _ in 0..nops {
        // SAFETY: a NOP. Not `nomem`, so it stays where it was put.
        unsafe { core::arch::asm!("nop", options(nostack, preserves_flags)) };
    }
}

/// Sweep the delays and report what each one cost.
pub(crate) fn run(ui: &mut crate::ui::Ui<'_>) {
    use catcard_ui::scroll::Line as Row;
    use core::fmt::Write as _;

    let Some(psram) = BOARD.psram else {
        let rows = [Row::title("PSRAM soak"), Row::body("no PSRAM on this board")];
        crate::menu::show_doc(ui, &rows, false, false);
        crate::menu::wait_for_any_key(ui);
        return;
    };
    let base = psram.base + OFFSET;
    // Stay clear of the recovery header whatever the region's size.
    if base + WORDS * 4 > psram.staging_header {
        let rows = [Row::title("PSRAM soak"), Row::body("region too small")];
        crate::menu::show_doc(ui, &rows, false, false);
        crate::menu::wait_for_any_key(ui);
        return;
    }

    type Line = heapless::String<48>;
    let mut lines: heapless::Vec<Line, { SWEEP.len() + 2 }> = heapless::Vec::new();

    for nops in SWEEP {
        crate::menu::blocking_screen(ui.panel, "PSRAM soak", "writing");
        // SAFETY: `base` is inside the board's PSRAM, above anything in use and below the
        // recovery header, and word-aligned. Nothing else writes here.
        unsafe {
            for i in 0..WORDS {
                store((base + i * 4) as *mut u32, expected(i), nops);
            }
        }

        // Read the whole pass back and count what did not stick. A word that holds what its
        // neighbour should is counted separately: that is the shifted-run signature, and it
        // is what distinguishes a mis-issued store from a bit that did not hold.
        let mut wrong = 0u32;
        let mut shifted = 0u32;
        let mut first = u32::MAX;
        for i in 0..WORDS {
            // SAFETY: as above; reads may be unaligned here but are not.
            let got = unsafe { core::ptr::read_volatile((base + i * 4) as *const u32) };
            if got == expected(i) {
                continue;
            }
            wrong += 1;
            if i > 0 && got == expected(i - 1) {
                shifted += 1;
            }
            if first == u32::MAX {
                first = i;
            }
        }

        let mut l = Line::new();
        if wrong == 0 {
            let _ = write!(l, "{nops:2} nops: clean");
        } else {
            let _ = write!(
                l,
                "{nops:2} nops: {wrong} wrong ({shifted} shifted), 1st word {first}"
            );
        }
        crate::catlog!(
            "psram soak: {} nops, {} wrong of {}, {} shifted, first {}",
            nops,
            wrong,
            WORDS,
            shifted,
            first
        );
        let _ = lines.push(l);
    }

    let mut rows: heapless::Vec<Row, { SWEEP.len() + 2 }> = heapless::Vec::new();
    let _ = rows.push(Row::title("PSRAM soak"));
    for l in lines.iter() {
        let _ = rows.push(Row::body(l.as_str()).small());
    }
    crate::menu::show_doc(ui, &rows, false, false);
}
