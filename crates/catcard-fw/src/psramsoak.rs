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

/// The second sweep: a read placed immediately after each write, which is the transition a
/// write-then-verify makes and the one that corrupted a staged image.
///
/// Two counts, because they mean different things. `late` is a read that disagreed and then
/// agreed when the same word was read again at the end of the pass -- the read was wrong.
/// `lost` is a word still wrong at the end -- the write was wrong. The first says reads need
/// the recovery; the second says writes do.
fn interleaved(base: u32, nops: u32) -> (u32, u32) {
    let mut disagreed = 0u32;
    let mut lost = 0u32;
    // A quarter of the write-only pass: enough to see a rate of one in tens of thousands.
    let words = WORDS / 4;
    // SAFETY: `base` is mapped, 4-aligned, and above anything in use; the caller checked
    // that the span stays below the recovery header.
    unsafe {
        for i in 0..words {
            let at = (base + i * 4) as *mut u32;
            store(at, expected(i), nops);
            if core::ptr::read_volatile(at as *const u32) != expected(i) {
                disagreed += 1;
            }
        }
        for i in 0..words {
            if core::ptr::read_volatile((base + i * 4) as *const u32) != expected(i) {
                lost += 1;
            }
        }
    }
    (disagreed, lost)
}

/// The third sweep, and the one that matters: a **bulk** write, then a read of somewhere
/// else, with `nops` between them.
///
/// This is the shape that broke firmware installs. Staging writes hundreds of kilobytes and
/// `inspect` then reads the image's 128-byte header -- the first read after all that writing
/// -- and it came back with its first forty bytes right and its last sixty-four wrong, so
/// every image failed its signature check and nothing said why. One word written and read
/// back does not reproduce it; this does.
///
/// Returns how many of `ROUNDS` reads came back wrong, and the first byte that differed.
fn after_bulk(base: u32, nops: u32) -> (u32, usize) {
    // A header-sized read from a header-ish offset, after a write of real size.
    const BULK_WORDS: u32 = 16 * 1024; // 64 KB
    const READ_AT: u32 = 0x3F80;
    const READ_LEN: usize = 128;
    const ROUNDS: u32 = 8;

    let mut wrong = 0u32;
    let mut first = READ_LEN;
    for round in 0..ROUNDS {
        // SAFETY: `base` is mapped, 4-aligned and above anything in use; the span stays
        // below the recovery header, as the caller checked.
        unsafe {
            for i in 0..BULK_WORDS {
                store((base + i * 4) as *mut u32, expected(i ^ round), nops);
            }
            // The gap under test: nothing between the last store and this read but NOPs.
            for _ in 0..nops {
                core::arch::asm!("nop", options(nostack, preserves_flags));
            }
            for i in 0..(READ_LEN as u32 / 4) {
                let at = READ_AT + i * 4;
                let got = core::ptr::read_volatile((base + at) as *const u32);
                if got != expected((at / 4) ^ round) {
                    wrong += 1;
                    first = first.min(i as usize * 4);
                    break;
                }
            }
        }
    }
    (wrong, first)
}

/// The fourth sweep: write a lot, then read all of it back, as verifying an image does.
///
/// This is where the last of the corruption lives. A firmware image staged from a card now
/// lands in PSRAM correctly -- reading it back over the debug monitor proves it -- and the
/// firmware's *own* digest of it still disagreed about three blocks in a megabyte. So the
/// reads are what to measure, at the size and shape the digest uses: 256 bytes at a time,
/// straight through, with CE# released every `gap_words`.
///
/// Returns the number of 256-byte reads that came back wrong, out of the whole span.
fn bulk_read_back(base: u32, words: u32, gap_words: u32, gap_nops: u32) -> u32 {
    // SAFETY: `base` is mapped, 4-aligned, above anything in use and below the recovery
    // header, as the caller checked.
    unsafe {
        let mut since = 0u32;
        for i in 0..words {
            if since >= gap_words {
                for _ in 0..gap_nops {
                    core::arch::asm!("nop", options(nostack, preserves_flags));
                }
                since = 0;
            }
            since += 1;
            core::ptr::write_volatile((base + i * 4) as *mut u32, expected(i));
        }
        let mut wrong = 0u32;
        let mut since = 0u32;
        for i in 0..words {
            if since >= gap_words {
                for _ in 0..gap_nops {
                    core::arch::asm!("nop", options(nostack, preserves_flags));
                }
                since = 0;
            }
            since += 1;
            if core::ptr::read_volatile((base + i * 4) as *const u32) != expected(i) {
                wrong += 1;
            }
        }
        wrong
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
    let mut lines: heapless::Vec<Line, { 3 * SWEEP.len() + 6 }> = heapless::Vec::new();

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

    // Now the same delays, with a read after every write.
    for nops in SWEEP {
        crate::menu::blocking_screen(ui.panel, "PSRAM soak", "write then read");
        let (disagreed, lost) = interleaved(base, nops);
        let mut l = Line::new();
        if disagreed == 0 && lost == 0 {
            let _ = write!(l, "{nops:2} nops r/w: clean");
        } else {
            let _ = write!(l, "{nops:2} nops r/w: {disagreed} late, {lost} lost");
        }
        crate::catlog!(
            "psram soak: {} nops, read after write: {} disagreed, {} lost of {}",
            nops,
            disagreed,
            lost,
            WORDS / 4
        );
        let _ = lines.push(l);
    }

    // And the shape that actually broke installs: bulk write, then read elsewhere.
    for nops in SWEEP {
        crate::menu::blocking_screen(ui.panel, "PSRAM soak", "bulk then read");
        let (wrong, first) = after_bulk(base, nops);
        let mut l = Line::new();
        if wrong == 0 {
            let _ = write!(l, "{nops:2} nops bulk: clean");
        } else {
            let _ = write!(l, "{nops:2} nops bulk: {wrong}/8 wrong, 1st byte {first}");
        }
        crate::catlog!(
            "psram soak: {} nops, after bulk write: {} of 8 reads wrong, first byte {}",
            nops,
            wrong,
            first
        );
        let _ = lines.push(l);
    }

    // The shape that still fails: a megabyte in, a megabyte back out. Swept by how often
    // CE# is released rather than by how long the gap is, since the datasheet bounds the
    // *time* the part may stay selected.
    for gap_words in [0u32, 64, 20, 8] {
        crate::menu::blocking_screen(ui.panel, "PSRAM soak", "write then verify");
        let words = 256 * 1024 / 4; // 256 KB, four times the earlier pass
        let effective = if gap_words == 0 { u32::MAX } else { gap_words };
        let wrong = bulk_read_back(base, words, effective, 80);
        let mut l = Line::new();
        if gap_words == 0 {
            let _ = write!(l, "no CE# gap: {wrong} wrong of {}", words);
        } else {
            let _ = write!(l, "gap every {gap_words}: {wrong} wrong of {}", words);
        }
        crate::catlog!(
            "psram soak: CE# gap every {} word(s): {} of {} reads wrong",
            gap_words,
            wrong,
            words
        );
        let _ = lines.push(l);
    }

    let mut rows: heapless::Vec<Row, { 3 * SWEEP.len() + 6 }> = heapless::Vec::new();
    let _ = rows.push(Row::title("PSRAM soak"));
    for l in lines.iter() {
        let _ = rows.push(Row::body(l.as_str()).small());
    }
    crate::menu::show_doc(ui, &rows, false, false);
}
