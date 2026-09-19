//! Staging into PSRAM, which is how mk4 and later do it.
//!
//! There is no SPI-NOR from mk4 onward. The bootloader looks for a **recovery header**
//! at a fixed address near the top of PSRAM and installs whatever it points at:
//!
//! ```text
//! struct { u32 magic1; u32 start; u32 size; u32 magic2; }   at 0x907F_F800
//!   magic1 = 0xDBCC_8350
//!   magic2 = 0xBAFC_FBA3
//! ```
//!
//! **Both magics must match or the bootloader ignores the region entirely.** That is the
//! safety property this module is built around: a half-written header stages nothing
//! rather than staging garbage, so the magics are written last and `magic1` last of all.
//!
//! PSRAM is volatile, so a staged image does not survive losing power — which is a
//! feature. An upgrade that was interrupted before the reboot leaves no trace.
//!
//! Source: `hw-reference/gpio-peripherals.md §Mk4` [C],
//! `hw-reference/install-and-usb-transport.md §2` [C].

use catcard_board::Psram;

use crate::StagingArea;

/// `magic1` of the recovery header.
pub const MAGIC1: u32 = 0xDBCC_8350;
/// `magic2` of the recovery header.
pub const MAGIC2: u32 = 0xBAFC_FBA3;

/// Bytes the recovery header itself occupies.
pub const HEADER_LEN: u32 = 16;

/// How far below the top of PSRAM the recovery header starts.
///
/// The header is sixteen bytes but is placed 2 KB from the end, so the rest of that
/// page is not ours to use — nothing here writes into it.
pub const HEADER_FROM_END: u32 = 2048;

/// A PSRAM region set up to stage one image.
/// Which way the last access went, so a change of direction can be waited out.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum Way {
    Nothing,
    Reading,
    Writing,
}

pub struct PsramArea {
    /// Where the image itself goes: an absolute address, for the writes.
    image_base: u32,
    /// The same location as an **offset from the PSRAM base** -- which is what the
    /// recovery header and `gate 18/7` want, not the absolute address. The bootloader
    /// computes `PSRAM_base + start`; handing it an absolute `start` made it read a
    /// gigabyte past the end and fail verification with -112. This is that `start`.
    image_offset: u32,
    /// Bytes available for it.
    capacity: u32,
    /// Where the bootloader reads the recovery header.
    header_at: u32,
    /// Which way the last access went: a change of direction starts a new burst, which
    /// `tCPH` says must have CE# high before it. See [`burst_gap`].
    way: Way,
    /// CPU cycles to idle between bursts, from [`gap_cycles`] and this board's clocks.
    gap: u32,
    /// Words touched since CE# was last allowed to rise.
    ///
    /// **State of the part, not of one call.** The chip does not know where a `write`
    /// ended and the next began -- it sees one unbroken run of accesses, and `tCEM` is a
    /// limit on that run. A counter local to each call reads as "every call is a fresh
    /// burst", which is only true if the calls are large.
    ///
    /// They are not. USB hands over [`CONT_PAYLOAD`](catcard_usb::CONT_PAYLOAD) -- 62
    /// bytes, about fifteen words -- and `usbtask` writes each frame straight through as
    /// it arrives. A per-call counter never reached [`WORDS_PER_BURST`], so staging a
    /// whole image over USB released CE# exactly **never**, and the refresh starvation
    /// that follows corrupted the staged image: a correct digest over bytes that were
    /// right, and a signature that would not verify. Staging the same image from a card
    /// worked, because a 512-byte sector is 128 words and does cross the threshold in
    /// one call.
    burst: Burst,
}

/// How many words have been touched since CE# was last allowed to rise.
///
/// A type of its own so the rule can be tested without a PSRAM: the thing that went
/// wrong was not the arithmetic but *where the count lived*, and that is only visible
/// across a sequence of calls.
#[derive(Copy, Clone, Default)]
pub struct Burst {
    since: u32,
    /// Words this bus may carry in one CE# assertion, from [`words_per_burst`]. Carried
    /// rather than global: it is a property of the board's clock, not of the code.
    limit: u32,
}

impl Burst {
    pub const fn new(limit: u32) -> Self {
        Self { since: 0, limit }
    }

    /// Account for one word, returning whether CE# must be released before it.
    pub fn word(&mut self) -> bool {
        if self.since >= self.limit {
            // This word begins the next burst, so it counts as its first.
            self.since = 1;
            true
        } else {
            self.since += 1;
            false
        }
    }

    /// A change of direction ends the run whatever its length.
    pub fn turned(&mut self) {
        self.since = 0;
    }
}

/// Writing outside the region this area was built for.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct OutOfRange;

impl PsramArea {
    /// Claim the upper half of PSRAM for staging.
    ///
    /// The lower half is left alone: the reference describes the firmware's scratch
    /// filesystem as mapping only the lower 4 MB, with the upper half carrying the
    /// recovery header. Staging into the half the header lives in keeps an upgrade clear
    /// of anything a scratch area is doing, which matters because a PSBT being signed
    /// and a firmware being received are exactly the two things a user might have in
    /// flight at once.
    ///
    /// # Safety
    ///
    /// `psram` must describe a memory-mapped PSRAM that is actually present and mapped,
    /// and nothing else may be using its upper half. Writes go straight to the address
    /// space with no further checking beyond the bounds recorded here.
    pub const unsafe fn claim(psram: &Psram, cpu_hz: u32) -> Self {
        let image_base = psram.image_base();
        Self {
            image_base,
            image_offset: image_base - psram.base,
            // Stop short of the header: an image long enough to reach it would overwrite
            // the marker that describes it, and the resulting header would be whatever
            // the image's last sixteen bytes happen to be.
            capacity: psram.staging_header - image_base,
            header_at: psram.staging_header,
            way: Way::Nothing,
            // Both from this board's clocks, not from a constant that happened to suit
            // the board it was worked out on.
            burst: Burst::new(words_per_burst(psram.ospi_hz)),
            gap: gap_cycles(psram.ospi_hz, psram.mmap_timeout_clocks, cpu_hz),
        }
    }

    fn in_range(&self, offset: u32, len: usize) -> Result<u32, OutOfRange> {
        let end = offset.checked_add(len as u32).ok_or(OutOfRange)?;
        if end > self.capacity {
            return Err(OutOfRange);
        }
        Ok(self.image_base + offset)
    }
}

/// NOPs executed after each memory-mapped PSRAM write.
///
/// Source: hw-reference/storage.md §PSRAM — *"Writes must be word-aligned (+ a NOP recovery
/// delay after writes)"* [C]. Every store into this region is an OctoSPI write transaction,
/// and the controller needs a moment before the next one; issued back to back, one is
/// mis-issued now and then -- a word appears that was never written and the rest of the run
/// sits four bytes along.
///
/// **One**, which is what stock uses. A sweep on the part found an uninterrupted run of
/// aligned word stores clean at every delay from zero upwards (`docs/PSRAM.md`), so the
/// delay is not what a run of writes needs -- the likely reading of the rule is that it is
/// the recovery a write needs before the controller is asked for a *read*, which is a
/// different command. Matching stock is better than picking a larger number that our own
/// measurements cannot justify.
pub const RECOVERY_NOPS: u32 = 1;

// --- what the part specifies -------------------------------------------------------
//
// ESP-PSRAM64H datasheet, Table 10-5 (`hw-reference/datasheets/`) [C]. These two are
// the whole contract. There is no refresh interval to discover: the part refreshes
// itself whenever CE# is high, and §5.5 says what happens if it is not let go --
// *"CE# must be pulled high immediately after all read/write operations. Not doing so
// will block internal refresh operations and cause memory failure."*
//
// A starved refresh loses data **anywhere in the chip**, not at the address being
// accessed, and not at once: the 8 us is the boundary of a guarantee, not the moment
// data goes bad. So the fault it produces is a word nobody wrote turning up somewhere
// nothing touched, a while later -- which is why it cannot be found by writing a region
// and reading the same words back, and why these are taken from the vendor rather than
// measured.

/// `tCEM`: the longest CE# may stay low, in nanoseconds.
pub const TCEM_NS: u32 = 8_000;
/// `tCPH`: the shortest CE# may stay high between bursts, in nanoseconds.
pub const TCPH_NS: u32 = 50;

// --- what the bus costs ------------------------------------------------------------

/// Clocks a burst spends on its command and address before any data moves.
///
/// Quad instruction and 24-bit address, plus the read command's 6 dummy cycles, which
/// is the more expensive of the two directions and so the one to budget for.
/// Source: hw-reference/storage.md §PSRAM [C].
const CMD_ADDR_CLOCKS: u32 = 14;

/// Clocks to move one 32-bit word: quad is four bits a clock, so eight.
const CLOCKS_PER_WORD: u32 = 32 / 4;

/// How much of `tCEM` a burst is allowed to use, as a percentage.
///
/// Not all of it. The datasheet quotes the maximum with no conditions attached, and the
/// bus clock it is measured against comes from the reference rather than from anything
/// we have put a probe on. A third of the budget leaves room for both to be somewhat
/// worse than believed, and costs only more frequent gaps -- a few milliseconds over a
/// megabyte, in a place nobody can feel.
const BUDGET_PERCENT: u32 = 30;

/// Multiple of the minimum gap actually taken, for the same reason.
const GAP_SAFETY: u32 = 2;

/// Words that may be written before CE# must be allowed to rise, on a given bus.
///
/// Derived, because the limit is a **time** and the number of words that fits inside it
/// depends on the clock: a figure worked out for one board is wrong on another, and
/// wrong in the direction that corrupts memory rather than the one that is slow.
///
/// At 60 MHz: 8 us is 480 clocks, a third of that is 144, less 14 for command and
/// address leaves 130, which is 16 words. Nobody has to trust that sentence -- the
/// tests check it, and they check what happens when the clock changes.
pub const fn words_per_burst(ospi_hz: u32) -> u32 {
    let budget = (ospi_hz as u64 * TCEM_NS as u64) / 1_000_000_000;
    let allowed = (budget * BUDGET_PERCENT as u64) / 100;
    let for_data = allowed.saturating_sub(CMD_ADDR_CLOCKS as u64);
    let words = for_data / CLOCKS_PER_WORD as u64;
    // Never zero: a burst of no words makes no progress, and a bus too slow to carry a
    // single word inside the budget is a configuration to reject, not to loop on.
    if words == 0 { 1 } else { words as u32 }
}

/// CPU cycles to idle so that CE# actually rises between bursts.
///
/// Two things have to fit, and the longer one is not the part's: the controller's
/// memory-mapped timeout has to fire, which is what drives CE# high once the bus goes
/// quiet, and then `tCPH` has to pass. Both convert into CPU cycles, so both depend on
/// two clocks that differ by board.
pub const fn gap_cycles(ospi_hz: u32, timeout_clocks: u32, cpu_hz: u32) -> u32 {
    if ospi_hz == 0 {
        return 0;
    }
    let for_timeout = (timeout_clocks as u64 * cpu_hz as u64) / ospi_hz as u64;
    let for_tcph = (TCPH_NS as u64 * cpu_hz as u64) / 1_000_000_000;
    (((for_timeout + for_tcph) * GAP_SAFETY as u64) + 1) as u32
}

/// Let CE# rise: idle the bus long enough for the controller to deselect the part.
///
/// # There was a `dsb` here, and it froze the device
///
/// The reasoning for it still looks right, which is why this comment exists rather than
/// a clean deletion. The region is *Normal, buffered* memory in the Cortex-M4 default
/// map, so `write_volatile` binds the compiler and not the bus: stores retire into the
/// write buffer and drain behind the CPU, and a delay made only of NOPs can therefore
/// run while the bus is still busy -- in which case the controller's memory-mapped
/// timeout never fires and CE# never rises.
///
/// What happened when the barrier was added: the first build whose own staging code ran
/// with it **froze the whole device** part way through writing an image, from the card
/// and over USB alike. Not a stalled task -- the keypad and screen stopped too, which
/// means the core itself was stopped on a bus access that never completed, which is what
/// `DSB` does when it is waiting for one.
///
/// So the barrier is out on evidence of harm, not because the argument for it was
/// wrong. Those are different things and the difference matters: without it the pacing
/// here may well be decorative, and the corruption it was meant to fix is presumably
/// still there. Settling it needs a way to try this on hardware that can be recovered
/// without a working staging path -- which is exactly what the freeze took away.
///
/// Source: ARMv7-M Architecture Reference Manual, default memory map and `DSB` [C];
/// the freeze, measured on a Q1, 2026-09-19.
#[inline(never)]
pub fn burst_gap(cycles: u32) {
    for _ in 0..cycles {
        #[cfg(target_arch = "arm")]
        // SAFETY: a NOP. Not `nomem`, so it is not moved out from between the accesses it
        // is separating -- which is the whole point of it.
        unsafe {
            core::arch::asm!("nop", options(nostack, preserves_flags))
        };
        #[cfg(not(target_arch = "arm"))]
        core::hint::spin_loop();
    }
}

/// Wait out the write recovery, per [`RECOVERY_NOPS`].
#[inline(always)]
pub fn recover() {
    for _ in 0..RECOVERY_NOPS {
        #[cfg(target_arch = "arm")]
        // SAFETY: a NOP. No operands, no memory, no flags. Deliberately *not* `nomem`, so
        // it is not reordered away from the store it is recovering from.
        unsafe {
            core::arch::asm!("nop", options(nostack, preserves_flags))
        };
        #[cfg(not(target_arch = "arm"))]
        core::hint::spin_loop();
    }
}

/// One 32-bit access in a span, and which bytes of it belong to the span.
///
/// Splitting the arithmetic out from the stores is what makes it testable: the addresses
/// PSRAM sees cannot be checked on a host, but the plan that produces them can.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
struct Word {
    /// The word's address: always 4-aligned.
    at: u32,
    /// First and last+1 byte of the word that the span covers (`0..4` when whole).
    lo: u32,
    hi: u32,
    /// Offset into the span's data of the first of those bytes.
    src: usize,
}

impl Word {
    /// The span covers all four bytes, so no read-merge is needed.
    fn whole(&self) -> bool {
        self.lo == 0 && self.hi == 4
    }

    fn len(&self) -> usize {
        (self.hi - self.lo) as usize
    }
}

/// The words a byte span touches, in order.
struct WordPlan {
    at: u32,
    end: u32,
    start: u32,
}

impl WordPlan {
    fn new(addr: u32, len: usize) -> Self {
        Self {
            at: addr & !3,
            end: addr + len as u32,
            start: addr,
        }
    }
}

impl Iterator for WordPlan {
    type Item = Word;

    fn next(&mut self) -> Option<Word> {
        if self.at >= self.end {
            return None;
        }
        let lo = self.start.max(self.at);
        let hi = self.end.min(self.at + 4);
        let word = Word {
            at: self.at,
            lo: lo - self.at,
            hi: hi - self.at,
            src: (lo - self.start) as usize,
        };
        self.at += 4;
        Some(word)
    }
}

impl StagingArea for PsramArea {
    type Error = OutOfRange;

    fn capacity(&self) -> u32 {
        self.capacity
    }

    /// Write the span with **32-bit stores only**, never byte stores.
    ///
    /// Byte stores into memory-mapped PSRAM are not reliable: a run of them beginning at an
    /// odd address comes back with a byte duplicated and the rest of the run shifted along
    /// by one. Measured on a Q1 (`docs/PSRAM.md` has the experiment), and it is why a
    /// firmware image read off a microSD card staged with one byte too many in the odd
    /// block and failed its signature check.
    ///
    /// A partial word at either end is read, merged and written whole, so the bytes outside
    /// the span keep their values.
    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), OutOfRange> {
        let addr = self.in_range(offset, data.len())?;
        // A change of direction is a new burst, and `tCPH` wants CE# high between bursts.
        if self.way == Way::Reading {
            burst_gap(self.gap);
            self.burst.turned();
        }
        self.way = Way::Writing;
        for word in WordPlan::new(addr, data.len()) {
            // CE# has to rise before `tCEM`, or the part stops refreshing itself.
            if self.burst.word() {
                burst_gap(self.gap);
            }
            let value = if word.whole() {
                u32::from_le_bytes([
                    data[word.src],
                    data[word.src + 1],
                    data[word.src + 2],
                    data[word.src + 3],
                ])
            } else {
                // SAFETY: `in_range` bounded the span, and a partial word at the edge lies
                // in the same word as bytes that are in it, so the word is mapped.
                let mut bytes =
                    unsafe { core::ptr::read_volatile(word.at as *const u32) }.to_le_bytes();
                bytes[word.lo as usize..word.hi as usize]
                    .copy_from_slice(&data[word.src..word.src + word.len()]);
                u32::from_le_bytes(bytes)
            };
            // SAFETY: `WordPlan` only yields 4-aligned addresses inside the span's words,
            // and `in_range` bounded the span to the region claimed in `claim`, whose
            // safety contract is that it is mapped and ours.
            unsafe { core::ptr::write_volatile(word.at as *mut u32, value) };
            recover();
        }
        Ok(())
    }

    /// Read the span with 32-bit loads, for symmetry with [`Self::write`] and because
    /// digesting a staged image a byte at a time is four times the bus traffic.
    fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<(), OutOfRange> {
        let addr = self.in_range(offset, out.len())?;
        // As in `write`: turning the bus round starts a new burst.
        if self.way == Way::Writing {
            burst_gap(self.gap);
            self.burst.turned();
        }
        self.way = Way::Reading;
        for word in WordPlan::new(addr, out.len()) {
            // Reads hold CE# exactly as writes do, and the digest reads a megabyte.
            if self.burst.word() {
                burst_gap(self.gap);
            }
            // SAFETY: as `write`.
            let bytes = unsafe { core::ptr::read_volatile(word.at as *const u32) }.to_le_bytes();
            let len = word.len();
            out[word.src..word.src + len]
                .copy_from_slice(&bytes[word.lo as usize..word.hi as usize]);
        }
        Ok(())
    }

    /// Write the recovery header, `magic1` last.
    ///
    /// Ordering is deliberate. The bootloader requires both magics, so as long as
    /// `magic1` is the final store, every earlier state of these sixteen bytes reads as
    /// "no image staged". There is no window in which a partially written header
    /// describes a partially written image.
    fn image_offset(&self) -> u32 {
        self.image_offset
    }

    fn publish(&mut self, len: u32) -> Result<(), OutOfRange> {
        // Turning the bus round starts a new burst, exactly as in `write`. This matters
        // now that `commit` reads the whole image back first: without it, the header --
        // the sixteen bytes the bootloader acts on -- would be the first write after a
        // megabyte of reads, issued with CE# still low from the read run.
        if self.way == Way::Reading {
            burst_gap(self.gap);
            self.burst.turned();
        }
        self.way = Way::Writing;
        let at = self.header_at as *mut u32;
        // SAFETY: `header_at` came from the board table's confirmed staging address and
        // lies inside the region claimed in `claim`. The writes are volatile and ordered
        // by a compiler fence so `magic1` cannot be hoisted above the fields it validates.
        // Each store gets its recovery delay, as every write into this region must. These
        // four are the ones the bootloader acts on, so a mis-issued one here is worse than
        // a mis-issued one in the image: the image is verified afterwards, the header is
        // what says where the image is.
        unsafe {
            core::ptr::write_volatile(at.add(1), self.image_offset);
            recover();
            core::ptr::write_volatile(at.add(2), len);
            recover();
            core::ptr::write_volatile(at.add(3), MAGIC2);
            recover();
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            core::ptr::write_volatile(at, MAGIC1);
            recover();
        }
        self.way = Way::Writing;
        burst_gap(self.gap);

        // Read it back before anyone acts on it.
        //
        // This is the last thing that happens before a reboot that overwrites the
        // running firmware, and the bootloader reads these sixteen bytes with no idea
        // where they came from. If the store did not land -- a mapping that is not what
        // the board table says, memory that does not hold -- the alternative to catching
        // it here is a device that reboots into an install of whatever those bytes
        // happen to be.
        //
        // It also makes the reboot itself evidence: a device that resets is a device
        // whose marker read back correctly.
        // SAFETY: as above.
        let seen = unsafe {
            [
                core::ptr::read_volatile(at as *const u32),
                core::ptr::read_volatile(at.add(1) as *const u32),
                core::ptr::read_volatile(at.add(2) as *const u32),
                core::ptr::read_volatile(at.add(3) as *const u32),
            ]
        };
        if seen != [MAGIC1, self.image_offset, len, MAGIC2] {
            return Err(OutOfRange);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use catcard_board::spec::ALL;

    /// The derivation, spelled out once so nobody has to redo it in their head.
    ///
    /// At 60 MHz, `tCEM` of 8 us is 480 OCTOSPI clocks. A third of that is 144; command
    /// and address take 14, leaving 130; quad moves a 32-bit word in 8 clocks, so 16
    /// words. Every number here is from the datasheet or the reference, and the point of
    /// the test is that the code computes it rather than a comment asserting it.
    #[test]
    fn the_burst_length_comes_out_of_the_bus_clock() {
        assert_eq!(words_per_burst(60_000_000), 16);

        // Halve the clock and the same bytes take twice as long, so half as many fit.
        assert_eq!(words_per_burst(30_000_000), 7);
        // Double it and more do. This is the whole reason it is not a constant: the
        // limit is a time, and a figure worked out on one board's bus silently allows
        // twice the CE# low it should on a board clocked half as fast.
        assert_eq!(words_per_burst(120_000_000), 34);
    }

    /// Whatever the clock, a burst stays inside the part's actual limit.
    ///
    /// The property that matters, checked against `tCEM` itself rather than against the
    /// number the function returned -- so an error in the derivation shows up here
    /// instead of being confirmed by its own output.
    #[test]
    fn no_bus_speed_produces_a_burst_longer_than_tcem() {
        for ospi_hz in [
            8_000_000,
            15_000_000,
            30_000_000,
            48_000_000,
            60_000_000,
            80_000_000,
            100_000_000,
            120_000_000,
            133_000_000,
        ] {
            let words = words_per_burst(ospi_hz);
            let clocks = CMD_ADDR_CLOCKS as u64 + words as u64 * CLOCKS_PER_WORD as u64;
            let ns = clocks * 1_000_000_000 / ospi_hz as u64;
            assert!(
                ns <= TCEM_NS as u64,
                "at {ospi_hz} Hz a {words}-word burst holds CE# for {ns} ns, past the \
                 {TCEM_NS} ns tCEM allows"
            );
            assert!(words >= 1, "a burst of no words makes no progress");
        }
    }

    /// The gap outlasts what has to happen inside it, on any pair of clocks.
    ///
    /// The controller's timeout is what drives CE# high, and `tCPH` is what the part
    /// wants after that. Both are times; both turn into CPU cycles through two clocks
    /// that differ by board.
    #[test]
    fn the_gap_outlasts_the_timeout_and_tcph() {
        for (ospi_hz, cpu_hz) in [
            (60_000_000, 120_000_000),
            (30_000_000, 120_000_000),
            (60_000_000, 80_000_000),
            (120_000_000, 200_000_000),
        ] {
            let cycles = gap_cycles(ospi_hz, 16, cpu_hz);
            let ns = cycles as u64 * 1_000_000_000 / cpu_hz as u64;
            let needed = 16 * 1_000_000_000 / ospi_hz as u64 + TCPH_NS as u64;
            assert!(
                ns >= needed,
                "at {ospi_hz}/{cpu_hz} the gap is {ns} ns, short of the {needed} ns the \
                 timeout and tCPH need"
            );
        }
    }

    /// Q1 and mk4/mk5 are the same bus, so the same burst -- but each is read from its
    /// own board entry, not assumed.
    #[test]
    fn every_board_with_psram_gets_a_workable_burst() {
        for board in ALL {
            let Some(psram) = board.psram else { continue };
            let words = words_per_burst(psram.ospi_hz);
            assert!(words >= 1, "{}: no words fit in tCEM", board.name);
            assert!(
                gap_cycles(psram.ospi_hz, psram.mmap_timeout_clocks, 120_000_000) > 0,
                "{}: a gap of no cycles is not a gap",
                board.name
            );
        }
    }

    /// Every byte of the span is covered exactly once, by 4-aligned words only.
    #[test]
    fn the_write_plan_covers_the_span_once_with_aligned_words() {
        for addr in 0x2000_0000u32..0x2000_0008 {
            for len in 1usize..24 {
                let mut seen = vec![None; len];
                let mut words = 0;
                for w in WordPlan::new(addr, len) {
                    assert_eq!(w.at % 4, 0, "{addr:#x}+{len}: unaligned word {:#x}", w.at);
                    assert!(w.lo < w.hi && w.hi <= 4, "{addr:#x}+{len}: {w:?}");
                    for i in 0..w.len() {
                        let byte = w.src + i;
                        assert!(byte < len, "{addr:#x}+{len}: {w:?} runs past the span");
                        assert!(seen[byte].is_none(), "{addr:#x}+{len}: byte {byte} twice");
                        // The byte of memory this covers is the byte of data it came from.
                        seen[byte] = Some(w.at + w.lo + i as u32);
                    }
                    words += 1;
                }
                for (i, at) in seen.iter().enumerate() {
                    assert_eq!(*at, Some(addr + i as u32), "{addr:#x}+{len}: byte {i}");
                }
                // No more words than the span can touch.
                let expect = ((addr + len as u32 + 3) & !3).saturating_sub(addr & !3) / 4;
                assert_eq!(words, expect, "{addr:#x}+{len}");
            }
        }
    }

    /// Only the words at the ends of a span can be partial, and only they need a merge.
    #[test]
    fn only_the_edges_of_a_span_are_partial_words() {
        let plan: Vec<_> = WordPlan::new(0x2000_0002, 13).collect();
        assert_eq!(plan.len(), 4);
        assert!(!plan[0].whole(), "the head starts mid-word");
        assert!(
            plan[1].whole() && plan[2].whole(),
            "the middle is whole words"
        );
        assert!(!plan[3].whole(), "the tail ends mid-word");
        // A span that starts and ends on word boundaries needs no merge at all, which is
        // the case every staging write takes: offsets there are multiples of 512.
        assert!(WordPlan::new(0x2000_0000, 512).all(|w| w.whole()));
    }

    #[test]
    fn the_staging_region_never_overlaps_the_recovery_header() {
        // An image long enough to reach the header would overwrite the marker that
        // describes it, and the bootloader would install whatever its last sixteen bytes
        // happened to say. The capacity has to stop short.
        for b in ALL {
            let Some(p) = b.psram else { continue };
            // SAFETY: not dereferenced; only the arithmetic is under test.
            let a = unsafe { PsramArea::claim(&p, 120_000_000) };
            assert!(a.image_base + a.capacity <= a.header_at, "{}", b.name);
            // The documented placement: 2 KB below the top, not 16 bytes below it.
            assert_eq!(a.header_at + HEADER_FROM_END, p.end(), "{}", b.name);
            const { assert!(HEADER_LEN <= HEADER_FROM_END) };
        }
    }

    #[test]
    fn there_is_room_for_the_largest_installable_image() {
        // Capacity has to cover the whole of main flash the image can occupy, or a
        // legitimate upgrade is refused for want of somewhere to put it.
        for b in ALL {
            let Some(p) = b.psram else { continue };
            // SAFETY: arithmetic only.
            let a = unsafe { PsramArea::claim(&p, 120_000_000) };
            assert!(
                a.capacity() >= b.memory.firmware_flash_len,
                "{}: {} of staging for {} of flash",
                b.name,
                a.capacity(),
                b.memory.firmware_flash_len
            );
        }
    }

    #[test]
    fn staging_stays_in_the_upper_half() {
        // The lower half is the scratch filesystem's. Receiving firmware must not walk
        // over a PSBT being signed.
        for b in ALL {
            let Some(p) = b.psram else { continue };
            // SAFETY: arithmetic only.
            let a = unsafe { PsramArea::claim(&p, 120_000_000) };
            assert!(a.image_base >= p.base + p.len / 2, "{}", b.name);
        }
    }

    #[test]
    fn the_recovery_header_sits_where_the_reference_says() {
        // Confirmed as an absolute address, so it is asserted as one. A change to
        // `Psram::len` that moved it would otherwise go unnoticed until a device
        // silently stopped installing upgrades.
        for b in ALL {
            let Some(p) = b.psram else { continue };
            assert_eq!(p.staging_header, 0x907F_F800, "{}", b.name);
            assert_eq!(p.base, 0x9000_0000, "{}", b.name);
            // The value the recovery header and gate 18/7 carry must be an OFFSET from
            // the PSRAM base, not the absolute staging address -- the bootloader adds it
            // to the base, and an absolute value sent it a gigabyte past the end.
            let a = unsafe { PsramArea::claim(&p, 120_000_000) };
            assert_eq!(
                a.image_offset,
                a.image_base - p.base,
                "{}: staging start must be a PSRAM offset",
                b.name
            );
            assert!(a.image_offset < p.len, "{}: offset inside PSRAM", b.name);
        }
    }
}

#[cfg(test)]
mod burst_tests {
    use super::*;

    /// The burst limit on the boards we have. Named from a real bus clock rather than
    /// written down, so these tests keep meaning the same thing if the bus changes.
    const Q1_WORDS: u32 = words_per_burst(60_000_000);

    /// Feed `calls` runs of `words` each through one counter, and report the longest run
    /// of words that went by with no gap -- which is what the part actually experiences.
    fn longest_run(calls: usize, words: usize) -> u32 {
        let mut burst = Burst::new(Q1_WORDS);
        let (mut run, mut worst) = (0u32, 0u32);
        for _ in 0..calls {
            for _ in 0..words {
                if burst.word() {
                    worst = worst.max(run);
                    run = 0;
                }
                run += 1;
            }
        }
        worst.max(run)
    }

    /// The limit is on the part, not on a call: many small writes are one long run.
    ///
    /// This is the bug that corrupted a staged image. USB hands over 62-byte frames --
    /// about fifteen words -- and `usbtask` writes each straight through. With the count
    /// living in the call, no single call ever reached the burst limit, so CE# was
    /// never released across an entire 476 KB transfer. Staging from a card worked
    /// because a 512-byte sector is 128 words and crosses the threshold on its own,
    /// which is exactly why the failure looked like a USB problem.
    #[test]
    fn many_small_calls_still_release_the_part() {
        // 62 bytes is 15 whole words plus a part-word either side: 15 to 17 in practice.
        for words in [1usize, 4, 15, 16, 17, 31] {
            let worst = longest_run(400, words);
            assert!(
                worst <= Q1_WORDS,
                "{words}-word calls ran {worst} words without releasing CE#, over the \
                 {Q1_WORDS} the 8 us tCEM budget allows"
            );
        }
    }

    /// And a call larger than the budget is broken up within itself, as before.
    #[test]
    fn one_large_call_is_broken_into_bursts() {
        for words in [32usize, 33, 64, 128, 1000] {
            let worst = longest_run(1, words);
            assert!(
                worst <= Q1_WORDS,
                "a {words}-word call ran {worst} words without releasing CE#"
            );
        }
    }

    /// The seam between two calls is a run like any other.
    ///
    /// The digest reads 256 bytes at a time -- 64 words, so one gap inside each call.
    /// With a per-call counter the tail of one call and the head of the next ran back to
    /// back: 64 words, twice the budget, every 256 bytes of a megabyte.
    #[test]
    fn the_seam_between_calls_is_not_a_free_burst() {
        assert!(longest_run(50, 64) <= Q1_WORDS);
    }

    /// Turning the bus round ends the run: the gap is emitted by the caller for `tCPH`.
    #[test]
    fn a_change_of_direction_starts_the_count_again() {
        let mut burst = Burst::new(Q1_WORDS);
        for _ in 0..Q1_WORDS {
            assert!(!burst.word());
        }
        burst.turned();
        // The next word follows a gap the direction change already paid for, so it must
        // not ask for a second one.
        assert!(!burst.word(), "a redundant gap after turning the bus");
    }
}
