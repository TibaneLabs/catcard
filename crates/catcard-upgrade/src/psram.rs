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
    pub const unsafe fn claim(psram: &Psram) -> Self {
        let image_base = psram.base + psram.len / 2;
        Self {
            image_base,
            image_offset: image_base - psram.base,
            // Stop short of the header: an image long enough to reach it would overwrite
            // the marker that describes it, and the resulting header would be whatever
            // the image's last sixteen bytes happen to be.
            capacity: psram.staging_header - image_base,
            header_at: psram.staging_header,
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
        for word in WordPlan::new(addr, data.len()) {
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
                let mut bytes = unsafe { core::ptr::read_volatile(word.at as *const u32) }
                    .to_le_bytes();
                bytes[word.lo as usize..word.hi as usize]
                    .copy_from_slice(&data[word.src..word.src + word.len()]);
                u32::from_le_bytes(bytes)
            };
            // SAFETY: `WordPlan` only yields 4-aligned addresses inside the span's words,
            // and `in_range` bounded the span to the region claimed in `claim`, whose
            // safety contract is that it is mapped and ours.
            unsafe { core::ptr::write_volatile(word.at as *mut u32, value) };
        }
        Ok(())
    }

    /// Read the span with 32-bit loads, for symmetry with [`Self::write`] and because
    /// digesting a staged image a byte at a time is four times the bus traffic.
    fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<(), OutOfRange> {
        let addr = self.in_range(offset, out.len())?;
        for word in WordPlan::new(addr, out.len()) {
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
        let at = self.header_at as *mut u32;
        // SAFETY: `header_at` came from the board table's confirmed staging address and
        // lies inside the region claimed in `claim`. The writes are volatile and ordered
        // by a compiler fence so `magic1` cannot be hoisted above the fields it validates.
        unsafe {
            core::ptr::write_volatile(at.add(1), self.image_offset);
            core::ptr::write_volatile(at.add(2), len);
            core::ptr::write_volatile(at.add(3), MAGIC2);
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            core::ptr::write_volatile(at, MAGIC1);
        }

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
        assert!(plan[1].whole() && plan[2].whole(), "the middle is whole words");
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
            let a = unsafe { PsramArea::claim(&p) };
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
            let a = unsafe { PsramArea::claim(&p) };
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
            let a = unsafe { PsramArea::claim(&p) };
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
            let a = unsafe { PsramArea::claim(&p) };
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
