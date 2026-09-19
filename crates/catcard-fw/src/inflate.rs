//! The heap buffers a paced inflate needs, and where a compressed scan lands.
//!
//! The expansion itself is [`catcard_upgrade::expand`], which is where it can be tested
//! against a memory-backed area rather than only against the real part. This is the
//! wrapper that knows what this device can spend on it.
//!
//! BBQr's `Z` compresses a file and only then cuts it into parts, so a scan of one
//! collects the compressed stream. On the Q1 image that is 342 codes instead of 449 --
//! a quarter fewer, not the half the ratio suggests, because the compressor keeps its
//! back-references inside a kilobyte so that a device can expand the result with a
//! window it can afford.

use crate::staging::Area;

/// The history window given to the decompressor, from the heap.
///
/// BBQr compresses within a kilobyte, so this is eight times what a conforming sender
/// needs. A stream made with a wider one fails with a reason rather than quietly
/// producing wrong bytes -- a back-reference past the window is exactly the case the
/// decompressor cannot serve, and it says so.
pub const WINDOW: usize = 8 * 1024;

/// Compressed input fetched per bus turnaround.
///
/// Every chunk costs a direction change and the driver pays a CE# gap for each, so a
/// kilobyte at a time makes those rare without asking much of the heap.
const CHUNK: usize = 1024;

/// Where the scanner puts a compressed stream, as an offset into the staging area.
///
/// Immediately above the largest image that can be expanded out of it. The expansion
/// writes from zero and `Staged::begin` refuses an image longer than the board's
/// firmware flash, so nothing the expansion produces can reach this -- which is what
/// lets it run forwards without ever overwriting input it has not read yet.
///
/// **Derived, not chosen.** It was 6 MiB, picked against the size of the PSRAM part.
/// The staging area is not the part: it is the upper half of it, stopping short of the
/// bootloader's header, so its capacity is about four megabytes and every write of a
/// compressed stream landed two megabytes past the end. A number reasoned out against
/// the wrong object looks just as deliberate as one reasoned out against the right one.
pub const fn compressed_at() -> u32 {
    // Word-aligned, because everything written here is written in whole words.
    catcard_board::BOARD
        .memory
        .firmware_flash_len
        .next_multiple_of(4)
}

/// Expand `len` compressed bytes at [`compressed_at`] into the area from offset zero.
///
/// The buffers come from the heap, which is the only reason this is not just the call
/// underneath. Returns how many bytes came out.
pub fn staged(area: &mut Area, len: u32, max: u32) -> Result<u32, &'static str> {
    let (Some(mut window), Some(mut chunk)) = (crate::heap::take(WINDOW), crate::heap::take(CHUNK))
    else {
        return Err("not enough memory to expand it");
    };
    catcard_upgrade::expand::inflate(
        area,
        compressed_at(),
        len,
        max,
        window.bytes(),
        chunk.bytes(),
    )
    .map_err(|why| {
        crate::catlog!("inflate: refused: {:?}", why);
        match why {
            catcard_upgrade::expand::Error::WindowTooSmall => "compressed with too wide a window",
            catcard_upgrade::expand::Error::TooLong => "it expands to more than can be staged",
            catcard_upgrade::expand::Error::Storage => "staging write failed",
            catcard_upgrade::expand::Error::NoRoom => "no room to expand it",
            catcard_upgrade::expand::Error::Damaged => "the compressed data is damaged",
        }
    })
}
