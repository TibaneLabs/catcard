//! Factory unique ID.
//!
//! # This is not entropy
//!
//! The 96-bit UID is a per-device constant, it is published as the device's USB serial
//! number, and on STM32L4 the first word encodes the wafer X/Y die coordinates — so
//! its real range is far smaller than 96 bits. Folding it into a seed generator as if
//! it were random is one of the two mistakes that made the stock firmware's seed
//! guessable.
//!
//! It is exposed here for the things it is actually good for: identifying the device
//! and domain-separating per-device storage. [`feed_pool`] mixes it as
//! [`Source::NonSecret`](catcard_entropy::Source::NonSecret), which is credited zero
//! bits by construction.
//!
//! Source: `hw-reference/platform.md §2-3` [C].

use catcard_board::memory::fixed;

/// Read the 96-bit unique ID.
///
/// # Safety
/// Reads factory flash, which is always mapped and always readable.
pub unsafe fn read() -> [u8; fixed::UNIQUE_ID_LEN] {
    let mut out = [0u8; fixed::UNIQUE_ID_LEN];
    for (i, b) in out.iter_mut().enumerate() {
        // SAFETY: reading within the documented 12-byte UID region.
        *b = unsafe { core::ptr::read_volatile((fixed::UNIQUE_ID as *const u8).add(i)) };
    }
    out
}

/// Mix the UID into the pool for domain separation only. Credited **zero** bits.
///
/// # Safety
/// As [`read`].
pub unsafe fn feed_pool(pool: &mut catcard_entropy::EntropyPool) {
    // SAFETY: forwarding to the documented read.
    let uid = unsafe { read() };
    pool.add(catcard_entropy::Source::NonSecret, &uid);
}
