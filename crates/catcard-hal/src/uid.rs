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

/// Where the die came from, as the UID encodes it.
///
/// RM0351 / RM0432 "Unique device ID register": bits 31:0 are the X and Y coordinates on
/// the wafer, bits 39:32 `WAF_NUM`, bits 95:40 `LOT_NUM` in ASCII [C].
///
/// The split of bits 31:0 into a 16-bit X then a 16-bit Y, both plain binary, is **[I]**:
/// the manual says the coordinates are "expressed in BCD", but units on the bench read
/// `0x001B` (not BCD) and values in a plausible die range when read as binary. The lot is
/// shown in memory order, which reads as letters and digits with a trailing space on every
/// unit seen (`PA4A07 `, `PN4N75 `, `P22B73 `) [I].
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Die {
    pub x: u16,
    pub y: u16,
    pub wafer: u8,
    lot: [u8; 7],
}

impl Die {
    pub fn from_uid(uid: &[u8; fixed::UNIQUE_ID_LEN]) -> Self {
        let mut lot = [0u8; 7];
        lot.copy_from_slice(&uid[5..12]);
        Self {
            x: u16::from_le_bytes([uid[0], uid[1]]),
            y: u16::from_le_bytes([uid[2], uid[3]]),
            wafer: uid[4],
            lot,
        }
    }

    /// The lot number, trimmed; non-printable bytes show as `?`.
    pub fn lot(&self) -> impl Iterator<Item = char> + '_ {
        let end = self
            .lot
            .iter()
            .rposition(|&b| b != b' ' && b != 0)
            .map_or(0, |i| i + 1);
        self.lot[..end].iter().map(|&b| {
            if (0x21..0x7f).contains(&b) {
                b as char
            } else {
                '?'
            }
        })
    }
}

/// `DBGMCU_IDCODE`, split into `(dev_id, rev_id)`.
///
/// # Safety
/// Reads a debug-block register that is always mapped.
pub unsafe fn idcode() -> (u16, u16) {
    // SAFETY: as documented; read on a locked Q1 over the debug monitor first.
    let v = unsafe { core::ptr::read_volatile(fixed::DBGMCU_IDCODE as *const u32) };
    ((v & 0xFFF) as u16, (v >> 16) as u16)
}

/// The part's flash size in KB, from the flash size data register.
///
/// # Safety
/// Reads factory system memory, always mapped.
pub unsafe fn flash_size_kb() -> u16 {
    // SAFETY: as documented; read on a locked Q1 over the debug monitor first.
    unsafe { core::ptr::read_volatile(fixed::FLASH_SIZE as *const u16) }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bench_q1s_uid_decodes_to_its_die() {
        // USB serial 080025000A50413441303720, which is the UID bytes in memory order.
        let uid = [
            0x08, 0x00, 0x25, 0x00, 0x0A, 0x50, 0x41, 0x34, 0x41, 0x30, 0x37, 0x20,
        ];
        let d = Die::from_uid(&uid);
        assert_eq!((d.x, d.y, d.wafer), (8, 37, 10));
        assert_eq!(d.lot().collect::<String>(), "PA4A07");
    }

    #[test]
    fn an_unprintable_lot_does_not_reach_the_screen_raw() {
        let mut uid = [0u8; 12];
        uid[5] = b'A';
        uid[6] = 0x07;
        assert_eq!(Die::from_uid(&uid).lot().collect::<String>(), "A?");
    }
}
