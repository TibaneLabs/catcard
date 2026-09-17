//! The MCU's own flash, for the region the settings live in.
//!
//! Everything else in this firmware treats internal flash as read-only: the image is there,
//! the bootloader is there, and the bootloader does the writing when an upgrade is
//! installed. The settings blob is the exception -- it is ours to erase and program, in the
//! 512 KB region above the firmware.
//!
//! # What makes this delicate
//!
//! On mk4/mk5/Q1 the part is configured **single bank** with **8 KB pages** (`DBANK = 0`,
//! which the bootloader asserts at compile time), so the settings pages are in the same bank
//! as the running code. An erase or a program stalls every flash access until it finishes,
//! the instruction fetches included, so the CPU simply waits -- but only if nothing needs to
//! run in the meantime. That is why each operation happens with interrupts masked by the
//! caller and takes milliseconds, not why it is dangerous: a torn write is dangerous, which
//! is what the settings format's two-slot rotation exists for.
//!
//! Sources: hw-reference/platform.md §"Flash page size" and §"Flash unlock" [C]; ST RM0432
//! (STM32L4+) and RM0351 (STM32L4) for the register layout [C].

use catcard_board::Mcu;

use crate::reg;

/// The flash interface's registers. Source: RM0432 §3.7 [C]
const FLASH: u32 = 0x4002_2000;
const KEYR: u32 = 0x08;
const SR: u32 = 0x10;
const CR: u32 = 0x14;
const OPTR: u32 = 0x20;

/// The two words that unlock `CR`. Source: platform.md §"Flash unlock" [C]
const KEY1: u32 = 0x4567_0123;
const KEY2: u32 = 0xCDEF_89AB;

/// `CR` bits. Source: RM0432 §3.7.5 [C]
const CR_PG: u32 = 1 << 0;
const CR_PER: u32 = 1 << 1;
const CR_PNB_SHIFT: u32 = 3;
const CR_PNB_MASK: u32 = 0xFF << CR_PNB_SHIFT;
const CR_BKER: u32 = 1 << 11;
const CR_STRT: u32 = 1 << 16;
const CR_LOCK: u32 = 1 << 31;

/// `SR` bits. `BSY` is the wait; the rest are how an operation failed.
const SR_EOP: u32 = 1 << 0;
const SR_OPERR: u32 = 1 << 1;
const SR_PROGERR: u32 = 1 << 3;
const SR_WRPERR: u32 = 1 << 4;
const SR_PGAERR: u32 = 1 << 5;
const SR_SIZERR: u32 = 1 << 6;
const SR_PGSERR: u32 = 1 << 7;
const SR_MISERR: u32 = 1 << 8;
const SR_FASTERR: u32 = 1 << 9;
const SR_BSY: u32 = 1 << 16;
/// Every error flag, which is also everything `SR` can be cleared of.
const SR_ERRORS: u32 =
    SR_OPERR | SR_PROGERR | SR_WRPERR | SR_PGAERR | SR_SIZERR | SR_PGSERR | SR_MISERR | SR_FASTERR;

/// `OPTR.DBANK`: set for dual bank. Source: RM0432 §3.7.8 [C]
const OPTR_DBANK: u32 = 1 << 22;

/// Polls before an erase or a program is called stuck.
///
/// An 8 KB page erase is specified in tens of milliseconds and the bus is stalled while it
/// runs, so this is a backstop against a controller that never clears `BSY`, not a timeout
/// anything reaches in normal use.
const BUSY_POLLS: u32 = 50_000_000;

/// Why a flash operation failed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// The part is not in the bank configuration this drives.
    Configuration { optr: u32 },
    /// The address is outside the region this was opened for, or not aligned as the
    /// operation needs.
    Address { addr: u32 },
    /// `BSY` never cleared.
    Stuck,
    /// The controller reported an error; the `SR` flags are included.
    Reported { sr: u32 },
}

/// Bytes programmed at once: flash takes a 64-bit doubleword. Source: RM0432 §3.3.7 [C]
pub const DWORD: usize = 8;

/// The page holding `addr`, as `(bank_bit_set, page_number)`.
///
/// Single bank (mk4/mk5/Q1) numbers every page from the start of flash with `BKER` clear.
/// Dual bank (mk3) splits flash in half and numbers each half from zero, with `BKER` saying
/// which half -- so the same page number means two different places depending on that bit,
/// which is the mistake worth making impossible.
pub const fn page_of(
    addr: u32,
    flash_base: u32,
    page_size: u32,
    dual_bank: bool,
    bank_len: u32,
) -> (bool, u32) {
    let off = addr - flash_base;
    if dual_bank {
        let bank2 = off >= bank_len;
        let within = if bank2 { off - bank_len } else { off };
        (bank2, within / page_size)
    } else {
        (false, off / page_size)
    }
}

/// The page size and bank layout this MCU is configured for.
///
/// mk3's L496 is dual bank with 2 KB pages; mk4/mk5/Q1's L4S5 runs single bank with 8 KB
/// pages, which is what the bootloader there asserts. A part found in the other
/// configuration is refused rather than written with the wrong page numbers.
/// Source: platform.md §"Flash page size" [C]
pub const fn expected(mcu: Mcu) -> (u32, bool) {
    match mcu {
        Mcu::Stm32L496 => (2 * 1024, true),
        Mcu::Stm32L4S5 => (8 * 1024, false),
    }
}

/// The MCU's flash, opened for one region.
pub struct Internal {
    start: u32,
    len: u32,
    page_size: u32,
    dual_bank: bool,
    bank_len: u32,
}

impl Internal {
    /// Claim `len` bytes of internal flash at `start` for erasing and programming.
    ///
    /// Checks the part is in the configuration this drives before anything is written: a
    /// wrong page size would erase the wrong 8 KB, and there is no undo for that.
    ///
    /// # Safety
    /// Nothing else may write this region. The region must not hold code that runs, and on a
    /// single-bank part every operation stalls the bus, so the caller must not need
    /// interrupts serviced during one.
    pub unsafe fn open(mcu: Mcu, start: u32, len: u32, flash_len: u32) -> Result<Self, Error> {
        let (page_size, dual_bank) = expected(mcu);
        // SAFETY: a read of the flash interface's option register.
        let optr = unsafe { reg::read(FLASH + OPTR) };
        if (optr & OPTR_DBANK != 0) != dual_bank {
            return Err(Error::Configuration { optr });
        }
        if !start.is_multiple_of(page_size) || !len.is_multiple_of(page_size) {
            return Err(Error::Address { addr: start });
        }
        Ok(Self {
            start,
            len,
            page_size,
            dual_bank,
            bank_len: flash_len / 2,
        })
    }

    pub fn page_size(&self) -> u32 {
        self.page_size
    }

    pub fn pages(&self) -> u32 {
        self.len / self.page_size
    }

    /// Read from the region. Flash is memory-mapped, so this is a copy.
    ///
    /// # Safety
    /// The region is mapped and readable; the caller's bounds are checked here.
    pub unsafe fn read(&self, off: u32, buf: &mut [u8]) -> Result<(), Error> {
        let end = off
            .checked_add(buf.len() as u32)
            .ok_or(Error::Address { addr: off })?;
        if end > self.len {
            return Err(Error::Address {
                addr: self.start + off,
            });
        }
        // SAFETY: within the region the caller opened, which is mapped flash.
        unsafe {
            core::ptr::copy_nonoverlapping(
                (self.start + off) as *const u8,
                buf.as_mut_ptr(),
                buf.len(),
            );
        }
        Ok(())
    }

    /// Erase page `index` of the region, after which it reads as `0xff`.
    ///
    /// # Safety
    /// As [`open`](Self::open): this destroys 8 KB, and the bus stalls until it is done.
    pub unsafe fn erase(&mut self, index: u32) -> Result<(), Error> {
        if index >= self.pages() {
            return Err(Error::Address {
                addr: self.start + index * self.page_size,
            });
        }
        let addr = self.start + index * self.page_size;
        let (bank2, pnb) = page_of(
            addr,
            catcard_board::memory::fixed::FLASH_BASE,
            self.page_size,
            self.dual_bank,
            self.bank_len,
        );
        // SAFETY: the caller owns this region; every write below is to the flash interface.
        unsafe {
            self.unlock()?;
            let bits = CR_PER | (pnb << CR_PNB_SHIFT) | if bank2 { CR_BKER } else { 0 };
            reg::modify(FLASH + CR, CR_PER | CR_PNB_MASK | CR_BKER, bits);
            reg::modify(FLASH + CR, 0, CR_STRT);
            let r = self.finish();
            reg::modify(FLASH + CR, CR_PER | CR_PNB_MASK | CR_BKER, 0);
            self.lock();
            r
        }
    }

    /// Program `data` at `off` within the region.
    ///
    /// `off` and `data.len()` must both be multiples of [`DWORD`], and the target must be
    /// erased: flash can only clear bits, so programming over data reports an error rather
    /// than quietly producing the AND of the two.
    ///
    /// # Safety
    /// As [`open`](Self::open).
    pub unsafe fn program(&mut self, off: u32, data: &[u8]) -> Result<(), Error> {
        if !off.is_multiple_of(DWORD as u32) || !data.len().is_multiple_of(DWORD) {
            return Err(Error::Address {
                addr: self.start + off,
            });
        }
        let end = off
            .checked_add(data.len() as u32)
            .ok_or(Error::Address { addr: off })?;
        if end > self.len {
            return Err(Error::Address {
                addr: self.start + off,
            });
        }
        // SAFETY: as documented; the region belongs to the caller.
        unsafe {
            self.unlock()?;
            reg::modify(FLASH + CR, 0, CR_PG);
            let mut r = Ok(());
            for (i, chunk) in data.as_chunks::<DWORD>().0.iter().enumerate() {
                let at = self.start + off + (i * DWORD) as u32;
                let lo = u32::from_le_bytes(chunk[..4].try_into().expect("4 bytes"));
                let hi = u32::from_le_bytes(chunk[4..].try_into().expect("4 bytes"));
                // Both halves, low first: the controller starts the write on the second.
                core::ptr::write_volatile(at as *mut u32, lo);
                core::ptr::write_volatile((at + 4) as *mut u32, hi);
                r = self.finish();
                if r.is_err() {
                    break;
                }
            }
            reg::modify(FLASH + CR, CR_PG, 0);
            self.lock();
            r
        }
    }

    /// # Safety
    /// Writes the flash interface's key register.
    unsafe fn unlock(&self) -> Result<(), Error> {
        // SAFETY: as documented.
        unsafe {
            self.wait_idle()?;
            if reg::read(FLASH + CR) & CR_LOCK != 0 {
                reg::write(FLASH + KEYR, KEY1);
                reg::write(FLASH + KEYR, KEY2);
            }
            if reg::read(FLASH + CR) & CR_LOCK != 0 {
                return Err(Error::Reported {
                    sr: reg::read(FLASH + SR),
                });
            }
            // Stale flags from an earlier operation would be read as this one's.
            reg::write(FLASH + SR, SR_ERRORS | SR_EOP);
            Ok(())
        }
    }

    /// # Safety
    /// Writes `CR`.
    unsafe fn lock(&self) {
        // SAFETY: as documented.
        unsafe { reg::modify(FLASH + CR, 0, CR_LOCK) }
    }

    /// Wait for `BSY` to clear.
    ///
    /// # Safety
    /// Reads `SR`.
    unsafe fn wait_idle(&self) -> Result<(), Error> {
        for _ in 0..BUSY_POLLS {
            // SAFETY: a register read.
            if unsafe { reg::read(FLASH + SR) } & SR_BSY == 0 {
                return Ok(());
            }
        }
        Err(Error::Stuck)
    }

    /// Wait for the operation to end, then report what the controller says about it.
    ///
    /// # Safety
    /// Reads and clears `SR`.
    unsafe fn finish(&self) -> Result<(), Error> {
        // SAFETY: as documented.
        unsafe {
            self.wait_idle()?;
            let sr = reg::read(FLASH + SR);
            reg::write(FLASH + SR, SR_ERRORS | SR_EOP);
            if sr & SR_ERRORS != 0 {
                return Err(Error::Reported { sr });
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u32 = 0x0800_0000;

    #[test]
    fn a_single_bank_part_numbers_pages_straight_through() {
        // mk4/mk5/Q1: 8 KB pages, no bank bit. The settings region starts at 0x08180000,
        // which is page 192, and its 512 KB are the last 64 pages of a 2 MB part.
        let (bank2, pnb) = page_of(0x0818_0000, BASE, 8 * 1024, false, 1024 * 1024);
        assert!(!bank2);
        assert_eq!(pnb, 192);
        let (_, last) = page_of(0x081F_E000, BASE, 8 * 1024, false, 1024 * 1024);
        assert_eq!(last, 255);
    }

    #[test]
    fn a_dual_bank_part_numbers_each_half_from_zero() {
        // mk3: 1 MB in two 512 KB banks of 2 KB pages.
        let bank_len = 512 * 1024;
        let (bank2, pnb) = page_of(0x0800_0800, BASE, 2048, true, bank_len);
        assert!(!bank2);
        assert_eq!(pnb, 1);
        // The first page of the second bank is page zero again, with the bank bit set --
        // the same number as the first page of the first.
        let (bank2, pnb) = page_of(0x0808_0000, BASE, 2048, true, bank_len);
        assert!(bank2);
        assert_eq!(pnb, 0);
        let (bank2, pnb) = page_of(0x0808_0800, BASE, 2048, true, bank_len);
        assert!((bank2, pnb) == (true, 1));
    }

    #[test]
    fn each_board_expects_the_configuration_its_bootloader_asserts() {
        assert_eq!(expected(Mcu::Stm32L4S5), (8 * 1024, false));
        assert_eq!(expected(Mcu::Stm32L496), (2 * 1024, true));
    }

    #[test]
    fn the_error_flags_cover_every_way_a_write_can_fail() {
        // Programming over data that is not erased reports `PROGERR`; a misaligned one
        // `PGAERR`; a write-protected page `WRPERR`. All three are in the mask that is
        // both checked and cleared, so none of them can be mistaken for success.
        for flag in [SR_PROGERR, SR_PGAERR, SR_WRPERR, SR_PGSERR, SR_SIZERR] {
            assert!(SR_ERRORS & flag != 0);
        }
        assert_eq!(SR_ERRORS & SR_EOP, 0);
        assert_eq!(SR_ERRORS & SR_BSY, 0);
    }
}
