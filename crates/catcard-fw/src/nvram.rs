//! Internal flash as the filesystem underneath the settings, in 512-byte blocks.
//!
//! The settings region is a LittleFS2 volume, and the one on a stock device is formatted
//! with **512-byte blocks** ([read off a real Q1](../../docs/SECRETS-AND-SETTINGS.md)) even
//! though the flash erases in 8 KB pages. That is what the firmware there presents through
//! its own block device, so being able to read an existing volume means presenting the same
//! thing: a block device whose blocks are sixteen to a page.
//!
//! # Erasing a sixteenth of a page
//!
//! Flash cannot erase less than a page, so erasing one 512-byte block means rewriting the
//! page around it: read the page into RAM, blank the block's part of it, erase, program the
//! rest back. Programming is direct, because the filesystem only ever programs a block it
//! has just erased.
//!
//! The cost is a page rewrite per block erase, and the risk is the usual one for
//! read-modify-write: power lost mid-rewrite takes the other fifteen blocks with it. The
//! settings format is built for exactly that -- a new slot is written before the old one is
//! removed, and the newest valid slot wins -- so a lost page costs the last change, not the
//! settings.

use catcard_board::BOARD;
use catcard_hal::iflash::{self, Internal};
use fstool::device::FlashDriver;

/// The filesystem's block size, as a stock volume is formatted.
pub const BLOCK: usize = 512;

/// The page rewrite buffer. One page, so a block erase can put back what it must keep.
///
/// Static rather than on the stack: 8 KB is more than a screen's call chain should carry,
/// and only one settings operation runs at a time.
const PAGE_MAX: usize = 8 * 1024;
static mut PAGE_BUF: [u8; PAGE_MAX] = [0; PAGE_MAX];

/// Internal flash, in filesystem blocks.
pub struct Blocks {
    flash: Internal,
    page_size: usize,
    blocks: u32,
}

/// Why the region could not be opened or written.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// This board keeps its settings somewhere else (mk3: SPI-NOR).
    NotHere,
    /// The flash driver refused.
    Flash(iflash::Error),
    /// The page does not divide into whole blocks, which the emulation needs.
    #[allow(dead_code)] // reported by the write path, which nothing calls yet
    Geometry { page_size: usize },
}

impl From<iflash::Error> for Error {
    fn from(e: iflash::Error) -> Self {
        Error::Flash(e)
    }
}

impl Blocks {
    /// Claim the board's settings region.
    ///
    /// # Safety
    /// Nothing else may write the region while this lives, and each operation stalls the
    /// bus (the settings pages share a bank with the running code), so the caller must not
    /// need an interrupt serviced during one.
    #[allow(dead_code)] // the writable path returns when settings are saved, not just read
    pub unsafe fn open() -> Result<Self, Error> {
        let (start, len) = match BOARD.settings {
            catcard_board::spec::SettingsArea::InternalFlash { start, len } => (start, len),
            _ => return Err(Error::NotHere),
        };
        // SAFETY: forwarding the caller's guarantee; the region is the board table's.
        let flash = unsafe { Internal::open(BOARD.mcu, start, len, BOARD.memory.total_flash_len)? };
        let page_size = flash.page_size() as usize;
        if !page_size.is_multiple_of(BLOCK) || page_size > PAGE_MAX {
            return Err(Error::Geometry { page_size });
        }
        Ok(Self {
            flash,
            page_size,
            blocks: len / BLOCK as u32,
        })
    }

    /// Claim the board's settings region **for reading only**.
    ///
    /// Makes no claim about the flash's bank configuration, so it opens on a part this
    /// driver would otherwise refuse -- a Q1 whose `DBANK` is not what the board table
    /// expects, for instance. [`FlashDriver::erase`] and `prog` then fail, so a volume
    /// mounted through this cannot modify what it is reading, by construction rather than
    /// by intention. That matters on a device whose settings are someone's notes.
    ///
    /// # Safety
    /// The region is mapped and readable; nothing is written.
    pub unsafe fn open_read_only() -> Result<Self, Error> {
        let (start, len) = match BOARD.settings {
            catcard_board::spec::SettingsArea::InternalFlash { start, len } => (start, len),
            _ => return Err(Error::NotHere),
        };
        // SAFETY: forwarding the caller's guarantee.
        let flash = unsafe { Internal::open_read_only(start, len)? };
        Ok(Self {
            flash,
            // Unused: a read needs no page geometry, and an erase is refused.
            page_size: BLOCK,
            blocks: len / BLOCK as u32,
        })
    }

    /// Blocks per flash page.
    fn per_page(&self) -> u32 {
        (self.page_size / BLOCK) as u32
    }

    /// The offset of `block` within the region.
    fn offset(&self, block: u32) -> u32 {
        block * BLOCK as u32
    }
}

impl FlashDriver for Blocks {
    type Error = iflash::Error;

    fn block_size(&self) -> u32 {
        BLOCK as u32
    }

    fn block_count(&self) -> u32 {
        self.blocks
    }

    /// The filesystem writes a whole block at a time here: the emulation cannot program
    /// less than it can put back.
    fn prog_size(&self) -> u32 {
        BLOCK as u32
    }

    fn read(&mut self, block: u32, off: u32, buf: &mut [u8]) -> Result<(), Self::Error> {
        // SAFETY: bounds are checked inside, and flash is memory-mapped for reads.
        unsafe { self.flash.read(self.offset(block) + off, buf) }
    }

    fn prog(&mut self, block: u32, off: u32, data: &[u8]) -> Result<(), Self::Error> {
        // Erased storage, per the trait: program it straight.
        // SAFETY: as in `open`.
        unsafe { self.flash.program(self.offset(block) + off, data) }
    }

    fn erase(&mut self, block: u32) -> Result<(), Self::Error> {
        let per_page = self.per_page();
        let page = block / per_page;
        let page_off = page * self.page_size as u32;
        let within = (block % per_page) as usize * BLOCK;

        // SAFETY: one settings operation at a time, foreground only.
        let scratch: &mut [u8; PAGE_MAX] = unsafe { &mut *core::ptr::addr_of_mut!(PAGE_BUF) };
        let buf = &mut scratch[..self.page_size];
        // SAFETY: as in `open`. Read the page, blank this block's share of it, put the
        // rest back: the fifteen other blocks in the page belong to the filesystem too.
        unsafe {
            self.flash.read(page_off, buf)?;
            buf[within..within + BLOCK].fill(0xFF);
            self.flash.erase(page)?;
            // Nothing to program where the page is already erased; skipping those keeps a
            // fresh volume's erase cheap and avoids programming 0xff over 0xff, which the
            // controller reports as an error on some parts.
            for (i, chunk) in buf.chunks(BLOCK).enumerate() {
                if chunk.iter().all(|&b| b == 0xFF) {
                    continue;
                }
                self.flash.program(page_off + (i * BLOCK) as u32, chunk)?;
            }
        }
        Ok(())
    }
}
