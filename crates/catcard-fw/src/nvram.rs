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

/// The largest page this driver will rewrite. Eight kilobytes is more than a screen's
/// call chain should carry on the stack, so the buffer comes from the heap instead --
/// taken when the region is opened and given back when it is dropped, rather than
/// reserved for the life of a device that spends most of it not writing settings.
const PAGE_MAX: usize = 8 * 1024;

/// Internal flash, in filesystem blocks.
pub struct Blocks {
    flash: Internal,
    page_size: usize,
    blocks: u32,
    /// One page, so a block erase can put back what it must keep. `None` on a
    /// read-only open, which never erases.
    page: Option<crate::heap::Block>,
}

/// Why the region could not be opened or written.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// This board keeps its settings somewhere else (mk3: SPI-NOR).
    NotHere,
    /// The flash driver refused.
    Flash(iflash::Error),
    /// The page does not divide into whole blocks, which the emulation needs.
    Geometry { page_size: usize },
    /// No heap room for the page rewrite buffer. Said at `open`, not part way through
    /// an erase -- there is no good answer to running out in the middle of one.
    NoMemory,
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
        // The rewrite buffer, for as long as this region is open. Refused here rather
        // than part way through an erase, where there is no answer but to lose the page.
        let page = crate::heap::take(page_size).ok_or(Error::NoMemory)?;
        Ok(Self {
            flash,
            page_size,
            blocks: len / BLOCK as u32,
            page: Some(page),
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
            page: None,
        })
    }

    /// Blocks per flash page.
    fn per_page(&self) -> u32 {
        (self.page_size / BLOCK) as u32
    }

    /// The offset of byte `off` of `block` within the region.
    ///
    /// `block` comes from on-flash filesystem metadata, which nobody has checked before
    /// this runs -- the pre-login read happens before the PIN prompt. A block number that
    /// multiplies past `u32` is a refusal here, not an arithmetic panic there: the flash
    /// driver's own bounds check then never sees it, so it is reported as the address
    /// error it would have been.
    fn offset(&self, block: u32, off: u32) -> Result<u32, iflash::Error> {
        block
            .checked_mul(BLOCK as u32)
            .and_then(|at| at.checked_add(off))
            .ok_or(iflash::Error::Address {
                addr: block.saturating_mul(BLOCK as u32),
            })
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
        let at = self.offset(block, off)?;
        // SAFETY: bounds are checked inside, and flash is memory-mapped for reads.
        unsafe { self.flash.read(at, buf) }
    }

    fn prog(&mut self, block: u32, off: u32, data: &[u8]) -> Result<(), Self::Error> {
        let at = self.offset(block, off)?;
        // Erased storage, per the trait: program it straight.
        // SAFETY: as in `open`.
        unsafe { self.flash.program(at, data) }
    }

    fn erase(&mut self, block: u32) -> Result<(), Self::Error> {
        let per_page = self.per_page();
        let page = block / per_page;
        // The page's first block is at most `block`, so if this overflows so would any
        // read of `block` itself; either way it is refused, not computed.
        let page_off = self.offset(page * per_page, 0)?;
        let within = (block % per_page) as usize * BLOCK;
        let page_size = self.page_size;

        // Destructured so the buffer and the flash are borrowed as the separate fields
        // they are; going through `&mut self` twice would not compile.
        let Self {
            flash, page: held, ..
        } = self;
        let Some(held) = held.as_mut() else {
            // A read-only open has no rewrite buffer, and erasing is what it does not
            // do. The flash driver already has the right word for this.
            return Err(iflash::Error::ReadOnly);
        };
        let buf = &mut held.bytes()[..page_size];
        // SAFETY: as in `open`. Read the page, blank this block's share of it, put the
        // rest back: the fifteen other blocks in the page belong to the filesystem too.
        unsafe {
            flash.read(page_off, buf)?;
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
