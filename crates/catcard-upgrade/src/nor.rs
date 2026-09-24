//! Staging into SPI-NOR, which is how mk3 does it — the one generation with no PSRAM.
//!
//! The bootloader runs `sf_firmware_upgrade()` every boot: it reads a firmware header at
//! SPI-NOR offset `0x3F80`, and if a validly-signed image is staged from offset 0 with a
//! matching **trailing duplicate header** at `firmware_length`, it copies the image into
//! main flash. So staging here is three moves:
//!
//! 1. write the image from offset 0 (its primary header is already at `0x3F80` inside it);
//! 2. write a copy of that header at `firmware_length`, **last** — its presence is the
//!    "upload complete" marker (an interrupted upload has none, so it installs nothing);
//! 3. reboot; the bootloader finds it.
//!
//! Unlike PSRAM (mk4+), there is no `gate 18/7` and no recovery-header magics: the trailing
//! header written last *is* the safety property, the same role the PSRAM magics play.
//!
//! **Settings coexistence.** The nvstore lives in the last 128 KB of the 1 MB part
//! (`0xE0000..0x100000`), so the image plus its trailing header must end below
//! [`NVSTORE_BASE`] or it overwrites settings — tighter than the bootloader's nominal
//! `FW_MAX_LENGTH`. Source: `hw-reference/storage.md §"mk3 firmware staging & recovery"` [C].

use catcard_flash::{Error as FlashError, NorFlash, SECTOR_SIZE, SpiDevice};
use catcard_fwhdr::{HEADER_LEN, HEADER_OFFSET};

use crate::StagingArea;

/// Start of the nvstore settings region in SPI-NOR. The staged image and its trailing
/// header must both end below this. Source: `hw-reference/storage.md` [C].
pub const NVSTORE_BASE: u32 = 0x000E_0000;

/// A SPI-NOR part set up to stage one image.
///
/// NOR only clears bits on a program, so every sector is erased before it is written. The
/// upgrade flow delivers the image in order from offset 0, so erasing runs as a watermark
/// just ahead of the writes rather than all up front.
pub struct NorArea<B: SpiDevice> {
    nor: NorFlash<B>,
    /// Largest image, bounded so image + trailing header stays below the settings region.
    capacity: u32,
    /// Everything below this offset has been erased.
    erased_to: u32,
    /// Where the trailing header was written by `publish`, so `retract` can find it.
    published_at: Option<u32>,
}

/// Why a SPI-NOR staging operation failed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum NorError<E> {
    /// The write would run past the staging area (into the settings region, or overflow).
    OutOfRange,
    /// The flash driver failed.
    Flash(FlashError<E>),
    /// The trailing header did not read back as written — the marker is not trustworthy,
    /// so refuse rather than reboot into an install of something half-written.
    MarkerNotVerified,
}

impl<B: SpiDevice> NorArea<B> {
    /// Wrap a brought-up NOR for staging.
    ///
    /// Capacity is the largest image whose trailing 128-byte header still ends below the
    /// settings region — so a legitimate mk3 image (≤ ~896 KB) fits and one that would
    /// clobber nvstore is refused at `begin` rather than mid-write.
    pub fn new(nor: NorFlash<B>) -> Self {
        Self {
            nor,
            capacity: NVSTORE_BASE - HEADER_LEN as u32,
            erased_to: 0,
            published_at: None,
        }
    }

    /// Erase whole sectors until everything below `end` is erased. Idempotent as the
    /// watermark only moves forward.
    fn erase_through(&mut self, end: u32) -> Result<(), FlashError<B::Error>> {
        while self.erased_to < end {
            self.nor.erase_sector(self.erased_to)?;
            self.erased_to += SECTOR_SIZE;
        }
        Ok(())
    }
}

impl<B: SpiDevice> StagingArea for NorArea<B> {
    type Error = NorError<B::Error>;

    fn capacity(&self) -> u32 {
        self.capacity
    }

    /// The bootloader reads the staged image from SPI-NOR **offset 0** (absolute), not a
    /// base+offset the way `gate 18/7` wants on PSRAM — so this is 0.
    fn image_offset(&self) -> u32 {
        0
    }

    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), Self::Error> {
        let end = offset
            .checked_add(data.len() as u32)
            .ok_or(NorError::OutOfRange)?;
        if end > self.capacity {
            return Err(NorError::OutOfRange);
        }
        self.erase_through(end).map_err(NorError::Flash)?;
        self.nor.write(offset, data).map_err(NorError::Flash)
    }

    fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<(), Self::Error> {
        let end = offset
            .checked_add(out.len() as u32)
            .ok_or(NorError::OutOfRange)?;
        if end > NVSTORE_BASE {
            return Err(NorError::OutOfRange);
        }
        self.nor.read(offset, out).map_err(NorError::Flash)
    }

    /// Write the trailing duplicate header at `firmware_length`, last of all.
    ///
    /// It is a byte-for-byte copy of the primary header already staged at
    /// [`HEADER_OFFSET`], so no header bytes are passed in — reading it back from the
    /// staged image and re-writing it at the end is exactly what the stock uploader does.
    /// Read back before returning: this is the last thing before a reboot that installs
    /// over the running firmware, and the bootloader trusts whatever these bytes say.
    fn publish(&mut self, len: u32) -> Result<(), Self::Error> {
        if len
            .checked_add(HEADER_LEN as u32)
            .is_none_or(|e| e > NVSTORE_BASE)
        {
            return Err(NorError::OutOfRange);
        }

        let mut hdr = [0u8; HEADER_LEN];
        self.nor
            .read(HEADER_OFFSET as u32, &mut hdr)
            .map_err(NorError::Flash)?;

        self.erase_through(len + HEADER_LEN as u32)
            .map_err(NorError::Flash)?;
        self.nor.write(len, &hdr).map_err(NorError::Flash)?;

        let mut back = [0u8; HEADER_LEN];
        self.nor.read(len, &mut back).map_err(NorError::Flash)?;
        if back != hdr {
            return Err(NorError::MarkerNotVerified);
        }
        self.published_at = Some(len);
        Ok(())
    }

    /// Zero the trailing header `publish` wrote, so the bootloader finds no image.
    ///
    /// NOR programs only clear bits, so zeros go over the header without an erase, and
    /// a header with no magic in it is exactly "nothing staged" -- the same property
    /// the header being written last gives `publish`. Read back, for the same reason
    /// `publish` reads back. Nothing to do if nothing was published.
    fn retract(&mut self) -> Result<(), Self::Error> {
        let Some(at) = self.published_at else {
            return Ok(());
        };
        self.nor
            .write(at, &[0u8; HEADER_LEN])
            .map_err(NorError::Flash)?;
        let mut back = [0xFFu8; HEADER_LEN];
        self.nor.read(at, &mut back).map_err(NorError::Flash)?;
        if back != [0u8; HEADER_LEN] {
            return Err(NorError::MarkerNotVerified);
        }
        self.published_at = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use catcard_flash::{cmd, status};
    use std::vec;
    use std::vec::Vec;

    /// A byte-accurate model of the MX25L8006E: 1 MB, 4 KB sector erase, 256-byte page
    /// program, one-bit-clearing programs. Enough of the command set for [`NorFlash`].
    struct MemNor {
        mem: Vec<u8>,
        wel: bool,
    }

    impl MemNor {
        fn new() -> Self {
            Self {
                mem: vec![0xFF; 1024 * 1024],
                wel: false,
            }
        }
    }

    impl SpiDevice for MemNor {
        type Error = ();

        fn transfer(&mut self, write: &[u8], read: &mut [u8]) -> Result<(), ()> {
            let addr = |w: &[u8]| ((w[1] as usize) << 16) | ((w[2] as usize) << 8) | w[3] as usize;
            match write[0] {
                cmd::RDID => {
                    // Macronix MX25L8006E: C2 20 14 (1 MB).
                    let id = [0xC2u8, 0x20, 0x14];
                    for (i, b) in read.iter_mut().enumerate() {
                        *b = *id.get(i).unwrap_or(&0);
                    }
                }
                cmd::READ_STATUS => {
                    let s = if self.wel { status::WEL } else { 0 };
                    read.iter_mut().for_each(|b| *b = s); // WIP always clear: instant ops
                }
                cmd::WRITE_ENABLE => self.wel = true,
                cmd::WRITE_DISABLE => self.wel = false,
                cmd::SECTOR_ERASE => {
                    assert!(self.wel, "erase without WREN");
                    let a = addr(write) & !(SECTOR_SIZE as usize - 1);
                    for b in &mut self.mem[a..a + SECTOR_SIZE as usize] {
                        *b = 0xFF;
                    }
                    self.wel = false;
                }
                cmd::PAGE_PROGRAM => {
                    assert!(self.wel, "program without WREN");
                    let a = addr(write);
                    for (i, b) in write[4..].iter().enumerate() {
                        // NOR programs clear bits only.
                        self.mem[a + i] &= b;
                    }
                    self.wel = false;
                }
                cmd::READ => {
                    let a = addr(write);
                    for (i, b) in read.iter_mut().enumerate() {
                        *b = self.mem[a + i];
                    }
                }
                other => panic!("unmodelled opcode {other:#04x}"),
            }
            Ok(())
        }
    }

    fn area() -> NorArea<MemNor> {
        NorArea::new(NorFlash::probe(MemNor::new()).unwrap())
    }

    /// A fake image: a recognisable byte at every offset, a 128-byte header stamped at
    /// `HEADER_OFFSET`, of `len` bytes.
    fn fake_image(len: usize) -> Vec<u8> {
        let mut img = vec![0u8; len];
        for (i, b) in img.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        for (i, b) in img[HEADER_OFFSET..HEADER_OFFSET + HEADER_LEN]
            .iter_mut()
            .enumerate()
        {
            *b = 0xA0 ^ (i as u8);
        }
        img
    }

    #[test]
    fn a_staged_image_reads_back_and_gets_a_matching_trailing_header() {
        let len = 300 * 1024; // a realistic mk3 image size
        let img = fake_image(len);
        let mut a = area();

        // Deliver it the way the upgrade flow does: in order, in small chunks.
        for (i, chunk) in img.chunks(64).enumerate() {
            a.write(i as u32 * 64, chunk).unwrap();
        }
        a.publish(len as u32).unwrap();

        // The image is byte-identical in SPI-NOR.
        let mut back = vec![0u8; len];
        a.read(0, &mut back).unwrap();
        assert_eq!(back, img, "staged image differs from what was written");

        // The trailing header at `len` is a copy of the primary header at 0x3F80.
        let mut primary = [0u8; HEADER_LEN];
        a.read(HEADER_OFFSET as u32, &mut primary).unwrap();
        let mut trailing = [0u8; HEADER_LEN];
        a.read(len as u32, &mut trailing).unwrap();
        assert_eq!(
            trailing, primary,
            "trailing header is not a copy of the primary"
        );
    }

    #[test]
    fn retracting_zeroes_the_trailing_header_and_nothing_else() {
        let len = 300 * 1024;
        let img = fake_image(len);
        let mut a = area();
        for (i, chunk) in img.chunks(64).enumerate() {
            a.write(i as u32 * 64, chunk).unwrap();
        }
        // Nothing published yet: retracting is a no-op, not an error.
        a.retract().unwrap();

        a.publish(len as u32).unwrap();
        a.retract().unwrap();

        // The marker the bootloader would act on is gone...
        let mut trailing = [0xFFu8; HEADER_LEN];
        a.read(len as u32, &mut trailing).unwrap();
        assert_eq!(trailing, [0u8; HEADER_LEN], "trailing header still there");
        // ...and the image itself, primary header included, is untouched.
        let mut back = vec![0u8; len];
        a.read(0, &mut back).unwrap();
        assert_eq!(back, img, "retract touched the staged image");
        // Retracting twice is still a no-op.
        a.retract().unwrap();
    }

    #[test]
    fn an_image_that_would_reach_the_settings_region_is_refused() {
        let mut a = area();
        // Capacity leaves room for the 128-byte trailing header below nvstore.
        assert_eq!(a.capacity(), NVSTORE_BASE - HEADER_LEN as u32);
        // A write whose end passes capacity is refused, not silently truncated.
        let big = vec![0u8; 64];
        assert_eq!(a.write(a.capacity(), &big), Err(NorError::OutOfRange));
        // And publishing a length whose trailing header would land in nvstore.
        assert_eq!(a.publish(NVSTORE_BASE), Err(NorError::OutOfRange));
    }

    #[test]
    fn the_staged_image_is_read_only_below_the_settings_region() {
        let mut a = area();
        let mut out = [0u8; 16];
        assert!(a.read(NVSTORE_BASE - 16, &mut out).is_ok());
        assert_eq!(a.read(NVSTORE_BASE, &mut out), Err(NorError::OutOfRange));
    }

    #[test]
    fn image_offset_is_zero_because_the_bootloader_reads_from_absolute_zero() {
        assert_eq!(area().image_offset(), 0);
    }
}
