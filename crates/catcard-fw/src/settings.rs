//! The settings blob on this board's medium.
//!
//! The rules live in [`catcard_settings::store`]; the format in
//! [`catcard_settings::nvstore`]. This is the medium: on mk4/mk5/Q1 the slots are files in
//! the LittleFS volume on internal flash, named as stock names them, so a device that has
//! been either firmware still finds its own settings.
//!
//! The mk3 keeps its slots in raw SPI-NOR blocks instead, with the block's byte offset as
//! the `pos` in the counter; that medium is not wired up yet.

use catcard_settings::nvstore::SLOT_LEN;
use catcard_settings::store::Slots;

use crate::nvram::Blocks;

/// Slots stock keeps on a LittleFS device, as `settings/000.aes` upwards.
/// Source: hw-reference/settings-nvstore-format.md §1 [C]
pub const SLOT_COUNT: u32 = 100;

/// The LittleFS volume, sized for the 512-byte blocks the region is formatted with.
type Volume = fstool::fs::littlefs::Volume<Blocks, { crate::nvram::BLOCK }, { crate::nvram::BLOCK }>;

/// Settings slots as files in the internal-flash volume.
pub struct Files {
    vol: Volume,
}

impl Files {
    /// Mount the settings volume.
    ///
    /// # Safety
    /// As [`Blocks::open`]: nothing else may touch the region, and each write stalls the bus.
    pub unsafe fn mount() -> Result<Self, &'static str> {
        // SAFETY: forwarding the caller's guarantee.
        let blocks = unsafe { Blocks::open() }.map_err(|_| "no settings region")?;
        let vol = Volume::mount(blocks).map_err(|_| "no filesystem there")?;
        Ok(Self { vol })
    }

    /// The path of slot `index`, as stock writes it: `settings/%03x.aes`.
    fn path(index: u32, out: &mut heapless::String<24>) {
        use core::fmt::Write as _;
        let _ = write!(out, "/settings/{index:03x}.aes");
    }
}

impl Slots for Files {
    fn count(&self) -> u32 {
        SLOT_COUNT
    }

    /// The file index, which is what stock puts in the counter on this medium.
    fn pos(&self, index: u32) -> u32 {
        index
    }

    fn read(&mut self, index: u32, buf: &mut [u8]) -> Result<Option<usize>, ()> {
        let mut path = heapless::String::new();
        Self::path(index, &mut path);
        // A slot that is not there is not an error: most of the hundred never are.
        let Ok(mut file) = self.vol.open_file(&path) else {
            return Ok(None);
        };
        let len = (file.len() as usize).min(buf.len());
        let mut got = 0;
        while got < len {
            match file.read(&mut self.vol, &mut buf[got..len]) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(_) => return Err(()),
            }
        }
        Ok(Some(got))
    }

    fn write(&mut self, index: u32, bytes: &[u8]) -> Result<(), ()> {
        let mut path = heapless::String::new();
        Self::path(index, &mut path);
        let mut file = self.vol.open_or_create_file(&path).map_err(|_| ())?;
        file.write_all(&mut self.vol, bytes).map_err(|_| ())?;
        file.set_len(&mut self.vol, bytes.len() as u32).map_err(|_| ())?;
        file.sync(&mut self.vol).map_err(|_| ())
    }

    fn clear(&mut self, index: u32) -> Result<(), ()> {
        let mut path = heapless::String::new();
        Self::path(index, &mut path);
        // Already gone is the outcome asked for.
        match self.vol.remove_file(&path) {
            Ok(()) => Ok(()),
            Err(_) => Ok(()),
        }
    }
}

/// A buffer big enough for one slot, for a caller that wants to read the settings.
pub const fn buffer() -> [u8; SLOT_LEN] {
    [0; SLOT_LEN]
}
