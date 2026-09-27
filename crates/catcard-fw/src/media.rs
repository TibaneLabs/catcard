//! The one block device every volume is mounted on: the microSD card, or the Virtual Disk.
//!
//! The FAT and exFAT drivers are generic over their device, and so is everything above
//! them here -- browse, read, write, export, stage a firmware, show a picture. With a
//! device type per medium, each of those was compiled twice, once for the card and once
//! for the disk: about 34 KB of the Q1 image was the same code a second time. Behind this
//! enum it is compiled once, and which medium it is costs a `match` per sector transfer,
//! next to a card command or a paced PSRAM burst.
//!
//! Only the card and the Virtual Disk go through here. The settings volume and a restore's
//! staged backup are other devices with drivers of their own.

use catcard_sd::fat::SectorDriver;

/// A mounted volume, on whichever medium.
pub(crate) type Volume = catcard_sd::AnyVolume<Media, 512>;

/// The medium under a [`Volume`].
///
/// `Card` is the larger by far -- it carries the card's session cipher -- so a
/// disk-backed volume is as big as a card-backed one. The card's is the size every
/// volume already had on the paths that reach it.
///
/// Not boxed, for all the lint's advice: that would put every card mount on the heap, and
/// a mount that fails for want of memory, to save a few hundred bytes of stack on the
/// disk's paths only -- which are shallower than the card's.
#[allow(clippy::large_enum_variant)]
pub(crate) enum Media {
    Card(catcard_sd::Sectors<catcard_hal::sdmmc::Sdmmc>),
    #[cfg(not(feature = "board-mk3"))]
    Disk(crate::vdisk::Vdisk),
}

/// What a sector transfer failed with, on whichever medium it was.
pub(crate) enum MediaError {
    Card(catcard_sd::Error),
    #[cfg(not(feature = "board-mk3"))]
    Disk(catcard_upgrade::psram::OutOfRange),
}

/// The medium's own error, as it printed before there was a wrapper round it: the log
/// lines are the same whichever device a volume sits on.
impl core::fmt::Debug for MediaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Card(e) => e.fmt(f),
            #[cfg(not(feature = "board-mk3"))]
            Self::Disk(e) => e.fmt(f),
        }
    }
}

impl SectorDriver for Media {
    type Error = MediaError;

    fn sector_size(&self) -> u32 {
        match self {
            Self::Card(c) => c.sector_size(),
            #[cfg(not(feature = "board-mk3"))]
            Self::Disk(d) => d.sector_size(),
        }
    }

    fn sector_count(&self) -> u64 {
        match self {
            Self::Card(c) => c.sector_count(),
            #[cfg(not(feature = "board-mk3"))]
            Self::Disk(d) => d.sector_count(),
        }
    }

    fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), MediaError> {
        match self {
            Self::Card(c) => c.read_sectors(lba, buf).map_err(MediaError::Card),
            #[cfg(not(feature = "board-mk3"))]
            Self::Disk(d) => d.read_sectors(lba, buf).map_err(MediaError::Disk),
        }
    }

    fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), MediaError> {
        match self {
            Self::Card(c) => c.write_sectors(lba, buf).map_err(MediaError::Card),
            #[cfg(not(feature = "board-mk3"))]
            Self::Disk(d) => d.write_sectors(lba, buf).map_err(MediaError::Disk),
        }
    }

    fn flush(&mut self) -> Result<(), MediaError> {
        match self {
            Self::Card(c) => c.flush().map_err(MediaError::Card),
            #[cfg(not(feature = "board-mk3"))]
            Self::Disk(d) => d.flush().map_err(MediaError::Disk),
        }
    }
}
