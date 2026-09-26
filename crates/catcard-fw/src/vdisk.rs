//! A PSRAM-backed **Virtual Disk**: a small FAT volume in a fixed region at the top of
//! PSRAM, exposed over USB mass storage and browsable locally, so a PSBT, descriptor or
//! export can be staged without a microSD card.
//!
//! # Where it lives
//!
//! The board table carves a fixed [`Psram::VDISK_RESERVE`](catcard_board::Psram::VDISK_RESERVE)
//! region just below the bootloader's recovery header and shrinks
//! [`Psram::usable`](catcard_board::Psram::usable) by it, so no
//! [`crate::psram::take`] lease (signing, a QR being reassembled, a settings restore, the
//! memory test) is ever handed bytes that overlap the disk. Unlike those, the disk is a
//! **dedicated facility, not a lease**: there is one, it is always the same region, and
//! foreground code (the USB Drive screen, the file browser) is its only user, one at a
//! time — so there is nothing to arbitrate.
//!
//! The one thing it is *not* fenced from is a firmware image on its way in: staging uses
//! the upper half of the part, which the disk sits inside. The two never run at once (a
//! host cannot offer firmware while the device is a disk, and staging reboots), and the
//! disk is volatile scratch, so an upgrade that lands on it just leaves a region the next
//! mount reformats. See [`Psram::VDISK_RESERVE`](catcard_board::Psram::VDISK_RESERVE).
//!
//! # Why the writes are paced
//!
//! It is memory-mapped RAM, but it is *PSRAM*: byte stores are unreliable and a burst
//! that holds CE# low past `tCEM` (8 µs) starves the part's refresh and corrupts memory
//! anywhere on the chip — a plain 512-byte `memcpy` at 60 MHz is roughly 17 µs, over
//! twice that. So every sector read and write goes through
//! [`catcard_upgrade::psram::PsramArea`], the same tested path staging uses: aligned
//! 32-bit stores only, CE# released inside `tCEM`. Sector reads and writes are always
//! 512-byte, 512-aligned within a word-aligned region, so no partial-word merge ever
//! happens. Source: `crates/catcard-upgrade/src/psram.rs`, `docs/PSRAM.md` [C].
//!
//! # Volatile
//!
//! Lost on power-off, which is the point: it is staging memory, not storage. On first use
//! (or after an upgrade overwrote it) it holds no filesystem, and [`ensure_formatted`]
//! lays down an empty FAT volume — silently, because an uninitialised region has nothing
//! to lose.

use catcard_sd::fat::{self, SectorDriver};
use catcard_sd::{AnyVolume, BLOCK_LEN};
use catcard_upgrade::StagingArea;
use catcard_upgrade::psram::{OutOfRange, PsramArea};

/// The volume serial stamped on the disk. It is one in-RAM region on one device, so the
/// value only has to be stable, not unique; a recognisable constant is plenty.
const VOLUME_ID: u32 = 0x0CA7_D15C;

/// The 11-byte, space-padded FAT volume label a host shows for the disk.
const LABEL: [u8; 11] = *b"CATCARD VD ";

/// The Virtual Disk as a block device over its reserved PSRAM region.
///
/// Holds a [`PsramArea`] pinned to the disk region, which does the paced word-aligned
/// access; every sector operation is a bounds-checked read or write through it. Cheap to
/// construct — it is a handful of addresses and the bus's burst budget — so it is made
/// fresh for each use rather than kept resident.
pub struct Vdisk {
    area: PsramArea,
    sectors: u64,
}

impl Vdisk {
    /// The disk over this board's reserved region, or `None` on a board without PSRAM.
    pub fn take() -> Option<Self> {
        let p = catcard_board::BOARD.psram?;
        // SAFETY: reading RCC to learn the CPU clock the burst pacing is computed against.
        // The clocks are up — boot configured them long before any screen exists.
        let cpu_hz = unsafe { catcard_hal::clock::hclk_hz() };
        // SAFETY: `vdisk_base()`/`vdisk_len()` are the fixed region the board table carves
        // below the recovery header; `usable()` stops short of it so no `psram::take`
        // lease overlaps it, and it never reaches the header's bytes. Foreground code is
        // its only user, one screen at a time, so nothing else is accessing it. The
        // region is passed as its own `header_at`, so a mistaken `publish`/`retract`
        // (which this module never calls) could not reach the bootloader's marker.
        let area = unsafe {
            PsramArea::claim_region(
                p.vdisk_base(),
                p.vdisk_len(),
                0,
                p.vdisk_base(),
                p.ospi_hz,
                p.mmap_timeout_clocks,
                cpu_hz,
            )
        };
        Some(Self {
            area,
            sectors: (p.vdisk_len() / BLOCK_LEN as u32) as u64,
        })
    }

    /// Byte offset of `lba`, or `OutOfRange` if the sector is past the region.
    fn offset(&self, lba: u64, sectors: usize) -> Result<u32, OutOfRange> {
        let end = lba.checked_add(sectors as u64).ok_or(OutOfRange)?;
        if end > self.sectors {
            return Err(OutOfRange);
        }
        u32::try_from(lba * BLOCK_LEN as u64).map_err(|_| OutOfRange)
    }
}

impl SectorDriver for Vdisk {
    type Error = OutOfRange;

    fn sector_size(&self) -> u32 {
        BLOCK_LEN as u32
    }

    fn sector_count(&self) -> u64 {
        self.sectors
    }

    fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), OutOfRange> {
        let off = self.offset(lba, buf.len() / BLOCK_LEN)?;
        self.area.read(off, buf)
    }

    fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), OutOfRange> {
        let off = self.offset(lba, buf.len() / BLOCK_LEN)?;
        self.area.write(off, buf)
    }
}

impl crate::msc_drive::BlockDev for Vdisk {
    fn read_block(&mut self, lba: u32, out: &mut [u8; BLOCK_LEN]) -> Result<(), ()> {
        self.read_sectors(lba as u64, out).map_err(|_| ())
    }

    fn write_block(&mut self, lba: u32, data: &[u8; BLOCK_LEN]) -> Result<(), ()> {
        self.write_sectors(lba as u64, data).map_err(|_| ())
    }

    fn block_count(&self) -> u32 {
        self.sectors as u32
    }
}

/// Mount the disk's filesystem, FAT or exFAT, for browsing.
///
/// A fresh [`Vdisk`] per attempt, because a failed FAT probe leaves the driver's cursor
/// where the exFAT attempt does not want it — the same contract [`AnyVolume::mount_with`]
/// is built for on a card.
pub fn mount() -> Result<AnyVolume<Vdisk, 512>, &'static str> {
    AnyVolume::mount_with(|| Vdisk::take().ok_or(())).map_err(|e| match e {
        catcard_sd::MountError::Device => "no PSRAM for a disk",
        catcard_sd::MountError::NoFilesystem => "disk holds no filesystem",
    })
}

/// Make sure the region holds a filesystem before anything reads it.
///
/// If it already mounts, it is left exactly as it is — the disk persists across menu
/// navigation, so a file staged earlier is still there. Only an *uninitialised* region
/// (a fresh boot, or one an upgrade overwrote) is formatted, and then silently: there is
/// nothing on it to warn about losing. A region that mounts is never reformatted here.
pub fn ensure_formatted() -> Result<(), &'static str> {
    if mount().is_ok() {
        return Ok(());
    }
    format()
}

/// Lay down an empty FAT volume over the whole region (a superfloppy: the filesystem at
/// sector 0, no partition table, using the region end to end).
///
/// **Erases the disk.** Callers that reach a formatted disk must warn first; the only
/// caller here is [`ensure_formatted`], which formats only what held no filesystem.
pub fn format() -> Result<(), &'static str> {
    let dev = Vdisk::take().ok_or("no PSRAM for a disk")?;
    let opts = fat::FormatOpts {
        volume_id: VOLUME_ID,
        label: LABEL,
        ..Default::default()
    };
    // `format` writes the boot sector, both FATs and the root directory and mounts the
    // result; dropping the volume is enough since our sector writes land straight in
    // memory-mapped PSRAM with no cache of their own.
    fat::Volume::<Vdisk, 512>::format(dev, &opts).map_err(|e| match e {
        fat::Error::Unsupported(_) => "region too small for a FAT volume",
        _ => "could not format the disk",
    })?;
    Ok(())
}
