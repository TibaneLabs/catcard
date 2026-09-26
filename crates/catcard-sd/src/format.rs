//! Formatting a card the way the SD standard says to.
//!
//! One MBR partition filling the card, holding the filesystem the SD Physical Layer
//! specification assigns to the card's capacity tier:
//!
//! | tier | capacity | filesystem |
//! |------|----------|------------|
//! | SDSC | ≤ 2 GB   | FAT16      |
//! | SDHC | ≤ 32 GB  | FAT32      |
//! | SDXC | ≤ 2 TB   | exFAT      |
//!
//! (SDUC, above 2 TB, is also exFAT but must use a GPT rather than an MBR — and a `u32`
//! [`Card::blocks`](crate::Card) cannot even count that many sectors, so it is out of
//! reach here until the capacity type is widened and SDUC is supported. Every card this
//! stack can address fits an MBR.)
//!
//! The partition table is written by hand — fstool's `Mbr`/`Gpt` writers need an allocator
//! — but the filesystem itself is laid down by fstool's no-allocator
//! [`Volume::format_at`](fstool::fs::fat::Volume::format_at), which writes only the
//! metadata (a few thousand sectors at most) and never touches the data region, so a
//! format is quick and does not wipe the whole card.

use fstool::fs::fat::SectorDriver;
use fstool::fs::{exfat, fat};

use crate::BLOCK_LEN;

/// One gibibyte, for the capacity-tier thresholds.
const GIB: u64 = 1024 * 1024 * 1024;

/// Where the single partition starts: 1 MiB in, the alignment every modern formatter uses.
/// Leaves room for the MBR and aligns the filesystem to a large flash boundary.
const PART_START: u64 = 2048;

/// Smallest partition worth formatting, so a comically small or misread card is refused
/// rather than handed to a formatter that would fail deep inside.
const MIN_PART_SECTORS: u64 = 128;

/// The filesystem the SD specification assigns to a capacity tier.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum FsKind {
    /// SDSC, up to 2 GB.
    Fat16,
    /// SDHC, up to 32 GB.
    Fat32,
    /// SDXC (and SDUC), above 32 GB.
    Exfat,
}

impl FsKind {
    /// A short name for a screen.
    pub fn name(self) -> &'static str {
        match self {
            FsKind::Fat16 => "FAT16",
            FsKind::Fat32 => "FAT32",
            FsKind::Exfat => "exFAT",
        }
    }

    /// The MBR partition-type byte the SD standard uses for this filesystem.
    /// `0x06` FAT16, `0x0C` FAT32 (LBA), `0x07` exFAT/IFS. Source: SD Physical Layer spec
    /// §10 partition types; matches what the SD Association's own formatter writes.
    fn mbr_type(self) -> u8 {
        match self {
            FsKind::Fat16 => 0x06,
            FsKind::Fat32 => 0x0C,
            FsKind::Exfat => 0x07,
        }
    }
}

/// Choose the filesystem for a card of `blocks` 512-byte sectors, by the SD capacity tiers.
pub fn standard_fs(blocks: u64) -> FsKind {
    let bytes = blocks.saturating_mul(BLOCK_LEN as u64);
    if bytes <= 2 * GIB {
        FsKind::Fat16
    } else if bytes <= 32 * GIB {
        FsKind::Fat32
    } else {
        FsKind::Exfat
    }
}

/// Why a format did not complete. `E` is the driver's own error type
/// ([`crate::Error`] for a real card).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum FormatError<E> {
    /// The card is too small to hold a partition worth making.
    TooSmall,
    /// A sector read or write to the card failed.
    Io(E),
    /// The filesystem layout could not be produced for this size (fstool refused it).
    Layout(&'static str),
}

/// Format a card to the SD standard: rewrite the MBR with one partition spanning the card,
/// then lay down the tier's filesystem in it. Consumes the driver; on success returns which
/// filesystem was written.
///
/// `volume_id` is the volume serial number, which should differ between cards — pass a
/// value from a random source. `label` is an optional volume label (FAT: first 11 bytes,
/// space-padded; exFAT: up to 11 characters); pass `""` for none.
///
/// Generic over the [`SectorDriver`] so it drives a real card ([`Sectors`](crate::Sectors))
/// in the firmware and a memory-backed device under test with the same code.
pub fn format<D: SectorDriver>(
    mut dev: D,
    volume_id: u32,
    label: &str,
) -> Result<FsKind, FormatError<D::Error>> {
    let blocks = dev.sector_count();
    let fs = standard_fs(blocks);

    if blocks <= PART_START + MIN_PART_SECTORS {
        return Err(FormatError::TooSmall);
    }
    let part_sectors = blocks - PART_START;

    // The partition table first: a fresh MBR with a single entry over the whole card. If
    // the filesystem format below fails, the card is left with a valid table pointing at a
    // partition that is not yet a filesystem, which a host reports as unformatted -- a
    // clearer state than a half-rewritten old table.
    write_mbr(&mut dev, PART_START, part_sectors, fs.mbr_type()).map_err(FormatError::Io)?;

    // Then the filesystem, inside the partition's extent.
    match fs {
        FsKind::Fat16 => format_fat(dev, fat::FatKind::Fat16, part_sectors, volume_id, label),
        FsKind::Fat32 => format_fat(dev, fat::FatKind::Fat32, part_sectors, volume_id, label),
        FsKind::Exfat => format_exfat(dev, part_sectors, volume_id, label),
    }?;
    Ok(fs)
}

/// FAT16/FAT32 in the partition. The kind is forced (not chosen by size) so the SD tier
/// decides it: fstool on its own would pick FAT32 from 512 MiB up, but the standard wants
/// FAT16 for an SDSC card.
fn format_fat<D: SectorDriver>(
    dev: D,
    kind: fat::FatKind,
    part_sectors: u64,
    volume_id: u32,
    label: &str,
) -> Result<(), FormatError<D::Error>> {
    let mut opts = fat::FormatOpts {
        kind: Some(kind),
        volume_id,
        ..Default::default()
    };
    fat_label(label, &mut opts.label);
    fat::Volume::<D, BLOCK_LEN>::format_at(dev, PART_START, part_sectors, &opts)
        .map(drop)
        .map_err(fat_err)
}

/// exFAT in the partition, with fstool's default (size-derived) cluster size.
fn format_exfat<D: SectorDriver>(
    dev: D,
    part_sectors: u64,
    volume_id: u32,
    label: &str,
) -> Result<(), FormatError<D::Error>> {
    let opts = exfat::VolumeFormatOpts {
        cluster_size: None,
        volume_serial: volume_id,
        label,
    };
    exfat::Volume::<D, BLOCK_LEN>::format_at(dev, PART_START, part_sectors, &opts)
        .map(drop)
        .map_err(exfat_err)
}

/// An 11-byte, space-padded FAT label, `NO NAME` when empty. Only ASCII is copied; other
/// bytes are dropped rather than mangled.
fn fat_label(label: &str, out: &mut [u8; 11]) {
    if label.is_empty() {
        return;
    }
    *out = *b"           ";
    let mut i = 0;
    for b in label.bytes() {
        if i == out.len() {
            break;
        }
        if b.is_ascii() && b != b' ' {
            out[i] = b.to_ascii_uppercase();
            i += 1;
        }
    }
    if i == 0 {
        *out = *b"NO NAME    ";
    }
}

fn fat_err<E>(e: fat::Error<E>) -> FormatError<E> {
    match e {
        fat::Error::Io(io) => FormatError::Io(io),
        fat::Error::Unsupported(why) => FormatError::Layout(why),
        _ => FormatError::Layout("FAT layout rejected"),
    }
}

fn exfat_err<E>(e: exfat::Error<E>) -> FormatError<E> {
    match e {
        exfat::Error::Io(io) => FormatError::Io(io),
        exfat::Error::Unsupported(why) => FormatError::Layout(why),
        _ => FormatError::Layout("exFAT layout rejected"),
    }
}

/// Write a fresh MBR at LBA 0: one primary partition, `type_byte`, from `start` for
/// `sectors`, the other three slots empty, and the `55 AA` boot signature. The 446-byte
/// bootstrap area is left zero.
fn write_mbr<D: SectorDriver>(
    dev: &mut D,
    start: u64,
    sectors: u64,
    type_byte: u8,
) -> Result<(), D::Error> {
    let mut mbr = [0u8; BLOCK_LEN];

    // Clamp to the 32-bit fields an MBR entry carries. A card this stack can address
    // (`u32` blocks) always fits, but the arithmetic is written not to wrap if it grows.
    let start32 = u32::try_from(start).unwrap_or(u32::MAX);
    let count32 = u32::try_from(sectors.min(u32::MAX as u64)).unwrap_or(u32::MAX);
    let end_lba = start.saturating_add(sectors).saturating_sub(1);

    let e = &mut mbr[446..462];
    e[0] = 0x00; // not bootable
    chs(start, &mut e[1..4]); // CHS start (cosmetic for LBA partitions)
    e[4] = type_byte;
    chs(end_lba, &mut e[5..8]); // CHS end
    e[8..12].copy_from_slice(&start32.to_le_bytes());
    e[12..16].copy_from_slice(&count32.to_le_bytes());

    mbr[510] = 0x55;
    mbr[511] = 0xAA;

    dev.write_sectors(0, &mbr)?;
    dev.flush()
}

/// Encode an LBA as a 3-byte CHS tuple with the classic 255-head, 63-sector geometry,
/// clamped to the maximum (`FE FF FF`) once the cylinder runs past 1023. Hosts read the
/// partition by its LBA fields; CHS is written only so old tools see something sane.
fn chs(lba: u64, out: &mut [u8]) {
    const HEADS: u64 = 255;
    const SPT: u64 = 63;
    let c = lba / (HEADS * SPT);
    if c > 1023 {
        out.copy_from_slice(&[0xFE, 0xFF, 0xFF]);
        return;
    }
    let h = (lba / SPT) % HEADS;
    let s = (lba % SPT) + 1;
    out[0] = h as u8;
    out[1] = (s as u8 & 0x3F) | (((c >> 2) as u8) & 0xC0);
    out[2] = (c & 0xFF) as u8;
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::AnyVolume;
    use std::collections::BTreeMap;
    use std::rc::Rc;
    use std::vec;
    use std::vec::Vec;

    /// A sparse, shared, in-memory block device: only written sectors take memory, so a
    /// device can claim a large `sector_count` without allocating it. Cloning shares the
    /// same store, so the bytes a format wrote survive the driver being consumed.
    #[derive(Clone)]
    struct Mem {
        store: Rc<std::cell::RefCell<BTreeMap<u64, [u8; BLOCK_LEN]>>>,
        sectors: u64,
    }

    impl Mem {
        fn new(sectors: u64) -> Self {
            Self {
                store: Rc::new(std::cell::RefCell::new(BTreeMap::new())),
                sectors,
            }
        }
        fn sector(&self, lba: u64) -> [u8; BLOCK_LEN] {
            self.store
                .borrow()
                .get(&lba)
                .copied()
                .unwrap_or([0; BLOCK_LEN])
        }
    }

    impl SectorDriver for Mem {
        type Error = ();
        fn sector_size(&self) -> u32 {
            BLOCK_LEN as u32
        }
        fn sector_count(&self) -> u64 {
            self.sectors
        }
        fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), ()> {
            let store = self.store.borrow();
            for (i, chunk) in buf.chunks_mut(BLOCK_LEN).enumerate() {
                let s = store
                    .get(&(lba + i as u64))
                    .copied()
                    .unwrap_or([0; BLOCK_LEN]);
                chunk.copy_from_slice(&s[..chunk.len()]);
            }
            Ok(())
        }
        fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), ()> {
            let mut store = self.store.borrow_mut();
            for (i, chunk) in buf.chunks(BLOCK_LEN).enumerate() {
                let mut s = [0u8; BLOCK_LEN];
                s[..chunk.len()].copy_from_slice(chunk);
                store.insert(lba + i as u64, s);
            }
            Ok(())
        }
    }

    #[test]
    fn the_capacity_tiers_follow_the_sd_standard() {
        let blocks = |gib: u64| gib * GIB / BLOCK_LEN as u64;
        // Boundaries: <=2GiB FAT16, <=32GiB FAT32, above exFAT.
        assert_eq!(standard_fs(blocks(1)), FsKind::Fat16);
        assert_eq!(standard_fs(blocks(2)), FsKind::Fat16);
        assert_eq!(standard_fs(blocks(2) + 1), FsKind::Fat32);
        assert_eq!(standard_fs(blocks(32)), FsKind::Fat32);
        assert_eq!(standard_fs(blocks(32) + 1), FsKind::Exfat);
        assert_eq!(standard_fs(blocks(128)), FsKind::Exfat);
    }

    #[test]
    fn a_card_too_small_to_partition_is_refused() {
        let mem = Mem::new(PART_START + MIN_PART_SECTORS);
        assert_eq!(format(mem, 1, ""), Err(FormatError::TooSmall));
    }

    /// Format a device of `sectors` blocks, check the MBR entry, then mount the result back
    /// through the same partition table to prove it is a real, findable filesystem.
    fn round_trip(sectors: u64, want: FsKind) {
        let mem = Mem::new(sectors);
        let fs = format(mem.clone(), 0xCA7CA7D, "CATCARD").expect("format failed");
        assert_eq!(fs, want, "wrong filesystem for {sectors} sectors");

        // The MBR: signature, one entry, correct type/start/size, LBA fields.
        let mbr = mem.sector(0);
        assert_eq!(&mbr[510..512], &[0x55, 0xAA], "no MBR signature");
        assert_eq!(mbr[446], 0x00, "partition marked bootable");
        assert_eq!(mbr[446 + 4], want.mbr_type(), "wrong partition type byte");
        let start = u32::from_le_bytes(mbr[454..458].try_into().unwrap());
        let count = u32::from_le_bytes(mbr[458..462].try_into().unwrap());
        assert_eq!(start as u64, PART_START);
        assert_eq!(count as u64, sectors - PART_START);
        // The other three slots are empty.
        assert!(mbr[462..510].iter().all(|&b| b == 0), "extra partitions");

        // Mounting reads that MBR to find the partition, then opens the filesystem in it --
        // so a successful mount proves both halves agree.
        let mut vol =
            AnyVolume::<Mem, 512>::mount_with(|| Ok(mem.clone())).expect("could not remount");
        let is_exfat = matches!(vol, AnyVolume::Exfat(_));
        assert_eq!(is_exfat, want == FsKind::Exfat, "mounted the wrong driver");

        // A freshly formatted volume has no files (a volume-label entry is not one).
        let mut names: Vec<std::string::String> = vec![];
        vol.enumerate("", |name, _is_dir, _len| names.push(name.into()))
            .expect("enumerate failed");
        assert!(names.is_empty(), "fresh volume had entries: {names:?}");
    }

    #[test]
    fn formats_fat16_for_an_sdsc_card() {
        // 64 MiB.
        round_trip(64 * 1024 * 1024 / BLOCK_LEN as u64, FsKind::Fat16);
    }

    #[test]
    fn formats_fat32_for_an_sdhc_card() {
        // 4 GiB.
        round_trip(4 * GIB / BLOCK_LEN as u64, FsKind::Fat32);
    }

    #[test]
    fn formats_exfat_for_an_sdxc_card() {
        // 128 GiB.
        round_trip(128 * GIB / BLOCK_LEN as u64, FsKind::Exfat);
    }

    /// The Virtual Disk's format path: an empty FAT volume laid down over the whole
    /// device at sector 0 (a superfloppy, no partition table), then mounted back through
    /// [`AnyVolume`] and found empty. Run at the firmware's reserved size —
    /// `catcard_board::Psram::VDISK_RESERVE`, 2 MiB — so a size that stopped producing a
    /// mountable FAT would fail here rather than only on hardware. This mirrors
    /// `catcard_fw::vdisk`, which formats with `fat::Volume::format` and mounts with
    /// `AnyVolume::mount_with`.
    #[test]
    fn a_two_mib_superfloppy_formats_and_mounts_empty() {
        const VDISK_BYTES: u64 = 2 * 1024 * 1024;
        let mem = Mem::new(VDISK_BYTES / BLOCK_LEN as u64);
        let opts = fat::FormatOpts {
            volume_id: 0x0CA7_D15C,
            label: *b"CATCARD VD ",
            ..Default::default()
        };
        fat::Volume::<Mem, BLOCK_LEN>::format(mem.clone(), &opts).expect("format vdisk");

        // Sector 0 is a boot sector (no MBR), so mount_auto mounts the whole device.
        let mut vol =
            AnyVolume::<Mem, 512>::mount_with(|| Ok(mem.clone())).expect("could not mount vdisk");
        assert!(matches!(vol, AnyVolume::Fat(_)), "vdisk should be FAT");
        let mut names: Vec<std::string::String> = vec![];
        vol.enumerate("", |name, _is_dir, _len| names.push(name.into()))
            .expect("enumerate failed");
        assert!(names.is_empty(), "fresh vdisk had entries: {names:?}");
    }

    #[test]
    fn chs_clamps_past_the_cylinder_limit() {
        // A start inside the CHS range encodes a real tuple.
        let mut small = [0u8; 3];
        chs(2048, &mut small);
        assert_ne!(
            small,
            [0xFE, 0xFF, 0xFF],
            "small LBA should encode a real CHS"
        );
        // Well past 1023 cylinders (255*63*1024 sectors) clamps to the max marker.
        let mut big = [0u8; 3];
        chs(255 * 63 * 2000, &mut big);
        assert_eq!(big, [0xFE, 0xFF, 0xFF]);
    }
}
