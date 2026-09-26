//! A fake card, and the sequence run against it.
//!
//! The point of the `Transport` split is this file: card bring-up is a conversation with
//! an ordering that matters, and every step of it can be checked here without silicon.

use super::*;

/// A card that answers the way the spec says, and records what it was asked.
struct FakeCard {
    log: heapless_vec::Vec,
    /// Times ACMD41 should claim to still be busy before reporting done.
    busy_for: u32,
    high_capacity: bool,
    /// CSD to hand back, most significant word first.
    csd: [u32; 4],
    present: bool,
    accept_4bit: bool,
    selected: bool,
    /// Argument of the last CMD17.
    last_read_arg: u32,
    /// Whether the data path was armed before the read command went out.
    armed_before_cmd: bool,
}

/// A tiny growable vector, so the test file needs no dependency.
mod heapless_vec {
    pub struct Vec {
        items: [u8; 64],
        len: usize,
    }
    impl Default for Vec {
        fn default() -> Self {
            Self {
                items: [0; 64],
                len: 0,
            }
        }
    }
    impl Vec {
        pub fn push(&mut self, v: u8) {
            if self.len < self.items.len() {
                self.items[self.len] = v;
                self.len += 1;
            }
        }
        pub fn as_slice(&self) -> &[u8] {
            &self.items[..self.len]
        }
    }
}

impl Default for FakeCard {
    fn default() -> Self {
        Self {
            log: heapless_vec::Vec::default(),
            busy_for: 0,
            high_capacity: true,
            // CSD v2 with C_SIZE = 0x3B37 -> (15159 + 1) * 1024 blocks = ~7.4 GiB.
            csd: [1 << 30, 0x3B37 >> 16, (0x3B37 & 0xFFFF) << 16, 0],
            present: true,
            accept_4bit: true,
            selected: false,
            last_read_arg: 0,
            armed_before_cmd: false,
        }
    }
}

impl Transport for FakeCard {
    fn command(&mut self, cmd: u8, arg: u32, _resp: Response) -> Result<[u32; 4], Error> {
        self.log.push(cmd);
        match cmd {
            CMD_GO_IDLE => Ok([0; 4]),
            CMD_SEND_IF_COND => Ok([arg & 0xFFF, 0, 0, 0]),
            CMD_APP => Ok([0; 4]),
            ACMD_OP_COND => {
                if self.busy_for > 0 {
                    self.busy_for -= 1;
                    return Ok([0, 0, 0, 0]);
                }
                let ccs = if self.high_capacity { OCR_CCS } else { 0 };
                Ok([OCR_BUSY_DONE | ccs, 0, 0, 0])
            }
            // A real-shaped CID so bring-up has something to keep: SanDisk "SC32G",
            // PSN 0x1234_5678. See the CID decode's known-answer test.
            CMD_ALL_SEND_CID => Ok([0x0353_4453, 0x4333_3247, 0x3012_3456, 0x7801_2901]),
            CMD_SEND_RCA => Ok([0x1234 << 16, 0, 0, 0]),
            CMD_SEND_CSD => Ok(self.csd),
            CMD_SELECT => {
                self.selected = true;
                Ok([0; 4])
            }
            CMD_READ_SINGLE => {
                if !self.selected {
                    return Err(Error::BadResponse { cmd });
                }
                assert!(
                    self.armed_before_cmd,
                    "CMD17 went out before the data path was armed"
                );
                self.last_read_arg = arg;
                Ok([0; 4])
            }
            _ => Err(Error::BadResponse { cmd }),
        }
    }

    fn read_data(&mut self, out: &mut [u8; BLOCK_LEN]) -> Result<(), Error> {
        out.fill(0x5A);
        Ok(())
    }

    fn set_bus_width_4(&mut self) -> Result<(), Error> {
        if self.accept_4bit {
            Ok(())
        } else {
            Err(Error::BadResponse { cmd: 6 })
        }
    }

    fn set_fast_clock(&mut self) {}

    fn card_present(&self) -> bool {
        self.present
    }

    fn arm_block_read(&mut self) {
        self.armed_before_cmd = true;
    }
}

#[test]
fn a_healthy_card_comes_up_and_reports_its_size() {
    let mut c = FakeCard::default();
    let card = init(&mut c).expect("init");
    assert_eq!(card.rca, 0x1234);
    assert_eq!(card.addressing, Addressing::BlockAddressed);
    assert!(card.wide);
    assert_eq!(card.blocks, 15160 * 1024);
    assert_eq!(card.mib(), 7580);
}

/// The order is not decoration: a card that is not selected cannot be read, and one
/// asked for its CSD before it has an address answers for a different card.
#[test]
fn the_commands_go_out_in_the_order_the_spec_requires() {
    let mut c = FakeCard::default();
    init(&mut c).expect("init");
    let seen = c.log.as_slice();
    let expected = [
        CMD_GO_IDLE,
        CMD_SEND_IF_COND,
        CMD_APP,
        ACMD_OP_COND,
        CMD_ALL_SEND_CID,
        CMD_SEND_RCA,
        CMD_SEND_CSD,
        CMD_SELECT,
    ];
    assert_eq!(seen, &expected, "bring-up order changed");
}

/// Bring-up keeps the CID from CMD2 rather than discarding it, and the serial accessor
/// reads the PSN back out of it — the field a later feature keys settings by, so a
/// regression here must fail a test rather than a device.
#[test]
fn init_retains_the_cid_and_exposes_the_serial() {
    let mut c = FakeCard::default();
    let card = init(&mut c).expect("init");
    assert_eq!(
        card.cid,
        [0x0353_4453, 0x4333_3247, 0x3012_3456, 0x7801_2901]
    );
    assert_eq!(card.serial(), 0x1234_5678);
    assert_eq!(&card.cid().pnm(), b"SC32G");
}

/// Every ACMD must be preceded by CMD55. One that is not is an ordinary command with
/// the same number, which on a real card means something entirely different.
#[test]
fn every_acmd_is_preceded_by_cmd55() {
    let mut c = FakeCard {
        busy_for: 3,
        ..Default::default()
    };
    init(&mut c).expect("init");
    let seen = c.log.as_slice();
    for (i, cmd) in seen.iter().enumerate() {
        if *cmd == ACMD_OP_COND {
            assert_eq!(
                seen[i - 1],
                CMD_APP,
                "ACMD41 at {i} was not prefixed by CMD55"
            );
        }
    }
}

#[test]
fn a_card_that_never_finishes_powering_up_is_an_error_not_a_hang() {
    let mut c = FakeCard {
        busy_for: u32::MAX,
        ..Default::default()
    };
    assert_eq!(init(&mut c), Err(Error::InitTimeout));
}

#[test]
fn an_empty_slot_is_reported_before_anything_is_sent() {
    let mut c = FakeCard {
        present: false,
        ..Default::default()
    };
    assert_eq!(init(&mut c), Err(Error::NoCard));
    assert!(c.log.as_slice().is_empty(), "talked to a slot with no card");
}

/// A card that refuses four-bit mode still works on one line. Refusing to come up at all
/// would trade a working card for a faster one.
#[test]
fn a_card_that_refuses_four_bit_mode_still_initialises() {
    let mut c = FakeCard {
        accept_4bit: false,
        ..Default::default()
    };
    let card = init(&mut c).expect("init");
    assert!(!card.wide);
}

/// The unit of a read argument depends on the card. Getting this wrong reads a location
/// 512 times off and *succeeds*, returning the wrong bytes with no error anywhere.
#[test]
fn read_arguments_are_blocks_on_hc_cards_and_bytes_on_standard_ones() {
    let mut c = FakeCard::default();
    let card = init(&mut c).expect("init");
    let mut buf = [0u8; BLOCK_LEN];
    read_block(&mut c, &card, 9, &mut buf).expect("read");
    assert_eq!(c.last_read_arg, 9, "high-capacity cards address by block");

    let mut c = FakeCard {
        high_capacity: false,
        // CSD v1: C_SIZE = 3751, C_SIZE_MULT = 5, READ_BL_LEN = 9 -> 1 GiB-ish.
        csd: [
            0,
            (9 << 16) | (3751 >> 2),
            ((3751 & 0x3) << 30) | (5 << 15),
            0,
        ],
        ..Default::default()
    };
    let card = init(&mut c).expect("init");
    assert_eq!(card.addressing, Addressing::ByteAddressed);
    read_block(&mut c, &card, 9, &mut buf).expect("read");
    assert_eq!(c.last_read_arg, 9 * 512, "standard cards address by byte");
}

/// The v1 formula has a factor of four in it that is easy to lose.
#[test]
fn csd_v1_capacity_uses_the_c_size_mult_exponent() {
    // C_SIZE = 3751, C_SIZE_MULT = 5, READ_BL_LEN = 9.
    // blocks = (3751 + 1) * 2^(5 + 2) * 2^9 / 512 = 3752 * 128 = 480256.
    let csd = [
        0,
        (9 << 16) | (3751 >> 2),
        ((3751 & 0x3) << 30) | (5 << 15),
        0,
    ];
    assert_eq!(capacity_blocks(&csd), Ok(480_256));
}

#[test]
fn a_csd_with_an_unknown_version_is_refused_rather_than_guessed_at() {
    assert_eq!(capacity_blocks(&[2 << 30, 0, 0, 0]), Err(Error::BadCsd));
    assert_eq!(capacity_blocks(&[3 << 30, 0, 0, 0]), Err(Error::BadCsd));
}

/// Reading past the end is caught here rather than being sent to the card, which would
/// answer with an out-of-range error at best and wrap at worst.
#[test]
fn reading_past_the_end_is_refused() {
    let mut c = FakeCard::default();
    let card = init(&mut c).expect("init");
    let mut buf = [0u8; BLOCK_LEN];
    assert_eq!(
        read_block(&mut c, &card, card.blocks, &mut buf),
        Err(Error::DataError { block: card.blocks })
    );
}

// ---------------------------------------------------------------------------
// FAT, read back through the card layer
// ---------------------------------------------------------------------------

mod fat_round_trip {
    use super::super::*;
    extern crate alloc;
    use alloc::vec;
    use alloc::vec::Vec;
    use fstool::block::{BlockDevice, MemoryBackend};
    use fstool::fs::fat::{Fat32, FatFormatOpts, FatKind};

    /// 64 MiB, the size `tools/emu/mksd.sh` makes, so FAT32 is a legal choice for it.
    const SECTORS: u32 = 131_072;

    /// A RAM disk the heapless driver can write, for putting a file on a fresh volume.
    struct RamDisk(Vec<u8>);

    impl fat::SectorDriver for RamDisk {
        type Error = ();
        fn sector_size(&self) -> u32 {
            512
        }
        fn sector_count(&self) -> u64 {
            (self.0.len() / 512) as u64
        }
        fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), ()> {
            let at = lba as usize * 512;
            buf.copy_from_slice(&self.0[at..at + buf.len()]);
            Ok(())
        }
        fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), ()> {
            let at = lba as usize * 512;
            self.0[at..at + buf.len()].copy_from_slice(buf);
            Ok(())
        }
    }

    /// A card whose blocks are an image, answering only what a read needs.
    struct ImageCard {
        image: Vec<u8>,
        next: u32,
        reads: u32,
    }

    impl Transport for ImageCard {
        fn command(&mut self, cmd: u8, arg: u32, _: Response) -> Result<[u32; 4], Error> {
            if cmd == CMD_READ_SINGLE {
                self.next = arg; // block-addressed card, so this is a block number
            }
            Ok([0; 4])
        }
        fn read_data(&mut self, out: &mut [u8; BLOCK_LEN]) -> Result<(), Error> {
            let at = self.next as usize * BLOCK_LEN;
            out.copy_from_slice(&self.image[at..at + BLOCK_LEN]);
            self.reads += 1;
            Ok(())
        }
        fn set_bus_width_4(&mut self) -> Result<(), Error> {
            Ok(())
        }
        fn set_fast_clock(&mut self) {}
        fn card_present(&self) -> bool {
            true
        }
    }

    /// A payload long enough to span several clusters, and different in every sector,
    /// so a read that returns the wrong sector -- or the first one twice -- cannot pass.
    fn payload() -> Vec<u8> {
        (0..10_000u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect()
    }

    fn card_with(name: &str, data: &[u8]) -> ImageCard {
        let mut mem = MemoryBackend::new(SECTORS as u64 * 512);
        let opts = FatFormatOpts {
            kind: FatKind::Fat32,
            total_sectors: SECTORS,
            ..Default::default()
        };
        Fat32::format(&mut mem, &opts).expect("format");
        let mut image = vec![0u8; SECTORS as usize * 512];
        mem.read_at(0, &mut image).expect("read image back");

        let mut vol = fat::Volume::<_, 512>::mount(RamDisk(image)).expect("mount ram disk");
        let mut f = vol.create_file(name).expect("create");
        f.write_all(&mut vol, data).expect("write");
        f.flush(&mut vol).expect("flush file");
        vol.flush().expect("flush volume");
        let image = vol.unmount().expect("unmount").0;

        ImageCard {
            image,
            next: 0,
            reads: 0,
        }
    }

    fn mounted(card: ImageCard) -> fat::Volume<Sectors<ImageCard>, 512> {
        let c = Card {
            rca: 1,
            addressing: Addressing::BlockAddressed,
            blocks: SECTORS,
            wide: true,
            cid: [0; 4],
        };
        fat::Volume::<_, 512>::mount_auto(Sectors::new(card, c)).expect("mount through card")
    }

    /// The whole point: a file written by an independent FAT implementation comes back
    /// byte for byte through the card layer and the heapless driver.
    #[test]
    fn a_file_on_a_fat32_card_reads_back_exactly() {
        let data = payload();
        let mut vol = mounted(card_with("/CATCARD.DFU", &data));

        let mut f = vol.open_file("/CATCARD.DFU").expect("open");
        assert_eq!(f.len() as usize, data.len());

        let mut got = Vec::new();
        let mut buf = [0u8; 700]; // deliberately not a sector multiple
        loop {
            let n = f.read(&mut vol, &mut buf).expect("read");
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        assert!(
            got == data,
            "file content differs after reading through the card"
        );
    }

    /// The adapter's own loop, exercised directly.
    ///
    /// The FAT driver only ever asks for one sector at a time, so the round-trip test
    /// above never runs this path -- breaking the per-sector offset left every test
    /// passing. `SectorIo` permits any whole multiple of a sector, so the boundary has
    /// to be tested at the boundary.
    #[test]
    fn a_multi_sector_read_returns_consecutive_sectors() {
        use fat::SectorDriver as _;

        let card = card_with("/CATCARD.DFU", &payload());
        let image = card.image.clone();
        let mut dev = Sectors::new(
            card,
            Card {
                rca: 1,
                addressing: Addressing::BlockAddressed,
                blocks: SECTORS,
                wide: true,
                cid: [0; 4],
            },
        );

        // Three sectors from somewhere with content, not from the zeroed tail.
        const LBA: u64 = 0;
        let mut got = [0u8; 3 * BLOCK_LEN];
        dev.read_sectors(LBA, &mut got).expect("multi-sector read");

        let at = LBA as usize * BLOCK_LEN;
        assert!(
            got[..] == image[at..at + got.len()],
            "a multi-sector read did not return consecutive sectors"
        );

        // And a request that is not a whole number of sectors is refused rather than
        // partly served.
        let mut odd = [0u8; BLOCK_LEN + 1];
        assert!(dev.read_sectors(0, &mut odd).is_err());
    }

    #[test]
    fn a_missing_file_is_an_error_not_an_empty_read() {
        let mut vol = mounted(card_with("/OTHER.BIN", b"x"));
        assert!(vol.open_file("/CATCARD.DFU").is_err());
    }

    /// Mounting and reading must never write. If the driver ever needs to, this layer
    /// answers `ReadOnly` and the mount fails loudly rather than half-working.
    #[test]
    fn reading_a_card_writes_nothing() {
        let data = payload();
        let card = card_with("/CATCARD.DFU", &data);
        let before = card.image.clone();
        let mut vol = mounted(card);
        let mut f = vol.open_file("/CATCARD.DFU").expect("open");
        let mut buf = [0u8; 4096];
        while f.read(&mut vol, &mut buf).expect("read") > 0 {}
        let after = vol.unmount().expect("unmount").into_inner();
        assert!(after.reads > 0, "nothing was read at all");
        assert!(after.image == before, "the card changed during a read");
    }

    /// CMD13's answer from a card that is done: transfer state, ready for data.
    const READY_IN_TRANSFER: u32 = (STATE_TRANSFER << STATUS_STATE_SHIFT) | STATUS_READY_FOR_DATA;

    /// A card that stays in the programming state for `busy` CMD13 polls after each write,
    /// and refuses any data command while it does -- which is what a real card does.
    struct SlowCard {
        busy: u32,
        left: u32,
        polls: u32,
        refused: u32,
    }

    impl Transport for SlowCard {
        fn command(&mut self, cmd: u8, _: u32, _: Response) -> Result<[u32; 4], Error> {
            match cmd {
                CMD_SEND_STATUS if self.left > 0 => {
                    self.left -= 1;
                    self.polls += 1;
                    // Programming state (7), not ready.
                    Ok([7 << STATUS_STATE_SHIFT, 0, 0, 0])
                }
                CMD_SEND_STATUS => {
                    self.polls += 1;
                    Ok([READY_IN_TRANSFER, 0, 0, 0])
                }
                CMD_READ_SINGLE | CMD_WRITE_SINGLE if self.left > 0 => {
                    self.refused += 1;
                    Err(Error::Timeout { cmd })
                }
                _ => Ok([0; 4]),
            }
        }
        fn read_data(&mut self, out: &mut [u8; BLOCK_LEN]) -> Result<(), Error> {
            out.fill(0);
            Ok(())
        }
        fn write_data(&mut self, _: &[u8; BLOCK_LEN]) -> Result<(), Error> {
            self.left = self.busy;
            Ok(())
        }
        fn set_bus_width_4(&mut self) -> Result<(), Error> {
            Ok(())
        }
        fn set_fast_clock(&mut self) {}
        fn card_present(&self) -> bool {
            true
        }
    }

    fn slow_card(busy: u32) -> SlowCard {
        SlowCard {
            busy,
            left: 0,
            polls: 0,
            refused: 0,
        }
    }

    const SMALL_CARD: Card = Card {
        rca: 1,
        addressing: Addressing::BlockAddressed,
        blocks: 64,
        wide: true,
        cid: [0; 4],
    };

    #[test]
    fn a_write_waits_for_the_card_to_finish_before_anything_else_goes_out() {
        let mut t = slow_card(30);
        let block = [0xA5u8; BLOCK_LEN];
        write_block(&mut t, &SMALL_CARD, 3, &block).unwrap();
        write_block(&mut t, &SMALL_CARD, 4, &block).unwrap();
        let mut out = [0u8; BLOCK_LEN];
        read_block(&mut t, &SMALL_CARD, 3, &mut out).unwrap();
        assert_eq!(
            t.refused, 0,
            "a data command went out while the card was busy"
        );
        assert_eq!(t.polls, 2 * 31);
    }

    #[test]
    fn a_card_that_never_finishes_is_busy_not_a_hang() {
        let mut t = slow_card(u32::MAX);
        let block = [0u8; BLOCK_LEN];
        assert_eq!(
            write_block(&mut t, &SMALL_CARD, 3, &block),
            Err(Error::Busy)
        );
        assert_eq!(t.polls, BUSY_POLLS);
    }

    /// A card whose blocks are an image that reads *and writes* back.
    ///
    /// The read-only `ImageCard` cannot exercise `write_sectors`, and the whole "save log
    /// to SD" path hangs off it. This is the write mirror: a `write_data` that lands in
    /// the image, so a file written through our `Sectors` adapter and the heapless driver
    /// can be read back out of the resulting bytes.
    struct RwImageCard {
        image: Vec<u8>,
        at: u32,
    }

    impl Transport for RwImageCard {
        fn command(&mut self, cmd: u8, arg: u32, _: Response) -> Result<[u32; 4], Error> {
            if cmd == CMD_READ_SINGLE || cmd == CMD_WRITE_SINGLE {
                self.at = arg; // block-addressed, so the argument is a block number
            }
            if cmd == CMD_SEND_STATUS {
                return Ok([READY_IN_TRANSFER, 0, 0, 0]);
            }
            Ok([0; 4])
        }
        fn read_data(&mut self, out: &mut [u8; BLOCK_LEN]) -> Result<(), Error> {
            let a = self.at as usize * BLOCK_LEN;
            out.copy_from_slice(&self.image[a..a + BLOCK_LEN]);
            Ok(())
        }
        fn write_data(&mut self, data: &[u8; BLOCK_LEN]) -> Result<(), Error> {
            let a = self.at as usize * BLOCK_LEN;
            self.image[a..a + BLOCK_LEN].copy_from_slice(data);
            Ok(())
        }
        fn set_bus_width_4(&mut self) -> Result<(), Error> {
            Ok(())
        }
        fn set_fast_clock(&mut self) {}
        fn card_present(&self) -> bool {
            true
        }
    }

    fn blank_fat32() -> Vec<u8> {
        let mut mem = MemoryBackend::new(SECTORS as u64 * 512);
        let opts = FatFormatOpts {
            kind: FatKind::Fat32,
            total_sectors: SECTORS,
            ..Default::default()
        };
        Fat32::format(&mut mem, &opts).expect("format");
        let mut image = vec![0u8; SECTORS as usize * 512];
        mem.read_at(0, &mut image).expect("read image back");
        image
    }

    fn rw_card(image: Vec<u8>) -> Sectors<RwImageCard> {
        Sectors::new(
            RwImageCard { image, at: 0 },
            Card {
                rca: 1,
                addressing: Addressing::BlockAddressed,
                blocks: SECTORS,
                wide: true,
                cid: [0; 4],
            },
        )
    }

    /// The point of the write path: a file written through `write_sectors` and the
    /// heapless driver reads back byte for byte after a fresh mount. This is what "save
    /// log to SD" does, minus the silicon the emulator does not model.
    #[test]
    fn a_file_written_through_the_card_layer_reads_back() {
        // A log-sized, every-byte-distinct payload, so a dropped or duplicated sector
        // cannot pass.
        let data: Vec<u8> = (0..5000u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 11) as u8)
            .collect();

        let image = {
            let mut vol = fat::Volume::<_, 512>::mount(rw_card(blank_fat32())).expect("mount");
            let mut f = vol.create_file("/CATCARD.LOG").expect("create");
            f.write_all(&mut vol, &data).expect("write");
            f.set_len(&mut vol, data.len() as u32).expect("set_len");
            f.flush(&mut vol).expect("flush file");
            vol.flush().expect("flush volume");
            vol.unmount().expect("unmount").into_inner().image
        };

        let mut vol = fat::Volume::<_, 512>::mount(rw_card(image)).expect("remount");
        let mut f = vol.open_file("/CATCARD.LOG").expect("open");
        assert_eq!(f.len() as usize, data.len(), "size wrong after write");

        let mut got = Vec::new();
        let mut buf = [0u8; 700];
        loop {
            let n = f.read(&mut vol, &mut buf).expect("read");
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        assert!(
            got == data,
            "file written through the card layer differs on read-back"
        );
    }

    /// Deleting through [`AnyVolume`] really removes the entry, and only that one.
    ///
    /// The browser re-lists the card after a delete, so what this has to be true of is the
    /// card and not the open volume: the file is gone after a fresh mount, and the file
    /// beside it is not. A delete that only cleared the in-memory directory would pass a
    /// same-mount check and lose nothing on the card.
    #[test]
    fn a_deleted_file_is_gone_after_a_remount_and_its_neighbour_is_not() {
        let image = {
            let mut vol = fat::Volume::<_, 512>::mount(rw_card(blank_fat32())).expect("mount");
            for name in ["/GONE.TXT", "/KEPT.TXT"] {
                let mut f = vol.create_file(name).expect("create");
                f.write_all(&mut vol, b"hello").expect("write");
                f.flush(&mut vol).expect("flush file");
            }
            vol.flush().expect("flush volume");
            vol.unmount().expect("unmount").into_inner().image
        };

        let image = {
            let mounted = fat::Volume::<_, 512>::mount(rw_card(image)).expect("remount");
            let mut vol = AnyVolume::Fat(mounted);
            vol.remove_file("/GONE.TXT").expect("remove");
            vol.flush().expect("flush volume");
            match vol {
                AnyVolume::Fat(v) => v.unmount().expect("unmount").into_inner().image,
                AnyVolume::Exfat(_) => unreachable!("mounted as FAT above"),
            }
        };

        let mut vol = fat::Volume::<_, 512>::mount(rw_card(image)).expect("remount");
        assert!(
            vol.open_file("/GONE.TXT").is_err(),
            "the deleted file is still on the card"
        );
        assert!(
            vol.open_file("/KEPT.TXT").is_ok(),
            "the file beside the deleted one went with it"
        );
    }

    /// A read-only transport (the default `write_data`) turns a write into `ReadOnly`
    /// rather than a silent success, so a mount that needs to write fails loudly.
    #[test]
    fn a_read_only_transport_refuses_writes() {
        use fat::SectorDriver as _;
        let mut dev = Sectors::new(
            ImageCard {
                image: vec![0u8; SECTORS as usize * 512],
                next: 0,
                reads: 0,
            },
            Card {
                rca: 1,
                addressing: Addressing::BlockAddressed,
                blocks: SECTORS,
                wide: true,
                cid: [0; 4],
            },
        );
        let block = [0u8; BLOCK_LEN];
        assert!(matches!(dev.write_sectors(0, &block), Err(Error::ReadOnly)));
    }
}

/// A big file on an exFAT card, read the way the firmware upgrade path reads one.
///
/// The card that showed this up is a 64 GB exFAT SDXC with **128 KB clusters**, holding a
/// 1.1 MB firmware image in a subdirectory. The image's header is in the first cluster, so
/// it parsed; the signature covers the whole image, and it did not verify -- which is what a
/// read that goes wrong after the first cluster looks like from the outside.
mod big_exfat {
    extern crate std;
    use std::vec;
    use std::vec::Vec;

    use super::*;
    use fstool::block::{BlockDevice, MemoryBackend};
    use fstool::fs::exfat::{Exfat, FormatOpts as ExfatFormatOpts};

    /// 1.1 MB, as the real image is: nine clusters of 128 KB.
    const FILE_LEN: usize = 1_155_072;
    /// 64 MB of card, enough for several such clusters.
    const CARD_SECTORS: u32 = 262_144;

    /// A RAM disk, as the other module has: the card under the driver.
    struct RamDisk(Vec<u8>);

    impl crate::fat::SectorDriver for RamDisk {
        type Error = ();
        fn sector_size(&self) -> u32 {
            512
        }
        fn sector_count(&self) -> u64 {
            (self.0.len() / 512) as u64
        }
        fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), ()> {
            let at = lba as usize * 512;
            let end = at + buf.len();
            if end > self.0.len() {
                return Err(());
            }
            buf.copy_from_slice(&self.0[at..end]);
            Ok(())
        }
        fn write_sectors(&mut self, lba: u64, data: &[u8]) -> Result<(), ()> {
            let at = lba as usize * 512;
            let end = at + data.len();
            if end > self.0.len() {
                return Err(());
            }
            self.0[at..end].copy_from_slice(data);
            Ok(())
        }
    }

    /// Every byte distinct across the whole file, so a cluster read from the wrong place
    /// cannot look right.
    fn payload() -> Vec<u8> {
        (0..FILE_LEN)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect()
    }

    /// An exFAT card with `data` at `/q1/fw.dfu`, cluster size 2^`shift` sectors.
    fn card_with(data: &[u8], shift: u8) -> Vec<u8> {
        let mut mem = MemoryBackend::new(CARD_SECTORS as u64 * 512);
        let opts = ExfatFormatOpts {
            bytes_per_sector_shift: 9,
            sectors_per_cluster_shift: shift,
            ..Default::default()
        };
        let mut fs = Exfat::format(&mut mem, &opts).expect("format exfat");
        let dir = fs.create_dir(&mut mem, "/q1", 0).expect("create directory");
        let _ = dir;
        let mut reader = fstool::io::Cursor::new(data.to_vec());
        fs.create_file(&mut mem, "/q1/fw.dfu", &mut reader, data.len() as u64, 0)
            .expect("create file");
        // The metadata lives in the handle until it is flushed; without this the image
        // has the file's data and an empty root.
        fs.flush(&mut mem).expect("flush");
        let mut image = vec![0u8; CARD_SECTORS as usize * 512];
        mem.read_at(0, &mut image).expect("read image back");
        image
    }

    /// The upgrade path's exact sequence: open, read the container header, seek back to
    /// where the image starts, then stream it in 512-byte blocks.
    ///
    /// Reading a file from the beginning is not what the firmware does -- it reads the
    /// DfuSe header first to find out where the image is, and only then streams. A driver
    /// whose position or cache is confused by that reads most of the file correctly and
    /// some of it not, which is what the device reports.
    #[test]
    fn the_upgrade_paths_read_sequence_returns_the_file() {
        let data = payload();
        for shift in [8u8, 3] {
            let image = card_with(&data, shift);
            let mut vol: AnyVolume<_, 512> =
                AnyVolume::mount_with(|| Ok(RamDisk(image.clone()))).expect("mount");
            let mut file = vol.open_file("/q1/fw.dfu").expect("open");

            // The container header, read in whatever pieces the driver gives.
            const HEAD: usize = 293;
            let mut head = [0u8; HEAD];
            let mut got = 0;
            while got < HEAD {
                let n = file.read(&mut vol, &mut head[got..]).expect("head");
                assert_ne!(n, 0);
                got += n;
            }
            assert_eq!(&head[..], &data[..HEAD], "header, cluster shift {shift}");

            // Back to the start of the image, then stream it.
            file.seek(&mut vol, HEAD as u64).expect("seek");
            let mut got = std::vec![0u8; FILE_LEN - HEAD];
            let mut at = 0usize;
            while at < got.len() {
                let want = (got.len() - at).min(512);
                let n = file.read(&mut vol, &mut got[at..at + want]).expect("read");
                assert_ne!(n, 0, "stopped at {at}, cluster shift {shift}");
                at += n;
            }
            if let Some(i) = (0..got.len()).find(|&i| got[i] != data[HEAD + i]) {
                std::panic!(
                    "cluster shift {shift}: first wrong byte at {:#x} of the image (cluster {})",
                    i,
                    (HEAD + i) / (512 << shift)
                );
            }
        }
    }

    #[test]
    fn a_file_spanning_clusters_reads_back_byte_for_byte() {
        let data = payload();
        // 128 KB clusters, as the card has, and 4 KB as a control.
        for shift in [8u8, 3] {
            let image = card_with(&data, shift);
            let mut vol: AnyVolume<_, 512> =
                AnyVolume::mount_with(|| Ok(RamDisk(image.clone()))).expect("mount");
            let mut file = vol.open_file("/q1/fw.dfu").expect("open");
            assert_eq!(file.len() as usize, FILE_LEN, "cluster shift {shift}");
            // Read in 256-byte blocks, as the upgrade path does.
            let mut got = vec![0u8; FILE_LEN];
            let mut at = 0usize;
            while at < FILE_LEN {
                let want = (FILE_LEN - at).min(256);
                let n = file.read(&mut vol, &mut got[at..at + want]).expect("read");
                assert_ne!(n, 0, "read stopped at {at} with cluster shift {shift}");
                at += n;
            }
            // Report the first difference rather than "not equal": which offset it is says
            // whether a cluster boundary or the chain is at fault.
            if let Some(i) = (0..FILE_LEN).find(|&i| got[i] != data[i]) {
                panic!(
                    "cluster shift {shift}: first wrong byte at {i:#x} \
                     (cluster {}), got {:#04x} want {:#04x}",
                    i / (512 << shift),
                    got[i],
                    data[i]
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CMD42 (LOCK_UNLOCK): the data structure, and the sequence around it
// ---------------------------------------------------------------------------

/// The lock/unlock data structure is a wire format: a command byte of flags, then a length
/// and the password for the operations that carry one. Get a bit or the length wrong and
/// the card does the wrong thing silently -- locks when it was asked to unlock, or reads a
/// password one byte short. These pin the framing without a card.
mod lock_unlock_payload {
    use super::super::*;

    /// Build into the same fixed buffer `lock_unlock` uses, and return the used slice.
    fn framed(op: LockOp<'_>) -> Result<([u8; 2 + MAX_LOCK_PWD], usize), Error> {
        let mut buf = [0u8; 2 + MAX_LOCK_PWD];
        let len = build_lock_payload(op, &mut buf)?;
        Ok((buf, len))
    }

    #[test]
    fn set_pwd_is_the_flag_then_the_length_then_the_password() {
        let (buf, len) = framed(LockOp::SetPassword(b"secret")).expect("set");
        assert_eq!(len, 2 + 6);
        assert_eq!(buf[0], 0b0001, "SET_PWD is bit 0");
        assert_eq!(buf[1], 6, "the password length byte");
        assert_eq!(&buf[2..8], b"secret");
    }

    #[test]
    fn each_operation_sets_the_bit_the_spec_names() {
        assert_eq!(framed(LockOp::SetPassword(b"pw")).unwrap().0[0], 0b0001);
        assert_eq!(framed(LockOp::ClearPassword(b"pw")).unwrap().0[0], 0b0010);
        assert_eq!(framed(LockOp::Lock(b"pw")).unwrap().0[0], 0b0100);
        // Unlock is the absence of every other flag; the password still travels.
        assert_eq!(framed(LockOp::Unlock(b"pw")).unwrap().0[0], 0b0000);
        assert_eq!(framed(LockOp::ForceErase).unwrap().0[0], 0b1000);
    }

    #[test]
    fn unlock_still_carries_the_password() {
        let (buf, len) = framed(LockOp::Unlock(b"open12")).expect("unlock");
        assert_eq!(len, 2 + 6);
        assert_eq!(buf[0], 0, "unlock sets no flag");
        assert_eq!(buf[1], 6);
        assert_eq!(&buf[2..8], b"open12");
    }

    #[test]
    fn force_erase_is_the_command_byte_alone() {
        let (buf, len) = framed(LockOp::ForceErase).expect("erase");
        assert_eq!(len, 1, "no length byte, no password");
        assert_eq!(buf[0], 0b1000);
    }

    #[test]
    fn a_sixteen_byte_password_fits_and_a_longer_one_is_refused() {
        let (buf, len) = framed(LockOp::SetPassword(&[b'x'; 16])).expect("max");
        assert_eq!(len, 2 + 16);
        assert_eq!(buf[1], 16);
        assert_eq!(
            framed(LockOp::SetPassword(&[b'x'; 17])),
            Err(Error::Unsupported)
        );
    }

    #[test]
    fn an_empty_password_is_refused_rather_than_framed() {
        for op in [
            LockOp::SetPassword(b""),
            LockOp::ClearPassword(b""),
            LockOp::Lock(b""),
            LockOp::Unlock(b""),
        ] {
            assert_eq!(
                build_lock_payload(op, &mut [0u8; 2 + MAX_LOCK_PWD]),
                Err(Error::Unsupported)
            );
        }
    }
}

/// The order around CMD42 matters as much as the payload: the data path is armed for a
/// power-of-two block before the command goes out, and the padded structure is what the
/// card is given. A fake transport records exactly what `lock_unlock` did.
mod lock_unlock_sequence {
    use super::super::*;

    #[derive(Default)]
    struct LockFake {
        armed_len: usize,
        armed_to_host: bool,
        cmd: Option<u8>,
        cmd_before_arm: bool,
        payload: [u8; 32],
        payload_len: usize,
    }

    impl Transport for LockFake {
        fn command(&mut self, cmd: u8, _arg: u32, _resp: Response) -> Result<[u32; 4], Error> {
            if self.armed_len == 0 {
                self.cmd_before_arm = true;
            }
            self.cmd = Some(cmd);
            Ok([0; 4])
        }
        fn read_data(&mut self, _out: &mut [u8; BLOCK_LEN]) -> Result<(), Error> {
            Err(Error::Unsupported)
        }
        fn set_bus_width_4(&mut self) -> Result<(), Error> {
            Ok(())
        }
        fn set_fast_clock(&mut self) {}
        fn card_present(&self) -> bool {
            true
        }
        fn arm_data(&mut self, len: usize, to_host: bool) -> Result<(), Error> {
            if len == 0 || !len.is_power_of_two() {
                return Err(Error::Unsupported);
            }
            self.armed_len = len;
            self.armed_to_host = to_host;
            Ok(())
        }
        fn write_short(&mut self, data: &[u8]) -> Result<(), Error> {
            self.payload[..data.len()].copy_from_slice(data);
            self.payload_len = data.len();
            Ok(())
        }
    }

    #[test]
    fn cmd42_goes_out_after_the_data_path_is_armed_outbound() {
        let mut t = LockFake::default();
        lock_unlock(&mut t, LockOp::SetPassword(b"secret")).expect("lock");
        assert!(
            !t.cmd_before_arm,
            "CMD42 went out before arming the data path"
        );
        assert_eq!(t.cmd, Some(42));
        assert!(!t.armed_to_host, "the structure is written host-to-card");
        // 2 + 6 = 8 is already a power of two, so no padding.
        assert_eq!(t.armed_len, 8);
        assert_eq!(t.payload_len, 8);
        assert_eq!(t.payload[0], 0b0001);
        assert_eq!(t.payload[1], 6);
        assert_eq!(&t.payload[2..8], b"secret");
    }

    #[test]
    fn a_short_structure_is_padded_to_a_multiple_of_four() {
        // FORCE_ERASE is one byte; the FIFO writer needs a multiple of four, so it goes
        // out as a four-byte padded block with the tail zeroed.
        let mut t = LockFake::default();
        lock_unlock(&mut t, LockOp::ForceErase).expect("erase");
        assert_eq!(t.armed_len, 4);
        assert_eq!(t.payload_len, 4);
        assert_eq!(t.payload[0], 0b1000);
        assert_eq!(&t.payload[1..4], &[0, 0, 0], "padding is zero");
    }

    #[test]
    fn an_odd_length_password_rounds_up_to_the_next_power_of_two() {
        // 2 + 5 = 7 bytes of structure -> an 8-byte block, tail zeroed.
        let mut t = LockFake::default();
        lock_unlock(&mut t, LockOp::Unlock(b"hello")).expect("unlock");
        assert_eq!(t.armed_len, 8);
        assert_eq!(t.payload_len, 8);
        assert_eq!(t.payload[0], 0);
        assert_eq!(t.payload[1], 5);
        assert_eq!(&t.payload[2..7], b"hello");
        assert_eq!(t.payload[7], 0, "the pad byte is zero");
    }

    #[test]
    fn too_long_a_password_never_touches_the_card() {
        let mut t = LockFake::default();
        assert_eq!(
            lock_unlock(&mut t, LockOp::SetPassword(&[b'x'; 17])),
            Err(Error::Unsupported)
        );
        assert_eq!(t.cmd, None, "no command was sent");
        assert_eq!(t.armed_len, 0, "the data path was never armed");
    }
}
