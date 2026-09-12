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
            CMD_ALL_SEND_CID => Ok([0xAAAA_AAAA, 0, 0, 0]),
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
}
