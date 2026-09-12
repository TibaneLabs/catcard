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
