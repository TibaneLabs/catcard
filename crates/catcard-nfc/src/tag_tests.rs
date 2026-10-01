//! The driver against a simulated ST25DV64KC.
//!
//! The simulation knows only what the datasheet and hw-reference say: which address
//! answers what, that the part NACKs everything during an EEPROM write cycle, that the RF
//! switch commands need `I2C_CFG` bit 5, that static registers need the I²C password, and
//! that `IT_STS_Dyn` reports a phone's write only when `GPO1` enables it. Each test is a
//! statement about one behaviour -- most of them about what a phone could still read.

extern crate std;

use super::*;
use std::vec;
use std::vec::Vec;

/// The simulated part.
struct Part {
    user: Vec<u8>,
    sys: [u8; 0x24],
    password: [u8; 8],
    session: bool,
    rf_mngt_dyn: u8,
    it_sts: u8,
    /// Polls left before the current write cycle ends.
    busy: u32,
    /// Polls one row of user memory keeps the part busy.
    row_polls: u32,
    /// Everything NACKs, for ever.
    dead: bool,
    /// Static register writes, in order.
    sys_writes: Vec<(u16, u8)>,
    /// Rows programmed in user memory.
    rows: usize,
    /// RFSwitchOn/Off commands seen.
    switches: usize,
    /// User memory as it stood each time RF came on: what a phone could have read.
    seen_by_rf: Vec<Vec<u8>>,
    waited_ms: u64,
}

impl Part {
    /// A part as a Coldcard leaves it: set up at the factory, RF asleep from power-up.
    fn coldcard() -> Self {
        let mut p = Self::factory();
        p.sys[reg::I2C_CFG as usize] = I2C_CFG_VALUE;
        p.sys[reg::RF_MNGT as usize] = RF_MNGT_VALUE;
        p.sys[reg::GPO1 as usize] = GPO1_VALUE;
        p.rf_mngt_dyn = RF_MNGT_VALUE;
        p
    }

    /// A part straight from ST: DS13519 factory values.
    fn factory() -> Self {
        let mut sys = [0u8; 0x24];
        sys[0x00] = 0x11; // GPO1 (Table 31)
        sys[0x02] = 0x01; // EH_MODE (Table 40)
        sys[0x0E] = 0x1A; // I2C_CFG (Table 91)
        // MEM_SIZE = 0x07FF: 2048 blocks of four. BLK_SIZE = 3.
        sys[0x14] = 0xFF;
        sys[0x15] = 0x07;
        sys[0x16] = 0x03;
        // UID, LSB first: ..., 0x02 (ST), 0xE0.
        sys[0x18..0x20].copy_from_slice(&[1, 2, 3, 4, 5, 6, 0x02, 0xE0]);
        Self {
            user: vec![0; USER_MEMORY],
            sys,
            password: [0; 8],
            session: false,
            rf_mngt_dyn: 0,
            it_sts: 0,
            busy: 0,
            row_polls: 4,
            dead: false,
            sys_writes: Vec::new(),
            rows: 0,
            switches: 0,
            seen_by_rf: Vec::new(),
            waited_ms: 0,
        }
    }

    fn rf_live(&self) -> bool {
        self.rf_mngt_dyn & 0x07 == 0
    }

    /// A phone writes over RF. Only possible with RF on.
    fn phone_writes(&mut self, at: usize, bytes: &[u8]) {
        assert!(self.rf_live(), "a phone cannot write with RF off");
        self.user[at..at + bytes.len()].copy_from_slice(bytes);
        if self.sys[reg::GPO1 as usize] & 0x80 != 0 {
            self.it_sts |= IT_RF_WRITE;
        }
    }

    fn handle_write(&mut self, addr: u8, bytes: &[u8]) -> Result<(), Nack> {
        match addr {
            addr::RF_SWITCH_ON | addr::RF_SWITCH_OFF => {
                self.switches += 1;
                assert!(bytes.is_empty(), "the switch commands are address-only");
                if self.sys[reg::I2C_CFG as usize] & 0x20 == 0 {
                    return Err(Nack);
                }
                if addr == addr::RF_SWITCH_ON {
                    self.rf_mngt_dyn &= !RF_OFF;
                } else {
                    self.rf_mngt_dyn |= RF_OFF;
                }
                Ok(())
            }
            addr::USER if bytes.is_empty() => Ok(()),
            addr::USER => {
                let at = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
                let data = &bytes[2..];
                if at >= 0x2000 {
                    // Dynamic: only RF_MNGT_Dyn's two low bits are written here.
                    assert_eq!(at, reg::RF_MNGT_DYN as usize);
                    self.rf_mngt_dyn = (self.rf_mngt_dyn & RF_OFF) | (data[0] & 0x03);
                    return Ok(());
                }
                assert!(!data.is_empty() && data.len() <= ROW);
                assert_eq!(
                    at / ROW,
                    (at + data.len() - 1) / ROW,
                    "one row per transfer"
                );
                assert!(!self.rf_live(), "user memory written with RF on");
                self.user[at..at + data.len()].copy_from_slice(data);
                self.rows += 1;
                self.busy = self.row_polls;
                Ok(())
            }
            addr::SYSTEM => {
                let at = u16::from_be_bytes([bytes[0], bytes[1]]);
                if at == reg::I2C_PWD {
                    assert_eq!(bytes.len(), 2 + 17);
                    let ok = bytes[2..10] == self.password
                        && bytes[10] == 0x09
                        && bytes[11..19] == self.password;
                    self.session = ok;
                    return Ok(());
                }
                assert_eq!(bytes.len(), 3, "one byte per system write");
                if !self.session {
                    // Written but not taken: the read-back will say so.
                    return Ok(());
                }
                self.sys[at as usize] = bytes[2];
                self.sys_writes.push((at, bytes[2]));
                if at == reg::RF_MNGT {
                    self.rf_mngt_dyn = (self.rf_mngt_dyn & RF_OFF) | (bytes[2] & 0x03);
                }
                self.busy = 3;
                Ok(())
            }
            _ => Err(Nack),
        }
    }
}

impl Bus for Part {
    fn write(&mut self, addr: u8, bytes: &[u8]) -> Result<(), Nack> {
        if self.dead {
            return Err(Nack);
        }
        if self.busy > 0 {
            self.busy -= 1;
            return Err(Nack);
        }
        let was_live = self.rf_live();
        let r = self.handle_write(addr, bytes);
        if !was_live && self.rf_live() {
            self.seen_by_rf.push(self.user.clone());
        }
        r
    }

    fn write_read(&mut self, addr: u8, bytes: &[u8], out: &mut [u8]) -> Result<(), Nack> {
        if self.dead {
            return Err(Nack);
        }
        if self.busy > 0 {
            self.busy -= 1;
            return Err(Nack);
        }
        let at = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        match addr {
            addr::USER if at >= 0x2000 => {
                out[0] = match at as u16 {
                    reg::RF_MNGT_DYN => self.rf_mngt_dyn,
                    reg::I2C_SSO_DYN => self.session as u8,
                    reg::IT_STS_DYN => core::mem::take(&mut self.it_sts),
                    _ => panic!("unexpected dynamic read {at:#x}"),
                };
            }
            addr::USER => out.copy_from_slice(&self.user[at..at + out.len()]),
            addr::SYSTEM => out.copy_from_slice(&self.sys[at..at + out.len()]),
            _ => return Err(Nack),
        }
        Ok(())
    }

    fn delay_ms(&mut self, ms: u32) {
        self.waited_ms += ms as u64;
    }
}

fn tag(part: Part, dirty: usize) -> Tag<Part> {
    Tag::new(part, dirty)
}

// ---------------------------------------------------------------------------
// Identification and configuration
// ---------------------------------------------------------------------------

#[test]
fn only_the_8k_st25dv_is_taken_for_the_tag() {
    assert_eq!(tag(Part::coldcard(), 0).identify(), Ok(()));

    let mut wrong_prefix = Part::coldcard();
    wrong_prefix.sys[0x1F] = 0x00;
    assert_eq!(tag(wrong_prefix, 0).identify(), Err(TagError::NotThePart));

    // A 16K part: 512 blocks of four.
    let mut smaller = Part::coldcard();
    smaller.sys[0x14] = 0xFF;
    smaller.sys[0x15] = 0x01;
    assert_eq!(tag(smaller, 0).identify(), Err(TagError::NotThePart));

    let mut nobody = Part::coldcard();
    nobody.dead = true;
    assert_eq!(tag(nobody, 0).identify(), Err(TagError::NoAnswer));
}

#[test]
fn a_tag_set_up_at_the_factory_is_configured_by_reading_alone() {
    let mut t = tag(Part::coldcard(), 0);
    t.prepare().unwrap();
    let p = t.into_bus();
    assert!(
        p.sys_writes.is_empty(),
        "EEPROM rewritten: {:?}",
        p.sys_writes
    );
    assert!(!p.session, "the password was presented for nothing");
}

#[test]
fn a_blank_part_gets_the_one_time_setup_with_the_session_open() {
    let mut t = tag(Part::factory(), 0);
    t.prepare().unwrap();
    let p = t.into_bus();
    assert_eq!(
        p.sys_writes,
        [
            (reg::I2C_CFG, 0x3A),
            (reg::RF_MNGT, 0x02),
            (reg::GPO1, 0x85)
        ]
    );
    // RF_SLEEP is copied into the dynamic register straight away: silent from here on.
    assert!(!p.rf_live());
}

#[test]
fn a_refused_password_is_an_error_and_writes_nothing() {
    let mut p = Part::factory();
    p.password = [1; 8];
    let mut t = tag(p, 0);
    assert_eq!(t.prepare(), Err(TagError::Refused));
    assert!(t.into_bus().sys_writes.is_empty());
}

// ---------------------------------------------------------------------------
// RF on and off
// ---------------------------------------------------------------------------

#[test]
fn rf_on_clears_the_power_up_sleep_and_rf_off_sets_rf_off() {
    let mut t = tag(Part::coldcard(), 0);
    assert!(!t.bus.rf_live(), "a Coldcard tag is asleep at power-up");
    t.rf_on().unwrap();
    assert_eq!(t.bus.rf_mngt_dyn, 0);
    t.rf_off().unwrap();
    assert_ne!(t.bus.rf_mngt_dyn & RF_OFF, 0);
}

#[test]
fn rf_switching_waits_out_a_write_cycle_and_gives_up_after_ten_tries() {
    let mut p = Part::coldcard();
    p.busy = 5;
    let mut t = tag(p, 0);
    assert_eq!(t.rf_on(), Ok(()));

    let mut p = Part::coldcard();
    p.dead = true;
    let mut t = tag(p, 0);
    assert_eq!(t.rf_off(), Err(TagError::RfStuck));
    let p = t.into_bus();
    assert!(p.waited_ms <= (RF_TRIES * RF_RETRY_MS) as u64);
}

#[test]
fn the_switch_commands_are_refused_until_i2c_cfg_allows_them() {
    let mut t = tag(Part::factory(), 0);
    assert_eq!(t.rf_off(), Err(TagError::RfStuck));
    assert_eq!(t.into_bus().switches, RF_TRIES as usize);
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

#[test]
fn a_write_waits_on_the_acknowledge_and_reads_itself_back() {
    let mut t = tag(Part::coldcard(), 0);
    let image: Vec<u8> = (0..100u8).collect();
    t.write(0, &image).unwrap();
    assert_eq!(&t.bus.user[..100], &image[..]);
    assert_eq!(t.bus.rows, 7);
    assert_eq!(t.dirty(), 100);
}

#[test]
fn a_write_cycle_that_never_ends_is_an_error_not_a_hang() {
    let mut p = Part::coldcard();
    p.row_polls = u32::MAX;
    let mut t = tag(p, 0);
    assert_eq!(t.write(0, &[1; 32]), Err(TagError::Busy));
    assert!(t.bus.waited_ms <= READY_POLLS as u64);
    // The mark moved before the write, so the half that landed is still owed a wipe.
    assert_eq!(t.dirty(), 32);
}

// ---------------------------------------------------------------------------
// Residue
// ---------------------------------------------------------------------------

/// What stock leaves: an older PSBT, 8000 bytes, of which only the first 512 were zeroed.
fn with_stock_residue() -> Part {
    let mut p = Part::coldcard();
    p.user[512..8000].fill(0xAA);
    p
}

#[test]
fn what_a_previous_firmware_left_is_gone_before_a_phone_can_see_the_tag() {
    // Power-up: nothing known, so the mark is the whole part.
    let mut t = tag(with_stock_residue(), USER_MEMORY);
    t.begin().unwrap();
    t.write(0, &[0x42; 60]).unwrap();
    t.go_live().unwrap();
    let seen = &t.bus.seen_by_rf[0];
    assert_eq!(&seen[..60], &[0x42; 60]);
    assert!(
        seen[60..].iter().all(|&b| b == 0),
        "residue visible over RF"
    );
}

#[test]
fn the_power_up_scan_programs_only_rows_that_hold_something() {
    let mut p = Part::coldcard();
    p.user[4096] = 1;
    let mut t = tag(p, USER_MEMORY);
    t.begin().unwrap();
    assert_eq!(t.bus.rows, 1);
    assert_eq!(t.dirty(), 0);
}

#[test]
fn after_a_share_the_wipe_reaches_exactly_what_was_written() {
    let mut t = tag(Part::coldcard(), 0);
    t.begin().unwrap();
    t.write(0, &[0x42; 600]).unwrap();
    t.go_live().unwrap();
    let before = t.bus.rows;
    t.finish().unwrap();
    assert!(t.bus.user.iter().all(|&b| b == 0));
    assert_eq!(t.bus.rows - before, 600usize.div_ceil(ROW));
    assert_eq!(t.dirty(), 0);
    assert_ne!(t.bus.rf_mngt_dyn & RF_OFF, 0, "RF left on");
}

#[test]
fn a_phone_writing_during_a_share_widens_the_wipe_to_the_whole_part() {
    let mut t = tag(Part::coldcard(), 0);
    t.begin().unwrap();
    t.write(0, &[0x42; 40]).unwrap();
    t.go_live().unwrap();
    t.bus.phone_writes(7000, b"a phone's own bytes");
    t.finish().unwrap();
    assert!(t.bus.user.iter().all(|&b| b == 0));
}

#[test]
fn a_receive_is_wiped_to_the_last_byte_the_phone_wrote() {
    let mut t = tag(Part::coldcard(), 0);
    t.begin().unwrap();
    t.write(0, &[0x42; 40]).unwrap();
    t.go_live().unwrap();
    t.bus.phone_writes(0, &[0x17; 5100]);
    let mut image = vec![0u8; USER_MEMORY];
    t.read_whole(&mut image).unwrap();
    assert_eq!(t.dirty(), 5100);
    assert_eq!(&image[..5100], &[0x17; 5100][..]);
    let before = t.bus.rows;
    t.finish().unwrap();
    assert!(t.bus.user.iter().all(|&b| b == 0));
    // Exactly the rows the phone filled: the IT_STS_Dyn write flag was cleared by the
    // whole read, so the wipe did not fall back to scanning the part.
    assert_eq!(t.bus.rows - before, 5100usize.div_ceil(ROW));
}

#[test]
fn a_wipe_that_fails_keeps_its_mark_and_the_next_session_wipes_before_rf_on() {
    let mut t = tag(Part::coldcard(), 0);
    t.begin().unwrap();
    t.write(0, &[0x42; 300]).unwrap();
    t.go_live().unwrap();
    t.bus.row_polls = u32::MAX;
    assert!(t.finish().is_err());
    assert_eq!(t.dirty(), 300);

    let mut p = t.into_bus();
    p.row_polls = 4;
    p.busy = 0;
    let mut t = tag(p, 300);
    t.begin().unwrap();
    t.go_live().unwrap();
    let seen = t.bus.seen_by_rf.last().unwrap();
    assert!(
        seen.iter().all(|&b| b == 0),
        "the old image went live again"
    );
}

#[test]
fn the_high_water_mark_is_the_end_of_the_last_byte_that_is_not_zero() {
    assert_eq!(high_water(&[]), 0);
    assert_eq!(high_water(&[0; 64]), 0);
    assert_eq!(high_water(&[0, 0, 7, 0, 0]), 3);
    assert_eq!(high_water(&[1; 16]), 16);
}
