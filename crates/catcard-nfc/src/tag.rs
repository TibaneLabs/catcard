//! The ST25DV64KC itself: who answers where on the bus, how the RF side is switched on and
//! off, and how the memory is left with nothing in it.
//!
//! Written against [`Bus`] rather than a pin driver, so the whole sequence -- the retries,
//! the bounds, what is wiped and what is not -- runs on the host against a simulated part.
//!
//! Sources: hw-reference/secure-elements.md §"NFC — ST25DV dynamic tag (mk4 / Mk5 / Q)"
//! and its subsections, and hw-reference/datasheets/ST25DV64KC-st.pdf (DS13519), whose
//! table numbers are quoted below.
//!
//! # One session
//!
//! ```text
//! begin       identify; one-time setup if never done; GPO1; RF off;
//!             zero whatever may be left from before            (RF still off)
//! write       the image, row by row, read back
//! go_live     IT_STS_Dyn read once to clear it; RF on          ... the screen ...
//! finish      RF off; a phone's write widens the wipe; zero up to the mark
//! ```
//!
//! # Residue
//!
//! Stock zeroes only the first 512 bytes after a non-secret share or a receive, so an older
//! object longer than that stays in EEPROM past byte 512, readable over I²C and by any RF
//! reader in the next RF session (secure-elements.md §"Data left in tag EEPROM" [C]). Here
//! [`Tag`] carries a **high-water mark**: the end of everything that may be non-zero. It
//! starts at the whole part -- nothing is known about a tag at power-up -- and every write,
//! every phone write and every whole read moves it; [`Tag::scrub`] zeroes up to it and
//! puts it back to zero.
//!
//! The arithmetic that picks this over always wiping the whole part: programming is one
//! write time `tW` (≤5.5 ms) per 16-byte row touched (DS13519 §6.4.2), plus about 1.7 ms
//! of bit-banged bus per row, so a blind 8 KB wipe is 512 rows -- about 3.7 s, every time.
//! The high-water wipe costs the same for an 8 KB image and a few tens of milliseconds for
//! an address. The whole-part pass -- the first session after power-up, or after a phone
//! wrote during a share -- reads first (about 0.75 s for 8 KB) and programs only the rows
//! that are not already zero.

/// The part's user memory: 8 KB. The driver refuses any other size.
/// Source: secure-elements.md §"Part, bus, pins", §Identification [C]
pub const USER_MEMORY: usize = 8192;

/// One EEPROM row: a write programs every row it touches, one `tW` each.
/// Source: DS13519 §6.4.2 "I²C sequential write" [C]
pub const ROW: usize = 16;

/// 7-bit addresses, with `I2C_CFG = 0x3A` (device code `1010b`, `E0 = 1`).
/// Source: secure-elements.md §"I²C addressing" [C]; DS13519 Table 89 [C]
pub mod addr {
    /// User memory `0x0000-0x1FFF` and dynamic registers `0x2000-0x2007`.
    pub const USER: u8 = 0x53;
    /// System configuration area: static registers, UID, password.
    pub const SYSTEM: u8 = 0x57;
    /// RFSwitchOn: an address-only write. NACKed until `I2C_CFG` bit 5 is set.
    pub const RF_SWITCH_ON: u8 = 0x51;
    /// RFSwitchOff: an address-only write. NACKed until `I2C_CFG` bit 5 is set.
    pub const RF_SWITCH_OFF: u8 = 0x55;
}

/// Register addresses, two bytes, most significant first.
/// Source: DS13519 Table 13 (system), Table 14 (dynamic) [C]
pub mod reg {
    /// `GPO1`, system. Source: Table 31 [C]
    pub const GPO1: u16 = 0x0000;
    /// `RF_MNGT`, system: the RF state at power-up. Source: Table 23 [C]
    pub const RF_MNGT: u16 = 0x0003;
    /// `I2C_CFG`, system. Source: Table 91 [C]
    pub const I2C_CFG: u16 = 0x000E;
    /// `MEM_SIZE`, system, two bytes little-endian; then `BLK_SIZE`, `IC_REF`, and the
    /// eight-byte `UID` at `0x0018`. Source: Table 13 [C]
    pub const MEM_SIZE: u16 = 0x0014;
    /// `I2C_PWD`, system: where "present password" is written. Source: §6.6.1 [C]
    pub const I2C_PWD: u16 = 0x0900;
    /// `RF_MNGT_Dyn`, at the user address. Source: Tables 24/25 [C]
    pub const RF_MNGT_DYN: u16 = 0x2003;
    /// `I2C_SSO_Dyn`, at the user address. Source: Tables 68/69 [C]
    pub const I2C_SSO_DYN: u16 = 0x2004;
    /// `IT_STS_Dyn`, at the user address, read-to-clear. Source: Tables 36/37 [C]
    pub const IT_STS_DYN: u16 = 0x2005;
}

/// `I2C_CFG` as Coldcard sets it: device code `1010b`, `E0 = 1`, and bit 5
/// `I2C_RF_SWITCHOFF_EN`. The factory value is `0x1A`.
/// Source: secure-elements.md §"Configuration Coldcard writes" [C]; DS13519 Table 91 [C]
pub const I2C_CFG_VALUE: u8 = 0x3A;
/// `RF_MNGT = RF_SLEEP`: the tag is RF-silent from power-up.
/// Source: secure-elements.md §"Configuration Coldcard writes" [C]; DS13519 Table 23 [C]
pub const RF_MNGT_VALUE: u8 = 0x02;
/// `GPO1 = GPO_EN | RF_ACTIVITY_EN | RF_WRITE_EN`, stock's value. What this driver needs
/// from it is `RF_WRITE_EN`, without which `IT_STS_Dyn` never reports a phone's write.
/// Source: secure-elements.md §"Configuration Coldcard writes" [C]; DS13519 Table 31, and
/// the note under Table 37 ("When enabled, RF events are reported") [C]
pub const GPO1_VALUE: u8 = 0x85;
/// `RF_MNGT_Dyn` bit 2: set only by RFSwitchOff, cleared only by RFSwitchOn.
/// Source: DS13519 Table 25 and its note [C]
pub const RF_OFF: u8 = 0x04;
/// `IT_STS_Dyn` bit 7: an RF write to EEPROM since the register was last read.
/// Source: DS13519 Table 37 [C]
pub const IT_RF_WRITE: u8 = 0x80;
/// The last UID byte: the ISO 15693 prefix. Anything else is "no tag".
/// Source: secure-elements.md §Identification [C]
pub const UID_PREFIX: u8 = 0xE0;

/// After a write to a system register, before polling. Source: secure-elements.md
/// §"Configuration Coldcard writes" ("Wait ≥10 ms") [C]
pub const SYSTEM_WRITE_MS: u32 = 10;
/// Polls, 1 ms apart, for the end of an EEPROM write cycle. One row is ≤5.5 ms and a
/// system byte is waited 10 ms before the first poll, so a hundred is a dead part, not a
/// slow one. Source: DS13519 §6.4.3, Table 251 (`tW`) [C]
pub const READY_POLLS: u32 = 100;
/// RF on/off attempts: the part NACKs everything while an EEPROM write cycle runs.
/// Source: secure-elements.md §"RF on/off control" [C]
pub const RF_TRIES: u32 = 10;
/// The pause between two RF on/off attempts. Source: as [`RF_TRIES`] [C]
pub const RF_RETRY_MS: u32 = 25;

/// Bytes read per transfer while checking or scanning: a multiple of [`ROW`] that keeps
/// the stack buffer small.
const CHUNK: usize = 64;

/// The part did not acknowledge: absent, or busy with a write cycle or the RF side.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Nack;

/// The bus the tag is on.
pub trait Bus {
    /// START, address+W, `bytes`, STOP. Empty `bytes` is an address-only write.
    fn write(&mut self, addr: u8, bytes: &[u8]) -> Result<(), Nack>;
    /// `bytes` as a write, a repeated START, then `out` read.
    fn write_read(&mut self, addr: u8, bytes: &[u8], out: &mut [u8]) -> Result<(), Nack>;
    /// Wait `ms` milliseconds.
    fn delay_ms(&mut self, ms: u32);
}

/// Why the tag could not do what was asked.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum TagError {
    /// Nothing acknowledged.
    NoAnswer,
    /// Something answered, but not an 8 KB ST25DV: wrong UID prefix or memory size.
    NotThePart,
    /// An EEPROM write cycle did not end within [`READY_POLLS`].
    Busy,
    /// The I²C password was refused, so the configuration could not be written.
    Refused,
    /// RF did not switch within [`RF_TRIES`].
    RfStuck,
    /// What was read back is not what was written, or a range past the part.
    NotTaken,
}

impl TagError {
    /// One line for the screen.
    pub fn message(self) -> &'static str {
        match self {
            TagError::NoAnswer => "the tag did not answer",
            TagError::NotThePart => "not the expected tag",
            TagError::Busy => "the tag stayed busy",
            TagError::Refused => "the tag refused setup",
            TagError::RfStuck => "NFC would not switch",
            TagError::NotTaken => "the tag did not take the write",
        }
    }
}

impl From<Nack> for TagError {
    fn from(_: Nack) -> Self {
        TagError::NoAnswer
    }
}

/// The part, and how much of it may hold something.
pub struct Tag<B: Bus> {
    bus: B,
    dirty: usize,
}

impl<B: Bus> Tag<B> {
    /// `dirty` is the high-water mark carried from the last session: [`USER_MEMORY`] when
    /// nothing is known, which is the case at power-up.
    pub fn new(bus: B, dirty: usize) -> Self {
        Self {
            bus,
            dirty: dirty.min(USER_MEMORY),
        }
    }

    /// The end of everything that may be non-zero.
    pub fn dirty(&self) -> usize {
        self.dirty
    }

    /// Hand the bus back.
    pub fn into_bus(self) -> B {
        self.bus
    }

    fn read(&mut self, dev: u8, at: u16, out: &mut [u8]) -> Result<(), TagError> {
        Ok(self.bus.write_read(dev, &at.to_be_bytes(), out)?)
    }

    fn read_byte(&mut self, dev: u8, at: u16) -> Result<u8, TagError> {
        let mut one = [0u8];
        self.read(dev, at, &mut one)?;
        Ok(one[0])
    }

    /// Check the part is the 8 KB ST25DV: UID ending in `0xE0`, and `MEM_SIZE` (blocks of
    /// four, minus one) adding up to 8192. Source: secure-elements.md §Identification [C]
    pub fn identify(&mut self) -> Result<(), TagError> {
        // MEM_SIZE (2), BLK_SIZE, IC_REF, UID (8): one transfer, 0x0014-0x001F.
        let mut id = [0u8; 12];
        self.read(addr::SYSTEM, reg::MEM_SIZE, &mut id)?;
        let blocks = u16::from_le_bytes([id[0], id[1]]) as usize;
        if id[11] != UID_PREFIX || (blocks + 1) * 4 != USER_MEMORY {
            return Err(TagError::NotThePart);
        }
        Ok(())
    }

    /// Identify the part, and put its configuration where this driver needs it.
    ///
    /// `I2C_CFG` and `RF_MNGT` are written only on a part that was never set up -- the
    /// factory does it, so on a Coldcard this is a read and nothing more. `GPO1` only if it
    /// differs. Every one of them is EEPROM, so writing what is already there would be wear
    /// for nothing. Source: secure-elements.md §"Configuration Coldcard writes" [C]
    pub fn prepare(&mut self) -> Result<(), TagError> {
        self.identify()?;
        if self.read_byte(addr::SYSTEM, reg::I2C_CFG)? != I2C_CFG_VALUE {
            self.open_session()?;
            self.write_system(reg::I2C_CFG, I2C_CFG_VALUE)?;
            self.write_system(reg::RF_MNGT, RF_MNGT_VALUE)?;
        }
        if self.read_byte(addr::SYSTEM, reg::GPO1)? != GPO1_VALUE {
            self.open_session()?;
            self.write_system(reg::GPO1, GPO1_VALUE)?;
        }
        Ok(())
    }

    /// Present the I²C password -- the factory all-zero one, never changed -- and check
    /// `I2C_SSO_Dyn` says the session is open: `pw(8) ‖ 0x09 ‖ pw(8)` at `0x0900`.
    /// Source: secure-elements.md §"Configuration Coldcard writes" [C]; DS13519 §6.6.1 [C]
    fn open_session(&mut self) -> Result<(), TagError> {
        let mut frame = [0u8; 2 + 17];
        frame[..2].copy_from_slice(&reg::I2C_PWD.to_be_bytes());
        frame[2 + 8] = 0x09;
        self.bus.write(addr::SYSTEM, &frame)?;
        self.wait_ready()?;
        if self.read_byte(addr::USER, reg::I2C_SSO_DYN)? & 0x01 == 0 {
            return Err(TagError::Refused);
        }
        Ok(())
    }

    /// One byte into a system register, waited out and read back. One byte per write is
    /// all the system area takes (DS13519 §6.4.2) [C].
    fn write_system(&mut self, at: u16, value: u8) -> Result<(), TagError> {
        let [hi, lo] = at.to_be_bytes();
        self.bus.write(addr::SYSTEM, &[hi, lo, value])?;
        self.bus.delay_ms(SYSTEM_WRITE_MS);
        self.wait_ready()?;
        if self.read_byte(addr::SYSTEM, at)? != value {
            return Err(TagError::NotTaken);
        }
        Ok(())
    }

    /// Wait out an EEPROM write cycle by polling for an acknowledge: an address-only write
    /// to the user address, which the part NACKs until the cycle ends. Bounded by
    /// [`READY_POLLS`]. Source: DS13519 §6.4.3, Figure 34 [C]
    pub fn wait_ready(&mut self) -> Result<(), TagError> {
        for _ in 0..READY_POLLS {
            if self.bus.write(addr::USER, &[]).is_ok() {
                return Ok(());
            }
            self.bus.delay_ms(1);
        }
        Err(TagError::Busy)
    }

    /// Program `bytes` at `at`, one row per transfer, each waited out. Not read back.
    fn program(&mut self, at: usize, bytes: &[u8]) -> Result<(), TagError> {
        let mut buf = [0u8; 2 + ROW];
        let mut done = 0;
        while done < bytes.len() {
            let here = at + done;
            // To the end of this row: a transfer never touches two.
            let n = (ROW - here % ROW).min(bytes.len() - done);
            buf[..2].copy_from_slice(&(here as u16).to_be_bytes());
            buf[2..2 + n].copy_from_slice(&bytes[done..done + n]);
            self.bus.write(addr::USER, &buf[..2 + n])?;
            self.wait_ready()?;
            done += n;
        }
        zeroize::Zeroize::zeroize(&mut buf);
        Ok(())
    }

    /// Read user memory from `at` into `out`.
    pub fn read_user(&mut self, at: usize, out: &mut [u8]) -> Result<(), TagError> {
        if at + out.len() > USER_MEMORY {
            return Err(TagError::NotTaken);
        }
        self.read(addr::USER, at as u16, out)
    }

    /// Write `bytes` into user memory at `at`, then read every byte back and compare: a
    /// write the part did not take looks exactly like one it did until a phone taps it.
    ///
    /// The high-water mark moves **before** the first row goes, so a write that fails
    /// halfway still gets wiped.
    pub fn write(&mut self, at: usize, bytes: &[u8]) -> Result<(), TagError> {
        let end = at + bytes.len();
        if end > USER_MEMORY {
            return Err(TagError::NotTaken);
        }
        self.dirty = self.dirty.max(end);
        self.program(at, bytes)?;
        let mut back = [0u8; CHUNK];
        let mut same = true;
        for (n, want) in bytes.chunks(CHUNK).enumerate() {
            let got = &mut back[..want.len()];
            self.read_user(at + n * CHUNK, got)?;
            same &= got == want;
        }
        zeroize::Zeroize::zeroize(&mut back);
        if same {
            Ok(())
        } else {
            Err(TagError::NotTaken)
        }
    }

    /// RFSwitchOff, then check `RF_MNGT_Dyn` bit 2 `RF_OFF`. Retried, because the part
    /// NACKs during a write cycle. Source: secure-elements.md §"RF on/off control" [C];
    /// DS13519 Table 25 [C]
    pub fn rf_off(&mut self) -> Result<(), TagError> {
        for _ in 0..RF_TRIES {
            if self.bus.write(addr::RF_SWITCH_OFF, &[]).is_ok()
                && matches!(self.read_byte(addr::USER, reg::RF_MNGT_DYN), Ok(v) if v & RF_OFF != 0)
            {
                return Ok(());
            }
            self.bus.delay_ms(RF_RETRY_MS);
        }
        Err(TagError::RfStuck)
    }

    /// RFSwitchOn, then `RF_MNGT_Dyn = 0` to clear the `RF_SLEEP` copied from the static
    /// register at power-up, and check it reads back zero. Retried as [`Tag::rf_off`].
    /// Source: secure-elements.md §"RF on/off control" [C]; DS13519 Tables 24/25 [C]
    pub fn rf_on(&mut self) -> Result<(), TagError> {
        let [hi, lo] = reg::RF_MNGT_DYN.to_be_bytes();
        for _ in 0..RF_TRIES {
            if self.bus.write(addr::RF_SWITCH_ON, &[]).is_ok()
                && self.bus.write(addr::USER, &[hi, lo, 0x00]).is_ok()
                && self.read_byte(addr::USER, reg::RF_MNGT_DYN) == Ok(0)
            {
                return Ok(());
            }
            self.bus.delay_ms(RF_RETRY_MS);
        }
        Err(TagError::RfStuck)
    }

    /// Read `IT_STS_Dyn`, which clears it. Whether a phone wrote to EEPROM since the last
    /// read -- and `true` when the read itself failed, since not knowing is treated as yes.
    /// Source: DS13519 Table 37 and its notes [C]
    pub fn rf_wrote(&mut self) -> bool {
        !matches!(self.read_byte(addr::USER, reg::IT_STS_DYN), Ok(v) if v & IT_RF_WRITE == 0)
    }

    /// Switch RF off and read the whole of user memory into `out`, which must be
    /// [`USER_MEMORY`] long. With every byte seen and nothing able to change them, the
    /// high-water mark becomes exactly the end of the last non-zero one.
    pub fn read_whole(&mut self, out: &mut [u8]) -> Result<(), TagError> {
        if out.len() != USER_MEMORY {
            return Err(TagError::NotTaken);
        }
        self.rf_off()?;
        // Cleared now that RF is off, so `finish` does not count a write already seen.
        let _ = self.rf_wrote();
        self.read_user(0, out)?;
        self.dirty = high_water(out);
        Ok(())
    }

    /// Zero user memory up to the high-water mark, reading first and programming only the
    /// rows that are not zero already, then reading back every chunk it programmed. On
    /// success nothing is left and the mark is zero; on failure the mark stays where it
    /// was, so the next session tries again **before** RF is switched on.
    pub fn scrub(&mut self) -> Result<(), TagError> {
        let end = self.dirty.next_multiple_of(ROW).min(USER_MEMORY);
        let mut buf = [0u8; CHUNK];
        let r = self.scrub_to(end, &mut buf);
        zeroize::Zeroize::zeroize(&mut buf);
        r?;
        self.dirty = 0;
        Ok(())
    }

    fn scrub_to(&mut self, end: usize, buf: &mut [u8; CHUNK]) -> Result<(), TagError> {
        let mut at = 0;
        while at < end {
            let n = CHUNK.min(end - at);
            self.read_user(at, &mut buf[..n])?;
            let mut wrote = false;
            for row in (0..n).step_by(ROW) {
                if buf[row..row + ROW].iter().any(|&b| b != 0) {
                    self.program(at + row, &[0u8; ROW])?;
                    wrote = true;
                }
            }
            if wrote {
                self.read_user(at, &mut buf[..n])?;
                if buf[..n].iter().any(|&b| b != 0) {
                    return Err(TagError::NotTaken);
                }
            }
            at += n;
        }
        Ok(())
    }

    /// The start of a session: identify and configure, take the part from the RF side, and
    /// zero anything a previous session -- or a previous firmware -- may have left. RF is
    /// still off afterwards.
    pub fn begin(&mut self) -> Result<(), TagError> {
        self.prepare()?;
        self.rf_off()?;
        if self.dirty > 0 {
            self.scrub()?;
        }
        Ok(())
    }

    /// Clear `IT_STS_Dyn` and switch RF on: a phone can see the tag from here.
    pub fn go_live(&mut self) -> Result<(), TagError> {
        let _ = self.rf_wrote();
        self.rf_on()
    }

    /// The end of a session: RF off, and everything this session may have left zeroed.
    ///
    /// The tag is RF-writable whenever RF is on -- no area protection is set
    /// (secure-elements.md §"Configuration Coldcard writes" [C]) -- so a phone that wrote
    /// may have written anywhere: the mark goes to the whole part and the scan finds what
    /// is really there. Scrubbed even when RF would not switch off; the first error is the
    /// one returned.
    pub fn finish(&mut self) -> Result<(), TagError> {
        let off = self.rf_off();
        if self.rf_wrote() {
            self.dirty = USER_MEMORY;
        }
        let wiped = self.scrub();
        off.and(wiped)
    }
}

/// The end of the last non-zero byte in `image`: how far a wipe has to reach.
pub fn high_water(image: &[u8]) -> usize {
    image.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1)
}

#[cfg(test)]
#[path = "tag_tests.rs"]
mod tests;
