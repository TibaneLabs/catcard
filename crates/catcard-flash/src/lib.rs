//! SPI-NOR flash.
//!
//! Holds PSBT scratch, the settings store, and the staging area a pending firmware
//! image is written to before reboot. Source for the command set and geometry:
//! `hw-reference/gpio-peripherals.md §SPI-NOR` [C].
//!
//! # NOR semantics, which the API is shaped around
//!
//! Programming can only clear bits: `1 -> 0`. Erasing is the only way to set them back,
//! and it works on whole sectors. So "write these bytes here" is not an operation NOR
//! offers — [`write`](NorFlash::write) programs into already-erased space, and
//! [`erase_sector`](NorFlash::erase_sector) is explicit.
//!
//! A driver that hides this behind a read-modify-write of a whole sector looks
//! convenient and loses data on power failure, because the erase and the rewrite are
//! not atomic. The settings store above this layer is what deals with that; the driver
//! stays honest about what the part actually does.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

/// JEDEC command opcodes. Source: gpio-peripherals.md §SPI-NOR [C]
pub mod cmd {
    /// Read JEDEC ID: manufacturer, memory type, capacity.
    pub const RDID: u8 = 0x9F;
    /// Read data, no dummy byte. Limited to lower clock rates on most parts.
    pub const READ: u8 = 0x03;
    /// Fast read: one dummy byte after the address.
    pub const FAST_READ: u8 = 0x0B;
    /// Page program, up to one page at a time.
    pub const PAGE_PROGRAM: u8 = 0x02;
    /// Write enable. Required before every program and erase.
    pub const WRITE_ENABLE: u8 = 0x06;
    /// Write disable.
    pub const WRITE_DISABLE: u8 = 0x04;
    /// Read status register.
    pub const READ_STATUS: u8 = 0x05;
    /// Write status register.
    pub const WRITE_STATUS: u8 = 0x01;
    /// Erase a 4 KB sector.
    pub const SECTOR_ERASE: u8 = 0x20;
    /// Erase a 64 KB block.
    pub const BLOCK_ERASE: u8 = 0xD8;
    /// Erase the whole part.
    pub const CHIP_ERASE: u8 = 0xC7;
}

/// Status register bits.
pub mod status {
    /// Write in progress. Set while a program or erase is running.
    pub const WIP: u8 = 1 << 0;
    /// Write enable latch. Set by `WRITE_ENABLE`, cleared when the operation completes.
    pub const WEL: u8 = 1 << 1;
}

/// Programmable page. Programming across a page boundary wraps to the start of the same
/// page instead of continuing — a silent corruption, so this driver splits writes.
pub const PAGE_SIZE: usize = 256;

/// Smallest erasable unit. Source: gpio-peripherals.md [C]
pub const SECTOR_SIZE: u32 = 4096;

/// A 64 KB erase block.
pub const BLOCK_SIZE: u32 = 65536;

/// Byte an erased cell reads as.
pub const ERASED: u8 = 0xFF;

/// Address bytes in a standard 3-byte-address command.
pub const ADDR_LEN: usize = 3;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error<E> {
    /// The bus reported a failure.
    Bus(E),
    /// An operation ran past the end of the device.
    OutOfRange { addr: u32, len: usize },
    /// An erase or program did not finish within its budget. The part is wedged, or the
    /// bus is not actually connected.
    Timeout,
    /// `WRITE_ENABLE` did not take effect, so a program would have silently done
    /// nothing. Checked because a NOR part accepts the command and ignores it.
    WriteEnableFailed,
    /// An erase or program was requested at an address that is not aligned to its unit.
    Misaligned { addr: u32, unit: u32 },
    /// The JEDEC ID read back as all-zero or all-ones: nothing is responding.
    NotResponding { id: [u8; 3] },
}

/// A chip-select-framed SPI transaction.
///
/// One method rather than separate write/read calls, because the whole exchange has to
/// happen inside a single assertion of chip-select: NOR parts latch the command on the
/// falling edge and abandon it on the rising one.
pub trait SpiDevice {
    type Error;

    /// Send `write`, then clock `read.len()` more bytes in, all within one chip-select.
    fn transfer(&mut self, write: &[u8], read: &mut [u8]) -> Result<(), Self::Error>;
}

/// The JEDEC identity of the attached part.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct JedecId {
    pub manufacturer: u8,
    pub memory_type: u8,
    /// Capacity code: the part is `1 << capacity` bytes for most vendors.
    pub capacity: u8,
}

impl JedecId {
    /// Device size implied by the capacity code, if it is plausible.
    ///
    /// Vendors encode capacity as a log2 byte count. Values outside 16..=32 (64 KB to
    /// 4 GB) are not a real SPI-NOR part and are rejected rather than shifted.
    pub fn size_bytes(&self) -> Option<u32> {
        if (16..=31).contains(&self.capacity) {
            Some(1u32 << self.capacity)
        } else {
            None
        }
    }
}

/// SPI-NOR driver.
pub struct NorFlash<B: SpiDevice> {
    bus: B,
    size: u32,
}

impl<B: SpiDevice> NorFlash<B> {
    /// Wrap a bus, taking the device size on trust.
    pub fn new(bus: B, size: u32) -> Self {
        Self { bus, size }
    }

    /// Wrap a bus and learn the size from the part itself.
    pub fn probe(mut bus: B) -> Result<Self, Error<B::Error>> {
        let id = Self::read_id_on(&mut bus)?;
        // All-zero or all-ones means MISO is stuck, which is what an unconnected or
        // mis-assigned CS pin looks like. Reporting it beats computing a size from it.
        if id == [0, 0, 0] || id == [0xFF, 0xFF, 0xFF] {
            return Err(Error::NotResponding { id });
        }
        let jedec = JedecId {
            manufacturer: id[0],
            memory_type: id[1],
            capacity: id[2],
        };
        let size = jedec.size_bytes().ok_or(Error::NotResponding { id })?;
        Ok(Self { bus, size })
    }

    fn read_id_on(bus: &mut B) -> Result<[u8; 3], Error<B::Error>> {
        let mut id = [0u8; 3];
        bus.transfer(&[cmd::RDID], &mut id).map_err(Error::Bus)?;
        Ok(id)
    }

    pub fn jedec_id(&mut self) -> Result<JedecId, Error<B::Error>> {
        let id = Self::read_id_on(&mut self.bus)?;
        Ok(JedecId {
            manufacturer: id[0],
            memory_type: id[1],
            capacity: id[2],
        })
    }

    pub fn size(&self) -> u32 {
        self.size
    }

    pub fn status(&mut self) -> Result<u8, Error<B::Error>> {
        let mut s = [0u8; 1];
        self.bus
            .transfer(&[cmd::READ_STATUS], &mut s)
            .map_err(Error::Bus)?;
        Ok(s[0])
    }

    pub fn is_busy(&mut self) -> Result<bool, Error<B::Error>> {
        Ok(self.status()? & status::WIP != 0)
    }

    /// Poll until the part reports idle, up to `tries` status reads.
    ///
    /// Bounded rather than looping forever: a NOR part that never clears WIP means the
    /// bus is misconfigured, and a wallet that hangs at boot gives no diagnosis.
    pub fn wait_ready(&mut self, tries: u32) -> Result<(), Error<B::Error>> {
        for _ in 0..tries {
            if !self.is_busy()? {
                return Ok(());
            }
        }
        Err(Error::Timeout)
    }

    fn check_range(&self, addr: u32, len: usize) -> Result<(), Error<B::Error>> {
        let end = addr as u64 + len as u64;
        if end > self.size as u64 {
            return Err(Error::OutOfRange { addr, len });
        }
        Ok(())
    }

    fn addr_bytes(cmd: u8, addr: u32) -> [u8; 1 + ADDR_LEN] {
        [cmd, (addr >> 16) as u8, (addr >> 8) as u8, addr as u8]
    }

    /// Read into `out`.
    pub fn read(&mut self, addr: u32, out: &mut [u8]) -> Result<(), Error<B::Error>> {
        self.check_range(addr, out.len())?;
        if out.is_empty() {
            return Ok(());
        }
        let header = Self::addr_bytes(cmd::READ, addr);
        self.bus.transfer(&header, out).map_err(Error::Bus)
    }

    fn write_enable(&mut self) -> Result<(), Error<B::Error>> {
        self.bus
            .transfer(&[cmd::WRITE_ENABLE], &mut [])
            .map_err(Error::Bus)?;
        // The part accepts WREN and ignores it when write-protected, so a program would
        // silently do nothing. Confirm the latch actually set.
        if self.status()? & status::WEL == 0 {
            return Err(Error::WriteEnableFailed);
        }
        Ok(())
    }

    /// Program bytes into already-erased space.
    ///
    /// Splits at page boundaries: a page program that crosses one wraps to the start of
    /// the *same* page rather than continuing, overwriting what it just wrote.
    ///
    /// Does not erase first. Bits already cleared stay cleared — see the module docs.
    pub fn write(&mut self, addr: u32, data: &[u8]) -> Result<(), Error<B::Error>> {
        self.check_range(addr, data.len())?;

        let mut at = addr;
        let mut rest = data;
        while !rest.is_empty() {
            let page_end = (at / PAGE_SIZE as u32 + 1) * PAGE_SIZE as u32;
            let chunk = rest.len().min((page_end - at) as usize);

            self.write_enable()?;

            // Command, address and data must be one transaction; a chip-select gap
            // between the address and the payload aborts the program.
            let mut frame = [0u8; 1 + ADDR_LEN + PAGE_SIZE];
            frame[..1 + ADDR_LEN].copy_from_slice(&Self::addr_bytes(cmd::PAGE_PROGRAM, at));
            frame[1 + ADDR_LEN..1 + ADDR_LEN + chunk].copy_from_slice(&rest[..chunk]);
            self.bus
                .transfer(&frame[..1 + ADDR_LEN + chunk], &mut [])
                .map_err(Error::Bus)?;

            self.wait_ready(PROGRAM_POLL_LIMIT)?;

            at += chunk as u32;
            rest = &rest[chunk..];
        }
        Ok(())
    }

    /// Erase one 4 KB sector. `addr` must be sector-aligned.
    pub fn erase_sector(&mut self, addr: u32) -> Result<(), Error<B::Error>> {
        self.erase(cmd::SECTOR_ERASE, addr, SECTOR_SIZE, ERASE_POLL_LIMIT)
    }

    /// Erase one 64 KB block. `addr` must be block-aligned.
    pub fn erase_block(&mut self, addr: u32) -> Result<(), Error<B::Error>> {
        self.erase(cmd::BLOCK_ERASE, addr, BLOCK_SIZE, ERASE_POLL_LIMIT * 16)
    }

    fn erase(&mut self, op: u8, addr: u32, unit: u32, tries: u32) -> Result<(), Error<B::Error>> {
        // Misalignment is rejected rather than rounded down: rounding erases a
        // neighbouring sector the caller did not name, and NOR erasure is not undoable.
        if addr % unit != 0 {
            return Err(Error::Misaligned { addr, unit });
        }
        self.check_range(addr, unit as usize)?;
        self.write_enable()?;
        self.bus
            .transfer(&Self::addr_bytes(op, addr), &mut [])
            .map_err(Error::Bus)?;
        self.wait_ready(tries)
    }

    /// True if every byte in the range reads as erased.
    ///
    /// Worth checking before programming: writing into a non-erased region produces the
    /// bitwise AND of old and new, which is not an error the part reports.
    pub fn is_erased(&mut self, addr: u32, len: usize) -> Result<bool, Error<B::Error>> {
        let mut buf = [0u8; 64];
        let mut at = addr;
        let mut left = len;
        while left > 0 {
            let n = left.min(buf.len());
            self.read(at, &mut buf[..n])?;
            if buf[..n].iter().any(|&b| b != ERASED) {
                return Ok(false);
            }
            at += n as u32;
            left -= n;
        }
        Ok(true)
    }

    pub fn bus_mut(&mut self) -> &mut B {
        &mut self.bus
    }
}

/// Status polls allowed for a page program. Typical page programs are under 1 ms.
pub const PROGRAM_POLL_LIMIT: u32 = 100_000;
/// Status polls allowed for a sector erase. Typical sector erases run to ~400 ms.
pub const ERASE_POLL_LIMIT: u32 = 2_000_000;

#[cfg(test)]
mod tests {
    use super::*;

    /// A NOR part faithful enough to catch the mistakes that matter: it enforces
    /// write-enable, models programming as bitwise AND, and wraps page programs at page
    /// boundaries the way real silicon does.
    struct MockNor {
        mem: Vec<u8>,
        wel: bool,
        id: [u8; 3],
        programs: usize,
        erases: usize,
        /// Refuse write-enable, standing in for a write-protected part.
        protected: bool,
    }

    impl MockNor {
        fn new(size: usize) -> Self {
            Self {
                mem: vec![ERASED; size],
                wel: false,
                id: [0xEF, 0x40, 0x15], // Winbond, 2 MB
                programs: 0,
                erases: 0,
                protected: false,
            }
        }
    }

    impl SpiDevice for MockNor {
        type Error = ();

        fn transfer(&mut self, write: &[u8], read: &mut [u8]) -> Result<(), ()> {
            match write[0] {
                cmd::RDID => {
                    read[..3].copy_from_slice(&self.id);
                }
                cmd::READ_STATUS => {
                    // WIP is never set: the mock completes instantly.
                    read[0] = if self.wel { status::WEL } else { 0 };
                }
                cmd::WRITE_ENABLE => {
                    self.wel = !self.protected;
                }
                cmd::WRITE_DISABLE => self.wel = false,
                cmd::READ => {
                    let addr = ((write[1] as usize) << 16)
                        | ((write[2] as usize) << 8)
                        | write[3] as usize;
                    for (i, slot) in read.iter_mut().enumerate() {
                        *slot = self.mem[(addr + i) % self.mem.len()];
                    }
                }
                cmd::PAGE_PROGRAM => {
                    assert!(self.wel, "program without write-enable");
                    let addr = ((write[1] as usize) << 16)
                        | ((write[2] as usize) << 8)
                        | write[3] as usize;
                    let data = &write[4..];
                    let page = addr / PAGE_SIZE;
                    for (i, b) in data.iter().enumerate() {
                        // Real NOR wraps within the page rather than spilling over.
                        let off = (addr + i) % PAGE_SIZE;
                        // And programming only ever clears bits.
                        self.mem[page * PAGE_SIZE + off] &= b;
                    }
                    self.programs += 1;
                    self.wel = false;
                }
                cmd::SECTOR_ERASE | cmd::BLOCK_ERASE => {
                    assert!(self.wel, "erase without write-enable");
                    let unit = if write[0] == cmd::SECTOR_ERASE {
                        SECTOR_SIZE
                    } else {
                        BLOCK_SIZE
                    } as usize;
                    let addr = ((write[1] as usize) << 16)
                        | ((write[2] as usize) << 8)
                        | write[3] as usize;
                    let base = addr - (addr % unit);
                    self.mem[base..base + unit].fill(ERASED);
                    self.erases += 1;
                    self.wel = false;
                }
                other => panic!("unexpected opcode {other:#04x}"),
            }
            Ok(())
        }
    }

    fn flash(size: usize) -> NorFlash<MockNor> {
        NorFlash::new(MockNor::new(size), size as u32)
    }

    #[test]
    fn probe_reads_the_jedec_id_and_derives_the_size() {
        let f = NorFlash::probe(MockNor::new(1 << 21)).unwrap();
        assert_eq!(f.size(), 1 << 21);
    }

    #[test]
    fn a_silent_bus_is_reported_not_interpreted() {
        // All-ones and all-zero are what an unconnected MISO or a wrong CS pin look
        // like. Deriving a size from either would give a plausible, wrong answer.
        for id in [[0u8; 3], [0xFFu8; 3]] {
            let mut m = MockNor::new(1024);
            m.id = id;
            assert!(matches!(
                NorFlash::probe(m),
                Err(Error::NotResponding { .. })
            ));
        }
    }

    #[test]
    fn implausible_capacity_codes_are_rejected() {
        assert_eq!(
            JedecId {
                manufacturer: 0xEF,
                memory_type: 0x40,
                capacity: 0x15
            }
            .size_bytes(),
            Some(1 << 21)
        );
        assert_eq!(
            JedecId {
                manufacturer: 1,
                memory_type: 1,
                capacity: 2
            }
            .size_bytes(),
            None
        );
        assert_eq!(
            JedecId {
                manufacturer: 1,
                memory_type: 1,
                capacity: 40
            }
            .size_bytes(),
            None
        );
    }

    #[test]
    fn read_after_erase_is_all_ones() {
        let mut f = flash(SECTOR_SIZE as usize * 2);
        f.erase_sector(0).unwrap();
        let mut buf = [0u8; 32];
        f.read(0, &mut buf).unwrap();
        assert_eq!(buf, [ERASED; 32]);
        assert!(f.is_erased(0, SECTOR_SIZE as usize).unwrap());
    }

    #[test]
    fn write_then_read_round_trips() {
        let mut f = flash(SECTOR_SIZE as usize);
        let data: Vec<u8> = (0..100).map(|i| i as u8).collect();
        f.write(10, &data).unwrap();
        let mut back = vec![0u8; 100];
        f.read(10, &mut back).unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn a_write_crossing_a_page_boundary_is_split() {
        // Unsplit, the tail wraps to the start of the same page and overwrites the
        // head — silently, with no error from the part.
        let mut f = flash(SECTOR_SIZE as usize);
        let data: Vec<u8> = (0..200).map(|i| (i as u8) ^ 0x5A).collect();
        let start = PAGE_SIZE as u32 - 100; // 100 bytes in this page, 100 in the next
        f.write(start, &data).unwrap();

        let mut back = vec![0u8; 200];
        f.read(start, &mut back).unwrap();
        assert_eq!(back, data, "page boundary was not handled");
        assert_eq!(
            f.bus_mut().programs,
            2,
            "should have issued two page programs"
        );
    }

    #[test]
    fn a_full_page_write_is_one_program() {
        let mut f = flash(SECTOR_SIZE as usize);
        f.write(0, &[0xAA; PAGE_SIZE]).unwrap();
        assert_eq!(f.bus_mut().programs, 1);
    }

    #[test]
    fn programming_only_clears_bits() {
        // The property that makes erase mandatory. A driver that pretends otherwise
        // corrupts data in a way that looks like a bad read.
        let mut f = flash(SECTOR_SIZE as usize);
        f.write(0, &[0b1010_1010]).unwrap();
        f.write(0, &[0b0110_0110]).unwrap();
        let mut b = [0u8; 1];
        f.read(0, &mut b).unwrap();
        assert_eq!(b[0], 0b1010_1010 & 0b0110_0110);
    }

    #[test]
    fn is_erased_detects_a_single_programmed_byte() {
        let mut f = flash(SECTOR_SIZE as usize);
        assert!(f.is_erased(0, SECTOR_SIZE as usize).unwrap());
        f.write(SECTOR_SIZE - 1, &[0x00]).unwrap();
        assert!(!f.is_erased(0, SECTOR_SIZE as usize).unwrap());
    }

    #[test]
    fn erase_requires_alignment() {
        let mut f = flash(SECTOR_SIZE as usize * 4);
        assert_eq!(
            f.erase_sector(1),
            Err(Error::Misaligned {
                addr: 1,
                unit: SECTOR_SIZE
            })
        );
        assert_eq!(
            f.erase_sector(SECTOR_SIZE + 16),
            Err(Error::Misaligned {
                addr: SECTOR_SIZE + 16,
                unit: SECTOR_SIZE
            })
        );
        assert!(f.erase_sector(SECTOR_SIZE).is_ok());
    }

    #[test]
    fn erase_only_touches_its_own_sector() {
        let mut f = flash(SECTOR_SIZE as usize * 3);
        f.write(0, &[0x00; 4]).unwrap();
        f.write(SECTOR_SIZE * 2, &[0x00; 4]).unwrap();

        f.erase_sector(SECTOR_SIZE).unwrap();

        let mut b = [0xFFu8; 4];
        f.read(0, &mut b).unwrap();
        assert_eq!(b, [0x00; 4], "erase clobbered the previous sector");
        f.read(SECTOR_SIZE * 2, &mut b).unwrap();
        assert_eq!(b, [0x00; 4], "erase clobbered the next sector");
    }

    #[test]
    fn operations_past_the_end_are_rejected() {
        let mut f = flash(SECTOR_SIZE as usize);
        let mut buf = [0u8; 8];
        assert!(matches!(
            f.read(SECTOR_SIZE - 4, &mut buf),
            Err(Error::OutOfRange { .. })
        ));
        assert!(matches!(
            f.write(SECTOR_SIZE - 4, &[0; 8]),
            Err(Error::OutOfRange { .. })
        ));
        assert!(matches!(
            f.erase_sector(SECTOR_SIZE),
            Err(Error::OutOfRange { .. })
        ));
    }

    #[test]
    fn range_checks_do_not_overflow() {
        let mut f = flash(SECTOR_SIZE as usize);
        assert!(matches!(
            f.read(u32::MAX - 2, &mut [0u8; 8]),
            Err(Error::OutOfRange { .. })
        ));
    }

    #[test]
    fn a_write_protected_part_is_reported_not_silently_ignored() {
        // NOR accepts WREN and ignores it when protected, so the program appears to
        // succeed and the data is never written.
        let mut f = flash(SECTOR_SIZE as usize);
        f.bus_mut().protected = true;
        assert_eq!(f.write(0, &[1, 2, 3]), Err(Error::WriteEnableFailed));
        assert_eq!(f.erase_sector(0), Err(Error::WriteEnableFailed));
    }

    #[test]
    fn an_empty_read_is_a_no_op() {
        let mut f = flash(SECTOR_SIZE as usize);
        assert!(f.read(0, &mut []).is_ok());
        assert!(f.write(0, &[]).is_ok());
    }

    #[test]
    fn addresses_are_big_endian_three_byte() {
        let frame = NorFlash::<MockNor>::addr_bytes(cmd::READ, 0x01_23_45);
        assert_eq!(frame, [cmd::READ, 0x01, 0x23, 0x45]);
    }

    #[test]
    fn wait_ready_gives_up_rather_than_hanging() {
        struct AlwaysBusy;
        impl SpiDevice for AlwaysBusy {
            type Error = ();
            fn transfer(&mut self, write: &[u8], read: &mut [u8]) -> Result<(), ()> {
                if write[0] == cmd::READ_STATUS {
                    read[0] = status::WIP;
                }
                Ok(())
            }
        }
        let mut f = NorFlash::new(AlwaysBusy, 1024);
        assert_eq!(f.wait_ready(10), Err(Error::Timeout));
    }
}
