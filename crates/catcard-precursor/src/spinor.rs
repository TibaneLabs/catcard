//! The SPI NOR flash: erase and program through the gateware's `spinor` command port;
//! reads through the memory-mapped window at `mem::SPIFLASH`.
//!
//! The flash is a Macronix MX66UM1G45G in octal DDR mode, driven by betrusted-soc's
//! `spinor` core. Firmware issues a raw command by writing `cmd_arg` then `command`,
//! and waits for `status.wip` to drop. Program data goes first into a page FIFO through
//! `wdata`, 16 bits per write (DDR moves two bytes per transfer), so lengths are even.
//! `lock_reads` holds memory-mapped reads off while a command sequence is in progress;
//! the sequence ends with an RDSR without it.
//!
//! **This code must not run from flash**: while a write or erase is in progress the
//! memory-mapped window is unreadable. The image runs from SRAM (build.rs), so it doesn't.
//!
//! Sources: Xous `services/spinor/src/main.rs` (command sequences: WREN until WEL, SE4B
//! 0x21, PP4B 0x12 per 256-byte page, RDSR 0x05 with 4 dummy cycles, RDSCUR 0x2B and its
//! P_FAIL/E_FAIL bits, WRDI, the closing RDSR without `lock_reads`, the D-cache flush
//! `0x500F`) [C]; utralib `precursor_pvt.rs` `spinor` field layout [C]; csr.csv
//! `spinor_*` addresses and `memory_region,spiflash` [C].

use crate::csr::{self, mem, reg};

/// Erase granule.
pub const SECTOR: u32 = 4096;
/// Program granule: one PP4B writes within one page.
const PAGE: u32 = 256;

// `command` fields.
const EXEC: u32 = 1 << 1;
const HAS_ARG: u32 = 1 << 10;
const fn code(c: u8) -> u32 {
    (c as u32) << 2
}
const fn dummy(n: u32) -> u32 {
    n << 11
}
const fn words(n: u32) -> u32 {
    n << 16
}
const LOCK_READS: u32 = 1 << 24;

// Status register (RDSR) and security register (RDSCUR) bits, MX66UM1G45G datasheet.
const SR_WIP: u32 = 1 << 0;
const SR_WEL: u32 = 1 << 1;
const SCUR_P_FAIL: u32 = 1 << 5;
const SCUR_E_FAIL: u32 = 1 << 6;

/// Why a flash operation failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The flash reported a program failure (RDSCUR P_FAIL).
    Program,
    /// The flash reported an erase failure (RDSCUR E_FAIL).
    Erase,
    /// An address or length this driver won't take.
    Bad,
    /// What was read back is not what was written.
    Verify,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::Program => "flash program failed",
            Error::Erase => "flash erase failed",
            Error::Bad => "bad flash address",
            Error::Verify => "flash verify failed",
        })
    }
}

fn command(bits: u32, arg: u32) {
    csr::write(reg::SPINOR_CMD_ARG, arg);
    csr::write(reg::SPINOR_COMMAND, EXEC | bits);
    while csr::read(reg::SPINOR_STATUS) & 1 != 0 {}
}

fn rdsr(lock: bool) -> u32 {
    let l = if lock { LOCK_READS } else { 0 };
    command(code(0x05) | dummy(4) | words(1) | HAS_ARG | l, 0);
    csr::read(reg::SPINOR_CMD_RBK_DATA)
}

fn rdscur() -> u32 {
    command(code(0x2B) | dummy(4) | words(1) | HAS_ARG | LOCK_READS, 0);
    csr::read(reg::SPINOR_CMD_RBK_DATA)
}

fn write_enable() {
    loop {
        command(code(0x06) | LOCK_READS, 0);
        if rdsr(true) & SR_WEL != 0 {
            return;
        }
    }
}

fn wait_idle() {
    while rdsr(true) & SR_WIP != 0 {
        crate::wdt::feed();
    }
}

/// WRDI, then the RDSR without `lock_reads` that lets memory-mapped reads through again.
fn finish() {
    while rdsr(true) & SR_WEL != 0 {
        command(code(0x04) | LOCK_READS, 0);
    }
    rdsr(false);
    flush_dcache();
}

/// Drops the D-cache, so reads through the window see what is now in the flash. The
/// VexRiscv data-cache flush instruction, as Xous issues it.
fn flush_dcache() {
    // SAFETY: a cache-maintenance instruction and a fence; no memory is touched.
    unsafe {
        core::arch::asm!(
            ".word 0x500F",
            "nop",
            "nop",
            "nop",
            "nop",
            "fence",
            "nop",
            "nop",
            "nop",
            "nop"
        );
    }
}

fn in_range(addr: u32, len: usize) -> bool {
    (addr as usize)
        .checked_add(len)
        .is_some_and(|end| end <= mem::SPIFLASH_LEN)
}

/// Erases the 4 KiB sector at `addr` (sector-aligned).
pub fn erase_sector(addr: u32) -> Result<(), Error> {
    if !addr.is_multiple_of(SECTOR) || !in_range(addr, SECTOR as usize) {
        return Err(Error::Bad);
    }
    write_enable();
    command(code(0x21) | HAS_ARG | LOCK_READS, addr);
    wait_idle();
    let scur = rdscur();
    finish();
    if scur & SCUR_E_FAIL != 0 {
        return Err(Error::Erase);
    }
    Ok(())
}

/// Programs `data` at `addr` into erased flash. `addr` and `data.len()` even.
pub fn program(addr: u32, data: &[u8]) -> Result<(), Error> {
    if !addr.is_multiple_of(2) || !data.len().is_multiple_of(2) || !in_range(addr, data.len()) {
        return Err(Error::Bad);
    }
    let mut at = addr;
    let mut rest = data;
    let mut result = Ok(());
    while !rest.is_empty() {
        let room = (PAGE - at % PAGE) as usize;
        let (chunk, tail) = rest.split_at(room.min(rest.len()));
        if chunk.chunks(2).any(|w| w != [0xff, 0xff]) {
            write_enable();
            for w in chunk.chunks(2) {
                csr::write(reg::SPINOR_WDATA, u32::from(w[0]) | u32::from(w[1]) << 8);
            }
            command(
                code(0x12) | HAS_ARG | words(chunk.len() as u32 / 2) | LOCK_READS,
                at,
            );
            wait_idle();
            if rdscur() & SCUR_P_FAIL != 0 {
                result = Err(Error::Program);
                break;
            }
        }
        at += chunk.len() as u32;
        rest = tail;
    }
    finish();
    result
}

/// Reads through the memory-mapped window.
pub fn read(addr: u32, out: &mut [u8]) -> Result<(), Error> {
    if !in_range(addr, out.len()) {
        return Err(Error::Bad);
    }
    let base = mem::SPIFLASH + addr as usize;
    for (i, b) in out.iter_mut().enumerate() {
        // SAFETY: inside the flash window (checked above), which is read-only memory
        // with no side effects on read.
        *b = unsafe { core::ptr::read_volatile((base + i) as *const u8) };
    }
    Ok(())
}

/// Erases the sector at `addr`, programs `data` from its start, reads it back.
pub fn rewrite_sector(addr: u32, data: &[u8]) -> Result<(), Error> {
    if data.len() > SECTOR as usize {
        return Err(Error::Bad);
    }
    erase_sector(addr)?;
    program(addr, data)?;
    let mut back = [0u8; 256];
    for (i, want) in data.chunks(256).enumerate() {
        let got = &mut back[..want.len()];
        read(addr + (i * 256) as u32, got)?;
        if got != want {
            return Err(Error::Verify);
        }
    }
    Ok(())
}
