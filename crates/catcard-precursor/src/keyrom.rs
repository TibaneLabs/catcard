//! The gateware's key ROM: 256 x 32-bit words baked into the (encrypted) bitstream.
//!
//! Register semantics: write a word address to `address`, read `data` (updated on the
//! following clock, so any CSR read after the write sees it). Writing an address to
//! `lockaddr` locks that word until the next reset: it then reads 0, and `lockstat`
//! reads 0 while a locked word is addressed.
//! Source: betrusted-io/gateware keyrom.py (CSRs, the `sync` data path, the lock
//! memory) [C]; csr.csv `keyrom_*` [C].
//!
//! Layout: see docs/PRECURSOR-KEYS.md. **Only public words may be printed.** The
//! secret slots -- the FPGA key, the device secret -- are read through
//! dedicated accessors once the provisioning code exists, and locked after use.

use core::fmt::Write;

use crate::csr::{self, reg};

/// The boot ROM's self-signing public key (0x10..0x18): non-zero means the loader must be
/// signed by this unit's own key. betrusted-boot `KeyLoc::SelfSignPub` [C].
pub const SELFSIGN_PUBKEY: u8 = 0x10;
/// The developer public key (0x18..0x20). betrusted-boot `KeyLoc::DevPub` [C].
pub const DEVELOPER_PUBKEY: u8 = 0x18;
/// Bench marker words written by the stage A patch test (0xf0..0xf4). Unused by Xous
/// and the boot ROM (Xous root-keys `KeyRomLocs`) [C].
pub const TEST_MARKER: u8 = 0xf0;
/// Version / configuration word. Xous root-keys `KeyRomLocs::CONFIG` [C].
pub const CONFIG: u8 = 0xff;

/// One word.
pub fn read(addr: u8) -> u32 {
    csr::write(reg::KEYROM_ADDRESS, u32::from(addr));
    // The data register is clocked from `address`; this read is a separate bus cycle,
    // but read twice so no timing assumption is left.
    let _ = csr::read(reg::KEYROM_DATA);
    csr::read(reg::KEYROM_DATA)
}

/// Locks one word until reset. Irreversible for this boot.
#[allow(dead_code)]
pub fn lock(addr: u8) {
    csr::write(reg::KEYROM_LOCKADDR, u32::from(addr));
}

fn read_into(base: u8, out: &mut [u32]) {
    for (i, w) in out.iter_mut().enumerate() {
        *w = read(base + i as u8);
    }
}

/// Prints the public words: the two signing keys, the test marker and the config word.
pub fn report(out: &mut impl Write) {
    let mut key = [0u32; 8];
    for (name, base) in [
        ("self-sign pubkey", SELFSIGN_PUBKEY),
        ("developer pubkey", DEVELOPER_PUBKEY),
    ] {
        read_into(base, &mut key);
        let _ = write!(out, "keyrom {name:16}: ");
        if key.iter().all(|&w| w == 0) {
            let _ = writeln!(out, "(none)");
        } else {
            for w in key {
                let _ = write!(out, "{w:08x}");
            }
            let _ = writeln!(out);
        }
    }
    let mut marker = [0u32; 4];
    read_into(TEST_MARKER, &mut marker);
    let _ = write!(out, "keyrom test marker      : ");
    for w in marker {
        let _ = write!(out, "{w:08x}");
    }
    let mut text = [0u8; 16];
    for (i, w) in marker.iter().enumerate() {
        text[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
    match core::str::from_utf8(&text) {
        Ok(s) if text.iter().all(|b| b.is_ascii_graphic() || *b == b' ') => {
            let _ = writeln!(out, " \"{s}\"");
        }
        _ => {
            let _ = writeln!(out);
        }
    }
    let _ = writeln!(out, "keyrom config           : {:08x}", read(CONFIG));
}
