//! The sealed seed in flash: one `catcard-sealed` record, kept twice.
//!
//! Two sectors at the top of the stock layout's kernel area -- the half Xous reserves
//! for a backup kernel and updates, empty on the bench unit (checked in its flash dump,
//! 2026-11-05) and never read by CatCard's loader slot or the boot ROM. Source: Xous
//! precursor-hal `board/precursor.rs` (`KERNEL_LOC` 0x98_0000 + `KERNEL_LEN`
//! 0x140_0000 = 0x1D8_0000 = `PDDB_LOC`) [C].
//!
//! A save rewrites slot A, verifies it, then slot B. Power lost part way leaves the
//! other slot whole, holding either the new record or the previous one. A load takes
//! the slots in order; if they differ, the caller tries each.
//!
//! The record is ciphertext; reading it back for verification is harmless. What makes
//! it worth anything is `DS`, which lives in the key ROM, not here.

use alloc::vec::Vec;

use catcard_sealed::{Contents, Cost, Error as SealError, Header, RECORD_LEN};
use zeroize::Zeroizing;

use crate::spinor;

/// Slot A, slot B.
pub const SLOTS: [u32; 2] = [0x01D7_E000, 0x01D7_F000];

/// Argon2id cost for new records. Every Argon2 call has to finish inside the
/// watchdog's shortest period, about 2.5 s (wdt.rs), when a previous firmware armed it.
/// To be calibrated on the device; the record carries its cost, so raising it later
/// needs no format change.
pub const COST: Cost = Cost {
    t: 2,
    m_kib: 2048,
    p: 1,
};

/// The records found, distinct, in slot order. Erased or foreign slots are skipped.
pub fn load() -> Vec<[u8; RECORD_LEN]> {
    let mut found: Vec<[u8; RECORD_LEN]> = Vec::new();
    for &at in &SLOTS {
        let mut rec = [0u8; RECORD_LEN];
        if spinor::read(at, &mut rec).is_err() || Header::parse(&rec).is_err() {
            continue;
        }
        if !found.contains(&rec) {
            found.push(rec);
        }
    }
    found
}

/// Whether a sealed seed is stored.
pub fn present() -> bool {
    !load().is_empty()
}

/// Opens whichever stored record `passphrase` and `ds` open.
pub fn open(passphrase: &[u8], ds: &[u8; 32]) -> Result<Contents, SealError> {
    let recs = load();
    let mut err = SealError::NotARecord;
    for rec in &recs {
        match catcard_sealed::open(rec, passphrase, ds) {
            Ok(c) => return Ok(c),
            Err(e) => err = e,
        }
    }
    Err(err)
}

/// Seals `contents` and writes it to both slots.
pub fn save(contents: &Contents, passphrase: &[u8], ds: &[u8; 32]) -> Result<(), &'static str> {
    let mut fresh = Zeroizing::new([0u8; 28]);
    crate::newseed::random(&mut fresh[..]).map_err(|_| "no randomness")?;
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    salt.copy_from_slice(&fresh[..16]);
    nonce.copy_from_slice(&fresh[16..]);
    let rec = catcard_sealed::seal(contents, passphrase, ds, COST, salt, nonce)
        .map_err(|_| "could not seal")?;
    for &at in &SLOTS {
        spinor::rewrite_sector(at, &rec).map_err(|_| "flash write failed")?;
    }
    Ok(())
}

/// Erases both slots.
pub fn erase() -> Result<(), &'static str> {
    for &at in &SLOTS {
        spinor::erase_sector(at).map_err(|_| "flash erase failed")?;
    }
    Ok(())
}
