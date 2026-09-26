//! The Coldcard multisig setup file: stock's own text format for a wallet.
//!
//! Older than descriptors and still what every Coldcard writes as its "Coldcard Export",
//! so the other cosigners of a wallet made on a stock device hand us one of these. It is
//! a handful of `Key: value` lines and then one line per cosigner:
//!
//! ```text
//! # Coldcard Multisig setup file (exported from 0F056943)
//! #
//! Name: Home vault
//! Policy: 2 of 3
//! Format: P2WSH
//!
//! Derivation: m/48h/0h/0h/2h
//!
//! 0F056943: xpub6E...
//! 11223344: xpub6F...
//! AABBCCDD: xpub6G...
//! ```
//!
//! Source: hw-reference/wallet-export-formats.md §"Format J1" [C]. The header comment, the
//! order of the lines, the blank lines and the omission of `Format:` for P2SH are all part
//! of the format, because stock's own reader is one of the readers.
//!
//! # What is fixed by the format
//!
//! - **Sorted.** A setup file has no way to say `multi` rather than `sortedmulti`, and stock
//!   only writes one for a BIP-67 wallet; so a file read here is always a sorted wallet.
//! - **One derivation per run of keys.** `Derivation:` applies to every key line after it
//!   until the next `Derivation:`; a shared path prints once. A key before any derivation
//!   line has no origin, and is refused rather than given one.
//! - **The count is the policy's.** `Policy: M of N` says how many keys the file must
//!   hold, and a file with more or fewer is a different wallet from the one its writer
//!   announced -- refused, rather than read as whatever N happens to be.

use core::fmt::Write as _;

use super::{Buf, Cosigner, Error, Kind, MAX_COSIGNERS, MAX_ORIGIN, Multisig, overflow};
use crate::bip32::serialize::MAX_BASE58_LEN;
use crate::bip32::{ExtendedPubKey, HARDENED_OFFSET};

/// A setup file, read.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Parsed<'a> {
    /// The `Name:` line, trimmed; empty if there was none.
    pub name: &'a str,
    pub wallet: Multisig,
}

/// Why a setup file could not be read.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum TextError {
    /// No `Policy:` line, or one that is not `M of N`.
    BadPolicy,
    /// A `Format:` value this does not know.
    BadFormat,
    /// A `Derivation:` line that is not a path.
    BadDerivation,
    /// A key line before any `Derivation:` line.
    NoDerivation,
    /// A key line whose fingerprint or xpub does not read.
    BadKey { at: usize },
    /// The file held `got` keys where `Policy:` promised `want`.
    KeyCount { want: usize, got: usize },
    /// The keys read, but do not make a wallet (a duplicate, a bad threshold, ...).
    Wallet(Error),
}

/// Whether `text` has the shape of a setup file: a `Policy:` line and at least one key
/// line. For deciding what arrived; [`parse`] decides whether it is any good.
pub fn looks_like(text: &str) -> bool {
    let mut policy = false;
    let mut key = false;
    for line in text.lines().map(str::trim) {
        if line.starts_with("Policy:") {
            policy = true;
        } else if split_key_line(line).is_some() {
            key = true;
        }
    }
    policy && key
}

/// Read a setup file.
pub fn parse(text: &str) -> Result<Parsed<'_>, TextError> {
    let mut name = "";
    let mut policy: Option<(u8, usize)> = None;
    let mut kind = Kind::P2sh;
    let mut origin: Option<([u32; MAX_ORIGIN], usize)> = None;
    let mut keys: [Option<Cosigner>; MAX_COSIGNERS] = [None; MAX_COSIGNERS];
    let mut got = 0usize;

    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(v) = line.strip_prefix("Name:") {
            name = v.trim();
        } else if let Some(v) = line.strip_prefix("Policy:") {
            policy = Some(parse_policy(v.trim()).ok_or(TextError::BadPolicy)?);
        } else if let Some(v) = line.strip_prefix("Format:") {
            kind = parse_format(v.trim()).ok_or(TextError::BadFormat)?;
        } else if let Some(v) = line.strip_prefix("Derivation:") {
            origin = Some(parse_path(v.trim()).ok_or(TextError::BadDerivation)?);
        } else if let Some((fp_text, xpub_text)) = split_key_line(line) {
            let at = got;
            let bad = TextError::BadKey { at };
            if got == MAX_COSIGNERS {
                return Err(TextError::Wallet(Error::CosignerCount { n: got + 1 }));
            }
            let (origin, origin_len) = origin.ok_or(TextError::NoDerivation)?;
            let fingerprint = parse_fingerprint(fp_text).ok_or(bad)?;
            let xpub = xpub_from_str(xpub_text).map_err(|_| bad)?;
            keys[got] = Some(Cosigner {
                fingerprint,
                origin,
                origin_len,
                xpub,
            });
            got += 1;
        }
        // Anything else -- a line this version does not know -- is skipped. The policy's
        // count is what catches a key line so mangled it was not recognised as one.
    }

    let (m, want) = policy.ok_or(TextError::BadPolicy)?;
    if got != want {
        return Err(TextError::KeyCount { want, got });
    }
    let mut cosigners = [Cosigner {
        fingerprint: [0; 4],
        origin: [0; MAX_ORIGIN],
        origin_len: 0,
        xpub: keys[0].ok_or(TextError::KeyCount { want, got: 0 })?.xpub,
    }; MAX_COSIGNERS];
    for (slot, key) in cosigners.iter_mut().zip(keys.iter()) {
        if let Some(c) = key {
            *slot = *c;
        }
    }
    let wallet = Multisig::new(m, &cosigners[..got], kind, true).map_err(TextError::Wallet)?;
    Ok(Parsed { name, wallet })
}

/// Write `wallet` as a setup file, under `name`, announced as exported from `ours`.
///
/// `ours` is this device's master fingerprint, which goes in the header comment whether
/// or not this device is a cosigner: it says who wrote the file, not who is in it.
///
/// Source: hw-reference/wallet-export-formats.md §"Format J1" [C].
pub fn write(name: &str, wallet: &Multisig, ours: [u8; 4], out: &mut [u8]) -> Result<usize, Error> {
    let mut buf = Buf { out, len: 0 };
    let [a, b, c, d] = ours;
    write!(
        buf,
        "# Coldcard Multisig setup file (exported from {a:02X}{b:02X}{c:02X}{d:02X})\n#\n"
    )
    .map_err(overflow)?;
    write!(
        buf,
        "Name: {name}\nPolicy: {} of {}\n",
        wallet.m,
        wallet.n()
    )
    .map_err(overflow)?;
    // P2SH is the format's default and is not written; the other two are named.
    match wallet.kind {
        Kind::P2sh => {}
        Kind::P2wsh => buf.write_str("Format: P2WSH\n").map_err(overflow)?,
        Kind::P2shP2wsh => buf.write_str("Format: P2SH-P2WSH\n").map_err(overflow)?,
    }
    let mut previous: Option<&[u32]> = None;
    for cosigner in wallet.cosigners() {
        // A derivation line before the first key, and again wherever the path changes;
        // a shared path prints once.
        if previous != Some(cosigner.origin()) {
            buf.write_str("\nDerivation: ").map_err(overflow)?;
            write_path(&mut buf, cosigner.origin())?;
            buf.write_str("\n\n").map_err(overflow)?;
            previous = Some(cosigner.origin());
        }
        let [a, b, c, d] = cosigner.fingerprint;
        write!(buf, "{a:02X}{b:02X}{c:02X}{d:02X}: ").map_err(overflow)?;
        let mut key = [0u8; MAX_BASE58_LEN];
        let n = cosigner.xpub.write_base58(&mut key).map_err(overflow)?;
        buf.write_str(core::str::from_utf8(&key[..n]).map_err(overflow)?)
            .map_err(overflow)?;
        buf.write_char('\n').map_err(overflow)?;
    }
    Ok(buf.len)
}

/// `m/48h/0h/0h/2h`: a path as this firmware writes one, hardened steps marked `h`.
pub fn write_path(out: &mut impl core::fmt::Write, origin: &[u32]) -> Result<(), Error> {
    out.write_char('m').map_err(|_| Error::Overflow)?;
    for &step in origin {
        if step & HARDENED_OFFSET != 0 {
            write!(out, "/{}h", step & !HARDENED_OFFSET).map_err(|_| Error::Overflow)?;
        } else {
            write!(out, "/{step}").map_err(|_| Error::Overflow)?;
        }
    }
    Ok(())
}

/// An extended public key from its Base58, in the classic form **or any SLIP-132 form**.
///
/// Stock writes a cosigner's key in whatever form was recorded on import, and its own
/// `ccxp` files carry `Ypub`/`Zpub` for the BIP-48 legs; so a setup file arrives with any
/// of the five prefixes. The version bytes are the only difference, and they say nothing
/// about the key -- the script form is the wallet's `Format:`, not the key's -- so
/// [`ExtendedPubKey::from_base58`] reads them for the network and drops the form, which
/// is what a setup file wants.
///
/// Source: hw-reference/wallet-export-formats.md §"Chain parameters" [C] for the table,
/// which lives in `bip32::serialize`.
pub fn xpub_from_str(text: &str) -> Result<ExtendedPubKey, crate::bip32::serialize::Error> {
    ExtendedPubKey::from_base58(text)
}

/// `M of N`.
fn parse_policy(text: &str) -> Option<(u8, usize)> {
    let (m, n) = text.split_once(" of ")?;
    let m: u8 = m.trim().parse().ok()?;
    let n: usize = n.trim().parse().ok()?;
    (m > 0 && n > 0 && m as usize <= n && n <= MAX_COSIGNERS).then_some((m, n))
}

/// The `Format:` names, and the one obsolete alias stock still reads.
fn parse_format(text: &str) -> Option<Kind> {
    if text.eq_ignore_ascii_case("P2SH") {
        Some(Kind::P2sh)
    } else if text.eq_ignore_ascii_case("P2WSH") {
        Some(Kind::P2wsh)
    } else if text.eq_ignore_ascii_case("P2SH-P2WSH") || text.eq_ignore_ascii_case("P2WSH-P2SH") {
        Some(Kind::P2shP2wsh)
    } else {
        None
    }
}

/// `m/48h/0h/0h/2h`, `48'/0'/0'/2'`, or `m` alone. Hardened as `h`, `H` or `'`.
pub(super) fn parse_path(text: &str) -> Option<([u32; MAX_ORIGIN], usize)> {
    let rest = text
        .strip_prefix("m/")
        .or_else(|| text.strip_prefix("m"))
        .unwrap_or(text);
    let mut origin = [0u32; MAX_ORIGIN];
    let mut len = 0usize;
    if rest.is_empty() {
        return Some((origin, 0));
    }
    for step in rest.split('/') {
        if len == MAX_ORIGIN {
            return None;
        }
        let (digits, hardened) = match step.strip_suffix(['h', 'H', '\'']) {
            Some(d) => (d, true),
            None => (step, false),
        };
        let index: u32 = digits.parse().ok()?;
        if index >= HARDENED_OFFSET {
            return None;
        }
        origin[len] = if hardened {
            index | HARDENED_OFFSET
        } else {
            index
        };
        len += 1;
    }
    Some((origin, len))
}

/// `0F056943: xpub...` split into its two halves, if the line has that shape.
fn split_key_line(line: &str) -> Option<(&str, &str)> {
    let (fp, key) = line.split_once(':')?;
    let (fp, key) = (fp.trim(), key.trim());
    (fp.len() == 8 && fp.bytes().all(|b| b.is_ascii_hexdigit()) && !key.is_empty())
        .then_some((fp, key))
}

fn parse_fingerprint(text: &str) -> Option<[u8; 4]> {
    if text.len() != 8 {
        return None;
    }
    let mut out = [0u8; 4];
    for (slot, pair) in out.iter_mut().zip(text.as_bytes().chunks(2)) {
        *slot = u8::from_str_radix(core::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}
