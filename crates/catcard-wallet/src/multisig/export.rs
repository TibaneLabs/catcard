//! The other things a registered wallet is written out as, and the key bundle a cosigner
//! hands round before there is a wallet at all.
//!
//! - [`bitcoin_core`] -- format J3, the `importdescriptors` line for Bitcoin Core.
//! - [`electrum`] -- format K, an Electrum multisig wallet file.
//! - [`ccxp`] -- format L, this device's BIP-45/48 keys for another Coldcard to build a
//!   wallet from; and [`read_ccxp`], the same file read back from a cosigner.
//!
//! The descriptor export (J2) is [`Multisig::write_descriptor`], and the Coldcard text
//! form (J1) is [`super::coldcard`].
//!
//! Source: hw-reference/wallet-export-formats.md §§"Format J3", "Format K", "Format L"
//! [C]. Spelling, key order and whitespace are copied from there: the reference marks the
//! `ccxp` file's layout as authoritative to the byte, because stock writes it by hand
//! rather than through a JSON encoder.

use core::fmt::Write as _;

use super::{Buf, Cosigner, Error, Kind, MAX_ORIGIN, Multisig, overflow};
use crate::bip32::ExtendedPubKey;
use crate::bip32::serialize::{MAX_BASE58_LEN, Slip132};

/// Format J3: Bitcoin Core's `importdescriptors` for a multisig wallet.
///
/// One line: the RPC verb, then a JSON array of the receive and change descriptors, each
/// with its own checksum. `range` is `[0,100]` and `timestamp` is `now`, as stock writes
/// them.
pub fn bitcoin_core(wallet: &Multisig, out: &mut [u8]) -> Result<usize, Error> {
    let mut buf = Buf { out, len: 0 };
    buf.write_str("importdescriptors '[").map_err(overflow)?;
    for chain in [0u32, 1] {
        if chain == 1 {
            buf.write_char(',').map_err(overflow)?;
        }
        buf.write_str("{\"desc\":\"").map_err(overflow)?;
        let n = wallet.write_descriptor_chain(chain, &mut buf.out[buf.len..])?;
        buf.len += n;
        write!(
            buf,
            "\",\"active\":true,\"timestamp\":\"now\",\"internal\":{},\"range\":[0,100]}}",
            chain == 1
        )
        .map_err(overflow)?;
    }
    buf.write_str("]'\n").map_err(overflow)?;
    Ok(buf.len)
}

/// Format K: an Electrum multisig wallet.
///
/// `wallet_type` is `MofN`, and each cosigner is an `x{i}/` keystore whose `xpub` is in
/// the wallet's SLIP-132 form -- `Zpub` for P2WSH, `Ypub` for P2SH-P2WSH, and classic for
/// P2SH -- because Electrum reads the script type off the version bytes.
pub fn electrum(wallet: &Multisig, out: &mut [u8]) -> Result<usize, Error> {
    let mut buf = Buf { out, len: 0 };
    write!(
        buf,
        "{{\"seed_version\":17,\"use_encryption\":false,\"wallet_type\":\"{}of{}\"",
        wallet.m,
        wallet.n()
    )
    .map_err(overflow)?;
    let form = match wallet.kind {
        Kind::P2sh => Slip132::Classic,
        Kind::P2wsh => Slip132::P2wsh,
        Kind::P2shP2wsh => Slip132::P2wshP2sh,
    };
    for (i, c) in wallet.cosigners().iter().enumerate() {
        let [a, b, cc, d] = c.fingerprint;
        // `ckcc_xfp` is the fingerprint's four bytes read as a little-endian number:
        // the value stock stores, written raw, so the two notations name one key.
        let xfp_int = u32::from_le_bytes(c.fingerprint);
        write!(
            buf,
            ",\"x{}/\":{{\"hw_type\":\"coldcard\",\"type\":\"hardware\",\"ckcc_xfp\":{xfp_int},\
             \"label\":\"Coldcard {a:02X}{b:02X}{cc:02X}{d:02X}\",\"derivation\":\"",
            i + 1
        )
        .map_err(overflow)?;
        super::coldcard::write_path(&mut buf, c.origin())?;
        let mut key = [0u8; MAX_BASE58_LEN];
        let n = c.xpub.write_base58_as(form, &mut key).map_err(overflow)?;
        write!(
            buf,
            "\",\"xpub\":\"{}\"}}",
            core::str::from_utf8(&key[..n]).map_err(overflow)?
        )
        .map_err(overflow)?;
    }
    buf.write_char('}').map_err(overflow)?;
    Ok(buf.len)
}

/// This device's keys for the three standard multisig legs, for [`ccxp`].
///
/// `p2sh` is the BIP-45 key at `m/45h`, which has no account level: it is `None` for any
/// account but zero, and the file then carries only the two BIP-48 legs.
pub struct OurKeys<'a> {
    pub fingerprint: [u8; 4],
    pub account: u32,
    /// The SLIP-44 coin type in the BIP-48 paths: 0 on mainnet, 1 otherwise.
    pub coin: u32,
    pub p2sh: Option<&'a ExtendedPubKey>,
    /// `m/48h/{coin}h/{account}h/1h`.
    pub p2sh_p2wsh: &'a ExtendedPubKey,
    /// `m/48h/{coin}h/{account}h/2h`.
    pub p2wsh: &'a ExtendedPubKey,
}

/// Format L: the `ccxp-{xfp}.json` key bundle another Coldcard reads when joining a wallet.
///
/// Hand-written JSON with two-space indents and one member per line, exactly as stock
/// writes it. The BIP-48 keys are SLIP-132 (`Ypub`/`Zpub`); each leg also carries a
/// descriptor *template* with literal `M` and `...` and no checksum, and the BIP-45 leg
/// carries none. `account` and `xfp` are strings.
pub fn ccxp(keys: &OurKeys<'_>, out: &mut [u8]) -> Result<usize, Error> {
    let mut buf = Buf { out, len: 0 };
    let [a, b, c, d] = keys.fingerprint;
    let mut key = [0u8; MAX_BASE58_LEN];

    buf.write_str("{\n").map_err(overflow)?;
    if let Some(p2sh) = keys.p2sh {
        let n = p2sh.write_base58(&mut key).map_err(overflow)?;
        write!(
            buf,
            "  \"p2sh_deriv\": \"m/45h\",\n  \"p2sh\": \"{}\",\n",
            core::str::from_utf8(&key[..n]).map_err(overflow)?
        )
        .map_err(overflow)?;
    }
    for (name, script, xpub, form, open, close) in [
        (
            "p2sh_p2wsh",
            1u32,
            keys.p2sh_p2wsh,
            Slip132::P2wshP2sh,
            "sh(wsh(sortedmulti(M,",
            ")))",
        ),
        (
            "p2wsh",
            2,
            keys.p2wsh,
            Slip132::P2wsh,
            "wsh(sortedmulti(M,",
            "))",
        ),
    ] {
        let path_tail = (keys.coin, keys.account, script);
        write!(
            buf,
            "  \"{name}_deriv\": \"m/48h/{}h/{}h/{}h\",\n",
            path_tail.0, path_tail.1, path_tail.2
        )
        .map_err(overflow)?;
        let n = xpub.write_base58_as(form, &mut key).map_err(overflow)?;
        write!(
            buf,
            "  \"{name}\": \"{}\",\n",
            core::str::from_utf8(&key[..n]).map_err(overflow)?
        )
        .map_err(overflow)?;
        let n = xpub.write_base58(&mut key).map_err(overflow)?;
        write!(
            buf,
            "  \"{name}_desc\": \"{open}[{a:02x}{b:02x}{c:02x}{d:02x}/48h/{}h/{}h/{}h]{}/0/*,...{close}\",\n",
            path_tail.0,
            path_tail.1,
            path_tail.2,
            core::str::from_utf8(&key[..n]).map_err(overflow)?
        )
        .map_err(overflow)?;
    }
    write!(
        buf,
        "  \"account\": \"{}\",\n  \"xfp\": \"{a:02X}{b:02X}{c:02X}{d:02X}\"\n}}\n",
        keys.account
    )
    .map_err(overflow)?;
    Ok(buf.len)
}

/// Why a `ccxp` file could not give a cosigner.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum CcxpError {
    /// No `xfp`, or not eight hex digits.
    NoFingerprint,
    /// The leg for the wanted script form is not in the file. The BIP-45 leg is absent
    /// from any file exported for a non-zero account.
    NoLeg,
    /// The leg's derivation is not a path.
    BadDerivation,
    /// The leg's key does not read.
    BadKey,
}

/// The cosigner a `ccxp` file describes for wallets of `kind`.
///
/// Reads the `{leg}`, `{leg}_deriv` and `xfp` members for the leg that `kind` uses, with
/// the key in whatever SLIP-132 form it was written. Nothing else in the file is looked
/// at: the descriptor templates are for software that wants them, and this wants keys.
pub fn read_ccxp(text: &str, kind: Kind) -> Result<Cosigner, CcxpError> {
    let (leg, deriv_key) = match kind {
        Kind::P2sh => ("p2sh", "p2sh_deriv"),
        Kind::P2wsh => ("p2wsh", "p2wsh_deriv"),
        Kind::P2shP2wsh => ("p2sh_p2wsh", "p2sh_p2wsh_deriv"),
    };
    let xfp = json_str(text, "xfp").ok_or(CcxpError::NoFingerprint)?;
    let fingerprint = parse_fingerprint(xfp).ok_or(CcxpError::NoFingerprint)?;
    let key_text = json_str(text, leg).ok_or(CcxpError::NoLeg)?;
    let deriv = json_str(text, deriv_key).ok_or(CcxpError::NoLeg)?;
    let (origin, origin_len) = parse_origin(deriv).ok_or(CcxpError::BadDerivation)?;
    let xpub = super::coldcard::xpub_from_str(key_text).map_err(|_| CcxpError::BadKey)?;
    Ok(Cosigner {
        fingerprint,
        origin,
        origin_len,
        xpub,
    })
}

/// The string value of `key` in a flat JSON object whose values hold no escapes.
///
/// Enough for a `ccxp` file, whose strings are paths, keys, hex and a number. The key is
/// matched with both its quotes, so `"p2wsh"` is not found inside `"p2sh_p2wsh"`.
fn json_str<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let mut from = 0usize;
    while let Some(at) = text[from..].find('"') {
        let start = from + at;
        let rest = &text[start + 1..];
        let end = rest.find('"')?;
        let found = &rest[..end];
        let after = &rest[end + 1..];
        if found == key {
            let after = after.trim_start();
            let after = after.strip_prefix(':')?.trim_start();
            let after = after.strip_prefix('"')?;
            let end = after.find('"')?;
            return Some(&after[..end]);
        }
        // Skip past the closing quote of this string, and past its value if it was a
        // key, so a value that happens to equal `key` is not read as a key.
        from = start + 1 + end + 1;
        let after_key = after.trim_start();
        if let Some(value) = after_key.strip_prefix(':') {
            let value = value.trim_start();
            if let Some(s) = value.strip_prefix('"') {
                let vend = s.find('"')?;
                from = text.len() - s.len() + vend + 1;
            }
        }
    }
    None
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

/// A `_deriv` path as an origin, through the setup-file path reader.
fn parse_origin(text: &str) -> Option<([u32; MAX_ORIGIN], usize)> {
    super::coldcard::parse_path(text)
}
