//! Open a TAPSIGNER card's encrypted backup and find the key inside it.
//!
//! A TAPSIGNER is an NFC signing card holding one BIP-32 key. A phone or a desktop reader
//! asks it for an encrypted **backup**; the card's owner has the 16-byte **Backup
//! Password** printed on the back of it. This device never talks to the card -- it only
//! ever sees the finished blob, off the card slot, an NFC tag or a QR code -- so what is
//! here is the whole of the format: unwrap the text a channel carried, decrypt, check,
//! split.
//! Source: hw-reference/tapsigner-backup-import.md §"What this is", §"The backup" [C]
//!
//! # The format
//!
//! ```text
//! ciphertext = AES-128-CTR(key = backup password, initial counter = 16 zero bytes, plaintext)
//! plaintext  = <xprv> "\n" <derivation path>          (ASCII, no MAC, no padding)
//! ```
//!
//! CTR has no integrity of its own, so the only thing that tells a wrong password from a
//! right one is what comes out: [`decrypt`] runs the acceptance check -- characters `1..4`
//! of the stripped text are `prv` -- and calls a miss [`Error::NoXprv`], which is what a
//! wrong password looks like almost every time. The ~2^-24 of wrong passwords that pass
//! it are caught by the `xprv`'s own Base58 checksum, which the caller's parse runs.
//! Source: hw-reference/tapsigner-backup-import.md §"Encryption", §"Plaintext",
//! §"Decryption and acceptance" [C]
//!
//! # What a channel carries
//!
//! The card slot carries the raw ciphertext as a file; NFC and QR carry it as text. Each
//! channel has its own limits, and they are here so the firmware cannot drift from them:
//! [`FILE_LEN`], [`NFC_RECORD_LEN`] with [`from_nfc`], and [`from_scanned`]'s
//! hex-then-Base64 order.
//! Source: hw-reference/tapsigner-backup-import.md §"Getting it onto the Coldcard" [C]
//!
//! # Every buffer belongs to the caller, and it holds a key
//!
//! There is no allocator here. [`decrypt`] takes the scratch it decrypts into and returns
//! slices of it; the caller zeroizes it, because the decrypted bytes are a private key.

use core::ops::RangeInclusive;

use crate::Error;
use purecrypto::cipher::{Aes128, Ctr};

/// The Backup Password: 16 bytes, an AES-128 key, printed as 32 hex digits.
/// Source: hw-reference/tapsigner-backup-import.md §"Key" [C]
pub const KEY_LEN: usize = 16;

/// The CTR initial counter block: all zero.
/// Source: hw-reference/tapsigner-backup-import.md §"Encryption" [C]
const IV: [u8; 16] = [0u8; 16];

/// How long a backup file on the card may be: the raw ciphertext, `.aes`, 100-160 bytes.
/// Source: hw-reference/tapsigner-backup-import.md §"Getting it onto the Coldcard",
/// microSD row [C]
pub const FILE_LEN: RangeInclusive<usize> = 100..=160;

/// How long an NFC record's payload must be to be taken as the backup: 150-280 bytes of
/// Base64. The first record in range is the backup; the others are skipped.
/// Source: hw-reference/tapsigner-backup-import.md §"Getting it onto the Coldcard",
/// NFC row [C]
pub const NFC_RECORD_LEN: RangeInclusive<usize> = 150..=280;

/// The most ciphertext any channel is held to: what an NFC record's 280 Base64 characters
/// decode to. Real backups are 113-130 bytes. A QR code has no limit of its own in the
/// reference; one decoding to more than this is not a backup a card made, and is refused.
pub const MAX_CIPHERTEXT: usize = *NFC_RECORD_LEN.end() / 4 * 3;

/// Parse a user-entered Backup Password -- exactly 32 hex digits -- into 16 bytes.
///
/// Case-insensitive, and the surrounding whitespace a keypad entry tends to collect is
/// trimmed. Anything else is [`Error::BadBackupKey`] or [`Error::NotHex`] rather than a
/// silently truncated key, so the owner is told which mistake it was.
/// Source: hw-reference/tapsigner-backup-import.md §"Key" [C]
pub fn parse_key(text: &str, out: &mut [u8; KEY_LEN]) -> Result<(), Error> {
    let t = text.trim();
    if t.len() != KEY_LEN * 2 {
        return Err(Error::BadBackupKey);
    }
    unhex(t.as_bytes(), out).map(|_| ())
}

fn hex_nibble(c: u8) -> Result<u8, Error> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(Error::NotHex),
    }
}

/// Hex digits into bytes. An odd count, or anything not a hex digit, is [`Error::NotHex`];
/// more bytes than `out` holds is [`Error::BackupSize`].
fn unhex(text: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    if !text.len().is_multiple_of(2) {
        return Err(Error::NotHex);
    }
    let n = text.len() / 2;
    let out = out.get_mut(..n).ok_or(Error::BackupSize)?;
    for (o, &[hi, lo]) in out.iter_mut().zip(text.as_chunks::<2>().0) {
        *o = (hex_nibble(hi)? << 4) | hex_nibble(lo)?;
    }
    Ok(n)
}

/// The ciphertext out of an NFC record's payload: Base64, ends trimmed.
///
/// The caller has already picked the record by [`NFC_RECORD_LEN`]; this only decodes it.
/// Source: hw-reference/tapsigner-backup-import.md §"Getting it onto the Coldcard",
/// NFC row [C]
pub fn from_nfc(payload: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let text = core::str::from_utf8(payload.trim_ascii()).map_err(|_| Error::NotBackupText)?;
    match outscript::base64::decode_to_slice(text, out) {
        Ok(0) => Err(Error::NotBackupText),
        Ok(n) => Ok(n),
        Err(outscript::base64::Error::BufferTooSmall) => Err(Error::BackupSize),
        Err(_) => Err(Error::NotBackupText),
    }
}

/// The ciphertext out of a scanned QR code: tried as hex first, then as Base64.
///
/// Neither is [`Error::NotBackupText`], which the scan screen answers by asking for
/// another code rather than giving up.
/// Source: hw-reference/tapsigner-backup-import.md §"Getting it onto the Coldcard",
/// QR row [C]
pub fn from_scanned(text: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let t = text.trim_ascii();
    match unhex(t, out) {
        Ok(0) => Err(Error::NotBackupText),
        Ok(n) => Ok(n),
        Err(Error::BackupSize) => Err(Error::BackupSize),
        Err(_) => from_nfc(t, out),
    }
}

/// What a backup opened to. Both borrow the caller's scratch, which holds the key.
#[derive(Debug)]
pub struct Opened<'o> {
    /// Line one: the extended private key, as text, checked no further than `?prv`.
    pub xprv: &'o str,
    /// Line two: the derivation path the card uses. Stock reads it and drops it; this
    /// device shows it ([`Opened::shown_path`]) and stores nothing from it either.
    /// Source: hw-reference/tapsigner-backup-import.md §"Decryption and acceptance"
    /// step 4, §"For an independent implementation" [C]
    pub path: &'o str,
}

impl Opened<'_> {
    /// The card's path, if it is shaped like one -- `m`, then `/`-separated indices with
    /// `h` or `'` marks, short enough for a screen line -- so that text from inside a
    /// backup is never put on the screen as a path when it is not one.
    pub fn shown_path(&self) -> Option<&str> {
        let p = self.path;
        let ok = p.len() <= 40
            && p.starts_with('m')
            && p.bytes()
                .skip(1)
                .all(|b| b.is_ascii_digit() || matches!(b, b'/' | b'h' | b'H' | b'\''));
        ok.then_some(p)
    }
}

/// Decrypt a backup and split it into its two lines.
///
/// The ciphertext is copied into `out` and decrypted there with AES-128-CTR, zero IV.
/// Then, in order:
///
/// 1. Surrounding whitespace is stripped, so a trailing newline is harmless.
/// 2. **Acceptance:** characters `1..4` must be `prv` -- `xprv`, `tprv`, `zprv` and the
///    rest. A miss is [`Error::NoXprv`]: the password is wrong; ask for it again.
/// 3. The text must split on `\n` into exactly two lines; anything else is
///    [`Error::NotTwoLines`], a generic "not a backup", also asked again.
///
/// Each line is trimmed of its own ends, which only lets in a `\r\n` backup a bare split
/// would leave a stray `\r` in. The `xprv` is **not** parsed here: the caller does that,
/// chain from its version prefix, inside the masked region.
/// Source: hw-reference/tapsigner-backup-import.md §"Decryption and acceptance" [C]
pub fn decrypt<'o>(
    ciphertext: &[u8],
    key: &[u8; KEY_LEN],
    out: &'o mut [u8],
) -> Result<Opened<'o>, Error> {
    let n = ciphertext.len();
    if n == 0 || n > MAX_CIPHERTEXT {
        return Err(Error::BackupSize);
    }
    let out = out.get_mut(..n).ok_or(Error::BufferTooSmall)?;
    out.copy_from_slice(ciphertext);
    Ctr::new(Aes128::new(key), &IV).apply_keystream(out);

    let text = out.trim_ascii();
    if text.get(1..4) != Some(b"prv".as_slice()) {
        return Err(Error::NoXprv);
    }
    let text = core::str::from_utf8(text).map_err(|_| Error::NotTwoLines)?;
    let mut lines = text.split('\n');
    match (lines.next(), lines.next(), lines.next()) {
        (Some(xprv), Some(path), None) => Ok(Opened {
            xprv: xprv.trim(),
            path: path.trim(),
        }),
        _ => Err(Error::NotTwoLines),
    }
}

#[cfg(test)]
mod tests;
