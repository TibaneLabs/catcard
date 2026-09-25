//! Decrypt a TAPSIGNER card backup into the master key it carries.
//!
//! A TAPSIGNER, on the `backup` command, hands out an encrypted blob and shows its owner
//! a **backup key** once -- 32 hex characters, 16 bytes. The blob is AES-128-CBC over
//! that key, and inside it is the card's BIP-32 master as an `xprv` text string. Importing
//! it here means decrypting the blob, finding the `xprv`, and handing it to the seed path
//! -- so a TAPSIGNER can be migrated onto this device.
//!
//! # What is confirmed and what is not
//!
//! The cipher (AES-128-CBC), the all-zero IV, and that the plaintext is an `xprv` text are
//! taken from the publicly documented TAPSIGNER/coinkite backup format, **not** measured
//! against a card here. They are tagged `[?]` in `docs/HARDWARE-OPEN-ITEMS.md`: the two
//! things most likely to differ are the block mode (some notes describe CTR) and whether
//! there is framing around the `xprv`. [`decrypt`] tolerates the latter by *searching* for
//! the key rather than assuming its offset; the former would need a card to settle.
//! Source: public TAPSIGNER backup notes / `cktap`. [?]
//!
//! # Every buffer belongs to the caller, and it holds a key
//!
//! There is no allocator here. [`decrypt`] takes the scratch it decrypts into, returns a
//! slice of it, and the caller zeroizes it -- the decrypted bytes are private-key material.

use crate::Error;
use purecrypto::cipher::{Aes128, Cbc};

/// The backup key: 16 bytes, shown to the owner as 32 hex characters.
pub const KEY_LEN: usize = 16;

/// The CBC initialisation vector. All-zero, per the documented format. [?]
const IV: [u8; 16] = [0u8; 16];

/// Parse a user-entered backup key -- exactly 32 hex characters -- into 16 bytes.
///
/// Case-insensitive, and the surrounding whitespace a keypad entry tends to collect is
/// trimmed. Anything else is [`Error::BadBackupKey`] or [`Error::NotHex`] rather than a
/// silently truncated key, because a wrong key decrypts to noise that has no `xprv` in it
/// and the owner should be told which mistake it was.
pub fn parse_key(text: &str, out: &mut [u8; KEY_LEN]) -> Result<(), Error> {
    let t = text.trim();
    if t.len() != KEY_LEN * 2 {
        return Err(Error::BadBackupKey);
    }
    let b = t.as_bytes();
    for (i, o) in out.iter_mut().enumerate() {
        *o = (hex_nibble(b[2 * i])? << 4) | hex_nibble(b[2 * i + 1])?;
    }
    Ok(())
}

fn hex_nibble(c: u8) -> Result<u8, Error> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(Error::NotHex),
    }
}

/// Decrypt a TAPSIGNER backup blob and return the `xprv`/`tprv` master inside it.
///
/// The ciphertext is copied into `out`, decrypted in place with AES-128-CBC under `key`,
/// and searched for a master key. `out` must be at least as long as the ciphertext; the
/// returned string borrows from it, so the caller zeroizes `out` once done with the key.
///
/// A ciphertext that is not a whole number of AES blocks is [`Error::BadCiphertext`], and
/// a decrypt that produced no `xprv` is [`Error::NoXprv`] -- which is what a wrong backup
/// key looks like, since the plaintext is then noise.
pub fn decrypt<'o>(ciphertext: &[u8], key: &[u8; KEY_LEN], out: &'o mut [u8]) -> Result<&'o str, Error> {
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
        return Err(Error::BadCiphertext);
    }
    if out.len() < ciphertext.len() {
        return Err(Error::BufferTooSmall);
    }
    let n = ciphertext.len();
    out[..n].copy_from_slice(ciphertext);
    Cbc::new(Aes128::new(key), &IV)
        .decrypt(&mut out[..n])
        .map_err(|_| Error::BadCiphertext)?;
    find_master(&out[..n]).ok_or(Error::NoXprv)
}

/// The base58 alphabet Bitcoin uses -- no `0`, `O`, `I`, or `l`.
fn is_base58(c: u8) -> bool {
    matches!(c, b'1'..=b'9' | b'A'..=b'H' | b'J'..=b'N' | b'P'..=b'Z' | b'a'..=b'k' | b'm'..=b'z')
}

/// Find an `xprv`/`tprv` string in decrypted plaintext, tolerating framing around it.
///
/// Searches for either version prefix and, from it, takes the run of base58 characters --
/// which stops at the first newline, NUL, PKCS padding byte or any other non-base58 byte.
/// Returns the whole run as text; the seed path is what actually validates it as a key.
pub fn find_master(plain: &[u8]) -> Option<&str> {
    let start = (0..plain.len()).find(|&i| {
        let rest = &plain[i..];
        rest.starts_with(b"xprv") || rest.starts_with(b"tprv")
    })?;
    let end = start + plain[start..].iter().take_while(|&&c| is_base58(c)).count();
    // A bare prefix with no body is not a key.
    if end - start <= 4 {
        return None;
    }
    core::str::from_utf8(&plain[start..end]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use purecrypto::cipher::{Aes128, Cbc};

    /// A key entered as hex round-trips to the 16 bytes the card would encrypt with,
    /// case and stray spaces notwithstanding, and the wrong length is refused.
    #[test]
    fn a_backup_key_parses_from_hex() {
        let mut k = [0u8; KEY_LEN];
        parse_key("000102030405060708090a0b0c0d0e0f", &mut k).unwrap();
        assert_eq!(k, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);

        let mut u = [0u8; KEY_LEN];
        parse_key("  FFEEDDCCBBAA99887766554433221100 ", &mut u).unwrap();
        assert_eq!(u[0], 0xFF);
        assert_eq!(u[15], 0x00);

        assert_eq!(parse_key("00", &mut k).unwrap_err(), Error::BadBackupKey);
        assert_eq!(
            parse_key("zz0102030405060708090a0b0c0d0e0f", &mut k).unwrap_err(),
            Error::NotHex
        );
    }

    /// A known-answer decrypt: build the exact ciphertext a card would (AES-128-CBC, zero
    /// IV, an `xprv` padded with a trailing newline and NULs to a block boundary), then
    /// decrypt it back to that `xprv`. The key math is what the import stands on, so it is
    /// pinned here rather than only exercised through the wrong-key path.
    #[test]
    fn a_tapsigner_backup_decrypts_to_its_xprv() {
        const KEY: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        // A real mainnet master xprv (BIP-32 test vector 1).
        const XPRV: &str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

        // Plaintext = the xprv, a newline, then NUL padding to a whole block.
        let mut plain = [0u8; 128];
        plain[..XPRV.len()].copy_from_slice(XPRV.as_bytes());
        plain[XPRV.len()] = b'\n';
        let block_len = XPRV.len().next_multiple_of(16).max(16) + 16;

        let mut ct = plain;
        Cbc::new(Aes128::new(&KEY), &IV)
            .encrypt(&mut ct[..block_len])
            .unwrap();

        let mut out = [0u8; 128];
        let got = decrypt(&ct[..block_len], &KEY, &mut out).unwrap();
        assert_eq!(got, XPRV);
    }

    /// The wrong key produces noise, and noise has no `xprv` in it: the import must fail,
    /// not hand a scrambled key to the seed path.
    #[test]
    fn the_wrong_key_finds_no_master() {
        const KEY: [u8; 16] = [1; 16];
        let x = b"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        let mut plain = [0u8; 128];
        plain[..x.len()].copy_from_slice(x);
        let block_len = 128;
        let mut ct = plain;
        Cbc::new(Aes128::new(&KEY), &IV)
            .encrypt(&mut ct[..block_len])
            .unwrap();

        let wrong = [2u8; 16];
        let mut out = [0u8; 128];
        assert_eq!(
            decrypt(&ct[..block_len], &wrong, &mut out).unwrap_err(),
            Error::NoXprv
        );
    }

    #[test]
    fn framing_around_the_key_is_tolerated() {
        let framed = b"\x01\x02deadbeefxprv9zzzz\nrest";
        // Not a real key, but the run stops at the newline.
        let got = find_master(framed).unwrap();
        assert_eq!(got, "xprv9zzzz");
        assert!(find_master(b"no key here").is_none());
        assert!(find_master(b"xprv").is_none(), "a bare prefix is not a key");
    }
}
