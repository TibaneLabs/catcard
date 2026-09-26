//! The encrypted wallet backup: one text file inside a 7-Zip AES-256 archive.
//!
//! A backup is the only thing a Coldcard produces that carries the seed off the device
//! in a form a *different* wallet can read, so both halves of it are wire formats and
//! neither is ours to invent:
//!
//! - [`body`] builds and parses the plaintext — `key = value` lines, JSON on the right
//!   hand side, `#` comments, LF endings.
//! - [`sevenz`] builds and parses the container — a 7z archive holding exactly one
//!   **stored** (uncompressed) file, AES-256-CBC encrypted.
//! - [`kdf`] is 7-Zip's password-to-key derivation, which is expensive on purpose and
//!   therefore sliceable here.
//!
//! # The password is twelve words, and they are the only copy
//!
//! Nothing in this crate chooses the password; the firmware draws the backup words from
//! the **UI DRBG** and shows them to the owner before the file is written. They are not
//! derived from the seed: a backup whose password can be recomputed from the thing it
//! protects is not encrypted, it is obfuscated. That also means a lost word list is a
//! lost backup, which is why the words go on screen first and the write happens second.
//!
//! The password can also be a passphrase the owner typed -- the same derivation, a
//! different string -- or there can be none at all: a **cleartext** archive holds the
//! file behind a lone Copy coder. Which of the three an archive is comes out of its
//! header ([`sevenz::Found`]), so a reader never has to ask.
//!
//! # Every buffer belongs to the caller
//!
//! There is no allocator here. A body is a few kilobytes and an archive a few more, and
//! the firmware knows where that memory should live -- PSRAM on mk4/Q1, the stack on
//! mk3 -- far better than this crate does. So every entry point takes the buffer it
//! writes into, returns a slice of it, and says [`Error::BufferTooSmall`] rather than
//! truncating.
//!
//! **Those buffers hold the seed in plaintext.** [`kdf::Key`] zeroizes itself; a body
//! buffer cannot, because it is borrowed. Callers zeroize it.
//!
//! # What is refused
//!
//! Reading is strict, because the alternative to refusing a malformed backup is
//! restoring half a wallet:
//!
//! - anything compressed (LZMA, LZMA2, BCJ...) -- [`Error::Compressed`]
//! - an archive holding other than exactly one file -- [`Error::NotOneFile`]
//! - a body line that is neither blank, a comment, nor `key = <valid JSON>`
//! - a key derivation the archive asks to be more expensive than [`kdf::MAX_CYCLES_POWER`]

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

pub mod body;
pub mod clone;
pub mod kdf;
pub mod sevenz;
pub mod tapsigner;

pub use kdf::{Key, KeyDerivation};

/// Everything that can go wrong building or reading a backup.
///
/// One enum for both layers: the firmware shows the owner a single "that backup could
/// not be read" screen either way, and splitting it would only make the call sites
/// convert between two types.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Error {
    /// The destination slice cannot hold the result.
    BufferTooSmall,
    /// Input ended in the middle of a structure.
    Truncated,
    /// The first six bytes are not 7-Zip's signature.
    NotSevenZip,
    /// A CRC in the archive does not match the bytes it covers.
    BadChecksum,
    /// The archive is structurally invalid -- a property out of order, a length that
    /// does not fit, a number that overflows.
    BadArchive,
    /// The archive is compressed. Only stored (`Copy`) files are supported.
    Compressed,
    /// The archive mixes encryption with something else: two AES coders in one folder,
    /// or an encrypted header over an unencrypted file. An archive with no encryption
    /// at all is not this -- it is read as [`sevenz::Found::Clear`].
    NotEncrypted,
    /// The archive holds other than exactly one file.
    NotOneFile,
    /// The ciphertext is not a whole number of AES blocks, or is padded by a whole
    /// block or more -- neither is something a 7-Zip writer produces.
    BadCiphertext,
    /// The archive asks for more key-derivation rounds than [`kdf::MAX_CYCLES_POWER`]
    /// allows. Refused rather than run: an attacker-supplied file must not be able to
    /// wedge the device for an hour.
    KdfTooExpensive,
    /// The password is longer than [`kdf::MAX_PASSWORD`].
    PasswordTooLong,
    /// [`KeyDerivation::finish`] was called before every round had run.
    KeyNotReady,
    /// A body line is not blank, a comment, or `key = value`.
    MalformedLine,
    /// The right-hand side of a body line is not exactly one well-formed JSON value.
    NotJson,
    /// A field expected to be a JSON string is not one.
    NotAString,
    /// A field expected to be a plain (escape-free) JSON string contains an escape.
    Escaped,
    /// A field expected to hold hex does not.
    NotHex,
    /// The body is missing the opening marker line.
    NotABackup,
    /// A TAPSIGNER backup key was not the expected 32 hex characters (16 bytes).
    BadBackupKey,
    /// A decrypted TAPSIGNER backup held no recognisable `xprv`/`tprv` master key.
    NoXprv,
    /// A clone file's magic does not match -- it is not a CatCard clone container.
    CloneBadMagic,
    /// The X25519 key agreement for a clone failed: the peer's public key is a
    /// small-order point, whose shared secret an attacker could have forced.
    CloneKeyAgreement,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Error::BufferTooSmall => "buffer too small",
            Error::Truncated => "truncated",
            Error::NotSevenZip => "not a 7-Zip archive",
            Error::BadChecksum => "checksum mismatch",
            Error::BadArchive => "malformed archive",
            Error::Compressed => "compressed archives are not supported",
            Error::NotEncrypted => "archive mixes AES-256 encryption with something else",
            Error::NotOneFile => "archive does not hold exactly one file",
            Error::BadCiphertext => "ciphertext length is not a plausible AES padding",
            Error::KdfTooExpensive => "key derivation too expensive",
            Error::PasswordTooLong => "password too long",
            Error::KeyNotReady => "key derivation is not finished",
            Error::MalformedLine => "malformed line",
            Error::NotJson => "value is not valid JSON",
            Error::NotAString => "value is not a string",
            Error::Escaped => "string contains an escape",
            Error::NotHex => "value is not hex",
            Error::NotABackup => "missing backup marker line",
            Error::BadBackupKey => "backup key is not 32 hex characters",
            Error::NoXprv => "no master key in the decrypted backup",
            Error::CloneBadMagic => "not a CatCard clone file",
            Error::CloneKeyAgreement => "clone key agreement failed",
        };
        f.write_str(s)
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Body in, body out, through the container -- the whole contract in one test.
    ///
    /// Written the way the firmware writes it: the body built where it will be
    /// encrypted, sealed in place, and read back by decrypting over the same bytes. The
    /// two sides are tested apart elsewhere; this is the one that fails if they stop
    /// fitting together.
    #[test]
    fn a_backup_survives_the_whole_round_trip() {
        const PASSWORD: &str = "canary lantern rubble twine";
        // Cheap rounds: the round count is pinned against the reference tool in
        // `kdf`, and repeating half a million SHA-256s here proves nothing new.
        const CYCLES: u8 = 8;

        let mut buf = [0u8; 1024];
        let body_len = {
            let mut w = body::BodyWriter::new(&mut buf[sevenz::BODY_OFFSET..]);
            w.preamble();
            w.section("Private key details: Bitcoin Mainnet");
            w.text("mnemonic", "abandon abandon abandon about");
            w.text("chain", "BTC");
            w.hex("raw_secret", &[0x82; 72]);
            w.section("User preferences");
            w.setting("xfp", "1130522146");
            w.eof();
            w.finish().unwrap().len()
        };

        let key = kdf::derive(PASSWORD, &[], CYCLES).unwrap();
        let archive_len = sevenz::seal_at(
            &mut buf,
            body_len,
            "backup.txt",
            &key,
            &[0x33; 16],
            &[],
            CYCLES,
        )
        .unwrap()
        .len();

        let file = match sevenz::open(&buf[..archive_len]).unwrap() {
            sevenz::Found::File(s) => s,
            other => panic!("we write one encrypted file, got {other:?}"),
        };
        let back = {
            let plain = sevenz::decrypt_in_place(&mut buf[..archive_len], &file, &key).unwrap();
            core::str::from_utf8(plain).unwrap()
        };

        let got = body::scan(back).unwrap();
        assert_eq!(got.details.mnemonic, Some("abandon abandon abandon about"));
        assert_eq!(got.details.raw_secret.map(str::len), Some(144));
        assert_eq!(got.settings, 1);
    }

    /// The other half of that: the wrong words must not produce a *parseable* body.
    /// Without the archive's CRC there would be nothing between a typo and a restore of
    /// whatever the noise happened to decode as.
    #[test]
    fn the_wrong_words_never_reach_the_parser() {
        let mut buf = [0u8; 512];
        let body_len = {
            let mut w = body::BodyWriter::new(&mut buf[sevenz::BODY_OFFSET..]);
            w.preamble();
            w.text("mnemonic", "abandon abandon about");
            w.eof();
            w.finish().unwrap().len()
        };
        let key = kdf::derive("right words here", &[], 8).unwrap();
        let n = sevenz::seal_at(&mut buf, body_len, "b", &key, &[1; 16], &[], 8)
            .unwrap()
            .len();

        let file = match sevenz::open(&buf[..n]).unwrap() {
            sevenz::Found::File(s) => s,
            other => panic!("we write one encrypted file, got {other:?}"),
        };
        let wrong = kdf::derive("wrong words here", &[], 8).unwrap();
        assert_eq!(
            sevenz::decrypt_in_place(&mut buf[..n], &file, &wrong).unwrap_err(),
            Error::BadChecksum
        );
    }

    /// The body the three password modes share, built where the sealer wants it.
    fn build_body(buf: &mut [u8]) -> usize {
        let mut w = body::BodyWriter::new(&mut buf[sevenz::BODY_OFFSET..]);
        w.preamble();
        w.section("Private key details: Bitcoin Mainnet");
        w.text("mnemonic", "abandon abandon abandon about");
        w.text("chain", "BTC");
        w.hex("raw_secret", &[0x82; 72]);
        w.eof();
        w.finish().unwrap().len()
    }

    /// A typed passphrase is the words path with a different string: same derivation,
    /// same container. Non-ASCII on purpose, because the KDF's UTF-16 step is where a
    /// typed password differs from twelve English words.
    #[test]
    fn a_typed_passphrase_backup_round_trips() {
        const PASSPHRASE: &str = "pässwörd — für die Sicherung 42";
        const CYCLES: u8 = 8;

        let mut buf = [0u8; 1024];
        let body_len = build_body(&mut buf);
        let key = kdf::derive(PASSPHRASE, &[], CYCLES).unwrap();
        let n = sevenz::seal_at(
            &mut buf,
            body_len,
            "backup.txt",
            &key,
            &[0x5A; 16],
            &[],
            CYCLES,
        )
        .unwrap()
        .len();

        let file = match sevenz::open(&buf[..n]).unwrap() {
            sevenz::Found::File(s) => s,
            other => panic!("a passphrase backup is one encrypted file, got {other:?}"),
        };
        // The reader derives from what the archive says, as the firmware does on restore.
        let again = kdf::derive(PASSPHRASE, file.salt(), file.cycles_power).unwrap();
        let plain = sevenz::decrypt_in_place(&mut buf[..n], &file, &again).unwrap();
        let got = body::scan(core::str::from_utf8(plain).unwrap()).unwrap();
        assert_eq!(got.details.mnemonic, Some("abandon abandon abandon about"));

        // And the words-shaped password does not open it: a typed passphrase is a
        // different key, not a different spelling of the same one.
        let mut buf = [0u8; 1024];
        let body_len = build_body(&mut buf);
        let n = sevenz::seal_at(
            &mut buf,
            body_len,
            "backup.txt",
            &key,
            &[0x5A; 16],
            &[],
            CYCLES,
        )
        .unwrap()
        .len();
        let wrong = kdf::derive("passwort fur die sicherung 42", &[], CYCLES).unwrap();
        assert_eq!(
            sevenz::decrypt_in_place(&mut buf[..n], &file, &wrong).unwrap_err(),
            Error::BadChecksum
        );
    }

    /// A cleartext backup: no key in, none needed out. The reader recognises it from
    /// the header, so a restore of one never asks for words -- and never derives a key
    /// for a file that has no use for one.
    #[test]
    fn a_cleartext_backup_round_trips_with_no_key() {
        let mut buf = [0u8; 1024];
        let body_len = build_body(&mut buf);
        let n = sevenz::seal_clear_at(&mut buf, body_len, "backup.txt")
            .unwrap()
            .len();

        // The body sits in the file exactly as written: that is what "cleartext" means.
        assert_eq!(&buf[sevenz::BODY_OFFSET..sevenz::BODY_OFFSET + 5], b"# Col");

        let plain = match sevenz::open(&buf[..n]).unwrap() {
            sevenz::Found::Clear(p) => p,
            other => panic!("a cleartext backup is detected, not asked about; got {other:?}"),
        };
        let file = sevenz::extract_in_place(&mut buf[..n], &plain).unwrap();
        let got = body::scan(core::str::from_utf8(file).unwrap()).unwrap();
        assert_eq!(got.details.mnemonic, Some("abandon abandon abandon about"));
        assert_eq!(got.details.raw_secret.map(str::len), Some(144));
    }

    /// The other side of detection: an encrypted backup is never mistaken for a
    /// cleartext one, however it was keyed, so a reader that skips the password screen
    /// on `Clear` cannot be tricked into skipping it by a file that needs one.
    #[test]
    fn an_encrypted_backup_is_never_read_as_cleartext() {
        for (password, cycles) in [("abandon ability able about", 8u8), ("typed 1234", 10)] {
            let mut buf = [0u8; 1024];
            let body_len = build_body(&mut buf);
            let key = kdf::derive(password, &[], cycles).unwrap();
            let n = sevenz::seal_at(&mut buf, body_len, "b", &key, &[1; 16], &[], cycles)
                .unwrap()
                .len();
            assert!(
                matches!(sevenz::open(&buf[..n]).unwrap(), sevenz::Found::File(_)),
                "{password:?} sealed an archive that did not read as encrypted"
            );
        }
    }
}
