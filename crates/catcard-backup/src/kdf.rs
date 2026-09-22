//! 7-Zip's password-to-key derivation, run a slice at a time.
//!
//! # What the format specifies
//!
//! One SHA-256 context is fed `salt ‖ password ‖ counter` once per round, for
//! `1 << cycles_power` rounds, where `counter` is the round number as a little-endian
//! u64 starting at zero. The final digest is the AES-256 key. There is no per-round
//! rehash and no output chaining: it is a single very long message.
//!
//! The password is **UTF-16LE**, with no byte-order mark and no terminator. For the
//! backup words -- ASCII separated by single spaces -- that is each byte followed by
//! `0x00`, but the encoder here is the real one, so a password that is not ASCII still
//! produces the key 7-Zip would.
//!
//! `cycles_power` is 19 in every archive the reference tool writes, which is 524 288
//! rounds over roughly 140 bytes each: about 70 MB of SHA-256. A Cortex-M4 takes tens of
//! seconds over that.
//!
//! Source: observed byte-for-byte against `7z` 17.05 output, cross-checked with the
//! public 7z format notes. The vectors in this module's tests pin it. [C]
//!
//! # Why it is sliced
//!
//! Tens of seconds with the screen frozen looks like a crash, so [`KeyDerivation::step`]
//! runs a caller-chosen number of rounds and returns, exactly as
//! `catcard_wallet::bip39::Stretch` does. **The slice boundary is a round count the
//! caller fixes in advance** -- it does not depend on the password, the salt or any
//! intermediate state, so an observer watching the screen learns the round count, which
//! is in the archive header anyway.
//!
//! # Why the cost is capped
//!
//! `cycles_power` comes out of the *file*. A restore reads it before it can check
//! anything, so a hostile card could ask for `2^62` rounds and the device would grind
//! until its battery died. [`MAX_CYCLES_POWER`] is the refusal: more than that is
//! [`Error::KdfTooExpensive`], not a long wait.

use purecrypto::hash::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Error;

/// The value every 7-Zip writer uses: 2^19 rounds.
///
/// Source: `props[0] & 0x3F` of an archive written by `7z` 17.05. [C]
pub const DEFAULT_CYCLES_POWER: u8 = 19;

/// The most expensive derivation this crate will run: 2^24 rounds.
///
/// Thirty-two times the standard cost, which is minutes rather than hours on this
/// hardware. Anything above it is refused rather than attempted; see the module docs.
pub const MAX_CYCLES_POWER: u8 = 24;

/// The longest password accepted, in UTF-8 bytes.
///
/// Twenty-four eight-letter words joined by single spaces is 215 bytes, and the backup
/// password is never anything else. The buffer is twice this because UTF-16 is at worst
/// two bytes per UTF-8 byte (which happens exactly when the text is ASCII).
pub const MAX_PASSWORD: usize = 224;

/// The longest salt 7-Zip can describe: the two length nibbles cap it at sixteen.
pub const MAX_SALT: usize = 16;

/// An AES-256 key, wiped when it goes out of scope.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key([u8; 32]);

impl Key {
    /// Wraps key bytes that came from somewhere other than this module -- a test vector,
    /// or a key the caller cached across screens.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Key(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for Key {
    /// Prints nothing but the type. A key that can be logged is a key that will be.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Key(..)")
    }
}

/// A derivation in progress.
///
/// Built with [`KeyDerivation::new`], advanced with [`KeyDerivation::step`] until
/// [`KeyDerivation::is_done`], then read with [`KeyDerivation::finish`].
pub struct KeyDerivation {
    sha: Sha256,
    salt: [u8; MAX_SALT],
    salt_len: u8,
    /// The password, already UTF-16LE encoded -- the form that is hashed.
    pw: [u8; MAX_PASSWORD * 2],
    pw_len: u16,
    round: u64,
    rounds: u64,
}

impl core::fmt::Debug for KeyDerivation {
    /// Progress only. The password and the hash state are both key material.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "KeyDerivation({}/{})", self.round, self.rounds)
    }
}

impl Drop for KeyDerivation {
    fn drop(&mut self) {
        self.pw.zeroize();
        self.salt.zeroize();
    }
}

impl KeyDerivation {
    /// Sets up a derivation for `password` over `salt`, `1 << cycles_power` rounds.
    ///
    /// Refuses a salt longer than [`MAX_SALT`], a password longer than [`MAX_PASSWORD`],
    /// and a `cycles_power` above [`MAX_CYCLES_POWER`] -- including 0x3F, which 7-Zip
    /// reads as "the password bytes *are* the key" and which no writer produces.
    pub fn new(password: &str, salt: &[u8], cycles_power: u8) -> Result<Self, Error> {
        if cycles_power > MAX_CYCLES_POWER {
            return Err(Error::KdfTooExpensive);
        }
        if salt.len() > MAX_SALT {
            return Err(Error::BadArchive);
        }
        if password.len() > MAX_PASSWORD {
            return Err(Error::PasswordTooLong);
        }

        let mut kd = KeyDerivation {
            sha: Sha256::new(),
            salt: [0u8; MAX_SALT],
            salt_len: salt.len() as u8,
            pw: [0u8; MAX_PASSWORD * 2],
            pw_len: 0,
            round: 0,
            rounds: 1u64 << cycles_power,
        };
        kd.salt[..salt.len()].copy_from_slice(salt);

        // UTF-16LE, code unit by code unit. `encode_utf16` yields two units for a
        // character outside the basic plane, which is why this is not a byte-doubling
        // loop. Cannot overflow: MAX_PASSWORD UTF-8 bytes are at most MAX_PASSWORD
        // UTF-16 code units.
        let mut n = 0usize;
        let mut units = [0u16; 2];
        for c in password.chars() {
            for unit in c.encode_utf16(&mut units) {
                kd.pw[n..n + 2].copy_from_slice(&unit.to_le_bytes());
                n += 2;
            }
        }
        kd.pw_len = n as u16;
        Ok(kd)
    }

    /// Rounds still to run.
    pub fn left(&self) -> u64 {
        self.rounds - self.round
    }

    /// Total rounds this derivation will run.
    pub fn rounds(&self) -> u64 {
        self.rounds
    }

    pub fn is_done(&self) -> bool {
        self.round == self.rounds
    }

    /// Runs up to `rounds` more rounds. Returns `true` once every round has run.
    ///
    /// `rounds` is the caller's slice size and must not be computed from anything
    /// secret; see the module docs.
    pub fn step(&mut self, rounds: u32) -> bool {
        let salt = &self.salt[..self.salt_len as usize];
        let pw = &self.pw[..self.pw_len as usize];
        let end = self.rounds.min(self.round + u64::from(rounds));
        while self.round < end {
            self.sha.update(salt);
            self.sha.update(pw);
            self.sha.update(&self.round.to_le_bytes());
            self.round += 1;
        }
        self.is_done()
    }

    /// Runs every remaining round in one go. Only for the host, where nothing is
    /// waiting on a screen.
    pub fn run(&mut self) {
        while !self.step(u32::MAX) {}
    }

    /// The derived key.
    ///
    /// Refuses before the last round, because a key from a half-finished hash is not a
    /// weaker key, it is a different one -- and the only symptom would be a backup that
    /// nothing can open.
    pub fn finish(&self) -> Result<Key, Error> {
        if !self.is_done() {
            return Err(Error::KeyNotReady);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(self.sha.clone().finalize().as_ref());
        Ok(Key(key))
    }
}

/// The whole derivation in one call, for the host and for tests.
pub fn derive(password: &str, salt: &[u8], cycles_power: u8) -> Result<Key, Error> {
    let mut kd = KeyDerivation::new(password, salt, cycles_power)?;
    kd.run();
    kd.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The key for the archive the reference `7z` wrote, recomputed here.
    ///
    /// Password "abc def", no salt, 2^19 rounds -- the parameters read out of the coder
    /// properties of a real archive. If this moves, every backup this firmware has ever
    /// written stops opening.
    #[test]
    fn the_reference_parameters_give_the_reference_key() {
        let key = derive("abc def", &[], 19).unwrap();
        assert_eq!(
            key.as_bytes()[..],
            hex("4d48055384a0200d8686f15f48c52b1aa08bcc561a41754aa2a8ec1cccfa4d09")[..]
        );
    }

    /// Slicing is an implementation detail and must not be a second algorithm.
    #[test]
    fn a_sliced_derivation_agrees_with_an_unsliced_one() {
        let whole = derive("hunter two", &[1, 2, 3, 4], 10).unwrap();
        let mut kd = KeyDerivation::new("hunter two", &[1, 2, 3, 4], 10).unwrap();
        let mut slices = 0;
        // Deliberately uneven, and not a divisor of 1024: the tail slice is where an
        // off-by-one in the round counter shows up.
        while !kd.step(97) {
            slices += 1;
            assert!(slices < 100, "step() is not making progress");
        }
        assert_eq!(kd.finish().unwrap().as_bytes(), whole.as_bytes());
    }

    #[test]
    fn a_key_read_before_the_last_round_is_refused() {
        let mut kd = KeyDerivation::new("x", &[], 8).unwrap();
        kd.step(255);
        assert_eq!(kd.left(), 1);
        assert_eq!(kd.finish().unwrap_err(), Error::KeyNotReady);
        assert!(kd.step(1));
        assert!(kd.finish().is_ok());
    }

    /// An archive that asks for an hour of grinding is a denial of service, not a file.
    #[test]
    fn an_absurd_round_count_is_refused_rather_than_attempted() {
        assert_eq!(
            KeyDerivation::new("x", &[], MAX_CYCLES_POWER + 1).unwrap_err(),
            Error::KdfTooExpensive
        );
        // 0x3F is 7-Zip's "the password is the key" escape. Refused too: nothing writes
        // it, and honouring it would mean a backup whose "encryption" is a rename.
        assert_eq!(
            KeyDerivation::new("x", &[], 0x3F).unwrap_err(),
            Error::KdfTooExpensive
        );
    }

    #[test]
    fn an_oversized_password_is_refused_rather_than_truncated() {
        let long = "w".repeat(MAX_PASSWORD + 1);
        assert_eq!(
            KeyDerivation::new(&long, &[], 8).unwrap_err(),
            Error::PasswordTooLong
        );
        let ok = "w".repeat(MAX_PASSWORD);
        assert!(KeyDerivation::new(&ok, &[], 8).is_ok());
    }

    /// The salt is part of the message, so it must change the key.
    #[test]
    fn the_salt_changes_the_key() {
        let a = derive("pw", &[], 8).unwrap();
        let b = derive("pw", &[0u8; 16], 8).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    /// Non-ASCII goes through UTF-16, not through the UTF-8 bytes. The two differ, and
    /// picking the wrong one would only be noticed by someone whose backup will not open.
    #[test]
    fn a_non_ascii_password_is_hashed_as_utf16() {
        // "é" is C3 A9 in UTF-8 and E9 00 in UTF-16LE.
        let mut sha = Sha256::new();
        for round in 0u64..(1 << 4) {
            sha.update(&[0xE9, 0x00]);
            sha.update(&round.to_le_bytes());
        }
        let expect: [u8; 32] = sha.finalize().as_ref().try_into().unwrap();
        assert_eq!(derive("\u{e9}", &[], 4).unwrap().as_bytes()[..], expect[..]);
    }

    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }
}
