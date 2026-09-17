//! The settings blob, in the format stock firmware uses.
//!
//! Everything that is not the seed lives here: which chain, which accounts have been seen,
//! the toggles, the nickname. It matters that this is stock's format and not one of ours,
//! because a device reflashed in either direction should still know its own configuration.
//! Losing it costs nobody their coins -- those follow the seed -- but it costs them every
//! setting they ever chose.
//!
//! # A slot
//!
//! One settings blob is one slot, and a slot is a single AES-256-CTR stream over
//!
//! ```text
//! JSON bytes ‖ zero padding to 4064 ‖ SHA256(that)
//! ```
//!
//! so 4096 bytes in the normal case. The digest is inside the stream, not beside it, and it
//! covers the padding as well as the JSON.
//!
//! # The key, and the counter
//!
//! The key is six SHA-256 calls over the **raw 72-byte secret** as the bootloader returns
//! it -- not the decoded seed ([`hash_key`]). Before login there is no secret, so a small
//! set of settings lives under a key of 32 zero bytes instead.
//!
//! The counter is `pack('<4I', 4, 3, 2, pos)`, where `pos` identifies the slot: the file
//! index on mk4 and later, the byte offset in SPI-NOR on mk3. Baking `pos` into the counter
//! is what stops a slot being copied somewhere else and still decrypting. The counter is
//! then incremented **big-endian** over all 16 bytes, which is the one detail that decrypts
//! the first block correctly and everything after it as rubbish if you get it wrong.
//!
//! Source: hw-reference/settings-nvstore-format.md §2, §3 [C]. The vectors in the tests come
//! from an independent implementation of that description.

use purecrypto::cipher::{Aes256, Ctr};
use purecrypto::hash::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Bytes of a normal slot: 4064 of padded JSON, then the digest.
pub const SLOT_LEN: usize = 4096;
/// Bytes the JSON and its padding occupy.
pub const BODY_LEN: usize = SLOT_LEN - DIGEST_LEN;
/// The trailing SHA-256.
pub const DIGEST_LEN: usize = 32;

/// The three bytes appended at each step of the key schedule. Source: §3 [C]
const PAD: &[u8] = b"pad";

/// The key a settings slot is encrypted under.
///
/// Five SHA-256 rounds that each append `"pad"`, then one plain SHA-256 -- six in total.
/// `raw_secret` is the 72 bytes `gate 18/4` returns, hashed without being decoded.
pub fn hash_key(raw_secret: &[u8]) -> Key {
    let mut a = [0u8; 32];
    let mut first = true;
    for _ in 0..5 {
        let mut h = Sha256::new();
        if first {
            h.update(raw_secret);
            first = false;
        } else {
            h.update(&a);
        }
        h.update(PAD);
        a.copy_from_slice(&h.finalize());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&Sha256::digest(&a));
    a.zeroize();
    Key(key)
}

/// The key used before login, when there is no secret to derive one from: 32 zero bytes.
///
/// Only the handful of settings that have to be readable at the PIN prompt live under it --
/// the nickname, the login countdown, whether the keypad is scrambled. Source: §3 [C]
pub fn prelogin_key() -> Key {
    Key([0u8; 32])
}

/// A settings key. Wiped when dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key([u8; 32]);

impl Key {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The initial counter block for slot `pos`.
///
/// `pack('<4I', 4, 3, 2, pos)`: three little-endian words that are always the same, then
/// the slot's own identifier. Source: §3 [C]
pub fn counter(pos: u32) -> [u8; 16] {
    let mut c = [0u8; 16];
    c[..4].copy_from_slice(&4u32.to_le_bytes());
    c[4..8].copy_from_slice(&3u32.to_le_bytes());
    c[8..12].copy_from_slice(&2u32.to_le_bytes());
    c[12..].copy_from_slice(&pos.to_le_bytes());
    c
}

/// Why a slot could not be read.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Shorter than a digest, so there is nothing to check.
    TooShort,
    /// The digest did not match: the wrong key, the wrong slot, or damaged bytes. Which of
    /// those it is cannot be told apart, and does not matter -- the slot is not usable.
    BadDigest,
    /// The buffer given for the result was too small.
    BufferTooSmall,
}

/// Encrypt and decrypt a slot in place: CTR is its own inverse.
fn crypt(key: &Key, pos: u32, buf: &mut [u8]) {
    let mut ctr = Ctr::new(Aes256::new(key.as_bytes()), &counter(pos));
    ctr.apply_keystream(buf);
}

/// Write `json` into `out` as slot `pos`: padded, digested, encrypted.
///
/// Returns the slot's length, which is [`SLOT_LEN`] unless the JSON is longer than the
/// padding allows, in which case the padding is dropped and the slot grows -- as stock's
/// own code allows.
pub fn seal(json: &[u8], key: &Key, pos: u32, out: &mut [u8]) -> Result<usize, Error> {
    let body = json.len().max(BODY_LEN);
    let total = body + DIGEST_LEN;
    if out.len() < total {
        return Err(Error::BufferTooSmall);
    }
    out[..json.len()].copy_from_slice(json);
    out[json.len()..body].fill(0);
    let digest = Sha256::digest(&out[..body]);
    out[body..total].copy_from_slice(&digest);
    crypt(key, pos, &mut out[..total]);
    Ok(total)
}

/// Decrypt slot `pos` in place and check its digest.
///
/// Returns the JSON's range within `buf`: everything before the padding, found by trusting
/// nothing but the bytes -- the JSON ends at its last `}`.
pub fn open(buf: &mut [u8], key: &Key, pos: u32) -> Result<core::ops::Range<usize>, Error> {
    if buf.len() <= DIGEST_LEN {
        return Err(Error::TooShort);
    }
    crypt(key, pos, buf);
    let body = buf.len() - DIGEST_LEN;
    let digest = Sha256::digest(&buf[..body]);
    if digest.as_slice() != &buf[body..] {
        return Err(Error::BadDigest);
    }
    // The padding is zero bytes after the JSON's closing brace. A slot whose digest checks
    // out but holds no brace is not settings at all.
    let end = buf[..body]
        .iter()
        .rposition(|&b| b == b'}')
        .ok_or(Error::BadDigest)?;
    Ok(0..end + 1)
}

/// Whether a slot's first two bytes decrypt to `{"`, the cheap pre-filter for a scan.
///
/// A slot that fails this is not ours, or not under this key; one that passes still has to
/// have its digest checked. Decrypting two bytes rather than four kilobytes is what makes
/// scanning a hundred slots at the PIN prompt quick. Source: §4 [C]
pub fn looks_like_ours(head: &[u8], key: &Key, pos: u32) -> bool {
    if head.len() < 2 {
        return false;
    }
    let mut two = [head[0], head[1]];
    crypt(key, pos, &mut two);
    two == *b"{\""
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 24-word BIP-39 stash: the marker, 32 bytes of entropy, then the unused tail.
    fn raw_secret() -> [u8; 72] {
        let mut s = [0u8; 72];
        s[0] = 0x82;
        for (i, b) in s[1..33].iter_mut().enumerate() {
            *b = i as u8;
        }
        s
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn the_key_schedule_matches_an_independent_implementation() {
        let key = hash_key(&raw_secret());
        assert_eq!(
            hex(key.as_bytes()),
            "444a1dc38fb0198585d18e67ea0aae0fc16ab361112853274fb6452fd8bc18f9"
        );
        // The pre-login key is fixed, and nothing like a derived one.
        assert_eq!(prelogin_key().as_bytes(), &[0u8; 32]);
        assert_ne!(key.as_bytes(), prelogin_key().as_bytes());
    }

    #[test]
    fn the_counter_is_three_fixed_words_then_the_slot() {
        assert_eq!(hex(&counter(7)), "04000000030000000200000007000000");
        assert_ne!(counter(7), counter(8));
    }

    /// The whole slot, byte for byte, against a reference built with OpenSSL's AES-256-CTR
    /// from the same key and counter. This pins the padding, the digest's placement inside
    /// the stream, and the big-endian counter increment: the bytes at offset 4064 are 254
    /// blocks past the first, so a wrong increment cannot match them.
    #[test]
    fn a_sealed_slot_matches_the_reference_bytes() {
        let key = hash_key(&raw_secret());
        let mut out = [0u8; SLOT_LEN];
        let n = seal(br#"{"_age": 3, "chain": "BTC"}"#, &key, 7, &mut out).unwrap();
        assert_eq!(n, SLOT_LEN);
        assert_eq!(
            hex(&out[..32]),
            "bfa13bd95f781cf1c64d7a6b62ee9a9c3c4061ae0b5a4be4b131256f155159e7"
        );
        assert_eq!(hex(&out[4064..4080]), "45b6feda5a67f04ce7e2e01060d4b3bb");
        assert_eq!(
            hex(&out[SLOT_LEN - 32..]),
            "45b6feda5a67f04ce7e2e01060d4b3bb8d112ac8507611bbfbe1b8f89fec82db"
        );
    }

    #[test]
    fn a_slot_round_trips_and_the_json_comes_back_without_its_padding() {
        let key = hash_key(&raw_secret());
        let json = br#"{"_age": 12, "chain": "BTC", "rz": 8}"#;
        let mut slot = [0u8; SLOT_LEN];
        let n = seal(json, &key, 3, &mut slot).unwrap();
        let range = open(&mut slot[..n], &key, 3).unwrap();
        assert_eq!(&slot[range], json);
    }

    #[test]
    fn a_slot_will_not_open_under_the_wrong_key_or_in_the_wrong_place() {
        let key = hash_key(&raw_secret());
        let mut other_secret = raw_secret();
        other_secret[1] ^= 1;
        let other = hash_key(&other_secret);

        let mut slot = [0u8; SLOT_LEN];
        let n = seal(br#"{"_age": 1}"#, &key, 5, &mut slot).unwrap();

        let mut copy = slot;
        assert_eq!(open(&mut copy[..n], &other, 5), Err(Error::BadDigest));
        // The slot's position is part of the keystream, so the same bytes moved to another
        // slot do not decrypt -- which is the point of putting `pos` in the counter.
        let mut copy = slot;
        assert_eq!(open(&mut copy[..n], &key, 6), Err(Error::BadDigest));
        // And a single flipped bit anywhere is caught by the digest.
        let mut copy = slot;
        copy[1000] ^= 0x01;
        assert_eq!(open(&mut copy[..n], &key, 5), Err(Error::BadDigest));
    }

    #[test]
    fn the_prefilter_recognises_our_slots_and_only_ours() {
        let key = hash_key(&raw_secret());
        let mut slot = [0u8; SLOT_LEN];
        let n = seal(br#"{"_age": 1}"#, &key, 9, &mut slot).unwrap();
        assert!(looks_like_ours(&slot[..2], &key, 9));
        // Right key, wrong slot; and right slot, wrong key.
        assert!(!looks_like_ours(&slot[..2], &key, 10));
        assert!(!looks_like_ours(&slot[..2], &prelogin_key(), 9));
        // An erased slot reads as 0xff and is not mistaken for ours.
        assert!(!looks_like_ours(&[0xff, 0xff], &key, 9));
        assert_eq!(n, SLOT_LEN);
    }

    #[test]
    fn json_longer_than_the_padding_grows_the_slot_rather_than_being_cut() {
        let key = hash_key(&raw_secret());
        let mut json = Vec::from(br#"{"big": ""#.as_slice());
        json.resize(BODY_LEN + 100, b'x');
        json.extend_from_slice(br#""}"#);
        let mut out = vec![0u8; json.len() + DIGEST_LEN];
        let n = seal(&json, &key, 1, &mut out).unwrap();
        assert_eq!(n, json.len() + DIGEST_LEN);
        let range = open(&mut out[..n], &key, 1).unwrap();
        assert_eq!(&out[range], &json[..]);
        // And a buffer that cannot hold it is refused rather than truncating the settings.
        assert_eq!(
            seal(&json, &key, 1, &mut [0u8; SLOT_LEN]),
            Err(Error::BufferTooSmall)
        );
    }

    #[test]
    fn a_slot_of_zeros_or_garbage_is_not_settings() {
        let key = hash_key(&raw_secret());
        let mut zeros = [0u8; SLOT_LEN];
        assert_eq!(open(&mut zeros, &key, 0), Err(Error::BadDigest));
        let mut short = [0u8; 8];
        assert_eq!(open(&mut short, &key, 0), Err(Error::TooShort));
    }
}
