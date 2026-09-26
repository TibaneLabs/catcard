//! Saved passphrases: a file on the card that only this seed can open.
//!
//! A BIP-39 passphrase is never stored on the device. Stock offers, as a convenience, to
//! keep one on the microSD card encrypted so it can be typed once and restored later;
//! this is the same convenience in a format of our own. What is saved is the typing, not
//! the wallet: a card without the seed opens nothing, and a seed without the card still
//! has its passphrase in the owner's head.
//!
//! # The key
//!
//! ```text
//! file_key = HMAC-SHA256(key = "CatCard saved passphrase v1", msg = seed entropy)
//! ```
//!
//! over the BIP-39 **entropy** of the wallet the passphrase sits on -- the stored seed's,
//! or a BIP-85 child's or a loaded seed's when one of those is in force -- computed inside
//! the masked region, since the entropy is the wallet. A passphrase only ever applies to
//! words, so the words are what the file is bound to; a device holding an XPRV or a WIF
//! key has no passphrase to save. Two devices with the same words open each other's
//! files, which is the right shape: the file belongs to the seed, not to the silicon.
//!
//! # The file
//!
//! ```text
//! magic   "CATPP1"                                              6 bytes
//! entries, each:
//!   xfp    the fingerprint of the wallet the passphrase opens    4 bytes, in clear
//!   nonce  fresh per entry, from the protocol DRBG                12 bytes
//!   len    the passphrase's length, 1..=100                       1 byte
//!   ct     AES-256-GCM of the passphrase's bytes                  len bytes
//!   tag    GCM tag over ct, with AAD = magic || xfp || len       16 bytes
//! ```
//!
//! The fingerprint is the label: it is what the restore list shows, what the owner wrote
//! down when the wallet was made, and what the restored wallet is checked against. It is
//! authenticated (it is in the AAD) but not hidden -- it is the same value every export
//! of that wallet carries. The passphrase itself is the only secret, and GCM's tag means
//! a byte flipped anywhere in an entry opens nothing rather than opening something else.
//!
//! Entries are appended and removed by rewriting; the file is small (at most sixteen
//! entries, [`FILE_MAX`] bytes) and a card write is a card write.

use purecrypto::cipher::{Aes256, Gcm};
use purecrypto::hash::HmacSha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::KeyWork;

/// The first six bytes of the file.
pub const MAGIC: &[u8; 6] = b"CATPP1";
/// The longest passphrase saved: stock's limit, and the typing screen's.
pub const MAX_PASSPHRASE: usize = 100;
/// The most entries one file holds. A list screen has to show them all by fingerprint.
pub const MAX_ENTRIES: usize = 16;
/// The nonce each entry carries.
pub const NONCE_LEN: usize = 12;
/// The GCM tag.
pub const TAG_LEN: usize = 16;
/// Bytes before the ciphertext in an entry: fingerprint, nonce, length.
const HEAD_LEN: usize = 4 + NONCE_LEN + 1;
/// The most bytes one entry takes.
pub const ENTRY_MAX: usize = HEAD_LEN + MAX_PASSPHRASE + TAG_LEN;
/// The most bytes a file takes, which is the buffer a reader needs.
pub const FILE_MAX: usize = MAGIC.len() + MAX_ENTRIES * ENTRY_MAX;

/// The HMAC key that separates this file's key from everything else derived from the seed.
const DOMAIN: &[u8] = b"CatCard saved passphrase v1";

/// The key a file is sealed under. Wiped when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct FileKey([u8; 32]);

/// Why a file could not be read, written or opened.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Not a saved-passphrase file: the magic is not there.
    BadMagic,
    /// The file already holds [`MAX_ENTRIES`].
    Full,
    /// No entry at that position.
    NoSuchEntry,
    /// The buffer cannot hold the result.
    BufferTooSmall,
    /// A passphrase that cannot be saved: empty, over [`MAX_PASSPHRASE`], or not ASCII
    /// (the only passphrases [`crate::bip39`] stretches).
    BadPassphrase,
    /// The tag did not check: a different seed's key, or a damaged entry.
    WrongKey,
}

/// The key for the file of the wallet whose BIP-39 entropy this is.
///
/// Private-key work: the entropy is the wallet, so it takes the [`KeyWork`] token.
pub fn file_key(entropy: &[u8], _kw: &KeyWork) -> FileKey {
    let mut mac = HmacSha256::new(DOMAIN);
    mac.update(entropy);
    FileKey(mac.finalize())
}

/// One saved passphrase, borrowed from the file it sits in.
#[derive(Copy, Clone)]
pub struct Entry<'a> {
    /// The fingerprint of the wallet the passphrase opens.
    pub xfp: [u8; 4],
    nonce: &'a [u8],
    ct: &'a [u8],
    tag: &'a [u8],
}

impl Entry<'_> {
    /// How many characters the passphrase has.
    pub fn len(&self) -> usize {
        self.ct.len()
    }

    /// Never: an entry holds at least one character.
    pub fn is_empty(&self) -> bool {
        self.ct.is_empty()
    }
}

/// Whether `file` starts as one of these files. An empty buffer does not.
pub fn is_file(file: &[u8]) -> bool {
    file.len() >= MAGIC.len() && &file[..MAGIC.len()] == MAGIC
}

/// The entries in `file`, in order, stopping at the first that is malformed or cut short.
///
/// A file without the magic has no entries, which reads as "nothing saved" rather than
/// an error: a card with some other file under this name is a card with nothing saved.
pub fn entries(file: &[u8]) -> Entries<'_> {
    let at = if is_file(file) {
        MAGIC.len()
    } else {
        file.len()
    };
    Entries { file, at }
}

/// The iterator [`entries`] returns.
pub struct Entries<'a> {
    file: &'a [u8],
    at: usize,
}

impl<'a> Iterator for Entries<'a> {
    type Item = Entry<'a>;

    fn next(&mut self) -> Option<Entry<'a>> {
        let rest = self.file.get(self.at..)?;
        if rest.len() < HEAD_LEN {
            return None;
        }
        let len = rest[HEAD_LEN - 1] as usize;
        if len == 0 || len > MAX_PASSPHRASE {
            return None;
        }
        let total = HEAD_LEN + len + TAG_LEN;
        if rest.len() < total {
            return None;
        }
        let mut xfp = [0u8; 4];
        xfp.copy_from_slice(&rest[..4]);
        let e = Entry {
            xfp,
            nonce: &rest[4..4 + NONCE_LEN],
            ct: &rest[HEAD_LEN..HEAD_LEN + len],
            tag: &rest[HEAD_LEN + len..total],
        };
        self.at += total;
        Some(e)
    }
}

/// The `i`th entry of `file`.
pub fn entry(file: &[u8], i: usize) -> Option<Entry<'_>> {
    entries(file).nth(i)
}

/// How many bytes of `file` the entries occupy, magic included: where the next one goes.
fn used(file: &[u8]) -> usize {
    let mut it = entries(file);
    for _ in it.by_ref() {}
    if is_file(file) { it.at } else { 0 }
}

/// The AAD an entry's tag covers: the magic, the label and the length. Binding the
/// label means an entry cannot be relabelled to look like another wallet's.
fn aad(xfp: &[u8; 4], len: usize) -> [u8; MAGIC.len() + 4 + 1] {
    let mut a = [0u8; MAGIC.len() + 4 + 1];
    a[..MAGIC.len()].copy_from_slice(MAGIC);
    a[MAGIC.len()..MAGIC.len() + 4].copy_from_slice(xfp);
    a[MAGIC.len() + 4] = len as u8;
    a
}

/// Append a passphrase to `file`, whose first `len` bytes are the file so far (zero for a
/// new one), and answer with the new length. The magic is written when the file is new.
///
/// `nonce` must be fresh for every call under one key: from the protocol DRBG, never
/// reused, since GCM under a repeated nonce leaks the XOR of two passphrases.
pub fn append(
    file: &mut [u8],
    len: usize,
    key: &FileKey,
    xfp: [u8; 4],
    nonce: &[u8; NONCE_LEN],
    passphrase: &str,
) -> Result<usize, Error> {
    if passphrase.is_empty() || passphrase.len() > MAX_PASSPHRASE || !passphrase.is_ascii() {
        return Err(Error::BadPassphrase);
    }
    let file_len = len.min(file.len());
    let mut at = if file_len == 0 {
        if file.len() < MAGIC.len() {
            return Err(Error::BufferTooSmall);
        }
        file[..MAGIC.len()].copy_from_slice(MAGIC);
        MAGIC.len()
    } else {
        if !is_file(&file[..file_len]) {
            return Err(Error::BadMagic);
        }
        // Past the entries that are whole; a cut-short tail is overwritten, not kept.
        used(&file[..file_len])
    };
    if entries(&file[..at]).count() >= MAX_ENTRIES {
        return Err(Error::Full);
    }
    let plen = passphrase.len();
    let total = HEAD_LEN + plen + TAG_LEN;
    if file.len() < at + total {
        return Err(Error::BufferTooSmall);
    }
    let out = &mut file[at..at + total];
    out[..4].copy_from_slice(&xfp);
    out[4..4 + NONCE_LEN].copy_from_slice(nonce);
    out[HEAD_LEN - 1] = plen as u8;
    out[HEAD_LEN..HEAD_LEN + plen].copy_from_slice(passphrase.as_bytes());
    let gcm = Gcm::new(Aes256::new(&key.0));
    let tag = gcm
        .try_encrypt(nonce, &aad(&xfp, plen), &mut out[HEAD_LEN..HEAD_LEN + plen])
        .map_err(|_| Error::BadPassphrase)?;
    out[HEAD_LEN + plen..].copy_from_slice(&tag);
    at += total;
    Ok(at)
}

/// Remove the `i`th entry of `file` (its first `len` bytes), closing the gap, and answer
/// with the new length. What was there is overwritten by what followed it, and the tail
/// beyond the new length is zeroed.
pub fn remove(file: &mut [u8], len: usize, i: usize) -> Result<usize, Error> {
    let file_len = len.min(file.len());
    if !is_file(&file[..file_len]) {
        return Err(Error::BadMagic);
    }
    let mut it = entries(&file[..file_len]);
    let mut start = MAGIC.len();
    let mut end = None;
    for (n, e) in it.by_ref().enumerate() {
        let total = HEAD_LEN + e.len() + TAG_LEN;
        if n == i {
            end = Some(start + total);
            break;
        }
        start += total;
    }
    let Some(end) = end else {
        return Err(Error::NoSuchEntry);
    };
    // Only the whole entries count as the file; a cut-short tail goes with the gap.
    let whole = used(&file[..file_len]);
    file.copy_within(end..whole, start);
    let new_len = whole - (end - start);
    file[new_len..whole].zeroize();
    Ok(new_len)
}

/// Decrypt `entry` into `out` and answer with the passphrase's length.
///
/// `out` is the caller's to wipe. A tag that does not check -- the wrong seed's key, or
/// a damaged entry -- gives [`Error::WrongKey`] and leaves `out` holding nothing of use.
pub fn open(entry: &Entry<'_>, key: &FileKey, out: &mut [u8]) -> Result<usize, Error> {
    let len = entry.len();
    if out.len() < len {
        return Err(Error::BufferTooSmall);
    }
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(entry.tag);
    let buf = &mut out[..len];
    buf.copy_from_slice(entry.ct);
    let gcm = Gcm::new(Aes256::new(&key.0));
    if gcm
        .try_decrypt(entry.nonce, &aad(&entry.xfp, len), buf, &tag)
        .is_err()
    {
        buf.zeroize();
        return Err(Error::WrongKey);
    }
    // What was sealed was ASCII; anything else means the file was not made here.
    if !buf.is_ascii() {
        buf.zeroize();
        return Err(Error::WrongKey);
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> FileKey {
        file_key(&[seed; 16], &KeyWork::host())
    }

    fn nonce(n: u8) -> [u8; NONCE_LEN] {
        [n; NONCE_LEN]
    }

    fn text(out: &[u8], n: usize) -> &str {
        core::str::from_utf8(&out[..n]).unwrap()
    }

    /// Three passphrases in, three out, each under its own label.
    #[test]
    fn saved_passphrases_come_back_under_their_labels() {
        let k = key(1);
        let mut file = [0u8; FILE_MAX];
        let mut len = 0;
        for (i, (xfp, pw)) in [
            ([1, 2, 3, 4], "correct horse"),
            ([5, 6, 7, 8], "a"),
            ([9, 9, 9, 9], "x".repeat(MAX_PASSPHRASE).as_str()),
        ]
        .iter()
        .enumerate()
        {
            len = append(&mut file, len, &k, *xfp, &nonce(i as u8), pw).unwrap();
        }
        assert!(is_file(&file[..len]));
        assert_eq!(entries(&file[..len]).count(), 3);
        let mut out = [0u8; MAX_PASSPHRASE];
        for (i, (xfp, pw)) in [
            ([1u8, 2, 3, 4], "correct horse".to_string()),
            ([5, 6, 7, 8], "a".to_string()),
            ([9, 9, 9, 9], "x".repeat(MAX_PASSPHRASE)),
        ]
        .iter()
        .enumerate()
        {
            let e = entry(&file[..len], i).unwrap();
            assert_eq!(e.xfp, *xfp);
            assert_eq!(e.len(), pw.len());
            let n = open(&e, &k, &mut out).unwrap();
            assert_eq!(text(&out, n), pw);
        }
        assert!(entry(&file[..len], 3).is_none());
        // Nothing of the passphrase is in the file in clear.
        assert!(!file[..len].windows(13).any(|w| w == b"correct horse"));
    }

    /// Another seed's key opens nothing: the tag fails and the buffer is left wiped.
    #[test]
    fn another_seeds_key_opens_nothing() {
        let mut file = [0u8; FILE_MAX];
        let len = append(&mut file, 0, &key(1), [1; 4], &nonce(0), "secret").unwrap();
        let e = entry(&file[..len], 0).unwrap();
        let mut out = [0xAAu8; MAX_PASSPHRASE];
        assert_eq!(open(&e, &key(2), &mut out), Err(Error::WrongKey));
        assert!(out[..6].iter().all(|&b| b == 0));
        // And the two keys really are different: the domain is over the entropy.
        assert_ne!(key(1).0, key(2).0);
    }

    /// The label is authenticated: relabelling an entry as another wallet's breaks it,
    /// as does any flipped byte in the ciphertext, the nonce or the tag.
    #[test]
    fn a_flipped_byte_anywhere_in_an_entry_opens_nothing() {
        let k = key(3);
        let mut file = [0u8; FILE_MAX];
        let len = append(&mut file, 0, &k, [1, 2, 3, 4], &nonce(7), "hunter2").unwrap();
        let mut out = [0u8; MAX_PASSPHRASE];
        assert!(open(&entry(&file[..len], 0).unwrap(), &k, &mut out).is_ok());
        for at in MAGIC.len()..len {
            let mut damaged = file;
            damaged[at] ^= 0x01;
            // The length byte is structural: a flipped bit there makes a different
            // (or no) entry rather than a wrong tag, which is also a refusal.
            match entry(&damaged[..len], 0) {
                Some(e) => assert_eq!(open(&e, &k, &mut out), Err(Error::WrongKey), "at {at}"),
                None => assert_eq!(at, MAGIC.len() + HEAD_LEN - 1),
            }
        }
    }

    /// Removing one closes the gap and leaves the others openable and in order.
    #[test]
    fn removing_an_entry_keeps_the_others() {
        let k = key(4);
        let mut file = [0u8; FILE_MAX];
        let mut len = 0;
        for i in 0..3u8 {
            let pw = format!("pass{i}");
            len = append(&mut file, len, &k, [i; 4], &nonce(i), &pw).unwrap();
        }
        let before = len;
        len = remove(&mut file, len, 1).unwrap();
        assert!(len < before);
        assert_eq!(entries(&file[..len]).count(), 2);
        let mut out = [0u8; MAX_PASSPHRASE];
        let e0 = entry(&file[..len], 0).unwrap();
        assert_eq!(e0.xfp, [0; 4]);
        let n = open(&e0, &k, &mut out).unwrap();
        assert_eq!(text(&out, n), "pass0");
        let e1 = entry(&file[..len], 1).unwrap();
        assert_eq!(e1.xfp, [2; 4]);
        let n = open(&e1, &k, &mut out).unwrap();
        assert_eq!(text(&out, n), "pass2");
        // The tail past the new length is zeroed, not left holding the old bytes.
        assert!(file[len..before].iter().all(|&b| b == 0));
        assert_eq!(remove(&mut file, len, 5), Err(Error::NoSuchEntry));
        // Down to none: the magic alone, which lists as empty.
        len = remove(&mut file, len, 0).unwrap();
        len = remove(&mut file, len, 0).unwrap();
        assert_eq!(len, MAGIC.len());
        assert_eq!(entries(&file[..len]).count(), 0);
    }

    /// A file cut short lists the entries that are whole and no more; appending to it
    /// overwrites the broken tail rather than keeping it.
    #[test]
    fn a_cut_short_file_lists_only_whole_entries() {
        let k = key(5);
        let mut file = [0u8; FILE_MAX];
        let mut len = 0;
        len = append(&mut file, len, &k, [1; 4], &nonce(1), "first").unwrap();
        let one = len;
        len = append(&mut file, len, &k, [2; 4], &nonce(2), "second").unwrap();
        let cut = len - 3;
        assert_eq!(entries(&file[..cut]).count(), 1);
        let len = append(&mut file, cut, &k, [3; 4], &nonce(3), "third").unwrap();
        assert_eq!(entries(&file[..len]).count(), 2);
        assert_eq!(entry(&file[..len], 1).unwrap().xfp, [3; 4]);
        assert_eq!(len, one + HEAD_LEN + 5 + TAG_LEN);
    }

    /// What cannot be saved: nothing, too much, non-ASCII, a seventeenth entry, a buffer
    /// with no room, or a file that is not one of these.
    #[test]
    fn what_is_refused() {
        let k = key(6);
        let mut file = [0u8; FILE_MAX];
        for bad in ["", "caf\u{e9}", "x".repeat(MAX_PASSPHRASE + 1).as_str()] {
            assert_eq!(
                append(&mut file, 0, &k, [0; 4], &nonce(0), bad),
                Err(Error::BadPassphrase)
            );
        }
        let mut len = 0;
        for i in 0..MAX_ENTRIES as u8 {
            len = append(&mut file, len, &k, [i; 4], &nonce(i), "p").unwrap();
        }
        assert_eq!(
            append(&mut file, len, &k, [0; 4], &nonce(0), "p"),
            Err(Error::Full)
        );
        let mut small = [0u8; 20];
        assert_eq!(
            append(&mut small, 0, &k, [0; 4], &nonce(0), "p"),
            Err(Error::BufferTooSmall)
        );
        let mut other = *b"not a passphrase file at all";
        let n = other.len();
        assert_eq!(
            append(&mut other, n, &k, [0; 4], &nonce(0), "p"),
            Err(Error::BadMagic)
        );
        assert_eq!(remove(&mut other, n, 0), Err(Error::BadMagic));
        assert_eq!(entries(&other).count(), 0);
        assert!(!is_file(&[]));
    }

    /// The file is bound to the words, not the passphrase or the device: the same
    /// entropy gives the same key, byte for byte.
    #[test]
    fn the_key_is_a_function_of_the_entropy_alone() {
        let kw = KeyWork::host();
        assert_eq!(file_key(&[7; 32], &kw).0, file_key(&[7; 32], &kw).0);
        assert_ne!(file_key(&[7; 32], &kw).0, file_key(&[7; 16], &kw).0);
        // Pinned, so a change of domain string or hash is a change someone has to mean:
        // every file on every card stops opening.
        let k = file_key(b"0123456789abcdef", &kw);
        let mut mac = HmacSha256::new(b"CatCard saved passphrase v1");
        mac.update(b"0123456789abcdef");
        assert_eq!(k.0, mac.finalize());
    }
}
