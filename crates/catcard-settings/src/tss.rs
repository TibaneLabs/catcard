//! Threshold-signing shares kept on the device (docs/TSS.md, "Where things live").
//!
//! # One file per share, sealed
//!
//! A share record is 13 to 55 KB -- far past a settings slot -- so each is a file of its
//! own in the settings volume, beside the slots, as the FIDO passkey file is. The file is
//! sealed the way that one is (`catcard_fido::passkeys`), encrypt-then-MAC:
//!
//! ```text
//! "CTSe" ‖ iv (16) ‖ tag (32) ‖ ct
//! ct  = AES-256-CTR(enc key, iv, share record)
//! tag = HMAC-SHA-256(mac key, "CTSe" ‖ iv ‖ ct), checked in constant time before
//!       anything is decrypted
//! ```
//!
//! The keys come from the **root wallet's settings key** -- the key its settings slots are
//! encrypted under, which is made from the secret the secure element holds -- by
//! HMAC-SHA-256 with a label per use ([`FileKey::new`]). So a share can be read only by
//! the wallet that kept it, and only after that wallet's PIN, like its settings; another
//! wallet on the same device sees a file it cannot open and leaves it alone.
//!
//! The file's name is `/tss-` and sixteen hex digits of an HMAC, under a third key, over
//! the wallet's public key and the member number ([`file_name`]): one name per share,
//! the same every time, and saying nothing about the wallet without the key.
//!
//! # Reading a record without decoding it
//!
//! A record's DKLs half is tsslib's key, and decoding it costs the device most of its
//! memory (docs/TSS.md, "Memory"). Listing the shares, showing a wallet's addresses or
//! taking a share in from a bundle needs none of it: the record repeats the public half in
//! its fixed header. [`summary`] and [`bundle_parts`] read those headers -- the layouts
//! `catcard_tss` documents for its share record and share bundle (format 1) -- and check
//! that the lengths add up, and nothing else. Whether the secret half is sound is for
//! `catcard_tss` to say, when it is used.

use purecrypto::cipher::{Aes256, Ctr};
use purecrypto::ct::ConstantTimeEq;
use purecrypto::hash::HmacSha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::nvstore::Key;

/// First four bytes of a sealed share file.
pub const MAGIC: [u8; 4] = *b"CTSe";
/// Magic, IV and tag: the bytes before the ciphertext.
pub const HEAD_LEN: usize = 4 + 16 + 32;
/// Every share file's name starts with this ...
pub const NAME_HEAD: &str = "/tss-";
/// ... and ends with this.
pub const NAME_TAIL: &str = ".ts";
/// The longest name [`file_name`] writes.
pub const NAME_LEN: usize = NAME_HEAD.len() + 16 + NAME_TAIL.len();

const DOMAIN: &[u8] = b"CatCard TSS share file v1\0";

/// Why a share file would not open.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Not a sealed share file, or cut short.
    NotOurs,
    /// The tag did not verify: another wallet's file, or a damaged one.
    BadTag,
}

/// The keys a wallet's share files are sealed and named under. Wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct FileKey {
    enc: [u8; 32],
    mac: [u8; 32],
    name: [u8; 32],
}

impl FileKey {
    /// The keys for the wallet whose settings are encrypted under `settings`.
    pub fn new(settings: &Key) -> Self {
        let derive = |label: &[u8]| {
            let mut h = HmacSha256::new(settings.as_bytes());
            h.update(DOMAIN);
            h.update(label);
            h.finalize()
        };
        FileKey {
            enc: derive(b"enc"),
            mac: derive(b"mac"),
            name: derive(b"name"),
        }
    }

    fn tag(&self, file: &[u8]) -> [u8; 32] {
        let mut h = HmacSha256::new(&self.mac);
        h.update(&file[..20]);
        h.update(&file[HEAD_LEN..]);
        h.finalize()
    }
}

/// The name of the file holding member `member`'s share of the wallet whose public key is
/// `joint_public`.
pub fn file_name(key: &FileKey, joint_public: &[u8; 33], member: u8) -> heapless::String<NAME_LEN> {
    use core::fmt::Write as _;
    let mut h = HmacSha256::new(&key.name);
    h.update(joint_public);
    h.update(&[member]);
    let digest = h.finalize();
    let mut out = heapless::String::new();
    let _ = out.push_str(NAME_HEAD);
    for b in &digest[..8] {
        let _ = write!(out, "{b:02x}");
    }
    let _ = out.push_str(NAME_TAIL);
    out
}

/// Whether `name`, as a directory listing gives it (no leading `/`), is a share file's.
pub fn is_share_file(name: &str) -> bool {
    let name = name.strip_prefix('/').unwrap_or(name);
    name.len() == NAME_LEN - 1
        && name.starts_with(&NAME_HEAD[1..])
        && name.ends_with(NAME_TAIL)
        && name[NAME_HEAD.len() - 1..name.len() - NAME_TAIL.len()]
            .bytes()
            .all(|c| c.is_ascii_hexdigit())
}

/// Seal the record at `buf[HEAD_LEN..HEAD_LEN + len]` in place; the file is
/// `buf[..HEAD_LEN + len]`, whose length is returned. `iv` must not repeat under one key:
/// draw it fresh for every write.
pub fn seal(buf: &mut [u8], len: usize, key: &FileKey, iv: &[u8; 16]) -> usize {
    let end = HEAD_LEN + len;
    buf[..4].copy_from_slice(&MAGIC);
    buf[4..20].copy_from_slice(iv);
    Ctr::new(Aes256::new(&key.enc), iv).apply_keystream(&mut buf[HEAD_LEN..end]);
    let tag = key.tag(&buf[..end]);
    buf[20..HEAD_LEN].copy_from_slice(&tag);
    end
}

/// Check and decrypt a sealed file in place. The record is `buf[HEAD_LEN..]` afterwards;
/// nothing is decrypted unless the tag verifies.
pub fn open(buf: &mut [u8], key: &FileKey) -> Result<(), Error> {
    if buf.len() <= HEAD_LEN || buf[..4] != MAGIC {
        return Err(Error::NotOurs);
    }
    let mut tag = key.tag(buf);
    let ok = bool::from(tag[..].ct_eq(&buf[20..HEAD_LEN]));
    tag.zeroize();
    if !ok {
        return Err(Error::BadTag);
    }
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&buf[4..20]);
    Ctr::new(Aes256::new(&key.enc), &iv).apply_keystream(&mut buf[HEAD_LEN..]);
    Ok(())
}

/// Deepest origin path a record carries (`catcard_tss::MAX_PATH`).
pub const MAX_PATH: usize = 10;

/// What a share record says about its wallet, read from its fixed header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    /// Created together (a DKG), rather than exported from one wallet.
    pub created: bool,
    pub member: u8,
    pub n: u8,
    pub t: u8,
    /// The wallet's public key: the joint key, or an exported wallet's account key.
    pub joint_public: [u8; 33],
    pub chain_code: [u8; 32],
    /// Of the joint key (created), or of the master the account is under (exported).
    pub fingerprint: [u8; 4],
    /// From that master to the wallet key; empty when created together.
    pub path: heapless::Vec<u32, MAX_PATH>,
}

/// A record's header, after checking that the record is as long as it says.
///
/// Layout: `catcard_tss` share record format 1 -- magic `CTSk`, version 1, origin, member,
/// n, t, 33-byte key, 32-byte chain code, 4-byte fingerprint, path depth and big-endian
/// steps, then the DKLs share's length (LE) and the share.
pub fn summary(record: &[u8]) -> Option<Summary> {
    let mut r = Reader(record);
    if r.take(4)? != b"CTSk" || r.byte()? != 1 {
        return None;
    }
    let created = match r.byte()? {
        1 => true,
        2 => false,
        _ => return None,
    };
    let (member, n, t) = (r.byte()?, r.byte()?, r.byte()?);
    if !(2..=9).contains(&n) || t < 2 || t > n || member == 0 || member > n {
        return None;
    }
    let joint_public: [u8; 33] = r.take(33)?.try_into().ok()?;
    let chain_code: [u8; 32] = r.take(32)?.try_into().ok()?;
    let fingerprint: [u8; 4] = r.take(4)?.try_into().ok()?;
    let depth = usize::from(r.byte()?);
    let mut path = heapless::Vec::new();
    for _ in 0..depth {
        let step = u32::from_be_bytes(r.take(4)?.try_into().ok()?);
        path.push(step).ok()?;
    }
    let len = u32::from_le_bytes(r.take(4)?.try_into().ok()?) as usize;
    if r.0.len() != len || len == 0 {
        return None;
    }
    Some(Summary {
        created,
        member,
        n,
        t,
        joint_public,
        chain_code,
        fingerprint,
        path,
    })
}

/// The two halves of a share bundle, borrowed from it.
pub struct BundleParts<'a> {
    pub member: u8,
    pub n: u8,
    pub t: u8,
    /// The Codex32 `cw1` share of the wallet's words.
    pub codex32: &'a str,
    /// The share record, as [`summary`] reads it.
    pub record: &'a [u8],
}

/// Split a bundle into its halves, checking only that the lengths add up and that the
/// two halves name the same member of the same split.
///
/// Layout: `catcard_tss` share bundle format 1 -- magic `CTSb`, version 1, member, n, t,
/// Codex32 length and text, record length (LE) and record.
pub fn bundle_parts(bundle: &[u8]) -> Option<BundleParts<'_>> {
    let mut r = Reader(bundle);
    if r.take(4)? != b"CTSb" || r.byte()? != 1 {
        return None;
    }
    let (member, n, t) = (r.byte()?, r.byte()?, r.byte()?);
    let clen = usize::from(r.byte()?);
    let codex32 = core::str::from_utf8(r.take(clen)?).ok()?;
    let rlen = u32::from_le_bytes(r.take(4)?.try_into().ok()?) as usize;
    let record = r.take(rlen)?;
    if !r.0.is_empty() {
        return None;
    }
    let s = summary(record)?;
    if (s.member, s.n, s.t) != (member, n, t) || s.created {
        return None;
    }
    Some(BundleParts {
        member,
        n,
        t,
        codex32,
        record,
    })
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head)
    }
    fn byte(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use catcard_tss::{AccountKey, Entropy, NoEntropy, export};
    use catcard_wallet::KeyWork;
    use std::vec::Vec;

    const KW: KeyWork = KeyWork::host();

    struct Counter(u8);
    impl Entropy for Counter {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), NoEntropy> {
            for b in out {
                self.0 = self.0.wrapping_mul(29).wrapping_add(7);
                *b = self.0;
            }
            Ok(())
        }
    }

    fn key(b: u8) -> FileKey {
        FileKey::new(&crate::nvstore::hash_key(&[b; 72]))
    }

    /// Real bundles, from the crate that writes them: a 2-of-3 split of a 12-word wallet.
    fn bundles() -> Vec<Vec<u8>> {
        let account = AccountKey::new(
            &[0x11; 32],
            &[0x22; 32],
            [0xde, 0xad, 0xbe, 0xef],
            &[0x8000_0054, 0x8000_0000, 0x8000_0000],
        );
        export(&[0x42; 16], &account, 3, 2, &mut Counter(1), &KW)
            .expect("export")
            .iter()
            .map(|b| b.to_bytes(&KW).expect("bytes").to_vec())
            .collect()
    }

    #[test]
    fn a_sealed_file_opens_under_its_key_alone() {
        let record = b"CTSk and then the rest of a record";
        let mut buf = std::vec![0u8; HEAD_LEN + record.len()];
        buf[HEAD_LEN..].copy_from_slice(record);
        let n = seal(&mut buf, record.len(), &key(1), &[9; 16]);
        assert_eq!(n, buf.len());
        assert_ne!(&buf[HEAD_LEN..], &record[..], "not encrypted");

        let mut other = buf.clone();
        assert_eq!(open(&mut other, &key(2)), Err(Error::BadTag));
        for i in [0, 5, 25, HEAD_LEN + 3] {
            let mut bad = buf.clone();
            bad[i] ^= 1;
            assert!(
                open(&mut bad, &key(1)).is_err(),
                "byte {i} changed and still opened"
            );
        }
        assert_eq!(open(&mut buf[..HEAD_LEN], &key(1)), Err(Error::NotOurs));
        open(&mut buf, &key(1)).expect("opens");
        assert_eq!(&buf[HEAD_LEN..], &record[..]);
    }

    #[test]
    fn names_are_per_share_per_wallet_and_recognised() {
        let pk = [2u8; 33];
        let a = file_name(&key(1), &pk, 1);
        assert_eq!(a, file_name(&key(1), &pk, 1));
        assert_ne!(a, file_name(&key(1), &pk, 2));
        assert_ne!(a, file_name(&key(2), &pk, 1));
        assert_eq!(a.len(), NAME_LEN);
        assert!(is_share_file(&a));
        assert!(is_share_file(&a[1..]));
        for bad in [
            "tss-0123.ts",
            "tss-0123456789abcdeg.ts",
            "fido-0123456789abcdef.pk",
        ] {
            assert!(!is_share_file(bad), "{bad}");
        }
    }

    #[test]
    fn a_bundle_splits_into_the_halves_catcard_tss_reads() {
        for (i, bytes) in bundles().iter().enumerate() {
            let parts = bundle_parts(bytes).expect("parts");
            let whole = catcard_tss::ShareBundle::from_bytes(bytes, &KW).expect("bundle");
            assert_eq!(parts.member, whole.member());
            assert_eq!(parts.member as usize, i + 1);
            assert_eq!((parts.n, parts.t), (3, 2));
            assert_eq!(parts.codex32, whole.codex32());
            assert_eq!(parts.record, &whole.record().to_bytes(&KW).unwrap()[..]);

            let s = summary(parts.record).expect("summary");
            let r = whole.record();
            assert!(!s.created);
            assert_eq!((s.member, s.n, s.t), (r.member(), r.n(), r.t()));
            assert_eq!(&s.joint_public, r.joint_public_key());
            assert_eq!(&s.chain_code, r.chain_code());
            assert_eq!(s.fingerprint, r.fingerprint());
            assert_eq!(&s.path[..], r.path());
        }
    }

    #[test]
    fn a_header_that_does_not_add_up_is_refused() {
        let b = bundles().remove(0);
        let record = bundle_parts(&b).unwrap().record.to_vec();
        assert!(summary(&record[..record.len() - 1]).is_none());
        let mut longer = record.clone();
        longer.push(0);
        assert!(summary(&longer).is_none());
        let mut bad_t = record.clone();
        bad_t[8] = 4;
        assert!(summary(&bad_t).is_none());
        // A bundle whose halves name different members.
        let mut swapped = b.clone();
        swapped[5] = 2;
        assert!(bundle_parts(&swapped).is_none());
        assert!(bundle_parts(&b[..b.len() - 1]).is_none());
    }
}
