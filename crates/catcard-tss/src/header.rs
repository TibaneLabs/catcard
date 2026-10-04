//! Reading a record's or a bundle's fixed header, without decoding its key.
//!
//! Listing the wallets a device keeps, showing one's addresses, or restoring words from
//! bundles needs none of the secret half: the record repeats the public half in its
//! header (`crate::share` has both layouts). [`summary`] and [`bundle_parts`] read those
//! headers and check that the lengths add up, and nothing else. Whether the key inside
//! is sound is for [`ShareRecord::from_bytes`](crate::ShareRecord::from_bytes) to say,
//! when it is used.

use alloc::vec::Vec;

use crate::PUBKEY_LEN;
use crate::share::{BUNDLE_MAGIC, DIGEST_LEN, FORMAT, MAX_PATH, RECORD_MAGIC, Reader};

/// What a share record says about its wallet, read from its fixed header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    /// Created together (a DKG), rather than exported from one wallet.
    pub created: bool,
    pub member: u8,
    pub n: u8,
    pub t: u8,
    /// The wallet's public key: the joint key, or an exported wallet's account key.
    pub joint_public: [u8; PUBKEY_LEN],
    pub chain_code: [u8; 32],
    /// Of the joint key (created), or of the master the account is under (exported).
    pub fingerprint: [u8; 4],
    /// From that master to the wallet key; empty when created together.
    pub path: Vec<u32>,
    /// The digest of the record's current pair cache; `None` when it names none.
    pub cache_digest: Option<[u8; DIGEST_LEN]>,
}

/// A record's header, after checking that the record is as long as it says.
pub fn summary(record: &[u8]) -> Option<Summary> {
    let mut r = Reader(record);
    if r.take(4).ok()? != RECORD_MAGIC || r.byte().ok()? != FORMAT {
        return None;
    }
    let created = match r.byte().ok()? {
        1 => true,
        2 => false,
        _ => return None,
    };
    let (member, n, t) = (r.byte().ok()?, r.byte().ok()?, r.byte().ok()?);
    if crate::share::check_params(n, t).is_err() || member == 0 || member > n {
        return None;
    }
    let joint_public: [u8; PUBKEY_LEN] = r.array().ok()?;
    let chain_code: [u8; 32] = r.array().ok()?;
    let fingerprint: [u8; 4] = r.array().ok()?;
    let depth = usize::from(r.byte().ok()?);
    if depth > MAX_PATH {
        return None;
    }
    let mut path = Vec::with_capacity(depth);
    for _ in 0..depth {
        path.push(u32::from_be_bytes(r.array().ok()?));
    }
    let digest: [u8; DIGEST_LEN] = r.array().ok()?;
    let len = usize::from(u16::from_le_bytes(r.array().ok()?));
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
        cache_digest: (digest != [0; DIGEST_LEN]).then_some(digest),
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
pub fn bundle_parts(bundle: &[u8]) -> Option<BundleParts<'_>> {
    let mut r = Reader(bundle);
    if r.take(4).ok()? != BUNDLE_MAGIC || r.byte().ok()? != FORMAT {
        return None;
    }
    let (member, n, t) = (r.byte().ok()?, r.byte().ok()?, r.byte().ok()?);
    let clen = usize::from(r.byte().ok()?);
    let codex32 = core::str::from_utf8(r.take(clen).ok()?).ok()?;
    let rlen = usize::from(u16::from_le_bytes(r.array().ok()?));
    let record = r.take(rlen).ok()?;
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
