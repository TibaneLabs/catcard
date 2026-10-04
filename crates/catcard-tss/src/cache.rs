//! The pair cache: a member's pairwise OT states, sealed for one device and one wallet,
//! kept on removable media and named by the digest its record holds.
//!
//! A record keeps the key core (`crate::share`); the pairs -- about 12.7 KB per other
//! member -- live in a file beside the session messages (docs/TSS.md, "Where things
//! live"). That file can be on a card, which anyone can copy, or on the Virtual Disk,
//! which is gone at power off. Neither is a loss: a missing pair is made again with its
//! peer ([`Session::pair_setup`](crate::Session::pair_setup)). What matters is that a
//! cache someone hands the device is the one it wrote, and is useless to anyone else.
//!
//! # The file
//!
//! Sealed the way the FIDO passkey file is (`catcard_fido::passkeys`) and the stage-1
//! share files were: AES-256-CTR, then HMAC-SHA-256 over everything before it,
//! encrypt-then-MAC, the tag checked in constant time before anything is decrypted.
//!
//! ```text
//!  off  len  field
//!    0    4  magic "CTSp"
//!    4    1  format version (1)
//!    5    1  member number
//!    6    1  n
//!    7   16  IV, fresh for every write
//!   23   32  tag = HMAC-SHA-256(mac key, bytes 0..23 ‖ ct)
//!   55    .  ct  = AES-256-CTR(enc key, IV, plaintext)
//!
//! plaintext = count ‖ per pair: peer member ‖ length (u32 LE) ‖ tsslib's binary
//!             encoding of the pair (`PairOTState::write_to`)
//! ```
//!
//! # The keys
//!
//! [`CacheKey::new`]: HMAC-SHA-256 keyed by the device's root secret (on the device, the
//! stored wallet's settings key, made from the secret the secure element holds), over a
//! domain, a label, the wallet's id ([`ShareRecord::wallet_id`]) and the member number.
//! So a cache opens on the device that wrote it, for the wallet and member it was written
//! for, and nowhere else: a copied card holds nothing usable without the device.
//!
//! # Current, not just authentic
//!
//! The record keeps the SHA-256 of the whole file it last wrote ([`digest`]). A cache is
//! taken only if it is that file: an older one -- from before a pair was made again -- or
//! one cut short or changed in any byte is refused before its tag is even computed. The
//! tag then says the file is this device's, for this wallet: a record copied to another
//! device keeps its digest, and the cache on the card still does not open there.

use alloc::vec::Vec;
use catcard_wallet::KeyWork;
use purecrypto::cipher::{Aes256, Ctr};
use purecrypto::ct::ConstantTimeEq;
use purecrypto::hash::{Digest, HmacSha256, Sha256};
use tsslib::dklstss::PairOTState;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::share::{Count, DIGEST_LEN, Exact, Reader, SecretPair, ShareRecord};
use crate::{Error, member_id};

/// First four bytes of a pair cache.
pub const MAGIC: [u8; 4] = *b"CTSp";
/// The cache format this crate writes and reads.
const FORMAT: u8 = 1;
/// Magic, version, member, n and IV: what the tag covers before the ciphertext.
const AUTH_LEN: usize = 4 + 1 + 1 + 1 + 16;
/// Everything before the ciphertext.
pub const HEAD_LEN: usize = AUTH_LEN + 32;

const KEY_DOMAIN: &[u8] = b"CatCard TSS pair cache v1\0";
const DIGEST_DOMAIN: &[u8] = b"CatCard TSS pair cache digest v1\0";

/// Why a pair cache was not taken. Each is a reason to make the pairs again, not a
/// failure: the record is untouched.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CacheRefused {
    /// Not the cache this record last wrote: an older one, another member's or wallet's,
    /// or one cut short or changed. Also every cache, when the record names none.
    NotCurrent,
    /// The record's own file by its digest, but sealed under other keys: written by
    /// another device, for which this record was copied.
    Foreign,
    /// It opened, and inside is not a set of pairs this record can take.
    Damaged,
}

/// The two keys one member's caches of one wallet are sealed under. Wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CacheKey {
    enc: [u8; 32],
    mac: [u8; 32],
}

impl CacheKey {
    /// The keys for `record`'s caches on the device whose root secret is `root`.
    pub fn new(root: &[u8; 32], record: &ShareRecord, _kw: &KeyWork) -> Self {
        let wallet = record.wallet_id();
        let derive = |label: &[u8]| {
            let mut h = HmacSha256::new(root);
            h.update(KEY_DOMAIN);
            h.update(label);
            h.update(&wallet);
            h.update(&[record.member]);
            h.finalize()
        };
        CacheKey {
            enc: derive(b"enc"),
            mac: derive(b"mac"),
        }
    }

    fn tag(&self, file: &[u8]) -> [u8; 32] {
        let mut h = HmacSha256::new(&self.mac);
        h.update(&file[..AUTH_LEN]);
        h.update(&file[HEAD_LEN..]);
        h.finalize()
    }
}

/// The digest a record keeps of the cache file it wrote.
pub fn digest(file: &[u8]) -> [u8; DIGEST_LEN] {
    let mut h = Sha256::new();
    h.update(DIGEST_DOMAIN);
    h.update(file);
    h.finalize()
}

/// The cache's file name: `TSS/<first 8 bytes of the wallet id, hex>-m<member>.pairs`.
/// Members of one wallet, and wallets, have different names, so one card holds several
/// side by side.
pub fn file_name(record: &ShareRecord) -> alloc::string::String {
    use core::fmt::Write as _;
    let id = record.wallet_id();
    let mut s = alloc::string::String::from("TSS/");
    for b in &id[..8] {
        let _ = write!(s, "{b:02x}");
    }
    let _ = write!(s, "-m{}.pairs", record.member);
    s
}

impl ShareRecord {
    /// Seal every pair this record holds into a new cache file, and make it the current
    /// one: the record's digest changes to the new file's, so the record has to be stored
    /// again for the change to last. `iv` must not repeat under one key: draw it fresh.
    ///
    /// Refused when no pair is loaded: there is nothing to keep.
    pub fn write_pair_cache(
        &mut self,
        key: &CacheKey,
        iv: &[u8; 16],
        _kw: &KeyWork,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let peers = self.pairs();
        if peers.is_empty() {
            return Err(Error::State("no pairs to keep"));
        }
        let pairs: Vec<(u8, &PairOTState)> = peers
            .iter()
            .filter_map(|&m| Some((m, self.key.0.pair(&member_id(m))?)))
            .collect();
        let mut body = 1;
        for (_, p) in &pairs {
            let mut c = Count(0);
            p.write_to(&mut c).map_err(|_| Error::Format("pair"))?;
            body += 5 + c.0;
        }
        let mut out = Zeroizing::new(Vec::with_capacity(HEAD_LEN + body));
        {
            let mut w = Exact(&mut out);
            w.put(&MAGIC)?;
            w.put(&[FORMAT, self.member, self.n])?;
            w.put(iv)?;
            w.put(&[0; 32])?;
            w.put(&[pairs.len() as u8])?;
            for (m, p) in &pairs {
                let mut c = Count(0);
                p.write_to(&mut c).map_err(|_| Error::Format("pair"))?;
                w.put(&[*m])?;
                w.put(&(c.0 as u32).to_le_bytes())?;
                p.write_to(&mut w).map_err(|_| Error::Format("pair"))?;
            }
        }
        if out.len() != HEAD_LEN + body {
            return Err(Error::Format("pair cache"));
        }
        Ctr::new(Aes256::new(&key.enc), iv).apply_keystream(&mut out[HEAD_LEN..]);
        let tag = key.tag(&out);
        out[AUTH_LEN..HEAD_LEN].copy_from_slice(&tag);
        self.cache_digest = digest(&out);
        Ok(out)
    }

    /// Take the pairs in `file`, if it is this record's current cache and was sealed
    /// under `key`. Decrypted in place: `file` holds the pairs in the clear afterwards,
    /// and the caller wipes it. Returns the members a pair was loaded with.
    ///
    /// Checked in this order, nothing taken unless all pass: the digest the record
    /// keeps ([`CacheRefused::NotCurrent`]), the header and the tag
    /// ([`CacheRefused::Foreign`]), then every pair inside ([`CacheRefused::Damaged`]).
    pub fn read_pair_cache(
        &mut self,
        file: &mut [u8],
        key: &CacheKey,
        _kw: &KeyWork,
    ) -> Result<Vec<u8>, Error> {
        let refused = |r| Err(Error::Cache(r));
        let Some(current) = self.cache_digest() else {
            return refused(CacheRefused::NotCurrent);
        };
        if !bool::from(digest(file)[..].ct_eq(&current[..])) {
            return refused(CacheRefused::NotCurrent);
        }
        if file.len() <= HEAD_LEN
            || file[..4] != MAGIC
            || file[4] != FORMAT
            || file[5] != self.member
            || file[6] != self.n
        {
            return refused(CacheRefused::Foreign);
        }
        let mut tag = key.tag(file);
        let ok = bool::from(tag[..].ct_eq(&file[AUTH_LEN..HEAD_LEN]));
        tag.zeroize();
        if !ok {
            return refused(CacheRefused::Foreign);
        }
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&file[7..AUTH_LEN]);
        Ctr::new(Aes256::new(&key.enc), &iv).apply_keystream(&mut file[HEAD_LEN..]);

        // Every pair parsed before any is installed: a cache is taken whole or not at all.
        let mut r = Reader(&file[HEAD_LEN..]);
        let parsed = (|| -> Result<Vec<(u8, SecretPair)>, Error> {
            let count = usize::from(r.byte()?);
            let mut out: Vec<(u8, SecretPair)> = Vec::with_capacity(count);
            for _ in 0..count {
                let peer = r.byte()?;
                let len = u32::from_le_bytes(r.array()?) as usize;
                let state =
                    PairOTState::from_bytes(r.take(len)?).map_err(|_| Error::Format("pair"))?;
                let pair = SecretPair(Some(state));
                if peer == 0
                    || peer > self.n
                    || peer == self.member
                    || out.iter().any(|(m, _)| *m == peer)
                {
                    return Err(Error::Format("pair"));
                }
                out.push((peer, pair));
            }
            if !r.0.is_empty() {
                return Err(Error::Format("pair cache"));
            }
            Ok(out)
        })();
        let Ok(mut parsed) = parsed else {
            return refused(CacheRefused::Damaged);
        };
        for (peer, pair) in parsed.iter_mut() {
            if let Some(state) = pair.0.take() {
                self.set_pair(*peer, state)?;
            }
        }
        Ok((1..=self.n)
            .filter(|m| parsed.iter().any(|(p, _)| p == m))
            .collect())
    }
}
