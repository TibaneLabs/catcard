//! Discoverable credentials (passkeys): what the device keeps so a site can sign in
//! without first saying who is signing in.
//!
//! # What is stored, and what is not
//!
//! A passkey's **private key is not stored**: it is the same seed-derived key as every
//! other credential ([`crate::keys`]), recomputed from the wallet's FIDO master and the
//! credential's 16-byte nonce, and its credential id is the same MAC'd form. What a
//! passkey adds is the part a site no longer sends -- which account, at which site --
//! so the device can find the credential from the site alone:
//!
//! | field | bytes | |
//! |---|---|---|
//! | nonce | 16 | the credential's own; with the master it gives the key and the id |
//! | rpIdHash | 32 | what GetAssertion matches on |
//! | order | 4 | creation order, newest answered first (CTAP 2.1 §6.2.2 step 11) |
//! | rp.id | 1 + 32 | truncated as CTAP 2.1 §6.8.7 prescribes, for listing only |
//! | user.id | 1 + 64 | WebAuthn L2 §5.4.3: at most 64 bytes [C] |
//! | user.name | 1 + 64 | cut at a character boundary |
//! | user.displayName | 1 + 64 | cut at a character boundary |
//! | algorithm | 1 | the credential id's version byte: 0x01 ES256, 0x02 EdDSA ([`crate::keys::Alg`]) |
//!
//! [`REC_LEN`] bytes per passkey, at most [`CAPACITY`] per wallet. A restored seed plus
//! this file recovers every passkey; a restored seed alone recovers every *login*, since
//! a site that still sends an allow list is answered from the id as before.
//!
//! # The file
//!
//! One file per wallet (and per FIDO generation), sealed under two keys made from the
//! wallet's FIDO master ([`crate::keys::Master::passkey_key`]), encrypt-then-MAC:
//!
//! ```text
//! "CPK1" ‖ iv (16) ‖ tag (32) ‖ ct
//! ct  = AES-256-CTR(enc key, iv, plaintext)
//! tag = HMAC-SHA-256(mac key, "CPK1" ‖ iv ‖ ct), checked in constant time before
//!       anything is decrypted
//! plaintext = version 2 ‖ count ‖ next order (u32 LE) ‖ 2 zero bytes ‖ records
//! ```
//!
//! **Version 1** files, written before EdDSA, have records one byte shorter: no algorithm
//! byte, every passkey ES256. [`Passkeys::open`] still reads them, widening the records in
//! place, and the next write of the file is version 2. Nothing writes version 1.
//!
//! CTR and HMAC rather than GCM because both are already in the image (the settings slots
//! are AES-256-CTR, every credential id is an HMAC): GCM's GHASH would be two more
//! kilobytes of flash for the same guarantee.
//!
//! So a file says nothing to anyone without the wallet, a changed byte fails the tag, and
//! a reset -- which changes the master -- leaves nothing that opens.
//!
//! # The backup copy
//!
//! A passkey is the one credential the seed alone does not bring back: the site, the
//! account and the user handle were given once, at registration. So the file can be
//! copied off the device ([`export`]) and read back ([`parse_export`]):
//!
//! ```text
//! "CPKB" ‖ version 1 ‖ generation (u32 LE) ‖ the sealed file, byte for byte
//! ```
//!
//! Nothing is decrypted to make it and nothing new is encrypted: the sealed file is
//! already safe anywhere -- without the wallet it is noise, and with the wallet you have
//! every login anyway. The generation travels with it because the key the file is sealed
//! under depends on it, and a wallet restored from its seed starts again at zero. It is
//! outside the tag, which costs nothing: a changed generation names a key the file was not
//! sealed under, and [`check`] fails.

use purecrypto::cipher::{Aes256, Ctr};
use purecrypto::ct::ConstantTimeEq;
use purecrypto::hash::HmacSha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::keys::{Alg, NONCE_LEN};

/// Passkeys per wallet. 50 × [`REC_LEN`] is 14 KB of plaintext, which fits one heap
/// block on every board with the request's own 2 KB beside it.
pub const CAPACITY: usize = 50;

/// Stored bytes of each field. Source: CTAP 2.1 §6.8.7 (at least 32 bytes of RP ID) [C];
/// WebAuthn L2 §5.4.3 (user handle at most 64 bytes) and §6.4.1 (authenticators SHOULD
/// store at least 64 bytes of `name` / `displayName`) [C]
pub const RP_MAX: usize = 32;
pub const USER_ID_MAX: usize = 64;
pub const NAME_MAX: usize = 64;

const OFF_NONCE: usize = 0;
const OFF_RP_HASH: usize = OFF_NONCE + NONCE_LEN;
const OFF_ORDER: usize = OFF_RP_HASH + 32;
const OFF_RP: usize = OFF_ORDER + 4;
const OFF_UID: usize = OFF_RP + 1 + RP_MAX;
const OFF_NAME: usize = OFF_UID + 1 + USER_ID_MAX;
const OFF_DISP: usize = OFF_NAME + 1 + NAME_MAX;
const OFF_ALG: usize = OFF_DISP + 1 + NAME_MAX;
/// One stored passkey.
pub const REC_LEN: usize = OFF_ALG + 1;
/// One stored passkey in a version 1 file: no algorithm byte.
const REC_LEN_V1: usize = OFF_ALG;

/// The plaintext's header: version, count, next order, padding.
pub const PLAIN_HEAD: usize = 8;
/// The sealed file's header: magic, IV, tag.
pub const FILE_HEAD: usize = 4 + 16 + 32;
const MAGIC: &[u8; 4] = b"CPK1";
const VERSION: u8 = 2;
const VERSION_V1: u8 = 1;

/// A buffer that holds a file of `records` passkeys, sealed or open.
pub const fn file_len(records: usize) -> usize {
    FILE_HEAD + PLAIN_HEAD + records * REC_LEN
}

/// The largest file there can be.
pub const MAX_FILE: usize = file_len(CAPACITY);

/// The buffer to open a stored file of `stored` bytes in (`None`: no file yet) with room
/// for one more passkey, at most [`MAX_FILE`].
///
/// The length alone does not say which version the file is, so the count is taken at the
/// shorter, version 1 stride. For a version 2 file that is still exact: `n` records of
/// [`REC_LEN`] bytes are `n` at the shorter stride too while `n` is under `REC_LEN_V1`
/// (280), and [`CAPACITY`] is 50.
pub const fn buffer_for(stored: Option<usize>) -> usize {
    let count = match stored {
        Some(n) if n > file_len(0) => (n - file_len(0)) / REC_LEN_V1,
        _ => 0,
    };
    let want = if count + 1 < CAPACITY {
        count + 1
    } else {
        CAPACITY
    };
    file_len(want)
}
const _: () = assert!(CAPACITY < REC_LEN_V1);

/// A short field: bytes and how many are used.
#[derive(Clone, PartialEq, Eq, Zeroize)]
pub struct Field<const N: usize> {
    len: u8,
    bytes: [u8; N],
}

impl<const N: usize> Field<N> {
    pub const fn empty() -> Self {
        Self {
            len: 0,
            bytes: [0; N],
        }
    }

    /// `b` as it fits: cut to `N` bytes, and for text at a character boundary so what is
    /// kept is still UTF-8.
    fn text(s: &str) -> Self {
        let mut n = s.len().min(N);
        while !s.is_char_boundary(n) {
            n -= 1;
        }
        Self::raw(&s.as_bytes()[..n])
    }

    /// `b` if it fits, else `None`.
    fn exact(b: &[u8]) -> Option<Self> {
        (b.len() <= N).then(|| Self::raw(b))
    }

    fn raw(b: &[u8]) -> Self {
        let mut f = Self::empty();
        f.bytes[..b.len()].copy_from_slice(b);
        f.len = b.len() as u8;
        f
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// As text: what was stored was cut at a boundary, so this only fails for a file
    /// made by something else, which then shows nothing.
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).unwrap_or("")
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn put(&self, out: &mut [u8]) {
        out[0] = self.len;
        out[1..1 + N].copy_from_slice(&self.bytes);
    }

    fn get(b: &[u8]) -> Option<Self> {
        let len = b[0];
        if len as usize > N {
            return None;
        }
        let mut f = Self::empty();
        f.len = len;
        f.bytes.copy_from_slice(&b[1..1 + N]);
        Some(f)
    }
}

/// One passkey.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Record {
    /// Public: the credential id carries it in the clear.
    #[zeroize(skip)]
    pub alg: Alg,
    pub nonce: [u8; NONCE_LEN],
    pub rp_id_hash: [u8; 32],
    pub order: u32,
    pub rp_id: Field<RP_MAX>,
    pub user_id: Field<USER_ID_MAX>,
    pub name: Field<NAME_MAX>,
    pub display_name: Field<NAME_MAX>,
}

/// An RP ID as it is kept: whole up to [`RP_MAX`] bytes, otherwise shortened on the left
/// behind an ellipsis, keeping a `scheme:` prefix if there is one.
/// Source: CTAP 2.1 §6.8.7 `maybe_truncate_rpid` [C]
pub fn truncate_rp_id(rp_id: &str) -> Field<RP_MAX> {
    let b = rp_id.as_bytes();
    if b.len() <= RP_MAX {
        return Field::raw(b);
    }
    let mut out = [0u8; RP_MAX];
    let mut used = 0;
    if let Some(colon) = b.iter().position(|&c| c == b':') {
        let n = (colon + 1).min(RP_MAX);
        out[..n].copy_from_slice(&b[..n]);
        used = n;
    }
    if RP_MAX - used < 3 {
        return Field::raw(&out[..used]);
    }
    out[used..used + 3].copy_from_slice("\u{2026}".as_bytes());
    used += 3;
    let rest = RP_MAX - used;
    out[used..].copy_from_slice(&b[b.len() - rest..]);
    Field::raw(&out)
}

impl Record {
    /// A new passkey for `rp_id`. `None` if `user_id` is longer than WebAuthn allows.
    pub fn new(
        alg: Alg,
        nonce: &[u8; NONCE_LEN],
        rp_id: &str,
        rp_id_hash: &[u8; 32],
        user_id: &[u8],
        name: Option<&str>,
        display_name: Option<&str>,
    ) -> Option<Self> {
        Some(Self {
            alg,
            nonce: *nonce,
            rp_id_hash: *rp_id_hash,
            order: 0,
            rp_id: truncate_rp_id(rp_id),
            user_id: Field::exact(user_id)?,
            name: Field::text(name.unwrap_or("")),
            display_name: Field::text(display_name.unwrap_or("")),
        })
    }

    /// Replace the name and display name: an absent or empty one is removed.
    /// Source: CTAP 2.1 §6.8.6 last step [C]
    pub fn set_names(&mut self, name: Option<&str>, display_name: Option<&str>) {
        self.name = Field::text(name.unwrap_or(""));
        self.display_name = Field::text(display_name.unwrap_or(""));
    }

    fn write(&self, out: &mut [u8]) {
        out[OFF_NONCE..OFF_RP_HASH].copy_from_slice(&self.nonce);
        out[OFF_RP_HASH..OFF_ORDER].copy_from_slice(&self.rp_id_hash);
        out[OFF_ORDER..OFF_RP].copy_from_slice(&self.order.to_le_bytes());
        self.rp_id.put(&mut out[OFF_RP..OFF_UID]);
        self.user_id.put(&mut out[OFF_UID..OFF_NAME]);
        self.name.put(&mut out[OFF_NAME..OFF_DISP]);
        self.display_name.put(&mut out[OFF_DISP..OFF_ALG]);
        out[OFF_ALG] = self.alg.version();
    }

    fn read(b: &[u8]) -> Option<Self> {
        Some(Self {
            alg: Alg::from_version(b[OFF_ALG])?,
            nonce: b[OFF_NONCE..OFF_RP_HASH].try_into().ok()?,
            rp_id_hash: b[OFF_RP_HASH..OFF_ORDER].try_into().ok()?,
            order: u32::from_le_bytes(b[OFF_ORDER..OFF_RP].try_into().ok()?),
            rp_id: Field::get(&b[OFF_RP..OFF_UID])?,
            user_id: Field::get(&b[OFF_UID..OFF_NAME])?,
            name: Field::get(&b[OFF_NAME..OFF_DISP])?,
            display_name: Field::get(&b[OFF_DISP..OFF_ALG])?,
        })
    }
}

/// Why a file would not open.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Not a passkey file, the wrong wallet's, or changed since it was written.
    Unreadable,
    /// The buffer cannot hold what is asked of it.
    TooSmall,
    /// Every place is taken. `CTAP2_ERR_KEY_STORE_FULL`.
    Full,
}

/// A wallet's passkeys, open: a view over the plaintext part of a file buffer.
pub struct Passkeys<'a> {
    plain: &'a mut [u8],
}

impl<'a> Passkeys<'a> {
    /// An empty list in `buf` (a file buffer: [`FILE_HEAD`] then the plaintext).
    pub fn empty(buf: &'a mut [u8]) -> Result<Self, Error> {
        if buf.len() < file_len(0) {
            return Err(Error::TooSmall);
        }
        let plain = &mut buf[FILE_HEAD..];
        plain[..PLAIN_HEAD].fill(0);
        plain[0] = VERSION;
        Ok(Self { plain })
    }

    /// Open the `len`-byte sealed file at the start of `buf`, in place. A version 1 file
    /// is widened to version 2 as it opens, which needs `buf` to hold
    /// `file_len(count)` -- as [`buffer_for`] sizes it.
    pub fn open(key: &PasskeyKey, buf: &'a mut [u8], len: usize) -> Result<Self, Error> {
        if len < file_len(0) || len > buf.len() || &buf[..4] != MAGIC {
            return Err(Error::Unreadable);
        }
        let mut tag = file_tag(key, &buf[..len]);
        let ok = bool::from(tag[..].ct_eq(&buf[20..52]));
        tag.zeroize();
        if !ok {
            return Err(Error::Unreadable);
        }
        let iv: [u8; 16] = buf[4..20].try_into().map_err(|_| Error::Unreadable)?;
        Ctr::new(Aes256::new(&key.enc), &iv).apply_keystream(&mut buf[FILE_HEAD..len]);
        let plain = &mut buf[FILE_HEAD..];
        let n = plain[1] as usize;
        let v1_len = FILE_HEAD + PLAIN_HEAD + n * REC_LEN_V1;
        let ok = n <= CAPACITY
            && match plain[0] {
                VERSION => len == file_len(n),
                VERSION_V1 => len == v1_len && buf.len() >= file_len(n),
                _ => false,
            };
        let plain = &mut buf[FILE_HEAD..];
        if !ok {
            plain.zeroize();
            return Err(Error::Unreadable);
        }
        if plain[0] == VERSION_V1 {
            // Widen from the last record down, so none is overwritten before it moves:
            // record i goes from i * 280 to i * 281, never below where it was.
            for i in (0..n).rev() {
                let from = PLAIN_HEAD + i * REC_LEN_V1;
                let to = PLAIN_HEAD + i * REC_LEN;
                plain.copy_within(from..from + REC_LEN_V1, to);
                plain[to + OFF_ALG] = Alg::Es256.version();
            }
            plain[0] = VERSION;
        }
        let p = Self { plain };
        for i in 0..n {
            if Record::read(p.slot(i)).is_none() {
                p.plain.zeroize();
                return Err(Error::Unreadable);
            }
        }
        Ok(p)
    }

    pub fn len(&self) -> usize {
        self.plain[1] as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Places left under [`CAPACITY`].
    pub fn remaining(&self) -> usize {
        CAPACITY - self.len()
    }

    fn next_order(&self) -> u32 {
        u32::from_le_bytes(self.plain[2..6].try_into().expect("4 bytes"))
    }

    fn slot(&self, i: usize) -> &[u8] {
        let at = PLAIN_HEAD + i * REC_LEN;
        &self.plain[at..at + REC_LEN]
    }

    fn slot_mut(&mut self, i: usize) -> &mut [u8] {
        let at = PLAIN_HEAD + i * REC_LEN;
        &mut self.plain[at..at + REC_LEN]
    }

    /// Passkey `i`, in stored order.
    pub fn get(&self, i: usize) -> Option<Record> {
        (i < self.len()).then(|| Record::read(self.slot(i)))?
    }

    /// Replace passkey `i`, keeping its place and order.
    pub fn set(&mut self, i: usize, r: &Record) {
        if i < self.len() {
            let order = self.get(i).map_or(r.order, |old| old.order);
            let mut r = r.clone();
            r.order = order;
            r.write(self.slot_mut(i));
        }
    }

    /// Remove passkey `i`, wiping the place it leaves.
    pub fn remove(&mut self, i: usize) {
        let n = self.len();
        if i >= n {
            return;
        }
        let start = PLAIN_HEAD + i * REC_LEN;
        let end = PLAIN_HEAD + n * REC_LEN;
        self.plain.copy_within(start + REC_LEN..end, start);
        self.plain[end - REC_LEN..end].zeroize();
        self.plain[1] = (n - 1) as u8;
    }

    /// Add a passkey, newest of all. One for the same site and account replaces it
    /// (CTAP 2.1 §6.1.2 step 17 "Overwrite that credential") [C]. `Full` when there is
    /// no place, `TooSmall` when the buffer was not sized for one more.
    pub fn add(&mut self, r: &Record) -> Result<(), Error> {
        let order = self.next_order();
        let mut r = r.clone();
        r.order = order;
        if let Some(i) = (0..self.len()).find(|&i| {
            self.get(i).is_some_and(|o| {
                o.rp_id_hash == r.rp_id_hash && o.user_id.as_bytes() == r.user_id.as_bytes()
            })
        }) {
            self.remove(i);
        }
        let n = self.len();
        if n >= CAPACITY {
            return Err(Error::Full);
        }
        if self.plain.len() < PLAIN_HEAD + (n + 1) * REC_LEN {
            return Err(Error::TooSmall);
        }
        r.write(self.slot_mut(n));
        self.plain[1] = (n + 1) as u8;
        self.plain[2..6].copy_from_slice(&order.wrapping_add(1).to_le_bytes());
        Ok(())
    }

    /// How many passkeys are for the site whose hash this is.
    pub fn count_for(&self, rp_id_hash: &[u8; 32]) -> usize {
        (0..self.len())
            .filter(|&i| self.slot(i)[OFF_RP_HASH..OFF_ORDER] == rp_id_hash[..])
            .count()
    }

    /// The index of the `k`-th newest passkey for the site (`k` = 0 is the newest).
    pub fn newest_for(&self, rp_id_hash: &[u8; 32], k: usize) -> Option<usize> {
        // Selection by rank, without a sort buffer: at most 50 × 50 comparisons.
        let order = |i: usize| {
            u32::from_le_bytes(self.slot(i)[OFF_ORDER..OFF_RP].try_into().expect("4 bytes"))
        };
        let mine = |i: usize| self.slot(i)[OFF_RP_HASH..OFF_ORDER] == rp_id_hash[..];
        (0..self.len()).filter(|&i| mine(i)).find(|&i| {
            (0..self.len())
                .filter(|&j| mine(j) && order(j) > order(i))
                .count()
                == k
        })
    }

    /// How many different sites have passkeys.
    pub fn sites(&self) -> usize {
        (0..self.len()).filter(|&i| self.first_of_site(i)).count()
    }

    /// The index of a passkey of the `k`-th site, sites in the order they first appear.
    pub fn site(&self, k: usize) -> Option<usize> {
        (0..self.len()).filter(|&i| self.first_of_site(i)).nth(k)
    }

    fn first_of_site(&self, i: usize) -> bool {
        let h = &self.slot(i)[OFF_RP_HASH..OFF_ORDER];
        !(0..i).any(|j| &self.slot(j)[OFF_RP_HASH..OFF_ORDER] == h)
    }

    /// The index of the passkey whose nonce this is, for the site whose hash this is.
    pub fn find(&self, rp_id_hash: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> Option<usize> {
        (0..self.len()).find(|&i| {
            let s = self.slot(i);
            s[OFF_RP_HASH..OFF_ORDER] == rp_id_hash[..] && s[OFF_NONCE..OFF_RP_HASH] == nonce[..]
        })
    }
}

/// The backup copy's magic and version. See the module notes.
pub const EXPORT_MAGIC: &[u8; 4] = b"CPKB";
const EXPORT_VERSION: u8 = 1;
/// The backup copy's header: magic, version, generation.
pub const EXPORT_HEAD: usize = 4 + 1 + 4;
/// The largest backup copy there can be.
pub const MAX_EXPORT: usize = EXPORT_HEAD + MAX_FILE;

/// The backup copy's header, for a sealed file of the given generation. The copy is this
/// followed by the sealed file unchanged.
pub fn export_head(generation: u32) -> [u8; EXPORT_HEAD] {
    let mut h = [0u8; EXPORT_HEAD];
    h[..4].copy_from_slice(EXPORT_MAGIC);
    h[4] = EXPORT_VERSION;
    h[5..].copy_from_slice(&generation.to_le_bytes());
    h
}

/// Write the backup copy of `sealed` into `out`: its length, or `None` if it does not fit.
pub fn export(generation: u32, sealed: &[u8], out: &mut [u8]) -> Option<usize> {
    let n = EXPORT_HEAD + sealed.len();
    out.get_mut(..EXPORT_HEAD)?
        .copy_from_slice(&export_head(generation));
    out.get_mut(EXPORT_HEAD..n)?.copy_from_slice(sealed);
    Some(n)
}

/// A backup copy's generation and the sealed file inside it. Only the framing is checked:
/// whether the file is this wallet's is [`check`]'s to say.
pub fn parse_export(b: &[u8]) -> Option<(u32, &[u8])> {
    if b.len() < EXPORT_HEAD + file_len(0) || b.len() > MAX_EXPORT || &b[..4] != EXPORT_MAGIC {
        return None;
    }
    if b[4] != EXPORT_VERSION {
        return None;
    }
    let generation = u32::from_le_bytes(b[5..9].try_into().ok()?);
    Some((generation, &b[EXPORT_HEAD..]))
}

/// Whether `sealed` is a passkey file sealed under `key`: its magic and tag, checked in
/// constant time, and nothing decrypted. A file that passes opens with
/// [`Passkeys::open`] unless it was sealed wrong by the wallet's own key, which this
/// firmware does not do.
pub fn check(key: &PasskeyKey, sealed: &[u8]) -> bool {
    if sealed.len() < file_len(0) || sealed.len() > MAX_FILE || &sealed[..4] != MAGIC {
        return false;
    }
    let mut tag = file_tag(key, sealed);
    let ok = bool::from(tag[..].ct_eq(&sealed[20..52]));
    tag.zeroize();
    ok
}

/// What [`Passkeys::merge`] did.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Merged {
    /// Passkeys this list did not have, now added.
    pub added: usize,
    /// Passkeys it already had, exactly: same credential, same site.
    pub already: usize,
    /// Passkeys there was no place for.
    pub no_room: usize,
}

impl Passkeys<'_> {
    /// Add every passkey of `from` this list does not already hold, oldest first so they
    /// keep their order among themselves, all newer than what is here.
    ///
    /// One already here -- the same credential for the same site -- is left as it is.
    /// One for the same site and account but another credential replaces the one here,
    /// as a registration would ([`add`](Self::add)): the backup is what the owner chose
    /// to restore. When the list fills, the rest are counted, not added.
    pub fn merge(&mut self, from: &Passkeys<'_>) -> Merged {
        let mut m = Merged::default();
        let mut last: Option<u32> = None;
        for _ in 0..from.len() {
            // The next oldest of `from` after `last`: a selection without a sort buffer,
            // at most 50 x 50 reads. Orders are distinct within a file.
            let next = (0..from.len())
                .filter_map(|i| from.get(i))
                .filter(|r| last.is_none_or(|l| r.order > l))
                .min_by_key(|r| r.order);
            let Some(r) = next else { break };
            last = Some(r.order);
            if self.find(&r.rp_id_hash, &r.nonce).is_some() {
                m.already += 1;
                continue;
            }
            match self.add(&r) {
                Ok(()) => m.added += 1,
                Err(_) => m.no_room += 1,
            }
        }
        m
    }
}

/// Seal the list that was opened over `buf` (or made there with [`Passkeys::empty`]):
/// the file's length. The plaintext is encrypted in place.
pub fn seal_file(buf: &mut [u8], key: &PasskeyKey, iv: &[u8; 16]) -> usize {
    let n = buf[FILE_HEAD + 1] as usize;
    let len = file_len(n);
    buf[..4].copy_from_slice(MAGIC);
    buf[4..20].copy_from_slice(iv);
    Ctr::new(Aes256::new(&key.enc), iv).apply_keystream(&mut buf[FILE_HEAD..len]);
    let tag = file_tag(key, &buf[..len]);
    buf[20..52].copy_from_slice(&tag);
    len
}

/// The file's MAC: over the magic, the IV and the ciphertext -- everything but itself.
fn file_tag(key: &PasskeyKey, file: &[u8]) -> [u8; 32] {
    let mut h = HmacSha256::new(&key.mac);
    h.update(&file[..20]);
    h.update(&file[FILE_HEAD..]);
    h.finalize()
}

/// The key a wallet's passkey file is sealed under, and the name it goes by.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PasskeyKey {
    pub(crate) enc: [u8; 32],
    pub(crate) mac: [u8; 32],
    /// Eight bytes that name the file: different per wallet and generation, and saying
    /// nothing about either without the wallet.
    pub name: [u8; 8],
}

impl PasskeyKey {
    #[cfg(test)]
    pub(crate) fn test(b: u8) -> Self {
        Self {
            enc: [b; 32],
            mac: [b ^ 0x55; 32],
            name: [b; 8],
        }
    }
}

/// The passkey file kept in a `Vec`, for the host simulator and the tests: open it (or
/// start an empty list), run `f`, and seal it back when `f` says it changed.
#[cfg(feature = "std")]
pub fn with_vec<R>(
    key: &PasskeyKey,
    file: &mut Option<std::vec::Vec<u8>>,
    iv: &[u8; 16],
    f: impl FnOnce(&mut Passkeys<'_>) -> (R, bool),
) -> Result<R, Error> {
    let mut buf = std::vec![0u8; MAX_FILE];
    let (r, changed) = {
        let mut p = match file {
            None => Passkeys::empty(&mut buf)?,
            Some(f) => {
                buf[..f.len()].copy_from_slice(f);
                Passkeys::open(key, &mut buf, f.len())?
            }
        };
        f(&mut p)
    };
    if changed {
        let n = seal_file(&mut buf, key, iv);
        *file = Some(buf[..n].to_vec());
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(rp: &str, user: &[u8], name: &str) -> Record {
        let h: [u8; 32] = purecrypto::hash::Sha256::digest(rp.as_bytes());
        Record::new(
            Alg::Es256,
            &[user[0]; 16],
            rp,
            &h,
            user,
            Some(name),
            Some("Display"),
        )
        .unwrap()
    }

    use purecrypto::hash::Digest as _;

    #[test]
    fn a_list_round_trips_through_its_sealed_file() {
        let key = PasskeyKey::test(3);
        let mut buf = vec![0u8; MAX_FILE];
        let mut p = Passkeys::empty(&mut buf).unwrap();
        p.add(&rec("example.com", b"u1", "alice")).unwrap();
        p.add(&rec("example.com", b"u2", "bob")).unwrap();
        p.add(&rec("other.org", b"u1", "carol")).unwrap();
        assert_eq!(p.len(), 3);
        let len = seal_file(&mut buf, &key, &[9; 16]);
        assert_eq!(len, file_len(3));
        assert!(
            !buf.windows(5).any(|w| w == b"alice"),
            "sealed means sealed"
        );

        let mut copy = buf.clone();
        let p = Passkeys::open(&key, &mut copy, len).unwrap();
        assert_eq!(p.len(), 3);
        assert_eq!(p.get(1).unwrap().name.as_str(), "bob");
        let h: [u8; 32] = purecrypto::hash::Sha256::digest(b"example.com");
        assert_eq!(p.count_for(&h), 2);
        // Newest first.
        assert_eq!(
            p.get(p.newest_for(&h, 0).unwrap()).unwrap().name.as_str(),
            "bob"
        );
        assert_eq!(
            p.get(p.newest_for(&h, 1).unwrap()).unwrap().name.as_str(),
            "alice"
        );
        assert_eq!(p.newest_for(&h, 2), None);
        assert_eq!(p.sites(), 2);
        assert_eq!(
            p.get(p.site(1).unwrap()).unwrap().rp_id.as_str(),
            "other.org"
        );

        // Another key, a flipped byte, a cut file: unreadable.
        let mut copy = buf.clone();
        assert!(Passkeys::open(&PasskeyKey::test(4), &mut copy, len).is_err());
        for at in [0, 5, 20, 40, len - 1] {
            let mut copy = buf.clone();
            copy[at] ^= 1;
            assert!(Passkeys::open(&key, &mut copy, len).is_err(), "byte {at}");
        }
        let mut copy = buf.clone();
        assert!(Passkeys::open(&key, &mut copy, len - REC_LEN).is_err());
    }

    /// A version 1 file -- written before EdDSA, records one byte shorter -- opens with
    /// every passkey ES256, and is version 2 once written back. Built here byte by byte
    /// as version 1 laid it out, so the test does not lean on the code it checks.
    #[test]
    fn a_version_1_file_opens_as_es256_and_is_written_back_as_version_2() {
        let key = PasskeyKey::test(3);
        let recs = [
            rec("example.com", b"u1", "alice"),
            rec("example.com", b"u2", "bob"),
            rec("other.org", b"u3", "carol"),
        ];
        let n = recs.len();
        let v1_len = FILE_HEAD + PLAIN_HEAD + n * REC_LEN_V1;
        let mut buf = vec![0u8; buffer_for(Some(v1_len))];
        assert!(buf.len() >= file_len(n + 1), "room to widen, and one more");
        {
            let plain = &mut buf[FILE_HEAD..];
            plain[0] = 1;
            plain[1] = n as u8;
            plain[2..6].copy_from_slice(&(n as u32).to_le_bytes());
            for (i, r) in recs.iter().enumerate() {
                let mut r = r.clone();
                r.order = i as u32;
                let mut slot = [0u8; REC_LEN];
                r.write(&mut slot);
                let at = PLAIN_HEAD + i * REC_LEN_V1;
                plain[at..at + REC_LEN_V1].copy_from_slice(&slot[..REC_LEN_V1]);
            }
        }
        // Sealed as version 1 was: the same magic, CTR and tag over its length.
        buf[..4].copy_from_slice(MAGIC);
        buf[4..20].copy_from_slice(&[7; 16]);
        Ctr::new(Aes256::new(&key.enc), &[7; 16]).apply_keystream(&mut buf[FILE_HEAD..v1_len]);
        let tag = file_tag(&key, &buf[..v1_len]);
        buf[20..52].copy_from_slice(&tag);

        // A buffer with no room to widen is refused rather than overrun.
        let mut tight = buf[..v1_len].to_vec();
        assert_eq!(
            Passkeys::open(&key, &mut tight, v1_len).err(),
            Some(Error::Unreadable)
        );

        let mut p = Passkeys::open(&key, &mut buf, v1_len).unwrap();
        assert_eq!(p.len(), n);
        for (i, want) in recs.iter().enumerate() {
            let got = p.get(i).unwrap();
            assert_eq!(got.alg, Alg::Es256);
            assert_eq!(got.nonce, want.nonce);
            assert_eq!(got.user_id.as_bytes(), want.user_id.as_bytes());
            assert_eq!(got.display_name.as_str(), "Display");
            assert_eq!(got.order, i as u32);
        }
        let mut ed = rec("ssh:", b"u4", "dave");
        ed.alg = Alg::EdDsa;
        p.add(&ed).unwrap();
        let len = seal_file(&mut buf, &key, &[8; 16]);
        assert_eq!(len, file_len(n + 1));
        let p = Passkeys::open(&key, &mut buf, len).unwrap();
        assert_eq!(p.plain[0], VERSION);
        assert_eq!(p.get(n).unwrap().alg, Alg::EdDsa);
        assert_eq!(p.get(0).unwrap().alg, Alg::Es256);
        assert_eq!(p.get(n).unwrap().order, n as u32);
    }

    /// The backup copy carries the sealed file untouched and its generation; only this
    /// wallet's key at that generation passes `check`, and nothing in the copy says
    /// anything without it.
    #[test]
    fn a_backup_copy_round_trips_and_only_its_own_key_checks_it() {
        let key = PasskeyKey::test(3);
        let mut buf = vec![0u8; MAX_FILE];
        let mut p = Passkeys::empty(&mut buf).unwrap();
        p.add(&rec("example.com", b"u1", "alice")).unwrap();
        let len = seal_file(&mut buf, &key, &[9; 16]);
        let sealed = buf[..len].to_vec();

        let mut out = vec![0u8; MAX_EXPORT];
        let n = export(7, &sealed, &mut out).unwrap();
        assert_eq!(n, EXPORT_HEAD + len);
        assert_eq!(&out[..4], b"CPKB");
        assert!(!out.windows(5).any(|w| w == b"alice"), "still sealed");
        let (generation, inner) = parse_export(&out[..n]).unwrap();
        assert_eq!(generation, 7);
        assert_eq!(inner, &sealed[..]);
        assert!(check(&key, inner));
        assert!(
            !check(&PasskeyKey::test(4), inner),
            "another wallet or generation"
        );
        for at in [0, 4, 20, 40, len - 1] {
            let mut bad = sealed.clone();
            bad[at] ^= 1;
            assert!(!check(&key, &bad), "byte {at}");
        }
        // Framing: the wrong magic or version, cut short, too long, no room to write.
        let mut bad = out[..n].to_vec();
        bad[0] = b'X';
        assert_eq!(parse_export(&bad), None);
        let mut bad = out[..n].to_vec();
        bad[4] = 2;
        assert_eq!(parse_export(&bad), None);
        assert_eq!(parse_export(&out[..EXPORT_HEAD + 10]), None);
        assert_eq!(parse_export(&vec![0u8; MAX_EXPORT + 1]), None);
        assert_eq!(export(7, &sealed, &mut out[..n - 1]), None);
    }

    /// Restoring into a list that already has some: what is new is added, oldest first;
    /// what is there already is left; and what does not fit is counted.
    #[test]
    fn merging_a_backup_adds_what_is_missing_and_says_what_did_not_fit() {
        let mut from_buf = vec![0u8; MAX_FILE];
        let mut from = Passkeys::empty(&mut from_buf).unwrap();
        from.add(&rec("a.com", b"1", "first")).unwrap();
        from.add(&rec("b.com", b"2", "second")).unwrap();
        from.add(&rec("c.com", b"3", "third")).unwrap();
        // Stored out of creation order, as removals leave a file.
        let first = from.get(0).unwrap();
        from.remove(0);
        from.add(&first).unwrap();

        let mut to_buf = vec![0u8; MAX_FILE];
        let mut to = Passkeys::empty(&mut to_buf).unwrap();
        to.add(&rec("b.com", b"2", "second")).unwrap();
        to.add(&rec("z.com", b"9", "mine")).unwrap();
        let m = to.merge(&from);
        assert_eq!(
            m,
            Merged {
                added: 2,
                already: 1,
                no_room: 0
            }
        );
        assert_eq!(to.len(), 4);
        // The two added are newer than everything here, in `from`'s own order -- which,
        // after "first" was removed and added again, has it newest.
        let h = |rp: &str| -> [u8; 32] { purecrypto::hash::Sha256::digest(rp.as_bytes()) };
        let order = |rp: &str| to.get(to.newest_for(&h(rp), 0).unwrap()).unwrap().order;
        assert!(order("z.com") < order("c.com"));
        assert!(order("c.com") < order("a.com"));

        // Merging again changes nothing.
        assert_eq!(
            to.merge(&from),
            Merged {
                added: 0,
                already: 3,
                no_room: 0
            }
        );

        // A full list takes nothing new and counts it.
        let mut full_buf = vec![0u8; MAX_FILE];
        let mut full = Passkeys::empty(&mut full_buf).unwrap();
        for i in 0..CAPACITY {
            full.add(&rec("x.com", &[i as u8 + 10, 1], "n")).unwrap();
        }
        let m = full.merge(&from);
        assert_eq!(m.added + m.no_room, 3);
        assert_eq!(m.no_room, 3);
    }

    /// The buffer size for a stored file counts its records right in either version.
    #[test]
    fn buffer_for_counts_both_versions() {
        assert_eq!(buffer_for(None), file_len(1));
        for n in 0..=CAPACITY {
            let want = file_len((n + 1).min(CAPACITY));
            assert_eq!(buffer_for(Some(file_len(n))), want, "v2, {n}");
            let v1 = FILE_HEAD + PLAIN_HEAD + n * REC_LEN_V1;
            assert_eq!(buffer_for(Some(v1)), want, "v1, {n}");
        }
    }

    /// An algorithm byte that names no algorithm makes the file unreadable, as any other
    /// bad field does.
    #[test]
    fn an_unknown_algorithm_byte_is_unreadable() {
        let key = PasskeyKey::test(3);
        let mut buf = vec![0u8; MAX_FILE];
        let mut p = Passkeys::empty(&mut buf).unwrap();
        p.add(&rec("a.com", b"x", "n")).unwrap();
        p.slot_mut(0)[OFF_ALG] = 0x09;
        let len = seal_file(&mut buf, &key, &[1; 16]);
        assert_eq!(
            Passkeys::open(&key, &mut buf, len).err(),
            Some(Error::Unreadable)
        );
    }

    #[test]
    fn same_site_and_account_replaces_and_the_store_fills() {
        let mut buf = vec![0u8; MAX_FILE];
        let mut p = Passkeys::empty(&mut buf).unwrap();
        p.add(&rec("a.com", b"x", "first")).unwrap();
        p.add(&rec("a.com", b"x", "second")).unwrap();
        assert_eq!(p.len(), 1, "same rp and user id: overwritten");
        assert_eq!(p.get(0).unwrap().name.as_str(), "second");
        for i in 1..CAPACITY {
            p.add(&rec("a.com", &[i as u8, 1], "n")).unwrap();
        }
        assert_eq!(p.remaining(), 0);
        assert_eq!(p.add(&rec("b.com", b"y", "n")), Err(Error::Full));
        // Replacing is still possible when full.
        p.add(&rec("a.com", b"x", "third")).unwrap();
        p.remove(0);
        assert_eq!(p.len(), CAPACITY - 1);
        // A buffer sized for what is there has no room for one more.
        let mut small = vec![0u8; file_len(1)];
        let mut q = Passkeys::empty(&mut small).unwrap();
        q.add(&rec("a.com", b"1", "n")).unwrap();
        assert_eq!(q.add(&rec("a.com", b"2", "n")), Err(Error::TooSmall));
    }

    #[test]
    fn long_fields_are_cut_as_the_spec_says() {
        // CTAP 2.1 §6.8.7's own examples.
        for (input, want) in [
            ("example.com", "example.com"),
            (
                "myfidousingwebsite.hostingprovider.net",
                "\u{2026}ngwebsite.hostingprovider.net",
            ),
            (
                "mygreatsite.hostingprovider.info",
                "mygreatsite.hostingprovider.info",
            ),
            (
                "otherprotocol://myfidousingwebsite.hostingprovider.net",
                "otherprotocol:\u{2026}ingprovider.net",
            ),
            (
                "veryexcessivelylargeprotocolname://example.com",
                "veryexcessivelylargeprotocolname",
            ),
        ] {
            assert_eq!(truncate_rp_id(input).as_str(), want, "{input}");
        }
        // A name is cut at a character boundary; a user id that is too long is refused.
        let long = "é".repeat(40);
        let r = Record::new(Alg::Es256, &[0; 16], "a", &[0; 32], b"u", Some(&long), None).unwrap();
        assert_eq!(r.name.as_str(), "é".repeat(32));
        assert!(Record::new(Alg::Es256, &[0; 16], "a", &[0; 32], &[0; 65], None, None).is_none());
    }
}
