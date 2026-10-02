//! What a member keeps: its share record, and the bundle an export writes per member.
//!
//! # Share record (format 1)
//!
//! ```text
//!  off  len  field
//!    0    4  magic "CTSk"
//!    4    1  format version (1)
//!    5    1  origin: 1 created together, 2 exported
//!    6    1  member number, 1..=n
//!    7    1  n
//!    8    1  t: members needed to sign or to restore
//!    9   33  joint public key, compressed
//!   42   32  chain code
//!   74    4  origin fingerprint: of the joint key (created), of the master (exported)
//!   78    1  origin path depth d, at most 10
//!   79   4d  origin path, big-endian u32s (empty when created together)
//!    .    4  DKLs share length, little-endian
//!    .    L  DKLs share: tsslib's key save format (version 4) in compact JSON
//! ```
//!
//! The joint key and chain code are repeated outside the DKLs share so a wallet's
//! xpub, fingerprint and addresses can be shown without decoding the secret half; on
//! decode the two copies must agree.
//!
//! The DKLs share holds this member's Shamir share and, per other member, the
//! OT-extension state set up at key generation -- about 12 KB a peer, which is why the
//! record grows with `n` (the crate's size test prints the numbers).
//!
//! # Share bundle (format 1)
//!
//! ```text
//!    0    4  magic "CTSb"
//!    4    1  format version (1)
//!    5    1  member number
//!    6    1  n
//!    7    1  t
//!    8    1  Codex32 string length C
//!    9    C  this member's Codex32 `cw1` share of the BIP-39 entropy, lowercase
//!    .    4  share record length, little-endian
//!    .    R  share record (above)
//! ```

use alloc::string::String;
use alloc::vec::Vec;
use catcard_wallet::KeyWork;
use catcard_wallet::bip32::hash160;
use purecrypto::ec::secp256k1::{ProjectivePoint, Scalar};
use tsslib::dklstss::Key;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{Error, MAX_MEMBERS, PUBKEY_LEN, bjson};

const RECORD_MAGIC: [u8; 4] = *b"CTSk";
const BUNDLE_MAGIC: [u8; 4] = *b"CTSb";
const FORMAT: u8 = 1;
/// Deepest origin path a record carries: BIP-32 allows 255, wallets use 3-5.
pub const MAX_PATH: usize = 10;

/// A DKLs key share, wiped when dropped: tsslib's `Key::zeroize` clears the Shamir share
/// and every pairwise OT seed.
pub(crate) struct SecretKey(pub(crate) Key);

impl Clone for SecretKey {
    fn clone(&self) -> Self {
        SecretKey(self.0.clone())
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl SecretKey {
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let json = Zeroizing::new(self.0.to_json().map_err(|_| Error::Format("DKLs share"))?);
        Ok(Zeroizing::new(bjson::encode(json.as_bytes())?))
    }

    fn decode(bin: &[u8]) -> Result<Self, Error> {
        let text = Zeroizing::new(bjson::decode(bin)?);
        let s = core::str::from_utf8(&text).map_err(|_| Error::Format("DKLs share"))?;
        Key::from_json(s)
            .map(SecretKey)
            .map_err(|_| Error::Format("DKLs share"))
    }
}

/// How a TSS wallet came to be.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Origin {
    /// `n` devices ran a DKG; nobody has ever held the key.
    Created = 1,
    /// One device split a wallet it held; the shares sign for its account.
    Exported = 2,
}

/// One member's share of a TSS wallet.
#[derive(Clone)]
pub struct ShareRecord {
    pub(crate) origin: Origin,
    pub(crate) member: u8,
    pub(crate) n: u8,
    pub(crate) t: u8,
    pub(crate) joint_public: [u8; PUBKEY_LEN],
    pub(crate) chain_code: [u8; 32],
    pub(crate) fingerprint: [u8; 4],
    pub(crate) path: Vec<u32>,
    pub(crate) key: SecretKey,
}

/// `p` compressed; `None` for the identity.
pub(crate) fn compress(p: &ProjectivePoint) -> Option<[u8; PUBKEY_LEN]> {
    p.to_affine().map(|a| a.to_sec1_compressed())
}

/// A member number as the scalar tsslib shares at: its party key, `[member]`.
pub(crate) fn member_scalar(member: u8) -> Scalar {
    let mut b = [0u8; 32];
    b[31] = member;
    Scalar::from_bytes_be_reduce(&b)
}

pub(crate) fn check_params(n: u8, t: u8) -> Result<(), Error> {
    if !(2..=MAX_MEMBERS).contains(&n) || t < 2 || t > n {
        return Err(Error::Parameters);
    }
    Ok(())
}

impl ShareRecord {
    /// Wrap a DKLs key from keygen or export, checking it says what the record says.
    pub(crate) fn from_key(
        origin: Origin,
        t: u8,
        fingerprint: Option<[u8; 4]>,
        path: Vec<u32>,
        key: SecretKey,
    ) -> Result<Self, Error> {
        let k = &key.0;
        let n = u8::try_from(k.n).map_err(|_| Error::Parameters)?;
        let member = u8::try_from(k.idx + 1).map_err(|_| Error::Parameters)?;
        let joint_public = compress(&k.ecdsa_pub).ok_or(Error::Format("DKLs share"))?;
        let fingerprint = fingerprint.unwrap_or_else(|| {
            let h = hash160(&joint_public);
            [h[0], h[1], h[2], h[3]]
        });
        let record = ShareRecord {
            origin,
            member,
            n,
            t,
            joint_public,
            chain_code: k.chain_code,
            fingerprint,
            path,
            key,
        };
        record.check()?;
        Ok(record)
    }

    /// The record's fields against each other and against the DKLs share inside it.
    fn check(&self) -> Result<(), Error> {
        check_params(self.n, self.t)?;
        let k = &self.key.0;
        let bad = Error::Format("share record");
        if self.member == 0
            || self.member > self.n
            || self.path.len() > MAX_PATH
            || k.n != usize::from(self.n)
            || k.t + 1 != usize::from(self.t)
            || k.idx + 1 != usize::from(self.member)
            || compress(&k.ecdsa_pub) != Some(self.joint_public)
            || k.chain_code != self.chain_code
        {
            return Err(bad);
        }
        // Members are numbered 1..=n and tsslib shares at the member number.
        for (i, p) in k.party_ids.iter().enumerate() {
            if p.key != [i as u8 + 1] {
                return Err(bad);
            }
        }
        k.validate_basic().map_err(|_| bad)
    }

    pub fn origin(&self) -> Origin {
        self.origin
    }
    /// This member's number, 1..=n.
    pub fn member(&self) -> u8 {
        self.member
    }
    pub fn n(&self) -> u8 {
        self.n
    }
    /// Members needed to sign, and to restore.
    pub fn t(&self) -> u8 {
        self.t
    }
    /// The wallet's public key: the account key of an exported wallet, the joint key of
    /// a created one.
    pub fn joint_public_key(&self) -> &[u8; PUBKEY_LEN] {
        &self.joint_public
    }
    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }
    /// Master fingerprint of the origin path (BIP-32 key origin).
    pub fn fingerprint(&self) -> [u8; 4] {
        self.fingerprint
    }
    /// The origin path from the master to [`Self::joint_public_key`]; empty when created
    /// together.
    pub fn path(&self) -> &[u32] {
        &self.path
    }

    /// The public key at a non-hardened `path` below the wallet key (BIP-32 CKDpub).
    pub fn child_public_key(&self, path: &[u32]) -> Result<[u8; PUBKEY_LEN], Error> {
        let (_, child) =
            tsslib::dklstss::derive_child(&self.key.0, path).map_err(|_| Error::Parameters)?;
        compress(&child).ok_or(Error::Parameters)
    }

    /// Serialise, secret share included.
    pub fn to_bytes(&self, _kw: &KeyWork) -> Result<Zeroizing<Vec<u8>>, Error> {
        let key = self.key.encode()?;
        let mut out = Vec::with_capacity(83 + 4 * self.path.len() + key.len());
        out.extend_from_slice(&RECORD_MAGIC);
        out.extend_from_slice(&[FORMAT, self.origin as u8, self.member, self.n, self.t]);
        out.extend_from_slice(&self.joint_public);
        out.extend_from_slice(&self.chain_code);
        out.extend_from_slice(&self.fingerprint);
        out.push(self.path.len() as u8);
        for i in &self.path {
            out.extend_from_slice(&i.to_be_bytes());
        }
        out.extend_from_slice(&(key.len() as u32).to_le_bytes());
        out.extend_from_slice(&key);
        Ok(Zeroizing::new(out))
    }

    /// Parse and check a record [`Self::to_bytes`] wrote.
    pub fn from_bytes(bytes: &[u8], _kw: &KeyWork) -> Result<Self, Error> {
        let bad = Error::Format("share record");
        let mut r = Reader(bytes);
        if r.take(4)? != RECORD_MAGIC || r.byte()? != FORMAT {
            return Err(bad);
        }
        let origin = match r.byte()? {
            1 => Origin::Created,
            2 => Origin::Exported,
            _ => return Err(bad),
        };
        let member = r.byte()?;
        let n = r.byte()?;
        let t = r.byte()?;
        let joint_public: [u8; PUBKEY_LEN] = r.array()?;
        let chain_code: [u8; 32] = r.array()?;
        let fingerprint: [u8; 4] = r.array()?;
        let depth = usize::from(r.byte()?);
        if depth > MAX_PATH {
            return Err(bad);
        }
        let mut path = Vec::with_capacity(depth);
        for _ in 0..depth {
            path.push(u32::from_be_bytes(r.array()?));
        }
        let len = u32::from_le_bytes(r.array()?) as usize;
        let key = SecretKey::decode(r.take(len)?)?;
        if !r.0.is_empty() {
            return Err(bad);
        }
        let record = ShareRecord {
            origin,
            member,
            n,
            t,
            joint_public,
            chain_code,
            fingerprint,
            path,
            key,
        };
        record.check()?;
        Ok(record)
    }
}

pub(crate) struct Reader<'a>(pub(crate) &'a [u8]);

impl<'a> Reader<'a> {
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.0.len() < n {
            return Err(Error::Format("truncated"));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    pub(crate) fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }
}

/// What an export writes for one member: the restore half and the signing half.
#[derive(Clone)]
pub struct ShareBundle {
    pub(crate) member: u8,
    pub(crate) n: u8,
    pub(crate) t: u8,
    pub(crate) codex32: Zeroizing<String>,
    pub(crate) record: ShareRecord,
}

impl ShareBundle {
    pub fn member(&self) -> u8 {
        self.member
    }
    pub fn n(&self) -> u8 {
        self.n
    }
    pub fn t(&self) -> u8 {
        self.t
    }
    /// This member's Codex32 share of the wallet's BIP-39 entropy, lowercase.
    pub fn codex32(&self) -> &str {
        &self.codex32
    }
    /// The signing half, to keep in a CatCard's settings.
    pub fn record(&self) -> &ShareRecord {
        &self.record
    }

    pub fn to_bytes(&self, kw: &KeyWork) -> Result<Zeroizing<Vec<u8>>, Error> {
        let record = self.record.to_bytes(kw)?;
        let text = self.codex32.as_bytes();
        let mut out = Vec::with_capacity(13 + text.len() + record.len());
        out.extend_from_slice(&BUNDLE_MAGIC);
        out.extend_from_slice(&[FORMAT, self.member, self.n, self.t, text.len() as u8]);
        out.extend_from_slice(text);
        out.extend_from_slice(&(record.len() as u32).to_le_bytes());
        out.extend_from_slice(&record);
        Ok(Zeroizing::new(out))
    }

    pub fn from_bytes(bytes: &[u8], kw: &KeyWork) -> Result<Self, Error> {
        let bad = Error::Format("share bundle");
        let mut r = Reader(bytes);
        if r.take(4)? != BUNDLE_MAGIC || r.byte()? != FORMAT {
            return Err(bad);
        }
        let member = r.byte()?;
        let n = r.byte()?;
        let t = r.byte()?;
        let len = usize::from(r.byte()?);
        let text = core::str::from_utf8(r.take(len)?).map_err(|_| bad.clone())?;
        let codex32 = Zeroizing::new(String::from(text));
        let rlen = u32::from_le_bytes(r.array()?) as usize;
        let record = ShareRecord::from_bytes(r.take(rlen)?, kw)?;
        if !r.0.is_empty() {
            return Err(bad);
        }
        // The two halves must describe the same member of the same split.
        let share = catcard_wallet::codex32::Share::parse(&codex32, kw).map_err(Error::Codex32)?;
        if record.member != member
            || record.n != n
            || record.t != t
            || share.threshold() != t
            || share.is_secret()
            || share.index() != crate::export::codex32_index(member)?
        {
            return Err(bad);
        }
        Ok(ShareBundle {
            member,
            n,
            t,
            codex32,
            record,
        })
    }
}

/// A created-together wallet's key, put back together. Wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct JointSecret {
    private: [u8; 32],
    chain_code: [u8; 32],
}

impl JointSecret {
    /// The private key, big-endian.
    pub fn private_key(&self) -> &[u8; 32] {
        &self.private
    }
    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }
}

/// Recombine the wallet key from `t` or more members' records.
///
/// **This ends the "nobody holds the key" property of a created-together wallet**: after
/// it, the device that ran it holds the whole key, as any single-signature wallet does.
/// The UI says so before calling it (docs/TSS.md, "Restore a created-together wallet").
/// It works on exported records too, and gives back the account key they share.
///
/// Lagrange interpolation at zero over the members' Shamir shares; the weights depend
/// only on the member numbers, which are public, and the sum is computed in purecrypto's
/// constant-time scalar arithmetic. The result is checked against the joint public key,
/// so a record of another wallet, or a tampered one, is refused rather than recombined
/// into a wrong key.
pub fn combine(records: &[&ShareRecord], _kw: &KeyWork) -> Result<JointSecret, Error> {
    let first = records.first().ok_or(Error::NotEnoughShares)?;
    for (i, r) in records.iter().enumerate() {
        if r.joint_public != first.joint_public
            || r.chain_code != first.chain_code
            || r.n != first.n
            || r.t != first.t
        {
            return Err(Error::Mismatch);
        }
        if records[..i].iter().any(|o| o.member == r.member) {
            return Err(Error::Mismatch);
        }
    }
    if records.len() < usize::from(first.t) {
        return Err(Error::NotEnoughShares);
    }
    let mut sum = Scalar::from_bytes_be_reduce(&[0u8; 32]);
    for r in records {
        let xi = member_scalar(r.member);
        let mut num = member_scalar(1);
        let mut den = num.clone();
        for o in records {
            if o.member != r.member {
                let xj = member_scalar(o.member);
                num = num.mul(&xj);
                den = den.mul(&xj.sub(&xi));
            }
        }
        let lambda = num.mul(&den.invert());
        sum = sum.add(&lambda.mul(&r.key.0.xi));
    }
    let check = compress(&ProjectivePoint::mul_generator(&sum));
    let secret = JointSecret {
        private: sum.to_bytes_be(),
        chain_code: first.chain_code,
    };
    if check != Some(first.joint_public) {
        return Err(Error::Mismatch);
    }
    Ok(secret)
}
