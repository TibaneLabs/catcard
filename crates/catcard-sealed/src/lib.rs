//! A seed sealed at rest: the Precursor's storage record.
//!
//! The Precursor has no secure element. What it has is a key ROM inside a gateware
//! encrypted to a key only its FPGA holds (docs/PRECURSOR-KEYS.md). This crate is the
//! record that joins the two halves: the owner's passphrase, and the **device secret**
//! `DS` read from that key ROM. Neither alone opens it.
//!
//! ```text
//! key   = Argon2id(password = passphrase, salt, secret = DS, ad = AD, 32 bytes)
//! body  = ChaCha20-Poly1305(key, nonce, aad = header, contents)
//! ```
//!
//! - **Flash alone** (a dump, a stolen device whose gateware an attacker can't decrypt):
//!   no `DS`, so no amount of passphrase guessing helps. Argon2's `secret` input is the
//!   place RFC 9106 gives a pepper.
//! - **Flash and `DS`** (a lab that broke the bitstream encryption): what's left is
//!   Argon2id against the passphrase, at the cost written in the header.
//! - **Writing flash** without `DS`: a record the attacker made doesn't authenticate,
//!   so they can't substitute a seed of their own. They can roll back to an older
//!   genuine record, or erase it; the seed words are the backup.
//!
//! The header -- format, cost, salt, nonce -- is authenticated as AAD. Costs are read
//! from it, so they can be raised later without a format change, and are **bounded**
//! before use: a record in flash is attacker-writable, and Argon2 allocates what it's
//! told to.
//!
//! The crate does no I/O and draws no randomness: the caller supplies salt and nonce
//! (fresh per seal, from the TRNG) and stores the bytes.

#![no_std]
#![deny(unsafe_code)]

use purecrypto::cipher::ChaCha20Poly1305;
use purecrypto::kdf::argon2::{Argon2Params, Argon2Type, argon2};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Identifies a record: "CCSL".
pub const MAGIC: [u8; 4] = *b"CCSL";
/// Format version this crate writes and reads.
pub const VERSION: u8 = 1;
/// KDF identifier: Argon2id v1.3.
const KDF_ARGON2ID_13: u8 = 2;

/// `magic(4) version(1) kdf(1) reserved(2) t(4) m_kib(4) p(4) salt(16) nonce(12)`.
pub const HEADER_LEN: usize = 48;
/// Encrypted contents.
pub const BODY_LEN: usize = 96;
/// Poly1305 tag.
pub const TAG_LEN: usize = 16;
/// A whole record.
pub const RECORD_LEN: usize = HEADER_LEN + BODY_LEN + TAG_LEN;

/// Argon2's associated data: binds the key to this use, so the same passphrase and
/// `DS` never produce this key for anything else.
const AD: &[u8] = b"CatCard Precursor sealed seed v1";

/// Largest seed entropy: 24 BIP-39 words.
pub const MAX_ENTROPY: usize = 32;

/// Bounds on costs read back from a record, before anything is allocated.
pub const MAX_T: u32 = 16;
/// 12 MiB: the most a Precursor build can lend Argon2 from its heap.
pub const MAX_M_KIB: u32 = 12 * 1024;
/// One lane: the device has one core, and more lanes only help a parallel attacker.
pub const MAX_P: u32 = 1;
/// Below this the passphrase is barely stretched; refuse to write such a record.
pub const MIN_M_KIB: u32 = 256;

/// Argon2id cost.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Cost {
    /// Passes over memory.
    pub t: u32,
    /// Memory, KiB.
    pub m_kib: u32,
    /// Lanes.
    pub p: u32,
}

impl Cost {
    fn valid(&self) -> bool {
        (1..=MAX_T).contains(&self.t)
            && (MIN_M_KIB..=MAX_M_KIB).contains(&self.m_kib)
            && (1..=MAX_P).contains(&self.p)
    }
}

/// What a record holds.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Contents {
    /// BIP-39 entropy length: 16 (12 words) to 32 (24 words), a multiple of 4.
    entropy_len: u8,
    entropy: [u8; MAX_ENTROPY],
    /// The unit's own firmware-signing key (Ed25519 seed), once provisioned.
    signing_key: Option<[u8; 32]>,
}

impl core::fmt::Debug for Contents {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Contents(..)")
    }
}

/// Body kinds.
const KIND_BIP39: u8 = 1;
const FLAG_SIGNING_KEY: u8 = 1;

impl Contents {
    /// A BIP-39 seed. `entropy` is 16, 20, 24, 28 or 32 bytes.
    pub fn bip39(entropy: &[u8]) -> Result<Self, Error> {
        if !(16..=MAX_ENTROPY).contains(&entropy.len()) || !entropy.len().is_multiple_of(4) {
            return Err(Error::BadContents);
        }
        let mut c = Contents {
            entropy_len: entropy.len() as u8,
            entropy: [0; MAX_ENTROPY],
            signing_key: None,
        };
        c.entropy[..entropy.len()].copy_from_slice(entropy);
        Ok(c)
    }

    /// Adds the firmware-signing key.
    pub fn with_signing_key(mut self, key: [u8; 32]) -> Self {
        self.signing_key = Some(key);
        self
    }

    /// The BIP-39 entropy.
    pub fn entropy(&self) -> &[u8] {
        &self.entropy[..usize::from(self.entropy_len)]
    }

    /// The firmware-signing key, if this record carries one.
    pub fn signing_key(&self) -> Option<&[u8; 32]> {
        self.signing_key.as_ref()
    }

    /// `kind(1) flags(1) len(1) reserved(1) entropy(32) signing_key(32) zero(28)`.
    fn encode(&self, out: &mut [u8; BODY_LEN]) {
        out.fill(0);
        out[0] = KIND_BIP39;
        out[1] = if self.signing_key.is_some() {
            FLAG_SIGNING_KEY
        } else {
            0
        };
        out[2] = self.entropy_len;
        out[4..36].copy_from_slice(&self.entropy);
        if let Some(k) = &self.signing_key {
            out[36..68].copy_from_slice(k);
        }
    }

    fn decode(b: &[u8; BODY_LEN]) -> Result<Self, Error> {
        let len = usize::from(b[2]);
        if b[0] != KIND_BIP39
            || b[1] & !FLAG_SIGNING_KEY != 0
            || b[3] != 0
            || b[68..].iter().any(|&x| x != 0)
            || b[4 + len.min(MAX_ENTROPY)..36].iter().any(|&x| x != 0)
        {
            return Err(Error::BadContents);
        }
        let mut c = Contents::bip39(&b[4..4 + len.min(MAX_ENTROPY)])?;
        if b[1] & FLAG_SIGNING_KEY != 0 {
            let mut k = [0u8; 32];
            k.copy_from_slice(&b[36..68]);
            c.signing_key = Some(k);
            k.zeroize();
        } else if b[36..68].iter().any(|&x| x != 0) {
            return Err(Error::BadContents);
        }
        Ok(c)
    }
}

/// Why a record could not be made or opened.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Not a record of this format: erased flash, something else, a later version.
    NotARecord,
    /// The cost is out of bounds (on open: possibly a hostile record).
    BadCost,
    /// Contents that this format can't hold, or a body that decrypted to nonsense.
    BadContents,
    /// The passphrase is wrong -- or the record is not this device's, or was altered.
    /// Deliberately one error: they can't be told apart, and shouldn't be.
    WrongPassphrase,
    /// Argon2 refused (allocation size, parameters).
    Kdf,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::NotARecord => "no sealed seed",
            Error::BadCost => "cost out of bounds",
            Error::BadContents => "bad contents",
            Error::WrongPassphrase => "wrong passphrase",
            Error::Kdf => "key derivation failed",
        })
    }
}

/// The record's public half.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// Argon2id cost.
    pub cost: Cost,
    /// Argon2 salt.
    pub salt: [u8; 16],
    /// AEAD nonce.
    pub nonce: [u8; 12],
}

impl Header {
    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        h[0..4].copy_from_slice(&MAGIC);
        h[4] = VERSION;
        h[5] = KDF_ARGON2ID_13;
        h[8..12].copy_from_slice(&self.cost.t.to_le_bytes());
        h[12..16].copy_from_slice(&self.cost.m_kib.to_le_bytes());
        h[16..20].copy_from_slice(&self.cost.p.to_le_bytes());
        h[20..36].copy_from_slice(&self.salt);
        h[36..48].copy_from_slice(&self.nonce);
        h
    }

    /// Parses the header of `record` without needing any key. Cost bounds are checked.
    pub fn parse(record: &[u8]) -> Result<Header, Error> {
        if record.len() < RECORD_LEN
            || record[0..4] != MAGIC
            || record[4] != VERSION
            || record[5] != KDF_ARGON2ID_13
            || record[6..8] != [0, 0]
        {
            return Err(Error::NotARecord);
        }
        let u = |at: usize| {
            u32::from_le_bytes([record[at], record[at + 1], record[at + 2], record[at + 3]])
        };
        let cost = Cost {
            t: u(8),
            m_kib: u(12),
            p: u(16),
        };
        if !cost.valid() {
            return Err(Error::BadCost);
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&record[20..36]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&record[36..48]);
        Ok(Header { cost, salt, nonce })
    }
}

/// A derived key, wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
struct Key([u8; 32]);

fn derive(passphrase: &[u8], ds: &[u8; 32], h: &Header) -> Result<Key, Error> {
    let params = Argon2Params {
        t_cost: h.cost.t,
        m_cost_kib: h.cost.m_kib,
        parallelism: h.cost.p,
        variant: Argon2Type::Argon2id,
        version: 0x13,
    };
    let mut k = Key([0; 32]);
    argon2(&params, passphrase, &h.salt, ds, AD, &mut k.0).map_err(|_| Error::Kdf)?;
    Ok(k)
}

/// Seals `contents` under `passphrase` and the device secret `ds`. `salt` and `nonce`
/// must be fresh random values for every seal.
pub fn seal(
    contents: &Contents,
    passphrase: &[u8],
    ds: &[u8; 32],
    cost: Cost,
    salt: [u8; 16],
    nonce: [u8; 12],
) -> Result<[u8; RECORD_LEN], Error> {
    if !cost.valid() {
        return Err(Error::BadCost);
    }
    let h = Header { cost, salt, nonce };
    let head = h.encode();
    let key = derive(passphrase, ds, &h)?;
    let mut out = [0u8; RECORD_LEN];
    out[..HEADER_LEN].copy_from_slice(&head);
    let mut body = [0u8; BODY_LEN];
    contents.encode(&mut body);
    let tag = ChaCha20Poly1305::new(&key.0).encrypt(&nonce, &head, &mut body);
    out[HEADER_LEN..HEADER_LEN + BODY_LEN].copy_from_slice(&body);
    out[HEADER_LEN + BODY_LEN..].copy_from_slice(&tag);
    Ok(out)
}

/// Opens a record. Takes as long as the record's cost says, wrong passphrase or not.
pub fn open(record: &[u8], passphrase: &[u8], ds: &[u8; 32]) -> Result<Contents, Error> {
    let h = Header::parse(record)?;
    let key = derive(passphrase, ds, &h)?;
    let mut body = [0u8; BODY_LEN];
    body.copy_from_slice(&record[HEADER_LEN..HEADER_LEN + BODY_LEN]);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&record[HEADER_LEN + BODY_LEN..RECORD_LEN]);
    ChaCha20Poly1305::new(&key.0)
        .decrypt(&h.nonce, &record[..HEADER_LEN], &mut body, &tag)
        .map_err(|_| Error::WrongPassphrase)?;
    let c = Contents::decode(&body);
    body.zeroize();
    c
}
