//! Key Teleport: moving a secret, a backup or a PSBT between two Q1s by QR or NFC.
//!
//! This is **stock's wire format, byte for byte**, so a CatCard Q1 can send to a stock Q1
//! and receive from one. Everything here is the arithmetic and the framing; the screens are
//! the firmware's (`catcard-fw/src/teleport.rs`).
//!
//! Source for every constant and step: hw-reference/key-teleport-protocol.md [C] unless
//! marked otherwise. The test at the bottom reproduces that document's §7 vector exactly.
//!
//! # The handshake
//!
//! 1. The **receiver** picks a secp256k1 keypair and shows its public key as the `R` QR,
//!    AES-CTR-encrypted under the SHA-256 of an eight-digit **receiver password** that is
//!    itself derived from the private key ([`rx_code`]). The password is read aloud.
//! 2. The **sender** scans `R`, types the digits, and recovers the public key
//!    ([`decrypt_rx_pubkey`]). It makes its own keypair, agrees `session_key =
//!    SHA256(X‖Y)` of the shared point ([`ecdh`]), picks a random 40-bit **teleport
//!    password** ([`noid_text`]), stretches the two into an inner key ([`Stretch`]), and
//!    seals the payload in two layers ([`seal`]). It shows the `S` QR -- its own public key
//!    in the clear, then the sealed bytes -- and reads the teleport password aloud.
//! 3. The receiver scans `S`, agrees the same session key, removes the outer layer
//!    ([`open_outer`]), asks for the teleport password and removes the inner one
//!    ([`open_inner`]).
//!
//! The multisig-PSBT variant (`E`) replaces both random keypairs with keys derived from
//! the co-signers' registered xpubs at `…/20250317/ri` ([`psbt_rx_pubkey`],
//! [`psbt_leg_key`]), with `ri` sent in the clear.
//!
//! # What this does and does not protect -- read before trusting it
//!
//! These are stock's choices and they are kept because interoperating is the point. They
//! are also documented in `docs/KEY-TELEPORT.md`.
//!
//! - **The two checksums are unkeyed**: the last two bytes of a plain SHA-256. They catch
//!   a wrong password or a damaged scan with probability `1 - 2^-16` each. They are *not*
//!   a MAC and are not forgery-resistant: this is AES-CTR with no AEAD.
//! - **Confidentiality** rests on the ECDH session key (only the two private keys make it)
//!   plus the teleport password for the inner layer. Someone who photographs both QRs but
//!   heard neither password learns nothing without breaking the ECDH or searching both
//!   passwords.
//! - **Authentication is the spoken passwords.** The receiver password is about 26.6
//!   bits and is what binds the sender to the right receiver; a man in the middle who can
//!   swap the `R` QR *and* hear the digits can substitute his own key. The teleport
//!   password is 40 bits, stretched by 5000 rounds of PBKDF2-HMAC-SHA512 -- modest against
//!   an offline search by someone holding the session key, which only the endpoints have.
//! - **Only about half of wrong receiver passwords are caught** when typed: the check is
//!   whether the decrypted bytes land on the curve ([`decrypt_rx_pubkey`]). The other half
//!   produce a key nobody holds, and the receiver's outer checksum refuses the result.
//! - **Malleability**: CTR ciphertext can be flipped bit for bit. The unkeyed checksums
//!   can be recomputed by anyone who can guess the plaintext they cover, so an attacker
//!   who knows a payload's contents could alter it undetected. In practice the outer layer
//!   is keyed by the session key the attacker lacks, so flips land in bytes the attacker
//!   cannot read; but this is a property of the construction, not of an integrity check.
//! - **No nonce is sent**: both layers start from the all-zero counter. That is safe only
//!   because every session key is fresh (a new random keypair per send, a new `ri` per
//!   PSBT). The receiver keeps its keypair across *failed* attempts (so a sender's payload
//!   stays valid); a second, different send to the same receiver key reuses the outer
//!   keystream only if the sender reuses its keypair, which the sender never does.

use purecrypto::cipher::{Aes256, Ctr};
use purecrypto::ec::secp256k1::{AffinePoint, Scalar};
use purecrypto::hash::{Digest as _, HmacSha512, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::bip32::{ChildNumber, ExtendedPrivKey, ExtendedPubKey};

/// The non-hardened index every PSBT-teleport key is derived under, before `ri`.
/// Source: key-teleport-protocol.md §1b `KT_RXPUBKEY_DERIV` [C]
pub const KT_RXPUBKEY_DERIV: u32 = 20_250_317;

/// `ri` is below this. Source: §1b `ngu.random.uniform(1<<28)` [C]
pub const RI_LIMIT: u32 = 1 << 28;

/// The literal appended to the receiver's private key -- misspelled, as stock has it.
/// Source: §2a [C]
pub const RX_SALT: &[u8] = b"COLCARD4EVER";

/// PBKDF2 rounds for the inner key. Source: §3 `noid_stretch` [C]
pub const NOID_ROUNDS: u32 = 5000;

/// Bytes of teleport password, and its length written in base32.
pub const NOID_LEN: usize = 5;
pub const NOID_TEXT_LEN: usize = 8;

/// Digits in the receiver password.
pub const RX_CODE_LEN: usize = 8;

/// A compressed secp256k1 public key.
pub const PUBKEY_LEN: usize = 33;

/// One truncated SHA-256 checksum, and what the two layers add to a body between them.
pub const CHECK_LEN: usize = 2;
pub const SEAL_OVERHEAD: usize = 2 * CHECK_LEN;

/// The `ri` prefix of an `E` payload.
pub const RI_LEN: usize = 4;

/// The size of a secret stash, as the secure element holds it and as the `s` body
/// re-pads to. Source: §4b `AE_SECRET_LEN` [C]
pub const STASH_LEN: usize = 72;

/// Payloads at least this long are offered by QR only. Source: §5b `NFC_SIZE_LIMIT` [C]
pub const NFC_SIZE_LIMIT: usize = 4096;

/// Where an NFC teleport link points. Source: §5b `KT_DOMAIN` [C]
pub const KT_DOMAIN: &str = "keyteleport.com";

/// What a teleport QR is, as its BBQr file-type letter.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Wire {
    /// `R`: the receiver's encrypted public key.
    Rx,
    /// `S`: sender's public key, then a sealed payload.
    Tx,
    /// `E`: `ri`, then a sealed PSBT for a multisig co-signer.
    Psbt,
}

impl Wire {
    /// The BBQr file-type character. Source: §4c [C]
    pub const fn code(self) -> char {
        match self {
            Wire::Rx => 'R',
            Wire::Tx => 'S',
            Wire::Psbt => 'E',
        }
    }

    /// The kind a file-type character stands for, in either case.
    pub const fn from_code(c: char) -> Option<Self> {
        match c.to_ascii_uppercase() {
            'R' => Some(Wire::Rx),
            'S' => Some(Wire::Tx),
            'E' => Some(Wire::Psbt),
            _ => None,
        }
    }

    /// Stock's `TYPE_LABELS`. Source: §4c [C]
    pub const fn label(self) -> &'static str {
        match self {
            Wire::Rx => "KT Rx",
            Wire::Tx => "KT Tx",
            Wire::Psbt => "KT PSBT",
        }
    }
}

/// What the cleartext body holds, as its leading byte. Source: §4a [C]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Dtype {
    /// `s`: a secret stash, trailing zeros trimmed.
    Secret,
    /// `x`: a binary extended private key. Accepted; stock's own menu never sends one.
    Xprv,
    /// `n`: a JSON array of notes and passwords.
    Notes,
    /// `v`: one Seed Vault entry, as a JSON list.
    Vault,
    /// `p`: a binary PSBT. Sent only as an `E` payload.
    Psbt,
    /// `b`: a backup body with its comment and blank lines removed.
    Backup,
}

impl Dtype {
    pub const fn byte(self) -> u8 {
        match self {
            Dtype::Secret => b's',
            Dtype::Xprv => b'x',
            Dtype::Notes => b'n',
            Dtype::Vault => b'v',
            Dtype::Psbt => b'p',
            Dtype::Backup => b'b',
        }
    }

    /// `r` is listed by stock but has no handler there either, so it is not one of these.
    pub const fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            b's' => Dtype::Secret,
            b'x' => Dtype::Xprv,
            b'n' => Dtype::Notes,
            b'v' => Dtype::Vault,
            b'p' => Dtype::Psbt,
            b'b' => Dtype::Backup,
            _ => return None,
        })
    }
}

/// Why a teleport step refused.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// A public key that is not on the curve, or a private key out of range.
    BadKey,
    /// The outer checksum did not match: wrong receiver key, wrong sender, or a damaged
    /// scan.
    Outer,
    /// The inner checksum did not match: the teleport password is wrong.
    Inner,
    /// Fewer bytes than the framing needs.
    TooShort,
    /// The caller's buffer has no room.
    NoRoom,
    /// Not text this parses: a bad base32 character, a missing header.
    Format,
}

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

/// The last two bytes of `SHA256(data)`: both layers' checksum. Unkeyed.
pub fn checksum(data: &[u8]) -> [u8; CHECK_LEN] {
    let h = Sha256::digest(data);
    [h[30], h[31]]
}

/// [`checksum`] over data that arrives in pieces.
#[derive(Clone)]
pub struct Checksum(Sha256);

impl Default for Checksum {
    fn default() -> Self {
        Self::new()
    }
}

impl Checksum {
    pub fn new() -> Self {
        Checksum(Sha256::new())
    }
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    pub fn finish(self) -> [u8; CHECK_LEN] {
        let h = self.0.finalize();
        [h[30], h[31]]
    }
}

/// AES-256-CTR from the all-zero counter block, which is how stock's `aes256ctr.new(key)`
/// starts. Encrypts and decrypts alike, and continues across calls.
/// Source: §3 "Cipher" [C]
pub struct Keystream(Ctr<Aes256>);

impl Keystream {
    pub fn new(key: &[u8; 32]) -> Self {
        Keystream(Ctr::new(Aes256::new(key), &[0u8; 16]))
    }
    pub fn apply(&mut self, data: &mut [u8]) {
        self.0.apply_keystream(data);
    }
}

/// A 32-byte key derived from private-key work: the ECDH session key, or the inner key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key32([u8; 32]);

impl Key32 {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    /// For a test or a caller that already holds the bytes.
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Key32(b)
    }
}

/// `session_key = SHA256(X‖Y)` of `my_priv * his_pub`, affine coordinates big-endian.
///
/// Not the x coordinate alone and not libsecp256k1's default hash of the compressed point.
/// Source: §1 "Shared-secret derivation" [C]
pub fn ecdh(
    my_priv: &[u8; 32],
    his_pub: &[u8; PUBKEY_LEN],
    _kw: &crate::KeyWork,
) -> Result<Key32, Error> {
    let scalar = Scalar::from_bytes_be(my_priv).map_err(|_| Error::BadKey)?;
    if bool::from(scalar.is_zero()) {
        return Err(Error::BadKey);
    }
    let point = AffinePoint::from_sec1(his_pub).map_err(|_| Error::BadKey)?;
    let shared = point
        .to_projective()
        .mul(&scalar)
        .to_affine()
        .ok_or(Error::BadKey)?;
    let mut xy = Zeroizing::new([0u8; 64]);
    xy[..32].copy_from_slice(&shared.x_bytes());
    xy[32..].copy_from_slice(&shared.y_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(&xy[..]));
    Ok(Key32(out))
}

/// The compressed public key of a private key, or `BadKey` for one out of range.
pub fn public_key(priv_key: &[u8; 32], kw: &crate::KeyWork) -> Result<[u8; PUBKEY_LEN], Error> {
    crate::bip32::public_key_of(priv_key, kw).ok_or(Error::BadKey)
}

// ---------------------------------------------------------------------------
// The receiver password
// ---------------------------------------------------------------------------

/// What the receiver shows: the eight digits and the 33-byte `R` payload.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RxCode {
    /// ASCII digits, zero-padded: `%08d`.
    pub digits: [u8; RX_CODE_LEN],
    pub payload: [u8; PUBKEY_LEN],
}

impl RxCode {
    pub fn digits_str(&self) -> &str {
        core::str::from_utf8(&self.digits).unwrap_or("")
    }
}

/// The receiver password and `R` payload for a receiver private key.
///
/// Deterministic, so a receive resumed with the same key shows the same digits and the
/// same QR. Source: §2a `generate_rx_code` [C]
pub fn rx_code(priv_key: &[u8; 32], kw: &crate::KeyWork) -> Result<RxCode, Error> {
    let mut pubkey = public_key(priv_key, kw)?;
    // nk = sha256d(priv || "COLCARD4EVER")
    let mut h = Sha256::new();
    h.update(priv_key);
    h.update(RX_SALT);
    let once = h.finalize();
    let nk = Zeroizing::new(Sha256::digest(&once[..]));
    // Only bit 0 of the prefix says anything; the other seven are masked with noise.
    pubkey[0] ^= nk[20] & 0xfe;
    let num = u32::from_be_bytes([nk[4], nk[5], nk[6], nk[7]]) % 100_000_000;
    let digits = format_code(num);
    let kk = Zeroizing::new(Sha256::digest(&digits[..]));
    let mut key = [0u8; 32];
    key.copy_from_slice(&kk[..]);
    Keystream::new(&key).apply(&mut pubkey);
    key.zeroize();
    Ok(RxCode {
        digits,
        payload: pubkey,
    })
}

/// `%08d`.
pub fn format_code(num: u32) -> [u8; RX_CODE_LEN] {
    let mut out = [b'0'; RX_CODE_LEN];
    let mut n = num % 100_000_000;
    for slot in out.iter_mut().rev() {
        *slot = b'0' + (n % 10) as u8;
        n /= 10;
    }
    out
}

/// The receiver's public key from an `R` payload and the digits typed, or `None` when the
/// result is not a point -- which is how about half of wrong passwords are caught.
/// Source: §2a `decrypt_rx_pubkey` [C]
pub fn decrypt_rx_pubkey(
    digits: &[u8; RX_CODE_LEN],
    payload: &[u8; PUBKEY_LEN],
) -> Option<[u8; PUBKEY_LEN]> {
    let kk = Sha256::digest(&digits[..]);
    let mut key = [0u8; 32];
    key.copy_from_slice(&kk[..]);
    let mut rx = *payload;
    Keystream::new(&key).apply(&mut rx);
    rx[0] &= 0x01;
    rx[0] |= 0x02;
    AffinePoint::from_sec1(&rx).ok().map(|_| rx)
}

// ---------------------------------------------------------------------------
// The teleport password
// ---------------------------------------------------------------------------

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The teleport password as shown: five bytes, eight base32 characters, no padding.
/// Source: §2b [C]
pub fn noid_text(key: &[u8; NOID_LEN]) -> [u8; NOID_TEXT_LEN] {
    let mut group = [0u8; 8];
    group[3..].copy_from_slice(key);
    let bits = u64::from_be_bytes(group);
    let mut out = [0u8; NOID_TEXT_LEN];
    for (i, c) in out.iter_mut().enumerate() {
        *c = B32[(bits >> (35 - 5 * i)) as usize & 31];
    }
    group.zeroize();
    out
}

/// The five bytes a typed teleport password stands for.
///
/// Case-insensitive, and the glyphs people confuse are mapped as stock's decoder maps
/// them: `0`→`O`, `1`→`L`, `8`→`B`. Spaces and dashes are ignored, so a password read out
/// in two groups can be typed that way. `None` for anything else or a wrong length.
/// Source: §2b "Entry / decode" [C]
pub fn noid_parse(text: &str) -> Option<[u8; NOID_LEN]> {
    let mut bits = 0u64;
    let mut n = 0usize;
    for c in text.bytes() {
        let c = match c.to_ascii_uppercase() {
            b' ' | b'-' => continue,
            b'0' => b'O',
            b'1' => b'L',
            b'8' => b'B',
            other => other,
        };
        let v = B32.iter().position(|&b| b == c)? as u64;
        n += 1;
        if n > NOID_TEXT_LEN {
            return None;
        }
        bits = (bits << 5) | v;
    }
    if n != NOID_TEXT_LEN {
        return None;
    }
    let b = bits.to_be_bytes();
    let mut out = [0u8; NOID_LEN];
    out.copy_from_slice(&b[3..]);
    Some(out)
}

/// `PBKDF2-HMAC-SHA512(password = session_key, salt = noid, 5000)[..32]`, sliced.
///
/// The session key is the *password* and the noid key the *salt* -- stock's argument
/// order. Stepped on a fixed round count, never on anything derived from a key, so a
/// screen can move between slices. Source: §3 `noid_stretch` [C]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Stretch {
    password: [u8; 32],
    u: [u8; 64],
    acc: [u8; 64],
    left: u32,
}

impl Stretch {
    /// Run U1.
    pub fn begin(session: &Key32, noid: &[u8; NOID_LEN], _kw: &crate::KeyWork) -> Self {
        let mut mac = HmacSha512::new(session.as_bytes());
        mac.update(noid);
        mac.update(&1u32.to_be_bytes());
        let u: [u8; 64] = mac.finalize();
        Stretch {
            password: *session.as_bytes(),
            u,
            acc: u,
            left: NOID_ROUNDS - 1,
        }
    }

    /// Rounds still to run.
    pub fn left(&self) -> u32 {
        self.left
    }

    /// Run up to `rounds` more. True when there are none left.
    pub fn step(&mut self, rounds: u32, _kw: &crate::KeyWork) -> bool {
        let n = rounds.min(self.left);
        for _ in 0..n {
            let mut mac = HmacSha512::new(&self.password);
            mac.update(&self.u);
            self.u = mac.finalize();
            for (o, x) in self.acc.iter_mut().zip(self.u.iter()) {
                *o ^= x;
            }
        }
        self.left -= n;
        self.left == 0
    }

    /// The inner key. Call once [`step`](Self::step) has returned true.
    pub fn finish(mut self, _kw: &crate::KeyWork) -> Key32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.acc[..32]);
        self.zeroize();
        Key32(out)
    }
}

/// The inner key in one go, for a host or a test.
pub fn inner_key(session: &Key32, noid: &[u8; NOID_LEN], kw: &crate::KeyWork) -> Key32 {
    let mut s = Stretch::begin(session, noid, kw);
    while !s.step(NOID_ROUNDS, kw) {}
    s.finish(kw)
}

// ---------------------------------------------------------------------------
// The two layers
// ---------------------------------------------------------------------------

/// Seal `buf[..body_len]` in place: inner layer and its checksum, then the outer layer
/// over both and its checksum. `buf` needs [`SEAL_OVERHEAD`] bytes of room past the
/// body. Returns the sealed length (`b2`, checksum included).
/// Source: §3 `encode_payload` [C]
pub fn seal(
    session: &Key32,
    inner: &Key32,
    buf: &mut [u8],
    body_len: usize,
) -> Result<usize, Error> {
    let total = body_len + SEAL_OVERHEAD;
    if buf.len() < total {
        return Err(Error::NoRoom);
    }
    let n = body_len;
    // b1 = AES(inner)(body) || sha256(body)[-2:]
    let c1 = checksum(&buf[..n]);
    Keystream::new(inner.as_bytes()).apply(&mut buf[..n]);
    buf[n..n + CHECK_LEN].copy_from_slice(&c1);
    // b2 = AES(session)(b1) || sha256(b1)[-2:]
    let m = n + CHECK_LEN;
    let c2 = checksum(&buf[..m]);
    Keystream::new(session.as_bytes()).apply(&mut buf[..m]);
    buf[m..m + CHECK_LEN].copy_from_slice(&c2);
    Ok(total)
}

/// Remove the outer layer from `buf` (all of `b2`) in place. Returns the length of `b1`.
///
/// On a checksum failure the bytes are put back as they were -- CTR undoes itself -- so a
/// caller can try another key against the same buffer. Source: §3 `decode_step1` [C]
pub fn open_outer(session: &Key32, buf: &mut [u8]) -> Result<usize, Error> {
    open_layer(session, buf, Error::Outer)
}

/// Remove the inner layer from `buf` (all of `b1`) in place. Returns the body's length.
/// A wrong teleport password leaves the buffer as it was. Source: §3 `decode_step2` [C]
pub fn open_inner(inner: &Key32, buf: &mut [u8]) -> Result<usize, Error> {
    open_layer(inner, buf, Error::Inner)
}

fn open_layer(key: &Key32, buf: &mut [u8], wrong: Error) -> Result<usize, Error> {
    if buf.len() < CHECK_LEN {
        return Err(Error::TooShort);
    }
    let n = buf.len() - CHECK_LEN;
    let (data, check) = buf.split_at_mut(n);
    Keystream::new(key.as_bytes()).apply(data);
    if checksum(data) != *check {
        Keystream::new(key.as_bytes()).apply(data);
        return Err(wrong);
    }
    Ok(n)
}

// ---------------------------------------------------------------------------
// Payload framing
// ---------------------------------------------------------------------------

/// An `S` payload's sender key and sealed bytes. Source: §4c [C]
pub fn split_tx(payload: &[u8]) -> Result<([u8; PUBKEY_LEN], &[u8]), Error> {
    if payload.len() < PUBKEY_LEN + SEAL_OVERHEAD {
        return Err(Error::TooShort);
    }
    let mut key = [0u8; PUBKEY_LEN];
    key.copy_from_slice(&payload[..PUBKEY_LEN]);
    Ok((key, &payload[PUBKEY_LEN..]))
}

/// An `E` payload's `ri` and sealed bytes. Source: §4c [C]
pub fn split_psbt(payload: &[u8]) -> Result<(u32, &[u8]), Error> {
    if payload.len() < RI_LEN + SEAL_OVERHEAD {
        return Err(Error::TooShort);
    }
    let ri = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    Ok((ri, &payload[RI_LEN..]))
}

/// An `ri` from four random bytes: uniform below 2^28. Source: §1b [C]
pub fn ri_from(random: [u8; 4]) -> u32 {
    u32::from_be_bytes(random) & (RI_LIMIT - 1)
}

/// The receiver's key for a PSBT teleport: his registered xpub, then `20250317/ri`, both
/// non-hardened. Public data only. Source: §1b `kt_make_rxkey` [C]
pub fn psbt_rx_pubkey(xpub: &ExtendedPubKey, ri: u32) -> Result<[u8; PUBKEY_LEN], Error> {
    let a = ChildNumber::normal(KT_RXPUBKEY_DERIV).map_err(|_| Error::BadKey)?;
    let b = ChildNumber::normal(ri).map_err(|_| Error::BadKey)?;
    let key = xpub
        .derive_child(a)
        .and_then(|k| k.derive_child(b))
        .map_err(|_| Error::BadKey)?;
    Ok(key.public_key)
}

/// Our own private key for a PSBT teleport: our multisig leg (the key at the origin path
/// the wallet names for us), then `20250317/ri`. Source: §1b `kt_my_keypair` [C]
pub fn psbt_leg_key(
    leg: &ExtendedPrivKey,
    ri: u32,
    kw: &crate::KeyWork,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let a = ChildNumber::normal(KT_RXPUBKEY_DERIV).map_err(|_| Error::BadKey)?;
    let b = ChildNumber::normal(ri).map_err(|_| Error::BadKey)?;
    let key = leg
        .derive_child(a, kw)
        .and_then(|k| k.derive_child(b, kw))
        .map_err(|_| Error::BadKey)?;
    Ok(Zeroizing::new(*key.secret_bytes()))
}

// ---------------------------------------------------------------------------
// The `s` body: a secret stash
// ---------------------------------------------------------------------------

/// How many bytes of a stash go on the wire: everything up to the last non-zero byte.
/// Source: §4b [C]
pub fn stash_wire_len(stash: &[u8; STASH_LEN]) -> usize {
    stash.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1)
}

/// A received `s` body re-padded into a stash. `None` for an empty one or one too long.
pub fn stash_from_wire(data: &[u8]) -> Option<Zeroizing<[u8; STASH_LEN]>> {
    if data.is_empty() || data.len() > STASH_LEN || data[0] == 0 {
        return None;
    }
    let mut out = Zeroizing::new([0u8; STASH_LEN]);
    out[..data.len()].copy_from_slice(data);
    Some(out)
}

/// What a stash marker says the secret is, for a screen. Source: §4b `summary` [C]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum StashKind {
    /// BIP-39 words: 12, 18 or 24.
    Words(u8),
    /// A BIP-32 root: chain code and key.
    Xprv,
    /// A raw master secret of this many bytes.
    Raw(u8),
}

pub fn stash_kind(marker: u8) -> Option<StashKind> {
    match marker {
        0x80..=0x82 => Some(StashKind::Words(match marker & 0x7f {
            0 => 12,
            1 => 18,
            _ => 24,
        })),
        0x01 => Some(StashKind::Xprv),
        16..=64 => Some(StashKind::Raw(marker)),
        _ => None,
    }
}

/// A received `x` body as an extended private key: the 78 serialised bytes, with or
/// without the four-byte base58 checksum after them. Source: §4a [C]
pub fn xprv_from_wire(data: &[u8], kw: &crate::KeyWork) -> Result<ExtendedPrivKey, Error> {
    const RAW: usize = crate::bip32::serialize::RAW_LEN;
    let raw = match data.len() {
        RAW => data,
        n if n == RAW + 4 => {
            let check = crate::encoding::base58::checksum(&data[..RAW]);
            if check[..] != data[RAW..] {
                return Err(Error::Format);
            }
            &data[..RAW]
        }
        _ => return Err(Error::Format),
    };
    ExtendedPrivKey::from_raw(raw, kw).map_err(|_| Error::Format)
}

// ---------------------------------------------------------------------------
// The `b` body: a backup without its comments
// ---------------------------------------------------------------------------

/// Drop comment lines and blank lines from a backup body, in place, joining what is left
/// with `\n` and no newline at the end. Returns the new length. Source: §4a [C]
pub fn strip_backup(buf: &mut [u8], len: usize) -> usize {
    let len = len.min(buf.len());
    let mut out = 0usize;
    let mut at = 0usize;
    while at < len {
        let end = buf[at..len]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(len, |p| at + p);
        let mut line_end = end;
        if line_end > at && buf[line_end - 1] == b'\r' {
            line_end -= 1;
        }
        let line = &buf[at..line_end];
        let first = line.iter().position(|b| !b.is_ascii_whitespace());
        let keep = match first {
            None => false,
            Some(i) => line[i] != b'#',
        };
        if keep {
            if out > 0 {
                buf[out] = b'\n';
                out += 1;
            }
            let n = line_end - at;
            buf.copy_within(at..line_end, out);
            out += n;
        }
        at = end + 1;
    }
    buf[out..len].zeroize();
    out
}

// ---------------------------------------------------------------------------
// Transport text
// ---------------------------------------------------------------------------

/// Base32 with `=` padding to a multiple of eight, as stock's `b32encode` writes the last
/// (or only) part. Returns the characters written.
pub fn b32_encode_padded(data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let len = data.len().div_ceil(5) * 8;
    let out = out.get_mut(..len).ok_or(Error::NoRoom)?;
    let used = (data.len() * 8).div_ceil(5);
    for (chars, bytes) in out.chunks_mut(8).zip(data.chunks(5)) {
        let mut group = [0u8; 8];
        group[3..3 + bytes.len()].copy_from_slice(bytes);
        let bits = u64::from_be_bytes(group);
        for (i, c) in chars.iter_mut().enumerate() {
            *c = B32[(bits >> (35 - 5 * i)) as usize & 31];
        }
    }
    for c in &mut out[used..] {
        *c = b'=';
    }
    Ok(len)
}

/// The BBQr header of a single-part teleport code: `B$2` `<t>` `0100`. Source: §5b [C]
pub fn short_header(wire: Wire) -> [u8; 8] {
    [b'B', b'$', b'2', wire.code() as u8, b'0', b'1', b'0', b'0']
}

/// A payload as one BBQr part: header, then padded base32. Source: §5b `short_bbqr` [C]
pub fn short_bbqr(wire: Wire, data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let body = out.get_mut(8..).ok_or(Error::NoRoom)?;
    let n = b32_encode_padded(data, body)?;
    out[..8].copy_from_slice(&short_header(wire));
    Ok(8 + n)
}

/// The NFC link, without its `https://`, which an NDEF URI record carries as one prefix
/// byte: `keyteleport.com/#B$2…`. Source: §5b [C]
pub fn nfc_url(wire: Wire, data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let head = KT_DOMAIN.len() + 2;
    if out.len() < head {
        return Err(Error::NoRoom);
    }
    out[..KT_DOMAIN.len()].copy_from_slice(KT_DOMAIN.as_bytes());
    out[KT_DOMAIN.len()..head].copy_from_slice(b"/#");
    let n = short_bbqr(wire, data, &mut out[head..])?;
    Ok(head + n)
}

/// The length of what [`nfc_url`] writes for `data_len` bytes.
pub const fn nfc_url_len(data_len: usize) -> usize {
    KT_DOMAIN.len() + 2 + 8 + data_len.div_ceil(5) * 8
}

/// The BBQr text inside a teleport link, with or without its scheme, or the text itself
/// if it is already a teleport code. `None` for anything else.
pub fn code_in(text: &str) -> Option<&str> {
    let t = text.trim();
    let t = t.strip_prefix("https://").unwrap_or(t);
    let t = match t.get(..KT_DOMAIN.len()) {
        Some(d) if d.eq_ignore_ascii_case(KT_DOMAIN) => {
            let rest = &t[KT_DOMAIN.len()..];
            rest.strip_prefix("/#").or_else(|| rest.strip_prefix('#'))?
        }
        _ => t,
    };
    let b = t.as_bytes();
    if b.len() >= 8 && &b[..3] == b"B$2" && Wire::from_code(b[3] as char).is_some() {
        Some(t)
    } else {
        None
    }
}

/// Which teleport kind a single BBQr part is, from its header. `None` if it is not one.
pub fn wire_of(text: &str) -> Option<Wire> {
    let t = code_in(text)?;
    Wire::from_code(t.as_bytes()[3] as char)
}

/// Decode a **single-part** teleport code (padding or not) into `out`. Returns its kind and
/// the payload length. Multi-part transfers go through the firmware's BBQr collector.
pub fn parse_short(text: &str, out: &mut [u8]) -> Result<(Wire, usize), Error> {
    let t = code_in(text).ok_or(Error::Format)?;
    let b = t.as_bytes();
    let wire = Wire::from_code(b[3] as char).ok_or(Error::Format)?;
    if &b[4..8] != b"0100" {
        return Err(Error::Format);
    }
    let body = t[8..].trim_end_matches('=');
    let n = b32_decode(body.as_bytes(), out)?;
    Ok((wire, n))
}

/// Unpadded base32, case-insensitive, trailing bits zero.
fn b32_decode(text: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    if matches!(text.len() % 8, 1 | 3 | 6) {
        return Err(Error::Format);
    }
    let len = text.len() * 5 / 8;
    let out = out.get_mut(..len).ok_or(Error::NoRoom)?;
    for (chars, bytes) in text.chunks(8).zip(out.chunks_mut(5)) {
        let mut bits = 0u64;
        for &c in chars {
            let v = B32
                .iter()
                .position(|&b| b == c.to_ascii_uppercase())
                .ok_or(Error::Format)? as u64;
            bits = (bits << 5) | v;
        }
        bits <<= 5 * (8 - chars.len());
        let group = &bits.to_be_bytes()[3..];
        if group[bytes.len()..].iter().any(|&b| b != 0) {
            return Err(Error::Format);
        }
        bytes.copy_from_slice(&group[..bytes.len()]);
    }
    Ok(len)
}

#[cfg(test)]
mod tests;
