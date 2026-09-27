//! `authenticatorClientPIN`: the security-key PIN a browser asks for, and the
//! pinUvAuthToken it trades it for.
//!
//! The PIN is typed **on the computer** and never crosses the wire in the clear: the
//! platform and the device agree a shared secret over P-256 ECDH, the platform encrypts
//! `LEFT(SHA-256(PIN), 16)` under it, and the device answers with a random token -- the
//! pinUvAuthToken -- that the platform then uses to MAC each request that needs user
//! verification. What the device keeps is only that 16-byte hash and a retries counter,
//! per wallet, in the wallet's own settings.
//!
//! Source: FIDO CTAP 2.1 (Proposed Standard, 2021-06-15, errata 2022-06-21) §6.5 [C]:
//! §6.5.2 the global state, §6.5.3.2 the token's state functions, §6.5.5 the command,
//! §6.5.6 and §6.5.7 PIN/UV auth protocols One and Two. Section numbers below are that
//! document's.
//!
//! # Where this departs from the letter, and why
//!
//! - **Every token is asked for on the device** (§6.5.5.7.1/2 step "If the authenticator
//!   has a display, request user consent"). A person presses before a PIN is even
//!   checked, so software on the computer cannot burn the eight retries -- and block the
//!   key, which only a reset (losing every passkey) undoes -- without someone at the
//!   device.
//! - **That press counts as the request's presence.** The token is begun with
//!   `userIsPresent: true` where §6.5.5.7.2 says `false`, for the user-present time limit
//!   ([`UP_MS`]): the person just answered a question naming the site, so the
//!   MakeCredential or GetAssertion that follows does not ask again. Without this every
//!   passkey sign-in would be two presses on the device. It is exactly what §6.5.5.7.3
//!   does for a built-in method that collects presence.
//! - **setPIN and changePIN are asked on the device** too. CTAP does not require it; a
//!   browser setting or changing the PIN of a key in someone's pocket is the thing this
//!   device exists to make impossible.
//! - A request that needs the PIN while none is set, or after it is blocked, is answered
//!   `CTAP2_ERR_PIN_NOT_SET` / `CTAP2_ERR_PIN_BLOCKED` before anything is decrypted.
//!
//! # Power cycles
//!
//! The "three consecutive mismatches, then power cycle" rule (§6.5.5.7.1) is kept in
//! [`Session`], which lives in RAM for as long as the device is on: unplugging it is the
//! power cycle. The retries counter is **written before the comparison's result is acted
//! on**, so cutting the power in the middle of a guess does not give the guess back.

use catcard_wallet::KeyWork;
use purecrypto::cipher::{Aes256, Cbc};
use purecrypto::ct::ConstantTimeEq;
use purecrypto::ec::ecdh::EcdhPrivateKey;
use purecrypto::ec::ecdsa::EcdsaPublicKey;
use purecrypto::hash::{Digest, HmacSha256, Sha256};
use purecrypto::kdf::hkdf;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::cbor::{self, Key, Reader, Writer};
use crate::ctap2::{Ask, Env, Note, Presence, status};

/// The PIN/UV auth protocols, in the order GetInfo offers them: Two first (§6.5.7, the
/// one a FIPS-minded platform wants), then One for CTAP 2.0 platforms.
/// Source: §6.4 `pinUvAuthProtocols` "in order of decreasing authenticator preference" [C]
pub const PROTOCOLS: [u8; 2] = [2, 1];

/// Retries a PIN starts with, and goes back to after a correct entry.
/// Source: §6.5.2.2 "Authenticators MUST allow no more than 8 retries" [C]
pub const MAX_RETRIES: u8 = 8;

/// Consecutive wrong PINs before the device wants a power cycle.
/// Source: §6.5.5.6, §6.5.5.7.1 "3 consecutive mismatches" [C]
pub const MISMATCH_LIMIT: u8 = 3;

/// The shortest PIN accepted, in Unicode code points. Source: §6.5.1 [C]
pub const MIN_PIN_LEN: usize = 4;
/// The longest, in UTF-8 bytes. Source: §6.5.1 [C]
pub const MAX_PIN_BYTES: usize = 63;
/// `newPinEnc`'s plaintext: the PIN padded with zeros. Source: §6.5.5.5 [C]
pub const PADDED_PIN: usize = 64;

/// A token must be used within this long of being issued, or it lapses.
/// Source: §6.5.2.1 "usb: 30 seconds" [C]
pub const INITIAL_USAGE_MS: u32 = 30_000;
/// And lives at most this long however much it is used. Source: §6.5.2.1 "10 minutes" [C]
pub const MAX_USAGE_MS: u32 = 600_000;
/// How long the press given for a token counts as presence. Source: §6.5.2.1 "user
/// present time limit ... defaults to the same ... as the initial usage time limit" [C]
pub const UP_MS: u32 = 30_000;
/// How long a stateful command's state is kept (GetNextAssertion, the credential
/// management enumerations). Source: §6.3 "greater than 30 seconds" [C]
pub const NEXT_MS: u32 = 30_000;

/// Token permissions. Source: §6.5.5.7 table [C]
pub mod perm {
    pub const MC: u8 = 0x01;
    pub const GA: u8 = 0x02;
    pub const CM: u8 = 0x04;
    pub const BE: u8 = 0x08;
    pub const LBW: u8 = 0x10;
    pub const ACFG: u8 = 0x20;
}

/// authenticatorClientPIN subcommands. Source: §6.5.5 [C]
pub mod sub {
    pub const GET_PIN_RETRIES: u64 = 0x01;
    pub const GET_KEY_AGREEMENT: u64 = 0x02;
    pub const SET_PIN: u64 = 0x03;
    pub const CHANGE_PIN: u64 = 0x04;
    pub const GET_PIN_TOKEN: u64 = 0x05;
    pub const GET_TOKEN_USING_UV: u64 = 0x06;
    pub const GET_UV_RETRIES: u64 = 0x07;
    pub const GET_TOKEN_USING_PIN: u64 = 0x09;
}

/// The COSE algorithm a key-agreement key is labelled with: ECDH-ES+HKDF-256, "although
/// this is not the algorithm actually used". Source: §6.5.6 getPublicKey [C]
pub const ECDH_ES_HKDF_256: i64 = -25;

/// The PIN as a wallet stores it: `LEFT(SHA-256(PIN), 16)` and the retries left.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct PinRecord {
    pub retries: u8,
    pub hash: [u8; 16],
}

impl PinRecord {
    /// A new PIN, with every retry. `pin` is the PIN's UTF-8 bytes.
    pub fn new(pin: &[u8], _kw: &KeyWork) -> Self {
        let mut d = Sha256::digest(pin);
        let mut hash = [0u8; 16];
        hash.copy_from_slice(&d[..16]);
        d.zeroize();
        Self {
            retries: MAX_RETRIES,
            hash,
        }
    }
}

// ---------------------------------------------------------------------------------------
// The protocols' primitives
// ---------------------------------------------------------------------------------------

/// A shared secret: 32 bytes for protocol One, 64 (HMAC key ‖ AES key) for Two.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Shared {
    protocol: u8,
    bytes: [u8; 64],
}

impl Shared {
    /// `kdf(Z)`. Source: §6.5.6 (SHA-256(Z)) and §6.5.7 (two HKDF-SHA-256 calls, salt 32
    /// zero bytes, infos "CTAP2 HMAC key" and "CTAP2 AES key") [C]
    pub fn from_z(protocol: u8, z: &[u8; 32]) -> Self {
        let mut s = Shared {
            protocol,
            bytes: [0; 64],
        };
        if protocol == 1 {
            s.bytes[..32].copy_from_slice(&Sha256::digest(z));
        } else {
            hkdf::<Sha256>(&[0u8; 32], z, b"CTAP2 HMAC key", &mut s.bytes[..32]);
            hkdf::<Sha256>(&[0u8; 32], z, b"CTAP2 AES key", &mut s.bytes[32..]);
        }
        s
    }

    fn aes_key(&self) -> &[u8; 32] {
        let k = if self.protocol == 1 {
            &self.bytes[..32]
        } else {
            &self.bytes[32..]
        };
        k.try_into().expect("32 bytes")
    }

    fn hmac_key(&self) -> &[u8] {
        &self.bytes[..32]
    }

    /// The bytes a ciphertext of `n` plaintext bytes takes. Protocol Two prefixes the IV.
    pub fn ciphertext_len(&self, n: usize) -> usize {
        if self.protocol == 1 { n } else { 16 + n }
    }

    /// `encrypt(key, plaintext)` into `out`, which is [`ciphertext_len`](Self::ciphertext_len)
    /// long. `iv` is used by protocol Two only (One's IV is all zero). Source: §6.5.6,
    /// §6.5.7 [C]
    pub fn encrypt(&self, plain: &[u8], iv: &[u8; 16], out: &mut [u8]) -> Option<usize> {
        if !plain.len().is_multiple_of(16) {
            return None;
        }
        let n = self.ciphertext_len(plain.len());
        let out = out.get_mut(..n)?;
        let (iv, body) = if self.protocol == 1 {
            ([0u8; 16], &mut out[..])
        } else {
            out[..16].copy_from_slice(iv);
            (*iv, &mut out[16..])
        };
        body.copy_from_slice(plain);
        Cbc::new(Aes256::new(self.aes_key()), &iv)
            .encrypt(body)
            .ok()?;
        Some(n)
    }

    /// `decrypt(key, ciphertext)` into `out`; its length. `None` for a ciphertext that
    /// is not whole blocks (or, for Two, shorter than its IV). Source: §6.5.6, §6.5.7 [C]
    pub fn decrypt(&self, ct: &[u8], out: &mut [u8]) -> Option<usize> {
        let (iv, body) = if self.protocol == 1 {
            ([0u8; 16], ct)
        } else {
            if ct.len() < 16 {
                return None;
            }
            (ct[..16].try_into().ok()?, &ct[16..])
        };
        if !body.len().is_multiple_of(16) {
            return None;
        }
        let o = out.get_mut(..body.len())?;
        o.copy_from_slice(body);
        Cbc::new(Aes256::new(self.aes_key()), &iv).decrypt(o).ok()?;
        Some(body.len())
    }

    /// `authenticate(sharedSecret, message)`: the MAC and its length. What a platform
    /// sends; the device only verifies.
    pub fn authenticate(&self, parts: &[&[u8]]) -> ([u8; 32], usize) {
        authenticate(self.protocol, self.hmac_key(), parts)
    }

    /// `verify(sharedSecret, message, signature)`.
    pub fn verify(&self, parts: &[&[u8]], sig: &[u8]) -> bool {
        verify(self.protocol, self.hmac_key(), parts, sig)
    }
}

/// `authenticate(key, message)`: HMAC-SHA-256, cut to 16 bytes for protocol One.
/// Source: §6.5.6, §6.5.7 [C]
pub fn authenticate(protocol: u8, key: &[u8], parts: &[&[u8]]) -> ([u8; 32], usize) {
    let mut h = HmacSha256::new(&key[..key.len().min(32)]);
    for p in parts {
        h.update(p);
    }
    let mac = h.finalize();
    (mac, if protocol == 1 { 16 } else { 32 })
}

/// `verify(key, message, signature)`, in constant time: `signature` must be exactly the
/// protocol's MAC length. Source: §6.5.6, §6.5.7 [C]
pub fn verify(protocol: u8, key: &[u8], parts: &[&[u8]], sig: &[u8]) -> bool {
    let (mut mac, n) = authenticate(protocol, key, parts);
    let ok = sig.len() == n && bool::from(mac[..n].ct_eq(sig));
    mac.zeroize();
    ok
}

/// A platform's key-agreement key, read from its COSE_Key: an uncompressed P-256 point.
/// Source: §6.5.6 getPublicKey (kty 2, alg, crv 1, x, y) [C]
pub fn read_cose_key(r: &mut Reader<'_>) -> Result<[u8; 65], u8> {
    let c = |e: cbor::Error| match e {
        cbor::Error::Unexpected => status::CBOR_UNEXPECTED_TYPE,
        _ => status::INVALID_CBOR,
    };
    let mut m = r.map().map_err(c)?;
    let (mut kty, mut alg, mut crv) = (None, None, None);
    let mut point = [0u8; 65];
    point[0] = 0x04;
    let (mut x, mut y) = (false, false);
    while let Some(k) = r.key(&mut m).map_err(c)? {
        match k {
            Key::Int(1) => kty = Some(r.int().map_err(c)?),
            Key::Int(3) => alg = Some(r.int().map_err(c)?),
            Key::Int(-1) => crv = Some(r.int().map_err(c)?),
            Key::Int(-2) | Key::Int(-3) => {
                let b = r.bytes().map_err(c)?;
                if b.len() != 32 {
                    return Err(status::INVALID_PARAMETER);
                }
                if k == Key::Int(-2) {
                    point[1..33].copy_from_slice(b);
                    x = true;
                } else {
                    point[33..].copy_from_slice(b);
                    y = true;
                }
            }
            _ => r.skip(cbor::MAX_DEPTH - 3).map_err(c)?,
        }
    }
    match (kty, alg, crv, x, y) {
        (Some(2), Some(_), Some(1), true, true) => Ok(point),
        (Some(_), Some(_), Some(_), true, true) => Err(status::INVALID_PARAMETER),
        _ => Err(status::MISSING_PARAMETER),
    }
}

/// A key-agreement public key as a COSE_Key. Source: §6.5.6 getPublicKey [C]
pub fn write_cose_key(w: &mut Writer<'_>, xy: &[u8; 64]) {
    w.map(5)
        .int(1)
        .int(2)
        .int(3)
        .int(ECDH_ES_HKDF_256)
        .int(-1)
        .int(1)
        .int(-2)
        .bytes(&xy[..32])
        .int(-3)
        .bytes(&xy[32..]);
}

// ---------------------------------------------------------------------------------------
// The state kept while the device is on
// ---------------------------------------------------------------------------------------

/// A stateful command's cursor: what the next "get next" returns. Source: §6.3, §6.8.3,
/// §6.8.4 [C]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Cursor {
    None,
    /// authenticatorGetNextAssertion: the site, the request's clientDataHash, the flags
    /// the first answer carried, and which credential (newest first) is next.
    Assertion {
        rp: [u8; 32],
        cdh: [u8; 32],
        next: u8,
        total: u8,
        up: bool,
        uv: bool,
        since: u32,
    },
    /// enumerateRPsGetNextRP.
    Rps {
        next: u8,
        total: u8,
        since: u32,
    },
    /// enumerateCredentialsGetNextCredential.
    Creds {
        rp: [u8; 32],
        next: u8,
        total: u8,
        since: u32,
    },
}

/// Everything the PIN/UV auth protocols keep from power-up to power-off: the key-agreement
/// keys, the one pinUvAuthToken and its state, the consecutive-mismatch count, and the
/// stateful commands' cursor. Nothing here is written to flash.
pub struct Session {
    /// Key-agreement private keys, per protocol (index 0 is Two, 1 is One), made when
    /// first asked for. Source: §6.5.6 "regenerate" [C]
    ka: [[u8; 32]; 2],
    ka_pub: [[u8; 64]; 2],
    ka_set: [bool; 2],
    /// The pinUvAuthToken, for `token_protocol` (0: none in use). Getting a new one
    /// resets the tokens of every protocol (§6.5.5.7.2), so one slot is all there is.
    token: [u8; 32],
    token_protocol: u8,
    permissions: u8,
    rp: Option<[u8; 32]>,
    user_present: bool,
    user_verified: bool,
    issued: u32,
    used: bool,
    mismatches: u8,
    /// The retries left after the last wrong PIN, for the log line of that request.
    last_wrong: Option<u8>,
    pub cursor: Cursor,
}

impl Zeroize for Session {
    fn zeroize(&mut self) {
        self.ka.zeroize();
        self.ka_pub.zeroize();
        self.token.zeroize();
        self.ka_set = [false; 2];
        self.stop_token();
        self.cursor = Cursor::None;
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Session {}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

fn slot(protocol: u8) -> usize {
    if protocol == 2 { 0 } else { 1 }
}

impl Session {
    pub const fn new() -> Self {
        Self {
            ka: [[0; 32]; 2],
            ka_pub: [[0; 64]; 2],
            ka_set: [false; 2],
            token: [0; 32],
            token_protocol: 0,
            permissions: 0,
            rp: None,
            user_present: false,
            user_verified: false,
            issued: 0,
            used: false,
            mismatches: 0,
            last_wrong: None,
            cursor: Cursor::None,
        }
    }

    /// `stopUsingPinUvAuthToken()`. Source: §6.5.3.2 [C]
    pub fn stop_token(&mut self) {
        self.token.zeroize();
        self.token_protocol = 0;
        self.permissions = 0;
        self.rp = None;
        self.user_present = false;
        self.user_verified = false;
        self.used = false;
    }

    /// A different wallet is in force: its PIN is a different PIN, so no token issued
    /// under the last one may answer for it. The mismatch count stays: only a power cycle
    /// clears that.
    pub fn forget_wallet(&mut self) {
        self.stop_token();
        self.cursor = Cursor::None;
    }

    /// Whether a PIN request must wait for a power cycle.
    pub fn power_cycle_needed(&self) -> bool {
        self.mismatches >= MISMATCH_LIMIT
    }

    /// The token's usage timer (§6.5.3.2 pinUvAuthTokenUsageTimerObserver): unused past
    /// the initial limit, or alive past the maximum, and it stops.
    fn observe(&mut self, now: u32) {
        if self.token_protocol == 0 {
            return;
        }
        let age = now.wrapping_sub(self.issued);
        if age > MAX_USAGE_MS || (!self.used && age > INITIAL_USAGE_MS) {
            self.stop_token();
        } else if age > UP_MS {
            self.user_present = false;
        }
    }

    /// `verify(pinUvAuthToken, message, signature)`, which fails for a token not in use.
    /// Source: §6.5.6 verify [C]
    pub fn verify_token(&mut self, protocol: u8, parts: &[&[u8]], sig: &[u8], now: u32) -> bool {
        self.observe(now);
        if self.token_protocol == 0 || self.token_protocol != protocol {
            return false;
        }
        let ok = verify(protocol, &self.token, parts, sig);
        if ok {
            self.used = true;
        }
        ok
    }

    pub fn has_permission(&self, p: u8) -> bool {
        self.token_protocol != 0 && self.permissions & p == p
    }

    /// The token's permissions RP ID (its hash), if one is bound.
    pub fn token_rp(&self) -> Option<&[u8; 32]> {
        self.rp.as_ref()
    }

    /// Bind the token to `rp` if nothing is bound yet. Source: §6.1.2 step 11, §6.2.2 step 6 [C]
    pub fn bind_rp(&mut self, rp: &[u8; 32]) {
        if self.rp.is_none() {
            self.rp = Some(*rp);
        }
    }

    /// `getUserVerifiedFlagValue()`.
    pub fn user_verified(&self) -> bool {
        self.token_protocol != 0 && self.user_verified
    }

    /// `getUserPresentFlagValue()`.
    pub fn user_present(&mut self, now: u32) -> bool {
        self.observe(now);
        self.token_protocol != 0 && self.user_present
    }

    /// `clearUserPresentFlag()`, `clearUserVerifiedFlag()`,
    /// `clearPinUvAuthTokenPermissionsExceptLbw()`: what a request that collected presence
    /// does to the token. Source: §6.1.2 step 14, §6.2.2 step 9 [C]
    pub fn consume(&mut self) {
        if self.token_protocol != 0 {
            self.user_present = false;
            self.user_verified = false;
            self.permissions &= perm::LBW;
        }
    }

    /// This protocol's key-agreement public key, making the key pair if this power-up has
    /// none yet. `None` if the DRBG failed.
    fn key_agreement<E: Env>(&mut self, protocol: u8, env: &mut E) -> Option<[u8; 64]> {
        let i = slot(protocol);
        if !self.ka_set[i] {
            // A uniformly random scalar, retried if out of range (once in 2^32).
            for _ in 0..16 {
                let mut d = [0u8; 32];
                if !env.random(&mut d) {
                    return None;
                }
                let made = env.masked(|_kw| {
                    EcdhPrivateKey::from_bytes(&d).ok().map(|k| {
                        let p = k.public_key().to_sec1();
                        let mut xy = [0u8; 64];
                        xy.copy_from_slice(&p[1..]);
                        xy
                    })
                });
                if let Some(xy) = made {
                    self.ka[i] = d;
                    self.ka_pub[i] = xy;
                    self.ka_set[i] = true;
                    d.zeroize();
                    break;
                }
                d.zeroize();
            }
        }
        self.ka_set[i].then_some(self.ka_pub[i])
    }

    /// `regenerate()`: a new key-agreement key next time one is asked for.
    fn regenerate(&mut self, protocol: u8) {
        let i = slot(protocol);
        self.ka[i].zeroize();
        self.ka_set[i] = false;
    }

    /// `decapsulate(peerCoseKey)`: ECDH with the platform's point and the protocol's KDF.
    /// Source: §6.5.6 ecdh [C]
    fn decapsulate(&self, protocol: u8, peer: &[u8; 65], _kw: &KeyWork) -> Option<Shared> {
        let i = slot(protocol);
        if !self.ka_set[i] {
            return None;
        }
        let key = EcdhPrivateKey::from_bytes(&self.ka[i]).ok()?;
        // `from_sec1` refuses a point off the curve or with coordinates out of range.
        let peer = EcdsaPublicKey::from_sec1(peer).ok()?;
        let mut z = key.diffie_hellman(&peer).ok()?;
        let s = Shared::from_z(protocol, &z);
        z.zeroize();
        Some(s)
    }
}

// ---------------------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------------------

struct ClientPin<'a> {
    protocol: Option<u64>,
    sub: u64,
    key_agreement: Option<[u8; 65]>,
    auth: Option<&'a [u8]>,
    new_pin: Option<&'a [u8]>,
    pin_hash: Option<&'a [u8]>,
    permissions: Option<u64>,
    rp_id: Option<&'a str>,
}

fn c<T>(r: Result<T, cbor::Error>) -> Result<T, u8> {
    r.map_err(|e| match e {
        cbor::Error::Unexpected => status::CBOR_UNEXPECTED_TYPE,
        cbor::Error::Invalid | cbor::Error::TooDeep => status::INVALID_CBOR,
        cbor::Error::Overflow => status::OTHER,
    })
}

fn parse(body: &[u8]) -> Result<ClientPin<'_>, u8> {
    let mut r = Reader::new(body);
    let mut m = c(r.map())?;
    let mut p = ClientPin {
        protocol: None,
        sub: 0,
        key_agreement: None,
        auth: None,
        new_pin: None,
        pin_hash: None,
        permissions: None,
        rp_id: None,
    };
    let mut sub = None;
    while let Some(k) = c(r.key(&mut m))? {
        match k {
            Key::Int(0x01) => p.protocol = Some(c(r.uint())?),
            Key::Int(0x02) => sub = Some(c(r.uint())?),
            Key::Int(0x03) => p.key_agreement = Some(read_cose_key(&mut r)?),
            Key::Int(0x04) => p.auth = Some(c(r.bytes())?),
            Key::Int(0x05) => p.new_pin = Some(c(r.bytes())?),
            Key::Int(0x06) => p.pin_hash = Some(c(r.bytes())?),
            Key::Int(0x09) => p.permissions = Some(c(r.uint())?),
            Key::Int(0x0A) => p.rp_id = Some(c(r.text())?),
            _ => c(r.skip(cbor::MAX_DEPTH - 1))?,
        }
    }
    c(r.finish())?;
    p.sub = sub.ok_or(status::MISSING_PARAMETER)?;
    Ok(p)
}

/// The protocol a request names: missing, or not one of ours. Source: §6.5.5.4 [C]
fn protocol(p: Option<u64>) -> Result<u8, u8> {
    match p {
        None => Err(status::MISSING_PARAMETER),
        Some(v) if v == 1 || v == 2 => Ok(v as u8),
        Some(_) => Err(status::INVALID_PARAMETER),
    }
}

/// Whether `protocol` is one of ours: the check MakeCredential, GetAssertion and the
/// credential management make on a `pinUvAuthParam`'s protocol.
pub fn check_protocol(p: Option<u64>) -> Result<u8, u8> {
    protocol(p)
}

/// What a `newPinEnc` decrypts to, checked: the PIN's bytes are `padded[..len]`.
/// Source: §6.5.5.5 (64 bytes, trailing zeros dropped, minPINLength in code points) [C];
/// §6.5.1 (at most 63 bytes) [C]
fn new_pin(shared: &Shared, enc: &[u8], padded: &mut [u8; 80]) -> Result<usize, u8> {
    let n = shared
        .decrypt(enc, padded)
        .ok_or(status::PIN_AUTH_INVALID)?;
    if n != PADDED_PIN {
        return Err(status::INVALID_PARAMETER);
    }
    let len = padded[..PADDED_PIN]
        .iter()
        .rposition(|&b| b != 0)
        .map_or(0, |i| i + 1);
    if len > MAX_PIN_BYTES {
        return Err(status::PIN_POLICY_VIOLATION);
    }
    let Ok(text) = core::str::from_utf8(&padded[..len]) else {
        return Err(status::PIN_POLICY_VIOLATION);
    };
    if text.chars().count() < MIN_PIN_LEN {
        return Err(status::PIN_POLICY_VIOLATION);
    }
    Ok(len)
}

/// What the device logs about a clientPIN request: never the PIN, a hash or a token.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Outcome {
    Retries(u8),
    KeyAgreement,
    PinSet,
    PinChanged,
    Token { retries: u8, permissions: u8 },
    Wrong { retries: u8 },
}

/// Answer an `authenticatorClientPIN` request into `out` (the response map); its length.
#[inline(never)]
pub fn handle<'a, E: Env>(
    body: &'a [u8],
    out: &mut [u8],
    s: &mut Session,
    env: &mut E,
    note: &mut Note<'a>,
) -> Result<usize, u8> {
    let p = parse(body)?;
    note.sub = Some(p.sub);
    note.rp_id = p.rp_id;
    s.last_wrong = None;
    let r = match p.sub {
        sub::GET_PIN_RETRIES => retries(out, s, env),
        sub::GET_KEY_AGREEMENT => key_agreement(&p, out, s, env),
        sub::SET_PIN => set_pin(&p, s, env),
        sub::CHANGE_PIN => change_pin(&p, s, env),
        sub::GET_PIN_TOKEN | sub::GET_TOKEN_USING_PIN => token(&p, out, s, env),
        // No built-in user verification: the device's own PIN protects the wallet at
        // login, and CTAP has no way to say so. Source: §6.5.5.7.3 [C]
        sub::GET_TOKEN_USING_UV | sub::GET_UV_RETRIES => Err(status::INVALID_SUBCOMMAND),
        _ => Err(status::INVALID_SUBCOMMAND),
    };
    note.pin = match (&r, s.last_wrong.take()) {
        (Ok((_, o)), _) => Some(*o),
        (Err(_), Some(left)) => Some(Outcome::Wrong { retries: left }),
        (Err(_), None) => None,
    };
    r.map(|(n, _)| n)
}

fn retries<E: Env>(out: &mut [u8], s: &Session, env: &mut E) -> Result<(usize, Outcome), u8> {
    let left = env.pin().map_or(MAX_RETRIES, |p| p.retries);
    let mut w = Writer::new(out);
    w.map(2)
        .uint(0x03)
        .uint(left as u64)
        .uint(0x04)
        .bool(s.power_cycle_needed());
    Ok((
        w.finish().map_err(|_| status::OTHER)?,
        Outcome::Retries(left),
    ))
}

fn key_agreement<E: Env>(
    p: &ClientPin<'_>,
    out: &mut [u8],
    s: &mut Session,
    env: &mut E,
) -> Result<(usize, Outcome), u8> {
    let proto = protocol(p.protocol)?;
    let xy = s.key_agreement(proto, env).ok_or(status::OTHER)?;
    let mut w = Writer::new(out);
    w.map(1).uint(0x01);
    write_cose_key(&mut w, &xy);
    Ok((
        w.finish().map_err(|_| status::OTHER)?,
        Outcome::KeyAgreement,
    ))
}

/// §6.5.5.5, with the device's own question before anything is stored.
#[inline(never)]
fn set_pin<E: Env>(
    p: &ClientPin<'_>,
    s: &mut Session,
    env: &mut E,
) -> Result<(usize, Outcome), u8> {
    let (Some(ka), Some(enc), Some(auth)) = (p.key_agreement.as_ref(), p.new_pin, p.auth) else {
        protocol(p.protocol)?;
        return Err(status::MISSING_PARAMETER);
    };
    let proto = protocol(p.protocol)?;
    if env.pin().is_some() {
        return Err(status::NOT_ALLOWED);
    }
    let rec = env.masked(|kw| {
        let shared = s
            .decapsulate(proto, ka, kw)
            .ok_or(status::INVALID_PARAMETER)?;
        if !shared.verify(&[enc], auth) {
            return Err(status::PIN_AUTH_INVALID);
        }
        let mut padded = [0u8; 80];
        let r = new_pin(&shared, enc, &mut padded).map(|n| PinRecord::new(&padded[..n], kw));
        padded.zeroize();
        r
    })?;
    match env.presence(Ask::SetPin) {
        Presence::Allowed => {}
        other => return Err(other.refusal()),
    }
    if !env.save_pin(&rec) {
        return Err(status::OTHER);
    }
    Ok((0, Outcome::PinSet))
}

/// The retries counter taken down by one and written, before the guess is judged.
fn spend_retry<E: Env>(stored: &PinRecord, env: &mut E) -> Result<PinRecord, u8> {
    let spent = PinRecord {
        retries: stored.retries.saturating_sub(1),
        hash: stored.hash,
    };
    if !env.save_pin(&spent) {
        return Err(status::OTHER);
    }
    Ok(spent)
}

/// A wrong PIN: a new key agreement, the mismatch counted, and the error that says what
/// is left. Source: §6.5.5.6 / §6.5.5.7.1 mismatch steps [C]
fn wrong(s: &mut Session, proto: u8, spent: &PinRecord) -> u8 {
    s.regenerate(proto);
    s.last_wrong = Some(spent.retries);
    s.mismatches = s.mismatches.saturating_add(1);
    if spent.retries == 0 {
        status::PIN_BLOCKED
    } else if s.power_cycle_needed() {
        status::PIN_AUTH_BLOCKED
    } else {
        status::PIN_INVALID
    }
}

/// Decrypt `pinHashEnc` and compare it with the stored hash, in constant time.
fn pin_matches(shared: &Shared, enc: &[u8], stored: &PinRecord) -> bool {
    let mut plain = [0u8; 48];
    let ok = matches!(shared.decrypt(enc, &mut plain), Some(16))
        && bool::from(plain[..16].ct_eq(&stored.hash));
    plain.zeroize();
    ok
}

/// §6.5.5.6, asked on the device before a retry is spent.
#[inline(never)]
fn change_pin<E: Env>(
    p: &ClientPin<'_>,
    s: &mut Session,
    env: &mut E,
) -> Result<(usize, Outcome), u8> {
    let (Some(ka), Some(hash_enc), Some(enc), Some(auth)) =
        (p.key_agreement.as_ref(), p.pin_hash, p.new_pin, p.auth)
    else {
        protocol(p.protocol)?;
        return Err(status::MISSING_PARAMETER);
    };
    let proto = protocol(p.protocol)?;
    let stored = env.pin().ok_or(status::PIN_NOT_SET)?;
    if stored.retries == 0 {
        return Err(status::PIN_BLOCKED);
    }
    if s.power_cycle_needed() {
        return Err(status::PIN_AUTH_BLOCKED);
    }
    let shared = env.masked(|kw| s.decapsulate(proto, ka, kw));
    let shared = shared.ok_or(status::INVALID_PARAMETER)?;
    if !shared.verify(&[enc, hash_enc], auth) {
        return Err(status::PIN_AUTH_INVALID);
    }
    match env.presence(Ask::ChangePin) {
        Presence::Allowed => {}
        other => return Err(other.refusal()),
    }
    let spent = spend_retry(&stored, env)?;
    if !env.masked(|_| pin_matches(&shared, hash_enc, &stored)) {
        return Err(wrong(s, proto, &spent));
    }
    s.mismatches = 0;
    // The old PIN was right: the retries go back to the maximum whatever happens to the
    // new one, in the same write as the new PIN when there is one.
    let next = env.masked(|kw| {
        let mut padded = [0u8; 80];
        let r = new_pin(&shared, enc, &mut padded).map(|n| PinRecord::new(&padded[..n], kw));
        padded.zeroize();
        r
    });
    let restored = PinRecord {
        retries: MAX_RETRIES,
        hash: stored.hash,
    };
    match next {
        Ok(rec) => {
            if !env.save_pin(&rec) {
                return Err(status::OTHER);
            }
            // Every token is void after a PIN change. Source: §6.5.5.6 last step [C]
            s.stop_token();
            Ok((0, Outcome::PinChanged))
        }
        Err(e) => {
            let _ = env.save_pin(&restored);
            Err(e)
        }
    }
}

/// §6.5.5.7.1 (getPinToken) and §6.5.5.7.2 (getPinUvAuthTokenUsingPinWithPermissions).
#[inline(never)]
fn token<E: Env>(
    p: &ClientPin<'_>,
    out: &mut [u8],
    s: &mut Session,
    env: &mut E,
) -> Result<(usize, Outcome), u8> {
    let legacy = p.sub == sub::GET_PIN_TOKEN;
    let (Some(ka), Some(hash_enc)) = (p.key_agreement.as_ref(), p.pin_hash) else {
        protocol(p.protocol)?;
        return Err(status::MISSING_PARAMETER);
    };
    if !legacy && p.permissions.is_none() {
        return Err(status::MISSING_PARAMETER);
    }
    let proto = protocol(p.protocol)?;
    let permissions = if legacy {
        if p.permissions.is_some() || p.rp_id.is_some() {
            return Err(status::INVALID_PARAMETER);
        }
        perm::MC | perm::GA
    } else {
        let want = p.permissions.unwrap_or(0);
        if want == 0 {
            return Err(status::INVALID_PARAMETER);
        }
        // Permissions this device has no command for. Undefined bits are ignored.
        let cm_ok = env.caps().rk;
        let refused = perm::BE | perm::LBW | perm::ACFG | if cm_ok { 0 } else { perm::CM };
        if want & u64::from(refused) != 0 {
            return Err(status::UNAUTHORIZED_PERMISSION);
        }
        (want as u8) & (perm::MC | perm::GA | perm::CM)
    };
    let stored = env.pin().ok_or(status::PIN_NOT_SET)?;
    if stored.retries == 0 {
        return Err(status::PIN_BLOCKED);
    }
    if s.power_cycle_needed() {
        return Err(status::PIN_AUTH_BLOCKED);
    }
    let shared = env.masked(|kw| s.decapsulate(proto, ka, kw));
    let shared = shared.ok_or(status::INVALID_PARAMETER)?;

    // The device has a screen, so the person is asked before the PIN is tried: see the
    // module notes for why, and why the answer also stands for the request's presence.
    match env.presence(Ask::UsePin {
        rp_id: p.rp_id,
        permissions,
    }) {
        Presence::Allowed => {}
        other => return Err(other.refusal()),
    }
    let spent = spend_retry(&stored, env)?;
    if !env.masked(|_| pin_matches(&shared, hash_enc, &stored)) {
        return Err(wrong(s, proto, &spent));
    }
    s.mismatches = 0;
    let restored = PinRecord {
        retries: MAX_RETRIES,
        hash: stored.hash,
    };
    if spent.retries != MAX_RETRIES && !env.save_pin(&restored) {
        return Err(status::OTHER);
    }

    // resetPinUvAuthToken() for every protocol, then beginUsingPinUvAuthToken().
    s.stop_token();
    let mut fresh = [0u8; 32];
    if !env.random(&mut fresh) {
        return Err(status::OTHER);
    }
    let mut iv = [0u8; 16];
    if !env.random(&mut iv) {
        fresh.zeroize();
        return Err(status::OTHER);
    }
    s.token = fresh;
    fresh.zeroize();
    s.token_protocol = proto;
    s.permissions = permissions;
    s.rp = p.rp_id.map(|id| Sha256::digest(id.as_bytes()));
    s.user_present = true;
    s.user_verified = true;
    s.issued = env.now_ms();
    s.used = false;

    let mut ct = [0u8; 48];
    let n = shared
        .encrypt(&s.token, &iv, &mut ct)
        .ok_or(status::OTHER)?;
    let mut w = Writer::new(out);
    w.map(1).uint(0x02).bytes(&ct[..n]);
    ct.zeroize();
    Ok((
        w.finish().map_err(|_| status::OTHER)?,
        Outcome::Token {
            retries: MAX_RETRIES,
            permissions,
        },
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The protocols' KDF, cipher and MAC against values computed independently with
    /// Python's `cryptography` (50.0.1) and `hashlib`/`hmac`:
    ///
    /// ```python
    /// from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    /// from cryptography.hazmat.primitives import hashes
    /// from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    /// import hashlib, hmac
    /// z = bytes(range(32)); pt = bytes(range(64)); iv = bytes([0xA5] * 16)
    /// hk = lambda info: HKDF(hashes.SHA256(), 32, bytes(32), info).derive(z)
    /// s1 = hashlib.sha256(z).digest(); s2 = hk(b"CTAP2 HMAC key") + hk(b"CTAP2 AES key")
    /// cbc = lambda k, iv: (lambda e: e.update(pt) + e.finalize())(Cipher(algorithms.AES(k), modes.CBC(iv)).encryptor())
    /// print(s1.hex(), s2.hex(), cbc(s1, bytes(16)).hex(), (iv + cbc(s2[32:], iv)).hex())
    /// print(hmac.new(s1, b"message", "sha256").digest()[:16].hex(), hmac.new(s2[:32], b"message", "sha256").hexdigest())
    /// ```
    #[test]
    fn both_protocols_match_an_independent_implementation() {
        struct V {
            shared1: &'static str,
            shared2: &'static str,
            cbc1: &'static str,
            cbc2: &'static str,
            mac1: &'static str,
            mac2: &'static str,
        }
        let v = V {
            shared1: "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd",
            shared2: concat!(
                "a689b3b92a6ebab91192408da9c4f05c674a2bc5f938d613077716c719a8df39",
                "0f6ff2ef211829c11638ef2893ea02edf195658c0572393e7680d93bc2b58d44"
            ),
            cbc1: concat!(
                "5b1b8c62089fae8afdcde68081977f19e6a0b8d59b6818113cd771f0867e8903",
                "b5f0ea5aa5b9eec0ddac8072204ab3a493dbd3357e1e4c5603258c49fb305ce5"
            ),
            cbc2: concat!(
                "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
                "63d9a4c08efb1fbb877067ed8586a337b01faed7eb5bc8366bc33ec12b5f5797",
                "3eb678a842cab0c4216bb7771f8624072082c932c7042f387d48020eba4c078f"
            ),
            mac1: "0e1ed6c97a5536d6813284ba23672f5a",
            mac2: "8ed41fb06108031d3e97613e4eb730eb882d7acdd3156b2abf9bc87cd0a9489d",
        };
        let z: [u8; 32] = core::array::from_fn(|i| i as u8);
        let pt: [u8; 64] = core::array::from_fn(|i| i as u8);
        let iv = [0xA5u8; 16];

        let s1 = Shared::from_z(1, &z);
        assert_eq!(&s1.bytes[..32], &unhex(v.shared1)[..]);
        let s2 = Shared::from_z(2, &z);
        assert_eq!(&s2.bytes[..], &unhex(v.shared2)[..]);

        let mut ct = [0u8; 96];
        let n = s1.encrypt(&pt, &iv, &mut ct).unwrap();
        assert_eq!(&ct[..n], &unhex(v.cbc1)[..], "protocol One: zero IV");
        let mut back = [0u8; 96];
        assert_eq!(s1.decrypt(&ct[..n], &mut back), Some(64));
        assert_eq!(&back[..64], &pt);

        let n = s2.encrypt(&pt, &iv, &mut ct).unwrap();
        assert_eq!(
            &ct[..n],
            &unhex(v.cbc2)[..],
            "protocol Two: IV ‖ ciphertext"
        );
        assert_eq!(s2.decrypt(&ct[..n], &mut back), Some(64));
        assert_eq!(&back[..64], &pt);

        let (m1, n1) = authenticate(1, &s1.bytes[..32], &[b"message"]);
        assert_eq!(&m1[..n1], &unhex(v.mac1)[..]);
        let (m2, n2) = authenticate(2, &s2.bytes, &[b"mess", b"age"]);
        assert_eq!(&m2[..n2], &unhex(v.mac2)[..]);
        assert!(s1.verify(&[b"message"], &unhex(v.mac1)));
        assert!(s2.verify(&[b"message"], &unhex(v.mac2)));
        // Lengths are exact: a truncated or extended MAC fails.
        assert!(!s2.verify(&[b"message"], &unhex(v.mac2)[..16]));
        assert!(!s1.verify(&[b"message"], &m2[..32]));
        assert!(!s1.verify(&[b"massage"], &unhex(v.mac1)));
        // Not whole blocks, or no room for Two's IV.
        assert_eq!(s1.decrypt(&ct[..15], &mut back), None);
        assert_eq!(s2.decrypt(&ct[..15], &mut back), None);
        assert_eq!(s2.decrypt(&ct[..33], &mut back), None);
    }

    #[test]
    fn the_pin_hash_is_the_left_half_of_sha256() {
        // python: hashlib.sha256(b"1234").digest()[:16].hex()
        let r = PinRecord::new(b"1234", &KeyWork::host());
        assert_eq!(r.hash.to_vec(), unhex("03ac674216f3e15c761ee1a5e255f067"));
        assert_eq!(r.retries, 8);
    }

    #[test]
    fn a_token_lapses_unused_and_expires_used() {
        let mut s = Session::new();
        s.token = [7; 32];
        s.token_protocol = 2;
        s.permissions = perm::MC | perm::GA;
        s.user_present = true;
        s.user_verified = true;
        s.issued = 1000;
        let (mac, _) = authenticate(2, &[7; 32], &[b"x"]);
        // Unused for longer than the initial limit: gone.
        let mut late = Session::new();
        late.token = [7; 32];
        late.token_protocol = 2;
        late.issued = 1000;
        assert!(!late.verify_token(2, &[b"x"], &mac, 1000 + INITIAL_USAGE_MS + 1));
        // The wrong protocol never verifies.
        assert!(!s.verify_token(1, &[b"x"], &mac[..16], 1001));
        assert!(s.verify_token(2, &[b"x"], &mac, 1001));
        // Used once, it lives past the initial limit, but presence does not.
        assert!(s.verify_token(2, &[b"x"], &mac, 1000 + INITIAL_USAGE_MS + 5));
        assert!(!s.user_present(1000 + UP_MS + 5));
        assert!(!s.verify_token(2, &[b"x"], &mac, 1000 + MAX_USAGE_MS + 1));
        // Consuming keeps nothing but lbw.
        let mut t = Session::new();
        t.token_protocol = 1;
        t.permissions = perm::MC | perm::CM | perm::LBW;
        t.user_present = true;
        t.user_verified = true;
        t.consume();
        assert_eq!(t.permissions, perm::LBW);
        assert!(!t.user_verified() && !t.user_present(0));
    }
}
