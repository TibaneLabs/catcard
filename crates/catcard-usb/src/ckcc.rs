//! Stock Coldcard's host protocol ("ckcc"), for the **ckcc** USB mode.
//!
//! In that mode the device enumerates with stock's USB identity and speaks stock's wire
//! protocol, so the host tools that already exist for it -- the `ckcc` command line,
//! HWI, Sparrow, Electrum's plugin -- can use it unchanged. The user chose this (see
//! `docs/USB.md`, "USB modes"); the default is still CatCard's own protocol.
//!
//! This module is the pure half: report framing ([`Rx`], [`Tx`]), the `ncry` session
//! (v1/v2/v3, [`Link`]), request parsing ([`Request`]) and reply encoding ([`reply`]).
//! It never waits, derives a key or talks to hardware. The firmware's USB task feeds it
//! reports and dispatches what comes out.
//!
//! Everything here is written from `hw-reference/usb-ckcc-protocol.md`; section numbers
//! in comments are that document's.
//!
//! # Framing (§1.2)
//!
//! Each 64-byte report is a flag byte and up to 63 payload bytes:
//!
//! ```text
//! bits 0..5  len_here   payload bytes in this report
//! bit  6     encrypted  set on the final report of an encrypted message
//! bit  7     last       final report of the message
//! ```
//!
//! A report with no payload and the last bit set is a **resync**: the device drops any
//! partial message and the upload state, and sends nothing back (§1.4).
//!
//! # Session (§2)
//!
//! `ncry` carries a version and the host's ephemeral secp256k1 key (`X‖Y`, 64 bytes).
//! The session key is `SHA-256(X‖Y)` of the shared point. v1 and v2 run AES-256-CTR under
//! that key in both directions, each stream from counter zero (v2 additionally binds the
//! link: every later message must be encrypted and `ncry` cannot be repeated). v3
//! derives four keys through HKDF over a transcript and appends a truncated HMAC to every
//! message, with a per-direction sequence number; any failure ends the link for good.

use purecrypto::cipher::{Aes256, Ctr};
use purecrypto::ct::ConstantTimeEq;
use purecrypto::ec::secp256k1::{AffinePoint, ProjectivePoint, Scalar};
use purecrypto::hash::{Digest, HmacSha256, Sha256};
use purecrypto::kdf::hkdf;
use zeroize::Zeroize;

/// Stock's USB vendor ID. Unregistered -- stock's own source calls it "unofficial,
/// unpermissioned" -- and presented only in ckcc mode, because it is what every existing
/// host tool looks for.
/// Source: hw-reference/usb-ckcc-protocol.md §1.1 [C]
pub const VENDOR_ID: u16 = 0xD13E;
/// Stock's USB product ID. Same caveats as [`VENDOR_ID`].
/// Source: hw-reference/usb-ckcc-protocol.md §1.1 [C]
pub const PRODUCT_ID: u16 = 0xCC10;

/// Bytes per report, both directions. Source: §1.1 [C]
pub const REPORT_LEN: usize = 64;
/// Payload bytes one report can carry after its flag byte. Source: §1.2 [C]
pub const REPORT_PAYLOAD: usize = REPORT_LEN - 1;

/// Largest `upld` / `dwld` data block. Source: §1.3 [C]
pub const MAX_BLK_LEN: usize = 2048;
/// Largest logical message, v1/v2: an `upld` header and one block. Source: §1.3 [C]
pub const MAX_MSG_LEN: usize = 4 + 4 + 4 + MAX_BLK_LEN;
/// Truncated HMAC appended to every v3 message. Source: §2.4 [C]
pub const TAG_LEN: usize = 16;
/// Largest reassembled v3 message: ciphertext and tag. Source: §2.4 [C]
pub const MAX_WIRE_LEN: usize = MAX_MSG_LEN + TAG_LEN;
/// Shortest message: the opcode. Source: §1.3 [C]
pub const MIN_MSG_LEN: usize = 4;

/// Longest message `smsg` signs. Source: §3.4 [C]
pub const MSG_SIGNING_MAX_LENGTH: usize = 240;

/// v3's HKDF info and transcript label. Source: §2.4 [C]
pub const V3_KDF_LABEL: &[u8] = b"ccncry3";
/// v3 direction label, host to device. Source: §2.4 [C]
pub const V3_C2D: [u8; 4] = *b"C2D\0";
/// v3 direction label, device to host. Source: §2.4 [C]
pub const V3_D2C: [u8; 4] = *b"D2C\0";

/// Length of an `ncry` public key: `X‖Y`, no `0x04` prefix. Source: §2.1 [C]
pub const PUBKEY_LEN: usize = 64;

/// Error text is cut to this many bytes after `err_`. Source: §3.10 [C]
pub const ERR_MAX: usize = 80;

/// The flag byte's bits. Source: §1.2 [C]
pub mod flag {
    /// Payload bytes in this report.
    pub const LEN_MASK: u8 = 0x3F;
    /// The message this report ends is encrypted.
    pub const ENCRYPTED: u8 = 0x40;
    /// Final report of the message.
    pub const LAST: u8 = 0x80;
}

/// `stxn` flag bits. Source: §3.3 [C]
pub mod stxn {
    pub const FINALIZE: u32 = 0x01;
    pub const VISUALIZE: u32 = 0x02;
    pub const SIGNED: u32 = 0x04;
    pub const MASK: u32 = 0x07;
}

/// Address-format bits and the composites built from them. Source: §3.6 [C]
pub mod af {
    pub const PUBKEY: u32 = 0x01;
    pub const SEGWIT: u32 = 0x02;
    pub const BECH32: u32 = 0x04;
    pub const SCRIPT: u32 = 0x08;
    pub const WRAPPED: u32 = 0x10;
    pub const BECH32M: u32 = 0x20;

    pub const CLASSIC: u32 = 0x01;
    pub const P2SH: u32 = 0x08;
    pub const P2WPKH: u32 = 0x07;
    pub const P2WSH: u32 = 0x0E;
    pub const P2WPKH_P2SH: u32 = 0x13;
    pub const P2WSH_P2SH: u32 = 0x1A;
    pub const P2TR: u32 = 0x27;
    /// An older host's taproot code, remapped to [`P2TR`] by `show`. Source: §3.6 [C]
    pub const P2TR_OLD: u32 = 0x17;
}

/// Why a message could not be taken off the wire. The wire word is [`Fram::reason`],
/// sent back as `fram` + reason. Source: §3.10 [C]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Fram {
    /// More arrived than the active maximum allows.
    XLong,
    /// The whole message is shorter than an opcode or longer than the maximum.
    BadSz,
    /// A cleartext message on a bound (v2/v3) link.
    MustEncrypt,
    /// An encrypted message with no session to open it.
    NoKey,
    /// A v3 tag that did not verify, or a message too short to carry one.
    Auth,
    /// A v3 sequence number would wrap.
    Seq,
    /// The opcode is not text.
    Decode,
    /// `ncry` asked for a version this device does not speak.
    BadNcryVersion,
    /// `ncry` again on a bound link.
    AlreadySetUp,
}

impl Fram {
    /// The word stock sends after `fram`.
    pub const fn reason(self) -> &'static str {
        match self {
            Fram::XLong => "xlong",
            Fram::BadSz => "badsz",
            Fram::MustEncrypt => "must encrypt",
            Fram::NoKey => "no key",
            Fram::Auth => "auth",
            Fram::Seq => "seq",
            Fram::Decode => "decode",
            Fram::BadNcryVersion => "bad ncry version",
            Fram::AlreadySetUp => "crypto already set up",
        }
    }
}

// ---------------------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------------------

/// What one report did.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum RxEvent {
    /// Taken; the message is not finished.
    More,
    /// A resync: drop everything in flight, answer nothing. Source: §1.4 [C]
    Reset,
    /// A whole message is in the buffer: `len` bytes, encrypted or not.
    Message { len: usize, encrypted: bool },
}

/// Reassembles reports into one message, in a buffer the caller owns.
///
/// The buffer is not held here because it is two kilobytes and the device lends it out
/// only while a message is in flight.
#[derive(Default, Debug)]
pub struct Rx {
    len: usize,
}

impl Rx {
    pub const fn new() -> Self {
        Self { len: 0 }
    }

    /// Bytes gathered so far; zero between messages.
    pub fn pending(&self) -> usize {
        self.len
    }

    /// Drop a partial message.
    pub fn reset(&mut self) {
        self.len = 0;
    }

    /// Take one report into `buf`, which must hold `max` bytes.
    ///
    /// `max` is the active limit: [`MAX_MSG_LEN`] on a v1/v2 or clear link, and
    /// [`MAX_WIRE_LEN`] once v3 is up. A report that would overrun it is `xlong`; a
    /// finished message shorter than an opcode or over the limit is `badsz`. On an error
    /// the partial message is dropped.
    pub fn feed(&mut self, report: &[u8], buf: &mut [u8], max: usize) -> Result<RxEvent, Fram> {
        let Some((&f, body)) = report.split_first() else {
            return Ok(RxEvent::More);
        };
        let here = usize::from(f & flag::LEN_MASK);
        let last = f & flag::LAST != 0;
        if here == 0 && last {
            // Source: §1.4 [C]
            self.len = 0;
            return Ok(RxEvent::Reset);
        }
        let max = max.min(buf.len());
        let here = here.min(body.len());
        if self.len + here > max {
            self.len = 0;
            return Err(Fram::XLong);
        }
        buf[self.len..self.len + here].copy_from_slice(&body[..here]);
        self.len += here;
        if !last {
            return Ok(RxEvent::More);
        }
        let len = core::mem::take(&mut self.len);
        if !(MIN_MSG_LEN..=max).contains(&len) {
            return Err(Fram::BadSz);
        }
        Ok(RxEvent::Message {
            len,
            encrypted: f & flag::ENCRYPTED != 0,
        })
    }
}

/// Where a reply is in being framed out; saved between reports so a long reply resumes
/// rather than restarts.
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
pub struct Tx {
    sent: usize,
    done: bool,
}

impl Tx {
    pub const fn new() -> Self {
        Self {
            sent: 0,
            done: false,
        }
    }

    /// Fill `out` with the next report of `msg`. False once every report has gone.
    ///
    /// The encrypted bit rides on the final report, as the host sets it. Unused bytes are
    /// zeroed so a report never carries what the buffer last held.
    pub fn next(&mut self, msg: &[u8], encrypted: bool, out: &mut [u8; REPORT_LEN]) -> bool {
        if self.done {
            return false;
        }
        out.fill(0);
        let n = (msg.len() - self.sent.min(msg.len())).min(REPORT_PAYLOAD);
        let last = self.sent + n >= msg.len();
        out[0] = n as u8
            | if last { flag::LAST } else { 0 }
            | if last && encrypted {
                flag::ENCRYPTED
            } else {
                0
            };
        out[1..1 + n].copy_from_slice(&msg[self.sent..self.sent + n]);
        self.sent += n;
        self.done = last;
        true
    }
}

// ---------------------------------------------------------------------------------------
// The session
// ---------------------------------------------------------------------------------------

/// `ncry` versions. Source: §2.3, §2.4 [C]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Version {
    V1 = 1,
    V2 = 2,
    V3 = 3,
}

impl Version {
    pub const fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Version::V1),
            2 => Some(Version::V2),
            3 => Some(Version::V3),
            _ => None,
        }
    }
}

/// One direction's AES-256-CTR stream: the key and how far into the keystream it is.
///
/// Kept as a key and a byte count rather than a live cipher, so the link is a few dozen
/// bytes in the firmware's static rather than two expanded key schedules; the schedule
/// is rebuilt per message, which costs microseconds.
struct Stream {
    key: [u8; 32],
    pos: u64,
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl Stream {
    fn new(key: [u8; 32]) -> Self {
        Self { key, pos: 0 }
    }

    /// XOR the next `data.len()` keystream bytes into `data`. The counter block is the
    /// 128-bit big-endian block index, starting from zero. Source: §2.3 [C]
    fn apply(&mut self, data: &mut [u8]) {
        let mut iv = [0u8; 16];
        iv[8..].copy_from_slice(&(self.pos / 16).to_be_bytes());
        let mut ctr = Ctr::new(Aes256::new(&self.key), &iv);
        let skip = (self.pos % 16) as usize;
        if skip > 0 {
            let mut waste = [0u8; 16];
            ctr.apply_keystream(&mut waste[..skip]);
            waste.zeroize();
        }
        ctr.apply_keystream(data);
        self.pos += data.len() as u64;
    }
}

/// v3's per-message tag: `HMAC-SHA256(key, dir ‖ u32le seq ‖ u32le len ‖ ct)[..16]`.
/// Source: §2.6 [C]
pub fn v3_tag(mac_key: &[u8; 32], dir: [u8; 4], seq: u32, ct: &[u8]) -> [u8; TAG_LEN] {
    let mut h = HmacSha256::new(mac_key);
    h.update(&dir);
    h.update(&seq.to_le_bytes());
    h.update(&(ct.len() as u32).to_le_bytes());
    h.update(ct);
    let full = h.finalize();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&full[..TAG_LEN]);
    tag
}

/// v3's four keys, `h2d_enc ‖ h2d_mac ‖ d2h_enc ‖ d2h_mac`. Source: §2.5 [C]
///
/// `transcript = SHA-256(label ‖ u32le 3 ‖ host_pub ‖ dev_pub)`; the keys are
/// `HKDF-SHA256(salt = transcript, ikm = session key, info = label)`, 128 bytes.
pub fn v3_keys(session_key: &[u8; 32], host_pub: &[u8; 64], dev_pub: &[u8; 64]) -> [u8; 128] {
    let mut h = Sha256::new();
    h.update(V3_KDF_LABEL);
    h.update(&3u32.to_le_bytes());
    h.update(host_pub);
    h.update(dev_pub);
    let transcript = h.finalize();
    let mut okm = [0u8; 128];
    hkdf::<Sha256>(&transcript, session_key, V3_KDF_LABEL, &mut okm);
    okm
}

/// The shared session key: `SHA-256(X ‖ Y)` of `scalar · point`. Source: §2.2 [C]
///
/// `None` when `their_pub` is not a point on the curve, or the product is the identity.
pub fn session_key(scalar: &[u8; 32], their_pub: &[u8; 64]) -> Option<[u8; 32]> {
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(their_pub);
    let point = AffinePoint::from_sec1(&sec1).ok()?;
    let k = Scalar::from_bytes_be(scalar).ok()?;
    if bool::from(k.is_zero()) {
        return None;
    }
    let shared = point.to_projective().mul(&k).to_affine()?;
    let mut h = Sha256::new();
    h.update(&shared.x_bytes());
    h.update(&shared.y_bytes());
    let out = h.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    Some(key)
}

/// `scalar · G` as `X‖Y`, or `None` for a scalar that is zero or out of range.
pub fn public_key(scalar: &[u8; 32]) -> Option<[u8; 64]> {
    let k = Scalar::from_bytes_be(scalar).ok()?;
    if bool::from(k.is_zero()) {
        return None;
    }
    let p = ProjectivePoint::mul_generator(&k).to_affine()?;
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&p.x_bytes());
    out[32..].copy_from_slice(&p.y_bytes());
    Some(out)
}

enum Cipher {
    /// v1/v2: one key, a stream each way from counter zero. Source: §2.3 [C]
    Shared { rx: Stream, tx: Stream },
    /// v3: a key each way for the stream and for the tag, and a sequence each way.
    V3 {
        rx: Stream,
        tx: Stream,
        rx_mac: [u8; 32],
        tx_mac: [u8; 32],
        rx_seq: u32,
        tx_seq: u32,
    },
}

impl Drop for Cipher {
    fn drop(&mut self) {
        // The streams wipe their own keys.
        if let Cipher::V3 { rx_mac, tx_mac, .. } = self {
            rx_mac.zeroize();
            tx_mac.zeroize();
        }
    }
}

/// Why `ncry` was refused.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum NcryError {
    /// Framing-level, answered `fram`: an unknown version, or a second `ncry` on a
    /// bound link.
    Fram(Fram),
    /// The host's key is not a curve point, or ours could not be made.
    BadKey,
}

/// The link's encryption state: none, a v1/v2 stream, or v3.
#[derive(Default)]
pub struct Link {
    cipher: Option<Cipher>,
    /// Kept for `mitm`, which signs it. Source: §2.8 [C]
    session_key: Option<[u8; 32]>,
    version: Option<Version>,
    /// v2/v3: every message must now be encrypted and `ncry` cannot run again.
    bound: bool,
    /// v3: a framing error ended the link; nothing more is processed. Source: §2.6 [C]
    dead: bool,
}

impl Drop for Link {
    fn drop(&mut self) {
        self.session_key.zeroize();
    }
}

impl Link {
    pub const fn new() -> Self {
        Self {
            cipher: None,
            session_key: None,
            version: None,
            bound: false,
            dead: false,
        }
    }

    /// Whether `ncry` has run.
    pub fn is_encrypted(&self) -> bool {
        self.cipher.is_some()
    }

    pub fn version(&self) -> Option<Version> {
        self.version
    }

    /// Whether every message must be encrypted (v2, v3).
    pub fn is_bound(&self) -> bool {
        self.bound
    }

    /// Whether a v3 failure has ended this link. Only a new bus session clears it.
    pub fn is_dead(&self) -> bool {
        self.dead
    }

    /// The largest message the reassembler should accept now.
    pub fn max_wire(&self) -> usize {
        if self.version == Some(Version::V3) {
            MAX_WIRE_LEN
        } else {
            MAX_MSG_LEN
        }
    }

    /// The 32-byte session key, for `mitm`.
    pub fn session_key(&self) -> Option<&[u8; 32]> {
        self.session_key.as_ref()
    }

    /// A framing error happened. On v3 that ends the link. Source: §2.6 [C]
    pub fn failed(&mut self) {
        if self.version == Some(Version::V3) {
            self.dead = true;
        }
    }

    /// A message was dropped unread (the device had no room for it), so this side's
    /// receive stream no longer lines up with the host's. v1 forgets the session -- the
    /// host sets up a new one with its next `ncry`, as every `ckcc` run does anyway; a
    /// bound link (v2/v3) cannot be re-keyed, so it ends.
    pub fn desync(&mut self) {
        if self.bound {
            self.dead = true;
        } else {
            self.cipher = None;
            self.session_key.zeroize();
            self.session_key = None;
            self.version = None;
        }
    }

    /// Answer `ncry`: take the host's key, make ours from `scalar`, and set up the
    /// streams. Returns our public key for the `mypb` reply.
    ///
    /// `scalar` is protocol randomness from the device's DRBG, never key material.
    pub fn handshake(
        &mut self,
        version: u32,
        host_pub: &[u8; 64],
        scalar: &[u8; 32],
    ) -> Result<[u8; 64], NcryError> {
        let v = Version::from_u32(version).ok_or(NcryError::Fram(Fram::BadNcryVersion))?;
        if self.bound {
            return Err(NcryError::Fram(Fram::AlreadySetUp));
        }
        let dev_pub = public_key(scalar).ok_or(NcryError::BadKey)?;
        let mut key = session_key(scalar, host_pub).ok_or(NcryError::BadKey)?;
        let cipher = match v {
            Version::V1 | Version::V2 => Cipher::Shared {
                rx: Stream::new(key),
                tx: Stream::new(key),
            },
            Version::V3 => {
                let mut okm = v3_keys(&key, host_pub, &dev_pub);
                let part = |i: usize| -> [u8; 32] {
                    let mut k = [0u8; 32];
                    k.copy_from_slice(&okm[i * 32..i * 32 + 32]);
                    k
                };
                let c = Cipher::V3 {
                    rx: Stream::new(part(0)),
                    rx_mac: part(1),
                    tx: Stream::new(part(2)),
                    tx_mac: part(3),
                    rx_seq: 0,
                    tx_seq: 0,
                };
                okm.zeroize();
                c
            }
        };
        self.cipher = Some(cipher);
        self.session_key = Some(key);
        key.zeroize();
        self.version = Some(v);
        self.bound = matches!(v, Version::V2 | Version::V3);
        Ok(dev_pub)
    }

    /// Open a received message in place and return the plaintext's length.
    ///
    /// A cleartext message passes through unless the link is bound. On v3 the tag is
    /// checked in constant time before anything is decrypted. Source: §2.6, §2.7 [C]
    pub fn open(&mut self, buf: &mut [u8], len: usize, encrypted: bool) -> Result<usize, Fram> {
        if self.dead {
            return Err(Fram::Auth);
        }
        if !encrypted {
            return if self.bound {
                Err(Fram::MustEncrypt)
            } else {
                Ok(len)
            };
        }
        let buf = &mut buf[..len];
        match self.cipher.as_mut() {
            None => Err(Fram::NoKey),
            Some(Cipher::Shared { rx, .. }) => {
                rx.apply(buf);
                Ok(len)
            }
            Some(Cipher::V3 {
                rx, rx_mac, rx_seq, ..
            }) => {
                if len <= TAG_LEN {
                    return Err(Fram::Auth);
                }
                let ct_len = len - TAG_LEN;
                if ct_len < MIN_MSG_LEN {
                    return Err(Fram::BadSz);
                }
                let (ct, tag) = buf.split_at_mut(ct_len);
                let want = v3_tag(rx_mac, V3_C2D, *rx_seq, ct);
                if !bool::from(want[..].ct_eq(&tag[..])) {
                    return Err(Fram::Auth);
                }
                *rx_seq = rx_seq.checked_add(1).ok_or(Fram::Seq)?;
                rx.apply(ct);
                Ok(ct_len)
            }
        }
    }

    /// Seal `len` bytes of reply in place, appending v3's tag. `buf` must have room for
    /// [`TAG_LEN`] more. Returns the length on the wire.
    pub fn seal(&mut self, buf: &mut [u8], len: usize) -> Result<usize, Fram> {
        match self.cipher.as_mut() {
            None => Err(Fram::NoKey),
            Some(Cipher::Shared { tx, .. }) => {
                tx.apply(&mut buf[..len]);
                Ok(len)
            }
            Some(Cipher::V3 {
                tx, tx_mac, tx_seq, ..
            }) => {
                if buf.len() < len + TAG_LEN {
                    return Err(Fram::BadSz);
                }
                let seq = *tx_seq;
                *tx_seq = seq.checked_add(1).ok_or(Fram::Seq)?;
                tx.apply(&mut buf[..len]);
                let tag = v3_tag(tx_mac, V3_D2C, seq, &buf[..len]);
                buf[len..len + TAG_LEN].copy_from_slice(&tag);
                Ok(len + TAG_LEN)
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------------------

/// A request, its arguments checked for shape. Source: §3 [C]
#[derive(Debug, PartialEq, Eq)]
pub enum Request<'a> {
    Logout,
    Reboot,
    Version,
    Ping(&'a [u8]),
    Ncry {
        version: u32,
        host_pub: &'a [u8; 64],
    },
    Mitm,
    Chain,
    Bag(&'a [u8]),
    Dfu,
    Upload {
        offset: u32,
        total: u32,
        data: &'a [u8],
    },
    Download {
        offset: u32,
        length: u32,
        file: u32,
    },
    Sha,
    SignTx {
        len: u32,
        flags: u32,
        sha: &'a [u8; 32],
    },
    SignTxPoll,
    SignMsg {
        addr_fmt: u32,
        path: &'a str,
        msg: &'a [u8],
    },
    SignMsgPoll,
    Backup,
    BackupPoll,
    Restore {
        len: u32,
        sha: &'a [u8; 32],
        flags: u8,
    },
    Xpub(&'a str),
    Show {
        addr_fmt: u32,
        path: &'a str,
    },
    P2sh(&'a [u8]),
    Enroll {
        len: u32,
        sha: &'a [u8; 32],
    },
    MultisigCheck {
        m: u32,
        n: u32,
        xfp_xor: u32,
    },
    Passphrase(&'a [u8]),
    PassphrasePoll,
    // HSM: the opcodes are parsed only far enough to be named; a later package builds
    // HSM on this transport.
    HsmStart,
    HsmStatus,
    StorageLocker,
    NewUser,
    RemoveUser,
    UserAuth,
    /// Opcodes the host library knows and stock v5.6.2 does not dispatch (miniscript).
    NotDispatched([u8; 4]),
    /// A simulator-only test command (upper-case), or anything else.
    Unknown([u8; 4]),
}

/// Why a request's arguments were refused. The wire text is [`BadArgs::text`], sent as
/// `err_` + text.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum BadArgs {
    Length,
    NotText,
}

impl BadArgs {
    pub const fn text(self) -> &'static str {
        match self {
            BadArgs::Length => "Bad arguments: length",
            BadArgs::NotText => "Bad arguments: not text",
        }
    }
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn text(b: &[u8]) -> Result<&str, BadArgs> {
    core::str::from_utf8(b).map_err(|_| BadArgs::NotText)
}

impl<'a> Request<'a> {
    /// Parse a whole plaintext message. `Err(Fram::Decode)` when the opcode is not text
    /// (answered `fram`); `Ok(Err(..))` when the opcode is known and its arguments are
    /// not the right shape (answered `err_`).
    pub fn parse(msg: &'a [u8]) -> Result<Result<Self, BadArgs>, Fram> {
        let Some((op, args)) = msg.split_first_chunk::<4>() else {
            return Err(Fram::BadSz);
        };
        if !op.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
            return Err(Fram::Decode);
        }
        Ok(Self::args(*op, args))
    }

    fn args(op: [u8; 4], a: &'a [u8]) -> Result<Self, BadArgs> {
        let len = |n: usize| {
            if a.len() == n {
                Ok(())
            } else {
                Err(BadArgs::Length)
            }
        };
        let at_least = |n: usize| {
            if a.len() >= n {
                Ok(())
            } else {
                Err(BadArgs::Length)
            }
        };
        Ok(match &op {
            b"logo" => Request::Logout,
            b"rebo" => Request::Reboot,
            b"vers" => Request::Version,
            b"ping" => Request::Ping(a),
            b"ncry" => {
                len(4 + PUBKEY_LEN)?;
                Request::Ncry {
                    version: u32_at(a, 0),
                    host_pub: a[4..].try_into().map_err(|_| BadArgs::Length)?,
                }
            }
            b"mitm" => Request::Mitm,
            b"blkc" => Request::Chain,
            b"bagi" => Request::Bag(a),
            b"dfu_" => Request::Dfu,
            b"upld" => {
                at_least(8)?;
                Request::Upload {
                    offset: u32_at(a, 0),
                    total: u32_at(a, 4),
                    data: &a[8..],
                }
            }
            b"dwld" => {
                len(12)?;
                Request::Download {
                    offset: u32_at(a, 0),
                    length: u32_at(a, 4),
                    file: u32_at(a, 8),
                }
            }
            b"sha2" => Request::Sha,
            b"stxn" => {
                len(40)?;
                Request::SignTx {
                    len: u32_at(a, 0),
                    flags: u32_at(a, 4),
                    sha: a[8..40].try_into().map_err(|_| BadArgs::Length)?,
                }
            }
            b"stok" => Request::SignTxPoll,
            b"smsg" => {
                at_least(12)?;
                let fmt = u32_at(a, 0);
                let lp = u32_at(a, 4) as usize;
                let lm = u32_at(a, 8) as usize;
                // Source: §3.4 -- `len(args) == 12 + len_subpath + len_msg` [C]
                if Some(a.len()) != 12usize.checked_add(lp).and_then(|n| n.checked_add(lm)) {
                    return Err(BadArgs::Length);
                }
                Request::SignMsg {
                    addr_fmt: fmt,
                    path: text(&a[12..12 + lp])?,
                    msg: &a[12 + lp..],
                }
            }
            b"smok" => Request::SignMsgPoll,
            b"back" => Request::Backup,
            b"bkok" => Request::BackupPoll,
            b"rest" => {
                len(37)?;
                Request::Restore {
                    len: u32_at(a, 0),
                    sha: a[4..36].try_into().map_err(|_| BadArgs::Length)?,
                    flags: a[36],
                }
            }
            b"xpub" => Request::Xpub(text(a)?),
            b"show" => {
                at_least(4)?;
                Request::Show {
                    addr_fmt: u32_at(a, 0),
                    path: text(&a[4..])?,
                }
            }
            b"p2sh" => Request::P2sh(a),
            b"enrl" => {
                len(36)?;
                Request::Enroll {
                    len: u32_at(a, 0),
                    sha: a[4..36].try_into().map_err(|_| BadArgs::Length)?,
                }
            }
            b"msck" => {
                len(12)?;
                Request::MultisigCheck {
                    m: u32_at(a, 0),
                    n: u32_at(a, 4),
                    xfp_xor: u32_at(a, 8),
                }
            }
            b"pass" => Request::Passphrase(a),
            b"pwok" => Request::PassphrasePoll,
            b"hsms" => Request::HsmStart,
            b"hsts" => Request::HsmStatus,
            b"gslr" => Request::StorageLocker,
            b"nwur" => Request::NewUser,
            b"rmur" => Request::RemoveUser,
            b"user" => Request::UserAuth,
            b"msls" | b"msdl" | b"msgt" | b"msas" | b"mins" => Request::NotDispatched(op),
            _ => Request::Unknown(op),
        })
    }
}

/// A `p2sh` request: show a multisig address. Source: usb-ckcc-protocol.md §3.6 [C]
///
/// `<IBBH addr_fmt, M, N, script_len>`, the witness or redeem script, then for each of the
/// N cosigners -- in the order their keys appear in the script -- `[u8 count]` and `count`
/// little-endian `u32`s: the key's master fingerprint, then its path.
#[derive(Debug, PartialEq, Eq)]
pub struct P2sh<'a> {
    pub addr_fmt: u32,
    pub m: u8,
    pub n: u8,
    pub script: &'a [u8],
    paths: &'a [u8],
}

/// Most cosigners, shortest and longest script, and the path depth a `p2sh` allows.
/// Source: usb-ckcc-protocol.md §3.6 [C]
pub const P2SH_MAX_N: u8 = 20;
pub const P2SH_SCRIPT: core::ops::RangeInclusive<usize> = 30..=520;
pub const P2SH_PATH_MAX: usize = 16;

impl<'a> P2sh<'a> {
    /// Check the shape: a script-type format, `1 <= M <= N <= 20`, a script of 30..=520
    /// bytes, and exactly N paths of 1..=16 numbers with nothing after them.
    pub fn parse(a: &'a [u8]) -> Result<Self, BadArgs> {
        if a.len() < 8 {
            return Err(BadArgs::Length);
        }
        let addr_fmt = u32_at(a, 0);
        let (m, n) = (a[4], a[5]);
        let slen = u16::from_le_bytes([a[6], a[7]]) as usize;
        if addr_fmt & af::SCRIPT == 0 || m == 0 || m > n || n > P2SH_MAX_N {
            return Err(BadArgs::Length);
        }
        if !P2SH_SCRIPT.contains(&slen) || a.len() < 8 + slen {
            return Err(BadArgs::Length);
        }
        let me = Self {
            addr_fmt,
            m,
            n,
            script: &a[8..8 + slen],
            paths: &a[8 + slen..],
        };
        // Walk them once now, so every later walk is known to be well formed.
        let mut count = 0;
        let mut at = 0;
        while at < me.paths.len() {
            let k = me.paths[at] as usize;
            if k == 0 || k > P2SH_PATH_MAX || me.paths.len() < at + 1 + 4 * k {
                return Err(BadArgs::Length);
            }
            at += 1 + 4 * k;
            count += 1;
        }
        if count != usize::from(n) {
            return Err(BadArgs::Length);
        }
        Ok(me)
    }

    /// Each cosigner's `(fingerprint, path)`, the path written into `out`, in order.
    pub fn cosigner(&self, i: usize, out: &mut [u32; P2SH_PATH_MAX]) -> Option<(u32, usize)> {
        let mut at = 0;
        for _ in 0..i {
            at += 1 + 4 * usize::from(*self.paths.get(at)?);
        }
        let k = usize::from(*self.paths.get(at)?);
        let words = self.paths.get(at + 1..at + 1 + 4 * k)?;
        let xfp = u32_at(words, 0);
        for (j, slot) in out.iter_mut().enumerate().take(k - 1) {
            *slot = u32_at(words, 4 + 4 * j);
        }
        Some((xfp, k - 1))
    }
}

/// A BIP-32 path as stock's host tools write it: `m/84'/0'/0'`, with `'`, `h`, `H` or
/// `p` marking a hardened step. A leading `m` is optional, and `m` (or empty) alone is
/// the master. Returns the depth, the steps written into `out`.
///
/// `None` for anything else: a step that is not a number, too large, or too deep for
/// `out`.
pub fn parse_path(s: &str, out: &mut [u32]) -> Option<usize> {
    let s = s.trim();
    let rest = s
        .strip_prefix("m/")
        .or_else(|| s.strip_prefix("M/"))
        .unwrap_or(s);
    if rest.is_empty() || rest == "m" || rest == "M" {
        return Some(0);
    }
    let mut depth = 0;
    for part in rest.split('/') {
        let (num, hard) = match part.strip_suffix(['\'', 'h', 'H', 'p']) {
            Some(n) => (n, true),
            None => (part, false),
        };
        if num.is_empty() || !num.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let v: u32 = num.parse().ok()?;
        if v >= 0x8000_0000 {
            return None;
        }
        *out.get_mut(depth)? = if hard { v | 0x8000_0000 } else { v };
        depth += 1;
    }
    Some(depth)
}

// ---------------------------------------------------------------------------------------
// Upload rules
// ---------------------------------------------------------------------------------------

/// The `upld` bookkeeping: where the next block must start, how long the file is, and
/// the running SHA-256 of what has arrived. Source: §3.2 [C]
#[derive(Clone)]
pub struct Upload {
    next: u32,
    total: u32,
    hash: Sha256,
}

impl Default for Upload {
    fn default() -> Self {
        Self::new()
    }
}

impl Upload {
    pub fn new() -> Self {
        Self {
            next: 0,
            total: 0,
            hash: Sha256::new(),
        }
    }

    /// Check a block against the rules before any byte of it is stored: 256-aligned,
    /// strictly the next offset, a total between 1 and `max`, not past the end, at most
    /// [`MAX_BLK_LEN`]. Offset zero starts a new file and resets the hash.
    pub fn check(&self, offset: u32, total: u32, len: usize, max: u32) -> Result<(), &'static str> {
        if len > MAX_BLK_LEN {
            return Err("Block too long");
        }
        if !offset.is_multiple_of(256) {
            return Err("Offset not aligned");
        }
        if total == 0 || total > max {
            return Err("File too big");
        }
        // Strictly the next block. The total may grow on a later block: a firmware
        // upgrade sends the image, then its 128-byte header again after it with the
        // total raised to cover it (observed from the host tool; see `docs/USB.md`).
        if offset != 0 && (offset != self.next || total < self.total) {
            return Err("Out of order");
        }
        if u64::from(offset) + len as u64 > u64::from(total) {
            return Err("Past end");
        }
        Ok(())
    }

    /// Record a block that [`check`](Self::check) passed and that has been stored.
    pub fn accept(&mut self, offset: u32, total: u32, data: &[u8]) {
        if offset == 0 {
            self.hash = Sha256::new();
        }
        self.total = total;
        self.hash.update(data);
        self.next = offset + data.len() as u32;
    }

    /// Bytes received of the current file.
    pub fn received(&self) -> u32 {
        self.next
    }

    /// The declared length of the current file.
    pub fn total(&self) -> u32 {
        self.total
    }

    /// Whether every declared byte has arrived.
    pub fn complete(&self) -> bool {
        self.total > 0 && self.next == self.total
    }

    /// The digest of what has arrived so far.
    pub fn digest(&self) -> [u8; 32] {
        let out = self.hash.clone().finalize();
        let mut d = [0u8; 32];
        d.copy_from_slice(&out);
        d
    }

    /// Forget the file: a resync, or a new session.
    pub fn clear(&mut self) {
        *self = Self::new();
    }
}

// ---------------------------------------------------------------------------------------
// Replies
// ---------------------------------------------------------------------------------------

/// Reply encoders. Each writes a complete reply at the start of `out` and returns its
/// length, or `None` when `out` is too small. Source: §3.10 [C]
pub mod reply {
    use super::ERR_MAX;

    fn put(out: &mut [u8], parts: &[&[u8]]) -> Option<usize> {
        let mut at = 0;
        for p in parts {
            out.get_mut(at..at + p.len())?.copy_from_slice(p);
            at += p.len();
        }
        Some(at)
    }

    /// `okay`: done, nothing to say.
    pub fn okay(out: &mut [u8]) -> Option<usize> {
        put(out, &[b"okay"])
    }

    /// `refu`: the person said no.
    pub fn refused(out: &mut [u8]) -> Option<usize> {
        put(out, &[b"refu"])
    }

    /// `busy`: another request is in progress.
    pub fn busy(out: &mut [u8]) -> Option<usize> {
        put(out, &[b"busy"])
    }

    /// `err_` + text, cut to [`ERR_MAX`].
    pub fn err(out: &mut [u8], text: &str) -> Option<usize> {
        let t = &text.as_bytes()[..text.len().min(ERR_MAX)];
        put(out, &[b"err_", t])
    }

    /// `fram` + reason.
    pub fn fram(out: &mut [u8], reason: &str) -> Option<usize> {
        put(out, &[b"fram", reason.as_bytes()])
    }

    /// `asci` + text.
    pub fn asci(out: &mut [u8], text: &[u8]) -> Option<usize> {
        put(out, &[b"asci", text])
    }

    /// `biny` + bytes.
    pub fn biny(out: &mut [u8], data: &[u8]) -> Option<usize> {
        put(out, &[b"biny", data])
    }

    /// `int1` + one little-endian `u32`.
    pub fn int1(out: &mut [u8], v: u32) -> Option<usize> {
        put(out, &[b"int1", &v.to_le_bytes()])
    }

    /// `mypb`: our key, the master fingerprint and the master xpub (both empty/zero when
    /// there is no wallet yet). Source: §2.1 [C]
    pub fn mypb(out: &mut [u8], dev_pub: &[u8; 64], xfp: u32, xpub: &[u8]) -> Option<usize> {
        put(
            out,
            &[
                b"mypb",
                dev_pub,
                &xfp.to_le_bytes(),
                &(xpub.len() as u32).to_le_bytes(),
                xpub,
            ],
        )
    }

    /// `smrx`: the address, then the 65-byte signature. Source: §3.4 [C]
    pub fn smrx(out: &mut [u8], address: &[u8], sig: &[u8; 65]) -> Option<usize> {
        put(
            out,
            &[b"smrx", &(address.len() as u32).to_le_bytes(), address, sig],
        )
    }

    /// `strx`: a result file's length and SHA-256. Source: §3.3 [C]
    pub fn strx(out: &mut [u8], len: u32, sha: &[u8; 32]) -> Option<usize> {
        put(out, &[b"strx", &len.to_le_bytes(), sha])
    }
}

#[cfg(test)]
mod tests;
