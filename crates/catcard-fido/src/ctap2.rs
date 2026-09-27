//! CTAP2: the authenticator API a browser speaks to a FIDO2 security key.
//!
//! A request is one command byte and, for most commands, a CBOR map with integer keys; a
//! response is one status byte and, on success, a CBOR map. What this device answers:
//!
//! | command | here |
//! |---|---|
//! | `authenticatorMakeCredential` (0x01) | ES256 only, `packed` self-attestation; `rk` stores a passkey |
//! | `authenticatorGetAssertion` (0x02) | an `allowList`, or none to find this wallet's passkeys for the site |
//! | `authenticatorGetInfo` (0x04) | [`get_info`], from the device's [`Caps`] |
//! | `authenticatorClientPIN` (0x06) | PIN/UV auth protocols 2 and 1, see [`crate::pin`] |
//! | `authenticatorReset` (0x07) | rotates the wallet's FIDO generation, clears its PIN and passkeys, see [`Env::reset`] |
//! | `authenticatorGetNextAssertion` (0x08) | the site's other passkeys, newest first |
//! | `authenticatorCredentialManagement` (0x0A, and 0x41) | see [`crate::credmgmt`] |
//! | `authenticatorSelection` (0x0B) | a press on the device |
//!
//! Source: FIDO CTAP 2.1 (Proposed Standard, 2021-06-15, errata 2022-06-21) §6 [C].
//! Section numbers below are that document's.
//!
//! # User verification
//!
//! The only user verification is the **client PIN** ([`crate::pin`]): typed in the
//! browser, traded for a token, and the token's MAC over the request's clientDataHash is
//! what sets the UV flag. There is no built-in method, so GetInfo carries no `uv` option
//! and a request with `uv: true` is `CTAP2_ERR_INVALID_OPTION` (§6.1.2 step 5).
//!
//! With a PIN set the key is "protected by some form of user verification" and:
//!
//! - a **passkey** (`rk: true`) needs the PIN: `CTAP2_ERR_PUAT_REQUIRED` without it
//!   (§6.1.2 step 7);
//! - an ordinary **second-factor** registration does not: GetInfo says
//!   `makeCredUvNotRqd: true`, which §6.4 says authenticators SHOULD, and §6.1.2 step 10
//!   lets it through with the UV flag clear. Without it, turning a PIN on would break every
//!   site that uses this key only as a second factor and whose browser does not ask for
//!   the PIN.
//!
//! With no PIN set, a site that requires UV is the browser's to handle: it sees
//! `clientPin: false` in GetInfo and offers to set one (§6.2.1 "the platform recovers in
//! some fashion").
//!
//! # What is refused, and with what
//!
//! - an algorithm list without ES256 (`alg` -7): `CTAP2_ERR_UNSUPPORTED_ALGORITHM`;
//! - `uv: true`: `CTAP2_ERR_INVALID_OPTION` -- no built-in user verification;
//! - `up: false` on MakeCredential: `CTAP2_ERR_INVALID_OPTION`;
//! - `rk: true` where the board keeps no passkeys (the mk3): `CTAP2_ERR_UNSUPPORTED_OPTION`;
//! - `enterpriseAttestation`: `CTAP1_ERR_INVALID_PARAMETER` (§6.1.2 step 9);
//! - `rk` in GetAssertion's options: `CTAP2_ERR_UNSUPPORTED_OPTION` (§6.2.2 step 3).
//!
//! Extensions are parsed (strictly) and ignored; none is supported, so none is answered.

use catcard_wallet::KeyWork;
use purecrypto::hash::{Digest, Sha256};

use crate::cbor::{self, Key, Reader, Writer};
use crate::der;
use crate::keys::{CRED_ID_LEN, CRED_VERSION, Master, NONCE_LEN};
use crate::passkeys::{self, Passkeys, Record};
use crate::pin::{self, Cursor, PinRecord, Session, perm};

/// This device's AAGUID, `54a5d3d6-f9d6-4b05-bdac-7cc541efc8f1`: a random (version 4)
/// UUID generated once (2026-09-27, Python's `uuid.uuid4()`) and fixed, so a relying party sees the same model identifier
/// from every CatCard. It identifies the firmware, never the unit or the wallet.
pub const AAGUID: [u8; 16] = [
    0x54, 0xa5, 0xd3, 0xd6, 0xf9, 0xd6, 0x4b, 0x05, 0xbd, 0xac, 0x7c, 0xc5, 0x41, 0xef, 0xc8, 0xf1,
];

/// Command bytes. Source: §6, §6.13 (0x41) [C]
pub mod command {
    pub const MAKE_CREDENTIAL: u8 = 0x01;
    pub const GET_ASSERTION: u8 = 0x02;
    pub const GET_INFO: u8 = 0x04;
    pub const CLIENT_PIN: u8 = 0x06;
    pub const RESET: u8 = 0x07;
    pub const GET_NEXT_ASSERTION: u8 = 0x08;
    pub const CREDENTIAL_MANAGEMENT: u8 = 0x0A;
    pub const SELECTION: u8 = 0x0B;
    /// The "FIDO_2_1_PRE" prototype of credential management, which some platforms
    /// still send. Answered as 0x0A. Source: §6.13 [C]
    pub const CREDENTIAL_MANAGEMENT_PRE: u8 = 0x41;
}

/// Status codes. Source: §8.2 "Status codes" [C]
pub mod status {
    pub const OK: u8 = 0x00;
    pub const INVALID_COMMAND: u8 = 0x01;
    pub const INVALID_PARAMETER: u8 = 0x02;
    pub const INVALID_LENGTH: u8 = 0x03;
    pub const CBOR_UNEXPECTED_TYPE: u8 = 0x11;
    pub const INVALID_CBOR: u8 = 0x12;
    pub const MISSING_PARAMETER: u8 = 0x14;
    pub const LIMIT_EXCEEDED: u8 = 0x15;
    pub const CREDENTIAL_EXCLUDED: u8 = 0x19;
    pub const UNSUPPORTED_ALGORITHM: u8 = 0x26;
    pub const OPERATION_DENIED: u8 = 0x27;
    pub const KEY_STORE_FULL: u8 = 0x28;
    pub const UNSUPPORTED_OPTION: u8 = 0x2B;
    pub const INVALID_OPTION: u8 = 0x2C;
    pub const KEEPALIVE_CANCEL: u8 = 0x2D;
    pub const NO_CREDENTIALS: u8 = 0x2E;
    pub const USER_ACTION_TIMEOUT: u8 = 0x2F;
    pub const NOT_ALLOWED: u8 = 0x30;
    pub const PIN_INVALID: u8 = 0x31;
    pub const PIN_BLOCKED: u8 = 0x32;
    pub const PIN_AUTH_INVALID: u8 = 0x33;
    pub const PIN_AUTH_BLOCKED: u8 = 0x34;
    pub const PIN_NOT_SET: u8 = 0x35;
    /// `CTAP2_ERR_PUAT_REQUIRED`, `CTAP2_ERR_PIN_REQUIRED` in CTAP 2.0.
    pub const PUAT_REQUIRED: u8 = 0x36;
    pub const PIN_POLICY_VIOLATION: u8 = 0x37;
    pub const REQUEST_TOO_LARGE: u8 = 0x39;
    pub const INVALID_SUBCOMMAND: u8 = 0x3E;
    pub const UNAUTHORIZED_PERMISSION: u8 = 0x40;
    pub const OTHER: u8 = 0x7F;
}

/// COSE algorithm ES256: ECDSA over P-256 with SHA-256.
/// Source: RFC 9053 §2.1; WebAuthn L2 §5.8.5 [C]
pub const ES256: i64 = -7;

/// Most credentials a platform should put in one `allowList` / `excludeList`, and the
/// longest credential id worth sending: ours are [`CRED_ID_LEN`], so anything longer
/// is another authenticator's. Together they keep a list inside [`crate::hid::MAX_MSG`].
/// Source: §6.4 `maxCredentialCountInList` (0x07), `maxCredentialIdLength` (0x08) [C]
pub const MAX_CRED_COUNT: u64 = 8;
pub const MAX_CRED_ID_LEN: u64 = 64;

/// Authenticator data flags. Source: WebAuthn L2 §6.1 [C]
pub mod flags {
    /// User present.
    pub const UP: u8 = 0x01;
    /// User verified.
    pub const UV: u8 = 0x04;
    /// Attested credential data included.
    pub const AT: u8 = 0x40;
}

/// What the device is asked to show a person.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Ask<'a> {
    /// Register with a site. `excluded`: this wallet is already registered there, and
    /// the answer will only be "already registered". `resident`: kept on the device as a
    /// passkey.
    Register {
        rp_id: &'a str,
        user_name: Option<&'a str>,
        display_name: Option<&'a str>,
        excluded: bool,
        resident: bool,
    },
    /// Sign in to a site. `known`: one of the offered credentials is this wallet's, or it
    /// has a passkey there.
    SignIn { rp_id: &'a str, known: bool },
    /// U2F registration: only a hash of the site is known.
    U2fRegister { app: &'a [u8; 32] },
    /// U2F sign-in.
    U2fSignIn { app: &'a [u8; 32] },
    /// The platform wants the person to pick this authenticator among several.
    Select,
    /// The computer wants to set the security-key PIN (none is set).
    SetPin,
    /// The computer wants to change the security-key PIN.
    ChangePin,
    /// The computer has the PIN and wants a token: for `permissions` ([`perm`]), at
    /// `rp_id` when it named one.
    UsePin {
        rp_id: Option<&'a str>,
        permissions: u8,
    },
}

/// How a person answered, or did not.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Presence {
    Allowed,
    /// They pressed cancel.
    Denied,
    /// Nobody answered in time.
    Timeout,
    /// The host withdrew the request (`CTAPHID_CANCEL`).
    Cancelled,
}

impl Presence {
    /// The status a request that did not get [`Presence::Allowed`] ends with.
    /// Source: §6.1.2 step 13, §6.2.2 [C]
    pub fn refusal(self) -> u8 {
        match self {
            Presence::Allowed => status::OK,
            Presence::Denied => status::OPERATION_DENIED,
            Presence::Timeout => status::USER_ACTION_TIMEOUT,
            Presence::Cancelled => status::KEEPALIVE_CANCEL,
        }
    }
}

/// What the device can do right now, as GetInfo reports it.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Caps {
    /// A PIN is set for the wallet in force (or one is stored and unreadable, which is
    /// treated as set and blocked).
    pub pin_set: bool,
    /// This board keeps passkeys.
    pub rk: bool,
    /// Passkeys that can still be stored, when known.
    pub remaining: Option<u8>,
}

/// One request, as the device's log says it: what was asked, about which site, and how
/// it ended. Never a PIN, a hash, a token, a key or a user id.
#[derive(Clone, Debug, Default)]
pub struct Note<'a> {
    pub command: u8,
    /// The subcommand, for clientPIN and credential management.
    pub sub: Option<u64>,
    pub rp_id: Option<&'a str>,
    pub rk: bool,
    pub uv: bool,
    /// Passkeys found, for a GetAssertion without an allow list.
    pub found: Option<u8>,
    pub pin: Option<pin::Outcome>,
    pub status: u8,
}

/// What the protocol needs from the device around it.
pub trait Env {
    /// Ask the person, and wait (bounded) for the answer.
    fn presence(&mut self, ask: Ask<'_>) -> Presence;
    /// Run `f` once with the FIDO master of the wallet in force, inside the masked region.
    /// False (and `f` not run) when there is no wallet to derive one from (logged out, no
    /// seed, a WIF key) or it could not be derived.
    ///
    /// Takes `dyn`: the device's side of this -- the derivation, the cache, the masking --
    /// then exists once in the image, not once per caller. [`with_master`](Self::with_master)
    /// is the typed way to call it.
    fn master_do(&mut self, f: &mut dyn FnMut(&Master, &KeyWork)) -> bool;
    /// [`master_do`](Self::master_do), returning what `f` returns.
    fn with_master<R>(&mut self, f: impl FnOnce(&Master, &KeyWork) -> R) -> Option<R>
    where
        Self: Sized,
    {
        let mut f = Some(f);
        let mut out = None;
        let ran = self.master_do(&mut |m, kw| {
            if let Some(f) = f.take() {
                out = Some(f(m, kw));
            }
        });
        if ran { out } else { None }
    }
    /// Run `f` inside the masked region, with no wallet: the PIN protocol's key
    /// agreement and PIN-hash work.
    fn masked<R>(&mut self, f: impl FnOnce(&KeyWork) -> R) -> R;
    /// Fill `out` from the device's DRBG. False if it cannot.
    fn random(&mut self, out: &mut [u8]) -> bool;
    /// Milliseconds, from any origin; wraps.
    fn now_ms(&mut self) -> u32;
    /// `authenticatorReset`: within the allowed window, asked twice, then the wallet's
    /// FIDO generation raised and its PIN and passkeys removed. Returns a [`status`] code.
    fn reset(&mut self) -> u8;
    /// U2F user presence for `app`: whether a press has been given for it. The device
    /// asks on its screen when one has not, after the answer has gone back; see
    /// [`crate::u2f`].
    fn u2f_presence(&mut self, register: bool, app: &[u8; 32]) -> bool;
    /// What GetInfo says.
    fn caps(&mut self) -> Caps;
    /// The wallet's PIN, `None` when none is set. A stored value that cannot be read
    /// comes back as set with no retries left: blocked until a reset.
    fn pin(&mut self) -> Option<PinRecord>;
    /// Write the wallet's PIN record. False if it could not be written, in which case the
    /// caller goes no further.
    fn save_pin(&mut self, rec: &PinRecord) -> bool;
    /// Run `f` once over the wallet's passkeys; when it returns `true` the list is written
    /// back. `Err` is a [`status`]: no passkeys on this board, no wallet, no memory, or a
    /// file that will not open or be written. `dyn` for the same reason as
    /// [`master_do`](Self::master_do); [`passkeys`](Self::passkeys) is the typed way.
    fn passkeys_do(&mut self, f: &mut dyn FnMut(&mut Passkeys<'_>) -> bool) -> Result<(), u8>;
    /// [`passkeys_do`](Self::passkeys_do), returning what `f` returns.
    fn passkeys<R>(&mut self, f: impl FnOnce(&mut Passkeys<'_>) -> (R, bool)) -> Result<R, u8>
    where
        Self: Sized,
    {
        let mut f = Some(f);
        let mut out = None;
        self.passkeys_do(&mut |p| match f.take() {
            Some(f) => {
                let (r, changed) = f(p);
                out = Some(r);
                changed
            }
            None => false,
        })?;
        out.ok_or(status::OTHER)
    }
    /// One request finished. For the log.
    fn note(&mut self, _note: &Note<'_>) {}
}

/// A request's parse failure as its status.
pub(crate) fn cbor_status(e: cbor::Error) -> u8 {
    match e {
        cbor::Error::Unexpected => status::CBOR_UNEXPECTED_TYPE,
        cbor::Error::Invalid | cbor::Error::TooDeep => status::INVALID_CBOR,
        cbor::Error::Overflow => status::OTHER,
    }
}

pub(crate) type R<T> = Result<T, u8>;

pub(crate) fn c<T>(r: Result<T, cbor::Error>) -> R<T> {
    r.map_err(cbor_status)
}

/// Answer one CTAP2 request (`req` is the command byte and its CBOR). The response --
/// status byte, then CBOR on success -- goes into `out`; returns its length.
///
/// `out` must be at least 512 bytes; [`crate::hid::MAX_MSG`] is plenty. `s` is the
/// state kept from power-up to power-off ([`Session`]).
#[inline(never)]
pub fn handle<E: Env>(req: &[u8], out: &mut [u8], s: &mut Session, env: &mut E) -> usize {
    let Some((&cmd, body)) = req.split_first() else {
        out[0] = status::INVALID_LENGTH;
        return 1;
    };
    // A stateful command's state lasts until any other command. Source: §6.3, §6.8.3 [C]
    if !matches!(
        cmd,
        command::GET_NEXT_ASSERTION
            | command::CREDENTIAL_MANAGEMENT
            | command::CREDENTIAL_MANAGEMENT_PRE
    ) {
        s.cursor = Cursor::None;
    }
    let mut note = Note {
        command: cmd,
        ..Note::default()
    };
    let result = match cmd {
        command::GET_INFO => {
            let caps = env.caps();
            return get_info(out, &caps);
        }
        command::MAKE_CREDENTIAL => make_credential(body, &mut out[1..], s, env, &mut note),
        command::GET_ASSERTION => get_assertion(body, &mut out[1..], s, env, &mut note),
        command::GET_NEXT_ASSERTION => get_next_assertion(&mut out[1..], s, env, &mut note),
        command::CLIENT_PIN => pin::handle(body, &mut out[1..], s, env, &mut note),
        command::CREDENTIAL_MANAGEMENT | command::CREDENTIAL_MANAGEMENT_PRE => {
            if env.caps().rk {
                crate::credmgmt::handle(body, &mut out[1..], s, env, &mut note)
            } else {
                Err(status::INVALID_COMMAND)
            }
        }
        command::RESET => match env.reset() {
            status::OK => {
                s.forget_wallet();
                Ok(0)
            }
            e => Err(e),
        },
        command::SELECTION => match env.presence(Ask::Select) {
            Presence::Allowed => Ok(0),
            p => Err(p.refusal()),
        },
        _ => Err(status::INVALID_COMMAND),
    };
    let n = match result {
        Ok(n) => {
            out[0] = status::OK;
            1 + n
        }
        Err(e) => {
            out[0] = e;
            1
        }
    };
    note.status = out[0];
    env.note(&note);
    n
}

/// `authenticatorGetInfo`: status byte and the map. Source: §6.4 [C]
pub fn get_info(out: &mut [u8], caps: &Caps) -> usize {
    out[0] = status::OK;
    let remaining = caps.remaining.filter(|_| caps.rk);
    let mut w = Writer::new(&mut out[1..]);
    w.map(10 + remaining.is_some() as usize);
    // 0x01 versions
    w.uint(0x01)
        .array(3)
        .text("U2F_V2")
        .text("FIDO_2_0")
        .text("FIDO_2_1");
    // 0x03 aaguid
    w.uint(0x03).bytes(&AAGUID);
    // 0x04 options, in canonical order (shorter keys first, then bytewise). No "uv": the
    // only user verification is the client PIN, which is not a built-in method (§6.4).
    w.uint(0x04).map(6 + caps.rk as usize);
    w.text("rk").bool(caps.rk);
    w.text("up").bool(true);
    w.text("plat").bool(false);
    if caps.rk {
        w.text("credMgmt").bool(true);
    }
    w.text("clientPin").bool(caps.pin_set);
    w.text("pinUvAuthToken").bool(true);
    // See the module notes: a second-factor registration needs no PIN.
    w.text("makeCredUvNotRqd").bool(true);
    // 0x05 maxMsgSize
    w.uint(0x05).uint(crate::hid::MAX_MSG as u64);
    // 0x06 pinUvAuthProtocols, preferred first
    w.uint(0x06).array(pin::PROTOCOLS.len());
    for p in pin::PROTOCOLS {
        w.uint(p as u64);
    }
    // 0x07 maxCredentialCountInList, 0x08 maxCredentialIdLength
    w.uint(0x07).uint(MAX_CRED_COUNT);
    w.uint(0x08).uint(MAX_CRED_ID_LEN);
    // 0x09 transports
    w.uint(0x09).array(1).text("usb");
    // 0x0A algorithms: [{"alg": -7, "type": "public-key"}]
    w.uint(0x0A)
        .array(1)
        .map(2)
        .text("alg")
        .int(ES256)
        .text("type")
        .text("public-key");
    // 0x0D minPINLength: required when clientPIN is supported (§6.4).
    w.uint(0x0D).uint(pin::MIN_PIN_LEN as u64);
    // 0x14 remainingDiscoverableCredentials, when known.
    if let Some(r) = remaining {
        w.uint(0x14).uint(r as u64);
    }
    match w.finish() {
        Ok(n) => 1 + n,
        Err(_) => {
            out[0] = status::OTHER;
            1
        }
    }
}

/// A PublicKeyCredentialDescriptor list, validated once and kept as its raw bytes so it
/// can be walked again without storing it.
#[derive(Copy, Clone, Default)]
struct Descriptors<'a> {
    raw: &'a [u8],
}

impl<'a> Descriptors<'a> {
    /// Read and check a list at `r`, keeping its bytes.
    fn read(r: &mut Reader<'a>, buf: &'a [u8]) -> R<Self> {
        let start = r.position();
        let n = c(r.array())?;
        for _ in 0..n {
            c(descriptor(r))?.ok_or(status::MISSING_PARAMETER)?;
        }
        Ok(Self {
            raw: &buf[start..r.position()],
        })
    }

    /// Each public-key credential id, in order, until `f` says stop.
    fn each(&self, mut f: impl FnMut(&'a [u8]) -> bool) {
        if self.raw.is_empty() {
            return;
        }
        let mut r = Reader::new(self.raw);
        let Ok(n) = r.array() else { return };
        for _ in 0..n {
            match descriptor(&mut r) {
                Ok(Some((id, true))) => {
                    if f(id) {
                        return;
                    }
                }
                Ok(_) => {}
                Err(_) => return,
            }
        }
    }

    fn is_empty(&self) -> bool {
        // An array header of zero is the one byte 0x80.
        self.raw.len() <= 1
    }
}

/// One descriptor: `(id, is a public key)`, or `None` when `id` or `type` is missing.
/// Source: WebAuthn L2 §5.8.3; CTAP 2.1 §6.1 (types other than "public-key" ignored) [C]
pub(crate) fn descriptor<'a>(r: &mut Reader<'a>) -> Result<Option<(&'a [u8], bool)>, cbor::Error> {
    let mut m = r.map()?;
    let mut id = None;
    let mut public_key = None;
    while let Some(k) = r.key(&mut m)? {
        match k {
            Key::Text("id") => id = Some(r.bytes()?),
            Key::Text("type") => public_key = Some(r.text()? == "public-key"),
            Key::Text("transports") => {
                let n = r.array()?;
                for _ in 0..n {
                    r.text()?;
                }
            }
            _ => r.skip(cbor::MAX_DEPTH - 3)?,
        }
    }
    Ok(match (id, public_key) {
        (Some(id), Some(pk)) => Some((id, pk)),
        _ => None,
    })
}

/// A PublicKeyCredentialUserEntity: `(id, name, displayName)`, `id` required and at most
/// 64 bytes. Source: WebAuthn L2 §5.4.3 [C]
pub(crate) type User<'a> = (&'a [u8], Option<&'a str>, Option<&'a str>);

pub(crate) fn user_entity<'a>(r: &mut Reader<'a>, depth: u8) -> R<User<'a>> {
    let mut e = c(r.map())?;
    let mut id = None;
    let (mut name, mut display) = (None, None);
    while let Some(k) = c(r.key(&mut e))? {
        match k {
            Key::Text("id") => id = Some(c(r.bytes())?),
            Key::Text("name") => name = Some(c(r.text())?),
            Key::Text("displayName") => display = Some(c(r.text())?),
            Key::Text("icon") => {
                c(r.text())?;
            }
            _ => c(r.skip(depth))?,
        }
    }
    let id = id.ok_or(status::MISSING_PARAMETER)?;
    if id.len() > passkeys::USER_ID_MAX {
        return Err(status::INVALID_PARAMETER);
    }
    Ok((id, name, display))
}

/// The options map both commands take. Unknown options are ignored.
#[derive(Copy, Clone, Default)]
struct Options {
    rk: Option<bool>,
    up: Option<bool>,
    uv: Option<bool>,
}

fn options(r: &mut Reader<'_>) -> R<Options> {
    let mut o = Options::default();
    let mut m = c(r.map())?;
    while let Some(k) = c(r.key(&mut m))? {
        match k {
            Key::Text("rk") => o.rk = Some(c(r.bool())?),
            Key::Text("up") => o.up = Some(c(r.bool())?),
            Key::Text("uv") => o.uv = Some(c(r.bool())?),
            _ => c(r.skip(cbor::MAX_DEPTH - 2))?,
        }
    }
    Ok(o)
}

fn hash32(b: &[u8]) -> R<&[u8; 32]> {
    b.try_into().map_err(|_| status::INVALID_PARAMETER)
}

/// §6.1.2 step 1 / §6.2.2 step 1: a zero-length `pinUvAuthParam` is a platform asking
/// the person to touch the key it will then ask for a PIN. The answer is only ever an
/// error, which says whether a PIN is set.
fn touch_probe<E: Env>(env: &mut E) -> u8 {
    match env.presence(Ask::Select) {
        Presence::Allowed if env.caps().pin_set => status::PIN_INVALID,
        Presence::Allowed => status::PIN_NOT_SET,
        p => p.refusal(),
    }
}

/// §6.1.2 step 11 / §6.2.2 step 6: the request's `pinUvAuthParam` checked against the
/// token -- its MAC over the clientDataHash, the permission, the site -- and the site
/// bound to the token if none was.
fn check_token(
    s: &mut Session,
    protocol: u8,
    cdh: &[u8; 32],
    param: &[u8],
    rp_id_hash: &[u8; 32],
    permission: u8,
    now: u32,
) -> R<()> {
    if !s.verify_token(protocol, &[cdh], param, now) {
        return Err(status::PIN_AUTH_INVALID);
    }
    if !s.user_verified() || !s.has_permission(permission) {
        return Err(status::PIN_AUTH_INVALID);
    }
    if s.token_rp().is_some_and(|rp| rp != rp_id_hash) {
        return Err(status::PIN_AUTH_INVALID);
    }
    s.bind_rp(rp_id_hash);
    Ok(())
}

struct MakeCredential<'a> {
    client_data_hash: &'a [u8; 32],
    rp_id: &'a str,
    user_id: &'a [u8],
    user_name: Option<&'a str>,
    display_name: Option<&'a str>,
    es256: bool,
    exclude: Descriptors<'a>,
    options: Options,
    pin_auth: Option<&'a [u8]>,
    pin_protocol: Option<u64>,
    enterprise: bool,
}

fn parse_make_credential(body: &[u8]) -> R<MakeCredential<'_>> {
    let mut r = Reader::new(body);
    let mut m = c(r.map())?;
    let mut cdh = None;
    let mut rp_id = None;
    let mut user = None;
    let mut params = None;
    let mut mc = MakeCredential {
        client_data_hash: &[0; 32],
        rp_id: "",
        user_id: &[],
        user_name: None,
        display_name: None,
        es256: false,
        exclude: Descriptors::default(),
        options: Options::default(),
        pin_auth: None,
        pin_protocol: None,
        enterprise: false,
    };
    while let Some(k) = c(r.key(&mut m))? {
        match k {
            Key::Int(0x01) => cdh = Some(c(r.bytes())?),
            Key::Int(0x02) => {
                // PublicKeyCredentialRpEntity: `id` required here.
                let mut e = c(r.map())?;
                let mut id = None;
                while let Some(k) = c(r.key(&mut e))? {
                    match k {
                        Key::Text("id") => id = Some(c(r.text())?),
                        Key::Text("name") | Key::Text("icon") => {
                            c(r.text())?;
                        }
                        _ => c(r.skip(cbor::MAX_DEPTH - 2))?,
                    }
                }
                rp_id = Some(id.ok_or(status::MISSING_PARAMETER)?);
            }
            Key::Int(0x03) => {
                let (id, name, display) = user_entity(&mut r, cbor::MAX_DEPTH - 2)?;
                mc.user_id = id;
                mc.user_name = name;
                mc.display_name = display;
                user = Some(());
            }
            Key::Int(0x04) => {
                let n = c(r.array())?;
                for _ in 0..n {
                    let mut e = c(r.map())?;
                    let mut alg = None;
                    let mut ty = None;
                    while let Some(k) = c(r.key(&mut e))? {
                        match k {
                            Key::Text("alg") => alg = Some(c(r.int())?),
                            Key::Text("type") => ty = Some(c(r.text())?),
                            _ => c(r.skip(cbor::MAX_DEPTH - 3))?,
                        }
                    }
                    let (Some(alg), Some(ty)) = (alg, ty) else {
                        return Err(status::MISSING_PARAMETER);
                    };
                    mc.es256 |= alg == ES256 && ty == "public-key";
                }
                params = Some(());
            }
            Key::Int(0x05) => mc.exclude = Descriptors::read(&mut r, body)?,
            Key::Int(0x06) => {
                // Extensions: none supported. Checked for shape, then ignored.
                let at = r.peek_major();
                if c(at)? != cbor::major::MAP {
                    return Err(status::CBOR_UNEXPECTED_TYPE);
                }
                c(r.skip(cbor::MAX_DEPTH - 1))?;
            }
            Key::Int(0x07) => mc.options = options(&mut r)?,
            Key::Int(0x08) => mc.pin_auth = Some(c(r.bytes())?),
            Key::Int(0x09) => mc.pin_protocol = Some(c(r.uint())?),
            Key::Int(0x0A) => {
                c(r.uint())?;
                mc.enterprise = true;
            }
            _ => c(r.skip(cbor::MAX_DEPTH - 1))?,
        }
    }
    c(r.finish())?;
    let (Some(cdh), Some(rp_id), Some(()), Some(())) = (cdh, rp_id, user, params) else {
        return Err(status::MISSING_PARAMETER);
    };
    mc.client_data_hash = hash32(cdh)?;
    mc.rp_id = rp_id;
    Ok(mc)
}

/// §6.1.2. The attestation is `packed` **self-attestation**: the statement is signed by
/// the new credential's own key, with no certificate. Chosen over `none` because it is a
/// real, verifiable statement a relying party asking for attestation can check (WebAuthn
/// L2 §8.2), and over a device attestation key because such a key would have to be
/// shared by every CatCard -- or else it would identify one -- and CatCard has neither a
/// vendor CA nor anything to attest beyond "this key signed this".
#[inline(never)]
fn make_credential<'a, E: Env>(
    body: &'a [u8],
    out: &mut [u8],
    s: &mut Session,
    env: &mut E,
    note: &mut Note<'a>,
) -> R<usize> {
    let mc = parse_make_credential(body)?;
    note.rp_id = Some(mc.rp_id);
    let rk = mc.options.rk == Some(true);
    note.rk = rk;
    // Step 1: the "touch this key" probe.
    if mc.pin_auth.is_some_and(|p| p.is_empty()) {
        return Err(touch_probe(env));
    }
    // Step 2.
    let protocol = match mc.pin_auth {
        Some(_) => Some(pin::check_protocol(mc.pin_protocol)?),
        None => None,
    };
    // Step 3.
    if !mc.es256 {
        return Err(status::UNSUPPORTED_ALGORITHM);
    }
    // Step 5: options. With a pinUvAuthParam, "uv" is treated as false.
    let caps = env.caps();
    if mc.pin_auth.is_none() && mc.options.uv == Some(true) {
        return Err(status::INVALID_OPTION);
    }
    if rk && !caps.rk {
        return Err(status::UNSUPPORTED_OPTION);
    }
    if mc.options.up == Some(false) {
        return Err(status::INVALID_OPTION);
    }
    // Step 7 (makeCredUvNotRqd is true): a passkey on a PIN-protected key needs the PIN.
    if caps.pin_set && mc.pin_auth.is_none() && rk {
        return Err(status::PUAT_REQUIRED);
    }
    // Step 9.
    if mc.enterprise {
        return Err(status::INVALID_PARAMETER);
    }
    let rp_id_hash: [u8; 32] = Sha256::digest(mc.rp_id.as_bytes());
    let now = env.now_ms();

    // Step 11: the token, when there is one to check. Without a PIN set there is no
    // token, and the step does not apply (the UV flag stays clear).
    let mut uv = false;
    if let (Some(param), Some(protocol), true) = (mc.pin_auth, protocol, caps.pin_set) {
        check_token(
            s,
            protocol,
            mc.client_data_hash,
            param,
            &rp_id_hash,
            perm::MC,
            now,
        )?;
        uv = true;
    }
    note.uv = uv;
    // The press given for the token, when it is still fresh, is this request's presence
    // (see `crate::pin`).
    let cached_up = uv && s.user_present(now);

    // Step 12: a credential of ours in the exclude list means this wallet is already
    // registered here. The person still answers -- so a host cannot learn that without
    // them -- and the answer is only ever "excluded".
    let excluded = if mc.exclude.is_empty() {
        false
    } else {
        env.with_master(|m, kw| {
            let mut hit = false;
            mc.exclude.each(|id| {
                hit = m.owns(&rp_id_hash, id, kw).is_some();
                hit
            });
            hit
        })
        .ok_or(status::OPERATION_DENIED)?
    };
    // Step 14.
    if !cached_up {
        let ask = Ask::Register {
            rp_id: mc.rp_id,
            user_name: mc.user_name,
            display_name: mc.display_name,
            excluded,
            resident: rk,
        };
        match env.presence(ask) {
            Presence::Allowed => {}
            p => return Err(p.refusal()),
        }
    }
    s.consume();
    if excluded {
        return Err(status::CREDENTIAL_EXCLUDED);
    }

    let mut nonce = [0u8; NONCE_LEN];
    if !env.random(&mut nonce) {
        return Err(status::OTHER);
    }
    let cdh = mc.client_data_hash;
    let flags = flags::UP | flags::AT | if uv { flags::UV } else { 0 };
    let n = env
        .with_master(|m, kw| {
            let id = m.credential_id(&rp_id_hash, &nonce, kw);
            let key = m
                .signing_key(&rp_id_hash, &nonce, kw)
                .ok_or(status::OTHER)?;
            let public = key.public_sec1(kw);
            let mut auth = [0u8; AUTH_DATA_MAX];
            let an = attested_auth_data(&rp_id_hash, flags, &id, &public, &mut auth)
                .ok_or(status::OTHER)?;
            let (r, s) = key.sign(&[&auth[..an], cdh], kw).ok_or(status::OTHER)?;
            let mut sig = [0u8; der::SIG_MAX];
            let sn = der::signature(&r, &s, &mut sig);
            let mut w = Writer::new(out);
            // {1: fmt, 2: authData, 3: attStmt{"alg", "sig"}}
            w.map(3)
                .uint(1)
                .text("packed")
                .uint(2)
                .bytes(&auth[..an])
                .uint(3)
                .map(2)
                .text("alg")
                .int(ES256)
                .text("sig")
                .bytes(&sig[..sn]);
            w.finish().map_err(|_| status::OTHER)
        })
        .ok_or(status::OPERATION_DENIED)??;

    // Step 17: a passkey is stored before the answer goes back, or there is no answer.
    if rk {
        let rec = Record::new(
            &nonce,
            mc.rp_id,
            &rp_id_hash,
            mc.user_id,
            mc.user_name,
            mc.display_name,
        )
        .ok_or(status::INVALID_PARAMETER)?;
        env.passkeys(|p| match p.add(&rec) {
            Ok(()) => (Ok(()), true),
            Err(passkeys::Error::Full) => (Err(status::KEY_STORE_FULL), false),
            Err(_) => (Err(status::OTHER), false),
        })??;
    }
    Ok(n)
}

/// Authenticator data with attested credential data: 37 + 16 + 2 + 33 + 77.
pub const AUTH_DATA_MAX: usize = 37 + 16 + 2 + CRED_ID_LEN + COSE_KEY_LEN;
/// The COSE key below, which is always this long.
pub(crate) const COSE_KEY_LEN: usize = 77;

/// An ES256 public key as a COSE_Key, EC2, canonical order: 1 (kty), 3 (alg), -1 (crv),
/// -2 (x), -3 (y). Source: RFC 9052 §7, RFC 9053 §7.1.1 [C]
pub(crate) fn write_cose_es256(w: &mut Writer<'_>, public: &[u8; 65]) {
    w.map(5)
        .int(1)
        .int(2)
        .int(3)
        .int(ES256)
        .int(-1)
        .int(1)
        .int(-2)
        .bytes(&public[1..33])
        .int(-3)
        .bytes(&public[33..65]);
}

/// `rpIdHash ‖ flags ‖ signCount ‖ aaguid ‖ credIdLen ‖ credId ‖ COSE_Key`.
/// Source: WebAuthn L2 §6.1, §6.5.1 [C]
///
/// The signature counter is **always zero**, which WebAuthn defines as "this
/// authenticator keeps no counter" (§6.1.1): a relying party then skips its clone check
/// rather than failing it. A real counter would have to be a write to the settings flash
/// at every sign-in -- a key derivation and a sealed-file rewrite each time -- and on a
/// seed-derived key it would still not detect a clone, since a restored seed on a second
/// device is exactly a clone that the owner made on purpose.
fn attested_auth_data(
    rp_id_hash: &[u8; 32],
    flags: u8,
    id: &[u8; CRED_ID_LEN],
    public: &[u8; 65],
    out: &mut [u8; AUTH_DATA_MAX],
) -> Option<usize> {
    out[..32].copy_from_slice(rp_id_hash);
    out[32] = flags;
    out[33..37].copy_from_slice(&0u32.to_be_bytes());
    out[37..53].copy_from_slice(&AAGUID);
    out[53..55].copy_from_slice(&(CRED_ID_LEN as u16).to_be_bytes());
    out[55..55 + CRED_ID_LEN].copy_from_slice(id);
    let at = 55 + CRED_ID_LEN;
    let mut w = Writer::new(&mut out[at..]);
    write_cose_es256(&mut w, public);
    let n = w.finish().ok()?;
    debug_assert_eq!(n, COSE_KEY_LEN);
    Some(at + n)
}

struct GetAssertion<'a> {
    rp_id: &'a str,
    client_data_hash: &'a [u8; 32],
    allow: Descriptors<'a>,
    options: Options,
    pin_auth: Option<&'a [u8]>,
    pin_protocol: Option<u64>,
}

fn parse_get_assertion(body: &[u8]) -> R<GetAssertion<'_>> {
    let mut r = Reader::new(body);
    let mut m = c(r.map())?;
    let mut rp_id = None;
    let mut cdh = None;
    let mut ga = GetAssertion {
        rp_id: "",
        client_data_hash: &[0; 32],
        allow: Descriptors::default(),
        options: Options::default(),
        pin_auth: None,
        pin_protocol: None,
    };
    while let Some(k) = c(r.key(&mut m))? {
        match k {
            Key::Int(0x01) => rp_id = Some(c(r.text())?),
            Key::Int(0x02) => cdh = Some(c(r.bytes())?),
            Key::Int(0x03) => ga.allow = Descriptors::read(&mut r, body)?,
            Key::Int(0x04) => {
                if c(r.peek_major())? != cbor::major::MAP {
                    return Err(status::CBOR_UNEXPECTED_TYPE);
                }
                c(r.skip(cbor::MAX_DEPTH - 1))?;
            }
            Key::Int(0x05) => ga.options = options(&mut r)?,
            Key::Int(0x06) => ga.pin_auth = Some(c(r.bytes())?),
            Key::Int(0x07) => ga.pin_protocol = Some(c(r.uint())?),
            _ => c(r.skip(cbor::MAX_DEPTH - 1))?,
        }
    }
    c(r.finish())?;
    let (Some(rp_id), Some(cdh)) = (rp_id, cdh) else {
        return Err(status::MISSING_PARAMETER);
    };
    ga.rp_id = rp_id;
    ga.client_data_hash = hash32(cdh)?;
    Ok(ga)
}

/// Which credential an assertion is made with. One lives on the stack for the length of
/// a request, so the passkey is held by value rather than boxed (there is no allocator).
#[allow(clippy::large_enum_variant)]
enum Chosen<'a> {
    /// From the allow list: its id, and the nonce inside it.
    Listed(&'a [u8], [u8; NONCE_LEN]),
    /// A passkey, and how many the site has.
    Resident(Record, u8),
}

/// §6.2.2. With an allow list, the first credential in it that is this wallet's for this
/// site; without one, this wallet's passkeys for the site, newest first. With `up: false`
/// nobody is asked and the UP flag stays clear; otherwise the person is asked even when
/// nothing matches, and only then told "no credentials", so a host cannot probe which
/// sites a wallet knows without someone pressing the key.
#[inline(never)]
fn get_assertion<'a, E: Env>(
    body: &'a [u8],
    out: &mut [u8],
    s: &mut Session,
    env: &mut E,
    note: &mut Note<'a>,
) -> R<usize> {
    let ga = parse_get_assertion(body)?;
    note.rp_id = Some(ga.rp_id);
    // Step 1.
    if ga.pin_auth.is_some_and(|p| p.is_empty()) {
        return Err(touch_probe(env));
    }
    // Step 2.
    let protocol = match ga.pin_auth {
        Some(_) => Some(pin::check_protocol(ga.pin_protocol)?),
        None => None,
    };
    // Step 4.
    if ga.pin_auth.is_none() && ga.options.uv == Some(true) {
        return Err(status::INVALID_OPTION);
    }
    if ga.options.rk.is_some() {
        return Err(status::UNSUPPORTED_OPTION);
    }
    let up = ga.options.up != Some(false);
    let rp_id_hash: [u8; 32] = Sha256::digest(ga.rp_id.as_bytes());
    let caps = env.caps();
    let now = env.now_ms();

    // Step 6.
    let mut uv = false;
    if let (Some(param), Some(protocol), true) = (ga.pin_auth, protocol, caps.pin_set) {
        check_token(
            s,
            protocol,
            ga.client_data_hash,
            param,
            &rp_id_hash,
            perm::GA,
            now,
        )?;
        uv = true;
    }
    note.uv = uv;
    let cached_up = uv && s.user_present(now);

    // Step 7: the applicable credentials.
    let found: Option<Chosen<'_>> = if !ga.allow.is_empty() {
        env.with_master(|m, kw| {
            let mut hit = None;
            ga.allow.each(|id| {
                hit = m.owns(&rp_id_hash, id, kw).map(|n| (id, n));
                hit.is_some()
            });
            hit
        })
        .ok_or(status::OPERATION_DENIED)?
        .map(|(id, n)| Chosen::Listed(id, n))
    } else if caps.rk {
        let r = env.passkeys(|p| {
            let n = p.count_for(&rp_id_hash);
            let first = p.newest_for(&rp_id_hash, 0).and_then(|i| p.get(i));
            (first.map(|r| (r, n as u8)), false)
        })?;
        note.found = Some(r.as_ref().map_or(0, |(_, n)| *n));
        r.map(|(r, n)| Chosen::Resident(r, n))
    } else {
        None
    };

    // Step 9.
    if up && !cached_up {
        let ask = Ask::SignIn {
            rp_id: ga.rp_id,
            known: found.is_some(),
        };
        match env.presence(ask) {
            Presence::Allowed => {}
            p => return Err(p.refusal()),
        }
    }
    if up {
        s.consume();
    }
    let Some(found) = found else {
        return Err(status::NO_CREDENTIALS);
    };
    let flags = if up { flags::UP } else { 0 } | if uv { flags::UV } else { 0 };
    match found {
        Chosen::Listed(id, nonce) => sign_assertion(
            out,
            env,
            &rp_id_hash,
            ga.client_data_hash,
            flags,
            Signed::Listed(id, &nonce),
        ),
        Chosen::Resident(rec, total) => {
            let n = sign_assertion(
                out,
                env,
                &rp_id_hash,
                ga.client_data_hash,
                flags,
                Signed::Resident {
                    rec: &rec,
                    names: uv && total > 1,
                    total: (total > 1).then_some(total),
                },
            )?;
            // Step 11: more than one, and no account picker on this device -- the
            // platform shows its own, fed by GetNextAssertion.
            if total > 1 {
                s.cursor = Cursor::Assertion {
                    rp: rp_id_hash,
                    cdh: *ga.client_data_hash,
                    next: 1,
                    total,
                    up,
                    uv,
                    since: now,
                };
            }
            Ok(n)
        }
    }
}

/// What an assertion is signed for.
enum Signed<'r> {
    Listed(&'r [u8], &'r [u8; NONCE_LEN]),
    /// A passkey: `names` when user verification was done and there is a choice to make
    /// (§6.2.2 step 11 "User identifiable information ... MUST NOT be returned if user
    /// verification is not done"), `total` for the first of several.
    Resident {
        rec: &'r Record,
        names: bool,
        total: Option<u8>,
    },
}

/// Sign `authData ‖ clientDataHash` and write the response map.
fn sign_assertion<E: Env>(
    out: &mut [u8],
    env: &mut E,
    rp_id_hash: &[u8; 32],
    cdh: &[u8; 32],
    flags: u8,
    what: Signed<'_>,
) -> R<usize> {
    env.with_master(|m, kw| {
        let (nonce, made_id);
        let id: &[u8] = match &what {
            Signed::Listed(id, n) => {
                nonce = **n;
                id
            }
            Signed::Resident { rec, .. } => {
                nonce = rec.nonce;
                made_id = m.credential_id(rp_id_hash, &nonce, kw);
                &made_id
            }
        };
        let key = m.signing_key(rp_id_hash, &nonce, kw).ok_or(status::OTHER)?;
        let mut auth = [0u8; 37];
        auth[..32].copy_from_slice(rp_id_hash);
        auth[32] = flags;
        // signCount 0: see `attested_auth_data`.
        let (r, s) = key.sign(&[&auth, cdh], kw).ok_or(status::OTHER)?;
        let mut sig = [0u8; der::SIG_MAX];
        let sn = der::signature(&r, &s, &mut sig);
        let mut w = Writer::new(out);
        let (user, total) = match &what {
            Signed::Listed(..) => (None, None),
            Signed::Resident { rec, names, total } => (Some((*rec, *names)), *total),
        };
        // {1: {"id", "type"}, 2: authData, 3: signature, 4: user, 5: numberOfCredentials}
        w.map(3 + user.is_some() as usize + total.is_some() as usize)
            .uint(1)
            .map(2)
            .text("id")
            .bytes(id)
            .text("type")
            .text("public-key")
            .uint(2)
            .bytes(&auth)
            .uint(3)
            .bytes(&sig[..sn]);
        if let Some((rec, names)) = user {
            w.uint(4);
            write_user(&mut w, rec, names);
        }
        if let Some(t) = total {
            w.uint(5).uint(t as u64);
        }
        w.finish().map_err(|_| status::OTHER)
    })
    .ok_or(status::OPERATION_DENIED)?
}

/// A PublicKeyCredentialUserEntity: the id, and the names when `names` and they are
/// stored. Keys in canonical order: "id", "name", "displayName".
pub(crate) fn write_user(w: &mut Writer<'_>, rec: &Record, names: bool) {
    let name = (names && !rec.name.is_empty()).then(|| rec.name.as_str());
    let display = (names && !rec.display_name.is_empty()).then(|| rec.display_name.as_str());
    w.map(1 + name.is_some() as usize + display.is_some() as usize)
        .text("id")
        .bytes(rec.user_id.as_bytes());
    if let Some(n) = name {
        w.text("name").text(n);
    }
    if let Some(d) = display {
        w.text("displayName").text(d);
    }
}

/// §6.3 authenticatorGetNextAssertion: the site's next passkey, with the same flags and
/// clientDataHash as the GetAssertion that started it, within 30 s of the last.
#[inline(never)]
fn get_next_assertion<E: Env>(
    out: &mut [u8],
    s: &mut Session,
    env: &mut E,
    note: &mut Note<'_>,
) -> R<usize> {
    let Cursor::Assertion {
        rp,
        cdh,
        next,
        total,
        up,
        uv,
        since,
    } = s.cursor
    else {
        return Err(status::NOT_ALLOWED);
    };
    let now = env.now_ms();
    if next >= total || now.wrapping_sub(since) > pin::NEXT_MS {
        s.cursor = Cursor::None;
        return Err(status::NOT_ALLOWED);
    }
    note.uv = uv;
    let rec = env
        .passkeys(|p| {
            (
                p.newest_for(&rp, next as usize).and_then(|i| p.get(i)),
                false,
            )
        })?
        .ok_or(status::NOT_ALLOWED)?;
    let flags = if up { flags::UP } else { 0 } | if uv { flags::UV } else { 0 };
    let n = sign_assertion(
        out,
        env,
        &rp,
        &cdh,
        flags,
        Signed::Resident {
            rec: &rec,
            names: uv,
            total: None,
        },
    )?;
    s.cursor = Cursor::Assertion {
        rp,
        cdh,
        next: next + 1,
        total,
        up,
        uv,
        since: now,
    };
    Ok(n)
}

/// The nonce inside a credential id of ours, from its public layout alone -- its MAC is
/// for [`Master::owns`] to check.
pub(crate) fn id_nonce(id: &[u8]) -> Option<[u8; NONCE_LEN]> {
    if id.len() != CRED_ID_LEN || id[0] != CRED_VERSION {
        return None;
    }
    id[1..1 + NONCE_LEN].try_into().ok()
}

// Our own ids must never be longer than what a platform is told to send.
const _: () = assert!(CRED_ID_LEN as u64 <= MAX_CRED_ID_LEN);

#[cfg(test)]
pub(crate) mod tests {
    use super::AAGUID;

    /// The AAGUID is a version-4 UUID: version nibble 4, variant bits `10`.
    #[test]
    fn the_aaguid_is_a_version_4_uuid() {
        assert_eq!(AAGUID[6] >> 4, 4, "version nibble");
        assert_eq!(AAGUID[8] >> 6, 0b10, "variant bits");
    }

    use super::*;
    use purecrypto::ec::ecdsa::{EcdsaPublicKey, Signature};

    /// A device with a wallet, a person who always says `answer`, a clock that only moves
    /// when told, a counting DRBG, a PIN and a passkey file in memory.
    pub(crate) struct Fake {
        pub master: Option<Master>,
        pub answer: Presence,
        pub asked: Vec<String>,
        pub counter: u8,
        pub reset_status: u8,
        pub u2f_ok: bool,
        pub now: u32,
        pub rk: bool,
        pub pin: Option<PinRecord>,
        /// Every retries count written, in order.
        pub pin_writes: Vec<u8>,
        pub pin_save_fails: bool,
        pub file: Option<Vec<u8>>,
        pub session: Option<Session>,
        pub notes: Vec<String>,
    }

    impl Fake {
        pub fn new(generation: u32) -> Self {
            Self {
                master: Some(Master::from_parts(
                    &[1; 32],
                    &[2; 32],
                    generation,
                    &KeyWork::host(),
                )),
                answer: Presence::Allowed,
                asked: Vec::new(),
                counter: 0,
                reset_status: status::OK,
                u2f_ok: true,
                now: 1_000,
                rk: true,
                pin: None,
                pin_writes: Vec::new(),
                pin_save_fails: false,
                file: None,
                session: Some(Session::new()),
                notes: Vec::new(),
            }
        }
    }

    impl Env for Fake {
        fn presence(&mut self, ask: Ask<'_>) -> Presence {
            self.asked.push(format!("{ask:?}"));
            self.answer
        }
        fn master_do(&mut self, f: &mut dyn FnMut(&Master, &KeyWork)) -> bool {
            match self.master.as_ref() {
                Some(m) => {
                    f(m, &KeyWork::host());
                    true
                }
                None => false,
            }
        }
        fn random(&mut self, out: &mut [u8]) -> bool {
            self.counter += 1;
            out.fill(self.counter);
            true
        }
        fn reset(&mut self) -> u8 {
            self.reset_status
        }
        fn u2f_presence(&mut self, register: bool, app: &[u8; 32]) -> bool {
            self.asked.push(format!("u2f {register} {:02x}", app[0]));
            self.u2f_ok
        }
        fn masked<T>(&mut self, f: impl FnOnce(&KeyWork) -> T) -> T {
            f(&KeyWork::host())
        }
        fn now_ms(&mut self) -> u32 {
            self.now
        }
        fn caps(&mut self) -> Caps {
            let remaining = self
                .master
                .clone()
                .and_then(|_| self.passkeys(|p| (p.remaining() as u8, false)).ok());
            Caps {
                pin_set: self.pin.is_some(),
                rk: self.rk,
                remaining,
            }
        }
        fn pin(&mut self) -> Option<PinRecord> {
            self.pin.clone()
        }
        fn save_pin(&mut self, rec: &PinRecord) -> bool {
            if self.pin_save_fails {
                return false;
            }
            self.pin_writes.push(rec.retries);
            self.pin = Some(rec.clone());
            true
        }
        fn passkeys_do(&mut self, f: &mut dyn FnMut(&mut Passkeys<'_>) -> bool) -> Result<(), u8> {
            if !self.rk {
                return Err(status::UNSUPPORTED_OPTION);
            }
            let m = self.master.as_ref().ok_or(status::OPERATION_DENIED)?;
            let key = m.passkey_key(&KeyWork::host());
            passkeys::with_vec(&key, &mut self.file, &[self.counter; 16], |p| ((), f(p)))
                .map_err(|_| status::OTHER)
        }
        fn note(&mut self, n: &Note<'_>) {
            self.notes.push(format!("{n:?}"));
        }
    }

    fn cbor(f: impl FnOnce(&mut Writer<'_>)) -> Vec<u8> {
        let mut b = vec![0u8; 2048];
        let mut w = Writer::new(&mut b);
        f(&mut w);
        let n = w.finish().unwrap();
        b.truncate(n);
        b
    }

    /// A MakeCredential request the way a browser sends one.
    pub(crate) fn make_credential_req(
        rp: &str,
        algs: &[i64],
        exclude: &[&[u8]],
        options: Option<(&str, bool)>,
    ) -> Vec<u8> {
        let mut n = 4;
        if !exclude.is_empty() {
            n += 1;
        }
        if options.is_some() {
            n += 1;
        }
        let mut v = vec![command::MAKE_CREDENTIAL];
        v.extend(cbor(|w| {
            w.map(n);
            w.uint(1).bytes(&[0xCD; 32]);
            w.uint(2)
                .map(2)
                .text("id")
                .text(rp)
                .text("name")
                .text("Example");
            w.uint(3)
                .map(3)
                .text("id")
                .bytes(b"user-1")
                .text("name")
                .text("alice@example.com")
                .text("displayName")
                .text("Alice");
            w.uint(4).array(algs.len());
            for &a in algs {
                w.map(2).text("alg").int(a).text("type").text("public-key");
            }
            if !exclude.is_empty() {
                w.uint(5).array(exclude.len());
                for id in exclude {
                    w.map(2)
                        .text("id")
                        .bytes(id)
                        .text("type")
                        .text("public-key");
                }
            }
            if let Some((k, v)) = options {
                w.uint(7).map(1).text(k).bool(v);
            }
        }));
        v
    }

    pub(crate) fn get_assertion_req(rp: &str, allow: &[&[u8]], up: Option<bool>) -> Vec<u8> {
        let mut v = vec![command::GET_ASSERTION];
        let n = 2 + (!allow.is_empty()) as usize + up.is_some() as usize;
        v.extend(cbor(|w| {
            w.map(n);
            w.uint(1).text(rp);
            w.uint(2).bytes(&[0xAB; 32]);
            if !allow.is_empty() {
                w.uint(3).array(allow.len());
                for id in allow {
                    w.map(2)
                        .text("id")
                        .bytes(id)
                        .text("type")
                        .text("public-key");
                }
            }
            if let Some(up) = up {
                w.uint(5).map(1).text("up").bool(up);
            }
        }));
        v
    }

    pub(crate) fn call(env: &mut Fake, req: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; crate::hid::MAX_MSG];
        let mut s = env.session.take().expect("one call at a time");
        let n = handle(req, &mut out, &mut s, env);
        env.session = Some(s);
        out.truncate(n);
        out
    }

    /// Parse a MakeCredential response: (credential id, public key, authData, sig).
    pub(crate) fn registered(resp: &[u8]) -> (Vec<u8>, [u8; 65], Vec<u8>, Vec<u8>) {
        assert_eq!(resp[0], status::OK, "status {:#04x}", resp[0]);
        let mut r = Reader::new(&resp[1..]);
        let mut m = r.map().unwrap();
        assert_eq!(r.key(&mut m).unwrap(), Some(Key::Int(1)));
        assert_eq!(r.text().unwrap(), "packed");
        assert_eq!(r.key(&mut m).unwrap(), Some(Key::Int(2)));
        let auth = r.bytes().unwrap().to_vec();
        assert_eq!(r.key(&mut m).unwrap(), Some(Key::Int(3)));
        let mut st = r.map().unwrap();
        assert_eq!(r.key(&mut st).unwrap(), Some(Key::Text("alg")));
        assert_eq!(r.int().unwrap(), ES256);
        assert_eq!(r.key(&mut st).unwrap(), Some(Key::Text("sig")));
        let sig = r.bytes().unwrap().to_vec();
        assert_eq!(r.key(&mut st).unwrap(), None);
        assert_eq!(r.key(&mut m).unwrap(), None);
        r.finish().unwrap();

        assert_eq!(auth[32] & !flags::UV, flags::UP | flags::AT);
        assert_eq!(&auth[33..37], &[0, 0, 0, 0]);
        assert_eq!(&auth[37..53], &AAGUID);
        let idlen = u16::from_be_bytes([auth[53], auth[54]]) as usize;
        let id = auth[55..55 + idlen].to_vec();
        // The COSE key, read back strictly: canonical order, EC2, ES256, P-256.
        let mut r = Reader::new(&auth[55 + idlen..]);
        let mut k = r.map().unwrap();
        let mut want = [(1i64, 2i64), (3, ES256), (-1, 1)].into_iter();
        let mut public = [0u8; 65];
        public[0] = 4;
        while let Some(Key::Int(label)) = r.key(&mut k).unwrap() {
            match label {
                -2 => public[1..33].copy_from_slice(r.bytes().unwrap()),
                -3 => public[33..].copy_from_slice(r.bytes().unwrap()),
                l => {
                    let (el, ev) = want.next().unwrap();
                    assert_eq!(l, el);
                    assert_eq!(r.int().unwrap(), ev);
                }
            }
        }
        r.finish().unwrap();
        (id, public, auth, sig)
    }

    fn verify(public: &[u8; 65], msg: &[&[u8]], der_sig: &[u8]) -> bool {
        let pk = EcdsaPublicKey::from_sec1(public).unwrap();
        // Minimal DER reader for the test: 30 L 02 Lr r 02 Ls s.
        assert_eq!(der_sig[0], 0x30);
        assert_eq!(der_sig[1] as usize, der_sig.len() - 2);
        let lr = der_sig[3] as usize;
        let r = &der_sig[4..4 + lr];
        let ls = der_sig[5 + lr] as usize;
        let s = &der_sig[6 + lr..6 + lr + ls];
        let pad = |v: &[u8]| {
            let v = if v.len() == 33 { &v[1..] } else { v };
            let mut o = [0u8; 32];
            o[32 - v.len()..].copy_from_slice(v);
            o
        };
        let sig = Signature::from_components(&pad(r), &pad(s));
        let mut all = Vec::new();
        for m in msg {
            all.extend_from_slice(m);
        }
        pk.verify::<Sha256>(&all, &sig).is_ok()
    }

    /// The exact bytes, so a change to what a platform is told is a deliberate one. The
    /// expected encodings are python-fido2 2.2.1's `fido2.cbor.encode` of the same maps
    /// (an independent canonical encoder), and the strict reader accepts ours.
    #[test]
    fn get_info_is_canonical_and_says_what_is_supported() {
        let cases = [
            (
                Caps {
                    pin_set: false,
                    rk: true,
                    remaining: Some(50),
                },
                concat!(
                    "ab0183665532465f5632684649444f5f325f30684649444f5f325f31",
                    "035054a5d3d6f9d64b05bdac7cc541efc8f1",
                    "04a762726bf5627570f564706c6174f468637265644d676d74f5",
                    "69636c69656e7450696ef46e70696e557641757468546f6b656ef5",
                    "706d616b654372656455764e6f74527164f5",
                    "05190400068202010708081840098163757362",
                    "0a81a263616c672664747970656a7075626c69632d6b6579",
                    "0d04141832",
                ),
            ),
            (
                Caps {
                    pin_set: true,
                    rk: false,
                    remaining: Some(50),
                },
                concat!(
                    "aa0183665532465f5632684649444f5f325f30684649444f5f325f31",
                    "035054a5d3d6f9d64b05bdac7cc541efc8f1",
                    "04a662726bf4627570f564706c6174f4",
                    "69636c69656e7450696ef56e70696e557641757468546f6b656ef5",
                    "706d616b654372656455764e6f74527164f5",
                    "05190400068202010708081840098163757362",
                    "0a81a263616c672664747970656a7075626c69632d6b6579",
                    "0d04",
                ),
            ),
        ];
        for (caps, expect) in cases {
            let mut out = [0u8; 512];
            let n = get_info(&mut out, &caps);
            assert_eq!(out[0], 0);
            let mut r = Reader::new(&out[1..n]);
            r.skip(cbor::MAX_DEPTH).unwrap();
            r.finish().unwrap();
            let got: String = out[1..n].iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(got, expect, "{caps:?}");
        }
    }

    #[test]
    fn make_credential_then_get_assertion_round_trip_with_verified_signatures() {
        let mut env = Fake::new(0);
        let resp = call(
            &mut env,
            &make_credential_req("example.com", &[-8, ES256], &[], None),
        );
        let (id, public, auth, sig) = registered(&resp);
        assert_eq!(id.len(), CRED_ID_LEN);
        assert_eq!(&auth[..32], &Sha256::digest(b"example.com"));
        // Packed self-attestation: authData ‖ clientDataHash under the credential key.
        assert!(verify(&public, &[&auth, &[0xCD; 32]], &sig));
        assert_eq!(env.asked.len(), 1);
        assert!(env.asked[0].contains("alice@example.com") && env.asked[0].contains("Alice"));

        // Sign in: an unknown id first, then ours.
        let resp = call(
            &mut env,
            &get_assertion_req("example.com", &[&[9u8; 40], &id], None),
        );
        assert_eq!(resp[0], status::OK);
        let mut r = Reader::new(&resp[1..]);
        let mut m = r.map().unwrap();
        assert_eq!(r.key(&mut m).unwrap(), Some(Key::Int(1)));
        let mut d = r.map().unwrap();
        assert_eq!(r.key(&mut d).unwrap(), Some(Key::Text("id")));
        assert_eq!(r.bytes().unwrap(), &id[..]);
        assert_eq!(r.key(&mut d).unwrap(), Some(Key::Text("type")));
        assert_eq!(r.text().unwrap(), "public-key");
        assert_eq!(r.key(&mut m).unwrap(), Some(Key::Int(2)));
        let a = r.bytes().unwrap().to_vec();
        assert_eq!(r.key(&mut m).unwrap(), Some(Key::Int(3)));
        let s = r.bytes().unwrap().to_vec();
        r.finish().unwrap();
        assert_eq!(a.len(), 37);
        assert_eq!(a[32], flags::UP);
        assert!(verify(&public, &[&a, &[0xAB; 32]], &s));

        // Silent: no question, UP clear, still a valid signature.
        let asked = env.asked.len();
        let resp = call(
            &mut env,
            &get_assertion_req("example.com", &[&id], Some(false)),
        );
        assert_eq!(resp[0], status::OK);
        assert_eq!(env.asked.len(), asked, "up:false asks nobody");
        let mut r = Reader::new(&resp[1..]);
        let mut m = r.map().unwrap();
        r.key(&mut m).unwrap();
        r.skip(4).unwrap();
        r.key(&mut m).unwrap();
        let a = r.bytes().unwrap().to_vec();
        r.key(&mut m).unwrap();
        let s = r.bytes().unwrap().to_vec();
        assert_eq!(a[32], 0);
        assert!(verify(&public, &[&a, &[0xAB; 32]], &s));
    }

    #[test]
    fn another_wallet_or_generation_or_site_does_not_know_the_credential() {
        let mut env = Fake::new(0);
        let (id, ..) = registered(&call(
            &mut env,
            &make_credential_req("example.com", &[ES256], &[], None),
        ));
        // After a reset (generation 1): asked, then no credentials.
        let mut reset = Fake::new(1);
        let resp = call(&mut reset, &get_assertion_req("example.com", &[&id], None));
        assert_eq!(resp, [status::NO_CREDENTIALS]);
        assert_eq!(
            reset.asked.len(),
            1,
            "the person is asked before being told"
        );
        assert!(reset.asked[0].contains("known: false"));
        // Another wallet, silently.
        let mut other = Fake::new(0);
        other.master = Some(Master::from_parts(&[1; 32], &[3; 32], 0, &KeyWork::host()));
        let resp = call(
            &mut other,
            &get_assertion_req("example.com", &[&id], Some(false)),
        );
        assert_eq!(resp, [status::NO_CREDENTIALS]);
        assert!(other.asked.is_empty());
        // Another site.
        let resp = call(
            &mut env,
            &get_assertion_req("example.org", &[&id], Some(false)),
        );
        assert_eq!(resp, [status::NO_CREDENTIALS]);
        // No allow list at all: nothing discoverable.
        let resp = call(
            &mut env,
            &get_assertion_req("example.com", &[], Some(false)),
        );
        assert_eq!(resp, [status::NO_CREDENTIALS]);
    }

    #[test]
    fn the_exclude_list_is_honoured_after_the_person_answers() {
        let mut env = Fake::new(0);
        let (id, ..) = registered(&call(
            &mut env,
            &make_credential_req("example.com", &[ES256], &[], None),
        ));
        let resp = call(
            &mut env,
            &make_credential_req("example.com", &[ES256], &[&[1u8; 16], &id], None),
        );
        assert_eq!(resp, [status::CREDENTIAL_EXCLUDED]);
        assert!(env.asked.last().unwrap().contains("excluded: true"));
        // A refusal is a refusal, whether or not it would have been excluded.
        env.answer = Presence::Denied;
        let resp = call(
            &mut env,
            &make_credential_req("example.com", &[ES256], &[&id], None),
        );
        assert_eq!(resp, [status::OPERATION_DENIED]);
        // The same id excludes nothing at another site.
        env.answer = Presence::Allowed;
        let resp = call(
            &mut env,
            &make_credential_req("example.org", &[ES256], &[&id], None),
        );
        assert_eq!(resp[0], status::OK);
    }

    #[test]
    fn what_is_not_supported_is_refused_by_name_and_before_anyone_is_asked() {
        let mut env = Fake::new(0);
        let cases: &[(Vec<u8>, u8)] = &[
            (
                make_credential_req("a.com", &[-8, -257], &[], None),
                status::UNSUPPORTED_ALGORITHM,
            ),
            (
                make_credential_req("a.com", &[ES256], &[], Some(("uv", true))),
                status::INVALID_OPTION,
            ),
            (
                make_credential_req("a.com", &[ES256], &[], Some(("up", false))),
                status::INVALID_OPTION,
            ),
            (vec![command::CLIENT_PIN, 0xa0], status::MISSING_PARAMETER),
            (vec![command::GET_NEXT_ASSERTION], status::NOT_ALLOWED),
            (vec![0x40], status::INVALID_COMMAND),
            (vec![], status::INVALID_LENGTH),
        ];
        for (req, want) in cases {
            assert_eq!(call(&mut env, req), [*want], "{req:02x?}");
        }
        // rk / uv on GetAssertion.
        let mut req = vec![command::GET_ASSERTION];
        req.extend(cbor(|w| {
            w.map(3).uint(1).text("a.com").uint(2).bytes(&[0; 32]);
            w.uint(5).map(1).text("rk").bool(false);
        }));
        assert_eq!(call(&mut env, &req), [status::UNSUPPORTED_OPTION]);
        assert!(
            env.asked.is_empty(),
            "nothing refused here was put to the person"
        );
        // A board that keeps no passkeys refuses rk, and has no credential management.
        env.rk = false;
        assert_eq!(
            call(
                &mut env,
                &make_credential_req("a.com", &[ES256], &[], Some(("rk", true)))
            ),
            [status::UNSUPPORTED_OPTION]
        );
        assert_eq!(
            call(&mut env, &[command::CREDENTIAL_MANAGEMENT, 0xa0]),
            [status::INVALID_COMMAND]
        );
    }

    #[test]
    fn a_pin_auth_param_without_a_pin_set() {
        let mut env = Fake::new(0);
        let mut req = vec![command::MAKE_CREDENTIAL];
        req.extend(cbor(|w| {
            w.map(5);
            w.uint(1).bytes(&[0; 32]);
            w.uint(2).map(1).text("id").text("a.com");
            w.uint(3).map(1).text("id").bytes(b"u");
            w.uint(4)
                .array(1)
                .map(2)
                .text("alg")
                .int(ES256)
                .text("type")
                .text("public-key");
            w.uint(8).bytes(&[]);
        }));
        // Zero length: the "touch this key" probe, answered after a press.
        assert_eq!(call(&mut env, &req), [status::PIN_NOT_SET]);
        assert_eq!(env.asked, ["Select"]);
        let mut req = vec![command::MAKE_CREDENTIAL];
        req.extend(cbor(|w| {
            w.map(6);
            w.uint(1).bytes(&[0; 32]);
            w.uint(2).map(1).text("id").text("a.com");
            w.uint(3).map(1).text("id").bytes(b"u");
            w.uint(4)
                .array(1)
                .map(2)
                .text("alg")
                .int(ES256)
                .text("type")
                .text("public-key");
            w.uint(8).bytes(&[1; 16]);
            w.uint(9).uint(3);
        }));
        // A protocol this device does not speak.
        assert_eq!(call(&mut env, &req), [status::INVALID_PARAMETER]);
        // With no PIN set there is no token to check (§6.1.2 step 11 does not apply):
        // registered, without the UV flag.
        let last = req.len() - 1;
        req[last] = 1;
        let resp = call(&mut env, &req);
        let (_, _, auth, _) = registered(&resp);
        assert_eq!(auth[32] & flags::UV, 0);
    }

    #[test]
    fn malformed_requests_get_cbor_errors_not_panics() {
        let mut env = Fake::new(0);
        let good = make_credential_req("example.com", &[ES256], &[], None);
        // Every truncation, and every single-byte corruption, of a real request.
        for n in 1..good.len() {
            let r = call(&mut env, &good[..n]);
            assert_ne!(r[0], status::OK, "truncated at {n}");
        }
        for i in 1..good.len() {
            for x in [0x01u8, 0x80, 0xFF] {
                let mut bad = good.clone();
                bad[i] ^= x;
                let _ = call(&mut env, &bad);
            }
        }
        // Missing fields, wrong types, trailing bytes, a non-canonical map.
        let missing = [command::GET_ASSERTION, 0xa1, 0x01, 0x61, b'a'];
        assert_eq!(call(&mut env, &missing), [status::MISSING_PARAMETER]);
        let wrong = [command::GET_ASSERTION, 0xa2, 0x01, 0x01, 0x02, 0x40];
        assert_eq!(call(&mut env, &wrong), [status::CBOR_UNEXPECTED_TYPE]);
        let trailing = [command::GET_ASSERTION, 0xa0, 0x00];
        assert_eq!(call(&mut env, &trailing), [status::INVALID_CBOR]);
        let unordered = [command::GET_ASSERTION, 0xa2, 0x02, 0x40, 0x01, 0x61, b'a'];
        assert_eq!(call(&mut env, &unordered), [status::INVALID_CBOR]);
        let not_a_map = [command::GET_ASSERTION, 0x80];
        assert_eq!(call(&mut env, &not_a_map), [status::CBOR_UNEXPECTED_TYPE]);
        // A client data hash that is not 32 bytes.
        let mut short = vec![command::GET_ASSERTION];
        short.extend(cbor(|w| {
            w.map(2).uint(1).text("a.com").uint(2).bytes(&[0; 31]);
        }));
        assert_eq!(call(&mut env, &short), [status::INVALID_PARAMETER]);
    }

    /// Requests as an independent encoder writes them: python-fido2 2.2.1's
    /// `fido2.cbor.encode`, which sorts keys the CTAP2 canonical way. Accepted by the
    /// strict reader, and answered.
    #[test]
    fn requests_encoded_by_python_fido2_are_accepted() {
        let unhex = |s: &str| -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        };
        let mut env = Fake::new(0);
        let mut mc = vec![command::MAKE_CREDENTIAL];
        mc.extend(unhex(concat!(
            "a5015820010101010101010101010101010101010101010101010101010101010101010102a2",
            "6269646b6578616d706c652e636f6d646e616d65674578616d706c6503a3626964420102646e",
            "616d65636140626b646973706c61794e616d6561410482a263616c672664747970656a707562",
            "6c69632d6b6579a263616c6739010064747970656a7075626c69632d6b657907a162726bf4",
        )));
        let (id, ..) = registered(&call(&mut env, &mc));
        assert!(env.asked[0].contains("a@b"));
        let mut ga = vec![command::GET_ASSERTION];
        ga.extend(unhex(concat!(
            "a4016b6578616d706c652e636f6d025820020202020202020202020202020202020202020202",
            "02020202020202020202020381a2626964582103030303030303030303030303030303030303",
            "030303030303030303030303030364747970656a7075626c69632d6b657905a1627570f4",
        )));
        // A well-formed request for an id that is not ours: parsed, and answered so.
        assert_eq!(call(&mut env, &ga), [status::NO_CREDENTIALS]);
        assert_eq!(id.len(), CRED_ID_LEN);
    }

    #[test]
    fn no_wallet_means_denied_without_asking() {
        let mut env = Fake::new(0);
        let (id, ..) = registered(&call(
            &mut env,
            &make_credential_req("a.com", &[ES256], &[], None),
        ));
        env.master = None;
        env.asked.clear();
        assert_eq!(
            call(&mut env, &get_assertion_req("a.com", &[&id], None)),
            [status::OPERATION_DENIED]
        );
        assert!(env.asked.is_empty());
    }

    #[test]
    fn refusals_map_to_their_statuses() {
        for (p, want) in [
            (Presence::Denied, status::OPERATION_DENIED),
            (Presence::Timeout, status::USER_ACTION_TIMEOUT),
            (Presence::Cancelled, status::KEEPALIVE_CANCEL),
        ] {
            let mut env = Fake::new(0);
            env.answer = p;
            assert_eq!(
                call(&mut env, &make_credential_req("a.com", &[ES256], &[], None)),
                [want]
            );
            assert_eq!(call(&mut env, &[command::SELECTION]), [want]);
        }
        let mut env = Fake::new(0);
        assert_eq!(call(&mut env, &[command::SELECTION]), [status::OK]);
        env.reset_status = status::NOT_ALLOWED;
        assert_eq!(call(&mut env, &[command::RESET]), [status::NOT_ALLOWED]);
        env.reset_status = status::OK;
        assert_eq!(call(&mut env, &[command::RESET]), [status::OK]);
    }
}
