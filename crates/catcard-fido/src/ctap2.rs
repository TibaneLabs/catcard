//! CTAP2: the authenticator API a browser speaks to a FIDO2 security key.
//!
//! A request is one command byte and, for most commands, a CBOR map with integer keys; a
//! response is one status byte and, on success, a CBOR map. What this device answers:
//!
//! | command | here |
//! |---|---|
//! | `authenticatorMakeCredential` (0x01) | ES256 only, non-resident, `packed` self-attestation |
//! | `authenticatorGetAssertion` (0x02) | `allowList` required; `up:false` answered silently |
//! | `authenticatorGetInfo` (0x04) | fixed bytes, [`get_info`] |
//! | `authenticatorClientPIN` (0x06) | `CTAP1_ERR_INVALID_COMMAND`: no PIN protocol |
//! | `authenticatorReset` (0x07) | rotates the wallet's FIDO generation, see [`Env::reset`] |
//! | `authenticatorGetNextAssertion` (0x08) | `CTAP2_ERR_NOT_ALLOWED`: one assertion per request |
//! | `authenticatorSelection` (0x0B) | a press on the device |
//!
//! Source: FIDO CTAP 2.1 (Proposed Standard, 2021-06-15) §6 [C]. Section numbers below
//! are that document's.
//!
//! # What is refused, and with what
//!
//! - an algorithm list without ES256 (`alg` -7): `CTAP2_ERR_UNSUPPORTED_ALGORITHM`;
//! - `rk: true` (a resident key / passkey): `CTAP2_ERR_UNSUPPORTED_OPTION` -- the device
//!   keeps no per-site state, see [`crate::keys`];
//! - `uv: true`: `CTAP2_ERR_INVALID_OPTION` -- there is no built-in user verification
//!   (§6.1.2 step 5; the PIN protected the whole device at login, but CTAP cannot say so);
//! - `up: false` on MakeCredential: `CTAP2_ERR_INVALID_OPTION`;
//! - a `pinUvAuthParam`: `CTAP2_ERR_MISSING_PARAMETER` without a protocol, otherwise
//!   `CTAP1_ERR_INVALID_PARAMETER` -- no protocol is supported (§6.1.2 step 2);
//! - `enterpriseAttestation`: `CTAP1_ERR_INVALID_PARAMETER` (§6.1.2 step 9);
//! - GetAssertion with no `allowList`, or `rk` in its options: there are no discoverable
//!   credentials to find, so `CTAP2_ERR_NO_CREDENTIALS` / `CTAP2_ERR_UNSUPPORTED_OPTION`.
//!
//! Extensions are parsed (strictly) and ignored; none is supported, so none is answered.

use catcard_wallet::KeyWork;
use purecrypto::hash::{Digest, Sha256};

use crate::cbor::{self, Key, Reader, Writer};
use crate::der;
use crate::keys::{CRED_ID_LEN, Master, NONCE_LEN};

/// This device's AAGUID: 16 random bytes generated once (2026-09-27, Python's
/// `secrets.token_hex(16)`) and fixed, so a relying party sees the same model identifier
/// from every CatCard. It identifies the firmware, never the unit or the wallet.
pub const AAGUID: [u8; 16] = [
    0x88, 0x10, 0xd8, 0xde, 0xf3, 0x8f, 0x2b, 0xfd, 0x98, 0x96, 0x58, 0xb6, 0x89, 0x2c, 0xf4, 0x47,
];

/// Command bytes. Source: §6 [C]
pub mod command {
    pub const MAKE_CREDENTIAL: u8 = 0x01;
    pub const GET_ASSERTION: u8 = 0x02;
    pub const GET_INFO: u8 = 0x04;
    pub const CLIENT_PIN: u8 = 0x06;
    pub const RESET: u8 = 0x07;
    pub const GET_NEXT_ASSERTION: u8 = 0x08;
    pub const SELECTION: u8 = 0x0B;
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
    pub const UNSUPPORTED_OPTION: u8 = 0x2B;
    pub const INVALID_OPTION: u8 = 0x2C;
    pub const KEEPALIVE_CANCEL: u8 = 0x2D;
    pub const NO_CREDENTIALS: u8 = 0x2E;
    pub const USER_ACTION_TIMEOUT: u8 = 0x2F;
    pub const NOT_ALLOWED: u8 = 0x30;
    pub const REQUEST_TOO_LARGE: u8 = 0x39;
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
    /// Attested credential data included.
    pub const AT: u8 = 0x40;
}

/// What the device is asked to show a person.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Ask<'a> {
    /// Register with a site. `excluded`: this wallet is already registered there, and
    /// the answer will only be "already registered".
    Register {
        rp_id: &'a str,
        user_name: Option<&'a str>,
        display_name: Option<&'a str>,
        excluded: bool,
    },
    /// Sign in to a site. `known`: one of the offered credentials is this wallet's.
    SignIn { rp_id: &'a str, known: bool },
    /// U2F registration: only a hash of the site is known.
    U2fRegister { app: &'a [u8; 32] },
    /// U2F sign-in.
    U2fSignIn { app: &'a [u8; 32] },
    /// The platform wants the person to pick this authenticator among several.
    Select,
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

/// What the protocol needs from the device around it.
pub trait Env {
    /// Ask the person, and wait (bounded) for the answer.
    fn presence(&mut self, ask: Ask<'_>) -> Presence;
    /// Run `f` with the FIDO master of the wallet in force, inside the masked region.
    /// `None` when there is no wallet to derive one from (logged out, no seed, a WIF key)
    /// or it could not be derived.
    fn with_master<R>(&mut self, f: impl FnOnce(&Master, &KeyWork) -> R) -> Option<R>;
    /// Fill `out` from the device's DRBG. False if it cannot.
    fn random(&mut self, out: &mut [u8]) -> bool;
    /// `authenticatorReset`: within the allowed window, asked twice, then the wallet's
    /// FIDO generation raised. Returns a [`status`] code.
    fn reset(&mut self) -> u8;
    /// U2F user presence for `app`: whether a press has been given for it. The device
    /// asks on its screen when one has not, after the answer has gone back; see
    /// [`crate::u2f`].
    fn u2f_presence(&mut self, register: bool, app: &[u8; 32]) -> bool;
}

/// A request's parse failure as its status.
fn cbor_status(e: cbor::Error) -> u8 {
    match e {
        cbor::Error::Unexpected => status::CBOR_UNEXPECTED_TYPE,
        cbor::Error::Invalid | cbor::Error::TooDeep => status::INVALID_CBOR,
        cbor::Error::Overflow => status::OTHER,
    }
}

type R<T> = Result<T, u8>;

fn c<T>(r: Result<T, cbor::Error>) -> R<T> {
    r.map_err(cbor_status)
}

/// Answer one CTAP2 request (`req` is the command byte and its CBOR). The response --
/// status byte, then CBOR on success -- goes into `out`; returns its length.
///
/// `out` must be at least 512 bytes; [`crate::hid::MAX_MSG`] is plenty.
pub fn handle<E: Env>(req: &[u8], out: &mut [u8], env: &mut E) -> usize {
    let Some((&cmd, body)) = req.split_first() else {
        out[0] = status::INVALID_LENGTH;
        return 1;
    };
    let result = match cmd {
        command::GET_INFO => return get_info(out),
        command::MAKE_CREDENTIAL => make_credential(body, &mut out[1..], env),
        command::GET_ASSERTION => get_assertion(body, &mut out[1..], env),
        command::RESET => match env.reset() {
            status::OK => Ok(0),
            e => Err(e),
        },
        command::SELECTION => match env.presence(Ask::Select) {
            Presence::Allowed => Ok(0),
            p => Err(p.refusal()),
        },
        command::GET_NEXT_ASSERTION => Err(status::NOT_ALLOWED),
        // No PIN protocol, and nothing else this device knows.
        _ => Err(status::INVALID_COMMAND),
    };
    match result {
        Ok(n) => {
            out[0] = status::OK;
            1 + n
        }
        Err(e) => {
            out[0] = e;
            1
        }
    }
}

/// `authenticatorGetInfo`: status byte and the fixed map. Source: §6.4 [C]
pub fn get_info(out: &mut [u8]) -> usize {
    out[0] = status::OK;
    let mut w = Writer::new(&mut out[1..]);
    w.map(8);
    // 0x01 versions
    w.uint(0x01)
        .array(3)
        .text("U2F_V2")
        .text("FIDO_2_0")
        .text("FIDO_2_1");
    // 0x03 aaguid
    w.uint(0x03).bytes(&AAGUID);
    // 0x04 options, canonical order: "rk", "up" (two bytes), then "plat". No "uv" and no
    // "clientPin" key: absent means not supported, which is the truth.
    w.uint(0x04)
        .map(3)
        .text("rk")
        .bool(false)
        .text("up")
        .bool(true)
        .text("plat")
        .bool(false);
    // 0x05 maxMsgSize
    w.uint(0x05).uint(crate::hid::MAX_MSG as u64);
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
fn descriptor<'a>(r: &mut Reader<'a>) -> Result<Option<(&'a [u8], bool)>, cbor::Error> {
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

/// §6.1.2 step 2 / §6.2.2 step 2, for an authenticator with no PIN/UV protocol at all.
fn pin_auth(param: Option<&[u8]>, protocol: Option<u64>) -> R<()> {
    match (param, protocol) {
        (None, _) => Ok(()),
        (Some(_), None) => Err(status::MISSING_PARAMETER),
        (Some(_), Some(_)) => Err(status::INVALID_PARAMETER),
    }
}

fn hash32(b: &[u8]) -> R<&[u8; 32]> {
    b.try_into().map_err(|_| status::INVALID_PARAMETER)
}

struct MakeCredential<'a> {
    client_data_hash: &'a [u8; 32],
    rp_id: &'a str,
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
                // PublicKeyCredentialUserEntity: `id` required, at most 64 bytes.
                // Source: WebAuthn L2 §5.4.3 [C]
                let mut e = c(r.map())?;
                let mut id = None;
                while let Some(k) = c(r.key(&mut e))? {
                    match k {
                        Key::Text("id") => id = Some(c(r.bytes())?),
                        Key::Text("name") => mc.user_name = Some(c(r.text())?),
                        Key::Text("displayName") => mc.display_name = Some(c(r.text())?),
                        Key::Text("icon") => {
                            c(r.text())?;
                        }
                        _ => c(r.skip(cbor::MAX_DEPTH - 2))?,
                    }
                }
                let id = id.ok_or(status::MISSING_PARAMETER)?;
                if id.len() > 64 {
                    return Err(status::INVALID_PARAMETER);
                }
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
fn make_credential<E: Env>(body: &[u8], out: &mut [u8], env: &mut E) -> R<usize> {
    let mc = parse_make_credential(body)?;
    pin_auth(mc.pin_auth, mc.pin_protocol)?;
    if !mc.es256 {
        return Err(status::UNSUPPORTED_ALGORITHM);
    }
    if mc.options.rk == Some(true) {
        return Err(status::UNSUPPORTED_OPTION);
    }
    if mc.options.up == Some(false) || mc.options.uv == Some(true) {
        return Err(status::INVALID_OPTION);
    }
    if mc.enterprise {
        return Err(status::INVALID_PARAMETER);
    }
    let rp_id_hash: [u8; 32] = Sha256::digest(mc.rp_id.as_bytes());

    // §6.1.2 step 11: a credential of ours in the exclude list means this wallet is
    // already registered here. The person still answers -- so a host cannot learn that
    // without them -- and the answer is only ever "excluded".
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
    let ask = Ask::Register {
        rp_id: mc.rp_id,
        user_name: mc.user_name,
        display_name: mc.display_name,
        excluded,
    };
    match env.presence(ask) {
        Presence::Allowed if excluded => return Err(status::CREDENTIAL_EXCLUDED),
        Presence::Allowed => {}
        p => return Err(p.refusal()),
    }

    let mut nonce = [0u8; NONCE_LEN];
    if !env.random(&mut nonce) {
        return Err(status::OTHER);
    }
    let cdh = mc.client_data_hash;
    env.with_master(|m, kw| {
        let id = m.credential_id(&rp_id_hash, &nonce, kw);
        let key = m
            .signing_key(&rp_id_hash, &nonce, kw)
            .ok_or(status::OTHER)?;
        let public = key.public_sec1(kw);
        let mut auth = [0u8; AUTH_DATA_MAX];
        let an = attested_auth_data(&rp_id_hash, &id, &public, &mut auth).ok_or(status::OTHER)?;
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
    .ok_or(status::OPERATION_DENIED)?
}

/// Authenticator data with attested credential data: 37 + 16 + 2 + 33 + 77.
pub const AUTH_DATA_MAX: usize = 37 + 16 + 2 + CRED_ID_LEN + COSE_KEY_LEN;
/// The COSE key below, which is always this long.
const COSE_KEY_LEN: usize = 77;

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
    id: &[u8; CRED_ID_LEN],
    public: &[u8; 65],
    out: &mut [u8; AUTH_DATA_MAX],
) -> Option<usize> {
    out[..32].copy_from_slice(rp_id_hash);
    out[32] = flags::UP | flags::AT;
    out[33..37].copy_from_slice(&0u32.to_be_bytes());
    out[37..53].copy_from_slice(&AAGUID);
    out[53..55].copy_from_slice(&(CRED_ID_LEN as u16).to_be_bytes());
    out[55..55 + CRED_ID_LEN].copy_from_slice(id);
    let at = 55 + CRED_ID_LEN;
    // COSE_Key, EC2, canonical order: 1 (kty), 3 (alg), -1 (crv), -2 (x), -3 (y).
    // Source: RFC 9052 §7, RFC 9053 §7.1.1 [C]
    let mut w = Writer::new(&mut out[at..]);
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

/// §6.2.2. One credential: the first in the allow list that is this wallet's for this
/// site. With `up: false` nobody is asked and the UP flag stays clear; otherwise the
/// person is asked even when nothing matches, and only then told "no credentials", so a
/// host cannot probe which sites a wallet knows without someone pressing the key.
fn get_assertion<E: Env>(body: &[u8], out: &mut [u8], env: &mut E) -> R<usize> {
    let ga = parse_get_assertion(body)?;
    pin_auth(ga.pin_auth, ga.pin_protocol)?;
    if ga.options.rk.is_some() {
        return Err(status::UNSUPPORTED_OPTION);
    }
    if ga.options.uv == Some(true) {
        return Err(status::INVALID_OPTION);
    }
    let up = ga.options.up != Some(false);
    let rp_id_hash: [u8; 32] = Sha256::digest(ga.rp_id.as_bytes());

    // Discoverable credentials are the only way to answer an empty list, and there are
    // none here.
    let found: Option<(&[u8], [u8; NONCE_LEN])> = if ga.allow.is_empty() {
        None
    } else {
        env.with_master(|m, kw| {
            let mut hit = None;
            ga.allow.each(|id| {
                hit = m.owns(&rp_id_hash, id, kw).map(|n| (id, n));
                hit.is_some()
            });
            hit
        })
        .ok_or(status::OPERATION_DENIED)?
    };
    if up {
        let ask = Ask::SignIn {
            rp_id: ga.rp_id,
            known: found.is_some(),
        };
        match env.presence(ask) {
            Presence::Allowed => {}
            p => return Err(p.refusal()),
        }
    }
    let Some((id, nonce)) = found else {
        return Err(status::NO_CREDENTIALS);
    };
    let cdh = ga.client_data_hash;
    env.with_master(|m, kw| {
        let key = m
            .signing_key(&rp_id_hash, &nonce, kw)
            .ok_or(status::OTHER)?;
        let mut auth = [0u8; 37];
        auth[..32].copy_from_slice(&rp_id_hash);
        auth[32] = if up { flags::UP } else { 0 };
        // signCount 0: see `attested_auth_data`.
        let (r, s) = key.sign(&[&auth, cdh], kw).ok_or(status::OTHER)?;
        let mut sig = [0u8; der::SIG_MAX];
        let sn = der::signature(&r, &s, &mut sig);
        let mut w = Writer::new(out);
        // {1: {"id", "type"}, 2: authData, 3: signature}
        w.map(3)
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
        w.finish().map_err(|_| status::OTHER)
    })
    .ok_or(status::OPERATION_DENIED)?
}

// Our own ids must never be longer than what a platform is told to send.
const _: () = assert!(CRED_ID_LEN as u64 <= MAX_CRED_ID_LEN);

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use purecrypto::ec::ecdsa::{EcdsaPublicKey, Signature};

    /// A device with a wallet, a person who always says `answer`, and a clock-free DRBG.
    pub(crate) struct Fake {
        pub master: Option<Master>,
        pub answer: Presence,
        pub asked: Vec<String>,
        pub counter: u8,
        pub reset_status: u8,
        pub u2f_ok: bool,
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
            }
        }
    }

    impl Env for Fake {
        fn presence(&mut self, ask: Ask<'_>) -> Presence {
            self.asked.push(format!("{ask:?}"));
            self.answer
        }
        fn with_master<T>(&mut self, f: impl FnOnce(&Master, &KeyWork) -> T) -> Option<T> {
            let m = self.master.as_ref()?;
            Some(f(m, &KeyWork::host()))
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

    fn call(env: &mut Fake, req: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; crate::hid::MAX_MSG];
        let n = handle(req, &mut out, env);
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

        assert_eq!(auth[32], flags::UP | flags::AT);
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

    #[test]
    fn get_info_is_canonical_and_says_what_is_supported() {
        let mut out = [0u8; 256];
        let n = get_info(&mut out);
        assert_eq!(out[0], 0);
        // Strict reader: canonical order, no duplicates, nothing trailing.
        let mut r = Reader::new(&out[1..n]);
        r.skip(cbor::MAX_DEPTH).unwrap();
        r.finish().unwrap();
        // The exact bytes, so a change to what a platform is told is a deliberate one.
        let expect = concat!(
            "a8",
            "0183665532465f5632684649444f5f325f30684649444f5f325f31",
            "03508810d8def38f2bfd989658b6892cf447",
            "04a362726bf4627570f564706c6174f4",
            "05190400",
            "0708",
            "081840",
            "098163757362",
            "0a81a263616c672664747970656a7075626c69632d6b6579",
        );
        let got: String = out[1..n].iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got, expect);
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
                make_credential_req("a.com", &[ES256], &[], Some(("rk", true))),
                status::UNSUPPORTED_OPTION,
            ),
            (
                make_credential_req("a.com", &[ES256], &[], Some(("uv", true))),
                status::INVALID_OPTION,
            ),
            (
                make_credential_req("a.com", &[ES256], &[], Some(("up", false))),
                status::INVALID_OPTION,
            ),
            (vec![command::CLIENT_PIN, 0xa0], status::INVALID_COMMAND),
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
    }

    #[test]
    fn a_pin_auth_param_with_no_protocol_support() {
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
        assert_eq!(call(&mut env, &req), [status::MISSING_PARAMETER]);
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
            w.uint(9).uint(1);
        }));
        assert_eq!(call(&mut env, &req), [status::INVALID_PARAMETER]);
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
