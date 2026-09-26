//! HSM users: the people whose one-time codes or passwords an HSM policy can require.
//!
//! Stock keeps them in the wallet's settings under `usr`, as
//! `{ username: [auth_mode, base32(secret), last_counter] }`, up to thirty of them.
//! Source: hw-reference/hsm-policy-format.md §2 [C]
//!
//! # Stock's key, because its shape is given
//!
//! Unlike the WIF store or the spending policy, the reference pins this value exactly --
//! the map, the three fields, what each counter means -- so this reads and writes stock's
//! own [`KEY`]. A device that ran stock keeps its users, and users made here carry over.
//!
//! # Three ways to authenticate
//!
//! - **TOTP** (RFC 6238, six digits): the host sends the code and the time slot it was
//!   made for (`totp_time`, Unix seconds / 30). A slot at or before the last one accepted
//!   is a replay.
//! - **HOTP** (RFC 4226, six digits): the next nine counters are accepted, to forgive
//!   codes nobody sent.
//! - **Password** (`USER_AUTH_HMAC`): the device holds a 32-byte key made from the
//!   password by PBKDF2; the host sends HMAC-SHA256 of the PSBT's hash under that key, so
//!   a token is good for one transaction.

use core::fmt::Write as _;

use emjson::JsonWriter;
use emjson::io::SliceWriter;
use purecrypto::ct::ConstantTimeEq;
use purecrypto::hash::{Digest, HmacSha256, Sha256, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::json::{self, Doc};

/// The settings key. Source: hsm-policy-format.md §2.1 [C]
pub const KEY: &str = "usr";
/// Most users. Source: §2.1 `MAX_NUMBER_USERS` [C]
pub const MAX_USERS: usize = 30;
/// Longest username. Source: §2.1 `MAX_USERNAME_LEN` [C]
pub const MAX_USERNAME_LEN: usize = 16;
/// Iterations of PBKDF2-HMAC-SHA512 for a password. Source: §2.2 [C]
pub const PBKDF2_ITER_COUNT: u32 = 2500;

/// `USER_AUTH_*`. Source: §2.2 [C]
pub const AUTH_TOTP: u8 = 1;
pub const AUTH_HOTP: u8 = 2;
pub const AUTH_HMAC: u8 = 3;
/// OR'ed into the mode at creation to ask for the secret as a QR; never stored.
pub const AUTH_SHOW_QR: u8 = 0x80;

/// Bytes of a TOTP/HOTP secret the device picks. Source: §2.2 "always 10 bytes" [C]
pub const PICKED_OTP_LEN: usize = 10;
/// Bytes of a password key. Source: §2.2 [C]
pub const HMAC_KEY_LEN: usize = 32;
/// Longest secret, in bytes.
pub const MAX_SECRET: usize = 32;
/// Its base32 text, padded.
pub const MAX_SECRET_B32: usize = 56;

/// The earliest TOTP slot accepted: when the code was written. Source: §2.3 [C]
pub const TOTP_FLOOR: u32 = 52_622_505;
/// HOTP counters tried past the last one. Source: §2.3 [C]
pub const HOTP_WINDOW: u64 = 9;
/// TOTP slots tried: the one named and the two before it. Source: §2.3 [C]
pub const TOTP_WINDOW: u32 = 3;

/// Shortest and longest token a `user` request may carry. Source: usb-ckcc-protocol.md
/// §4.2 [C]
pub const TOKEN_LEN: (usize, usize) = (6, 32);

/// A stored user: what [`list`] reads. Borrowed from the settings text.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct User<'a> {
    pub name: &'a str,
    pub mode: u8,
    /// The secret, base32.
    pub secret: &'a str,
    pub counter: u64,
}

impl User<'_> {
    /// How the users screen says what kind of user this is.
    pub fn kind(&self) -> &'static str {
        match self.mode {
            AUTH_TOTP => "TOTP (time-based code)",
            AUTH_HOTP => "HOTP (counter-based code)",
            AUTH_HMAC => "password",
            _ => "unknown kind",
        }
    }
}

/// Why a user could not be made, or a list not stored.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Longer than [`MAX_USERNAME_LEN`], shorter than two, or starting with `_`.
    /// Source: §2.1 [C]
    BadName,
    /// A name that cannot be written as a settings key as it stands: a quote, a
    /// backslash or a control character. **Ours**: stock stores whatever it is given.
    NameNotStorable,
    /// Already a user by that name. Source: §2.1 [C]
    Exists,
    /// No user by that name.
    NoSuchUser,
    /// Thirty already.
    TooMany,
    /// Not one of the three modes.
    BadMode,
    /// A secret of the wrong length for its mode. Source: §2.2 [C]
    BadSecret,
    /// The buffer given to [`render`] was too small.
    Overflow,
}

impl Error {
    pub fn text(self) -> &'static str {
        match self {
            Error::BadName => "username must be 2 to 16 characters, not starting with _",
            Error::NameNotStorable => "username has a character this cannot store",
            Error::Exists => "user already exists: delete it on the device first",
            Error::NoSuchUser => "no such user",
            Error::TooMany => "too many users (30)",
            Error::BadMode => "unknown auth mode",
            Error::BadSecret => "secret is the wrong length for that mode",
            Error::Overflow => "too many users to store",
        }
    }
}

/// Check a new username. Source: §2.1 `1 < len <= MAX_USERNAME_LEN`, no leading `_` [C]
pub fn check_name(name: &str) -> Result<(), Error> {
    let n = name.chars().count();
    if !(2..=MAX_USERNAME_LEN).contains(&n) || name.starts_with('_') {
        return Err(Error::BadName);
    }
    if name
        .chars()
        .any(|c| c == '"' || c == '\\' || c.is_control())
    {
        return Err(Error::NameNotStorable);
    }
    Ok(())
}

/// The secret lengths each mode takes. Source: §2.2 [C]
pub fn secret_len_ok(mode: u8, len: usize) -> bool {
    match mode {
        AUTH_TOTP | AUTH_HOTP => len == 10 || len == 20,
        AUTH_HMAC => len == HMAC_KEY_LEN,
        _ => false,
    }
}

/// Read the users out of a settings document. Entries of the wrong shape are skipped.
pub fn list<'a>(doc: &Doc<'a>, out: &mut [User<'a>]) -> usize {
    let Some(raw) = doc.get(KEY) else {
        return 0;
    };
    let Ok(map) = Doc::parse(raw.as_bytes()) else {
        return 0;
    };
    let mut n = 0;
    for e in map.entries() {
        if n == out.len() {
            break;
        }
        let Ok(mut items) = json::elements(e.raw) else {
            continue;
        };
        let (Some(Ok(mode)), Some(Ok(secret)), Some(Ok(counter))) =
            (items.next(), items.next(), items.next())
        else {
            continue;
        };
        let (Ok(mode), Some(secret), Ok(counter)) = (
            mode.parse::<u8>(),
            secret.strip_prefix('"').and_then(|s| s.strip_suffix('"')),
            counter.parse::<u64>(),
        ) else {
            continue;
        };
        out[n] = User {
            name: e.key,
            mode,
            secret,
            counter,
        };
        n += 1;
    }
    n
}

/// Write the users back as the value of [`KEY`].
pub fn render(users: &[User<'_>], out: &mut [u8]) -> Result<usize, Error> {
    let mut w = JsonWriter::new(SliceWriter::new(out));
    let r: Result<(), emjson::io::BufferFull> = (|| {
        w.begin_object()?;
        for u in users {
            w.key(u.name)?;
            w.begin_array()?;
            w.u32(u32::from(u.mode))?;
            w.string(u.secret)?;
            w.u64(u.counter)?;
            w.end_array()?;
        }
        w.end_object()
    })();
    r.map_err(|_| Error::Overflow)?;
    Ok(w.get_ref().written().len())
}

/// `users` with `new` added: refused when the name is taken or the list full.
pub fn with_added<'a>(
    users: &[User<'a>],
    new: User<'a>,
    out: &mut [User<'a>],
) -> Result<usize, Error> {
    check_name(new.name)?;
    if users.iter().any(|u| u.name == new.name) {
        return Err(Error::Exists);
    }
    if users.len() >= MAX_USERS || users.len() >= out.len() {
        return Err(Error::TooMany);
    }
    out[..users.len()].copy_from_slice(users);
    out[users.len()] = new;
    Ok(users.len() + 1)
}

/// `users` without `name`.
pub fn without<'a>(users: &[User<'a>], name: &str, out: &mut [User<'a>]) -> Result<usize, Error> {
    let mut n = 0;
    for u in users.iter().filter(|u| u.name != name) {
        out[n] = *u;
        n += 1;
    }
    if n == users.len() {
        return Err(Error::NoSuchUser);
    }
    Ok(n)
}

/// `users` with `name`'s counter set to `counter`.
pub fn with_counter<'a>(
    users: &[User<'a>],
    name: &str,
    counter: u64,
    out: &mut [User<'a>],
) -> usize {
    for (o, u) in out.iter_mut().zip(users) {
        *o = *u;
        if u.name == name {
            o.counter = counter;
        }
    }
    users.len().min(out.len())
}

// ---------------------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------------------

/// A user's secret in the clear: wiped when dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secret {
    bytes: [u8; MAX_SECRET],
    len: usize,
}

impl Secret {
    pub fn new(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_SECRET {
            return None;
        }
        let mut me = Self {
            bytes: [0; MAX_SECRET],
            len: bytes.len(),
        };
        me.bytes[..bytes.len()].copy_from_slice(bytes);
        Some(me)
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Decoded from its stored base32.
    pub fn from_base32(text: &str) -> Option<Self> {
        let mut b = [0u8; MAX_SECRET + 8];
        let n = crate::notes::base32_decode(text, &mut b)?;
        let me = Self::new(b.get(..n)?);
        b.zeroize();
        me
    }

    /// As stored: base32, RFC 4648 alphabet, padded with `=`. `[I]`: stock's encoder is
    /// named (`ngu.codecs.b32_encode`) but not its padding; the ten- and twenty-byte OTP
    /// secrets need none either way, and this reader ignores `=`.
    pub fn base32(&self) -> heapless::String<MAX_SECRET_B32> {
        base32_encode(self.bytes())
    }
}

/// RFC 4648 base32, padded.
pub fn base32_encode(data: &[u8]) -> heapless::String<MAX_SECRET_B32> {
    const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut s = heapless::String::new();
    for chunk in data.chunks(5) {
        let mut b = [0u8; 5];
        b[..chunk.len()].copy_from_slice(chunk);
        let n = u64::from_be_bytes([0, 0, 0, b[0], b[1], b[2], b[3], b[4]]);
        let chars = (chunk.len() * 8).div_ceil(5);
        for i in 0..8 {
            let c = if i < chars {
                A[((n >> (35 - 5 * i)) & 31) as usize] as char
            } else {
                '='
            };
            let _ = s.push(c);
        }
    }
    s
}

/// The salt for a password: SHA-256 of `pepper` and the device's serial number, as the
/// host computes it from the USB serial string. Source: §2.2 [C]
pub fn password_salt(serial: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"pepper");
    h.update(serial.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// The 32-byte key a password becomes: PBKDF2-HMAC-SHA512, 2500 rounds, first 32 bytes.
/// Source: §2.2 [C]
pub fn password_key(password: &[u8], serial: &str) -> Secret {
    let salt = password_salt(serial);
    let mut out = [0u8; HMAC_KEY_LEN];
    purecrypto::kdf::pbkdf2::<Sha512>(password, &salt, PBKDF2_ITER_COUNT, &mut out);
    let s = Secret::new(&out).unwrap_or(Secret {
        bytes: [0; MAX_SECRET],
        len: 0,
    });
    out.zeroize();
    s
}

/// The enrolment link an authenticator app reads from a QR: the Key URI format.
/// `issuer` is shown by the app beside the code.
pub fn otpauth_uri(
    mode: u8,
    name: &str,
    secret_b32: &str,
    issuer: &str,
    out: &mut heapless::String<200>,
) -> core::fmt::Result {
    out.clear();
    let kind = if mode == AUTH_HOTP { "hotp" } else { "totp" };
    write!(out, "otpauth://{kind}/")?;
    percent(name, out)?;
    write!(out, "?secret={}", secret_b32.trim_end_matches('='))?;
    if mode == AUTH_HOTP {
        // Counter zero is never accepted (see `check`), so the app starts at one.
        out.write_str("&counter=1")?;
    }
    out.write_str("&issuer=")?;
    percent(issuer, out)
}

fn percent(s: &str, out: &mut impl core::fmt::Write) -> core::fmt::Result {
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.write_char(b as char)?;
        } else {
            write!(out, "%{b:02X}")?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Checking a token
// ---------------------------------------------------------------------------------------

/// Why a token was refused: the short words stock sends back. Source: §2.3 [C]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Refused {
    UnknownUser,
    Mismatch,
    ExpectOtp,
    Replay,
    Range,
}

impl Refused {
    pub fn text(self) -> &'static str {
        match self {
            Refused::UnknownUser => "unknown user",
            Refused::Mismatch => "mismatch",
            Refused::ExpectOtp => "expect otp",
            Refused::Replay => "replay",
            Refused::Range => "range",
        }
    }
}

/// `Users.auth_okay`: check `token` for `user`, returning the counter to store on success.
/// `psbt_hash` binds a password token to one transaction; none (a dry run) is 32 zeros.
/// Source: hsm-policy-format.md §2.3 [C]
pub fn check(
    user: &User<'_>,
    token: &[u8],
    totp_time: u32,
    psbt_hash: Option<&[u8; 32]>,
) -> Result<u64, Refused> {
    let secret = Secret::from_base32(user.secret).ok_or(Refused::Mismatch)?;
    match user.mode {
        AUTH_HMAC => {
            let mut mac = HmacSha256::new(secret.bytes());
            mac.update(psbt_hash.unwrap_or(&[0u8; 32]));
            let want = mac.finalize();
            if token.len() == want.len() && bool::from(want[..].ct_eq(token)) {
                // Only "used at least once". Source: §2.3 [C]
                Ok(1)
            } else {
                Err(Refused::Mismatch)
            }
        }
        AUTH_HOTP => {
            let code = otp_digits(token)?;
            // The nine counters past the last one accepted. Counter zero is not tried: a
            // fresh user's counter is zero too, and accepting it would let that first code
            // be sent again. `[I]` -- see docs/USB.md.
            for c in user.counter.saturating_add(1)..=user.counter.saturating_add(HOTP_WINDOW) {
                if six(crate::notes::hotp(secret.bytes(), c, 6))
                    .as_bytes()
                    .ct_eq(code)
                    .into()
                {
                    return Ok(c);
                }
            }
            Err(Refused::Mismatch)
        }
        AUTH_TOTP => {
            let code = otp_digits(token)?;
            if totp_time < TOTP_FLOOR {
                return Err(Refused::Range);
            }
            if u64::from(totp_time) <= user.counter {
                return Err(Refused::Replay);
            }
            for back in 0..TOTP_WINDOW {
                let slot = totp_time - back;
                if u64::from(slot) <= user.counter {
                    break;
                }
                if six(crate::notes::hotp(secret.bytes(), u64::from(slot), 6))
                    .as_bytes()
                    .ct_eq(code)
                    .into()
                {
                    return Ok(u64::from(slot));
                }
            }
            Err(Refused::Mismatch)
        }
        _ => Err(Refused::Mismatch),
    }
}

fn otp_digits(token: &[u8]) -> Result<&[u8], Refused> {
    if token.len() == 6 && token.iter().all(u8::is_ascii_digit) {
        Ok(token)
    } else {
        Err(Refused::ExpectOtp)
    }
}

fn six(code: u32) -> heapless::String<8> {
    let mut s = heapless::String::new();
    let _ = write!(s, "{code:06}");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(s: &str) -> Doc<'_> {
        Doc::parse(s.as_bytes()).unwrap()
    }

    #[test]
    fn stock_shaped_users_read_back_and_round_trip() {
        let text =
            r#"{"usr": {"alice": [1, "JBSWY3DPEHPK3PXP", 52622600], "bob": [3, "AAAA", 0]}}"#;
        let d = doc(text);
        let mut u = [User {
            name: "",
            mode: 0,
            secret: "",
            counter: 0,
        }; MAX_USERS];
        let n = list(&d, &mut u);
        assert_eq!(n, 2);
        assert_eq!(
            u[0],
            User {
                name: "alice",
                mode: 1,
                secret: "JBSWY3DPEHPK3PXP",
                counter: 52622600
            }
        );
        let mut out = [0u8; 256];
        let len = render(&u[..n], &mut out).unwrap();
        let again = Doc::parse(&out[..len]).unwrap();
        assert_eq!(again.len(), 2);
        let wrapped = format!(
            "{{\"usr\": {}}}",
            core::str::from_utf8(&out[..len]).unwrap()
        );
        let mut v = [User {
            name: "",
            mode: 0,
            secret: "",
            counter: 0,
        }; MAX_USERS];
        assert_eq!(list(&doc(&wrapped), &mut v), 2);
        assert_eq!(&v[..2], &u[..2]);
    }

    #[test]
    fn names_follow_stocks_rule() {
        assert_eq!(check_name("a"), Err(Error::BadName));
        assert_eq!(check_name("ab"), Ok(()));
        assert_eq!(check_name("abcdefghijklmnop"), Ok(()));
        assert_eq!(check_name("abcdefghijklmnopq"), Err(Error::BadName));
        assert_eq!(check_name("_ab"), Err(Error::BadName));
        assert_eq!(check_name("a\"b"), Err(Error::NameNotStorable));
    }

    #[test]
    fn a_duplicate_or_a_thirty_first_user_is_refused() {
        let base = User {
            name: "alice",
            mode: 1,
            secret: "AAAA",
            counter: 0,
        };
        let mut out = [base; MAX_USERS];
        assert_eq!(with_added(&[base], base, &mut out), Err(Error::Exists));
        let full = [base; MAX_USERS];
        let new = User {
            name: "zed",
            ..base
        };
        assert_eq!(with_added(&full, new, &mut out), Err(Error::TooMany));
        assert_eq!(with_added(&[base], new, &mut out), Ok(2));
        assert_eq!(without(&out[..2], "alice", &mut [base; 2]), Ok(1));
        assert_eq!(
            without(&[base], "nobody", &mut [base; 1]),
            Err(Error::NoSuchUser)
        );
    }

    #[test]
    fn secret_lengths_per_mode() {
        assert!(secret_len_ok(AUTH_TOTP, 10));
        assert!(secret_len_ok(AUTH_TOTP, 20));
        assert!(!secret_len_ok(AUTH_TOTP, 32));
        assert!(secret_len_ok(AUTH_HMAC, 32));
        assert!(!secret_len_ok(AUTH_HMAC, 10));
        assert!(!secret_len_ok(4, 10));
    }

    #[test]
    fn base32_matches_rfc_4648() {
        // RFC 4648 §10 test vectors.
        assert_eq!(base32_encode(b"").as_str(), "");
        assert_eq!(base32_encode(b"f").as_str(), "MY======");
        assert_eq!(base32_encode(b"fo").as_str(), "MZXQ====");
        assert_eq!(base32_encode(b"foo").as_str(), "MZXW6===");
        assert_eq!(base32_encode(b"foob").as_str(), "MZXW6YQ=");
        assert_eq!(base32_encode(b"fooba").as_str(), "MZXW6YTB");
        assert_eq!(base32_encode(b"foobar").as_str(), "MZXW6YTBOI======");
        let s = Secret::new(b"Hello!\xde\xad\xbe\xef").unwrap();
        assert_eq!(s.base32().as_str(), "JBSWY3DPEHPK3PXP");
        assert_eq!(
            Secret::from_base32("JBSWY3DPEHPK3PXP").unwrap().bytes(),
            b"Hello!\xde\xad\xbe\xef"
        );
    }

    /// The RFC 4226 / RFC 6238 SHA-1 secret, as stored.
    fn rfc_user(counter: u64) -> (heapless::String<MAX_SECRET_B32>, u64) {
        (
            Secret::new(b"12345678901234567890").unwrap().base32(),
            counter,
        )
    }

    #[test]
    fn totp_accepts_the_named_slot_and_two_before_and_refuses_replays() {
        let (b32, _) = rfc_user(0);
        // 2000000000 s -> slot 66666666, RFC 6238: 69279037 -> 279037.
        let slot = 2_000_000_000 / 30;
        let u = User {
            name: "t",
            mode: AUTH_TOTP,
            secret: &b32,
            counter: 0,
        };
        assert_eq!(check(&u, b"279037", slot, None), Ok(u64::from(slot)));
        // The same code named one or two slots later still matches its own slot.
        assert_eq!(check(&u, b"279037", slot + 2, None), Ok(u64::from(slot)));
        assert_eq!(check(&u, b"279037", slot + 3, None), Err(Refused::Mismatch));
        // Once used, that slot and everything before it are replays.
        let used = User {
            counter: u64::from(slot),
            ..u
        };
        assert_eq!(check(&used, b"279037", slot, None), Err(Refused::Replay));
        assert_eq!(
            check(&used, b"279037", slot + 1, None),
            Err(Refused::Mismatch)
        );
        // Below the floor: range.
        let early = User { counter: 0, ..u };
        assert_eq!(check(&early, b"287082", 1, None), Err(Refused::Range));
        assert_eq!(check(&u, b"12345", slot, None), Err(Refused::ExpectOtp));
        assert_eq!(check(&u, b"abcdef", slot, None), Err(Refused::ExpectOtp));
    }

    #[test]
    fn hotp_takes_the_next_nine_counters() {
        // RFC 4226 appendix D: counter 1 -> 287082, 9 -> 520489.
        let (b32, _) = rfc_user(0);
        let u = User {
            name: "h",
            mode: AUTH_HOTP,
            secret: &b32,
            counter: 0,
        };
        assert_eq!(check(&u, b"287082", 0, None), Ok(1));
        assert_eq!(check(&u, b"520489", 0, None), Ok(9));
        // Counter zero (755224) is not accepted: see `check`.
        assert_eq!(check(&u, b"755224", 0, None), Err(Refused::Mismatch));
        let later = User { counter: 1, ..u };
        assert_eq!(check(&later, b"287082", 0, None), Err(Refused::Mismatch));
    }

    #[test]
    fn a_password_token_is_bound_to_the_psbt() {
        let key = password_key(b"hunter2", "F1F1F1F1F1F1");
        let b32 = key.base32();
        let u = User {
            name: "p",
            mode: AUTH_HMAC,
            secret: &b32,
            counter: 0,
        };
        let psbt = [7u8; 32];
        let mut mac = HmacSha256::new(key.bytes());
        mac.update(&psbt);
        let token = mac.finalize();
        assert_eq!(check(&u, &token, 0, Some(&psbt)), Ok(1));
        assert_eq!(
            check(&u, &token, 0, Some(&[8u8; 32])),
            Err(Refused::Mismatch)
        );
        // A dry run binds to 32 zeros.
        assert_eq!(check(&u, &token, 0, None), Err(Refused::Mismatch));
        assert_eq!(check(&u, b"123456", 0, Some(&psbt)), Err(Refused::Mismatch));
    }

    #[test]
    fn password_key_is_pbkdf2_sha512_over_the_peppered_serial() {
        // Independent: Python's hashlib.pbkdf2_hmac('sha512', b'hunter2',
        // sha256(b'pepper' + b'F1F1F1F1F1F1').digest(), 2500)[:32].
        let got = password_key(b"hunter2", "F1F1F1F1F1F1");
        let mut hex = String::new();
        for b in got.bytes() {
            hex.push_str(&format!("{b:02x}"));
        }
        assert_eq!(hex, PBKDF2_VECTOR);
    }

    const PBKDF2_VECTOR: &str = "2cc1ca5cbf0794c9b78fe495768cc6b7be17e00a5864624a963c4db8d1297710";

    #[test]
    fn the_enrolment_link_is_a_key_uri() {
        let mut s = heapless::String::new();
        otpauth_uri(AUTH_TOTP, "a b", "JBSWY3DPEHPK3PXP", "CatCard 0A1B", &mut s).unwrap();
        assert_eq!(
            s.as_str(),
            "otpauth://totp/a%20b?secret=JBSWY3DPEHPK3PXP&issuer=CatCard%200A1B"
        );
        otpauth_uri(AUTH_HOTP, "h", "MZXW6===", "x", &mut s).unwrap();
        assert_eq!(
            s.as_str(),
            "otpauth://hotp/h?secret=MZXW6&counter=1&issuer=x"
        );
    }
}
