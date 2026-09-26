//! HSM mode's policy: what it may hold, what it refuses, how a transaction is judged
//! against it, the velocity clock, the local confirmation code and the status report.
//!
//! Written from `hw-reference/hsm-policy-format.md` (the policy file, the rules and their
//! enforcement) and `usb-ckcc-protocol.md` §4 (the opcodes that carry it). This module is
//! the part a host can test; the firmware's `hsm` module is the screens, the storage and
//! the hand-off to signing.
//!
//! # One text, parsed where it is needed
//!
//! A policy is JSON, validated once by [`Policy::load`] -- every bound, every refusal the
//! reference lists -- and then written back in a canonical form ([`Policy::write`]), which
//! is what is kept on the flash and hashed. The parsed [`Policy`] is a view over that text,
//! a few hundred bytes whatever the lists hold: the whitelists and path lists stay as the
//! JSON they were written as, walked when a request needs them. So a policy with every
//! rule carrying a full whitelist costs its text and not a copy of it.
//!
//! # What this refuses that stock accepts
//!
//! Each is a feature whose shape the reference does not give, refused with a sentence
//! saying so rather than guessed:
//!
//! - **`set_sl` / `allow_sl`** -- the Storage Locker lives in the secure element's long
//!   secret, and neither the read/write selection of gate 18 method 6 nor the stored
//!   encoding (the "2-byte length prefix + padded value") is pinned down.
//! - **`must_log`** -- the microSD audit log's file name and format are not given. This
//!   firmware writes no audit log, so `never_log` is honoured by construction.
//! - **`whitelist_opts.mode = "ATTEST"`** -- where an output's attestation signature is
//!   carried, and what it signs, are not given.
//! - **A `*` path step that is hardened**, and more than [`MAX_RULES`] rules or
//!   [`MAX_PATHS`] paths in a list: our bounds, stated. `*` matches exactly one
//!   unhardened step (the reference names `cleanup_deriv_path(s, allow_star=True)` without
//!   its matching rule), which is never wider than whatever stock's rule is.
//!
//! # The hash is ours
//!
//! Stock hashes `ujson.dumps` of its own canonical dictionary, whose key order and
//! defaults the reference does not give. [`Policy::write`] is our canonical form and
//! [`Policy::hash`] is SHA-256 over it: stable for this firmware, shown on the approval
//! screen and in the status report, but not the number stock would print for the same
//! file. `[I]`

use core::fmt::Write as _;

use emjson::JsonWriter;
use emjson::io::SliceWriter;
use purecrypto::hash::{Digest, HmacSha256, Sha256};

use crate::json::{self, Doc};

// ---------------------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------------------

/// Where stock keeps the policy: `/flash/hsm-policy.json`, the internal-flash volume --
/// whose root is `/flash` in stock and `/` in this firmware's view of the same volume.
/// Source: hsm-policy-format.md §1.1 [C]
pub const POLICY_PATH: &str = "/hsm-policy.json";

/// The largest amount any rule may name: 21 million BTC in satoshis.
/// Source: hsm-policy-format.md §1.4 `MAX_SATS` [C]
pub const MAX_SATS: u64 = 2_100_000_000_000_000;

/// The longest velocity period, in minutes: three days. Source: §1.3 `period` [C]
pub const PERIOD_MAX: u64 = 3 * 24 * 60;

/// `notes`: 1 to 80 characters. Source: §1.3 [C]
pub const NOTES_LEN: (usize, usize) = (1, 80);
/// `boot_to_hsm`: 1 to 6 characters. Source: §1.3 [C]
pub const BOOT_LEN: (usize, usize) = (1, 6);
/// A rule's `wallet`: 1 to 20 characters. Source: §1.4 [C]
pub const WALLET_LEN: (usize, usize) = (1, 20);
/// `allow_sl`: 1 to 100 reads. Source: §1.3 [C]
pub const ALLOW_SL: (u64, u64) = (1, 100);
/// `set_sl`: 16 to 414 characters. Source: §1.3 [C]
pub const SET_SL_LEN: (usize, usize) = (16, 414);
/// `min_pct_self_transfer`: 0 to 100 percent. Source: §1.4 [C]
///
/// Held as millionths of a percent, not as a float: the check is then exact integer
/// arithmetic, and the firmware carries no floating-point parser or formatter (thirty
/// kilobytes of image) for one field.
pub const PCT_MAX: Percent = Percent(100 * PCT_ONE);
/// Millionths in one percent.
pub const PCT_ONE: u64 = 1_000_000;

/// A percentage, in millionths of a percent.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct Percent(pub u64);

impl core::fmt::Display for Percent {
    /// `50`, `99.5`, `0.000001`: the digits there are, no more.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let (whole, frac) = (self.0 / PCT_ONE, self.0 % PCT_ONE);
        if frac == 0 {
            return write!(f, "{whole}");
        }
        let mut digits = [0u8; 6];
        let mut v = frac;
        for d in digits.iter_mut().rev() {
            *d = b'0' + (v % 10) as u8;
            v /= 10;
        }
        let mut end = 6;
        while digits[end - 1] == b'0' {
            end -= 1;
        }
        write!(
            f,
            "{whole}.{}",
            core::str::from_utf8(&digits[..end]).unwrap_or("0")
        )
    }
}

/// Rules one policy may hold. **Ours**: the reference sets no bound, and a policy is held
/// in RAM for as long as HSM mode runs.
pub const MAX_RULES: usize = 16;
/// Paths in one of `msg_paths`, `share_xpubs`, `share_addrs`. **Ours**, as above.
pub const MAX_PATHS: usize = 16;
/// Addresses in one rule's whitelist. Stock's documented bound.
/// Source: hw-reference/firmware-features.md §11 "CCC/HSM address whitelist: up to 25" [C]
pub const MAX_WHITELIST: usize = 25;
/// Longest address kept, in bytes: bech32's ceiling.
pub const MAX_ADDRESS: usize = 90;
/// Deepest path a pattern may name.
pub const MAX_DEPTH: usize = 12;

/// Digits the local operator types. Source: §3.2 `LOCAL_PIN_LENGTH` [C]
pub const LOCAL_PIN_LENGTH: usize = 6;
/// Seconds of uptime during which typing the `boot_to_hsm` code leaves HSM mode.
/// Source: §3.2 `BOOT_LOCKOUT_TIME` [C]
pub const BOOT_LOCKOUT_S: u64 = 60;
/// Refusals after which the device shuts itself down. Source: §3.1
/// `ABSOLUTE_MAX_REFUSALS` [C]
pub const MAX_REFUSALS: u32 = 100;
/// Random bytes behind `next_local_code`. Source: §3.2 [C]
pub const LOCAL_KEY_LEN: usize = 15;
/// `next_local_code` as text: base64 of [`LOCAL_KEY_LEN`] bytes.
pub const LOCAL_KEY_TEXT: usize = 20;

/// The transaction shapes a rule may insist on. Source: §1.4 `TX_PATTERNS` [C]
pub const PATTERNS: [&str; 3] = ["EQ_NUM_INS_OUTS", "EQ_NUM_OWN_INS_OUTS", "EQ_OUT_AMOUNTS"];

/// Longest canonical policy this firmware keeps. Every list at its bound, every rule
/// present, fits with room.
pub const MAX_CANONICAL: usize = 48 * 1024;

// ---------------------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------------------

/// What is wrong with a policy.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Problem {
    /// Not JSON at all.
    NotJson,
    /// JSON, but not an object.
    NotObject,
    /// A key given twice. JSON leaves this undefined; a policy that means two things is
    /// refused rather than read as whichever came last.
    DuplicateKey,
    /// A key the reference does not list. Source: §1.1 `assert_empty_dict` [C]
    UnknownKey,
    NotInteger,
    NotNumber,
    NotBool,
    NotString,
    NotList,
    NotDict,
    /// A number outside its bounds.
    OutOfRange,
    /// A string whose length is outside its bounds.
    BadLength,
    /// `must_log` and `never_log` together. Source: §1.3 "log conflict" [C]
    LogConflict,
    /// A rule with `per_period` and no top-level `period`. Source: §1.3 [C]
    NeedsPeriod,
    /// A user this device does not have. Source: §1.4 "Unknown user" [C]
    UnknownUser,
    /// A user named twice in one rule. Source: §1.4 [C]
    DuplicateUser,
    /// `min_users` outside `1..=len(users)`. Source: §1.4 [C]
    BadMinUsers,
    /// No registered multisig wallet has this name. Source: §1.4 [C]
    UnknownWallet,
    /// More than one registered wallet has this name. Source: §1.4 "must be unique" [C]
    WalletNotUnique,
    /// `whitelist_opts` without a whitelist. Source: §1.4 [C]
    OptsWithoutWhitelist,
    /// A whitelist mode that is neither `BASIC` nor `ATTEST`. Source: §1.4 [C]
    BadMode,
    /// `ATTEST`: see the module documentation.
    AttestNotSupported,
    /// Not one of [`PATTERNS`]. Source: §1.4 [C]
    BadPattern,
    /// Not a derivation path this reads.
    BadPath,
    /// Not an address on this device's network.
    BadAddress,
    /// `set_sl` without `allow_sl >= 1`. Source: §1.3 "need allow_sl>=1" [C]
    NeedAllowSl,
    /// The Storage Locker: see the module documentation.
    StorageLockerNotSupported,
    /// `must_log`: see the module documentation.
    MustLogNotSupported,
    /// More than [`MAX_RULES`].
    TooManyRules,
    /// A list longer than its bound.
    TooManyEntries,
    /// The canonical form would not fit [`MAX_CANONICAL`].
    TooLarge,
}

impl Problem {
    pub fn text(self) -> &'static str {
        match self {
            Problem::NotJson => "not JSON",
            Problem::NotObject => "not a JSON object",
            Problem::DuplicateKey => "given twice",
            Problem::UnknownKey => "unknown key",
            Problem::NotInteger => "must be a whole number",
            Problem::NotNumber => "must be a number",
            Problem::NotBool => "must be true or false",
            Problem::NotString => "must be a string",
            Problem::NotList => "must be a list",
            Problem::NotDict => "must be an object",
            Problem::OutOfRange => "out of range",
            Problem::BadLength => "wrong length",
            Problem::LogConflict => "log conflict",
            Problem::NeedsPeriod => "Needs period to be specified",
            Problem::UnknownUser => "Unknown user",
            Problem::DuplicateUser => "user listed twice",
            Problem::BadMinUsers => "min_users out of range",
            Problem::UnknownWallet => "no multisig wallet by that name",
            Problem::WalletNotUnique => "more than one wallet by that name",
            Problem::OptsWithoutWhitelist => "whitelist_opts needs a whitelist",
            Problem::BadMode => "mode must be BASIC or ATTEST",
            Problem::AttestNotSupported => {
                "ATTEST mode is not supported: its signature format is not specified"
            }
            Problem::BadPattern => "unknown pattern",
            Problem::BadPath => "bad derivation path",
            Problem::BadAddress => "not an address on this network",
            Problem::NeedAllowSl => "need allow_sl>=1",
            Problem::StorageLockerNotSupported => {
                "Storage Locker is not supported on this firmware"
            }
            Problem::MustLogNotSupported => {
                "must_log is not supported: this firmware writes no audit log"
            }
            Problem::TooManyRules => "too many rules",
            Problem::TooManyEntries => "too many entries",
            Problem::TooLarge => "policy too large",
        }
    }
}

/// Why a policy was refused, and where.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Refusal<'a> {
    pub problem: Problem,
    /// The key the problem is in -- or, for an unknown key, the key itself.
    pub key: &'a str,
    /// The rule it is in, counted from 1.
    pub rule: Option<usize>,
}

impl core::fmt::Display for Refusal<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if let Some(r) = self.rule {
            write!(f, "rule {r}: ")?;
        }
        if self.key.is_empty() {
            f.write_str(self.problem.text())
        } else if self.problem == Problem::UnknownKey {
            write!(f, "{}: {}", self.problem.text(), self.key)
        } else {
            write!(f, "{}: {}", self.key, self.problem.text())
        }
    }
}

fn refuse<'a, T>(problem: Problem, key: &'a str, rule: Option<usize>) -> Result<T, Refusal<'a>> {
    Err(Refusal { problem, key, rule })
}

/// What a policy is checked against: this device's users, wallets and network.
pub trait Env {
    /// A user of that name exists ([`crate::hsmusers`]).
    fn user_exists(&self, name: &str) -> bool;
    /// How many registered multisig wallets carry this name.
    fn wallets_named(&self, name: &str) -> usize;
    /// `addr` is an address on this device's network.
    fn address_ok(&self, addr: &str) -> bool;
}

/// The checks already passed: a policy read back from its own canonical text, once it
/// is in force. Users cannot be removed and wallets cannot be registered while HSM mode
/// runs, so what was true at activation still is.
pub struct Trusted;

impl Env for Trusted {
    fn user_exists(&self, _: &str) -> bool {
        true
    }
    fn wallets_named(&self, _: &str) -> usize {
        1
    }
    fn address_ok(&self, _: &str) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------------------
// Reading values the way stock's `pop_*` helpers do
// ---------------------------------------------------------------------------------------

/// An object's keys, each taken once; whatever is left over is an unknown key.
struct Obj<'a> {
    doc: Doc<'a>,
    used: u128,
}

impl<'a> Obj<'a> {
    fn parse(text: &'a str) -> Result<Self, Problem> {
        let doc = Doc::parse(text.as_bytes()).map_err(|_| {
            if text.trim_start().starts_with('{') {
                Problem::NotJson
            } else {
                Problem::NotObject
            }
        })?;
        Ok(Self { doc, used: 0 })
    }

    /// The first key given twice.
    fn duplicate(&self) -> Option<&'a str> {
        let e = self.doc.entries();
        for (i, a) in e.iter().enumerate() {
            if e[..i].iter().any(|b| b.key == a.key) {
                return Some(a.key);
            }
        }
        None
    }

    /// The raw value of `key`, marked as read. JSON `null` reads as absent, as a
    /// `pop(name, None)` would.
    fn take(&mut self, key: &str) -> Option<&'a str> {
        let at = self.doc.entries().iter().position(|e| e.key == key)?;
        self.used |= 1 << at;
        let raw = self.doc.entries()[at].raw;
        (raw != "null").then_some(raw)
    }

    /// A key nobody took.
    fn leftover(&self) -> Option<&'a str> {
        self.doc
            .entries()
            .iter()
            .enumerate()
            .find(|(i, _)| self.used & (1 << i) == 0)
            .map(|(_, e)| e.key)
    }
}

/// `pop_int`: a whole number in `lo..=hi`. Source: §1.2 [C]
fn int(raw: &str, lo: u64, hi: u64) -> Result<u64, Problem> {
    let digits = raw.strip_prefix('-').unwrap_or(raw);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Problem::NotInteger);
    }
    if raw.starts_with('-') {
        // Every bound here starts at zero or above.
        return Err(Problem::OutOfRange);
    }
    let v: u64 = digits.parse().map_err(|_| Problem::OutOfRange)?;
    if v < lo || v > hi {
        return Err(Problem::OutOfRange);
    }
    Ok(v)
}

/// `pop_float`: a number in `0..=hi`, as a [`Percent`]. Source: §1.2 [C]
///
/// A decimal written plainly -- `50`, `99.5`, `0.25` -- with up to six digits after the
/// point; a seventh or later digit rounds the threshold **up**, never down, so a limit
/// is never looser than written. An exponent (`1e1`) is refused as not a number: JSON
/// allows it, and a percentage has no need of it.
fn percent(raw: &str, hi: Percent) -> Result<Percent, Problem> {
    let (neg, body) = match raw.strip_prefix('-') {
        Some(b) => (true, b),
        None => (false, raw),
    };
    let (whole, frac) = match body.split_once('.') {
        Some((w, f)) => (w, Some(f)),
        None => (body, None),
    };
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(whole) || frac.is_some_and(|f| !digits(f)) {
        return Err(Problem::NotNumber);
    }
    // Past the bound, the digits are not needed to know it is out of range.
    let w: u64 = if whole.len() > 4 {
        u64::MAX / 2
    } else {
        whole.parse().map_err(|_| Problem::NotNumber)?
    };
    let mut micro = w.saturating_mul(PCT_ONE);
    if let Some(f) = frac {
        let mut scale = PCT_ONE / 10;
        for (i, b) in f.bytes().enumerate() {
            let d = u64::from(b - b'0');
            if i < 6 {
                micro += d * scale;
                scale /= 10;
            } else if d != 0 {
                micro += 1;
                break;
            }
        }
    }
    if neg && micro != 0 {
        return Err(Problem::OutOfRange);
    }
    if micro > hi.0 {
        return Err(Problem::OutOfRange);
    }
    Ok(Percent(micro))
}

/// `pop_bool`: `true`/`false`, or stock's `1`/`0`. Source: §1.2 [C]
fn boolean(raw: &str) -> Result<bool, Problem> {
    match raw {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(Problem::NotBool),
    }
}

/// Room for any one string this module unescapes: a note of 80 characters at four bytes
/// each, or the longest `set_sl`.
const STR_BUF: usize = 4 * SET_SL_LEN.1;

/// `pop_string`: a string whose length in characters is in `lo..=hi`, unescaped into
/// `buf`. Source: §1.2 [C]
fn string<'b>(raw: &str, (lo, hi): (usize, usize), buf: &'b mut [u8]) -> Result<&'b str, Problem> {
    if !raw.starts_with('"') {
        return Err(Problem::NotString);
    }
    let n = json::unescape(raw, buf).map_err(|_| Problem::BadLength)?;
    let s = core::str::from_utf8(&buf[..n]).map_err(|_| Problem::NotString)?;
    let chars = s.chars().count();
    if chars < lo || chars > hi {
        return Err(Problem::BadLength);
    }
    Ok(s)
}

/// A JSON list's raw text and element count, bounded.
fn list(raw: &str, max: usize) -> Result<usize, Problem> {
    if !raw.starts_with('[') {
        return Err(Problem::NotList);
    }
    let mut n = 0;
    for e in json::elements(raw).map_err(|_| Problem::NotList)? {
        e.map_err(|_| Problem::NotList)?;
        n += 1;
        if n > max {
            return Err(Problem::TooManyEntries);
        }
    }
    Ok(n)
}

/// Walk a list's string items, unescaped, stopping early when `f` says so. Items that
/// are not strings are skipped: the list was validated when it was loaded.
fn each_str(raw: &str, mut f: impl FnMut(&str) -> bool) {
    if raw.is_empty() {
        return;
    }
    let Ok(items) = json::elements(raw) else {
        return;
    };
    let mut buf = [0u8; 4 * MAX_ADDRESS];
    for item in items.flatten() {
        if let Ok(n) = json::unescape(item, &mut buf)
            && let Ok(s) = core::str::from_utf8(&buf[..n])
            && !f(s)
        {
            return;
        }
    }
}

// ---------------------------------------------------------------------------------------
// Derivation-path patterns
// ---------------------------------------------------------------------------------------

/// One step of a path pattern.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Step {
    /// This index exactly (the hardened bit included).
    Is(u32),
    /// Any one unhardened index: `*`.
    Any,
}

const HARD: u32 = 0x8000_0000;

/// Read `m/84h/0h/0h/*` (`'`, `h`, `H` or `p` marking hardened, the leading `m/`
/// optional) into steps. `None` for anything else, including a hardened `*`.
pub fn parse_pattern(s: &str, out: &mut [Step; MAX_DEPTH]) -> Option<usize> {
    let s = s.trim();
    let rest = match s {
        "m" | "M" | "" => return Some(0),
        _ => s
            .strip_prefix("m/")
            .or_else(|| s.strip_prefix("M/"))
            .unwrap_or(s),
    };
    let mut depth = 0;
    for part in rest.split('/') {
        let step = if part == "*" {
            Step::Any
        } else {
            let (num, hard) = match part.strip_suffix(['\'', 'h', 'H', 'p']) {
                Some(n) => (n, true),
                None => (part, false),
            };
            if num == "*" || num.is_empty() || !num.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let v: u32 = num.parse().ok()?;
            if v >= HARD {
                return None;
            }
            Step::Is(if hard { v | HARD } else { v })
        };
        *out.get_mut(depth)? = step;
        depth += 1;
    }
    Some(depth)
}

/// The pattern in this firmware's canonical spelling: `m/84h/0h/0h/*`.
fn write_pattern(steps: &[Step], out: &mut impl core::fmt::Write) -> core::fmt::Result {
    out.write_char('m')?;
    for s in steps {
        match s {
            Step::Any => out.write_str("/*")?,
            Step::Is(v) => {
                write!(out, "/{}", v & !HARD)?;
                if v & HARD != 0 {
                    out.write_char('h')?;
                }
            }
        }
    }
    Ok(())
}

/// Whether `path` is one the pattern names: same depth, every fixed step equal, every `*`
/// an unhardened index.
pub fn pattern_matches(steps: &[Step], path: &[u32]) -> bool {
    steps.len() == path.len()
        && steps.iter().zip(path).all(|(s, p)| match s {
            Step::Is(v) => v == p,
            Step::Any => p & HARD == 0,
        })
}

/// A list of paths as the policy holds it: `msg_paths`, `share_xpubs`, `share_addrs`.
#[derive(Copy, Clone, Debug, Default)]
pub struct Paths<'a> {
    raw: &'a str,
    pub len: usize,
}

impl<'a> Paths<'a> {
    /// `pop_deriv_list`: each item a path pattern, or the literal `any`, or `extra` where
    /// one is allowed (`p2sh` in `share_addrs`). Source: §1.2 [C]
    fn load(raw: &'a str, extra: Option<&str>) -> Result<Self, Problem> {
        let len = list(raw, MAX_PATHS)?;
        let mut bad = None;
        for item in json::elements(raw).map_err(|_| Problem::NotList)?.flatten() {
            let mut buf = [0u8; 4 * MAX_ADDRESS];
            if !item.starts_with('"') {
                bad = Some(Problem::NotString);
                break;
            }
            let s = json::unescape(item, &mut buf)
                .ok()
                .and_then(|n| core::str::from_utf8(&buf[..n]).ok());
            let Some(s) = s else {
                bad = Some(Problem::BadPath);
                break;
            };
            let mut steps = [Step::Any; MAX_DEPTH];
            if s != "any" && Some(s) != extra && parse_pattern(s, &mut steps).is_none() {
                bad = Some(Problem::BadPath);
                break;
            }
        }
        match bad {
            Some(p) => Err(p),
            None => Ok(Self { raw, len }),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether `any` is listed.
    pub fn any(&self) -> bool {
        self.has_literal("any")
    }

    /// Whether this literal (`any`, `p2sh`) is listed.
    pub fn has_literal(&self, word: &str) -> bool {
        let mut found = false;
        each_str(self.raw, |s| {
            found = s == word;
            !found
        });
        found
    }

    /// Whether `path` is covered: by `any`, or by a pattern that matches it.
    pub fn allows(&self, path: &[u32]) -> bool {
        let mut ok = false;
        each_str(self.raw, |s| {
            let mut steps = [Step::Any; MAX_DEPTH];
            ok = s == "any"
                || parse_pattern(s, &mut steps).is_some_and(|n| pattern_matches(&steps[..n], path));
            !ok
        });
        ok
    }

    /// Each entry in canonical spelling.
    pub fn for_each(&self, mut f: impl FnMut(&str)) {
        each_str(self.raw, |s| {
            let mut steps = [Step::Any; MAX_DEPTH];
            match parse_pattern(s, &mut steps) {
                Some(n) if s != "any" && s != "p2sh" => {
                    let mut t: heapless::String<{ 2 + MAX_DEPTH * 12 }> = heapless::String::new();
                    let _ = write_pattern(&steps[..n], &mut t);
                    f(&t);
                }
                _ => f(s),
            }
            true
        });
    }

    fn write(&self, w: &mut JsonWriter<SliceWriter<'_>>) -> Result<(), emjson::io::BufferFull> {
        w.begin_array()?;
        let mut r = Ok(());
        self.for_each(|s| {
            if r.is_ok() {
                r = w.string(s);
            }
        });
        r?;
        w.end_array()
    }
}

// ---------------------------------------------------------------------------------------
// Addresses
// ---------------------------------------------------------------------------------------

/// An address as it is compared: bech32 lower-cased (it is case-insensitive, and every
/// address this firmware renders is lower case), base58 as written.
pub fn normalise_address(addr: &str, out: &mut heapless::String<MAX_ADDRESS>) -> bool {
    out.clear();
    let lower = addr.len() > 3
        && ["bc1", "tb1", "bcrt1"]
            .iter()
            .any(|h| addr.len() >= h.len() && addr[..h.len()].eq_ignore_ascii_case(h));
    for c in addr.chars() {
        let c = if lower { c.to_ascii_lowercase() } else { c };
        if out.push(c).is_err() {
            return false;
        }
    }
    true
}

/// A rule's whitelist.
#[derive(Copy, Clone, Debug, Default)]
pub struct Whitelist<'a> {
    raw: &'a str,
    pub len: usize,
}

impl<'a> Whitelist<'a> {
    fn load(raw: &'a str, env: &dyn Env) -> Result<Self, Problem> {
        let len = list(raw, MAX_WHITELIST)?;
        let mut bad = None;
        for item in json::elements(raw).map_err(|_| Problem::NotList)?.flatten() {
            let mut buf = [0u8; 4 * MAX_ADDRESS];
            let mut norm = heapless::String::new();
            let ok = item.starts_with('"')
                && json::unescape(item, &mut buf)
                    .ok()
                    .and_then(|n| core::str::from_utf8(&buf[..n]).ok())
                    .is_some_and(|s| normalise_address(s, &mut norm) && env.address_ok(&norm));
            if !ok {
                bad = Some(Problem::BadAddress);
                break;
            }
        }
        match bad {
            Some(p) => Err(p),
            None => Ok(Self { raw, len }),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether `addr` is on the list.
    pub fn contains(&self, addr: &str) -> bool {
        let mut want = heapless::String::new();
        if addr.is_empty() || !normalise_address(addr, &mut want) {
            return false;
        }
        let mut found = false;
        each_str(self.raw, |s| {
            let mut have = heapless::String::new();
            found = normalise_address(s, &mut have) && have == want;
            !found
        });
        found
    }

    pub fn for_each(&self, mut f: impl FnMut(&str)) {
        each_str(self.raw, |s| {
            let mut n = heapless::String::new();
            if normalise_address(s, &mut n) {
                f(&n);
            }
            true
        });
    }
}

// ---------------------------------------------------------------------------------------
// The policy
// ---------------------------------------------------------------------------------------

/// Users a rule names.
#[derive(Copy, Clone, Debug, Default)]
pub struct Users<'a> {
    raw: &'a str,
    pub len: usize,
}

impl<'a> Users<'a> {
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn for_each(&self, mut f: impl FnMut(&str)) {
        each_str(self.raw, |s| {
            f(s);
            true
        });
    }

    /// How many of `given` this rule names.
    pub fn count_in(&self, given: &[&str]) -> usize {
        let mut n = 0;
        self.for_each(|u| {
            if given.contains(&u) {
                n += 1;
            }
        });
        n
    }

    pub fn contains(&self, name: &str) -> bool {
        let mut found = false;
        each_str(self.raw, |s| {
            found = s == name;
            !found
        });
        found
    }
}

/// One entry of `rules`. Source: §1.4 [C]
#[derive(Copy, Clone, Debug, Default)]
pub struct Rule<'a> {
    pub per_period: Option<u64>,
    pub max_amount: Option<u64>,
    /// Raw JSON string: `"1"` for single-signer, or a multisig wallet's name.
    wallet: Option<&'a str>,
    pub users: Users<'a>,
    /// Effective: `len(users)` when not given and users are listed. Source: §1.4 [C]
    pub min_users: Option<u32>,
    pub local_conf: bool,
    pub whitelist: Whitelist<'a>,
    /// Only `BASIC` is accepted, so this is the one option left.
    pub allow_zeroval_outs: bool,
    pub min_pct_self_transfer: Option<Percent>,
    /// Bit `i` set: [`PATTERNS`]`[i]` required.
    pub patterns: u8,
}

/// What a rule says about which wallet may spend.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum WalletRule<'b> {
    Any,
    /// `"1"`: single-signer only.
    SingleSigner,
    /// A registered multisig wallet's name.
    Named(&'b str),
}

impl<'a> Rule<'a> {
    /// The wallet this rule is for, unescaped into `buf`.
    pub fn wallet<'b>(&self, buf: &'b mut [u8; 4 * WALLET_LEN.1]) -> WalletRule<'b> {
        let Some(raw) = self.wallet else {
            return WalletRule::Any;
        };
        match string(raw, WALLET_LEN, buf) {
            Ok("1") => WalletRule::SingleSigner,
            Ok(name) => WalletRule::Named(name),
            // Validated at load; unreachable from a loaded policy.
            Err(_) => WalletRule::Named(""),
        }
    }

    fn load(raw: &'a str, index: usize, env: &dyn Env) -> Result<Self, Refusal<'a>> {
        let at = Some(index + 1);
        if !raw.starts_with('{') {
            return refuse(Problem::NotDict, "rules", at);
        }
        let mut o = Obj::parse(raw).map_err(|p| Refusal {
            problem: p,
            key: "rules",
            rule: at,
        })?;
        if let Some(k) = o.duplicate() {
            return refuse(Problem::DuplicateKey, k, at);
        }
        let mut r = Rule::default();
        let e = |p: Problem, k: &'a str| Refusal {
            problem: p,
            key: k,
            rule: at,
        };
        if let Some(v) = o.take("per_period") {
            r.per_period = Some(int(v, 0, MAX_SATS).map_err(|p| e(p, "per_period"))?);
        }
        if let Some(v) = o.take("max_amount") {
            r.max_amount = Some(int(v, 0, MAX_SATS).map_err(|p| e(p, "max_amount"))?);
        }
        if let Some(v) = o.take("wallet") {
            let mut buf = [0u8; 4 * WALLET_LEN.1];
            let name = string(v, WALLET_LEN, &mut buf).map_err(|p| e(p, "wallet"))?;
            if name != "1" {
                match env.wallets_named(name) {
                    0 => return Err(e(Problem::UnknownWallet, "wallet")),
                    1 => {}
                    _ => return Err(e(Problem::WalletNotUnique, "wallet")),
                }
            }
            r.wallet = Some(v);
        }
        if let Some(v) = o.take("users") {
            let n = list(v, crate::hsmusers::MAX_USERS).map_err(|p| e(p, "users"))?;
            let mut seen: heapless::Vec<
                heapless::String<{ 4 * crate::hsmusers::MAX_USERNAME_LEN }>,
                { crate::hsmusers::MAX_USERS },
            > = heapless::Vec::new();
            for item in json::elements(v)
                .map_err(|_| e(Problem::NotList, "users"))?
                .flatten()
            {
                let mut buf = [0u8; 4 * crate::hsmusers::MAX_USERNAME_LEN];
                let name = string(item, (1, crate::hsmusers::MAX_USERNAME_LEN), &mut buf)
                    .map_err(|_| e(Problem::UnknownUser, "users"))?;
                if !env.user_exists(name) {
                    return Err(e(Problem::UnknownUser, "users"));
                }
                if seen.iter().any(|s| s == name) {
                    return Err(e(Problem::DuplicateUser, "users"));
                }
                let mut s = heapless::String::new();
                let _ = s.push_str(name);
                let _ = seen.push(s);
            }
            if n > 0 {
                r.users = Users { raw: v, len: n };
            }
        }
        if let Some(v) = o.take("min_users") {
            let hi = r.users.len as u64;
            if hi == 0 {
                return Err(e(Problem::BadMinUsers, "min_users"));
            }
            r.min_users =
                Some(int(v, 1, hi).map_err(|_| e(Problem::BadMinUsers, "min_users"))? as u32);
        } else if !r.users.is_empty() {
            r.min_users = Some(r.users.len as u32);
        }
        if let Some(v) = o.take("local_conf") {
            r.local_conf = boolean(v).map_err(|p| e(p, "local_conf"))?;
        }
        if let Some(v) = o.take("whitelist") {
            let w = Whitelist::load(v, env).map_err(|p| e(p, "whitelist"))?;
            if !w.is_empty() {
                r.whitelist = w;
            }
        }
        if let Some(v) = o.take("whitelist_opts") {
            if r.whitelist.is_empty() {
                return Err(e(Problem::OptsWithoutWhitelist, "whitelist_opts"));
            }
            if !v.starts_with('{') {
                return Err(e(Problem::NotDict, "whitelist_opts"));
            }
            let mut opts = Obj::parse(v).map_err(|p| e(p, "whitelist_opts"))?;
            if let Some(k) = opts.duplicate() {
                return Err(e(Problem::DuplicateKey, k));
            }
            if let Some(m) = opts.take("mode") {
                let mut buf = [0u8; 32];
                let mode = string(m, (1, 8), &mut buf).map_err(|_| e(Problem::BadMode, "mode"))?;
                if mode.eq_ignore_ascii_case("ATTEST") {
                    return Err(e(Problem::AttestNotSupported, "whitelist_opts"));
                }
                if !mode.eq_ignore_ascii_case("BASIC") {
                    return Err(e(Problem::BadMode, "whitelist_opts"));
                }
            }
            if let Some(z) = opts.take("allow_zeroval_outs") {
                r.allow_zeroval_outs = boolean(z).map_err(|p| e(p, "allow_zeroval_outs"))?;
            }
            if let Some(k) = opts.leftover() {
                return Err(e(Problem::UnknownKey, k));
            }
        }
        if let Some(v) = o.take("min_pct_self_transfer") {
            r.min_pct_self_transfer =
                Some(percent(v, PCT_MAX).map_err(|p| e(p, "min_pct_self_transfer"))?);
        }
        if let Some(v) = o.take("patterns") {
            list(v, PATTERNS.len() * 4).map_err(|p| e(p, "patterns"))?;
            for item in json::elements(v)
                .map_err(|_| e(Problem::NotList, "patterns"))?
                .flatten()
            {
                let mut buf = [0u8; 64];
                let name = string(item, (1, 32), &mut buf)
                    .map_err(|_| e(Problem::BadPattern, "patterns"))?;
                let Some(i) = PATTERNS.iter().position(|p| *p == name) else {
                    return Err(e(Problem::BadPattern, "patterns"));
                };
                r.patterns |= 1 << i;
            }
        }
        if let Some(k) = o.leftover() {
            return Err(e(Problem::UnknownKey, k));
        }
        Ok(r)
    }

    fn write(&self, w: &mut JsonWriter<SliceWriter<'_>>) -> Result<(), emjson::io::BufferFull> {
        w.begin_object()?;
        if let Some(v) = self.per_period {
            w.member("per_period", &v)?;
        }
        if let Some(v) = self.max_amount {
            w.member("max_amount", &v)?;
        }
        let mut buf = [0u8; 4 * WALLET_LEN.1];
        match self.wallet(&mut buf) {
            WalletRule::Any => {}
            WalletRule::SingleSigner => w.member("wallet", "1")?,
            WalletRule::Named(n) => w.member("wallet", n)?,
        }
        if !self.users.is_empty() {
            w.key("users")?;
            w.begin_array()?;
            let mut r = Ok(());
            self.users.for_each(|u| {
                if r.is_ok() {
                    r = w.string(u);
                }
            });
            r?;
            w.end_array()?;
        }
        if let Some(m) = self.min_users {
            w.member("min_users", &m)?;
        }
        if self.local_conf {
            w.member("local_conf", &true)?;
        }
        if !self.whitelist.is_empty() {
            w.key("whitelist")?;
            w.begin_array()?;
            let mut r = Ok(());
            self.whitelist.for_each(|a| {
                if r.is_ok() {
                    r = w.string(a);
                }
            });
            r?;
            w.end_array()?;
            w.key("whitelist_opts")?;
            w.begin_object()?;
            w.member("mode", "BASIC")?;
            w.member("allow_zeroval_outs", &self.allow_zeroval_outs)?;
            w.end_object()?;
        }
        if let Some(p) = self.min_pct_self_transfer {
            let mut t: heapless::String<16> = heapless::String::new();
            let _ = write!(t, "{p}");
            w.key("min_pct_self_transfer")?;
            w.raw(&t)?;
        }
        if self.patterns != 0 {
            w.key("patterns")?;
            w.begin_array()?;
            for (i, p) in PATTERNS.iter().enumerate() {
                if self.patterns & (1 << i) != 0 {
                    w.string(p)?;
                }
            }
            w.end_array()?;
        }
        w.end_object()
    }

    /// One line for the approval screen: what this rule lets through.
    pub fn describe(&self, out: &mut impl core::fmt::Write) -> core::fmt::Result {
        let mut buf = [0u8; 4 * WALLET_LEN.1];
        match self.wallet(&mut buf) {
            WalletRule::Any => out.write_str("Any wallet")?,
            WalletRule::SingleSigner => out.write_str("Single-signer wallet only")?,
            WalletRule::Named(n) => write!(out, "Multisig wallet \"{n}\" only")?,
        }
        match self.max_amount {
            Some(v) => {
                out.write_str(", up to ")?;
                write_btc(v, out)?;
                out.write_str(" per transaction")?;
            }
            None => out.write_str(", any amount")?,
        }
        if let Some(v) = self.per_period {
            out.write_str(", at most ")?;
            write_btc(v, out)?;
            out.write_str(" per period")?;
        }
        if !self.whitelist.is_empty() {
            write!(out, ", only to these {} address(es):", self.whitelist.len)?;
            let mut r = Ok(());
            self.whitelist.for_each(|a| {
                if r.is_ok() {
                    r = write!(out, " {a}");
                }
            });
            r?;
            if self.allow_zeroval_outs {
                out.write_str(" (zero-value outputs allowed)")?;
            }
        }
        if !self.users.is_empty() {
            write!(out, ", needs {} of:", self.min_users.unwrap_or(0))?;
            let mut r = Ok(());
            self.users.for_each(|u| {
                if r.is_ok() {
                    r = write!(out, " {u}");
                }
            });
            r?;
        }
        if self.local_conf {
            out.write_str(", needs the local code typed here")?;
        }
        if let Some(p) = self.min_pct_self_transfer {
            write!(out, ", at least {p}% back to this wallet")?;
        }
        for (i, p) in PATTERNS.iter().enumerate() {
            if self.patterns & (1 << i) != 0 {
                write!(out, ", {p}")?;
            }
        }
        out.write_char('.')
    }
}

/// Satoshis as BTC, every digit kept: `0.00250000 BTC`.
pub fn write_btc(sats: u64, out: &mut impl core::fmt::Write) -> core::fmt::Result {
    write!(out, "{}.{:08} BTC", sats / 100_000_000, sats % 100_000_000)
}

/// A policy, validated. A view over the text it was loaded from.
#[derive(Clone, Debug, Default)]
pub struct Policy<'a> {
    pub rules: heapless::Vec<Rule<'a>, MAX_RULES>,
    /// Minutes. Source: §1.3 [C]
    pub period: Option<u64>,
    pub never_log: bool,
    pub priv_over_ux: bool,
    pub warnings_ok: bool,
    pub msg_paths: Paths<'a>,
    pub share_xpubs: Paths<'a>,
    pub share_addrs: Paths<'a>,
    /// Raw JSON string.
    notes: Option<&'a str>,
    /// Raw JSON string.
    boot_to_hsm: Option<&'a str>,
}

impl<'a> Policy<'a> {
    /// `HSMPolicy.load`: every key read, every bound checked, anything unknown refused.
    /// Source: hsm-policy-format.md §1 [C]
    pub fn load(text: &'a str, env: &dyn Env) -> Result<Self, Refusal<'a>> {
        let mut o = Obj::parse(text).map_err(|p| Refusal {
            problem: p,
            key: "",
            rule: None,
        })?;
        if let Some(k) = o.duplicate() {
            return refuse(Problem::DuplicateKey, k, None);
        }
        let e = |p: Problem, k: &'a str| Refusal {
            problem: p,
            key: k,
            rule: None,
        };
        let mut me = Policy::default();

        if let Some(v) = o.take("rules") {
            let n = list(v, MAX_RULES).map_err(|p| match p {
                Problem::TooManyEntries => e(Problem::TooManyRules, "rules"),
                p => e(p, "rules"),
            })?;
            let _ = n;
            for (i, item) in json::elements(v)
                .map_err(|_| e(Problem::NotList, "rules"))?
                .enumerate()
            {
                let item = item.map_err(|_| e(Problem::NotList, "rules"))?;
                let r = Rule::load(item, i, env)?;
                me.rules
                    .push(r)
                    .map_err(|_| e(Problem::TooManyRules, "rules"))?;
            }
        }
        if let Some(v) = o.take("period") {
            me.period = Some(int(v, 1, PERIOD_MAX).map_err(|p| e(p, "period"))?);
        }
        let must_log = match o.take("must_log") {
            Some(v) => boolean(v).map_err(|p| e(p, "must_log"))?,
            None => false,
        };
        if let Some(v) = o.take("never_log") {
            me.never_log = boolean(v).map_err(|p| e(p, "never_log"))?;
        }
        if must_log && me.never_log {
            return Err(e(Problem::LogConflict, ""));
        }
        if must_log {
            return Err(e(Problem::MustLogNotSupported, ""));
        }
        if let Some(v) = o.take("priv_over_ux") {
            me.priv_over_ux = boolean(v).map_err(|p| e(p, "priv_over_ux"))?;
        }
        if let Some(v) = o.take("warnings_ok") {
            me.warnings_ok = boolean(v).map_err(|p| e(p, "warnings_ok"))?;
        }
        if let Some(v) = o.take("msg_paths") {
            me.msg_paths = Paths::load(v, None).map_err(|p| e(p, "msg_paths"))?;
        }
        if let Some(v) = o.take("share_xpubs") {
            me.share_xpubs = Paths::load(v, None).map_err(|p| e(p, "share_xpubs"))?;
        }
        if let Some(v) = o.take("share_addrs") {
            me.share_addrs = Paths::load(v, Some("p2sh")).map_err(|p| e(p, "share_addrs"))?;
        }
        let mut buf = [0u8; STR_BUF];
        if let Some(v) = o.take("notes") {
            string(v, NOTES_LEN, &mut buf).map_err(|p| e(p, "notes"))?;
            me.notes = Some(v);
        }
        if let Some(v) = o.take("boot_to_hsm") {
            string(v, BOOT_LEN, &mut buf).map_err(|p| e(p, "boot_to_hsm"))?;
            me.boot_to_hsm = Some(v);
        }
        let allow_sl = match o.take("allow_sl") {
            Some(v) => Some(int(v, ALLOW_SL.0, ALLOW_SL.1).map_err(|p| e(p, "allow_sl"))?),
            None => None,
        };
        if let Some(v) = o.take("set_sl") {
            string(v, SET_SL_LEN, &mut buf).map_err(|p| e(p, "set_sl"))?;
            if allow_sl.is_none() {
                return Err(e(Problem::NeedAllowSl, "set_sl"));
            }
        }
        if allow_sl.is_some() {
            return Err(e(Problem::StorageLockerNotSupported, "allow_sl"));
        }
        if let Some(k) = o.leftover() {
            return Err(e(Problem::UnknownKey, k));
        }
        if me.period.is_none()
            && let Some(i) = me.rules.iter().position(|r| r.per_period.is_some())
        {
            return refuse(Problem::NeedsPeriod, "period", Some(i + 1));
        }
        Ok(me)
    }

    /// The `notes` text, unescaped into `buf`.
    pub fn notes<'b>(&self, buf: &'b mut [u8; STR_BUF]) -> Option<&'b str> {
        string(self.notes?, NOTES_LEN, buf).ok()
    }

    /// The `boot_to_hsm` code, unescaped into `buf`.
    pub fn boot_to_hsm<'b>(&self, buf: &'b mut [u8; 4 * BOOT_LEN.1]) -> Option<&'b str> {
        string(self.boot_to_hsm?, BOOT_LEN, buf).ok()
    }

    /// Whether the policy boots straight into HSM mode.
    pub fn boots_to_hsm(&self) -> bool {
        self.boot_to_hsm.is_some()
    }

    /// Whether the `boot_to_hsm` code can be typed as the six-digit escape at all. One that
    /// cannot leaves no way out of HSM mode on this device. Source: §3.2 [C]
    pub fn boot_code_typeable(&self) -> bool {
        let mut buf = [0u8; 4 * BOOT_LEN.1];
        self.boot_to_hsm(&mut buf)
            .is_some_and(|c| c.len() == LOCAL_PIN_LENGTH && c.bytes().all(|b| b.is_ascii_digit()))
    }

    /// Whether any rule wants the local operator's code. Source: §3.5 [C]
    pub fn uses_local_conf(&self) -> bool {
        self.rules.iter().any(|r| r.local_conf)
    }

    /// Whether any rule has a velocity limit.
    pub fn uses_velocity(&self) -> bool {
        self.rules.iter().any(|r| r.per_period.is_some())
    }

    /// The canonical form: what is stored and hashed. Keys in the reference's order,
    /// defaults left out, paths and addresses in one spelling each.
    pub fn write(&self, out: &mut [u8]) -> Result<usize, Problem> {
        let mut w = JsonWriter::new(SliceWriter::new(out));
        self.write_into(&mut w).map_err(|_| Problem::TooLarge)?;
        Ok(w.get_ref().written().len())
    }

    fn write_into(
        &self,
        w: &mut JsonWriter<SliceWriter<'_>>,
    ) -> Result<(), emjson::io::BufferFull> {
        w.begin_object()?;
        w.key("rules")?;
        w.begin_array()?;
        for r in &self.rules {
            r.write(w)?;
        }
        w.end_array()?;
        if let Some(p) = self.period {
            w.member("period", &p)?;
        }
        if self.never_log {
            w.member("never_log", &true)?;
        }
        if self.priv_over_ux {
            w.member("priv_over_ux", &true)?;
        }
        if self.warnings_ok {
            w.member("warnings_ok", &true)?;
        }
        for (key, list) in [
            ("msg_paths", &self.msg_paths),
            ("share_xpubs", &self.share_xpubs),
            ("share_addrs", &self.share_addrs),
        ] {
            if !list.is_empty() {
                w.key(key)?;
                list.write(w)?;
            }
        }
        let mut buf = [0u8; STR_BUF];
        if let Some(n) = self.notes(&mut buf) {
            w.member("notes", n)?;
        }
        let mut code = [0u8; 4 * BOOT_LEN.1];
        if let Some(c) = self.boot_to_hsm(&mut code) {
            w.member("boot_to_hsm", c)?;
        }
        w.end_object()
    }

    /// SHA-256 over the canonical text, as hex. See the module documentation for why this
    /// is not stock's number.
    pub fn hash(canonical: &[u8]) -> heapless::String<64> {
        let d = Sha256::digest(canonical);
        let mut s = heapless::String::new();
        for b in d.iter() {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// The plain-language account the approval screen shows, one paragraph per line.
    /// Source: help-and-warning-screens.md §13 "Review & enable" [C]
    pub fn explain(&self, out: &mut impl core::fmt::Write) -> core::fmt::Result {
        let mut buf = [0u8; STR_BUF];
        if let Some(n) = self.notes(&mut buf) {
            writeln!(out, "{n}")?;
        }
        if self.rules.is_empty() {
            writeln!(out, "No rules: no transaction will ever be signed.")?;
        } else {
            writeln!(
                out,
                "Transactions are signed WITHOUT asking anyone here when a rule allows them. Rules are tried in order:"
            )?;
            for (i, r) in self.rules.iter().enumerate() {
                write!(out, "Rule {}: ", i + 1)?;
                r.describe(out)?;
                writeln!(out)?;
            }
        }
        if let Some(p) = self.period {
            writeln!(
                out,
                "Velocity period: {p} minutes, counted from the first spend."
            )?;
        }
        if self.msg_paths.is_empty() {
            writeln!(out, "Message signing: not allowed.")?;
        } else {
            write!(out, "Messages signed without asking, for:")?;
            let mut r = Ok(());
            self.msg_paths.for_each(|p| {
                if r.is_ok() {
                    r = write!(out, " {p}");
                }
            });
            r?;
            writeln!(out)?;
        }
        write!(out, "XPUBs shared: m")?;
        let mut r = Ok(());
        self.share_xpubs.for_each(|p| {
            if r.is_ok() {
                r = write!(out, " {p}");
            }
        });
        r?;
        writeln!(out)?;
        if self.share_addrs.is_empty() {
            writeln!(out, "Addresses shown: none.")?;
        } else {
            write!(out, "Addresses shown for:")?;
            let mut r = Ok(());
            self.share_addrs.for_each(|p| {
                if r.is_ok() {
                    r = write!(out, " {p}");
                }
            });
            r?;
            writeln!(out)?;
        }
        writeln!(
            out,
            "{}",
            if self.warnings_ok {
                "Transactions with warnings are signed anyway."
            } else {
                "Transactions with any warning are refused."
            }
        )?;
        writeln!(out, "No audit log is written.")?;
        if self.priv_over_ux {
            writeln!(out, "Privacy over UX: the status report says less.")?;
        }
        if self.boots_to_hsm() {
            writeln!(
                out,
                "BOOT TO HSM: after every login this device goes straight into HSM mode, with no menus."
            )?;
            if self.boot_code_typeable() {
                writeln!(
                    out,
                    "The only way out is typing the boot code here within 60 seconds of power-on."
                )?;
            } else {
                writeln!(
                    out,
                    "IRREVERSIBLE: the boot code is not 6 digits, so it can never be typed. This device could NEVER leave HSM mode again."
                )?;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------
// Judging a transaction
// ---------------------------------------------------------------------------------------

/// Which wallet a transaction spends from, as the review worked it out.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Spender<'a> {
    /// Single-signer inputs only.
    Single,
    /// One registered multisig wallet only.
    Multi(&'a str),
    /// A mix, or a multisig wallet with no name: only a rule for any wallet matches.
    Other,
}

/// What the review found, for the rules.
#[derive(Copy, Clone, Debug)]
pub struct Facts<'a> {
    pub inputs: usize,
    pub outputs: usize,
    pub own_inputs: usize,
    /// Outputs proven to come back to this wallet.
    pub own_outputs: usize,
    /// Value of our inputs.
    pub own_in: u64,
    /// Value of the outputs back to us.
    pub own_out: u64,
    /// Value of the outputs to anyone else: `total_out` in the reference.
    pub sending: u64,
    pub spender: Spender<'a>,
    /// Users whose authentication checked out.
    pub users: &'a [&'a str],
    /// The local operator typed the right code for this transaction.
    pub local_ok: bool,
}

/// Per-rule state gathered while the outputs go past.
#[derive(Copy, Clone, Default)]
struct Seen {
    off_whitelist: bool,
}

/// A transaction being judged: outputs are fed in, then [`Judge::verdict`].
pub struct Judge<'p, 'a> {
    policy: &'p Policy<'a>,
    seen: [Seen; MAX_RULES],
    first_amount: Option<u64>,
    equal_amounts: bool,
}

/// Why no rule allowed it: one reason per rule, as a sentence.
pub type Reasons = heapless::String<200>;

impl<'p, 'a> Judge<'p, 'a> {
    pub fn new(policy: &'p Policy<'a>) -> Self {
        Self {
            policy,
            seen: [Seen::default(); MAX_RULES],
            first_amount: None,
            equal_amounts: true,
        }
    }

    /// One output: its value, whether it is proven change, and its address (empty for a
    /// script with none).
    pub fn output(&mut self, amount: u64, change: bool, address: &str) {
        match self.first_amount {
            None => self.first_amount = Some(amount),
            Some(a) if a != amount => self.equal_amounts = false,
            Some(_) => {}
        }
        if change {
            return;
        }
        for (r, seen) in self.policy.rules.iter().zip(self.seen.iter_mut()) {
            if r.whitelist.is_empty() || seen.off_whitelist {
                continue;
            }
            if amount == 0 && r.allow_zeroval_outs {
                continue;
            }
            if !r.whitelist.contains(address) {
                seen.off_whitelist = true;
            }
        }
    }

    /// The first rule that allows the transaction, and its spend recorded; or `None`, with
    /// every rule's reason for refusing in `why`. Warnings and the users' own checks come before this and are
    /// the caller's. Source: §3.1 steps 3-6, §1.4 [C]
    pub fn verdict(
        &self,
        facts: &Facts<'_>,
        rt: &mut Runtime,
        now: u64,
        why: &mut Reasons,
    ) -> Option<usize> {
        why.clear();
        if self.policy.rules.is_empty() {
            let _ = why.push_str("no txn signing allowed");
            return None;
        }
        rt.time_left(self.policy.period, now);
        for (i, r) in self.policy.rules.iter().enumerate() {
            match self.rule_refuses(i, r, facts, rt) {
                None => {
                    if r.per_period.is_some() {
                        rt.record_spend(i, facts.sending, now);
                    }
                    return Some(i);
                }
                Some(reason) => {
                    if !why.is_empty() {
                        let _ = why.push_str("; ");
                    }
                    let _ = write!(why, "rule {}: {}", i + 1, reason);
                }
            }
        }
        None
    }

    fn rule_refuses(
        &self,
        i: usize,
        r: &Rule<'_>,
        f: &Facts<'_>,
        rt: &Runtime,
    ) -> Option<&'static str> {
        let mut buf = [0u8; 4 * WALLET_LEN.1];
        match (r.wallet(&mut buf), f.spender) {
            (WalletRule::Any, _) => {}
            (WalletRule::SingleSigner, Spender::Single) => {}
            (WalletRule::SingleSigner, _) => return Some("not a single-signer spend"),
            (WalletRule::Named(n), Spender::Multi(m)) if n == m => {}
            (WalletRule::Named(_), _) => return Some("wrong wallet"),
        }
        if let Some(max) = r.max_amount
            && f.sending > max
        {
            return Some("amount exceeds max_amount");
        }
        if let Some(limit) = r.per_period
            && rt.spent[i].saturating_add(f.sending) > limit
        {
            return Some("would exceed the velocity limit");
        }
        if !r.whitelist.is_empty() && self.seen[i].off_whitelist {
            return Some("an output is not whitelisted");
        }
        if let Some(pct) = r.min_pct_self_transfer {
            if f.own_in == 0 {
                return Some("nothing of ours spent");
            }
            // own_out / own_in * 100 >= pct, exactly: both sides in millionths.
            let back = u128::from(f.own_out) * 100 * u128::from(PCT_ONE);
            if back < u128::from(pct.0) * u128::from(f.own_in) {
                return Some("too little comes back to this wallet");
            }
        }
        if r.patterns & 1 != 0 && f.inputs != f.outputs {
            return Some("EQ_NUM_INS_OUTS not met");
        }
        if r.patterns & 2 != 0 && f.own_inputs != f.own_outputs {
            return Some("EQ_NUM_OWN_INS_OUTS not met");
        }
        if r.patterns & 4 != 0 && !self.equal_amounts {
            return Some("EQ_OUT_AMOUNTS not met");
        }
        if !r.users.is_empty() {
            let got = r.users.count_in(f.users);
            let need = r.min_users.unwrap_or(r.users.len as u32) as usize;
            if got == 0 || got < need {
                return Some("need more users to confirm");
            }
        }
        if r.local_conf && !f.local_ok {
            return Some("local confirmation code wrong or missing");
        }
        None
    }
}

// ---------------------------------------------------------------------------------------
// The running counters
// ---------------------------------------------------------------------------------------

/// Longest last-refusal text kept.
pub const LAST_REFUSAL: usize = 120;

/// What HSM mode counts while it runs. Nothing here persists: a restart starts over (and a
/// boot-to-HSM restart starts with every velocity limit spent, [`Runtime::precharge`]).
#[derive(Clone, Debug)]
pub struct Runtime {
    pub approvals: u32,
    pub refusals: u32,
    pub last_refusal: heapless::String<LAST_REFUSAL>,
    /// Seconds of uptime at the first spend of the period; `None` before one.
    pub period_started: Option<u64>,
    /// Spent in this period, per rule.
    pub spent: [u64; MAX_RULES],
}

/// What [`Runtime::time_left`] says.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum TimeLeft {
    /// The policy has no period.
    NoPeriod,
    /// Nothing spent yet: the period has not begun.
    NotStarted,
    /// Seconds until the spending resets.
    Seconds(u64),
}

impl Default for Runtime {
    fn default() -> Self {
        Self::new()
    }
}

impl Runtime {
    pub const fn new() -> Self {
        Self {
            approvals: 0,
            refusals: 0,
            last_refusal: heapless::String::new(),
            period_started: None,
            spent: [0; MAX_RULES],
        }
    }

    /// `get_time_left`: what is left of the period, resetting every rule's spending once
    /// it has run out. Source: §3.4 [C]
    pub fn time_left(&mut self, period_minutes: Option<u64>, now: u64) -> TimeLeft {
        let Some(p) = period_minutes else {
            return TimeLeft::NoPeriod;
        };
        let Some(start) = self.period_started else {
            return TimeLeft::NotStarted;
        };
        let end = start.saturating_add(p * 60);
        if now >= end {
            self.reset_period();
            return TimeLeft::NotStarted;
        }
        TimeLeft::Seconds(end - now)
    }

    /// `reset_period`. Source: §3.4 [C]
    pub fn reset_period(&mut self) {
        self.spent = [0; MAX_RULES];
        self.period_started = None;
    }

    /// `record_spend`: the period starts at the first spend. Source: §3.4 [C]
    pub fn record_spend(&mut self, rule: usize, amount: u64, now: u64) {
        if self.period_started.is_none() {
            self.period_started = Some(now);
        }
        if let Some(s) = self.spent.get_mut(rule) {
            *s = s.saturating_add(amount);
        }
    }

    /// A boot-to-HSM start from the stored policy: every velocity limit counted as used,
    /// the period starting now -- the spending before the restart cannot be known.
    /// Source: §4 "pre-charges every velocity rule to its full per_period" [C]; that the
    /// period starts at that moment is `[I]`: a period that never started would never end.
    pub fn precharge(&mut self, policy: &Policy<'_>, now: u64) {
        let mut any = false;
        for (i, r) in policy.rules.iter().enumerate() {
            if let Some(v) = r.per_period {
                self.spent[i] = v;
                any = true;
            }
        }
        if any {
            self.period_started = Some(now);
        }
    }

    pub fn approve(&mut self) {
        self.approvals = self.approvals.wrapping_add(1);
    }

    /// Count a refusal and keep its reason. True once [`MAX_REFUSALS`] is reached: the
    /// device must shut down. Source: §3.1 [C]
    pub fn refuse(&mut self, why: &str) -> bool {
        self.refusals = self.refusals.saturating_add(1);
        self.last_refusal.clear();
        for c in why.chars() {
            if self.last_refusal.push(c).is_err() {
                break;
            }
        }
        self.refusals >= MAX_REFUSALS
    }
}

// ---------------------------------------------------------------------------------------
// The local confirmation code
// ---------------------------------------------------------------------------------------

/// The six-digit code for a PSBT: HMAC-SHA256 keyed with the decoded `next_local_code`
/// over the file's SHA-256, its last four bytes as a big-endian number, modulo a million.
/// Source: §3.2 [C]; the byte order is the host tool's (`ckcc local-conf`, run as a black
/// box against a known key and file) [C].
pub fn local_code(key: &[u8], psbt_sha: &[u8; 32]) -> u32 {
    let mut mac = HmacSha256::new(key);
    mac.update(psbt_sha);
    let d = mac.finalize();
    u32::from_be_bytes([d[28], d[29], d[30], d[31]]) % 1_000_000
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// `next_local_code` as the status report carries it: base64 of the key.
pub fn local_key_text(key: &[u8; LOCAL_KEY_LEN]) -> heapless::String<LOCAL_KEY_TEXT> {
    let mut s = heapless::String::new();
    for c in key.chunks(3) {
        let n = (u32::from(c[0]) << 16) | (u32::from(c[1]) << 8) | u32::from(c[2]);
        for shift in [18, 12, 6, 0] {
            let _ = s.push(B64[((n >> shift) & 63) as usize] as char);
        }
    }
    s
}

/// The six digits the operator typed, checked against the code this PSBT needs. The
/// comparison is on the digits, in constant time.
pub fn local_code_matches(typed: &str, key: &[u8; LOCAL_KEY_LEN], psbt_sha: &[u8; 32]) -> bool {
    use purecrypto::ct::ConstantTimeEq;
    if typed.len() != LOCAL_PIN_LENGTH {
        return false;
    }
    let mut want: heapless::String<8> = heapless::String::new();
    let _ = write!(want, "{:06}", local_code(key, psbt_sha));
    bool::from(want.as_bytes().ct_eq(typed.as_bytes()))
}

// ---------------------------------------------------------------------------------------
// The status report
// ---------------------------------------------------------------------------------------

/// What `hsts` reports. Source: §3.5 "Status-report fields" [C]
///
/// `active` and `policy_available` are ours: the reference lists the fields of an active
/// policy's report and not what a device with none says. `[I]`
pub struct Status<'s, 'a> {
    pub active: bool,
    pub policy_available: bool,
    /// The policy in force, its canonical hash, and its counters.
    pub running: Option<Running<'s, 'a>>,
}

pub struct Running<'s, 'a> {
    pub policy: &'s Policy<'a>,
    pub hash: &'s str,
    pub runtime: &'s Runtime,
    pub next_local_code: &'s str,
    /// Seconds since boot.
    pub uptime: u64,
    pub time_left: TimeLeft,
    /// Every user on the device.
    pub users: &'s [&'s str],
    /// Authentications queued for the next PSBT.
    pub pending_auth: usize,
    /// Most bytes of the `summary` text sent: a reply has a fixed size, and the summary
    /// is the one field that can be cut without losing a number.
    pub summary_max: usize,
}

impl Status<'_, '_> {
    /// The report as JSON. With `priv_over_ux` only the counters and the refusal go out,
    /// beside the hash (and the local code when a rule needs it). Source: §3.5 [C]
    pub fn write(&self, out: &mut [u8]) -> Result<usize, Problem> {
        let mut w = JsonWriter::new(SliceWriter::new(out));
        self.write_into(&mut w).map_err(|_| Problem::TooLarge)?;
        Ok(w.get_ref().written().len())
    }

    fn write_into(
        &self,
        w: &mut JsonWriter<SliceWriter<'_>>,
    ) -> Result<(), emjson::io::BufferFull> {
        w.begin_object()?;
        w.member("active", &self.active)?;
        w.member("policy_available", &self.policy_available)?;
        if let Some(r) = &self.running {
            w.member("policy_hash", r.hash)?;
            if r.policy.uses_local_conf() {
                w.member("next_local_code", r.next_local_code)?;
            }
            match r.runtime.last_refusal.as_str() {
                "" => {
                    w.key("last_refusal")?;
                    w.null()?;
                }
                s => w.member("last_refusal", s)?,
            }
            w.member("approvals", &r.runtime.approvals)?;
            w.member("refusals", &r.runtime.refusals)?;
            if !r.policy.priv_over_ux {
                let mut summary: heapless::String<1024> = heapless::String::new();
                // Cut short rather than left out when it runs over: the report still fits.
                let _ = r.policy.explain(&mut summary);
                let mut cut = summary.len().min(r.summary_max);
                while !summary.is_char_boundary(cut) {
                    cut -= 1;
                }
                w.member("summary", &summary[..cut])?;
                w.member("sl_reads", &0u32)?;
                match r.policy.period {
                    Some(p) => w.member("period", &p)?,
                    None => {
                        w.key("period")?;
                        w.null()?;
                    }
                }
                w.member("uptime", &r.uptime)?;
                w.key("period_ends")?;
                match r.time_left {
                    TimeLeft::Seconds(s) => w.u64(s)?,
                    _ => w.null()?,
                }
                w.key("has_spent")?;
                w.begin_array()?;
                for (i, rule) in r.policy.rules.iter().enumerate() {
                    if rule.per_period.is_some() {
                        w.u64(r.runtime.spent[i])?;
                    } else {
                        w.null()?;
                    }
                }
                w.end_array()?;
                w.key("users")?;
                w.begin_array()?;
                for u in r.users {
                    w.string(u)?;
                }
                w.end_array()?;
                w.member("pending_auth", &(r.pending_auth as u32))?;
            }
        }
        w.end_object()
    }
}

#[cfg(test)]
mod tests;
