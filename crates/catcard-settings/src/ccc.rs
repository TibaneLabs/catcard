//! Coldcard Co-Sign (CCC): key C, how it is stored, and when it may sign.
//!
//! CCC puts a second seed on the device -- key C, an independent BIP-39 phrase -- whose
//! only job is to be one of the keys of a 2-of-N multisig and to sign only when a
//! transaction meets a spending policy. Key A is the device's own seed, key B a backup
//! held elsewhere. Spending within the policy needs this device alone (A + C); outside
//! it, A + B.
//! Source: hw-reference/ccc-key-storage.md §§1-5 [C]; help-and-warning-screens.md §12
//! "CCC" [C]
//!
//! This module is the host-testable part: the stored value, the policy decision for a
//! co-signature, and the key-C word challenge's counter. The firmware's `ccc` module is the
//! screens and the signing.
//!
//! # Stock's key, in stock's shape
//!
//! Unlike the single-signer policy (our own `cat_sssp`), CCC is stored under **stock's own
//! key `ccc`**, because the reference gives its value exactly:
//!
//! ```json
//! {"secret":"8010...","c_xfp":4052576440,"c_xpub":"xpub661...","pol":{"mag":1,"vel":144,
//!  "block_h":0,"web2fa":"","addrs":[]}}
//! ```
//!
//! - `secret` -- uppercase hex of key C's secret-stash encoding (marker byte then entropy),
//!   trailing zero bytes stripped; read back zero-padded to the 72-byte slot.
//! - `c_xfp` -- key C's fingerprint as the little-endian number of its four bytes.
//! - `c_xpub` -- key C's master xpub at `m/`.
//! - `pol` -- the spending policy, the same fields as stock's single-signer one.
//!
//! Source: hw-reference/ccc-key-storage.md §1.2 "Exact value shape" [C], §3 policy
//! fields [C]; secret-stash-format.md §Layout [C]. A device moved between stock and this
//! firmware keeps its co-signer either way.
//!
//! # What doubt reads as
//!
//! A `ccc` value that is present and will not read is [`Read::Damaged`]: the firmware then
//! refuses to co-sign (key A still signs), and Remove CCC clears it. Damage never reads as
//! a policy that allows everything, and never as "no key C" to a screen that would then
//! offer to make a new one over it.
//!
//! # Web 2FA
//!
//! Stock's policy can also require a round trip to Coinkite's closed coldcard.com service.
//! That is deliberately left out of this firmware. A `web2fa` secret written by stock is
//! kept as it is, and a policy that has one is never met here ([`Violation::Web2fa`]):
//! co-signing it would silently drop a rule the owner chose.

use crate::json::{self, Doc};
use crate::policy::{
    self, Allowed, Checker, MAX_ADDRESS, MAX_VELOCITY, MAX_WHITELIST, Out, Policy, Violation,
};
use purecrypto::ct::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Where key C and its policy live in the (master) wallet's settings. **Stock's key.**
/// Source: hw-reference/ccc-key-storage.md §1.1 [C]; settings-nvstore-format.md "`ccc`" [C]
pub const KEY: &str = "ccc";

/// The last co-signature refused, as text. Our own key: stock keeps its reason under
/// `lfr`, whose value shape the reference does not give. `[I]`
pub const VIOLATION_KEY: &str = "cat_ccc_viol";

/// The secure element's secret slot, which is what `secret` pads back out to.
/// Source: hw-reference/secret-stash-format.md "72-byte slot (`AE_SECRET_LEN`)" [C]
pub const SECRET_LEN: usize = 72;

/// Longest xpub text kept for `c_xpub`: base58 of 82 bytes is 111 characters.
pub const MAX_XPUB: usize = 116;

/// Longest Web 2FA secret carried through untouched.
pub const MAX_WEB2FA: usize = 64;

/// Room for a rendered `ccc` value at the whitelist's bound.
pub const RENDER_MAX: usize = 512 + MAX_WHITELIST * (MAX_ADDRESS + 3);

/// The policy a fresh key C starts with: 1 BTC per transaction, one spend per 144 blocks.
/// Source: hw-reference/ccc-key-storage.md §3 table "`mag` default `1` (=1 BTC)", "`vel`
/// default `144`" [C]
pub const DEFAULT_MAGNITUDE: u64 = 100_000_000;
pub const DEFAULT_VELOCITY: u32 = 144;

/// Wrong key-C phrases allowed in one session before the device restarts.
/// Source: hw-reference/ccc-key-storage.md §1.4(a) "3 failures -> `clean_shutdown()`" [C]
pub const MAX_CHALLENGE_FAILS: u8 = 3;

/// Stock's magnitude threshold: a `mag` below this is bitcoin, at or above it satoshis.
/// Source: hw-reference/ccc-key-storage.md §3 "if `< 1000` treated as **BTC**, else
/// **sats**" [C]
const BTC_BELOW: u128 = 1000;
const SATS_PER_BTC: u128 = 100_000_000;

/// Key C and its policy, as stored.
///
/// Holds key C's secret, so it is wiped when dropped, and nothing here prints it.
#[derive(Clone)]
pub struct Ccc {
    /// The stash encoding: marker then entropy, zero-padded.
    secret: [u8; SECRET_LEN],
    /// Key C's fingerprint, as its four bytes.
    pub xfp: [u8; 4],
    /// Key C's master xpub, as written.
    pub xpub: heapless::String<MAX_XPUB>,
    /// The spending policy: magnitude, velocity (`last_height` is stock's `block_h`),
    /// whitelist. The single-signer flags are not part of stock's `pol` and stay false.
    pub policy: Policy,
    /// A Web 2FA enrolment made on stock firmware, kept so a rewrite does not drop it.
    pub web2fa: heapless::String<MAX_WEB2FA>,
}

impl Zeroize for Ccc {
    fn zeroize(&mut self) {
        self.secret.zeroize();
    }
}

impl Drop for Ccc {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl ZeroizeOnDrop for Ccc {}

impl core::fmt::Debug for Ccc {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never the secret.
        f.debug_struct("Ccc")
            .field("xfp", &self.xfp)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

/// What the settings say about CCC.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Read {
    /// No key C.
    Absent,
    /// Key C and its policy.
    Ccc(Ccc),
    /// Something is under `ccc` and it will not read. Nothing is co-signed.
    Damaged,
}

/// Read `ccc` out of a wallet's settings object. Stock's `null` (a removed key written
/// back) and `false` read as absent, as stock's own truth test on the value does.
pub fn read(doc: &Doc<'_>) -> Read {
    match doc.get(KEY) {
        None | Some("null") | Some("false") | Some("{}") => Read::Absent,
        Some(raw) => match parse_object(raw) {
            Some(c) => Read::Ccc(c),
            None => Read::Damaged,
        },
    }
}

/// The number of words a stash-encoded BIP-39 secret carries, from its marker; `None`
/// for anything that is not words.
/// Source: hw-reference/secret-stash-format.md §Layout "`0x80 | ((L/8)-2)`" [C]
pub fn words_of(secret: &[u8]) -> Option<usize> {
    let marker = *secret.first()?;
    if marker & 0x80 == 0 || marker & 0x7C != 0 {
        return None;
    }
    let len = ((marker & 0x03) as usize + 2) * 8;
    if secret.len() < 1 + len {
        return None;
    }
    Some(len * 3 / 4)
}

/// Parse a `ccc` object's text. `None` if anything present is malformed.
pub fn parse_object(raw: &str) -> Option<Ccc> {
    let doc = Doc::parse(raw.as_bytes()).ok()?;

    let hex = doc.get_str("secret")?;
    if hex.is_empty() || !hex.len().is_multiple_of(2) || hex.len() > 2 * SECRET_LEN {
        return None;
    }
    let mut secret = [0u8; SECRET_LEN];
    for (i, pair) in hex.as_bytes().chunks(2).enumerate() {
        let d = |c: u8| (c as char).to_digit(16);
        match (d(pair[0]), d(pair[1])) {
            (Some(h), Some(l)) => secret[i] = (h * 16 + l) as u8,
            _ => {
                secret.zeroize();
                return None;
            }
        }
    }
    let mut c = Ccc {
        secret,
        xfp: [0; 4],
        xpub: heapless::String::new(),
        policy: Policy::default(),
        web2fa: heapless::String::new(),
    };
    secret.zeroize();
    // Key C is a phrase: nothing else can be challenged for, or re-encoded to compare.
    words_of(&c.secret)?;

    let xfp = doc.get_u64("c_xfp")?;
    c.xfp = u32::try_from(xfp).ok()?.to_le_bytes();
    let xpub = doc.get_str("c_xpub")?;
    if !policy::storable_text(xpub) {
        return None;
    }
    c.xpub.push_str(xpub).ok()?;

    let pol = Doc::parse(doc.get("pol")?.as_bytes()).ok()?;
    c.policy.magnitude = match pol.get("mag") {
        None | Some("null") => 0,
        Some(t) => parse_magnitude(t)?,
    };
    let vel = match pol.get("vel") {
        None | Some("null") => 0,
        Some(t) => t.parse::<u64>().ok()?,
    };
    if vel > u64::from(MAX_VELOCITY) {
        return None;
    }
    c.policy.velocity = vel as u32;
    c.policy.last_height = match pol.get("block_h") {
        None | Some("null") => 0,
        Some(t) => u32::try_from(t.parse::<u64>().ok()?).ok()?,
    };
    match pol.get("web2fa") {
        None | Some("null") | Some("false") => {}
        Some(t) => {
            let s = t.strip_prefix('"')?.strip_suffix('"')?;
            if !policy::storable_text(s) {
                return None;
            }
            c.web2fa.push_str(s).ok()?;
        }
    }
    if let Some(list) = pol.get("addrs") {
        for item in json::elements(list).ok()? {
            let item = item.ok()?;
            let text = item.strip_prefix('"')?.strip_suffix('"')?;
            if !policy::valid_address(text) {
                return None;
            }
            let mut owned: heapless::String<MAX_ADDRESS> = heapless::String::new();
            owned.push_str(text).ok()?;
            c.policy.whitelist.push(owned).ok()?;
        }
    }
    Some(c)
}

impl Ccc {
    /// A fresh key C: its stash encoding, fingerprint and master xpub, under the default
    /// policy. `None` if the secret is not a BIP-39 phrase's encoding or the xpub cannot be
    /// stored.
    pub fn new(secret: &[u8; SECRET_LEN], xfp: [u8; 4], xpub: &str) -> Option<Ccc> {
        words_of(secret)?;
        if !policy::storable_text(xpub) {
            return None;
        }
        let mut c = Ccc {
            secret: *secret,
            xfp,
            xpub: heapless::String::new(),
            policy: Policy {
                magnitude: DEFAULT_MAGNITUDE,
                velocity: DEFAULT_VELOCITY,
                ..Policy::default()
            },
            web2fa: heapless::String::new(),
        };
        c.xpub.push_str(xpub).ok()?;
        Some(c)
    }

    /// Key C's stash encoding. Key material: read it inside the firmware's masked region.
    pub fn secret(&self) -> &[u8; SECRET_LEN] {
        &self.secret
    }

    /// Key C's BIP-39 entropy. Key material, as [`Self::secret`].
    pub fn entropy(&self) -> &[u8] {
        let n = words_of(&self.secret).unwrap_or(0) * 4 / 3;
        &self.secret[1..1 + n]
    }

    /// How many words key C has: 12, 18 or 24. What the challenge asks for.
    pub fn word_count(&self) -> usize {
        words_of(&self.secret).unwrap_or(0)
    }

    /// `c_xfp`: the fingerprint's bytes read as a little-endian number.
    pub fn xfp_number(&self) -> u32 {
        u32::from_le_bytes(self.xfp)
    }

    /// Whether `typed` -- the stash encoding of the phrase the owner entered -- is key C,
    /// byte for byte over the whole slot. The key-C challenge: every word has to be right,
    /// not a fingerprint and not the first and last words. Constant time.
    /// Source: hw-reference/ccc-key-storage.md §1.4(a) "`enc == cls.get_encoded_secret()`" [C]
    pub fn matches(&self, typed: &[u8; SECRET_LEN]) -> bool {
        bool::from(self.secret[..].ct_eq(&typed[..]))
    }

    /// Write the value for [`KEY`] into `out`, in stock's field names. `None` if it does
    /// not fit.
    ///
    /// Every string here passed [`policy::storable_text`] or [`policy::valid_address`],
    /// and the secret is hex, so nothing needs escaping.
    pub fn render<'o>(&self, out: &'o mut [u8]) -> Option<&'o str> {
        let mut w = W { out, at: 0 };
        w.put(b"{\"secret\":\"")?;
        // Trailing zero bytes stripped, as stock writes it.
        let used = self
            .secret
            .iter()
            .rposition(|&b| b != 0)
            .map_or(0, |i| i + 1);
        for b in &self.secret[..used] {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            w.put(&[HEX[(b >> 4) as usize], HEX[(b & 15) as usize]])?;
        }
        w.put(b"\",\"c_xfp\":")?;
        w.num(u64::from(self.xfp_number()))?;
        w.put(b",\"c_xpub\":\"")?;
        w.put(self.xpub.as_bytes())?;
        w.put(b"\",\"pol\":{\"mag\":")?;
        let mut mag = [0u8; 24];
        w.put(render_magnitude(self.policy.magnitude, &mut mag).as_bytes())?;
        w.put(b",\"vel\":")?;
        w.num(u64::from(self.policy.velocity))?;
        w.put(b",\"block_h\":")?;
        w.num(u64::from(self.policy.last_height))?;
        w.put(b",\"web2fa\":\"")?;
        w.put(self.web2fa.as_bytes())?;
        w.put(b"\",\"addrs\":[")?;
        for (i, a) in self.policy.whitelist.iter().enumerate() {
            if i > 0 {
                w.put(b",")?;
            }
            w.put(b"\"")?;
            w.put(a.as_bytes())?;
            w.put(b"\"")?;
        }
        w.put(b"]}}")?;
        let n = w.at;
        core::str::from_utf8(&out[..n]).ok()
    }

    /// Whether a co-signature is allowed before the outputs are looked at: a review
    /// warning, or a Web 2FA rule this firmware cannot meet, refuses it outright.
    pub fn precheck(&self, warnings: bool) -> Result<(), Violation> {
        if !self.web2fa.is_empty() {
            return Err(Violation::Web2fa);
        }
        if warnings {
            return Err(Violation::Warnings);
        }
        Ok(())
    }
}

/// What an allowed co-signature leaves behind.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Cosign {
    /// The new `block_h` to store, when the transaction names a later height than the one
    /// recorded. Stock keeps it strictly ascending and bumps it on every co-signature,
    /// whether or not velocity is limited.
    /// Source: hw-reference/ccc-key-storage.md §3 "`block_h` ... strictly ascending,
    /// updated on each sign" [C]
    pub record_height: Option<u32>,
}

/// Finish a co-signing decision: the single-signer engine's verdict over the outputs,
/// then the height to record.
pub fn finish(
    ccc: &Ccc,
    checker: Checker<'_>,
    sending: u64,
    height: Option<u32>,
) -> Result<Cosign, Violation> {
    let Allowed { .. } = checker.finish(sending, height)?;
    Ok(Cosign {
        record_height: height.filter(|h| *h > ccc.policy.last_height),
    })
}

/// A whole co-signing decision at once: [`Ccc::precheck`], the outputs, the totals.
pub fn judge(
    ccc: &Ccc,
    outputs: &[Out<'_>],
    sending: u64,
    height: Option<u32>,
    warnings: bool,
) -> Result<Cosign, Violation> {
    ccc.precheck(warnings)?;
    let mut c = Checker::new(&ccc.policy);
    for o in outputs {
        c.output(*o);
    }
    finish(ccc, c, sending, height)
}

/// The key-C challenge's outcome, counted across a session.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Challenge {
    /// The words were key C.
    Pass,
    /// Wrong; this many tries remain this session.
    Wrong { left: u8 },
    /// The last try was used: restart the device.
    Shutdown,
}

/// Count one attempt at the key-C challenge. `fails` is the session's count, which a
/// correct answer does not reset: three wrong phrases in one session restart the device,
/// however they are spread.
pub fn challenge(matched: bool, fails: &mut u8) -> Challenge {
    if matched {
        return Challenge::Pass;
    }
    *fails = fails.saturating_add(1);
    if *fails >= MAX_CHALLENGE_FAILS {
        Challenge::Shutdown
    } else {
        Challenge::Wrong {
            left: MAX_CHALLENGE_FAILS - *fails,
        }
    }
}

/// A `mag` value as stock writes it, in satoshis: a number below 1000 is bitcoin (and may
/// have a fraction, or an exponent as Python writes small floats), one at or above it is
/// satoshis. `None` for a negative, a fraction of a satoshi, or anything not a number.
pub fn parse_magnitude(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    let mut i = 0usize;
    let mut mantissa: u128 = 0;
    let mut digits = 0usize;
    let mut frac = 0i32;
    let mut seen_dot = false;
    while i < bytes.len() {
        match bytes[i] {
            b'0'..=b'9' => {
                mantissa = mantissa
                    .checked_mul(10)?
                    .checked_add(u128::from(bytes[i] - b'0'))?;
                digits += 1;
                if seen_dot {
                    frac += 1;
                }
            }
            b'.' if !seen_dot => seen_dot = true,
            _ => break,
        }
        i += 1;
    }
    if digits == 0 {
        return None;
    }
    let mut exp = 0i32;
    if i < bytes.len() {
        if !matches!(bytes[i], b'e' | b'E') {
            return None;
        }
        i += 1;
        let neg = match bytes.get(i) {
            Some(b'-') => {
                i += 1;
                true
            }
            Some(b'+') => {
                i += 1;
                false
            }
            _ => false,
        };
        let rest = text.get(i..)?;
        if rest.is_empty() || rest.len() > 3 || !rest.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let e: i32 = rest.parse().ok()?;
        exp = if neg { -e } else { e };
    }
    // value = mantissa * 10^scale
    let scale = exp - frac;
    let times = |m: u128, s: i32| -> Option<(u128, bool)> {
        // (m * 10^s, exact)
        if s >= 0 {
            let mut v = m;
            for _ in 0..s {
                v = v.checked_mul(10)?;
            }
            Some((v, true))
        } else {
            let mut v = m;
            let mut exact = true;
            for _ in 0..(-s) {
                if !v.is_multiple_of(10) {
                    exact = false;
                }
                v /= 10;
            }
            Some((v, exact))
        }
    };
    // In bitcoin terms first: `value < 1000` is the same as `value * 10^8 < 10^11`, and a
    // truncated product is below an integer bound exactly when the real one is. Below it
    // the number is bitcoin, and must come to whole satoshis.
    let (as_sats, exact) = times(mantissa, scale + 8)?;
    if as_sats < BTC_BELOW * SATS_PER_BTC {
        return if exact {
            u64::try_from(as_sats).ok()
        } else {
            None
        };
    }
    // At or above 1000: satoshis, which must be whole.
    let (sats, exact) = times(mantissa, scale)?;
    if !exact {
        return None;
    }
    u64::try_from(sats).ok()
}

/// A magnitude in satoshis as a `mag` stock reads back to the same amount: satoshis when
/// that is 1000 or more, a decimal of bitcoin below it (which stock reads as bitcoin).
pub fn render_magnitude(sats: u64, out: &mut [u8; 24]) -> &str {
    let mut w = W {
        out: &mut out[..],
        at: 0,
    };
    if sats == 0 || u128::from(sats) >= BTC_BELOW {
        let _ = w.num(sats);
    } else {
        // Below 1000 sat: 0.00000xyz bitcoin, trailing zeros trimmed.
        let mut digits = [b'0'; 8];
        let mut v = sats;
        for d in digits.iter_mut().rev() {
            *d = b'0' + (v % 10) as u8;
            v /= 10;
        }
        let end = digits.iter().rposition(|&d| d != b'0').map_or(1, |i| i + 1);
        let _ = w.put(b"0.");
        let _ = w.put(&digits[..end]);
    }
    let n = w.at;
    core::str::from_utf8(&out[..n]).unwrap_or("0")
}

struct W<'o> {
    out: &'o mut [u8],
    at: usize,
}

impl W<'_> {
    fn put(&mut self, bytes: &[u8]) -> Option<()> {
        let end = self.at.checked_add(bytes.len())?;
        self.out.get_mut(self.at..end)?.copy_from_slice(bytes);
        self.at = end;
        Some(())
    }

    fn num(&mut self, n: u64) -> Option<()> {
        let mut buf = [0u8; 20];
        let mut i = buf.len();
        let mut v = n;
        loop {
            i -= 1;
            buf[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        self.put(&buf[i..])
    }
}

#[cfg(test)]
mod tests;
