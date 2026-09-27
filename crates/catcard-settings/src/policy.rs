//! The Single-Signer Spending Policy (SSSP): what it holds, how it is stored, what it
//! refuses, and which menu rows survive it.
//!
//! Stock's feature is a policy -- a per-transaction magnitude cap, a block-height velocity
//! limit, an address whitelist, optionally a web-2FA round trip -- that, once activated,
//! puts the device in a "hobbled" mode where the main PIN reaches signing and addresses
//! and little else, and a dedicated unlock PIN (an SE2 trick PIN) is the way back out.
//! Source: hw-reference/firmware-features.md §8 "Spending Policy (single-sig)", "Hobbled
//! mode" [C]; menu-map-mk4-mk5-q1-v5.6.2.md §B4, §SP1, §SP-POL [C];
//! help-and-warning-screens.md §12 "SSSP" [C].
//!
//! This module is the part a host can test: the JSON shape, every bound, the check, and
//! the row filter. The screens, the settings plumbing and the unlock prompt are the
//! firmware's `policy` module.
//!
//! # Not stock's key
//!
//! Stock keeps its policy in the wallet settings under keys the reference names (`mag`,
//! `vel`, `addrs`, `words`, `notes`, `okeys`, `web2fa`) without pinning where they nest or
//! what the values look like `[?]`. A policy written in a shape stock misread could hobble
//! a stock device with a policy nobody chose -- or, worse, read as "no policy" on ours
//! while stock enforces one. So the whole policy is one object under our own [`KEY`],
//! which stock ignores as it ignores every key it does not know. `[I]`
//!
//! # What doubt reads as
//!
//! The policy is under the wallet's own settings key, sealed under the seed: nobody who
//! cannot log in can write it, and nobody who can log in while hobbled is offered a screen
//! that writes it. So a present-but-unreadable policy is a bug or a torn write, not an
//! attack -- and it still reads as [`Read::Damaged`], which the firmware treats as a policy
//! that allows nothing. The direction that matters is that damage never reads as **off**:
//! a policy that evaporated with two bad bytes would be no policy at all. The unlock PIN
//! is the way out of a damaged one, exactly as it is out of a good one.
//!
//! # The way out
//!
//! Stock's escape: a trick PIN in the second secure element whose flags are `TC_FW_DEFINED`
//! and whose argument is `TCA_SP_UNLOCK` (hw-reference/trick-pin-slot-format.md §1.4 [C]).
//! Typed at the login prompt, it is followed by the main PIN, and the policy is suspended
//! for that session. Nothing about it is kept here: it is `catcard_pin::trick` and the
//! firmware's `trickpin`.

use crate::json::{self, Doc};

/// Where the policy lives in the wallet's settings object. **Not** a stock key. `[I]`
pub const KEY: &str = "cat_sssp";

/// Most whitelisted addresses. Stock's bound for its spending-policy whitelist.
/// Source: hw-reference/firmware-features.md §"Limits" "CCC/HSM address whitelist: up to
/// 25" [C]
pub const MAX_WHITELIST: usize = 25;

/// Longest address kept, in bytes: bech32's ceiling, which is longer than any base58.
pub const MAX_ADDRESS: usize = 90;
/// Shortest anything that could be an address is.
pub const MIN_ADDRESS: usize = 14;

/// Longest text a recorded violation keeps.
pub const MAX_VIOLATION: usize = 64;

/// The magnitude velocity starts from when it is switched on with no cap set: one bitcoin,
/// in satoshis. Source: hw-reference/help-and-warning-screens.md §12 "Enable velocity with
/// no magnitude ... magnitude is auto-set to 1 BTC" [C]
pub const DEFAULT_VELOCITY_MAGNITUDE: u64 = 100_000_000;

/// Most blocks a velocity limit can ask for: about a year.
pub const MAX_VELOCITY: u32 = 52_560;

/// One policy, as stored.
///
/// Owns its whitelist -- about two and a half kilobytes at the bound -- so an address
/// typed or scanned on the device can be added without the settings text it was read
/// beside having to outlive it. One of these is live at a time, on the menu task's stack,
/// never in `.bss`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Policy {
    /// The most a transaction may send away, in satoshis; zero is no cap.
    pub magnitude: u64,
    /// At most one spend per this many blocks; zero is off.
    pub velocity: u32,
    /// The height the last allowed spend named, or zero for none yet.
    pub last_height: u32,
    /// Changing or removing the policy also needs the first and last seed words.
    pub word_check: bool,
    /// Secure Notes stay readable while hobbled (Q1).
    pub allow_notes: bool,
    /// Passphrase wallets, temporary seeds and the vault stay reachable while hobbled.
    pub related_keys: bool,
    /// Whether the policy is in force: hobbled mode from the next login.
    pub active: bool,
    /// Destinations a transaction may pay; empty means any.
    pub whitelist: heapless::Vec<heapless::String<MAX_ADDRESS>, MAX_WHITELIST>,
    /// The last refusal, as text; empty for none.
    pub violation: heapless::String<MAX_VIOLATION>,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            magnitude: 0,
            velocity: 0,
            last_height: 0,
            word_check: false,
            allow_notes: false,
            related_keys: false,
            active: false,
            whitelist: heapless::Vec::new(),
            violation: heapless::String::new(),
        }
    }
}

/// What the wallet's settings say about the policy.
///
/// The policy variant is the whole owned whitelist; there is no allocator here to box
/// it, and a caller holds one of these on its stack for a moment before taking the
/// policy out.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Read {
    /// No policy has ever been written.
    Absent,
    /// A policy, active or not.
    Policy(Policy),
    /// Something is under the key and it will not read. Allows nothing.
    Damaged,
}

/// Read the policy out of a wallet's settings object.
pub fn read(doc: &Doc<'_>) -> Read {
    let Some(raw) = doc.get(KEY) else {
        return Read::Absent;
    };
    match parse_object(raw) {
        Some(p) => Read::Policy(p),
        None => Read::Damaged,
    }
}

/// Parse the policy object's text (the value under [`KEY`], braces and all).
///
/// Every field is optional and reads as its default when absent; a field that is present
/// and wrong makes the whole thing `None`, which [`read`] turns into [`Read::Damaged`].
/// Lenient on what is missing and strict on what is malformed, so a policy written by a
/// later version with a field this one does not know still reads, and a torn one does not.
pub fn parse_object(raw: &str) -> Option<Policy> {
    let mut p = Policy::default();
    parse_object_into(raw, &mut p).then_some(p)
}

/// [`parse_object`], into `p` rather than a new policy: for a caller whose policy lives
/// off the stack, where a returned one would be built on it first.
///
/// False when it will not read, and `p` is then back at the defaults: a torn policy never
/// leaves half its rules behind to be enforced as if they were all of them.
pub fn parse_object_into(raw: &str, p: &mut Policy) -> bool {
    p.reset();
    let ok = fill(raw, p).is_some();
    if !ok {
        p.reset();
    }
    ok
}

impl Policy {
    /// Back to [`Policy::default`], in place.
    fn reset(&mut self) {
        let Policy {
            magnitude,
            velocity,
            last_height,
            word_check,
            allow_notes,
            related_keys,
            active,
            whitelist,
            violation,
        } = self;
        *magnitude = 0;
        *velocity = 0;
        *last_height = 0;
        *word_check = false;
        *allow_notes = false;
        *related_keys = false;
        *active = false;
        whitelist.clear();
        violation.clear();
    }
}

fn fill(raw: &str, p: &mut Policy) -> Option<()> {
    let inner = Doc::parse(raw.as_bytes()).ok()?;

    let number = |key: &str| -> Option<Option<u64>> {
        match inner.get(key) {
            None => Some(None),
            Some(_) => inner.get_u64(key).map(Some),
        }
    };
    let flag = |key: &str| -> Option<bool> {
        match inner.get(key) {
            None => Some(false),
            Some(_) => inner.get_bool(key),
        }
    };

    p.magnitude = number("mag")?.unwrap_or(0);
    let vel = number("vel")?.unwrap_or(0);
    if vel > u64::from(MAX_VELOCITY) {
        return None;
    }
    p.velocity = vel as u32;
    let last = number("last")?.unwrap_or(0);
    if last > u64::from(u32::MAX) {
        return None;
    }
    p.last_height = last as u32;
    p.word_check = flag("words")?;
    p.allow_notes = flag("notes")?;
    p.related_keys = flag("okeys")?;
    p.active = flag("active")?;

    if let Some(list) = inner.get("addrs") {
        for item in json::elements(list).ok()? {
            let item = item.ok()?;
            let text = item.strip_prefix('"')?.strip_suffix('"')?;
            if !valid_address(text) {
                return None;
            }
            let mut owned: heapless::String<MAX_ADDRESS> = heapless::String::new();
            owned.push_str(text).ok()?;
            p.whitelist.push(owned).ok()?;
        }
    }
    if let Some(v) = inner.get("viol") {
        let text = v.strip_prefix('"')?.strip_suffix('"')?;
        if !storable_text(text) {
            return None;
        }
        p.violation.push_str(text).ok()?;
    }
    Some(())
}

impl Policy {
    /// Write the object as the value for [`KEY`], into `out`. `None` if it will not fit.
    ///
    /// Every string written here passed [`valid_address`] or [`storable_text`], neither of
    /// which admits a quote or a backslash, so nothing needs escaping.
    pub fn render<'o>(&self, out: &'o mut [u8]) -> Option<&'o str> {
        let mut w = Writer { out, at: 0 };
        w.put(b"{\"mag\":")?;
        w.num(self.magnitude)?;
        w.put(b",\"vel\":")?;
        w.num(u64::from(self.velocity))?;
        w.put(b",\"last\":")?;
        w.num(u64::from(self.last_height))?;
        for (name, on) in [
            ("words", self.word_check),
            ("notes", self.allow_notes),
            ("okeys", self.related_keys),
            ("active", self.active),
        ] {
            w.put(b",\"")?;
            w.put(name.as_bytes())?;
            w.put(if on { b"\":true" } else { b"\":false" })?;
        }
        w.put(b",\"addrs\":[")?;
        for (i, a) in self.whitelist.iter().enumerate() {
            if i > 0 {
                w.put(b",")?;
            }
            w.put(b"\"")?;
            w.put(a.as_bytes())?;
            w.put(b"\"")?;
        }
        w.put(b"]")?;
        if !self.violation.is_empty() {
            w.put(b",\"viol\":\"")?;
            w.put(self.violation.as_bytes())?;
            w.put(b"\"")?;
        }
        w.put(b"}")?;
        let n = w.at;
        core::str::from_utf8(&out[..n]).ok()
    }

    /// Whether anything at all is limited: a policy with no rule set is one that allows
    /// every transaction, and activating it hobbles the device for nothing.
    pub fn has_rules(&self) -> bool {
        self.magnitude > 0 || self.velocity > 0 || !self.whitelist.is_empty()
    }

    /// Add an address to the whitelist, trimmed. Says why not.
    pub fn add_address(&mut self, address: &str) -> Result<(), AddError> {
        let text = address.trim();
        if !valid_address(text) {
            return Err(AddError::NotAnAddress);
        }
        if self.whitelist.iter().any(|a| same_address(a, text)) {
            return Err(AddError::Duplicate);
        }
        let mut owned: heapless::String<MAX_ADDRESS> = heapless::String::new();
        owned.push_str(text).map_err(|_| AddError::NotAnAddress)?;
        self.whitelist.push(owned).map_err(|_| AddError::Full)
    }
}

/// Why an address was not added to the whitelist.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum AddError {
    NotAnAddress,
    Duplicate,
    Full,
}

impl AddError {
    pub fn text(self) -> &'static str {
        match self {
            AddError::NotAnAddress => "not an address",
            AddError::Duplicate => "already listed",
            AddError::Full => "whitelist is full",
        }
    }
}

/// Whether `s` has the shape of a Bitcoin address: base58 or bech32 characters only,
/// within the lengths either can have. The syntax, not the checksum: the firmware shows
/// what it stores, and a whitelist that refuses a valid address of a kind this parser did
/// not anticipate is worse than one that admits a typo the owner can see.
pub fn valid_address(s: &str) -> bool {
    if s.len() < MIN_ADDRESS || s.len() > MAX_ADDRESS {
        return false;
    }
    let bytes = s.as_bytes();
    if is_bech32_prefix(s) {
        // The data part is lower or upper case, never mixed; the check below admits
        // either, and `same_address` compares them case-blind.
        let lower = bytes.iter().any(|b| b.is_ascii_lowercase());
        let upper = bytes.iter().any(|b| b.is_ascii_uppercase());
        if lower && upper {
            return false;
        }
        return bytes.iter().all(|b| b.is_ascii_alphanumeric());
    }
    // Base58: no 0, O, I, l.
    bytes
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() && !matches!(b, b'0' | b'O' | b'I' | b'l'))
}

/// Whether `s` starts as a bech32 address of one of the networks this device speaks.
fn is_bech32_prefix(s: &str) -> bool {
    let lower =
        |p: &str| s.len() > p.len() && s.as_bytes()[..p.len()].eq_ignore_ascii_case(p.as_bytes());
    lower("bc1") || lower("tb1") || lower("bcrt1")
}

/// Whether two addresses name the same destination: byte-equal, or bech32 in the other
/// case. Base58 is case-sensitive and compared as such.
pub fn same_address(a: &str, b: &str) -> bool {
    if is_bech32_prefix(a) && is_bech32_prefix(b) {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

/// Whether text may be stored unescaped: printable ASCII with no quote or backslash.
pub fn storable_text(s: &str) -> bool {
    s.bytes()
        .all(|b| (0x20..0x7f).contains(&b) && b != b'"' && b != b'\\')
}

/// A bounded byte writer for [`Policy::render`].
struct Writer<'o> {
    out: &'o mut [u8],
    at: usize,
}

impl Writer<'_> {
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

// ---------------------------------------------------------------------------------------
// The check
// ---------------------------------------------------------------------------------------

/// One output of the transaction being judged.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Out<'a> {
    pub index: usize,
    pub amount: u64,
    /// Change back to this wallet, proven -- never counted as leaving.
    pub change: bool,
    /// The address, or empty for a script that has none.
    pub address: &'a str,
}

/// Why a transaction is refused.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Violation {
    /// More leaves than the cap allows.
    Magnitude { sending: u64, cap: u64 },
    /// An output pays somewhere the whitelist does not name.
    NotWhitelisted { index: usize },
    /// An output carries value to a script with no address, under a whitelist.
    NoAddress { index: usize },
    /// Velocity is limited and the transaction names no block height to measure by.
    NoHeight,
    /// Too soon after the last spend.
    TooSoon { height: u32, allowed_at: u32 },
    /// The policy itself will not read, so nothing can be allowed.
    Damaged,
    /// The review raised a warning (an unusual sighash, a fee over the warning level).
    /// Co-signing refuses any transaction with one, as stock's policy does.
    /// Source: hw-reference/ccc-key-storage.md §3 "rejects any PSBT with warnings" [C]
    Warnings,
    /// The policy was enrolled in Web 2FA on another firmware. This one does not speak it
    /// (Coinkite's closed service), so the rule can never be met here.
    Web2fa,
}

impl Violation {
    /// The refusal as one line, for the screen and for `viol`.
    pub fn describe(self) -> heapless::String<MAX_VIOLATION> {
        use core::fmt::Write as _;
        let mut s = heapless::String::new();
        let _ = match self {
            Violation::Magnitude { sending, cap } => {
                write!(s, "over cap: {sending} > {cap} sat")
            }
            Violation::NotWhitelisted { index } => write!(s, "output {index} not whitelisted"),
            Violation::NoAddress { index } => write!(s, "output {index} has no address"),
            Violation::NoHeight => write!(s, "velocity: no block height in tx"),
            Violation::TooSoon { height, allowed_at } => {
                write!(s, "velocity: block {height} < {allowed_at}")
            }
            Violation::Damaged => write!(s, "policy unreadable"),
            Violation::Warnings => write!(s, "transaction has warnings"),
            Violation::Web2fa => write!(s, "needs Web 2FA, not supported"),
        };
        s
    }
}

/// What an allowed transaction leaves behind.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Allowed {
    /// The height to record as the last spend's, when velocity is limited.
    pub record_height: Option<u32>,
}

/// The rules, applied one output at a time so a transaction of any length can be judged
/// a page at a time; [`Checker::finish`] adds the totals.
pub struct Checker<'p> {
    policy: &'p Policy,
    first: Option<Violation>,
}

impl<'p> Checker<'p> {
    pub fn new(policy: &'p Policy) -> Self {
        Checker {
            policy,
            first: None,
        }
    }

    /// Judge one output. Change is never looked at; a zero-value output with no address
    /// (an `OP_RETURN`) carries nothing away and is let through.
    pub fn output(&mut self, out: Out<'_>) {
        if self.first.is_some() || out.change || self.policy.whitelist.is_empty() {
            return;
        }
        if out.address.is_empty() {
            if out.amount > 0 {
                self.first = Some(Violation::NoAddress { index: out.index });
            }
            return;
        }
        let listed = self
            .policy
            .whitelist
            .iter()
            .any(|a| same_address(a, out.address));
        if !listed {
            self.first = Some(Violation::NotWhitelisted { index: out.index });
        }
    }

    /// The totals: `sending` is everything leaving the wallet, change excluded; `height`
    /// is the block height the transaction's lock time names, if it names one.
    ///
    /// # Why the lock time is the height
    ///
    /// The device has no clock and no chain, so "how many blocks since the last spend" has
    /// to come from the transaction. A host that wants a transaction to spend now sets
    /// its `nLockTime` to the current height (the anti-fee-sniping convention every
    /// wallet follows), and a host that lies forward only makes its own transaction
    /// invalid until that height comes -- so the number is self-limiting, which is what
    /// makes it usable. Stock measures velocity by "block-height" and this is the height
    /// a transaction carries. A transaction with no height lock, or a time lock, is
    /// refused under a velocity limit rather than measured against a guess.
    /// Source: hw-reference/firmware-features.md §8 "block-height velocity" [C]; that the
    /// PSBT's lock time is the measure `[I]`
    pub fn finish(self, sending: u64, height: Option<u32>) -> Result<Allowed, Violation> {
        if let Some(v) = self.first {
            return Err(v);
        }
        let p = self.policy;
        if p.magnitude > 0 && sending > p.magnitude {
            return Err(Violation::Magnitude {
                sending,
                cap: p.magnitude,
            });
        }
        if p.velocity == 0 {
            return Ok(Allowed {
                record_height: None,
            });
        }
        let Some(height) = height.filter(|h| *h > 0) else {
            return Err(Violation::NoHeight);
        };
        if p.last_height > 0 {
            let allowed_at = p.last_height.saturating_add(p.velocity);
            if height < allowed_at {
                return Err(Violation::TooSoon { height, allowed_at });
            }
        }
        Ok(Allowed {
            record_height: Some(height),
        })
    }
}

/// [`Checker`] over a whole transaction at once.
pub fn check(
    policy: &Policy,
    outputs: &[Out<'_>],
    sending: u64,
    height: Option<u32>,
) -> Result<Allowed, Violation> {
    let mut c = Checker::new(policy);
    for o in outputs {
        c.output(*o);
    }
    c.finish(sending, height)
}

// ---------------------------------------------------------------------------------------
// Hobbled mode: which rows survive
// ---------------------------------------------------------------------------------------

/// Which of the firmware's menus a row is on.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Menu {
    Main,
    Settings,
    Utils,
    /// The key menu: which wallet is in force.
    Derive,
}

/// The policy's own allowances, which decide the optional rows.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Allow {
    pub notes: bool,
    pub related_keys: bool,
}

/// Whether a menu row is offered while hobbled.
///
/// A filter over the ordinary menus rather than a second menu tree, so a row cannot exist
/// in one and be forgotten in the other. The rows are this firmware's own labels; what
/// each stands for in stock's map is noted where it is not obvious.
/// Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §B4 HobbledTopMenu [C]; where our
/// drawers differ from stock's, which of ours a row lands in is `[I]`
pub fn hobbled_row(menu: Menu, label: &str, allow: Allow) -> bool {
    match menu {
        Menu::Main => match label {
            // Ready To Sign, Address Explorer, Scan Any QR Code, Advanced/Tools, Secure
            // Logout; Help is ours, a row on the mono boards. (The Q1 has no Help row: its
            // help is the strip at the foot of each screen, which this filter never sees
            // and which writes nothing, so it stays in a hobbled device too.)
            "Sign" | "Addresses" | "Scan QR" | "Utils" | "Settings" | "Help" | "Logout" => true,
            // Only while test-driving; the firmware adds the row itself.
            "EXIT TEST DRIVE" => true,
            // `Secure Notes & Passwords` under `sssp_allow_notes`.
            "Notes" => allow.notes,
            // `Type Passwords` under `emu` and `sssp_related_keys`; `Passphrase` and
            // `Temporary Seed` under `sssp_related_keys` -- both are under Derive here.
            "Type Passwords" | "Derive" => allow.related_keys,
            // The wallet-in-force header row, on the boards that show one.
            l if l.starts_with(['[', '<']) => true,
            _ => false,
        },
        // Stock's hobbled menu has no Settings drawer at all. Ours keeps the drawer for
        // About (stock's View Identity and Show FW Version live under Advanced/Tools) and
        // Help (a row on the mono boards, the strip on the Q1), and Passphrase under
        // Related Keys; every preference row goes, because a
        // hobbled device refuses to save them. `[I]`
        Menu::Settings => match label {
            "About" | "Help" => true,
            "Passphrase" => allow.related_keys,
            _ => false,
        },
        // HobbledAdvancedMenu: File Management (Sign Text File, Batch Sign, List Files,
        // Export Wallet, Verify Sig File, file shares, Format SD Card, Format RAM Disk),
        // Export Wallet, View Identity, Paper Wallets, NFC Tools, WIF Store (related
        // keys), Show FW Version. Upgrade Firmware is kept: an upgrade is a signed image
        // the bootloader checks, not a wallet secret. Backup goes, as stock drops it.
        Menu::Utils => match label {
            "Export wallet" | "Paper wallet" | "Browse files" | "SD card" | "Format"
            | "Delete PSBTs" | "NFC Tools" | "Upgrade Firmware" | "Help" | "USB Drive"
            | "Analyze RNG" | "Games" => true,
            "WIF Store" => allow.related_keys,
            _ => false,
        },
        // Reached only under Related Keys: passphrase wallets, temporary seeds and the
        // vault (stock's EphemeralSeedMenu and Seed Vault). BIP-85 and Seed XOR derive
        // *from* the seed and are stock's Derive Seeds / Seed Functions, which hobbled
        // mode does not offer.
        Menu::Derive => {
            allow.related_keys
                && matches!(
                    label,
                    "Back to root" | "Passphrase" | "Import key" | "New words" | "Key vault"
                )
        }
    }
}

/// Whether a wallet-settings key may be written while hobbled.
///
/// Only the policy's own object -- for the last violation and the last spend height --
/// and the identity keys every save adds to a file that lacks them. Everything else a
/// hobbled owner could write is a preference or a store the policy exists to freeze.
///
/// The co-signing key's object and its last refusal are the one exception outside the
/// single-signer policy's own: a co-signature under an active single-signer policy still
/// has to record the height it spent at. No screen that changes them is reachable while
/// hobbled.
pub fn may_save(key: &str) -> bool {
    matches!(
        key,
        KEY | "chain" | "xfp" | "words" | "xpub" | crate::ccc::KEY | crate::ccc::VIOLATION_KEY
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const BTC: u64 = 100_000_000;
    const A1: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const A2: &str = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
    const A3: &str = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";

    fn doc(json: &str) -> Doc<'_> {
        Doc::parse(json.as_bytes()).unwrap()
    }

    fn out(index: usize, amount: u64, change: bool, address: &str) -> Out<'_> {
        Out {
            index,
            amount,
            change,
            address,
        }
    }

    // --- storage ---------------------------------------------------------------------

    /// Parsing into a policy that held another one reads exactly what `parse_object`
    /// reads, and a torn object leaves the defaults -- not the rules read before the tear,
    /// and not the ones the policy held before.
    #[test]
    fn parse_into_matches_parse_and_a_torn_one_leaves_defaults() {
        let mut held = Policy {
            magnitude: 7,
            velocity: 3,
            last_height: 9,
            word_check: true,
            allow_notes: true,
            related_keys: true,
            active: true,
            ..Policy::default()
        };
        held.add_address(A3).unwrap();
        let _ = held.violation.push_str("old");

        let raw = format!(r#"{{"mag":{BTC},"vel":6,"active":true,"addrs":["{A1}","{A2}"]}}"#);
        assert!(parse_object_into(&raw, &mut held));
        assert_eq!(Some(held.clone()), parse_object(&raw));

        let torn = format!(r#"{{"mag":5,"addrs":["{A1}","not an address"]}}"#);
        assert!(!parse_object_into(&torn, &mut held));
        assert_eq!(held, Policy::default());
        assert_eq!(parse_object(&torn), None);
    }

    #[test]
    fn absent_is_absent_and_a_policy_round_trips() {
        assert_eq!(read(&doc("{}")), Read::Absent);
        assert_eq!(read(&doc(r#"{"sssp":{"mag":1}}"#)), Read::Absent);

        let mut p = Policy {
            magnitude: 3 * BTC,
            velocity: 144,
            last_height: 850_000,
            word_check: true,
            allow_notes: true,
            related_keys: false,
            active: true,
            ..Policy::default()
        };
        p.add_address(A1).unwrap();
        p.add_address(A2).unwrap();
        p.violation.push_str("over cap: 5 > 3").unwrap();
        let mut buf = [0u8; 512];
        let text = p.render(&mut buf).unwrap().to_owned();
        let json = format!(r#"{{"nick":"x","{KEY}":{text}}}"#);
        assert_eq!(read(&doc(&json)), Read::Policy(p));
    }

    #[test]
    fn a_fresh_object_reads_as_the_defaults() {
        let Read::Policy(p) = read(&doc(r#"{"cat_sssp":{}}"#)) else {
            panic!()
        };
        assert_eq!(p, Policy::default());
        assert!(!p.active);
        assert!(!p.has_rules());
    }

    /// Damage is never "off": a torn or foreign value under our key allows nothing.
    #[test]
    fn anything_malformed_is_damaged_not_absent() {
        for json in [
            r#"{"cat_sssp":1}"#,
            r#"{"cat_sssp":"x"}"#,
            r#"{"cat_sssp":{"mag":"1"}}"#,
            r#"{"cat_sssp":{"mag":-1}}"#,
            r#"{"cat_sssp":{"vel":99999999}}"#,
            r#"{"cat_sssp":{"last":4294967296}}"#,
            r#"{"cat_sssp":{"active":"yes"}}"#,
            r#"{"cat_sssp":{"addrs":"bc1q"}}"#,
            r#"{"cat_sssp":{"addrs":[1]}}"#,
            r#"{"cat_sssp":{"addrs":["not an address"]}}"#,
            r#"{"cat_sssp":{"viol":1}}"#,
            r#"{"cat_sssp":{"viol":"a\"b"}}"#,
        ] {
            assert_eq!(read(&doc(json)), Read::Damaged, "{json}");
        }
    }

    #[test]
    fn stocks_habit_of_one_and_zero_reads_as_a_flag() {
        let Read::Policy(p) = read(&doc(r#"{"cat_sssp":{"active":1,"words":0}}"#)) else {
            panic!()
        };
        assert!(p.active);
        assert!(!p.word_check);
    }

    #[test]
    fn the_whitelist_is_bounded_at_twenty_five() {
        const B58: &[u8] = b"123456789abcdefghijkmnpqrstuvwxyz";
        let addresses: Vec<String> = (0..MAX_WHITELIST + 1)
            .map(|i| format!("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNV{}", B58[i] as char))
            .collect();
        let mut p = Policy::default();
        for a in &addresses[..MAX_WHITELIST] {
            p.add_address(a).unwrap();
        }
        assert_eq!(
            p.add_address(&addresses[MAX_WHITELIST]),
            Err(AddError::Full)
        );
        // Read back the same bound: a list one too long is damage.
        let list: Vec<String> = addresses.iter().map(|a| format!("\"{a}\"")).collect();
        let json = format!(r#"{{"cat_sssp":{{"addrs":[{}]}}}}"#, list.join(","));
        assert_eq!(read(&doc(&json)), Read::Damaged);
        let json = format!(
            r#"{{"cat_sssp":{{"addrs":[{}]}}}}"#,
            list[..MAX_WHITELIST].join(",")
        );
        assert!(matches!(read(&doc(&json)), Read::Policy(_)));
    }

    #[test]
    fn addresses_are_checked_and_deduplicated_case_blind_for_bech32() {
        let long = "x".repeat(91);
        let upper = A1.to_ascii_uppercase();
        let mut p = Policy::default();
        assert_eq!(p.add_address("hello"), Err(AddError::NotAnAddress));
        assert_eq!(
            p.add_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNV0l"),
            Err(AddError::NotAnAddress)
        );
        assert_eq!(
            p.add_address("bc1qMIXEDcase0000000000000000000"),
            Err(AddError::NotAnAddress)
        );
        assert_eq!(p.add_address(&long), Err(AddError::NotAnAddress));
        p.add_address(A1).unwrap();
        assert_eq!(p.add_address(&upper), Err(AddError::Duplicate));
        assert_eq!(p.add_address(A1), Err(AddError::Duplicate));
        p.add_address(A3).unwrap();
        assert_eq!(
            p.add_address(" 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy "),
            Err(AddError::Duplicate)
        );
        assert_eq!(p.whitelist.len(), 2);
    }

    #[test]
    fn violation_text_is_bounded_and_storable() {
        let v = Violation::Magnitude {
            sending: u64::MAX,
            cap: u64::MAX,
        };
        let t = v.describe();
        assert!(t.len() <= MAX_VIOLATION);
        assert!(storable_text(&t));
        for v in [
            Violation::NotWhitelisted { index: 99_999 },
            Violation::NoAddress { index: 0 },
            Violation::NoHeight,
            Violation::Warnings,
            Violation::Web2fa,
            Violation::TooSoon {
                height: u32::MAX,
                allowed_at: u32::MAX,
            },
            Violation::Damaged,
        ] {
            assert!(storable_text(&v.describe()));
        }
    }

    #[test]
    fn render_refuses_a_buffer_too_small() {
        let mut p = Policy::default();
        p.add_address(A1).unwrap();
        let mut small = [0u8; 40];
        assert!(p.render(&mut small).is_none());
    }

    // --- the check -------------------------------------------------------------------

    #[test]
    fn no_rules_allows_everything() {
        let p = Policy::default();
        let outs = [out(0, 5 * BTC, false, ""), out(1, 1, false, A2)];
        assert_eq!(
            check(&p, &outs, 5 * BTC + 1, None),
            Ok(Allowed {
                record_height: None
            })
        );
    }

    #[test]
    fn magnitude_caps_what_leaves_and_change_does_not_count() {
        let p = Policy {
            magnitude: BTC,
            ..Policy::default()
        };
        // Exactly the cap passes; one satoshi over does not.
        assert!(check(&p, &[], BTC, None).is_ok());
        assert_eq!(
            check(&p, &[], BTC + 1, None),
            Err(Violation::Magnitude {
                sending: BTC + 1,
                cap: BTC
            })
        );
        // The caller's `sending` already excludes change; an output marked change is
        // never inspected here whatever its size.
        let outs = [out(0, 10 * BTC, true, A1)];
        assert!(check(&p, &outs, BTC / 2, None).is_ok());
    }

    #[test]
    fn magnitude_zero_is_no_limit() {
        let p = Policy {
            magnitude: 0,
            ..Policy::default()
        };
        assert!(check(&p, &[], u64::MAX, None).is_ok());
    }

    #[test]
    fn whitelist_requires_every_paying_output_to_be_listed() {
        let mut p = Policy::default();
        p.add_address(A1).unwrap();
        p.add_address(A2).unwrap();
        assert!(check(&p, &[out(0, 1, false, A1), out(1, 1, false, A2)], 2, None).is_ok());
        // Case-blind for bech32.
        let upper = A1.to_ascii_uppercase();
        assert!(check(&p, &[out(0, 1, false, &upper)], 1, None).is_ok());
        assert_eq!(
            check(&p, &[out(0, 1, false, A1), out(1, 1, false, A3)], 2, None),
            Err(Violation::NotWhitelisted { index: 1 })
        );
        // Change is exempt, whatever it pays.
        assert!(check(&p, &[out(0, 1, false, A1), out(1, 1, true, A3)], 1, None).is_ok());
        // A script with no address and value is refused; a zero-value one (OP_RETURN) is
        // not paying anyone.
        assert_eq!(
            check(&p, &[out(0, 1, false, "")], 1, None),
            Err(Violation::NoAddress { index: 0 })
        );
        assert!(check(&p, &[out(0, 0, false, "")], 0, None).is_ok());
        // The first offending output is the one named.
        assert_eq!(
            check(&p, &[out(3, 1, false, A3), out(7, 1, false, "")], 2, None),
            Err(Violation::NotWhitelisted { index: 3 })
        );
    }

    #[test]
    fn an_empty_whitelist_is_no_whitelist() {
        let p = Policy::default();
        assert!(check(&p, &[out(0, 1, false, A3), out(1, 1, false, "")], 2, None).is_ok());
    }

    #[test]
    fn velocity_needs_a_height_and_never_guesses_one() {
        let p = Policy {
            magnitude: BTC,
            velocity: 144,
            ..Policy::default()
        };
        assert_eq!(check(&p, &[], 1, None), Err(Violation::NoHeight));
        assert_eq!(check(&p, &[], 1, Some(0)), Err(Violation::NoHeight));
        // First spend ever: any height, and it is recorded.
        assert_eq!(
            check(&p, &[], 1, Some(850_000)),
            Ok(Allowed {
                record_height: Some(850_000)
            })
        );
    }

    #[test]
    fn velocity_allows_one_spend_per_window() {
        let p = Policy {
            magnitude: BTC,
            velocity: 144,
            last_height: 850_000,
            ..Policy::default()
        };
        assert_eq!(
            check(&p, &[], 1, Some(850_143)),
            Err(Violation::TooSoon {
                height: 850_143,
                allowed_at: 850_144
            })
        );
        assert_eq!(
            check(&p, &[], 1, Some(850_144)),
            Ok(Allowed {
                record_height: Some(850_144)
            })
        );
        // Earlier than the last spend is "too soon" too: a host cannot roll back.
        assert!(matches!(
            check(&p, &[], 1, Some(1)),
            Err(Violation::TooSoon { .. })
        ));
        // Saturates rather than wrapping at the top of the range.
        let top = Policy {
            velocity: MAX_VELOCITY,
            last_height: u32::MAX - 1,
            ..p.clone()
        };
        assert!(matches!(
            check(&top, &[], 1, Some(u32::MAX - 1)),
            Err(Violation::TooSoon { .. })
        ));
    }

    #[test]
    fn velocity_off_records_nothing() {
        let p = Policy {
            magnitude: BTC,
            ..Policy::default()
        };
        assert_eq!(
            check(&p, &[], 1, Some(850_000)),
            Ok(Allowed {
                record_height: None
            })
        );
    }

    #[test]
    fn the_first_violation_found_wins_and_whitelist_comes_before_totals() {
        let mut p = Policy {
            magnitude: 1,
            velocity: 1,
            ..Policy::default()
        };
        p.add_address(A1).unwrap();
        assert_eq!(
            check(&p, &[out(0, 5, false, A3)], 5, None),
            Err(Violation::NotWhitelisted { index: 0 })
        );
        assert_eq!(
            check(&p, &[out(0, 5, false, A1)], 5, None),
            Err(Violation::Magnitude { sending: 5, cap: 1 })
        );
        assert_eq!(
            check(&p, &[out(0, 1, false, A1)], 1, None),
            Err(Violation::NoHeight)
        );
    }

    // --- hobbled rows ----------------------------------------------------------------

    #[test]
    fn hobbled_main_menu_keeps_signing_and_addresses_and_drops_the_seed() {
        let none = Allow::default();
        for l in [
            "Sign",
            "Addresses",
            "Utils",
            "Settings",
            "Help",
            "Logout",
            "Scan QR",
        ] {
            assert!(hobbled_row(Menu::Main, l, none), "{l}");
        }
        for l in ["Derive", "Notes", "Type Passwords", "New", "Import"] {
            assert!(!hobbled_row(Menu::Main, l, none), "{l}");
        }
        assert!(hobbled_row(Menu::Main, "[0123ABCD]", none));
        assert!(hobbled_row(Menu::Main, "<0123ABCD>", none));
        assert!(hobbled_row(Menu::Main, "EXIT TEST DRIVE", none));
        let notes = Allow {
            notes: true,
            ..none
        };
        assert!(hobbled_row(Menu::Main, "Notes", notes));
        assert!(!hobbled_row(Menu::Main, "Derive", notes));
        let related = Allow {
            related_keys: true,
            ..none
        };
        assert!(hobbled_row(Menu::Main, "Derive", related));
        assert!(hobbled_row(Menu::Main, "Type Passwords", related));
        assert!(!hobbled_row(Menu::Main, "Notes", related));
    }

    #[test]
    fn hobbled_settings_keeps_only_what_writes_nothing() {
        let none = Allow::default();
        for l in ["About", "Help"] {
            assert!(hobbled_row(Menu::Settings, l, none), "{l}");
        }
        for l in [
            "Login",
            "Passphrase",
            "Multisig",
            "Spending Policy",
            "Idle timeout",
            "Display units",
            "Max network fee",
            "Danger zone",
            "Debug",
            "Secure notes",
            "Hardware On/Off",
        ] {
            assert!(!hobbled_row(Menu::Settings, l, none), "{l}");
        }
        assert!(hobbled_row(
            Menu::Settings,
            "Passphrase",
            Allow {
                related_keys: true,
                ..none
            }
        ));
    }

    #[test]
    fn hobbled_utils_keeps_files_and_exports_and_drops_backup() {
        let none = Allow::default();
        for l in [
            "Export wallet",
            "Paper wallet",
            "Browse files",
            "SD card",
            "Format",
            "Delete PSBTs",
            "NFC Tools",
            "Upgrade Firmware",
            "Help",
        ] {
            assert!(hobbled_row(Menu::Utils, l, none), "{l}");
        }
        for l in ["Backup", "WIF Store", "Encrypt card"] {
            assert!(!hobbled_row(Menu::Utils, l, none), "{l}");
        }
        assert!(hobbled_row(
            Menu::Utils,
            "WIF Store",
            Allow {
                related_keys: true,
                ..none
            }
        ));
    }

    #[test]
    fn hobbled_derive_exists_only_under_related_keys_and_never_derives() {
        let related = Allow {
            related_keys: true,
            notes: false,
        };
        for l in [
            "Back to root",
            "Passphrase",
            "Import key",
            "New words",
            "Key vault",
        ] {
            assert!(hobbled_row(Menu::Derive, l, related), "{l}");
            assert!(!hobbled_row(Menu::Derive, l, Allow::default()), "{l}");
        }
        for l in ["BIP-85", "XOR split", "XOR join"] {
            assert!(!hobbled_row(Menu::Derive, l, related), "{l}");
        }
    }

    #[test]
    fn only_the_policy_and_identity_keys_may_be_saved_while_hobbled() {
        assert!(may_save(KEY));
        for k in ["chain", "xfp", "words", "xpub"] {
            assert!(may_save(k), "{k}");
        }
        for k in [
            "cat_idle",
            "cat_fee",
            "cat_notes",
            "cat_wifs",
            "cat_secnap",
            "multisig",
        ] {
            assert!(!may_save(k), "{k}");
        }
    }
}
