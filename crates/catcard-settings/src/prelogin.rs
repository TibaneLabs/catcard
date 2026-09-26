//! The login preferences kept in the pre-login settings, beside the nickname.
//!
//! Stock keeps its scrambled keypad and login countdown there too, as `rngk` and `lgto`
//! (hw-reference/settings-nvstore-format.md §5 [C]), but the reference names those keys
//! without saying what their values look like [?]. A value written here in a shape stock
//! misread could put a stock login behind a countdown nobody chose -- so these are **our
//! own keys**, which stock ignores as it ignores every key it does not know. When stock's
//! shapes are known, reading `rngk` and `lgto` as well is an addition, not a migration.
//!
//! # Every doubt reads as off
//!
//! Both are read before the PIN, and both stand between the owner and their wallet. A
//! value that does not parse, or is out of range, means the feature is **off**: a device
//! that skips a countdown it should have run is a weaker device, and one that runs a
//! countdown it should not have -- or scrambles a keypad wrongly -- is one its owner cannot
//! get into.

use crate::json::Doc;

/// Shuffle the number row at login: `"1"` for on.
pub const SCRAMBLE: &str = "cat_rngk";
/// Calculator login (Q1): the login screen looks like a calculator, and the PIN is typed
/// into it. Our own key: stock's `calc` is a different value shape.
pub const CALC: &str = "cat_calc";
/// Wait this many minutes after a correct PIN before the menu: decimal digits, as a string.
pub const COUNTDOWN: &str = "cat_lgto";

/// The digit that, typed at login, erases the seed: `"0"` to `"9"`. Release builds only.
pub const KILL_KEY: &str = "cat_kbtn";
/// The microSD cards that let a login through: SHA-256 of each card's token, hex, joined
/// by commas. Release builds only.
pub const SD2FA: &str = "cat_sd2fa";
/// Most cards enrolled at once.
pub const SD2FA_MAX: usize = 4;
/// The token's file on the card, and its size.
pub const SD2FA_FILE: &str = "catcard.2fa";
pub const SD2FA_TOKEN_LEN: usize = 32;

/// The Q1's on-battery power-off: seconds with no key before the device turns itself
/// off while running on its batteries, as decimal digits; `"0"` is never.
///
/// **Pre-login, not per-wallet**, because stock runs it before login too: a device left
/// at its PIN prompt drains its cells as surely as one left at the menu, and there is no
/// wallet to read a setting from until the PIN is in. Our own key: stock's `batt_to` is
/// named without its home or value shape being given `[?]`.
/// Source: hw-reference/power.md §"Battery idle auto-power-off (Q1)" [C]
pub const BATT_OFF: &str = "cat_bto";

/// Stock's default: ten minutes. What an absent or unreadable value means.
/// Source: power.md §"Battery idle auto-power-off (Q1)" -- "Default `batt_to` = 10 min" [C]
pub const BATT_OFF_DEFAULT_SECONDS: u32 = 10 * 60;

/// The chooser's rows, as stock offers them: label and seconds, `0` for never.
/// Source: power.md §"Battery idle auto-power-off (Q1)" -- "30 s / 60 s / 2 / 5 / 10 /
/// 15 / 30 min / 1 h / 4 h / Never" [C]
pub const BATT_OFF_CHOICES: [(&str, u32); 10] = [
    ("30 seconds", 30),
    ("60 seconds", 60),
    ("2 minutes", 2 * 60),
    ("5 minutes", 5 * 60),
    ("10 minutes", 10 * 60),
    ("15 minutes", 15 * 60),
    ("30 minutes", 30 * 60),
    ("1 hour", 60 * 60),
    ("4 hours", 4 * 60 * 60),
    ("Never", 0),
];

/// The longest on-battery power-off read back: a day. Past it, the value is nonsense.
pub const MAX_BATT_OFF_SECONDS: u32 = 24 * 60 * 60;

/// The longest countdown offered: twenty-eight days, stock's own ceiling.
/// Source: hw-reference/firmware-features.md §"PIN & login" -- "5 min–28 days" [C]
pub const MAX_COUNTDOWN_MINUTES: u32 = 28 * 24 * 60;

/// The value's text without its quotes, if it is a string.
fn text<'a>(doc: &Doc<'a>, key: &str) -> Option<&'a str> {
    doc.get(key)?.strip_prefix('"')?.strip_suffix('"')
}

/// Whether the number row is to be shuffled at login.
pub fn scramble(doc: &Doc<'_>) -> bool {
    text(doc, SCRAMBLE) == Some("1")
}

/// Whether the login screen is the calculator (Q1). Only a literal `"1"` turns it on:
/// a screen that hides the PIN prompt behind a disguise must never appear by accident,
/// because an owner who does not know the convention cannot log in through it.
pub fn calc(doc: &Doc<'_>) -> bool {
    text(doc, CALC) == Some("1")
}

/// The login countdown in minutes, if one is set and sane. `None` is off.
pub fn countdown_minutes(doc: &Doc<'_>) -> Option<u32> {
    let t = text(doc, COUNTDOWN)?;
    if t.is_empty() || t.len() > 5 || !t.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let m: u32 = t.parse().ok()?;
    (1..=MAX_COUNTDOWN_MINUTES).contains(&m).then_some(m)
}

/// Whether the on-battery power-off has been set at all -- the key is present.
///
/// Separate from its value because "absent" is the one case a legacy per-wallet value
/// may fill in: see the firmware's migration of `cat_bidle`.
pub fn battery_off_set(doc: &Doc<'_>) -> bool {
    doc.get(BATT_OFF).is_some()
}

/// The on-battery power-off in seconds, or `None` for never.
///
/// **Doubt reads as the default, ten minutes** -- not as never, unlike the login
/// preferences above, which this module's rule reads as off. Those stand between the
/// owner and their wallet; this one only turns an unattended device off, which a press of
/// the power button undoes, and "never" read from a garbled byte would be a device that
/// drains its batteries on the desk. Only a literal `"0"` is never.
pub fn battery_off_seconds(doc: &Doc<'_>) -> Option<u32> {
    let Some(t) = text(doc, BATT_OFF) else {
        return Some(BATT_OFF_DEFAULT_SECONDS);
    };
    if t == "0" {
        return None;
    }
    if t.is_empty() || t.len() > 6 || !t.bytes().all(|b| b.is_ascii_digit()) {
        return Some(BATT_OFF_DEFAULT_SECONDS);
    }
    match t.parse::<u32>() {
        Ok(s) if (1..=MAX_BATT_OFF_SECONDS).contains(&s) => Some(s),
        _ => Some(BATT_OFF_DEFAULT_SECONDS),
    }
}

/// The kill key's digit, if one is set and is a single digit.
///
/// Doubt reads as **no kill key**. That is the one direction a misread here must never
/// go the other way: a kill key read from garbage would erase the seed of an owner who
/// never set one.
pub fn kill_key(doc: &Doc<'_>) -> Option<u8> {
    match text(doc, KILL_KEY)?.as_bytes() {
        [d @ b'0'..=b'9'] => Some(d - b'0'),
        _ => None,
    }
}

/// The enrolled cards' digests, as many as `out` holds; how many.
///
/// **Here doubt cannot simply read as off**, because off means "no card needed" and the
/// feature exists to stop exactly that. So a list that is present but malformed is still
/// *enrolled*: [`Sd2fa::Damaged`], which the login treats as a card that does not match.
/// Only an absent key, or an empty string, is off.
pub fn sd2fa(doc: &Doc<'_>, out: &mut [[u8; 32]; SD2FA_MAX]) -> Sd2fa {
    let Some(raw) = doc.get(SD2FA) else {
        return Sd2fa::Off;
    };
    let Some(t) = raw.strip_prefix('"').and_then(|t| t.strip_suffix('"')) else {
        return Sd2fa::Damaged;
    };
    if t.is_empty() {
        return Sd2fa::Off;
    }
    let mut n = 0;
    for part in t.split(',') {
        if n == SD2FA_MAX || part.len() != 64 {
            return Sd2fa::Damaged;
        }
        for (i, pair) in part.as_bytes().chunks(2).enumerate() {
            let hex = |c: u8| (c as char).to_digit(16);
            match (hex(pair[0]), hex(pair[1])) {
                (Some(a), Some(b)) => out[n][i] = (a * 16 + b) as u8,
                _ => return Sd2fa::Damaged,
            }
        }
        n += 1;
    }
    Sd2fa::Cards(n)
}

/// What the pre-login settings say about microSD 2FA.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Sd2fa {
    /// Not in use.
    Off,
    /// This many cards enrolled, their digests in the caller's buffer.
    Cards(usize),
    /// Enrolled, but the list will not read. No card can match it.
    Damaged,
}

/// The digest a card's token is enrolled under.
pub fn card_digest(token: &[u8]) -> [u8; 32] {
    use purecrypto::hash::{Digest, Sha256};
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(token));
    out
}

/// Write `digests` as the [`SD2FA`] value, into `out`. `None` if it will not fit.
pub fn render_sd2fa<'o>(digests: &[[u8; 32]], out: &'o mut [u8]) -> Option<&'o str> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let need = digests.len() * 65;
    if digests.len() > SD2FA_MAX || out.len() < need {
        return None;
    }
    let mut at = 0;
    for (i, d) in digests.iter().enumerate() {
        if i > 0 {
            out[at] = b',';
            at += 1;
        }
        for b in d {
            out[at] = HEX[(b >> 4) as usize];
            out[at + 1] = HEX[(b & 15) as usize];
            at += 2;
        }
    }
    core::str::from_utf8(&out[..at]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(json: &str) -> Doc<'_> {
        Doc::parse(json.as_bytes()).unwrap()
    }

    #[test]
    fn set_values_read_back() {
        let d = doc(r#"{"nick":"cat","cat_rngk":"1","cat_lgto":"60","cat_calc":"1"}"#);
        assert!(scramble(&d));
        assert!(calc(&d));
        assert_eq!(countdown_minutes(&d), Some(60));
    }

    /// The calculator disguise is on only when the value is exactly `"1"`: absent, `"0"`,
    /// a bare number, another word, or stock's own key all leave the plain PIN pad.
    #[test]
    fn calculator_login_needs_an_explicit_one() {
        for json in [
            r#"{}"#,
            r#"{"cat_calc":"0"}"#,
            r#"{"cat_calc":1}"#,
            r#"{"cat_calc":"on"}"#,
            r#"{"cat_calc":""}"#,
            r#"{"cat_calc":"11"}"#,
            r#"{"calc":"1"}"#,
        ] {
            assert!(!calc(&doc(json)), "{json}");
        }
        assert!(calc(&doc(r#"{"cat_calc":"1"}"#)));
    }

    /// Absent, zero, garbage, a number rather than a string, negative, too long: all off.
    #[test]
    fn anything_doubtful_is_off() {
        for json in [
            r#"{}"#,
            r#"{"cat_rngk":"0","cat_lgto":"0"}"#,
            r#"{"cat_rngk":1,"cat_lgto":60}"#,
            r#"{"cat_rngk":"yes","cat_lgto":"-5"}"#,
            r#"{"cat_rngk":"","cat_lgto":""}"#,
            r#"{"cat_lgto":"99999999999"}"#,
            r#"{"cat_lgto":"6 0"}"#,
            r#"{"cat_lgto":"40321"}"#,
        ] {
            let d = doc(json);
            assert!(!scramble(&d), "{json}");
            assert_eq!(countdown_minutes(&d), None, "{json}");
        }
    }

    /// Every row stock offers reads back as itself, "0" is never, and anything absent or
    /// doubtful is the ten-minute default -- never "never".
    #[test]
    fn the_battery_power_off_reads_back_and_doubt_is_ten_minutes() {
        for (_, secs) in BATT_OFF_CHOICES {
            let json = format!(r#"{{"cat_bto":"{secs}"}}"#);
            let want = (secs > 0).then_some(secs);
            assert_eq!(battery_off_seconds(&doc(&json)), want, "{json}");
            assert!(battery_off_set(&doc(&json)));
        }
        assert_eq!(BATT_OFF_CHOICES[4].1, BATT_OFF_DEFAULT_SECONDS);
        for json in [
            r#"{}"#,
            r#"{"cat_bto":""}"#,
            r#"{"cat_bto":600}"#,
            r#"{"cat_bto":"-5"}"#,
            r#"{"cat_bto":"ten"}"#,
            r#"{"cat_bto":"00"}"#,
            r#"{"cat_bto":"86401"}"#,
            r#"{"cat_bto":"9999999"}"#,
            r#"{"batt_to":"0"}"#,
        ] {
            assert_eq!(
                battery_off_seconds(&doc(json)),
                Some(BATT_OFF_DEFAULT_SECONDS),
                "{json}"
            );
        }
        assert!(!battery_off_set(&doc(r#"{}"#)));
        assert_eq!(
            battery_off_seconds(&doc(r#"{"cat_bto":"86400"}"#)),
            Some(86400)
        );
    }

    #[test]
    fn the_ceiling_is_inclusive() {
        let d = doc(r#"{"cat_lgto":"40320"}"#);
        assert_eq!(countdown_minutes(&d), Some(MAX_COUNTDOWN_MINUTES));
    }

    #[test]
    fn the_kill_key_is_one_digit_or_nothing() {
        assert_eq!(kill_key(&doc(r#"{"cat_kbtn":"7"}"#)), Some(7));
        assert_eq!(kill_key(&doc(r#"{"cat_kbtn":"0"}"#)), Some(0));
        for json in [
            r#"{}"#,
            r#"{"cat_kbtn":""}"#,
            r#"{"cat_kbtn":"77"}"#,
            r#"{"cat_kbtn":"x"}"#,
            r#"{"cat_kbtn":7}"#,
            r#"{"kbtn":"7"}"#,
        ] {
            assert_eq!(kill_key(&doc(json)), None, "{json}");
        }
    }

    /// Enrolled cards round-trip; absent or empty is off; anything else present is
    /// damaged -- never off, which would let a login through without its card.
    #[test]
    fn sd2fa_reads_back_and_damage_is_not_off() {
        let a = card_digest(b"card a");
        let b = card_digest(b"card b");
        let mut buf = [0u8; 200];
        let text = render_sd2fa(&[a, b], &mut buf).unwrap().to_owned();
        let json = format!(r#"{{"cat_sd2fa":"{text}"}}"#);
        let mut out = [[0u8; 32]; SD2FA_MAX];
        assert_eq!(sd2fa(&doc(&json), &mut out), Sd2fa::Cards(2));
        assert_eq!((out[0], out[1]), (a, b));

        assert_eq!(sd2fa(&doc(r#"{}"#), &mut out), Sd2fa::Off);
        assert_eq!(sd2fa(&doc(r#"{"cat_sd2fa":""}"#), &mut out), Sd2fa::Off);
        for json in [
            r#"{"cat_sd2fa":"abc"}"#,
            r#"{"cat_sd2fa":1}"#,
            r#"{"cat_sd2fa":"zz00000000000000000000000000000000000000000000000000000000000000"}"#,
        ] {
            assert_eq!(sd2fa(&doc(json), &mut out), Sd2fa::Damaged, "{json}");
        }
    }

    /// Stock's own keys are not ours to read until their shape is known.
    #[test]
    fn stocks_keys_are_left_alone() {
        let d = doc(r#"{"rngk":"1","lgto":"60"}"#);
        assert!(!scramble(&d));
        assert_eq!(countdown_minutes(&d), None);
    }
}
