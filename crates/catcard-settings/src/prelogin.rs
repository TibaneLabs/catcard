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
/// Wait this many minutes after a correct PIN before the menu: decimal digits, as a string.
pub const COUNTDOWN: &str = "cat_lgto";

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

/// The login countdown in minutes, if one is set and sane. `None` is off.
pub fn countdown_minutes(doc: &Doc<'_>) -> Option<u32> {
    let t = text(doc, COUNTDOWN)?;
    if t.is_empty() || t.len() > 5 || !t.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let m: u32 = t.parse().ok()?;
    (1..=MAX_COUNTDOWN_MINUTES).contains(&m).then_some(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(json: &str) -> Doc<'_> {
        Doc::parse(json.as_bytes()).unwrap()
    }

    #[test]
    fn set_values_read_back() {
        let d = doc(r#"{"nick":"cat","cat_rngk":"1","cat_lgto":"60"}"#);
        assert!(scramble(&d));
        assert_eq!(countdown_minutes(&d), Some(60));
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

    #[test]
    fn the_ceiling_is_inclusive() {
        let d = doc(r#"{"cat_lgto":"40320"}"#);
        assert_eq!(countdown_minutes(&d), Some(MAX_COUNTDOWN_MINUTES));
    }

    /// Stock's own keys are not ours to read until their shape is known.
    #[test]
    fn stocks_keys_are_left_alone() {
        let d = doc(r#"{"rngk":"1","lgto":"60"}"#);
        assert!(!scramble(&d));
        assert_eq!(countdown_minutes(&d), None);
    }
}
