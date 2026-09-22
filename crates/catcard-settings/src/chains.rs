//! Which chains the owner wants to see, in the order they want them.
//!
//! A multichain build carries every chain it knows; an owner who holds two of them should
//! not have to scroll past seven. So the root wallet's settings keep a list:
//!
//! ```json
//! "chains": ["BTC", "ETH", "SOL"]
//! ```
//!
//! Tickers, upper case, in display order. **Absent means all of them**, in the build's own
//! order -- the list only exists once someone has chosen. A ticker this build does not
//! carry is skipped when read and kept when written back, so a list made by a build with
//! more chains survives a trip through one with fewer.
//!
//! It lives in the **root** wallet's file, not the file of whatever key is in force: it
//! is about the device's owner, not about one of the wallets they reach from it.

use crate::json::{Doc, elements};

/// Where the list lives in the settings object.
pub const KEY: &str = "chains";

/// Most entries read. Far more than any build carries.
pub const MAX: usize = 32;

/// The tickers in `doc`'s list, in order, as many as `out` holds.
///
/// `None` if there is no list -- which means *all chains*, and is different from an empty
/// list. Entries that are not strings are skipped.
pub fn list<'a>(doc: &Doc<'a>, out: &mut [&'a str]) -> Option<usize> {
    let raw = doc.get(KEY)?;
    let items = elements(raw).ok()?;
    let mut n = 0;
    for item in items {
        if n == out.len() {
            break;
        }
        let Ok(item) = item else { break };
        let Some(t) = item.strip_prefix('"').and_then(|t| t.strip_suffix('"')) else {
            continue;
        };
        if t.is_empty() || !t.bytes().all(|b| b.is_ascii_alphanumeric()) {
            continue;
        }
        out[n] = t;
        n += 1;
    }
    Some(n)
}

/// Write `tickers` as the JSON array that goes under [`KEY`].
///
/// Refuses a ticker that is not plain ASCII letters and digits, so nothing this writes can
/// break the document another firmware reads.
pub fn render(tickers: &[&str], out: &mut [u8]) -> Option<usize> {
    let mut at = 0usize;
    let mut put = |s: &[u8], at: &mut usize| -> Option<()> {
        out.get_mut(*at..*at + s.len())?.copy_from_slice(s);
        *at += s.len();
        Some(())
    };
    put(b"[", &mut at)?;
    for (i, t) in tickers.iter().enumerate() {
        if t.is_empty() || !t.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return None;
        }
        if i > 0 {
            put(b",", &mut at)?;
        }
        put(b"\"", &mut at)?;
        put(t.as_bytes(), &mut at)?;
        put(b"\"", &mut at)?;
    }
    put(b"]", &mut at)?;
    Some(at)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(json: &str) -> Option<Vec<String>> {
        let doc = Doc::parse(json.as_bytes()).unwrap();
        let mut out = [""; MAX];
        list(&doc, &mut out).map(|n| out[..n].iter().map(|s| s.to_string()).collect())
    }

    /// No list is not an empty list: it means every chain, and the caller has to be told
    /// the difference.
    #[test]
    fn no_list_is_all_and_an_empty_list_is_none() {
        assert_eq!(read(r#"{"_age":3}"#), None);
        assert_eq!(read(r#"{"chains":[]}"#), Some(vec![]));
    }

    #[test]
    fn the_list_reads_in_order() {
        assert_eq!(
            read(r#"{"chains":["SOL","BTC","ETH"]}"#),
            Some(vec!["SOL".into(), "BTC".into(), "ETH".into()])
        );
    }

    /// A malformed entry is skipped and the rest still read.
    #[test]
    fn a_bad_entry_does_not_take_the_list_with_it() {
        assert_eq!(
            read(r#"{"chains":["BTC",7,"",{"x":1},"B\"AD","LTC"]}"#),
            Some(vec!["BTC".into(), "LTC".into()])
        );
    }

    #[test]
    fn it_renders_and_reads_back() {
        let mut buf = [0u8; 64];
        let n = render(&["BTC", "ETH", "XEP"], &mut buf).unwrap();
        let text = core::str::from_utf8(&buf[..n]).unwrap();
        assert_eq!(text, r#"["BTC","ETH","XEP"]"#);
        let doc = format!(r#"{{"chains":{text}}}"#);
        assert_eq!(
            read(&doc),
            Some(vec!["BTC".into(), "ETH".into(), "XEP".into()])
        );
        assert_eq!(render(&["B\"TC"], &mut buf), None);
    }
}
