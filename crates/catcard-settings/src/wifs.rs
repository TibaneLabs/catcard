//! The WIF store: individual private keys kept in the settings, as a JSON array.
//!
//! Each entry is `{"n": <label>, "w": <wif>}` -- an optional name for the owner and the
//! Wallet Import Format string itself. The WIF *is* the private key, so an entry is a
//! secret; what keeps it safe at rest is that the whole settings slot is sealed
//! ([`crate::nvstore`]), and what keeps it safe in RAM is that the firmware reads and
//! writes it through leased, zeroized scratch. This module only shapes the JSON.
//!
//! # Not under a stock key
//!
//! Stock keeps a WIF store, but the settings-format document does not pin its JSON shape,
//! and inventing stock's key would risk overwriting the store of anyone whose device has
//! been stock. So these live under [`KEY`] (`ccwif`), and a stock store, wherever it is,
//! is left untouched. `[?]` -- stock's own key and layout are unknown; see
//! `docs/HARDWARE-OPEN-ITEMS.md`.
//!
//! # Identity is the WIF
//!
//! Re-importing the same key replaces its entry rather than making a second, so importing
//! twice is harmless. Two different keys are two entries even when they share a label.

use crate::json::Doc;

/// Where the store lives in the settings dictionary. **Not** a stock key; see the module
/// documentation. `[?]`
pub const KEY: &str = "ccwif";

/// Keys one device may store, matching stock's limit.
/// Source: hw-reference/firmware-features.md §7, §11 "WIF store: up to 30 keys" [C]
pub const MAX_KEYS: usize = 30;

/// Longest label this stores, in bytes. A name is a convenience, not the key; a longer one
/// is refused rather than truncated.
pub const MAX_LABEL: usize = 32;

/// One stored key: a label for the owner, and the WIF itself.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct WifEntry<'a> {
    pub label: &'a str,
    pub wif: &'a str,
}

/// Why an entry could not be stored.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// More than [`MAX_KEYS`].
    TooMany,
    /// The label or WIF holds a character this cannot store: a quote, a backslash, or a
    /// control character. Escaping them would be easy and wrong -- a WIF containing one is
    /// not a WIF, and a label containing one came from somewhere to look at, not to
    /// quietly accommodate.
    NotStorable,
    /// The label is longer than [`MAX_LABEL`].
    LabelTooLong,
    /// The buffer given to [`render`] was too small.
    Overflow,
}

/// Read the stored keys out of a settings document.
///
/// Entries that are not objects, or lack a WIF, are skipped rather than failing the list:
/// one unreadable entry must not hide the others, and the settings may have been written
/// by a version that stores more fields than this reads.
pub fn list<'a>(doc: &Doc<'a>, out: &mut [WifEntry<'a>]) -> usize {
    let Some(raw) = doc.get(KEY) else {
        return 0;
    };
    let Ok(elements) = crate::json::elements(raw) else {
        return 0;
    };
    let mut n = 0;
    for element in elements {
        if n == out.len() {
            break;
        }
        let Ok(text) = element else { break };
        let Ok(entry) = Doc::parse(text.as_bytes()) else {
            continue;
        };
        let Some(wif) = entry.get_str("w") else {
            continue;
        };
        out[n] = WifEntry {
            label: entry.get_str("n").unwrap_or(""),
            wif,
        };
        n += 1;
    }
    n
}

/// The list with `entry` added, or replacing the one with the same WIF.
///
/// Returns how many entries `out` now holds. Replacing rather than appending is what makes
/// importing the same key twice harmless.
pub fn with_added<'a>(
    existing: &[WifEntry<'a>],
    entry: WifEntry<'a>,
    out: &mut [WifEntry<'a>],
) -> Result<usize, Error> {
    if entry.label.len() > MAX_LABEL {
        return Err(Error::LabelTooLong);
    }
    if !storable(entry.wif) || !storable(entry.label) {
        return Err(Error::NotStorable);
    }
    let mut n = 0;
    let mut replaced = false;
    for w in existing {
        if n == out.len() {
            return Err(Error::TooMany);
        }
        if w.wif == entry.wif {
            out[n] = entry;
            replaced = true;
        } else {
            out[n] = *w;
        }
        n += 1;
    }
    if !replaced {
        if n == out.len() || n == MAX_KEYS {
            return Err(Error::TooMany);
        }
        out[n] = entry;
        n += 1;
    }
    Ok(n)
}

/// The list without the entry at `index`. Returns how many remain.
///
/// By position rather than by WIF: the delete screen already holds the list it is showing,
/// so it knows the row, and keying the removal on the WIF would mean carrying the secret
/// string back out of the screen only to match it again.
pub fn without_index<'a>(
    existing: &[WifEntry<'a>],
    index: usize,
    out: &mut [WifEntry<'a>],
) -> usize {
    let mut n = 0;
    for (i, w) in existing.iter().enumerate() {
        if i == index || n == out.len() {
            continue;
        }
        out[n] = *w;
        n += 1;
    }
    n
}

/// Write the list as the JSON array that goes into the settings.
pub fn render(entries: &[WifEntry<'_>], out: &mut [u8]) -> Result<usize, Error> {
    let mut at = 0usize;
    let mut put = |s: &str, at: &mut usize| -> Result<(), Error> {
        let end = *at + s.len();
        out.get_mut(*at..end)
            .ok_or(Error::Overflow)?
            .copy_from_slice(s.as_bytes());
        *at = end;
        Ok(())
    };
    put("[", &mut at)?;
    for (i, w) in entries.iter().enumerate() {
        if !storable(w.wif) || !storable(w.label) {
            return Err(Error::NotStorable);
        }
        if i > 0 {
            put(",", &mut at)?;
        }
        put("{\"n\":\"", &mut at)?;
        put(w.label, &mut at)?;
        put("\",\"w\":\"", &mut at)?;
        put(w.wif, &mut at)?;
        put("\"}", &mut at)?;
    }
    put("]", &mut at)?;
    Ok(at)
}

/// Whether a string can go into the JSON as it stands. Nothing here escapes; see
/// [`crate::wallets`], which refuses the same characters for the same reason.
fn storable(text: &str) -> bool {
    !text
        .bytes()
        .any(|b| b == b'"' || b == b'\\' || b < 0x20 || b == 0x7F)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
    const B: &str = "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf";

    fn empty() -> [WifEntry<'static>; MAX_KEYS] {
        [WifEntry { label: "", wif: "" }; MAX_KEYS]
    }

    #[test]
    fn a_rendered_store_reads_back_to_the_same_entries() {
        let entries = [
            WifEntry { label: "cold", wif: A },
            WifEntry { label: "", wif: B },
        ];
        let mut buf = [0u8; 512];
        let n = render(&entries, &mut buf).unwrap();
        let json = std::format!("{{\"{KEY}\":{}}}", core::str::from_utf8(&buf[..n]).unwrap());
        let doc = Doc::parse(json.as_bytes()).unwrap();
        let mut out = empty();
        let got = list(&doc, &mut out);
        assert_eq!(got, 2);
        assert_eq!(out[0], entries[0]);
        assert_eq!(out[1], entries[1]);
    }

    #[test]
    fn re_adding_the_same_wif_replaces_rather_than_duplicates() {
        let existing = [WifEntry { label: "old", wif: A }];
        let mut out = empty();
        let n = with_added(&existing, WifEntry { label: "new", wif: A }, &mut out).unwrap();
        assert_eq!(n, 1);
        assert_eq!(out[0], WifEntry { label: "new", wif: A });
    }

    #[test]
    fn a_different_wif_is_appended() {
        let existing = [WifEntry { label: "a", wif: A }];
        let mut out = empty();
        let n = with_added(&existing, WifEntry { label: "b", wif: B }, &mut out).unwrap();
        assert_eq!(n, 2);
    }

    #[test]
    fn the_store_caps_at_thirty() {
        // Thirty distinct WIFs so none replaces another; the thirty-first is refused.
        let distinct: std::vec::Vec<std::string::String> =
            (0..MAX_KEYS).map(|i| std::format!("wif{i}")).collect();
        let full: std::vec::Vec<WifEntry> = distinct
            .iter()
            .map(|s| WifEntry {
                label: "x",
                wif: s.as_str(),
            })
            .collect();
        let mut out = empty();
        assert_eq!(
            with_added(&full, WifEntry { label: "y", wif: B }, &mut out),
            Err(Error::TooMany)
        );
    }

    #[test]
    fn deleting_by_index_removes_the_right_one() {
        let existing = [
            WifEntry { label: "a", wif: A },
            WifEntry { label: "b", wif: B },
        ];
        let mut out = empty();
        let n = without_index(&existing, 0, &mut out);
        assert_eq!(n, 1);
        assert_eq!(out[0], existing[1]);
    }

    #[test]
    fn a_wif_with_a_quote_is_refused_not_escaped() {
        let existing: [WifEntry; 0] = [];
        let mut out = empty();
        assert_eq!(
            with_added(&existing, WifEntry { label: "", wif: "ab\"cd" }, &mut out),
            Err(Error::NotStorable)
        );
    }

    #[test]
    fn an_over_long_label_is_refused() {
        let long = "x".repeat(MAX_LABEL + 1);
        let existing: [WifEntry; 0] = [];
        let mut out = empty();
        assert_eq!(
            with_added(&existing, WifEntry { label: &long, wif: A }, &mut out),
            Err(Error::LabelTooLong)
        );
    }
}
