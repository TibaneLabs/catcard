//! Codex32's two settings: the raw-master flag, and a partial share set saved for later.
//!
//! ```json
//! "c32": true,
//! "c32_shares": ["MS12W7F2AQQQSYQ...", "MS12W7F2CFFFGRF..."]
//! ```
//!
//! - **`c32`** says the stored secret is a raw BIP-32 master seed rather than words or an
//!   xprv. It is recomputed from the secret, never carried in a backup.
//! - **`c32_shares`** is the set a Recover or Derive was collecting when the owner chose
//!   "Save & Exit": a list of codex32 strings. It belongs to the *master's* settings, so a
//!   temporary-seed session sees the same saved set; it is cleared once the threshold is
//!   reached, and it is not in backups either.
//!
//! On a device with no wallet the settings key is derived from an all-zero secret, so a
//! saved set there is readable by anyone holding the device. The screen says so.
//!
//! Source: hw-reference/settings-nvstore-format.md §5 `c32`, `c32_shares`, MASTER_FIELDS;
//! hw-reference/codex32-format.md §Storage [C]

use crate::json::{Doc, Error, elements};

/// The raw-master flag.
pub const RAW_KEY: &str = "c32";

/// The saved partial share set.
pub const SHARES_KEY: &str = "c32_shares";

/// Settings that a backup leaves out: both are about a secret the backup already carries
/// in its own form, or about shares that are not a backup. Source: as above [C]
pub const NOT_IN_BACKUPS: &[&str] = &[RAW_KEY, SHARES_KEY];

/// Most strings kept: one set, which a threshold of nine fills.
pub const MAX_SHARES: usize = 9;

/// Longest string kept: a 127-character codex32 string.
pub const MAX_SHARE: usize = 127;

/// Room [`render`] needs for a full set: the brackets, every string in quotes, and the
/// commas between them.
pub const MAX_RENDERED: usize = 1 + MAX_SHARES * (MAX_SHARE + 3);

/// The saved strings in `doc`, as many as `out` holds. Returns how many.
///
/// A row that is not a plain string of letters and digits is skipped: the screen parses
/// and checks every string anyway, and an odd row is not worth losing the rest over.
pub fn list<'a>(doc: &Doc<'a>, out: &mut [&'a str]) -> usize {
    let Some(raw) = doc.get(SHARES_KEY) else {
        return 0;
    };
    let Ok(rows) = elements(raw) else {
        return 0;
    };
    let mut n = 0;
    for row in rows {
        let Ok(row) = row else { break };
        if n == out.len() {
            break;
        }
        if let Some(s) = row.strip_prefix('"').and_then(|r| r.strip_suffix('"'))
            && storable(s)
        {
            out[n] = s;
            n += 1;
        }
    }
    n
}

/// Whether a string can be kept: non-empty, at most [`MAX_SHARE`] bytes, letters and
/// digits only -- nothing that would need escaping.
pub fn storable(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_SHARE && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Write `shares` as the JSON array that goes under [`SHARES_KEY`]. Returns its length.
pub fn render(shares: &[&str], out: &mut [u8]) -> Result<usize, Error> {
    let mut at = 0usize;
    let mut put = |s: &[u8], at: &mut usize| -> Result<(), Error> {
        let end = *at + s.len();
        out.get_mut(*at..end)
            .ok_or(Error::Malformed { at: *at })?
            .copy_from_slice(s);
        *at = end;
        Ok(())
    };
    put(b"[", &mut at)?;
    for (i, s) in shares.iter().enumerate() {
        if !storable(s) || i >= MAX_SHARES {
            return Err(Error::Malformed { at });
        }
        put(if i == 0 { b"\"" } else { b",\"" }, &mut at)?;
        put(s.as_bytes(), &mut at)?;
        put(b"\"", &mut at)?;
    }
    put(b"]", &mut at)?;
    Ok(at)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "MS12W7F2AQQQSYQCYQ5RQWZQFPG9SCRGWPUAM077H9XN5W88";
    const C: &str = "MS12W7F2CFFFGRFURFZ6FJVFTLA4GU6AJL3SM7JJ23UZRHJU";

    #[test]
    fn a_saved_set_reads_back_as_it_was_written() {
        let mut buf = [0u8; 256];
        let n = render(&[A, C], &mut buf).unwrap();
        let mut doc = std::string::String::from(r#"{"_age":3,"c32_shares":"#);
        doc.push_str(core::str::from_utf8(&buf[..n]).unwrap());
        doc.push('}');
        let parsed = Doc::parse(doc.as_bytes()).unwrap();
        let mut out = [""; MAX_SHARES];
        assert_eq!(list(&parsed, &mut out), 2);
        assert_eq!(&out[..2], &[A, C]);
    }

    #[test]
    fn a_full_set_of_the_longest_strings_fits_the_render_buffer() {
        let long = "M".repeat(MAX_SHARE);
        let all = [long.as_str(); MAX_SHARES];
        let mut buf = [0u8; MAX_RENDERED];
        assert_eq!(render(&all, &mut buf).unwrap(), MAX_RENDERED);
    }

    #[test]
    fn an_empty_set_is_an_empty_list() {
        let mut buf = [0u8; 8];
        let n = render(&[], &mut buf).unwrap();
        assert_eq!(&buf[..n], b"[]");
        let mut out = [""; MAX_SHARES];
        assert_eq!(
            list(&Doc::parse(br#"{"c32_shares":[]}"#).unwrap(), &mut out),
            0
        );
        assert_eq!(list(&Doc::parse(br#"{"c32":true}"#).unwrap(), &mut out), 0);
    }

    #[test]
    fn a_row_that_is_not_a_plain_string_is_skipped_not_fatal() {
        let doc = format!(r#"{{"c32_shares":[1,"a\"b",{{}},"{A}"]}}"#);
        let mut out = [""; MAX_SHARES];
        let parsed = Doc::parse(doc.as_bytes()).unwrap();
        assert_eq!(list(&parsed, &mut out), 1);
        assert_eq!(out[0], A);
    }

    #[test]
    fn nothing_that_would_need_escaping_is_written() {
        let mut buf = [0u8; 64];
        assert!(render(&["ms1\"x"], &mut buf).is_err());
        assert!(render(&[""], &mut buf).is_err());
    }

    #[test]
    fn the_backup_exclusions_name_both_keys() {
        assert!(NOT_IN_BACKUPS.contains(&"c32"));
        assert!(NOT_IN_BACKUPS.contains(&"c32_shares"));
    }
}
