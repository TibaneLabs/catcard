//! The threshold-signing (TSS) wallets a wallet keeps, as they sit in its settings
//! (docs/TSS.md, "Where things live").
//!
//! # What is kept here
//!
//! Each TSS wallet this device is a member of is one **share record** -- `catcard_tss`'s
//! format 3: the member's key core, the wallet's public half and the digest of its pair
//! cache. About 0.5 KB at 3 members, 1 KB at 9. The pairwise OT state signing also needs
//! is not here: it is twelve and more kilobytes per other member, and it lives in a
//! sealed cache file on the card or the Virtual Disk, which the record names by digest.
//!
//! The records are a JSON array of strings under [`KEY`], each a record in standard
//! base64 (RFC 4648 §4), in the settings of the wallet in force -- under its settings
//! encryption, like its multisig registrations and its WIF store. A record holds a secret
//! share, so what keeps it safe at rest is that the whole slot is sealed
//! ([`crate::nvstore`]); what keeps it safe in RAM is that the firmware reads and writes it
//! through leased, zeroized scratch. This module only shapes the JSON; the firmware
//! encodes and decodes the base64 and the records.
//!
//! # Not a stock key
//!
//! Stock has no threshold signing, so [`KEY`] (`cctss`) is this firmware's own.
//!
//! # Room
//!
//! A settings object is four kilobytes for everything the wallet keeps. A record is
//! about 0.7 KB of base64 at 3 members and 1.4 KB at 9, so a wallet keeps a handful at
//! most; [`render`] says so when they do not fit, and the save refuses rather than
//! dropping one.

use crate::json::Doc;

/// Where the records live in the settings dictionary. **Not** a stock key.
pub const KEY: &str = "cctss";

/// Records one wallet keeps, at most: more than the settings object has room for at any
/// size, so a bound on the arithmetic rather than a policy.
pub const MAX_KEPT: usize = 8;

/// Why the list could not be written.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// More than [`MAX_KEPT`].
    TooMany,
    /// An entry holds a character that is not base64.
    NotStorable,
    /// The buffer given to [`render`] was too small.
    Overflow,
}

/// The records kept, as their base64 text, borrowed from the settings document.
///
/// Elements that are not plain strings of base64 are skipped rather than failing the
/// list: one unreadable entry must not hide the others.
pub fn list<'a>(doc: &Doc<'a>, out: &mut [&'a str]) -> usize {
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
        let Some(inner) = text.strip_prefix('"').and_then(|t| t.strip_suffix('"')) else {
            continue;
        };
        if inner.is_empty() || !storable(inner) {
            continue;
        }
        out[n] = inner;
        n += 1;
    }
    n
}

/// Write `entries` as the JSON array that goes into the settings.
pub fn render(entries: &[&str], out: &mut [u8]) -> Result<usize, Error> {
    if entries.len() > MAX_KEPT {
        return Err(Error::TooMany);
    }
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
    for (i, e) in entries.iter().enumerate() {
        if e.is_empty() || !storable(e) {
            return Err(Error::NotStorable);
        }
        if i > 0 {
            put(",", &mut at)?;
        }
        put("\"", &mut at)?;
        put(e, &mut at)?;
        put("\"", &mut at)?;
    }
    put("]", &mut at)?;
    Ok(at)
}

/// Standard base64's alphabet and padding, nothing else: no quote or backslash can end
/// up in the JSON.
fn storable(text: &str) -> bool {
    text.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_round_trip_through_the_settings_json() {
        let a = "Q1RTawMBAQMC";
        let b = "Q1RTawMBAgMC+/==";
        let mut out = [0u8; 64];
        let n = render(&[a, b], &mut out).unwrap();
        let text = core::str::from_utf8(&out[..n]).unwrap();
        assert_eq!(text, "[\"Q1RTawMBAQMC\",\"Q1RTawMBAgMC+/==\"]");

        let mut json = [0u8; 128];
        let head = b"{\"cctss\":";
        json[..head.len()].copy_from_slice(head);
        json[head.len()..head.len() + n].copy_from_slice(&out[..n]);
        json[head.len() + n] = b'}';
        let doc = Doc::parse(&json[..head.len() + n + 1]).unwrap();
        let mut got = [""; MAX_KEPT];
        assert_eq!(list(&doc, &mut got), 2);
        assert_eq!(&got[..2], &[a, b]);
    }

    #[test]
    fn what_is_not_base64_is_neither_written_nor_read() {
        let mut out = [0u8; 64];
        for bad in ["a\"b", "a\\b", "", "a b", "é"] {
            assert_eq!(render(&[bad], &mut out), Err(Error::NotStorable), "{bad}");
        }
        assert_eq!(
            render(&["QUJD"; MAX_KEPT + 1], &mut out),
            Err(Error::TooMany)
        );
        assert_eq!(render(&["QUJD"; 4], &mut out[..10]), Err(Error::Overflow));

        let doc = Doc::parse(br#"{"cctss":["QUJD",7,{"x":1},"a\"b","","REVG"]}"#).unwrap();
        let mut got = [""; MAX_KEPT];
        assert_eq!(list(&doc, &mut got), 2);
        assert_eq!(&got[..2], &["QUJD", "REVG"]);
        assert_eq!(list(&Doc::parse(b"{}").unwrap(), &mut got), 0);
    }
}
