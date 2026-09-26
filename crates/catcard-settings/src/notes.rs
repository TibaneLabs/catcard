//! Secure Notes & Passwords: short notes and credentials kept in the settings object.
//!
//! A note is a title and a body; a password item is a title, a user name, the password,
//! a site, a free-text field, and optionally a base32 TOTP secret whose current code the
//! device can show. Everything lives in the wallet's own settings file, so it is encrypted
//! at rest under that wallet's stash and goes away with it; the firmware reads and writes
//! it through leased, zeroized scratch. This module shapes the JSON, bounds it, sorts it,
//! merges an import, and computes the TOTP codes -- the parts a host can test.
//!
//! # Not under stock's key
//!
//! Stock keeps its notes under `notes` and its opt-in flag under `secnap`, but the
//! settings-format document names those keys without pinning the value shapes
//! (hw-reference/settings-nvstore-format.md §5 `[C]` for the names, `[?]` for the shapes).
//! Writing a list stock cannot parse under stock's own key could stop a stock device from
//! opening its notes at all, so ours live under [`KEY`] (`cat_notes`) and the flag under
//! `cat_secnap`; stock's `notes` list is still *read*, for display, and never written.
//! See `docs/HARDWARE-OPEN-ITEMS.md`.
//!
//! # Two forms of an item
//!
//! An [`Item`] is either **text** -- what the owner typed, what the screen shows -- or
//! **raw**, straight out of the JSON with its quotes and escapes intact. [`Item::parse`]
//! gives the raw form; [`Item::unescape`] turns it into text; [`Item::render`] takes text
//! and escapes it. Keeping the two apart is what stops a `\n` from becoming `\\n` on the
//! second save. At the list level everything is a raw object string, so an item the owner
//! did not touch is copied byte for byte, escapes and unknown fields included.
//!
//! # TOTP
//!
//! RFC 6238 over RFC 4226: HMAC-SHA-1 of the 30-second step counter, dynamically
//! truncated, six or eight digits. The secret is base32 as every authenticator app shows
//! it (RFC 4648 §6, case-insensitive, padding optional).

use crate::json::{self, Doc};
use emjson::JsonWriter;
use emjson::io::SliceWriter;
use purecrypto::hash::{Hmac, Sha1};

/// Where our list lives in the settings object. **Not** a stock key; see the module
/// documentation. `[?]`
pub const KEY: &str = "cat_notes";

/// Stock's own list, read for display and never written. `[?]` for its value shape.
/// Source: hw-reference/settings-nvstore-format.md §5 [C] (the key name only)
pub const STOCK_KEY: &str = "notes";

/// Most items one wallet keeps. A settings slot is four kilobytes shared with everything
/// else, and the point of a bound is that "store full" is said rather than found.
pub const MAX_NOTES: usize = 20;

/// Longest title, in bytes of text.
pub const MAX_TITLE: usize = 32;
/// Longest user name.
pub const MAX_USER: usize = 64;
/// Longest password.
pub const MAX_PASSWORD: usize = 100;
/// Longest site or URL.
pub const MAX_SITE: usize = 96;
/// Longest note body, or the free text on a password item.
pub const MAX_BODY: usize = 512;
/// Longest base32 TOTP secret, in characters: forty bytes of key, which is more than any
/// issuer hands out.
pub const MAX_TOTP: usize = 64;
/// Bytes a decoded TOTP secret can take.
pub const MAX_TOTP_BYTES: usize = MAX_TOTP * 5 / 8;

/// The TOTP step every issuer uses, in seconds. Source: RFC 6238 §4 (`X = 30`) [C]
pub const TOTP_STEP: u32 = 30;

/// Which kind of item this is.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum Kind {
    /// A title and a body.
    #[default]
    Note,
    /// A credential: user, password, site, notes, optional TOTP.
    Password,
}

impl Kind {
    /// The JSON tag.
    const fn tag(self) -> &'static str {
        match self {
            Kind::Note => "note",
            Kind::Password => "pw",
        }
    }
}

/// One item, borrowed. Text or raw: see the module documentation.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Item<'a> {
    pub kind: Kind,
    pub title: &'a str,
    /// The note's body, or a password item's free text.
    pub body: &'a str,
    pub user: &'a str,
    pub password: &'a str,
    pub site: &'a str,
    /// Base32 TOTP secret; empty for none.
    pub totp: &'a str,
    /// Digits in a TOTP code: 6 or 8. Zero reads as six.
    pub digits: u8,
}

impl Default for Item<'_> {
    /// An empty note with the six-digit default, so a parsed item and a built one agree.
    fn default() -> Self {
        Item {
            kind: Kind::Note,
            title: "",
            body: "",
            user: "",
            password: "",
            site: "",
            totp: "",
            digits: 6,
        }
    }
}

/// Why an item or a list could not be stored.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// More than [`MAX_NOTES`].
    TooMany,
    /// A title must not be empty.
    NoTitle,
    /// A field is longer than its bound.
    TooLong,
    /// A field holds a control character other than newline or tab.
    NotStorable,
    /// The TOTP secret is not base32, or the digit count is not 6 or 8.
    BadTotp,
    /// The buffer given to a renderer was too small.
    Overflow,
    /// The file is not an export of ours.
    NotAnExport,
}

impl<'a> Item<'a> {
    /// Read an item out of one JSON object. The fields come back **raw**: quoted, escapes
    /// intact, `""` for absent. `None` if the object has no title.
    pub fn parse(raw: &'a str) -> Option<Self> {
        let doc = Doc::parse(raw.as_bytes()).ok()?;
        let title = doc.get("title")?;
        if !title.starts_with('"') {
            return None;
        }
        let quoted = |key: &str| {
            doc.get(key)
                .filter(|v| v.starts_with('"'))
                .unwrap_or("\"\"")
        };
        let kind = match doc.get_str("kind") {
            Some("pw") => Kind::Password,
            _ => Kind::Note,
        };
        let digits = doc.get_u64("digits").unwrap_or(0);
        Some(Item {
            kind,
            title,
            body: quoted("body"),
            user: quoted("user"),
            password: quoted("password"),
            site: quoted("site"),
            totp: quoted("totp"),
            digits: if digits == 8 { 8 } else { 6 },
        })
    }

    /// The text form of a raw item, with every field unescaped into `arena`.
    ///
    /// The arena shrinks as it is used, so each string keeps its own bytes for as long as
    /// the caller needs them. `None` if it ran out, or a field was not valid once decoded.
    pub fn unescape<'b>(&self, arena: &mut &'b mut [u8]) -> Option<Item<'b>> {
        Some(Item {
            kind: self.kind,
            title: text(arena, self.title)?,
            body: text(arena, self.body)?,
            user: text(arena, self.user)?,
            password: text(arena, self.password)?,
            site: text(arena, self.site)?,
            totp: text(arena, self.totp)?,
            digits: self.digits,
        })
    }

    /// Whether a text item can be stored, and why not if it cannot.
    pub fn check(&self) -> Result<(), Error> {
        if self.title.is_empty() {
            return Err(Error::NoTitle);
        }
        let bounds = [
            (self.title, MAX_TITLE),
            (self.body, MAX_BODY),
            (self.user, MAX_USER),
            (self.password, MAX_PASSWORD),
            (self.site, MAX_SITE),
            (self.totp, MAX_TOTP),
        ];
        for (field, max) in bounds {
            if field.len() > max {
                return Err(Error::TooLong);
            }
            if !storable(field) {
                return Err(Error::NotStorable);
            }
        }
        if !self.totp.is_empty() {
            let mut key = [0u8; MAX_TOTP_BYTES];
            if base32_decode(self.totp, &mut key).is_none() {
                return Err(Error::BadTotp);
            }
        }
        if !matches!(self.digits, 0 | 6 | 8) {
            return Err(Error::BadTotp);
        }
        Ok(())
    }

    /// Write a text item as one JSON object, escaping as it goes. Fields that are empty
    /// are left out; `digits` goes in only beside a TOTP secret.
    pub fn render(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.check()?;
        let mut w = JsonWriter::new(SliceWriter::new(out));
        self.write(&mut w).map_err(|_| Error::Overflow)?;
        Ok(w.get_ref().written().len())
    }

    fn write(&self, w: &mut JsonWriter<SliceWriter<'_>>) -> Result<(), emjson::io::BufferFull> {
        w.begin_object()?;
        w.member("title", self.title)?;
        w.member("kind", self.kind.tag())?;
        for (key, value) in [
            ("body", self.body),
            ("user", self.user),
            ("password", self.password),
            ("site", self.site),
            ("totp", self.totp),
        ] {
            if !value.is_empty() {
                w.member(key, value)?;
            }
        }
        if !self.totp.is_empty() {
            w.member("digits", &(self.digits.max(6) as u32))?;
        }
        w.end_object()
    }
}

/// Unescape one raw quoted field into the arena. An empty raw string costs nothing.
fn text<'b>(arena: &mut &'b mut [u8], raw: &str) -> Option<&'b str> {
    if raw == "\"\"" {
        return Some("");
    }
    let n = json::unescape(raw, arena).ok()?;
    let taken = core::mem::take(arena);
    let (mine, rest) = taken.split_at_mut(n);
    *arena = rest;
    core::str::from_utf8(mine).ok()
}

/// Whether text can be stored: no control characters but newline and tab, which a note
/// body legitimately holds. The writer escapes quotes and backslashes itself.
pub fn storable(s: &str) -> bool {
    !s.chars()
        .any(|c| (c.is_control() && c != '\n' && c != '\t') || c == '\u{7F}')
}

/// The raw objects under `key` in `doc`, as many as `out` holds. Returns how many.
///
/// Elements that are not objects with a title are skipped rather than failing the list:
/// one unreadable entry must not hide the others.
pub fn list<'a>(doc: &Doc<'a>, key: &str, out: &mut [&'a str]) -> usize {
    let Some(raw) = doc.get(key) else {
        return 0;
    };
    let Ok(elements) = json::elements(raw) else {
        return 0;
    };
    let mut n = 0;
    for element in elements {
        if n == out.len() {
            break;
        }
        let Ok(obj) = element else { break };
        if Item::parse(obj).is_none() {
            continue;
        }
        out[n] = obj;
        n += 1;
    }
    n
}

/// Write raw objects as the JSON array that goes into the settings.
///
/// The count is checked here, so a list that grew past [`MAX_NOTES`] by any route is
/// refused at the one place every save goes through.
pub fn render_list(items: &[&str], out: &mut [u8]) -> Result<usize, Error> {
    if items.len() > MAX_NOTES {
        return Err(Error::TooMany);
    }
    let mut w = JsonWriter::new(SliceWriter::new(out));
    let mut go = || -> Result<(), emjson::io::BufferFull> {
        w.begin_array()?;
        for item in items {
            w.raw(item)?;
        }
        w.end_array()
    };
    go().map_err(|_| Error::Overflow)?;
    Ok(w.get_ref().written().len())
}

/// The raw quoted title of a raw object, for matching.
pub fn title_of(raw: &str) -> Option<&str> {
    Item::parse(raw).map(|i| i.title)
}

/// The index of the item whose title (raw, quoted) is `title`.
pub fn find_title(items: &[&str], title: &str) -> Option<usize> {
    items.iter().position(|r| title_of(r) == Some(title))
}

/// Whether two raw objects describe the same item, field for field.
pub fn same(a: &str, b: &str) -> bool {
    match (Item::parse(a), Item::parse(b)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

/// The order that sorts `items` by title, case-insensitively, as indices into `items`.
/// Stable, so two items with one title keep their order. Returns how many were written.
pub fn sorted(items: &[&str], out: &mut [usize]) -> usize {
    let n = items.len().min(out.len());
    for (i, slot) in out.iter_mut().enumerate().take(n) {
        *slot = i;
    }
    // Insertion sort: twenty items at most, and no allocator.
    for i in 1..n {
        let mut j = i;
        while j > 0 && title_lt(items[out[j]], items[out[j - 1]]) {
            out.swap(j, j - 1);
            j -= 1;
        }
    }
    n
}

fn title_lt(a: &str, b: &str) -> bool {
    let ta = title_of(a)
        .unwrap_or("")
        .bytes()
        .map(|c| c.to_ascii_lowercase());
    let tb = title_of(b)
        .unwrap_or("")
        .bytes()
        .map(|c| c.to_ascii_lowercase());
    ta.lt(tb)
}

/// What to do with one incoming item against the list it is joining.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Merge {
    /// No item has this title: add it.
    Add,
    /// An item with this title already says the same thing: nothing to do.
    Same,
    /// An item with this title says something else; carries its index.
    Conflict(usize),
}

/// How `incoming` (a raw object) merges into `items`. `None` if it is not an item.
pub fn merge(items: &[&str], incoming: &str) -> Option<Merge> {
    let title = title_of(incoming)?;
    Some(match find_title(items, title) {
        None => Merge::Add,
        Some(i) if same(items[i], incoming) => Merge::Same,
        Some(i) => Merge::Conflict(i),
    })
}

// ---------------------------------------------------------------------------
// Export file
// ---------------------------------------------------------------------------

/// The marker that says a JSON file is one of ours.
const EXPORT_TAG: &str = "catcard_notes";

/// Write raw objects as the export file: `{"catcard_notes":1,"notes":[...]}`.
pub fn export(items: &[&str], out: &mut [u8]) -> Result<usize, Error> {
    let mut w = JsonWriter::pretty(SliceWriter::new(out), 2);
    let mut go = || -> Result<(), emjson::io::BufferFull> {
        w.begin_object()?;
        w.member(EXPORT_TAG, &1u32)?;
        w.key("notes")?;
        w.begin_array()?;
        for item in items {
            w.raw(item)?;
        }
        w.end_array()?;
        w.end_object()
    };
    go().map_err(|_| Error::Overflow)?;
    Ok(w.get_ref().written().len())
}

/// The raw `notes` array inside an export file, ready for [`json::elements`].
///
/// A file without the marker is still accepted if it has a `notes` list -- a stock export
/// or a hand-written one -- because every element is checked on its own way in.
pub fn exported(file: &[u8]) -> Result<&str, Error> {
    let doc = Doc::parse(file).map_err(|_| Error::NotAnExport)?;
    let raw = doc.get("notes").ok_or(Error::NotAnExport)?;
    if !raw.starts_with('[') {
        return Err(Error::NotAnExport);
    }
    Ok(raw)
}

// ---------------------------------------------------------------------------
// TOTP
// ---------------------------------------------------------------------------

/// Decode base32 (RFC 4648 §6) into `out`. Case-insensitive; `=` padding, spaces and
/// dashes are ignored, as authenticator apps print them. Returns the byte count, or
/// `None` for a character outside the alphabet, an empty secret, or no room.
pub fn base32_decode(text: &str, out: &mut [u8]) -> Option<usize> {
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut n = 0usize;
    let mut any = false;
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a',
            b'2'..=b'7' => c - b'2' + 26,
            b'=' | b' ' | b'-' => continue,
            _ => return None,
        };
        any = true;
        acc = (acc << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            *out.get_mut(n)? = (acc >> bits) as u8;
            acc &= (1 << bits) - 1;
            n += 1;
        }
    }
    (any && n > 0).then_some(n)
}

/// An HOTP code (RFC 4226 §5.3): HMAC-SHA-1 over the big-endian counter, dynamically
/// truncated to 31 bits, reduced to `digits` decimal digits (6 or 8).
pub fn hotp(secret: &[u8], counter: u64, digits: u8) -> u32 {
    let mac = Hmac::<Sha1>::new(secret)
        .chain(&counter.to_be_bytes())
        .finalize();
    let offset = (mac[19] & 0x0F) as usize;
    let bin = ((mac[offset] as u32 & 0x7F) << 24)
        | ((mac[offset + 1] as u32) << 16)
        | ((mac[offset + 2] as u32) << 8)
        | (mac[offset + 3] as u32);
    let modulus = if digits == 8 { 100_000_000 } else { 1_000_000 };
    bin % modulus
}

/// The TOTP code for `unix` seconds (RFC 6238 §4, `T0 = 0`), and how many seconds of
/// the current step remain.
pub fn totp(secret: &[u8], unix: u64, step: u32, digits: u8) -> (u32, u32) {
    let step = step.max(1) as u64;
    let counter = unix / step;
    let left = step - (unix % step);
    (hotp(secret, counter, digits), left as u32)
}

/// A code as its zero-padded digits.
pub fn format_code(code: u32, digits: u8) -> heapless::String<8> {
    use core::fmt::Write as _;
    let mut s = heapless::String::new();
    if digits == 8 {
        let _ = write!(s, "{code:08}");
    } else {
        let _ = write!(s, "{code:06}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(title: &'static str, body: &'static str) -> Item<'static> {
        Item {
            kind: Kind::Note,
            title,
            body,
            ..Item::default()
        }
    }

    fn rendered(item: &Item<'_>) -> std::string::String {
        let mut buf = [0u8; 1024];
        let n = item.render(&mut buf).unwrap();
        std::string::String::from_utf8(buf[..n].to_vec()).unwrap()
    }

    /// The bug the two forms exist to prevent: a body with a newline and a quote saved,
    /// read, and saved again must be the same bytes, not a growing pile of backslashes.
    #[test]
    fn a_rendered_item_reads_back_unescaped_and_re_renders_identically() {
        let item = note("shopping", "milk \"whole\"\neggs\ttab");
        let first = rendered(&item);
        let raw = Item::parse(&first).unwrap();
        assert_eq!(raw.title, "\"shopping\"");
        let mut arena_buf = [0u8; 256];
        let mut arena: &mut [u8] = &mut arena_buf;
        let text = raw.unescape(&mut arena).unwrap();
        assert_eq!(text, item);
        assert_eq!(rendered(&text), first);
    }

    #[test]
    fn a_password_item_keeps_every_field() {
        let item = Item {
            kind: Kind::Password,
            title: "mail",
            body: "recovery codes in the safe",
            user: "me@example.org",
            password: "hunter2",
            site: "https://mail.example.org",
            totp: "JBSWY3DPEHPK3PXP",
            digits: 8,
        };
        let text = rendered(&item);
        let raw = Item::parse(&text).unwrap();
        let mut arena_buf = [0u8; 512];
        let mut arena: &mut [u8] = &mut arena_buf;
        assert_eq!(raw.unescape(&mut arena).unwrap(), item);
    }

    #[test]
    fn a_note_without_a_totp_carries_no_digits_and_reads_as_six() {
        let text = rendered(&note("a", "b"));
        assert!(!text.contains("digits"));
        assert_eq!(Item::parse(&text).unwrap().digits, 6);
    }

    #[test]
    fn empty_fields_are_left_out_and_come_back_empty() {
        let text = rendered(&note("a", ""));
        assert!(!text.contains("body"));
        let raw = Item::parse(&text).unwrap();
        assert_eq!(raw.body, "\"\"");
        let mut arena_buf = [0u8; 64];
        let mut arena: &mut [u8] = &mut arena_buf;
        assert_eq!(raw.unescape(&mut arena).unwrap().body, "");
    }

    #[test]
    fn an_empty_title_is_refused() {
        assert_eq!(note("", "x").check(), Err(Error::NoTitle));
    }

    #[test]
    fn an_over_long_field_is_refused_not_truncated() {
        let long = "x".repeat(MAX_BODY + 1);
        let item = Item {
            body: &long,
            ..note("t", "")
        };
        assert_eq!(item.check(), Err(Error::TooLong));
    }

    #[test]
    fn a_control_character_is_refused_but_newline_and_tab_are_fine() {
        assert_eq!(note("t", "a\x01b").check(), Err(Error::NotStorable));
        assert_eq!(note("t", "a\nb\tc").check(), Ok(()));
    }

    #[test]
    fn a_bad_totp_secret_is_refused() {
        let item = Item {
            kind: Kind::Password,
            totp: "not base32!",
            ..note("t", "")
        };
        assert_eq!(item.check(), Err(Error::BadTotp));
        let item = Item {
            digits: 7,
            ..note("t", "")
        };
        assert_eq!(item.check(), Err(Error::BadTotp));
    }

    #[test]
    fn a_list_renders_and_lists_back_and_skips_junk() {
        let a = rendered(&note("a", "1"));
        let b = rendered(&note("b", "2"));
        let mut buf = [0u8; 512];
        let n = render_list(&[&a, "{\"nope\":1}", &b], &mut buf).unwrap();
        let json = std::format!("{{\"{KEY}\":{}}}", core::str::from_utf8(&buf[..n]).unwrap());
        let doc = Doc::parse(json.as_bytes()).unwrap();
        let mut out = [""; MAX_NOTES];
        assert_eq!(list(&doc, KEY, &mut out), 2);
        assert_eq!(out[0], a);
        assert_eq!(out[1], b);
    }

    #[test]
    fn the_list_caps_at_max_notes() {
        let a = rendered(&note("a", ""));
        let too_many = std::vec![a.as_str(); MAX_NOTES + 1];
        let mut buf = [0u8; 4096];
        assert_eq!(render_list(&too_many, &mut buf), Err(Error::TooMany));
        let just = std::vec![a.as_str(); MAX_NOTES];
        assert!(render_list(&just, &mut buf).is_ok());
    }

    #[test]
    fn a_full_buffer_is_overflow_not_a_truncated_list() {
        let a = rendered(&note("a", "some body text"));
        let mut small = [0u8; 16];
        assert_eq!(render_list(&[&a], &mut small), Err(Error::Overflow));
    }

    #[test]
    fn sorting_is_by_title_case_insensitive_and_stable() {
        let items = [
            rendered(&note("banana", "1")),
            rendered(&note("Apple", "2")),
            rendered(&note("apple", "3")),
            rendered(&note("cherry", "4")),
        ];
        let refs: std::vec::Vec<&str> = items.iter().map(|s| s.as_str()).collect();
        let mut order = [0usize; MAX_NOTES];
        let n = sorted(&refs, &mut order);
        assert_eq!(&order[..n], &[1, 2, 0, 3]);
    }

    #[test]
    fn merge_adds_skips_and_flags_conflicts_by_title() {
        let a = rendered(&note("a", "1"));
        let b = rendered(&note("b", "2"));
        let a2 = rendered(&note("a", "changed"));
        let c = rendered(&note("c", "3"));
        let existing = [a.as_str(), b.as_str()];
        assert_eq!(merge(&existing, &c), Some(Merge::Add));
        assert_eq!(merge(&existing, &a), Some(Merge::Same));
        assert_eq!(merge(&existing, &a2), Some(Merge::Conflict(0)));
        assert_eq!(merge(&existing, "[1,2]"), None);
    }

    #[test]
    fn an_export_round_trips_through_exported() {
        let a = rendered(&note("a", "line\nbreak"));
        let b = rendered(&Item {
            kind: Kind::Password,
            user: "u",
            password: "p",
            ..note("b", "")
        });
        let mut file = [0u8; 1024];
        let n = export(&[&a, &b], &mut file).unwrap();
        let raw = exported(&file[..n]).unwrap();
        let got: std::vec::Vec<&str> = json::elements(raw).unwrap().map(|e| e.unwrap()).collect();
        assert_eq!(got.len(), 2);
        assert!(same(got[0], &a));
        assert!(same(got[1], &b));
    }

    #[test]
    fn a_file_without_a_notes_list_is_not_an_export() {
        assert_eq!(exported(b"{\"x\":1}"), Err(Error::NotAnExport));
        assert_eq!(exported(b"not json"), Err(Error::NotAnExport));
        assert_eq!(exported(b"{\"notes\":\"str\"}"), Err(Error::NotAnExport));
    }

    // --- base32 (RFC 4648 §10 test vectors) ---

    #[test]
    fn base32_decodes_the_rfc_4648_vectors() {
        let cases: [(&str, &[u8]); 6] = [
            ("MY======", b"f"),
            ("MZXQ====", b"fo"),
            ("MZXW6===", b"foo"),
            ("MZXW6YQ=", b"foob"),
            ("MZXW6YTB", b"fooba"),
            ("MZXW6YTBOI======", b"foobar"),
        ];
        for (text, want) in cases {
            let mut out = [0u8; 16];
            let n = base32_decode(text, &mut out).unwrap();
            assert_eq!(&out[..n], want, "{text}");
        }
    }

    #[test]
    fn base32_is_case_insensitive_and_ignores_spaces_and_dashes() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        let na = base32_decode("mzxw 6ytb-oi", &mut a).unwrap();
        let nb = base32_decode("MZXW6YTBOI", &mut b).unwrap();
        assert_eq!(&a[..na], &b[..nb]);
    }

    #[test]
    fn base32_refuses_the_wrong_alphabet_and_nothing() {
        let mut out = [0u8; 16];
        assert_eq!(base32_decode("MZXW6YTB1", &mut out), None);
        assert_eq!(base32_decode("", &mut out), None);
        assert_eq!(base32_decode("====", &mut out), None);
        let mut tiny = [0u8; 1];
        assert_eq!(base32_decode("MZXW6YTBOI", &mut tiny), None);
    }

    // --- HOTP / TOTP (RFC 4226 Appendix D and RFC 6238 Appendix B) ---

    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn hotp_matches_the_rfc_4226_vectors() {
        let want = [
            755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
        ];
        for (counter, code) in want.iter().enumerate() {
            assert_eq!(
                hotp(RFC_SECRET, counter as u64, 6),
                *code,
                "counter {counter}"
            );
        }
    }

    #[test]
    fn totp_sha1_matches_the_rfc_6238_vectors() {
        // Appendix B, the SHA-1 column, eight digits.
        let want: [(u64, u32); 6] = [
            (59, 94287082),
            (1111111109, 7081804),
            (1111111111, 14050471),
            (1234567890, 89005924),
            (2000000000, 69279037),
            (20000000000, 65353130),
        ];
        for (t, code) in want {
            let (got, _) = totp(RFC_SECRET, t, TOTP_STEP, 8);
            assert_eq!(got, code, "T={t}");
        }
    }

    #[test]
    fn totp_says_how_long_the_step_has_left() {
        assert_eq!(totp(RFC_SECRET, 59, 30, 6).1, 1);
        assert_eq!(totp(RFC_SECRET, 60, 30, 6).1, 30);
        assert_eq!(totp(RFC_SECRET, 61, 30, 6).1, 29);
    }

    #[test]
    fn six_digit_codes_are_the_eight_digit_ones_reduced() {
        let (eight, _) = totp(RFC_SECRET, 59, TOTP_STEP, 8);
        let (six, _) = totp(RFC_SECRET, 59, TOTP_STEP, 6);
        assert_eq!(six, eight % 1_000_000);
        assert_eq!(format_code(six, 6).as_str(), "287082");
        assert_eq!(format_code(eight, 8).as_str(), "94287082");
        assert_eq!(format_code(7081804, 8).as_str(), "07081804");
    }
}
