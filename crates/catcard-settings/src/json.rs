//! The settings dictionary: reading the keys this device knows, keeping the ones it does not.
//!
//! The blob is a flat JSON object whose values can be anything -- numbers, strings, lists of
//! multisig wallets. This device understands a handful of those keys and has no business
//! understanding the rest, but it must not *lose* the rest: a settings blob written by stock
//! firmware, or by a later version of this one, carries configuration whose owner would have
//! to re-enter it.
//!
//! So a [`Doc`] is the object's keys in order, each with its value as the **raw bytes it was
//! written as**. Reading a key it knows is a lookup; everything else is there to be copied
//! out exactly as it came in. Nothing is interpreted that does not need to be.
//!
//! Parsing is [`emjson`]'s: a pull parser over the slice, no allocation, no `unsafe`, with
//! `raw_value` handing back a value's bytes zero-copy. **Changing** a value is
//! `emjson::edit`, which moves the document's tail once and leaves every other byte where it
//! was -- which is the property this store needs, and a better guarantee than rebuilding the
//! object around the change.
//!
//! No allocation here either: the entries borrow the buffer they were parsed from.

use emjson::{Parser, Token};

/// Keys one settings object can hold.
///
/// Stock's own list is about forty; this leaves room for it to grow and for keys we have
/// never heard of. A blob with more is refused rather than silently truncated.
pub const MAX_KEYS: usize = 96;

/// How deeply a value may nest, which is `emjson`'s parser stack. `multisig` is a list of
/// objects, which is two.
const MAX_DEPTH: usize = 8;

/// Why a settings object could not be read.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Not a JSON object, or malformed at this byte offset.
    Malformed { at: usize },
    /// More keys than [`MAX_KEYS`].
    TooManyKeys,
    /// Nesting deeper than this reads.
    TooDeep,
    /// The buffer given to [`unescape`] was too small.
    BufferTooSmall,
}

/// A parser whose stack is [`MAX_DEPTH`] deep, over a slice.
type Slice<'a> = Parser<emjson::SliceSource<'a>, MAX_DEPTH>;

/// Turn an `emjson` failure into ours, keeping where it happened.
fn failed<E>(e: emjson::Error<E>) -> Error {
    use emjson::ErrorKind;
    match e.kind() {
        // The parser's stack is `MAX_DEPTH`, so this is exactly "nested deeper than we read".
        Some(ErrorKind::DepthLimitExceeded) => Error::TooDeep,
        Some(ErrorKind::BufferTooSmall) => Error::BufferTooSmall,
        _ => Error::Malformed {
            at: e.offset().unwrap_or(0) as usize,
        },
    }
}

/// One key and the raw text of its value.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Entry<'a> {
    /// The key, as written between its quotes. Settings keys are plain ASCII, so nothing
    /// here decodes escapes -- [`unescape`] is for values people typed.
    pub key: &'a str,
    /// The value exactly as it appears in the object, including any quotes.
    pub raw: &'a str,
}

/// A parsed settings object.
#[derive(Clone, Debug, Default)]
pub struct Doc<'a> {
    entries: heapless::Vec<Entry<'a>, MAX_KEYS>,
}

/// The elements of a JSON array, each as the raw text it was written as.
///
/// `notes` is a list of objects, and reading it means walking the list and parsing each
/// element as its own [`Doc`]. Nothing is interpreted here either: an element comes back as
/// the bytes it was written as, so an object this firmware does not understand still comes
/// out whole.
pub struct Elements<'a> {
    parser: Slice<'a>,
    done: bool,
}

/// Walk a JSON array's elements. `raw` is the array including its brackets, as an
/// [`Entry::raw`] gives it.
pub fn elements(raw: &str) -> Result<Elements<'_>, Error> {
    let mut parser = Slice::from_slice(raw.as_bytes());
    parser.begin_array().map_err(failed)?;
    Ok(Elements {
        parser,
        done: false,
    })
}

impl<'a> Iterator for Elements<'a> {
    type Item = Result<&'a str, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.parser.has_next() {
            Ok(false) => {
                self.done = true;
                None
            }
            Err(e) => {
                self.done = true;
                Some(Err(failed(e)))
            }
            Ok(true) => Some(raw_text(&mut self.parser).inspect_err(|_| self.done = true)),
        }
    }
}

/// The next value's raw text, zero copy.
fn raw_text<'a>(p: &mut Slice<'a>) -> Result<&'a str, Error> {
    let bytes = p.raw_value().map_err(failed)?;
    core::str::from_utf8(bytes).map_err(|e| Error::Malformed {
        at: e.valid_up_to(),
    })
}

/// Copy a JSON string's text into `out` with its escapes undone, returning the byte count.
///
/// `raw` is the string as written, quotes and all. Stock's `ujson.dumps` escapes anything
/// non-ASCII as `\uXXXX`, so a note written with an accent or an emoji arrives that way and
/// is unreadable until this runs; and a note's body carries real newlines as `\n`. A lone
/// surrogate is refused rather than written out as bytes that are not UTF-8.
pub fn unescape(raw: &str, out: &mut [u8]) -> Result<usize, Error> {
    let mut p = Slice::from_slice(raw.as_bytes());
    // Not a string at all: hand back the text as it stands, so a number or `true` prints.
    if p.peek().map_err(failed)? != Token::String {
        if raw.len() > out.len() {
            return Err(Error::BufferTooSmall);
        }
        out[..raw.len()].copy_from_slice(raw.as_bytes());
        return Ok(raw.len());
    }
    Ok(p.read_str(out).map_err(failed)?.len())
}

impl<'a> Doc<'a> {
    /// An empty object, for a device with no settings yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Read an object's keys and the raw text of each value, in order.
    pub fn parse(json: &'a [u8]) -> Result<Self, Error> {
        let mut p = Slice::from_slice(json);
        p.begin_object().map_err(failed)?;
        let mut entries = heapless::Vec::new();
        while p.has_next().map_err(failed)? {
            // The key's own bytes, between its quotes: `skip_key` steps over it, and the
            // offsets either side of that are where it was.
            let from = p.offset() as usize;
            p.skip_key().map_err(failed)?;
            let to = p.offset() as usize;
            let key = json
                .get(from + 1..to - 1)
                .and_then(|k| core::str::from_utf8(k).ok())
                .ok_or(Error::Malformed { at: from })?;
            let raw = raw_text(&mut p)?;
            entries
                .push(Entry { key, raw })
                .map_err(|_| Error::TooManyKeys)?;
        }
        // Anything after the object -- a second object, trailing junk -- means this is not
        // the blob it claims to be, and reading half of it is worse than refusing it.
        p.end_object().map_err(failed)?;
        p.finish().map_err(failed)?;
        Ok(Self { entries })
    }

    /// How many keys it holds.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether it holds none.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every key and raw value, in the order they were written.
    pub fn entries(&self) -> &[Entry<'a>] {
        &self.entries
    }

    /// The raw text of `key`'s value.
    pub fn get(&self, key: &str) -> Option<&'a str> {
        self.entries.iter().find(|e| e.key == key).map(|e| e.raw)
    }

    /// `key` as an unsigned number, if it is one.
    pub fn get_u64(&self, key: &str) -> Option<u64> {
        self.get(key)?.parse().ok()
    }

    /// `key` as a string, with its quotes removed. Escapes are not decoded, so a value
    /// holding one is returned as written -- this device's own strings have none, and
    /// [`unescape`] is there for the ones people typed.
    pub fn get_str(&self, key: &str) -> Option<&'a str> {
        let raw = self.get(key)?;
        raw.strip_prefix('"')?.strip_suffix('"')
    }

    /// `key` as a boolean: JSON `true`/`false`, or stock's habit of writing `1`/`0`.
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        match self.get(key)? {
            "true" | "1" => Some(true),
            "false" | "0" => Some(false),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    /// `notes` is a list of objects, and each one has to come back whole.
    #[test]
    fn a_list_of_notes_walks_element_by_element() {
        let raw = r#"[{"title": "Wifi", "misc": "hunter2"}, {"title": "Bank", "user": "me"}]"#;
        let got: Vec<&str> = super::elements(raw).unwrap().map(|e| e.unwrap()).collect();
        assert_eq!(got.len(), 2);
        let first = Doc::parse(got[0].as_bytes()).unwrap();
        assert_eq!(first.get_str("title"), Some("Wifi"));
        assert_eq!(first.get_str("misc"), Some("hunter2"));
        let second = Doc::parse(got[1].as_bytes()).unwrap();
        assert_eq!(second.get_str("user"), Some("me"));
        // An empty list is a list, not an error: a device with the feature enabled and no
        // notes written yet has exactly this.
        assert_eq!(super::elements("[]").unwrap().count(), 0);
    }

    /// A note's body holds braces, brackets and commas, and none of them end the element.
    #[test]
    fn punctuation_inside_a_note_does_not_end_it() {
        let raw = r#"[{"title": "a}b],c", "misc": "{\"not\": \"json\"}"}, {"title": "z"}]"#;
        let got: Vec<&str> = super::elements(raw).unwrap().map(|e| e.unwrap()).collect();
        assert_eq!(got.len(), 2, "the braces in the strings are text, not structure");
        assert_eq!(
            Doc::parse(got[0].as_bytes()).unwrap().get_str("title"),
            Some("a}b],c")
        );
        assert_eq!(Doc::parse(got[1].as_bytes()).unwrap().get_str("title"), Some("z"));
    }

    /// The escapes stock writes have to come back as the text the owner typed.
    #[test]
    fn a_notes_text_comes_back_as_it_was_typed() {
        let mut out = [0u8; 64];
        let n = super::unescape(r#""line one\nline \"two\"\ttabbed""#, &mut out).unwrap();
        assert_eq!(
            core::str::from_utf8(&out[..n]).unwrap(),
            "line one\nline \"two\"\ttabbed"
        );
        // ujson escapes everything non-ASCII, so an accent arrives as \uXXXX.
        let n = super::unescape(r#""café""#, &mut out).unwrap();
        assert_eq!(core::str::from_utf8(&out[..n]).unwrap(), "café");
        // Outside the basic plane it is a surrogate pair, and the two halves make one char.
        let n = super::unescape(r#""😺""#, &mut out).unwrap();
        assert_eq!(core::str::from_utf8(&out[..n]).unwrap(), "😺");
        // A lone surrogate is not a character: refuse rather than write invalid UTF-8.
        assert!(super::unescape(r#""\ud83d""#, &mut out).is_err());
        // A value that is not a string prints as it stands.
        let n = super::unescape("true", &mut out).unwrap();
        assert_eq!(&out[..n], b"true");
        // A body longer than the screen's buffer says so instead of truncating silently.
        let mut small = [0u8; 4];
        assert_eq!(
            super::unescape(r#""much longer than four""#, &mut small),
            Err(Error::BufferTooSmall)
        );
    }

    use super::*;

    /// A blob shaped like one stock writes: numbers, strings, a nested list of objects.
    const STOCK: &[u8] = br#"{"_age": 41, "chain": "BTC", "rz": 8, "wa": 1,
        "multisig": [["nunchuk", 2, [[1234, "Zpub..."]], {"ft": 14}]],
        "accts": [[0, 0], [8, 1]], "nick": "cat \"box\"", "idle_to": 0}"#;

    #[test]
    fn the_keys_this_device_knows_are_readable() {
        let doc = Doc::parse(STOCK).unwrap();
        assert_eq!(doc.len(), 8);
        assert_eq!(doc.get_u64("_age"), Some(41));
        assert_eq!(doc.get_str("chain"), Some("BTC"));
        assert_eq!(doc.get_u64("rz"), Some(8));
        assert_eq!(doc.get_bool("wa"), Some(true));
        assert_eq!(doc.get_u64("idle_to"), Some(0));
        assert_eq!(doc.get("nope"), None);
        // A nested value comes back whole, unparsed.
        assert_eq!(doc.get("accts"), Some("[[0, 0], [8, 1]]"));
        assert!(doc.get("multisig").unwrap().starts_with("[[\"nunchuk\""));
    }




    #[test]
    fn a_string_holding_braces_or_escapes_does_not_confuse_the_scan() {
        let doc = Doc::parse(br#"{"a": "}{[\",", "b": 1}"#).unwrap();
        assert_eq!(doc.len(), 2);
        assert_eq!(doc.get("a"), Some(r#""}{[\",""#));
        assert_eq!(doc.get_u64("b"), Some(1));
    }

    /// A pre-login blob in stock's shape reads the same however it was spaced.
    ///
    /// `ujson.dumps` and `json.dumps` differ over the space after a colon, and a settings
    /// blob can have been written by either, on any firmware version. The keys and the raw
    /// values must come out identical either way.
    #[test]
    fn stock_spacing_does_not_change_what_is_read() {
        let spaced = br#"{"_age": 3, "nick": "Kitty", "terms_ok": 1, "rngk": 0}"#;
        let packed = br#"{"_age":3,"nick":"Kitty","terms_ok":1,"rngk":0}"#;
        for src in [&spaced[..], &packed[..]] {
            let doc = Doc::parse(src).unwrap();
            let keys: Vec<&str> = doc.entries().iter().map(|e| e.key).collect();
            assert_eq!(keys, ["_age", "nick", "terms_ok", "rngk"]);
            assert_eq!(doc.get_u64("_age"), Some(3));
            assert_eq!(doc.get_str("nick"), Some("Kitty"));
            assert_eq!(doc.get_bool("terms_ok"), Some(true));
        }
        // An empty nickname is a value, not a missing key: the device that prompted this
        // test held `"nick": ""`, and "set but empty" has to be tellable from "never set".
        let doc = Doc::parse(br#"{"_age":3,"nick":""}"#).unwrap();
        assert_eq!(doc.get("nick"), Some(r#""""#));
        assert_eq!(doc.get_str("nick"), Some(""));
    }

    /// An empty object is a settings blob: a device with the store formatted and nothing
    /// saved yet has exactly this, and reading it must not be an error.
    #[test]
    fn an_empty_object_is_fine() {
        let doc = Doc::parse(b"{}").unwrap();
        assert!(doc.is_empty());
        assert_eq!(doc.len(), 0);
        assert_eq!(doc.get("anything"), None);
    }

    #[test]
    fn malformed_input_is_refused_rather_than_half_read() {
        for bad in [
            &b"not json"[..],
            b"[1,2]",
            b"{",
            b"{\"a\"}",
            b"{\"a\": }",
            b"{\"a\": 1,}",
            b"{\"a\": \"unterminated}",
            b"{\"a\": 1} trailing",
        ] {
            assert!(Doc::parse(bad).is_err(), "accepted {:?}", bad);
        }
    }

    #[test]
    fn too_many_keys_is_refused_but_deep_nesting_is_simply_kept() {
        let mut many = Vec::from(b"{".as_slice());
        for i in 0..MAX_KEYS + 1 {
            if i > 0 {
                many.push(b',');
            }
            many.extend_from_slice(format!("\"k{i}\":{i}").as_bytes());
        }
        many.push(b'}');
        assert_eq!(Doc::parse(&many).err(), Some(Error::TooManyKeys));

        // Nesting is no longer refused, and that is the better answer. Values are never
        // descended into -- each comes back as the raw bytes it was written as -- so depth
        // costs nothing here, and refusing a blob for it would cost the owner every setting
        // in it. A future `multisig` shape nested deeper than this reads still survives a
        // save byte-identically.
        let mut deep = Vec::from(br#"{"a":"#.as_slice());
        deep.extend(core::iter::repeat_n(b'[', MAX_DEPTH + 2));
        deep.extend(core::iter::repeat_n(b']', MAX_DEPTH + 2));
        deep.push(b'}');
        let doc = Doc::parse(&deep).expect("a deeply nested value is kept, not refused");
        assert_eq!(doc.len(), 1);
        assert_eq!(
            doc.get("a").map(str::len),
            Some(2 * (MAX_DEPTH + 2)),
            "the value comes back whole, brackets and all"
        );
    }


    #[test]
    fn numbers_and_literals_survive_as_written() {
        let doc =
            Doc::parse(br#"{"a": -1, "b": 1.5e3, "c": true, "d": null, "e": false}"#).unwrap();
        assert_eq!(doc.get("a"), Some("-1"));
        assert_eq!(doc.get("b"), Some("1.5e3"));
        assert_eq!(doc.get_bool("c"), Some(true));
        assert_eq!(doc.get("d"), Some("null"));
        assert_eq!(doc.get_bool("e"), Some(false));
    }
}

