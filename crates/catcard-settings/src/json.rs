//! The settings dictionary: reading it, changing one key, writing it back.
//!
//! The blob is a flat JSON object whose values can be anything -- numbers, strings, lists
//! of multisig wallets. This device understands a handful of those keys and has no business
//! understanding the rest, but it must not *lose* the rest: a settings blob written by stock
//! firmware, or by a later version of this one, carries configuration whose owner would have
//! to re-enter it.
//!
//! So a [`Doc`] is the object's keys in order, each with its value as the **raw bytes it was
//! written as**. Reading a key it knows is a lookup; changing one replaces that value in
//! place; everything else is copied out exactly as it came in. Nothing is interpreted that
//! does not need to be.
//!
//! No allocation: the entries borrow the buffer they were parsed from, and rendering writes
//! into a caller buffer.

/// Keys one settings object can hold.
///
/// Stock's own list is about forty; this leaves room for it to grow and for keys we have
/// never heard of. A blob with more is refused rather than silently truncated.
pub const MAX_KEYS: usize = 96;

/// How deeply a value may nest. `multisig` is a list of objects, which is two.
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
    /// The buffer given to [`Doc::render`] was too small.
    BufferTooSmall,
}

/// One key and the raw text of its value.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Entry<'a> {
    /// The key, with its quotes and escapes removed only if it had none: see [`Doc::get`].
    pub key: &'a str,
    /// The value exactly as it appears in the object, including any quotes.
    pub raw: &'a str,
}

/// A parsed settings object.
#[derive(Clone, Debug, Default)]
pub struct Doc<'a> {
    entries: heapless::Vec<Entry<'a>, MAX_KEYS>,
}

struct Scan<'a> {
    src: &'a [u8],
    at: usize,
}

impl<'a> Scan<'a> {
    fn err<T>(&self) -> Result<T, Error> {
        Err(Error::Malformed { at: self.at })
    }

    fn skip_ws(&mut self) {
        while matches!(self.src.get(self.at), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn byte(&self) -> Option<u8> {
        self.src.get(self.at).copied()
    }

    fn expect(&mut self, b: u8) -> Result<(), Error> {
        if self.byte() == Some(b) {
            self.at += 1;
            Ok(())
        } else {
            self.err()
        }
    }

    /// A JSON string, returning its span including the quotes.
    fn string(&mut self) -> Result<(usize, usize), Error> {
        let start = self.at;
        self.expect(b'"')?;
        loop {
            match self.byte() {
                None => return self.err(),
                Some(b'\\') => {
                    // Whatever is escaped is consumed without interpretation: this only has
                    // to find the string's end.
                    self.at += 2;
                }
                Some(b'"') => {
                    self.at += 1;
                    return Ok((start, self.at));
                }
                Some(_) => self.at += 1,
            }
        }
    }

    /// One value, returning its span. Objects and arrays are spanned whole, unparsed.
    fn value(&mut self, depth: usize) -> Result<(usize, usize), Error> {
        if depth > MAX_DEPTH {
            return Err(Error::TooDeep);
        }
        self.skip_ws();
        let start = self.at;
        match self.byte() {
            None => self.err(),
            Some(b'"') => {
                self.string()?;
                Ok((start, self.at))
            }
            Some(b'{') | Some(b'[') => {
                let open = self.byte().unwrap_or(b'{');
                let close = if open == b'{' { b'}' } else { b']' };
                self.at += 1;
                loop {
                    self.skip_ws();
                    match self.byte() {
                        None => return self.err(),
                        // A nested string may hold braces; skip it as a unit.
                        Some(b'"') => {
                            self.string()?;
                        }
                        Some(b'{') | Some(b'[') => {
                            self.value(depth + 1)?;
                        }
                        Some(b) if b == close => {
                            self.at += 1;
                            return Ok((start, self.at));
                        }
                        Some(_) => self.at += 1,
                    }
                }
            }
            Some(_) => {
                // A number, or one of the three literals: everything up to the next comma
                // or closing brace, trimmed.
                while !matches!(self.byte(), None | Some(b',') | Some(b'}') | Some(b']')) {
                    self.at += 1;
                }
                let mut end = self.at;
                while end > start && matches!(self.src[end - 1], b' ' | b'\t' | b'\n' | b'\r') {
                    end -= 1;
                }
                if end == start {
                    return self.err();
                }
                Ok((start, end))
            }
        }
    }
}

impl<'a> Doc<'a> {
    /// An empty object, for a device with no settings yet.
    pub fn new() -> Self {
        Self {
            entries: heapless::Vec::new(),
        }
    }

    /// Parse a settings object.
    pub fn parse(json: &'a [u8]) -> Result<Self, Error> {
        let text = core::str::from_utf8(json).map_err(|e| Error::Malformed {
            at: e.valid_up_to(),
        })?;
        let mut s = Scan { src: json, at: 0 };
        let mut doc = Self::new();
        s.skip_ws();
        s.expect(b'{')?;
        s.skip_ws();
        if s.byte() == Some(b'}') {
            return Ok(doc);
        }
        loop {
            s.skip_ws();
            let (ks, ke) = s.string()?;
            s.skip_ws();
            s.expect(b':')?;
            let (vs, ve) = s.value(1)?;
            doc.entries
                .push(Entry {
                    // Without the quotes. An escaped key is left escaped: this device's own
                    // keys have none, and a key it does not know is only ever copied.
                    key: &text[ks + 1..ke - 1],
                    raw: &text[vs..ve],
                })
                .map_err(|_| Error::TooManyKeys)?;
            s.skip_ws();
            match s.byte() {
                Some(b',') => s.at += 1,
                Some(b'}') => {
                    s.at += 1;
                    break;
                }
                _ => return s.err(),
            }
        }
        s.skip_ws();
        if s.at != json.len() {
            return s.err();
        }
        Ok(doc)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[Entry<'a>] {
        &self.entries
    }

    /// The raw value of `key`, quotes and all.
    pub fn get(&self, key: &str) -> Option<&'a str> {
        self.entries.iter().find(|e| e.key == key).map(|e| e.raw)
    }

    /// `key` as an unsigned number, if it is one.
    pub fn get_u64(&self, key: &str) -> Option<u64> {
        self.get(key)?.parse().ok()
    }

    /// `key` as a string, with its quotes removed. Escapes are not decoded, so a value
    /// holding one is returned as written -- this device's own strings have none.
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

    /// Set `key` to the raw JSON `value`, replacing it in place if it is already there.
    ///
    /// `value` must be valid JSON on its own -- a number, or a quoted string. Nothing here
    /// checks that, because the values this writes are its own.
    pub fn set(&mut self, key: &'a str, value: &'a str) -> Result<(), Error> {
        if let Some(e) = self.entries.iter_mut().find(|e| e.key == key) {
            e.raw = value;
            return Ok(());
        }
        self.entries
            .push(Entry { key, raw: value })
            .map_err(|_| Error::TooManyKeys)
    }

    /// Remove `key`, keeping the order of the rest.
    pub fn remove(&mut self, key: &str) -> bool {
        if let Some(at) = self.entries.iter().position(|e| e.key == key) {
            // `heapless::Vec` has no `remove`, so shift the tail down.
            for i in at..self.entries.len() - 1 {
                self.entries[i] = self.entries[i + 1];
            }
            self.entries.pop();
            true
        } else {
            false
        }
    }

    /// Bytes [`render`](Self::render) will write.
    pub fn rendered_len(&self) -> usize {
        // `{}` plus `"key":value` per entry with a comma between.
        let inner: usize = self
            .entries
            .iter()
            .map(|e| e.key.len() + 3 + e.raw.len())
            .sum();
        2 + inner + self.entries.len().saturating_sub(1)
    }

    /// Write the object into `out`, returning its length.
    ///
    /// Keys keep the order they were parsed in, with new ones appended, so a blob that goes
    /// unchanged comes back byte for byte.
    pub fn render(&self, out: &mut [u8]) -> Result<usize, Error> {
        let need = self.rendered_len();
        if out.len() < need {
            return Err(Error::BufferTooSmall);
        }
        let mut at = 0;
        let mut put = |bytes: &[u8], at: &mut usize| {
            out[*at..*at + bytes.len()].copy_from_slice(bytes);
            *at += bytes.len();
        };
        put(b"{", &mut at);
        for (i, e) in self.entries.iter().enumerate() {
            if i > 0 {
                put(b",", &mut at);
            }
            put(b"\"", &mut at);
            put(e.key.as_bytes(), &mut at);
            put(b"\":", &mut at);
            put(e.raw.as_bytes(), &mut at);
        }
        put(b"}", &mut at);
        Ok(at)
    }
}

#[cfg(test)]
mod tests {
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
    fn a_blob_nothing_touched_renders_back_to_the_same_keys_and_values() {
        let doc = Doc::parse(STOCK).unwrap();
        let mut out = [0u8; 512];
        let n = doc.render(&mut out).unwrap();
        // Re-parsing the rendered form gives the same entries: whitespace is not preserved,
        // the content is.
        let again = Doc::parse(&out[..n]).unwrap();
        assert_eq!(again.entries(), doc.entries());
        // Including the ones this device has no idea about.
        assert_eq!(again.get("multisig"), doc.get("multisig"));
        assert_eq!(again.get_str("nick"), doc.get_str("nick"));
    }

    #[test]
    fn changing_one_key_leaves_every_other_byte_alone() {
        let mut doc = Doc::parse(STOCK).unwrap();
        doc.set("rz", "0").unwrap();
        doc.set("new_key", "\"hello\"").unwrap();
        let mut out = [0u8; 512];
        let n = doc.render(&mut out).unwrap();
        let again = Doc::parse(&out[..n]).unwrap();
        assert_eq!(again.get_u64("rz"), Some(0));
        assert_eq!(again.get_str("new_key"), Some("hello"));
        // Untouched keys keep their place and their text.
        assert_eq!(again.entries()[0].key, "_age");
        assert_eq!(again.get("multisig"), doc.get("multisig"));
        assert_eq!(again.len(), 9);
        // And a new key goes last, so the order a reader sees is stable.
        assert_eq!(again.entries().last().unwrap().key, "new_key");
    }

    #[test]
    fn removing_a_key_keeps_the_order_of_the_rest() {
        let mut doc = Doc::parse(STOCK).unwrap();
        assert!(doc.remove("chain"));
        assert!(!doc.remove("chain"));
        let keys: Vec<&str> = doc.entries().iter().map(|e| e.key).collect();
        assert_eq!(
            keys,
            ["_age", "rz", "wa", "multisig", "accts", "nick", "idle_to"]
        );
    }

    #[test]
    fn a_string_holding_braces_or_escapes_does_not_confuse_the_scan() {
        let doc = Doc::parse(br#"{"a": "}{[\",", "b": 1}"#).unwrap();
        assert_eq!(doc.len(), 2);
        assert_eq!(doc.get("a"), Some(r#""}{[\",""#));
        assert_eq!(doc.get_u64("b"), Some(1));
    }

    #[test]
    fn an_empty_object_is_fine_and_renders_as_one() {
        let doc = Doc::parse(b"{}").unwrap();
        assert!(doc.is_empty());
        let mut out = [0u8; 8];
        let n = doc.render(&mut out).unwrap();
        assert_eq!(&out[..n], b"{}");
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
    fn a_blob_with_too_many_keys_or_too_much_nesting_is_refused() {
        let mut many = Vec::from(b"{".as_slice());
        for i in 0..MAX_KEYS + 1 {
            if i > 0 {
                many.push(b',');
            }
            many.extend_from_slice(format!("\"k{i}\":{i}").as_bytes());
        }
        many.push(b'}');
        assert_eq!(Doc::parse(&many).err(), Some(Error::TooManyKeys));

        let mut deep = Vec::from(br#"{"a":"#.as_slice());
        deep.extend(core::iter::repeat_n(b'[', MAX_DEPTH + 2));
        deep.extend(core::iter::repeat_n(b']', MAX_DEPTH + 2));
        deep.push(b'}');
        assert_eq!(Doc::parse(&deep).err(), Some(Error::TooDeep));
    }

    #[test]
    fn a_render_buffer_that_is_too_small_is_an_error_not_a_truncated_blob() {
        let doc = Doc::parse(STOCK).unwrap();
        let mut out = [0u8; 16];
        assert_eq!(doc.render(&mut out), Err(Error::BufferTooSmall));
        assert!(doc.rendered_len() > 16);
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
