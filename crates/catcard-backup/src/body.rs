//! The plaintext inside the archive: `key = value` lines, JSON on the right.
//!
//! ```text
//! # Coldcard backup file! DO NOT CHANGE.
//!
//! # Private key details: Bitcoin Mainnet
//! mnemonic = "word word ..."
//! chain = "BTC"
//! xprv = "xprv..."
//! ...
//! setting.<name> = <JSON value>
//!
//! # EOF
//! ```
//!
//! Lines end with LF. A line is blank, a `#` comment, or a field: a name, `=`, and
//! exactly one well-formed JSON value. Nothing else is a line, and a file containing
//! something else is refused rather than partly read -- restoring three quarters of a
//! wallet is worse than restoring none of it.
//!
//! # Values stay as they were written
//!
//! [`Field`] hands back the **raw** JSON text, not a decoded value. That is what lets a
//! `setting.` this firmware has never heard of go back onto the device byte-identically,
//! and it is the same choice `catcard_settings::json` makes for the same reason. The
//! decoders ([`Field::text`], [`Field::hex_into`]) are opt-in, per field.
//!
//! # `text` refuses escapes on purpose
//!
//! Every field the backup itself owns -- the mnemonic, an xprv, hex -- is drawn from an
//! alphabet with no character JSON needs to escape. So [`Field::text`] returns a borrow
//! of the file when the string is plain and [`crate::Error::Escaped`] when it is not,
//! rather than quietly needing a scratch buffer on a path where a scratch buffer would
//! be another copy of the seed. [`Field::text_into`] is there for the general case,
//! which in practice means a user-set preference.
//!
//! # The buffer holds the seed
//!
//! Both halves of this module work on a caller-owned buffer, and while a backup is in
//! it that buffer is the plaintext seed. Zeroize it.

use crate::Error;

/// The line every backup opens with.
pub const MARKER: &str = "# Coldcard backup file! DO NOT CHANGE.";

/// The prefix on a preference's name.
pub const SETTING_PREFIX: &str = "setting.";

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/// Builds a body into a caller-owned buffer.
///
/// Errors are remembered rather than returned per call, so a body reads as a straight
/// sequence of statements and is checked once at [`BodyWriter::finish`]. Nothing is
/// handed back until every write succeeded: a truncated backup must not exist.
pub struct BodyWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
    bad: Option<Error>,
}

impl<'a> BodyWriter<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        BodyWriter {
            buf,
            pos: 0,
            bad: None,
        }
    }

    /// The marker line and the blank line under it.
    pub fn preamble(&mut self) {
        self.raw(MARKER);
        self.raw("\n\n");
    }

    /// A `# ...` heading, with exactly one blank line above it.
    pub fn section(&mut self, title: &str) {
        self.ensure_blank_line();
        self.raw("# ");
        self.comment_text(title);
        self.raw("\n");
    }

    /// A field whose value is a JSON string.
    pub fn text(&mut self, key: &str, value: &str) {
        self.key(key);
        self.quoted(value);
        self.raw("\n");
    }

    /// A field whose value is a JSON string of lower-case hex, no `0x`.
    pub fn hex(&mut self, key: &str, bytes: &[u8]) {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        self.key(key);
        self.raw("\"");
        for b in bytes {
            self.byte(DIGITS[usize::from(b >> 4)]);
            self.byte(DIGITS[usize::from(b & 0x0F)]);
        }
        self.raw("\"\n");
    }

    /// A field whose value is already rendered JSON -- a number, an array, an object.
    ///
    /// Validated before it is written: a settings blob carried through from elsewhere
    /// must not be able to inject a second line or a broken value into the backup.
    pub fn json(&mut self, key: &str, raw: &str) {
        if raw.contains('\n') || raw.contains('\r') {
            self.fail(Error::MalformedLine);
            return;
        }
        if emjson::validate(emjson::SliceSource::new(raw.as_bytes())).is_err() {
            self.fail(Error::NotJson);
            return;
        }
        self.key(key);
        self.raw(raw);
        self.raw("\n");
    }

    /// `setting.<name> = <raw JSON>`.
    pub fn setting(&mut self, name: &str, raw: &str) {
        if !name_ok(name) {
            self.fail(Error::MalformedLine);
            return;
        }
        if raw.contains('\n') || raw.contains('\r') {
            self.fail(Error::MalformedLine);
            return;
        }
        if emjson::validate(emjson::SliceSource::new(raw.as_bytes())).is_err() {
            self.fail(Error::NotJson);
            return;
        }
        self.raw(SETTING_PREFIX);
        self.raw(name);
        self.raw(" = ");
        self.raw(raw);
        self.raw("\n");
    }

    /// The closing `# EOF`, with a blank line above it.
    pub fn eof(&mut self) {
        self.ensure_blank_line();
        self.raw("# EOF\n");
    }

    /// How many bytes have been written so far -- for a progress bar, and for deciding
    /// whether the next section will fit.
    pub fn len(&self) -> usize {
        self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.pos == 0
    }

    /// The finished body, or the first thing that went wrong.
    pub fn finish(self) -> Result<&'a [u8], Error> {
        match self.bad {
            Some(e) => Err(e),
            None => Ok(&self.buf[..self.pos]),
        }
    }

    // --- internals ---

    fn fail(&mut self, e: Error) {
        self.bad.get_or_insert(e);
    }

    fn byte(&mut self, b: u8) {
        match self.buf.get_mut(self.pos) {
            Some(slot) => {
                *slot = b;
                self.pos += 1;
            }
            None => self.fail(Error::BufferTooSmall),
        }
    }

    fn raw(&mut self, s: &str) {
        for b in s.as_bytes() {
            self.byte(*b);
        }
    }

    fn key(&mut self, key: &str) {
        if !name_ok(key) {
            self.fail(Error::MalformedLine);
        }
        self.raw(key);
        self.raw(" = ");
    }

    /// A heading must not be able to close the comment and start a field.
    fn comment_text(&mut self, s: &str) {
        for b in s.as_bytes() {
            if *b == b'\n' || *b == b'\r' {
                self.fail(Error::MalformedLine);
                return;
            }
            self.byte(*b);
        }
    }

    fn quoted(&mut self, s: &str) {
        self.raw("\"");
        for b in s.as_bytes() {
            match b {
                b'"' => self.raw("\\\""),
                b'\\' => self.raw("\\\\"),
                b'\n' => self.raw("\\n"),
                b'\r' => self.raw("\\r"),
                b'\t' => self.raw("\\t"),
                0x00..=0x1F => {
                    const DIGITS: &[u8; 16] = b"0123456789abcdef";
                    self.raw("\\u00");
                    self.byte(DIGITS[usize::from(b >> 4)]);
                    self.byte(DIGITS[usize::from(b & 0x0F)]);
                }
                _ => self.byte(*b),
            }
        }
        self.raw("\"");
    }

    fn ensure_blank_line(&mut self) {
        if self.pos == 0 {
            return;
        }
        if self.buf.get(self.pos.wrapping_sub(1)) != Some(&b'\n') {
            self.raw("\n");
        }
        if self.pos >= 2 && self.buf[self.pos - 2] != b'\n' {
            self.raw("\n");
        }
    }
}

/// A field name: what a key may be made of.
///
/// Deliberately narrow. Everything the format uses is in here, and a name that needed
/// anything more would be a name that could carry a `=` or a newline.
fn name_ok(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/// One `key = value` line, with the value still as it was written.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Field<'a> {
    pub key: &'a str,
    /// The JSON value, exactly as the file spells it -- quotes and all.
    pub raw: &'a str,
}

impl<'a> Field<'a> {
    /// The preference name, for a `setting.` field.
    pub fn setting(&self) -> Option<&'a str> {
        self.key.strip_prefix(SETTING_PREFIX)
    }

    /// A JSON string with no escapes in it, borrowed from the file.
    ///
    /// See the module docs for why an escape is refused here rather than decoded.
    pub fn text(&self) -> Result<&'a str, Error> {
        let inner = self
            .raw
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .ok_or(Error::NotAString)?;
        if inner.contains('\\') {
            return Err(Error::Escaped);
        }
        Ok(inner)
    }

    /// A JSON string with its escapes resolved into `out`.
    pub fn text_into<'o>(&self, out: &'o mut [u8]) -> Result<&'o str, Error> {
        let inner = self
            .raw
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .ok_or(Error::NotAString)?;
        let mut n = 0usize;
        let push = |b: u8, n: &mut usize, out: &mut [u8]| -> Result<(), Error> {
            *out.get_mut(*n).ok_or(Error::BufferTooSmall)? = b;
            *n += 1;
            Ok(())
        };
        let mut it = inner.chars();
        while let Some(c) = it.next() {
            if c != '\\' {
                let mut tmp = [0u8; 4];
                for b in c.encode_utf8(&mut tmp).as_bytes() {
                    push(*b, &mut n, out)?;
                }
                continue;
            }
            let esc = it.next().ok_or(Error::NotJson)?;
            let plain = match esc {
                '"' => b'"',
                '\\' => b'\\',
                '/' => b'/',
                'b' => 0x08,
                'f' => 0x0C,
                'n' => b'\n',
                'r' => b'\r',
                't' => b'\t',
                'u' => {
                    // Only the basic plane, which is all a preference ever carries. A
                    // surrogate pair would need a second escape and a state machine;
                    // refusing is honest and nothing writes one.
                    let mut code = 0u32;
                    for _ in 0..4 {
                        let d = it
                            .next()
                            .and_then(|d| d.to_digit(16))
                            .ok_or(Error::NotJson)?;
                        code = code * 16 + d;
                    }
                    let ch = char::from_u32(code).ok_or(Error::NotJson)?;
                    let mut tmp = [0u8; 4];
                    for b in ch.encode_utf8(&mut tmp).as_bytes() {
                        push(*b, &mut n, out)?;
                    }
                    continue;
                }
                _ => return Err(Error::NotJson),
            };
            push(plain, &mut n, out)?;
        }
        core::str::from_utf8(&out[..n]).map_err(|_| Error::NotJson)
    }

    /// A JSON string of hex, decoded into `out`.
    pub fn hex_into<'o>(&self, out: &'o mut [u8]) -> Result<&'o [u8], Error> {
        unhex(self.text()?, out)
    }
}

/// Decodes an even-length run of hex digits.
pub fn unhex<'o>(text: &str, out: &'o mut [u8]) -> Result<&'o [u8], Error> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(Error::NotHex);
    }
    let n = bytes.len() / 2;
    if out.len() < n {
        return Err(Error::BufferTooSmall);
    }
    let (pairs, _) = bytes.as_chunks::<2>();
    for (slot, pair) in out[..n].iter_mut().zip(pairs) {
        let hi = (pair[0] as char).to_digit(16).ok_or(Error::NotHex)?;
        let lo = (pair[1] as char).to_digit(16).ok_or(Error::NotHex)?;
        *slot = (hi * 16 + lo) as u8;
    }
    Ok(&out[..n])
}

/// Walks the fields of a body, refusing at the first line that is not one.
///
/// Comments and blank lines are skipped. The iterator stops after it yields an error,
/// so a caller that drives it with `?` in a `for` loop cannot accidentally carry on past
/// a malformed file.
pub struct Fields<'a> {
    rest: &'a str,
    stopped: bool,
}

/// Starts a walk over `text`.
pub fn fields(text: &str) -> Fields<'_> {
    Fields {
        rest: text,
        stopped: false,
    }
}

impl<'a> Iterator for Fields<'a> {
    type Item = Result<Field<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.stopped {
            let (line, rest) = match self.rest.find('\n') {
                Some(i) => (&self.rest[..i], &self.rest[i + 1..]),
                None if self.rest.is_empty() => return None,
                None => (self.rest, ""),
            };
            self.rest = rest;
            // A body is LF-terminated, but a file that has been through a host editor
            // may have picked up CRs. Accepted on the way in, never written on the way
            // out.
            let line = line.trim_matches(|c| c == '\r' || c == ' ' || c == '\t');
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            return Some(match split_field(line) {
                Ok(f) => Ok(f),
                Err(e) => {
                    self.stopped = true;
                    Err(e)
                }
            });
        }
        None
    }
}

fn split_field(line: &str) -> Result<Field<'_>, Error> {
    let eq = line.find('=').ok_or(Error::MalformedLine)?;
    let key = line[..eq].trim_matches(|c| c == ' ' || c == '\t');
    let raw = line[eq + 1..].trim_matches(|c| c == ' ' || c == '\t');
    if !name_ok(key) {
        return Err(Error::MalformedLine);
    }
    if raw.is_empty() {
        return Err(Error::NotJson);
    }
    if emjson::validate(emjson::SliceSource::new(raw.as_bytes())).is_err() {
        return Err(Error::NotJson);
    }
    Ok(Field { key, raw })
}

/// The fields a restore acts on, picked out of a body in one pass.
///
/// Every one is optional: which are present says what kind of wallet was backed up, and
/// deciding that is the caller's, not this crate's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Details<'a> {
    pub mnemonic: Option<&'a str>,
    pub chain: Option<&'a str>,
    pub xprv: Option<&'a str>,
    pub xpub: Option<&'a str>,
    /// Hex, still undecoded: the 72-byte secret stash as the device stores it.
    pub raw_secret: Option<&'a str>,
    /// Hex, still undecoded.
    pub long_secret: Option<&'a str>,
    pub fw_date: Option<&'a str>,
    pub fw_version: Option<&'a str>,
    pub fw_timestamp: Option<&'a str>,
    /// Hex, still undecoded: the device that *wrote* the backup, not the one reading it.
    pub serial: Option<&'a str>,
    pub hardware: Option<&'a str>,
}

/// What [`scan`] found.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Scan<'a> {
    pub details: Details<'a>,
    /// How many `setting.` fields there are. They are not collected: there can be
    /// dozens, they are the caller's to replay, and holding them would mean a bound.
    pub settings: u32,
    /// Fields that are neither a known one nor a `setting.`. Counted, not refused: a
    /// newer firmware may have written something this one has no use for, and dropping
    /// it is the right answer, but the caller should be able to say so.
    pub unknown: u32,
}

/// Reads a whole body, refusing at the first malformed line.
///
/// The first non-blank line must be a comment, which is the cheapest check that this is
/// a backup at all and not, say, a PSBT that decrypted to noise.
pub fn scan(text: &str) -> Result<Scan<'_>, Error> {
    let first = text.lines().find(|l| !l.trim().is_empty());
    if !first.is_some_and(|l| l.trim_start().starts_with('#')) {
        return Err(Error::NotABackup);
    }

    let mut out = Scan::default();
    for field in fields(text) {
        let f = field?;
        if f.setting().is_some() {
            out.settings += 1;
            continue;
        }
        let slot = match f.key {
            "mnemonic" => &mut out.details.mnemonic,
            "chain" => &mut out.details.chain,
            "xprv" => &mut out.details.xprv,
            "xpub" => &mut out.details.xpub,
            "raw_secret" => &mut out.details.raw_secret,
            "long_secret" => &mut out.details.long_secret,
            "fw_date" => &mut out.details.fw_date,
            "fw_version" => &mut out.details.fw_version,
            "fw_timestamp" => &mut out.details.fw_timestamp,
            "serial" => &mut out.details.serial,
            "hardware" => &mut out.details.hardware,
            _ => {
                out.unknown += 1;
                continue;
            }
        };
        *slot = Some(f.text()?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A body with one of everything, built the way the firmware builds it.
    fn sample(buf: &mut [u8]) -> &[u8] {
        let mut w = BodyWriter::new(buf);
        w.preamble();
        w.section("Private key details: Bitcoin Mainnet");
        w.text("mnemonic", "abandon abandon about");
        w.text("chain", "BTC");
        w.text("xprv", "xprvTEST");
        w.text("xpub", "xpubTEST");
        w.hex("raw_secret", &[0x80, 0x01, 0xFE]);
        w.section("Firmware version (informational)");
        w.text("fw_version", "7.0.0");
        w.section("Coldcard Hardware");
        w.hex("serial", &[0xAB, 0xCD]);
        w.text("hardware", "q1");
        w.section("User preferences");
        w.setting("xfp", "1130522146");
        w.setting("chain", "\"BTC\"");
        w.setting("words", "[12, 24]");
        w.eof();
        w.finish().unwrap()
    }

    #[test]
    fn a_body_reads_back_as_what_was_written() {
        let mut buf = [0u8; 512];
        let text = core::str::from_utf8(sample(&mut buf)).unwrap();
        let got = scan(text).unwrap();
        assert_eq!(got.details.mnemonic, Some("abandon abandon about"));
        assert_eq!(got.details.chain, Some("BTC"));
        assert_eq!(got.details.raw_secret, Some("8001fe"));
        assert_eq!(got.details.hardware, Some("q1"));
        assert_eq!(got.settings, 3);
        assert_eq!(got.unknown, 0);
    }

    #[test]
    fn the_body_has_the_shape_the_format_describes() {
        let mut buf = [0u8; 512];
        let text = core::str::from_utf8(sample(&mut buf)).unwrap();
        assert!(text.starts_with(MARKER), "{text}");
        assert!(text.ends_with("\n# EOF\n"), "{text}");
        assert!(text.contains("\n\n# Firmware version (informational)\n"));
        assert!(text.contains("\nmnemonic = \"abandon abandon about\"\n"));
        assert!(text.contains("\nsetting.words = [12, 24]\n"));
        // LF only, both on the way in and on the way out.
        assert!(!text.contains('\r'));
        // No accidental run of blank lines between sections.
        assert!(!text.contains("\n\n\n"));
    }

    /// A settings value this firmware does not understand must come back byte for byte,
    /// or a round trip through CatCard quietly rewrites the owner's preferences.
    #[test]
    fn an_unknown_setting_survives_unchanged() {
        let mut buf = [0u8; 256];
        let mut w = BodyWriter::new(&mut buf);
        w.preamble();
        w.setting("from_the_future", r#"{"a":[1,2,{"b":null}],"c":"x"}"#);
        w.eof();
        let text = core::str::from_utf8(w.finish().unwrap()).unwrap();
        let f = fields(text).next().unwrap().unwrap();
        assert_eq!(f.setting(), Some("from_the_future"));
        assert_eq!(f.raw, r#"{"a":[1,2,{"b":null}],"c":"x"}"#);
    }

    #[test]
    fn a_line_that_is_not_a_field_is_refused() {
        for bad in [
            "# ok\nmnemonic\n",              // no '='
            "# ok\n = \"x\"\n",              // no key
            "# ok\nmne monic = \"x\"\n",     // a space in the key
            "# ok\nmnemonic = \n",           // no value
            "# ok\nmnemonic = not json\n",   // bare word
            "# ok\nmnemonic = \"unclosed\n", // a string running off the line
            "# ok\nmnemonic = \"a\" junk\n", // trailing rubbish after a value
            "# ok\nmnemonic = 1 2\n",
        ] {
            assert!(scan(bad).is_err(), "accepted: {bad:?}");
        }
    }

    /// Anything that is not a backup at all -- most importantly, a file that decrypted
    /// to noise because the words were wrong and the archive carried no checksum.
    #[test]
    fn something_that_is_not_a_backup_is_refused() {
        assert_eq!(scan("").unwrap_err(), Error::NotABackup);
        assert_eq!(scan("mnemonic = \"x\"\n").unwrap_err(), Error::NotABackup);
        assert_eq!(scan("\u{1}\u{2}\u{3}").unwrap_err(), Error::NotABackup);
    }

    /// The iterator must not hand out a second field after refusing one: a caller that
    /// collects what it can would otherwise restore the half of a file that parsed.
    #[test]
    fn the_walk_stops_at_the_first_bad_line() {
        let text = "# ok\na = 1\nbroken\nb = 2\n";
        let mut it = fields(text);
        assert_eq!(it.next().unwrap().unwrap().key, "a");
        assert!(it.next().unwrap().is_err());
        assert!(it.next().is_none());
    }

    #[test]
    fn a_body_that_does_not_fit_is_refused_rather_than_truncated() {
        let mut buf = [0u8; 40];
        let mut w = BodyWriter::new(&mut buf);
        w.preamble();
        w.text("mnemonic", "a rather long list of words indeed");
        w.eof();
        assert_eq!(w.finish().unwrap_err(), Error::BufferTooSmall);
    }

    /// A settings blob carried over from another firmware is attacker-reachable in the
    /// sense that matters here: it decides the shape of a file we then sign off as a
    /// backup. It must not be able to add a line.
    #[test]
    fn a_setting_cannot_inject_a_line_or_a_broken_value() {
        let mut buf = [0u8; 256];
        let mut w = BodyWriter::new(&mut buf);
        w.preamble();
        w.setting("evil", "1\nxprv = \"stolen\"");
        assert_eq!(w.finish().unwrap_err(), Error::MalformedLine);

        let mut buf = [0u8; 256];
        let mut w = BodyWriter::new(&mut buf);
        w.preamble();
        w.setting("evil", "{oops}");
        assert_eq!(w.finish().unwrap_err(), Error::NotJson);

        let mut buf = [0u8; 256];
        let mut w = BodyWriter::new(&mut buf);
        w.preamble();
        w.setting("evil = 1\nxprv", "1");
        assert_eq!(w.finish().unwrap_err(), Error::MalformedLine);
    }

    #[test]
    fn a_string_with_a_quote_in_it_is_escaped_and_comes_back_whole() {
        let mut buf = [0u8; 256];
        let mut w = BodyWriter::new(&mut buf);
        w.preamble();
        w.text("note", "say \"hi\"\\\tnow");
        w.eof();
        let text = core::str::from_utf8(w.finish().unwrap()).unwrap();
        assert!(text.contains(r#"note = "say \"hi\"\\\tnow""#), "{text}");
        let f = fields(text).next().unwrap().unwrap();
        // Escape-free borrowing refuses it ...
        assert_eq!(f.text().unwrap_err(), Error::Escaped);
        // ... and the decoding path gets it back.
        let mut out = [0u8; 64];
        assert_eq!(f.text_into(&mut out).unwrap(), "say \"hi\"\\\tnow");
    }

    #[test]
    fn hex_fields_decode_and_reject_what_is_not_hex() {
        let mut buf = [0u8; 128];
        let mut w = BodyWriter::new(&mut buf);
        w.preamble();
        w.hex("raw_secret", &[0x00, 0x7F, 0xFF]);
        let text = core::str::from_utf8(w.finish().unwrap()).unwrap();
        let f = fields(text).next().unwrap().unwrap();
        let mut out = [0u8; 8];
        assert_eq!(f.hex_into(&mut out).unwrap(), &[0x00, 0x7F, 0xFF]);

        let bad = Field {
            key: "raw_secret",
            raw: "\"00ZZ\"",
        };
        assert_eq!(bad.hex_into(&mut out).unwrap_err(), Error::NotHex);
        let odd = Field {
            key: "raw_secret",
            raw: "\"000\"",
        };
        assert_eq!(odd.hex_into(&mut out).unwrap_err(), Error::NotHex);
    }

    /// CRLF is not what we write, but a file that has been through a host editor may
    /// have it, and refusing a backup over line endings would be a poor trade.
    #[test]
    fn crlf_is_tolerated_on_the_way_in() {
        let got = scan("# ok\r\nmnemonic = \"a b c\"\r\n\r\n# EOF\r\n").unwrap();
        assert_eq!(got.details.mnemonic, Some("a b c"));
    }

    #[test]
    fn a_secret_field_that_is_not_a_string_is_refused() {
        assert_eq!(
            scan("# ok\nmnemonic = 12\n").unwrap_err(),
            Error::NotAString
        );
        assert_eq!(
            scan("# ok\nxprv = [\"a\"]\n").unwrap_err(),
            Error::NotAString
        );
    }
}
