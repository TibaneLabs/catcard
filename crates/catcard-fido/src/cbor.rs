//! CBOR, the subset CTAP2 speaks, strictly.
//!
//! CTAP2 carries its requests and responses as CBOR in the **CTAP2 canonical encoding**:
//! integers and lengths in their shortest form, definite lengths only, map keys in the
//! order RFC 7049 §3.9 gives (shorter encoding first, then bytewise), no duplicate keys.
//! "All encoders MUST serialize CBOR in the CTAP2 canonical CBOR encoding form ... All
//! decoders SHOULD reject CBOR that is not validly encoded in the CTAP2 canonical CBOR
//! encoding form and SHOULD reject messages with duplicate map keys."
//! Source: FIDO CTAP 2.1 §8 "Message Encoding" [C]; RFC 8949 §3, §4.2 [C]
//!
//! So this reader rejects, rather than tolerates:
//!
//! - a length or integer in a longer form than it needs;
//! - an indefinite length (additional information 31) and the reserved values 28..30;
//! - a map whose keys are out of canonical order, or repeat;
//! - tags, floating-point values and simple values other than `false`/`true`/`null`
//!   (nothing CTAP sends is one of them);
//! - text that is not UTF-8, and a declared length or count the buffer cannot hold;
//! - nesting deeper than [`MAX_DEPTH`];
//! - trailing bytes after the one top-level item ([`Reader::finish`]).
//!
//! Nothing here allocates. Byte and text strings are borrowed from the input.

/// How deep a value may nest. CTAP's deepest request -- an extension's COSE key inside
/// the extension map inside the request map -- is four; six leaves margin without letting
/// a hostile message recurse the device's stack away. [I]
pub const MAX_DEPTH: u8 = 6;

/// Why a message was refused.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Malformed, truncated or not canonical: `CTAP2_ERR_INVALID_CBOR`.
    Invalid,
    /// Well-formed, but not the type the field must be: `CTAP2_ERR_CBOR_UNEXPECTED_TYPE`.
    Unexpected,
    /// Nested deeper than [`MAX_DEPTH`].
    TooDeep,
    /// The encoder ran out of room.
    Overflow,
}

/// Major types. Source: RFC 8949 §3.1 [C]
pub mod major {
    pub const UINT: u8 = 0;
    pub const NINT: u8 = 1;
    pub const BYTES: u8 = 2;
    pub const TEXT: u8 = 3;
    pub const ARRAY: u8 = 4;
    pub const MAP: u8 = 5;
    pub const TAG: u8 = 6;
    pub const SIMPLE: u8 = 7;
}

/// A map key, as CTAP uses them: an integer (requests, responses, COSE) or text (the
/// WebAuthn dictionaries).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Key<'a> {
    Int(i64),
    Text(&'a str),
}

/// A map being read: how many entries are left, and where the previous key's encoding
/// sat, for the ordering check.
#[derive(Copy, Clone, Debug)]
pub struct Map {
    left: usize,
    prev: Option<(usize, usize)>,
}

impl Map {
    /// Entries not yet read.
    pub fn left(&self) -> usize {
        self.left
    }
}

/// Reads one CBOR item from a byte slice.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes consumed so far.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Nothing may follow the top-level item.
    pub fn finish(&self) -> Result<(), Error> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(Error::Invalid)
        }
    }

    fn byte(&mut self) -> Result<u8, Error> {
        let b = *self.buf.get(self.pos).ok_or(Error::Invalid)?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Invalid)?;
        let s = self.buf.get(self.pos..end).ok_or(Error::Invalid)?;
        self.pos = end;
        Ok(s)
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// The major type of the next item, without consuming it.
    pub fn peek_major(&self) -> Result<u8, Error> {
        Ok(*self.buf.get(self.pos).ok_or(Error::Invalid)? >> 5)
    }

    /// One item's head: its major type and argument, with the shortest-form rule
    /// applied. Major type 7 comes back with the additional information as its argument,
    /// and only for `false`, `true` and `null`.
    #[inline(never)]
    fn head(&mut self) -> Result<(u8, u64), Error> {
        let b = self.byte()?;
        let major = b >> 5;
        let ai = b & 0x1F;
        if major == major::SIMPLE {
            // false, true, null. `undefined`, one-byte simple values and the floats are
            // valid CBOR that no CTAP message contains.
            return match ai {
                20..=22 => Ok((major, ai as u64)),
                _ => Err(Error::Invalid),
            };
        }
        let arg = match ai {
            0..=23 => ai as u64,
            24 => {
                let v = self.byte()? as u64;
                if v < 24 {
                    return Err(Error::Invalid);
                }
                v
            }
            25 => {
                let s = self.take(2)?;
                let v = u16::from_be_bytes([s[0], s[1]]) as u64;
                if v <= 0xFF {
                    return Err(Error::Invalid);
                }
                v
            }
            26 => {
                let s = self.take(4)?;
                let v = u32::from_be_bytes([s[0], s[1], s[2], s[3]]) as u64;
                if v <= 0xFFFF {
                    return Err(Error::Invalid);
                }
                v
            }
            27 => {
                let s = self.take(8)?;
                let mut a = [0u8; 8];
                a.copy_from_slice(s);
                let v = u64::from_be_bytes(a);
                if v <= 0xFFFF_FFFF {
                    return Err(Error::Invalid);
                }
                v
            }
            // 28..30 reserved; 31 is an indefinite length, which canonical CBOR forbids.
            _ => return Err(Error::Invalid),
        };
        if major == major::TAG {
            // Well-formed, but CTAP has no tagged values.
            return Err(Error::Invalid);
        }
        Ok((major, arg))
    }

    /// A length argument, checked against what is left so a count can never be believed
    /// past the end of the buffer.
    fn length(&self, arg: u64, per_item: usize) -> Result<usize, Error> {
        let n = usize::try_from(arg).map_err(|_| Error::Invalid)?;
        if n.checked_mul(per_item).ok_or(Error::Invalid)? > self.remaining() {
            return Err(Error::Invalid);
        }
        Ok(n)
    }

    /// An unsigned integer.
    pub fn uint(&mut self) -> Result<u64, Error> {
        let at = self.pos;
        match self.head()? {
            (major::UINT, v) => Ok(v),
            _ => {
                self.pos = at;
                Err(Error::Unexpected)
            }
        }
    }

    /// A signed integer in `i64`'s range.
    pub fn int(&mut self) -> Result<i64, Error> {
        let at = self.pos;
        match self.head()? {
            (major::UINT, v) => i64::try_from(v).map_err(|_| Error::Invalid),
            // -1 - v
            (major::NINT, v) => {
                let v = i64::try_from(v).map_err(|_| Error::Invalid)?;
                Ok(-1 - v)
            }
            _ => {
                self.pos = at;
                Err(Error::Unexpected)
            }
        }
    }

    /// A byte string, borrowed.
    pub fn bytes(&mut self) -> Result<&'a [u8], Error> {
        let at = self.pos;
        match self.head()? {
            (major::BYTES, n) => {
                let n = self.length(n, 1)?;
                self.take(n)
            }
            _ => {
                self.pos = at;
                Err(Error::Unexpected)
            }
        }
    }

    /// A text string, borrowed; refused unless it is UTF-8.
    pub fn text(&mut self) -> Result<&'a str, Error> {
        let at = self.pos;
        match self.head()? {
            (major::TEXT, n) => {
                let n = self.length(n, 1)?;
                core::str::from_utf8(self.take(n)?).map_err(|_| Error::Invalid)
            }
            _ => {
                self.pos = at;
                Err(Error::Unexpected)
            }
        }
    }

    /// `true` or `false`.
    pub fn bool(&mut self) -> Result<bool, Error> {
        let at = self.pos;
        match self.head()? {
            (major::SIMPLE, 20) => Ok(false),
            (major::SIMPLE, 21) => Ok(true),
            _ => {
                self.pos = at;
                Err(Error::Unexpected)
            }
        }
    }

    /// An array header: how many items follow.
    pub fn array(&mut self) -> Result<usize, Error> {
        let at = self.pos;
        match self.head()? {
            (major::ARRAY, n) => self.length(n, 1),
            _ => {
                self.pos = at;
                Err(Error::Unexpected)
            }
        }
    }

    /// A map header. Read its entries with [`key`](Self::key), each followed by exactly
    /// one value.
    pub fn map(&mut self) -> Result<Map, Error> {
        let at = self.pos;
        match self.head()? {
            (major::MAP, n) => Ok(Map {
                left: self.length(n, 2)?,
                prev: None,
            }),
            _ => {
                self.pos = at;
                Err(Error::Unexpected)
            }
        }
    }

    /// The next key of `m`, or `None` when the map is done.
    ///
    /// Keys must be integers or text, and must come in canonical order: a key whose
    /// encoding is not strictly after the previous one's -- out of order, or the same key
    /// twice -- makes the whole message invalid.
    pub fn key(&mut self, m: &mut Map) -> Result<Option<Key<'a>>, Error> {
        if m.left == 0 {
            return Ok(None);
        }
        m.left -= 1;
        let start = self.pos;
        let key = match self.peek_major()? {
            major::UINT | major::NINT => Key::Int(self.int()?),
            major::TEXT => Key::Text(self.text()?),
            // Legal CBOR, but no CTAP map is keyed by anything else.
            _ => return Err(Error::Unexpected),
        };
        let span = (start, self.pos);
        if let Some(prev) = m.prev
            && !canonically_before(&self.buf[prev.0..prev.1], &self.buf[span.0..span.1])
        {
            return Err(Error::Invalid);
        }
        m.prev = Some(span);
        Ok(Some(key))
    }

    /// Step over one item of any shape, checking it as strictly as the typed readers
    /// would. `depth` is how much deeper it may go; the caller passes what it has left.
    pub fn skip(&mut self, depth: u8) -> Result<(), Error> {
        if depth == 0 {
            return Err(Error::TooDeep);
        }
        match self.peek_major()? {
            major::UINT | major::NINT => {
                self.head()?;
            }
            major::BYTES => {
                self.bytes()?;
            }
            major::TEXT => {
                self.text()?;
            }
            major::ARRAY => {
                let n = self.array()?;
                for _ in 0..n {
                    self.skip(depth - 1)?;
                }
            }
            major::MAP => {
                let mut m = self.map()?;
                while self.any_key(&mut m, depth - 1)? {
                    self.skip(depth - 1)?;
                }
            }
            _ => {
                self.head()?;
            }
        }
        Ok(())
    }

    /// A key of a map being skipped: any shape (it is not ours to interpret), still in
    /// canonical order.
    fn any_key(&mut self, m: &mut Map, depth: u8) -> Result<bool, Error> {
        if m.left == 0 {
            return Ok(false);
        }
        m.left -= 1;
        let start = self.pos;
        self.skip(depth)?;
        let span = (start, self.pos);
        if let Some(prev) = m.prev
            && !canonically_before(&self.buf[prev.0..prev.1], &self.buf[span.0..span.1])
        {
            return Err(Error::Invalid);
        }
        m.prev = Some(span);
        Ok(true)
    }
}

/// Whether encoded key `a` sorts strictly before encoded key `b`: shorter first, then
/// bytewise. Source: RFC 7049 §3.9, which CTAP 2.1 §8 adopts [C]
pub fn canonically_before(a: &[u8], b: &[u8]) -> bool {
    (a.len(), a) < (b.len(), b)
}

/// Writes CBOR into a caller's buffer.
///
/// Running out of room is sticky: every later write is dropped and [`finish`] reports
/// [`Error::Overflow`], so a builder can write a whole structure and check once. **Key
/// order is the caller's**: every map written here is laid out in canonical order by
/// hand, and the tests read the output back through the strict [`Reader`], which would
/// refuse it otherwise.
///
/// [`finish`]: Self::finish
pub struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
    overflow: bool,
}

impl<'a> Writer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            overflow: false,
        }
    }

    /// Bytes written, or the overflow.
    pub fn finish(self) -> Result<usize, Error> {
        if self.overflow {
            Err(Error::Overflow)
        } else {
            Ok(self.pos)
        }
    }

    /// Bytes written so far (meaningless after an overflow).
    pub fn position(&self) -> usize {
        self.pos
    }

    // Out of line, like `head` below: every field of every response is written through
    // these two, and inlined they cost kilobytes of flash for nothing.
    #[inline(never)]
    pub fn raw(&mut self, b: &[u8]) -> &mut Self {
        if self.overflow {
            return self;
        }
        match self.buf.get_mut(self.pos..self.pos + b.len()) {
            Some(d) => {
                d.copy_from_slice(b);
                self.pos += b.len();
            }
            None => self.overflow = true,
        }
        self
    }

    #[inline(never)]
    fn head(&mut self, major: u8, arg: u64) -> &mut Self {
        let m = major << 5;
        if arg < 24 {
            self.raw(&[m | arg as u8])
        } else if arg <= 0xFF {
            self.raw(&[m | 24, arg as u8])
        } else if arg <= 0xFFFF {
            let b = (arg as u16).to_be_bytes();
            self.raw(&[m | 25, b[0], b[1]])
        } else if arg <= 0xFFFF_FFFF {
            let b = (arg as u32).to_be_bytes();
            self.raw(&[m | 26, b[0], b[1], b[2], b[3]])
        } else {
            self.raw(&[m | 27]).raw(&arg.to_be_bytes())
        }
    }

    pub fn uint(&mut self, v: u64) -> &mut Self {
        self.head(major::UINT, v)
    }

    pub fn int(&mut self, v: i64) -> &mut Self {
        if v >= 0 {
            self.head(major::UINT, v as u64)
        } else {
            self.head(major::NINT, (-1 - v) as u64)
        }
    }

    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.head(major::BYTES, b.len() as u64).raw(b)
    }

    pub fn text(&mut self, s: &str) -> &mut Self {
        self.head(major::TEXT, s.len() as u64).raw(s.as_bytes())
    }

    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.raw(&[if v { 0xF5 } else { 0xF4 }])
    }

    pub fn array(&mut self, n: usize) -> &mut Self {
        self.head(major::ARRAY, n as u64)
    }

    pub fn map(&mut self, n: usize) -> &mut Self {
        self.head(major::MAP, n as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(f: impl FnOnce(&mut Writer<'_>)) -> Vec<u8> {
        let mut buf = [0u8; 256];
        let mut w = Writer::new(&mut buf);
        f(&mut w);
        let n = w.finish().unwrap();
        buf[..n].to_vec()
    }

    /// RFC 8949 Appendix A, the examples this subset covers, both directions.
    #[test]
    fn rfc8949_appendix_a_integers() {
        let cases: &[(i64, &[u8])] = &[
            (0, &[0x00]),
            (1, &[0x01]),
            (10, &[0x0a]),
            (23, &[0x17]),
            (24, &[0x18, 0x18]),
            (25, &[0x18, 0x19]),
            (100, &[0x18, 0x64]),
            (1000, &[0x19, 0x03, 0xe8]),
            (1_000_000, &[0x1a, 0x00, 0x0f, 0x42, 0x40]),
            (
                1_000_000_000_000,
                &[0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00],
            ),
            (-1, &[0x20]),
            (-10, &[0x29]),
            (-100, &[0x38, 0x63]),
            (-1000, &[0x39, 0x03, 0xe7]),
        ];
        for &(v, bytes) in cases {
            assert_eq!(
                enc(|w| {
                    w.int(v);
                }),
                bytes,
                "{v}"
            );
            let mut r = Reader::new(bytes);
            assert_eq!(r.int().unwrap(), v);
            r.finish().unwrap();
        }
    }

    #[test]
    fn rfc8949_appendix_a_strings_and_containers() {
        assert_eq!(
            enc(|w| {
                w.bytes(&[]);
            }),
            [0x40]
        );
        assert_eq!(
            enc(|w| {
                w.bytes(&[1, 2, 3, 4]);
            }),
            [0x44, 1, 2, 3, 4]
        );
        assert_eq!(
            enc(|w| {
                w.text("");
            }),
            [0x60]
        );
        assert_eq!(
            enc(|w| {
                w.text("a");
            }),
            [0x61, 0x61]
        );
        assert_eq!(
            enc(|w| {
                w.text("IETF");
            }),
            [0x64, 0x49, 0x45, 0x54, 0x46]
        );
        assert_eq!(
            enc(|w| {
                w.text("\u{00fc}");
            }),
            [0x62, 0xc3, 0xbc],
            "UTF-8 bytes, counted in bytes"
        );
        assert_eq!(
            enc(|w| {
                w.bool(false);
            }),
            [0xf4]
        );
        assert_eq!(
            enc(|w| {
                w.bool(true);
            }),
            [0xf5]
        );
        // [1, [2, 3], [4, 5]]
        let nested = [0x83, 0x01, 0x82, 0x02, 0x03, 0x82, 0x04, 0x05];
        assert_eq!(
            enc(|w| {
                w.array(3)
                    .uint(1)
                    .array(2)
                    .uint(2)
                    .uint(3)
                    .array(2)
                    .uint(4)
                    .uint(5);
            }),
            nested
        );
        let mut r = Reader::new(&nested);
        r.skip(MAX_DEPTH).unwrap();
        r.finish().unwrap();
        // {1: 2, 3: 4}
        let m = [0xa2, 0x01, 0x02, 0x03, 0x04];
        let mut r = Reader::new(&m);
        let mut map = r.map().unwrap();
        assert_eq!(r.key(&mut map).unwrap(), Some(Key::Int(1)));
        assert_eq!(r.uint().unwrap(), 2);
        assert_eq!(r.key(&mut map).unwrap(), Some(Key::Int(3)));
        assert_eq!(r.uint().unwrap(), 4);
        assert_eq!(r.key(&mut map).unwrap(), None);
        r.finish().unwrap();
        // {"a": 1, "b": [2, 3]}
        let m = [0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x82, 0x02, 0x03];
        let mut r = Reader::new(&m);
        r.skip(MAX_DEPTH).unwrap();
        r.finish().unwrap();
    }

    #[test]
    fn a_non_shortest_form_is_refused() {
        // 0 written in one extra byte, 255 in two, 65535 in four, and a length the same.
        for bad in [
            &[0x18, 0x00][..],
            &[0x18, 0x17],
            &[0x19, 0x00, 0xff],
            &[0x1a, 0x00, 0x00, 0xff, 0xff],
            &[0x1b, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff],
            &[0x58, 0x01, 0xaa],
            &[0x38, 0x00],
        ] {
            assert_eq!(
                Reader::new(bad).skip(MAX_DEPTH),
                Err(Error::Invalid),
                "{bad:02x?}"
            );
        }
    }

    #[test]
    fn indefinite_lengths_tags_floats_and_reserved_values_are_refused() {
        for bad in [
            &[0x5f, 0x41, 0x01, 0xff][..], // indefinite byte string
            &[0x9f, 0x01, 0xff],           // indefinite array
            &[0xbf, 0x01, 0x02, 0xff],     // indefinite map
            &[0xc1, 0x1a, 0, 0, 0, 1],     // tag 1 (epoch time)
            &[0xf9, 0x3c, 0x00],           // half float 1.0
            &[0xfb, 0x3f, 0xf1, 0x99, 0x99, 0x99, 0x99, 0x99, 0x9a], // double 1.1
            &[0xf7],                       // undefined
            &[0xf8, 0xff],                 // simple(255)
            &[0x1c],                       // reserved
            &[0x1f],                       // break on its own
        ] {
            assert_eq!(
                Reader::new(bad).skip(MAX_DEPTH),
                Err(Error::Invalid),
                "{bad:02x?}"
            );
        }
        // null is fine to step over (CTAP never needs it, but may carry it).
        Reader::new(&[0xf6]).skip(1).unwrap();
    }

    #[test]
    fn keys_out_of_canonical_order_or_repeated_are_refused() {
        // {3: 0, 1: 0}: out of order.
        let mut r = Reader::new(&[0xa2, 0x03, 0x00, 0x01, 0x00]);
        let mut m = r.map().unwrap();
        r.key(&mut m).unwrap();
        r.uint().unwrap();
        assert_eq!(r.key(&mut m), Err(Error::Invalid));
        // {1: 0, 1: 0}: repeated.
        let mut r = Reader::new(&[0xa2, 0x01, 0x00, 0x01, 0x00]);
        let mut m = r.map().unwrap();
        r.key(&mut m).unwrap();
        r.uint().unwrap();
        assert_eq!(r.key(&mut m), Err(Error::Invalid));
        // Length first: "up" (2 bytes of text) sorts before "plat" whatever the letters.
        let ok = [
            0xa2, 0x62, b'u', b'p', 0xf5, 0x64, b'p', b'l', b'a', b't', 0xf4,
        ];
        Reader::new(&ok).skip(MAX_DEPTH).unwrap();
        let bad = [
            0xa2, 0x64, b'p', b'l', b'a', b't', 0xf4, 0x62, b'u', b'p', 0xf5,
        ];
        assert_eq!(Reader::new(&bad).skip(MAX_DEPTH), Err(Error::Invalid));
        // And integers before negative integers of the same length: 0x01 < 0x20.
        Reader::new(&[0xa2, 0x01, 0x00, 0x20, 0x00])
            .skip(2)
            .unwrap();
        assert_eq!(
            Reader::new(&[0xa2, 0x20, 0x00, 0x01, 0x00]).skip(2),
            Err(Error::Invalid)
        );
    }

    #[test]
    fn counts_and_lengths_past_the_buffer_are_refused_before_anything_is_believed() {
        // A byte string claiming 4 GiB, an array claiming 2^32 items, a map claiming more
        // entries than there are bytes left.
        for bad in [
            &[0x5a, 0xff, 0xff, 0xff, 0xff, 0x00][..],
            &[0x9a, 0xff, 0xff, 0xff, 0xff],
            &[0xa3, 0x01, 0x02],
            &[0x62, b'a'],
        ] {
            assert_eq!(
                Reader::new(bad).skip(MAX_DEPTH),
                Err(Error::Invalid),
                "{bad:02x?}"
            );
        }
    }

    #[test]
    fn nesting_past_the_limit_is_refused() {
        let deep = [0x81u8; 10];
        let mut v = deep.to_vec();
        v.push(0x00);
        assert_eq!(Reader::new(&v).skip(MAX_DEPTH), Err(Error::TooDeep));
        let ok = [0x81, 0x81, 0x00];
        Reader::new(&ok).skip(MAX_DEPTH).unwrap();
    }

    #[test]
    fn text_must_be_utf8_and_types_must_match() {
        assert_eq!(Reader::new(&[0x62, 0xc3, 0x28]).text(), Err(Error::Invalid));
        // A text where bytes were wanted is the wrong type, and the reader has not moved.
        let mut r = Reader::new(&[0x61, b'a']);
        assert_eq!(r.bytes(), Err(Error::Unexpected));
        assert_eq!(r.text().unwrap(), "a");
        assert_eq!(Reader::new(&[0x01]).bool(), Err(Error::Unexpected));
        assert_eq!(Reader::new(&[0x20]).uint(), Err(Error::Unexpected));
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut r = Reader::new(&[0x01, 0x02]);
        r.uint().unwrap();
        assert_eq!(r.finish(), Err(Error::Invalid));
    }

    #[test]
    fn the_writer_reports_overflow_rather_than_truncating() {
        let mut buf = [0u8; 3];
        let mut w = Writer::new(&mut buf);
        w.text("four");
        assert_eq!(w.finish(), Err(Error::Overflow));
    }

    #[test]
    fn integer_extremes_round_trip() {
        for v in [
            i64::MIN,
            i64::MIN + 1,
            -24,
            -25,
            -256,
            -257,
            i64::MAX,
            65535,
            65536,
        ] {
            let b = enc(|w| {
                w.int(v);
            });
            assert_eq!(Reader::new(&b).int().unwrap(), v, "{v}");
        }
        // 2^64-1 as a positive integer is valid CBOR, but not an i64.
        let big = [0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(Reader::new(&big).int(), Err(Error::Invalid));
        assert_eq!(Reader::new(&big).uint().unwrap(), u64::MAX);
    }
}
