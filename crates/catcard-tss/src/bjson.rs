//! A compact, lossless binary form of the JSON tsslib speaks.
//!
//! tsslib's wire messages and its key save format are JSON, and it spends most of their
//! bytes on two habits: byte strings written as base64 text, and -- in a saved key --
//! the OT-extension seeds written as arrays of decimal numbers, about 3.6 characters per
//! byte. A 2-of-2 key is 45 KB of JSON and 12 KB of information. Both the settings store
//! and a QR code pay for every byte, so this module re-encodes the *text*, token by
//! token, and back:
//!
//! | tag | JSON                                   | binary                          |
//! |-----|----------------------------------------|---------------------------------|
//! | 0   | `null`                                 | -                               |
//! | 1/2 | `false` / `true`                       | -                               |
//! | 3   | an unsigned integer, canonical decimal | len, big-endian magnitude       |
//! | 4   | any other number                       | len, the text                   |
//! | 5   | a string                               | len, the text between the quotes |
//! | 6   | a string that is canonical base64      | len, the decoded bytes          |
//! | 7   | a non-empty array of integers 0..=255  | len, one byte each              |
//! | 8   | an array                               | values, then tag 10             |
//! | 9   | an object                              | (len+1, key text, value)*, 0    |
//!
//! Lengths are LEB128. "Canonical" is checked by a round trip, so every encoding decodes
//! to the text it came from (whitespace aside -- serde_json writes none). Only that
//! property is relied on: the decoded text goes to serde_json, which is the parser.
//!
//! # Secret material
//!
//! A saved key's text holds the member's secret share (a decimal number) and its OT
//! seeds. So both directions size their output exactly in a first, counting pass and
//! write it in a second: the output `Vec` never grows, and growing is what leaves
//! unwiped copies of a buffer behind in freed heap. Scratch for the decimal conversion
//! lives on the stack and is wiped. The caller owns -- and wipes -- input and output.
//!
//! The decimal conversion's running time depends on the number's length, which for a
//! scalar leaks whether it has leading zero bytes; tsslib's own decimal writer has the
//! same property. Nothing else here branches on a value.

use alloc::vec::Vec;
use zeroize::Zeroize;

use crate::Error;

const T_NULL: u8 = 0;
const T_FALSE: u8 = 1;
const T_TRUE: u8 = 2;
const T_UINT: u8 = 3;
const T_NUM: u8 = 4;
const T_STR: u8 = 5;
const T_B64: u8 = 6;
const T_BYTES: u8 = 7;
const T_ARR: u8 = 8;
const T_OBJ: u8 = 9;
const T_END: u8 = 10;

/// Deepest nesting either direction accepts. tsslib's documents are four deep.
const MAX_DEPTH: usize = 16;

/// Longest unsigned integer carried as a magnitude: 64 bytes, 155 decimal digits.
const MAX_UINT_BYTES: usize = 64;
const MAX_UINT_DIGITS: usize = 155;

const BAD: Error = Error::Format("compact json");

/// Where output goes: counted first, then written.
trait Sink {
    fn put(&mut self, b: u8);
    fn put_all(&mut self, bytes: &[u8]);
}

struct Count(usize);

impl Sink for Count {
    fn put(&mut self, _: u8) {
        self.0 += 1;
    }
    fn put_all(&mut self, bytes: &[u8]) {
        self.0 += bytes.len();
    }
}

impl Sink for Vec<u8> {
    fn put(&mut self, b: u8) {
        debug_assert!(self.len() < self.capacity());
        self.push(b);
    }
    fn put_all(&mut self, bytes: &[u8]) {
        debug_assert!(self.len() + bytes.len() <= self.capacity());
        self.extend_from_slice(bytes);
    }
}

fn put_len(out: &mut impl Sink, mut v: usize) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.put(b);
            return;
        }
        out.put(b | 0x80);
    }
}

/// JSON text to compact binary. The result is exactly sized.
pub fn encode(json: &[u8]) -> Result<Vec<u8>, Error> {
    let mut count = Count(0);
    encode_into(json, &mut count)?;
    let mut out = Vec::with_capacity(count.0);
    encode_into(json, &mut out)?;
    Ok(out)
}

/// Compact binary to JSON text. The result is exactly sized.
pub fn decode(bin: &[u8]) -> Result<Vec<u8>, Error> {
    let mut count = Count(0);
    decode_into(bin, &mut count)?;
    let mut out = Vec::with_capacity(count.0);
    decode_into(bin, &mut out)?;
    Ok(out)
}

// ---------------------------------------------------------------------------------------
// Text to binary
// ---------------------------------------------------------------------------------------

struct Text<'a> {
    s: &'a [u8],
    at: usize,
}

impl Text<'_> {
    fn skip_ws(&mut self) {
        while let Some(b' ' | b'\n' | b'\r' | b'\t') = self.s.get(self.at) {
            self.at += 1;
        }
    }

    fn peek(&mut self) -> Result<u8, Error> {
        self.skip_ws();
        self.s.get(self.at).copied().ok_or(BAD)
    }

    fn expect(&mut self, b: u8) -> Result<(), Error> {
        if self.peek()? != b {
            return Err(BAD);
        }
        self.at += 1;
        Ok(())
    }

    fn literal(&mut self, word: &[u8]) -> Result<(), Error> {
        if self.s[self.at..].starts_with(word) {
            self.at += word.len();
            Ok(())
        } else {
            Err(BAD)
        }
    }

    /// The raw text of a string, between its quotes, escapes left as written.
    fn string(&mut self) -> Result<&[u8], Error> {
        self.expect(b'"')?;
        let start = self.at;
        loop {
            match self.s.get(self.at).copied() {
                None => return Err(BAD),
                Some(b'"') => break,
                Some(b'\\') => self.at += 2,
                Some(c) if c < 0x20 => return Err(BAD),
                Some(_) => self.at += 1,
            }
        }
        let raw = self.s.get(start..self.at).ok_or(BAD)?;
        self.at += 1;
        Ok(raw)
    }

    fn number(&mut self) -> &[u8] {
        let start = self.at;
        while let Some(b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E') = self.s.get(self.at) {
            self.at += 1;
        }
        &self.s[start..self.at]
    }
}

fn encode_into(json: &[u8], out: &mut impl Sink) -> Result<(), Error> {
    let mut t = Text { s: json, at: 0 };
    value(&mut t, out, 0)?;
    t.skip_ws();
    if t.at != json.len() {
        return Err(BAD);
    }
    Ok(())
}

fn value(t: &mut Text<'_>, out: &mut impl Sink, depth: usize) -> Result<(), Error> {
    if depth > MAX_DEPTH {
        return Err(BAD);
    }
    match t.peek()? {
        b'n' => {
            t.literal(b"null")?;
            out.put(T_NULL);
        }
        b'f' => {
            t.literal(b"false")?;
            out.put(T_FALSE);
        }
        b't' => {
            t.literal(b"true")?;
            out.put(T_TRUE);
        }
        b'"' => {
            let raw = t.string()?;
            string(raw, out);
        }
        b'-' | b'0'..=b'9' => {
            let raw = t.number();
            number(raw, out)?;
        }
        b'[' => {
            if let Some(len) = byte_array_len(t) {
                out.put(T_BYTES);
                put_len(out, len);
                t.at += 1;
                for i in 0..len {
                    if i > 0 {
                        t.expect(b',')?;
                    }
                    t.skip_ws();
                    let raw = t.number();
                    out.put(small_uint(raw).ok_or(BAD)?);
                }
                t.expect(b']')?;
                return Ok(());
            }
            t.at += 1;
            out.put(T_ARR);
            if t.peek()? == b']' {
                t.at += 1;
            } else {
                loop {
                    value(t, out, depth + 1)?;
                    match t.peek()? {
                        b',' => t.at += 1,
                        b']' => {
                            t.at += 1;
                            break;
                        }
                        _ => return Err(BAD),
                    }
                }
            }
            out.put(T_END);
        }
        b'{' => {
            t.at += 1;
            out.put(T_OBJ);
            if t.peek()? == b'}' {
                t.at += 1;
            } else {
                loop {
                    let key = t.string()?;
                    put_len(out, key.len() + 1);
                    out.put_all(key);
                    t.expect(b':')?;
                    value(t, out, depth + 1)?;
                    match t.peek()? {
                        b',' => t.at += 1,
                        b'}' => {
                            t.at += 1;
                            break;
                        }
                        _ => return Err(BAD),
                    }
                }
            }
            put_len(out, 0);
        }
        _ => return Err(BAD),
    }
    Ok(())
}

fn string(raw: &[u8], out: &mut impl Sink) {
    let mut buf = [0u8; 3];
    if let Some(n) = base64_len(raw) {
        out.put(T_B64);
        put_len(out, n);
        for quad in raw.chunks(4) {
            let k = base64_quad(quad, &mut buf);
            out.put_all(&buf[..k]);
        }
        buf.zeroize();
        return;
    }
    out.put(T_STR);
    put_len(out, raw.len());
    out.put_all(raw);
}

fn number(raw: &[u8], out: &mut impl Sink) -> Result<(), Error> {
    if raw.is_empty() {
        return Err(BAD);
    }
    if is_canonical_uint(raw) && raw.len() <= MAX_UINT_DIGITS {
        let mut mag = [0u8; MAX_UINT_BYTES];
        let used = decimal_to_be(raw, &mut mag);
        let r = match used {
            Some(n) => {
                out.put(T_UINT);
                put_len(out, n);
                out.put_all(&mag[MAX_UINT_BYTES - n..]);
                Ok(())
            }
            None => Err(BAD),
        };
        mag.zeroize();
        return r;
    }
    out.put(T_NUM);
    put_len(out, raw.len());
    out.put_all(raw);
    Ok(())
}

fn is_canonical_uint(raw: &[u8]) -> bool {
    !raw.is_empty() && raw.iter().all(u8::is_ascii_digit) && (raw.len() == 1 || raw[0] != b'0')
}

/// `raw` as a byte, if it is a canonical integer 0..=255.
fn small_uint(raw: &[u8]) -> Option<u8> {
    if !is_canonical_uint(raw) || raw.len() > 3 {
        return None;
    }
    let v = raw
        .iter()
        .fold(0u32, |acc, d| acc * 10 + u32::from(d - b'0'));
    u8::try_from(v).ok()
}

/// If the array at `t` (on its `[`) holds only integers 0..=255, how many. Looks ahead
/// without consuming.
fn byte_array_len(t: &mut Text<'_>) -> Option<usize> {
    let mut probe = Text { s: t.s, at: t.at };
    probe.expect(b'[').ok()?;
    let mut n = 0usize;
    loop {
        probe.skip_ws();
        let raw = probe.number();
        small_uint(raw)?;
        n += 1;
        match probe.peek().ok()? {
            b',' => probe.at += 1,
            b']' => return Some(n),
            _ => return None,
        }
    }
}

/// Decimal digits to a big-endian magnitude at the end of `out`; the count of bytes
/// used (zero for "0").
fn decimal_to_be(digits: &[u8], out: &mut [u8; MAX_UINT_BYTES]) -> Option<usize> {
    out.fill(0);
    for d in digits {
        let mut carry = u32::from(d - b'0');
        for b in out.iter_mut().rev() {
            let v = u32::from(*b) * 10 + carry;
            *b = v as u8;
            carry = v >> 8;
        }
        if carry != 0 {
            return None;
        }
    }
    let lead = out.iter().position(|&b| b != 0).unwrap_or(MAX_UINT_BYTES);
    Some(MAX_UINT_BYTES - lead)
}

// ---------------------------------------------------------------------------------------
// Binary to text
// ---------------------------------------------------------------------------------------

struct Bin<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Bin<'a> {
    fn byte(&mut self) -> Result<u8, Error> {
        let v = *self.b.get(self.at).ok_or(BAD)?;
        self.at += 1;
        Ok(v)
    }

    fn len(&mut self) -> Result<usize, Error> {
        let mut v = 0usize;
        for shift in (0..35).step_by(7) {
            let b = self.byte()?;
            v |= usize::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                // A non-minimal encoding would give one value two forms.
                if b == 0 && shift > 0 {
                    return Err(BAD);
                }
                return Ok(v);
            }
        }
        Err(BAD)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(n).ok_or(BAD)?;
        let s = self.b.get(self.at..end).ok_or(BAD)?;
        self.at = end;
        Ok(s)
    }
}

fn decode_into(bin: &[u8], out: &mut impl Sink) -> Result<(), Error> {
    let mut b = Bin { b: bin, at: 0 };
    let tag = b.byte()?;
    unvalue(&mut b, tag, out, 0)?;
    if b.at != bin.len() {
        return Err(BAD);
    }
    Ok(())
}

fn unvalue(b: &mut Bin<'_>, tag: u8, out: &mut impl Sink, depth: usize) -> Result<(), Error> {
    if depth > MAX_DEPTH {
        return Err(BAD);
    }
    match tag {
        T_NULL => out.put_all(b"null"),
        T_FALSE => out.put_all(b"false"),
        T_TRUE => out.put_all(b"true"),
        T_UINT => {
            let n = b.len()?;
            let mag = b.take(n)?;
            if n > MAX_UINT_BYTES || mag.first() == Some(&0) {
                return Err(BAD);
            }
            be_to_decimal(mag, out);
        }
        T_NUM => {
            let n = b.len()?;
            let raw = b.take(n)?;
            if raw.is_empty()
                || is_canonical_uint(raw)
                || !raw
                    .iter()
                    .all(|c| matches!(c, b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E'))
            {
                return Err(BAD);
            }
            out.put_all(raw);
        }
        T_STR => {
            let n = b.len()?;
            let raw = b.take(n)?;
            if !plain_string(raw) || base64_len(raw).is_some() {
                return Err(BAD);
            }
            out.put(b'"');
            out.put_all(raw);
            out.put(b'"');
        }
        T_B64 => {
            let n = b.len()?;
            let bytes = b.take(n)?;
            out.put(b'"');
            let mut quad = [0u8; 4];
            for chunk in bytes.chunks(3) {
                base64_chunk(chunk, &mut quad);
                out.put_all(&quad);
            }
            quad.zeroize();
            out.put(b'"');
        }
        T_BYTES => {
            let n = b.len()?;
            if n == 0 {
                return Err(BAD);
            }
            let bytes = b.take(n)?;
            out.put(b'[');
            let mut digits = [0u8; 3];
            for (i, &v) in bytes.iter().enumerate() {
                if i > 0 {
                    out.put(b',');
                }
                let k = small_decimal(v, &mut digits);
                out.put_all(&digits[3 - k..]);
            }
            digits.zeroize();
            out.put(b']');
        }
        T_ARR => {
            out.put(b'[');
            let mut first = true;
            loop {
                let tag = b.byte()?;
                if tag == T_END {
                    break;
                }
                if !first {
                    out.put(b',');
                }
                first = false;
                unvalue(b, tag, out, depth + 1)?;
            }
            out.put(b']');
        }
        T_OBJ => {
            out.put(b'{');
            let mut first = true;
            while let Some(key) = key_or_end(b)? {
                if !first {
                    out.put(b',');
                }
                first = false;
                if !plain_string(key) {
                    return Err(BAD);
                }
                out.put(b'"');
                out.put_all(key);
                out.put_all(b"\":");
                let tag = b.byte()?;
                unvalue(b, tag, out, depth + 1)?;
            }
            out.put(b'}');
        }
        _ => return Err(BAD),
    }
    Ok(())
}

/// A string body that can sit between quotes as-is: no bare quote, no control
/// character, no dangling escape.
fn plain_string(raw: &[u8]) -> bool {
    let mut i = 0;
    while i < raw.len() {
        match raw[i] {
            b'"' => return false,
            c if c < 0x20 => return false,
            b'\\' => {
                if i + 1 >= raw.len() {
                    return false;
                }
                i += 2;
            }
            _ => i += 1,
        }
    }
    true
}

fn small_decimal(mut v: u8, out: &mut [u8; 3]) -> usize {
    let mut k = 0;
    loop {
        out[2 - k] = b'0' + v % 10;
        v /= 10;
        k += 1;
        if v == 0 {
            return k;
        }
    }
}

/// A big-endian magnitude (no leading zero byte) as decimal digits.
fn be_to_decimal(mag: &[u8], out: &mut impl Sink) {
    if mag.is_empty() {
        out.put(b'0');
        return;
    }
    let mut work = [0u8; MAX_UINT_BYTES];
    let mut digits = [0u8; MAX_UINT_DIGITS];
    let w = &mut work[..mag.len()];
    w.copy_from_slice(mag);
    let mut n = 0;
    while w.iter().any(|&b| b != 0) {
        let mut rem = 0u32;
        for b in w.iter_mut() {
            let v = (rem << 8) | u32::from(*b);
            *b = (v / 10) as u8;
            rem = v % 10;
        }
        digits[MAX_UINT_DIGITS - 1 - n] = b'0' + rem as u8;
        n += 1;
    }
    out.put_all(&digits[MAX_UINT_DIGITS - n..]);
    work.zeroize();
    digits.zeroize();
}

// ---------------------------------------------------------------------------------------
// Object keys
// ---------------------------------------------------------------------------------------
//
// An object's members are (length, key, value). Where an array's end is a tag, an
// object's would sit where a key length goes, and every byte is a possible length. So a
// key's length is written plus one, and the object ends with a zero: an empty key --
// legal JSON -- is the single byte 1.

fn key_or_end<'a>(b: &mut Bin<'a>) -> Result<Option<&'a [u8]>, Error> {
    let n = b.len()?;
    if n == 0 {
        return Ok(None);
    }
    Ok(Some(b.take(n - 1)?))
}

// ---------------------------------------------------------------------------------------
// Base64 (RFC 4648 §4, standard alphabet, padded) -- what tsslib writes byte strings as
// ---------------------------------------------------------------------------------------

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// The decoded length, if `raw` is non-empty canonical padded base64 -- the only form
/// that re-encodes to itself.
fn base64_len(raw: &[u8]) -> Option<usize> {
    if raw.is_empty() || !raw.len().is_multiple_of(4) {
        return None;
    }
    let pad = raw.iter().rev().take_while(|&&c| c == b'=').count();
    if pad > 2 {
        return None;
    }
    let body = &raw[..raw.len() - pad];
    if !body.iter().all(|&c| b64_value(c).is_some()) {
        return None;
    }
    // Canonical: the bits a padded final group does not carry must be zero.
    let last = b64_value(*body.last()?)?;
    let spare = match pad {
        1 => last & 0x03,
        2 => last & 0x0f,
        _ => 0,
    };
    if spare != 0 {
        return None;
    }
    Some(raw.len() / 4 * 3 - pad)
}

/// Decode one validated group of four; how many bytes it carries.
fn base64_quad(quad: &[u8], out: &mut [u8; 3]) -> usize {
    let v = |i: usize| b64_value(quad[i]).unwrap_or(0);
    let n = (u32::from(v(0)) << 18)
        | (u32::from(v(1)) << 12)
        | (u32::from(v(2)) << 6)
        | u32::from(v(3));
    out[0] = (n >> 16) as u8;
    out[1] = (n >> 8) as u8;
    out[2] = n as u8;
    3 - quad.iter().filter(|&&c| c == b'=').count()
}

fn base64_chunk(chunk: &[u8], out: &mut [u8; 4]) {
    let b = |i: usize| u32::from(chunk.get(i).copied().unwrap_or(0));
    let n = (b(0) << 16) | (b(1) << 8) | b(2);
    for (i, o) in out.iter_mut().enumerate() {
        *o = B64[((n >> (18 - 6 * i)) & 63) as usize];
    }
    if chunk.len() < 3 {
        out[3] = b'=';
    }
    if chunk.len() < 2 {
        out[2] = b'=';
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(json: &str) -> Vec<u8> {
        let bin = encode(json.as_bytes()).unwrap();
        let back = decode(&bin).unwrap();
        assert_eq!(core::str::from_utf8(&back).unwrap(), json);
        bin
    }

    #[test]
    fn every_token_kind_comes_back_as_written() {
        round_trip(
            r#"{"a":null,"b":true,"c":false,"d":0,"e":12345678901234567890123456789,"f":-3,"g":1.5e3}"#,
        );
        round_trip(
            r#"{"s":"dkls:keygen:r1bc","esc":"a\"b\\c\u0001","k":"3q2+7w==","e":"","x":[]}"#,
        );
        round_trip(r#"[[1,2,255],[0],[256],{"":1},{"0123456789":2}]"#);
    }

    #[test]
    fn byte_arrays_and_base64_shrink_to_their_bytes() {
        let bin = round_trip("[1,2,3,200,255]");
        assert_eq!(bin, [T_BYTES, 5, 1, 2, 3, 200, 255]);
        let bin = round_trip(r#""3q2+7w==""#);
        assert_eq!(bin, [T_B64, 4, 0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn non_canonical_forms_stay_text() {
        // Leading zero, a padding bit set: re-encoding would not give these back.
        round_trip("[01,2]");
        round_trip(r#""3q2+7x==""#);
        round_trip("007");
    }

    #[test]
    fn truncated_or_padded_binary_is_refused() {
        let bin = encode(br#"{"a":[1,2,3],"b":"xyz"}"#).unwrap();
        for cut in 0..bin.len() {
            assert!(decode(&bin[..cut]).is_err(), "cut at {cut}");
        }
        let mut long = bin.clone();
        long.push(0);
        assert!(decode(&long).is_err());
    }

    #[test]
    fn nesting_past_the_limit_is_refused() {
        let deep = "[".repeat(MAX_DEPTH + 2) + &"]".repeat(MAX_DEPTH + 2);
        assert!(encode(deep.as_bytes()).is_err());
    }
}
