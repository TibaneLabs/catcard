//! Just enough RLP to read a transaction, and to write one back for its hash.
//!
//! RLP is two things: a byte string, and a list of items. Everything else -- integers,
//! addresses, the transaction itself -- is one of those two carrying an agreed meaning.
//! So this decodes to `&[u8]` and to "a cursor over a list", and nothing else. The
//! meaning is applied a layer up, where it can be named.
//!
//! **Nothing is copied and nothing is allocated.** Every item read is a slice of the
//! caller's buffer, which is what lets a transaction be parsed in place out of whatever
//! it arrived in.
//!
//! Source: Ethereum Yellow Paper Appendix B, and the equivalent prose in
//! <https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/>.

/// Why some bytes are not the RLP they claimed to be.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// The item runs past the end of the input.
    Truncated,
    /// A length was written in more bytes than it needed, or with a leading zero: RLP
    /// has exactly one encoding per value, and accepting a second one is how two
    /// implementations disagree about what they signed.
    NotCanonical,
    /// A list was found where a string was wanted, or the other way about.
    WrongKind,
    /// A length that does not fit this machine's `usize`.
    TooLong,
}

/// One decoded item: where its payload is, and whether it was a list.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Item<'a> {
    pub payload: &'a [u8],
    pub list: bool,
    /// The whole item including its header, for a caller that needs to skip it or hash
    /// it exactly as it arrived.
    pub raw: &'a [u8],
}

/// Read one item from the front of `bytes`.
pub fn item(bytes: &[u8]) -> Result<Item<'_>, Error> {
    let &first = bytes.first().ok_or(Error::Truncated)?;
    let (head, len, list) = match first {
        // A single byte below 0x80 is itself, header and all.
        0x00..=0x7f => (0usize, 1usize, false),
        0x80..=0xb7 => (1, (first - 0x80) as usize, false),
        0xb8..=0xbf => (1 + (first - 0xb7) as usize, 0, false),
        0xc0..=0xf7 => (1, (first - 0xc0) as usize, true),
        0xf8..=0xff => (1 + (first - 0xf7) as usize, 0, true),
    };
    // The long forms carry the length in the bytes after the first.
    let len = if head > 1 {
        let n = head - 1;
        let bytes = bytes.get(1..1 + n).ok_or(Error::Truncated)?;
        // Minimal: no leading zero, and not a length that the short form could hold.
        if bytes[0] == 0 {
            return Err(Error::NotCanonical);
        }
        let mut v = 0usize;
        for &b in bytes {
            v = v
                .checked_mul(256)
                .and_then(|v| v.checked_add(b as usize))
                .ok_or(Error::TooLong)?;
        }
        if v < 56 {
            return Err(Error::NotCanonical);
        }
        v
    } else {
        len
    };
    let end = head.checked_add(len).ok_or(Error::TooLong)?;
    let raw = bytes.get(..end).ok_or(Error::Truncated)?;
    let payload = &raw[head..];
    // A single byte below 0x80 must be written as itself, not as a one-byte string.
    if head == 1 && !list && payload.len() == 1 && payload[0] < 0x80 {
        return Err(Error::NotCanonical);
    }
    Ok(Item { payload, list, raw })
}

/// A cursor over the items of a list.
#[derive(Copy, Clone)]
pub struct List<'a> {
    rest: &'a [u8],
}

impl<'a> List<'a> {
    /// Open `bytes` as a list, which it must be the whole of.
    pub fn open(bytes: &'a [u8]) -> Result<Self, Error> {
        let it = item(bytes)?;
        if !it.list {
            return Err(Error::WrongKind);
        }
        if it.raw.len() != bytes.len() {
            return Err(Error::Truncated);
        }
        Ok(List { rest: it.payload })
    }

    /// Whether every item has been taken.
    pub fn done(&self) -> bool {
        self.rest.is_empty()
    }

    /// The next item, whatever it is.
    pub fn next_item(&mut self) -> Result<Item<'a>, Error> {
        let it = item(self.rest)?;
        self.rest = &self.rest[it.raw.len()..];
        Ok(it)
    }

    /// The next item as a byte string.
    pub fn bytes(&mut self) -> Result<&'a [u8], Error> {
        let it = self.next_item()?;
        if it.list {
            return Err(Error::WrongKind);
        }
        Ok(it.payload)
    }

    /// The next item as a list, returned as its own cursor.
    pub fn list(&mut self) -> Result<List<'a>, Error> {
        let it = self.next_item()?;
        if !it.list {
            return Err(Error::WrongKind);
        }
        Ok(List { rest: it.payload })
    }

    /// The next item as an unsigned integer, which RLP writes big-endian with no
    /// leading zeros.
    ///
    /// Returned as the slice rather than a number: the values in a transaction run to
    /// 256 bits and only some of them fit a `u64`, so the caller says how wide it
    /// expects this one to be.
    pub fn uint(&mut self) -> Result<&'a [u8], Error> {
        let b = self.bytes()?;
        if b.first() == Some(&0) {
            return Err(Error::NotCanonical);
        }
        Ok(b)
    }

    /// What is left, for a caller that wants to skip the rest.
    pub fn remainder(&self) -> &'a [u8] {
        self.rest
    }
}

/// An unsigned integer as a `u64`, or `None` if it is wider than one.
pub fn as_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.len() > 8 {
        return None;
    }
    let mut v = 0u64;
    for &b in bytes {
        v = (v << 8) | b as u64;
    }
    Some(v)
}

/// An unsigned integer as a 256-bit big-endian value, right-aligned.
pub fn as_u256(bytes: &[u8]) -> Option<[u8; 32]> {
    if bytes.len() > 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    Some(out)
}

/// How many bytes the header of a string or list of `len` payload bytes takes.
const fn header_len(len: usize, single_small_byte: bool) -> usize {
    if single_small_byte {
        0
    } else if len < 56 {
        1
    } else {
        1 + len_of_len(len)
    }
}

const fn len_of_len(mut len: usize) -> usize {
    let mut n = 0;
    while len > 0 {
        n += 1;
        len >>= 8;
    }
    n
}

/// Write one byte string's header into `out`, returning what is left of it.
fn write_header(out: &mut [u8], len: usize, list: bool, short: bool) -> Option<&mut [u8]> {
    let base = if list { 0xc0u8 } else { 0x80u8 };
    if short {
        return Some(out);
    }
    if len < 56 {
        let (h, rest) = out.split_first_mut()?;
        *h = base + len as u8;
        return Some(rest);
    }
    let n = len_of_len(len);
    let (h, rest) = out.split_at_mut_checked(1 + n)?;
    h[0] = base + 55 + n as u8;
    for (i, slot) in h[1..].iter_mut().enumerate() {
        *slot = (len >> (8 * (n - 1 - i))) as u8;
    }
    Some(rest)
}

/// Build an RLP list of byte strings into `out`, returning the bytes written.
///
/// The writing half. Nothing on the signing path needs it -- what gets hashed is the
/// bytes exactly as they arrived -- but a caller that has to build a transaction, and
/// every test that has to build one to read back, does.
pub fn list_of<'o>(items: &[&[u8]], out: &'o mut [u8]) -> Option<&'o [u8]> {
    // Two passes: the payload's length decides the header's length.
    let payload: usize = items
        .iter()
        .map(|i| {
            let small = i.len() == 1 && i[0] < 0x80;
            header_len(i.len(), small) + i.len()
        })
        .sum();
    let total = header_len(payload, false) + payload;
    if out.len() < total {
        return None;
    }
    let (whole, _) = out.split_at_mut(total);
    let mut rest: &mut [u8] = whole;
    rest = write_header(rest, payload, true, false)?;
    for i in items {
        let small = i.len() == 1 && i[0] < 0x80;
        rest = write_header(rest, i.len(), false, small)?;
        let (slot, next) = rest.split_at_mut_checked(i.len())?;
        slot.copy_from_slice(i);
        rest = next;
    }
    Some(whole)
}
