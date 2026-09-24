//! Just enough CBOR for the UR transport and for the registry items this device reads.
//!
//! Definite lengths only, shortest-form on the way out, no floats and no indefinite
//! anything. Every registry item in BCR-2020-006's table is written by a conforming
//! encoder inside that subset, so that subset is the whole grammar here: a general
//! CBOR reader would be more code and more surface in the path that decides what gets
//! signed, to parse shapes a conforming sender never produces.
//!
//! Two shapes matter. A multi-part UR part is `[seqNum, seqLen, messageLen, checksum,
//! data]` -- [`part`] reads exactly that and nothing else. A registry item is a map,
//! sometimes under a tag, sometimes nested -- [`Reader`] walks those.
//!
//! Source: BCR-2024-001 for the part array, RFC 8949 for the encoding. [C]

use crate::Part;

/// What the bytes are not.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Ran out of bytes part way through a value.
    Short,
    /// An additional-information value this does not read: a reserved 28..=30, or 31,
    /// which is an indefinite length.
    Unsupported(u8),
    /// A major type where another was required.
    WrongType { expected: u8, found: u8 },
    /// Not an array of exactly five elements.
    NotAPart,
    /// An integer too large for the field it belongs to.
    TooLarge,
    /// A value nested, or an array sized, past what a bounded walk will follow.
    TooDeep,
    /// The output buffer is too small for what is being written.
    NoRoom,
    /// A text string that is not UTF-8, which CBOR says a text string is.
    NotText,
}

// Major types, RFC 8949 §3.1. [C]
pub const UINT: u8 = 0;
pub const NINT: u8 = 1;
pub const BYTES: u8 = 2;
pub const TEXT: u8 = 3;
pub const ARRAY: u8 = 4;
pub const MAP: u8 = 5;
pub const TAG: u8 = 6;
pub const SIMPLE: u8 = 7;

/// `false` and `true` as simple values 20 and 21. RFC 8949 §3.3. [C]
const FALSE: u8 = 0xF4;
const TRUE: u8 = 0xF5;

/// The most items [`Reader::skip`] will walk past in one call.
///
/// Skipping is how an unknown map entry is stepped over, and a hostile encoder can
/// claim an array of four billion elements in three bytes. The walk is iterative, so
/// there is no stack to blow, but it still has to end: past this it is refused rather
/// than counted out.
const SKIP_LIMIT: u32 = 4096;

/// Read one unsigned integer, returning it and what follows.
fn uint(at: &[u8]) -> Result<(u64, &[u8]), Error> {
    let (&head, rest) = at.split_first().ok_or(Error::Short)?;
    // Major type 0 is an unsigned integer; anything else here is not a part.
    if head >> 5 != UINT {
        return Err(Error::WrongType {
            expected: UINT,
            found: head >> 5,
        });
    }
    read_count(head & 0x1F, rest)
}

/// The count an item's additional-information field encodes, and what follows it.
fn read_count(info: u8, rest: &[u8]) -> Result<(u64, &[u8]), Error> {
    let width = match info {
        0..=23 => return Ok((info as u64, rest)),
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        // 28..=30 are reserved; 31 is an indefinite length, which nothing here has.
        other => return Err(Error::Unsupported(other)),
    };
    if rest.len() < width {
        return Err(Error::Short);
    }
    let (bytes, rest) = rest.split_at(width);
    let mut n = 0u64;
    for &b in bytes {
        n = n << 8 | b as u64;
    }
    Ok((n, rest))
}

/// Read a multi-part UR header, returning it and the range of `data` within `buf`.
///
/// A range rather than a slice: the caller owns the buffer and often wants to keep
/// using it, and handing back a borrow of it would stop that for no reason.
pub fn part(buf: &[u8]) -> Result<(Part, core::ops::Range<usize>), Error> {
    let (&head, rest) = buf.split_first().ok_or(Error::Short)?;
    // Major type 4 is an array, and a part is five elements.
    if head >> 5 != ARRAY {
        return Err(Error::NotAPart);
    }
    let (count, rest) = read_count(head & 0x1F, rest)?;
    if count != 5 {
        return Err(Error::NotAPart);
    }

    let (seq_num, rest) = uint(rest)?;
    let (seq_len, rest) = uint(rest)?;
    let (message_len, rest) = uint(rest)?;
    let (checksum, rest) = uint(rest)?;

    // The fifth element is the fragment, major type 2.
    let (&head, after) = rest.split_first().ok_or(Error::Short)?;
    if head >> 5 != BYTES {
        return Err(Error::NotAPart);
    }
    let (len, after) = read_count(head & 0x1F, after)?;
    let len = usize::try_from(len).map_err(|_| Error::TooLarge)?;
    if after.len() < len {
        return Err(Error::Short);
    }
    // Where that landed in the original buffer.
    let start = buf.len() - after.len();

    Ok((
        Part {
            seq_num: u32::try_from(seq_num).map_err(|_| Error::TooLarge)?,
            seq_len: u32::try_from(seq_len).map_err(|_| Error::TooLarge)?,
            message_len: u32::try_from(message_len).map_err(|_| Error::TooLarge)?,
            checksum: u32::try_from(checksum).map_err(|_| Error::TooLarge)?,
        },
        start..start + len,
    ))
}

// --- reading a registry item --------------------------------------------------------

/// A cursor over one CBOR document.
///
/// Every method either consumes exactly one well-formed item and advances, or fails and
/// leaves the cursor where it was -- so a caller that peeks, then reads, reads the thing
/// it peeked at.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub const fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    /// Whether every byte has been consumed. A registry item that leaves a tail is a
    /// different document than the one that was read, so callers check this.
    pub const fn at_end(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// The major type of the next item, without consuming it.
    pub fn peek(&self) -> Result<u8, Error> {
        self.buf.get(self.pos).map(|h| h >> 5).ok_or(Error::Short)
    }

    /// Read an item's head: its major type and the argument its additional information
    /// encodes.
    fn head(&mut self) -> Result<(u8, u64), Error> {
        let &first = self.buf.get(self.pos).ok_or(Error::Short)?;
        let rest = &self.buf[self.pos + 1..];
        let (arg, after) = read_count(first & 0x1F, rest)?;
        self.pos = self.buf.len() - after.len();
        Ok((first >> 5, arg))
    }

    /// Read a head that must be of a particular major type.
    fn head_of(&mut self, expected: u8) -> Result<u64, Error> {
        let found = self.peek()?;
        if found != expected {
            return Err(Error::WrongType { expected, found });
        }
        let (_, arg) = self.head()?;
        Ok(arg)
    }

    /// An unsigned integer.
    pub fn uint(&mut self) -> Result<u64, Error> {
        self.head_of(UINT)
    }

    /// An unsigned integer that must fit a `u32` -- every fingerprint, child index and
    /// coin type in the registry is one.
    pub fn u32(&mut self) -> Result<u32, Error> {
        u32::try_from(self.uint()?).map_err(|_| Error::TooLarge)
    }

    /// A signed integer: major type 0, or major type 1, where the argument `n` encodes
    /// `-1 - n`. RFC 8949 §3.1. [C]
    pub fn int(&mut self) -> Result<i64, Error> {
        let found = self.peek()?;
        let (major, arg) = match found {
            UINT | NINT => self.head()?,
            _ => {
                return Err(Error::WrongType {
                    expected: UINT,
                    found,
                });
            }
        };
        let arg = i64::try_from(arg).map_err(|_| Error::TooLarge)?;
        Ok(if major == NINT { -1 - arg } else { arg })
    }

    /// A byte string, borrowed from the document.
    /// A text string, which CBOR says is UTF-8 and this checks rather than assumes.
    pub fn text(&mut self) -> Result<&'a str, Error> {
        let at = self.pos;
        let len = self.head_of(TEXT)?;
        let len = usize::try_from(len).map_err(|_| Error::TooLarge)?;
        match self.buf.get(self.pos..self.pos + len) {
            Some(data) => {
                self.pos += len;
                core::str::from_utf8(data).map_err(|_| Error::NotText)
            }
            None => {
                self.pos = at;
                Err(Error::Short)
            }
        }
    }

    pub fn bytes(&mut self) -> Result<&'a [u8], Error> {
        let at = self.pos;
        let len = self.head_of(BYTES)?;
        let len = usize::try_from(len).map_err(|_| Error::TooLarge)?;
        match self.buf.get(self.pos..self.pos + len) {
            Some(data) => {
                self.pos += len;
                Ok(data)
            }
            None => {
                self.pos = at;
                Err(Error::Short)
            }
        }
    }

    /// The number of elements in a definite-length array.
    pub fn array(&mut self) -> Result<u64, Error> {
        self.head_of(ARRAY)
    }

    /// The number of pairs in a definite-length map.
    pub fn map(&mut self) -> Result<u64, Error> {
        self.head_of(MAP)
    }

    /// A tag number. The item it tags follows.
    pub fn tag(&mut self) -> Result<u64, Error> {
        self.head_of(TAG)
    }

    /// Whether the next item is a tag, without consuming it -- how an optional tag is
    /// tested for.
    pub fn is_tag(&self) -> bool {
        self.peek() == Ok(TAG)
    }

    /// The next item's tag number, without consuming it, or `None` if it is not a tag.
    ///
    /// Reading a chain of nested tags means deciding, tag by tag, whether the next one
    /// belongs to the chain or starts the thing the chain wraps.
    pub fn peek_tag(&self) -> Option<u64> {
        let mut probe = self.clone();
        probe.tag().ok()
    }

    /// `true` or `false`, and nothing else: the other simple values, and every float,
    /// are refused rather than coerced.
    pub fn bool(&mut self) -> Result<bool, Error> {
        match self.buf.get(self.pos) {
            Some(&TRUE) => {
                self.pos += 1;
                Ok(true)
            }
            Some(&FALSE) => {
                self.pos += 1;
                Ok(false)
            }
            Some(&other) if other >> 5 == SIMPLE => Err(Error::Unsupported(other & 0x1F)),
            Some(&other) => Err(Error::WrongType {
                expected: SIMPLE,
                found: other >> 5,
            }),
            None => Err(Error::Short),
        }
    }

    /// Step over one item, whatever it is -- an unknown map key's value, a field this
    /// does not read.
    ///
    /// Iterative, with a pending-item count rather than recursion, so a deeply nested
    /// document costs no stack; [`SKIP_LIMIT`] bounds how long it can run, because an
    /// array header of three bytes can claim four billion elements.
    pub fn skip(&mut self) -> Result<(), Error> {
        let mut pending: u64 = 1;
        let mut steps = 0u32;
        while pending > 0 {
            steps += 1;
            if steps > SKIP_LIMIT || pending > SKIP_LIMIT as u64 {
                return Err(Error::TooDeep);
            }
            pending -= 1;
            let (major, arg) = self.head()?;
            match major {
                UINT | NINT | SIMPLE => {}
                BYTES | TEXT => {
                    let len = usize::try_from(arg).map_err(|_| Error::TooLarge)?;
                    if self.buf.len() - self.pos < len {
                        return Err(Error::Short);
                    }
                    self.pos += len;
                }
                // `arg` is whatever the head claimed, up to `u64::MAX`, and adding it
                // to the count unchecked is an overflow -- which, with overflow checks
                // on and `panic = "abort"`, is a device reset from one scanned code. So
                // the sum is checked and bounded in the same step: anything past the
                // limit would be refused at the top of the loop anyway, and refusing it
                // here means the arithmetic never has to hold it.
                ARRAY => pending = bounded_add(pending, arg)?,
                // A map's pairs are two items each.
                MAP => pending = bounded_add(pending, arg.checked_mul(2).ok_or(Error::TooDeep)?)?,
                // A tag is followed by exactly the one item it tags. `pending` is at
                // most `SKIP_LIMIT` here, so this cannot overflow.
                _ => pending += 1,
            }
        }
        Ok(())
    }
}

/// `pending + claimed`, refused rather than wrapped, and refused past [`SKIP_LIMIT`].
///
/// The bound is checked here as well as at the top of [`Reader::skip`]'s loop so that
/// the count never has to hold a value it is about to refuse: a claim of `u64::MAX`
/// elements is not a large number to count down, it is an addition that does not fit.
fn bounded_add(pending: u64, claimed: u64) -> Result<u64, Error> {
    pending
        .checked_add(claimed)
        .filter(|&p| p <= SKIP_LIMIT as u64)
        .ok_or(Error::TooDeep)
}

// --- writing a registry item --------------------------------------------------------

/// A cursor that writes CBOR into a caller's buffer.
///
/// Shortest-form heads throughout: the registry's test vectors are byte-exact, and an
/// encoder that wrote `18 05` where `05` would do produces a different document with
/// the same meaning -- which is fine for a reader and useless for a comparison.
pub struct Writer<'a> {
    out: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    pub fn new(out: &'a mut [u8]) -> Self {
        Writer { out, pos: 0 }
    }

    /// How many bytes have been written.
    pub const fn len(&self) -> usize {
        self.pos
    }

    fn push(&mut self, byte: u8) -> Result<(), Error> {
        *self.out.get_mut(self.pos).ok_or(Error::NoRoom)? = byte;
        self.pos += 1;
        Ok(())
    }

    /// An item head: the major type and its argument, in the shortest form that holds
    /// the argument.
    pub fn head(&mut self, major: u8, arg: u64) -> Result<(), Error> {
        let major = major << 5;
        match arg {
            0..=23 => self.push(major | arg as u8),
            24..=0xFF => {
                self.push(major | 24)?;
                self.push(arg as u8)
            }
            0x100..=0xFFFF => {
                self.push(major | 25)?;
                self.raw(&(arg as u16).to_be_bytes())
            }
            0x1_0000..=0xFFFF_FFFF => {
                self.push(major | 26)?;
                self.raw(&(arg as u32).to_be_bytes())
            }
            _ => {
                self.push(major | 27)?;
                self.raw(&arg.to_be_bytes())
            }
        }
    }

    /// Bytes as they are, for a nested document already encoded.
    pub fn raw(&mut self, data: &[u8]) -> Result<(), Error> {
        let end = self.pos.checked_add(data.len()).ok_or(Error::NoRoom)?;
        self.out.get_mut(self.pos..end).ok_or(Error::NoRoom)?[..].copy_from_slice(data);
        self.pos = end;
        Ok(())
    }

    pub fn uint(&mut self, n: u64) -> Result<(), Error> {
        self.head(UINT, n)
    }

    /// A signed integer, as major type 0 or 1.
    pub fn int(&mut self, n: i64) -> Result<(), Error> {
        match n {
            0.. => self.head(UINT, n as u64),
            _ => self.head(NINT, (-1 - n) as u64),
        }
    }

    /// A text string: the same shape as a byte string, under its own major type.
    pub fn text(&mut self, s: &str) -> Result<(), Error> {
        self.head(TEXT, s.len() as u64)?;
        self.raw(s.as_bytes())
    }

    pub fn bytes(&mut self, data: &[u8]) -> Result<(), Error> {
        self.head(BYTES, data.len() as u64)?;
        self.raw(data)
    }

    pub fn array(&mut self, len: u64) -> Result<(), Error> {
        self.head(ARRAY, len)
    }

    pub fn map(&mut self, len: u64) -> Result<(), Error> {
        self.head(MAP, len)
    }

    pub fn tag(&mut self, tag: u64) -> Result<(), Error> {
        self.head(TAG, tag)
    }

    pub fn bool(&mut self, value: bool) -> Result<(), Error> {
        self.push(if value { TRUE } else { FALSE })
    }
}
