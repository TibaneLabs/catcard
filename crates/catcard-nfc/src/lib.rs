//! What goes into an NFC tag's memory so a phone tapped on it reads something, and what
//! comes back out of a tag a phone has written.
//!
//! The device writes the tag over I²C; a phone reads it over RF, expecting an **NFC Forum
//! Type 5** tag: a capability container at the start of user memory, then TLV blocks, one
//! of which holds an NDEF message. This crate builds those bytes and parses them back.
//! Nothing here touches hardware, so the format is settled on the host and the driver only
//! has to deliver it.
//!
//! Sources: NFC Forum Type 5 Tag, NDEF and RTD (URI, Text) specifications (public
//! standards), and hw-reference/datasheets/ST25DV64KC-st.pdf for the memory the CC
//! describes [C].
//!
//! # The shape of it
//!
//! ```text
//! CC (8 bytes)   E2 40 00 01 00 00 <MLEN hi> <MLEN lo>
//! TLV            03 <length>            NDEF message TLV
//! NDEF record    <header> 01 <payload length> 'U' <prefix> <uri text>
//! TLV            FE                     terminator
//! ```
//!
//! One record is the whole message, so its header carries both the message-begin and
//! message-end bits. A payload of 255 bytes or fewer takes the short form; anything longer
//! -- which a transaction's hex is -- takes the four-byte length.
//!
//! # The area is the tag's, not the buffer's
//!
//! Every builder takes the T5T `area` -- how many bytes of the part sit past the container
//! -- rather than reading it off the output buffer. The container tells a phone how much
//! room it has to **write**, and a forty-byte buffer holding a forty-byte record would
//! otherwise announce a forty-byte tag: a phone would then refuse to put a transaction on
//! a part with eight kilobytes free.
//!
//! # Reading is not trusting
//!
//! [`read`] parses a tag a *phone* wrote, so every length in it is someone else's number.
//! A length that runs past what was read is [`ReadError::Truncated`] and the record is not
//! produced -- never a shorter slice that pretends to be the whole of it.

#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]

/// The eight-byte capability container, for a tag whose T5T area is `area` bytes.
///
/// `E2` is the magic for the eight-byte form, which is what a memory bigger than 2040
/// bytes needs; `40` is version 1.0 with read and write always allowed; `01` says the tag
/// answers a multiple-block read. MLEN counts the area in eight-byte blocks and excludes
/// the container itself.
pub fn capability_container(area: usize) -> [u8; CC_LEN] {
    let blocks = (area / 8) as u16;
    [
        0xE2,
        0x40,
        0x00,
        0x01,
        0x00,
        0x00,
        (blocks >> 8) as u8,
        blocks as u8,
    ]
}

/// Length of the capability container this writes.
pub const CC_LEN: usize = 8;

/// The URI prefixes NDEF abbreviates to one byte. Only the two this device writes.
pub mod prefix {
    /// `http://www.`
    pub const HTTP_WWW: u8 = 0x01;
    /// `https://www.`
    pub const HTTPS_WWW: u8 = 0x02;
    /// `https://`
    pub const HTTPS: u8 = 0x04;
    /// No abbreviation: the URI is written whole.
    pub const NONE: u8 = 0x00;
}

/// The one-byte record types of the two well-known RTDs this device uses.
pub mod rtd {
    /// RTD "U": a URI.
    pub const URI: u8 = b'U';
    /// RTD "T": text with a language code.
    pub const TEXT: u8 = b'T';
}

/// The language a text record is tagged with. Two letters, so the status byte is `0x02`.
pub const TEXT_LANG: &[u8] = b"en";

/// What a text record's payload carries before the text itself: the status byte and the
/// language code.
const TEXT_HEAD: usize = 1 + TEXT_LANG.len();

/// Why a tag image could not be built.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// The tag is not big enough for this record.
    TooLong { needed: usize, room: usize },
}

/// Bytes a whole tag image takes for one record carrying `payload` bytes.
pub const fn record_image_len(payload: usize) -> usize {
    let record = if payload <= 255 { 4 } else { 7 } + payload;
    let tlv = if record < 255 { 2 } else { 4 };
    CC_LEN + tlv + record + 1 // the terminator
}

/// How many bytes a tag image for a URI of `uri_len` bytes (after the prefix byte) takes.
pub const fn image_len(uri_len: usize) -> usize {
    record_image_len(uri_len + 1) // the prefix byte
}

/// How many bytes a tag image for `text_len` bytes of text takes.
pub const fn text_image_len(text_len: usize) -> usize {
    record_image_len(TEXT_HEAD + text_len)
}

/// Write the container, the TLV header and the record header for a record of `kind`
/// carrying `payload` bytes. Returns where the payload goes.
fn open(out: &mut [u8], area: usize, kind: u8, payload: usize) -> Result<usize, Error> {
    let needed = record_image_len(payload);
    if out.len() < needed {
        return Err(Error::TooLong {
            needed,
            room: out.len(),
        });
    }
    let record_len = if payload <= 255 { 4 } else { 7 } + payload;

    out[..CC_LEN].copy_from_slice(&capability_container(area));
    let mut at = CC_LEN;

    // The NDEF TLV: type 3, then its length -- one byte, or the escape and two more.
    out[at] = 0x03;
    at += 1;
    if record_len < 255 {
        out[at] = record_len as u8;
        at += 1;
    } else {
        out[at] = 0xFF;
        out[at + 1] = (record_len >> 8) as u8;
        out[at + 2] = record_len as u8;
        at += 3;
    }

    // One record, which is the whole message: MB and ME both set, TNF 1 (well known).
    // SR as well where the payload is short enough for a one-byte length.
    let short = payload <= 255;
    out[at] = 0xC1 | if short { 0x10 } else { 0x00 };
    out[at + 1] = 1; // the type is one byte
    at += 2;
    if short {
        out[at] = payload as u8;
        at += 1;
    } else {
        out[at..at + 4].copy_from_slice(&(payload as u32).to_be_bytes());
        at += 4;
    }
    out[at] = kind;
    Ok(at + 1)
}

/// Write everything up to the URI text: the container, the TLV header and the record
/// header. Returns how many bytes were written, which is where the URI text goes.
///
/// Split in two because the URI this device writes is mostly a transaction's hex, which is
/// expanded straight into the buffer rather than built somewhere first.
pub fn begin(out: &mut [u8], area: usize, uri_len: usize, prefix: u8) -> Result<usize, Error> {
    let at = open(out, area, rtd::URI, uri_len + 1)?;
    out[at] = prefix;
    Ok(at + 1)
}

/// As [`begin`], for a text record: returns where the text goes.
pub fn begin_text(out: &mut [u8], area: usize, text_len: usize) -> Result<usize, Error> {
    let at = open(out, area, rtd::TEXT, TEXT_HEAD + text_len)?;
    // Status byte: bit 7 clear for UTF-8, the low six bits the language code's length.
    out[at] = TEXT_LANG.len() as u8;
    out[at + 1..at + 1 + TEXT_LANG.len()].copy_from_slice(TEXT_LANG);
    Ok(at + TEXT_HEAD)
}

/// Close the image: the TLV terminator after the record's payload. `at` is where it ended.
pub fn finish(out: &mut [u8], at: usize) -> Result<usize, Error> {
    if at >= out.len() {
        return Err(Error::TooLong {
            needed: at + 1,
            room: out.len(),
        });
    }
    out[at] = 0xFE;
    Ok(at + 1)
}

/// Build a whole image for `uri`, for callers that already hold the text.
pub fn uri_image(out: &mut [u8], area: usize, uri: &str, prefix: u8) -> Result<usize, Error> {
    let at = begin(out, area, uri.len(), prefix)?;
    out[at..at + uri.len()].copy_from_slice(uri.as_bytes());
    finish(out, at + uri.len())
}

/// Build a whole image holding one text record.
pub fn text_image(out: &mut [u8], area: usize, text: &str) -> Result<usize, Error> {
    let at = begin_text(out, area, text.len())?;
    out[at..at + text.len()].copy_from_slice(text.as_bytes());
    finish(out, at + text.len())
}

/// Build an image holding an **empty** NDEF message: a tag with nothing on it.
///
/// What a screen writes when it is done, so that an address or a signed transaction is not
/// left sitting on a tag for the next phone that comes near the device.
pub fn empty_image(out: &mut [u8], area: usize) -> Result<usize, Error> {
    let needed = CC_LEN + 3;
    if out.len() < needed {
        return Err(Error::TooLong {
            needed,
            room: out.len(),
        });
    }
    out[..CC_LEN].copy_from_slice(&capability_container(area));
    out[CC_LEN] = 0x03; // an NDEF TLV...
    out[CC_LEN + 1] = 0x00; // ...of no length
    out[CC_LEN + 2] = 0xFE; // and the terminator
    Ok(needed)
}

// ---------------------------------------------------------------------------
// Reading a tag back
// ---------------------------------------------------------------------------

/// Why a tag's bytes could not be read as records.
///
/// Separate from [`Error`] on purpose: that one is "this device asked for something that
/// does not fit", and these are "what came back from a phone is not what it claims". They
/// are different failures with different cures and should not share a name.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ReadError {
    /// No capability container at the start: this is not a formatted Type 5 tag.
    NoContainer,
    /// The container is there, but no NDEF message TLV follows it.
    NoMessage,
    /// A length runs past the bytes that were read. **Refused, never clamped.**
    Truncated,
    /// A record split across several (the chunk flag). Nothing this device talks to
    /// produces them at these sizes, and guessing at a reassembly would be inventing
    /// content.
    Chunked,
}

/// One NDEF record out of a tag.
///
/// The slices borrow the buffer the tag was read into: nothing is copied, so a record is
/// only as alive as the bytes behind it.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Record<'a> {
    /// Type name format: 1 well known, 2 MIME, 3 absolute URI, 4 external.
    pub tnf: u8,
    /// Whether this was the last record of the message.
    pub last: bool,
    /// The type name: `b"U"`, `b"T"`, a MIME type, an external type.
    pub kind: &'a [u8],
    /// The record's id, usually empty.
    pub id: &'a [u8],
    /// The payload, exactly as written -- with whatever header its type puts in front of
    /// it (a URI's prefix byte, a text record's status byte) still there.
    pub payload: &'a [u8],
}

/// Type name format: an NFC Forum well-known type, which is what [`rtd`] names.
pub const TNF_WELL_KNOWN: u8 = 1;
/// Type name format: the type name is a MIME type.
pub const TNF_MIME: u8 = 2;
/// Type name format: the type name is an absolute URI.
pub const TNF_ABSOLUTE_URI: u8 = 3;
/// Type name format: the type name is an external (domain-qualified) type.
pub const TNF_EXTERNAL: u8 = 4;

impl<'a> Record<'a> {
    /// Whether this is the well-known record type `kind` -- one of [`rtd`]'s.
    pub fn is(&self, kind: u8) -> bool {
        self.tnf == TNF_WELL_KNOWN && self.kind == [kind]
    }

    /// The text of an RTD Text record, without its status byte or language code.
    ///
    /// `None` for any other record, for UTF-16 text (bit 7 of the status byte, which this
    /// does not decode), and for a language code longer than the payload -- a length from
    /// the tag, so it is checked rather than trusted.
    pub fn text(&self) -> Option<&'a str> {
        if !self.is(rtd::TEXT) {
            return None;
        }
        let (&status, rest) = self.payload.split_first()?;
        if status & 0x80 != 0 {
            return None;
        }
        core::str::from_utf8(rest.get((status & 0x3F) as usize..)?).ok()
    }

    /// An RTD URI record as its abbreviation and the rest of the text.
    ///
    /// The two are not joined: doing so needs a buffer, and every caller here either wants
    /// the tail alone (a `bitcoin:` URI, written whole under [`prefix::NONE`]) or wants to
    /// show both. `None` for any other record, or for a prefix byte outside the table.
    pub fn uri(&self) -> Option<(&'static str, &'a str)> {
        if !self.is(rtd::URI) {
            return None;
        }
        let (&code, rest) = self.payload.split_first()?;
        Some((uri_prefix(code)?, core::str::from_utf8(rest).ok()?))
    }
}

/// The URI abbreviation table, as the NDEF URI RTD fixes it. `0x00` is "no abbreviation".
pub fn uri_prefix(code: u8) -> Option<&'static str> {
    const TABLE: [&str; 36] = [
        "",
        "http://www.",
        "https://www.",
        "http://",
        "https://",
        "tel:",
        "mailto:",
        "ftp://anonymous:anonymous@",
        "ftp://ftp.",
        "ftps://",
        "sftp://",
        "smb://",
        "nfs://",
        "ftp://",
        "dav://",
        "news:",
        "telnet://",
        "imap:",
        "rtsp://",
        "urn:",
        "pop:",
        "sip:",
        "sips:",
        "tftp:",
        "btspp://",
        "btl2cap://",
        "btgoep://",
        "tcpobex://",
        "irdaobex://",
        "file://",
        "urn:epc:id:",
        "urn:epc:tag:",
        "urn:epc:pat:",
        "urn:epc:raw:",
        "urn:epc:",
        "urn:nfc:",
    ];
    TABLE.get(code as usize).copied()
}

/// The records of the NDEF message in a tag image.
///
/// Stops for good at the first malformed record: after a length that cannot be trusted,
/// where the next record begins is a guess.
pub struct Records<'a> {
    rest: &'a [u8],
    done: bool,
}

impl<'a> Iterator for Records<'a> {
    type Item = Result<Record<'a>, ReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.rest.is_empty() {
            return None;
        }
        match parse_record(self.rest) {
            Ok((record, rest)) => {
                self.rest = rest;
                self.done = record.last;
                Some(Ok(record))
            }
            Err(why) => {
                self.done = true;
                Some(Err(why))
            }
        }
    }
}

/// Walk a tag image's container and TLVs to the NDEF message inside it.
///
/// `image` is however much of the tag was read: a message whose TLV claims more than that
/// is [`ReadError::Truncated`], because the rest of it was never seen.
pub fn read(image: &[u8]) -> Result<Records<'_>, ReadError> {
    // The container's first byte says which form it is: four bytes for a small memory,
    // eight for anything past 2040 bytes. Both are read, because a phone may reformat a
    // tag with either.
    let head = match image.first() {
        Some(0xE1) => 4,
        Some(0xE2) => CC_LEN,
        _ => return Err(ReadError::NoContainer),
    };
    let mut rest = image.get(head..).ok_or(ReadError::NoContainer)?;
    loop {
        let (&t, tail) = rest.split_first().ok_or(ReadError::NoMessage)?;
        match t {
            // The null TLV is one byte of padding and carries no length.
            0x00 => {
                rest = tail;
                continue;
            }
            // The terminator: everything past it is whatever was in the memory before.
            0xFE => return Err(ReadError::NoMessage),
            _ => {}
        }
        let (len, body) = tlv_len(tail)?;
        if len > body.len() {
            return Err(ReadError::Truncated);
        }
        // Type 3 is the NDEF message; 1 and 2 are the lock and memory control TLVs, which
        // describe the tag rather than carry content, and are stepped over.
        if t == 0x03 {
            return Ok(Records {
                rest: &body[..len],
                done: false,
            });
        }
        rest = &body[len..];
    }
}

/// A TLV's length and the bytes after it: one byte, or the `FF` escape and two more.
fn tlv_len(after_type: &[u8]) -> Result<(usize, &[u8]), ReadError> {
    let (&first, tail) = after_type.split_first().ok_or(ReadError::Truncated)?;
    if first != 0xFF {
        return Ok((first as usize, tail));
    }
    let two = tail.get(..2).ok_or(ReadError::Truncated)?;
    Ok((u16::from_be_bytes([two[0], two[1]]) as usize, &tail[2..]))
}

/// One record off the front of a message, and what follows it.
fn parse_record(bytes: &[u8]) -> Result<(Record<'_>, &[u8]), ReadError> {
    let (&header, mut rest) = bytes.split_first().ok_or(ReadError::Truncated)?;
    if header & 0x20 != 0 {
        return Err(ReadError::Chunked);
    }
    let (&type_len, after) = rest.split_first().ok_or(ReadError::Truncated)?;
    let type_len = type_len as usize;
    rest = after;

    let payload_len = if header & 0x10 != 0 {
        // SR: one byte of length.
        let (&n, after) = rest.split_first().ok_or(ReadError::Truncated)?;
        rest = after;
        n as usize
    } else {
        let four = rest.get(..4).ok_or(ReadError::Truncated)?;
        let n = u32::from_be_bytes([four[0], four[1], four[2], four[3]]);
        rest = &rest[4..];
        // A four-byte length from a tag can say four gigabytes. It is compared against
        // what was actually read, below; this only gets it into a `usize` without wrapping
        // on the way.
        usize::try_from(n).map_err(|_| ReadError::Truncated)?
    };
    let id_len = if header & 0x08 != 0 {
        let (&n, after) = rest.split_first().ok_or(ReadError::Truncated)?;
        rest = after;
        n as usize
    } else {
        0
    };

    // Each of these refuses rather than shortens: a record claiming more than is there is
    // a record this device has not got, not a smaller one.
    let kind = rest.get(..type_len).ok_or(ReadError::Truncated)?;
    rest = &rest[type_len..];
    let id = rest.get(..id_len).ok_or(ReadError::Truncated)?;
    rest = &rest[id_len..];
    let payload = rest.get(..payload_len).ok_or(ReadError::Truncated)?;

    Ok((
        Record {
            tnf: header & 0x07,
            last: header & 0x40 != 0,
            kind,
            id,
            payload,
        },
        &rest[payload_len..],
    ))
}

#[cfg(test)]
mod tests;
