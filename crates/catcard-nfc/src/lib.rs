//! What goes into an NFC tag's memory so a phone tapped on it opens a URL.
//!
//! The device writes the tag over I²C; a phone reads it over RF, expecting an **NFC Forum
//! Type 5** tag: a capability container at the start of user memory, then TLV blocks, one
//! of which holds an NDEF message. This crate builds those bytes. Nothing here touches
//! hardware, so the format is settled on the host and the driver only has to deliver it.
//!
//! Sources: NFC Forum Type 5 Tag and NDEF specifications (public standards), and
//! hw-reference/datasheets/ST25DV64KC-st.pdf for the memory the CC describes [C].
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
//! The URI is one record, and the record is the whole message, so the header carries both
//! the message-begin and message-end bits. A payload of 255 bytes or fewer takes the short
//! form; anything longer -- which a transaction's hex is -- takes the four-byte length.

#![cfg_attr(not(feature = "std"), no_std)]
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

/// Why a tag image could not be built.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// The tag is not big enough for this URI.
    TooLong { needed: usize, room: usize },
}

/// How many bytes a tag image for a URI of `uri_len` bytes (after the prefix byte) takes.
pub fn image_len(uri_len: usize) -> usize {
    let payload = uri_len + 1; // the prefix byte
    let record = if payload <= 255 { 4 } else { 7 } + payload;
    let tlv = if record < 255 { 2 } else { 4 };
    CC_LEN + tlv + record + 1 // the terminator
}

/// Write everything up to the URI text: the container, the TLV header and the record
/// header. Returns how many bytes were written, which is where the URI text goes.
///
/// Split in two because the URI this device writes is mostly a transaction's hex, which is
/// expanded straight into the buffer rather than built somewhere first.
pub fn begin(out: &mut [u8], uri_len: usize, prefix: u8) -> Result<usize, Error> {
    let needed = image_len(uri_len);
    if out.len() < needed {
        return Err(Error::TooLong {
            needed,
            room: out.len(),
        });
    }
    let payload = uri_len + 1;
    let record_len = if payload <= 255 { 4 } else { 7 } + payload;

    let cc = capability_container(out.len() - CC_LEN);
    out[..CC_LEN].copy_from_slice(&cc);
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
    out[at + 1] = 1; // the type is one byte: 'U'
    at += 2;
    if short {
        out[at] = payload as u8;
        at += 1;
    } else {
        out[at..at + 4].copy_from_slice(&(payload as u32).to_be_bytes());
        at += 4;
    }
    out[at] = b'U';
    out[at + 1] = prefix;
    Ok(at + 2)
}

/// Close the image: the TLV terminator after the URI text. `at` is where the text ended.
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
pub fn uri_image(uri: &str, prefix: u8, out: &mut [u8]) -> Result<usize, Error> {
    let at = begin(out, uri.len(), prefix)?;
    out[at..at + uri.len()].copy_from_slice(uri.as_bytes());
    finish(out, at + uri.len())
}

#[cfg(test)]
mod tests;
