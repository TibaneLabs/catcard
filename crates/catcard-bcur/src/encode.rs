//! Writing UR parts, so a payload can leave the device as animated QR.
//!
//! The mirror of the reader: CBOR the header, append a CRC-32, spell the whole thing in
//! bytewords, and put `ur:<type>/<seqNum>-<seqLen>/` in front.
//!
//! # Upper case, and why it costs nothing to say so
//!
//! Bytewords are lower case, and QR's alphanumeric mode is upper case only -- so a UR
//! written as it reads forces byte mode and loses a third of the symbol's capacity. The
//! UR specification allows the whole thing to be upper-cased for exactly this reason,
//! and a conforming reader lower-cases it again. So [`part`] writes upper case: it is
//! the same UR, in the mode that fits.
//!
//! Even upper-cased this is less dense than BBQr -- two characters a byte against
//! base32's 1.6 -- which is why a Bitcoin-only payload should go the other way. This is
//! here for the payloads BBQr has no file type for.

use outscript::bcur::bytewords::{self, Style};

/// What a part could not be written as.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// `seq_len` is zero, or `seq_num` is outside `1..=seq_len`.
    Numbering,
    /// The output buffer is too small for the line.
    TooLong,
}

/// The `ur:` prefix and the separators, without the type or the payload.
const FRAME: usize = "UR:".len() + 2; // two '/' separators

/// Characters a single-part UR of a `message`-byte message will occupy.
pub const fn single_len(ty: &str, message: usize) -> usize {
    // `UR:` + type + one '/' + the bytewords, which carry their own four-byte CRC.
    "UR:".len() + ty.len() + 1 + bytewords::encoded_len(message, Style::Minimal)
}

/// Write the whole message as one UR, with no sequence field.
///
/// The shape a reader sees when a message fits in one code: the bytewords are the
/// message itself, with no five-element wrapper, so it is shorter than the same
/// message as `1-1`. Returns [`Error::TooLong`] when it will not fit `out` -- a caller
/// that is sizing against a QR's capacity uses [`single_len`] first and falls back to
/// [`part`].
///
/// Source: BCR-2020-005 §"Types" -- `ur:<type>/<bytewords>`. [C]
pub fn single(ty: &str, message: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let need = single_len(ty, message.len());
    if need > out.len() {
        return Err(Error::TooLong);
    }
    let head = 3 + ty.len() + 1;
    out[..3].copy_from_slice(b"UR:");
    out[3..3 + ty.len()].copy_from_slice(ty.as_bytes());
    out[3 + ty.len()] = b'/';
    let n = bytewords::encode_to_slice(message, Style::Minimal, &mut out[head..])
        .map_err(|_| Error::TooLong)?;
    // Upper case throughout, for the reason in this module's header: one lower-case
    // letter drops the whole symbol out of QR's alphanumeric mode.
    out[..head + n].make_ascii_uppercase();
    Ok(head + n)
}

/// Characters a part's line will occupy.
///
/// `fragment` is the payload bytes this part carries; `ty` is the UR type, and the
/// sequence numbers are written in decimal so their width depends on how many there are.
pub fn encoded_len(ty: &str, fragment: usize, seq_num: u32, seq_len: u32) -> usize {
    // The CBOR header, generously: five elements, four integers of at most five bytes
    // each, and a byte-string header of at most three.
    let cbor = 1 + 4 * 5 + 3 + fragment;
    // Bytewords is two characters a byte, and the checksum adds four of them.
    FRAME
        + ty.len()
        + digits(seq_num)
        + 1
        + digits(seq_len)
        + bytewords::encoded_len(cbor, Style::Minimal)
}

const fn digits(mut n: u32) -> usize {
    let mut d = 1;
    while n >= 10 {
        n /= 10;
        d += 1;
    }
    d
}

/// The widest sequence number a part's line is sized for.
///
/// An animation does not stop at `seq_len`: past it the parts are fountain mixtures,
/// numbered upwards for as long as the screen is shown, so the number in the header
/// keeps growing. Sized for a hundred thousand parts, which at four a second is seven
/// hours of somebody holding a phone up to the panel -- and costing the fragment a few
/// bytes against that is better than a line that outgrows its symbol mid-animation.
const SEQ_WIDEST: u32 = 99_999;

/// The bytes a fragment should carry if a part's line must fit `chars` characters.
///
/// Solved by trying, because the header's size depends on the numbers in it and the
/// numbers do not depend on the fragment: a few steps, once, when a screen is opened.
pub fn fits(ty: &str, chars: usize, seq_len: u32) -> usize {
    let mut best = 0;
    // Against the widest number the animation can reach, not the last pure part's.
    for fragment in 1..chars {
        if encoded_len(ty, fragment, SEQ_WIDEST.max(seq_len), seq_len) <= chars {
            best = fragment;
        } else {
            break;
        }
    }
    best
}

/// Write one part of `message` into `out`, returning how many characters it took.
///
/// Fragments are all the same length, the last padded with zeroes -- `message_len` in
/// the header is what says where the real data stops, so a reader never sees the
/// padding as content.
pub fn part(
    ty: &str,
    message: &[u8],
    seq_num: u32,
    seq_len: u32,
    out: &mut [u8],
) -> Result<usize, Error> {
    if seq_len == 0 || seq_num == 0 {
        return Err(Error::Numbering);
    }
    let fragment = message.len().div_ceil(seq_len as usize);

    // The CBOR body, built into the tail of `out` so there is one buffer rather than
    // two: bytewords doubles the length, so the second half is always free at this
    // point and is overwritten from the front as the words are written.
    let checksum = outscript::bcur::crc32(message);
    // **Past `seq_len` this is a fountain mixture**, not a repeat of a pure part.
    //
    // An encoder that looped 1, 2, 3, 1, 2, 3 makes a receiver wait for whichever part
    // it missed to come round again; a fountain lets any later part fill any gap, which
    // is the whole reason the format has them. The set is chosen by the same function
    // the decoder uses, so the two agree by construction rather than by two people
    // reading the same specification.
    //
    // A message that fits one symbol never comes through here: that is `single`, and a
    // static code is read at a glance rather than waited on.
    let set = crate::fountain::choose_fragments(seq_num, seq_len as usize, checksum)
        .ok_or(Error::Numbering)?;
    let mut body: heapless::Vec<u8, 1024> = heapless::Vec::new();
    let _ = body.push(0x85); // array of five
    uint(seq_num as u64, &mut body);
    uint(seq_len as u64, &mut body);
    uint(message.len() as u64, &mut body);
    uint(checksum as u64, &mut body);
    bytes_header(fragment, &mut body);
    for i in 0..fragment {
        // Every fragment in the set, XORed. For a pure part the set holds one, so this
        // is a copy; past the end of the message is padding, which the reader discards.
        let mut b = 0u8;
        for f in 0..seq_len as usize {
            if set.has(f) {
                b ^= message.get(f * fragment + i).copied().unwrap_or(0);
            }
        }
        let _ = body.push(b);
    }

    let head = {
        let mut h: heapless::String<64> = heapless::String::new();
        use core::fmt::Write as _;
        // The type is upper-cased along with everything else: one lower-case letter
        // anywhere in the line drops the whole symbol out of alphanumeric mode.
        let _ = write!(h, "UR:");
        for c in ty.chars() {
            let _ = h.push(c.to_ascii_uppercase());
        }
        let _ = write!(h, "/{seq_num}-{seq_len}/");
        h
    };
    let need = head.len() + bytewords::encoded_len(body.len(), Style::Minimal);
    if need > out.len() {
        return Err(Error::TooLong);
    }
    out[..head.len()].copy_from_slice(head.as_bytes());
    let n = bytewords::encode_to_slice(&body, Style::Minimal, &mut out[head.len()..])
        .map_err(|_| Error::TooLong)?;
    // Upper case, for the same reason the prefix and the type are: one lower-case letter
    // anywhere in the line drops the whole symbol out of QR's alphanumeric mode, which
    // costs a third of its capacity. The specification allows it and a reader lower-cases
    // it again.
    out[head.len()..head.len() + n].make_ascii_uppercase();
    Ok(head.len() + n)
}

/// A CBOR unsigned integer, shortest form.
fn uint(n: u64, out: &mut heapless::Vec<u8, 1024>) {
    match n {
        0..=23 => {
            let _ = out.push(n as u8);
        }
        24..=0xFF => {
            let _ = out.extend_from_slice(&[24, n as u8]);
        }
        0x100..=0xFFFF => {
            let _ = out.push(25);
            let _ = out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        _ => {
            let _ = out.push(26);
            let _ = out.extend_from_slice(&(n as u32).to_be_bytes());
        }
    }
}

/// A CBOR byte-string header of `len` bytes.
fn bytes_header(len: usize, out: &mut heapless::Vec<u8, 1024>) {
    match len {
        0..=23 => {
            let _ = out.push(0x40 | len as u8);
        }
        24..=0xFF => {
            let _ = out.extend_from_slice(&[0x58, len as u8]);
        }
        _ => {
            let _ = out.push(0x59);
            let _ = out.extend_from_slice(&(len as u16).to_be_bytes());
        }
    }
}
