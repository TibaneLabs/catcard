//! The Q1's QR scanner, as a protocol.
//!
//! **Not a camera.** The Q1 carries a decoded-barcode engine on USART2 that does the
//! imaging and the decoding itself and hands back plain text, so nothing here rasterises
//! or decodes anything — this is the wire format for talking to that module, and the
//! rules for reading what it says back.
//!
//! Splitting it from the UART is what makes it testable. The framing is where protocol
//! bugs live — a checksum over the wrong span, a length read the wrong way round — and
//! none of that needs hardware to get wrong or to prove right.
//!
//! # The frame
//!
//! ```text
//! 5A  <fid:1>  <len:2, big-endian>  <body…>  <BCC:1>  A5
//! ```
//!
//! `5A` opens and `A5` closes. **BCC is the XOR of fid, both length bytes and the body**
//! — the delimiters are not in it. Commands go out with `fid = 0` and replies come back
//! with `fid = 1`. The bodies are ASCII command strings *inside* the frame: an earlier
//! reading of this protocol had them going out bare, which is wrong and is the sort of
//! thing that looks like a dead module rather than a wrong frame.
//!
//! A decoded QR does **not** arrive framed. It comes as plain CR/LF-terminated text,
//! because setup asks for that (`S_CMD_059A`).
//!
//! Source: hw-reference/input.md §"QR scanner (Q1)" [C]

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

/// Start of a frame.
pub const STX: u8 = 0x5A;
/// End of a frame.
pub const ETX: u8 = 0xA5;
/// Frames this host sends.
pub const FID_COMMAND: u8 = 0x00;
/// Frames the module sends.
pub const FID_REPLY: u8 = 0x01;

/// Bytes a frame adds around its body: STX, fid, two length bytes, BCC, ETX.
pub const OVERHEAD: usize = 6;

/// The largest QR the module will hand over: a version-40 code.
///
/// Stock sizes its receive buffer at exactly this. A longer reply is the module and the
/// host disagreeing about the protocol, not a bigger QR.
pub const MAX_PAYLOAD: usize = 4350;

/// Why a frame could not be read.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Not enough bytes yet. Not a failure: read more and try again.
    Incomplete,
    /// The first byte is not [`STX`], so this is not a frame boundary.
    NotAFrame,
    /// The closing [`ETX`] is not where the length said it would be.
    Unterminated,
    /// The checksum over the frame does not match the one it carries.
    BadChecksum,
    /// Longer than [`MAX_PAYLOAD`], or than the buffer given.
    TooLong,
}

/// XOR of the fid, the length bytes and the body.
///
/// The delimiters are deliberately outside it: including them would still produce a
/// self-consistent scheme, which is exactly why it has to be checked against the
/// reference rather than reasoned about.
pub fn bcc(fid: u8, body: &[u8]) -> u8 {
    let len = body.len() as u16;
    let mut x = fid ^ (len >> 8) as u8 ^ (len & 0xFF) as u8;
    for &b in body {
        x ^= b;
    }
    x
}

/// Wrap `body` as a command frame into `out`, returning how many bytes it used.
pub fn wrap<'a>(fid: u8, body: &[u8], out: &'a mut [u8]) -> Result<&'a [u8], Error> {
    let total = body.len() + OVERHEAD;
    if body.len() > MAX_PAYLOAD || out.len() < total {
        return Err(Error::TooLong);
    }
    let len = body.len() as u16;
    out[0] = STX;
    out[1] = fid;
    out[2] = (len >> 8) as u8;
    out[3] = (len & 0xFF) as u8;
    out[4..4 + body.len()].copy_from_slice(body);
    out[4 + body.len()] = bcc(fid, body);
    out[5 + body.len()] = ETX;
    Ok(&out[..total])
}

/// A frame read off the wire.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Frame<'a> {
    pub fid: u8,
    pub body: &'a [u8],
    /// Bytes this frame occupied, so a caller can advance its buffer.
    pub used: usize,
}

/// Read one frame from the front of `bytes`.
///
/// [`Error::Incomplete`] means the frame has not all arrived; every other error means
/// the bytes are not a frame and the caller should resynchronise rather than wait.
pub fn unwrap(bytes: &[u8]) -> Result<Frame<'_>, Error> {
    if bytes.len() < 4 {
        return Err(Error::Incomplete);
    }
    if bytes[0] != STX {
        return Err(Error::NotAFrame);
    }
    let fid = bytes[1];
    let len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    if len > MAX_PAYLOAD {
        return Err(Error::TooLong);
    }
    let total = len + OVERHEAD;
    if bytes.len() < total {
        return Err(Error::Incomplete);
    }
    let body = &bytes[4..4 + len];
    if bytes[total - 1] != ETX {
        return Err(Error::Unterminated);
    }
    if bytes[total - 2] != bcc(fid, body) {
        return Err(Error::BadChecksum);
    }
    Ok(Frame {
        fid,
        body,
        used: total,
    })
}

/// The module's positive acknowledgement: a reply frame whose body is `OKAY`.
///
/// **Silence is the negative.** There is no NACK frame, so a caller waits for this and
/// times out; treating "nothing yet" as "no" is how a slow module reads as a broken one.
pub fn is_ack(frame: &Frame<'_>) -> bool {
    frame.fid == FID_REPLY && frame.body == b"OKAY"
}

/// Commands, as the strings that go inside a frame.
///
/// Source: hw-reference/input.md §"QR scanner (Q1)" [C]
pub mod cmd {
    /// Ask the module its version. Used to find the baud rate it is listening at.
    pub const VERSION: &[u8] = b"T_OUT_CVER";
    /// Lock the link to 57600 baud. 115200 does not work on this module.
    pub const BAUD_57600: &[u8] = b"S_CMD_H3BR57600";
    /// Factory reset, which setup does first so the module's state is known.
    pub const FACTORY_RESET: &[u8] = b"S_CMD_FFFF";
    /// Save the current configuration.
    pub const SAVE: &[u8] = b"S_CMD_0000";
    /// Append CRLF to a decoded barcode, which is how a read is known to have ended.
    pub const APPEND_CRLF: &[u8] = b"S_CMD_059A";
    /// Turn the small yellow status LED on.
    pub const STATUS_LED: &[u8] = b"S_CMD_0407";
    /// Start scanning, continuously.
    pub const SCAN_START: &[u8] = b"S_CMD_020E";
    /// Stop scanning.
    pub const SCAN_STOP: &[u8] = b"S_CMD_020D";
    /// The illumination LED: off, always on, and on when the module decides it is needed.
    pub const TORCH_OFF: &[u8] = b"S_CMD_03L0";
    pub const TORCH_ON: &[u8] = b"S_CMD_03L1";
    pub const TORCH_AUTO: &[u8] = b"S_CMD_03L2";
}

/// What the module says when it read a code it cannot represent as text.
///
/// It is a *decoded* answer, not a failure: the module read a QR and is telling us it
/// held bytes rather than characters. Passing it on as if it were the QR's contents is
/// how a wallet ends up trying to parse the words "unsupported binary QR".
pub const UNSUPPORTED: &[u8] = b"(unsupported binary QR)";

/// Baud rates to try, in the order stock tries them.
pub const BAUDS: [u32; 2] = [57600, 9600];

#[cfg(test)]
mod tests;
