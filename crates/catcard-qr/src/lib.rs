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
//! Source: hw-reference/qr.md [C]

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

/// The module's acknowledgement, as bytes.
///
/// The reference calls this `OKAY`, which is a **name and not the payload**: the frame it
/// describes, `wrap(0x9000, fid=1)`, is eight bytes long, and eight bytes only leaves room
/// for a two-byte body. Reading the name as ASCII gives a ten-byte frame that never
/// matches anything the module sends, so every command reads as unanswered and the probe
/// never finds a scanner that is sitting right there answering.
pub const ACK: [u8; 2] = [0x90, 0x00];

/// The module's positive acknowledgement.
///
/// **Silence is the negative.** There is no NACK frame, so a caller waits for this and
/// times out; treating "nothing yet" as "no" is how a slow module reads as a broken one.
pub fn is_ack(frame: &Frame<'_>) -> bool {
    frame.fid == FID_REPLY && frame.body == ACK
}

/// Whether an acknowledgement appears **anywhere** in `bytes`.
///
/// A command sent while the module is scanning is answered in the middle of whatever it
/// was already saying: the reply is not at the front of the buffer, it is somewhere
/// inside a barcode. Insisting the whole buffer be an ack is how stopping a running scan
/// came to fail every time and fall back to the blind shutdown -- which leaves the
/// module awake with its aimer lit, since the blind path cannot know whether it landed.
///
/// Both forms, because both occur: the framed reply to a framed command, and the bare
/// [`ACK`] that answers an unframed one.
pub fn ack_within(bytes: &[u8]) -> bool {
    if bytes.windows(ACK.len()).any(|w| w == ACK) {
        return true;
    }
    // A framed ack can start at any offset, so every plausible start is tried. Bounded
    // by the buffer, which a caller sizes.
    (0..bytes.len()).any(|at| matches!(unwrap(&bytes[at..]), Ok(f) if is_ack(&f)))
}

/// Whether a reply looks like the version string `T_OUT_CVER` asks for, e.g. `V2.3.0.7`.
///
/// The version query is the *presence* check, and it does not answer with an
/// acknowledgement -- it answers with the version. Waiting for an ack here is waiting for
/// something the module will never send.
pub fn is_version(body: &[u8]) -> bool {
    matches!(body.first(), Some(b'V')) && body.len() >= 2
}

/// Remove the bare acknowledgement wherever it appears inside `line`, returning the new
/// length.
///
/// Commands sent unframed while a scan is running -- the torch, notably -- are answered
/// with a bare [`ACK`] that lands **in the middle of the barcode stream**. A reader that
/// does not take it out hands back a QR's text with two bytes spliced into it, which is
/// an address that does not parse or, worse, one that does.
///
/// Safe to do blindly: `0x90 0x00` is not a sequence a text QR contains.
pub fn strip_inline_ack(line: &mut [u8]) -> usize {
    let mut out = 0;
    let mut i = 0;
    while i < line.len() {
        if line[i..].starts_with(&ACK) {
            i += ACK.len();
            continue;
        }
        line[out] = line[i];
        out += 1;
        i += 1;
    }
    out
}

/// Commands, as the strings that go inside a frame.
///
/// Source: hw-reference/qr.md §5, §7 [C]
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
    /// Let the module assert its decode-success output.
    ///
    /// The yellow LED this lights is **on the board, not the module**: the FFC's
    /// `DECODE_LED` drives `D14` through a MOSFET. This command only enables the module
    /// to assert that line -- nothing here drives the LED, and no GPIO of ours does
    /// either. Source: hw-reference/qr.md §8 [C]
    pub const STATUS_LED: &[u8] = b"S_CMD_0407";
    /// Start scanning, continuously.
    pub const SCAN_START: &[u8] = b"S_CMD_020E";
    /// Stop scanning.
    pub const SCAN_STOP: &[u8] = b"S_CMD_020D";
    /// The illumination LED: off, always on, and on when the module decides it is needed.
    pub const TORCH_OFF: &[u8] = b"S_CMD_03L0";
    pub const TORCH_ON: &[u8] = b"S_CMD_03L1";
    pub const TORCH_AUTO: &[u8] = b"S_CMD_03L2";

    /// Sleep, which drops the module's current to about nothing.
    ///
    /// Sent **bare, not framed**, and sent *twice* about 150 ms apart: the module has two
    /// sleep layers and one command only reaches the first.
    pub const SLEEP: &[u8] = b"SRDF0050";
    /// Wake, also bare. The first send is swallowed while the module is still coming up,
    /// so it is retried until it answers.
    pub const WAKE: &[u8] = b"SRDF0051";

    /// The setup sequence, in order, every one framed.
    ///
    /// Not a subset: the trigger mode, the sleep behaviour and the continuous-read
    /// timings all have to be set, or the module scans on rules nobody chose. The last
    /// entry locks the setting codes, so that pointing the scanner at a configuration
    /// barcode cannot reprogram it -- which is a security property and belongs at the
    /// end, after everything it is protecting.
    ///
    /// Source: hw-reference/qr.md §5 [C]
    pub const CONFIG: [&[u8]; 14] = [
        FACTORY_RESET,
        b"S_CMD_MTRS5000", // read timeout, 5000 ms
        b"S_CMD_MT11",     // trigger on an edge, not a level
        b"S_CMD_MT30",     // no delay before the same code may be read again
        b"S_CMD_MT20",     // sleep by itself when idle
        b"S_CMD_MTRF500",  // ... after 500 ms
        APPEND_CRLF,       // required: the driver reads by line
        TORCH_OFF,
        STATUS_LED,
        b"S_CMD_MARS0000", // continuous mode: single-read duration 0 ms
        b"S_CMD_MARR000",  // continuous mode: interval between reads 0 ms
        b"S_CMD_MA31",     // apply a delay before re-reading the same code
        b"S_CMD_MARI0050", // ... of 50 ms
        SAVE,              // lock the setting codes; must be last
    ];
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
