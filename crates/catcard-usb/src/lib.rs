//! CatCard's USB transport: 64-byte HID reports, and the framing over them.
//!
//! # Why HID rather than WebUSB
//!
//! Both are reachable from a browser, and the deciding factor is what a user has to do
//! before either works. A HID device binds to the OS's own driver everywhere — no
//! install on Windows, no `udev` rule on Linux — and `WebHID` reaches it. WebUSB needs a
//! WinUSB binding advertised through MS OS 2.0 descriptors on Windows and a `udev` rule
//! on Linux, and a hardware wallet whose first instruction is "now edit a system file"
//! has lost most of its users. It is also the transport wallet extensions already speak.
//!
//! The cost is throughput: 64 bytes per frame at 1 kHz is 64 KB/s, so a 256 KB firmware
//! upgrade takes about four seconds. That is a fine price.
//!
//! # The protocol is ours
//!
//! Only the *transport* is standard. The stock firmware also uses 64-byte HID reports,
//! with a framed ECDH+AES-256-CTR protocol on top; the reference says in as many words
//! to ignore it and design our own, and this is our own. Nothing here is derived from
//! it, and the two are not interoperable.
//!
//! # Framing
//!
//! ```text
//! byte 0   kind    0x01 START, 0x02 CONT
//! byte 1   seq     increments per frame within a message, wrapping
//! START:
//!   2..4   u16     opcode (request) or status (response)
//!   4..8   u32     total payload length
//!   8..64  payload (56 bytes)
//! CONT:
//!   2..64  payload (62 bytes)
//! ```
//!
//! A message is one opcode and up to 4 GiB of payload, which is what lets a firmware
//! image be a single message rather than a chunking scheme layered on a chunking scheme.
//! The device never buffers it: [`Reassembler`] hands each frame's bytes straight to the
//! caller as they arrive.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod control;
pub mod descriptor;

/// Every report is exactly this long, in both directions.
pub const REPORT_LEN: usize = 64;

/// First frame of a message.
pub const KIND_START: u8 = 0x01;
/// Any frame after the first.
pub const KIND_CONT: u8 = 0x02;

/// Payload bytes a `START` frame carries, after its header.
pub const START_PAYLOAD: usize = REPORT_LEN - 8;
/// Payload bytes a `CONT` frame carries.
pub const CONT_PAYLOAD: usize = REPORT_LEN - 2;

/// Protocol version, reported by [`Opcode::Identify`].
///
/// Bumped when a host that understood the previous version would get this one wrong.
pub const PROTOCOL_VERSION: u16 = 1;

/// What the host is asking for.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum Opcode {
    /// Round-trip check. The payload is echoed.
    Ping = 0x0001,
    /// Who are you: protocol version, firmware version, board, chains built in.
    Identify = 0x0002,
    /// Payload is a complete signed firmware image.
    ///
    /// Nothing is installed by this. The device stages and validates it, then answers
    /// with what it found so a human can be asked.
    UpgradeOffer = 0x0010,
    /// Press a key, as though someone had pressed it on the device.
    ///
    /// Payload is one byte: `0x00..=0x09` a digit, [`KEY_CANCEL`], [`KEY_CONFIRM`].
    ///
    /// **This removes physical presence**, which is the property the rest of this design
    /// rests on: a host that can press keys can approve its own firmware once the device
    /// has been unlocked by its owner. It exists because a keypad whose mapping is not
    /// yet confirmed on hardware is the only way onto a device that has a PIN, and a
    /// wrong mapping costs thirteen attempts and then the secure element.
    ///
    /// It is behind the `usb-key-injection` feature, reported by [`Opcode::Identify`],
    /// and shown on the device's own screen. See `docs/USB.md`.
    InjectKey = 0x0020,
    /// Install the image offered, once the user has approved it on the device.
    ///
    /// **Irreversible**: the device reboots and the bootloader overwrites the running
    /// firmware before verifying it. Separate from the offer so that approval is a
    /// distinct act, and so a host cannot install by accident.
    UpgradeCommit = 0x0011,
    /// What happened the last time an install was attempted.
    ///
    /// Exists because a device whose screen is dark cannot say. The install path ends
    /// either in a reboot or in a message on a panel — and when the panel is the thing
    /// that is broken, the only honest answer to "did it work?" was silence, which is
    /// indistinguishable from a host that never asked.
    LastInstall = 0x0012,
}

/// Why the last install attempt did not install anything.
///
/// The device reboots on success, so there is no success code: a device that can answer
/// this at all did not install.
pub mod install {
    /// No install has been attempted since boot.
    pub const NONE: u8 = 0;
    /// The bootloader's own verification rejected the staged image (`gate 18/7`, -112).
    pub const REFUSED_BY_BOOTLOADER: u8 = 1;
    /// The login had gone stale, so the authorisation could not be signed.
    pub const STALE_LOGIN: u8 = 2;
    /// The secure element wanted more time.
    pub const RATE_LIMITED: u8 = 3;
    /// The callgate itself could not be reached.
    pub const GATE_UNREACHABLE: u8 = 4;
    /// Staging failed: the area refused the write, or did not read back what was
    /// written. On mk4 and later that is what an unmapped PSRAM looks like.
    pub const STAGING_FAILED: u8 = 5;
    /// Refused for a reason with no more specific code.
    pub const REFUSED: u8 = 6;
}

impl Opcode {
    pub const fn from_u16(v: u16) -> Option<Self> {
        Some(match v {
            0x0001 => Opcode::Ping,
            0x0002 => Opcode::Identify,
            0x0010 => Opcode::UpgradeOffer,
            0x0011 => Opcode::UpgradeCommit,
            0x0012 => Opcode::LastInstall,
            0x0020 => Opcode::InjectKey,
            _ => return None,
        })
    }
}

/// The `x` key, in an [`Opcode::InjectKey`] payload.
pub const KEY_CANCEL: u8 = 0x0A;
/// The `y` / OK key.
pub const KEY_CONFIRM: u8 = 0x0B;

/// Device state bits reported by [`Opcode::Identify`].
///
/// A host driving the device needs to know which screen it is answering. Without this it
/// has to infer the state from what its keypresses do, which is guesswork against a
/// device it may not be able to see.
pub mod state {
    /// The PIN has been entered.
    pub const UNLOCKED: u8 = 1 << 0;
    /// No PIN has ever been set: the device wants setup, not a login.
    pub const BLANK: u8 = 1 << 1;
}

/// Capability bits reported by [`Opcode::Identify`].
pub mod caps {
    /// This build accepts [`Opcode::InjectKey`](super::Opcode::InjectKey).
    pub const KEY_INJECTION: u8 = 1 << 0;
    /// The device can stage and install a firmware image. Absent on a board with no
    /// staging area wired up — USB still enumerates and still answers everything else,
    /// because a device that cannot be upgraded is exactly the one worth being able to
    /// reach.
    pub const UPGRADE: u8 = 1 << 1;
}

/// How a request turned out. `Ok` is zero; everything else is a refusal.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum Status {
    Ok = 0x0000,
    /// The opcode is not one this build knows.
    UnknownOpcode = 0x0001,
    /// Well-formed, but not allowed in the device's current state — asking to commit an
    /// upgrade nobody offered, for instance.
    NotNow = 0x0002,
    /// The payload is not what the opcode expects.
    BadRequest = 0x0003,
    /// The user declined at the device.
    Declined = 0x0004,
    /// The offered image was refused. The payload carries the reason.
    Refused = 0x0005,
    /// The device is busy with something a host cannot interrupt.
    Busy = 0x0006,
}

/// A framing error. All of them mean the host and the device have lost sync, and the
/// only cure is to start the message again.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum FrameError {
    /// Not [`KIND_START`] or [`KIND_CONT`].
    BadKind(u8),
    /// A continuation arrived with no message open.
    NoMessage,
    /// A new message started while one was still in progress.
    Interrupted,
    /// The sequence number skipped, so a frame was lost.
    ///
    /// USB interrupt transfers are retried by the hardware, so this should not happen on
    /// a healthy link; it is here because a host bug that silently drops a frame would
    /// otherwise corrupt a firmware image in a way only the digest would catch.
    OutOfSequence { expected: u8, got: u8 },
    /// More payload arrived than the message said it would carry.
    Overrun { total: u32 },
}

/// The header of a message being received.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Message {
    /// The raw opcode, so an unknown one can be reported rather than dropped.
    pub opcode: u16,
    pub total: u32,
}

/// What one frame contributed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Progress<'a> {
    /// Set on the first frame of a message.
    pub started: Option<Message>,
    /// This frame's payload bytes, already trimmed to the declared total.
    pub payload: &'a [u8],
    /// Every declared byte has now arrived.
    pub complete: bool,
}

/// Turns a stream of reports back into messages, without buffering them.
///
/// Holds no payload: a firmware image is a quarter of a megabyte and the device has 192
/// KB of RAM, so the bytes have to go somewhere else the moment they arrive.
#[derive(Default)]
pub struct Reassembler {
    open: Option<Message>,
    received: u32,
    next_seq: u8,
}

impl Reassembler {
    pub const fn new() -> Self {
        Self {
            open: None,
            received: 0,
            next_seq: 0,
        }
    }

    /// Abandon any message in progress.
    ///
    /// Call on a USB reset or when a transfer is given up on, so the next `START` is not
    /// reported as [`FrameError::Interrupted`].
    pub fn reset(&mut self) {
        self.open = None;
        self.received = 0;
        self.next_seq = 0;
    }

    /// Whether a message is currently being received.
    pub fn in_progress(&self) -> bool {
        self.open.is_some()
    }

    /// Feed one report.
    pub fn feed<'a>(&mut self, report: &'a [u8; REPORT_LEN]) -> Result<Progress<'a>, FrameError> {
        let kind = report[0];
        let seq = report[1];

        if kind == KIND_START {
            if self.open.is_some() {
                // A host that starts a new message mid-transfer has lost track of what
                // it was doing. Silently restarting would let a partial firmware image
                // be spliced onto the front of another one.
                return Err(FrameError::Interrupted);
            }
            let opcode = u16::from_le_bytes([report[2], report[3]]);
            let total = u32::from_le_bytes([report[4], report[5], report[6], report[7]]);
            let msg = Message { opcode, total };

            let n = (total as usize).min(START_PAYLOAD);
            let complete = n as u32 == total;
            // A short message finishes here. Leaving it open would make the *next*
            // message look like an interruption -- and Ping, Identify and UpgradeCommit
            // are all single-frame, so the second command a host ever sent would fail.
            self.open = (!complete).then_some(msg);
            self.received = n as u32;
            self.next_seq = if complete { 0 } else { seq.wrapping_add(1) };
            return Ok(Progress {
                started: Some(msg),
                payload: &report[8..8 + n],
                complete,
            });
        }

        if kind != KIND_CONT {
            return Err(FrameError::BadKind(kind));
        }
        let Some(msg) = self.open else {
            return Err(FrameError::NoMessage);
        };
        if seq != self.next_seq {
            return Err(FrameError::OutOfSequence {
                expected: self.next_seq,
                got: seq,
            });
        }

        let left = msg.total - self.received;
        if left == 0 {
            return Err(FrameError::Overrun { total: msg.total });
        }
        let n = (left as usize).min(CONT_PAYLOAD);
        self.received += n as u32;
        self.next_seq = self.next_seq.wrapping_add(1);
        let complete = self.received == msg.total;
        if complete {
            self.open = None;
            self.next_seq = 0;
        }
        Ok(Progress {
            started: None,
            payload: &report[2..2 + n],
            complete,
        })
    }
}

/// Builds the reports of one outgoing message.
///
/// Responses are small — the largest is an identity string or a refusal reason — so this
/// takes the whole payload as a slice rather than streaming it.
pub struct Writer<'a> {
    status: u16,
    payload: &'a [u8],
    sent: usize,
    seq: u8,
    started: bool,
}

impl<'a> Writer<'a> {
    /// A response carrying `status` and `payload`.
    pub fn response(status: Status, payload: &'a [u8]) -> Self {
        Self {
            status: status as u16,
            payload,
            sent: 0,
            seq: 0,
            started: false,
        }
    }

    /// Fill `out` with the next report. Returns false when the message is finished.
    ///
    /// Unused bytes are zeroed rather than left as they were: a report is always 64
    /// bytes on the wire, and leaving the tail alone would leak whatever the buffer last
    /// held to the host.
    pub fn next(&mut self, out: &mut [u8; REPORT_LEN]) -> bool {
        if self.started && self.sent == self.payload.len() {
            return false;
        }
        out.fill(0);
        let rest = &self.payload[self.sent..];
        if !self.started {
            let n = rest.len().min(START_PAYLOAD);
            out[0] = KIND_START;
            out[1] = self.seq;
            out[2..4].copy_from_slice(&self.status.to_le_bytes());
            out[4..8].copy_from_slice(&(self.payload.len() as u32).to_le_bytes());
            out[8..8 + n].copy_from_slice(&rest[..n]);
            self.sent += n;
            self.started = true;
        } else {
            let n = rest.len().min(CONT_PAYLOAD);
            out[0] = KIND_CONT;
            out[1] = self.seq;
            out[2..2 + n].copy_from_slice(&rest[..n]);
            self.sent += n;
        }
        self.seq = self.seq.wrapping_add(1);
        true
    }
}

#[cfg(test)]
mod tests;
