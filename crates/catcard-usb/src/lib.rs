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
pub mod hostwallet;
pub mod kbd;
pub mod msc;
pub mod ncry;

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
///
/// `2`: the encrypted channel is paired by a compared code (`PairCommit`/`PairReveal`/
/// `PairConfirm`), and the unauthenticated v1 `NcryStart` is gone -- a v1 host's
/// handshake is now `UnknownOpcode`.
pub const PROTOCOL_VERSION: u16 = 2;

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
    /// Payload is a complete signed firmware image, deflated.
    ///
    /// The image itself is the same one [`Opcode::UpgradeOffer`] takes, and reaches the
    /// same staging area through the same checks -- only the wire is smaller. Firmware
    /// deflates to about two thirds, and this transport moves 62 bytes a frame, so the
    /// third that is not sent is a third of the wait.
    ///
    /// The payload is `[u32 uncompressed length][deflate streams...]`, each stream
    /// inflating to 8 KiB except the last. The length is the one the signature was
    /// computed over, and the device stops there: a stream claiming more is refused,
    /// not truncated. The message's own `total` counts the compressed bytes, which is
    /// what crosses the wire and not what is installed.
    ///
    /// Reported by [`caps::UPGRADE_PACKED`]. A host that does not see that bit sends
    /// [`Opcode::UpgradeOffer`] instead, which every build understands.
    UpgradePacked = 0x0013,
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
    /// Unlock the device by submitting the PIN whole, instead of typing it key by key.
    ///
    /// Payload is the PIN as ASCII, prefix and suffix joined by `-`, e.g.
    /// `b"1234-5678"`. The device runs it through the same login state machine the
    /// keypad drives -- prefix, anti-phishing words, suffix -- and the reply's `Ok`
    /// means only that the request was *accepted*; the host polls [`Opcode::Identify`]
    /// for the `UNLOCKED` state bit to learn whether the PIN was right.
    ///
    /// Same trust boundary and same `usb-key-injection` feature as [`Opcode::InjectKey`]:
    /// a host that can type a PIN blindly can send one whole. It **auto-confirms the
    /// anti-phishing words**, so it is a bring-up convenience for driving upgrades, not
    /// a path that preserves the substituted-device check a person performs.
    UnlockPin = 0x0021,
    /// Read raw memory. Payload `[u32 addr][u8 width][u8 count]`; reply is the bytes.
    /// **Bring-up only** (`usb-debug-mem`): reads anything, including secrets.
    DebugPeek = 0x0030,
    /// Write raw memory. Payload `[u32 addr][u8 width][bytes...]`.
    /// **Bring-up only**: writes anywhere, including live code.
    DebugPoke = 0x0031,
    /// Call an address as `fn(u32) -> u32`, interrupts masked. Payload `[u32 addr][u32
    /// arg]`; reply `[u32 ret]`. **Bring-up only**: runs whatever the host sends.
    DebugJsr = 0x0032,
    /// Run the microSD bring-up read: init the card and read block 0, logging each step
    /// (`sddiag:` lines, fetched with [`Opcode::ReadLog`]). No payload; the reply is a
    /// terse `[u8 phase][u32 sta][u32 dcount]`. **Bring-up only** (`usb-debug-mem`) --
    /// it is a diagnostic for the SD data path, reachable when the panel is not.
    DebugSd = 0x0033,
    /// Send one raw command to the microSD card and hand back what it said.
    ///
    /// The request is `[u8 cmd][u8 flags][u16 len][u32 arg]` and, when `flags` says the
    /// data goes to the card, `len` bytes after it. `flags` bits 0-1 are the response
    /// shape (0 none, 1 short, 2 long), bit 2 means a data phase card-to-host and bit 3
    /// host-to-card. The reply is `[u8 status][u8 reserved][u16 len][u32 resp0..3]` and
    /// then `len` bytes for a read.
    ///
    /// **Bring-up only** (`usb-debug-mem`), and for good reason: this is the whole card
    /// protocol, which includes erasing it and locking it with a password nobody knows.
    /// It exists to find out what real cards do -- which of them answer CMD42, what
    /// their CID says -- on a device kept for that, not on anybody's.
    DebugSdRaw = 0x0034,
    /// Install the image offered, once the user has approved it on the device.
    ///
    /// **Irreversible**: the device reboots and the bootloader overwrites the running
    /// firmware before verifying it. Separate from the offer so that approval is a
    /// distinct act, and so a host cannot install by accident.
    UpgradeCommit = 0x0011,
    /// Page out the device's log.
    ///
    /// The payload is a `u32` offset counted from the oldest byte held; the reply is
    /// `[u32 total][u8 flags][bytes...]`, where `flags` bit 0 means the log has wrapped
    /// and dropped its oldest lines. A host reads with rising offsets until a reply
    /// comes back empty.
    ///
    /// Exists because every other diagnostic this firmware has ends on a screen, and a
    /// device whose panel is dark can still answer this.
    ///
    /// Carries nothing secret: see `logbuf`.
    ReadLog = 0x0012,
    // 0x0040 was `NcryStart`, the unauthenticated v1 handshake. Retired with protocol
    // version 2 and not reused: a v1 host sending it gets `UnknownOpcode`, not a
    // different command.
    /// A command (or its reply) sealed for the channel [paired](ncry) by
    /// [`Opcode::PairCommit`] / [`Opcode::PairReveal`].
    ///
    /// The payload is `[ciphertext][16-byte tag]`; the plaintext inside is an ordinary
    /// message — `[u16 opcode][payload]` on the way in, `[u16 status][payload]` on the
    /// way out — dispatched exactly as if it had arrived in the clear. Until the session
    /// is paired the only inner opcode admitted is [`Opcode::PairConfirm`]; any other
    /// tears the session down. The bulk upgrade opcodes are not accepted here: the image
    /// is public and signed, and it streams to staging without being buffered whole.
    NcryMsg = 0x0041,
    /// Start pairing. Payload is the host's 32-byte commitment,
    /// `SHA-256("catcard-pair-v2/commit" ‖ host_pub)`; the reply is the device's 32-byte
    /// ephemeral X25519 public key. `NotNow` before the PIN, `Busy` while a pairing prompt
    /// is already on the screen or cooling down. Reported by [`caps::PAIRING`].
    PairCommit = 0x0042,
    /// Finish the handshake. Payload is the host's 32-byte ephemeral public key, which
    /// must hash to the commitment; the reply is empty. After an `Ok` the device shows
    /// the pairing code and asks its user; see [`ncry`].
    PairReveal = 0x0043,
    /// **Sealed only**, as the inner opcode of an [`Opcode::NcryMsg`]: the host's user
    /// compared the code and accepted. Empty payload. The sealed reply's inner status is
    /// `Ok` once the device's user has accepted too (the session is paired), `NotNow`
    /// while the device is still asking -- send it again. Sent in the clear it is
    /// `BadRequest`.
    PairConfirm = 0x0044,
    /// Abandon pairing: the host's user said the codes differ, or gave up. Tears down any
    /// handshake or session and takes the prompt off the device screen. Empty payload,
    /// always `Ok`. Unauthenticated, like a tampered record: it can end a session, never
    /// start or extend one.
    PairAbort = 0x0045,
    /// Ask for this wallet's addresses. **Only inside [`Opcode::NcryMsg`].**
    ///
    /// No payload. `Ok` means the request is queued for the person at the device, who
    /// picks the account (and, on a multichain build, the chains) and confirms; the host
    /// then polls [`Opcode::HostResult`]. `NotNow` + [`hostwallet::busy`] while the device
    /// is locked or another request or an upgrade offer is pending. See [`hostwallet`].
    HostAddresses = 0x0050,
    /// Open an upload of a sign request: `[u8 chain][u32 blob length]`. Only inside the
    /// channel. Reply `Ok` + `[u32 largest chunk]`, or `Refused` + reason when the board
    /// cannot take that much or the chain does not sign.
    HostSignBegin = 0x0051,
    /// One chunk of the upload: `[u32 offset][bytes]`, in order. Only inside the channel.
    /// Reply `Ok` + `[u32 bytes received]`.
    HostSignData = 0x0052,
    /// The upload is whole: parse it, check its keys against what this session was
    /// shown, and queue the review. Only inside the channel.
    HostSignCommit = 0x0053,
    /// Poll for the outcome, and page the result out: `[u32 offset]`. Only inside the
    /// channel. `NotNow` + [`hostwallet::stage`] while the person decides.
    HostResult = 0x0054,
    /// Drop an upload that was not committed, or a result nobody will fetch. Cannot
    /// withdraw a request already waiting for the person. Only inside the channel.
    HostAbort = 0x0055,
}

impl Opcode {
    /// Decode a wire opcode, or `None` if this build does not know it.
    ///
    /// Explicit rather than derived: an unknown opcode must be answerable with
    /// `UnknownOpcode` rather than being mistaken for a neighbour.
    pub const fn from_u16(v: u16) -> Option<Self> {
        Some(match v {
            0x0001 => Opcode::Ping,
            0x0002 => Opcode::Identify,
            0x0010 => Opcode::UpgradeOffer,
            0x0011 => Opcode::UpgradeCommit,
            0x0013 => Opcode::UpgradePacked,
            0x0012 => Opcode::ReadLog,
            0x0041 => Opcode::NcryMsg,
            0x0042 => Opcode::PairCommit,
            0x0043 => Opcode::PairReveal,
            0x0044 => Opcode::PairConfirm,
            0x0045 => Opcode::PairAbort,
            0x0050 => Opcode::HostAddresses,
            0x0051 => Opcode::HostSignBegin,
            0x0052 => Opcode::HostSignData,
            0x0053 => Opcode::HostSignCommit,
            0x0054 => Opcode::HostResult,
            0x0055 => Opcode::HostAbort,
            0x0020 => Opcode::InjectKey,
            0x0021 => Opcode::UnlockPin,
            0x0030 => Opcode::DebugPeek,
            0x0031 => Opcode::DebugPoke,
            0x0032 => Opcode::DebugJsr,
            0x0033 => Opcode::DebugSd,
            0x0034 => Opcode::DebugSdRaw,
            _ => return None,
        })
    }
}

/// Bits in the flags byte of a [`Opcode::ReadLog`] reply.
pub mod log_flags {
    /// The log filled up and dropped its oldest lines, so the first line held is not the
    /// first line written. Worth saying: a truncated boot log that looks complete is how
    /// a reader concludes the wrong thing about what happened first.
    pub const WRAPPED: u8 = 1 << 0;
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
    /// This build exposes the raw memory monitor (`DebugPeek`/`Poke`/`Jsr`). It should
    /// never be set on anything but a bench device -- a host seeing this bit is talking
    /// to a build that will read its own RAM out to anyone.
    pub const DEBUG_MEM: u8 = 1 << 2;
    /// This build accepts [`Opcode::UnlockPin`](super::Opcode::UnlockPin). Set exactly
    /// when `KEY_INJECTION` is: the two share the `usb-key-injection` feature.
    pub const UNLOCK_PIN: u8 = 1 << 3;
    /// This build accepts [`Opcode::UpgradePacked`](super::Opcode::UpgradePacked), a
    /// deflated image. Never set without [`UPGRADE`]: it is the same staging area
    /// reached through a smaller wire, so a device that cannot install cannot install a
    /// compressed one either.
    pub const UPGRADE_PACKED: u8 = 1 << 4;
    // Bit 5 was `NCRY`, the unauthenticated v1 channel. Retired with protocol version 2
    // and left unused, so no bit ever changes meaning under a host that remembers it.
    /// This build answers the host-wallet commands (`HostAddresses` .. `HostAbort`)
    /// inside the encrypted channel: a computer may ask for addresses and for signatures,
    /// each decided by the person at the device. See [`hostwallet`](super::hostwallet).
    pub const HOST_WALLET: u8 = 1 << 6;
    /// This build pairs an encrypted channel by a compared code:
    /// [`PairCommit`](super::Opcode::PairCommit), [`PairReveal`](super::Opcode::PairReveal)
    /// and a sealed [`PairConfirm`](super::Opcode::PairConfirm), then sensitive commands
    /// inside [`NcryMsg`](super::Opcode::NcryMsg). See [`ncry`](super::ncry).
    pub const PAIRING: u8 = 1 << 7;
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
    /// The device cannot spare the memory to decompress right now. **Not a refusal of
    /// the image**: the same image sent with [`Opcode::UpgradeOffer`] will be accepted.
    ///
    /// Compression buys wire time and costs a buffer, and a device that is short of
    /// room should spend the time rather than fail. So this is the one status a host is
    /// expected to act on by itself, without asking anybody.
    RetryUncompressed = 0x0007,
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

    /// Resume a response partway through, from state saved between frames.
    ///
    /// A device that holds its reply in a buffer rather than a live `Writer` (because the
    /// borrow would be self-referential) reconstructs the writer each frame from the
    /// `(sent, seq, started)` it saved. Passing them back is how a multi-frame reply
    /// keeps going instead of restarting at frame zero every call -- which it silently
    /// did, capping every reply at one frame.
    pub fn resume(status: Status, payload: &'a [u8], sent: usize, seq: u8, started: bool) -> Self {
        Self {
            status: status as u16,
            payload,
            sent,
            seq,
            started,
        }
    }

    /// The framing state to save between frames: `(sent, seq, started)`.
    pub fn state(&self) -> (usize, u8, bool) {
        (self.sent, self.seq, self.started)
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
