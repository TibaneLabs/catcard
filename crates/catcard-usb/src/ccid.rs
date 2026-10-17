//! The CCID smart-card interface the device can add beside the wallet's: descriptors,
//! the reader's messages, and the one APDU it answers.
//!
//! # Why a smart-card reader
//!
//! A phone or tablet has no way to open a vendor HID device: iOS gives an app no HID
//! API at all. What it does give is CryptoTokenKit, which drives any **class-compliant
//! CCID reader** on the USB-C port and lets an app exchange APDUs with the card in it.
//! So the device presents itself as a reader with one slot, holding one card that is
//! always inserted, and that card answers exactly one proprietary APDU: a CatCard wire
//! message, the same `[opcode][payload]` the HID transport carries, dispatched by the
//! same code. Pairing, the host-wallet commands and everything else behave as they do
//! over HID, because they are the same bytes reaching the same handlers.
//!
//! **Only our own APDU.** Nothing of ISO 7816-4's interindustry set is implemented --
//! no `SELECT`, no PIV, no OpenPGP card -- and every other class or instruction is
//! refused with the ISO status word that says so. A host that probes this card for a
//! known application learns nothing and gets nothing.
//!
//! **Always on, part of CatCard's own identity from boot.** Unlike the keyboard
//! ([`crate::kbd`]) and the security key ([`crate::fido`]) it adds no capability a host
//! did not already have over interface 0 -- it is the HID interface by another route,
//! behind the same PIN and the same compared code -- so there is no switch. The
//! wallet's vendor interface stays interface 0, the keyboard and the security key keep
//! their places when they are on, and the reader comes last. Interfaces are numbered
//! without gaps (USB 2.0 §9.6.5 [C]), which is why its number moves and the others'
//! never do. Stock's identity (ckcc mode) and the mass-storage one never carry it.
//!
//! Only the *portable* part is here -- tables, message layouts, the reader's state and
//! the APDU parser -- tested on the host. Moving bytes over the bulk endpoints is the
//! HAL's, and dispatching a message is the firmware's (`usbtask`, through `ccid`).
//!
//! Source: USB Device Class Specification for USB Chip/Smart Card Interface Devices
//! (CCID) Rev 1.1: §5.1 Table 5.1-1 (the class descriptor), §5.3 (class-specific
//! requests), §6.1 and §6.2 (the bulk messages), Table 6.2-2 (error codes) [C];
//! ISO/IEC 7816-3 §8 (the ATR) and 7816-4 §5 (APDUs, status words) [C].

use core::ops::Range;

use crate::descriptor::{self, kind};

/// The reader's bulk endpoints. `0x81`/`0x01` stay the wallet's, `0x82` the keyboard's
/// and `0x83`/`0x03` the security key's. OTG_FS has endpoints 0..5 in each direction.
/// Source: RM0432 §USB OTG_FS "6 bidirectional endpoints" [C]
pub const EP_IN: u8 = 0x84;
pub const EP_OUT: u8 = 0x04;

/// Largest bulk packet at full speed. Source: USB 2.0 §5.8.3 [C]
pub const MAX_PACKET: usize = 64;

/// The longest CCID message the reader takes or gives, header included: the class
/// descriptor's `dwMaxCCIDMessageLength`, and the size of the buffer the firmware leases
/// for one. Sized for the longest APDU a message needs: an extended header, the wire
/// message's own six bytes, a sealed record of [`crate::ncry::RECORD_MAX`] bytes and a
/// two-byte `Le`, with a little to spare. Seventeen packets.
pub const MESSAGE_MAX: usize = 1088;
/// The most APDU an `XfrBlock` can carry: the message less its header.
pub const APDU_MAX: usize = MESSAGE_MAX - Header::LEN;
const _: () = assert!(APDU_MAX >= 7 + apdu::HEADER + crate::ncry::RECORD_MAX + 2);

/// The class-specific descriptor type: `bDescriptorType` of the smart-card class
/// descriptor, the same value HID uses for its own (0x21). Source: CCID 1.1 §5.1 [C]
pub const CLASS_DESCRIPTOR_TYPE: u8 = 0x21;

/// `bInterfaceClass` of a smart-card reader; subclass and protocol are both zero.
/// Source: CCID 1.1 §4.1 [C]
pub const INTERFACE_CLASS: u8 = 0x0B;

/// The reader's one clock frequency, in kHz, and its one data rate, in bps -- what the
/// class descriptor says and what `GET_CLOCK_FREQUENCIES` / `GET_DATA_RATES` answer.
/// There is no card to clock: these are the values a host expects to see of a reader
/// that handles everything itself (ISO 7816-3's defaults: Fi 372, Di 1 at 3.57 MHz
/// gives 9600 bps). [C]
pub const CLOCK_KHZ: u32 = 4000;
pub const DATA_RATE_BPS: u32 = 9600;

/// `dwFeatures` (CCID 1.1 §5.1 Table 5.1-1 [C]): the reader does every step of card
/// handling itself, and talks APDUs rather than TPDUs.
///
/// | bit | |
/// |---|---|
/// | `0x0000_0002` | automatic parameter configuration from the ATR |
/// | `0x0000_0004` | automatic activation on insertion |
/// | `0x0000_0008` | automatic voltage selection |
/// | `0x0000_0010` | automatic clock frequency change |
/// | `0x0000_0020` | automatic baud rate change |
/// | `0x0000_0040` | automatic parameter negotiation |
/// | `0x0000_0080` | automatic PPS |
/// | `0x0004_0000` | short **and extended** APDU level exchange |
///
/// APDU level, so a host hands the reader whole APDUs and never a T=1 block; extended
/// too, so a 512-byte reply comes back in one exchange rather than through
/// `GET RESPONSE` pages (which also work, for a host that only speaks short APDUs).
pub const FEATURES: u32 = 0x0004_00FE;

/// The 54-byte smart-card class descriptor. Source: CCID 1.1 §5.1 Table 5.1-1 [C]
pub const CLASS_DESCRIPTOR: [u8; 54] = {
    let mut d = [0u8; 54];
    d[0] = 54; // bLength
    d[1] = CLASS_DESCRIPTOR_TYPE;
    d[2] = 0x10;
    d[3] = 0x01; // bcdCCID 1.10
    d[4] = 0; // bMaxSlotIndex: one slot
    d[5] = 0x07; // bVoltageSupport: 5 V, 3 V, 1.8 V -- there is no card to power
    put_u32(&mut d, 6, 0x0000_0002); // dwProtocols: T=1
    put_u32(&mut d, 10, CLOCK_KHZ); // dwDefaultClock
    put_u32(&mut d, 14, CLOCK_KHZ); // dwMaximumClock
    d[18] = 0; // bNumClockSupported: only the default
    put_u32(&mut d, 19, DATA_RATE_BPS); // dwDataRate
    put_u32(&mut d, 23, DATA_RATE_BPS); // dwMaxDataRate
    d[27] = 0; // bNumDataRatesSupported: only the default
    put_u32(&mut d, 28, IFSC as u32); // dwMaxIFSD
    put_u32(&mut d, 32, 0); // dwSynchProtocols: none
    put_u32(&mut d, 36, 0); // dwMechanical: none
    put_u32(&mut d, 40, FEATURES); // dwFeatures
    put_u32(&mut d, 44, MESSAGE_MAX as u32); // dwMaxCCIDMessageLength
    d[48] = 0xFF; // bClassGetResponse: echo the command's class
    d[49] = 0xFF; // bClassEnvelope
    d[50] = 0;
    d[51] = 0; // wLcdLayout: no display the host can drive
    d[52] = 0; // bPINSupport: no PIN pad the host can drive
    d[53] = 1; // bMaxCCIDBusySlots
    d
};

const fn put_u32(d: &mut [u8; 54], at: usize, v: u32) {
    let b = v.to_le_bytes();
    d[at] = b[0];
    d[at + 1] = b[1];
    d[at + 2] = b[2];
    d[at + 3] = b[3];
}

/// The data of a `GET_CLOCK_FREQUENCIES` answer: the one frequency, as a `u32` kHz
/// array of length one. Source: CCID 1.1 §5.3.2 [C]
pub const CLOCK_FREQUENCIES: [u8; 4] = CLOCK_KHZ.to_le_bytes();
/// The data of a `GET_DATA_RATES` answer. Source: CCID 1.1 §5.3.3 [C]
pub const DATA_RATES: [u8; 4] = DATA_RATE_BPS.to_le_bytes();

/// Bytes of the reader's block: interface, class descriptor, two endpoints.
pub const BLOCK_LEN: usize = 9 + CLASS_DESCRIPTOR.len() + 7 + 7;

/// The interface block for interface number `number`.
const fn block(number: u8) -> [u8; BLOCK_LEN] {
    let mut b = [0u8; BLOCK_LEN];
    // --- interface ---
    b[0] = 9;
    b[1] = kind::INTERFACE;
    b[2] = number;
    b[3] = 0; // bAlternateSetting
    b[4] = 2; // bNumEndpoints: bulk in and out; no interrupt endpoint, nothing is ever
    // inserted or removed (CCID 1.1 §5.2: the interrupt endpoint is optional [C])
    b[5] = INTERFACE_CLASS;
    b[6] = 0x00; // bInterfaceSubClass
    b[7] = 0x00; // bInterfaceProtocol: CCID (0x01/0x02 are ICCD) [C]
    b[8] = 0; // iInterface
    // --- class descriptor ---
    let mut i = 0;
    while i < CLASS_DESCRIPTOR.len() {
        b[9 + i] = CLASS_DESCRIPTOR[i];
        i += 1;
    }
    let e = 9 + CLASS_DESCRIPTOR.len();
    // --- endpoint IN (bulk) ---
    b[e] = 7;
    b[e + 1] = kind::ENDPOINT;
    b[e + 2] = EP_IN;
    b[e + 3] = 0x02; // bulk
    b[e + 4] = MAX_PACKET as u8;
    b[e + 5] = 0;
    b[e + 6] = 0; // bInterval: ignored for bulk
    // --- endpoint OUT (bulk) ---
    b[e + 7] = 7;
    b[e + 8] = kind::ENDPOINT;
    b[e + 9] = EP_OUT;
    b[e + 10] = 0x02;
    b[e + 11] = MAX_PACKET as u8;
    b[e + 12] = 0;
    b[e + 13] = 0;
    b
}

/// `base` (a whole configuration) with the reader's block appended as interface
/// `number`, and the header's total length and interface count raised to match.
const fn with_block<const B: usize, const T: usize>(base: &[u8; B], number: u8) -> [u8; T] {
    assert!(T == B + BLOCK_LEN);
    let mut c = [0u8; T];
    let mut i = 0;
    while i < B {
        c[i] = base[i];
        i += 1;
    }
    let b = block(number);
    let mut j = 0;
    while j < BLOCK_LEN {
        c[B + j] = b[j];
        j += 1;
    }
    c[2] = T as u8;
    c[3] = (T >> 8) as u8;
    c[4] = base[4] + 1; // bNumInterfaces
    c
}

const WALLET_LEN: usize = descriptor::CONFIGURATION.len();
const KBD_LEN: usize = crate::kbd::CONFIGURATION.len();
const FIDO_LEN: usize = crate::fido::CONFIGURATION.len();
const KBD_FIDO_LEN: usize = crate::fido::CONFIGURATION_WITH_KBD.len();

/// Wallet (interface 0) and reader (interface 1).
pub const CONFIGURATION: [u8; WALLET_LEN + BLOCK_LEN] = with_block(&descriptor::CONFIGURATION, 1);
/// Wallet (0), keyboard (1) and reader (2).
pub const CONFIGURATION_WITH_KBD: [u8; KBD_LEN + BLOCK_LEN] =
    with_block(&crate::kbd::CONFIGURATION, 2);
/// Wallet (0), security key (1) and reader (2).
pub const CONFIGURATION_WITH_FIDO: [u8; FIDO_LEN + BLOCK_LEN] =
    with_block(&crate::fido::CONFIGURATION, 2);
/// Wallet (0), keyboard (1), security key (2) and reader (3).
pub const CONFIGURATION_WITH_KBD_FIDO: [u8; KBD_FIDO_LEN + BLOCK_LEN] =
    with_block(&crate::fido::CONFIGURATION_WITH_KBD, 3);

/// The longest configuration this device ever describes. The HAL sizes the buffer it
/// holds a long endpoint-zero reply in by this.
pub const CONFIGURATION_MAX: usize = CONFIGURATION_WITH_KBD_FIDO.len();

// Endpoint zero's data stage ends in a short packet, and a reply that is a whole number
// of packets would need an empty one after it, which the HAL does not send. None of
// these is, and none can quietly become one.
const _: () = assert!(
    !CONFIGURATION.len().is_multiple_of(64)
        && !CONFIGURATION_WITH_KBD.len().is_multiple_of(64)
        && !CONFIGURATION_WITH_FIDO.len().is_multiple_of(64)
        && !CONFIGURATION_WITH_KBD_FIDO.len().is_multiple_of(64)
);

/// Class-specific requests on the reader's interface. Source: CCID 1.1 §5.3 [C]
pub mod request {
    /// Host-to-device, no data: `wValue` is `bSeq << 8 | bSlot`. The reader drops
    /// whatever command it is in the middle of, and until the matching bulk
    /// `PC_to_RDR_Abort` arrives answers every other command `CMD_ABORTED`.
    pub const ABORT: u8 = 0x01;
    /// Device-to-host: the array of supported clock frequencies, kHz each.
    pub const GET_CLOCK_FREQUENCIES: u8 = 0x02;
    /// Device-to-host: the array of supported data rates, bps each.
    pub const GET_DATA_RATES: u8 = 0x03;
}

// ---------------------------------------------------------------------------------------
// The card: its ATR and T=1 parameters
// ---------------------------------------------------------------------------------------

/// T=1's information field size the card accepts: the most ISO 7816-3 allows, so the
/// reader -- which is the card -- never has to chain blocks.
pub const IFSC: u8 = 0xFE;
/// TB3: BWI 4, CWI 5 -- the block and character waiting integers, which only a real
/// reader clocking a real card would time. Echoed by `GetParameters`.
const WAITING_INTEGERS: u8 = 0x45;
/// The historical bytes: the card's name, in a proprietary category (a first byte other
/// than `00`, `10` or `80`; ISO 7816-4 §8.1.1 [C]).
const HISTORICAL: &[u8] = b"CatCard";

/// Length of the ATR: TS, T0, TD1, TD2, TA3, TB3, the historical bytes, TCK.
pub const ATR_LEN: usize = 6 + HISTORICAL.len() + 1;

/// The Answer To Reset the card gives on power-on: direct convention, T=1 only, IFSC
/// [`IFSC`], the waiting integers above, and `CatCard` as the historical bytes. The
/// check byte is the XOR of everything after TS. Source: ISO/IEC 7816-3 §8.2 [C]
pub const ATR: [u8; ATR_LEN] = {
    let mut a = [0u8; ATR_LEN];
    a[0] = 0x3B; // TS: direct convention
    a[1] = 0x80 | HISTORICAL.len() as u8; // T0: TD1 follows; the historical count
    a[2] = 0x81; // TD1: TD2 follows; first offered protocol T=1
    a[3] = 0x31; // TD2: TA3 and TB3 follow; T=1
    a[4] = IFSC; // TA3
    a[5] = WAITING_INTEGERS; // TB3
    let mut i = 0;
    while i < HISTORICAL.len() {
        a[6 + i] = HISTORICAL[i];
        i += 1;
    }
    let mut tck = 0u8;
    let mut j = 1;
    while j < ATR_LEN - 1 {
        tck ^= a[j];
        j += 1;
    }
    a[ATR_LEN - 1] = tck;
    a
};
const _: () = assert!(HISTORICAL.len() <= 15 && ATR_LEN <= 33);

/// The T=1 protocol parameters, as `RDR_to_PC_Parameters` gives them for
/// `bProtocolNum = 1`. Source: CCID 1.1 §6.2.3 [C]
pub const PARAMETERS_T1: [u8; 7] = [
    0x11,             // bmFindexDindex: Fi 372, Di 1
    0x10,             // bmTCCKST1: direct convention, LRC checksum
    0x00,             // bGuardTimeT1
    WAITING_INTEGERS, // bmWaitingIntegersT1
    0x00,             // bClockStop: not allowed
    IFSC,             // bIFSC
    0x00,             // bNadValue
];

// ---------------------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------------------

/// `bMessageType` of each command the host sends. Source: CCID 1.1 §6.1 [C]
pub mod cmd {
    pub const ICC_POWER_ON: u8 = 0x62;
    pub const ICC_POWER_OFF: u8 = 0x63;
    pub const GET_SLOT_STATUS: u8 = 0x65;
    pub const XFR_BLOCK: u8 = 0x6F;
    pub const GET_PARAMETERS: u8 = 0x6C;
    pub const RESET_PARAMETERS: u8 = 0x6D;
    pub const SET_PARAMETERS: u8 = 0x61;
    pub const ESCAPE: u8 = 0x6B;
    pub const ICC_CLOCK: u8 = 0x6E;
    pub const T0_APDU: u8 = 0x6A;
    pub const SECURE: u8 = 0x69;
    pub const MECHANICAL: u8 = 0x71;
    pub const ABORT: u8 = 0x72;
    pub const SET_DATA_RATE_AND_CLOCK: u8 = 0x73;
}

/// `bMessageType` of each answer. Source: CCID 1.1 §6.2 [C]
pub mod reply {
    pub const DATA_BLOCK: u8 = 0x80;
    pub const SLOT_STATUS: u8 = 0x81;
    pub const PARAMETERS: u8 = 0x82;
    pub const ESCAPE: u8 = 0x83;
    pub const DATA_RATE_AND_CLOCK: u8 = 0x84;
}

/// `bError` values. Source: CCID 1.1 Table 6.2-2 [C]
pub mod error {
    /// The command was aborted by a control `ABORT`.
    pub const CMD_ABORTED: u8 = 0xFF;
    /// The card did not answer -- here, the card is not powered.
    pub const ICC_MUTE: u8 = 0xFE;
    /// Another command is in progress on the slot.
    pub const CMD_SLOT_BUSY: u8 = 0xE0;
    /// The command is not one this reader does.
    pub const CMD_NOT_SUPPORTED: u8 = 0x00;
    /// Values 1..=127 name the offset of the bad parameter in the command.
    pub const BAD_LENGTH: u8 = 1;
    pub const BAD_SLOT: u8 = 5;
    pub const BAD_LEVEL: u8 = 8;
}

/// Bits of `bStatus`. Source: CCID 1.1 §6.2.6 [C]
pub mod status {
    /// `bmICCStatus`: a card is present and powered.
    pub const ICC_ACTIVE: u8 = 0;
    /// A card is present and not powered.
    pub const ICC_INACTIVE: u8 = 1;
    /// No card.
    pub const ICC_ABSENT: u8 = 2;
    /// `bmCommandStatus`: the command failed; `bError` says how.
    pub const FAILED: u8 = 0x40;
}

/// The ten bytes every message in either direction begins with.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Header {
    pub kind: u8,
    /// Bytes of data after the header.
    pub len: u32,
    pub slot: u8,
    pub seq: u8,
    /// The three message-specific bytes.
    pub p: [u8; 3],
}

impl Header {
    pub const LEN: usize = 10;

    pub fn parse(b: &[u8; Self::LEN]) -> Self {
        Self {
            kind: b[0],
            len: u32::from_le_bytes([b[1], b[2], b[3], b[4]]),
            slot: b[5],
            seq: b[6],
            p: [b[7], b[8], b[9]],
        }
    }

    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let l = self.len.to_le_bytes();
        [
            self.kind, l[0], l[1], l[2], l[3], self.slot, self.seq, self.p[0], self.p[1], self.p[2],
        ]
    }
}

/// What the reader does with one whole command.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// Answer with `head` followed by `data` bytes the reader wrote at the front of the
    /// command's buffer.
    Reply { head: Header, data: usize },
    /// An `XfrBlock`: the APDU is the command's data, and the caller answers it with
    /// [`Reader::data_block`] once it has.
    Apdu { seq: u8 },
}

/// The reader and its one virtual card: powered or not, and whether a control `ABORT`
/// is waiting for its bulk half.
#[derive(Default, Debug)]
pub struct Reader {
    powered: bool,
    abort: Option<u8>,
}

impl Reader {
    pub const fn new() -> Self {
        Self {
            powered: false,
            abort: None,
        }
    }

    /// As after a bus reset: the card unpowered, nothing waiting.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    pub fn powered(&self) -> bool {
        self.powered
    }

    /// A control `ABORT` arrived naming `seq`. Whatever was in progress is dropped by the
    /// caller; from here every command but the matching bulk `Abort` is `CMD_ABORTED`.
    pub fn control_abort(&mut self, seq: u8) {
        self.abort = Some(seq);
    }

    /// `bStatus` for a command that went well.
    fn ok_status(&self) -> u8 {
        if self.powered {
            status::ICC_ACTIVE
        } else {
            status::ICC_INACTIVE
        }
    }

    /// The header of a successful `RDR_to_PC_DataBlock` carrying `len` bytes.
    pub fn data_block(&self, seq: u8, len: usize) -> Header {
        Header {
            kind: reply::DATA_BLOCK,
            len: len as u32,
            slot: 0,
            seq,
            p: [self.ok_status(), 0, 0],
        }
    }

    /// The failed answer to the command `hdr` began, with `err` as the reason: for a
    /// command whose data could not be taken at all (`error::BAD_LENGTH`, longer than
    /// [`MESSAGE_MAX`]), which the caller discards before answering.
    pub fn refused(&self, hdr: &Header, err: u8) -> Header {
        self.failed(reply_kind(hdr.kind), hdr.seq, err, self.ok_status())
    }

    /// The header of a failed answer of `kind`, with no data.
    fn failed(&self, kind: u8, seq: u8, err: u8, icc: u8) -> Header {
        Header {
            kind,
            len: 0,
            slot: 0,
            seq,
            p: [icc | status::FAILED, err, 0],
        }
    }

    /// Act on one whole command: its header, and its data at the front of `buf`
    /// (`hdr.len` bytes, already checked to fit). A reply's data, if any, is written over
    /// the same bytes, which have been read by then.
    pub fn command(&mut self, hdr: &Header, buf: &mut [u8]) -> Outcome {
        let seq = hdr.seq;
        let kind = reply_kind(hdr.kind);
        let icc = self.ok_status();

        // A control ABORT is answered only by its own bulk Abort; everything else in
        // between is told it was aborted. Source: CCID 1.1 §5.3.1 [C]
        if let Some(want) = self.abort {
            if hdr.kind == cmd::ABORT && hdr.seq == want && hdr.slot == 0 {
                self.abort = None;
                return Outcome::Reply {
                    head: Header {
                        kind: reply::SLOT_STATUS,
                        len: 0,
                        slot: 0,
                        seq,
                        p: [icc, 0, 0],
                    },
                    data: 0,
                };
            }
            return Outcome::Reply {
                head: self.failed(kind, seq, error::CMD_ABORTED, icc),
                data: 0,
            };
        }
        if hdr.slot != 0 {
            return Outcome::Reply {
                head: self.failed(kind, seq, error::BAD_SLOT, status::ICC_ABSENT),
                data: 0,
            };
        }

        match hdr.kind {
            cmd::ICC_POWER_ON => {
                // Any voltage: there is nothing to power. The ATR is the answer.
                self.powered = true;
                buf[..ATR_LEN].copy_from_slice(&ATR);
                Outcome::Reply {
                    head: self.data_block(seq, ATR_LEN),
                    data: ATR_LEN,
                }
            }
            cmd::ICC_POWER_OFF => {
                self.powered = false;
                Outcome::Reply {
                    head: Header {
                        kind: reply::SLOT_STATUS,
                        len: 0,
                        slot: 0,
                        seq,
                        p: [self.ok_status(), 0, 0],
                    },
                    data: 0,
                }
            }
            cmd::GET_SLOT_STATUS | cmd::ABORT => Outcome::Reply {
                head: Header {
                    kind: reply::SLOT_STATUS,
                    len: 0,
                    slot: 0,
                    seq,
                    p: [icc, 0, 0],
                },
                data: 0,
            },
            cmd::XFR_BLOCK => {
                if !self.powered {
                    return Outcome::Reply {
                        head: self.failed(kind, seq, error::ICC_MUTE, icc),
                        data: 0,
                    };
                }
                // `wLevelParameter` (CCID 1.1 §6.1.4 [C]): an APDU that begins and ends
                // in this command is 0. The reader's whole APDU fits one message, so the
                // other values -- a host chaining an APDU longer than the message -- are
                // refused as a bad parameter.
                if hdr.p[1] != 0 || hdr.p[2] != 0 {
                    return Outcome::Reply {
                        head: self.failed(kind, seq, error::BAD_LEVEL, icc),
                        data: 0,
                    };
                }
                Outcome::Apdu { seq }
            }
            cmd::GET_PARAMETERS | cmd::RESET_PARAMETERS | cmd::SET_PARAMETERS => {
                // The parameters are what they are: a host asking to set them is
                // answered with the ones in force, as a reader that negotiated them
                // itself would be.
                let n = PARAMETERS_T1.len();
                buf[..n].copy_from_slice(&PARAMETERS_T1);
                Outcome::Reply {
                    head: Header {
                        kind: reply::PARAMETERS,
                        len: n as u32,
                        slot: 0,
                        seq,
                        p: [icc, 0, 1], // bProtocolNum: T=1
                    },
                    data: n,
                }
            }
            cmd::SET_DATA_RATE_AND_CLOCK => {
                // The one clock and the one rate, whatever was asked.
                buf[..4].copy_from_slice(&CLOCK_FREQUENCIES);
                buf[4..8].copy_from_slice(&DATA_RATES);
                Outcome::Reply {
                    head: Header {
                        kind: reply::DATA_RATE_AND_CLOCK,
                        len: 8,
                        slot: 0,
                        seq,
                        p: [icc, 0, 0],
                    },
                    data: 0,
                }
                .with_data(8)
            }
            // Escape, clock control, T=0 APDU handling, secure PIN entry, mechanical
            // functions, and anything this reader has never heard of.
            _ => Outcome::Reply {
                head: self.failed(kind, seq, error::CMD_NOT_SUPPORTED, icc),
                data: 0,
            },
        }
    }
}

/// Which answer a failure of command `kind` takes. Source: CCID 1.1 §6.2 [C]
fn reply_kind(kind: u8) -> u8 {
    match kind {
        cmd::ICC_POWER_ON | cmd::XFR_BLOCK | cmd::SECURE => reply::DATA_BLOCK,
        cmd::GET_PARAMETERS | cmd::RESET_PARAMETERS | cmd::SET_PARAMETERS => reply::PARAMETERS,
        cmd::ESCAPE => reply::ESCAPE,
        cmd::SET_DATA_RATE_AND_CLOCK => reply::DATA_RATE_AND_CLOCK,
        _ => reply::SLOT_STATUS,
    }
}

impl Outcome {
    fn with_data(self, n: usize) -> Self {
        match self {
            Outcome::Reply { head, .. } => Outcome::Reply { head, data: n },
            other => other,
        }
    }
}

// ---------------------------------------------------------------------------------------
// The one APDU
// ---------------------------------------------------------------------------------------

/// The APDU the card answers, and the ISO plumbing around it.
///
/// ```text
/// CLA  0x80   a whole message, or the last chunk of one
///      0x90   a chunk with more to follow (ISO 7816-4 command chaining, bit 0x10)
/// INS  0xCC
/// P1 P2  0x00 0x00
/// data   first chunk: [u16 opcode LE][u32 total LE][payload...]
///        later chunks: [payload...]
/// Le     always send one: 0x00 (256) short, or 0x00 0x00 (65536) extended
///
/// reply  [u16 status LE][u32 total LE][payload...]   SW 9000
///        a chunk that is not the last is acknowledged with no data and 9000
/// ```
///
/// The six-byte header is the HID `START` frame's, without the frame kind and sequence
/// that the transport supplies: a host that has the HID framing has this one. The
/// total is what lets a firmware image stream to staging as it arrives, as over HID.
///
/// A reply longer than `Le` comes back `Le` bytes at a time: the first page with
/// `61 xx` (bytes still waiting, 255 meaning that many or more) and the rest through
/// `GET RESPONSE` (`00 C0 00 00 Le`). With an extended `Le` of 65536 every reply this
/// firmware gives fits the first page. Source: ISO/IEC 7816-4 §5.3, §7.6.1 [C]
pub mod apdu {
    use core::ops::Range;

    use crate::{Message, Progress};

    /// Proprietary class.
    pub const CLA: u8 = 0x80;
    /// Command chaining: more chunks of this message follow.
    pub const CLA_CHAIN: u8 = 0x10;
    /// The message instruction.
    pub const INS_MESSAGE: u8 = 0xCC;
    /// `GET RESPONSE`, with the interindustry class.
    pub const INS_GET_RESPONSE: u8 = 0xC0;
    /// `[u16 opcode][u32 total]`, or `[u16 status][u32 total]` on the way back.
    pub const HEADER: usize = 6;

    /// Status words. Source: ISO/IEC 7816-4 §5.1.3 [C]
    pub mod sw {
        pub const OK: u16 = 0x9000;
        /// `61 xx`: more data waits for `GET RESPONSE`.
        pub const MORE: u16 = 0x6100;
        pub const WRONG_LENGTH: u16 = 0x6700;
        /// Nothing waits to be fetched.
        pub const NOTHING_PENDING: u16 = 0x6985;
        pub const WRONG_P1P2: u16 = 0x6A86;
        pub const INS_NOT_SUPPORTED: u16 = 0x6D00;
        pub const CLA_NOT_SUPPORTED: u16 = 0x6E00;
    }

    /// How much the host is ready to take back.
    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    pub enum Le {
        /// No `Le`: data is not expected, so any is announced with `61 xx` and sent
        /// nothing until asked.
        None,
        /// A short `Le`, 1..=256.
        Short(usize),
        /// An extended `Le`, 1..=65536.
        Extended(usize),
    }

    impl Le {
        /// Bytes the host will take in this exchange.
        pub fn take(self) -> usize {
            match self {
                Le::None => 0,
                Le::Short(n) | Le::Extended(n) => n,
            }
        }
    }

    /// A parsed command APDU.
    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    pub struct Command<'a> {
        pub cla: u8,
        pub ins: u8,
        pub p1: u8,
        pub p2: u8,
        pub data: &'a [u8],
        pub le: Le,
    }

    /// Decode the four cases of ISO 7816-4 §5.3.2, short and extended. A body that is
    /// none of them is `6700`.
    pub fn parse(b: &[u8]) -> Result<Command<'_>, u16> {
        if b.len() < 4 {
            return Err(sw::WRONG_LENGTH);
        }
        let (cla, ins, p1, p2) = (b[0], b[1], b[2], b[3]);
        let rest = &b[4..];
        let (data, le) = match rest.len() {
            0 => (&[][..], Le::None),
            1 => (&[][..], Le::Short(short(rest[0]))),
            _ if rest[0] != 0 => {
                let lc = rest[0] as usize;
                if rest.len() == 1 + lc {
                    (&rest[1..1 + lc], Le::None)
                } else if rest.len() == 2 + lc {
                    (&rest[1..1 + lc], Le::Short(short(rest[1 + lc])))
                } else {
                    return Err(sw::WRONG_LENGTH);
                }
            }
            // A leading zero announces extended lengths.
            2 => return Err(sw::WRONG_LENGTH),
            3 => (&[][..], Le::Extended(extended(rest[1], rest[2]))),
            _ => {
                let lc = u16::from_be_bytes([rest[1], rest[2]]) as usize;
                if lc == 0 {
                    return Err(sw::WRONG_LENGTH);
                }
                if rest.len() == 3 + lc {
                    (&rest[3..3 + lc], Le::None)
                } else if rest.len() == 5 + lc {
                    (
                        &rest[3..3 + lc],
                        Le::Extended(extended(rest[3 + lc], rest[4 + lc])),
                    )
                } else {
                    return Err(sw::WRONG_LENGTH);
                }
            }
        };
        Ok(Command {
            cla,
            ins,
            p1,
            p2,
            data,
            le,
        })
    }

    fn short(b: u8) -> usize {
        if b == 0 { 256 } else { b as usize }
    }

    fn extended(hi: u8, lo: u8) -> usize {
        let n = u16::from_be_bytes([hi, lo]) as usize;
        if n == 0 { 65536 } else { n }
    }

    /// What the host is asking the card for.
    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    pub enum Request<'a> {
        /// A whole message or a chunk of one. `more` is the chaining bit.
        Chunk { more: bool, data: &'a [u8], le: Le },
        /// The next page of a reply.
        GetResponse { le: Le },
    }

    /// Sort a command into the two this card answers, or the status word for one it
    /// does not: the class first (`6E00`), then the instruction (`6D00`), then P1 P2
    /// (`6A86`), as ISO 7816-4 §5.1.3 orders the checks.
    pub fn classify<'a>(c: &Command<'a>) -> Result<Request<'a>, u16> {
        match (c.cla, c.ins) {
            (CLA, INS_MESSAGE) | (0x90, INS_MESSAGE) => {
                if (c.p1, c.p2) != (0, 0) {
                    return Err(sw::WRONG_P1P2);
                }
                Ok(Request::Chunk {
                    more: c.cla & CLA_CHAIN != 0,
                    data: c.data,
                    le: c.le,
                })
            }
            (0x00, INS_GET_RESPONSE) | (CLA, INS_GET_RESPONSE) => {
                if (c.p1, c.p2) != (0, 0) {
                    return Err(sw::WRONG_P1P2);
                }
                if !c.data.is_empty() || c.le == Le::None {
                    return Err(sw::WRONG_LENGTH);
                }
                Ok(Request::GetResponse { le: c.le })
            }
            (CLA | 0x90 | 0x00, _) => Err(sw::INS_NOT_SUPPORTED),
            _ => Err(sw::CLA_NOT_SUPPORTED),
        }
    }

    /// Why a chunk did not fit the message it claims to be part of. All of them end
    /// the message; the host starts it again.
    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    pub enum ChainError {
        /// A first chunk without the six-byte header.
        NoHeader = 1,
        /// More payload than the total announced.
        Overrun = 2,
        /// The last chunk (chaining bit clear) left the message short.
        Short = 3,
        /// A chunk announced more to come when the message was already whole.
        Spurious = 4,
    }

    /// Turns chained chunks back into one message, without buffering: each chunk's
    /// payload is handed on as it arrives, as [`crate::Reassembler`] does for frames.
    #[derive(Default, Debug)]
    pub struct Chain {
        open: Option<Message>,
        received: u32,
    }

    impl Chain {
        pub const fn new() -> Self {
            Self {
                open: None,
                received: 0,
            }
        }

        pub fn reset(&mut self) {
            self.open = None;
            self.received = 0;
        }

        pub fn in_progress(&self) -> bool {
            self.open.is_some()
        }

        /// Feed one chunk. Any error resets the chain.
        pub fn feed<'a>(&mut self, more: bool, data: &'a [u8]) -> Result<Progress<'a>, ChainError> {
            let r = self.feed_inner(more, data);
            if r.is_err() {
                self.reset();
            }
            r
        }

        fn feed_inner<'a>(
            &mut self,
            more: bool,
            data: &'a [u8],
        ) -> Result<Progress<'a>, ChainError> {
            let (started, payload, msg) = match self.open {
                None => {
                    let Some(h) = data.first_chunk::<HEADER>() else {
                        return Err(ChainError::NoHeader);
                    };
                    let msg = Message {
                        opcode: u16::from_le_bytes([h[0], h[1]]),
                        total: u32::from_le_bytes([h[2], h[3], h[4], h[5]]),
                    };
                    self.received = 0;
                    (Some(msg), &data[HEADER..], msg)
                }
                Some(msg) => (None, data, msg),
            };
            let left = msg.total - self.received;
            if payload.len() as u64 > left as u64 {
                return Err(ChainError::Overrun);
            }
            self.received += payload.len() as u32;
            let complete = self.received == msg.total;
            if more && complete {
                return Err(ChainError::Spurious);
            }
            if !more && !complete {
                return Err(ChainError::Short);
            }
            self.open = if complete { None } else { Some(msg) };
            Ok(Progress {
                started,
                payload,
                complete,
            })
        }
    }

    /// The reply header: `[u16 status][u32 total]`.
    pub fn response_header(status: u16, total: usize) -> [u8; HEADER] {
        let s = status.to_le_bytes();
        let t = (total as u32).to_le_bytes();
        [s[0], s[1], t[0], t[1], t[2], t[3]]
    }

    /// A reply being paged out: `len` bytes in all (header and payload), `sent` gone.
    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    pub struct Paged {
        pub len: usize,
        pub sent: usize,
    }

    impl Paged {
        pub const fn new(len: usize) -> Self {
            Self { len, sent: 0 }
        }

        /// The next page for a host that will take `le`: the range of the reply to
        /// send, and the status word to send after it.
        pub fn page(&mut self, le: Le) -> (Range<usize>, u16) {
            let left = self.len - self.sent;
            let n = le.take().min(left);
            let r = self.sent..self.sent + n;
            self.sent += n;
            let left = self.len - self.sent;
            let sw = if left == 0 {
                sw::OK
            } else {
                sw::MORE | left.min(255) as u16
            };
            (r, sw)
        }

        pub fn done(&self) -> bool {
            self.sent == self.len
        }
    }
}

/// The bytes of one bulk-IN message, assembled from its pieces as it is sent: the CCID
/// header, up to a few bytes of its own, a range of a body held elsewhere, and a tail.
/// Nothing is copied into one place; each packet is composed from the pieces.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Outgoing {
    /// The header and any inline data: an ATR, the parameters, a reply's own header.
    local: [u8; Header::LEN + 16],
    local_len: usize,
    /// A range of the body the caller holds (a reply's payload).
    body: Range<usize>,
    /// The status word, for an APDU answer.
    tail: [u8; 2],
    tail_len: usize,
    sent: usize,
}

impl Outgoing {
    /// `head`, then `inline`, then `body[body]` of a buffer the caller holds, then `tail`.
    /// The inline part must fit sixteen bytes: an ATR does, and that is the longest.
    pub fn new(head: Header, inline: &[u8], body: Range<usize>, tail: &[u8]) -> Self {
        let mut local = [0u8; Header::LEN + 16];
        local[..Header::LEN].copy_from_slice(&head.to_bytes());
        let n = inline.len().min(16);
        local[Header::LEN..Header::LEN + n].copy_from_slice(&inline[..n]);
        let mut t = [0u8; 2];
        let tn = tail.len().min(2);
        t[..tn].copy_from_slice(&tail[..tn]);
        Self {
            local,
            local_len: Header::LEN + n,
            body,
            tail: t,
            tail_len: tn,
            sent: 0,
        }
    }

    /// Bytes in the whole message.
    pub fn len(&self) -> usize {
        self.local_len + self.body.len() + self.tail_len
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether every packet, including a closing empty one, has been handed out.
    pub fn done(&self) -> bool {
        self.sent > self.len()
            || (self.sent == self.len() && !self.len().is_multiple_of(MAX_PACKET))
    }

    /// Compose the next packet into `out`, reading the body from `body`, without
    /// counting it sent: [`advance`](Self::advance) does that once the endpoint took
    /// it, so a send the FIFO refused is composed again next time. `None` once the
    /// message is finished. A message that is a whole number of packets ends with an
    /// empty one, so the host's read -- for more than the message is long -- ends.
    pub fn next_packet(&self, body: &[u8], out: &mut [u8; MAX_PACKET]) -> Option<usize> {
        if self.done() {
            return None;
        }
        let len = self.len();
        let n = (len - self.sent).min(MAX_PACKET);
        for (i, slot) in out.iter_mut().enumerate().take(n) {
            let at = self.sent + i;
            *slot = if at < self.local_len {
                self.local[at]
            } else if at < self.local_len + self.body.len() {
                body.get(self.body.start + at - self.local_len)
                    .copied()
                    .unwrap_or(0)
            } else {
                self.tail[at - self.local_len - self.body.len()]
            };
        }
        Some(n)
    }

    /// The packet [`next_packet`](Self::next_packet) composed has been sent.
    pub fn advance(&mut self) {
        let n = (self.len() - self.sent).min(MAX_PACKET);
        // An empty closing packet counts one past the end, so `done` can tell it apart
        // from a message that simply has not started.
        self.sent += n.max(1);
    }
}

#[cfg(test)]
mod tests {
    use super::apdu::{self, ChainError, Le, Request};
    use super::*;

    fn walk(c: &[u8]) -> Vec<u8> {
        assert_eq!(u16::from_le_bytes([c[2], c[3]]) as usize, c.len());
        let mut at = 0;
        let mut seen = Vec::new();
        while at < c.len() {
            let len = c[at] as usize;
            assert!(len >= 2 && at + len <= c.len(), "at {at}");
            seen.push(c[at + 1]);
            at += len;
        }
        assert_eq!(at, c.len());
        seen
    }

    #[test]
    fn every_composite_walks_cleanly_and_keeps_the_earlier_interfaces_byte_for_byte() {
        let (c, i, h, e) = (
            kind::CONFIGURATION,
            kind::INTERFACE,
            kind::HID,
            kind::ENDPOINT,
        );
        assert_eq!(
            walk(&CONFIGURATION),
            vec![c, i, h, e, e, i, CLASS_DESCRIPTOR_TYPE, e, e]
        );
        assert_eq!(CONFIGURATION[4], 2);
        assert_eq!(
            &CONFIGURATION[9..WALLET_LEN],
            &descriptor::CONFIGURATION[9..]
        );
        assert_eq!(CONFIGURATION[WALLET_LEN + 2], 1, "interface 1");

        assert_eq!(walk(&CONFIGURATION_WITH_KBD).len(), 12);
        assert_eq!(CONFIGURATION_WITH_KBD[4], 3);
        assert_eq!(
            &CONFIGURATION_WITH_KBD[9..KBD_LEN],
            &crate::kbd::CONFIGURATION[9..]
        );
        assert_eq!(CONFIGURATION_WITH_KBD[KBD_LEN + 2], 2);

        assert_eq!(walk(&CONFIGURATION_WITH_FIDO).len(), 13);
        assert_eq!(CONFIGURATION_WITH_FIDO[4], 3);
        assert_eq!(
            &CONFIGURATION_WITH_FIDO[9..FIDO_LEN],
            &crate::fido::CONFIGURATION[9..]
        );
        assert_eq!(CONFIGURATION_WITH_FIDO[FIDO_LEN + 2], 2);

        assert_eq!(walk(&CONFIGURATION_WITH_KBD_FIDO).len(), 16);
        assert_eq!(CONFIGURATION_WITH_KBD_FIDO[4], 4);
        assert_eq!(
            &CONFIGURATION_WITH_KBD_FIDO[9..KBD_FIDO_LEN],
            &crate::fido::CONFIGURATION_WITH_KBD[9..]
        );
        assert_eq!(CONFIGURATION_WITH_KBD_FIDO[KBD_FIDO_LEN + 2], 3);
        assert_eq!(CONFIGURATION_MAX, CONFIGURATION_WITH_KBD_FIDO.len());
    }

    #[test]
    fn the_interface_is_a_ccid_reader_with_two_bulk_endpoints_of_its_own() {
        for (c, at) in [
            (&CONFIGURATION[..], WALLET_LEN),
            (&CONFIGURATION_WITH_KBD[..], KBD_LEN),
            (&CONFIGURATION_WITH_FIDO[..], FIDO_LEN),
            (&CONFIGURATION_WITH_KBD_FIDO[..], KBD_FIDO_LEN),
        ] {
            assert_eq!(c[at + 5], INTERFACE_CLASS);
            assert_eq!((c[at + 6], c[at + 7]), (0, 0));
            assert_eq!(&c[at + 9..at + 9 + 54], &CLASS_DESCRIPTOR);
            let (i, o) = (at + 9 + 54, at + 9 + 54 + 7);
            assert_eq!((c[i + 2], c[i + 3]), (EP_IN, 0x02));
            assert_eq!((c[o + 2], c[o + 3]), (EP_OUT, 0x02));
            assert_eq!(u16::from_le_bytes([c[i + 4], c[i + 5]]) as usize, 64);
            assert_eq!(u16::from_le_bytes([c[o + 4], c[o + 5]]) as usize, 64);
        }
        for ep in [
            descriptor::EP_IN,
            descriptor::EP_OUT,
            crate::kbd::EP_IN,
            crate::fido::EP_IN,
            crate::fido::EP_OUT,
        ] {
            assert_ne!(ep & 0x0F, EP_IN & 0x0F, "must not share an endpoint number");
        }
        assert_eq!(EP_IN & 0x0F, EP_OUT & 0x0F);
    }

    #[test]
    fn the_class_descriptor_says_t1_apdu_level_and_our_message_length() {
        let d = &CLASS_DESCRIPTOR;
        assert_eq!(d[0] as usize, d.len());
        assert_eq!(d[1], CLASS_DESCRIPTOR_TYPE);
        assert_eq!(u16::from_le_bytes([d[2], d[3]]), 0x0110);
        assert_eq!(d[4], 0, "one slot");
        let u = |at: usize| u32::from_le_bytes([d[at], d[at + 1], d[at + 2], d[at + 3]]);
        assert_eq!(u(6), 2, "T=1 only");
        assert_eq!(u(10), CLOCK_KHZ);
        assert_eq!(u(19), DATA_RATE_BPS);
        assert_eq!(u(28), IFSC as u32);
        assert_eq!(u(40), FEATURES);
        assert_ne!(u(40) & 0x0004_0000, 0, "extended APDU level");
        assert_eq!(u(44) as usize, MESSAGE_MAX);
        assert_eq!(d[53], 1);
        assert_eq!(CLOCK_FREQUENCIES, CLOCK_KHZ.to_le_bytes());
        assert_eq!(DATA_RATES, DATA_RATE_BPS.to_le_bytes());
    }

    #[test]
    fn the_atr_is_direct_convention_t1_and_checks() {
        assert_eq!(ATR[0], 0x3B);
        assert_eq!(ATR[1] & 0x0F, HISTORICAL.len() as u8);
        assert_eq!(ATR[1] & 0xF0, 0x80, "only TD1 after T0");
        assert_eq!(ATR[2] & 0x0F, 1, "T=1");
        assert_eq!(ATR[3], 0x31);
        assert_eq!(&ATR[6..6 + HISTORICAL.len()], HISTORICAL);
        let tck = ATR[1..ATR_LEN - 1].iter().fold(0, |a, b| a ^ b);
        assert_eq!(ATR[ATR_LEN - 1], tck);
        assert_eq!(PARAMETERS_T1[5], IFSC);
        assert_eq!(PARAMETERS_T1[3], ATR[5]);
    }

    fn hdr(kind: u8, len: u32, seq: u8, p: [u8; 3]) -> Header {
        Header {
            kind,
            len,
            slot: 0,
            seq,
            p,
        }
    }

    #[test]
    fn a_header_round_trips() {
        let h = hdr(cmd::XFR_BLOCK, 0x0102_0304, 7, [1, 2, 3]);
        assert_eq!(Header::parse(&h.to_bytes()), h);
        assert_eq!(h.to_bytes()[1..5], [4, 3, 2, 1]);
    }

    #[test]
    fn power_on_answers_the_atr_and_the_card_is_mute_until_then() {
        let mut r = Reader::new();
        let mut buf = [0u8; 64];
        let o = r.command(&hdr(cmd::XFR_BLOCK, 4, 1, [0, 0, 0]), &mut buf);
        let Outcome::Reply { head, data } = o else {
            panic!("{o:?}")
        };
        assert_eq!(head.kind, reply::DATA_BLOCK);
        assert_eq!(head.p[0], status::ICC_INACTIVE | status::FAILED);
        assert_eq!(head.p[1], error::ICC_MUTE);
        assert_eq!(data, 0);

        let o = r.command(&hdr(cmd::ICC_POWER_ON, 0, 2, [0, 0, 0]), &mut buf);
        let Outcome::Reply { head, data } = o else {
            panic!("{o:?}")
        };
        assert_eq!(
            (head.kind, head.seq, head.len as usize),
            (reply::DATA_BLOCK, 2, ATR_LEN)
        );
        assert_eq!(head.p, [status::ICC_ACTIVE, 0, 0]);
        assert_eq!(&buf[..data], &ATR);
        assert!(r.powered());

        let o = r.command(&hdr(cmd::XFR_BLOCK, 4, 3, [0, 0, 0]), &mut buf);
        assert_eq!(o, Outcome::Apdu { seq: 3 });

        let o = r.command(&hdr(cmd::ICC_POWER_OFF, 0, 4, [0, 0, 0]), &mut buf);
        let Outcome::Reply { head, .. } = o else {
            panic!("{o:?}")
        };
        assert_eq!(head.kind, reply::SLOT_STATUS);
        assert_eq!(head.p[0], status::ICC_INACTIVE);
        assert!(!r.powered());
    }

    #[test]
    fn slot_status_parameters_and_rates_are_answered_and_the_rest_refused() {
        let mut r = Reader::new();
        let mut buf = [0u8; 64];
        let o = r.command(&hdr(cmd::GET_SLOT_STATUS, 0, 9, [0, 0, 0]), &mut buf);
        let Outcome::Reply { head, data } = o else {
            panic!()
        };
        assert_eq!((head.kind, head.seq, data), (reply::SLOT_STATUS, 9, 0));
        assert_eq!(head.p, [status::ICC_INACTIVE, 0, 0]);

        for k in [
            cmd::GET_PARAMETERS,
            cmd::RESET_PARAMETERS,
            cmd::SET_PARAMETERS,
        ] {
            let o = r.command(&hdr(k, 0, 1, [1, 0, 0]), &mut buf);
            let Outcome::Reply { head, data } = o else {
                panic!()
            };
            assert_eq!(head.kind, reply::PARAMETERS);
            assert_eq!(head.p[2], 1, "T=1");
            assert_eq!(&buf[..data], &PARAMETERS_T1);
        }

        let o = r.command(
            &hdr(cmd::SET_DATA_RATE_AND_CLOCK, 8, 1, [0, 0, 0]),
            &mut buf,
        );
        let Outcome::Reply { head, data } = o else {
            panic!()
        };
        assert_eq!((head.kind, data), (reply::DATA_RATE_AND_CLOCK, 8));
        assert_eq!(&buf[..4], &CLOCK_FREQUENCIES);
        assert_eq!(&buf[4..8], &DATA_RATES);

        for (k, want) in [
            (cmd::ESCAPE, reply::ESCAPE),
            (cmd::ICC_CLOCK, reply::SLOT_STATUS),
            (cmd::T0_APDU, reply::SLOT_STATUS),
            (cmd::SECURE, reply::DATA_BLOCK),
            (cmd::MECHANICAL, reply::SLOT_STATUS),
            (0x55, reply::SLOT_STATUS),
        ] {
            let o = r.command(&hdr(k, 0, 1, [0, 0, 0]), &mut buf);
            let Outcome::Reply { head, data } = o else {
                panic!()
            };
            assert_eq!(head.kind, want, "{k:#x}");
            assert_eq!(head.p[0] & status::FAILED, status::FAILED);
            assert_eq!(head.p[1], error::CMD_NOT_SUPPORTED);
            assert_eq!(data, 0);
        }
    }

    #[test]
    fn a_second_slot_does_not_exist_and_a_chained_xfr_is_refused() {
        let mut r = Reader::new();
        let mut buf = [0u8; 64];
        let mut h = hdr(cmd::GET_SLOT_STATUS, 0, 1, [0, 0, 0]);
        h.slot = 1;
        let Outcome::Reply { head, .. } = r.command(&h, &mut buf) else {
            panic!()
        };
        assert_eq!(
            head.p,
            [status::ICC_ABSENT | status::FAILED, error::BAD_SLOT, 0]
        );

        r.command(&hdr(cmd::ICC_POWER_ON, 0, 1, [0, 0, 0]), &mut buf);
        let o = r.command(&hdr(cmd::XFR_BLOCK, 4, 2, [0, 1, 0]), &mut buf);
        let Outcome::Reply { head, .. } = o else {
            panic!()
        };
        assert_eq!(head.p[1], error::BAD_LEVEL);
    }

    #[test]
    fn a_control_abort_is_answered_only_by_its_own_bulk_abort() {
        let mut r = Reader::new();
        let mut buf = [0u8; 64];
        r.command(&hdr(cmd::ICC_POWER_ON, 0, 1, [0, 0, 0]), &mut buf);
        r.control_abort(7);
        // Anything else meanwhile: aborted.
        let Outcome::Reply { head, .. } =
            r.command(&hdr(cmd::XFR_BLOCK, 4, 8, [0, 0, 0]), &mut buf)
        else {
            panic!()
        };
        assert_eq!(
            (head.kind, head.p[1]),
            (reply::DATA_BLOCK, error::CMD_ABORTED)
        );
        // A bulk Abort with the wrong sequence: also aborted.
        let Outcome::Reply { head, .. } = r.command(&hdr(cmd::ABORT, 0, 6, [0, 0, 0]), &mut buf)
        else {
            panic!()
        };
        assert_eq!(head.p[1], error::CMD_ABORTED);
        // The matching one ends it.
        let Outcome::Reply { head, .. } = r.command(&hdr(cmd::ABORT, 0, 7, [0, 0, 0]), &mut buf)
        else {
            panic!()
        };
        assert_eq!(
            (head.kind, head.p),
            (reply::SLOT_STATUS, [status::ICC_ACTIVE, 0, 0])
        );
        assert_eq!(
            r.command(&hdr(cmd::XFR_BLOCK, 4, 9, [0, 0, 0]), &mut buf),
            Outcome::Apdu { seq: 9 }
        );
        // Power survives the abort.
        assert!(r.powered());
    }

    // --- APDU ---

    #[test]
    fn every_apdu_case_parses_and_the_malformed_are_6700() {
        let c = apdu::parse(&[0x80, 0xCC, 0, 0]).unwrap();
        assert_eq!((c.data, c.le), (&[][..], Le::None));
        let c = apdu::parse(&[0x80, 0xCC, 0, 0, 0x00]).unwrap();
        assert_eq!(c.le, Le::Short(256));
        let c = apdu::parse(&[0x80, 0xCC, 0, 0, 0x10]).unwrap();
        assert_eq!(c.le, Le::Short(16));
        let c = apdu::parse(&[0x80, 0xCC, 0, 0, 2, 0xAA, 0xBB]).unwrap();
        assert_eq!((c.data, c.le), (&[0xAA, 0xBB][..], Le::None));
        let c = apdu::parse(&[0x80, 0xCC, 0, 0, 2, 0xAA, 0xBB, 0x00]).unwrap();
        assert_eq!((c.data, c.le), (&[0xAA, 0xBB][..], Le::Short(256)));
        let c = apdu::parse(&[0x80, 0xCC, 0, 0, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!((c.data, c.le), (&[][..], Le::Extended(65536)));
        let c = apdu::parse(&[0x80, 0xCC, 0, 0, 0x00, 0x01, 0x00]).unwrap();
        assert_eq!(c.le, Le::Extended(256));
        let c = apdu::parse(&[0x80, 0xCC, 0, 0, 0x00, 0x00, 0x02, 1, 2]).unwrap();
        assert_eq!((c.data, c.le), (&[1, 2][..], Le::None));
        let c = apdu::parse(&[0x80, 0xCC, 0, 0, 0x00, 0x00, 0x02, 1, 2, 0x00, 0x00]).unwrap();
        assert_eq!((c.data, c.le), (&[1, 2][..], Le::Extended(65536)));

        for bad in [
            &[0x80u8, 0xCC, 0][..],
            &[0x80, 0xCC, 0, 0, 2, 0xAA],
            &[0x80, 0xCC, 0, 0, 2, 0xAA, 0xBB, 0x00, 0x00],
            &[0x80, 0xCC, 0, 0, 0x00, 0x05],
            &[0x80, 0xCC, 0, 0, 0x00, 0x00, 0x00, 1],
            &[0x80, 0xCC, 0, 0, 0x00, 0x00, 0x02, 1],
            &[0x80, 0xCC, 0, 0, 0x00, 0x00, 0x02, 1, 2, 0x00],
        ] {
            assert_eq!(apdu::parse(bad), Err(apdu::sw::WRONG_LENGTH), "{bad:02x?}");
        }
    }

    #[test]
    fn only_our_instruction_and_get_response_are_answered() {
        let m = |b: &[u8]| {
            apdu::parse(b).map(|c| apdu::classify(&c).map(|r| matches!(r, Request::Chunk { .. })))
        };
        assert_eq!(m(&[0x80, 0xCC, 0, 0, 1, 9, 0]), Ok(Ok(true)));
        assert_eq!(m(&[0x90, 0xCC, 0, 0, 1, 9, 0]), Ok(Ok(true)));
        assert_eq!(m(&[0x00, 0xC0, 0, 0, 0]), Ok(Ok(false)));
        assert_eq!(m(&[0x80, 0xC0, 0, 0, 0]), Ok(Ok(false)));
        let sw = |b: &[u8]| apdu::classify(&apdu::parse(b).unwrap()).unwrap_err();
        assert_eq!(
            sw(&[0x00, 0xA4, 0x04, 0x00, 0]),
            apdu::sw::INS_NOT_SUPPORTED,
            "SELECT"
        );
        assert_eq!(sw(&[0x80, 0x01, 0, 0]), apdu::sw::INS_NOT_SUPPORTED);
        assert_eq!(sw(&[0xFF, 0xCC, 0, 0]), apdu::sw::CLA_NOT_SUPPORTED);
        assert_eq!(sw(&[0x80, 0xCC, 1, 0]), apdu::sw::WRONG_P1P2);
        assert_eq!(sw(&[0x00, 0xC0, 0, 1, 0]), apdu::sw::WRONG_P1P2);
        assert_eq!(
            sw(&[0x00, 0xC0, 0, 0]),
            apdu::sw::WRONG_LENGTH,
            "GET RESPONSE needs Le"
        );
        assert_eq!(sw(&[0x00, 0xC0, 0, 0, 1, 5, 0]), apdu::sw::WRONG_LENGTH);
        let c = apdu::parse(&[0x90, 0xCC, 0, 0, 1, 9, 0]).unwrap();
        let Ok(Request::Chunk { more, data, le }) = apdu::classify(&c) else {
            panic!()
        };
        assert_eq!((more, data, le), (true, &[9][..], Le::Short(256)));
    }

    #[test]
    fn a_whole_message_in_one_chunk_and_one_spread_over_three() {
        let mut ch = apdu::Chain::new();
        let p = ch.feed(false, &[0x02, 0x00, 0, 0, 0, 0]).unwrap();
        assert_eq!(p.started.map(|m| (m.opcode, m.total)), Some((2, 0)));
        assert!(p.complete && p.payload.is_empty());
        assert!(!ch.in_progress());

        let p = ch.feed(true, &[0x10, 0x00, 5, 0, 0, 0, 1, 2]).unwrap();
        assert_eq!(p.started.map(|m| m.total), Some(5));
        assert_eq!((p.payload, p.complete), (&[1, 2][..], false));
        assert!(ch.in_progress());
        let p = ch.feed(true, &[3]).unwrap();
        assert_eq!((p.started, p.payload, p.complete), (None, &[3][..], false));
        let p = ch.feed(false, &[4, 5]).unwrap();
        assert_eq!(
            (p.started, p.payload, p.complete),
            (None, &[4, 5][..], true)
        );
        assert!(!ch.in_progress());
    }

    #[test]
    fn a_chunk_that_does_not_fit_its_message_ends_the_message() {
        let mut ch = apdu::Chain::new();
        assert_eq!(ch.feed(false, &[1, 0, 0]), Err(ChainError::NoHeader));
        assert_eq!(
            ch.feed(false, &[1, 0, 1, 0, 0, 0, 7, 8]),
            Err(ChainError::Overrun)
        );
        assert_eq!(
            ch.feed(false, &[1, 0, 2, 0, 0, 0, 7]),
            Err(ChainError::Short)
        );
        assert_eq!(
            ch.feed(true, &[1, 0, 1, 0, 0, 0, 7]),
            Err(ChainError::Spurious)
        );
        assert!(!ch.in_progress());
        ch.feed(true, &[1, 0, 4, 0, 0, 0, 7]).unwrap();
        assert_eq!(ch.feed(true, &[1, 2, 3]), Err(ChainError::Spurious));
        assert!(!ch.in_progress(), "the error reset the chain");
        ch.feed(true, &[1, 0, 4, 0, 0, 0, 7]).unwrap();
        assert_eq!(ch.feed(false, &[1, 2, 3, 4]), Err(ChainError::Overrun));
        // And a fresh start after an error is a fresh start.
        let p = ch.feed(false, &[1, 0, 1, 0, 0, 0, 9]).unwrap();
        assert!(p.complete);
    }

    #[test]
    fn a_long_reply_is_paged_by_le_and_get_response() {
        let mut p = apdu::Paged::new(300);
        assert_eq!(p.page(Le::Short(256)), (0..256, 0x612C));
        assert_eq!(p.page(Le::Short(256)), (256..300, 0x9000));
        assert!(p.done());

        let mut p = apdu::Paged::new(600);
        assert_eq!(p.page(Le::None), (0..0, 0x61FF));
        assert_eq!(p.page(Le::Short(100)), (0..100, 0x61FF));
        assert_eq!(p.page(Le::Short(256)), (100..356, 0x61F4));
        assert_eq!(p.page(Le::Extended(65536)), (356..600, 0x9000));

        let mut p = apdu::Paged::new(518);
        assert_eq!(p.page(Le::Extended(65536)), (0..518, 0x9000));
        assert_eq!(apdu::response_header(0x0005, 7), [5, 0, 7, 0, 0, 0]);
    }

    #[test]
    fn an_outgoing_message_is_composed_from_its_pieces_and_ends_short() {
        let body = [0xAAu8; 200];
        let head = Reader::new().data_block(3, 6 + 100 + 2);
        let mut o = Outgoing::new(head, &[1, 2, 3, 4, 5, 6], 50..150, &[0x90, 0x00]);
        assert_eq!(o.len(), 10 + 6 + 100 + 2);
        let mut all = Vec::new();
        let mut pkt = [0u8; 64];
        let mut sizes = Vec::new();
        // Composed twice, sent once: a refused send costs nothing.
        assert_eq!(o.next_packet(&body, &mut pkt), Some(64));
        while let Some(n) = o.next_packet(&body, &mut pkt) {
            sizes.push(n);
            all.extend_from_slice(&pkt[..n]);
            o.advance();
        }
        assert_eq!(sizes, vec![64, 54]);
        assert_eq!(&all[..10], &head.to_bytes());
        assert_eq!(&all[10..16], &[1, 2, 3, 4, 5, 6]);
        assert!(all[16..116].iter().all(|&b| b == 0xAA));
        assert_eq!(&all[116..], &[0x90, 0x00]);
        assert!(o.done());

        // Exactly two packets long: a third, empty one closes it.
        let head = Reader::new().data_block(1, 118);
        let mut o = Outgoing::new(head, &[], 0..118, &[]);
        assert_eq!(o.len(), 128);
        let mut sizes = Vec::new();
        while let Some(n) = o.next_packet(&body, &mut pkt) {
            sizes.push(n);
            o.advance();
        }
        assert_eq!(sizes, vec![64, 64, 0]);
        assert!(o.done());

        // Ten bytes, the shortest answer, is one packet.
        let mut o = Outgoing::new(Reader::new().data_block(1, 0), &[], 0..0, &[]);
        assert_eq!(o.next_packet(&[], &mut pkt), Some(10));
        o.advance();
        assert_eq!(o.next_packet(&[], &mut pkt), None);

        // A message too long to take is refused with the offset of its length field.
        let r = Reader::new();
        let h = r.refused(&hdr(cmd::XFR_BLOCK, 5000, 4, [0, 0, 0]), error::BAD_LENGTH);
        assert_eq!((h.kind, h.seq, h.len), (reply::DATA_BLOCK, 4, 0));
        assert_eq!(
            h.p,
            [status::ICC_INACTIVE | status::FAILED, error::BAD_LENGTH, 0]
        );
    }
}
