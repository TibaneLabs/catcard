//! USB Mass Storage Class: SCSI transparent command set over Bulk-Only Transport.
//!
//! The portable half -- descriptors, the BOT wrappers, and the SCSI command decode and
//! fixed replies -- lives here and is tested on the host, exactly like [`crate::control`]
//! for the HID side. Moving bytes over the bulk endpoints and reading/writing the card
//! is the firmware's, because only that needs a device.
//!
//! Bulk-Only Transport (USB MSC BBB, rev 1.0): the host sends a 31-byte **CBW** on the
//! bulk-OUT endpoint, then a data phase in the direction the CBW names, then reads a
//! 13-byte **CSW** from bulk-IN. The command inside the CBW is SCSI; only the handful of
//! commands an OS issues to mount and use a removable disk are implemented, and anything
//! else is failed with a sense key the host can read back with `REQUEST SENSE`.
//!
//! Source: USB Mass Storage Class Bulk-Only Transport 1.0; SCSI SPC-3 / SBC-3 for the
//! command and reply layouts.

use catcard_board::{PRODUCT_ID, VENDOR_ID};

use crate::descriptor::kind;

/// Bytes in a disk block. Every card here is 512-byte addressed.
pub const BLOCK_LEN: usize = 512;

/// Bulk endpoint addresses, reusing EP1 in both directions as the HID build does. The
/// device is only ever one class at a time (it re-enumerates to switch), so there is no
/// clash with the interrupt endpoints of the HID configuration.
pub const EP_IN: u8 = 0x81;
pub const EP_OUT: u8 = 0x01;

/// Largest bulk packet at full speed.
pub const MAX_PACKET: u16 = 64;

// ---------------------------------------------------------------------------
// Descriptors
// ---------------------------------------------------------------------------

/// Device descriptor for the mass-storage identity. Same VID/PID as the HID build --
/// it is the same device, wearing a different class for the length of one screen -- with
/// the class defined at the interface, as mass storage requires.
pub const DEVICE: [u8; 18] = [
    18,
    kind::DEVICE,
    0x00,
    0x02, // bcdUSB 2.00
    0x00, // bDeviceClass: per interface
    0x00,
    0x00,
    64, // bMaxPacketSize0
    VENDOR_ID as u8,
    (VENDOR_ID >> 8) as u8,
    PRODUCT_ID as u8,
    (PRODUCT_ID >> 8) as u8,
    0x01,
    0x00, // bcdDevice 0.01
    1,    // iManufacturer
    2,    // iProduct
    3,    // iSerialNumber
    1,    // bNumConfigurations
];

/// Total length of [`CONFIGURATION`].
pub const CONFIG_TOTAL: u16 = 9 + 9 + 7 + 7;

/// Configuration + one mass-storage interface + two bulk endpoints.
pub const CONFIGURATION: [u8; CONFIG_TOTAL as usize] = [
    // --- configuration ---
    9,
    kind::CONFIGURATION,
    CONFIG_TOTAL as u8,
    (CONFIG_TOTAL >> 8) as u8,
    1,    // bNumInterfaces
    1,    // bConfigurationValue
    0,    // iConfiguration
    0x80, // bus powered
    50,   // 100 mA
    // --- interface: Mass Storage / SCSI transparent / Bulk-Only ---
    9,
    kind::INTERFACE,
    0,    // bInterfaceNumber
    0,    // bAlternateSetting
    2,    // bNumEndpoints
    0x08, // bInterfaceClass: Mass Storage
    0x06, // bInterfaceSubClass: SCSI transparent command set
    0x50, // bInterfaceProtocol: Bulk-Only Transport
    0,    // iInterface
    // --- endpoint IN (bulk) ---
    7,
    kind::ENDPOINT,
    EP_IN,
    0x02, // bmAttributes: bulk
    MAX_PACKET as u8,
    (MAX_PACKET >> 8) as u8,
    0, // bInterval: ignored for bulk
    // --- endpoint OUT (bulk) ---
    7,
    kind::ENDPOINT,
    EP_OUT,
    0x02,
    MAX_PACKET as u8,
    (MAX_PACKET >> 8) as u8,
    0,
];

// ---------------------------------------------------------------------------
// Bulk-Only Transport wrappers
// ---------------------------------------------------------------------------

/// `dCBWSignature` -- "USBC" little-endian.
pub const CBW_SIGNATURE: u32 = 0x4342_5355;
/// `dCSWSignature` -- "USBS" little-endian.
pub const CSW_SIGNATURE: u32 = 0x5342_5355;
pub const CBW_LEN: usize = 31;
pub const CSW_LEN: usize = 13;

/// CSW status codes.
pub mod csw_status {
    pub const PASSED: u8 = 0x00;
    pub const FAILED: u8 = 0x01;
    pub const PHASE_ERROR: u8 = 0x02;
}

/// A parsed Command Block Wrapper.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Cbw {
    pub tag: u32,
    /// Bytes the host will move in the data phase.
    pub data_len: u32,
    /// True when the data phase is device-to-host.
    pub data_in: bool,
    pub lun: u8,
    pub cb: [u8; 16],
    pub cb_len: u8,
}

impl Cbw {
    /// Parse a 31-byte CBW. `None` if it is the wrong length or signature -- a host that
    /// sends a bad CBW is out of sync, and the firmware stalls the pipe rather than
    /// acting on garbage.
    pub fn parse(b: &[u8]) -> Option<Cbw> {
        if b.len() < CBW_LEN {
            return None;
        }
        if u32::from_le_bytes([b[0], b[1], b[2], b[3]]) != CBW_SIGNATURE {
            return None;
        }
        let cb_len = b[14] & 0x1F;
        if cb_len == 0 || cb_len as usize > 16 {
            return None;
        }
        let mut cb = [0u8; 16];
        cb.copy_from_slice(&b[15..31]);
        Some(Cbw {
            tag: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            data_len: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
            data_in: b[12] & 0x80 != 0,
            lun: b[13] & 0x0F,
            cb,
            cb_len,
        })
    }
}

/// Build the 13-byte Command Status Wrapper into `out`, returning its length.
pub fn csw(out: &mut [u8; CSW_LEN], tag: u32, residue: u32, status: u8) {
    out[0..4].copy_from_slice(&CSW_SIGNATURE.to_le_bytes());
    out[4..8].copy_from_slice(&tag.to_le_bytes());
    out[8..12].copy_from_slice(&residue.to_le_bytes());
    out[12] = status;
}

// ---------------------------------------------------------------------------
// SCSI
// ---------------------------------------------------------------------------

/// The SCSI commands this device understands, decoded from a CBW's command block.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Command {
    TestUnitReady,
    RequestSense {
        alloc: u8,
    },
    Inquiry {
        alloc: u16,
    },
    ModeSense {
        alloc: u16,
    },
    ReadCapacity,
    ReadFormatCapacities {
        alloc: u16,
    },
    Read {
        lba: u32,
        blocks: u16,
    },
    Write {
        lba: u32,
        blocks: u16,
    },
    /// PREVENT/ALLOW MEDIUM REMOVAL, START STOP UNIT (spin), SYNCHRONIZE CACHE:
    /// acknowledged with no data. A removable card does not act on them, but refusing
    /// makes some hosts retry or unmount.
    NoData,
    /// START STOP UNIT with the load/eject bit set: the host is ejecting the drive. The
    /// firmware takes it as "done", the same as leaving the screen.
    Eject,
    /// Anything else. Failed with `INVALID COMMAND`, and the host asks with `REQUEST
    /// SENSE` what went wrong.
    Unsupported,
}

/// SCSI operation codes.
mod op {
    pub const TEST_UNIT_READY: u8 = 0x00;
    pub const REQUEST_SENSE: u8 = 0x03;
    pub const INQUIRY: u8 = 0x12;
    pub const MODE_SENSE_6: u8 = 0x1A;
    pub const START_STOP_UNIT: u8 = 0x1B;
    pub const PREVENT_ALLOW: u8 = 0x1E;
    pub const READ_CAPACITY_10: u8 = 0x25;
    pub const READ_10: u8 = 0x28;
    pub const WRITE_10: u8 = 0x2A;
    pub const SYNCHRONIZE_CACHE: u8 = 0x35;
    pub const READ_FORMAT_CAPACITIES: u8 = 0x23;
}

/// Decode a command block. Reads only the fields each command defines; a truncated block
/// decodes to [`Command::Unsupported`] rather than reading past it.
pub fn decode(cb: &[u8]) -> Command {
    let be16 = |i: usize| -> u16 { u16::from_be_bytes([cb[i], cb[i + 1]]) };
    let be32 = |i: usize| -> u32 { u32::from_be_bytes([cb[i], cb[i + 1], cb[i + 2], cb[i + 3]]) };
    match cb.first().copied() {
        Some(op::TEST_UNIT_READY) => Command::TestUnitReady,
        Some(op::REQUEST_SENSE) if cb.len() >= 5 => Command::RequestSense { alloc: cb[4] },
        Some(op::INQUIRY) if cb.len() >= 5 => Command::Inquiry { alloc: be16(3) },
        Some(op::MODE_SENSE_6) if cb.len() >= 5 => Command::ModeSense {
            alloc: cb[4] as u16,
        },
        Some(op::READ_CAPACITY_10) => Command::ReadCapacity,
        Some(op::READ_FORMAT_CAPACITIES) if cb.len() >= 9 => {
            Command::ReadFormatCapacities { alloc: be16(7) }
        }
        Some(op::READ_10) if cb.len() >= 8 => Command::Read {
            lba: be32(2),
            blocks: be16(7),
        },
        Some(op::WRITE_10) if cb.len() >= 8 => Command::Write {
            lba: be32(2),
            blocks: be16(7),
        },
        // START STOP UNIT byte 4 bit 1 is LOEJ: set means eject.
        Some(op::START_STOP_UNIT) if cb.len() >= 5 && cb[4] & 0x02 != 0 => Command::Eject,
        Some(op::PREVENT_ALLOW | op::START_STOP_UNIT | op::SYNCHRONIZE_CACHE) => Command::NoData,
        _ => Command::Unsupported,
    }
}

// ---------------------------------------------------------------------------
// SCSI sense
// ---------------------------------------------------------------------------

/// A sense code: what to answer the next `REQUEST SENSE` with. `(key, asc, ascq)`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Sense {
    pub key: u8,
    pub asc: u8,
    pub ascq: u8,
}

impl Sense {
    /// No error.
    pub const OK: Sense = Sense {
        key: 0x00,
        asc: 0x00,
        ascq: 0x00,
    };
    /// ILLEGAL REQUEST / INVALID COMMAND OPERATION CODE.
    pub const INVALID_COMMAND: Sense = Sense {
        key: 0x05,
        asc: 0x20,
        ascq: 0x00,
    };
    /// ILLEGAL REQUEST / LOGICAL BLOCK ADDRESS OUT OF RANGE.
    pub const LBA_OUT_OF_RANGE: Sense = Sense {
        key: 0x05,
        asc: 0x21,
        ascq: 0x00,
    };
    /// MEDIUM ERROR / UNRECOVERED READ ERROR (or write) -- the card said no.
    pub const MEDIUM_ERROR: Sense = Sense {
        key: 0x03,
        asc: 0x11,
        ascq: 0x00,
    };
    /// NOT READY / MEDIUM NOT PRESENT.
    pub const NOT_READY: Sense = Sense {
        key: 0x02,
        asc: 0x3A,
        ascq: 0x00,
    };
}

// ---------------------------------------------------------------------------
// Fixed reply builders
// ---------------------------------------------------------------------------

/// Standard INQUIRY data (36 bytes). Removable direct-access block device.
pub fn inquiry(out: &mut [u8]) -> usize {
    const N: usize = 36;
    let b = &mut out[..N];
    b.fill(0);
    b[0] = 0x00; // direct-access block device
    b[1] = 0x80; // RMB: removable
    b[2] = 0x04; // SPC-2
    b[3] = 0x02; // response data format
    b[4] = (N - 5) as u8; // additional length
    b[8..16].copy_from_slice(b"Karpeles"); // vendor (8)
    b[16..32].copy_from_slice(b"CatCard SD Card "); // product (16)
    b[32..36].copy_from_slice(b"0001"); // revision (4)
    N
}

/// READ CAPACITY(10) data (8 bytes): last addressable LBA and block length, big-endian.
pub fn read_capacity(blocks: u32, out: &mut [u8]) -> usize {
    let last = blocks.saturating_sub(1);
    out[0..4].copy_from_slice(&last.to_be_bytes());
    out[4..8].copy_from_slice(&(BLOCK_LEN as u32).to_be_bytes());
    8
}

/// Fixed-format REQUEST SENSE data (18 bytes).
pub fn request_sense(sense: Sense, out: &mut [u8]) -> usize {
    const N: usize = 18;
    let b = &mut out[..N];
    b.fill(0);
    b[0] = 0x70; // current error, fixed format
    b[2] = sense.key & 0x0F;
    b[7] = (N - 8) as u8; // additional sense length
    b[12] = sense.asc;
    b[13] = sense.ascq;
    N
}

/// MODE SENSE(6) data: just the 4-byte parameter header, no pages. `write_protected`
/// sets the WP bit so a read-only export mounts read-only.
pub fn mode_sense(write_protected: bool, out: &mut [u8]) -> usize {
    out[0] = 3; // mode data length (bytes after this one)
    out[1] = 0; // medium type
    out[2] = if write_protected { 0x80 } else { 0x00 }; // device-specific: WP bit
    out[3] = 0; // block descriptor length
    4
}

/// READ FORMAT CAPACITIES data. Windows issues this before mounting; a Linux host does
/// not, but answering it costs nothing. One "formatted" capacity descriptor.
pub fn read_format_capacities(blocks: u32, out: &mut [u8]) -> usize {
    out[0..3].fill(0);
    out[3] = 8; // capacity list length: one 8-byte descriptor
    out[4..8].copy_from_slice(&blocks.to_be_bytes()); // number of blocks
    out[8] = 0x02; // descriptor code: formatted media
    out[9..12].copy_from_slice(&[
        (BLOCK_LEN >> 16) as u8,
        (BLOCK_LEN >> 8) as u8,
        BLOCK_LEN as u8,
    ]);
    12
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cbw_bytes(tag: u32, data_len: u32, data_in: bool, cb: &[u8]) -> [u8; CBW_LEN] {
        let mut b = [0u8; CBW_LEN];
        b[0..4].copy_from_slice(&CBW_SIGNATURE.to_le_bytes());
        b[4..8].copy_from_slice(&tag.to_le_bytes());
        b[8..12].copy_from_slice(&data_len.to_le_bytes());
        b[12] = if data_in { 0x80 } else { 0 };
        b[13] = 0;
        b[14] = cb.len() as u8;
        b[15..15 + cb.len()].copy_from_slice(cb);
        b
    }

    #[test]
    fn cbw_parses_and_rejects() {
        let b = cbw_bytes(0x1234, 512, true, &[0x28, 0, 0, 0, 0, 0x10, 0, 0, 1, 0]);
        let cbw = Cbw::parse(&b).expect("valid CBW");
        assert_eq!(cbw.tag, 0x1234);
        assert_eq!(cbw.data_len, 512);
        assert!(cbw.data_in);
        assert_eq!(cbw.cb_len, 10);

        // Bad signature is refused, not misread.
        let mut bad = b;
        bad[0] ^= 0xFF;
        assert!(Cbw::parse(&bad).is_none());
        // A zero-length command block is refused.
        let mut zero = b;
        zero[14] = 0;
        assert!(Cbw::parse(&zero).is_none());
    }

    #[test]
    fn decodes_the_commands_an_os_issues() {
        assert_eq!(decode(&[0x00]), Command::TestUnitReady);
        assert_eq!(decode(&[0x12, 0, 0, 0, 36]), Command::Inquiry { alloc: 36 });
        assert_eq!(decode(&[0x25]), Command::ReadCapacity);
        // READ(10): LBA 0x10 big-endian, 8 blocks.
        assert_eq!(
            decode(&[0x28, 0, 0, 0, 0, 0x10, 0, 0, 8]),
            Command::Read {
                lba: 0x10,
                blocks: 8
            }
        );
        assert_eq!(
            decode(&[0x2A, 0, 0, 0, 0, 0x01, 0, 0, 2]),
            Command::Write { lba: 1, blocks: 2 }
        );
        assert_eq!(decode(&[0x1E, 0, 0, 0, 1]), Command::NoData);
        // START STOP UNIT: eject (LOEJ set) vs a plain spin request.
        assert_eq!(decode(&[0x1B, 0, 0, 0, 0x02]), Command::Eject);
        assert_eq!(decode(&[0x1B, 0, 0, 0, 0x01]), Command::NoData);
        assert_eq!(decode(&[0xF0]), Command::Unsupported);
        // A truncated READ(10) does not read past its block and is not misdecoded.
        assert_eq!(decode(&[0x28, 0, 0]), Command::Unsupported);
    }

    #[test]
    fn csw_layout() {
        let mut b = [0u8; CSW_LEN];
        csw(&mut b, 0xAABBCCDD, 4, csw_status::FAILED);
        assert_eq!(&b[0..4], &CSW_SIGNATURE.to_le_bytes());
        assert_eq!(u32::from_le_bytes([b[4], b[5], b[6], b[7]]), 0xAABBCCDD);
        assert_eq!(u32::from_le_bytes([b[8], b[9], b[10], b[11]]), 4);
        assert_eq!(b[12], csw_status::FAILED);
    }

    #[test]
    fn inquiry_is_well_formed() {
        let mut b = [0u8; 64];
        let n = inquiry(&mut b);
        assert_eq!(n, 36);
        assert_eq!(b[0], 0x00); // block device
        assert_eq!(b[1], 0x80); // removable
        assert_eq!(b[4], 31); // additional length = n - 5
    }

    #[test]
    fn read_capacity_reports_last_lba_and_512() {
        let mut b = [0u8; 8];
        assert_eq!(read_capacity(0x1_0000, &mut b), 8);
        assert_eq!(u32::from_be_bytes([b[0], b[1], b[2], b[3]]), 0xFFFF); // last = blocks-1
        assert_eq!(u32::from_be_bytes([b[4], b[5], b[6], b[7]]), 512);
    }

    #[test]
    fn mode_sense_write_protect_bit() {
        let mut b = [0u8; 4];
        mode_sense(false, &mut b);
        assert_eq!(b[2] & 0x80, 0);
        mode_sense(true, &mut b);
        assert_eq!(b[2] & 0x80, 0x80);
    }

    #[test]
    fn request_sense_carries_the_code() {
        let mut b = [0u8; 18];
        assert_eq!(request_sense(Sense::INVALID_COMMAND, &mut b), 18);
        assert_eq!(b[0], 0x70);
        assert_eq!(b[2] & 0x0F, 0x05);
        assert_eq!(b[12], 0x20);
        assert_eq!(b[7], 10);
    }

    #[test]
    fn configuration_length_matches_header() {
        // The header's wTotalLength must equal the table it heads, or the host binds
        // nothing.
        let total = u16::from_le_bytes([CONFIGURATION[2], CONFIGURATION[3]]);
        assert_eq!(total as usize, CONFIGURATION.len());
        assert_eq!(total, CONFIG_TOTAL);
    }
}
