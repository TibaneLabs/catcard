//! The USB descriptors this device answers enumeration with.
//!
//! Built as `const` byte tables rather than assembled at runtime: they never vary, and a
//! descriptor whose `bLength` disagrees with its contents is a class of bug that shows
//! up as a device the host silently refuses to bind, with no error anywhere. The tests
//! walk them the way a host does and check every length against what is actually there.

use catcard_board::{PRODUCT_ID, VENDOR_ID};

use crate::REPORT_LEN;

/// Descriptor type codes. Source: USB 2.0 §9.4, HID 1.11 §7.1.
pub mod kind {
    pub const DEVICE: u8 = 0x01;
    pub const CONFIGURATION: u8 = 0x02;
    pub const STRING: u8 = 0x03;
    pub const INTERFACE: u8 = 0x04;
    pub const ENDPOINT: u8 = 0x05;
    pub const HID: u8 = 0x21;
    pub const HID_REPORT: u8 = 0x22;
}

/// Endpoint addresses. IN is device-to-host, so its top bit is set.
pub const EP_IN: u8 = 0x81;
pub const EP_OUT: u8 = 0x01;

/// Polling interval in milliseconds. 1 ms is the fastest a full-speed interrupt endpoint
/// is allowed, and it is what sets the transfer rate: 64 bytes per frame is 64 KB/s.
pub const INTERVAL_MS: u8 = 1;

/// String descriptor indices.
pub mod string {
    pub const LANGID: u8 = 0;
    pub const MANUFACTURER: u8 = 1;
    pub const PRODUCT: u8 = 2;
    pub const SERIAL: u8 = 3;
}

/// `bcdUSB 2.00`, one configuration, class defined at the interface.
pub const DEVICE: [u8; 18] = [
    18,           // bLength
    kind::DEVICE, // bDescriptorType
    0x00,
    0x02, // bcdUSB 2.00
    0x00, // bDeviceClass -- per interface, so the HID class lives on the interface
    0x00, // bDeviceSubClass
    0x00, // bDeviceProtocol
    64,   // bMaxPacketSize0
    VENDOR_ID as u8,
    (VENDOR_ID >> 8) as u8,
    PRODUCT_ID as u8,
    (PRODUCT_ID >> 8) as u8,
    0x01,
    0x00,                 // bcdDevice 0.01
    string::MANUFACTURER, // iManufacturer
    string::PRODUCT,      // iProduct
    string::SERIAL,       // iSerialNumber
    1,                    // bNumConfigurations
];

/// Total length of [`CONFIGURATION`], which its own header has to state.
pub const CONFIG_TOTAL: u16 = 9 + 9 + 9 + 7 + 7;

/// Configuration, interface, HID and both endpoint descriptors, concatenated as a host
/// reads them in one `GET_DESCRIPTOR(CONFIGURATION)`.
pub const CONFIGURATION: [u8; CONFIG_TOTAL as usize] = [
    // --- configuration ---
    9,
    kind::CONFIGURATION,
    CONFIG_TOTAL as u8,
    (CONFIG_TOTAL >> 8) as u8,
    1,    // bNumInterfaces
    1,    // bConfigurationValue
    0,    // iConfiguration
    0x80, // bmAttributes: bus powered, no remote wakeup
    50,   // bMaxPower: 100 mA
    // --- interface ---
    9,
    kind::INTERFACE,
    0,    // bInterfaceNumber
    0,    // bAlternateSetting
    2,    // bNumEndpoints
    0x03, // bInterfaceClass: HID
    0x00, // bInterfaceSubClass: none -- not a boot keyboard or mouse
    0x00, // bInterfaceProtocol: none
    0,    // iInterface
    // --- HID ---
    9,
    kind::HID,
    0x11,
    0x01, // bcdHID 1.11
    0x00, // bCountryCode: not localised
    1,    // bNumDescriptors
    kind::HID_REPORT,
    REPORT_DESCRIPTOR.len() as u8,
    (REPORT_DESCRIPTOR.len() >> 8) as u8,
    // --- endpoint IN ---
    7,
    kind::ENDPOINT,
    EP_IN,
    0x03, // bmAttributes: interrupt
    REPORT_LEN as u8,
    0,
    INTERVAL_MS,
    // --- endpoint OUT ---
    7,
    kind::ENDPOINT,
    EP_OUT,
    0x03,
    REPORT_LEN as u8,
    0,
    INTERVAL_MS,
];

/// One vendor-defined 64-byte report in each direction.
///
/// Vendor-defined on purpose: a usage page in the vendor range (`0xFF00`) is what keeps
/// the OS from claiming the device as a keyboard or a mouse, and on macOS and Windows it
/// is what makes the device reachable at all without a driver.
pub const REPORT_DESCRIPTOR: [u8; 25] = [
    0x06,
    0x00,
    0xFF, // Usage Page (Vendor Defined 0xFF00)
    0x09,
    0x01, // Usage (1)
    0xA1,
    0x01, // Collection (Application)
    0x09,
    0x20, //   Usage (0x20) -- host to device
    0x15,
    0x00, //   Logical Minimum (0)
    0x26,
    0xFF,
    0x00, //   Logical Maximum (255)
    0x75,
    0x08, //   Report Size (8 bits)
    0x95,
    REPORT_LEN as u8, //   Report Count (64)
    0x81,
    0x02, //   Input (Data, Var, Abs)
    0x09,
    0x21, //   Usage (0x21) -- device to host
    // Report Size and Report Count are global items and still in force, so the output
    // report is the same 64 bytes without repeating them.
    0x91,
    0x02, //   Output (Data, Var, Abs)
    0xC0, // End Collection
];

/// `LANGID` list: US English only.
pub const LANGIDS: [u8; 4] = [4, kind::STRING, 0x09, 0x04];

pub const MANUFACTURER: &str = "Karpeles Lab";
pub const PRODUCT: &str = "CatCard";

/// Encode `s` as a USB string descriptor into `out`, returning the bytes written.
///
/// USB strings are UTF-16LE with a two-byte header. Only ASCII is emitted — everything
/// this device names itself is ASCII, and a non-ASCII character would need surrogate
/// handling for no benefit — so anything else is replaced rather than truncating the
/// descriptor to a length that disagrees with its header.
pub fn string_descriptor(s: &str, out: &mut [u8]) -> Option<usize> {
    let n = s.chars().count();
    let len = 2 + n * 2;
    if len > 255 || len > out.len() {
        return None;
    }
    out[0] = len as u8;
    out[1] = kind::STRING;
    for (i, c) in s.chars().enumerate() {
        let u = if c.is_ascii() {
            c as u16
        } else {
            u16::from(b'?')
        };
        out[2 + i * 2..4 + i * 2].copy_from_slice(&u.to_le_bytes());
    }
    Some(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_device_descriptor_carries_our_allocated_identity() {
        // The one thing here that is externally meaningful: 0x39F2 is allocated to us.
        assert_eq!(u16::from_le_bytes([DEVICE[8], DEVICE[9]]), 0x39F2);
        assert_eq!(u16::from_le_bytes([DEVICE[10], DEVICE[11]]), 0x0401);
        assert_eq!(DEVICE[0] as usize, DEVICE.len());
        assert_eq!(DEVICE[1], kind::DEVICE);
    }

    #[test]
    fn every_descriptor_states_its_own_length() {
        // Walk the configuration the way a host does: each descriptor's first byte says
        // how far the next one starts. If any bLength is wrong the walk desynchronises,
        // which on a real host is a device that enumerates and then does nothing.
        assert_eq!(CONFIGURATION[0] as usize, 9);
        assert_eq!(
            u16::from_le_bytes([CONFIGURATION[2], CONFIGURATION[3]]) as usize,
            CONFIGURATION.len(),
            "wTotalLength does not match the bytes that follow"
        );

        let mut at = 0;
        let mut seen = Vec::new();
        while at < CONFIGURATION.len() {
            let len = CONFIGURATION[at] as usize;
            assert!(len >= 2, "zero-length descriptor at {at}");
            assert!(
                at + len <= CONFIGURATION.len(),
                "descriptor at {at} overruns"
            );
            seen.push(CONFIGURATION[at + 1]);
            at += len;
        }
        assert_eq!(at, CONFIGURATION.len(), "the walk did not land on the end");
        assert_eq!(
            seen,
            vec![
                kind::CONFIGURATION,
                kind::INTERFACE,
                kind::HID,
                kind::ENDPOINT,
                kind::ENDPOINT
            ]
        );
    }

    #[test]
    fn the_hid_descriptor_reports_the_report_descriptors_real_length() {
        // A host asks for exactly this many bytes. Too few and it parses a truncated
        // descriptor; too many and the request stalls.
        let at = 9 + 9;
        assert_eq!(CONFIGURATION[at + 1], kind::HID);
        let stated = u16::from_le_bytes([CONFIGURATION[at + 7], CONFIGURATION[at + 8]]);
        assert_eq!(stated as usize, REPORT_DESCRIPTOR.len());
    }

    #[test]
    fn both_endpoints_are_interrupt_and_report_sized() {
        for at in [9 + 9 + 9, 9 + 9 + 9 + 7] {
            assert_eq!(CONFIGURATION[at], 7);
            assert_eq!(CONFIGURATION[at + 1], kind::ENDPOINT);
            assert_eq!(CONFIGURATION[at + 3], 0x03, "not an interrupt endpoint");
            let size = u16::from_le_bytes([CONFIGURATION[at + 4], CONFIGURATION[at + 5]]);
            assert_eq!(size as usize, REPORT_LEN);
            assert_eq!(CONFIGURATION[at + 6], INTERVAL_MS);
        }
        // One in each direction, and they are the ones the driver will enable.
        assert_eq!(CONFIGURATION[9 + 9 + 9 + 2], EP_IN);
        assert_eq!(CONFIGURATION[9 + 9 + 9 + 7 + 2], EP_OUT);
        assert_eq!(EP_IN & 0x80, 0x80, "IN must be device-to-host");
        assert_eq!(EP_OUT & 0x80, 0x00, "OUT must be host-to-device");
    }

    #[test]
    fn the_report_descriptor_is_vendor_defined_and_64_bytes_each_way() {
        // Vendor usage page keeps the OS from claiming this as a keyboard. If it ever
        // became a generic desktop usage, the device would start typing into the
        // foreground window.
        assert_eq!(&REPORT_DESCRIPTOR[..3], &[0x06, 0x00, 0xFF]);
        let counts: Vec<u8> = REPORT_DESCRIPTOR
            .windows(2)
            .filter(|w| w[0] == 0x95)
            .map(|w| w[1])
            .collect();
        assert!(!counts.is_empty(), "no Report Count item");
        assert!(counts.iter().all(|&c| c as usize == REPORT_LEN));
        assert_eq!(
            *REPORT_DESCRIPTOR.last().unwrap(),
            0xC0,
            "unclosed collection"
        );
    }

    #[test]
    fn strings_encode_as_utf16le_with_a_matching_length() {
        let mut buf = [0u8; 64];
        let n = string_descriptor("CatCard", &mut buf).unwrap();
        assert_eq!(n, 2 + 7 * 2);
        assert_eq!(buf[0] as usize, n);
        assert_eq!(buf[1], kind::STRING);
        assert_eq!(&buf[2..6], &[b'C', 0, b'a', 0]);
    }

    #[test]
    fn a_string_that_does_not_fit_is_refused_rather_than_truncated() {
        // A descriptor whose header says one length and whose body is another is worse
        // than no descriptor: the host reads past the end of it.
        let mut small = [0u8; 8];
        assert_eq!(string_descriptor("CatCard", &mut small), None);
    }

    #[test]
    fn the_langid_descriptor_is_well_formed() {
        assert_eq!(LANGIDS[0] as usize, LANGIDS.len());
        assert_eq!(LANGIDS[1], kind::STRING);
    }
}
