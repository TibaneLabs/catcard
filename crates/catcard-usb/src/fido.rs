//! The FIDO security-key interface the device can add beside the wallet's: descriptors.
//!
//! **Off by default, and a separate enumeration when it is on**, exactly like the
//! keyboard ([`crate::kbd`]): the wallet's vendor interface stays interface 0 with its
//! endpoints, the keyboard (when it is on) stays interface 1, and the security key comes
//! after them -- interface 1 alone, interface 2 beside the keyboard. Interfaces are
//! numbered without gaps (USB 2.0 §9.6.5 "zero-based value identifying the index in the
//! array of concurrent interfaces" [C]), which is why its number moves and the others'
//! never do.
//!
//! A browser finds a security key by its HID usage page, `0xF1D0` (FIDO Alliance), usage
//! `0x01` (CTAPHID), with one 64-byte input and one 64-byte output report on interrupt
//! endpoints of their own. Source: CTAP 2.1 §11.2.8.1 "HID Report Descriptor and Device
//! Discovery", §11.2.2 [C]
//!
//! The protocol that runs over it is `catcard-fido`'s; this module only describes the
//! interface to the host.

use crate::descriptor::{self, kind};

/// The security key's endpoints. `0x81`/`0x01` stay the wallet's and `0x82` the
/// keyboard's. OTG_FS has endpoints 0..5 in each direction.
/// Source: RM0432 §USB OTG_FS "6 bidirectional endpoints" [C]
pub const EP_IN: u8 = 0x83;
pub const EP_OUT: u8 = 0x03;

/// CTAPHID reports are 64 bytes both ways, with no report ID. Source: CTAP 2.1 §11.2.2 [C]
pub const REPORT_LEN: usize = 64;

/// Polling interval asked for, in milliseconds. A CTAP transaction is a handful of
/// reports; 5 ms keeps a registration well under a second on the wire. [I]
pub const INTERVAL_MS: u8 = 5;

/// The CTAPHID report descriptor, as CTAP 2.1 §11.2.8.1 gives it: FIDO usage page,
/// CTAPHID usage, and a 64-byte input (usage 0x20) and output (usage 0x21) report. The
/// report size and count are spelled out for both rather than left to the global items,
/// because this is the byte sequence host parsers are tested against.
pub const REPORT_DESCRIPTOR: [u8; 34] = [
    0x06,
    0xD0,
    0xF1, // Usage Page (FIDO Alliance, 0xF1D0)
    0x09,
    0x01, // Usage (CTAPHID)
    0xA1,
    0x01, // Collection (Application)
    0x09,
    0x20, //   Usage (Input Report Data)
    0x15,
    0x00, //   Logical Minimum (0)
    0x26,
    0xFF,
    0x00, //   Logical Maximum (255)
    0x75,
    0x08, //   Report Size (8)
    0x95,
    REPORT_LEN as u8, //   Report Count (64)
    0x81,
    0x02, //   Input (Data, Var, Abs)
    0x09,
    0x21, //   Usage (Output Report Data)
    0x15,
    0x00, //   Logical Minimum (0)
    0x26,
    0xFF,
    0x00, //   Logical Maximum (255)
    0x75,
    0x08, //   Report Size (8)
    0x95,
    REPORT_LEN as u8, //   Report Count (64)
    0x91,
    0x02, //   Output (Data, Var, Abs)
    0xC0, // End Collection
];

/// Bytes of the security key's block: interface, HID, two endpoints.
pub const BLOCK_LEN: usize = 9 + 9 + 7 + 7;

/// The interface block for interface number `number`.
const fn block(number: u8) -> [u8; BLOCK_LEN] {
    [
        // --- interface ---
        9,
        kind::INTERFACE,
        number,
        0,    // bAlternateSetting
        2,    // bNumEndpoints
        0x03, // bInterfaceClass: HID
        0x00, // bInterfaceSubClass: none
        0x00, // bInterfaceProtocol: none
        0,    // iInterface
        // --- HID ---
        9,
        kind::HID,
        0x11,
        0x01, // bcdHID 1.11
        0x00, // bCountryCode
        1,    // bNumDescriptors
        kind::HID_REPORT,
        REPORT_DESCRIPTOR.len() as u8,
        (REPORT_DESCRIPTOR.len() >> 8) as u8,
        // --- endpoint IN ---
        7,
        kind::ENDPOINT,
        EP_IN,
        0x03, // interrupt
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
    ]
}

/// `base` (a whole configuration) with the security key's block appended as interface
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

/// Wallet (interface 0) and security key (interface 1).
pub const CONFIGURATION: [u8; WALLET_LEN + BLOCK_LEN] = with_block(&descriptor::CONFIGURATION, 1);

/// Wallet (0), keyboard (1) and security key (2).
pub const CONFIGURATION_WITH_KBD: [u8; KBD_LEN + BLOCK_LEN] =
    with_block(&crate::kbd::CONFIGURATION, 2);

/// Where the security key's HID descriptor sits in each table, for answering a host that
/// asks for it on its own.
pub mod at {
    pub const HID: usize = super::WALLET_LEN + 9;
    pub const HID_WITH_KBD: usize = super::KBD_LEN + 9;
}

#[cfg(test)]
mod tests {
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
    fn both_composites_walk_cleanly_and_keep_the_earlier_interfaces_byte_for_byte() {
        let (c, i, h, e) = (
            kind::CONFIGURATION,
            kind::INTERFACE,
            kind::HID,
            kind::ENDPOINT,
        );
        assert_eq!(walk(&CONFIGURATION), vec![c, i, h, e, e, i, h, e, e]);
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
        assert_eq!(CONFIGURATION_WITH_KBD[KBD_LEN + 2], 2, "interface 2");
    }

    #[test]
    fn the_interface_is_ctaphid_with_two_64_byte_interrupt_endpoints_of_its_own() {
        for (c, hid) in [
            (&CONFIGURATION[..], at::HID),
            (&CONFIGURATION_WITH_KBD[..], at::HID_WITH_KBD),
        ] {
            assert_eq!(c[hid + 1], kind::HID);
            let stated = u16::from_le_bytes([c[hid + 7], c[hid + 8]]);
            assert_eq!(stated as usize, REPORT_DESCRIPTOR.len());
            let (i, o) = (hid + 9, hid + 16);
            assert_eq!((c[i + 2], c[i + 3]), (EP_IN, 0x03));
            assert_eq!((c[o + 2], c[o + 3]), (EP_OUT, 0x03));
            assert_eq!(u16::from_le_bytes([c[i + 4], c[i + 5]]) as usize, 64);
            assert_eq!(u16::from_le_bytes([c[o + 4], c[o + 5]]) as usize, 64);
        }
        for ep in [descriptor::EP_IN, descriptor::EP_OUT, crate::kbd::EP_IN] {
            assert_ne!(ep & 0x0F, EP_IN & 0x0F, "must not share an endpoint number");
        }
    }

    #[test]
    fn the_report_descriptor_is_the_fido_usage_page_and_ctaphid_usage() {
        // A browser matches on exactly these: page 0xF1D0, usage 1.
        assert_eq!(&REPORT_DESCRIPTOR[..5], &[0x06, 0xD0, 0xF1, 0x09, 0x01]);
        assert_eq!(*REPORT_DESCRIPTOR.last().unwrap(), 0xC0);
        let counts: Vec<u8> = REPORT_DESCRIPTOR
            .windows(2)
            .filter(|w| w[0] == 0x95)
            .map(|w| w[1])
            .collect();
        assert_eq!(counts, vec![64, 64]);
    }
}
