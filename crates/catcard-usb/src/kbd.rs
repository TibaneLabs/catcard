//! The USB keyboard the device can pretend to be: descriptors, keycodes and reports.
//!
//! **Off by default, and a separate enumeration when it is on.** A keyboard interface is
//! the one class of USB device that acts on the host without being asked -- whatever it
//! sends lands in the focused window -- so it exists on the bus only while the owner has
//! switched `Keyboard EMU` on, and the host is made to re-enumerate when that changes
//! (the descriptor set is fixed for the life of an enumeration). While it is on, the
//! device is a *composite*: the wallet's own vendor HID interface stays interface 0 with
//! the endpoints it has always had, so every host tool that speaks to it is unaffected,
//! and the keyboard is interface 1 with an IN endpoint of its own.
//!
//! A *boot-protocol* keyboard, because that is the one report shape every host already
//! understands without reading the report descriptor: 8 bytes, a modifier bitmap, a
//! reserved byte and up to six keycodes (HID 1.11 Appendix B.1). Sending a report with a
//! key in it presses it; sending an empty one releases it.
//!
//! Only the *portable* part is here -- tables and byte layouts, tested on the host.
//! Which endpoint register to write is the HAL's, and when to send what is the
//! firmware's (`usbkbd`).
//!
//! Source: USB HID 1.11 §7.2 (class requests), Appendix B.1 (boot keyboard report),
//! Appendix E.6 (report descriptor); USB HID Usage Tables 1.12 §10 (Keyboard/Keypad
//! page, `0x07`) for every keycode below. [C]

use crate::descriptor::{self, kind};

/// The keyboard's interrupt IN endpoint. `0x81`/`0x01` stay the wallet's.
pub const EP_IN: u8 = 0x82;

/// Interface number of the keyboard in the composite configuration. The wallet's vendor
/// interface keeps number 0.
pub const INTERFACE: u8 = 1;

/// A boot-protocol keyboard input report: modifiers, reserved, six keycodes.
/// Source: HID 1.11 Appendix B.1 [C]
pub const REPORT_LEN: usize = 8;

/// Polling interval the host is asked for, in milliseconds. Eight is what most real
/// keyboards advertise; the firmware paces itself more slowly than this anyway, so the
/// host always has a chance to take one report before the next is offered.
pub const INTERVAL_MS: u8 = 8;

/// Modifier bits, byte 0 of the report. Source: HID 1.11 §8.3 [C]
pub mod modifier {
    pub const LEFT_CTRL: u8 = 1 << 0;
    pub const LEFT_SHIFT: u8 = 1 << 1;
    pub const LEFT_ALT: u8 = 1 << 2;
    pub const LEFT_GUI: u8 = 1 << 3;
    pub const RIGHT_CTRL: u8 = 1 << 4;
    pub const RIGHT_SHIFT: u8 = 1 << 5;
    pub const RIGHT_ALT: u8 = 1 << 6;
    pub const RIGHT_GUI: u8 = 1 << 7;
}

/// The keycodes this module can emit that are not letters or digits.
/// Source: USB HID Usage Tables 1.12 §10, Keyboard/Keypad page [C]
pub mod key {
    pub const ENTER: u8 = 0x28;
    pub const TAB: u8 = 0x2B;
    pub const SPACE: u8 = 0x2C;
    pub const MINUS: u8 = 0x2D;
    pub const EQUAL: u8 = 0x2E;
    pub const LEFT_BRACKET: u8 = 0x2F;
    pub const RIGHT_BRACKET: u8 = 0x30;
    pub const BACKSLASH: u8 = 0x31;
    pub const SEMICOLON: u8 = 0x33;
    pub const QUOTE: u8 = 0x34;
    pub const GRAVE: u8 = 0x35;
    pub const COMMA: u8 = 0x36;
    pub const PERIOD: u8 = 0x37;
    pub const SLASH: u8 = 0x38;
}

/// One keystroke: the modifier byte and the keycode to put in the report.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct Stroke {
    pub modifiers: u8,
    pub code: u8,
}

/// The keystroke that types `c` on a host set to the **US** layout, or `None` if there
/// is no such key.
///
/// US only, and said out loud rather than approximated: a host set to another layout
/// will type something else for the shifted symbols (a German host turns `y` into `z`,
/// a French one turns `a` into `q`), and there is no way for the device to know. The
/// letters, digits, space and Enter agree across the common layouts; the symbols are
/// the risk, and the caller decides whether to take it.
///
/// Every printable ASCII character has a key; control characters, DEL and anything
/// beyond ASCII have none. `\n` is Enter and `\t` is Tab, because a caller typing a line
/// of text means them as keys; `\r` is refused, because a host that receives Enter twice
/// for `\r\n` has been told something the caller did not say.
///
/// Source: USB HID Usage Tables 1.12 §10 [C]; the shift pairs are the US ANSI keycap
/// legends.
pub const fn keycode(c: char) -> Option<Stroke> {
    Some(match c {
        // 0x04..=0x1D: `a`..`z`, in order.
        'a'..='z' => plain(0x04 + (c as u8 - b'a')),
        'A'..='Z' => shifted(0x04 + (c as u8 - b'A')),
        // 0x1E..=0x27: `1`..`9` then `0` -- zero is *last* on this page, not first.
        '1'..='9' => plain(0x1E + (c as u8 - b'1')),
        '0' => plain(0x27),
        '!' => shifted(0x1E),
        '@' => shifted(0x1F),
        '#' => shifted(0x20),
        '$' => shifted(0x21),
        '%' => shifted(0x22),
        '^' => shifted(0x23),
        '&' => shifted(0x24),
        '*' => shifted(0x25),
        '(' => shifted(0x26),
        ')' => shifted(0x27),
        '\n' => plain(key::ENTER),
        '\t' => plain(key::TAB),
        ' ' => plain(key::SPACE),
        '-' => plain(key::MINUS),
        '_' => shifted(key::MINUS),
        '=' => plain(key::EQUAL),
        '+' => shifted(key::EQUAL),
        '[' => plain(key::LEFT_BRACKET),
        '{' => shifted(key::LEFT_BRACKET),
        ']' => plain(key::RIGHT_BRACKET),
        '}' => shifted(key::RIGHT_BRACKET),
        '\\' => plain(key::BACKSLASH),
        '|' => shifted(key::BACKSLASH),
        ';' => plain(key::SEMICOLON),
        ':' => shifted(key::SEMICOLON),
        '\'' => plain(key::QUOTE),
        '"' => shifted(key::QUOTE),
        '`' => plain(key::GRAVE),
        '~' => shifted(key::GRAVE),
        ',' => plain(key::COMMA),
        '<' => shifted(key::COMMA),
        '.' => plain(key::PERIOD),
        '>' => shifted(key::PERIOD),
        '/' => plain(key::SLASH),
        '?' => shifted(key::SLASH),
        _ => return None,
    })
}

const fn plain(code: u8) -> Stroke {
    Stroke { modifiers: 0, code }
}

const fn shifted(code: u8) -> Stroke {
    Stroke {
        modifiers: modifier::LEFT_SHIFT,
        code,
    }
}

/// Whether every character of `text` has a key, so a caller can refuse a string whole
/// rather than typing half of it into the host before finding out.
pub fn typeable(text: &str) -> Result<(), char> {
    match text.chars().find(|&c| keycode(c).is_none()) {
        Some(c) => Err(c),
        None => Ok(()),
    }
}

/// A boot-protocol input report, as the bytes that go on the wire.
///
/// `[modifiers, 0, key0, key1, key2, key3, key4, key5]`. The firmware only ever presses
/// one key at a time -- a password is typed, not chorded -- so [`press`](Self::press)
/// fills `key0` and leaves the rest zero, and [`RELEASE`](Self::RELEASE) is all zeros.
/// Source: HID 1.11 Appendix B.1 [C]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Report(pub [u8; REPORT_LEN]);

impl Report {
    /// No key down. Sent after every press: a host that never sees the release holds the
    /// key and auto-repeats it.
    pub const RELEASE: Report = Report([0; REPORT_LEN]);

    /// One key down, with its modifiers.
    pub const fn press(s: Stroke) -> Report {
        Report([s.modifiers, 0, s.code, 0, 0, 0, 0, 0])
    }

    pub const fn as_bytes(&self) -> &[u8; REPORT_LEN] {
        &self.0
    }
}

/// The boot keyboard report descriptor, as HID 1.11 Appendix E.6 gives it.
///
/// Byte for byte the canonical one, because that is the descriptor every host's HID
/// parser has been tested against. The LED output report is included for the same
/// reason -- a host sets Num Lock on bind and expects somewhere to put it -- and the
/// device acknowledges it and does nothing, since it has no lights to light.
pub const REPORT_DESCRIPTOR: [u8; 63] = [
    0x05, 0x01, // Usage Page (Generic Desktop)
    0x09, 0x06, // Usage (Keyboard)
    0xA1, 0x01, // Collection (Application)
    0x05, 0x07, //   Usage Page (Keyboard/Keypad)
    0x19, 0xE0, //   Usage Minimum (Left Control, 0xE0)
    0x29, 0xE7, //   Usage Maximum (Right GUI, 0xE7)
    0x15, 0x00, //   Logical Minimum (0)
    0x25, 0x01, //   Logical Maximum (1)
    0x75, 0x01, //   Report Size (1)
    0x95, 0x08, //   Report Count (8)
    0x81, 0x02, //   Input (Data, Var, Abs)      -- the modifier byte
    0x95, 0x01, //   Report Count (1)
    0x75, 0x08, //   Report Size (8)
    0x81, 0x01, //   Input (Const)               -- the reserved byte
    0x95, 0x05, //   Report Count (5)
    0x75, 0x01, //   Report Size (1)
    0x05, 0x08, //   Usage Page (LEDs)
    0x19, 0x01, //   Usage Minimum (Num Lock)
    0x29, 0x05, //   Usage Maximum (Kana)
    0x91, 0x02, //   Output (Data, Var, Abs)     -- the LED report
    0x95, 0x01, //   Report Count (1)
    0x75, 0x03, //   Report Size (3)
    0x91, 0x01, //   Output (Const)              -- LED padding
    0x95, 0x06, //   Report Count (6)
    0x75, 0x08, //   Report Size (8)
    0x15, 0x00, //   Logical Minimum (0)
    0x25, 0x65, //   Logical Maximum (101)
    0x05, 0x07, //   Usage Page (Keyboard/Keypad)
    0x19, 0x00, //   Usage Minimum (0)
    0x29, 0x65, //   Usage Maximum (101)
    0x81, 0x00, //   Input (Data, Array)         -- the six keycodes
    0xC0, // End Collection
];

/// Where each block sits inside [`CONFIGURATION`].
///
/// Spelled out because [`crate::control`] hands the host slices of this table by offset
/// -- the HID descriptor of either interface on request -- and an offset that drifted
/// from the table would answer with the wrong nine bytes and no error anywhere.
pub mod at {
    /// The wallet's vendor interface: identical bytes to the single-interface table, at
    /// the same offset, so a host reading either sees the same interface 0.
    pub const VENDOR_INTERFACE: usize = 9;
    pub const VENDOR_HID: usize = VENDOR_INTERFACE + 9;
    pub const KBD_INTERFACE: usize = VENDOR_INTERFACE + 9 + 9 + 7 + 7;
    pub const KBD_HID: usize = KBD_INTERFACE + 9;
    pub const KBD_ENDPOINT: usize = KBD_HID + 9;
}

/// Total length of [`CONFIGURATION`]: the vendor interface with its HID and two
/// endpoint descriptors, then the keyboard interface with its HID and one endpoint.
pub const CONFIG_TOTAL: u16 = (at::KBD_ENDPOINT + 7) as u16;

/// The composite configuration: the wallet's HID interface exactly as
/// [`descriptor::CONFIGURATION`] describes it, then the keyboard.
///
/// The 32 bytes of interface 0 after the configuration header are *copied* from the
/// single-interface table rather than restated, and a test checks they still match: the
/// promise to host tools is that interface 0 does not change when the keyboard appears.
pub const CONFIGURATION: [u8; CONFIG_TOTAL as usize] = {
    let mut c = [0u8; CONFIG_TOTAL as usize];
    // --- configuration ---
    c[0] = 9;
    c[1] = kind::CONFIGURATION;
    c[2] = CONFIG_TOTAL as u8;
    c[3] = (CONFIG_TOTAL >> 8) as u8;
    c[4] = 2; // bNumInterfaces
    c[5] = 1; // bConfigurationValue
    c[6] = 0; // iConfiguration
    c[7] = 0x80; // bus powered, no remote wakeup
    c[8] = 50; // 100 mA
    // --- interface 0: the wallet, byte for byte ---
    let mut i = at::VENDOR_INTERFACE;
    while i < at::KBD_INTERFACE {
        c[i] = descriptor::CONFIGURATION[i];
        i += 1;
    }
    // --- interface 1: boot keyboard ---
    let k = at::KBD_INTERFACE;
    c[k] = 9;
    c[k + 1] = kind::INTERFACE;
    c[k + 2] = INTERFACE; // bInterfaceNumber
    c[k + 3] = 0; // bAlternateSetting
    c[k + 4] = 1; // bNumEndpoints: IN only; LEDs arrive on the control pipe
    c[k + 5] = 0x03; // bInterfaceClass: HID
    c[k + 6] = 0x01; // bInterfaceSubClass: boot interface
    c[k + 7] = 0x01; // bInterfaceProtocol: keyboard
    c[k + 8] = 0; // iInterface
    // --- HID ---
    let h = at::KBD_HID;
    c[h] = 9;
    c[h + 1] = kind::HID;
    c[h + 2] = 0x11;
    c[h + 3] = 0x01; // bcdHID 1.11
    c[h + 4] = 0x00; // bCountryCode: not localised (the table above is US, see `keycode`)
    c[h + 5] = 1; // bNumDescriptors
    c[h + 6] = kind::HID_REPORT;
    c[h + 7] = REPORT_DESCRIPTOR.len() as u8;
    c[h + 8] = (REPORT_DESCRIPTOR.len() >> 8) as u8;
    // --- endpoint IN ---
    let e = at::KBD_ENDPOINT;
    c[e] = 7;
    c[e + 1] = kind::ENDPOINT;
    c[e + 2] = EP_IN;
    c[e + 3] = 0x03; // interrupt
    c[e + 4] = REPORT_LEN as u8;
    c[e + 5] = 0;
    c[e + 6] = INTERVAL_MS;
    c
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_zero_is_byte_for_byte_the_wallet_it_always_was() {
        // The promise to every host tool: switching the keyboard on changes nothing
        // about the interface they open. Same number, same endpoints, same HID
        // descriptor, at the same offset.
        assert_eq!(
            &CONFIGURATION[at::VENDOR_INTERFACE..at::KBD_INTERFACE],
            &descriptor::CONFIGURATION[at::VENDOR_INTERFACE..],
        );
        assert_eq!(
            CONFIGURATION[at::VENDOR_INTERFACE + 2],
            0,
            "bInterfaceNumber"
        );
        assert_eq!(CONFIGURATION[at::VENDOR_HID + 9 + 2], descriptor::EP_IN);
        assert_eq!(
            CONFIGURATION[at::VENDOR_HID + 9 + 7 + 2],
            descriptor::EP_OUT
        );
    }

    #[test]
    fn the_composite_configuration_walks_cleanly_and_declares_two_interfaces() {
        assert_eq!(
            u16::from_le_bytes([CONFIGURATION[2], CONFIGURATION[3]]) as usize,
            CONFIGURATION.len()
        );
        assert_eq!(CONFIGURATION[4], 2, "bNumInterfaces");
        let mut at = 0;
        let mut seen = Vec::new();
        while at < CONFIGURATION.len() {
            let len = CONFIGURATION[at] as usize;
            assert!(len >= 2 && at + len <= CONFIGURATION.len(), "at {at}");
            seen.push(CONFIGURATION[at + 1]);
            at += len;
        }
        assert_eq!(at, CONFIGURATION.len());
        assert_eq!(
            seen,
            vec![
                kind::CONFIGURATION,
                kind::INTERFACE,
                kind::HID,
                kind::ENDPOINT,
                kind::ENDPOINT,
                kind::INTERFACE,
                kind::HID,
                kind::ENDPOINT,
            ]
        );
    }

    #[test]
    fn the_keyboard_interface_is_a_boot_keyboard_with_its_own_in_endpoint() {
        let k = at::KBD_INTERFACE;
        assert_eq!(CONFIGURATION[k + 1], kind::INTERFACE);
        assert_eq!(CONFIGURATION[k + 2], INTERFACE);
        assert_eq!(
            CONFIGURATION[k + 5..k + 8],
            [0x03, 0x01, 0x01],
            "HID / boot / keyboard"
        );
        let h = at::KBD_HID;
        assert_eq!(CONFIGURATION[h + 1], kind::HID);
        let stated = u16::from_le_bytes([CONFIGURATION[h + 7], CONFIGURATION[h + 8]]);
        assert_eq!(stated as usize, REPORT_DESCRIPTOR.len());
        let e = at::KBD_ENDPOINT;
        assert_eq!(CONFIGURATION[e + 1], kind::ENDPOINT);
        assert_eq!(CONFIGURATION[e + 2], EP_IN);
        assert_ne!(
            EP_IN,
            descriptor::EP_IN,
            "must not share the wallet's endpoint"
        );
        assert_eq!(EP_IN & 0x80, 0x80, "a keyboard talks to the host");
        assert_eq!(CONFIGURATION[e + 3], 0x03, "interrupt");
        assert_eq!(
            u16::from_le_bytes([CONFIGURATION[e + 4], CONFIGURATION[e + 5]]) as usize,
            REPORT_LEN
        );
    }

    #[test]
    fn the_report_descriptor_is_generic_desktop_keyboard_and_closes_its_collection() {
        assert_eq!(
            &REPORT_DESCRIPTOR[..6],
            &[0x05, 0x01, 0x09, 0x06, 0xA1, 0x01]
        );
        assert_eq!(*REPORT_DESCRIPTOR.last().unwrap(), 0xC0);
        // Walk the short items: each is a one-byte prefix whose low two bits give the
        // data size. A miscounted byte here desynchronises every host parser.
        let mut at = 0;
        while at < REPORT_DESCRIPTOR.len() {
            let prefix = REPORT_DESCRIPTOR[at];
            let size = match prefix & 0x03 {
                3 => 4,
                n => n as usize,
            };
            at += 1 + size;
        }
        assert_eq!(at, REPORT_DESCRIPTOR.len(), "item walk overran");
        // Modifiers: 8 one-bit fields from usage 0xE0. Keys: 6 bytes, array, 0..=101.
        assert!(
            REPORT_DESCRIPTOR
                .windows(4)
                .any(|w| w == [0x19, 0xE0, 0x29, 0xE7])
        );
        assert!(
            REPORT_DESCRIPTOR
                .windows(4)
                .any(|w| w == [0x95, 0x06, 0x75, 0x08])
        );
    }

    #[test]
    fn every_printable_ascii_character_has_a_key_and_nothing_else_does() {
        for b in 0x20u8..0x7F {
            assert!(keycode(b as char).is_some(), "{:?}", b as char);
        }
        for b in (0u8..0x20).chain(0x7F..=0xFF) {
            let c = b as char;
            if c == '\n' || c == '\t' {
                assert!(keycode(c).is_some());
            } else {
                assert!(keycode(c).is_none(), "{c:?} should have no key");
            }
        }
        assert!(keycode('é').is_none());
        assert!(keycode('€').is_none());
        assert!(keycode('\r').is_none(), "CR would double an Enter");
    }

    #[test]
    fn letters_and_digits_follow_the_usage_table_and_case_is_only_shift() {
        // Usage Tables 1.12 §10: `a` = 0x04 .. `z` = 0x1D; `1` = 0x1E .. `9` = 0x26,
        // `0` = 0x27. Zero comes last, which is the mistake a naive table makes.
        assert_eq!(
            keycode('a'),
            Some(Stroke {
                modifiers: 0,
                code: 0x04
            })
        );
        assert_eq!(
            keycode('z'),
            Some(Stroke {
                modifiers: 0,
                code: 0x1D
            })
        );
        assert_eq!(keycode('1').unwrap().code, 0x1E);
        assert_eq!(keycode('9').unwrap().code, 0x26);
        assert_eq!(keycode('0').unwrap().code, 0x27);
        for (lower, upper) in ('a'..='z').zip('A'..='Z') {
            let l = keycode(lower).unwrap();
            let u = keycode(upper).unwrap();
            assert_eq!(l.code, u.code, "{lower}/{upper}");
            assert_eq!(l.modifiers, 0);
            assert_eq!(u.modifiers, modifier::LEFT_SHIFT);
        }
        for d in '0'..='9' {
            assert_eq!(keycode(d).unwrap().modifiers, 0);
        }
    }

    #[test]
    fn shifted_symbols_share_the_key_of_their_unshifted_legend() {
        // The US ANSI keycaps, pair by pair. A password with a `#` in it is typed as
        // shift-3, and on a US host that is a `#`.
        for (plain, shifted) in [
            ('1', '!'),
            ('2', '@'),
            ('3', '#'),
            ('4', '$'),
            ('5', '%'),
            ('6', '^'),
            ('7', '&'),
            ('8', '*'),
            ('9', '('),
            ('0', ')'),
            ('-', '_'),
            ('=', '+'),
            ('[', '{'),
            (']', '}'),
            ('\\', '|'),
            (';', ':'),
            ('\'', '"'),
            ('`', '~'),
            (',', '<'),
            ('.', '>'),
            ('/', '?'),
        ] {
            let p = keycode(plain).unwrap();
            let s = keycode(shifted).unwrap();
            assert_eq!(p.code, s.code, "{plain}/{shifted}");
            assert_eq!(p.modifiers, 0, "{plain}");
            assert_eq!(s.modifiers, modifier::LEFT_SHIFT, "{shifted}");
        }
        assert_eq!(keycode(' ').unwrap().code, key::SPACE);
        assert_eq!(keycode('\n').unwrap().code, key::ENTER);
        assert_eq!(keycode('\t').unwrap().code, key::TAB);
    }

    #[test]
    fn no_two_characters_map_to_the_same_stroke() {
        // A collision would type the wrong character silently -- the worst failure a
        // password typist can have.
        let mut seen = std::collections::HashMap::new();
        for b in 0u8..=0x7F {
            let c = b as char;
            if let Some(s) = keycode(c)
                && let Some(prev) = seen.insert(s, c)
            {
                panic!("{prev:?} and {c:?} both map to {s:?}");
            }
        }
    }

    #[test]
    fn reports_are_eight_bytes_with_the_key_in_slot_zero() {
        let r = Report::press(keycode('A').unwrap());
        assert_eq!(
            r.as_bytes(),
            &[modifier::LEFT_SHIFT, 0, 0x04, 0, 0, 0, 0, 0]
        );
        let r = Report::press(keycode('7').unwrap());
        assert_eq!(r.as_bytes(), &[0, 0, 0x24, 0, 0, 0, 0, 0]);
        assert_eq!(Report::RELEASE.as_bytes(), &[0; REPORT_LEN]);
        assert_eq!(REPORT_LEN, 8);
    }

    #[test]
    fn typeable_names_the_first_character_it_cannot_type() {
        assert_eq!(typeable("catcard keyboard ok"), Ok(()));
        assert_eq!(typeable("Tr0ub4dor&3"), Ok(()));
        assert_eq!(typeable("caf\u{e9} au lait"), Err('\u{e9}'));
        assert_eq!(typeable("a\rb"), Err('\r'));
        assert_eq!(typeable(""), Ok(()));
    }
}
