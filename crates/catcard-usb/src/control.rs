//! Endpoint-zero control transfers: what to answer, and when.
//!
//! Deciding how to answer a `SETUP` packet is pure logic, so it lives here and is tested
//! on the host. Only moving bytes through a FIFO needs a device, and that is the HAL's.
//!
//! The split matters more than it looks. Enumeration failures are close to
//! undiagnosable on hardware — the host gives up and unbinds, and nothing on the device
//! is told why — so the value of being able to ask "what would we reply to *this*
//! packet?" at a desk is hard to overstate.
//!
//! Source: USB 2.0 §9.3–9.4 (standard requests), HID 1.11 §7.2 (class requests).

use crate::descriptor::{self, kind};

/// The eight bytes of a `SETUP` packet.
///
/// Field names are USB 2.0's, in its own casing, because every reference a reader will
/// check against uses them.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[allow(non_snake_case)]
pub struct Setup {
    pub bmRequestType: u8,
    pub bRequest: u8,
    pub wValue: u16,
    pub wIndex: u16,
    pub wLength: u16,
}

impl Setup {
    pub const LEN: usize = 8;

    pub fn from_bytes(b: &[u8; Self::LEN]) -> Self {
        Self {
            bmRequestType: b[0],
            bRequest: b[1],
            wValue: u16::from_le_bytes([b[2], b[3]]),
            wIndex: u16::from_le_bytes([b[4], b[5]]),
            wLength: u16::from_le_bytes([b[6], b[7]]),
        }
    }

    /// True when the data stage runs device-to-host.
    pub fn is_in(&self) -> bool {
        self.bmRequestType & 0x80 != 0
    }

    /// `Standard`, `Class` or `Vendor`.
    pub fn kind(&self) -> u8 {
        (self.bmRequestType >> 5) & 0x03
    }

    /// `Device`, `Interface` or `Endpoint`.
    pub fn recipient(&self) -> u8 {
        self.bmRequestType & 0x1F
    }
}

/// Standard request codes. Source: USB 2.0 table 9-4.
pub mod request {
    pub const GET_STATUS: u8 = 0;
    pub const CLEAR_FEATURE: u8 = 1;
    pub const SET_FEATURE: u8 = 3;
    pub const SET_ADDRESS: u8 = 5;
    pub const GET_DESCRIPTOR: u8 = 6;
    pub const GET_CONFIGURATION: u8 = 8;
    pub const SET_CONFIGURATION: u8 = 9;
    pub const GET_INTERFACE: u8 = 10;
    pub const SET_INTERFACE: u8 = 11;
}

/// HID class request codes. Source: HID 1.11 §7.2.
pub mod hid_request {
    pub const GET_REPORT: u8 = 0x01;
    pub const GET_IDLE: u8 = 0x02;
    pub const SET_REPORT: u8 = 0x09;
    pub const SET_IDLE: u8 = 0x0A;
    pub const SET_PROTOCOL: u8 = 0x0B;
}

/// Request types, from `bmRequestType`.
pub mod req_kind {
    pub const STANDARD: u8 = 0;
    pub const CLASS: u8 = 1;
}

/// Recipients, from `bmRequestType`.
pub mod recipient {
    pub const DEVICE: u8 = 0;
    pub const INTERFACE: u8 = 1;
    pub const ENDPOINT: u8 = 2;
}

/// What the driver should do about a `SETUP` packet.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Action<'a> {
    /// Send these bytes as the data stage, then expect a status stage.
    ///
    /// Already truncated to `wLength`: a device that sends more than the host asked for
    /// is a babble error, and one that sends less without a short packet hangs the
    /// transfer.
    Data(&'a [u8]),
    /// No data stage; acknowledge with a zero-length packet.
    Ack,
    /// Acknowledge, then take this address once the status stage has completed.
    ///
    /// Order matters and is easy to get backwards: the status stage of `SET_ADDRESS` is
    /// still addressed to zero. Taking the new address too early makes the device
    /// disappear mid-transfer.
    AckThenAddress(u8),
    /// Refuse. The host will either recover or give up on the request.
    Stall,
}

/// Where enumeration has got to.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum Phase {
    /// Reset, no address assigned.
    #[default]
    Default,
    /// Addressed but not configured.
    Addressed,
    /// Configured: the data endpoints are live.
    Configured,
}

/// Device state that control transfers read and write.
pub struct Device {
    pub phase: Phase,
    pub address: u8,
    pub configuration: u8,
    /// HID idle rate, in 4 ms units. Stored because `GET_IDLE` must return what
    /// `SET_IDLE` was given, and nothing else here uses it.
    pub idle: u8,
    /// Serial number string, from the MCU's unique ID.
    pub serial: &'static str,
}

impl Device {
    pub const fn new(serial: &'static str) -> Self {
        Self {
            phase: Phase::Default,
            address: 0,
            configuration: 0,
            idle: 0,
            serial,
        }
    }

    /// Back to the unconfigured state, as a bus reset requires.
    pub fn reset(&mut self) {
        self.phase = Phase::Default;
        self.address = 0;
        self.configuration = 0;
    }

    pub fn is_configured(&self) -> bool {
        self.phase == Phase::Configured
    }
}

/// Decide how to answer one `SETUP` packet.
///
/// `scratch` holds any reply that has to be built rather than pointed at — string
/// descriptors and the two-byte status replies. It must be at least 64 bytes.
pub fn handle<'a>(dev: &mut Device, setup: &Setup, scratch: &'a mut [u8]) -> Action<'a> {
    match (setup.kind(), setup.recipient()) {
        (req_kind::STANDARD, _) => standard(dev, setup, scratch),
        (req_kind::CLASS, recipient::INTERFACE) => class(dev, setup, scratch),
        // Vendor requests are the WebUSB/WinUSB door, and this device does not use it.
        // Stalling is the correct answer, not silence: a host that gets no reply waits
        // out the timeout on every enumeration.
        _ => Action::Stall,
    }
}

fn standard<'a>(dev: &mut Device, setup: &Setup, scratch: &'a mut [u8]) -> Action<'a> {
    match (setup.bRequest, setup.recipient()) {
        (request::GET_DESCRIPTOR, _) => get_descriptor(dev, setup, scratch),

        (request::SET_ADDRESS, recipient::DEVICE) => {
            let addr = setup.wValue as u8;
            if addr > 127 {
                return Action::Stall;
            }
            dev.address = addr;
            dev.phase = if addr == 0 {
                Phase::Default
            } else {
                Phase::Addressed
            };
            Action::AckThenAddress(addr)
        }

        (request::SET_CONFIGURATION, recipient::DEVICE) => {
            match setup.wValue as u8 {
                // Configuration 0 means "unconfigure me", which is legal and has to
                // put the data endpoints back to sleep rather than being ignored.
                0 => {
                    dev.configuration = 0;
                    dev.phase = Phase::Addressed;
                    Action::Ack
                }
                1 => {
                    dev.configuration = 1;
                    dev.phase = Phase::Configured;
                    Action::Ack
                }
                _ => Action::Stall,
            }
        }

        (request::GET_CONFIGURATION, recipient::DEVICE) => {
            scratch[0] = dev.configuration;
            Action::Data(trim(&scratch[..1], setup.wLength))
        }

        (request::GET_STATUS, _) => {
            // Bus-powered, no remote wakeup, and no endpoint halted: two zero bytes.
            scratch[0] = 0;
            scratch[1] = 0;
            Action::Data(trim(&scratch[..2], setup.wLength))
        }

        // There is one interface with one setting, so the only legal answers are fixed.
        (request::GET_INTERFACE, recipient::INTERFACE) => {
            scratch[0] = 0;
            Action::Data(trim(&scratch[..1], setup.wLength))
        }
        (request::SET_INTERFACE, recipient::INTERFACE) if setup.wValue == 0 => Action::Ack,

        // Halt is the only endpoint feature, and nothing here needs to hold one halted:
        // the transport recovers by abandoning the message, not by halting a pipe.
        (request::CLEAR_FEATURE | request::SET_FEATURE, recipient::ENDPOINT) => Action::Ack,

        _ => Action::Stall,
    }
}

fn get_descriptor<'a>(dev: &Device, setup: &Setup, scratch: &'a mut [u8]) -> Action<'a> {
    let what = (setup.wValue >> 8) as u8;
    let index = setup.wValue as u8;

    match what {
        kind::DEVICE => Action::Data(trim_static(&descriptor::DEVICE, setup.wLength)),
        kind::CONFIGURATION => Action::Data(trim_static(&descriptor::CONFIGURATION, setup.wLength)),
        kind::HID_REPORT => {
            Action::Data(trim_static(&descriptor::REPORT_DESCRIPTOR, setup.wLength))
        }
        kind::STRING => {
            let text = match index {
                descriptor::string::LANGID => {
                    return Action::Data(trim_static(&descriptor::LANGIDS, setup.wLength));
                }
                descriptor::string::MANUFACTURER => descriptor::MANUFACTURER,
                descriptor::string::PRODUCT => descriptor::PRODUCT,
                descriptor::string::SERIAL => dev.serial,
                _ => return Action::Stall,
            };
            match descriptor::string_descriptor(text, scratch) {
                Some(n) => Action::Data(trim(&scratch[..n], setup.wLength)),
                None => Action::Stall,
            }
        }
        // The HID descriptor is not fetched on its own -- it comes inside the
        // configuration -- but some hosts ask anyway, and it is inside a slice we
        // already hold, so answering is free.
        kind::HID => {
            const AT: usize = 9 + 9;
            Action::Data(trim_static(
                &descriptor::CONFIGURATION[AT..AT + 9],
                setup.wLength,
            ))
        }
        _ => Action::Stall,
    }
}

fn class<'a>(dev: &mut Device, setup: &Setup, scratch: &'a mut [u8]) -> Action<'a> {
    match setup.bRequest {
        // Windows sends SET_IDLE during enumeration and will not proceed if it stalls.
        hid_request::SET_IDLE => {
            dev.idle = (setup.wValue >> 8) as u8;
            Action::Ack
        }
        hid_request::GET_IDLE => {
            scratch[0] = dev.idle;
            Action::Data(trim(&scratch[..1], setup.wLength))
        }
        // Only the report protocol exists here; there is no boot protocol for a
        // vendor-defined usage page.
        hid_request::SET_PROTOCOL => Action::Ack,
        // A control-pipe GET_REPORT is answered with an empty report rather than a
        // stall: some hosts probe it during enumeration, and real traffic goes over the
        // interrupt endpoints.
        hid_request::GET_REPORT => {
            let n = (setup.wLength as usize).min(scratch.len());
            scratch[..n].fill(0);
            Action::Data(&scratch[..n])
        }
        hid_request::SET_REPORT => Action::Ack,
        _ => Action::Stall,
    }
}

/// Never send the host more than it asked for.
fn trim(data: &[u8], want: u16) -> &[u8] {
    &data[..data.len().min(want as usize)]
}

fn trim_static(data: &'static [u8], want: u16) -> &'static [u8] {
    &data[..data.len().min(want as usize)]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev() -> Device {
        Device::new("CAFEBABE0001")
    }

    fn setup(bm: u8, req: u8, value: u16, index: u16, len: u16) -> Setup {
        Setup {
            bmRequestType: bm,
            bRequest: req,
            wValue: value,
            wIndex: index,
            wLength: len,
        }
    }

    /// The exact sequence a host runs at plug-in.
    #[test]
    fn a_real_enumeration_sequence_completes() {
        let mut d = dev();
        let mut s = [0u8; 64];

        // 1. The host reads the first 8 bytes of the device descriptor to learn EP0's
        //    max packet size, before it knows anything else.
        let a = handle(
            &mut d,
            &setup(0x80, request::GET_DESCRIPTOR, 0x0100, 0, 8),
            &mut s,
        );
        let Action::Data(b) = a else { panic!("{a:?}") };
        assert_eq!(b.len(), 8, "must honour the short wLength");
        assert_eq!(b[7], 64, "bMaxPacketSize0");

        // 2. Address.
        let a = handle(&mut d, &setup(0x00, request::SET_ADDRESS, 7, 0, 0), &mut s);
        assert_eq!(a, Action::AckThenAddress(7));
        assert_eq!(d.phase, Phase::Addressed);

        // 3. The full device descriptor, now at the new address.
        let a = handle(
            &mut d,
            &setup(0x80, request::GET_DESCRIPTOR, 0x0100, 0, 18),
            &mut s,
        );
        let Action::Data(b) = a else { panic!("{a:?}") };
        assert_eq!(b.len(), 18);

        // 4. Configuration header, then the whole thing.
        let a = handle(
            &mut d,
            &setup(0x80, request::GET_DESCRIPTOR, 0x0200, 0, 9),
            &mut s,
        );
        let Action::Data(b) = a else { panic!("{a:?}") };
        assert_eq!(b.len(), 9);
        let total = u16::from_le_bytes([b[2], b[3]]);
        let a = handle(
            &mut d,
            &setup(0x80, request::GET_DESCRIPTOR, 0x0200, 0, total),
            &mut s,
        );
        let Action::Data(b) = a else { panic!("{a:?}") };
        assert_eq!(b.len() as u16, total);

        // 5. Configure.
        let a = handle(
            &mut d,
            &setup(0x00, request::SET_CONFIGURATION, 1, 0, 0),
            &mut s,
        );
        assert_eq!(a, Action::Ack);
        assert!(d.is_configured());

        // 6. HID: idle rate, then the report descriptor.
        let a = handle(&mut d, &setup(0x21, hid_request::SET_IDLE, 0, 0, 0), &mut s);
        assert_eq!(a, Action::Ack);
        let a = handle(
            &mut d,
            &setup(0x81, request::GET_DESCRIPTOR, 0x2200, 0, 256),
            &mut s,
        );
        let Action::Data(b) = a else { panic!("{a:?}") };
        assert_eq!(b, &descriptor::REPORT_DESCRIPTOR[..]);
    }

    #[test]
    fn a_reply_is_never_longer_than_the_host_asked_for() {
        // Sending more than wLength is a babble error and the host drops the device.
        let mut d = dev();
        let mut s = [0u8; 64];
        for want in [0u16, 1, 4, 9, 17, 18, 255] {
            let a = handle(
                &mut d,
                &setup(0x80, request::GET_DESCRIPTOR, 0x0100, 0, want),
                &mut s,
            );
            let Action::Data(b) = a else { panic!("{a:?}") };
            assert!(b.len() <= want as usize, "want {want}, got {}", b.len());
        }
    }

    #[test]
    fn the_address_is_taken_after_the_status_stage_not_before() {
        // The status stage of SET_ADDRESS is still addressed to zero. A driver that
        // applied the address immediately would vanish mid-transfer, which presents as
        // a device that enumerates once in ten tries.
        let mut d = dev();
        let mut s = [0u8; 64];
        let a = handle(&mut d, &setup(0x00, request::SET_ADDRESS, 42, 0, 0), &mut s);
        assert_eq!(
            a,
            Action::AckThenAddress(42),
            "the action has to carry the ordering, not just the value"
        );
    }

    #[test]
    fn a_bus_reset_returns_the_device_to_its_unconfigured_state() {
        let mut d = dev();
        let mut s = [0u8; 64];
        handle(&mut d, &setup(0x00, request::SET_ADDRESS, 3, 0, 0), &mut s);
        handle(
            &mut d,
            &setup(0x00, request::SET_CONFIGURATION, 1, 0, 0),
            &mut s,
        );
        assert!(d.is_configured());
        d.reset();
        assert_eq!(d.phase, Phase::Default);
        assert_eq!(d.address, 0);
        assert!(!d.is_configured());
    }

    #[test]
    fn set_configuration_zero_unconfigures_rather_than_being_ignored() {
        let mut d = dev();
        let mut s = [0u8; 64];
        handle(
            &mut d,
            &setup(0x00, request::SET_CONFIGURATION, 1, 0, 0),
            &mut s,
        );
        let a = handle(
            &mut d,
            &setup(0x00, request::SET_CONFIGURATION, 0, 0, 0),
            &mut s,
        );
        assert_eq!(a, Action::Ack);
        assert_eq!(d.phase, Phase::Addressed);
        assert!(!d.is_configured());
    }

    #[test]
    fn an_unsupported_configuration_is_refused() {
        let mut d = dev();
        let mut s = [0u8; 64];
        let a = handle(
            &mut d,
            &setup(0x00, request::SET_CONFIGURATION, 2, 0, 0),
            &mut s,
        );
        assert_eq!(a, Action::Stall);
        assert!(!d.is_configured());
    }

    #[test]
    fn every_string_index_answers_or_stalls_but_never_panics() {
        let mut d = dev();
        let mut s = [0u8; 64];
        for i in 0..=255u8 {
            let a = handle(
                &mut d,
                &setup(
                    0x80,
                    request::GET_DESCRIPTOR,
                    0x0300 | i as u16,
                    0x0409,
                    255,
                ),
                &mut s,
            );
            match i {
                0..=3 => assert!(matches!(a, Action::Data(_)), "index {i}"),
                _ => assert_eq!(a, Action::Stall, "index {i}"),
            }
        }
    }

    #[test]
    fn the_serial_string_is_the_one_the_device_was_built_with() {
        let mut d = Device::new("0123456789AB");
        let mut s = [0u8; 64];
        let a = handle(
            &mut d,
            &setup(0x80, request::GET_DESCRIPTOR, 0x0303, 0x0409, 255),
            &mut s,
        );
        let Action::Data(b) = a else { panic!("{a:?}") };
        assert_eq!(b[0] as usize, 2 + 12 * 2);
        assert_eq!(&b[2..6], &[b'0', 0, b'1', 0]);
    }

    #[test]
    fn set_idle_is_acknowledged_because_windows_will_not_enumerate_without_it() {
        let mut d = dev();
        let mut s = [0u8; 64];
        assert_eq!(
            handle(
                &mut d,
                &setup(0x21, hid_request::SET_IDLE, 0x0500, 0, 0),
                &mut s
            ),
            Action::Ack
        );
        assert_eq!(d.idle, 5);
        let a = handle(&mut d, &setup(0xA1, hid_request::GET_IDLE, 0, 0, 1), &mut s);
        let Action::Data(b) = a else { panic!("{a:?}") };
        assert_eq!(b, &[5]);
    }

    #[test]
    fn vendor_requests_stall_rather_than_going_unanswered() {
        // Silence costs the host a timeout on every enumeration; a stall is instant.
        let mut d = dev();
        let mut s = [0u8; 64];
        assert_eq!(
            handle(&mut d, &setup(0xC0, 0x20, 0, 7, 64), &mut s),
            Action::Stall
        );
    }

    #[test]
    fn an_unknown_standard_request_stalls() {
        let mut d = dev();
        let mut s = [0u8; 64];
        assert_eq!(
            handle(&mut d, &setup(0x80, 0x7F, 0, 0, 8), &mut s),
            Action::Stall
        );
    }

    #[test]
    fn setup_packets_decode_the_way_the_spec_lays_them_out() {
        let s = Setup::from_bytes(&[0x80, 0x06, 0x00, 0x01, 0x09, 0x04, 0x40, 0x00]);
        assert!(s.is_in());
        assert_eq!(s.kind(), req_kind::STANDARD);
        assert_eq!(s.recipient(), recipient::DEVICE);
        assert_eq!(s.bRequest, request::GET_DESCRIPTOR);
        assert_eq!(s.wValue, 0x0100);
        assert_eq!(s.wIndex, 0x0409);
        assert_eq!(s.wLength, 64);
    }
}
