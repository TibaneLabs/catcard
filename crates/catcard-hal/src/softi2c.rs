//! A bit-banged I²C master on two open-drain GPIOs.
//!
//! The Q1's I²C1 -- the NFC tag and the GPU co-processor -- is driven this way by the stock
//! firmware rather than through the hardware peripheral: plain open-drain PB6/PB7 against
//! external pull-ups, clock stretching honoured. This does the same, at a comfortably slow
//! rate, since the traffic here is a handful of one-byte commands.
//!
//! The protocol is written against [`Lines`] so it can be run on the host against a
//! simulated device; [`GpioLines`] is the hardware implementation.
//!
//! Every wait is bounded: a device holding the clock low for longer than
//! [`STRETCH_POLLS`] allows is an error, not a hang.
//!
//! Source: hw-reference/gpio.md §"I²C buses" -- "I2C1 -- NFC + GPU is SOFTWARE bit-banged
//! ... plain open-drain PB6/PB7 ... clock-stretch honored (50 ms timeout), external
//! pull-ups" [C]

use catcard_board::Pin;

/// Why a transfer did not complete.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// No device acknowledged: nothing at that address, or it is busy.
    Nack,
    /// The clock stayed low past the stretch limit.
    Stretched,
}

/// The two bus lines, open-drain: "high" means released to the pull-up.
pub trait Lines {
    fn scl(&mut self, high: bool);
    fn sda(&mut self, high: bool);
    fn read_scl(&mut self) -> bool;
    fn read_sda(&mut self) -> bool;
    /// A quarter of a bit period.
    fn pause(&mut self);
}

/// Pauses to wait for a stretched clock. At the quarter period [`GpioLines`] uses (~2.5
/// µs), 20 000 is about 50 ms -- the stock timeout.
pub const STRETCH_POLLS: u32 = 20_000;

/// An I²C master over some [`Lines`].
pub struct SoftI2c<L: Lines> {
    lines: L,
}

impl<L: Lines> SoftI2c<L> {
    pub fn new(mut lines: L) -> Self {
        lines.sda(true);
        lines.scl(true);
        Self { lines }
    }

    /// Write `bytes` to the 7-bit address `addr`.
    pub fn write(&mut self, addr: u8, bytes: &[u8]) -> Result<(), Error> {
        let r = self.start().and_then(|()| self.write_byte(addr << 1));
        let r = r.and_then(|()| bytes.iter().try_for_each(|&b| self.write_byte(b)));
        // A stop is sent whatever happened, so a failed transfer does not leave the bus held.
        let _ = self.stop();
        r
    }

    /// Fill `out` from the 7-bit address `addr`.
    pub fn read(&mut self, addr: u8, out: &mut [u8]) -> Result<(), Error> {
        let r = self.start().and_then(|()| self.write_byte((addr << 1) | 1));
        self.read_into(r, out)
    }

    /// Write `bytes`, then read `out` back **without letting go of the bus between**.
    ///
    /// The second start is a *repeated* start: no stop condition separates the two halves.
    /// That is what an addressed read of a memory wants -- the write carries the address to
    /// read from, and a stop in the middle would let another master in between the two, or
    /// leave a device free to decide the transfer was over.
    ///
    /// Source: ST25DV64KC datasheet §6.5.1 "Random address read" -- "A dummy write is first
    /// performed to load the address into this address counter ... but without sending a
    /// Stop condition. Then, the bus controller sends another Start condition (reStart)"
    /// [C]
    pub fn write_read(&mut self, addr: u8, bytes: &[u8], out: &mut [u8]) -> Result<(), Error> {
        let r = self
            .start()
            .and_then(|()| self.write_byte(addr << 1))
            .and_then(|()| bytes.iter().try_for_each(|&b| self.write_byte(b)))
            .and_then(|()| self.start())
            .and_then(|()| self.write_byte((addr << 1) | 1));
        self.read_into(r, out)
    }

    /// The reading half both of the above share: bytes in, acknowledged until the last, and
    /// a stop whatever happened so a failed transfer does not leave the bus held.
    fn read_into(&mut self, mut r: Result<(), Error>, out: &mut [u8]) -> Result<(), Error> {
        let n = out.len();
        for (i, slot) in out.iter_mut().enumerate() {
            if r.is_err() {
                break;
            }
            // Acknowledge every byte but the last, which tells the device to stop sending.
            match self.read_byte(i + 1 < n) {
                Ok(b) => *slot = b,
                Err(e) => r = Err(e),
            }
        }
        let _ = self.stop();
        r
    }

    /// Hand the lines back.
    pub fn into_lines(self) -> L {
        self.lines
    }

    fn start(&mut self) -> Result<(), Error> {
        self.lines.sda(true);
        self.clock_high()?;
        self.lines.pause();
        // SDA falling while SCL is high.
        self.lines.sda(false);
        self.lines.pause();
        self.lines.scl(false);
        self.lines.pause();
        Ok(())
    }

    fn stop(&mut self) -> Result<(), Error> {
        self.lines.sda(false);
        self.lines.pause();
        self.clock_high()?;
        self.lines.pause();
        // SDA rising while SCL is high.
        self.lines.sda(true);
        self.lines.pause();
        Ok(())
    }

    /// Release the clock and wait for it to actually rise: a device may hold it low.
    fn clock_high(&mut self) -> Result<(), Error> {
        self.lines.scl(true);
        for _ in 0..STRETCH_POLLS {
            if self.lines.read_scl() {
                return Ok(());
            }
            self.lines.pause();
        }
        Err(Error::Stretched)
    }

    fn write_bit(&mut self, bit: bool) -> Result<(), Error> {
        self.lines.sda(bit);
        self.lines.pause();
        self.clock_high()?;
        self.lines.pause();
        self.lines.scl(false);
        self.lines.pause();
        Ok(())
    }

    fn read_bit(&mut self) -> Result<bool, Error> {
        self.lines.sda(true);
        self.lines.pause();
        self.clock_high()?;
        self.lines.pause();
        let bit = self.lines.read_sda();
        self.lines.scl(false);
        self.lines.pause();
        Ok(bit)
    }

    fn write_byte(&mut self, byte: u8) -> Result<(), Error> {
        for i in (0..8).rev() {
            self.write_bit((byte >> i) & 1 == 1)?;
        }
        // The device pulls SDA low to acknowledge.
        if self.read_bit()? {
            Err(Error::Nack)
        } else {
            Ok(())
        }
    }

    fn read_byte(&mut self, ack: bool) -> Result<u8, Error> {
        let mut b = 0u8;
        for _ in 0..8 {
            b = (b << 1) | u8::from(self.read_bit()?);
        }
        self.write_bit(!ack)?;
        Ok(b)
    }
}

/// [`Lines`] on two real open-drain GPIOs.
pub struct GpioLines {
    scl: Pin,
    sda: Pin,
    quarter: u32,
}

impl GpioLines {
    /// Configure `scl` and `sda` as open-drain outputs, released.
    ///
    /// # Safety
    /// Claims both pins; nothing else may drive them while this lives.
    pub unsafe fn new(scl: Pin, sda: Pin) -> Self {
        use crate::gpio::{self, Mode, OutputType, Pull, Speed};
        // SAFETY: the caller owns both pins.
        unsafe {
            for p in [scl, sda] {
                gpio::enable_port(p.port);
                gpio::write(p, true);
                // The bus has external pull-ups; the internal ones only keep a disconnected
                // line from floating.
                gpio::configure(p, Mode::Output, OutputType::OpenDrain, Pull::Up, Speed::Low);
            }
        }
        // ~100 kHz: a quarter period of 2.5 µs. Well under the 400 kHz the bus runs at in
        // stock, which leaves the unmeasured traces and pull-ups plenty of margin.
        // SAFETY: reads RCC only.
        let hz = unsafe { crate::clock::hclk_hz() };
        Self {
            scl,
            sda,
            quarter: (hz / 400_000).max(1),
        }
    }
}

impl Lines for GpioLines {
    fn scl(&mut self, high: bool) {
        // SAFETY: configured as an open-drain output in `new`.
        unsafe { crate::gpio::write(self.scl, high) }
    }
    fn sda(&mut self, high: bool) {
        // SAFETY: as above.
        unsafe { crate::gpio::write(self.sda, high) }
    }
    fn read_scl(&mut self) -> bool {
        // SAFETY: an open-drain output still reads the pad.
        unsafe { crate::gpio::read(self.scl) }
    }
    fn read_sda(&mut self) -> bool {
        // SAFETY: as above.
        unsafe { crate::gpio::read(self.sda) }
    }
    fn pause(&mut self) {
        crate::dwt::delay_cycles(self.quarter);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A device on a simulated bus: acknowledges its address, records what it is sent, and
    /// answers reads from `reply`. Decodes the waveform the master actually produces, so a
    /// wrong bit order or a mistimed sample fails here rather than on the Q1.
    struct Device {
        addr: u8,
        scl: bool,
        master_sda: bool,
        device_sda: bool,
        /// Bits clocked since the last start, and the byte being assembled.
        bits: u32,
        byte: u8,
        reading: bool,
        addressed: bool,
        received: Vec<u8>,
        reply: Vec<u8>,
        reply_at: usize,
        stretch: u32,
        starts: u32,
        stops: u32,
    }

    impl Device {
        fn new(addr: u8) -> Self {
            Self {
                addr,
                scl: true,
                master_sda: true,
                device_sda: true,
                bits: 0,
                byte: 0,
                reading: false,
                addressed: false,
                received: Vec::new(),
                reply: Vec::new(),
                reply_at: 0,
                stretch: 0,
                starts: 0,
                stops: 0,
            }
        }

        fn line(&self) -> bool {
            self.master_sda && self.device_sda
        }

        /// What the device drives for the bit about to be clocked.
        fn drive_next(&mut self) {
            let phase = self.bits % 9;
            self.device_sda = true;
            if phase == 8 {
                // Acknowledge: the address if it is ours, and every byte written to us.
                let acking = if self.bits == 8 {
                    self.addressed
                } else {
                    self.addressed && !self.reading
                };
                if acking {
                    self.device_sda = false;
                }
            } else if self.reading && self.bits > 8 {
                let b = self.reply.get(self.reply_at).copied().unwrap_or(0xFF);
                self.device_sda = (b >> (7 - phase)) & 1 == 1;
            }
        }

        fn rising(&mut self) {
            let phase = self.bits % 9;
            let bit = self.line();
            if phase < 8 {
                self.byte = (self.byte << 1) | u8::from(bit);
            } else if self.bits == 8 {
                // The address byte just completed.
                self.addressed = self.byte >> 1 == self.addr;
                self.reading = self.byte & 1 == 1;
            } else if !self.reading {
                if self.addressed {
                    self.received.push(self.byte);
                }
            } else {
                self.reply_at += 1;
            }
            if phase == 7 && self.bits == 7 {
                // Decide the address now, so the acknowledge is driven in time.
                self.addressed = self.byte >> 1 == self.addr;
                self.reading = self.byte & 1 == 1;
            }
            self.bits += 1;
            if phase == 8 {
                self.byte = 0;
            }
        }
    }

    impl Lines for &mut Device {
        fn scl(&mut self, high: bool) {
            if high && !self.scl {
                if self.stretch > 0 {
                    return;
                }
                self.scl = true;
                self.rising();
            } else if !high && self.scl {
                self.scl = false;
                self.drive_next();
            }
        }
        fn sda(&mut self, high: bool) {
            if self.scl && self.master_sda && !high {
                self.starts += 1;
                self.bits = 0;
                self.byte = 0;
                self.addressed = false;
                self.reading = false;
                self.device_sda = true;
            } else if self.scl && !self.master_sda && high {
                self.stops += 1;
            }
            self.master_sda = high;
        }
        fn read_scl(&mut self) -> bool {
            if self.stretch > 0 {
                self.stretch -= 1;
                if self.stretch == 0 {
                    self.scl = true;
                    self.rising();
                }
                return self.stretch == 0;
            }
            self.scl
        }
        fn read_sda(&mut self) -> bool {
            self.line()
        }
        fn pause(&mut self) {}
    }

    #[test]
    fn a_write_reaches_the_device_in_order() {
        let mut dev = Device::new(0x65);
        {
            let mut bus = SoftI2c::new(&mut dev);
            assert_eq!(bus.write(0x65, b"a"), Ok(()));
            assert_eq!(bus.write(0x65, &[0x12, 0x34]), Ok(()));
        }
        assert_eq!(dev.received, vec![b'a', 0x12, 0x34]);
        assert_eq!((dev.starts, dev.stops), (2, 2));
    }

    #[test]
    fn nobody_home_is_a_nack_and_the_bus_is_still_released() {
        let mut dev = Device::new(0x65);
        {
            let mut bus = SoftI2c::new(&mut dev);
            assert_eq!(bus.write(0x64, b"v"), Err(Error::Nack));
        }
        assert!(dev.received.is_empty());
        assert_eq!(dev.stops, 1, "no stop after a nack leaves the bus held");
        assert!(dev.master_sda && dev.scl);
    }

    #[test]
    fn a_read_takes_the_reply_most_significant_bit_first() {
        let mut dev = Device::new(0x65);
        dev.reply = b"1.3.3\0".to_vec();
        let mut bus = SoftI2c::new(&mut dev);
        let mut out = [0u8; 6];
        assert_eq!(bus.read(0x65, &mut out), Ok(()));
        assert_eq!(&out, b"1.3.3\0");
    }

    /// An addressed read: the address goes out, then a **repeated** start turns the
    /// transfer around. Two starts and one stop is the whole statement -- a stop between
    /// the halves would end the transfer, and a memory whose address counter was just
    /// loaded would be free to forget it.
    #[test]
    fn a_write_read_turns_the_bus_around_without_letting_go_of_it() {
        let mut dev = Device::new(0x53);
        dev.reply = vec![0xE2, 0x40, 0x00, 0x01];
        {
            let mut bus = SoftI2c::new(&mut dev);
            let mut out = [0u8; 4];
            assert_eq!(bus.write_read(0x53, &[0x00, 0x00], &mut out), Ok(()));
            assert_eq!(out, [0xE2, 0x40, 0x00, 0x01]);
        }
        assert_eq!(dev.received, vec![0x00, 0x00]);
        assert_eq!((dev.starts, dev.stops), (2, 1));
    }

    /// Nobody at that address: no bytes are written, nothing is read, and the bus is let go.
    #[test]
    fn a_write_read_to_nobody_is_a_nack() {
        let mut dev = Device::new(0x53);
        {
            let mut bus = SoftI2c::new(&mut dev);
            let mut out = [0u8; 4];
            assert_eq!(
                bus.write_read(0x52, &[0x00, 0x00], &mut out),
                Err(Error::Nack)
            );
            assert_eq!(out, [0, 0, 0, 0]);
        }
        assert!(dev.received.is_empty());
        assert_eq!(dev.stops, 1);
    }

    #[test]
    fn a_stretched_clock_is_waited_for_and_a_stuck_one_is_an_error() {
        let mut dev = Device::new(0x65);
        dev.stretch = 5;
        {
            let mut bus = SoftI2c::new(&mut dev);
            assert_eq!(bus.write(0x65, b"a"), Ok(()));
        }
        assert_eq!(dev.received, vec![b'a']);

        let mut stuck = Device::new(0x65);
        stuck.stretch = STRETCH_POLLS + 10;
        let mut bus = SoftI2c::new(&mut stuck);
        assert_eq!(bus.write(0x65, b"a"), Err(Error::Stretched));
    }
}
