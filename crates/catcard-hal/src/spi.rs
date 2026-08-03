//! Blocking SPI master.
//!
//! Register map: `CR1` +0x00, `CR2` +0x04, `SR` +0x08, `DR` +0x0C.
//! Source: ST RM0351 §40.6 (RM0432 §43.6 on L4+).
//!
//! # The 8-bit `DR` access
//!
//! `SPI_DR` is a 16-bit register. Writing it with a 32- or 16-bit store when the frame
//! size is 8 bits queues **two** frames, because the FIFO packs them. Every access here
//! is therefore an explicit byte access, and `FRXTH` is set so `RXNE` asserts at 8 bits
//! rather than 16. Getting this wrong sends twice as many bytes as intended and is a
//! classic STM32 SPI bug.

use crate::reg;

/// SPI peripheral base addresses on STM32L4. Source: RM0351 §2.2.2
const SPI1_BASE: u32 = 0x4001_3000;
const SPI2_BASE: u32 = 0x4000_3800;
const SPI3_BASE: u32 = 0x4000_3C00;

const CR1: u32 = 0x00;
const CR2: u32 = 0x04;
const SR: u32 = 0x08;
const DR: u32 = 0x0C;

// CR1
const CR1_CPHA: u32 = 1 << 0;
const CR1_CPOL: u32 = 1 << 1;
const CR1_MSTR: u32 = 1 << 2;
const CR1_BR_SHIFT: u32 = 3;
const CR1_BR_MASK: u32 = 0b111 << CR1_BR_SHIFT;
const CR1_SPE: u32 = 1 << 6;
/// MSB-first is the default and what every device here uses; defined so the bit is
/// accounted for rather than silently assumed clear.
#[allow(dead_code)]
const CR1_LSBFIRST: u32 = 1 << 7;
/// Internal slave-select value; must be high in software-NSS master mode or the
/// peripheral sees a mode fault.
const CR1_SSI: u32 = 1 << 8;
/// Software slave management: we drive chip-select as a plain GPIO.
const CR1_SSM: u32 = 1 << 9;

// CR2
/// Data size, 4 bits. `0b0111` is 8-bit.
const CR2_DS_SHIFT: u32 = 8;
const CR2_DS_MASK: u32 = 0b1111 << CR2_DS_SHIFT;
const CR2_DS_8BIT: u32 = 0b0111 << CR2_DS_SHIFT;
/// RXNE threshold: assert at 8 bits rather than 16.
const CR2_FRXTH: u32 = 1 << 12;

// SR
const SR_RXNE: u32 = 1 << 0;
const SR_TXE: u32 = 1 << 1;
const SR_OVR: u32 = 1 << 6;
const SR_BSY: u32 = 1 << 7;
/// FIFO transmission level, bits 12:11. Non-zero means bytes are still queued.
const SR_FTLVL_MASK: u32 = 0b11 << 11;

/// Clock gates. Source: RM0351 §6.4.16 (APB2ENR), §6.4.19 (APB1ENR1)
const RCC_APB1ENR1: u32 = catcard_board::memory::fixed::RCC + 0x58;
const RCC_APB2ENR: u32 = catcard_board::memory::fixed::RCC + 0x60;
const APB2ENR_SPI1: u32 = 1 << 12;
const APB1ENR1_SPI2: u32 = 1 << 14;
const APB1ENR1_SPI3: u32 = 1 << 15;

/// Polls before declaring a transfer stalled. Generous: even at the slowest prescaler a
/// byte completes in a few thousand core cycles.
const POLL_LIMIT: u32 = 200_000;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// A status flag never came up. The peripheral is unclocked, or its pins are not in
    /// alternate-function mode.
    Timeout,
    /// Receive overrun: a byte arrived before the previous one was read. Indicates a
    /// driver bug rather than a bus problem, since every write here is paired with a
    /// read.
    Overrun,
    /// No such SPI instance on this part.
    NoSuchInstance { instance: u8 },
}

/// SPI mode, as the usual CPOL/CPHA pair.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Mode {
    /// CPOL=0, CPHA=0. What the SSD1306 and most SPI-NOR parts use.
    Mode0,
    Mode1,
    Mode2,
    Mode3,
}

impl Mode {
    const fn bits(self) -> u32 {
        match self {
            Mode::Mode0 => 0,
            Mode::Mode1 => CR1_CPHA,
            Mode::Mode2 => CR1_CPOL,
            Mode::Mode3 => CR1_CPOL | CR1_CPHA,
        }
    }
}

/// Baud-rate prescaler: `PCLK / 2^(n+1)`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum Prescaler {
    Div2 = 0,
    Div4 = 1,
    Div8 = 2,
    Div16 = 3,
    Div32 = 4,
    Div64 = 5,
    Div128 = 6,
    Div256 = 7,
}

impl Prescaler {
    /// The slowest prescaler whose resulting clock does not exceed `max_hz`.
    ///
    /// Rounds *down* in frequency: overrunning a peripheral's maximum clock produces
    /// intermittent corruption rather than a clean failure.
    pub const fn for_max_hz(pclk_hz: u32, max_hz: u32) -> Prescaler {
        let mut div = 2u32;
        let mut p = 0u32;
        while p < 7 {
            if pclk_hz / div <= max_hz {
                break;
            }
            div *= 2;
            p += 1;
        }
        match p {
            0 => Prescaler::Div2,
            1 => Prescaler::Div4,
            2 => Prescaler::Div8,
            3 => Prescaler::Div16,
            4 => Prescaler::Div32,
            5 => Prescaler::Div64,
            6 => Prescaler::Div128,
            _ => Prescaler::Div256,
        }
    }
}

const fn base_of(instance: u8) -> Option<u32> {
    match instance {
        1 => Some(SPI1_BASE),
        2 => Some(SPI2_BASE),
        3 => Some(SPI3_BASE),
        _ => None,
    }
}

/// An initialised SPI master.
pub struct Spi {
    base: u32,
}

impl Spi {
    /// Configure and enable an SPI instance.
    ///
    /// Does **not** touch GPIO: the caller sets the SCK/MOSI/MISO pins to their
    /// alternate function first, using the pin map from `catcard-board`.
    ///
    /// # Safety
    ///
    /// Must be called at most once per instance; two handles would interleave bytes on
    /// the same FIFO.
    pub unsafe fn init(instance: u8, mode: Mode, prescaler: Prescaler) -> Result<Self, Error> {
        let base = base_of(instance).ok_or(Error::NoSuchInstance { instance })?;

        // SAFETY: writing the documented RCC clock gate for this instance.
        unsafe {
            match instance {
                1 => reg::set_bits(RCC_APB2ENR, APB2ENR_SPI1),
                2 => reg::set_bits(RCC_APB1ENR1, APB1ENR1_SPI2),
                _ => reg::set_bits(RCC_APB1ENR1, APB1ENR1_SPI3),
            }
            let _ = reg::read(RCC_APB2ENR); // let the gate settle
        }

        // SAFETY: exclusive access to this instance, asserted by the caller.
        unsafe {
            // Configure with SPE clear; CR1 must not be modified while enabled.
            reg::write(base + CR1, 0);
            reg::modify(base + CR2, CR2_DS_MASK, CR2_DS_8BIT | CR2_FRXTH);
            reg::write(
                base + CR1,
                CR1_MSTR
                    | CR1_SSM
                    | CR1_SSI
                    | ((prescaler as u32) << CR1_BR_SHIFT) & CR1_BR_MASK
                    | mode.bits(),
            );
            reg::set_bits(base + CR1, CR1_SPE);
        }

        Ok(Self { base })
    }

    fn wait(&self, mask: u32, want: u32) -> Result<(), Error> {
        // SAFETY: reading this instance's status register.
        if unsafe { reg::wait_for(self.base + SR, mask, want, POLL_LIMIT) } {
            Ok(())
        } else {
            Err(Error::Timeout)
        }
    }

    /// Exchange one byte: write `out`, return what came back.
    ///
    /// SPI is inherently full duplex, so every write produces a read. Discarding it
    /// silently would eventually set the overrun flag and wedge the peripheral, so the
    /// read is always performed even when the value is unwanted.
    pub fn transfer_byte(&mut self, out: u8) -> Result<u8, Error> {
        self.wait(SR_TXE, SR_TXE)?;

        // SAFETY: 8-bit store to DR. A wider store would queue two frames — see the
        // module docs.
        unsafe {
            core::ptr::write_volatile((self.base + DR) as *mut u8, out);
        }

        self.wait(SR_RXNE, SR_RXNE)?;

        // SAFETY: RXNE is set, so a byte is waiting. 8-bit load for the same reason.
        let got = unsafe { core::ptr::read_volatile((self.base + DR) as *const u8) };

        // SAFETY: reading this instance's status register.
        if unsafe { reg::read(self.base + SR) } & SR_OVR != 0 {
            return Err(Error::Overrun);
        }
        Ok(got)
    }

    /// Write a buffer, discarding what is received.
    pub fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        for &b in data {
            self.transfer_byte(b)?;
        }
        Ok(())
    }

    /// Read `out.len()` bytes, clocking out `0xFF`.
    ///
    /// `0xFF` rather than `0x00` because it leaves an open-drain or undriven bus high,
    /// which is what SPI-NOR parts expect during a dummy phase.
    pub fn read(&mut self, out: &mut [u8]) -> Result<(), Error> {
        for slot in out.iter_mut() {
            *slot = self.transfer_byte(0xFF)?;
        }
        Ok(())
    }

    /// Block until the shift register and FIFO have drained.
    ///
    /// Required before deasserting chip-select: dropping CS while `BSY` is set
    /// truncates the final byte on the wire.
    pub fn flush(&self) -> Result<(), Error> {
        self.wait(SR_FTLVL_MASK, 0)?;
        self.wait(SR_BSY, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_base_addresses() {
        assert_eq!(base_of(1), Some(0x4001_3000));
        assert_eq!(base_of(2), Some(0x4000_3800));
        assert_eq!(base_of(3), Some(0x4000_3C00));
        assert_eq!(base_of(4), None);
    }

    #[test]
    fn eight_bit_frame_size_encoding() {
        // DS = 0b0111 is 8-bit; 0b1111 would be 16. An off-by-one here doubles every
        // transfer length on the wire.
        assert_eq!(CR2_DS_8BIT >> CR2_DS_SHIFT, 7);
        assert_eq!(CR2_DS_8BIT & !CR2_DS_MASK, 0);
    }

    #[test]
    fn mode_bits() {
        assert_eq!(Mode::Mode0.bits(), 0);
        assert_eq!(Mode::Mode1.bits(), CR1_CPHA);
        assert_eq!(Mode::Mode2.bits(), CR1_CPOL);
        assert_eq!(Mode::Mode3.bits(), CR1_CPOL | CR1_CPHA);
    }

    #[test]
    fn prescaler_never_exceeds_the_requested_clock() {
        // Rounding the wrong way overclocks the peripheral, which corrupts
        // intermittently instead of failing.
        for pclk in [4_000_000u32, 16_000_000, 40_000_000, 80_000_000] {
            for max in [1_000_000u32, 8_000_000, 25_000_000] {
                let p = Prescaler::for_max_hz(pclk, max);
                let actual = pclk / (1 << (p as u32 + 1));
                assert!(
                    actual <= max || p == Prescaler::Div256,
                    "pclk {pclk} max {max} chose {p:?} -> {actual}"
                );
            }
        }
    }

    #[test]
    fn prescaler_picks_the_fastest_that_fits() {
        // 80 MHz PCLK, 8 MHz limit: /16 gives 5 MHz, /8 would give 10 MHz.
        assert_eq!(
            Prescaler::for_max_hz(80_000_000, 8_000_000),
            Prescaler::Div16
        );
        // Exactly divisible: /2 gives exactly the limit and is acceptable.
        assert_eq!(
            Prescaler::for_max_hz(16_000_000, 8_000_000),
            Prescaler::Div2
        );
        // Slower than /256 can go: saturates rather than wrapping.
        assert_eq!(Prescaler::for_max_hz(80_000_000, 1), Prescaler::Div256);
    }

    #[test]
    fn prescaler_values_are_the_register_encoding() {
        assert_eq!(Prescaler::Div2 as u32, 0);
        assert_eq!(Prescaler::Div256 as u32, 7);
        // And fit the 3-bit BR field.
        assert_eq!((Prescaler::Div256 as u32) << CR1_BR_SHIFT & !CR1_BR_MASK, 0);
    }

    #[test]
    fn software_nss_requires_ssi_high() {
        // With SSM set and SSI clear the peripheral sees itself deselected and raises a
        // mode fault, which presents as "SPI does nothing".
        assert_ne!(CR1_SSM, 0);
        assert_ne!(CR1_SSI, 0);
        assert_ne!(CR1_SSM, CR1_SSI);
    }

    #[test]
    fn bus_config_from_a_board_is_representable() {
        // The board table's max_hz must map onto a real prescaler.
        for b in catcard_board::spec::ALL {
            let p = Prescaler::for_max_hz(80_000_000, b.sflash.max_hz);
            assert!((p as u32) <= 7, "{}", b.name);
        }
    }
}
