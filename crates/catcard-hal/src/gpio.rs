//! GPIO.
//!
//! Register map per port: `MODER` +0x00, `OTYPER` +0x04, `OSPEEDR` +0x08, `PUPDR`
//! +0x0C, `IDR` +0x10, `ODR` +0x14, `BSRR` +0x18, `AFRL` +0x20, `AFRH` +0x24.
//! Source: ST RM0351 §8.4 / RM0432 §9.4.
//!
//! Port base addresses and the 0x400 stride come from
//! `catcard_board::memory::fixed::GPIOA` and [`Port::offset`].

use catcard_board::memory::fixed;
use catcard_board::pin::{Pin, Port};

use crate::reg;

const MODER: u32 = 0x00;
const OTYPER: u32 = 0x04;
const OSPEEDR: u32 = 0x08;
const PUPDR: u32 = 0x0C;
const IDR: u32 = 0x10;
const BSRR: u32 = 0x18;
const AFRL: u32 = 0x20;

/// `RCC_AHB2ENR` — bits 0..=7 are the GPIOA..GPIOH clock gates.
/// Source: RM0351 §6.4.17.
const RCC_AHB2ENR: u32 = fixed::RCC + 0x4C;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum Mode {
    Input = 0b00,
    Output = 0b01,
    Alternate = 0b10,
    Analog = 0b11,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum OutputType {
    PushPull,
    /// Required for the numpad rows, which are wired as a shared matrix and would
    /// short against each other if driven push-pull.
    OpenDrain,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum Pull {
    None = 0b00,
    Up = 0b01,
    Down = 0b10,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum Speed {
    Low = 0b00,
    Medium = 0b01,
    High = 0b10,
    VeryHigh = 0b11,
}

const fn port_base(p: Port) -> u32 {
    fixed::GPIOA + p.offset()
}

/// Turn on the clock for a port. Nothing in a GPIO block responds until this is done.
///
/// # Safety
/// Writes RCC.
pub unsafe fn enable_port(port: Port) {
    unsafe {
        reg::set_bits(RCC_AHB2ENR, 1 << (port as u32));
        let _ = reg::read(RCC_AHB2ENR); // let the gate settle before first access
    }
}

/// Configure a pin.
///
/// # Safety
///
/// Writes the port's registers with a read-modify-write, so the caller must not race
/// another context configuring a pin on the same port. The port's clock must already
/// be enabled via [`enable_port`].
pub unsafe fn configure(pin: Pin, mode: Mode, otype: OutputType, pull: Pull, speed: Speed) {
    let base = port_base(pin.port);
    let n = pin.num as u32;
    let two_bit = 0b11 << (n * 2);

    unsafe {
        reg::modify(base + PUPDR, two_bit, (pull as u32) << (n * 2));
        reg::modify(base + OSPEEDR, two_bit, (speed as u32) << (n * 2));
        match otype {
            OutputType::PushPull => reg::clear_bits(base + OTYPER, 1 << n),
            OutputType::OpenDrain => reg::set_bits(base + OTYPER, 1 << n),
        }
        // MODER last: the pin only starts driving once its mode is set, so the rest of
        // the configuration is already in place when it does.
        reg::modify(base + MODER, two_bit, (mode as u32) << (n * 2));
    }
}

/// Select an alternate function (`AF0`..`AF15`) and switch the pin to alternate mode.
///
/// # Safety
/// As [`configure`]. `af` must be < 16.
pub unsafe fn set_alternate(pin: Pin, af: u8, otype: OutputType, pull: Pull, speed: Speed) {
    assert!(af < 16, "alternate function must be 0..=15");
    let base = port_base(pin.port);
    let n = pin.num as u32;
    // AFRL covers pins 0-7, AFRH pins 8-15; four bits each.
    let (regaddr, shift) = if n < 8 {
        (base + AFRL, n * 4)
    } else {
        (base + AFRL + 4, (n - 8) * 4)
    };
    unsafe {
        reg::modify(regaddr, 0b1111 << shift, (af as u32) << shift);
        configure(pin, Mode::Alternate, otype, pull, speed);
    }
}

/// Drive a pin high or low via `BSRR`, which is atomic and needs no read-modify-write.
///
/// # Safety
/// The pin must be configured as an output. `BSRR` is write-only and per-pin, so this
/// cannot disturb other pins on the port.
#[inline]
pub unsafe fn write(pin: Pin, high: bool) {
    let bit = if high {
        1u32 << pin.num
    } else {
        1u32 << (pin.num + 16)
    };
    unsafe { reg::write(port_base(pin.port) + BSRR, bit) }
}

/// Read a pin's input level.
///
/// # Safety
/// Reads `IDR`, which has no side effects, but the port clock must be enabled.
#[inline]
pub unsafe fn read(pin: Pin) -> bool {
    unsafe { reg::read(port_base(pin.port) + IDR) & (1 << pin.num) != 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use catcard_board::pin::{pa, pc, pd};

    #[test]
    fn port_bases_follow_the_0x400_stride() {
        assert_eq!(port_base(Port::A), 0x4800_0000);
        assert_eq!(port_base(Port::B), 0x4800_0400);
        assert_eq!(port_base(Port::C), 0x4800_0800);
        assert_eq!(port_base(Port::D), 0x4800_0C00);
        assert_eq!(port_base(Port::H), 0x4800_1C00);
    }

    /// The AFRL/AFRH split at pin 8 is the classic off-by-one in GPIO code, so pin the
    /// arithmetic down without touching hardware.
    #[test]
    fn alternate_function_register_selection() {
        fn target(pin: Pin) -> (u32, u32) {
            let base = port_base(pin.port);
            let n = pin.num as u32;
            if n < 8 {
                (base + AFRL, n * 4)
            } else {
                (base + AFRL + 4, (n - 8) * 4)
            }
        }
        assert_eq!(target(pa(0)), (0x4800_0020, 0));
        assert_eq!(target(pa(7)), (0x4800_0020, 28));
        assert_eq!(target(pa(8)), (0x4800_0024, 0));
        assert_eq!(target(pd(15)), (0x4800_0C24, 28));
    }

    #[test]
    fn bsrr_bit_positions() {
        // Set is the low half, reset the high half.
        let set = 1u32 << pc(6).num;
        let clear = 1u32 << (pc(6).num + 16);
        assert_eq!(set, 1 << 6);
        assert_eq!(clear, 1 << 22);
    }
}
