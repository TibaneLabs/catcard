//! GPIO pin naming, independent of any HAL.
//!
//! Board files are const data; they must be usable from `build.rs` on the host as
//! well as from firmware, so nothing here touches MCU registers.

/// STM32 GPIO port.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Port {
    A = 0,
    B = 1,
    C = 2,
    D = 3,
    E = 4,
    F = 5,
    G = 6,
    H = 7,
}

impl Port {
    /// Byte offset of this port's register block from `GPIOA_BASE`.
    ///
    /// STM32L4 places the GPIO blocks 0x400 apart starting at 0x4800_0000.
    /// Source: ST RM0351 §2.2.2 / RM0432 §2.2.2 (memory map).
    pub const fn offset(self) -> u32 {
        (self as u32) * 0x400
    }

    pub const fn letter(self) -> char {
        match self {
            Port::A => 'A',
            Port::B => 'B',
            Port::C => 'C',
            Port::D => 'D',
            Port::E => 'E',
            Port::F => 'F',
            Port::G => 'G',
            Port::H => 'H',
        }
    }
}

/// A single GPIO, e.g. `PA6`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Pin {
    pub port: Port,
    /// 0..=15
    pub num: u8,
}

impl Pin {
    pub const fn new(port: Port, num: u8) -> Self {
        // `assert!` in const fn is stable and gives a compile-time error for a
        // typo'd pin number in a board file.
        assert!(num < 16, "GPIO pin number must be 0..=15");
        Self { port, num }
    }

    /// Bit mask for this pin within its port's 16-bit registers.
    pub const fn mask(self) -> u16 {
        1u16 << self.num
    }
}

/// A pin that may be absent on a given board (e.g. card-detect on some revisions).
pub type MaybePin = Option<Pin>;

/// Convenience constructors: `pa(6)` reads better than `Pin::new(Port::A, 6)` in
/// the dense pin tables below.
pub const fn pa(n: u8) -> Pin {
    Pin::new(Port::A, n)
}
pub const fn pb(n: u8) -> Pin {
    Pin::new(Port::B, n)
}
pub const fn pc(n: u8) -> Pin {
    Pin::new(Port::C, n)
}
pub const fn pd(n: u8) -> Pin {
    Pin::new(Port::D, n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_offsets_are_0x400_apart() {
        assert_eq!(Port::A.offset(), 0x000);
        assert_eq!(Port::B.offset(), 0x400);
        assert_eq!(Port::D.offset(), 0xC00);
    }

    #[test]
    fn pin_mask() {
        assert_eq!(pa(0).mask(), 1);
        assert_eq!(pc(12).mask(), 1 << 12);
    }
}
