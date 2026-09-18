//! USART2, full duplex, for the Q1's QR scanner.
//!
//! The one full-duplex serial port this firmware owns. [`se1swi`](crate::se1swi) also
//! drives a USART, but that is a different job: it borrows UART4 from the bootloader for
//! a handful of bytes, in half-duplex, and puts every register back. Nothing owns UART4.
//! This *does* own USART2 — the scanner is the only thing on it.
//!
//! # Bounded, like everything else here
//!
//! Every wait takes a budget in loop iterations and gives up. A scanner that is unplugged,
//! asleep or answering at the wrong baud rate must produce a timeout that a screen can
//! report, not a device that stops.
//!
//! Register layout: ST RM0351 §38.8 (USART), §6.4 (RCC). Pins and the peripheral:
//! hw-reference/gpio.md §Q1 [C].

use crate::gpio::{self, Mode, OutputType, Pull, Speed};
use catcard_board::Pin;
use catcard_board::memory::fixed;

/// USART2. Source: RM0351 Table 1 (memory map) [C]
const USART2: u32 = 0x4000_4400;
#[allow(clippy::identity_op)]
const CR1: u32 = USART2 + 0x00;
const CR2: u32 = USART2 + 0x04;
const CR3: u32 = USART2 + 0x08;
const BRR: u32 = USART2 + 0x0C;
const ISR: u32 = USART2 + 0x1C;
const ICR: u32 = USART2 + 0x20;
const RDR: u32 = USART2 + 0x24;
const TDR: u32 = USART2 + 0x28;

// Source: RM0351 §38.8.1-38.8.11 [C]
const CR1_UE: u32 = 1 << 0;
const CR1_RE: u32 = 1 << 2;
const CR1_TE: u32 = 1 << 3;
const ISR_RXNE: u32 = 1 << 5;
const ISR_TC: u32 = 1 << 6;
const ISR_TXE: u32 = 1 << 7;
const ISR_ORE: u32 = 1 << 3;
const ISR_NE: u32 = 1 << 2;
const ISR_FE: u32 = 1 << 1;
const ISR_PE: u32 = 1 << 0;
const ICR_PECF: u32 = 1 << 0;
const ICR_FECF: u32 = 1 << 1;
const ICR_NECF: u32 = 1 << 2;
const ICR_ORECF: u32 = 1 << 3;

/// `RCC_APB1ENR1.USART2EN`, bit 17. Source: RM0351 §6.4.19 [C]
const RCC_APB1ENR1: u32 = fixed::RCC + 0x58;
const APB1ENR1_USART2EN: u32 = 1 << 17;
/// `RCC_CCIPR.USART2SEL`, bits 3:2; `00` is PCLK1. Source: RM0351 §6.4.28 [C]
const RCC_CCIPR: u32 = fixed::RCC + 0x88;
const CCIPR_USART2SEL: u32 = 0b11 << 2;

/// USART2 on PA2/PA3. Source: STM32L496 datasheet, alternate function table (AF7) [C]
const AF_USART2: u8 = 7;

/// Why a transfer did not happen.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Nothing arrived inside the budget. The commonest real cause is the other end
    /// listening at a different baud rate, which is why the scanner probes.
    Timeout,
    /// The line said something the framing could not accept: a break, noise, or bytes
    /// arriving faster than they were read. Reported rather than swallowed, because at
    /// the wrong baud rate this is what a reply looks like.
    Framing,
}

/// USART2, configured and owned.
pub struct Usart {
    /// Kept so [`set_baud`](Self::set_baud) can recompute the divisor.
    pclk_hz: u32,
}

impl Usart {
    /// Take USART2 and its pins at `baud`.
    ///
    /// # Safety
    /// Claims USART2, its clock gate, and the board's scanner TX/RX pins. Call once;
    /// nothing else may drive them.
    pub unsafe fn init(tx: Pin, rx: Pin, baud: u32) -> Self {
        // SAFETY: the caller's contract -- these registers and pins are ours.
        unsafe {
            gpio::enable_port(tx.port);
            gpio::enable_port(rx.port);
            gpio::set_alternate(tx, AF_USART2, OutputType::PushPull, Pull::None, Speed::High);
            // A pull-up on the receive line so an unplugged or powered-down module reads
            // as idle rather than as a stream of break conditions.
            gpio::set_alternate(rx, AF_USART2, OutputType::PushPull, Pull::Up, Speed::High);

            crate::reg::modify(RCC_APB1ENR1, 0, APB1ENR1_USART2EN);
            // PCLK1 as the kernel clock, which is what the divisor below assumes.
            crate::reg::modify(RCC_CCIPR, CCIPR_USART2SEL, 0);

            // Configure with the peripheral disabled: most of CR1 is write-protected
            // while UE is set, and a half-applied configuration is a port that answers
            // at the wrong rate rather than one that fails.
            crate::reg::write(CR1, 0);
            crate::reg::write(CR2, 0);
            crate::reg::write(CR3, 0);
        }
        let pclk_hz = {
            // SAFETY: reads RCC only.
            unsafe { crate::clock::pclk1_hz() }
        };
        let mut port = Self { pclk_hz };
        port.set_baud(baud);
        // SAFETY: as above.
        unsafe { crate::reg::write(CR1, CR1_UE | CR1_TE | CR1_RE) };
        port
    }

    /// Change the line rate.
    ///
    /// The scanner is found by trying rates until one answers, so this happens with the
    /// port already up. `UE` is dropped across the write: `BRR` must not change while the
    /// peripheral is enabled.
    pub fn set_baud(&mut self, baud: u32) {
        // Oversampling by 16, so the divisor is simply the clock over the rate; the
        // rounding is deliberate rather than truncating, since the error is what decides
        // whether the far end can frame the byte at all.
        let div = (self.pclk_hz + baud / 2) / baud.max(1);
        // SAFETY: our own peripheral; the write is one register.
        unsafe {
            let cr1 = crate::reg::read(CR1);
            crate::reg::write(CR1, cr1 & !CR1_UE);
            crate::reg::write(BRR, div.max(16));
            crate::reg::write(CR1, cr1 | CR1_UE);
        }
    }

    /// Throw away anything already received, and any sticky error.
    ///
    /// Called before a command so the reply is read against a clean line: at the wrong
    /// baud rate the receiver collects noise, and an overrun left set would fail the
    /// *next* read rather than the one that caused it.
    pub fn flush_input(&mut self) {
        // SAFETY: our own peripheral.
        unsafe {
            crate::reg::write(ICR, ICR_ORECF | ICR_FECF | ICR_NECF | ICR_PECF);
            // Drain whatever is in the register. Bounded: this is a one-deep receiver,
            // so anything past a couple of reads means the line is live, not backed up.
            for _ in 0..4 {
                if crate::reg::read(ISR) & ISR_RXNE == 0 {
                    break;
                }
                let _ = crate::reg::read(RDR);
            }
        }
    }

    /// Send one byte, waiting for room in the transmit register.
    pub fn write_byte(&mut self, b: u8, budget: u32) -> Result<(), Error> {
        for _ in 0..budget {
            // SAFETY: our own peripheral.
            if unsafe { crate::reg::read(ISR) } & ISR_TXE != 0 {
                // SAFETY: as above.
                unsafe { crate::reg::write(TDR, b as u32) };
                return Ok(());
            }
        }
        Err(Error::Timeout)
    }

    /// Send every byte, then wait for the last one to leave the shift register.
    ///
    /// The wait matters before a baud change or a reset: dropping `UE` with a byte still
    /// going out truncates it, and the module answers a truncated command with silence,
    /// which is indistinguishable from the wrong rate.
    pub fn write(&mut self, bytes: &[u8], budget: u32) -> Result<(), Error> {
        for &b in bytes {
            self.write_byte(b, budget)?;
        }
        for _ in 0..budget {
            // SAFETY: our own peripheral.
            if unsafe { crate::reg::read(ISR) } & ISR_TC != 0 {
                return Ok(());
            }
        }
        Err(Error::Timeout)
    }

    /// Read one byte, or say why not.
    pub fn read_byte(&mut self, budget: u32) -> Result<u8, Error> {
        for _ in 0..budget {
            // SAFETY: our own peripheral.
            let isr = unsafe { crate::reg::read(ISR) };
            if isr & (ISR_ORE | ISR_NE | ISR_FE | ISR_PE) != 0 {
                // SAFETY: as above. Clear it, or every later read reports the same fault.
                unsafe { crate::reg::write(ICR, ICR_ORECF | ICR_FECF | ICR_NECF | ICR_PECF) };
                return Err(Error::Framing);
            }
            if isr & ISR_RXNE != 0 {
                // SAFETY: as above.
                return Ok(unsafe { crate::reg::read(RDR) } as u8);
            }
        }
        Err(Error::Timeout)
    }

    /// Fill `out`, stopping early on a timeout. Returns how many bytes arrived.
    ///
    /// A short read is the normal case, not an error: the module answers what it has and
    /// then says nothing, and "nothing more" is how the end of a reply is known.
    pub fn read(&mut self, out: &mut [u8], budget: u32) -> usize {
        let mut n = 0;
        while n < out.len() {
            match self.read_byte(budget) {
                Ok(b) => {
                    out[n] = b;
                    n += 1;
                }
                // Framing errors are dropped bytes, not the end of the reply: keep going
                // so a burst of noise at the wrong rate does not truncate a good tail.
                Err(Error::Framing) => continue,
                Err(Error::Timeout) => break,
            }
        }
        n
    }
}

/// Pulse the scanner's reset line.
///
/// **Open-drain, active-low**: driven low for the pulse and released to the board's
/// pull-up afterwards, never driven high. The module needs about two seconds after this
/// before it will answer, which is the caller's to wait out.
///
/// # Safety
/// Claims the pin. Source: hw-reference/input.md §"QR scanner (Q1)" [C]
pub unsafe fn pulse_reset(pin: Pin, low_cycles: u32) {
    // SAFETY: the caller's contract.
    unsafe {
        gpio::enable_port(pin.port);
        gpio::configure(
            pin,
            Mode::Output,
            OutputType::OpenDrain,
            Pull::Up,
            Speed::Low,
        );
        gpio::write(pin, false);
        crate::dwt::delay_cycles(low_cycles);
        // Released, not driven: open-drain means the pull-up brings it back up.
        gpio::write(pin, true);
    }
}
