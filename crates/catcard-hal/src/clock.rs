//! Clock tree.
//!
//! Current state: enough to run the RNG. The core keeps the reset-default MSI clock,
//! which is slow but correct; the PLL bring-up is deliberately not guessed at (see
//! [`PLL_DIVISORS`]).

use catcard_board::memory::fixed;

use crate::reg;

// Offsets are written out in full, including `+ 0x00`, so each line can be checked
// against the reference-manual register table without mental arithmetic.
#[allow(clippy::identity_op)]
const RCC_CR: u32 = fixed::RCC + 0x00;
/// Clock Recovery RC register — HSI48 control. Source: RM0351 §6.4.29 / RM0432.
const RCC_CRRCR: u32 = fixed::RCC + 0x98;
/// Peripherals Independent Clock Configuration. Source: RM0351 §6.4.28.
const RCC_CCIPR: u32 = fixed::RCC + 0x88;

const CRRCR_HSI48ON: u32 = 1 << 0;
const CRRCR_HSI48RDY: u32 = 1 << 1;

/// `CLK48SEL[1:0]` at bits 27:26. `00` selects HSI48.
const CCIPR_CLK48SEL_MASK: u32 = 0b11 << 26;
const CCIPR_CLK48SEL_HSI48: u32 = 0b00 << 26;

const READY_TRIES: u32 = 100_000;

/// PLL divisors recorded for this hardware: `N=40, M=2, R=2, P=7, Q=4`, sourced from
/// the MSI. Source: `hw-reference/platform.md §1` [C].
///
/// **Not yet applied.** The resulting frequencies depend on the MSI range the board
/// runs at, which the reference does not state — and `VCO = MSI / M * N` with
/// `SYSCLK = VCO / R` gives 40 MHz at MSI=4 MHz but 80 MHz at MSI=8 MHz. Programming
/// the PLL from a wrong assumption either underclocks the device or overclocks it past
/// its voltage-scaling limit. Confirm the MSI range on hardware first; see
/// `docs/HARDWARE-OPEN-ITEMS.md`.
pub const PLL_DIVISORS: PllDivisors = PllDivisors {
    n: 40,
    m: 2,
    r: 2,
    p: 7,
    q: 4,
};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PllDivisors {
    pub n: u32,
    pub m: u32,
    pub r: u32,
    pub p: u32,
    pub q: u32,
}

impl PllDivisors {
    /// VCO frequency for a given PLL input.
    pub const fn vco_hz(&self, input_hz: u32) -> u32 {
        input_hz / self.m * self.n
    }
    /// SYSCLK for a given PLL input.
    pub const fn sysclk_hz(&self, input_hz: u32) -> u32 {
        self.vco_hz(input_hz) / self.r
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// HSI48 did not come up.
    Hsi48NotReady,
}

/// Start HSI48 and route it to the 48 MHz peripheral clock.
///
/// The RNG will not produce a single word without this; `DRDY` simply never asserts.
/// HSI48 is used rather than a PLL output because it needs no knowledge of the board's
/// input clock, so it is correct on every generation.
///
/// # Safety
/// Touches RCC. Call once, early, before any 48 MHz peripheral is enabled.
pub unsafe fn enable_hsi48() -> Result<(), Error> {
    unsafe {
        reg::set_bits(RCC_CRRCR, CRRCR_HSI48ON);
        if !reg::wait_for(RCC_CRRCR, CRRCR_HSI48RDY, CRRCR_HSI48RDY, READY_TRIES) {
            return Err(Error::Hsi48NotReady);
        }
        reg::modify(RCC_CCIPR, CCIPR_CLK48SEL_MASK, CCIPR_CLK48SEL_HSI48);
    }
    Ok(())
}

/// Whether HSI48 is currently running.
///
/// # Safety
/// Reads RCC.
pub unsafe fn hsi48_ready() -> bool {
    unsafe { reg::read(RCC_CRRCR) & CRRCR_HSI48RDY != 0 }
}

/// Raw `RCC_CR`, for diagnostics on the selftest screen.
///
/// # Safety
/// Reads RCC.
pub unsafe fn rcc_cr() -> u32 {
    unsafe { reg::read(RCC_CR) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pll_arithmetic() {
        // The ambiguity that keeps the PLL unprogrammed, stated as a test so the
        // reasoning is not lost.
        assert_eq!(PLL_DIVISORS.sysclk_hz(4_000_000), 40_000_000);
        assert_eq!(PLL_DIVISORS.sysclk_hz(8_000_000), 80_000_000);
    }
}
