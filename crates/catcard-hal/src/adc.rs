//! ADC1 on the STM32L4+, one channel at a time, software-triggered.
//!
//! Enough to read a slow, divided voltage -- the Q1's battery sense -- and nothing more:
//! no DMA, no injected channels, no watchdogs. Everything left at its reset value stays
//! there: `ADC_CFGR` resets to 12-bit, right-aligned, single conversion, software
//! trigger, which is exactly the mode wanted.
//!
//! Register map: ADC1 at `0x5004_0000` (the ADC block's 1 KB window on AHB2, master ADC
//! at offset 0); `ISR` +0x00, `CR` +0x08, `SMPR1` +0x14, `SQR1` +0x30, `DR` +0x40; the
//! common `CCR` at +0x300 + 0x08. `ADCEN` is `RCC_AHB2ENR` bit 13.
//! Source: RM0432 Rev 9 §2.2.2 memory map ("0x5004 0000 - 0x5004 03FF ADC"), §21.6.1,
//! §21.6.3, §21.6.6, §21.6.11, §21.6.15, §21.7.2, Table 142; §6.4.17 [C].
//!
//! Bring-up follows RM0432 §21.4.6 (leave deep power-down, enable the regulator, wait),
//! §21.4.8 (single-ended calibration with ADEN=0) and §21.4.9 (clear ADRDY, set ADEN,
//! wait for ADRDY) [C]. Every wait is bounded.

use catcard_board::memory::fixed;

use crate::reg;

/// ADC1 (master) base. Source: RM0432 §2.2.2, Table 142 [C]
const BASE: u32 = 0x5004_0000;
#[allow(clippy::identity_op)]
const ISR: u32 = BASE + 0x00;
const CR: u32 = BASE + 0x08;
const SMPR1: u32 = BASE + 0x14;
const SQR1: u32 = BASE + 0x30;
const DR: u32 = BASE + 0x40;
/// Common control register: master base + 0x300 + 0x08. Source: RM0432 §21.7.2 [C]
const CCR: u32 = BASE + 0x308;

// ADC_ISR. Source: RM0432 §21.6.1 [C]
const ISR_ADRDY: u32 = 1 << 0;
const ISR_EOC: u32 = 1 << 2;
const ISR_EOS: u32 = 1 << 3;
const ISR_OVR: u32 = 1 << 4;

// ADC_CR. Source: RM0432 §21.6.3 [C]
const CR_ADEN: u32 = 1 << 0;
const CR_ADSTART: u32 = 1 << 2;
const CR_ADVREGEN: u32 = 1 << 28;
const CR_DEEPPWD: u32 = 1 << 29;
const CR_ADCALDIF: u32 = 1 << 30;
const CR_ADCAL: u32 = 1 << 31;

/// `CCR.CKMODE = 0b11`: the ADC clocked from HCLK/4, synchronously. Needs nothing from
/// the RCC's kernel-clock mux, and quarters the core clock -- 30 MHz from 120 MHz, well
/// inside the ADC's range (the datasheet figure is not in the references, so the
/// slowest synchronous divider is the choice that leaves the most margin [I];
/// docs/HARDWARE-OPEN-ITEMS.md). Source: RM0432 §21.7.2 [C]
const CCR_CKMODE_MASK: u32 = 0b11 << 16;
const CCR_CKMODE_HCLK_DIV4: u32 = 0b11 << 16;

/// `SMPx = 0b111`: 640.5 ADC clocks of sampling, the longest on offer. A resistive
/// divider has a source impedance nobody here has measured; the longest sample is the
/// one that settles through the most of it. Source: RM0432 §21.6.6 [C]
const SMP_640_5: u32 = 0b111;

// RCC_AHB2ENR bit 13. Source: RM0432 §6.4.17 [C]
const RCC_AHB2ENR: u32 = fixed::RCC + 0x4C;
const AHB2ENR_ADCEN: u32 = 1 << 13;

/// Polls allowed for any one flag. A conversion here is ~650 ADC clocks, about 22 us at
/// 30 MHz; calibration is of the same order. This is orders of magnitude over both.
const TRIES: u32 = 1_000_000;

/// Why a reading could not be taken.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// A channel past the ones `SMPR1` covers (0..=9), which is all this driver sets up.
    Channel,
    /// Calibration never finished.
    Calibration,
    /// `ADRDY` never came up.
    NotReady,
    /// A conversion never finished.
    Conversion,
}

/// Bring ADC1 up and calibrate it, if it is not already running.
///
/// # Safety
/// Takes ADC1 and its common register for the caller; nothing else in the firmware may
/// use the ADC. Reads RCC. Foreground only.
pub unsafe fn init() -> Result<(), Error> {
    // SAFETY: the caller owns the ADC; these are its registers and RCC's enable bit.
    unsafe {
        if reg::read(RCC_AHB2ENR) & AHB2ENR_ADCEN != 0 && reg::read(CR) & CR_ADEN != 0 {
            return Ok(());
        }
        reg::set_bits(RCC_AHB2ENR, AHB2ENR_ADCEN);
        // Read back, so the enable has reached the bus before the ADC is touched.
        let _ = reg::read(RCC_AHB2ENR);

        // The clock mode may only be written with every ADC disabled, which it is here.
        reg::modify(CCR, CCR_CKMODE_MASK, CCR_CKMODE_HCLK_DIV4);

        // §21.4.6: out of deep power-down, regulator on, then its start-up time. The
        // figure is in the datasheet, which the references do not include; a whole
        // millisecond is far past it [I].
        reg::clear_bits(CR, CR_DEEPPWD);
        reg::set_bits(CR, CR_ADVREGEN);
        crate::dwt::delay_ms(1);

        // §21.4.8: single-ended calibration, with ADEN=0.
        reg::clear_bits(CR, CR_ADCALDIF);
        reg::set_bits(CR, CR_ADCAL);
        if !reg::wait_for(CR, CR_ADCAL, 0, TRIES) {
            return Err(Error::Calibration);
        }
        // "ADEN bit cannot be set ... during four ADC clock cycles after the ADCAL bit is
        // cleared": 4 ADC clocks at HCLK/4 are 16 core cycles; wait well past that.
        crate::dwt::delay_cycles(1_000);

        // §21.4.9: clear ADRDY, enable, wait for ADRDY.
        reg::write(ISR, ISR_ADRDY);
        reg::set_bits(CR, CR_ADEN);
        if !reg::wait_for(ISR, ISR_ADRDY, ISR_ADRDY, TRIES) {
            return Err(Error::NotReady);
        }
        reg::write(ISR, ISR_ADRDY);
    }
    Ok(())
}

/// One conversion of `channel`, 12 bits right-aligned (0..=4095).
///
/// # Safety
/// As [`init`], which must have succeeded.
pub unsafe fn read(channel: u32) -> Result<u16, Error> {
    if channel > 9 {
        return Err(Error::Channel);
    }
    // SAFETY: the caller owns the enabled ADC; ADSTART is 0 between reads, which is
    // when SMPR1 and SQR1 may be written (RM0432 §21.6.6, §21.6.11).
    unsafe {
        let shift = channel * 3;
        reg::modify(SMPR1, 0b111 << shift, SMP_640_5 << shift);
        // SQR1: L = 0 (one conversion), SQ1 = channel (bits 10:6).
        reg::write(SQR1, channel << 6);
        reg::write(ISR, ISR_EOC | ISR_EOS | ISR_OVR);
        reg::set_bits(CR, CR_ADSTART);
        if !reg::wait_for(ISR, ISR_EOC, ISR_EOC, TRIES) {
            return Err(Error::Conversion);
        }
        // Reading DR clears EOC. Source: RM0432 §21.6.1 [C]
        Ok((reg::read(DR) & 0xFFF) as u16)
    }
}

/// Millivolts at the pin for the mean of `samples`, against a reference of `vref_mv`,
/// scaled by `divider` for a resistive divider in front of it.
///
/// 12-bit full scale is 4095. Integer arithmetic throughout, rounded to the nearest
/// millivolt.
pub fn millivolts(samples: &[u16], vref_mv: u32, divider: u32) -> Option<u32> {
    if samples.is_empty() {
        return None;
    }
    let sum: u64 = samples.iter().map(|&s| u64::from(s.min(4095))).sum();
    let n = samples.len() as u64;
    let num = sum * u64::from(vref_mv) * u64::from(divider);
    let den = n * 4095;
    Some(((num + den / 2) / den) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_scale_is_the_reference_times_the_divider() {
        assert_eq!(millivolts(&[4095; 4], 3300, 2), Some(6600));
        assert_eq!(millivolts(&[0; 4], 3300, 2), Some(0));
        // Half scale.
        assert_eq!(millivolts(&[2048, 2047, 2048, 2047], 3300, 2), Some(3300));
    }

    #[test]
    fn it_is_the_mean_and_no_sample_can_exceed_full_scale() {
        assert_eq!(millivolts(&[1000, 3000], 3300, 1), Some(1612));
        assert_eq!(millivolts(&[u16::MAX], 3300, 1), Some(3300));
        assert_eq!(millivolts(&[], 3300, 2), None);
    }
}
