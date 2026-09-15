//! Reading the RTC, only as an entropy source.
//!
//! The wallet does not keep time and never sets the RTC. But on mk4 and later the
//! bootloader leaves it running off the 32 kHz oscillator, so its sub-second counter
//! (`RTC_SSR`) is advancing -- and its value at the instant a key is pressed is a
//! fine-grained sample of real time that no polling schedule can predict. Mixed into the
//! UI DRBG it is extra entropy, never a precondition. If the RTC is not running the
//! registers read a constant, and mixing a constant is harmless.
//!
//! Sources: RTC register map RM0432 §RTC [C]; `RTCAPBEN` is `RCC_APB1ENR1` bit 10 [C].

use crate::reg;
use catcard_board::memory::fixed;

/// RTC peripheral base.
const RTC: u32 = 0x4000_2800;
/// Time register (BCD hours/minutes/seconds).
const RTC_TR: u32 = RTC;
/// Date register (BCD year/month/day).
const RTC_DR: u32 = RTC + 0x04;
/// Sub-second down-counter, reloaded from the synchronous prescaler each second.
const RTC_SSR: u32 = RTC + 0x28;

/// `RCC_APB1ENR1`, and its bit 10 gating APB access to the RTC/TAMP/BKP registers.
/// Enabling it only lets the CPU *read* the registers; it does not start or alter the RTC.
const RCC_APB1ENR1: u32 = fixed::RCC + 0x58;
const RTCAPBEN: u32 = 1 << 10;

/// A snapshot of the RTC's sub-second, time and date registers, for entropy only.
///
/// # Safety
/// Opens the RTC's APB clock gate (idempotent, read-only in effect) and reads three RTC
/// registers. Single-threaded callers.
pub unsafe fn snapshot() -> [u32; 3] {
    // SAFETY: as documented. A read with the gate closed could fault, so open it first;
    // the gate is otherwise unused by this firmware.
    unsafe {
        reg::set_bits(RCC_APB1ENR1, RTCAPBEN);
        [reg::read(RTC_SSR), reg::read(RTC_TR), reg::read(RTC_DR)]
    }
}
