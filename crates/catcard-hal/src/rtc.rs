//! Reading the RTC, only as an entropy source.
//!
//! The wallet does not keep time and never sets the RTC. But on mk4 and later the
//! bootloader leaves it running off the 32 kHz oscillator, so its sub-second counter
//! (`RTC_SSR`) is advancing -- and its value at the instant a key is pressed is a
//! fine-grained sample of real time that no polling schedule can predict. Mixed into the
//! UI DRBG it is extra entropy, never a precondition. If the RTC is not running the
//! registers read a constant, and mixing a constant is harmless.
//!
//! Sources: base `0x4000_2800`, `RTC_TR`=+0x00, `RTC_SSR`=+0x28 — hw-reference/platform.md
//! §2 [C]; `RTC_DR`=+0x04 and the shadow-register read order (SSR, TR, DR unlocks the
//! shadow) from RM0432 §RTC [C]; `RTCAPBEN` is `RCC_APB1ENR1` bit 10 [C]. No VBAT, so the
//! RTC counts elapsed-since-boot, never wall-clock time (platform.md §3) — which is exactly
//! why it is used only as timing jitter, credited nothing on its own.

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

/// Open the RTC's APB read gate, once, so [`snapshot`] can read the registers.
///
/// Separate from [`snapshot`] on purpose: this is the only part that writes RCC, via a
/// read-modify-write shared with the SPI and PWR clock gates on the same register. So it
/// runs once from the foreground during bring-up, never from the interrupt handler that
/// samples the RTC per keypress -- which would otherwise race a concurrent foreground
/// gate change and lose it. After this, `snapshot` is pure reads and interrupt-safe.
///
/// # Safety
/// Writes `RCC_APB1ENR1`. Call from a single-threaded context before any interrupt can
/// call [`snapshot`], and not concurrently with another read-modify-write of that register.
pub unsafe fn enable() {
    // SAFETY: idempotent gate enable; the caller guarantees no concurrent RMW of this reg.
    unsafe {
        reg::set_bits(RCC_APB1ENR1, RTCAPBEN);
        let _ = reg::read(RCC_APB1ENR1); // let the gate settle before first access
    }
}

/// A snapshot of the RTC's sub-second, time and date registers, for entropy only.
///
/// Pure reads, so it is safe to call from an interrupt handler. The shadow registers
/// unlock when `RTC_DR` is read, so the order (SSR, TR, DR) matters; entropy does not care
/// about the values, but reading DR last keeps a caller that did care unblocked.
///
/// # Safety
/// Reads three RTC registers; [`enable`] must have opened the APB gate first, or the read
/// can fault. No side effects otherwise.
pub unsafe fn snapshot() -> [u32; 3] {
    // SAFETY: reads only; the gate was opened by `enable` during bring-up.
    unsafe { [reg::read(RTC_SSR), reg::read(RTC_TR), reg::read(RTC_DR)] }
}
