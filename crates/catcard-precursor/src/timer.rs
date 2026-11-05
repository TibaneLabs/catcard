//! Milliseconds since the SoC came out of reset, from the gateware ticktimer.
//!
//! The ticktimer is a 64-bit count in an always-on clock domain. It is not reset by a
//! CPU-only reset, so the runner entering this image finds it already counting.
//!
//! Layout, measured rather than assumed: LiteX splits a 64-bit status register across
//! two words with the most significant word first, so `ticktimer_time` (+0x04) is the
//! high word and +0x08 the low word; over 2.011 s the low word advanced by 2005, so one
//! tick is one millisecond on this build.
//! Source: csr.csv `ticktimer_time,0xf0012004,2,ro` [C]; word order and tick rate read on
//! the bench unit over the USB bridge, 2026-11-05 [C].

use crate::csr::{self, reg};

const _: () = assert!(reg::TICKTIMER_TIME_WORDS == 2);

/// Milliseconds since the SoC was reset.
pub fn now_ms() -> u64 {
    let hi_addr = reg::TICKTIMER_TIME;
    let lo_addr = reg::TICKTIMER_TIME + 4;
    // The two halves are read separately, so a carry between them would tear the value.
    // Read high, low, high: if the high word moved, the low word wrapped in between and
    // the second pass is consistent. Two passes always suffice, since the low word takes
    // 49 days to wrap.
    for _ in 0..2 {
        let hi = csr::read(hi_addr);
        let lo = csr::read(lo_addr);
        if csr::read(hi_addr) == hi {
            return (u64::from(hi) << 32) | u64::from(lo);
        }
    }
    let hi = csr::read(hi_addr);
    (u64::from(hi) << 32) | u64::from(csr::read(lo_addr))
}

/// Spins for at least `ms` milliseconds, feeding the watchdog while it waits.
pub fn delay_ms(ms: u64) {
    let until = now_ms() + ms;
    while now_ms() < until {
        crate::wdt::feed();
    }
}
