//! Run for `arg` seconds (default 3) mostly busy, without yielding, so the kernel has to
//! preempt the app to keep USB alive; log a heartbeat every half second. Exits with the
//! number of heartbeats.
#![no_std]
#![no_main]

use catcard_app::{Line, sys};
use core::fmt::Write as _;

#[unsafe(no_mangle)]
pub extern "C" fn app_main(arg: u32) -> i32 {
    let secs = if arg == 0 { 3 } else { arg.min(30) };
    let start = sys::ticks();
    let mut beats = 0u32;
    let mut next = start + 500;
    let mut spins: u32 = 0;
    loop {
        // Busy work the compiler cannot drop, and no service call in between: only the
        // timer can take the CPU away from this loop.
        for _ in 0..10_000 {
            spins = core::hint::black_box(spins.wrapping_add(1));
        }
        let now = sys::ticks();
        if now.wrapping_sub(start) >= secs * 1000 {
            break;
        }
        if now.wrapping_sub(next) < 0x8000_0000 {
            beats += 1;
            next += 500;
            let mut l = Line::new();
            let _ = write!(l, "spin: beat {beats} at {} ms", now.wrapping_sub(start));
            l.log();
        }
    }
    beats as i32
}
