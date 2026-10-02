//! The smallest app: say hello, read the clock, sleep, and exit with `42 + arg`.
#![no_std]
#![no_main]

use catcard_app::{Line, sys};
use core::fmt::Write as _;

/// Proves `.data` is loaded and writable, and `.bss` starts at zero.
static mut COUNT: u32 = 7;
static mut ZEROED: u32 = 0;

#[unsafe(no_mangle)]
pub extern "C" fn app_main(arg: u32) -> i32 {
    sys::log("hello from an app");
    let mut l = Line::new();
    // SAFETY: one thread of execution; nothing else touches these.
    let (count, zeroed) = unsafe {
        let c = &mut *core::ptr::addr_of_mut!(COUNT);
        *c += 1;
        (*c, *core::ptr::addr_of!(ZEROED))
    };
    let t0 = sys::ticks();
    sys::sleep_ms(250);
    let slept = sys::ticks().wrapping_sub(t0);
    let _ = write!(
        l,
        "data {count} (want 8), bss {zeroed} (want 0), slept {slept} ms, arg {arg}"
    );
    l.log();
    42 + arg as i32
}
