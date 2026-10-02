//! The games as an app: `arg` 0 is Block Mine, 1 Block Cutter.
#![no_std]
#![no_main]

// The SDK's entry point and panic handler come in with the crate.
use catcard_app as _;

#[unsafe(no_mangle)]
pub extern "C" fn app_main(arg: u32) -> i32 {
    match arg {
        0 => app_games::block_mine(),
        1 => app_games::block_cutter(),
        _ => return -1,
    }
    0
}
