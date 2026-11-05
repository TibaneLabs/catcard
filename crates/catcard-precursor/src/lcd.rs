//! The 336x536 Sharp memory LCD, through the gateware's `memlcd` block.
//!
//! The block keeps a framebuffer in block RAM at `0xB000_0000` and streams it to the
//! panel on command. A line is 336 pixels padded to 11 words (44 bytes); the panel has
//! 536 lines; 1 is white, 0 black. `memlcd_command` bit 1 (`UpdateAll`) sends every line,
//! and `memlcd_Busy` bit 0 is set until the transfer ends. The prescaler resets to 1 MHz
//! SCLK at the 100 MHz system clock and is left alone.
//! Source: betrusted gateware memlcd.py (geometry, polarity, command/busy fields,
//! prescaler reset) [C]; csr.csv `memory_region,memlcd,0xb0000000,23584` [C].
//!
//! Pixel placement: the block reads each line's words in increasing address order and
//! shifts each word out least significant bit first, and framebuffer line `i` goes out
//! as panel line `i + 1`. The panel's own line 1 is the top of the device as held and
//! its first pixel the leftmost -- seen on the bench unit with a CPU-less test design
//! driving the panel directly, which also showed the block's documentation (MSB leftmost,
//! bottom line first) does not describe this panel as mounted. So pixel (x, y), origin
//! top left, is bit `x % 32` of word `y * 11 + x / 32`.
//! Source: memlcd.py fetch/shift logic [C]; panel orientation, hw test 2026-11-05 [C];
//! the combination through this block [C]: this firmware's test card, photographed on the
//! bench unit 2026-11-06, has the triangle top left and the checkerboard bottom right, and
//! a framebuffer read back over the USB bridge matches what was drawn.
//!
//! Also visible on the panel and not ours: a dashed line on framebuffer line 7. The block
//! forces it when the boot ROM booted on a developer or third-party key ("devboot"), and
//! it cannot be cleared short of a full reset -- see memlcd.py `devboot`.

use crate::csr::{self, mem, reg};

pub const WIDTH: usize = 336;
pub const HEIGHT: usize = 536;
const WORDS_PER_LINE: usize = 11;
const FB_WORDS: usize = WORDS_PER_LINE * HEIGHT;

const _: () = assert!(mem::MEMLCD_LEN == FB_WORDS * 4);

const CMD_UPDATE_ALL: u32 = 1 << 1;
const BUSY: u32 = 1 << 0;

/// A full refresh is 536 lines of ~370 bits at 1 MHz, about 0.2 s. Five times that
/// means the block is not finishing, and the caller gets an error rather than a hang.
const UPDATE_TIMEOUT_MS: u64 = 1000;

pub enum Error {
    /// The block was still busy (or never went idle) after `UPDATE_TIMEOUT_MS`.
    Timeout,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Timeout => write!(f, "update did not finish within {UPDATE_TIMEOUT_MS} ms"),
        }
    }
}

fn fb_write(word: usize, value: u32) {
    debug_assert!(word < FB_WORDS);
    // SAFETY: `word` < FB_WORDS, and the framebuffer region is FB_WORDS words long
    // (checked against the gateware table above); it is plain block RAM on the bus.
    unsafe { core::ptr::write_volatile((mem::MEMLCD as *mut u32).add(word), value) }
}

fn wait_idle() -> Result<(), Error> {
    let deadline = crate::timer::now_ms() + UPDATE_TIMEOUT_MS;
    while csr::read(reg::MEMLCD_BUSY) & BUSY != 0 {
        crate::wdt::feed();
        if crate::timer::now_ms() >= deadline {
            return Err(Error::Timeout);
        }
    }
    Ok(())
}

/// Draws an orientation test card and pushes it to the panel. Returns how long the
/// panel update took, in milliseconds.
///
/// A black frame, a solid black triangle in the top-left corner and a checkerboard in
/// the bottom-right one: if the triangle is not at the top left, the placement in the
/// module comment is wrong, and in which way is obvious from where it ended up.
pub fn draw_test_card() -> Result<u64, Error> {
    wait_idle()?;
    for y in 0..HEIGHT {
        for w in 0..WORDS_PER_LINE {
            let mut word = 0u32;
            for bit in 0..32 {
                let x = w * 32 + bit;
                if x < WIDTH && pixel_is_white(x, y) {
                    word |= 1 << bit;
                }
            }
            fb_write(y * WORDS_PER_LINE + w, word);
        }
    }
    let start = crate::timer::now_ms();
    csr::write(reg::MEMLCD_COMMAND, CMD_UPDATE_ALL);
    // The block raises Busy a cycle or two after the command; give it a moment so the
    // wait below does not see the idle state from before the command.
    let settle = crate::timer::now_ms() + 2;
    while crate::timer::now_ms() < settle {}
    wait_idle()?;
    Ok(crate::timer::now_ms() - start)
}

fn pixel_is_white(x: usize, y: usize) -> bool {
    let frame = x < 4 || y < 4 || x >= WIDTH - 4 || y >= HEIGHT - 4;
    let triangle = x >= 12 && y >= 12 && (x - 12) + (y - 12) < 80;
    let checker = x >= WIDTH - 92
        && y >= HEIGHT - 92
        && x < WIDTH - 12
        && y < HEIGHT - 12
        && ((x / 8) + (y / 8)).is_multiple_of(2);
    !(frame || triangle || checker)
}
