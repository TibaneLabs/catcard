//! The Q1's GPU co-processor: the one thing on this board that can animate the screen while
//! the CPU is stuck in a callgate call.
//!
//! A small STM32C011 shares the LCD's SPI bus. Told to show its activity bar and handed the
//! bus, it draws a 5-row strip of moving stripes along the bottom of the panel on every
//! tear pulse, by itself -- the Q1's equivalent of the OLED's hardware scroll.
//!
//! It can also blink a text cursor. The PIN screen does not ask it to: what it draws is a
//! filled cell of its own 9x22 grid in a colour of its own choosing, which is neither the
//! size nor the colour of a caret, and a caret the firmware draws costs only the rows it
//! changes. Its firmware update is not used either.
//!
//! This module only speaks to it over I²C1. Handing the SPI bus over and taking it back is
//! the display's business, in [`crate::display`].
//!
//! A co-processor that does not answer is not an error anyone sees: stock treats it the
//! same way, and the screen simply has no bar.
//!
//! Source: hw-reference/gpu.md "App protocol @0x65", "Probe / absent behaviour" [C]

use catcard_board::BOARD;
use catcard_hal::gpio::{self, Mode, OutputType, Pull, Speed};
use catcard_hal::softi2c::{GpioLines, SoftI2c};

/// The co-processor's application firmware. `0x64` is its ROM bootloader, never used here.
/// Source: gpu.md [C]
const APP_ADDR: u8 = 0x65;

/// Opcodes. Source: gpu.md opcode table [C]
const OP_VERSION: u8 = b'v';
const OP_ACTIVITY_BAR: u8 = b'a';

/// How many bytes a version read takes. The reply is shorter and padded with `0xFF`, which
/// is also what an app still starting returns. Source: gpu.md "`"1.3.3"\0` (read 20)" [C]
const VERSION_LEN: usize = 20;

/// Version polls after releasing reset, 10 ms apart: half a second for the part to boot.
const BOOT_POLLS: u32 = 50;

#[derive(Copy, Clone, PartialEq, Eq)]
enum State {
    Unknown,
    Absent,
    Ready,
}

/// What the probe found. Foreground only, single core.
static mut STATE: State = State::Unknown;

fn bus() -> Option<SoftI2c<GpioLines>> {
    let nfc = BOARD.nfc?;
    // SAFETY: I²C1's two pins; nothing else in this firmware drives them.
    Some(SoftI2c::new(unsafe { GpioLines::new(nfc.scl, nfc.sda?) }))
}

/// Release the co-processor from reset and wait for its application to answer.
fn probe() -> bool {
    let Some(reset) = BOARD.gpu_reset else {
        return false;
    };
    let Some(mut i2c) = bus() else {
        return false;
    };
    // SAFETY: `G_RESET` belongs to the co-processor alone. Open-drain with a pull-up, as
    // the reference has it: released is high. Source: gpu.md [C]
    unsafe {
        gpio::enable_port(reset.port);
        gpio::write(reset, true);
        gpio::configure(
            reset,
            Mode::Output,
            OutputType::OpenDrain,
            Pull::Up,
            Speed::Low,
        );
    }
    let mut reply = [0u8; VERSION_LEN];
    for _ in 0..BOOT_POLLS {
        // SAFETY: reads RCC only.
        unsafe { catcard_hal::dwt::delay_ms(10) };
        if i2c.write(APP_ADDR, &[OP_VERSION]).is_err() {
            continue;
        }
        reply.fill(0xFF);
        if i2c.read(APP_ADDR, &mut reply).is_err() || reply[0] == 0xFF {
            continue;
        }
        let len = reply
            .iter()
            .position(|&b| b == 0 || b == 0xFF)
            .unwrap_or(VERSION_LEN);
        crate::catlog!(
            "gpu: version {}",
            core::str::from_utf8(&reply[..len]).unwrap_or("?")
        );
        return true;
    }
    crate::catlog!("gpu: no answer at 0x{:02x}; no activity bar", APP_ADDR);
    false
}

/// Have the co-processor show its activity bar the next time it is given the bus.
///
/// Probes on first use. False if it is absent or did not take the command, in which case
/// the bus must stay with the CPU -- there is nothing to hand it to.
pub fn activity_bar() -> bool {
    send(&[OP_ACTIVITY_BAR], "activity bar")
}

/// One command to the co-processor, probing first. False if it is not there.
fn send(cmd: &[u8], what: &str) -> bool {
    // SAFETY: foreground only, single core.
    let state = unsafe { &mut *core::ptr::addr_of_mut!(STATE) };
    if *state == State::Unknown {
        *state = if probe() { State::Ready } else { State::Absent };
    }
    if *state != State::Ready {
        return false;
    }
    let Some(mut i2c) = bus() else {
        return false;
    };
    match i2c.write(APP_ADDR, cmd) {
        Ok(()) => true,
        Err(e) => {
            crate::catlog!("gpu: {} refused: {:?}", what, e);
            false
        }
    }
}
