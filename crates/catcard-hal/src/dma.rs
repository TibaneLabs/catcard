//! A circular memory-to-peripheral DMA channel on the STM32L4+ (DMA1 through DMAMUX1).
//!
//! For feeding a peripheral while the CPU is somewhere it cannot come back from -- inside
//! a bootloader callgate, with interrupts masked. The channel runs a buffer round and
//! round into the peripheral's data register at the pace of the peripheral's own
//! requests, and nothing else happens: no interrupts are enabled, so nothing trips the
//! firewall.
//!
//! Only DMA1, only byte-wide, only memory-to-peripheral: the one shape that has a user.
//!
//! # Register facts
//!
//! - DMA1 at `0x4002_0000`, the channel ("BDMA") kind: `ISR` +0x00, `IFCR` +0x04, then
//!   one block per channel at `+0x08 + 20 * (n - 1)` holding `CCR` +0, `CNDTR` +4,
//!   `CPAR` +8, `CMAR` +0xC. `CCR`: EN 0, TCIE 1, HTIE 2, TEIE 3, DIR 4, CIRC 5, PINC 6,
//!   MINC 7, PSIZE 8-9, MSIZE 10-11, PL 12-13, MEM2MEM 14.
//! - DMAMUX1 at `0x4002_0800`: one `CxCR` per mux channel at `4 * c`, `DMAREQ_ID` in
//!   bits 0-7. DMA1 channel `n` is DMAMUX1 channel `n - 1`.
//! - `RCC_AHB1ENR` at `RCC + 0x48`: DMA1EN bit 0, DMAMUX1EN bit 2.
//!
//! Source: embassy `stm32-data-generated` (MIT/Apache-2.0), chip `STM32L4S5VI` and
//! register files `bdma_v1`, `dmamux_v1`, `rcc_l4plus` -- generated from ST's own
//! descriptions; RM0432 §11 (DMA), §12 (DMAMUX), §6.4 (RCC) [C]

use crate::reg;

const DMA1: u32 = 0x4002_0000;
const DMAMUX1: u32 = 0x4002_0800;
const RCC_AHB1ENR: u32 = catcard_board::memory::fixed::RCC + 0x48;
const AHB1ENR_DMA1EN: u32 = 1 << 0;
const AHB1ENR_DMAMUX1EN: u32 = 1 << 2;

const IFCR: u32 = 0x04;
const CCR_EN: u32 = 1 << 0;
/// Read from memory, write to the peripheral.
const CCR_DIR_MEM_TO_PERIPH: u32 = 1 << 4;
const CCR_CIRC: u32 = 1 << 5;
const CCR_MINC: u32 = 1 << 7;
// PSIZE and MSIZE left at 0b00: byte transfers on both sides.

/// Most transfers one run can hold: `CNDTR` is 16 bits.
pub const MAX_LEN: usize = 0xFFFF;

/// Why a channel was not started.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Channels are numbered 1 to 7.
    NoSuchChannel,
    /// Empty, or longer than `CNDTR` counts.
    Length,
}

/// A DMA1 channel running a buffer round into a peripheral. Stop it with [`stop`].
#[derive(Debug)]
pub struct Circular {
    channel: u8,
}

fn ch_base(channel: u8) -> u32 {
    DMA1 + 0x08 + 20 * (channel as u32 - 1)
}

/// Start DMA1 channel `channel` sending `mem` to the byte register at `periph`, over and
/// over, one byte per request from DMAMUX1 input `request`.
///
/// # Safety
///
/// - `mem` must stay valid and unchanged until [`stop`]: the channel reads it with no
///   borrow the compiler can see.
/// - Nothing else may use this channel or its DMAMUX channel meanwhile.
/// - `periph` must be a peripheral data register that accepts byte writes, and the
///   peripheral must be set to raise `request` -- or the channel simply never moves.
pub unsafe fn start(channel: u8, request: u8, periph: u32, mem: &[u8]) -> Result<Circular, Error> {
    if !(1..=7).contains(&channel) {
        return Err(Error::NoSuchChannel);
    }
    if mem.is_empty() || mem.len() > MAX_LEN {
        return Err(Error::Length);
    }
    let ch = ch_base(channel);
    let mux = DMAMUX1 + 4 * (channel as u32 - 1);
    // SAFETY: the documented clock gates and this channel's own registers, which the
    // caller has promised nobody else is using.
    unsafe {
        reg::set_bits(RCC_AHB1ENR, AHB1ENR_DMA1EN | AHB1ENR_DMAMUX1EN);
        let _ = reg::read(RCC_AHB1ENR); // let the gate settle
        // Configuration only takes with the channel off.
        reg::write(ch, 0);
        reg::write(mux, request as u32);
        // Clear the channel's four flags, so nothing stale reads as an error.
        reg::write(DMA1 + IFCR, 0xF << (4 * (channel as u32 - 1)));
        reg::write(ch + 0x8, periph);
        reg::write(ch + 0xC, mem.as_ptr() as u32);
        reg::write(ch + 0x4, mem.len() as u32);
        // No interrupt enables: this runs while the CPU is inside a callgate whose
        // firewall resets the part if an interrupt lands.
        reg::write(ch, CCR_DIR_MEM_TO_PERIPH | CCR_CIRC | CCR_MINC | CCR_EN);
    }
    Ok(Circular { channel })
}

/// Stop the channel and release its DMAMUX input.
///
/// A byte already fetched still reaches the peripheral; the caller drains the peripheral
/// afterwards if that matters.
pub fn stop(run: Circular) {
    let ch = ch_base(run.channel);
    let mux = DMAMUX1 + 4 * (run.channel as u32 - 1);
    // SAFETY: this channel's registers, which `run` is the proof of owning.
    unsafe {
        reg::clear_bits(ch, CCR_EN);
        reg::write(mux, 0);
        reg::write(DMA1 + IFCR, 0xF << (4 * (run.channel as u32 - 1)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_seven_is_where_the_reference_puts_it() {
        assert_eq!(ch_base(1), 0x4002_0008);
        assert_eq!(ch_base(7), 0x4002_0080);
    }
}
