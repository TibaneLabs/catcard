//! The SDMMC controller, enough of it to read a card.
//!
//! This is the half of SD support that needs silicon. The conversation with the card —
//! CMD0, CMD8, ACMD41, CID, RCA, CSD — lives in `catcard-sd` and runs on a host against
//! a fake; what is here is the peripheral underneath it.
//!
//! **None of this has been exercised.** The emulator models SDMMC's command registers
//! and stops there: a probe of every offset from `0x00` to `0xFC` came back named only
//! through `MASK` at `0x3C`, with no FIFO and no data path. So unlike the USB driver,
//! which was wrong in four ways that register read-backs caught, this one meets its
//! first real card on hardware.
//!
//! That shapes it. Every enable is written **and read back**, every wait is bounded, and
//! a failure returns a reason rather than hanging — because the alternative, learned
//! from `PWR_CR2.USV`, is a peripheral that looks initialised and is connected to
//! nothing. `Debug → microSD` puts `STA` on the screen for the same reason.
//!
//! Sources: the register block is named by generation in RM0351 §SDMMC (L4) and RM0432
//! §SDMMC (L4+); the offsets below were cross-checked against an independent
//! implementation, which names `0x00 POWER, 0x04 CLKCR, 0x08 ARG, 0x0C CMD, 0x10
//! RESPCMD, 0x14..0x20 RESP1-4, 0x24 DTIMER, 0x28 DLEN, 0x2C DCTRL, 0x30 DCOUNT,
//! 0x34 STA, 0x38 ICR, 0x3C MASK` at both the L4 and L4+ base addresses. `[I]`

use catcard_board::{BoardSpec, Mcu};
use catcard_sd::{Error, Response, Transport, BLOCK_LEN};

use crate::reg;

/// Base of SDMMC1, which moved between generations.
///
/// `0x4001_2800` on the L496 (APB2) and `0x5006_2400` on the L4+ (AHB2), the latter
/// sitting in the same `0x5006_xxxx` block as the RNG, HASH and AES the reference
/// already places there. `[I]`
///
/// Takes the board rather than reading a global, like every other driver here: this
/// crate has no board of its own, and host builds of it select none.
const fn base(mcu: Mcu) -> u32 {
    match mcu {
        Mcu::Stm32L4S5 => 0x5006_2400,
        _ => 0x4001_2800,
    }
}

const POWER: u32 = 0x00;
const CLKCR: u32 = 0x04;
const ARG: u32 = 0x08;
const CMD: u32 = 0x0C;
const RESP1: u32 = 0x14;
const DTIMER: u32 = 0x24;
const DLEN: u32 = 0x28;
const DCTRL: u32 = 0x2C;
const STA: u32 = 0x34;
const ICR: u32 = 0x38;
/// Receive FIFO. Outside the range the emulator names, so this offset rests on the
/// reference manual alone. `[?]` — see `docs/HARDWARE-OPEN-ITEMS.md`.
const FIFO: u32 = 0x80;

/// `PWRCTRL[1:0] = 11`: the card is powered and the clock may run.
const POWER_ON: u32 = 0b11;

/// `CPSMEN`, start the command state machine.
const CMD_CPSMEN: u32 = 1 << 12;
/// `WAITRESP[1:0]` at bits 9:8.
const CMD_WAITRESP_SHORT: u32 = 0b01 << 8;
const CMD_WAITRESP_LONG: u32 = 0b11 << 8;
/// `CMDTRANS`, set when the command is followed by a data transfer. Present on the L4+
/// controller and ignored by the older one, which starts the data path from `DCTRL`
/// alone — so setting it on both is right for one and harmless for the other. `[I]`
const CMD_CMDTRANS: u32 = 1 << 6;

/// `STA` bits, in the order the reference lists them.
const STA_CCRCFAIL: u32 = 1 << 0;
const STA_DCRCFAIL: u32 = 1 << 1;
const STA_CTIMEOUT: u32 = 1 << 2;
const STA_DTIMEOUT: u32 = 1 << 3;
const STA_RXOVERR: u32 = 1 << 5;
const STA_CMDREND: u32 = 1 << 6;
const STA_CMDSENT: u32 = 1 << 7;
const STA_DATAEND: u32 = 1 << 8;
const STA_RXFIFOHF: u32 = 1 << 15;
const STA_RXDAVL: u32 = 1 << 21;
const STA_TXUNDERR: u32 = 1 << 4;
const STA_TXFIFOF: u32 = 1 << 16;

/// Everything write-one-to-clear, for wiping the slate before each command.
const ICR_ALL: u32 = 0x1FE0_0FFF;

/// `DCTRL`: enable, card-to-host direction, and a block size of 2^9 = 512.
const DCTRL_DTEN: u32 = 1 << 0;
const DCTRL_DTDIR_CARD_TO_HOST: u32 = 1 << 1;
const DCTRL_BLOCK_512: u32 = 9 << 4;

/// Polls before a command is called lost.
///
/// A count rather than a duration: there is no timer here, and the card's own timeout is
/// the one that matters. Generous, because a card may legitimately take milliseconds.
const CMD_TRIES: u32 = 200_000;
/// Polls waiting for data. Larger: a whole block has to arrive.
const DATA_TRIES: u32 = 2_000_000;

/// Identification-mode clock: 400 kHz or under, from the 48 MHz kernel clock.
///
/// `SDMMC_CK = kernel / (2 * CLKDIV)` on the older controller and `kernel / (2 *
/// CLKDIV)` on the L4+ one as well, so 48 MHz / (2 * 60) = 400 kHz. Cards are required
/// to accept 400 kHz or less until they are out of identification mode. `[I]`
const CLKDIV_SLOW: u32 = 60;
/// Transfer clock once the card is addressed: 48 / (2 * 2) = 12 MHz, well inside the
/// 25 MHz every card must accept, and slow enough not to depend on board trace lengths
/// that have never been measured.
const CLKDIV_FAST: u32 = 2;
/// `WIDBUS[1:0]` at 15:14 — `01` is four-bit.
const CLKCR_WIDBUS_4: u32 = 0b01 << 14;
/// Keep the clock running; the power-saving mode stops it between transfers and a card
/// that loses its clock mid-conversation has to be brought up again.
const CLKCR_CLKDIV_MASK: u32 = 0x3FF;

/// The SDMMC controller, as `catcard-sd`'s [`Transport`].
pub struct Sdmmc {
    base: u32,
    /// Whether the slot reports a card. Latched at init; `card_present` reports it.
    present: bool,
    wide: bool,
}

impl Sdmmc {
    /// Bring the controller up. Does not talk to the card — `catcard_sd::init` does.
    ///
    /// # Safety
    /// Claims SDMMC1 and its pins. Call once.
    pub unsafe fn init(spec: &BoardSpec) -> Result<Self, Error> {
        let b = base(spec.mcu);
        // SAFETY: as documented.
        unsafe {
            enable_clock(spec.mcu)?;
            configure_pins(spec);

            reg::write(b + POWER, POWER_ON);
            // Read back: an unclocked peripheral swallows writes silently, which is the
            // failure that cost a hardware round trip on USB.
            if reg::read(b + POWER) & POWER_ON != POWER_ON {
                return Err(Error::Peripheral);
            }

            reg::write(b + CLKCR, CLKDIV_SLOW & CLKCR_CLKDIV_MASK);
            reg::write(b + DTIMER, u32::MAX);
            reg::write(b + ICR, ICR_ALL);
        }

        Ok(Self {
            base: b,
            present: card_detect(spec),
            wide: false,
        })
    }

    /// `STA`, for the debug screen. Reading it changes nothing.
    pub fn status(&self) -> u32 {
        // SAFETY: a read of a peripheral this type owns.
        unsafe { reg::read(self.base + STA) }
    }
}

impl Transport for Sdmmc {
    fn command(&mut self, cmd: u8, arg: u32, resp: Response) -> Result<[u32; 4], Error> {
        let b = self.base;
        // SAFETY: this type owns SDMMC1 for its lifetime.
        unsafe {
            reg::write(b + ICR, ICR_ALL);
            reg::write(b + ARG, arg);

            let wait = match resp {
                Response::None => 0,
                Response::Short => CMD_WAITRESP_SHORT,
                Response::Long => CMD_WAITRESP_LONG,
            };
            // CMD17 and CMD24 are the commands here followed by a data phase, and their
            // data path is armed before this call.
            let trans = if cmd == 17 || cmd == 24 {
                CMD_CMDTRANS
            } else {
                0
            };
            reg::write(b + CMD, u32::from(cmd) | wait | trans | CMD_CPSMEN);

            // Done is either "response arrived" or, for a command with no response,
            // "command went out". Waiting for the wrong one hangs on every CMD0.
            let done = match resp {
                Response::None => STA_CMDSENT,
                _ => STA_CMDREND,
            };
            let mut tries = 0;
            loop {
                let sta = reg::read(b + STA);
                if sta & done != 0 {
                    break;
                }
                if sta & STA_CTIMEOUT != 0 {
                    reg::write(b + ICR, ICR_ALL);
                    return Err(Error::Timeout { cmd });
                }
                // A CRC failure on a response is still a response: some commands answer
                // with a deliberately wrong CRC, and the card layer decides.
                if sta & STA_CCRCFAIL != 0 {
                    break;
                }
                tries += 1;
                if tries >= CMD_TRIES {
                    return Err(Error::Timeout { cmd });
                }
            }

            let mut out = [0u32; 4];
            if !matches!(resp, Response::None) {
                for (i, word) in out.iter_mut().enumerate() {
                    *word = reg::read(b + RESP1 + 4 * i as u32);
                }
            }
            reg::write(b + ICR, ICR_ALL);
            Ok(out)
        }
    }

    fn read_data(&mut self, out: &mut [u8; BLOCK_LEN]) -> Result<(), Error> {
        let b = self.base;
        // SAFETY: as above.
        unsafe {
            let mut at = 0usize;
            let mut tries = 0u32;
            loop {
                let sta = reg::read(b + STA);
                if sta & (STA_DCRCFAIL | STA_DTIMEOUT | STA_RXOVERR) != 0 {
                    reg::write(b + ICR, ICR_ALL);
                    return Err(Error::DataError { block: u32::MAX });
                }
                // Drain whatever is there, a word at a time. `RXDAVL` rather than only
                // the half-full flag, or the tail of a block is left behind when fewer
                // than eight words remain.
                while (sta & STA_RXDAVL != 0 || sta & STA_RXFIFOHF != 0) && at < BLOCK_LEN {
                    let w = reg::read(b + FIFO).to_le_bytes();
                    let n = w.len().min(BLOCK_LEN - at);
                    out[at..at + n].copy_from_slice(&w[..n]);
                    at += n;
                    if reg::read(b + STA) & STA_RXDAVL == 0 {
                        break;
                    }
                }
                if at >= BLOCK_LEN {
                    break;
                }
                if sta & STA_DATAEND != 0 && at == 0 {
                    reg::write(b + ICR, ICR_ALL);
                    return Err(Error::DataError { block: u32::MAX });
                }
                tries += 1;
                if tries >= DATA_TRIES {
                    reg::write(b + ICR, ICR_ALL);
                    return Err(Error::DataError { block: u32::MAX });
                }
            }
            reg::write(b + ICR, ICR_ALL);
        }
        Ok(())
    }

    fn write_data(&mut self, data: &[u8; BLOCK_LEN]) -> Result<(), Error> {
        let b = self.base;
        // SAFETY: this type owns SDMMC1 for its lifetime.
        unsafe {
            let mut at = 0usize;
            let mut tries = 0u32;
            // Feed the FIFO until the block is in it, a word at a time while there is
            // room. `BLOCK_LEN` is a multiple of four, so there is no trailing partial
            // word to special-case.
            while at < BLOCK_LEN {
                let sta = reg::read(b + STA);
                if sta & (STA_DCRCFAIL | STA_DTIMEOUT | STA_TXUNDERR) != 0 {
                    reg::write(b + ICR, ICR_ALL);
                    return Err(Error::DataError { block: u32::MAX });
                }
                while reg::read(b + STA) & STA_TXFIFOF == 0 && at < BLOCK_LEN {
                    let w = [data[at], data[at + 1], data[at + 2], data[at + 3]];
                    reg::write(b + FIFO, u32::from_le_bytes(w));
                    at += 4;
                }
                tries += 1;
                if tries >= DATA_TRIES {
                    reg::write(b + ICR, ICR_ALL);
                    return Err(Error::DataError { block: u32::MAX });
                }
            }
            // The block is queued; the card still has to program it. `DATAEND` is that,
            // and a CRC or underrun in the meantime is the card rejecting what it got.
            let mut tries = 0u32;
            loop {
                let sta = reg::read(b + STA);
                if sta & (STA_DCRCFAIL | STA_DTIMEOUT | STA_TXUNDERR) != 0 {
                    reg::write(b + ICR, ICR_ALL);
                    return Err(Error::DataError { block: u32::MAX });
                }
                if sta & STA_DATAEND != 0 {
                    break;
                }
                tries += 1;
                if tries >= DATA_TRIES {
                    reg::write(b + ICR, ICR_ALL);
                    return Err(Error::DataError { block: u32::MAX });
                }
            }
            reg::write(b + ICR, ICR_ALL);
        }
        Ok(())
    }

    fn set_bus_width_4(&mut self) -> Result<(), Error> {
        // ACMD6 tells the card; CLKCR tells the controller. Both, in that order, or the
        // two disagree about how many lines carry the next block.
        self.command(55, 0, Response::Short)?;
        self.command(6, 2, Response::Short)?;
        // SAFETY: this type owns SDMMC1.
        unsafe {
            reg::modify(self.base + CLKCR, 0, CLKCR_WIDBUS_4);
        }
        self.wide = true;
        Ok(())
    }

    fn set_fast_clock(&mut self) {
        // SAFETY: as above.
        unsafe {
            reg::modify(self.base + CLKCR, CLKCR_CLKDIV_MASK, CLKDIV_FAST);
        }
    }

    fn card_present(&self) -> bool {
        self.present
    }

    fn arm_block_read(&mut self) {
        // SAFETY: this type owns SDMMC1.
        unsafe { arm_block_read(self.base) }
    }

    fn arm_block_write(&mut self) {
        // SAFETY: this type owns SDMMC1.
        unsafe { arm_block_write(self.base) }
    }
}

/// Arm the data path for one block, before the read command goes out.
///
/// Separate from `read_data` because the order matters: the controller has to be waiting
/// before the card is asked, or the first words arrive with nowhere to go.
///
/// # Safety
/// Caller owns SDMMC1.
pub unsafe fn arm_block_read(b: u32) {
    // SAFETY: as documented.
    unsafe {
        reg::write(b + DLEN, BLOCK_LEN as u32);
        reg::write(
            b + DCTRL,
            DCTRL_DTEN | DCTRL_DTDIR_CARD_TO_HOST | DCTRL_BLOCK_512,
        );
    }
}

/// Arm the data path for one outgoing block, before the write command goes out.
///
/// The mirror of [`arm_block_read`], with the direction bit clear: `DTDIR = 0` is
/// host-to-card. Same ordering reason -- the controller has to be waiting before the
/// card is told to expect the block.
///
/// # Safety
/// Caller owns SDMMC1.
pub unsafe fn arm_block_write(b: u32) {
    // SAFETY: as documented.
    unsafe {
        reg::write(b + DLEN, BLOCK_LEN as u32);
        reg::write(b + DCTRL, DCTRL_DTEN | DCTRL_BLOCK_512);
    }
}

/// Whether the slot reports a card, where the board has a pin for it.
fn card_detect(spec: &BoardSpec) -> bool {
    let Some(pin) = spec.sdmmc.card_detect else {
        // No pin: assume a card and let the conversation fail if there is none. Better
        // than refusing to look on a board whose detect line we never confirmed.
        return true;
    };
    // SAFETY: reads one GPIO; `enable_port` is idempotent.
    unsafe {
        crate::gpio::enable_port(pin.port);
        crate::gpio::configure(
            pin,
            crate::gpio::Mode::Input,
            crate::gpio::OutputType::PushPull,
            crate::gpio::Pull::Up,
            crate::gpio::Speed::Low,
        );
        crate::dwt::delay_cycles(1_000);
        // mk3's `SD_SW` reads **high** when a card is present. The mk4/Q1 lines are not
        // documented either way, so their polarity is assumed to match rather than
        // guessed at separately -- see docs/HARDWARE-OPEN-ITEMS.md.
        crate::gpio::read(pin)
    }
}

/// Clock gate for SDMMC1, verified.
///
/// # Safety
/// Writes RCC.
unsafe fn enable_clock(mcu: Mcu) -> Result<(), Error> {
    const RCC_AHB2ENR: u32 = catcard_board::memory::fixed::RCC + 0x4C;
    const RCC_APB2ENR: u32 = catcard_board::memory::fixed::RCC + 0x60;
    /// `SDMMC1EN`. On the L4+ the controller sits on AHB2 beside the RNG; on the L496 it
    /// is an APB2 peripheral. Both bit positions are `[?]` — they are read back below,
    /// so a wrong one is an error on screen rather than a peripheral that never answers.
    const AHB2ENR_SDMMC1EN: u32 = 1 << 22;
    const APB2ENR_SDMMC1EN: u32 = 1 << 10;

    let (r, bit) = match mcu {
        Mcu::Stm32L4S5 => (RCC_AHB2ENR, AHB2ENR_SDMMC1EN),
        _ => (RCC_APB2ENR, APB2ENR_SDMMC1EN),
    };
    // SAFETY: as documented.
    unsafe {
        reg::set_bits(r, bit);
        let _ = reg::read(r);
        if reg::read(r) & bit == 0 {
            return Err(Error::Peripheral);
        }
    }
    Ok(())
}

/// The six pins, all on AF12.
///
/// Source: `hw-reference/gpio-peripherals.md` §Bus instance summary [C] for the pins;
/// AF12 is the SDMMC function on these parts `[I]`.
///
/// # Safety
/// Claims the pins named by `BoardSpec::sdmmc`.
unsafe fn configure_pins(spec: &BoardSpec) {
    use crate::gpio::{set_alternate, OutputType, Pull, Speed};
    const AF_SDMMC: u8 = 12;
    let s = spec.sdmmc;
    // SAFETY: as documented.
    unsafe {
        for p in [s.d0, s.d1, s.d2, s.d3, s.cmd, s.ck] {
            crate::gpio::enable_port(p.port);
            // Pull-ups on data and command, as the bus expects; the clock is driven.
            let pull = if p.num == s.ck.num && p.port as u8 == s.ck.port as u8 {
                Pull::None
            } else {
                Pull::Up
            };
            set_alternate(p, AF_SDMMC, OutputType::PushPull, pull, Speed::VeryHigh);
        }
    }
}
