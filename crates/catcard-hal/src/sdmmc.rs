//! The SDMMC controller, enough of it to read a card.
//!
//! This is the half of SD support that needs silicon. The conversation with the card —
//! CMD0, CMD8, ACMD41, CID, RCA, CSD — lives in `catcard-sd` and runs on a host against
//! a fake; what is here is the peripheral underneath it.
//!
//! **It was written blind, then proven on hardware.** The emulator models SDMMC's command
//! registers and stops there: a probe of every offset from `0x00` to `0xFC` came back
//! named only through `MASK` at `0x3C`, with no FIFO and no data path. So this driver was
//! first written against a fake that could not exercise the data path at all — but it has
//! since read and written real cards on hardware.
//!
//! That origin still shapes it, and the discipline earns its keep against a bad card
//! rather than a bug: every enable is written **and read back**, every wait is bounded,
//! and a failure returns a reason rather than hanging — because the alternative, learned
//! from `PWR_CR2.USV`, is a peripheral that looks initialised and is connected to
//! nothing. `Debug → microSD` puts `STA` on the screen for the same reason.
//!
//! Sources: the register block is named by generation in RM0351 §SDMMC (L4) and RM0432
//! §SDMMC (L4+); the offsets below were cross-checked against an independent
//! implementation, which names `0x00 POWER, 0x04 CLKCR, 0x08 ARG, 0x0C CMD, 0x10
//! RESPCMD, 0x14..0x20 RESP1-4, 0x24 DTIMER, 0x28 DLEN, 0x2C DCTRL, 0x30 DCOUNT,
//! 0x34 STA, 0x38 ICR, 0x3C MASK` at both the L4 and L4+ base addresses. `[I]`

use catcard_board::{BoardSpec, Mcu};
use catcard_sd::{BLOCK_LEN, Error, Response, Transport};

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
const DCOUNT: u32 = 0x30;
const STA: u32 = 0x34;
const ICR: u32 = 0x38;
/// Receive FIFO. Outside the range the emulator names, so this offset rests on the
/// reference manual alone. `[?]` — see `docs/HARDWARE-OPEN-ITEMS.md`.
const FIFO: u32 = 0x80;

/// `PWRCTRL[1:0] = 11`: the card is powered and the clock may run.
const POWER_ON: u32 = 0b11;

/// The bits that sit in different places on the two SDMMC controllers.
///
/// The register *offsets* are the same on the L4 (mk3) and the L4+ (mk4/mk5/Q1), which is
/// what made it easy to believe the *bits* were too. They are not, and on the mk3 that was
/// a card slot that never worked: `CPSMEN` written at the L4+ position never started the
/// command state machine, and without `CLKEN` the card never saw a clock, so CMD0 timed
/// out before anything reached the card. Confirmed on a live mk3 by poking the L4 layout
/// in by hand -- CMD0 then reports `CMDSENT`, and CMD8 comes back with `CMDREND` and the
/// `0x1AA` check pattern echoed.
///
/// Source: RM0351 §SDMMC register descriptions (L4) [C], verified on hardware as above;
/// RM0432 §SDMMC (L4+) [C].
#[derive(Copy, Clone)]
struct Bits {
    /// `CMD.CPSMEN`: start the command state machine.
    cpsmen: u32,
    /// `CMD.WAITRESP[1:0]`'s low bit.
    waitresp_shift: u32,
    /// `CMD.CMDTRANS`, on the controller that has it. On the L4 bit 6 is `WAITRESP`, so
    /// setting this there would ask for a response instead of starting a transfer.
    cmdtrans: u32,
    /// `CLKCR.CLKEN`: the L4 gates `SDMMC_CK` with it; the L4+ has no such bit.
    clken: u32,
    clkdiv_mask: u32,
    /// `CLKCR.WIDBUS = 01`, four-bit.
    widbus_4: u32,
    /// Every static flag `ICR` can clear.
    icr_all: u32,
    /// Identification clock, 400 kHz from 48 MHz: `48 / (DIV + 2)` on the L4, `48 / (2 *
    /// DIV)` on the L4+.
    div_slow: u32,
    /// Transfer clock, 12 MHz by either formula.
    div_fast: u32,
}

/// The L4's controller (mk3).
const BITS_L4: Bits = Bits {
    cpsmen: 1 << 10,
    waitresp_shift: 6,
    cmdtrans: 0,
    clken: 1 << 8,
    clkdiv_mask: 0xFF,
    widbus_4: 0b01 << 11,
    icr_all: 0x5FF,
    div_slow: 118,
    div_fast: 2,
};

/// The L4+'s controller (mk4, mk5, Q1).
const BITS_L4PLUS: Bits = Bits {
    cpsmen: 1 << 12,
    waitresp_shift: 8,
    cmdtrans: 1 << 6,
    clken: 0,
    clkdiv_mask: 0x3FF,
    widbus_4: 0b01 << 14,
    icr_all: 0x1FE0_0FFF,
    div_slow: 60,
    div_fast: 2,
};

/// `STA` bits, in the order the reference lists them.
const STA_CCRCFAIL: u32 = 1 << 0;
const STA_DCRCFAIL: u32 = 1 << 1;
const STA_CTIMEOUT: u32 = 1 << 2;
const STA_DTIMEOUT: u32 = 1 << 3;
const STA_RXOVERR: u32 = 1 << 5;
const STA_CMDREND: u32 = 1 << 6;
const STA_CMDSENT: u32 = 1 << 7;
const STA_DATAEND: u32 = 1 << 8;
/// `RXFIFOE`: the receive FIFO is empty. Its complement is the reliable "a word is
/// waiting" test on both controllers -- `RXDAVL`/`RXFIFOHF` leave the last few words of
/// a block unread on the L4+ IP, which stalls the data path with the FIFO half-full.
const STA_RXFIFOE: u32 = 1 << 19;
const STA_TXUNDERR: u32 = 1 << 4;
/// `TXFIFOHE`: the transmit FIFO is at least half empty, i.e. has room for a burst of
/// eight words. Filling a word at a time against `TXFIFOF` (full) races on the L4+ IP
/// and drops words -- the write mirror of the receive-drain bug.
const STA_TXFIFOHE: u32 = 1 << 14;

/// `DCTRL`: enable, card-to-host direction, and a block size of 2^9 = 512.
/// The command's own flags in `ICR`: response CRC, response timeout, response received,
/// command sent. Same four bits on both IPs.
///
/// Clearing *only* these after a response is what lets the data phase keep its own flags:
/// the data path of a CMD17 is already running while the response is read, and a block that
/// finishes quickly sets `DATAEND` before then. Clearing everything wiped it, and the read
/// then waited for an end that had already happened and could not come again.
const ICR_CMD: u32 = STA_CCRCFAIL | STA_CTIMEOUT | STA_CMDREND | STA_CMDSENT;

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
/// Polls waiting for a finished transfer to say so, once its bytes are already read.
///
/// Short on purpose: it is paid on every block of every read, and the bytes are in hand
/// whatever the flag does. A block is 512 bytes at 12 MHz on four lines -- about 85 us --
/// so a transfer that has delivered everything is at its end already.
const END_POLLS: u32 = 10_000;

/// Where the last data-path or command failure happened, what `STA` read at that moment
/// (before `ICR` cleared it) and what `DCOUNT` still expected -- or, for a command, which
/// command. The error types above say only "timeout" or "data error"; this is what tells an
/// underrun from a CRC rejection from a card that never answered.
///
/// Statics, not fields: the transport is buried inside a mounted volume by the time a write
/// fails, and the firmware reads this afterwards to log it. Single-threaded use only.
pub mod last_failure {
    use core::sync::atomic::{AtomicU32, Ordering};

    static PHASE: AtomicU32 = AtomicU32::new(0);
    static STA: AtomicU32 = AtomicU32::new(0);
    static DETAIL: AtomicU32 = AtomicU32::new(0);

    /// Command timed out (`CTIMEOUT`); detail is the command index.
    pub const CMD_TIMEOUT: u32 = 1;
    /// No response flag within the poll budget; detail is the command index.
    pub const CMD_NO_ANSWER: u32 = 2;
    /// Error flag while receiving; detail is `DCOUNT`.
    pub const READ_ERROR: u32 = 3;
    /// Receive never completed; detail is `DCOUNT`.
    pub const READ_STALLED: u32 = 4;
    /// Error flag while filling the transmit FIFO; detail is `DCOUNT`.
    pub const WRITE_FILL_ERROR: u32 = 5;
    /// The FIFO never had room within the poll budget; detail is `DCOUNT`.
    pub const WRITE_FILL_STALLED: u32 = 6;
    /// Error flag while waiting for the card to finish the block; detail is `DCOUNT`.
    pub const WRITE_END_ERROR: u32 = 7;
    /// `DATAEND` never came; detail is `DCOUNT`.
    pub const WRITE_END_STALLED: u32 = 8;

    pub(super) fn record(phase: u32, sta: u32, detail: u32) {
        PHASE.store(phase, Ordering::Relaxed);
        STA.store(sta, Ordering::Relaxed);
        DETAIL.store(detail, Ordering::Relaxed);
    }

    /// `(phase, sta, detail)` of the most recent failure, phase 0 if none since power-up.
    pub fn get() -> (u32, u32, u32) {
        (
            PHASE.load(Ordering::Relaxed),
            STA.load(Ordering::Relaxed),
            DETAIL.load(Ordering::Relaxed),
        )
    }

    /// A short name for a phase.
    pub fn name(phase: u32) -> &'static str {
        match phase {
            0 => "none",
            CMD_TIMEOUT => "cmd timeout",
            CMD_NO_ANSWER => "cmd no answer",
            READ_ERROR => "read error",
            READ_STALLED => "read stalled",
            WRITE_FILL_ERROR => "write fill error",
            WRITE_FILL_STALLED => "write fill stalled",
            WRITE_END_ERROR => "write end error",
            WRITE_END_STALLED => "write end stalled",
            _ => "?",
        }
    }
}

/// The SDMMC controller, as `catcard-sd`'s [`Transport`].
pub struct Sdmmc {
    base: u32,
    /// Whether the slot reports a card. Latched at init; `card_present` reports it.
    present: bool,
    wide: bool,
    /// The L4+ "new" SDMMC IP starts the data path from the command's `CMDTRANS` bit, so
    /// `DCTRL.DTEN` must stay clear or the DPSM starts early (before the command) and the
    /// read never happens. The older controller has no `CMDTRANS` and needs `DTEN`.
    new_ip: bool,
    bits: Bits,
}

/// Which microSD slot to talk to, on a board with more than one.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Slot {
    /// The first slot -- the only one on mk3/mk4/mk5, the top one on Q1.
    A,
    /// Q1's bottom slot.
    B,
}

impl Sdmmc {
    /// Bring the controller up on the board's first (or only) slot. Does not talk to the
    /// card — `catcard_sd::init` does.
    ///
    /// # Safety
    /// Claims SDMMC1 and its pins. Call once.
    pub unsafe fn init(spec: &BoardSpec) -> Result<Self, Error> {
        // SAFETY: forwarding the caller's guarantee.
        unsafe { Self::init_slot(spec, Slot::A) }
    }

    /// Bring the controller up on `slot`, steering the board's slot multiplexer to it
    /// first where there is one. A slot the board does not have is [`Error::NoCard`].
    ///
    /// # Safety
    /// Claims SDMMC1, its pins, and the slot's multiplexer and detect lines. Call once.
    pub unsafe fn init_slot(spec: &BoardSpec, slot: Slot) -> Result<Self, Error> {
        if slot == Slot::B && spec.sdmmc.slot_b.is_none() {
            return Err(Error::NoCard);
        }
        let b = base(spec.mcu);
        let bits = if matches!(spec.mcu, Mcu::Stm32L4S5) {
            BITS_L4PLUS
        } else {
            BITS_L4
        };
        // SAFETY: as documented.
        unsafe {
            // Before the bus comes up, so the card that answers CMD0 is the one asked for.
            select_slot(spec, slot);
            enable_clock(spec.mcu)?;
            configure_pins(spec);

            reg::write(b + POWER, POWER_ON);
            // Read back: an unclocked peripheral swallows writes silently, which is the
            // failure that cost a hardware round trip on USB.
            if reg::read(b + POWER) & POWER_ON != POWER_ON {
                return Err(Error::Peripheral);
            }

            reg::write(b + CLKCR, bits.clken | (bits.div_slow & bits.clkdiv_mask));
            reg::write(b + DTIMER, u32::MAX);
            reg::write(b + ICR, bits.icr_all);
        }

        Ok(Self {
            base: b,
            present: card_detect(spec, slot),
            wide: false,
            new_ip: matches!(spec.mcu, Mcu::Stm32L4S5),
            bits,
        })
    }

    /// `STA`, for the debug screen. Reading it changes nothing.
    pub fn status(&self) -> u32 {
        // SAFETY: a read of a peripheral this type owns.
        unsafe { reg::read(self.base + STA) }
    }

    /// `DCOUNT` -- bytes still to transfer in the current data block. 512 (a full block)
    /// means nothing has moved; a falling value means data is arriving. For diagnostics.
    pub fn dcount(&self) -> u32 {
        // SAFETY: a read of a peripheral this type owns.
        unsafe { reg::read(self.base + DCOUNT) }
    }
}

impl Transport for Sdmmc {
    fn command(&mut self, cmd: u8, arg: u32, resp: Response) -> Result<[u32; 4], Error> {
        let b = self.base;
        // SAFETY: this type owns SDMMC1 for its lifetime.
        unsafe {
            reg::write(b + ICR, self.bits.icr_all);
            reg::write(b + ARG, arg);

            let bits = self.bits;
            let wait = match resp {
                Response::None => 0,
                Response::Short => 0b01 << bits.waitresp_shift,
                Response::Long => 0b11 << bits.waitresp_shift,
            };
            // CMD17 and CMD24 are the commands here followed by a data phase, and their
            // data path is armed before this call. `cmdtrans` is 0 on the L4, which starts
            // the data path from `DCTRL.DTEN` instead.
            let trans = if cmd == 17 || cmd == 24 {
                bits.cmdtrans
            } else {
                0
            };
            reg::write(b + CMD, u32::from(cmd) | wait | trans | bits.cpsmen);

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
                    last_failure::record(last_failure::CMD_TIMEOUT, sta, u32::from(cmd));
                    reg::write(b + ICR, self.bits.icr_all);
                    return Err(Error::Timeout { cmd });
                }
                // A CRC failure on a response is still a response: some commands answer
                // with a deliberately wrong CRC, and the card layer decides.
                if sta & STA_CCRCFAIL != 0 {
                    break;
                }
                tries += 1;
                if tries >= CMD_TRIES {
                    last_failure::record(last_failure::CMD_NO_ANSWER, sta, u32::from(cmd));
                    return Err(Error::Timeout { cmd });
                }
            }

            let mut out = [0u32; 4];
            if !matches!(resp, Response::None) {
                for (i, word) in out.iter_mut().enumerate() {
                    *word = reg::read(b + RESP1 + 4 * i as u32);
                }
            }
            reg::write(b + ICR, ICR_CMD);
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
                    last_failure::record(last_failure::READ_ERROR, sta, reg::read(b + DCOUNT));
                    reg::write(b + ICR, self.bits.icr_all);
                    return Err(Error::DataError { block: u32::MAX });
                }
                // Drain while the FIFO is not empty. `RXFIFOE` (empty) is the reliable
                // flag on the L4+ IP: `RXDAVL`/`RXFIFOHF` leave a block's last few words
                // unread there, and the undrained FIFO then wedges the data path with
                // `DCOUNT` stuck short of zero -- which is what a partial read looked like.
                while reg::read(b + STA) & STA_RXFIFOE == 0 && at < BLOCK_LEN {
                    let w = reg::read(b + FIFO).to_le_bytes();
                    let n = w.len().min(BLOCK_LEN - at);
                    out[at..at + n].copy_from_slice(&w[..n]);
                    at += n;
                }
                if at >= BLOCK_LEN {
                    // The bytes are all here, but the controller may not be: `DATAEND` says
                    // the data path has closed. Returning while it is still running lets it
                    // run into the next command, and a word left in the FIFO is then read as
                    // the start of the next block -- which is how a long read comes back
                    // mostly right with the occasional block wrong.
                    //
                    // The wait is short and its expiry is not an error: the data is already
                    // in hand. Whether it ended or not, the FIFO is emptied and the data
                    // path is switched off below, so the next command starts clean either
                    // way. A long wait here would cost every block of every read.
                    for _ in 0..END_POLLS {
                        if reg::read(b + STA) & (STA_DATAEND | STA_DCRCFAIL | STA_DTIMEOUT) != 0 {
                            break;
                        }
                    }
                    while reg::read(b + STA) & STA_RXFIFOE == 0 {
                        let _ = reg::read(b + FIFO);
                    }
                    // `DTEN` off: the old controller's data path stays armed otherwise, and
                    // the new one ignores the bit. Either way the next transfer arms itself.
                    reg::write(b + DCTRL, 0);
                    break;
                }
                if sta & STA_DATAEND != 0 && at == 0 {
                    last_failure::record(last_failure::READ_ERROR, sta, reg::read(b + DCOUNT));
                    reg::write(b + ICR, self.bits.icr_all);
                    return Err(Error::DataError { block: u32::MAX });
                }
                tries += 1;
                if tries >= DATA_TRIES {
                    last_failure::record(last_failure::READ_STALLED, sta, reg::read(b + DCOUNT));
                    reg::write(b + ICR, self.bits.icr_all);
                    return Err(Error::DataError { block: u32::MAX });
                }
            }
            reg::write(b + ICR, self.bits.icr_all);
        }
        Ok(())
    }

    fn write_data(&mut self, data: &[u8; BLOCK_LEN]) -> Result<(), Error> {
        let b = self.base;
        // SAFETY: this type owns SDMMC1 for its lifetime.
        unsafe {
            let mut at = 0usize;
            let mut tries = 0u32;
            // Feed the FIFO an eight-word burst at a time, only when `TXFIFOHE` says there
            // is room for one. `BLOCK_LEN` is a multiple of 32, so the bursts divide it
            // evenly. Writing per word against `TXFIFOF` instead races on the L4+ IP: the
            // "full" flag lags a word behind, the extra write is dropped, and the transfer
            // then stalls with `DCOUNT` short of zero -- exactly what a partial write was.
            while at < BLOCK_LEN {
                let sta = reg::read(b + STA);
                if sta & (STA_DCRCFAIL | STA_DTIMEOUT | STA_TXUNDERR) != 0 {
                    last_failure::record(
                        last_failure::WRITE_FILL_ERROR,
                        sta,
                        reg::read(b + DCOUNT),
                    );
                    reg::write(b + ICR, self.bits.icr_all);
                    return Err(Error::DataError { block: u32::MAX });
                }
                if sta & STA_TXFIFOHE != 0 {
                    let mut n = 0;
                    while n < 8 && at < BLOCK_LEN {
                        let w = [data[at], data[at + 1], data[at + 2], data[at + 3]];
                        reg::write(b + FIFO, u32::from_le_bytes(w));
                        at += 4;
                        n += 1;
                    }
                }
                tries += 1;
                if tries >= DATA_TRIES {
                    last_failure::record(
                        last_failure::WRITE_FILL_STALLED,
                        sta,
                        reg::read(b + DCOUNT),
                    );
                    reg::write(b + ICR, self.bits.icr_all);
                    return Err(Error::DataError { block: u32::MAX });
                }
            }
            // The block is queued; the card still has to program it. `DATAEND` is that,
            // and a CRC or underrun in the meantime is the card rejecting what it got.
            let mut tries = 0u32;
            loop {
                let sta = reg::read(b + STA);
                if sta & (STA_DCRCFAIL | STA_DTIMEOUT | STA_TXUNDERR) != 0 {
                    last_failure::record(last_failure::WRITE_END_ERROR, sta, reg::read(b + DCOUNT));
                    reg::write(b + ICR, self.bits.icr_all);
                    return Err(Error::DataError { block: u32::MAX });
                }
                if sta & STA_DATAEND != 0 {
                    break;
                }
                tries += 1;
                if tries >= DATA_TRIES {
                    last_failure::record(
                        last_failure::WRITE_END_STALLED,
                        sta,
                        reg::read(b + DCOUNT),
                    );
                    reg::write(b + ICR, self.bits.icr_all);
                    return Err(Error::DataError { block: u32::MAX });
                }
            }
            reg::write(b + ICR, self.bits.icr_all);
            // Take the data path out of transmit. After a block the mk3's controller still
            // reported `TXACT`, and the next command found it that way; `DTEN` is clear on
            // the L4+ anyway, so this costs that controller nothing.
            reg::write(b + DCTRL, 0);
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
            reg::modify(self.base + CLKCR, 0, self.bits.widbus_4);
        }
        self.wide = true;
        Ok(())
    }

    fn set_fast_clock(&mut self) {
        // SAFETY: as above.
        unsafe {
            reg::modify(
                self.base + CLKCR,
                self.bits.clkdiv_mask,
                self.bits.div_fast & self.bits.clkdiv_mask,
            );
        }
    }

    fn card_present(&self) -> bool {
        self.present
    }

    fn arm_block_read(&mut self) {
        // SAFETY: this type owns SDMMC1. `DTEN` only on the old IP -- the new one starts
        // the data path from the command's `CMDTRANS`, so setting `DTEN` there would run
        // the DPSM before the command and the read would never happen.
        unsafe { arm_block_read(self.base, !self.new_ip) }
    }

    fn arm_block_write(&mut self) {
        // SAFETY: as in `arm_block_read`.
        unsafe { arm_block_write(self.base, !self.new_ip) }
    }
}

/// Arm the data path for one block, before the read command goes out.
///
/// Separate from `read_data` because the order matters: the controller has to be waiting
/// before the card is asked, or the first words arrive with nowhere to go.
///
/// # Safety
/// Caller owns SDMMC1.
pub unsafe fn arm_block_read(b: u32, dten: bool) {
    // SAFETY: as documented.
    unsafe {
        reg::write(b + DLEN, BLOCK_LEN as u32);
        let en = if dten { DCTRL_DTEN } else { 0 };
        reg::write(b + DCTRL, en | DCTRL_DTDIR_CARD_TO_HOST | DCTRL_BLOCK_512);
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
pub unsafe fn arm_block_write(b: u32, dten: bool) {
    // SAFETY: as documented.
    unsafe {
        reg::write(b + DLEN, BLOCK_LEN as u32);
        let en = if dten { DCTRL_DTEN } else { 0 };
        reg::write(b + DCTRL, en | DCTRL_BLOCK_512);
    }
}

/// Steer the board's slot multiplexer to `slot`. Nothing to do on a single-slot board.
///
/// # Safety
/// Claims the multiplexer line.
unsafe fn select_slot(spec: &BoardSpec, slot: Slot) {
    let Some(mux) = spec.sdmmc.mux else {
        return;
    };
    // SAFETY: as documented; `enable_port` is idempotent.
    unsafe {
        crate::gpio::enable_port(mux.port);
        crate::gpio::configure(
            mux,
            crate::gpio::Mode::Output,
            crate::gpio::OutputType::PushPull,
            crate::gpio::Pull::None,
            crate::gpio::Speed::Low,
        );
        // Low is slot A, high slot B. Source: gpio-peripherals.md §SDMMC1 [C]
        crate::gpio::write(mux, slot == Slot::B);
        // An analog switch settles in well under this; the pause is so the detect read
        // that follows does not race it.
        crate::dwt::delay_cycles(1_000);
    }
}

/// Whether `slot` reports a card, where the board has a pin for it.
fn card_detect(spec: &BoardSpec, slot: Slot) -> bool {
    let pin = match slot {
        Slot::A => spec.sdmmc.card_detect,
        Slot::B => spec.sdmmc.slot_b.map(|b| b.card_detect),
    };
    let Some(pin) = pin else {
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
        // The sense differs by board -- high on mk3/mk4, low on Q1 -- so it comes from the
        // board table rather than being assumed here.
        crate::gpio::read(pin) == spec.sdmmc.card_present_high
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
    use crate::gpio::{OutputType, Pull, Speed, set_alternate};
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
