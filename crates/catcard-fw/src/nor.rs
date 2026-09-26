//! The SPI-NOR flash, wired to the board's SPI2 bus.
//!
//! mk3 only: it is the one generation with no PSRAM, so its SPI-NOR (Macronix MX25L8006E,
//! 1 MB) holds the settings store and the firmware-staging area a self-upgrade is written
//! to. mk4/mk5/Q1 have no SPI-NOR part (`BOARD.sflash` is `None`), so [`init`] returns
//! `None` there and this module does nothing.
//!
//! The driver itself lives in [`catcard_flash`] over a one-method [`SpiDevice`]; this
//! module is only the glue that turns the HAL's [`Spi`] plus a GPIO chip-select into that
//! device. The chip-select is a plain GPIO output driven low around each transaction, not
//! the SPI2 hardware NSS. Source: hw-reference/storage.md §SPI-NOR [C].
//!
//! # One holder at a time
//!
//! Two things in this firmware drive the part: firmware staging, which writes an image
//! from offset 0 upwards, and the settings store, which owns the last 128 KB. They never
//! overlap in the part -- the staging area's ceiling is the settings region's floor -- but
//! they share one bus and one chip-select, and a settings save landing in the middle of
//! a staging write would interleave two commands on it. So the part is [`claim`]ed, by
//! name, and the second holder is told no rather than handed the bus. A staging in
//! progress refuses a settings save; a settings screen refuses a USB offer; both say
//! which.

use catcard_board::BOARD;
use catcard_board::pin::Pin;
use catcard_flash::{NorFlash, SpiDevice};
use catcard_hal::gpio::{self, Mode, OutputType, Pull, Speed};
use catcard_hal::spi::{self, Prescaler, Spi};
#[cfg(feature = "board-mk3")]
use catcard_settings::norslots::BlockMedium;
#[cfg(feature = "board-mk3")]
use catcard_settings::store::MediumError;
#[cfg(feature = "board-mk3")]
use catcard_upgrade::claim::{Claim, Ticket};

/// SPI2 SCK/MISO/MOSI are alternate function 5 on the L496. Source: STM32L496 datasheet,
/// Table 15 [C].
const AF_SPI: u8 = 5;

/// Who may hold the part.
#[cfg(feature = "board-mk3")]
static HELD: Claim = Claim::new();

/// Firmware staging holds it: an image is being written from offset 0.
#[cfg(feature = "board-mk3")]
pub const STAGING: u8 = 1;
/// The settings store holds it: a slot in the last 128 KB is being read or written.
#[cfg(feature = "board-mk3")]
pub const SETTINGS: u8 = 2;
/// The Debug probe holds it, to read the JEDEC id.
#[cfg(feature = "board-mk3")]
pub const PROBE: u8 = 3;

/// Take the part for `holder`, or `None` if someone already has it. Released when the
/// ticket is dropped. `holder` is [`STAGING`] or [`SETTINGS`].
#[cfg(feature = "board-mk3")]
pub fn claim(holder: u8) -> Option<Ticket> {
    HELD.take(holder)
}

/// Who holds the part, for a refusal that can say so. `None` if nobody does.
#[cfg(feature = "board-mk3")]
pub fn holder() -> Option<&'static str> {
    match HELD.holder()? {
        STAGING => Some("firmware staging"),
        SETTINGS => Some("the settings store"),
        PROBE => Some("the Debug probe"),
        _ => Some("an unnamed holder"),
    }
}

/// The SPI2 bus and its software chip-select, presented as a NOR [`SpiDevice`].
pub struct NorBus {
    spi: Spi,
    cs: Pin,
}

impl SpiDevice for NorBus {
    type Error = spi::Error;

    fn transfer(&mut self, write: &[u8], read: &mut [u8]) -> Result<(), spi::Error> {
        // One chip-select spans the whole command: drive CS low, clock out the command and
        // any write data, clock in the read bytes, then raise CS -- always, even on error,
        // so a failed transfer leaves the bus idle rather than the chip selected.
        // SAFETY: `cs` was configured as an output in `init`.
        unsafe { gpio::write(self.cs, false) };
        let out = self.spi.write(write);
        let inp = out.and_then(|()| self.spi.read(read));
        let _ = self.spi.flush();
        // SAFETY: as above.
        unsafe { gpio::write(self.cs, true) };
        inp
    }
}

/// The SPI-NOR flash on this board, once brought up.
pub type Nor = NorFlash<NorBus>;

/// The part as the settings store sees it: read anywhere, erase a sector, program.
///
/// Every wait underneath is bounded by the driver -- a fixed number of status polls
/// per erase (`ERASE_POLL_LIMIT`) and per page program (`PROGRAM_POLL_LIMIT`) -- so a
/// part that stops answering costs a settings save, not the device. The driver's
/// error is logged here, where its detail still exists; the store sees one
/// [`MediumError`] and reports the save as failed.
#[cfg(feature = "board-mk3")]
pub struct NorMedium(pub Nor);

#[cfg(feature = "board-mk3")]
impl BlockMedium for NorMedium {
    fn read(&mut self, addr: u32, out: &mut [u8]) -> Result<(), MediumError> {
        self.0.read(addr, out).map_err(|e| {
            crate::catlog!("nor: read {:#x} failed: {:?}", addr, e);
            MediumError
        })
    }

    fn erase_sector(&mut self, addr: u32) -> Result<(), MediumError> {
        self.0.erase_sector(addr).map_err(|e| {
            crate::catlog!("nor: erase {:#x} failed: {:?}", addr, e);
            MediumError
        })
    }

    fn program(&mut self, addr: u32, data: &[u8]) -> Result<(), MediumError> {
        self.0.write(addr, data).map_err(|e| {
            crate::catlog!("nor: program {:#x} failed: {:?}", addr, e);
            MediumError
        })
    }
}

/// Bring up the SPI-NOR, if this board has one.
///
/// Configures the SPI2 bus pins and the GPIO chip-select, opens the SPI instance at the
/// board's rate, then probes the JEDEC ID -- which both proves the part is talking and
/// sets the size. Returns `None` on a board with no SPI-NOR, or if the probe finds nothing.
///
/// # Safety
/// Takes the SPI2 instance and the sflash pins; only one holder may have them at a time,
/// which is what [`claim`] enforces -- take a ticket first. Re-initialising the bus for
/// each holder is deliberate: nothing else is on SPI2, and a fresh bring-up costs a
/// JEDEC read.
pub unsafe fn init() -> Option<Nor> {
    let sf = BOARD.sflash?;
    let cs = sf.cs?;

    // SAFETY: forwarding the board's own pin assignment; these pins are the SPI-NOR's alone.
    unsafe {
        // Chip-select: a GPIO output, idle high (deselected).
        gpio::enable_port(cs.port);
        gpio::configure(
            cs,
            Mode::Output,
            OutputType::PushPull,
            Pull::None,
            Speed::High,
        );
        gpio::write(cs, true);

        // Bus pins to alternate-function mode.
        for p in [Some(sf.spi.sck), Some(sf.spi.mosi), sf.spi.miso]
            .into_iter()
            .flatten()
        {
            gpio::enable_port(p.port);
            gpio::set_alternate(p, AF_SPI, OutputType::PushPull, Pull::None, Speed::VeryHigh);
        }

        // SAFETY: this instance is not initialised anywhere else -- SPI2 is the SPI-NOR's
        // alone. The prescaler is derived from the real APB1 clock, not a guessed default.
        let spi = Spi::init(
            sf.spi.instance,
            spi::Mode::Mode0,
            Prescaler::for_max_hz(catcard_hal::clock::pclk1_hz(), sf.max_hz),
        )
        .ok()?;

        NorFlash::probe(NorBus { spi, cs }).ok()
    }
}
