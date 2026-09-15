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

use catcard_board::pin::Pin;
use catcard_board::BOARD;
use catcard_flash::{NorFlash, SpiDevice};
use catcard_hal::gpio::{self, Mode, OutputType, Pull, Speed};
use catcard_hal::spi::{self, Prescaler, Spi};

/// SPI2 SCK/MISO/MOSI are alternate function 5 on the L496. Source: STM32L496 datasheet,
/// Table 15 [C].
const AF_SPI: u8 = 5;

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

/// Bring up the SPI-NOR, if this board has one.
///
/// Configures the SPI2 bus pins and the GPIO chip-select, opens the SPI instance at the
/// board's rate, then probes the JEDEC ID -- which both proves the part is talking and
/// sets the size. Returns `None` on a board with no SPI-NOR, or if the probe finds nothing.
///
/// # Safety
/// Takes the SPI2 instance and the sflash pins; call at most once, and only where nothing
/// else has claimed them (the board pin table enforces no other owner).
pub unsafe fn init() -> Option<Nor> {
    let sf = BOARD.sflash?;
    let cs = sf.cs?;

    // SAFETY: forwarding the board's own pin assignment; these pins are the SPI-NOR's alone.
    unsafe {
        // Chip-select: a GPIO output, idle high (deselected).
        gpio::enable_port(cs.port);
        gpio::configure(cs, Mode::Output, OutputType::PushPull, Pull::None, Speed::High);
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
