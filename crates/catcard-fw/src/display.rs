//! Binding the panel driver to this board's SPI and GPIO.
//!
//! `catcard-ui` owns the SSD1306 command set and knows nothing about hardware;
//! `catcard-hal` owns SPI and GPIO and knows nothing about panels. This is the seam.

use catcard_board::spec::{Display, SpiBus};
use catcard_board::{Pin, BOARD};
use catcard_hal::gpio::{self, Mode, OutputType, Pull, Speed};
use catcard_hal::spi::{self, Prescaler, Spi};
use catcard_ui::{DisplayBus, Ssd1306};

/// Alternate function for SPI1 and SPI2 on the pins this board uses.
/// Source: STM32L496 datasheet, Table 15 (alternate function mapping).
const AF_SPI: u8 = 5;

/// Reset pulse width. The SSD1306 datasheet asks for at least 3 microseconds; this is
/// several orders of magnitude more, which costs nothing at boot.
const RESET_CYCLES: u32 = 10_000;

/// SPI clock ceiling for the panel. The SSD1306 is specified to 10 MHz; staying under
/// it matters because an overclocked panel corrupts intermittently rather than failing.
const DISPLAY_MAX_HZ: u32 = 8_000_000;

/// Core clock assumed when choosing the prescaler.
///
/// The PLL is not programmed yet, so the part runs on the reset-default MSI. Using the
/// real (slower) figure means the prescaler picks a *lower* SPI clock than necessary —
/// safe. Revisit when `clock::init_pll` lands; see `docs/HARDWARE-OPEN-ITEMS.md`.
const ASSUMED_PCLK_HZ: u32 = 4_000_000;

/// The panel wired up on this board.
pub struct PanelBus {
    spi: Spi,
    dc: Pin,
    cs: Pin,
    reset: Pin,
}

impl PanelBus {
    /// Configure the pins and SPI instance this board's panel sits on.
    ///
    /// # Safety
    ///
    /// Call once. Takes exclusive ownership of the SPI instance and the four GPIOs in
    /// the board's display description.
    pub unsafe fn init() -> Result<Self, spi::Error> {
        let (bus, reset, dc, cs) = match BOARD.display {
            Display::Ssd1306 {
                spi, reset, dc, cs, ..
            }
            | Display::St77xx {
                spi, reset, dc, cs, ..
            } => (spi, reset, dc, cs),
        };

        // SAFETY: single-threaded bring-up; PC1 is unused on every board that is not an
        // mk5, and on an mk5 the reference lists it as `V12EN` with nothing else on it.
        unsafe { enable_panel_rail() };

        // SAFETY: single-threaded bring-up; these pins belong to the panel alone, which
        // the board table's pin-conflict test enforces.
        unsafe {
            for p in [reset, dc, cs] {
                gpio::enable_port(p.port);
                gpio::configure(
                    p,
                    Mode::Output,
                    OutputType::PushPull,
                    Pull::None,
                    Speed::High,
                );
            }
            // Idle states before anything is driven: chip deselected, panel held in
            // reset until `reset()` releases it.
            gpio::write(cs, true);
            gpio::write(reset, false);

            configure_spi_pins(&bus);
        }

        // SAFETY: this instance is not initialised anywhere else.
        let spi = unsafe {
            Spi::init(
                bus.instance,
                spi::Mode::Mode0,
                Prescaler::for_max_hz(ASSUMED_PCLK_HZ, DISPLAY_MAX_HZ),
            )?
        };

        Ok(Self { spi, dc, cs, reset })
    }

    /// Drive a transfer with D/C at `dc_high`, framed by chip-select.
    #[allow(clippy::needless_lifetimes)]
    fn transfer(&mut self, dc_high: bool, bytes: &[u8]) -> Result<(), spi::Error> {
        // SAFETY: these pins were configured as outputs in `init`.
        unsafe {
            gpio::write(self.dc, dc_high);
            gpio::write(self.cs, false);
        }
        // The panel has no MISO line, so nothing is received and progress must not
        // depend on RXNE. `write_only` also drains the FIFO before returning.
        let r = self.spi.write_only(bytes);
        // Drain again even on the error path, so a failed transfer does not leave the
        // panel selected with a byte still shifting.
        let flushed = self.spi.flush();
        // SAFETY: as above.
        unsafe {
            gpio::write(self.cs, true);
        }
        r.and(flushed)
    }
}

impl DisplayBus for PanelBus {
    type Error = spi::Error;

    fn command(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.transfer(false, bytes)
    }

    fn data(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.transfer(true, bytes)
    }

    fn reset(&mut self) -> Result<(), Self::Error> {
        // SAFETY: configured as an output in `init`.
        unsafe {
            gpio::write(self.reset, false);
            catcard_hal::dwt::delay_cycles(RESET_CYCLES);
            gpio::write(self.reset, true);
            catcard_hal::dwt::delay_cycles(RESET_CYCLES);
        }
        Ok(())
    }
}

/// Put the bus pins into alternate-function mode.
///
/// # Safety
/// The pins must belong to this SPI instance.
unsafe fn configure_spi_pins(bus: &SpiBus) {
    // SAFETY: forwarding the board's own pin assignment.
    unsafe {
        for p in [Some(bus.sck), Some(bus.mosi), bus.miso]
            .into_iter()
            .flatten()
        {
            gpio::enable_port(p.port);
            gpio::set_alternate(p, AF_SPI, OutputType::PushPull, Pull::None, Speed::VeryHigh);
        }
    }
}

/// The panel, ready to draw on.
pub type Panel = Ssd1306<PanelBus>;

/// Bring up the panel. Returns `None` if SPI would not initialise.
///
/// # Safety
/// Call once, after `catcard_hal::init_core`.
pub unsafe fn init() -> Option<Panel> {
    // SAFETY: forwarding the caller's once-only guarantee.
    let bus = unsafe { PanelBus::init() }.ok()?;
    let mut panel = Ssd1306::new_128x64(bus);
    panel.init().ok()?;
    Some(panel)
}

/// `V12EN` — the supply an mk5 panel needs and an mk4 one does not. `[?]`
///
/// mk4 and mk5 share every pin we know of except `STRAP_MK5` and this, and an mk5 came
/// up with a dark screen on firmware that drew fine on an mk4. That is the whole of the
/// evidence: the reference names `V12EN=PC1` and says nothing about what it switches.
///
/// The earlier argument that it could not be a display rail — that an SSD1306 makes its
/// own panel voltage from the charge pump `ssd1306::init` enables — holds only for a
/// module that has one. A board that supplies panel voltage itself, through a boost
/// enabled here, fits the name and fits the symptom.
///
/// Driven only when the mk5 strap is low, so an mk4 is untouched. A settle delay follows,
/// because a rail that is still rising when the panel is initialised gives exactly the
/// symptom being chased.
///
/// **Unconfirmed.** If an mk5 lights up with this and not without it, that is the
/// confirmation; see `docs/HARDWARE-OPEN-ITEMS.md`.
///
/// # Safety
/// Claims PC1. Nothing else in this firmware drives it.
unsafe fn enable_panel_rail() {
    // SAFETY: as documented.
    if !unsafe { catcard_hal::strap::is_mk5() } {
        return;
    }
    let pin = catcard_board::Pin::new(catcard_board::Port::C, 1);
    // SAFETY: as documented.
    unsafe {
        gpio::enable_port(pin.port);
        gpio::configure(
            pin,
            Mode::Output,
            OutputType::PushPull,
            Pull::None,
            Speed::Low,
        );
        gpio::write(pin, true);
        // Let the rail come up before the panel is spoken to. 40 ms at the MSI reset
        // default; a boost converter needs milliseconds, not microseconds.
        catcard_hal::dwt::delay_cycles(160_000);
    }
}
