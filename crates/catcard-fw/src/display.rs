//! Binding the panel driver to this board's SPI and GPIO.
//!
//! `catcard-ui` owns the SSD1306 command set and knows nothing about hardware;
//! `catcard-hal` owns SPI and GPIO and knows nothing about panels. This is the seam.

use catcard_board::spec::{Display, SpiBus};
use catcard_board::{BOARD, Pin};
use catcard_hal::gpio::{self, Mode, OutputType, Pull, Speed};
use catcard_hal::spi::{self, Prescaler, Spi};
use catcard_ui::DisplayBus;
#[cfg(not(feature = "board-q1"))]
use catcard_ui::Ssd1306;

/// Alternate function for SPI1 and SPI2 on the pins this board uses.
/// Source: STM32L496 datasheet, Table 15 (alternate function mapping).
const AF_SPI: u8 = 5;

/// SPI clock ceiling for the panel. The SSD1306 is specified to 10 MHz; staying under
/// it matters because an overclocked panel corrupts intermittently rather than failing.
const DISPLAY_MAX_HZ: u32 = 8_000_000;

/// SPI clock ceiling for the Q1's ST7789.
///
/// The reference has the bootloader and stock firmware at 60 MHz (SPI1 at its APB
/// ceiling). Half that is plenty for a 256x128 image and leaves margin on a trace length
/// nobody has measured. Source: display.md §Q1 "At firmware start" [C] for the 60 MHz
const Q1_DISPLAY_MAX_HZ: u32 = 30_000_000;

/// The panel wired up on this board.
pub struct PanelBus {
    spi: Spi,
    dc: Pin,
    cs: Pin,
    reset: Pin,
    /// The bootloader set this panel up and the firmware must not reset it (Q1).
    inherited: bool,
}

impl PanelBus {
    /// Configure the pins and SPI instance this board's panel sits on.
    ///
    /// # Safety
    ///
    /// Call once. Takes exclusive ownership of the SPI instance and the GPIOs in the
    /// board's display description.
    pub unsafe fn init() -> Result<Self, spi::Error> {
        let (bus, reset, dc, cs, inherited, max_hz) = match BOARD.display {
            Display::Ssd1306 {
                spi, reset, dc, cs, ..
            } => (spi, reset, dc, cs, false, DISPLAY_MAX_HZ),
            Display::St77xx {
                spi, reset, dc, cs, ..
            } => (spi, reset, dc, cs, true, Q1_DISPLAY_MAX_HZ),
        };

        // SAFETY: single-threaded bring-up; PC1 is unused on every board that is not an
        // mk5, and on an mk5 the reference lists it as `V12EN` with nothing else on it.
        unsafe { enable_panel_rail() };

        // An inherited panel keeps RESET exactly as the bootloader left it: configuring it
        // as an output that idles low -- what the OLED wants -- resets a working LCD.
        // Source: display.md §Q1 "leaves LCD_RESET ... exactly as the bootloader
        // configured" [C]
        let owned: &[Pin] = if inherited {
            &[dc, cs]
        } else {
            &[reset, dc, cs]
        };

        // SAFETY: single-threaded bring-up; these pins belong to the panel alone, which
        // the board table's pin-conflict test enforces.
        unsafe {
            for &p in owned {
                gpio::enable_port(p.port);
                gpio::configure(
                    p,
                    Mode::Output,
                    OutputType::PushPull,
                    Pull::None,
                    Speed::High,
                );
            }
            // Idle states before anything is driven: chip deselected, and an OLED held in
            // reset until `reset()` releases it.
            gpio::write(cs, true);
            if !inherited {
                gpio::write(reset, false);
            }

            configure_spi_pins(&bus);
        }

        // SAFETY: this instance is not initialised anywhere else.
        let spi = unsafe {
            Spi::init(
                bus.instance,
                spi::Mode::Mode0,
                // The real APB2 clock, read from RCC -- the bootloader left the PLL
                // running at 80 MHz, and assuming the 4 MHz MSI reset default clocked
                // the panel 5x past its limit, garbling every write. SAFETY: reads RCC.
                Prescaler::for_max_hz(catcard_hal::clock::pclk2_hz(), max_hz),
            )?
        };

        Ok(Self {
            spi,
            dc,
            cs,
            reset,
            inherited,
        })
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
        // An inherited panel is never reset: the bootloader's init is the only init it gets,
        // and a pulse here would blank it with nothing to set it up again.
        if self.inherited {
            return Ok(());
        }
        // The controller discards commands sent before this pulse, and the pulse must be
        // real milliseconds -- `RES=1, 1 ms; RES=0, 10 ms; RES=1, 10 ms` -- not a cycle
        // count, which at the inherited 80 MHz clock came out ~80x too short and left the
        // panel un-reset, so the init was thrown away. Source: gpio-peripherals.md
        // §Display "Hardware reset" [C].
        // SAFETY: `reset` is an output; `delay_ms` reads RCC.
        unsafe {
            gpio::write(self.reset, true);
            catcard_hal::dwt::delay_ms(1);
            gpio::write(self.reset, false);
            catcard_hal::dwt::delay_ms(10);
            gpio::write(self.reset, true);
            catcard_hal::dwt::delay_ms(10);
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
#[cfg(not(feature = "board-q1"))]
pub type Panel = Ssd1306<PanelBus>;
/// The panel, ready to draw on: the Q1's ST7789, showing the 128x64 UI at 2x.
#[cfg(feature = "board-q1")]
pub type Panel = catcard_ui::st7789::St7789<PanelBus>;

/// Clear the whole panel, borders included.
///
/// The mono UI only ever redraws its centred 2x window, so a screen that painted outside
/// it -- the colour chart -- calls this on the way out, or its edges stay behind.
#[cfg(feature = "board-q1")]
pub fn wipe(panel: &mut Panel) {
    let _ = panel.clear(catcard_ui::st7789::BLACK);
}

/// Nothing to do: on the OLED every redraw covers the whole panel.
#[cfg(not(feature = "board-q1"))]
pub fn wipe(_panel: &mut Panel) {}

/// How long to wait for the display co-processor to finish a frame and free SPI1.
///
/// It draws only between tear pulses (~61 Hz) and only once released from reset, which
/// the bootloader has not done, so the bus should be free at once; a second is far past
/// any frame. Bounded, because a dead co-processor must cost the panel, not the boot.
#[cfg(feature = "board-q1")]
const BUS_GRANT_MS: u32 = 1_000;

/// Bring up the Q1 panel on the bootloader's setup: take SPI1 from the co-processor, open
/// the bus without touching RESET, clear it, and switch the backlight on.
///
/// `None` on any failure, which sends the session down the headless path -- a panel that
/// half works must never cost the USB recovery.
///
/// # Safety
/// Call once, after `catcard_hal::init_core`.
#[cfg(feature = "board-q1")]
pub unsafe fn init() -> Option<Panel> {
    let Display::St77xx {
        backlight,
        bus_grant,
        ..
    } = BOARD.display
    else {
        return None;
    };

    if let Some((request, busy)) = bus_grant {
        // SAFETY: single-threaded bring-up; the grant pins belong to the panel alone.
        if !unsafe { take_bus(request, busy) } {
            crate::catlog!("display: co-processor never freed SPI1; no panel");
            return None;
        }
    }

    // SAFETY: forwarding the caller's once-only guarantee.
    let Ok(bus) = (unsafe { PanelBus::init() }) else {
        crate::catlog!("display: SPI1 would not start; no panel");
        return None;
    };
    let mut panel = catcard_ui::st7789::St7789::new(bus);
    // Clear before the backlight comes on, so nothing half-drawn is ever lit.
    if panel.clear(catcard_ui::st7789::BLACK).is_err() {
        crate::catlog!("display: ST7789 write failed; no panel");
        return None;
    }

    if let Some(bl) = backlight {
        // SAFETY: single-threaded bring-up; `BL_ENABLE` belongs to the panel alone.
        unsafe {
            gpio::enable_port(bl.port);
            gpio::configure(bl, Mode::Output, OutputType::PushPull, Pull::None, Speed::Low);
            gpio::write(bl, true);
        }
    }
    crate::catlog!("display: ST7789 inherited, backlight on");
    Some(panel)
}

/// Take SPI1 from the display co-processor: raise `request`, then wait for `busy` low.
///
/// `request` is open-drain with a pull-up and `busy` has a pull-down, as the reference
/// has them. True once the bus is ours, false if `busy` never cleared.
/// Source: gpio-peripherals.md §GPU co-processor "LCD-bus arbitration" [C]
///
/// # Safety
/// Claims both pins.
#[cfg(feature = "board-q1")]
unsafe fn take_bus(request: Pin, busy: Pin) -> bool {
    // SAFETY: as documented.
    unsafe {
        gpio::enable_port(request.port);
        gpio::configure(request, Mode::Output, OutputType::OpenDrain, Pull::Up, Speed::Low);
        gpio::write(request, true);
        gpio::enable_port(busy.port);
        gpio::configure(busy, Mode::Input, OutputType::PushPull, Pull::Down, Speed::Low);
        for _ in 0..BUS_GRANT_MS {
            if !gpio::read(busy) {
                return true;
            }
            catcard_hal::dwt::delay_ms(1);
        }
    }
    false
}

/// Bring up the panel. Returns `None` if SPI would not initialise.
///
/// # Safety
/// Call once, after `catcard_hal::init_core`.
#[cfg(not(feature = "board-q1"))]
pub unsafe fn init() -> Option<Panel> {
    // SAFETY: forwarding the caller's once-only guarantee.
    let bus = unsafe { PanelBus::init() }.ok()?;
    let mut panel = Ssd1306::new_128x64(bus);
    // mk5 uses its own init -- externally-powered panel, charge pump off, unflipped
    // orientation. `running_board` reads the strap only on an mk4/mk5 build: on any other
    // board `PE0` is something else (`QR_RESET` on Q1) and must not be sampled as a strap.
    if crate::running_board() == "mk5" {
        panel.init_mk5().ok()?;
    } else {
        panel.init().ok()?;
    }
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
/// Driven only on an mk4/mk5 build whose strap says mk5, so an mk4 is untouched. A settle
/// delay follows, because a rail that is still rising when the panel is initialised gives
/// exactly the symptom being chased.
///
/// Never on any other board, whatever `PE0` reads: on Q1 `PE0` is `QR_RESET` and `PC1` is
/// `NOT_BATTERY_OLD`, an input from the power circuit on early revisions, so driving it
/// would fight the part that owns it. Source: gpio-peripherals.md §Q/Q1 Power [C]
///
/// **Unconfirmed.** If an mk5 lights up with this and not without it, that is the
/// confirmation; see `docs/HARDWARE-OPEN-ITEMS.md`.
///
/// # Safety
/// Claims PC1. Nothing else in this firmware drives it.
unsafe fn enable_panel_rail() {
    if crate::running_board() != "mk5" {
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
        // Let the external +12 V rail come up before the panel is reset and initialised.
        // Real milliseconds: a boost converter needs a few, and the early board revs that
        // actually depend on this pin are the ones that most need the settle.
        catcard_hal::dwt::delay_ms(50);
        crate::catlog!("display: V12EN (PC1) driven high, mk5 strap low");
    }
}
