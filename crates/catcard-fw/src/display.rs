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

/// SPI clock ceiling for the Q1's ST7789: 60 MHz, SPI1 at its APB ceiling, as the
/// bootloader and stock firmware drive it.
///
/// This was halved to 30 MHz for margin on an unmeasured trace, which cost nothing while
/// the write loop was the bottleneck. Once that loop was fixed, a full 320x240 frame
/// (~140 KB) became wire-limited, and scrolling is where it shows. Stock ships at 60 MHz on
/// this exact board.
///
/// Source: display.md §Q1 "At firmware start" [C]
const Q1_DISPLAY_MAX_HZ: u32 = 60_000_000;

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
                // The real APB2 clock, read from RCC -- the bootloader hands off with the
                // PLL running (120 MHz on the L4S5 boards, 80 MHz on mk3), and assuming
                // the 4 MHz MSI reset default clocked the panel past its limit, garbling
                // every write. SAFETY: reads RCC.
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
/// The panel, ready to draw on: the Q1's ST7789, flushed full-screen from a 16-level
/// [`Screen`] -- see [`draw`].
#[cfg(feature = "board-q1")]
pub type Panel = catcard_ui::st7789::St7789<PanelBus>;

/// Clear the whole panel, borders included.
///
/// For a screen that painted the panel directly, behind the canvas -- the colour chart. The
/// canvas and its row cache no longer describe what the panel shows, so the panel is
/// cleared and the next frame is sent whole.
#[cfg(feature = "board-q1")]
pub fn wipe(panel: &mut Panel) {
    reclaim_bus();
    let _ = panel.clear(catcard_ui::st7789::BLACK);
    // Painted behind the row cache's back, so the next frame must be sent whole.
    // SAFETY: foreground only, single core, and not while `draw` holds the cache.
    unsafe { (*core::ptr::addr_of_mut!(ROWS_SENT)).invalidate() };
}

/// On the OLED a redraw covers the whole panel, so there is nothing to clear -- but the
/// next one has to actually be sent, which it would not be if it happened to match what
/// the cache believes is already there.
#[cfg(not(feature = "board-q1"))]
pub fn wipe(_panel: &mut Panel) {
    forget_frame();
}

/// Hand the busy bar to the panel itself, so it keeps moving while the CPU cannot draw.
///
/// A callgate call -- a PIN check, a secret fetch -- runs with interrupts masked for a
/// second or more, and the firewall resets the CPU if one lands inside it. Nothing the
/// firmware does can repaint across that. The SSD1306 can: told to scroll a page, it steps
/// it a column at a time from its own frame counter, with no host involvement at all.
///
/// The bar occupies the bottom rows, which on a 64-row panel is page 7, so that is the page
/// handed over. The next [`draw`] stops it -- `flush` always does -- which is why nothing
/// here has to remember to turn it off.
///
/// The command depends on the panel: the mk5's needs the longer setup with a column range,
/// and an SSD1306 must never be sent that form. So the choice follows the same strap-based
/// board check that picks the mk5's panel init. The mk3 and mk4 keep the SSD1306 form.
#[cfg(not(feature = "board-q1"))]
pub fn scroll_busy_bar(panel: &mut Panel) {
    let last_page = (SCREEN_H / 8 - 1) as u8;
    let interval = catcard_ui::ssd1306::Interval::FASTEST;
    let _ = if crate::running_board() == "mk5" {
        panel.scroll_pages_with_columns(last_page, last_page, interval)
    } else {
        panel.scroll_pages(last_page, last_page, interval)
    };
    // The panel is now showing something the framebuffer does not describe, and the next
    // flush is what stops the scrolling. So that flush must happen even if the frame is
    // unchanged -- otherwise a bar handed over here would go on sliding under the next
    // screen's text.
    forget_frame();
}

/// Whether blocking screens hand the Q1's bus to the GPU co-processor for its bar.
///
/// Watched working on the Q1 from Debug -> Scroll test before this was turned on: a PIN
/// check is on the boot path, and this board has no recovery.
#[cfg(feature = "board-q1")]
pub const GPU_BAR_ON_BLOCKING: bool = true;

/// The Q1's ST7789 cannot scroll by itself, but the GPU co-processor sharing its bus can
/// draw a moving bar along the bottom while the CPU is stuck. Ask it to, and hand it the
/// bus; the next [`draw`] takes the bus back before sending anything.
///
/// Without a co-processor that answers, the bus stays with the CPU and the screen simply
/// has no bar -- as on stock.
#[cfg(feature = "board-q1")]
pub fn scroll_busy_bar(_panel: &mut Panel) {
    if crate::gpu::activity_bar() {
        // SAFETY: foreground only; not inside a draw, which never calls this.
        unsafe { give_bus() };
    }
}

/// Wait for the start of the panel's next tear pulse, so a change made now lands between
/// two refreshes rather than across one. False if no pulse came within 50 ms -- three
/// frames at the ~61 Hz the tear line runs at on this panel (measured: 360 edges in 3 s).
///
/// Source: display.md §Q1 init step 7 "TEON ... LCD_TEAR=PB11 (~61 Hz)" [C]
#[cfg(feature = "board-q1")]
pub fn wait_tear() -> bool {
    let Display::St77xx {
        tear: Some(tear), ..
    } = BOARD.display
    else {
        return false;
    };
    // SAFETY: the panel drives the tear line; configuring it as an input takes nothing
    // from anyone. Reads RCC for the clock.
    unsafe {
        gpio::enable_port(tear.port);
        gpio::configure(
            tear,
            Mode::Input,
            OutputType::PushPull,
            Pull::None,
            Speed::Low,
        );
        let limit = catcard_hal::clock::hclk_hz() / 20;
        let start = catcard_hal::dwt::cycles();
        let mut was_high = gpio::read(tear);
        while catcard_hal::dwt::cycles().wrapping_sub(start) < limit {
            let high = gpio::read(tear);
            if high && !was_high {
                return true;
            }
            was_high = high;
        }
    }
    false
}

/// Put the panel's scrolling back and have the next frame sent whole. For a screen that
/// scrolled the panel directly: everything else draws as if nothing were shifted.
#[cfg(feature = "board-q1")]
pub fn end_scroll(panel: &mut Panel) {
    let _ = panel.end_scroll();
    wipe(panel);
}

/// Whether the GPU co-processor holds the LCD bus. Foreground only, single core.
#[cfg(feature = "board-q1")]
static mut BUS_GIVEN: bool = false;

/// How long to wait for the co-processor to finish the frame it is drawing when the bus is
/// taken back. One frame is ~16 ms at the ~61 Hz tear rate.
#[cfg(feature = "board-q1")]
const BUS_RECLAIM_MS: u32 = 100;

/// Let the co-processor draw: SCK, MOSI, CS and D/C to high impedance, then `G_CTRL` low.
///
/// The reference's `give_spi()` releases only SCK and MOSI. That is not enough here: with
/// CS and D/C still driven, the co-processor raised `G_BUSY` for about a third of every
/// second -- it was drawing -- and nothing reached the panel. With CS and D/C released as
/// well, the bar moved. It drives the panel's select and command lines itself.
///
/// Source: gpu.md "LCD-bus arbitration" [C]; CS/DC measured on the Q1 (Debug -> Scroll
/// test, busy 969 ms of 3 s with the tear line at ~60 Hz in both cases, visible only with
/// CS and D/C released) [C]
///
/// # Safety
/// Foreground only; the panel must not be mid-write.
#[cfg(feature = "board-q1")]
unsafe fn give_bus() {
    let Display::St77xx {
        spi,
        cs,
        dc,
        bus_grant: Some((request, _)),
        ..
    } = BOARD.display
    else {
        return;
    };
    // SAFETY: the panel's own pins, per the caller.
    unsafe {
        for p in [spi.sck, spi.mosi, cs, dc] {
            gpio::configure(p, Mode::Input, OutputType::PushPull, Pull::None, Speed::Low);
        }
        gpio::write(request, false);
        *core::ptr::addr_of_mut!(BUS_GIVEN) = true;
    }
}

/// Take the bus back if the co-processor has it: `G_CTRL` high, wait (bounded) for
/// `G_BUSY` low, CS (deselected) and D/C back to outputs, SCK and MOSI back to SPI. The panel's contents are no longer what the row
/// cache says -- the bar is on it -- so the next frame goes whole.
/// Source: gpu.md "LCD-bus arbitration" -- `take_spi()` [C]
#[cfg(feature = "board-q1")]
fn reclaim_bus() {
    // SAFETY: foreground only, single core.
    if !unsafe { core::ptr::replace(core::ptr::addr_of_mut!(BUS_GIVEN), false) } {
        return;
    }
    let Display::St77xx {
        spi,
        cs,
        dc,
        bus_grant: Some((request, busy)),
        ..
    } = BOARD.display
    else {
        return;
    };
    // SAFETY: the panel's own pins; nothing is drawing.
    unsafe {
        gpio::write(request, true);
        let mut freed = false;
        for _ in 0..BUS_RECLAIM_MS {
            if !gpio::read(busy) {
                freed = true;
                break;
            }
            catcard_hal::dwt::delay_ms(1);
        }
        if !freed {
            crate::catlog!("display: co-processor still busy; taking the bus anyway");
        }
        gpio::write(cs, true);
        for p in [cs, dc] {
            gpio::configure(
                p,
                Mode::Output,
                OutputType::PushPull,
                Pull::None,
                Speed::High,
            );
        }
        configure_spi_pins(&spi);
        (*core::ptr::addr_of_mut!(ROWS_SENT)).invalidate();
    }
}

/// The canvas every screen on this board draws into: the OLED's own 128x64 framebuffer, or
/// the Q1's whole 320x240 at 16 levels.
#[cfg(not(feature = "board-q1"))]
pub type Screen = catcard_ui::Mono128x64;
/// The canvas every screen on this board draws into: the OLED's own 128x64 framebuffer, or
/// the Q1's whole 320x240 at 16 levels.
#[cfg(feature = "board-q1")]
pub type Screen = catcard_ui::canvas::Gray320x240;

/// What a screen is handed to draw into.
///
/// On the Q1 this is the panel with the status bar's rows withheld, so a screen simply
/// cannot reach them: the alternative -- every screen remembering to start lower -- is
/// one forgotten screen away from text under the bar. On the mono boards there is no bar
/// and it is the whole framebuffer.
#[cfg(feature = "board-q1")]
pub type Surface<'a> = catcard_ui::canvas::Inset<'a, Screen>;
/// As above, for the boards with no status bar.
#[cfg(not(feature = "board-q1"))]
pub type Surface<'a> = Screen;

/// Rows the status bar occupies at the top of the panel.
///
/// Zero where there is no bar. Pinned to the face it is drawn in by a test below rather
/// than being computed here, because it has to be a constant: [`SCREEN_H`] is derived
/// from it and screens lay themselves out against that.
#[cfg(feature = "board-q1")]
pub const BAR_H: usize = 16;
/// No bar on the mono boards: 16 of 64 rows is a quarter of the screen, and their keypad
/// has no modifiers to report. Zero, rather than absent, because it is also the row the
/// frame's palette changes at -- and on these boards it never does.
#[cfg(not(feature = "board-q1"))]
pub const BAR_H: usize = 0;
/// Which faces and spacing this board's screens use.
#[cfg(not(feature = "board-q1"))]
pub const LAYOUT: catcard_ui::widgets::Layout<'static> = catcard_ui::widgets::Layout::compact();
/// Which faces and spacing this board's screens use.
#[cfg(feature = "board-q1")]
pub const LAYOUT: catcard_ui::widgets::Layout<'static> = catcard_ui::widgets::Layout::roomy();

/// The faces and spacing the scrollable document view ([`catcard_ui::scroll`]) uses on
/// this board: a title, a readable body, and a small face for notes and dense values.
/// On the mono panel the title and body are the same 7x14 face -- bigger than the old
/// 4x6 body, so menus and words read at arm's length.
#[cfg(not(feature = "board-q1"))]
pub const FONTS: catcard_ui::scroll::Fonts<'static> = catcard_ui::scroll::Fonts {
    title: &catcard_ui::font::peep7x14::FONT,
    body: &catcard_ui::font::peep7x14::FONT,
    small: &catcard_ui::font::misc4x6::FONT,
    gap: 1,
    margin: 2,
};
/// As above, for the Q1's colour panel: a 10x20 title and body over a 7x14 small face.
#[cfg(feature = "board-q1")]
pub const FONTS: catcard_ui::scroll::Fonts<'static> = catcard_ui::scroll::Fonts {
    title: &catcard_ui::font::peep10x20::FONT,
    body: &catcard_ui::font::peep10x20::FONT,
    small: &catcard_ui::font::peep7x14::FONT,
    gap: 2,
    margin: 6,
};

/// Panel height in pixels, for sizing a pager window against a layout at runtime (the
/// number of rows depends on the body face, which the words layout changes).
#[cfg(not(feature = "board-q1"))]
pub const SCREEN_H: usize = 64;
/// As above, for the Q1, where the status bar's rows are not a screen's to lay out in.
#[cfg(feature = "board-q1")]
pub const SCREEN_H: usize = 240 - BAR_H;

/// Panel width in pixels, for wrapping a document to the panel.
#[cfg(not(feature = "board-q1"))]
pub const SCREEN_W: usize = 128;
/// As above, for the Q1.
#[cfg(feature = "board-q1")]
pub const SCREEN_W: usize = 320;

/// Whether scrolling is animated.
///
/// On for every board. The Q1 used to jump instead, on the reasoning that a scroll dirties
/// every row of its 320x240 frame and so defeats the row cache. Measured, one scroll frame
/// there came to ~75 ms, and almost none of it was the SPI clock: 30 and 60 MHz gave the
/// same number. It was pixel conversion and a per-byte helper call in the SPI write loop.
/// With both fixed a frame is ~38 ms -- ~15 of it rendering, the rest now genuinely the
/// wire -- which is cheap enough to animate.
pub const SMOOTH_SCROLL: bool = true;

/// Frames in a scroll glide, the settled one included, and the pause between them.
///
/// The mono panel's frame is a ~1 KB blit, so the pause is what sets the pace: six frames
/// ~6 ms apart. On the Q1 the frame itself takes ~38 ms, which is already a pace, so the
/// glide there is shorter and does not wait: two in-between frames, about 76 ms a row.
/// Smaller steps would read smoother but cost a whole frame each -- 2 px at a time is
/// eleven frames for a 22 px row, over 400 ms.
#[cfg(not(feature = "board-q1"))]
pub const GLIDE_FRAMES: usize = 6;
#[cfg(not(feature = "board-q1"))]
pub const GLIDE_PAUSE_CYCLES: u32 = 700_000;
#[cfg(feature = "board-q1")]
pub const GLIDE_FRAMES: usize = 3;
#[cfg(feature = "board-q1")]
pub const GLIDE_PAUSE_CYCLES: u32 = 0;

/// What this board's confirm key is labelled with. The mk pads carry a tick moulded into
/// the cap; the Q1's key is printed ENTER.
/// Source: gpio-peripherals.md §Q/Q1 "Key decode" [C] for the Q1 legend.
#[cfg(not(feature = "board-q1"))]
pub const CONFIRM: catcard_ui::icons::KeyMark =
    catcard_ui::icons::KeyMark::Icon(&catcard_ui::icons::CHECK);
/// What this board's cancel key is labelled with: a cross moulded into the cap.
#[cfg(not(feature = "board-q1"))]
pub const CANCEL: catcard_ui::icons::KeyMark =
    catcard_ui::icons::KeyMark::Icon(&catcard_ui::icons::CROSS);
/// The Q1 has no tick or cross: its keys are printed ENTER and CANCEL, so the screens
/// name them that way. Source: gpio-peripherals.md §Q/Q1 "Key decode" [C]
#[cfg(feature = "board-q1")]
pub const CONFIRM: catcard_ui::icons::KeyMark = catcard_ui::icons::KeyMark::Word("ENTER");
/// The Q1 has no tick or cross: its keys are printed ENTER and CANCEL, so the screens
/// name them that way. Source: gpio-peripherals.md §Q/Q1 "Key decode" [C]
#[cfg(feature = "board-q1")]
pub const CANCEL: catcard_ui::icons::KeyMark = catcard_ui::icons::KeyMark::Word("CANCEL");

/// What to call the confirm key in a line of running text, as it is marked on this board.
#[cfg(not(feature = "board-q1"))]
pub const CONFIRM_KEY: &str = "y";
/// What to call the confirm key in a line of running text, as it is marked on this board.
#[cfg(feature = "board-q1")]
pub const CONFIRM_KEY: &str = "ENTER";
/// What to call the cancel key in a line of running text, as it is marked on this board.
#[cfg(not(feature = "board-q1"))]
pub const CANCEL_KEY: &str = "x";
/// What to call the cancel key in a line of running text, as it is marked on this board.
#[cfg(feature = "board-q1")]
pub const CANCEL_KEY: &str = "CANCEL";

/// Body rows a list or info screen shows: `LAYOUT.rows(Screen height)` as a constant, for
/// sizing line buffers. Pinned to the layouts by catcard-ui's widget tests (6 and 12).
#[cfg(not(feature = "board-q1"))]
pub const ROWS: usize = 6;
/// Body rows a list or info screen shows: `LAYOUT.rows(Screen height)` as a constant, for
/// sizing line buffers. Pinned to the layouts by catcard-ui's widget tests (6 and 12).
#[cfg(feature = "board-q1")]
pub const ROWS: usize = 12;

/// Body characters across the screen after the left margin: 4x6 on 128, 7x14 on 320.
#[cfg(not(feature = "board-q1"))]
pub const LOG_COLS: usize = (128 - 2) / 4;
/// Body characters across the screen after the left margin: 4x6 on 128, 7x14 on 320.
#[cfg(feature = "board-q1")]
pub const LOG_COLS: usize = (320 - 6) / 7;

/// The one canvas. Static, not on the stack: the Q1's is 38.4 KB and screens are drawn
/// from deep call chains.
static mut SCREEN: Screen = Screen::new();

/// Set while a screen is being drawn. A drawing closure that called [`draw`] again would
/// alias the canvas; that call is refused instead.
static DRAWING: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Draw a screen: hand `f` the canvas, then put the canvas on the panel.
///
/// The widgets clear the canvas themselves, so every frame replaces the whole of the last
/// one. A flush that fails is not worth stopping for -- the device is still reachable over
/// USB, and the next draw tries again.
///
/// Every ordinary screen paints in [`AMBER`](catcard_ui::st7789::AMBER), the hue the
/// bootloader hands over in, so the device does not change colour between the loader and
/// the firmware. The splash and About screens are the exception: they draw through the
/// artwork's own palette, where text is white so "CatCard" and the version stand off the
/// cat rather than disappearing into it.
pub fn draw(panel: &mut Panel, f: impl FnOnce(&mut Surface<'_>)) {
    draw_with(panel, &catcard_ui::st7789::AMBER, f)
}

/// [`draw`], with the content drawn through a palette of the screen's choosing.
///
/// The status bar keeps its own greys either way; this is the band below it. A screen
/// full of pixel art needs the art's colours rather than the amber ramp text reads best
/// in, and the two cannot be mixed on one scanline -- the canvas holds indices and the
/// palette is what they mean.
pub fn draw_with(panel: &mut Panel, content: &[u16; 16], f: impl FnOnce(&mut Surface<'_>)) {
    use core::sync::atomic::Ordering;
    if DRAWING.swap(true, Ordering::SeqCst) {
        crate::catlog!("display: nested draw refused");
        return;
    }
    // SAFETY: `DRAWING` makes this the only live reference to `SCREEN`; the firmware is
    // single-threaded and nothing draws from interrupt context.
    let screen = unsafe { &mut *core::ptr::addr_of_mut!(SCREEN) };
    #[cfg(feature = "board-q1")]
    {
        // The screen paints into the rows below the bar, then the bar goes on top of its
        // own. It is painted last because the widgets clear their canvas every frame, and
        // it is painted every frame because that is what keeps a held modifier honest.
        {
            let mut surface = catcard_ui::canvas::Inset::new(&mut *screen, BAR_H);
            f(&mut surface);
        }
        catcard_ui::statusbar::render(screen, FONTS.small, &crate::statusbar::status());
    }
    #[cfg(not(feature = "board-q1"))]
    f(screen);
    #[cfg(feature = "board-q1")]
    BAR_SHOWN.store(true, Ordering::SeqCst);
    show(panel, screen, content, BAR_H);
    DRAWING.store(false, Ordering::SeqCst);
}

/// The pause a screen takes between keypad polls while it waits for a key.
///
/// The status bar is refreshed here rather than only when a frame is drawn, because the
/// modifiers decode to no key: holding SHIFT produces no event, so nothing would repaint,
/// and an indicator that lit only once you had typed would be reporting what you did
/// rather than what you are about to do. Nothing happens unless the state actually moved.
pub fn idle(panel: &mut Panel) {
    #[cfg(feature = "board-q1")]
    crate::statusbar::poll(panel);
    #[cfg(not(feature = "board-q1"))]
    let _ = panel;
    catcard_hal::dwt::delay_cycles(crate::usbtask::IDLE_PAUSE_CYCLES);
}

/// Whether the frame on the panel is one with a status bar.
///
/// The artwork screens draw through their own palette and full height, so the bar has no
/// place on them -- and repainting it there would flush the whole frame in the wrong
/// palette, recolouring the art.
#[cfg(feature = "board-q1")]
static BAR_SHOWN: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Repaint the status bar over the frame already on the panel.
///
/// For the idle poll: a modifier is held and released without ever producing a key event,
/// so nothing would otherwise redraw, and an indicator that lit up only once you typed
/// would be telling you what you already did rather than what you are about to do. The
/// content of the frame is untouched, and the row cache means only the bar's rows reach
/// the wire.
#[cfg(feature = "board-q1")]
pub fn refresh_bar(panel: &mut Panel) {
    use core::sync::atomic::Ordering;
    // Nothing to refresh over artwork, and painting here would re-flush the whole frame
    // in this function's palette rather than the art's.
    if !BAR_SHOWN.load(Ordering::SeqCst) || DRAWING.swap(true, Ordering::SeqCst) {
        return;
    }
    // SAFETY: as in `draw`.
    let screen = unsafe { &mut *core::ptr::addr_of_mut!(SCREEN) };
    // The palette the frame under the bar was actually drawn through, not this
    // function's idea of one. Naming a different palette here makes `show` think the
    // colours changed, which invalidates the row cache and re-sends the *whole* frame
    // through it -- and that is what turned the icon grid amber the first time the bar
    // refreshed over it. With the right palette nothing but the bar's rows differ.
    // SAFETY: as above; the reads finish within these statements.
    let palette = unsafe { *core::ptr::addr_of!(LAST_PALETTE) };
    let split = unsafe { *core::ptr::addr_of!(LAST_SPLIT) };
    catcard_ui::statusbar::render(screen, FONTS.small, &crate::statusbar::status());
    show(panel, screen, &palette, split);
    DRAWING.store(false, Ordering::SeqCst);
}

/// Draw a screen whose canvas means colours rather than greys.
///
/// The canvas holds an index per pixel; `palette` says what those indices look like. Art
/// baked by `tools/artgen/svg2rs.py` carries its own palette, with 0 the background and 15
/// white, so text and the progress bar keep drawing in white over it.
#[cfg(feature = "board-q1")]
pub fn draw_with_palette(panel: &mut Panel, palette: &[u16; 16], f: impl FnOnce(&mut Screen)) {
    use core::sync::atomic::Ordering;
    if DRAWING.swap(true, Ordering::SeqCst) {
        crate::catlog!("display: nested draw refused");
        return;
    }
    // Full height, own palette, no bar -- and say so, so an idle refresh leaves it be.
    BAR_SHOWN.store(false, Ordering::SeqCst);
    // SAFETY: `DRAWING` makes this the only live reference to `SCREEN`; the firmware is
    // single-threaded and nothing draws from interrupt context.
    let screen = unsafe { &mut *core::ptr::addr_of_mut!(SCREEN) };
    f(screen);
    show(panel, screen, palette, 0);
    DRAWING.store(false, Ordering::SeqCst);
}

#[cfg(not(feature = "board-q1"))]
fn show(panel: &mut Panel, screen: &Screen, _palette: &[u16; 16], _split: usize) {
    // Two colours, so a palette says nothing here.
    // SAFETY: only reached from a draw, under `DRAWING`; foreground, single core.
    let cache = unsafe { &mut *core::ptr::addr_of_mut!(FRAME_SENT) };
    let _ = panel.flush_changed(screen, cache);
}

/// What the mono panel was last sent, so an identical frame is not sent again.
///
/// The colour panel has the same thing per row ([`ROWS_SENT`]); this one is per frame,
/// because the SSD1306 is flushed whole.
#[cfg(not(feature = "board-q1"))]
static mut FRAME_SENT: catcard_ui::display::FrameCache = catcard_ui::display::FrameCache::new();

/// Forget what the mono panel shows, so the next frame is sent whatever it holds.
///
/// For anything that writes to the panel without going through [`show`] -- a hardware
/// scroll, a direct clear. Skipping an identical frame is only safe while the cache is
/// telling the truth about what is on the glass.
#[cfg(not(feature = "board-q1"))]
fn forget_frame() {
    // SAFETY: foreground only, single core, and never inside a draw.
    unsafe { (*core::ptr::addr_of_mut!(FRAME_SENT)).invalidate() };
}

/// Which rows of the Q1 panel already show what the canvas holds.
#[cfg(feature = "board-q1")]
static mut ROWS_SENT: catcard_ui::st7789::RowCache<240> = catcard_ui::st7789::RowCache::new();

/// Where the last frame's palette changed, so a change of layout invalidates the cache.
#[cfg(feature = "board-q1")]
static mut LAST_SPLIT: usize = 0;

/// Send the rows of the canvas that changed. A cursor step or a progress tick is a few
/// rows, not the 153,600 bytes of a full frame.
#[cfg(feature = "board-q1")]
fn show(panel: &mut Panel, screen: &Screen, palette: &[u16; 16], split: usize) {
    reclaim_bus();
    // SAFETY: only reached from `draw`, under `DRAWING`; `wipe` runs in the foreground and
    // never inside a draw. Single core, nothing in interrupt context.
    let cache = unsafe { &mut *core::ptr::addr_of_mut!(ROWS_SENT) };
    let last = unsafe { &mut *core::ptr::addr_of_mut!(LAST_PALETTE) };
    // Same indices mean different colours under a new palette, so what the panel already
    // shows is no longer what the cache says it shows. The split counts too: the bar's
    // rows change ramp when a full-screen artwork frame gives way to an ordinary one.
    // SAFETY: as above -- foreground, single core, inside a draw.
    let last_split = unsafe { &mut *core::ptr::addr_of_mut!(LAST_SPLIT) };
    if *last != *palette || *last_split != split {
        *last = *palette;
        *last_split = split;
        cache.invalidate();
    }
    let _ =
        panel.flush_gray_changed_split(screen, &catcard_ui::st7789::GREYS, palette, split, cache);
}

/// The palette the panel was last flushed through.
#[cfg(feature = "board-q1")]
static mut LAST_PALETTE: [u16; 16] = catcard_ui::st7789::GREYS;

/// Show a screen that is still drawn for the 128x64 mono panel.
///
/// On the OLED that framebuffer is the panel's own. On the Q1 it is copied at 2x into the
/// full canvas and flushed with it, so it replaces a full-screen frame completely instead
/// of leaving that frame's edges around a scaled window.
pub fn show_mono(panel: &mut Panel, fb: &catcard_ui::Mono128x64) {
    #[cfg(not(feature = "board-q1"))]
    {
        // Through the same cache as `show`: it records what the panel was last sent, and
        // this is the panel's own framebuffer type, whoever owns the buffer.
        // SAFETY: foreground only, single core, and not inside a draw.
        let cache = unsafe { &mut *core::ptr::addr_of_mut!(FRAME_SENT) };
        let _ = panel.flush_changed(fb, cache);
    }
    #[cfg(feature = "board-q1")]
    draw(panel, |c| {
        use catcard_ui::canvas::Canvas as _;
        c.clear();
        catcard_ui::canvas::blit_scaled(c, fb, 2);
    });
}

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
            gpio::configure(
                bl,
                Mode::Output,
                OutputType::PushPull,
                Pull::None,
                Speed::Low,
            );
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
        gpio::configure(
            request,
            Mode::Output,
            OutputType::OpenDrain,
            Pull::Up,
            Speed::Low,
        );
        gpio::write(request, true);
        gpio::enable_port(busy.port);
        gpio::configure(
            busy,
            Mode::Input,
            OutputType::PushPull,
            Pull::Down,
            Speed::Low,
        );
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
