//! SSD1306 panel driver.
//!
//! Split from the bus deliberately: this module knows the command sequence and the
//! memory layout, and nothing about SPI or GPIO. The firmware supplies a [`DisplayBus`]
//! that drives the D/C line and pushes bytes; the host test suite supplies a recording
//! mock. That is what makes the init sequence and the flush window testable without
//! hardware — the parts most likely to be wrong and least likely to announce it.

use crate::framebuffer::Framebuffer;
use crate::ssd1306::{INIT_128X64, cmd, full_window};

/// What the driver needs from the outside world.
///
/// The D/C line is part of the *transfer*, not a separate operation: it must be settled
/// before the first clock edge of the bytes it describes. Modelling it as two methods
/// rather than a settable pin makes that ordering impossible to get wrong.
pub trait DisplayBus {
    type Error;

    /// Send bytes with D/C low.
    fn command(&mut self, bytes: &[u8]) -> Result<(), Self::Error>;

    /// Send bytes with D/C high.
    fn data(&mut self, bytes: &[u8]) -> Result<(), Self::Error>;

    /// Pulse the panel's reset line and leave it deasserted.
    fn reset(&mut self) -> Result<(), Self::Error>;
}

/// A driver bound to a bus.
pub struct Ssd1306<B: DisplayBus> {
    bus: B,
    width: u8,
    pages: u8,
}

impl<B: DisplayBus> Ssd1306<B> {
    /// Wrap a bus for a 128x64 panel.
    pub fn new_128x64(bus: B) -> Self {
        Self {
            bus,
            width: 128,
            pages: 8,
        }
    }

    /// Reset the panel and run the initialisation sequence.
    pub fn init(&mut self) -> Result<(), B::Error> {
        self.bus.reset()?;
        self.bus.command(INIT_128X64)
    }

    /// Bring up the mk5 panel: same reset, but the mk5 init sequence.
    ///
    /// The panel is fed from the external +12 V rail (V12EN), so the SSD1306's internal
    /// charge pump is left **disabled** and the segment/COM scan is unflipped -- the mk4
    /// sequence, which enables the pump and flips orientation, would leave an mk5 panel
    /// dark or upside down. See [`INIT_128X64_MK5`](crate::ssd1306::INIT_128X64_MK5).
    pub fn init_mk5(&mut self) -> Result<(), B::Error> {
        self.bus.reset()?;
        self.bus.command(crate::ssd1306::INIT_128X64_MK5)
    }

    /// Push a whole framebuffer.
    ///
    /// Sets the column and page window first. Without that the controller keeps
    /// whatever window a previous partial write left behind, and the image wraps —
    /// which looks like a corrupted framebuffer rather than a missing command.
    ///
    /// Stops any scrolling first, which is both what the datasheet asks for before
    /// rewriting the ram and the rule that keeps [`scroll_pages`](Self::scroll_pages)
    /// honest: a bar left scrolling would go on sliding under the next screen's text, so
    /// scrolling lasts exactly as long as the frame that asked for it.
    pub fn flush<const W: usize, const P: usize, const N: usize>(
        &mut self,
        fb: &Framebuffer<W, P, N>,
    ) -> Result<(), B::Error> {
        self.bus.command(&crate::ssd1306::SCROLL_OFF)?;
        self.bus.command(&full_window(self.width, self.pages))?;
        self.bus.data(fb.as_bytes())
    }

    /// Have the controller scroll pages `first..=last` sideways until the next flush.
    ///
    /// For the waits the firmware cannot draw through: a callgate call holds the CPU with
    /// interrupts masked, and this keeps moving anyway because the panel does it itself.
    /// See [`ssd1306::scroll_right`](crate::ssd1306::scroll_right).
    pub fn scroll_pages(
        &mut self,
        first: u8,
        last: u8,
        interval: crate::ssd1306::Interval,
    ) -> Result<(), B::Error> {
        self.bus
            .command(&crate::ssd1306::scroll_right(first, last, interval))
    }

    /// [`scroll_pages`](Self::scroll_pages) for a panel that takes the column range too --
    /// the mk5's. See [`ssd1306::scroll_right_with_columns`](crate::ssd1306::scroll_right_with_columns)
    /// for why this must never go to an SSD1306.
    pub fn scroll_pages_with_columns(
        &mut self,
        first: u8,
        last: u8,
        interval: crate::ssd1306::Interval,
    ) -> Result<(), B::Error> {
        self.bus.command(&crate::ssd1306::scroll_right_with_columns(
            first, last, interval,
        ))
    }

    /// Turn the panel on or off without discarding its contents.
    pub fn set_on(&mut self, on: bool) -> Result<(), B::Error> {
        self.bus.command(&[if on {
            cmd::DISPLAY_ON
        } else {
            cmd::DISPLAY_OFF
        }])
    }

    /// Set contrast, 0 to 255.
    pub fn set_contrast(&mut self, level: u8) -> Result<(), B::Error> {
        self.bus.command(&[cmd::SET_CONTRAST, level])
    }

    /// Invert the panel. Useful as an unmissable warning state.
    pub fn set_inverted(&mut self, inverted: bool) -> Result<(), B::Error> {
        self.bus.command(&[if inverted {
            cmd::INVERT_DISPLAY
        } else {
            cmd::NORMAL_DISPLAY
        }])
    }

    pub fn bus_mut(&mut self) -> &mut B {
        &mut self.bus
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framebuffer::Mono128x64;

    /// Records everything the driver sends, tagged by D/C state.
    #[derive(Default)]
    struct MockBus {
        resets: usize,
        commands: Vec<Vec<u8>>,
        data: Vec<Vec<u8>>,
        /// Every call in order, so ordering bugs are visible.
        log: Vec<&'static str>,
    }

    impl DisplayBus for MockBus {
        type Error = ();
        fn command(&mut self, bytes: &[u8]) -> Result<(), ()> {
            self.commands.push(bytes.to_vec());
            self.log.push("cmd");
            Ok(())
        }
        fn data(&mut self, bytes: &[u8]) -> Result<(), ()> {
            self.data.push(bytes.to_vec());
            self.log.push("data");
            Ok(())
        }
        fn reset(&mut self) -> Result<(), ()> {
            self.resets += 1;
            self.log.push("reset");
            Ok(())
        }
    }

    #[test]
    fn init_resets_before_sending_commands() {
        // Commands sent before the reset pulse are discarded by the panel, which
        // presents as a display that stays dark for no visible reason.
        let mut d = Ssd1306::new_128x64(MockBus::default());
        d.init().unwrap();
        assert_eq!(d.bus_mut().log, vec!["reset", "cmd"]);
        assert_eq!(d.bus_mut().resets, 1);
        assert_eq!(d.bus_mut().commands[0], INIT_128X64);
    }

    #[test]
    fn flush_sets_the_window_before_the_data() {
        let mut d = Ssd1306::new_128x64(MockBus::default());
        let fb = Mono128x64::new();
        d.flush(&fb).unwrap();

        assert_eq!(d.bus_mut().log, vec!["cmd", "cmd", "data"]);
        assert_eq!(d.bus_mut().commands[0], vec![cmd::SCROLL_OFF]);
        assert_eq!(
            d.bus_mut().commands[1],
            vec![cmd::COLUMN_ADDR, 0, 127, cmd::PAGE_ADDR, 0, 7]
        );
        assert_eq!(d.bus_mut().data[0].len(), 1024);
    }

    #[test]
    fn a_scroll_is_set_up_stopped_and_only_then_started() {
        // Order matters: the controller ignores scroll setup while a scroll is running,
        // so a bar asked for twice would keep the first bar's page range.
        let mut d = Ssd1306::new_128x64(MockBus::default());
        d.scroll_pages(7, 7, crate::ssd1306::Interval::FASTEST)
            .unwrap();
        let c = d.bus_mut().commands[0].clone();
        assert_eq!(c[0], cmd::SCROLL_OFF);
        assert_eq!(c[1], cmd::SCROLL_RIGHT);
        assert_eq!((c[3], c[5]), (7, 7), "page range");
        assert_eq!(*c.last().unwrap(), cmd::SCROLL_ON);
    }

    #[test]
    fn a_flush_stops_whatever_was_scrolling() {
        // Otherwise the busy bar keeps sliding under the screen that replaced it -- and
        // the datasheet wants the ram rewritten after a scroll stops anyway.
        let mut d = Ssd1306::new_128x64(MockBus::default());
        d.scroll_pages(7, 7, crate::ssd1306::Interval::FASTEST)
            .unwrap();
        d.flush(&Mono128x64::new()).unwrap();
        assert_eq!(d.bus_mut().commands[1], vec![cmd::SCROLL_OFF]);
    }

    #[test]
    fn flush_sends_the_framebuffer_verbatim() {
        let mut d = Ssd1306::new_128x64(MockBus::default());
        let mut fb = Mono128x64::new();
        fb.set(0, 0, true);
        fb.set(127, 63, true);
        d.flush(&fb).unwrap();
        assert_eq!(d.bus_mut().data[0], fb.as_bytes());
    }

    #[test]
    fn display_data_never_travels_as_commands() {
        // A byte of pixel data interpreted as a command can reconfigure the panel.
        let mut d = Ssd1306::new_128x64(MockBus::default());
        let mut fb = Mono128x64::new();
        fb.fill();
        d.init().unwrap();
        d.flush(&fb).unwrap();
        for c in &d.bus_mut().commands {
            assert!(c.len() < 64, "a command block looks like pixel data");
        }
    }

    #[test]
    fn power_and_contrast_are_single_commands() {
        let mut d = Ssd1306::new_128x64(MockBus::default());
        d.set_on(true).unwrap();
        d.set_on(false).unwrap();
        d.set_contrast(0x40).unwrap();
        d.set_inverted(true).unwrap();
        d.set_inverted(false).unwrap();
        let c = &d.bus_mut().commands;
        assert_eq!(c[0], vec![cmd::DISPLAY_ON]);
        assert_eq!(c[1], vec![cmd::DISPLAY_OFF]);
        assert_eq!(c[2], vec![cmd::SET_CONTRAST, 0x40]);
        assert_eq!(c[3], vec![cmd::INVERT_DISPLAY]);
        assert_eq!(c[4], vec![cmd::NORMAL_DISPLAY]);
    }

    #[test]
    fn a_bus_error_propagates_rather_than_being_swallowed() {
        struct Failing;
        impl DisplayBus for Failing {
            type Error = u8;
            fn command(&mut self, _: &[u8]) -> Result<(), u8> {
                Err(7)
            }
            fn data(&mut self, _: &[u8]) -> Result<(), u8> {
                Err(7)
            }
            fn reset(&mut self) -> Result<(), u8> {
                Ok(())
            }
        }
        let mut d = Ssd1306::new_128x64(Failing);
        assert_eq!(d.init(), Err(7));
        assert_eq!(d.flush(&Mono128x64::new()), Err(7));
    }
}
