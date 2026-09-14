//! Sitronix ST7789 colour LCD (Q / Q1), drawn on the bootloader's own setup.
//!
//! The Q1 bootloader resets and initialises this panel -- `MADCTL`, `COLMOD`, `INVON`,
//! `DISPON` -- and the firmware must inherit that state rather than repeat it: resetting a
//! working LCD blanks it and gains nothing (`hw-reference/display.md §Q1`, "inherit, do not
//! reset" [C]). So unlike [`crate::display::Ssd1306`] there is no init and no reset here.
//! The driver only opens a window and writes pixels.
//!
//! Every screen the firmware has draws into a 128x64 mono framebuffer. Until there is a
//! native Q1 UI the panel shows that framebuffer at [`SCALE`]x, centred, which makes the
//! whole firmware usable on a Q1 with one driver rather than a second set of screens.

use crate::canvas::{Canvas, Gray4};
use crate::display::DisplayBus;
use crate::framebuffer::Framebuffer;

/// The address space the bootloader's `MADCTL = 0x60` leaves: 320 columns by 240 rows.
/// Source: display.md §Q1 ST7789 init [C]
pub const WIDTH: usize = 320;
pub const HEIGHT: usize = 240;

/// Integer scale for the mono framebuffer: 128x64 at 2x is 256x128.
pub const SCALE: usize = 2;

/// The three commands drawing needs. MIPI DCS numbering, which the ST7789 uses. [C]
pub mod cmd {
    /// Column address set: start and end column, each big-endian.
    pub const CASET: u8 = 0x2A;
    /// Row address set: start and end row, each big-endian.
    pub const RASET: u8 = 0x2B;
    /// Memory write: every data byte after it is pixel data, filling the window.
    pub const RAMWR: u8 = 0x2C;
}

/// RGB565 black and white, sent high byte first -- the reference's `swab16` before SPI.
/// Source: display.md §Q1 "Pixel data" [C]
///
/// That `0x0000` *shows* black despite the bootloader's `INVON` is a fact about the glass,
/// which is inverted to match: first inferred by the emulator's model from the bootloader
/// clearing to `0x0000` before `DISPON`, then confirmed by eye on a Q1 running this driver
/// (white text on black, reading left to right). [C]
pub const BLACK: u16 = 0x0000;
pub const WHITE: u16 = 0xFFFF;

/// Pack red (5 bits), green (6 bits) and blue (5 bits) into RGB565. Bits beyond each
/// component's width are dropped rather than bleeding into the next.
pub const fn rgb565(r: u8, g: u8, b: u8) -> u16 {
    ((r as u16 & 0x1F) << 11) | ((g as u16 & 0x3F) << 5) | (b as u16 & 0x1F)
}

/// The colour chart's first band: the primaries and secondaries, brightest first.
pub const BARS: [u16; 8] = [
    WHITE,
    rgb565(31, 63, 0), // yellow
    rgb565(0, 63, 31), // cyan
    rgb565(0, 63, 0),  // green
    rgb565(31, 0, 31), // magenta
    rgb565(31, 0, 0),  // red
    rgb565(0, 0, 31),  // blue
    BLACK,
];

/// Sixteen greys, black to white: how a [`Gray4`] canvas's levels look when nothing asks
/// for colour. Green gets the sixth bit so every step is a distinct, rising RGB565 value.
pub const GREYS: [u16; 16] = {
    let mut p = [0u16; 16];
    let mut i = 0;
    while i < 16 {
        let v = (i * 31 / 15) as u8;
        p[i] = rgb565(v, (v << 1) | (v >> 4), v);
        i += 1;
    }
    p
};

/// Height of one colour-chart band: six of them fill the panel.
const BAND: usize = HEIGHT / 6;

/// Step `s` of the chart's ramp in `band`: 1 grey, 2 red, 3 green, 4 blue.
fn ramp(band: usize, s: usize) -> u16 {
    let v = s as u8;
    match band {
        // Grey: stretch 5 bits onto green's 6 so white is exactly 0xFFFF.
        1 => rgb565(v, (v << 1) | (v >> 4), v),
        2 => rgb565(v, 0, 0),
        3 => rgb565(0, v, 0),
        _ => rgb565(0, 0, v),
    }
}

/// Step `s` of 64 around the hue wheel at full saturation.
fn hue(s: usize) -> u16 {
    // Six 63-wide segments over 64 steps; within each, one component rises or falls.
    let x = s * 6 * 63 / 64;
    let (seg, f) = (x / 63, (x % 63) as u8);
    let (r, g, b) = match seg {
        0 => (63, f, 0),
        1 => (63 - f, 63, 0),
        2 => (0, 63, f),
        3 => (0, 63 - f, 63),
        4 => (f, 0, 63),
        _ => (63, 0, 63 - f),
    };
    rgb565(r >> 1, g, b >> 1)
}

/// A panel whose controller the bootloader already set up.
pub struct St7789<B: DisplayBus> {
    bus: B,
    fg: u16,
    bg: u16,
}

impl<B: DisplayBus> St7789<B> {
    /// Wrap a bus. Sends nothing: the panel is already initialised.
    pub fn new(bus: B) -> Self {
        Self {
            bus,
            fg: WHITE,
            bg: BLACK,
        }
    }

    /// Colours for lit and unlit framebuffer pixels.
    pub fn set_colours(&mut self, fg: u16, bg: u16) {
        self.fg = fg;
        self.bg = bg;
    }

    /// Open the inclusive window `[x0, x1] x [y0, y1]` and start a memory write.
    fn window(&mut self, x0: usize, y0: usize, x1: usize, y1: usize) -> Result<(), B::Error> {
        let be = |v: usize| (v as u16).to_be_bytes();
        let (a, b, c, d) = (be(x0), be(x1), be(y0), be(y1));
        self.bus.command(&[cmd::CASET])?;
        self.bus.data(&[a[0], a[1], b[0], b[1]])?;
        self.bus.command(&[cmd::RASET])?;
        self.bus.data(&[c[0], c[1], d[0], d[1]])?;
        self.bus.command(&[cmd::RAMWR])
    }

    /// Fill the whole panel with one colour.
    pub fn clear(&mut self, colour: u16) -> Result<(), B::Error> {
        self.fill_rect(0, 0, WIDTH, HEIGHT, colour)
    }

    /// Fill `w` x `h` pixels at `(x, y)` with one colour, clipped to the panel.
    pub fn fill_rect(
        &mut self,
        x: usize,
        y: usize,
        w: usize,
        h: usize,
        colour: u16,
    ) -> Result<(), B::Error> {
        if x >= WIDTH || y >= HEIGHT || w == 0 || h == 0 {
            return Ok(());
        }
        let (w, h) = (w.min(WIDTH - x), h.min(HEIGHT - y));
        self.window(x, y, x + w - 1, y + h - 1)?;
        let mut line = [0u8; WIDTH * 2];
        for px in line[..w * 2].as_chunks_mut::<2>().0 {
            *px = colour.to_be_bytes();
        }
        for _ in 0..h {
            self.bus.data(&line[..w * 2])?;
        }
        Ok(())
    }

    /// Paint the whole panel with a chart of what it can show, in six 40-pixel bands:
    ///
    /// 1. [`BARS`]: white, yellow, cyan, green, magenta, red, blue, black
    /// 2. grey, all 32 steps
    /// 3. red, all 32 steps of its 5 bits
    /// 4. green, all 64 steps of its 6 bits
    /// 5. blue, all 32 steps
    /// 6. a hue sweep at full saturation, red through the spectrum back to red
    ///
    /// The ramps are the point: a step that does not show is a bit that is not reaching
    /// the glass, and a band that comes out the wrong colour is a byte-order or colour-order
    /// mistake. This paints outside the centred UI window, so the caller wipes the panel
    /// before the mono UI draws again.
    pub fn draw_colour_chart(&mut self) -> Result<(), B::Error> {
        let bar = WIDTH / BARS.len();
        for (i, &c) in BARS.iter().enumerate() {
            self.fill_rect(i * bar, 0, bar, BAND, c)?;
        }
        for (band, steps) in [(1, 32), (2, 32), (3, 64), (4, 32)] {
            let w = WIDTH / steps;
            for s in 0..steps {
                self.fill_rect(s * w, band * BAND, w, BAND, ramp(band, s))?;
            }
        }
        let w = WIDTH / 64;
        for s in 0..64 {
            self.fill_rect(s * w, 5 * BAND, w, BAND, hue(s))?;
        }
        Ok(())
    }

    /// Draw a mono framebuffer at [`SCALE`]x, centred on the panel.
    ///
    /// One scaled line is built and sent [`SCALE`] times, so the bus sees whole rows
    /// rather than a transfer per pixel. A framebuffer larger than the panel at this
    /// scale is clipped to it rather than wrapping.
    pub fn flush<const W: usize, const P: usize, const N: usize>(
        &mut self,
        fb: &Framebuffer<W, P, N>,
    ) -> Result<(), B::Error> {
        let w = (W * SCALE).min(WIDTH);
        let h = (P * 8 * SCALE).min(HEIGHT);
        if w == 0 || h == 0 {
            return Ok(());
        }
        let (x0, y0) = ((WIDTH - w) / 2, (HEIGHT - h) / 2);
        self.window(x0, y0, x0 + w - 1, y0 + h - 1)?;

        let (fg, bg) = (self.fg.to_be_bytes(), self.bg.to_be_bytes());
        let mut line = [0u8; WIDTH * 2];
        for fy in 0..h / SCALE {
            for x in 0..w {
                let px = if fb.get(x / SCALE, fy) { fg } else { bg };
                line[x * 2..x * 2 + 2].copy_from_slice(&px);
            }
            for _ in 0..SCALE {
                self.bus.data(&line[..w * 2])?;
            }
        }
        Ok(())
    }

    /// Push a 16-level canvas at its own size -- no scaling -- mapping each level through
    /// `palette`. A canvas smaller than the panel is centred; a larger one is clipped.
    ///
    /// This is the full-screen path: a 320x240 [`Gray4`] covers the whole panel pixel for
    /// pixel, which is what lets screens use all of it rather than a doubled 128x64.
    pub fn flush_gray<const W: usize, const H: usize, const N: usize>(
        &mut self,
        fb: &Gray4<W, H, N>,
        palette: &[u16; 16],
    ) -> Result<(), B::Error> {
        let (w, h) = (W.min(WIDTH), H.min(HEIGHT));
        if w == 0 || h == 0 {
            return Ok(());
        }
        let (x0, y0) = ((WIDTH - w) / 2, (HEIGHT - h) / 2);
        self.window(x0, y0, x0 + w - 1, y0 + h - 1)?;
        let mut line = [0u8; WIDTH * 2];
        for y in 0..h {
            for (x, px) in line[..w * 2].as_chunks_mut::<2>().0.iter_mut().enumerate() {
                *px = palette[fb.get(x, y) as usize & 0x0F].to_be_bytes();
            }
            self.bus.data(&line[..w * 2])?;
        }
        Ok(())
    }

    pub fn bus_mut(&mut self) -> &mut B {
        &mut self.bus
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framebuffer::Mono128x64;

    #[derive(Default)]
    struct MockBus {
        resets: usize,
        /// `(dc_high, bytes)` in order.
        log: Vec<(bool, Vec<u8>)>,
    }

    impl DisplayBus for MockBus {
        type Error = ();
        fn command(&mut self, bytes: &[u8]) -> Result<(), ()> {
            self.log.push((false, bytes.to_vec()));
            Ok(())
        }
        fn data(&mut self, bytes: &[u8]) -> Result<(), ()> {
            self.log.push((true, bytes.to_vec()));
            Ok(())
        }
        fn reset(&mut self) -> Result<(), ()> {
            self.resets += 1;
            Ok(())
        }
    }

    impl MockBus {
        fn commands(&self) -> Vec<u8> {
            self.log
                .iter()
                .filter(|(dc, _)| !dc)
                .flat_map(|(_, b)| b.clone())
                .collect()
        }
        /// Data bytes after the last RAMWR.
        fn pixels(&self) -> Vec<u8> {
            let at = self
                .log
                .iter()
                .rposition(|(dc, b)| !dc && b == &[cmd::RAMWR])
                .expect("no RAMWR");
            self.log[at + 1..]
                .iter()
                .flat_map(|(_, b)| b.clone())
                .collect()
        }
    }

    #[test]
    fn construction_sends_nothing_and_nothing_ever_resets_the_panel() {
        // The bootloader owns the reset and the init. A driver that sent either would
        // blank the LCD the firmware is supposed to inherit.
        let mut p = St7789::new(MockBus::default());
        assert!(p.bus_mut().log.is_empty());
        p.flush(&Mono128x64::new()).unwrap();
        p.clear(BLACK).unwrap();
        assert_eq!(p.bus_mut().resets, 0);
        for c in p.bus_mut().commands() {
            assert!(
                [cmd::CASET, cmd::RASET, cmd::RAMWR].contains(&c),
                "sent command {c:#04x}, which only the bootloader may send"
            );
        }
    }

    #[test]
    fn flush_opens_a_centred_window_the_size_of_the_scaled_framebuffer() {
        let mut p = St7789::new(MockBus::default());
        p.flush(&Mono128x64::new()).unwrap();
        let log = &p.bus_mut().log;
        // 256x128 centred on 320x240: columns 32..=287, rows 56..=183.
        assert_eq!(log[0], (false, vec![cmd::CASET]));
        assert_eq!(log[1], (true, vec![0x00, 32, 0x01, 0x1F]));
        assert_eq!(log[2], (false, vec![cmd::RASET]));
        assert_eq!(log[3], (true, vec![0x00, 56, 0x00, 183]));
        assert_eq!(log[4], (false, vec![cmd::RAMWR]));
        assert_eq!(p.bus_mut().pixels().len(), 256 * 128 * 2);
    }

    #[test]
    fn a_lit_pixel_becomes_a_scale_by_scale_block_high_byte_first() {
        let mut fb = Mono128x64::new();
        fb.set(0, 0, true);
        let mut p = St7789::new(MockBus::default());
        p.set_colours(0xF800, 0x001F); // red on blue: the byte order is visible
        p.flush(&fb).unwrap();
        let px = p.bus_mut().pixels();
        let at = |x: usize, y: usize| [px[(y * 256 + x) * 2], px[(y * 256 + x) * 2 + 1]];
        for (x, y) in [(0, 0), (1, 0), (0, 1), (1, 1)] {
            assert_eq!(at(x, y), [0xF8, 0x00], "({x},{y}) should be lit");
        }
        assert_eq!(at(2, 0), [0x00, 0x1F]);
        assert_eq!(at(0, 2), [0x00, 0x1F]);
    }

    /// Replay the bus log onto a 320x240 frame: CASET and RASET set the window, and the
    /// data after RAMWR fills it left to right, top to bottom -- what the controller does.
    fn replay(log: &[(bool, Vec<u8>)]) -> Vec<u16> {
        let mut frame = vec![0u16; WIDTH * HEIGHT];
        let (mut xs, mut xe, mut ys, mut ye) = (0, 0, 0, 0);
        let (mut x, mut y) = (0, 0);
        let mut last = 0u8;
        for (dc, bytes) in log {
            if !dc {
                last = bytes[0];
                if last == cmd::RAMWR {
                    (x, y) = (xs, ys);
                }
                continue;
            }
            let be = |i: usize| u16::from_be_bytes([bytes[i], bytes[i + 1]]) as usize;
            match last {
                cmd::CASET => (xs, xe) = (be(0), be(2)),
                cmd::RASET => (ys, ye) = (be(0), be(2)),
                cmd::RAMWR => {
                    for px in bytes.as_chunks::<2>().0 {
                        if y <= ye {
                            frame[y * WIDTH + x] = u16::from_be_bytes(*px);
                        }
                        x += 1;
                        if x > xe {
                            (x, y) = (xs, y + 1);
                        }
                    }
                }
                _ => {}
            }
        }
        frame
    }

    #[test]
    fn rgb565_masks_each_component_to_its_width() {
        assert_eq!(rgb565(0xFF, 0, 0), 0xF800);
        assert_eq!(rgb565(0, 0xFF, 0), 0x07E0);
        assert_eq!(rgb565(0, 0, 0xFF), 0x001F);
        assert_eq!(rgb565(31, 63, 31), WHITE);
    }

    #[test]
    fn fill_rect_clips_to_the_panel_and_skips_what_is_off_it() {
        let mut p = St7789::new(MockBus::default());
        p.fill_rect(310, 230, 50, 50, WHITE).unwrap();
        assert_eq!(p.bus_mut().log[1], (true, vec![0x01, 0x36, 0x01, 0x3F]));
        assert_eq!(p.bus_mut().log[3], (true, vec![0x00, 230, 0x00, 239]));
        assert_eq!(p.bus_mut().pixels().len(), 10 * 10 * 2);

        let mut p = St7789::new(MockBus::default());
        p.fill_rect(WIDTH, 0, 10, 10, WHITE).unwrap();
        p.fill_rect(0, 0, 0, 10, WHITE).unwrap();
        assert!(p.bus_mut().log.is_empty(), "drew something that is not on the panel");
    }

    #[test]
    fn the_colour_chart_paints_every_pixel_once_with_the_bands_it_documents() {
        let mut p = St7789::new(MockBus::default());
        p.draw_colour_chart().unwrap();
        let log = &p.bus_mut().log;

        // Window parameters are 4-byte data; every pixel run in the chart is 10+ bytes.
        let painted: usize = log
            .iter()
            .filter(|(dc, b)| *dc && b.len() > 4)
            .map(|(_, b)| b.len())
            .sum();
        assert_eq!(painted, WIDTH * HEIGHT * 2, "not every pixel exactly once");

        let f = replay(log);
        let at = |x: usize, y: usize| f[y * WIDTH + x];
        for (i, &c) in BARS.iter().enumerate() {
            assert_eq!(at(i * 40 + 20, 20), c, "bar {i}");
        }
        // Ramps start at black and end at the full component.
        for y in [60, 100, 140, 180] {
            assert_eq!(at(1, y), BLACK, "ramp at y={y} does not start black");
        }
        assert_eq!(at(315, 60), WHITE, "grey should top out at exactly white");
        assert_eq!(at(315, 100), 0xF800);
        assert_eq!(at(317, 140), 0x07E0);
        assert_eq!(at(315, 180), 0x001F);
        // Every step is a distinct, brighter value: a stuck bit would repeat one.
        let reds: Vec<u16> = (0..32).map(|s| at(s * 10 + 5, 100)).collect();
        let greens: Vec<u16> = (0..64).map(|s| at(s * 5 + 2, 140)).collect();
        let blues: Vec<u16> = (0..32).map(|s| at(s * 10 + 5, 180)).collect();
        for (name, r) in [("red", &reds), ("green", &greens), ("blue", &blues)] {
            assert!(r.windows(2).all(|w| w[1] > w[0]), "{name} ramp not rising");
        }
        // The hue sweep starts and ends at red.
        assert_eq!(at(2, 220), 0xF800);
        assert_eq!(at(317, 220) >> 11, 31, "sweep should end back at red");
    }

    #[test]
    fn a_full_screen_gray_canvas_is_sent_one_to_one_through_the_palette() {
        let mut g = crate::canvas::Gray320x240::new();
        g.put(0, 0, 15);
        g.put(1, 0, 7);
        g.put(319, 239, 3);
        let mut p = St7789::new(MockBus::default());
        p.flush_gray(&g, &GREYS).unwrap();
        assert_eq!(p.bus_mut().log[1], (true, vec![0, 0, 0x01, 0x3F]));
        assert_eq!(p.bus_mut().log[3], (true, vec![0, 0, 0x00, 0xEF]));
        assert_eq!(p.bus_mut().pixels().len(), WIDTH * HEIGHT * 2, "not 1:1");
        let f = replay(&p.bus_mut().log);
        assert_eq!(f[0], GREYS[15]);
        assert_eq!(f[1], GREYS[7], "the right pixel of a byte is its low nibble");
        assert_eq!(f[2], GREYS[0]);
        assert_eq!(f[239 * WIDTH + 319], GREYS[3]);
    }

    #[test]
    fn the_grey_palette_runs_from_black_to_white_rising_every_step() {
        assert_eq!(GREYS[0], BLACK);
        assert_eq!(GREYS[15], WHITE);
        assert!(GREYS.windows(2).all(|w| w[1] > w[0]));
    }

    #[test]
    fn clear_covers_the_whole_panel() {
        let mut p = St7789::new(MockBus::default());
        p.clear(WHITE).unwrap();
        let log = &p.bus_mut().log;
        assert_eq!(log[1], (true, vec![0, 0, 0x01, 0x3F]));
        assert_eq!(log[3], (true, vec![0, 0, 0x00, 0xEF]));
        let px = p.bus_mut().pixels();
        assert_eq!(px.len(), WIDTH * HEIGHT * 2);
        assert!(px.iter().all(|&b| b == 0xFF));
    }
}
