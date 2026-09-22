//! Sitronix ST7789 colour LCD (Q / Q1), drawn on the bootloader's own setup.
//!
//! The Q1 bootloader resets and initialises this panel -- `MADCTL`, `COLMOD`, `INVON`,
//! `DISPON` -- and the firmware must inherit that state rather than repeat it: resetting a
//! working LCD blanks it and gains nothing (`hw-reference/display.md §Q1`, "inherit, do not
//! reset" [C]). So unlike [`crate::display::Ssd1306`] there is no init and no reset here.
//! The driver only opens a window and writes pixels.
//!
//! Screens draw into a 16-level [`Gray4`] canvas the size of the panel, which
//! [`St7789::flush_gray_changed`] sends through a palette, only the rows that changed.
//! [`St7789::flush`] still shows a 128x64 mono framebuffer at [`SCALE`]x, for anything
//! drawn that way.

use crate::canvas::Gray4;
use crate::display::DisplayBus;
use crate::framebuffer::Framebuffer;

/// The address space the bootloader's `MADCTL = 0x60` leaves: 320 columns by 240 rows.
/// Source: display.md §Q1 ST7789 init [C]
pub const WIDTH: usize = 320;
pub const HEIGHT: usize = 240;

/// Integer scale for the mono framebuffer: 128x64 at 2x is 256x128.
pub const SCALE: usize = 2;

/// The commands this driver sends. MIPI DCS numbering, which the ST7789 uses. [C]
pub mod cmd {
    /// Normal display mode on: leaves partial and scrolling modes.
    /// Source: Sitronix ST7789V datasheet, command 13h NORON [C]
    pub const NORON: u8 = 0x13;
    /// Vertical scrolling definition: top fixed, scrolled, bottom fixed line counts, each
    /// big-endian, summing to the panel's 320 lines. Source: ST7789V datasheet, command 33h VSCRDEF [C]
    pub const VSCRDEF: u8 = 0x33;
    /// Vertical scroll start address: the frame-memory line shown first in the scrolled
    /// area, big-endian. Source: ST7789V datasheet, command 37h VSCSAD [C]
    pub const VSCSAD: u8 = 0x37;
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

/// The device's own ramp: the artwork's background up to white.
///
/// This is what an ordinary screen paints in. Index 0 is `#303030` -- the same grey the
/// icons are drawn on, exactly, so a list and the icon grid are the same surface rather
/// than two screens that happen to be next to each other. Index 15 is white, which is
/// what text and a selected row's bar are drawn in.
///
/// Neutral all the way up, with no hue in it: the marks in a list carry the colour, and
/// a ramp with a tint of its own would put a cast on every logo's anti-aliased edge,
/// which is blended against these levels.
///
/// **This replaces the amber.** The bootloader hands over in amber and the stock
/// firmware stays there, so painting in it was a parity claim: the device did not change
/// colour between the loader and the firmware. That was worth keeping while the UI was
/// text on a ramp. It is not worth keeping now that the screens carry pictures drawn on
/// `#303030` -- amber behind them made every icon look pasted onto the wrong page.
///
/// So nothing in this firmware paints in [`AMBER`] any more. The constant stays because
/// it is the reference's own sixteen values, which is a fact about the hardware worth
/// keeping written down whether or not a screen uses it.
pub const SLATE: [u16; 16] = {
    let mut p = [0u16; 16];
    let mut i = 0;
    while i < 16 {
        // 0x30 to 0xFF in sixteen steps, at each channel's own depth so index 0 is
        // exactly `#303030` (0x3186) and index 15 is exactly white.
        let v8 = 0x30 + (0xFF - 0x30) * i / 15;
        p[i] = rgb565((v8 >> 3) as u8, (v8 >> 2) as u8, (v8 >> 3) as u8);
        i += 1;
    }
    p
};

/// Black to the Coldcard amber: the hue the bootloader and the stock UI paint in.
///
/// The top of the ramp is `COL_TEXT` = `0xFD60` = (31, 43, 0), and blue stays at zero the
/// whole way up, which is what makes it one hue rather than a wash toward white. Because
/// the levels are a ramp and not a single colour, anti-aliased glyph edges land on dimmer
/// *amber* instead of fringing grey.
///
/// These are the reference's own sixteen values rather than a ramp recomputed here. A
/// linear one is close but not identical — index 11 would come out (22, 31, 0) against
/// the real (21, 30, 0) — and "the same amber as the bootloader" is a parity claim, so it
/// is copied rather than approximated.
///
/// The values are true RGB565; [`St7789::send_gray_rows`] emits them big-endian. The
/// stock firmware stores its own copies byte-swapped to suit `swab16`, which is a fact
/// about its storage and not about these numbers.
///
/// Source: hw-reference/display.md §"Q1 — colour palette & screen layout" [C]
pub const AMBER: [u16; 16] = [
    0x0000, 0x0840, 0x18A0, 0x2900, 0x3940, 0x49A0, 0x5A00, 0x6A60, 0x7AA0, 0x8B00, 0x9B60, 0xABC0,
    0xBC00, 0xDCC0, 0xED00, 0xFD60,
];

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

/// Full-colour pixels laid over the canvas as it is flushed: a `w` x `h` rectangle at
/// `(x, y)` in the framebuffer's own coordinates, `pixels` row after row, RGB565.
///
/// The canvas is 4 bits a pixel; the panel takes 16. Something that needs its own colours
/// -- a coin's logo -- is put into each row's line as the flush builds it, so every pixel
/// reaches the panel once, already final. Painted afterwards instead, the row would first
/// go out with a hole where the picture belongs, and the hole would show as a flicker.
pub struct Overlay<'a> {
    pub x: usize,
    pub y: usize,
    pub w: usize,
    pub h: usize,
    pub pixels: &'a [u16],
}

impl Overlay<'_> {
    /// This overlay's pixels on framebuffer row `y`, if it covers it.
    fn row(&self, y: usize) -> Option<&[u16]> {
        let dy = y.checked_sub(self.y).filter(|&d| d < self.h)?;
        self.pixels.get(dy * self.w..(dy + 1) * self.w)
    }
}

/// Hashes of the rows last sent, so a redraw sends only the rows that changed.
///
/// A full frame is 153,600 bytes of SPI, polled a byte at a time; a menu step or a progress
/// tick changes a handful of rows of it. A hash per row costs 1 KB, where remembering the
/// frame itself would cost another 38 KB. Two different rows hashing alike would leave one
/// stale until something else redraws it -- a 1-in-2^32 cosmetic fault, not a data one.
pub struct RowCache<const H: usize> {
    hashes: [u32; H],
    valid: bool,
}

impl<const H: usize> Default for RowCache<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const H: usize> RowCache<H> {
    /// Knows nothing yet: the first flush through it sends every row.
    pub const fn new() -> Self {
        Self {
            hashes: [0; H],
            valid: false,
        }
    }

    /// Forget what the panel shows, so the next flush sends every row. For anything that
    /// drew on the panel without going through the cache.
    pub fn invalidate(&mut self) {
        self.valid = false;
    }
}

impl<const H: usize> RowCache<H> {
    /// Record rows `from..` as already on the glass, for a caller that put them there
    /// by another route -- a page slid in by the panel's own scrolling, which reaches
    /// the frame memory without going through a flush.
    ///
    /// Rows above `from` keep the hashes they had, which still describe what the panel
    /// shows: a caller that scrolls a page moves those rows about but does not change
    /// what is in them. The next flush then sends exactly the rows that really did
    /// change -- the status bar, if the clock ticked -- and nothing else.
    ///
    /// Overlays are not considered: a frame put there this way carries no full-colour
    /// marks, and a caller that has some must flush instead.
    pub fn note<const W: usize, const N: usize>(&mut self, fb: &Gray4<W, H, N>, from: usize) {
        let row_len = W.div_ceil(2);
        let bytes = fb.as_bytes();
        for y in from..H.min(HEIGHT) {
            self.hashes[y] = row_hash(&bytes[y * row_len..(y + 1) * row_len]);
        }
        self.valid = true;
    }
}

/// FNV-1a over one packed row.
fn row_hash(bytes: &[u8]) -> u32 {
    let mut h: u32 = 0x811C_9DC5;
    for &b in bytes {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
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

    /// Paint `w` x `h` pixels at `(x, y)`, each the colour `f(dx, dy)` gives, clipped to the
    /// panel. One window and one row buffer, so a sprite is a single short transfer rather
    /// than a window per pixel.
    pub fn paint(
        &mut self,
        x: usize,
        y: usize,
        w: usize,
        h: usize,
        mut f: impl FnMut(usize, usize) -> u16,
    ) -> Result<(), B::Error> {
        if x >= WIDTH || y >= HEIGHT || w == 0 || h == 0 {
            return Ok(());
        }
        let (w, h) = (w.min(WIDTH - x), h.min(HEIGHT - y));
        self.window(x, y, x + w - 1, y + h - 1)?;
        let mut line = [0u8; WIDTH * 2];
        for dy in 0..h {
            for (dx, px) in line[..w * 2].as_chunks_mut::<2>().0.iter_mut().enumerate() {
                *px = f(dx, dy).to_be_bytes();
            }
            self.bus.data(&line[..w * 2])?;
        }
        Ok(())
    }

    /// Scroll the panel in the controller, with no pixels sent: the frame memory is a ring
    /// of [`WIDTH`] lines, and `set_scroll_start` picks which of them is shown first.
    ///
    /// The ST7789 calls this vertical scrolling. Its lines run along the panel's long side,
    /// and the Q1 mounts the panel landscape, so on this board it moves the picture
    /// **sideways**, and the fixed areas are strips at the left and right edges rather than
    /// bands at the top and bottom. Which edge is "first", and which way a growing start
    /// moves the picture, depends on `MADCTL` and is measured, not assumed -- see the
    /// Debug scroll test.
    ///
    /// `fixed_first + fixed_last` must leave at least one line to scroll; the scrolled
    /// area is whatever remains of the 320.
    ///
    /// Source: ST7789V datasheet, commands 33h VSCRDEF and 37h VSCSAD [C]
    pub fn set_scroll_area(
        &mut self,
        fixed_first: usize,
        fixed_last: usize,
    ) -> Result<(), B::Error> {
        let fixed_first = fixed_first.min(WIDTH - 1);
        let fixed_last = fixed_last.min(WIDTH - 1 - fixed_first);
        let scrolled = WIDTH - fixed_first - fixed_last;
        let (a, b, c) = (
            (fixed_first as u16).to_be_bytes(),
            (scrolled as u16).to_be_bytes(),
            (fixed_last as u16).to_be_bytes(),
        );
        self.bus.command(&[cmd::VSCRDEF])?;
        self.bus.data(&[a[0], a[1], b[0], b[1], c[0], c[1]])
    }

    /// Show frame-memory line `line` first in the scrolled area. See
    /// [`set_scroll_area`](Self::set_scroll_area).
    pub fn set_scroll_start(&mut self, line: usize) -> Result<(), B::Error> {
        let v = ((line % WIDTH) as u16).to_be_bytes();
        self.bus.command(&[cmd::VSCSAD])?;
        self.bus.data(&v)
    }

    /// Put scrolling back as the rest of the firmware assumes it: start 0, the whole panel
    /// one area, normal display mode. Every other drawing path addresses the panel as if
    /// nothing were shifted, so a scroll left behind garbles every screen after it.
    pub fn end_scroll(&mut self) -> Result<(), B::Error> {
        self.set_scroll_start(0)?;
        self.set_scroll_area(0, 0)?;
        self.bus.command(&[cmd::NORON])
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
    /// mistake. This paints the panel directly, behind any canvas, so the caller wipes the
    /// panel and invalidates its row cache before the next frame.
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
        self.send_gray_rows(fb, palette, w, 0, h, &[])
    }

    /// [`flush_gray`](Self::flush_gray), sending only the rows that changed since the last
    /// flush through `cache` -- in runs, one window per run. Returns the rows sent.
    ///
    /// The cache is marked valid only once every run has gone out, so a transfer that fails
    /// part-way makes the next flush send the whole frame rather than trust a half-sent one.
    pub fn flush_gray_changed<const W: usize, const H: usize, const N: usize>(
        &mut self,
        fb: &Gray4<W, H, N>,
        palette: &[u16; 16],
        cache: &mut RowCache<H>,
    ) -> Result<usize, B::Error> {
        self.flush_gray_changed_split(fb, palette, palette, 0, cache, &[])
    }

    /// [`flush_gray_changed`](Self::flush_gray_changed) with a different palette for the
    /// rows above `split`.
    ///
    /// The canvas holds an index per pixel and the palette is what turns one into a
    /// colour, at send time -- so two regions of one frame can be two different colour
    /// ramps without the drawing code knowing. That is how the status bar comes out in
    /// grey and white over a screen that is otherwise the bootloader's amber: nothing
    /// about the canvas changes, only which table its indices are read through.
    ///
    /// `split` is the first row that uses `bottom`; rows before it use `top`. A run of
    /// changed rows never spans the boundary, since one send is one palette.
    pub fn flush_gray_changed_split<const W: usize, const H: usize, const N: usize>(
        &mut self,
        fb: &Gray4<W, H, N>,
        top: &[u16; 16],
        bottom: &[u16; 16],
        split: usize,
        cache: &mut RowCache<H>,
        overlays: &[Overlay<'_>],
    ) -> Result<usize, B::Error> {
        let (w, h) = (W.min(WIDTH), H.min(HEIGHT));
        if w == 0 || h == 0 {
            return Ok(0);
        }
        let (x0, y0) = ((WIDTH - w) / 2, (HEIGHT - h) / 2);
        let bytes = fb.as_bytes();
        let row_len = W.div_ceil(2);
        let trusted = core::mem::replace(&mut cache.valid, false);
        let changed = |cache: &mut RowCache<H>, y: usize| {
            // What goes out on this row is the canvas row *and* any overlay on it, so both
            // go into the hash: a logo that changes on an unchanged row still resends it,
            // and an unchanged row with its logo is not sent at all.
            let mut hash = row_hash(&bytes[y * row_len..(y + 1) * row_len]);
            for o in overlays {
                if let Some(px) = o.row(y) {
                    for p in px {
                        for b in p.to_be_bytes() {
                            hash ^= b as u32;
                            hash = hash.wrapping_mul(0x0100_0193);
                        }
                    }
                    hash ^= o.x as u32;
                }
            }
            let differs = !trusted || cache.hashes[y] != hash;
            cache.hashes[y] = hash;
            differs
        };

        // Where a run must stop even if the next row also changed, because it would be
        // sent through a different palette.
        let boundary = split.min(h);
        let (mut y, mut sent) = (0, 0);
        while y < h {
            if !changed(cache, y) {
                y += 1;
                continue;
            }
            let start = y;
            let limit = if start < boundary { boundary } else { h };
            y += 1;
            while y < limit && changed(cache, y) {
                y += 1;
            }
            let palette = if start < boundary { top } else { bottom };
            self.window(x0, y0 + start, x0 + w - 1, y0 + y - 1)?;
            self.send_gray_rows(fb, palette, w, start, y, overlays)?;
            sent += y - start;
        }
        cache.valid = true;
        Ok(sent)
    }

    /// Rows `start..end` of `fb`, `w` pixels each, into the window already open.
    fn send_gray_rows<const W: usize, const H: usize, const N: usize>(
        &mut self,
        fb: &Gray4<W, H, N>,
        palette: &[u16; 16],
        w: usize,
        start: usize,
        end: usize,
        overlays: &[Overlay<'_>],
    ) -> Result<(), B::Error> {
        // A packed byte holds two pixels, the even one in its high nibble. Expanding a whole
        // byte through a 256-entry table built once per flush turns 76 800 bounds-checked
        // `get`s a frame into one lookup per byte -- on the Q1 this conversion ran for every
        // row of every scroll frame, and it was a sizeable share of a 75 ms frame.
        let mut expand = [[0u8; 4]; 256];
        for (b, out) in expand.iter_mut().enumerate() {
            let hi = palette[b >> 4].to_be_bytes();
            let lo = palette[b & 0x0F].to_be_bytes();
            *out = [hi[0], hi[1], lo[0], lo[1]];
        }

        let row_len = W.div_ceil(2);
        let bytes = fb.as_bytes();
        let mut line = [0u8; WIDTH * 2 + 2];
        for y in start..end {
            let row = &bytes[y * row_len..y * row_len + w.div_ceil(2)];
            for (packed, out) in row.iter().zip(line.as_chunks_mut::<4>().0.iter_mut()) {
                *out = expand[*packed as usize];
            }
            for o in overlays {
                let Some(px) = o.row(y) else { continue };
                for (dx, p) in px.iter().enumerate() {
                    let x = o.x + dx;
                    if x < w {
                        line[x * 2..x * 2 + 2].copy_from_slice(&p.to_be_bytes());
                    }
                }
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
    use crate::canvas::Canvas;
    use crate::framebuffer::Mono128x64;

    #[test]
    fn paint_sends_each_pixel_from_the_closure_in_row_order_and_clips() {
        let mut p = St7789::new(MockBus::default());
        p.paint(318, 0, 4, 2, |dx, dy| (dy * 16 + dx) as u16)
            .unwrap();
        let log = &p.bus_mut().log;
        // Clipped to two columns at the right edge.
        assert_eq!(log[1], (true, vec![0x01, 0x3E, 0x01, 0x3F]));
        // CASET, its data, RASET, its data, RAMWR, then one transfer per row.
        assert_eq!(log[5], (true, vec![0, 0, 0, 1]));
        assert_eq!(log[6], (true, vec![0, 16, 0, 17]));
        assert_eq!(log.len(), 7);
    }

    #[test]
    fn a_scroll_area_always_covers_the_320_lines() {
        let mut p = St7789::new(MockBus::default());
        p.set_scroll_area(40, 0).unwrap();
        p.set_scroll_area(400, 400).unwrap();
        let log = &p.bus_mut().log;
        assert_eq!(log[0], (false, vec![cmd::VSCRDEF]));
        assert_eq!(log[1], (true, vec![0, 40, 0x01, 0x18, 0, 0]));
        // Absurd fixed areas are clamped so one line still scrolls, never a sum past 320.
        let d = &log[3].1;
        let sum: u16 = d.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).sum();
        assert_eq!(sum, 320);
        assert!(u16::from_be_bytes([d[2], d[3]]) >= 1);
    }

    #[test]
    fn a_scroll_start_wraps_and_ending_puts_everything_back() {
        let mut p = St7789::new(MockBus::default());
        p.set_scroll_start(330).unwrap();
        assert_eq!(p.bus_mut().log[1], (true, vec![0, 10]));
        p.bus_mut().log.clear();
        p.end_scroll().unwrap();
        let log = &p.bus_mut().log;
        assert_eq!(log[0], (false, vec![cmd::VSCSAD]));
        assert_eq!(log[1], (true, vec![0, 0]));
        assert_eq!(log[2], (false, vec![cmd::VSCRDEF]));
        assert_eq!(log[3], (true, vec![0, 0, 0x01, 0x40, 0, 0]));
        assert_eq!(log[4], (false, vec![cmd::NORON]));
    }

    /// The status bar comes out grey and white over an amber screen, from one canvas.
    ///
    /// The canvas holds indices, not colours; the palette is applied at send time. So the
    /// bar's rows are sent through the grey ramp and everything below through amber,
    /// without the drawing code knowing there are two.
    #[test]
    fn the_rows_above_the_split_are_sent_through_the_other_palette() {
        use crate::canvas::{Canvas, INK};

        const SPLIT: usize = 4;
        let mut fb: Gray4<8, 8, 32> = Gray4::new();
        // Full ink everywhere: the index is the same above and below, so any difference
        // in what goes out is the palette and nothing else.
        fb.fill_rect(0, 0, 8, 8, INK);

        let mut p = St7789::new(MockBus::default());
        let mut cache = RowCache::<8>::new();
        p.flush_gray_changed_split(&fb, &GREYS, &AMBER, SPLIT, &mut cache, &[])
            .unwrap();

        // Pixel data only, in order: two runs, one per palette.
        let data: Vec<Vec<u8>> = p
            .bus_mut()
            .log
            .iter()
            .filter(|(dc, b)| *dc && b.len() >= 16)
            .map(|(_, b)| b.clone())
            .collect();
        assert!(!data.is_empty(), "nothing was sent");
        let white = WHITE.to_be_bytes();
        let amber = AMBER[15].to_be_bytes();
        assert_ne!(white, amber, "the two ramps must differ at full ink");

        let top: Vec<u8> = data[..SPLIT].concat();
        let bottom: Vec<u8> = data[SPLIT..].concat();
        assert!(
            top.chunks(2).all(|c| c == white),
            "the bar's rows did not come out white"
        );
        assert!(
            bottom.chunks(2).all(|c| c == amber),
            "the screen below the bar did not come out amber"
        );
    }

    /// An overlay's own pixels go out in place, in the same pass as the canvas -- and a
    /// second flush of the same frame and the same overlay sends nothing, which is the
    /// whole of the flicker fix: nothing is resent, so nothing blinks.
    #[test]
    fn an_overlay_goes_out_with_its_rows_and_only_when_they_change() {
        use crate::canvas::Gray320x240;
        let fb = Gray320x240::new();
        let logo = [0xF81F_u16; 4 * 3]; // magenta, 4x3
        let at = [Overlay {
            x: 10,
            y: 20,
            w: 4,
            h: 3,
            pixels: &logo,
        }];
        let mut p = St7789::new(MockBus::default());
        let mut cache = RowCache::<240>::new();
        p.flush_gray_changed_split(&fb, &GREYS, &AMBER, 0, &mut cache, &at)
            .unwrap();
        let frame = replay(&p.bus_mut().log);
        assert_eq!(frame[20 * WIDTH + 10], 0xF81F);
        assert_eq!(frame[22 * WIDTH + 13], 0xF81F);
        assert_ne!(frame[20 * WIDTH + 14], 0xF81F, "past its width");
        assert_ne!(frame[23 * WIDTH + 10], 0xF81F, "past its height");

        // The same frame again: nothing to send.
        p.bus_mut().log.clear();
        let sent = p
            .flush_gray_changed_split(&fb, &GREYS, &AMBER, 0, &mut cache, &at)
            .unwrap();
        assert_eq!(sent, 0);

        // A different logo on the same rows: exactly those rows go again.
        let other = [0x07E0_u16; 4 * 3];
        let moved = [Overlay {
            x: 10,
            y: 20,
            w: 4,
            h: 3,
            pixels: &other,
        }];
        let sent = p
            .flush_gray_changed_split(&fb, &GREYS, &AMBER, 0, &mut cache, &moved)
            .unwrap();
        assert_eq!(sent, 3);
    }

    /// A run of changed rows never spans the split, since one send is one palette.
    #[test]
    fn a_changed_run_stops_at_the_palette_boundary() {
        use crate::canvas::{Canvas, INK};
        let mut fb: Gray4<8, 8, 32> = Gray4::new();
        fb.fill_rect(0, 0, 8, 8, INK);

        let mut p = St7789::new(MockBus::default());
        let mut cache = RowCache::<8>::new();
        // Every row changed, so without a boundary this would be one window and one send.
        let sent = p
            .flush_gray_changed_split(&fb, &GREYS, &AMBER, 4, &mut cache, &[])
            .unwrap();
        assert_eq!(sent, 8);
        let windows = p
            .bus_mut()
            .log
            .iter()
            .filter(|(dc, b)| !*dc && b == &vec![cmd::RASET])
            .count();
        assert_eq!(windows, 2, "the run crossed the palette boundary");
    }

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
        assert!(
            p.bus_mut().log.is_empty(),
            "drew something that is not on the panel"
        );
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
        assert_eq!(
            f[1], GREYS[7],
            "the right pixel of a byte is its low nibble"
        );
        assert_eq!(f[2], GREYS[0]);
        assert_eq!(f[239 * WIDTH + 319], GREYS[3]);
    }

    /// The row ranges each RASET in the log opened, in order.
    fn row_windows(log: &[(bool, Vec<u8>)]) -> Vec<(u16, u16)> {
        log.windows(2)
            .filter(|w| w[0] == (false, vec![cmd::RASET]))
            .map(|w| {
                let b = &w[1].1;
                (
                    u16::from_be_bytes([b[0], b[1]]),
                    u16::from_be_bytes([b[2], b[3]]),
                )
            })
            .collect()
    }

    #[test]
    fn an_unchanged_frame_sends_nothing_and_changed_rows_send_only_themselves() {
        let mut g = crate::canvas::Gray320x240::new();
        let mut cache = RowCache::<240>::new();
        let mut p = St7789::new(MockBus::default());
        assert_eq!(
            p.flush_gray_changed(&g, &GREYS, &mut cache).unwrap(),
            240,
            "first flush"
        );
        assert_eq!(row_windows(&p.bus_mut().log), vec![(0, 239)]);

        p.bus_mut().log.clear();
        assert_eq!(p.flush_gray_changed(&g, &GREYS, &mut cache).unwrap(), 0);
        assert!(
            p.bus_mut().log.is_empty(),
            "an unchanged frame touched the bus"
        );

        g.put(5, 100, 15);
        g.put(6, 101, 15);
        g.put(7, 200, 9);
        assert_eq!(p.flush_gray_changed(&g, &GREYS, &mut cache).unwrap(), 3);
        assert_eq!(row_windows(&p.bus_mut().log), vec![(100, 101), (200, 200)]);
        let f = replay(&p.bus_mut().log);
        assert_eq!(f[100 * WIDTH + 5], GREYS[15]);
        assert_eq!(f[101 * WIDTH + 6], GREYS[15]);
        assert_eq!(f[200 * WIDTH + 7], GREYS[9]);

        p.bus_mut().log.clear();
        cache.invalidate();
        assert_eq!(
            p.flush_gray_changed(&g, &GREYS, &mut cache).unwrap(),
            240,
            "after invalidate"
        );
    }

    #[test]
    fn the_grey_palette_runs_from_black_to_white_rising_every_step() {
        assert_eq!(GREYS[0], BLACK);
        assert_eq!(GREYS[15], WHITE);
        assert!(GREYS.windows(2).all(|w| w[1] > w[0]));
    }

    /// The amber ramp has to stay the bootloader's amber, and stay one hue.
    ///
    /// Blue at zero is the property that makes it a hue rather than a wash toward white:
    /// let blue climb and the top of the ramp drifts to cream, which is what a
    /// "simplified" linear ramp reintroduces.
    #[test]
    fn the_amber_palette_is_the_reference_ramp_and_never_leaves_its_hue() {
        assert_eq!(AMBER[0], BLACK);
        // COL_TEXT from display.md: (31, 43, 0).
        assert_eq!(AMBER[15], 0xFD60);
        assert_eq!(AMBER[15], rgb565(31, 43, 0));
        assert!(AMBER.windows(2).all(|w| w[1] > w[0]), "not rising");
        assert!(AMBER.iter().all(|v| v & 0x1F == 0), "blue is not zero");
        assert_ne!(AMBER[15], WHITE, "amber should not reach white");
        // Copied from the reference, not recomputed: a rounded linear ramp puts
        // (22, 31, 0) at index 11 where the real one has (21, 30, 0).
        assert_eq!(AMBER[11], 0xABC0);
        assert_ne!(AMBER, GREYS);
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
