//! Indexed-colour artwork: the pixels a renderer produced, and the palette they need.
//!
//! A [`Canvas`](crate::canvas::Canvas) holds 4 bits per pixel and the panel flush maps
//! those through a 16-entry RGB565 palette, so a picture travels as its own palette plus
//! one nibble per pixel. That is how a rasterised SVG -- glow, gradient, anti-aliased
//! edges -- reaches the screen without a 150 KB RGB565 framebuffer nobody has the RAM for.
//!
//! **Index 0 is the background and is never drawn**, so art composes over whatever is
//! already on the canvas instead of carrying a transparency mask. Index 15 is left for
//! white, which is what text and the progress bar draw in.
//!
//! On a mono panel the same indices threshold to ink or paper, so the art degrades to a
//! silhouette rather than needing a second asset -- though a hand-drawn 1-bit picture
//! still reads better there, which is why [`cat`](super::cat) stays.

use crate::canvas::Canvas;

/// A picture as indices into its own palette, deflated.
///
/// # How it is stored, and why
///
/// The pixels are packed two to a byte, left pixel in the high nibble, row after row --
/// the layout a [`Gray4`](crate::canvas::Gray4) canvas uses -- and then raw-deflated with
/// a 512-byte window. The art is mostly background, so this is where the flash went:
/// the menu icons were 34,816 bytes packed and are 8,734 deflated, the splash logo 7,200
/// and 1,571.
///
/// Nothing is inflated into memory to draw one. [`draw_indexed`] feeds the stream through
/// a decoder whose output *is* the canvas: each byte is painted the moment it comes out,
/// index 0 skipped as it goes, so the only memory a draw needs is the decoder's own
/// working state and a 512-byte history ring for the back-references -- the reason the
/// window is 512, the smallest deflate allows. A stream made with a wider one is refused
/// part-way rather than drawn wrong.
///
/// `tools/artgen/deflate.py` is the encoder, shared by both generators.
pub struct Indexed {
    pub width: u16,
    pub height: u16,
    /// Colours for indices 0..=15, RGB565. Index 0 is the background.
    pub palette: [u16; 16],
    /// The packed pixels, raw deflate, 512-byte window.
    pub deflated: &'static [u8],
}

/// The history the decoder keeps: the compressor's window, which must not be larger.
/// Source: tools/artgen/deflate.py `WINDOW_BITS = 9`.
pub const WINDOW: usize = 512;

impl Indexed {
    /// Bytes one packed row occupies.
    pub const fn row_len(&self) -> usize {
        (self.width as usize).div_ceil(2)
    }

    /// The palette index at `(x, y)`. Outside the picture reads 0.
    ///
    /// Decodes up to the pixel asked for: for tests and one-off questions, not for
    /// drawing, which is [`draw_indexed`].
    pub fn index(&self, x: usize, y: usize) -> u8 {
        if x >= self.width as usize || y >= self.height as usize {
            return 0;
        }
        let mut found = 0;
        let _ = decode(self, |px, py, index| {
            if (px, py) == (x, y) {
                found = index;
            }
        });
        found
    }
}

/// Inflate `art`, handing every pixel to `each(x, y, index)` as it comes out.
///
/// Background pixels included: [`draw_indexed`] is what skips them. Bounded by the
/// picture's size -- a stream that decodes to more is stopped at the picture's edge
/// with [`minizlib::Error::OutputFull`].
pub fn decode(art: &Indexed, each: impl FnMut(usize, usize, u8)) -> Result<(), minizlib::Error> {
    let mut out = Painter {
        ring: [0; WINDOW],
        pos: 0,
        total: 0,
        limit: art.row_len() * art.height as usize,
        row_len: art.row_len(),
        width: art.width as usize,
        each,
    };
    minizlib::inflate(art.deflated, &mut out).map(|_| ())
}

/// A deflate output that paints: every byte is two pixels, handed on as it arrives, and
/// kept in a ring as long as a back-reference can reach.
struct Painter<F> {
    ring: [u8; WINDOW],
    pos: usize,
    total: usize,
    limit: usize,
    row_len: usize,
    width: usize,
    each: F,
}

impl<F: FnMut(usize, usize, u8)> minizlib::Output for Painter<F> {
    fn put<C: minizlib::Checksum>(
        &mut self,
        byte: u8,
        check: &mut C,
    ) -> Result<(), minizlib::Error> {
        if self.total >= self.limit {
            return Err(minizlib::Error::OutputFull);
        }
        self.ring[self.pos] = byte;
        self.pos = (self.pos + 1) % WINDOW;
        let (y, x) = (self.total / self.row_len, (self.total % self.row_len) * 2);
        (self.each)(x, y, byte >> 4);
        // An odd width's last byte carries one pixel and a nibble of padding.
        if x + 1 < self.width {
            (self.each)(x + 1, y, byte & 0x0F);
        }
        self.total += 1;
        check.update(core::slice::from_ref(&byte));
        Ok(())
    }

    fn copy<C: minizlib::Checksum>(
        &mut self,
        dist: usize,
        len: usize,
        check: &mut C,
    ) -> Result<(), minizlib::Error> {
        if dist > self.total {
            return Err(minizlib::Error::InvalidDistance);
        }
        if dist > WINDOW || dist == 0 {
            return Err(minizlib::Error::WindowTooSmall);
        }
        for _ in 0..len {
            let byte = self.ring[(self.pos + WINDOW - dist) % WINDOW];
            self.put(byte, check)?;
        }
        Ok(())
    }

    fn flush<C: minizlib::Checksum>(&mut self, _: &mut C) -> Result<(), minizlib::Error> {
        Ok(())
    }

    fn written(&self) -> u64 {
        self.total as u64
    }
}

/// Draw `art` with its top-left at `(x, y)`, clipped. Index 0 is not drawn.
///
/// Straight out of the decoder: see [`Indexed`]. A picture that fails to decode stops
/// where it failed; the generated ones all decode, which the tests check.
///
/// The canvas must be flushed through `art.palette` for the colours to be the ones the
/// renderer chose -- see the firmware's `display::draw_with_palette`.
pub fn draw_indexed<C: Canvas + ?Sized>(canvas: &mut C, art: &Indexed, x: usize, y: usize) {
    let _ = decode(art, |ax, ay, index| {
        if index != 0 {
            canvas.put(x.saturating_add(ax), y.saturating_add(ay), index);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canvas::{Gray320x240, PAPER};

    /// Deflate `packed` as the generators do -- raw deflate -- for a picture made in a
    /// test. Leaked: an `Indexed` holds `'static` data.
    fn squeeze(packed: &[u8]) -> &'static [u8] {
        let mut out = vec![0u8; packed.len() * 2 + 64];
        let mut table = vec![0u16; 4096];
        let n = minizlib::deflate(packed, &mut table, minizlib::Buffer::new(&mut out)).unwrap();
        out.truncate(n as usize);
        Box::leak(out.into_boxed_slice())
    }

    /// 3x2: indices 1, 2, 0 / 0, 15, 3. Odd width, so the last nibble of each row is
    /// padding.
    fn small() -> Indexed {
        Indexed {
            width: 3,
            height: 2,
            palette: [0; 16],
            deflated: squeeze(&[0x12, 0x00, 0x0F, 0x30]),
        }
    }

    #[test]
    fn indices_come_out_of_the_stream_high_nibble_first_and_clip() {
        let small = small();
        assert_eq!(
            [
                small.index(0, 0),
                small.index(1, 0),
                small.index(2, 0),
                small.index(0, 1),
                small.index(1, 1),
                small.index(2, 1)
            ],
            [1, 2, 0, 0, 15, 3]
        );
        assert_eq!(small.index(3, 0), 0, "past the width");
        assert_eq!(small.index(0, 2), 0, "past the height");
        assert_eq!(small.index(usize::MAX, usize::MAX), 0);
    }

    /// Every picture the generators made decodes, to exactly its size -- the check that
    /// `tools/artgen/deflate.py` and this decoder agree, window included.
    #[test]
    fn every_generated_picture_decodes_to_its_size() {
        use crate::art::menuicons as m;
        let all: &[(&str, &Indexed)] = &[
            ("ADDRESS_LIST", &m::ADDRESS_LIST),
            ("DERIVE_BIP85_INDEX", &m::DERIVE_BIP85_INDEX),
            ("DERIVE_KEY", &m::DERIVE_KEY),
            ("DERIVE_PASSPHRASE", &m::DERIVE_PASSPHRASE),
            ("IMPORT_PASSPHRASE", &m::IMPORT_PASSPHRASE),
            ("KEY_VAULT", &m::KEY_VAULT),
            ("LOGOUT", &m::LOGOUT),
            ("NEW_PASSPHRASE", &m::NEW_PASSPHRASE),
            ("NOTES", &m::NOTES),
            ("READING_SEED", &m::READING_SEED),
            ("RETURN_ROOT_KEY", &m::RETURN_ROOT_KEY),
            ("SCAN_QR_CODE", &m::SCAN_QR_CODE),
            ("SETTINGS", &m::SETTINGS),
            ("SIGN", &m::SIGN),
            ("UTILS", &m::UTILS),
            ("XOR_JOIN", &m::XOR_JOIN),
            ("XOR_SPLIT", &m::XOR_SPLIT),
            ("LOGO", &crate::art::tibane::LOGO),
        ];
        for (name, art) in all {
            let mut pixels = 0usize;
            decode(art, |x, y, _| {
                assert!(x < art.width as usize && y < art.height as usize, "{name}");
                pixels += 1;
            })
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
            assert_eq!(pixels, art.width as usize * art.height as usize, "{name}");
        }
    }

    /// A stream whose back-references reach further than the ring is refused, not drawn
    /// from the wrong bytes. The generators never make one; this is what happens if a
    /// picture is ever compressed some other way.
    #[test]
    fn a_stream_with_a_wider_window_is_refused() {
        // 2 KB: a kilobyte of noise, then the same kilobyte again -- the second half is
        // one back-reference a kilobyte long, twice what the ring holds.
        let mut packed = vec![0u8; 2048];
        let mut seed = 0x1234_5678u32;
        for b in packed.iter_mut().take(1024) {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            *b = (seed >> 16) as u8;
        }
        packed.copy_within(0..1024, 1024);
        let art = Indexed {
            width: 64,
            height: 64,
            palette: [0; 16],
            deflated: squeeze(&packed),
        };
        assert_eq!(
            decode(&art, |_, _, _| {}),
            Err(minizlib::Error::WindowTooSmall)
        );
    }

    /// A stream that decodes to more than the picture is stopped at its edge.
    #[test]
    fn a_stream_longer_than_the_picture_is_stopped() {
        let art = Indexed {
            width: 2,
            height: 1,
            palette: [0; 16],
            deflated: squeeze(&[0x11, 0x22, 0x33]),
        };
        assert_eq!(decode(&art, |_, _, _| {}), Err(minizlib::Error::OutputFull));
    }

    #[test]
    fn drawing_keeps_the_indices_and_leaves_the_background_alone() {
        let mut c = Gray320x240::new();
        c.put(2, 0, 9); // under an index-0 pixel of the art
        draw_indexed(&mut c, &small(), 0, 0);
        assert_eq!(c.get(0, 0), 1);
        assert_eq!(c.get(1, 0), 2);
        assert_eq!(c.get(2, 0), 9, "index 0 should not have painted over this");
        assert_eq!(c.get(0, 1), PAPER);
        assert_eq!(c.get(1, 1), 15);
        assert_eq!(c.get(2, 1), 3);
    }

    #[test]
    fn drawing_off_the_canvas_is_clipped_not_a_panic() {
        let mut c = Gray320x240::new();
        draw_indexed(&mut c, &small(), 319, 239);
        assert_eq!(c.get(319, 239), 1);
        draw_indexed(&mut c, &small(), usize::MAX - 1, usize::MAX - 1);
    }
}
