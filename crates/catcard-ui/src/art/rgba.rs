//! Full-colour art with alpha, for pictures the 4-bit canvas cannot hold.
//!
//! The panel takes 16 bits a pixel -- COLMOD `0x05`, RGB565, 65,536 colours
//! (hw-reference/display.md §Q1 init step 3 [C]). The *canvas* holds 4, flushed through
//! one 16-entry palette a frame, because a 16-bit canvas would be 150 KB. So a picture
//! that needs its own colours -- a coin's logo -- does not go on the canvas at all: it is
//! written straight to the panel after the frame, blended as it goes against whatever it
//! sits on. See the firmware's `display::overlay_marks`.
//!
//! Stored as RGBA8888, deflated with the same 512-byte window as [`super::indexed`], and
//! decoded the same way: a stream, handed out a pixel at a time, nothing inflated into a
//! buffer of its own.

use super::indexed::WINDOW;

/// A picture as RGBA8888, row after row, raw deflate with a [`WINDOW`]-byte window.
pub struct Rgba {
    pub width: u16,
    pub height: u16,
    pub deflated: &'static [u8],
}

/// Inflate `art`, handing each pixel to `each(x, y, [r, g, b, a])` as it comes out.
pub fn decode(art: &Rgba, each: impl FnMut(usize, usize, [u8; 4])) -> Result<(), minizlib::Error> {
    let mut out = Pixels {
        ring: [0; WINDOW],
        pos: 0,
        total: 0,
        limit: art.width as usize * art.height as usize * 4,
        width: art.width as usize,
        px: [0; 4],
        each,
    };
    minizlib::inflate(art.deflated, &mut out).map(|_| ())
}

/// A deflate output that groups bytes into pixels and hands them on.
struct Pixels<F> {
    ring: [u8; WINDOW],
    pos: usize,
    total: usize,
    limit: usize,
    width: usize,
    px: [u8; 4],
    each: F,
}

impl<F: FnMut(usize, usize, [u8; 4])> minizlib::Output for Pixels<F> {
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
        self.px[self.total % 4] = byte;
        if self.total % 4 == 3 {
            let n = self.total / 4;
            (self.each)(n % self.width, n / self.width, self.px);
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

/// `[r, g, b, a]` over an RGB565 background, as RGB565: what the panel should show.
pub fn over(px: [u8; 4], background: u16) -> u16 {
    let [r, g, b, a] = px.map(u32::from);
    let (br, bg, bb) = (
        ((background >> 11) & 0x1F) as u32 * 255 / 31,
        ((background >> 5) & 0x3F) as u32 * 255 / 63,
        (background & 0x1F) as u32 * 255 / 31,
    );
    let mix = |fg: u32, bg: u32| (fg * a + bg * (255 - a)) / 255;
    let (r, g, b) = (mix(r, br), mix(g, bg), mix(b, bb));
    ((r as u16 >> 3) << 11) | ((g as u16 >> 2) << 5) | (b as u16 >> 3)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn squeeze(raw: &[u8]) -> &'static [u8] {
        let mut out = vec![0u8; raw.len() * 2 + 64];
        let mut table = vec![0u16; 4096];
        let n = minizlib::deflate(raw, &mut table, minizlib::Buffer::new(&mut out)).unwrap();
        out.truncate(n as usize);
        Box::leak(out.into_boxed_slice())
    }

    /// Pixels come out in raster order with their own four bytes.
    #[test]
    fn pixels_come_out_in_order() {
        let raw = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let art = Rgba {
            width: 3,
            height: 1,
            deflated: squeeze(&raw),
        };
        let mut seen = vec![];
        decode(&art, |x, y, p| seen.push((x, y, p))).unwrap();
        assert_eq!(
            seen,
            vec![
                (0, 0, [1, 2, 3, 4]),
                (1, 0, [5, 6, 7, 8]),
                (2, 0, [9, 10, 11, 12])
            ]
        );
    }

    /// Opaque is the colour, clear is the background, half is between.
    #[test]
    fn blending_over_a_background() {
        assert_eq!(over([0xFF, 0xFF, 0xFF, 255], 0x0000), 0xFFFF);
        assert_eq!(over([0xFF, 0xFF, 0xFF, 0], 0x0000), 0x0000);
        assert_eq!(over([0, 0, 0, 0], 0xFD60), 0xFD60);
        let half = over([0xFF, 0xFF, 0xFF, 128], 0x0000);
        assert!(half > 0x7000 && half < 0x9000, "{half:#06x}");
    }

    /// Every chain mark decodes to exactly its size. Only where the colour art is in the
    /// build at all -- a one-bit board carries none of it.
    #[cfg(feature = "colour-marks")]
    #[test]
    fn every_chain_mark_decodes() {
        for t in [
            "BTC", "ETH", "SOL", "LTC", "BCH", "DOGE", "TRX", "MONA", "NMC", "XEP",
        ] {
            let crate::scroll::Mark::Art { colour: art, .. } =
                crate::art::chainicons::mark(t).unwrap()
            else {
                panic!("{t}: a colour build should give the colour form");
            };
            let mut n = 0;
            decode(art, |_, _, _| n += 1).unwrap_or_else(|e| panic!("{t}: {e:?}"));
            assert_eq!(n, art.width as usize * art.height as usize, "{t}");
        }
    }
}
