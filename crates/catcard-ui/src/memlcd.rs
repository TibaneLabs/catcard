//! A canvas in the format of the Precursor's memory-LCD framebuffer.
//!
//! The Precursor's 336x536 Sharp memory LCD is driven by a gateware block that streams a
//! framebuffer of 32-bit words to the panel: 11 words per line (336 pixels padded to 352),
//! 536 lines, top line first; within a line the words run left to right and each word's
//! least significant bit is its leftmost pixel; a set bit is **white**. This type holds a
//! frame in exactly that layout, so the board copies it out word for word.
//!
//! The layout is a hardware fact, established on a Precursor and recorded with its
//! sources in `catcard-precursor/src/lcd.rs`; this module only has to agree with it, which
//! the tests pin down.

use crate::canvas::{Canvas, INK, Level, PAPER};

/// Panel width in pixels.
pub const WIDTH: usize = 336;
/// Panel height in pixels.
pub const HEIGHT: usize = 536;
/// Words per line, padding included.
pub const WORDS_PER_LINE: usize = 11;
/// Words in a frame.
pub const WORDS: usize = WORDS_PER_LINE * HEIGHT;

/// One frame for the memory LCD. Thresholded like the mono OLED's framebuffer: a level of
/// 8 or more is ink (black), below it paper (white).
pub struct MemLcd {
    words: [u32; WORDS],
}

impl Default for MemLcd {
    fn default() -> Self {
        Self::new()
    }
}

impl MemLcd {
    /// A blank (all white) frame.
    pub const fn new() -> Self {
        Self {
            words: [Self::BLANK_WORD; WORDS],
        }
    }

    /// Every pixel white; the padding bits past 336 left clear (the panel never shows them).
    const BLANK_WORD: u32 = u32::MAX;

    fn slot(x: usize, y: usize) -> Option<(usize, u32)> {
        (x < WIDTH && y < HEIGHT).then(|| (y * WORDS_PER_LINE + x / 32, 1 << (x % 32)))
    }

    /// The frame as the gateware block wants it.
    pub fn words(&self) -> &[u32; WORDS] {
        &self.words
    }
}

impl Canvas for MemLcd {
    fn width(&self) -> usize {
        WIDTH
    }
    fn height(&self) -> usize {
        HEIGHT
    }
    fn put(&mut self, x: usize, y: usize, level: Level) {
        if let Some((i, bit)) = Self::slot(x, y) {
            if level >= 8 {
                self.words[i] &= !bit;
            } else {
                self.words[i] |= bit;
            }
        }
    }
    fn get(&self, x: usize, y: usize) -> Level {
        match Self::slot(x, y) {
            Some((i, bit)) if self.words[i] & bit == 0 => INK,
            _ => PAPER,
        }
    }
    fn clear(&mut self) {
        self.words = [Self::BLANK_WORD; WORDS];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_matches_the_gateware_block() {
        let mut fb = MemLcd::new();
        // Top-left pixel: bit 0 of word 0. Ink clears it, because a set bit is white.
        fb.put(0, 0, INK);
        assert_eq!(fb.words()[0], !1);
        // Pixel 33 of line 2: word 2*11 + 1, bit 1.
        fb.put(33, 2, INK);
        assert_eq!(fb.words()[2 * 11 + 1], !(1 << 1));
        // Last pixel of the last line: word 535*11 + 10, bit 335 % 32 = 15.
        fb.put(335, 535, INK);
        assert_eq!(fb.words()[535 * 11 + 10], !(1 << 15));
    }

    #[test]
    fn reads_back_what_was_drawn_and_clips() {
        let mut fb = MemLcd::new();
        assert_eq!(fb.get(5, 5), PAPER);
        fb.put(5, 5, INK);
        assert_eq!(fb.get(5, 5), INK);
        fb.put(5, 5, 7); // below the threshold is paper
        assert_eq!(fb.get(5, 5), PAPER);
        fb.put(336, 0, INK); // off the right edge: ignored, padding untouched
        fb.put(0, 536, INK);
        assert_eq!(fb.words()[10], u32::MAX);
        fb.put(1, 1, INK);
        fb.clear();
        assert_eq!(fb.get(1, 1), PAPER);
    }
}
