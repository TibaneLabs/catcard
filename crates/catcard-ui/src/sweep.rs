//! A moving blue-white-blue bar, drawn by nobody.
//!
//! During a PIN check the CPU is inside the bootloader with interrupts masked, and
//! nothing this firmware owns can run. A DMA channel can: it streams this buffer round
//! and round into the panel's memory-write, and the panel does the rest. This module
//! is the arithmetic that makes a fixed buffer *move*.
//!
//! # Why the buffer is 1,605 pixels for a 1,600-pixel window
//!
//! The panel's write window is `W x H` and the controller wraps back to its top-left on
//! its own, so the stream's pixel `k` lands at window position `k mod (W*H)`. The buffer
//! is read at `k mod L`. Make `L` a little longer than the window and every pass lands
//! a little further along: the pattern slides.
//!
//! What it cannot do is slide with every row identical. Row-identical and seamless
//! together force `L` to a whole number of rows, and then a pass moves the picture by
//! whole rows, which is no motion at all. So the pattern leans: with a period `P` that
//! divides `L` and satisfies `W ≡ -1 (mod P)`, each row sits one pixel behind the row
//! above, and on a five-row bar a four-pixel lean is invisible.
//!
//! `W = 320`, `H = 5`, `L = 1605`, `P = 321`: `320 ≡ -1 (mod 321)`, `1605 = 5 * 321`,
//! and each pass moves the hump `L - W*H = 5` pixels.

/// Window width: the whole panel.
pub const W: usize = 320;
/// Window height: the five rows at the bottom the co-processor's bar also used.
pub const H: usize = 5;
/// Pixels each pass of the buffer moves the pattern by.
pub const STEP: usize = 5;
/// Pixels in the buffer.
pub const LEN: usize = W * H + STEP;
/// One blue-white-blue hump, in pixels.
pub const PERIOD: usize = W + 1;

// The two facts the motion rests on, checked where they are stated.
const _: () = assert!(LEN.is_multiple_of(PERIOD), "the buffer must be seamless");
const _: () = assert!(
    W % PERIOD == PERIOD - 1,
    "rows must lean one pixel, not more"
);

/// The blue at the ends of the hump: between pure blue and cyan -- `#2080FF`.
pub const BLUE: (u8, u8, u8) = (0x20, 0x80, 0xFF);
/// The white at its middle.
pub const WHITE: (u8, u8, u8) = (0xFF, 0xFF, 0xFF);

/// An RGB888 colour as the panel wants it: RGB565, high byte first.
const fn rgb565_be((r, g, b): (u8, u8, u8)) -> [u8; 2] {
    let v = ((r as u16 >> 3) << 11) | ((g as u16 >> 2) << 5) | (b as u16 >> 3);
    v.to_be_bytes()
}

/// The colour at position `i` of a hump `PERIOD` pixels long: blue at the ends, white in
/// the middle, eased so the white is a glow rather than a spike.
pub fn colour_at(i: usize) -> (u8, u8, u8) {
    // Closeness to the middle: 1024 at the centre, 0 at the ends.
    let half = (PERIOD / 2) as i32;
    let d = ((i % PERIOD) as i32 - half).abs();
    let t = 1024 - (d * 1024 / half).min(1024);
    // Smoothstep, in fixed point: t^2 (3 - 2t).
    let s = t * t / 1024 * (3 * 1024 - 2 * t) / 1024;
    let mix = |a: u8, b: u8| (a as i32 + (b as i32 - a as i32) * s / 1024) as u8;
    (
        mix(BLUE.0, WHITE.0),
        mix(BLUE.1, WHITE.1),
        mix(BLUE.2, WHITE.2),
    )
}

/// Fill `out` with the stream: `LEN` pixels, two bytes each. Returns the bytes written,
/// or `None` if `out` is shorter than that.
pub fn fill(out: &mut [u8]) -> Option<usize> {
    fill_from(out, 0)
}

/// [`fill`], starting `phase` pixels into the hump.
///
/// Still seamless for any phase: the buffer is a whole number of humps, so shifting where
/// it starts only rotates it.
pub fn fill_from(out: &mut [u8], phase: usize) -> Option<usize> {
    let bytes = LEN * 2;
    let out = out.get_mut(..bytes)?;
    for (i, px) in out.as_chunks_mut::<2>().0.iter_mut().enumerate() {
        *px = rgb565_be(colour_at(phase + i));
    }
    Some(bytes)
}

/// Where a stopped sweep was: `(phase, at)`, the pattern phase of the last pixel sent
/// and the window position it went to.
///
/// `started` is the phase it was started at, `passes` how many whole passes of the
/// buffer went out, `into` how many pixels of the current one.
pub const fn stopped_at(started: usize, passes: usize, into: usize) -> (usize, usize) {
    let k = passes * LEN + into;
    ((started + k) % PERIOD, k % (W * H))
}

/// The phase to start again at so the sweep carries on from where it stopped.
///
/// A restart always writes the window from its top-left, so the new first pass has to be
/// *the pass that was in progress* -- the pixels already on the glass from it are then
/// rewritten with themselves, and the ones it had not reached yet get what they were
/// about to. `phase` and `at` are [`stopped_at`]'s.
pub const fn resume_phase(phase: usize, at: usize) -> usize {
    (phase + PERIOD - at % PERIOD) % PERIOD
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the window shows after `passes` whole passes of the buffer, as the panel
    /// renders it: stream pixel `k` written at `k mod (W*H)`.
    fn window_after(buf: &[u8], passes: usize) -> Vec<u16> {
        let px: Vec<u16> = buf
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_be_bytes(*c))
            .collect();
        let mut win = vec![0u16; W * H];
        for k in 0..(passes * LEN) {
            win[k % (W * H)] = px[k % LEN];
        }
        win
    }

    /// Where the whitest pixel of `row` is: the most red, since the blue has little.
    fn peak(win: &[u16], row: usize) -> usize {
        (0..W).max_by_key(|&x| win[row * W + x] >> 11).unwrap()
    }

    fn buffer() -> Vec<u8> {
        let mut buf = vec![0u8; LEN * 2];
        assert_eq!(fill(&mut buf), Some(LEN * 2));
        buf
    }

    /// The whole point: each pass moves the hump by `STEP` pixels.
    #[test]
    fn each_pass_moves_the_hump_along() {
        let buf = buffer();
        let a = peak(&window_after(&buf, 3), 0);
        let b = peak(&window_after(&buf, 4), 0);
        assert_eq!((b + W - a) % W, STEP, "moved from {a} to {b}");
    }

    /// Rows lean by one pixel each, never more: the bar reads as one band.
    #[test]
    fn rows_lean_a_pixel_at_most() {
        let win = window_after(&buffer(), 7);
        for r in 1..H {
            let lean = (peak(&win, r - 1) + W - peak(&win, r)) % W;
            assert!(lean <= 1 || lean >= W - 1, "row {r} leans {lean}");
        }
    }

    /// Blue at the ends of a hump, white in its middle.
    #[test]
    fn it_is_blue_white_blue() {
        assert_eq!(colour_at(0), BLUE);
        assert_eq!(colour_at(PERIOD / 2), WHITE);
        assert_eq!(colour_at(PERIOD - 1), colour_at(1));
    }

    /// Stop anywhere, start again at `resume_phase`, and the first pass puts back exactly
    /// what the stopped sweep was about to: the glass shows no jump.
    #[test]
    fn a_resumed_sweep_carries_on_where_it_stopped() {
        let px = |buf: &[u8]| -> Vec<u16> {
            buf.as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_be_bytes(*c))
                .collect()
        };
        let first = px(&buffer());
        for &(passes, into) in &[(0usize, 700usize), (3, 1), (7, 1604), (12, 800)] {
            let k = passes * LEN + into;
            // What the unbroken stream would have put at each window position next.
            let next: Vec<u16> = (0..(W * H))
                .map(|q| {
                    let w = k % (W * H);
                    let step = if q >= w { q - w } else { W * H - w + q };
                    first[(k + step) % LEN]
                })
                .collect();
            // What a restart writes on its first pass.
            let (phase, at) = stopped_at(0, passes, into);
            let mut again = vec![0u8; LEN * 2];
            fill_from(&mut again, resume_phase(phase, at)).unwrap();
            let again = px(&again);
            // The pixels the old pass had not reached: exactly what they were about to be.
            let w = k % (W * H);
            for q in w..(W * H) {
                assert_eq!(again[q], next[q], "stop {passes}/{into}: pixel {q}");
            }
            // The ones it had: the same as they already are -- the current pass again.
            for q in 0..w {
                assert_eq!(
                    again[q],
                    first[(k - w + q) % LEN],
                    "stop {passes}/{into}: pixel {q}"
                );
            }
        }
    }

    /// Short buffers are refused rather than half filled.
    #[test]
    fn a_short_buffer_is_refused() {
        let mut small = [0u8; 16];
        assert_eq!(fill(&mut small), None);
    }
}
