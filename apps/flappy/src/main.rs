//! Flappy Cat, as an app: the panel scrolls, and only what changed is drawn.
//!
//! The game itself is [`catcard_ui::flappy`], the same code the firmware used to link. This
//! is the part that drives the panel, now through the kernel's services: the whole panel
//! scrolls in hardware, the scene is painted once, and from then on each frame is the column
//! coming in on the right, the cat's few hundred pixels, the score a column over from where
//! it was, and one scroll command, all sent after a tear pulse. A full frame is 153 KB; a
//! game frame is about 2.
//!
//! The pixels are rendered here, in the app's own memory, and handed to the kernel a patch
//! at a time ([`sys::paint`]). Built at `opt-level = 3` whatever the firmware is built at.
#![no_std]
#![no_main]

use catcard_app::{Key, Line, sys};
use catcard_ui::art::flappy::{Art, GAME_OVER, UNPACKED_LEN};
use catcard_ui::flappy::{self as fl, Column, Game};
use core::fmt::Write as _;

/// Frames after a game ends before a key counts, so the flap that crashed the cat does not
/// also skip the game-over screen.
const GAME_OVER_HOLD: u32 = 40;
/// Where the game-over banner sits on the glass, from the top.
const BANNER_Y: usize = 60;
/// The per-boot word that keeps the best score between games and launches.
const KV_BEST: u32 = 0;
/// Columns rendered per paint: wide enough for the cat's and the score's patches in one go.
const CHUNK: usize = 40;
/// Frame-memory columns: the panel's ring of lines that the hardware scroll moves through.
const RING: usize = catcard_ui::st7789::WIDTH;

/// The sprites, unpacked once per launch.
static mut ART: [u8; UNPACKED_LEN] = [0; UNPACKED_LEN];
/// One patch of pixels on its way to the panel.
static mut PIXELS: [u16; CHUNK * fl::HEIGHT] = [0; CHUNK * fl::HEIGHT];

#[unsafe(no_mangle)]
pub extern "C" fn app_main(_arg: u32) -> i32 {
    sys::message("Flappy Cat", "any key flaps", "cancel quits");
    sys::wait_any_key();

    // SAFETY: one thread of execution; the buffer lives as long as the app.
    let art = match catcard_ui::art::flappy::unpack(unsafe { &mut *core::ptr::addr_of_mut!(ART) }) {
        Ok(art) => art,
        Err(_) => {
            sys::log("flappy: art would not unpack");
            return -1;
        }
    };
    if !sys::panel_begin() {
        sys::log("flappy: no colour panel");
        return -2;
    }
    loop {
        let mut seed = [0u8; 4];
        sys::random(&mut seed);
        if !play(&art, u32::from_le_bytes(seed)) {
            break;
        }
    }
    sys::panel_end();
    0
}

/// Paint world columns `x0 .. x0 + w`, rows `y0 .. y0 + h`, from the columns `column`
/// describes -- asked once per column, not per pixel -- split where the columns wrap around
/// the ring of frame memory.
fn paint_world(
    art: &Art<'_>,
    x0: u32,
    w: usize,
    y0: usize,
    h: usize,
    column: impl Fn(u32) -> Column,
) {
    // SAFETY: one thread of execution.
    let px = unsafe { &mut *core::ptr::addr_of_mut!(PIXELS) };
    let mut cols = [Column::EMPTY; CHUNK];
    let mut done = 0;
    while done < w {
        let x = x0 + done as u32;
        let col = fl::memory_column(x);
        let run = (w - done).min(RING - col).min(CHUNK);
        for (i, c) in cols[..run].iter_mut().enumerate() {
            *c = column(x + i as u32);
        }
        for dy in 0..h {
            for (dx, c) in cols[..run].iter().enumerate() {
                px[dy * run + dx] = c.colour(art, y0 + dy);
            }
        }
        sys::paint(col as u32, y0 as u32, run as u32, h as u32, &px[..run * h]);
        done += run;
    }
}

/// [`paint_world`] a pixel at a time, for the one-off banner whose sprite is not a column.
fn paint_world_pixels(x0: u32, w: usize, y0: usize, h: usize, f: impl Fn(u32, usize) -> u16) {
    // SAFETY: one thread of execution.
    let px = unsafe { &mut *core::ptr::addr_of_mut!(PIXELS) };
    let mut done = 0;
    while done < w {
        let x = x0 + done as u32;
        let col = fl::memory_column(x);
        let run = (w - done).min(RING - col).min(CHUNK);
        for dy in 0..h {
            for dx in 0..run {
                px[dy * run + dx] = f(x + dx as u32, y0 + dy);
            }
        }
        sys::paint(col as u32, y0 as u32, run as u32, h as u32, &px[..run * h]);
        done += run;
    }
}

/// One game. True to play again, false to leave.
fn play(art: &Art<'_>, seed: u32) -> bool {
    let mut g = Game::new(seed);
    sys::scroll_start(fl::scroll_start(0) as u32);
    paint_world(art, g.scroll, fl::PLAY_W, 0, fl::HEIGHT, |x| {
        g.shown_column(x)
    });

    let mut started = false;
    let mut score = 0;
    let (mut frames, mut late) = (0u32, 0u32);
    let hz = sys::clock_hz().max(1);
    let frame_cycles = hz / 61;
    // Summed a frame at a time: the cycle counter wraps every 36 s at 120 MHz.
    let (mut elapsed, mut last) = (0u64, sys::cycles());
    let (mut worst, mut slow) = (0u32, 0u32);
    while !g.over {
        let now = sys::cycles();
        elapsed += u64::from(now.wrapping_sub(last));
        last = now;
        if !sys::wait_tear() {
            late += 1;
        }
        let work_start = sys::cycles();
        match sys::key() {
            Some(Key::Cancel) => return false,
            Some(_) => {
                started = true;
                g.flap();
            }
            None => {}
        }

        let (old_scroll, old_x, old_y) = (g.scroll, g.cat_x(), g.cat_y());
        let old_score = g.score();
        if started {
            g.step(art);
        } else {
            g.idle();
        }
        frames += 1;

        // The column coming in on the right. Its memory column is the one leaving on the
        // left, which the scroll below takes off the glass in the same gap.
        let incoming = (g.scroll - old_scroll) as usize;
        if incoming > 0 {
            let x = old_scroll + fl::PLAY_W as u32;
            paint_world(art, x, incoming, 0, fl::HEIGHT, |x| g.shown_column(x));
        }
        // The cat: where it was and where it is, as one patch.
        let top = old_y.min(g.cat_y());
        let bottom = (old_y.max(g.cat_y()) + fl::CAT_H).min(fl::HEIGHT);
        let width = (g.cat_x() - old_x) as usize + fl::CAT_W;
        paint_world(art, old_x, width, top, bottom - top, |x| g.shown_column(x));
        // The score: where it was on the world and where it is now, which is a column on
        // -- or a digit wider when the count gains one.
        let (old_left, old_w) = fl::score_span(old_score);
        let (new_left, new_w) = fl::score_span(g.score());
        let from = (old_scroll + old_left as u32).min(g.scroll + new_left as u32);
        let to = (old_scroll + (old_left + old_w) as u32).max(g.scroll + (new_left + new_w) as u32);
        paint_world(
            art,
            from,
            (to - from) as usize,
            fl::SCORE_TOP,
            fl::SCORE_H,
            |x| g.shown_column(x),
        );

        sys::scroll_start(fl::scroll_start(g.scroll) as u32);
        score = g.score();
        let work = sys::cycles().wrapping_sub(work_start);
        worst = worst.max(work);
        if work > frame_cycles {
            slow += 1;
        }
    }

    let best = sys::kv_get(KV_BEST).max(score);
    sys::kv_set(KV_BEST, best);
    let tenths = elapsed / u64::from((hz / 10).max(1));
    let worst_tenth_ms = u64::from(worst) * 10_000 / u64::from(hz);
    let mut l = Line::new();
    let _ = write!(
        l,
        "flappy: score {score}, best {best}, {frames} frames in {}.{} s, {late} late; worst {}.{} ms, {slow} slow",
        tenths / 10,
        tenths % 10,
        worst_tenth_ms / 10,
        worst_tenth_ms % 10,
    );
    l.log();

    // The banner over the frozen scene, centred on the glass.
    let banner_x = g.scroll + (fl::PLAY_W as u32 - GAME_OVER.width as u32) / 2;
    paint_world_pixels(
        banner_x,
        GAME_OVER.width as usize,
        BANNER_Y,
        GAME_OVER.height as usize,
        |x, y| {
            GAME_OVER
                .at(art, (x - banner_x) as usize, y - BANNER_Y)
                .unwrap_or_else(|| g.shown(art, x, y))
        },
    );

    let mut held = 0;
    loop {
        sys::wait_tear();
        let key = sys::key();
        if held < GAME_OVER_HOLD {
            held += 1;
            continue;
        }
        match key {
            Some(Key::Cancel) => return false,
            Some(_) => return true,
            None => {}
        }
    }
}
