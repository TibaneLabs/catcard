//! Flappy Cat, on the Q1: the panel scrolls, the firmware only draws what changed.
//!
//! The game itself is [`catcard_ui::flappy`]. This is the part that talks to the panel: the
//! whole panel scrolls, the scene is painted once, and from then on each frame is the column
//! coming in on the right, the cat's few hundred pixels, the score a column over from where
//! it was, and one scroll command, all sent after a tear pulse. A full frame is 153 KB; a
//! game frame is about 2.
//!
//! Every way out puts the panel's scrolling back before anything else draws: the rest of
//! the firmware addresses the panel as though nothing were shifted.
//!
//! Nothing here touches the wallet.

use catcard_ui::art::flappy::GAME_OVER;
use catcard_ui::flappy::{self as fl, Column, Game};
use catcard_ui::keypad::{Event, KEYS, Key};

use crate::display;
use crate::ui::Ui;

/// The best score since power-up. Foreground only.
static mut BEST: u32 = 0;

/// Frames after a game ends before a key counts, so the flap that crashed the cat does not
/// also skip the game-over screen.
const GAME_OVER_HOLD: u32 = 40;

/// Where the game-over banner sits on the glass, from the top.
const BANNER_Y: usize = 60;

/// Columns worked out ahead of one paint: enough for the cat's and the score's patches in
/// one go, and a stack array small enough for any task. Wider areas go in chunks.
const CHUNK: usize = 40;

/// Paint world columns `x0 .. x0 + w`, rows `y0 .. y0 + h`, from the columns `column`
/// describes -- asked once per column, not per pixel -- split where the columns wrap around
/// the ring of frame memory.
fn paint_world(
    panel: &mut display::Panel,
    x0: u32,
    w: usize,
    y0: usize,
    h: usize,
    column: impl Fn(u32) -> Column,
) {
    let mut cols = [Column::EMPTY; CHUNK];
    let mut done = 0;
    while done < w {
        let x = x0 + done as u32;
        let col = fl::memory_column(x);
        let run = (w - done).min(catcard_ui::st7789::WIDTH - col).min(CHUNK);
        for (i, c) in cols[..run].iter_mut().enumerate() {
            *c = column(x + i as u32);
        }
        let _ = panel.paint(col, y0, run, h, |dx, dy| cols[dx].colour(y0 + dy));
        done += run;
    }
}

/// [`paint_world`] a pixel at a time, for the one-off banner whose sprite is not a column.
fn paint_world_pixels(
    panel: &mut display::Panel,
    x0: u32,
    w: usize,
    y0: usize,
    h: usize,
    f: impl Fn(u32, usize) -> u16,
) {
    let mut done = 0;
    while done < w {
        let x = x0 + done as u32;
        let col = fl::memory_column(x);
        let run = (w - done).min(catcard_ui::st7789::WIDTH - col);
        let _ = panel.paint(col, y0, run, h, |dx, dy| f(x + dx as u32, y0 + dy));
        done += run;
    }
}

/// The whole scene, every column on the glass.
fn paint_scene(panel: &mut display::Panel, g: &Game) {
    paint_world(panel, g.scroll, fl::PLAY_W, 0, fl::HEIGHT, |x| {
        g.shown_column(x)
    });
}

/// A key pressed since the last call, if any.
fn poll_key(ui: &mut Ui<'_>) -> Option<Key> {
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    let _ = crate::usbtask::pump();
    crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
    // Cancel wins over anything pressed with it.
    keys.iter()
        .copied()
        .find(|&k| k == Key::Cancel)
        .or(keys.first().copied())
}

/// Play until cancel: a game, its game-over screen, and another game on any other key.
pub(crate) fn flappy_cat(ui: &mut Ui<'_>) {
    crate::menu::message(ui.panel, "Flappy Cat", "any key flaps", "cancel quits");
    crate::menu::wait_for_any_key(ui);

    // The game scrolls the panel itself, at raw lines: from origin 0.
    display::reset_origin(ui.panel);
    let _ = ui.panel.set_scroll_area(0, 0);
    loop {
        let mut seed = [0u8; 4];
        let _ = ui.drbg.generate(&mut seed);
        if !play(ui, u32::from_le_bytes(seed)) {
            break;
        }
    }
    display::end_scroll(ui.panel);
}

/// One game. True to play again, false to leave.
fn play(ui: &mut Ui<'_>, seed: u32) -> bool {
    let mut g = Game::new(seed);
    let _ = ui.panel.set_scroll_start(fl::scroll_start(0));
    paint_scene(ui.panel, &g);

    let mut started = false;
    let mut score = 0;
    let (mut frames, mut late) = (0u32, 0u32);
    // Summed a frame at a time: the cycle counter wraps every 36 s at 120 MHz.
    let (mut elapsed, mut last) = (0u64, catcard_hal::dwt::cycles());
    // The slowest frame's work, tear pulse to scroll command, and how many ran past a frame.
    // SAFETY: reads RCC only.
    let frame_cycles = unsafe { catcard_hal::clock::hclk_hz() } / 61;
    let (mut worst, mut slow) = (0u32, 0u32);
    while !g.over {
        let now = catcard_hal::dwt::cycles();
        elapsed += u64::from(now.wrapping_sub(last));
        last = now;
        if !display::wait_tear() {
            late += 1;
        }
        let work_start = catcard_hal::dwt::cycles();
        match poll_key(ui) {
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
            g.step();
        } else {
            g.idle();
        }
        frames += 1;

        // The column coming in on the right. Its memory column is the one leaving on the
        // left, which the scroll below takes off the glass in the same gap.
        let incoming = (g.scroll - old_scroll) as usize;
        if incoming > 0 {
            let x = old_scroll + fl::PLAY_W as u32;
            paint_world(ui.panel, x, incoming, 0, fl::HEIGHT, |x| g.shown_column(x));
        }
        // The cat: where it was and where it is, as one patch.
        let top = old_y.min(g.cat_y());
        let bottom = (old_y.max(g.cat_y()) + fl::CAT_H).min(fl::HEIGHT);
        let width = (g.cat_x() - old_x) as usize + fl::CAT_W;
        paint_world(ui.panel, old_x, width, top, bottom - top, |x| {
            g.shown_column(x)
        });
        // The score: where it was on the world and where it is now, which is a column on
        // -- or a digit wider when the count gains one.
        let (old_left, old_w) = fl::score_span(old_score);
        let (new_left, new_w) = fl::score_span(g.score());
        let from = (old_scroll + old_left as u32).min(g.scroll + new_left as u32);
        let to = (old_scroll + (old_left + old_w) as u32).max(g.scroll + (new_left + new_w) as u32);
        paint_world(
            ui.panel,
            from,
            (to - from) as usize,
            fl::SCORE_TOP,
            fl::SCORE_H,
            |x| g.shown_column(x),
        );

        let _ = ui.panel.set_scroll_start(fl::scroll_start(g.scroll));
        score = g.score();
        let work = catcard_hal::dwt::cycles().wrapping_sub(work_start);
        worst = worst.max(work);
        if work > frame_cycles {
            slow += 1;
        }
    }

    // SAFETY: foreground only, single core.
    let best = unsafe { &mut *core::ptr::addr_of_mut!(BEST) };
    *best = (*best).max(score);
    // SAFETY: reads RCC only.
    let hz = unsafe { catcard_hal::clock::hclk_hz() }.max(1);
    let tenths = elapsed / u64::from((hz / 10).max(1));
    let worst_tenth_ms = u64::from(worst) * 10_000 / u64::from(hz);
    crate::catlog!(
        "flappy: score {}, best {}, {} frames in {}.{} s, {} late; worst frame {}.{} ms, {} slow",
        score,
        *best,
        frames,
        tenths / 10,
        tenths % 10,
        late,
        worst_tenth_ms / 10,
        worst_tenth_ms % 10,
        slow
    );

    // The banner over the frozen scene, centred on the glass.
    let banner_x = g.scroll + (fl::PLAY_W as u32 - GAME_OVER.width as u32) / 2;
    paint_world_pixels(
        ui.panel,
        banner_x,
        GAME_OVER.width as usize,
        BANNER_Y,
        GAME_OVER.height as usize,
        |x, y| {
            GAME_OVER
                .at((x - banner_x) as usize, y - BANNER_Y)
                .unwrap_or_else(|| g.shown(x, y))
        },
    );

    let mut held = 0;
    loop {
        display::wait_tear();
        let key = poll_key(ui);
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
