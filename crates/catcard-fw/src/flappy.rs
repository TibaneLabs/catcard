//! Flappy, on the Q1: the panel scrolls, the firmware only draws what changed.
//!
//! The game itself is [`catcard_ui::flappy`]. This is the part that talks to the panel: the
//! scroll area is set once, the whole scene painted once, and from then on each frame is
//! the column coming in on the right, the bird's few hundred pixels, and one scroll command,
//! all sent in the gap after a tear pulse. A full frame is 153 KB; a game frame is about 1.
//!
//! Every way out puts the panel's scrolling back before anything else draws: the rest of
//! the firmware addresses the panel as though nothing were shifted.
//!
//! Nothing here touches the wallet.

use catcard_ui::art::flappy::{DIGITS, GAME_OVER};
use catcard_ui::flappy::{self as fl, Game};
use catcard_ui::keypad::{Event, KEYS, Key};

use crate::display;
use crate::ui::Ui;

/// The best score since power-up. Foreground only.
static mut BEST: u32 = 0;

/// Frames after a game ends before a key counts, so the flap that crashed the bird does not
/// also skip the game-over screen.
const GAME_OVER_HOLD: u32 = 40;

/// Where the game-over banner sits on the glass, from the top.
const BANNER_Y: usize = 60;

/// Paint world columns `x0 .. x0 + w`, rows `y0 .. y0 + h`, split where the columns wrap
/// around the ring of frame memory.
fn paint_world(
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

/// The fixed strip's score area, redrawn.
fn paint_score(panel: &mut display::Panel, score: u32) {
    let h = DIGITS[0].height as usize + 8;
    let _ = panel.paint(0, 0, fl::STRIP, h, |x, y| fl::strip_colour(score, x, y));
}

/// The whole scene: strip, then every visible world column.
fn paint_scene(panel: &mut display::Panel, g: &Game) {
    let _ = panel.paint(0, 0, fl::STRIP, fl::HEIGHT, |x, y| {
        fl::strip_colour(0, x, y)
    });
    paint_world(panel, g.scroll, fl::PLAY_W, 0, fl::HEIGHT, |x, y| {
        g.pixel(x, y)
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
pub(crate) fn flappy(ui: &mut Ui<'_>) {
    crate::menu::message(ui.panel, "Flappy", "any key flaps", "cancel quits");
    crate::menu::wait_for_any_key(ui);

    let _ = ui.panel.set_scroll_area(fl::STRIP, 0);
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
    while !g.over {
        let now = catcard_hal::dwt::cycles();
        elapsed += u64::from(now.wrapping_sub(last));
        last = now;
        if !display::wait_tear() {
            late += 1;
        }
        match poll_key(ui) {
            Some(Key::Cancel) => return false,
            Some(_) => {
                started = true;
                g.flap();
            }
            None => {}
        }

        let (old_scroll, old_x, old_y) = (g.scroll, g.bird_x(), g.bird_y());
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
            paint_world(ui.panel, x, incoming, 0, fl::HEIGHT, |x, y| {
                g.world.colour(x, y)
            });
        }
        // The bird: where it was and where it is, as one patch.
        let top = old_y.min(g.bird_y());
        let bottom = (old_y.max(g.bird_y()) + fl::BIRD_H).min(fl::HEIGHT);
        let width = (g.bird_x() - old_x) as usize + fl::BIRD_W;
        paint_world(ui.panel, old_x, width, top, bottom - top, |x, y| {
            g.pixel(x, y)
        });

        let _ = ui.panel.set_scroll_start(fl::scroll_start(g.scroll));
        if g.score() != score {
            score = g.score();
            paint_score(ui.panel, score);
        }
    }

    // SAFETY: foreground only, single core.
    let best = unsafe { &mut *core::ptr::addr_of_mut!(BEST) };
    *best = (*best).max(score);
    // SAFETY: reads RCC only.
    let hz = unsafe { catcard_hal::clock::hclk_hz() }.max(1);
    let tenths = elapsed / u64::from((hz / 10).max(1));
    crate::catlog!(
        "flappy: score {}, best {}, {} frames in {}.{} s, {} late",
        score,
        *best,
        frames,
        tenths / 10,
        tenths % 10,
        late
    );

    // The banner over the frozen scene, centred on the glass.
    let banner_x = g.scroll + (fl::PLAY_W as u32 - GAME_OVER.width as u32) / 2;
    paint_world(
        ui.panel,
        banner_x,
        GAME_OVER.width as usize,
        BANNER_Y,
        GAME_OVER.height as usize,
        |x, y| {
            GAME_OVER
                .at((x - banner_x) as usize, y - BANNER_Y)
                .unwrap_or_else(|| g.pixel(x, y))
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
