//! Block Mine -- a Boulder Dash-style micro game on 8x8 tiles.
//!
//! Dig through dirt with the arrow keys (`5` up, `8` down, `7` left, `9` right), collect
//! bitcoins, and reach the exit once you have enough. Boulders and coins fall when you dig
//! out their support and roll off each other; a falling boulder crushes you, and a coin
//! that falls on you is collected. Creatures patrol the tunnels and catch you on contact,
//! but a falling boulder squashes them. `x` quits.
//!
//! Nothing here touches the wallet: no secret is read and the grid is a fixed level.

use crate::keypad::{GpioMatrix, Keypad};
use crate::{display, usbtask};
use catcard_entropy::HmacDrbg;
use catcard_ui::canvas::{Canvas, INK};
use catcard_ui::keypad::{Event, KEYS, Key};
use core::fmt::Write as _;

/// Level dimensions, in tiles.
const W: usize = 24;
const H: usize = 14;
const TILE: usize = 8;
/// The camera window, in tiles: 16 wide (128 px) and 7 tall, leaving a HUD row on top.
const VIEW_W: usize = 16;
const VIEW_H: usize = 7;
const HUD_H: usize = 8;

// Terrain codes.
const EMPTY: u8 = 0;
const DIRT: u8 = 1;
const WALL: u8 = 2;
const BOULDER: u8 = 3;
const COIN: u8 = 4;
const EXIT: u8 = 5;

/// The one level. `#` wall, `.` dirt, ` ` tunnel, `O` boulder, `$` bitcoin, `E` creature,
/// `X` exit, `P` the miner's start. Every row is [`W`] characters.
const LEVEL: &[&[u8]] = &[
    b"########################",
    b"#P..$....O......$...E..#",
    b"#..OO..$..###..$..OO.$.#",
    b"#.$..###.....$...###..$#",
    b"#..$..O.$.###.$.O..$...#",
    b"#.###...$..O.O..$..###.#",
    b"#..$..OO.#.#..OO..$..$.#",
    b"#$..$..$..$.$..$..$...O#",
    b"#.###.###.###.###.###..#",
    b"#..O...$...O...$..O..E.#",
    b"#.$.$.$.$.$.$.$.$.$.$.$#",
    b"#..#..#..#..#..#..#..#.#",
    b"#..................$.X.#",
    b"########################",
];

// 8x8 tile art, one byte per row, most-significant bit at the left.
const DIRT_PAT: [u8; 8] = [0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55];
const WALL_PAT: [u8; 8] = [0xFF, 0x88, 0x88, 0xFF, 0x22, 0x22, 0xFF, 0x88];
const BOULDER_PAT: [u8; 8] = [0x3C, 0x7E, 0xFF, 0xFF, 0xFF, 0xFF, 0x7E, 0x3C];
const COIN_PAT: [u8; 8] = [0x18, 0x24, 0x42, 0x81, 0x81, 0x42, 0x24, 0x18];
const EXIT_PAT: [u8; 8] = [0xFF, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0xFF];
const EXIT_OPEN_PAT: [u8; 8] = [0xFF, 0xBD, 0xA5, 0x99, 0x99, 0xA5, 0xBD, 0xFF];
const PLAYER_PAT: [u8; 8] = [0x18, 0x18, 0x3C, 0x7E, 0x18, 0x18, 0x24, 0x24];
const ENEMY_PAT: [u8; 8] = [0x81, 0x5A, 0x3C, 0x7E, 0x7E, 0x3C, 0x5A, 0x81];

/// Cycles between gravity ticks and creature ticks; the loop's own idle pause paces input.
/// At ~80 MHz these are roughly 150 ms and 450 ms.
const GRAVITY_CYCLES: u32 = 12_000_000;
const ENEMY_CYCLES: u32 = 36_000_000;

/// A creature, with the direction it last travelled (0 up, 1 right, 2 down, 3 left).
#[derive(Copy, Clone)]
struct Enemy {
    x: usize,
    y: usize,
    dir: u8,
}

struct Game {
    grid: [u8; W * H],
    /// Whether the object at a cell is mid-fall; only a falling object crushes.
    falling: [bool; W * H],
    px: usize,
    py: usize,
    enemies: heapless::Vec<Enemy, 8>,
    coins: u32,
    needed: u32,
    dead: bool,
    won: bool,
}

fn dir_delta(dir: u8) -> (isize, isize) {
    match dir & 3 {
        0 => (0, -1),
        1 => (1, 0),
        2 => (0, 1),
        _ => (-1, 0),
    }
}

/// Where the camera's top-left tile sits so the player stays roughly centered.
fn camera(p: usize, view: usize, total: usize) -> usize {
    if total <= view {
        0
    } else {
        p.saturating_sub(view / 2).min(total - view)
    }
}

impl Game {
    fn load() -> Self {
        let mut g = Game {
            grid: [WALL; W * H],
            falling: [false; W * H],
            px: 1,
            py: 1,
            enemies: heapless::Vec::new(),
            coins: 0,
            needed: 0,
            dead: false,
            won: false,
        };
        let mut total = 0u32;
        for y in 0..H {
            let row = LEVEL.get(y).copied().unwrap_or(b"");
            for x in 0..W {
                let t = match row.get(x).copied().unwrap_or(b'#') {
                    b'#' => WALL,
                    b'.' => DIRT,
                    b' ' => EMPTY,
                    b'O' => BOULDER,
                    b'$' => {
                        total += 1;
                        COIN
                    }
                    b'X' => EXIT,
                    b'P' => {
                        g.px = x;
                        g.py = y;
                        EMPTY
                    }
                    b'E' => {
                        let _ = g.enemies.push(Enemy { x, y, dir: 1 });
                        EMPTY
                    }
                    _ => WALL,
                };
                g.grid[y * W + x] = t;
            }
        }
        // Not every coin need survive the boulders, so ask for three quarters of them.
        g.needed = (total * 3 / 4).max(1);
        g
    }

    fn at(&self, x: usize, y: usize) -> u8 {
        self.grid[y * W + x]
    }

    fn enemy_at(&self, x: usize, y: usize) -> Option<usize> {
        self.enemies.iter().position(|e| e.x == x && e.y == y)
    }

    /// A cell an object may fall or roll into: empty terrain with nobody standing on it.
    fn free(&self, x: usize, y: usize) -> bool {
        x < W
            && y < H
            && self.at(x, y) == EMPTY
            && !(self.px == x && self.py == y)
            && self.enemy_at(x, y).is_none()
    }

    /// Move the player by one step, digging, collecting, or pushing as the target allows.
    fn step_player(&mut self, dx: isize, dy: isize) {
        let nx = self.px as isize + dx;
        let ny = self.py as isize + dy;
        if nx < 0 || ny < 0 || nx >= W as isize || ny >= H as isize {
            return;
        }
        let (nx, ny) = (nx as usize, ny as usize);
        if self.enemy_at(nx, ny).is_some() {
            self.dead = true;
            return;
        }
        match self.at(nx, ny) {
            WALL => {}
            EXIT => {
                if self.coins >= self.needed {
                    self.won = true;
                }
            }
            DIRT | EMPTY => {
                self.grid[ny * W + nx] = EMPTY;
                self.px = nx;
                self.py = ny;
            }
            COIN => {
                self.coins += 1;
                self.grid[ny * W + nx] = EMPTY;
                self.px = nx;
                self.py = ny;
            }
            // Only a horizontal shove, and only into an empty cell beyond; a vertical
            // push (or a blocked one) falls through to the default and does nothing.
            BOULDER if dy == 0 => {
                let bx = nx as isize + dx;
                if bx >= 0 && (bx as usize) < W && self.free(bx as usize, ny) {
                    let bx = bx as usize;
                    self.grid[ny * W + bx] = BOULDER;
                    self.grid[ny * W + nx] = EMPTY;
                    self.px = nx;
                    self.py = ny;
                }
            }
            _ => {}
        }
    }

    /// Move an object one cell and carry its falling state.
    fn move_obj(&mut self, x: usize, y: usize, nx: usize, ny: usize) {
        self.grid[ny * W + nx] = self.grid[y * W + x];
        self.grid[y * W + x] = EMPTY;
        self.falling[ny * W + nx] = true;
        self.falling[y * W + x] = false;
    }

    /// One gravity tick: boulders and coins fall a cell, roll off rounded neighbours, and
    /// a falling one crushes the player or squashes a creature. Bottom-up so a stack
    /// settles a cell per tick rather than all at once.
    fn gravity(&mut self) {
        for y in (0..H).rev() {
            for x in 0..W {
                let t = self.at(x, y);
                if t != BOULDER && t != COIN {
                    continue;
                }
                let i = y * W + x;
                if y + 1 >= H {
                    self.falling[i] = false;
                    continue;
                }
                let by = y + 1;
                match self.at(x, by) {
                    EMPTY => {
                        if self.px == x && self.py == by {
                            if self.falling[i] {
                                // A coin lands as a collect; a boulder crushes.
                                if t == COIN {
                                    self.coins += 1;
                                    self.grid[i] = EMPTY;
                                } else {
                                    self.dead = true;
                                }
                            }
                            self.falling[i] = false;
                        } else if let Some(ei) = self.enemy_at(x, by) {
                            if self.falling[i] {
                                self.enemies.swap_remove(ei);
                                self.move_obj(x, y, x, by);
                            } else {
                                self.falling[i] = false;
                            }
                        } else {
                            self.move_obj(x, y, x, by);
                        }
                    }
                    // Rest, then roll off a rounded object if a diagonal is clear.
                    below => {
                        self.falling[i] = false;
                        if below == BOULDER || below == COIN {
                            for side in [-1isize, 1] {
                                let sx = x as isize + side;
                                if sx >= 0
                                    && (sx as usize) < W
                                    && self.free(sx as usize, y)
                                    && self.free(sx as usize, by)
                                {
                                    self.move_obj(x, y, sx as usize, y);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// One creature tick: each patrols the tunnels by a left-hand rule and catches the
    /// player on contact.
    fn move_enemies(&mut self) {
        for i in 0..self.enemies.len() {
            let e = self.enemies[i];
            // Prefer turning left, then straight, then right, then back.
            for turn in [3u8, 0, 1, 2] {
                let nd = (e.dir + turn) & 3;
                let (dx, dy) = dir_delta(nd);
                let nx = e.x as isize + dx;
                let ny = e.y as isize + dy;
                if nx < 0 || ny < 0 || nx >= W as isize || ny >= H as isize {
                    continue;
                }
                let (nx, ny) = (nx as usize, ny as usize);
                // Creatures travel only through open tunnels, never through anyone else.
                if self.at(nx, ny) != EMPTY || self.enemy_at(nx, ny).is_some() {
                    continue;
                }
                if self.px == nx && self.py == ny {
                    self.dead = true;
                }
                self.enemies[i] = Enemy { x: nx, y: ny, dir: nd };
                break;
            }
        }
    }
}

/// Draw one 8x8 pattern with its top-left at `(sx, sy)`.
fn blit<C: Canvas + ?Sized>(c: &mut C, sx: usize, sy: usize, pat: &[u8; 8]) {
    for (gy, row) in pat.iter().enumerate() {
        for gx in 0..8 {
            if row & (0x80 >> gx) != 0 {
                c.put(sx + gx, sy + gy, INK);
            }
        }
    }
}

fn render<C: Canvas + ?Sized>(c: &mut C, g: &Game) {
    c.clear();
    let cam_x = camera(g.px, VIEW_W, W);
    let cam_y = camera(g.py, VIEW_H, H);

    for row in 0..VIEW_H {
        for col in 0..VIEW_W {
            let (tx, ty) = (cam_x + col, cam_y + row);
            if tx >= W || ty >= H {
                continue;
            }
            let (sx, sy) = (col * TILE, HUD_H + row * TILE);
            let pat = match g.at(tx, ty) {
                DIRT => Some(&DIRT_PAT),
                WALL => Some(&WALL_PAT),
                BOULDER => Some(&BOULDER_PAT),
                COIN => Some(&COIN_PAT),
                EXIT => Some(if g.coins >= g.needed {
                    &EXIT_OPEN_PAT
                } else {
                    &EXIT_PAT
                }),
                _ => None,
            };
            if let Some(p) = pat {
                blit(c, sx, sy, p);
            }
        }
    }

    for e in g.enemies.iter() {
        if e.x >= cam_x && e.x < cam_x + VIEW_W && e.y >= cam_y && e.y < cam_y + VIEW_H {
            blit(c, (e.x - cam_x) * TILE, HUD_H + (e.y - cam_y) * TILE, &ENEMY_PAT);
        }
    }
    if g.px >= cam_x && g.px < cam_x + VIEW_W && g.py >= cam_y && g.py < cam_y + VIEW_H {
        blit(c, (g.px - cam_x) * TILE, HUD_H + (g.py - cam_y) * TILE, &PLAYER_PAT);
    }

    let mut hud = heapless::String::<24>::new();
    let _ = write!(hud, "BTC {}/{}  x quit", g.coins, g.needed);
    catcard_ui::text::draw_text(c, &catcard_ui::font::misc4x6::FONT, 1, 1, &hud);
}

/// Show a centered end-of-game message and wait for a key.
fn end_screen(
    panel: &mut display::Panel,
    pad: &mut Keypad,
    matrix: &mut GpioMatrix,
    drbg: &mut HmacDrbg,
    head: &str,
    line: &str,
) {
    display::draw(panel, |c| {
        catcard_ui::widgets::message(c, &display::LAYOUT, head, line, "any key");
    });
    // Drain the key that ended the game, then wait for a fresh press.
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        let _ = usbtask::pump();
        crate::pinentry::pressed_keys(pad, matrix, drbg, &mut events, &mut keys);
        if pad.held_count() == 0 {
            break;
        }
        catcard_hal::dwt::delay_cycles(usbtask::IDLE_PAUSE_CYCLES);
    }
    loop {
        let _ = usbtask::pump();
        crate::pinentry::pressed_keys(pad, matrix, drbg, &mut events, &mut keys);
        if !keys.is_empty() {
            return;
        }
        catcard_hal::dwt::delay_cycles(usbtask::IDLE_PAUSE_CYCLES);
    }
}

/// Play one round of Block Mine, returning to the menu when it ends or `x` is pressed.
pub(crate) fn block_mine(
    panel: &mut display::Panel,
    pad: &mut Keypad,
    matrix: &mut GpioMatrix,
    drbg: &mut HmacDrbg,
) {
    let mut g = Game::load();
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    let mut last_gravity = catcard_hal::dwt::cycles();
    let mut last_enemy = last_gravity;
    let mut redraw = true;

    loop {
        if redraw {
            display::draw(panel, |c| render(c, &g));
            redraw = false;
        }
        if g.won {
            end_screen(panel, pad, matrix, drbg, "You win!", "exit reached");
            return;
        }
        if g.dead {
            end_screen(panel, pad, matrix, drbg, "Game over", "you were caught");
            return;
        }

        let _ = usbtask::pump();
        crate::pinentry::pressed_keys(pad, matrix, drbg, &mut events, &mut keys);
        for k in keys.iter() {
            match k {
                Key::Cancel => return,
                Key::Digit(5) => {
                    g.step_player(0, -1);
                    redraw = true;
                }
                Key::Digit(8) => {
                    g.step_player(0, 1);
                    redraw = true;
                }
                Key::Digit(7) => {
                    g.step_player(-1, 0);
                    redraw = true;
                }
                Key::Digit(9) => {
                    g.step_player(1, 0);
                    redraw = true;
                }
                _ => {}
            }
        }

        let now = catcard_hal::dwt::cycles();
        if now.wrapping_sub(last_gravity) >= GRAVITY_CYCLES {
            g.gravity();
            last_gravity = now;
            redraw = true;
        }
        if now.wrapping_sub(last_enemy) >= ENEMY_CYCLES {
            g.move_enemies();
            last_enemy = now;
            redraw = true;
        }
        catcard_hal::dwt::delay_cycles(usbtask::IDLE_PAUSE_CYCLES);
    }
}
