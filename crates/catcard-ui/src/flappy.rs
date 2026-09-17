//! Flappy: the game, with no hardware in it.
//!
//! Built for the Q1's panel scrolling itself (see
//! [`St7789::set_scroll_area`](crate::st7789::St7789::set_scroll_area)): the world is drawn
//! into the controller's frame memory **in world coordinates**, and moving the scroll start
//! is what moves it across the glass. So nothing here thinks in screen positions except the
//! bird, which stays at one place on the glass while the world slides under it.
//!
//! The whole panel scrolls as one ring of [`PLAY_W`] lines. World column `x` lives in
//! frame-memory column [`memory_column`]`(x)` forever, and with the view at `scroll` the
//! glass shows world columns `scroll .. scroll + PLAY_W`, left to right (measured on a Q1).
//!
//! The score is the one thing that stays put on the glass while the world moves under it,
//! so it is redrawn every frame, a column over from where it was: [`Game::shown`] layers
//! it over the bird over the world, and any patch painted through that comes out right
//! wherever the score, the bird and the pipes overlap.
//!
//! The art is the game's own, at its native 144x256 scale ([`crate::art::flappy`]), and so
//! are the proportions: a 200-row playfield over the ground, 26-wide pipes 72 apart with a
//! 50-row gap. The physics is the common 30 fps rendition's, halved for the scale and
//! re-timed for the panel's ~61 Hz: gravity 1/8 px per frame², a flap of -2.25 px per
//! frame, a fall capped at 2.5, and the world moving a pixel a frame.
//!
//! Everything is integer arithmetic, and the pipes come from a seed, so a world column can
//! be redrawn at any time and come out the same.

use crate::art::flappy::{BACKGROUND, BASE, BIRD_DOWN, BIRD_MID, BIRD_UP, DIGITS, PIPE, Sprite};

/// The scrolling area: the whole width of the panel.
pub const PLAY_W: usize = 320;
pub const HEIGHT: usize = 240;

/// Rows from here down are ground.
pub const GROUND_Y: usize = 200;

/// World pixels the view moves per frame.
pub const SPEED: u32 = 1;

/// Where the bird sits on the glass, from the left edge of the scrolling area.
pub const BIRD_X: u32 = 50;
pub const BIRD_W: usize = BIRD_MID.width as usize;
pub const BIRD_H: usize = BIRD_MID.height as usize;

pub const PIPE_W: u32 = PIPE.width as u32;
pub const PIPE_SPACING: u32 = 72;
pub const GAP: i32 = 50;
/// The gap's top edge: from 40 to 110, a fifth of the playfield down and 70 rows of play.
const GAP_TOP_MIN: i32 = 40;
const GAP_TOP_SPAN: u32 = 71;
/// The first pipe comes in from off the right edge after a moment of open sky.
const FIRST_PIPE: u32 = PLAY_W as u32 + 100;

/// Physics in sixteenths of a pixel per frame.
const FP: i32 = 16;
const GRAVITY: i32 = 2;
const FLAP: i32 = -36;
const MAX_FALL: i32 = 40;

/// Frames each wing position shows for.
const WING_FRAMES: u32 = 8;

/// The frame-memory column world column `x` is drawn in.
pub const fn memory_column(x: u32) -> usize {
    (x % PLAY_W as u32) as usize
}

/// The scroll start that puts world column `scroll` at the left of the scrolling area.
pub const fn scroll_start(scroll: u32) -> usize {
    memory_column(scroll)
}

/// Background and ground at world `(x, y)`: the parts that tile.
fn scenery(x: u32, y: usize) -> u16 {
    let tile = |s: &Sprite, y: usize| s.at((x % s.width as u32) as usize, y).unwrap_or(0);
    if y >= GROUND_Y {
        tile(&BASE, y - GROUND_Y)
    } else {
        tile(&BACKGROUND, y)
    }
}

/// The pipes, from a seed.
#[derive(Copy, Clone)]
pub struct World {
    seed: u32,
}

impl World {
    pub const fn new(seed: u32) -> Self {
        Self { seed }
    }

    /// The top row of pipe `i`'s gap.
    ///
    /// The average of two hashed values, the ones for `i` and `i + 1`, so neighbours share
    /// one and a gap moves at most half the range from the last -- 35 rows. With every gap
    /// independent, as the original has it, a 70-row change between neighbours comes up
    /// now and then and is flyable by half a pixel at best, flapping every frame. Still a
    /// pure function of the index, so any pipe can be asked for in any order.
    pub fn gap_top(&self, i: u32) -> i32 {
        GAP_TOP_MIN + ((self.hash(i) + self.hash(i.wrapping_add(1))) / 2) as i32
    }

    /// A value in `0..GAP_TOP_SPAN` for `i`.
    fn hash(&self, i: u32) -> u32 {
        let mut h = self.seed ^ i.wrapping_mul(0x9E37_79B9);
        h ^= h >> 16;
        h = h.wrapping_mul(0x85EB_CA6B);
        h ^= h >> 13;
        h = h.wrapping_mul(0xC2B2_AE35);
        h ^= h >> 16;
        h % GAP_TOP_SPAN
    }

    /// The pipe covering world column `x`, and how far into it `x` is.
    pub fn pipe_at(&self, x: u32) -> Option<(u32, u32)> {
        let rel = x.checked_sub(FIRST_PIPE)?;
        let into = rel % PIPE_SPACING;
        (into < PIPE_W).then_some((rel / PIPE_SPACING, into))
    }

    /// The colour of world pixel `(x, y)`, the bird not included.
    ///
    /// The pipe sprite has its lip at the top, so the lower pipe draws it as it is from the
    /// gap down, and the upper pipe draws it flipped from the gap up. A pipe longer than the
    /// sprite repeats its last row, which is plain body.
    pub fn colour(&self, x: u32, y: usize) -> u16 {
        if y < GROUND_Y
            && let Some((i, into)) = self.pipe_at(x)
        {
            let (top, yi) = (self.gap_top(i), y as i32);
            let row = if yi < top {
                Some(top - 1 - yi)
            } else if yi >= top + GAP {
                Some(yi - top - GAP)
            } else {
                None
            };
            if let Some(r) = row {
                let r = (r as usize).min(PIPE.height as usize - 1);
                if let Some(c) = PIPE.at(into as usize, r) {
                    return c;
                }
            }
        }
        scenery(x, y)
    }
}

/// One game in progress.
pub struct Game {
    pub world: World,
    /// World column at the left of the scrolling area.
    pub scroll: u32,
    /// The bird's top edge, in sixteenths of a pixel.
    y: i32,
    vy: i32,
    frame: u32,
    pub over: bool,
}

impl Game {
    pub fn new(seed: u32) -> Self {
        Self {
            world: World::new(seed),
            scroll: 0,
            y: ((GROUND_Y - BIRD_H) as i32 / 2) * FP,
            vy: 0,
            frame: 0,
            over: false,
        }
    }

    /// The bird's top edge, in pixels.
    pub fn bird_y(&self) -> usize {
        (self.y / FP).max(0) as usize
    }

    /// The world column under the bird's left edge.
    pub fn bird_x(&self) -> u32 {
        self.scroll + BIRD_X
    }

    pub fn flap(&mut self) {
        if !self.over {
            self.vy = FLAP;
        }
    }

    /// Before the first flap: the bird hovers, bobbing, and the world does not move.
    pub fn idle(&mut self) {
        self.frame += 1;
        let phase = (self.frame / 4) % 16;
        let bob = if phase < 8 { phase } else { 16 - phase } as i32;
        self.y = ((GROUND_Y - BIRD_H) as i32 / 2 - 4 + bob) * FP;
    }

    /// Pipes the bird is past.
    pub fn score(&self) -> u32 {
        match self.bird_x().checked_sub(FIRST_PIPE + PIPE_W) {
            Some(d) => d / PIPE_SPACING + 1,
            None => 0,
        }
    }

    /// One frame: fall, move on, and see what the bird hit.
    pub fn step(&mut self) {
        if self.over {
            return;
        }
        self.frame += 1;
        self.vy = (self.vy + GRAVITY).min(MAX_FALL);
        self.y += self.vy;
        if self.y < 0 {
            // The sky is a ceiling, not a death.
            self.y = 0;
            self.vy = 0;
        }
        self.scroll += SPEED;
        self.over = self.hit();
    }

    /// Whether the bird's opaque pixels touch the ground or a pipe.
    fn hit(&self) -> bool {
        let (bx, by) = (self.bird_x(), self.bird_y());
        if by + BIRD_H > GROUND_Y {
            return true;
        }
        let sprite = self.bird();
        (0..BIRD_W).any(|dx| {
            let Some((i, _)) = self.world.pipe_at(bx + dx as u32) else {
                return false;
            };
            let top = self.world.gap_top(i);
            (0..BIRD_H).any(|dy| {
                let y = (by + dy) as i32;
                (y < top || y >= top + GAP) && sprite.at(dx, dy).is_some()
            })
        })
    }

    /// The wing position this frame. Held still once the game is over.
    pub fn bird(&self) -> &'static Sprite {
        match (self.frame / WING_FRAMES) % 4 {
            0 => &BIRD_UP,
            2 => &BIRD_DOWN,
            _ => &BIRD_MID,
        }
    }

    /// What world pixel `(x, y)` looks like with the bird drawn in.
    pub fn pixel(&self, x: u32, y: usize) -> u16 {
        let (bx, by) = (self.bird_x(), self.bird_y());
        if x >= bx
            && y >= by
            && let Some(c) = self.bird().at((x - bx) as usize, y - by)
        {
            return c;
        }
        self.world.colour(x, y)
    }
}

/// The score's top row on the glass.
pub const SCORE_TOP: usize = 8;
pub const SCORE_H: usize = DIGITS[0].height as usize;
/// Digits in the largest `u32`.
const MAX_DIGITS: usize = 10;

/// `score`'s digits, most significant first.
fn digits(score: u32) -> ([usize; MAX_DIGITS], usize) {
    let mut out = [0usize; MAX_DIGITS];
    let (mut n, mut count) = (score, 0);
    loop {
        out[MAX_DIGITS - 1 - count] = (n % 10) as usize;
        n /= 10;
        count += 1;
        if n == 0 {
            break;
        }
    }
    (out, count)
}

/// Where `score` sits on the glass: its left column and width, centred. Even the largest
/// `u32` is 120 wide, well inside the panel.
pub fn score_span(score: u32) -> (usize, usize) {
    let (d, count) = digits(score);
    let width: usize = d[MAX_DIGITS - count..]
        .iter()
        .map(|&d| DIGITS[d].width as usize)
        .sum();
    ((PLAY_W - width) / 2, width)
}

/// The score's colour at glass column `sx`, row `y`, or `None` where it does not cover.
pub fn score_colour(score: u32, sx: usize, y: usize) -> Option<u16> {
    let (mut left, width) = score_span(score);
    if !(SCORE_TOP..SCORE_TOP + SCORE_H).contains(&y) || !(left..left + width).contains(&sx) {
        return None;
    }
    let (d, count) = digits(score);
    for &digit in &d[MAX_DIGITS - count..] {
        let s = &DIGITS[digit];
        if sx < left + s.width as usize {
            return s.at(sx - left, y - SCORE_TOP);
        }
        left += s.width as usize;
    }
    None
}

impl Game {
    /// World pixel `(x, y)` as the glass shows it: the score over the bird over the world.
    ///
    /// The score only covers glass columns, so a world column behind the view -- one the
    /// scroll has not reached, or has left -- never carries it.
    pub fn shown(&self, x: u32, y: usize) -> u16 {
        if let Some(sx) = x.checked_sub(self.scroll)
            && (sx as usize) < PLAY_W
            && let Some(c) = score_colour(self.score(), sx as usize, y)
        {
            return c;
        }
        self.pixel(x, y)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::art::flappy::GAME_OVER;

    #[test]
    fn the_art_is_the_size_the_layout_assumes() {
        assert_eq!((BACKGROUND.width, BACKGROUND.height), (144, 200));
        assert_eq!(BASE.height as usize, HEIGHT - GROUND_Y);
        assert_eq!((PIPE.width, PIPE.height), (26, 160));
        assert_eq!((BIRD_W, BIRD_H), (17, 12));
        for b in [&BIRD_UP, &BIRD_DOWN] {
            assert_eq!((b.width as usize, b.height as usize), (BIRD_W, BIRD_H));
        }
        assert!(GAME_OVER.width as usize <= PLAY_W);
        assert!((GAP_TOP_MIN + GAP_TOP_SPAN as i32 - 1 + GAP) < GROUND_Y as i32);
        // The longest pipe the gaps can ask for still has sprite rows or its body to repeat.
        assert!(PIPE.at(13, PIPE.height as usize - 1).is_some());
    }

    #[test]
    fn a_world_column_keeps_its_memory_column_as_the_view_moves() {
        // The whole trick: draw once, scroll for free.
        assert_eq!(memory_column(0), 0);
        assert_eq!(memory_column(PLAY_W as u32 - 1), 319);
        assert_eq!(memory_column(PLAY_W as u32), 0);
        assert_eq!(scroll_start(1000), memory_column(1000));
    }

    #[test]
    fn every_gap_is_between_the_sky_and_the_ground() {
        let w = World::new(0xDEAD_BEEF);
        let tops: Vec<i32> = (0..10_000).map(|i| w.gap_top(i)).collect();
        assert!(tops.iter().all(|&t| (40..=110).contains(&t)));
        // The whole range is used, neighbours are never more than 35 rows apart, and the
        // seed matters.
        assert!(tops.contains(&40) && tops.contains(&110));
        assert!(tops.windows(2).all(|p| (p[0] - p[1]).abs() <= 35));
        assert!((0..20).any(|i| World::new(1).gap_top(i) != World::new(2).gap_top(i)));
    }

    #[test]
    fn a_pipe_is_open_at_its_gap_and_solid_above_and_below() {
        let w = World::new(9);
        let x = FIRST_PIPE + PIPE_W / 2;
        let top = w.gap_top(0) as usize;
        let open = w.colour(x, top + 10);
        assert_eq!(open, scenery(x, top + 10));
        assert_ne!(w.colour(x, top - 20), scenery(x, top - 20));
        assert_ne!(
            w.colour(x, top + GAP as usize + 20),
            scenery(x, top + GAP as usize + 20)
        );
    }

    #[test]
    fn a_bird_left_alone_falls_to_the_ground_and_the_game_ends() {
        let mut g = Game::new(7);
        let mut frames = 0;
        while !g.over {
            g.step();
            frames += 1;
            assert!(frames < 300, "never landed");
        }
        assert!(g.bird_y() + BIRD_H > GROUND_Y);
        assert_eq!(g.score(), 0);
    }

    #[test]
    fn every_gap_can_be_flown_through_with_this_physics() {
        // An autopilot aiming at the middle of the first pipe not yet passed, flapping when
        // below it and falling. It proves the gaps are passable with this physics -- the
        // steepest climb and drop between neighbours included -- not just that pipes exist.
        for seed in [1, 42, 0xC0FFEE] {
            let mut g = Game::new(seed);
            for _ in 0..20_000 {
                let bx = g.bird_x();
                // The first pipe whose right edge is not yet behind the bird, and the one
                // after it.
                let next = match bx.checked_sub(FIRST_PIPE + PIPE_W) {
                    None => 0,
                    Some(d) => d / PIPE_SPACING + 1,
                };
                let this_top = g.world.gap_top(next);
                let after = g.world.gap_top(next + 1) + GAP / 2;
                // Flapping when below the target keeps the centre between 20 rows above it
                // and a few below, so the target is kept where that whole swing clears this
                // gap -- and within that, as close to the next gap as it can get.
                let target = after.clamp(this_top + 27, this_top + 40);
                let centre = g.bird_y() as i32 + BIRD_H as i32 / 2;
                if centre > target && g.vy >= 0 {
                    g.flap();
                }
                g.step();
                assert!(!g.over, "seed {seed}: hit something at score {}", g.score());
            }
            assert!(g.score() >= 250, "score {}", g.score());
        }
    }

    #[test]
    fn the_bird_is_drawn_over_the_world_and_nowhere_else() {
        let g = Game::new(3);
        let (bx, by) = (g.bird_x(), g.bird_y());
        let sprite = g.bird();
        let (dx, dy) = (0..BIRD_W)
            .flat_map(|x| (0..BIRD_H).map(move |y| (x, y)))
            .find(|&(x, y)| sprite.at(x, y).is_some())
            .unwrap();
        assert_eq!(g.pixel(bx + dx as u32, by + dy), sprite.at(dx, dy).unwrap());
        assert_eq!(g.pixel(bx + 200, by), g.world.colour(bx + 200, by));
    }

    #[test]
    fn the_score_is_centred_and_even_the_largest_fits() {
        let (left, width) = score_span(0);
        assert_eq!(width, DIGITS[0].width as usize);
        assert_eq!(left * 2 + width, PLAY_W);
        let (left, width) = score_span(u32::MAX);
        assert!(width > 100 && left + width <= PLAY_W);
        // A 1 is narrower than the others, and the span says so.
        assert!(score_span(11).1 < score_span(22).1);
    }

    #[test]
    fn the_score_stays_on_the_glass_as_the_world_moves_under_it() {
        let mut g = Game::new(5);
        let sx = (0..PLAY_W)
            .find(|&sx| score_colour(0, sx, SCORE_TOP + 4).is_some())
            .unwrap();
        let ink = score_colour(0, sx, SCORE_TOP + 4).unwrap();
        for _ in 0..3 {
            assert_eq!(g.shown(g.scroll + sx as u32, SCORE_TOP + 4), ink);
            g.flap();
            g.step();
        }
        // Where the score was, a frame ago, the world shows through again.
        let x = g.scroll - 1 + sx as u32;
        if score_colour(0, sx - 1, SCORE_TOP + 4).is_none() {
            assert_eq!(g.shown(x, SCORE_TOP + 4), g.pixel(x, SCORE_TOP + 4));
        }
        // Off the glass, nothing.
        assert_eq!(
            g.shown(g.scroll + PLAY_W as u32, SCORE_TOP + 4),
            g.pixel(g.scroll + PLAY_W as u32, SCORE_TOP + 4)
        );
    }
}
