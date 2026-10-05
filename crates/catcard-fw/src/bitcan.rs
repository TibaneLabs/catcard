//! Seed words as BitCan glyphs: shown in place of the words, and read back in by line.
//!
//! A glyph is a word's wordlist index drawn as eleven lines, bold for a set bit and light
//! for a clear one (`catcard_ui::bitcan`). Showing one is a picture of the same eleven bits
//! the word spells; entering one is answering "bold or light?" eleven times, from the
//! bottom edge up, which is the order that halves the candidate words at each line.
//!
//! Entry plugs into the ordinary phrase reader as its word reader, so a BitCan import gets
//! the same last-word filter, checksum check and fix-a-word menu as typed words.
//!
//! Source: https://bitcan.world, format definition [C]

use catcard_ui::bitcan::{self, ENTRY_ORDER, Mark, Page, Pens, SEGMENTS, Shape};
#[cfg(feature = "board-q1")]
use catcard_ui::canvas::Canvas as _;
use catcard_ui::keypad::{Event, KEYS, Key};
use catcard_wallet::bip39::{MAX_WORDS, Mnemonic, wordlist};
use core::fmt::Write;

use crate::display;
use crate::menu::{WordPick, wait_for_release};
use crate::ui::Ui;
use crate::usbtask;

/// One glyph page per board: four across the OLED, two rows of six on the Q1.
#[cfg(not(feature = "board-q1"))]
const PAGE: Page = Page {
    cols: 4,
    rows: 1,
    glyph_h: 54,
};
#[cfg(feature = "board-q1")]
const PAGE: Page = Page {
    cols: 6,
    rows: 2,
    glyph_h: 88,
};

#[cfg(not(feature = "board-q1"))]
const PENS: Pens = Pens::MONO;
#[cfg(feature = "board-q1")]
const PENS: Pens = Pens::GRAY;

/// Height of a glyph on the entry screen: most of the panel, beside the text.
#[cfg(not(feature = "board-q1"))]
const ENTRY_H: usize = 60;
#[cfg(feature = "board-q1")]
const ENTRY_H: usize = 200;

/// Wait for the next key press, keeping USB answered.
fn next_key(ui: &mut Ui<'_>) -> Key {
    wait_for_release(ui);
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        let _ = usbtask::pump();
        crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
        if let Some(&k) = keys.first() {
            return k;
        }
        display::idle(ui.panel);
    }
}

/// Show `m`'s words as glyphs, a page at a time.
///
/// `5`/`8` (and `7`/`9`) turn the page, `1` swaps between the Stack and Fold drawings.
/// As with the words, OK pages forward until every glyph has been on screen; then it
/// finishes, and the result is true. `x` goes back to the words, and the result is false.
pub(crate) fn show(ui: &mut Ui<'_>, m: &Mnemonic) -> bool {
    let mut idx = zeroize::Zeroizing::new([0u16; MAX_WORDS]);
    let n = m.word_indices(&mut idx);
    let per = PAGE.per_page();
    let pages = n.div_ceil(per);
    let (mut page, mut seen, mut shape) = (0usize, 0usize, Shape::Stack);
    loop {
        seen = seen.max(page);
        let first = page * per;
        let last = (first + per).min(n);
        display::draw(ui.panel, |c| {
            c.clear();
            bitcan::draw_page(
                c,
                display::LAYOUT.body,
                &PAGE,
                first + 1,
                &idx[first..last],
                shape,
                &PENS,
            );
            #[cfg(feature = "board-q1")]
            {
                let mut hint: heapless::String<48> = heapless::String::new();
                let _ = write!(
                    hint,
                    "{}-{} of {}   1: {}   OK: {}",
                    first + 1,
                    last,
                    n,
                    shape.toggled().name(),
                    if page + 1 < pages { "next" } else { "done" }
                );
                let y = display::SCREEN_H - display::LAYOUT.body.line_height();
                catcard_ui::text::draw_text(c, display::LAYOUT.body, 4, y, &hint);
            }
        });
        match next_key(ui) {
            Key::Digit(5) | Key::Digit(7) => page = page.saturating_sub(1),
            Key::Digit(8) | Key::Digit(9) => page = (page + 1).min(pages - 1),
            Key::Digit(1) => shape = shape.toggled(),
            Key::Confirm => {
                if page + 1 < pages {
                    page += 1;
                } else if seen + 1 >= pages {
                    return true;
                }
            }
            Key::Cancel => return false,
            _ => {}
        }
    }
}

/// Read one word as a glyph, line by line from the bottom edge: `1` bold, `0` light, `x`
/// back a line (or, at the first line, back a word). Once all eleven are in, the word is
/// shown and OK takes it.
///
/// `only` is the last word's checksum-valid set when the count is known; a glyph outside
/// it is refused there and then, as the typed reader refuses such a word. With no count,
/// OK twice on an empty glyph finishes the phrase.
pub(crate) fn read_word(ui: &mut Ui<'_>, num: usize, only: Option<&[u16]>) -> WordPick {
    let mut bits = zeroize::Zeroizing::new(0u16);
    let mut known = 0usize;
    let mut armed = false;
    loop {
        let value = *bits;
        let complete = known == SEGMENTS;
        let allowed = !complete || only.is_none_or(|o| o.contains(&value));
        draw_entry(ui, num, value, known, allowed, armed);
        let k = next_key(ui);
        let was_armed = core::mem::take(&mut armed);
        match k {
            Key::Digit(d @ (0 | 1)) if !complete => {
                let seg = ENTRY_ORDER[known];
                *bits = (*bits & !(1 << seg)) | (u16::from(d) << seg);
                known += 1;
            }
            Key::Cancel => {
                if known == 0 {
                    return WordPick::Back;
                }
                known -= 1;
                *bits &= !(1 << ENTRY_ORDER[known]);
            }
            Key::Confirm if complete && allowed => return WordPick::Word(value),
            Key::Confirm if known == 0 && only.is_none() => {
                if was_armed {
                    return WordPick::Finish;
                }
                armed = true;
            }
            _ => {}
        }
    }
}

/// The entry screen: the glyph so far on the left, the question and the words it could
/// still be on the right.
fn draw_entry(ui: &mut Ui<'_>, num: usize, bits: u16, known: usize, allowed: bool, armed: bool) {
    let mut marks = [Mark::Unknown; SEGMENTS];
    for (i, &seg) in ENTRY_ORDER.iter().enumerate() {
        marks[seg] = match i.cmp(&known) {
            core::cmp::Ordering::Less if bitcan::bold(bits, seg) => Mark::On,
            core::cmp::Ordering::Less => Mark::Off,
            core::cmp::Ordering::Equal => Mark::Here,
            core::cmp::Ordering::Greater => Mark::Unknown,
        };
    }
    let (lo, hi) = bitcan::range(bits, known);
    let mut head: heapless::String<24> = heapless::String::new();
    let _ = write!(head, "Word {num}");
    let mut l1: heapless::String<24> = heapless::String::new();
    let mut l2: heapless::String<24> = heapless::String::new();
    let mut l3: heapless::String<24> = heapless::String::new();
    let mut l4: heapless::String<24> = heapless::String::new();
    if known < SEGMENTS {
        let _ = write!(l1, "Line {} of {}", known + 1, SEGMENTS);
        let _ = l2.push_str("1 bold, 0 light");
        let _ = write!(l3, "{}", wordlist::word(lo as usize));
        let _ = write!(l4, "to {}", wordlist::word(hi as usize));
        if armed {
            l2.clear();
            let _ = l2.push_str("OK again: finish");
        }
    } else {
        let _ = l1.push_str(wordlist::word(bits as usize));
        if allowed {
            let _ = l2.push_str("OK: take it");
        } else {
            let _ = l2.push_str("not a last word");
        }
        let _ = l3.push_str("x: change");
    }
    let body = display::LAYOUT.body;
    let title = display::LAYOUT.title;
    display::draw(ui.panel, |c| {
        c.clear();
        bitcan::draw(c, 2, 2, ENTRY_H, Shape::Stack, &marks, &PENS);
        let x = ENTRY_H / 2 + 8;
        let mut y = 0;
        catcard_ui::text::draw_text(c, title, x, y, &head);
        y += title.line_height() + display::LAYOUT.gap;
        let big = known == SEGMENTS;
        for (n, s) in [&l1, &l2, &l3, &l4].into_iter().enumerate() {
            // The finished word in the title face, so it reads at arm's length.
            let face = if big && n == 0 { title } else { body };
            catcard_ui::text::draw_text(c, face, x, y, s);
            y += face.line_height() + display::LAYOUT.gap;
        }
    });
}
