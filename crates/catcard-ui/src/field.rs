//! Input fields: a card of one or more rows, with a caret in the one being typed into.
//!
//! The PIN screen drew one of these by hand -- a white card, paw prints for the digits, a
//! hairline caret -- and then every other screen that takes typing had its own idea. The
//! passphrase was a wrapped paragraph, the BIP-85 index was a number with a `<` beside it
//! and arrow keys to nudge it. Three screens, three answers to "where does what I type
//! appear", on a device where the answer should never be in doubt.
//!
//! So it is one widget with options: how the content is shown ([`Show`]), how many rows,
//! how tall each is, and which one is live. What a screen keeps is a buffer and a cursor;
//! what it draws is this.
//!
//! # What it does not do
//!
//! It does not read keys and it does not own the text. A caller holds its own buffer --
//! which for a secret means it can zeroize it -- passes a borrow in, and decides what each
//! key means. The caret's blink is the caller's too: pass `caret: false` on the dark half
//! of the blink. Nothing here keeps state between frames.

use zeroize::Zeroize as _;

use crate::canvas::{Canvas, INK, Level};
use crate::text::{draw_text_in, width_of};
use crate::widgets::Layout;

/// Black, in both palettes a field is drawn through: index 1 of the art palette and the
/// bottom of the grey ramp. What sits on a white card.
const MARK: Level = 1;

/// Air above and below a row's content, for a board whose body face is this tall.
///
/// Proportional, not fixed: eight pixels is a comfortable margin beside a 14-pixel face
/// on the Q1 and a third of the whole card beside a 6-pixel one on the OLED, where two
/// rows then do not fit on the panel at all.
fn lead(l: &Layout<'_>) -> usize {
    (l.body.line_height() / 2).max(2)
}

/// Gap between a row's label and its value.
const LABEL_GAP: usize = 8;

/// The width a caret is drawn at: a hairline, as a text cursor is.
const CARET_W: usize = 1;

/// How a row shows what has been typed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Show {
    /// The characters themselves, wrapped into at most `lines` rows and scrolled so the
    /// end -- where the typing is -- is always the part on screen.
    Text { lines: usize },
    /// One paw print per character, room kept for `max` of them.
    ///
    /// The same thing a row of stars said: how many, and nothing about which. Room for
    /// the longest the field can be, so the prints do not slide sideways as they go in.
    Marks { max: usize },
}

/// How a card is drawn on this board's panel.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Skin {
    /// A white card with black content: paper, on a colour panel with a grey page.
    Paper,
    /// An outlined box with the panel's own ink inside, for a two-colour OLED where a
    /// filled card would be a lamp.
    Outline,
}

/// What a field will take from the keyboard.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Accept {
    /// `0` to `9` and nothing else, for an index or a count.
    Digits,
    /// Any printable character, for a passphrase or a label.
    Text,
}

/// A buffer being typed into: what it will take, and how much.
///
/// The state a screen keeps between frames, so the screen itself is left with nothing
/// but "which key means what". Zeroized on [`clear`](Self::clear) and on drop, because
/// the two things typed into one of these are a passphrase and a derivation index.
pub struct Input<const N: usize> {
    text: heapless::String<N>,
    accept: Accept,
    max: usize,
}

impl<const N: usize> Input<N> {
    /// An empty field. `max` is clamped to the buffer, so a caller cannot promise more
    /// room than there is.
    pub fn new(accept: Accept, max: usize) -> Self {
        Self {
            text: heapless::String::new(),
            accept,
            max: max.min(N),
        }
    }

    /// Add a character. False if it is not one this field takes, or there is no room --
    /// in which case nothing changes and the caller can say so.
    pub fn put(&mut self, c: char) -> bool {
        let ok = match self.accept {
            Accept::Digits => c.is_ascii_digit(),
            // Printable ASCII only: the faces are ASCII, and a character that draws as
            // nothing is a character nobody can check they typed.
            Accept::Text => (' '..='~').contains(&c),
        };
        if !ok || self.text.chars().count() >= self.max {
            return false;
        }
        self.text.push(c).is_ok()
    }

    /// Remove the last character. False if there was none, which a caller usually reads
    /// as "leave this screen".
    pub fn backspace(&mut self) -> bool {
        self.text.pop().is_some()
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn len(&self) -> usize {
        self.text.chars().count()
    }

    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// The most characters this will take.
    pub fn max(&self) -> usize {
        self.max
    }

    /// Empty it, wiping what was there.
    pub fn clear(&mut self) {
        let mut bytes = core::mem::take(&mut self.text).into_bytes();
        bytes.zeroize();
        bytes.clear();
    }

    /// The digits as a number, if they are digits and they fit.
    ///
    /// `None` rather than a wrapped or saturated value: an index that silently became a
    /// different index is a different wallet, found only by the person who lost theirs.
    pub fn value(&self) -> Option<u32> {
        if self.accept != Accept::Digits || self.text.is_empty() {
            return None;
        }
        self.text.parse::<u32>().ok()
    }
}

impl<const N: usize> Drop for Input<N> {
    fn drop(&mut self) {
        self.clear();
    }
}

/// One row of a card.
pub struct Field<'a> {
    /// Drawn small at the left of the row; `""` for none, which centres the value.
    pub label: &'a str,
    /// What has been typed.
    pub text: &'a str,
    /// How to show it.
    pub show: Show,
    /// Whether the caret belongs in this row.
    pub active: bool,
    /// Centre the value instead of starting it at the left.
    pub centred: bool,
    /// The most characters a text row takes, which is what sizes it. `None` for a row
    /// that should have the whole width -- a passphrase is as long as its owner makes it.
    /// A marks row is sized by its own `max` and ignores this.
    pub max: Option<usize>,
    /// Lines shown in place of the content, one per line, centred -- with the row keeping
    /// the size its input gives it.
    ///
    /// For a row that is showing something *about* what was typed rather than the typing:
    /// the PIN prompt's prefix, once accepted, becomes its two anti-phishing words. The
    /// row stays the size of six paw prints, so the card does not change shape under the
    /// owner's hands at the moment they are meant to be reading it.
    pub placeholder: &'a [&'a str],
}

impl<'a> Field<'a> {
    /// A row showing text, on one line.
    pub fn text(label: &'a str, text: &'a str) -> Self {
        Self {
            label,
            text,
            show: Show::Text { lines: 1 },
            active: false,
            centred: false,
            max: None,
            placeholder: &[],
        }
    }

    /// A row showing one mark per character, with room for `max`.
    pub fn marks(text: &'a str, max: usize) -> Self {
        Self {
            label: "",
            text,
            show: Show::Marks { max },
            active: false,
            centred: true,
            max: None,
            placeholder: &[],
        }
    }

    /// The same row, live: the caret goes in it.
    pub fn live(mut self, yes: bool) -> Self {
        self.active = yes;
        self
    }

    /// Centred in the row rather than starting at the left.
    pub fn centred(mut self) -> Self {
        self.centred = true;
        self
    }

    /// Sized for at most `n` characters rather than the whole width.
    pub fn max(mut self, n: usize) -> Self {
        self.max = Some(n);
        self
    }

    /// Show these lines instead of the content, keeping the row's size.
    pub fn placeholder(mut self, lines: &'a [&'a str]) -> Self {
        self.placeholder = lines;
        self
    }

    /// Over `lines` lines rather than one.
    pub fn lines(mut self, lines: usize) -> Self {
        if let Show::Text { lines: n } = &mut self.show {
            *n = lines.max(1);
        }
        self
    }
}

/// How big the paw prints are on a canvas this tall.
///
/// One at the size the 128x64 panel drew them, three on the Q1's 240 rows: the prints are
/// pixel art, so they go up in whole multiples or they go ragged.
pub fn mark_scale(height: usize) -> usize {
    (height / 64).max(1)
}

/// How tall one row is.
fn row_height(l: &Layout<'_>, f: &Field<'_>, scale: usize) -> usize {
    match f.show {
        Show::Text { lines } => lines * l.body.line_height() + 2 * lead(l),
        Show::Marks { .. } => crate::icons::paw_trail_size(1, scale).1 + 2 * lead(l),
    }
}

/// How wide a row's content can get, or `None` if it should have the whole width.
fn natural_width(l: &Layout<'_>, f: &Field<'_>, scale: usize) -> Option<usize> {
    let label = if f.label.is_empty() {
        0
    } else {
        width_of(l.body, f.label) + LABEL_GAP
    };
    let content = match f.show {
        Show::Marks { max } => crate::icons::paw_trail_size(max, scale).0,
        // The widest glyph, so a field of `n` of anything fits in it, with room for the
        // caret after the last.
        Show::Text { .. } => f.max? * l.body.advance(b'W') + 2,
    };
    // A placeholder has to fit too: the words are longer than six prints in some cases.
    let shown = f
        .placeholder
        .iter()
        .map(|line| width_of(l.title, line))
        .max()
        .unwrap_or(0);
    Some(label + content.max(shown))
}

/// Total height of the card these rows make.
pub fn height(c_height: usize, l: &Layout<'_>, fields: &[Field<'_>]) -> usize {
    let scale = mark_scale(c_height);
    fields.iter().map(|f| row_height(l, f, scale)).sum()
}

/// Draw the card at `y`, returning the first row below it.
///
/// The rows share their edges: one box with a line between each pair, because they are
/// parts of one answer and not a list of questions.
pub fn stack<C: Canvas + ?Sized>(
    c: &mut C,
    l: &Layout<'_>,
    y: usize,
    fields: &[Field<'_>],
    skin: Skin,
    caret: bool,
) -> usize {
    if fields.is_empty() {
        return y;
    }
    let scale = mark_scale(c.height());
    let pad = 2 * l.margin;
    // As wide as the widest row needs for the most it can hold, and no wider: a six-digit
    // field that spans the panel says "type a lot here". A row with no maximum takes the
    // whole width. Sized by capacity, never by what is in it now, so the card keeps its
    // shape as it fills -- and as a placeholder replaces the content, which keeps the
    // row's own size.
    let full = c.width().saturating_sub(2 * pad);
    let w = fields
        .iter()
        .map(|f| natural_width(l, f, scale).map_or(full, |n| n + 2 * pad))
        .max()
        .unwrap_or(full)
        .min(full);
    let x = c.width().saturating_sub(w) / 2;
    let total: usize = fields.iter().map(|f| row_height(l, f, scale)).sum();

    // The card, then the content on top of it.
    match skin {
        Skin::Paper => c.fill_rect(x, y, w, total, INK),
        Skin::Outline => {
            c.fill_rect(x, y, w, 1, INK);
            c.fill_rect(x, y + total.saturating_sub(1), w, 1, INK);
            c.fill_rect(x, y, 1, total, INK);
            c.fill_rect(x + w.saturating_sub(1), y, 1, total, INK);
        }
    }
    let ink = match skin {
        Skin::Paper => MARK,
        Skin::Outline => INK,
    };

    let mut row_y = y;
    for (i, f) in fields.iter().enumerate() {
        let h = row_height(l, f, scale);
        if i > 0 {
            c.fill_rect(x, row_y, w, 1, ink);
        }
        let mut left = x + pad;
        if !f.label.is_empty() {
            let ly = row_y + h.saturating_sub(l.body.line_height()) / 2;
            draw_text_in(c, l.body, left, ly, f.label, ink);
            left += width_of(l.body, f.label) + LABEL_GAP;
        }
        let right = x + w.saturating_sub(pad);
        let live = caret && f.active;
        if !f.placeholder.is_empty() {
            row_placeholder(c, l, f.placeholder, left, right, row_y, h, ink);
            row_y += h;
            continue;
        }
        match f.show {
            Show::Text { lines } => row_text(c, l, f, left, right, row_y, h, lines, ink, live),
            Show::Marks { max } => {
                row_marks(c, f.text, left, right, row_y, h, max, scale, ink, live)
            }
        }
        row_y += h;
    }
    y + total
}

/// The characters, wrapped, with the end of the text always on screen.
#[allow(clippy::too_many_arguments)]
fn row_text<C: Canvas + ?Sized>(
    c: &mut C,
    l: &Layout<'_>,
    f: &Field<'_>,
    left: usize,
    right: usize,
    y: usize,
    h: usize,
    lines: usize,
    ink: Level,
    caret: bool,
) {
    let text = f.text;
    let avail = right.saturating_sub(left);
    // Break on width, not on words: a passphrase has no words, and a wrap that hunted for
    // a space would move half of one onto the next line as it was being typed.
    let mut starts: heapless::Vec<usize, 16> = heapless::Vec::new();
    let _ = starts.push(0);
    let mut used = 0;
    for (i, b) in text.bytes().enumerate() {
        let adv = l.body.advance(b);
        if used + adv > avail && i > 0 {
            if starts.push(i).is_err() {
                // More lines than the buffer holds: keep the last ones, which is what
                // the reader is looking at anyway.
                starts.remove(0);
                let _ = starts.push(i);
            }
            used = 0;
        }
        used += adv;
    }
    // The tail: the last `lines` of them, so what was just typed is always visible.
    let first = starts.len().saturating_sub(lines);
    let shown = &starts[first..];
    let top = y + h.saturating_sub(shown.len() * l.body.line_height()) / 2;
    let mut end_x = left;
    for (n, &s) in shown.iter().enumerate() {
        let e = shown.get(n + 1).copied().unwrap_or(text.len());
        let ly = top + n * l.body.line_height();
        let line = &text[s..e];
        let lx = if f.centred {
            left + avail.saturating_sub(width_of(l.body, line)) / 2
        } else {
            left
        };
        end_x = draw_text_in(c, l.body, lx, ly, line, ink);
        if n + 1 == shown.len() && caret {
            let cy = ly;
            c.fill_rect(
                end_x.min(right.saturating_sub(CARET_W)),
                cy,
                CARET_W,
                l.body.line_height(),
                ink,
            );
        }
    }
    // An empty field still says where the next character goes.
    if text.is_empty() && caret {
        let lx = if f.centred { left + avail / 2 } else { left };
        c.fill_rect(lx, top, CARET_W, l.body.line_height(), ink);
    }
    let _ = end_x;
}

/// Placeholder lines, each centred, the block centred in the row.
///
/// In the title face: these are what the owner is meant to *read* -- the anti-phishing
/// words -- and the row they sit in is sized for paw prints, which is room enough.
#[allow(clippy::too_many_arguments)]
fn row_placeholder<C: Canvas + ?Sized>(
    c: &mut C,
    l: &Layout<'_>,
    lines: &[&str],
    left: usize,
    right: usize,
    y: usize,
    h: usize,
    ink: Level,
) {
    let face = l.title;
    let lh = face.line_height();
    let span = right.saturating_sub(left);
    let top = y + h.saturating_sub(lines.len() * lh) / 2;
    for (n, line) in lines.iter().enumerate() {
        let lx = left + span.saturating_sub(width_of(face, line)) / 2;
        draw_text_in(c, face, lx, top + n * lh, line, ink);
    }
}

/// One print per character, and the caret where the next one will land.
#[allow(clippy::too_many_arguments)]
fn row_marks<C: Canvas + ?Sized>(
    c: &mut C,
    text: &str,
    left: usize,
    right: usize,
    y: usize,
    h: usize,
    max: usize,
    scale: usize,
    ink: Level,
    caret: bool,
) {
    let (trail_w, trail_h) = crate::icons::paw_trail_size(max, scale);
    let step = crate::icons::paw_trail_size(2, scale)
        .0
        .saturating_sub(crate::icons::paw_trail_size(1, scale).0);
    // Centred in whatever the label left, so a labelled row of marks still reads as one.
    let span = right.saturating_sub(left);
    let x = left + span.saturating_sub(trail_w) / 2;
    let top = y + h.saturating_sub(trail_h) / 2;
    let n = text.chars().count().min(max);
    crate::icons::draw_paw_trail_in(c, n, x, top, scale, ink);
    if caret && n < max {
        c.fill_rect(x + n * step, top, CARET_W, trail_h, ink);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Mono128x64;
    use crate::canvas::{Gray320x240, PAPER};

    fn roomy() -> Layout<'static> {
        Layout::roomy()
    }

    fn ink_count<C: Canvas>(c: &C, level: Level) -> usize {
        let (w, h) = (c.width(), c.height());
        (0..h)
            .flat_map(|y| (0..w).map(move |x| (x, y)))
            .filter(|&(x, y)| c.get(x, y) == level)
            .count()
    }

    /// The card is one box: two rows of marks share the line between them rather than
    /// each having an edge of its own.
    #[test]
    fn rows_share_their_edge() {
        let mut c = Gray320x240::new();
        c.clear();
        let fields = [Field::marks("", 6).live(true), Field::marks("", 6)];
        let below = stack(&mut c, &roomy(), 40, &fields, Skin::Paper, true);
        let h = height(c.height(), &roomy(), &fields);
        assert_eq!(below, 40 + h);
        // White where the card is, page colour above it.
        assert!(c.get(c.width() / 2, 40 + h / 4) == INK);
        assert!(c.get(c.width() / 2, 39) == PAPER);
    }

    /// A mark per character, and one more with each one typed.
    #[test]
    fn each_character_adds_a_print() {
        let mut before = Gray320x240::new();
        before.clear();
        let mut after = Gray320x240::new();
        after.clear();
        stack(
            &mut before,
            &roomy(),
            40,
            &[Field::marks("12", 6)],
            Skin::Paper,
            false,
        );
        stack(
            &mut after,
            &roomy(),
            40,
            &[Field::marks("123", 6)],
            Skin::Paper,
            false,
        );
        let (a, b) = (ink_count(&before, MARK), ink_count(&after, MARK));
        assert!(b > a, "a third print adds ink: {a} then {b}");
    }

    /// The caret is drawn only in the live row, and only when the caller says so.
    #[test]
    fn the_caret_belongs_to_one_row_and_to_the_blink() {
        let draw = |caret: bool, live: usize| {
            let mut c = Gray320x240::new();
            c.clear();
            let fields = [
                Field::text("words", "24").live(live == 0),
                Field::text("index", "1981").live(live == 1),
            ];
            stack(&mut c, &roomy(), 40, &fields, Skin::Paper, caret);
            ink_count(&c, MARK)
        };
        let dark = draw(false, 0);
        assert!(draw(true, 0) > dark, "the caret is ink");
        // Both live rows draw the same amount of ink: same text, caret moved.
        assert_eq!(draw(true, 0), draw(true, 1));
    }

    /// An empty field still shows where the next character goes.
    #[test]
    fn an_empty_field_has_a_caret() {
        let mut c = Gray320x240::new();
        c.clear();
        stack(
            &mut c,
            &roomy(),
            40,
            &[Field::text("index", "").live(true)],
            Skin::Paper,
            true,
        );
        assert!(ink_count(&c, MARK) > 0);
    }

    /// Long text keeps its *end* on screen: that is where the typing is.
    #[test]
    fn a_long_line_shows_its_tail() {
        let mut c = Gray320x240::new();
        c.clear();
        let long = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz";
        let one = [Field::text("", long)];
        stack(&mut c, &roomy(), 40, &one, Skin::Paper, false);
        let single = ink_count(&c, MARK);
        let mut c3 = Gray320x240::new();
        c3.clear();
        let three = [Field::text("", long).lines(3)];
        stack(&mut c3, &roomy(), 40, &three, Skin::Paper, false);
        // Three lines show more of the same text than one does.
        assert!(ink_count(&c3, MARK) > single);
        // And a taller row is taller.
        assert!(height(240, &roomy(), &three) > height(240, &roomy(), &one));
    }

    /// The mono panel gets an outline, not a lamp: the inside stays the page.
    #[test]
    fn the_outline_skin_does_not_fill() {
        let mut c = Mono128x64::new();
        c.clear();
        let fields = [Field::marks("12", 6).live(true)];
        stack(&mut c, &Layout::compact(), 10, &fields, Skin::Outline, true);
        let h = height(c.height(), &Layout::compact(), &fields);
        // The middle of the card is not painted over; the frame is there.
        assert!(!c.get(c.width() / 2, 10 + h / 2 - 1), "inside stays dark");
        assert!(c.get(c.width() / 2, 10), "the top edge is drawn");
    }

    /// A six-digit field is as wide as six prints, not as wide as the panel; a row with
    /// no maximum still takes the whole width.
    #[test]
    fn a_field_is_as_wide_as_what_it_can_hold() {
        let l = roomy();
        let mut pin = Gray320x240::new();
        pin.clear();
        stack(&mut pin, &l, 40, &[Field::marks("", 6)], Skin::Paper, false);
        let mut wide = Gray320x240::new();
        wide.clear();
        stack(
            &mut wide,
            &l,
            40,
            &[Field::text("", "")],
            Skin::Paper,
            false,
        );
        // Just inside the full-width card's edge: card there, page for the PIN field.
        let edge = 2 * l.margin + 4;
        assert_eq!(wide.get(edge, 44), INK, "the unbounded row is full width");
        assert_eq!(pin.get(edge, 44), PAPER, "six prints do not need the panel");
        // But the PIN field still holds its six prints.
        assert_eq!(pin.get(pin.width() / 2, 44), INK);

        // A text row with a maximum is sized by it too.
        let mut index = Gray320x240::new();
        index.clear();
        stack(
            &mut index,
            &l,
            40,
            &[Field::text("index", "").max(10)],
            Skin::Paper,
            false,
        );
        assert_eq!(index.get(edge, 44), PAPER);
    }

    /// Swapping the prints for two words keeps the row exactly the size it was: the card
    /// does not move under the owner at the moment they are meant to be reading it.
    #[test]
    fn a_placeholder_keeps_the_rows_size() {
        let l = roomy();
        let words: &[&str] = &["abandon", "ability"];
        let prints = [Field::marks("123", 6), Field::marks("", 6).live(true)];
        let shown = [
            Field::marks("", 6).placeholder(words),
            Field::marks("", 6).live(true),
        ];
        assert_eq!(height(240, &l, &prints), height(240, &l, &shown));

        let mut a = Gray320x240::new();
        a.clear();
        let mut b = Gray320x240::new();
        b.clear();
        let below_a = stack(&mut a, &l, 40, &prints, Skin::Paper, false);
        let below_b = stack(&mut b, &l, 40, &shown, Skin::Paper, false);
        assert_eq!(below_a, below_b, "same height");
        // Same width: the card's left edge is in the same column.
        let row = 44;
        let edge = |c: &Gray320x240| (0..c.width()).find(|&x| c.get(x, row) == INK);
        assert_eq!(edge(&a), edge(&b), "same width");
        // And the words are drawn.
        assert!(ink_count(&b, MARK) > 0);
    }

    /// A digits field takes digits and nothing else -- which is what makes it safe to
    /// read back with `value`.
    #[test]
    fn a_digits_field_refuses_everything_else() {
        let mut i = Input::<8>::new(Accept::Digits, 8);
        assert!(i.put('1'));
        assert!(!i.put('a'));
        assert!(!i.put(' '));
        assert!(i.put('9'));
        assert_eq!(i.as_str(), "19");
        assert_eq!(i.value(), Some(19));
    }

    /// An index that overflowed into a different index would be a different wallet, so
    /// there is no number rather than the wrong one.
    #[test]
    fn a_number_too_big_for_the_path_has_no_value() {
        let mut i = Input::<12>::new(Accept::Digits, 12);
        for c in "99999999999".chars() {
            assert!(i.put(c));
        }
        assert_eq!(i.value(), None);
        let mut ok = Input::<12>::new(Accept::Digits, 12);
        for c in "19800101".chars() {
            assert!(ok.put(c));
        }
        assert_eq!(ok.value(), Some(19_800_101));
    }

    /// Full is full: the press does nothing rather than dropping a character somewhere.
    #[test]
    fn a_full_field_takes_no_more() {
        let mut i = Input::<8>::new(Accept::Text, 3);
        assert!(i.put('a'));
        assert!(i.put('b'));
        assert!(i.put('c'));
        assert!(!i.put('d'));
        assert_eq!(i.as_str(), "abc");
        assert!(i.backspace());
        assert!(i.put('d'));
        assert_eq!(i.as_str(), "abd");
    }

    /// Backspace on an empty field says so, which is how a screen knows to leave.
    #[test]
    fn backspace_on_an_empty_field_reports_it() {
        let mut i = Input::<8>::new(Accept::Text, 8);
        assert!(!i.backspace());
        assert!(i.put('x'));
        assert!(i.backspace());
        assert!(!i.backspace());
    }

    /// A text field takes what the faces can draw, and nothing they cannot.
    #[test]
    fn a_text_field_takes_printable_ascii() {
        let mut i = Input::<16>::new(Accept::Text, 16);
        assert!(i.put(' '));
        assert!(i.put('~'));
        assert!(i.put('A'));
        assert!(!i.put('\n'));
        assert!(!i.put('é'));
        assert_eq!(i.as_str(), " ~A");
        assert_eq!(i.value(), None);
    }

    /// Prints scale with the panel: one on the OLED, three on the Q1.
    #[test]
    fn prints_are_sized_for_the_panel() {
        assert_eq!(mark_scale(64), 1);
        assert_eq!(mark_scale(240), 3);
        assert_eq!(mark_scale(224), 3);
    }
}
