//! The screens' plumbing: one frame, one layout, input, and the UART for a log line per
//! screen. Every helper draws with catcard-ui's widgets and waits for keys itself, feeding
//! the watchdog while it does.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use catcard_ui::keypad::Key;
use catcard_ui::memlcd::{self, MemLcd};
use catcard_ui::menu::Scroll;
use catcard_ui::widgets::{self, Layout};

use crate::input::Input;
use crate::uart::Uart;

/// Keys as the screens read them (the Q1 convention, see catcard_ui::precursorkeys).
pub const UP: Key = Key::Digit(5);
pub const DOWN: Key = Key::Digit(8);

pub struct Ui {
    pub out: Uart,
    pub layout: Layout<'static>,
    pub frame: MemLcd,
    pub input: Input,
}

impl Ui {
    pub fn new(out: Uart) -> Self {
        Self {
            out,
            layout: Layout::large(),
            frame: MemLcd::new(),
            input: Input::new(),
        }
    }

    /// Pushes the frame to the panel; logs which screen it was.
    pub fn show(&mut self, what: &str) {
        match crate::lcd::show(&self.frame) {
            Ok(_) => {
                let _ = writeln!(self.out, "screen: {what}");
            }
            Err(e) => {
                let _ = writeln!(self.out, "lcd: {what}: {e}");
            }
        }
    }

    pub fn rows(&self) -> usize {
        self.layout.rows(memlcd::HEIGHT)
    }

    /// A list to pick from. `Some(index)` on confirm, `None` on cancel.
    pub fn menu(&mut self, title: &str, note: &str, items: &[&str]) -> Option<usize> {
        let mut sc = Scroll::default();
        loop {
            widgets::menu(&mut self.frame, &self.layout, title, note, items, sc);
            self.show(title);
            match self.input.press() {
                UP => sc = sc.step(items.len(), self.rows(), false),
                DOWN => sc = sc.step(items.len(), self.rows(), true),
                Key::Confirm if !items.is_empty() => return Some(sc.cursor),
                Key::Cancel => return None,
                _ => {}
            }
        }
    }

    /// A heading and two lines; returns as soon as it is drawn.
    pub fn notice(&mut self, head: &str, a: &str, b: &str) {
        widgets::message(&mut self.frame, &self.layout, head, a, b);
        self.show(head);
    }

    /// A heading and two lines, until confirm (`true`) or cancel (`false`).
    pub fn ask(&mut self, head: &str, a: &str, b: &str) -> bool {
        self.notice(head, a, b);
        loop {
            match self.input.press() {
                Key::Confirm => return true,
                Key::Cancel => return false,
                _ => {}
            }
        }
    }

    /// Lines a page at a time; up/down turn pages. `true` on confirm, `false` on cancel.
    pub fn pages<S: AsRef<str>>(&mut self, title: &str, lines: &[S]) -> bool {
        let per = self.rows().max(1);
        let count = lines.len().div_ceil(per).max(1);
        let mut page = 0;
        loop {
            let start = page * per;
            let shown = &lines[start.min(lines.len())..(start + per).min(lines.len())];
            let mut head = String::new();
            if count > 1 {
                let _ = write!(head, "{title} {}/{count}", page + 1);
            } else {
                head.push_str(title);
            }
            widgets::info(&mut self.frame, &self.layout, &head, shown);
            self.show(title);
            match self.input.press() {
                UP if page > 0 => page -= 1,
                DOWN if page + 1 < count => page += 1,
                Key::Confirm => return true,
                Key::Cancel => return false,
                _ => {}
            }
        }
    }

    /// `text` as a QR code with the text wrapped under it, until any key.
    ///
    /// Drawn here rather than with `widgets::qr_with_text`, for two reasons particular to
    /// this panel: that widget sets the code beside its text, which suits a landscape
    /// screen and leaves a portrait one with a postage stamp; and it draws the background
    /// in ink and the modules in paper, right for an OLED (ink is light) but an inverted
    /// code on a reflective LCD (ink is black). Here: dark modules on a light quiet zone of
    /// four modules, as ISO/IEC 18004 has it, the code as large as fits above the text.
    pub fn qr(&mut self, what: &str, text: &str) {
        use anyd::codes::qr::{EcLevel, QrEncoder};
        use catcard_ui::canvas::{Canvas as _, INK};
        let mut scratch = [0u8; QrEncoder::MAX_BUFFER_LEN];
        let mut storage = [0u8; QrEncoder::MAX_BUFFER_LEN];
        let encoder = QrEncoder::new();
        let Ok((grid, _)) =
            encoder.encode_text_into(text.as_bytes(), EcLevel::M, &mut scratch, &mut storage)
        else {
            self.notice(what, "could not encode", "the QR code");
            self.input.press();
            return;
        };

        let face = self.layout.body;
        let margin = self.layout.margin;
        let cols = ((memlcd::WIDTH - 2 * margin) / face.advance(b'0').max(1)).max(1);
        let lines: Vec<&str> = text
            .as_bytes()
            .chunks(cols)
            .map(|c| core::str::from_utf8(c).unwrap_or(""))
            .collect();
        let text_h = lines.len() * self.layout.pitch();

        self.frame.clear();
        let modules = grid.width();
        let room = memlcd::HEIGHT
            .saturating_sub(text_h + 2 * self.layout.gap)
            .min(memlcd::WIDTH);
        let scale = room / (modules + 8);
        if scale == 0 {
            self.notice(what, "too long for", "one QR code");
            self.input.press();
            return;
        }
        let side = (modules + 8) * scale;
        let (x0, y0) = ((memlcd::WIDTH - side) / 2, 0);
        for my in 0..modules {
            for mx in 0..modules {
                if grid.get(mx, my) {
                    self.frame.fill_rect(
                        x0 + (4 + mx) * scale,
                        y0 + (4 + my) * scale,
                        scale,
                        scale,
                        INK,
                    );
                }
            }
        }
        let mut y = side + self.layout.gap;
        for line in lines {
            catcard_ui::text::draw_text(&mut self.frame, face, margin, y, line);
            y += self.layout.pitch();
        }
        self.show(what);
        self.input.press();
    }

    /// Picks one string out of many, typing a prefix to narrow them: the BIP-39 word entry.
    /// Letters type, backspace deletes (or, on an empty prefix, returns `Err(())` so the
    /// caller can step back), up/down move, confirm takes the word under the cursor.
    pub fn pick_word(&mut self, title: &str) -> Result<&'static str, ()> {
        let mut prefix = String::new();
        let mut sc = Scroll::default();
        loop {
            let found: Vec<&'static str> = if prefix.is_empty() {
                Vec::new()
            } else {
                catcard_wallet::bip39::wordlist::all()
                    .filter(|w| w.starts_with(prefix.as_str()))
                    .collect()
            };
            let mut note = String::new();
            let _ = write!(note, "> {prefix}_");
            widgets::menu(&mut self.frame, &self.layout, title, &note, &found, sc);
            self.show(title);
            match self.input.press() {
                Key::Char(c @ b'a'..=b'z') if prefix.len() < 8 => {
                    prefix.push(c as char);
                    sc = Scroll::default();
                }
                Key::Cancel if prefix.is_empty() => return Err(()),
                Key::Cancel => {
                    prefix.pop();
                    sc = Scroll::default();
                }
                UP => sc = sc.step(found.len(), self.rows(), false),
                DOWN => sc = sc.step(found.len(), self.rows(), true),
                Key::Confirm if !found.is_empty() => return Ok(found[sc.cursor]),
                _ => {}
            }
        }
    }
}
