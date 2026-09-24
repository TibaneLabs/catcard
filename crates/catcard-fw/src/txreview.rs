//! Laying a transaction out so somebody can decide about it.
//!
//! **Chain-neutral on purpose.** What a person needs from a Solana transaction and from
//! an EVM one is the same thing in the same shape, so the screen lives here and each
//! chain only says what its rows contain. A chain added later gets the screen for free,
//! and -- just as important -- gets the *same* screen, so nobody has to learn two.
//!
//! # A list you can open, not a page you have to read
//!
//! The first version of this put everything on one scroll: every address, every label,
//! every detail, in the order they occurred. On a 320-pixel panel a 44-character address
//! does not fit, so it ran off the side, and the whole thing read as a paragraph nobody
//! would read to the end -- which on a signing device means nobody reads it at all.
//!
//! So: **one row per element**, each row short enough to fit, and the detail one keypress
//! away.
//!
//! ```text
//!   Solana transaction
//!   Fee                    0.000005 SOL
//!   Nonce            BKnzsP…KaZyQE7
//!   Send 0.1 SOL      to 3k9z7k…vQRFEWk
//!   Sign it
//! ```
//!
//! Opening `Send 0.1 SOL` gives its own screen, with the addresses in full and in blocks
//! of four -- which is where a person compares them against something else, and the only
//! place an address is worth the room it takes.
//!
//! # Two things are marked, and nothing else is
//!
//! A mark on every row is decoration, and decoration is what the eye learns to skip. Two
//! earn one:
//!
//! - **Yours.** The rows that touch a key this device holds. "Is this my account?" is the
//!   question underneath every other question, and it is one the device can answer and a
//!   person cannot -- an address is 44 characters they would have to compare by eye.
//! - **Unreadable.** A part this build could not decode, in red, with a whole red screen
//!   in front of the list saying how many there are. A transaction that calls a program
//!   this build has no reader for is normal on Solana, so refusing to sign those would
//!   make the device useless and saying nothing would make it dangerous.
//!
//! # A total that is short of something says so
//!
//! "Signing this will:" is the number somebody reads instead of the rows. It is added up
//! from the parts that were decoded, so a part that was not -- or one whose amount is not
//! written in the bytes, like the rent a closed account returns -- leaves it short. The
//! summary then ends with a line saying so, because a total that is silently partial
//! reads as a whole one, and that is worse than no total.

use catcard_ui::art::txicons::Kind;
use catcard_ui::scroll::Line;
use core::fmt::Write as _;

use crate::menu;
use crate::ui::Ui;

/// How long one row of a review can be.
///
/// A summary row is meant to fit the panel; a field's value may be an address, which is
/// 44 characters plus the spaces that group it.
const LINE: usize = 64;
/// How long a field's label can be: `authority`, `to`, `token`.
const LABEL: usize = 16;

/// The most rows a review can run to.
///
/// A ceiling, not a budget: what does not fit is counted, and a review that did not fit
/// does not offer to sign.
const MAX_ROWS: usize = 256;

/// How many assets a summary can name.
///
/// A transaction that moves more kinds of thing than this is one whose summary would not
/// fit a screen anyway; what does not fit is said, rather than dropped quietly.
const EFFECTS: usize = 6;

/// Where the action rows' ids start, clear of the elements'.
const ACTION: u32 = 1_000;

/// What a row is.
#[derive(Copy, Clone, PartialEq, Eq)]
enum Role {
    /// Opens an element: one line on the list, and the title of its own screen.
    Element { kind: Option<Kind>, mine: bool },
    /// A labelled field, shown when the element is opened.
    Field,
    /// A line of explanation inside an element.
    Note,
}

struct Row {
    label: heapless::String<LABEL>,
    text: heapless::String<LINE>,
    role: Role,
}

/// A transaction, in the rows a screen shows.
pub(crate) struct Review {
    /// What signing changes, per asset. Shown at the top, before anything has to be
    /// opened -- it is the answer to the question somebody actually has.
    effects: heapless::Vec<heapless::String<LINE>, EFFECTS>,
    /// Set when there were more assets than there is room for, so a total that is not
    /// the whole total never reads as one.
    effects_lost: bool,
    rows: alloc::vec::Vec<Row>,
    /// Rows that did not fit. Stops the screen offering to sign, for the reason the
    /// module header gives: nothing is signed that was not shown.
    dropped: usize,
    /// Parts that could not be read.
    alarms: usize,
    /// Parts that move an amount the bytes do not give, so the total is short of it.
    unwritten: usize,
}

impl Review {
    /// Room for a review, or `None` if the heap has nothing to spare.
    pub(crate) fn new() -> Option<Self> {
        let mut rows = alloc::vec::Vec::new();
        rows.try_reserve_exact(MAX_ROWS).ok()?;
        Some(Review {
            effects: heapless::Vec::new(),
            effects_lost: false,
            rows,
            dropped: 0,
            alarms: 0,
            unwritten: 0,
        })
    }

    /// Whether the summary at the top is short of something: a part it could not read,
    /// or an amount the bytes do not carry.
    fn incomplete(&self) -> bool {
        self.alarms > 0 || self.unwritten > 0
    }

    fn push(&mut self, role: Role, label: &str, args: core::fmt::Arguments<'_>) {
        if self.rows.len() == self.rows.capacity() {
            self.dropped += 1;
            return;
        }
        let mut text: heapless::String<LINE> = heapless::String::new();
        // A line too long for the buffer would be truncated by `write_fmt`, which on a
        // row holding an address means showing most of a key. Counted as dropped, so the
        // screen refuses rather than showing three quarters of somebody's address.
        if text.write_fmt(format_args!("{args}")).is_err() {
            self.dropped += 1;
            return;
        }
        let mut l: heapless::String<LABEL> = heapless::String::new();
        let _ = l.push_str(&label[..label.len().min(LABEL)]);
        self.rows.push(Row {
            label: l,
            text,
            role,
        });
    }

    /// Open an element: the one line that says what this part of the transaction does.
    ///
    /// `mine` marks a part that touches a key this device holds.
    pub(crate) fn element(&mut self, mine: bool, args: core::fmt::Arguments<'_>) {
        let kind = mine.then_some(Kind::Payer);
        self.push(Role::Element { kind, mine }, "", args);
    }

    /// Open an element for something this device could not read.
    pub(crate) fn cannot_read(&mut self, args: core::fmt::Arguments<'_>) {
        self.alarms += 1;
        self.push(
            Role::Element {
                kind: Some(Kind::Warning),
                mine: false,
            },
            "",
            args,
        );
    }

    /// Say that the element above moves an amount these bytes do not give.
    ///
    /// Closing a token account returns its rent to somebody, and how much is in the
    /// account's balance on-chain rather than in the instruction. The row is ordinary;
    /// what this changes is the summary, which is now short of a number it cannot
    /// know, and says so.
    pub(crate) fn unwritten(&mut self) {
        self.unwritten += 1;
    }

    /// A labelled field of the element above: shown when it is opened.
    pub(crate) fn field(&mut self, label: &str, args: core::fmt::Arguments<'_>) {
        self.push(Role::Field, label, args);
    }

    /// An address field, grouped in fours so it can be compared character by character.
    pub(crate) fn address(&mut self, label: &str, address: &str) {
        let mut grouped: heapless::String<LINE> = heapless::String::new();
        for (i, c) in address.chars().enumerate() {
            if i > 0 && i % 4 == 0 {
                let _ = grouped.push(' ');
            }
            let _ = grouped.push(c);
        }
        self.push(Role::Field, label, format_args!("{grouped}"));
    }

    /// One line of what signing changes: an asset and how much of it moves.
    ///
    /// Written by the chain, because only the chain can add up its own amounts -- what
    /// counts as "the same asset" is a mint on Solana and a contract on an EVM chain.
    /// What this side guarantees is where it appears: at the top, before anything has to
    /// be opened.
    pub(crate) fn effect(&mut self, args: core::fmt::Arguments<'_>) {
        let mut text: heapless::String<LINE> = heapless::String::new();
        if text.write_fmt(args).is_err() || self.effects.push(text).is_err() {
            self.effects_lost = true;
        }
    }

    /// A line of explanation inside the element above.
    pub(crate) fn note(&mut self, args: core::fmt::Arguments<'_>) {
        self.push(Role::Note, "", args);
    }

    /// Whether the whole of it can be shown, and so whether anything may be signed.
    pub(crate) fn complete(&self) -> bool {
        self.dropped == 0
    }

    /// Show the list, and say which action was chosen.
    ///
    /// Opening an element is handled here rather than by the caller: it is navigation
    /// inside one screen, and a caller that had to loop for it would be a caller that
    /// could forget to. `None` means the owner backed out.
    ///
    /// The actions are rows like any other, which is why the screen after signing uses
    /// this too: what somebody wants then -- see it again, hand it to a phone, sign with
    /// another account -- is the same list with different rows at the bottom.
    pub(crate) fn show(&self, ui: &mut Ui<'_>, title: &str, actions: &[&str]) -> Option<usize> {
        // The red screen first. Before the list, because somebody scrolling a list is
        // reading it, and this has to interrupt rather than wait its turn.
        if self.alarms > 0 {
            let mut said: heapless::String<48> = heapless::String::new();
            let _ = if self.alarms == 1 {
                write!(said, "one part cannot be read")
            } else {
                write!(said, "{} parts cannot be read", self.alarms)
            };
            menu::alarm(ui.panel, title, &said, "they are marked in red");
            menu::wait_for_any_key(ui);
        }

        loop {
            match self.list(ui, title, actions)? {
                id if id >= ACTION => return Some((id - ACTION) as usize),
                element => self.detail(ui, element as usize),
            }
        }
    }

    /// The list itself: every element, then the actions.
    fn list(&self, ui: &mut Ui<'_>, title: &str, actions: &[&str]) -> Option<u32> {
        let mut lines: alloc::vec::Vec<Line<'_>> = alloc::vec::Vec::new();
        if lines
            .try_reserve_exact(self.rows.len() + actions.len() + self.effects.len() + 6)
            .is_err()
        {
            menu::message(ui.panel, title, "not enough memory", "any key to go back");
            menu::wait_for_any_key(ui);
            return None;
        }
        lines.push(Line::title(title));
        // What it comes to, first. Everything below is how it got there. A summary that
        // is short of something ends by saying so -- and is shown even when it has no
        // number in it at all, since "whatever the unread parts do" is then the whole
        // answer to what signing will do.
        if !self.effects.is_empty() || self.incomplete() {
            lines.push(Line::body("Signing this will:").small());
            for effect in &self.effects {
                lines.push(Line::body(effect).large());
            }
        }
        if self.effects_lost {
            lines.push(Line::body("and more than fits here").small());
        }
        if self.incomplete() {
            let joined = !self.effects.is_empty() || self.effects_lost;
            let said = match (self.alarms > 0, joined) {
                (true, true) => "and whatever the unread parts do",
                (true, false) => "whatever the unread parts do",
                (false, true) => "and amounts these bytes do not give",
                (false, false) => "move amounts these bytes do not give",
            };
            lines.push(Line::body(said).small());
        }
        for (i, row) in self.rows.iter().enumerate() {
            let Role::Element { kind, .. } = row.role else {
                continue;
            };
            let mut line = Line::item(&row.text, i as u32);
            if let Some(kind) = kind {
                line = line.with_mark(catcard_ui::art::txicons::mark(kind));
            }
            lines.push(line);
        }

        let mut complaint: heapless::String<LINE> = heapless::String::new();
        if self.complete() {
            for (i, label) in actions.iter().enumerate() {
                lines.push(Line::item(label, ACTION + i as u32));
            }
        } else {
            let _ = write!(complaint, "{} rows than fit here", self.dropped);
            lines.push(Line::body("nothing is offered:").small());
            lines.push(Line::body(&complaint).small());
        }

        // No cursor wrap: the action rows are last, and up from the top must not land on
        // "Sign it" before the list has been read.
        match menu::show_doc_nowrap(ui, &lines) {
            menu::DocExit::Selected(id) => Some(id),
            _ => None,
        }
    }

    /// One element on its own screen: its summary as the title, then its fields.
    ///
    /// This is where an address is worth its room. On the list it is shortened to fit a
    /// line; here it is whole, in blocks of four, wrapped rather than cut -- which is the
    /// form somebody can hold next to a phone and compare.
    fn detail(&self, ui: &mut Ui<'_>, at: usize) {
        let Some(head) = self.rows.get(at) else {
            return;
        };
        let mut lines: alloc::vec::Vec<Line<'_>> = alloc::vec::Vec::new();
        let rest = &self.rows[at + 1..];
        let body = rest
            .iter()
            .take_while(|r| !matches!(r.role, Role::Element { .. }));
        if lines.try_reserve_exact(rest.len() * 2 + 4).is_err() {
            return;
        }
        lines.push(Line::title(&head.text));
        if matches!(head.role, Role::Element { mine: true, .. }) {
            lines.push(Line::body("an account this device holds").small());
        }
        for row in body {
            match row.role {
                Role::Field => {
                    if !row.label.is_empty() {
                        lines.push(Line::body(&row.label).small());
                    }
                    lines.push(Line::body(&row.text).wrapped());
                }
                _ => lines.push(Line::body(&row.text).small()),
            }
        }
        let _ = menu::show_doc(ui, &lines, false, false);
    }
}

/// An address as a row shows it: the ends, which is what a person checks anyway.
///
/// The middle of a base58 address is what nobody compares -- the eye goes to the first
/// characters and the last -- and a row that showed all 44 would not fit the panel, which
/// is how the first version of this screen ran off the side.
pub(crate) fn short<'o>(address: &str, out: &'o mut heapless::String<LINE>) -> &'o str {
    const ENDS: usize = 6;
    out.clear();
    if address.len() <= ENDS * 2 + 1 {
        let _ = out.push_str(address);
    } else {
        let _ = out.push_str(&address[..ENDS]);
        let _ = out.push_str("..");
        let _ = out.push_str(&address[address.len() - ENDS..]);
    }
    out.as_str()
}
