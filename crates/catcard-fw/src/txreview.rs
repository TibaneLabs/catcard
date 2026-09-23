//! Laying a transaction out so somebody can decide about it.
//!
//! **Chain-neutral on purpose.** What a person needs from a Solana transaction and from
//! an EVM one is the same thing in the same shape: a short line saying what each part
//! does, the addresses and amounts under it, and something unmissable where this device
//! could not read a part at all. Only the reading differs, so only the reading lives in
//! [`crate::solanatx`] and [`crate::evmtx`] -- the screen is here, and a chain added
//! later gets it for free.
//!
//! # The shape of a review
//!
//! A column of **cards**. Each has a mark, a headline, and any number of detail lines
//! under it:
//!
//! ```text
//!  [wallet]  Pays 0.000005 SOL
//!            7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU
//!  [clock]   Durable nonce
//!            authority 9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM
//!  [arrow]   Send 0.1 SOL
//!            to 3dxxKMdhLXW5zGCyaTKvKuoXqPgMLJ4TNJ8Q2ZxY4pMi
//! ```
//!
//! The mark is what makes it a column rather than a wall of sentences: the shapes say
//! what is in the transaction before a word of it is read, and they differ in outline so
//! the answer is the same on a panel with no colour.
//!
//! # What cannot be read is the loudest thing on the device
//!
//! A transaction that calls a program this build has no reader for is the normal case on
//! Solana -- there are thousands of programs and this knows a handful -- so refusing to
//! sign those would make the device useless, and saying nothing would make it dangerous.
//! What it does instead: a red card in the list, and, before the list is even shown, a
//! whole screen in red saying how many parts could not be read. One palette, no fringing,
//! and impossible to scroll past without seeing.

use catcard_ui::art::txicons::Kind;
use catcard_ui::scroll::Line;
use core::fmt::Write as _;

use crate::menu;
use crate::ui::Ui;

/// How long one line of a review can be.
///
/// A base58 address is 44 characters and a label goes in front of it, so this is the
/// address plus room to say what it is. Longer than the panel shows at once, which the
/// scroller handles by marqueeing the selected line.
const LINE: usize = 64;

/// The most lines a review can run to.
///
/// A ceiling, not a budget: what does not fit is counted, and a review that did not fit
/// does not offer to sign. Sixteen kilobytes of heap at the worst case, which is why it
/// is a number and not "as many as it takes".
const MAX_LINES: usize = 256;

/// One line of a review, with what it is.
struct Row {
    text: heapless::String<LINE>,
    /// The mark, on the line that opens a card. Detail lines carry none, which is what
    /// indents them under the card they belong to.
    mark: Option<Kind>,
    /// Drawn in the small face: the addresses and numbers under a headline.
    small: bool,
}

/// A transaction, in the words and shapes a screen uses.
pub(crate) struct Review {
    rows: alloc::vec::Vec<Row>,
    /// Lines that did not fit, and parts that could not be read. Both stop the screen
    /// from offering a signature, for the same reason: nothing is signed that was not
    /// shown.
    dropped: usize,
    alarms: usize,
}

impl Review {
    /// Room for a review, or `None` if the heap has nothing to spare.
    pub(crate) fn new() -> Option<Self> {
        let mut rows = alloc::vec::Vec::new();
        rows.try_reserve_exact(MAX_LINES).ok()?;
        Some(Review {
            rows,
            dropped: 0,
            alarms: 0,
        })
    }

    fn push(&mut self, mark: Option<Kind>, small: bool, args: core::fmt::Arguments<'_>) {
        if self.rows.len() == self.rows.capacity() {
            self.dropped += 1;
            return;
        }
        let mut text: heapless::String<LINE> = heapless::String::new();
        // A line too long for the buffer would be truncated by `write_fmt`, which on a
        // line holding an address means showing most of a key. Counted as dropped, so
        // the screen refuses rather than showing three quarters of somebody's address.
        if text.write_fmt(args).is_err() {
            self.dropped += 1;
            return;
        }
        self.rows.push(Row { text, mark, small });
    }

    /// Open a card: a mark and the one line that says what this part does.
    pub(crate) fn card(&mut self, kind: Kind, args: core::fmt::Arguments<'_>) {
        self.push(Some(kind), false, args);
    }

    /// A detail under the card above it: an address, an amount, a count.
    pub(crate) fn detail(&mut self, args: core::fmt::Arguments<'_>) {
        self.push(None, true, args);
    }

    /// Open a card for something this device could not read.
    ///
    /// Counted as well as marked. The count is what puts a red screen in front of the
    /// review and what stops the review offering to sign.
    pub(crate) fn cannot_read(&mut self, args: core::fmt::Arguments<'_>) {
        self.alarms += 1;
        self.push(Some(Kind::Warning), false, args);
    }

    /// Show it, and say whether the owner chose to go ahead.
    ///
    /// `action` is the row that does something -- "Sign it" -- and is offered only when
    /// the whole review is on the screen. A review with lines it could not fit does not
    /// get one: a signature over a part nobody was shown is the one thing a signing
    /// device must never produce, and "the screen ran out of room" is not a reason to
    /// make an exception.
    pub(crate) fn show(&self, ui: &mut Ui<'_>, title: &str, action: &str) -> bool {
        const ROW: u32 = 1;

        // The red screen first. Before the list, because a person scrolling a list is
        // reading it, and this is the one thing that has to interrupt rather than wait
        // its turn.
        if self.alarms > 0 {
            let mut said: heapless::String<48> = heapless::String::new();
            let _ = if self.alarms == 1 {
                write!(said, "one part cannot be read")
            } else {
                write!(said, "{} parts cannot be read", self.alarms)
            };
            menu::alarm(ui.panel, title, &said, "they are marked below");
            menu::wait_for_any_key(ui);
        }

        let mut lines: alloc::vec::Vec<Line<'_>> = alloc::vec::Vec::new();
        if lines.try_reserve_exact(self.rows.len() + 4).is_err() {
            menu::message(ui.panel, title, "not enough memory", "any key to go back");
            menu::wait_for_any_key(ui);
            return false;
        }
        lines.push(Line::title(title));
        for row in &self.rows {
            let mut line = Line::body(&row.text);
            if row.small {
                line = line.small();
            }
            if let Some(kind) = row.mark {
                line = line.with_mark(catcard_ui::art::txicons::mark(kind));
            }
            lines.push(line);
        }

        let mut complaint: heapless::String<64> = heapless::String::new();
        if self.dropped == 0 {
            lines.push(Line::item(action, ROW));
        } else {
            let _ = write!(complaint, "{} more lines than fit here", self.dropped);
            lines.push(Line::body(&complaint).small());
            lines.push(Line::body("not offered: it cannot all be shown").small());
        }

        matches!(
            menu::show_doc(ui, &lines, false, false),
            menu::DocExit::Selected(ROW)
        )
    }
}
