//! The pairing prompt: the code a host's handshake produced, for the person to compare.
//!
//! The encrypted USB channel (`catcard_usb::ncry`) is paired afresh on every connection by
//! a six-digit code both ends derive from the handshake. A relay in the middle produces a
//! different code on each screen, so the comparison is the whole defence, and this screen
//! is where it happens: the code, big enough to read, and yes / no.
//!
//! It takes the screen from the menu loop the way the upgrade offer does -- checked after
//! the keys are read -- and the answer goes back with the prompt's id, so a yes given to a
//! code that has since timed out or been abandoned by the host applies to nothing.
//!
//! Nothing is stored: no list of paired computers, no key kept for next time.

use crate::display;

/// Draw the prompt for `code`.
///
/// The code is what has to be read, so it goes in the largest face the panel has. On the
/// Q1 the 10x20 title fits the whole question, with the code under it in the 7x14 body; on
/// the mono panels the body face is 4x6, too small to compare digits at arm's length, so
/// the code takes the 7x14 title row and the question moves below it.
pub fn show(panel: &mut display::Panel, code: u32) {
    let text = catcard_usb::ncry::code_text(code);
    // Always ASCII digits and one space; the fallback is never taken.
    let code = core::str::from_utf8(&text).unwrap_or("??? ???");
    #[cfg(feature = "board-q1")]
    crate::menu::ask(
        panel,
        "Pair with this computer?",
        code,
        "same code on computer?",
    );
    #[cfg(not(feature = "board-q1"))]
    crate::menu::ask(
        panel,
        code,
        "Pair with this computer?",
        "same code shown there?",
    );
}

/// Draw the warning that pairing is blocked: a computer took `abandoned` device keys and
/// dropped each before revealing its own -- what a relay re-rolling the code looks like,
/// and not something an honest host does.
///
/// Dismissing it lets pairing go on; the next few abandoned attempts block it again, so a
/// relay that is still there needs the person each time.
pub fn show_blocked(panel: &mut display::Panel, abandoned: u8) {
    use core::fmt::Write as _;
    let mut line: heapless::String<32> = heapless::String::new();
    let _ = write!(line, "{abandoned} pairing attempts");
    crate::menu::ask(
        panel,
        "Pairing blocked",
        &line,
        "abandoned. OK = allow again",
    );
}
