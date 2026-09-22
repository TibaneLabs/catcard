//! Checking a signed-message file from the card.
//!
//! The other half of [`crate::signmsg`], and the half that needs no key at all: a
//! signature is public, so this screen works with no wallet loaded and asks for no PIN.
//! It is the screen someone uses to check what a counterparty sent them, and the thing it
//! must never do is say yes on the file's say-so.
//!
//! So the file's own claims are checked, never used:
//!
//! - the signature is recovered or verified against the message *in that file*, so a
//!   signature moved onto other text fails;
//! - the key that comes out is measured against the address *in that file*, so a signature
//!   made by another key fails.
//!
//! Both schemes [`catcard_wallet::signfile`] reads are checked here -- legacy and BIP-322
//! -- and the screen says which one the file turned out to carry, because "verified" means
//! something slightly different in each and the owner is entitled to know which they got.
//!
//! "Cannot check this" is its own answer. A P2WSH multisig file, or one of BIP-322's other
//! variants, is refused as unreadable rather than reported as a bad signature: a screen
//! that renders "I have no script interpreter" as "forged" teaches people to ignore it.

use catcard_wallet::signfile::{self, Scheme};

use crate::display;
use crate::menu;
use crate::ui::Ui;

/// Longest signed-message file this reads. The armoured block is a few hundred bytes; the
/// rest is room for a note above it and for saying so about a file that is not one.
const MAX_FILE: usize = 2048;

/// Pick a signed-message file and say whether its signature is its address's.
pub(crate) fn screen(ui: &mut Ui<'_>) {
    const HEAD: &str = "Verify sig";

    let Some(path) = menu::browse_sd(ui, "Pick a signed .txt", Some("txt"), true) else {
        return;
    };
    let mut raw = [0u8; MAX_FILE];
    menu::card_wait(ui.panel, HEAD, "reading the card");
    let len = match crate::signtx::read_card_file(&path, &mut raw) {
        Ok(n) => n,
        Err(why) => return say(ui, HEAD, why),
    };
    let Ok(text) = core::str::from_utf8(&raw[..len]) else {
        return say(ui, HEAD, "not text");
    };
    let file = match signfile::parse(text) {
        Ok(f) => f,
        Err(why) => return say(ui, HEAD, describe(why)),
    };

    match signfile::verify(&file) {
        Ok(scheme) => {
            crate::catlog!("verify: {} good ({})", file.address, scheme.name());
            good(ui, &file, scheme);
        }
        Err(why) => {
            crate::catlog!("verify: {}: {}", path.as_str(), describe(why));
            bad(ui, &file, describe(why));
        }
    }
}

/// Why a file could not be checked, in the words a screen has.
///
/// `Invalid` is the only one of these that means the signature is wrong. The rest say
/// this device could not answer the question, which is not the same news.
fn describe(e: signfile::Error) -> &'static str {
    match e {
        signfile::Error::NotArmoured => "not a signed message file",
        signfile::Error::Malformed => "file is damaged",
        signfile::Error::Unsupported => "cannot check this kind",
        signfile::Error::BadAddress => "address not readable",
        signfile::Error::Invalid => "signature does NOT match",
    }
}

/// The verdict for a signature that checked out.
fn good(ui: &mut Ui<'_>, file: &signfile::Armoured<'_>, scheme: Scheme) {
    use catcard_ui::scroll::Line;
    let mut note: heapless::String<32> = heapless::String::new();
    let _ = core::fmt::Write::write_fmt(&mut note, format_args!("{} signature", scheme.name()));
    let mut doc: heapless::Vec<Line, 8> = heapless::Vec::new();
    let _ = doc.push(Line::title("Signature good"));
    let _ = doc.push(Line::body("signed by").small());
    let _ = doc.push(Line::body(file.address).small().wrapped());
    let _ = doc.push(Line::body(file.message).wrapped());
    let _ = doc.push(Line::body(note.as_str()).small());
    page(ui, &doc);
}

/// The verdict for one that did not, or could not be checked.
fn bad(ui: &mut Ui<'_>, file: &signfile::Armoured<'_>, why: &str) {
    use catcard_ui::scroll::Line;
    let mut doc: heapless::Vec<Line, 8> = heapless::Vec::new();
    let _ = doc.push(Line::title("Not verified"));
    let _ = doc.push(Line::body(why).wrapped());
    let _ = doc.push(Line::body("claimed address").small());
    let _ = doc.push(Line::body(file.address).small().wrapped());
    let _ = doc.push(Line::body(file.message).wrapped());
    page(ui, &doc);
}

fn page(ui: &mut Ui<'_>, doc: &[catcard_ui::scroll::Line]) {
    let mut view = catcard_ui::scroll::ScrollView::build(
        doc,
        display::SCREEN_W,
        display::SCREEN_H,
        display::FONTS,
    );
    let _ = menu::scroll_choice(ui, &mut view);
}

fn say(ui: &mut Ui<'_>, head: &str, what: &str) {
    menu::message(ui.panel, head, what, "any key to go back");
    menu::wait_for_any_key(ui);
}
