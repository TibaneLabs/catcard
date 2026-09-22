//! Secure Notes & Passwords, as stock writes them into the settings blob.
//!
//! The settings dictionary's `notes` key is a list of objects, one per note, and `secnap`
//! says the feature is on. The field names inside a note are not fixed by anything we can
//! check, so nothing here assumes them: every field of every note is shown under its own
//! name, with its text unescaped. A note written by a firmware version that added a field
//! still shows the field.
//!
//! Read-only, and the settings volume is mounted read-only underneath, so this cannot
//! modify what it is reading.

use catcard_settings::json::{self, Doc};
use catcard_settings::store::SCRATCH;
use catcard_ui::scroll::Line as Row;

// The decrypted settings blob and the unescaped note text both come from the heap, for
// as long as this screen is up. Neither belongs on the stack -- a screen runs on an 8 KB
// task stack and the blob alone is four of those kilobytes -- and neither belongs in
// `.bss`, where they were resident on a device that mostly never opens this screen.

/// Unescaped note text, which the rows on screen borrow.
///
/// Sized for the document rather than for a title: a note can hold a whole text file,
/// and the point of the screen is to show what is in there.
const TEXT_LEN: usize = 6 * 1024;

/// Rows the document can hold: a title plus a few fields per note.
const MAX_ROWS: usize = 96;

/// Copy `raw`'s text into the arena with its escapes undone, and hand back a slice of it.
///
/// The arena shrinks as it is used, so each string keeps its own bytes for as long as the
/// document needs them, with no allocator and no copying twice.
fn keep<'a>(arena: &mut &'a mut [u8], raw: &str) -> Option<&'a str> {
    let n = json::unescape(raw, arena).ok()?;
    let taken = core::mem::take(arena);
    let (mine, rest) = taken.split_at_mut(n);
    *arena = rest;
    core::str::from_utf8(mine).ok()
}

/// Show every note in the settings blob.
///
/// Passwords are marked as secrets, so they arrive on screen scrambled and are revealed
/// deliberately -- the same treatment as a seed word. A title is not a secret; a password
/// on a screen someone is holding up to read their notes is.
pub(crate) fn view(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut crate::ui::Ui<'_>,
) {
    use catcard_settings::nvstore;
    use catcard_settings::store;
    use zeroize::Zeroize as _;

    // Held for as long as this screen is up, and given back however it leaves. A device
    // with no room for them does not open the screen, which is a thing to say rather
    // than a thing to crash over.
    let (Some(mut blob_held), Some(mut text_held)) =
        (crate::heap::take(SCRATCH), crate::heap::take(TEXT_LEN))
    else {
        let rows = [Row::title("Secure Notes"), Row::body("not enough memory")];
        crate::menu::show_doc(ui, &rows, false, false);
        crate::menu::wait_for_any_key(ui);
        return;
    };
    let blob: &mut [u8] = blob_held.bytes();
    let mut arena: &mut [u8] = text_held.bytes();

    let mut rows: heapless::Vec<Row, MAX_ROWS> = heapless::Vec::new();
    let _ = rows.push(Row::title("Secure Notes"));

    let say = |ui: &mut crate::ui::Ui<'_>, why: &str| {
        let rows = [Row::title("Secure Notes"), Row::body(why)];
        crate::menu::show_doc(ui, &rows, false, false);
    };

    // SAFETY: the region is mapped and readable; nothing is written through this.
    let mut files = match unsafe { crate::settings::Files::mount_read_only() } {
        Ok(f) => f,
        Err(why) => {
            crate::catlog!("notes: mount failed: {:?}", why);
            say(ui, "no settings store on this board");
            crate::menu::wait_for_any_key(ui);
            return;
        }
    };

    crate::menu::reading_seed(ui.panel, "Secure Notes");
    let pin_gate = crate::pinentry::BootloaderGate::new(gate);
    let mut secret = match login.fetch_secret(&pin_gate) {
        Ok(s) => s,
        Err(_) => {
            say(ui, "could not read the secret");
            crate::menu::wait_for_any_key(ui);
            return;
        }
    };
    // Six hashes over the raw stash: derived from the secret, so interrupts are masked.
    let key = crate::keywork::run(|_| nvstore::hash_key(&secret));
    secret.zeroize();

    let read = store::read(&mut files, &key, blob);
    let n = match read {
        Ok(n) => n,
        Err(e) => {
            crate::catlog!("notes: settings read: {:?}", e);
            say(ui, "no settings for this wallet");
            crate::menu::wait_for_any_key(ui);
            return;
        }
    };
    let Ok(doc) = Doc::parse(&blob[..n]) else {
        say(ui, "the settings did not parse");
        crate::menu::wait_for_any_key(ui);
        return;
    };
    let Some(list) = doc.get("notes") else {
        say(ui, "no notes on this wallet");
        crate::menu::wait_for_any_key(ui);
        return;
    };

    let mut count = 0usize;
    let mut walked = match json::elements(list) {
        Ok(w) => w,
        Err(_) => {
            say(ui, "notes is not a list");
            crate::menu::wait_for_any_key(ui);
            return;
        }
    };
    for element in &mut walked {
        let Ok(raw) = element else { break };
        let Ok(note) = Doc::parse(raw.as_bytes()) else {
            continue;
        };
        count += 1;
        // The title first and in full size, then the other fields under their own names.
        // A note with no title still gets a heading, or its fields would run into the
        // previous note's.
        let title = note
            .get("title")
            .and_then(|t| keep(&mut arena, t))
            .unwrap_or("(untitled)");
        let _ = rows.push(Row::body(title));
        for e in note.entries() {
            if e.key == "title" {
                continue;
            }
            let Some(text) = keep(&mut arena, e.raw) else {
                // Out of arena, or text that is not valid once unescaped. Say which field
                // rather than leaving a gap that reads as "the note was empty".
                let _ = rows.push(Row::body(e.key).small());
                let _ = rows.push(Row::body("(too long to show)").small());
                continue;
            };
            let _ = rows.push(Row::body(e.key).small());
            // Anything that looks like a credential is treated as one.
            let secret = matches!(e.key, "password" | "pw" | "pass" | "secret" | "pin");
            let row = Row::body(text);
            let _ = rows.push(if secret { row.secret() } else { row });
        }
    }

    crate::catlog!("notes: {} note(s), {} bytes of settings", count, n);
    if count == 0 {
        say(ui, "the list is empty");
        crate::menu::wait_for_any_key(ui);
        return;
    }
    // Scrambled: the rows marked secret stay hidden until revealed on purpose.
    crate::menu::show_doc(ui, &rows, true, false);
}
