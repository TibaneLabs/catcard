//! Secure Notes & Passwords: short notes and credentials kept in the wallet's settings.
//!
//! Stock offers this where there is a keyboard to type on, so it is Q1-only here too.
//! Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §N, help-and-warning-screens.md
//! §16 [C]. The list, the two kinds of item, the sort, the export and import, and the TOTP
//! arithmetic are [`catcard_settings::notes`]; this is the screens around them.
//!
//! # Where they live
//!
//! In the wallet-in-force's own settings file, under [`notes::KEY`] (`cat_notes`), so a
//! passphrase wallet's notes are its own. The slot is sealed on the medium; in RAM every
//! buffer that holds a decrypted note is a leased [`crate::heap`] block, wiped when it is
//! dropped. Stock's own `notes` list is read for display and never written, because its
//! value shape is not documented (`[?]`, see `docs/HARDWARE-OPEN-ITEMS.md`).
//!
//! # The clock
//!
//! A TOTP code needs the time, and this device has no wall clock -- the RTC counts from
//! boot with no battery behind it (`catcard_hal::rtc`). So the owner types the Unix time
//! once per session and the kernel's millisecond tick carries it from there. It is never
//! stored: a clock that was right last week is a code that is wrong today.
//!
//! # Sending a password
//!
//! **Send Password** types the item into the host through [`crate::usbkbd`], with
//! `Keyboard EMU` on; the same screen serves the main menu's `Type Passwords`
//! ([`type_passwords`]), which lists the password items alone. The text is never logged.
//!
//! # What is not here
//!
//! - **Multi-line bodies** typed on the device: the keyboard has no Enter key event
//!   ([`catcard_ui::keypad::Key`] carries printable characters only), so a body typed here
//!   is one paragraph. A body written elsewhere with line breaks shows them.

use catcard_backup::{kdf, sevenz};
use catcard_settings::json::{self, Doc};
use catcard_settings::notes::{self, Item, Kind, Merge};
use catcard_settings::store::{self, SCRATCH};
use catcard_ui::field::{self, Accept, Field, Input};
use catcard_ui::keypad::{Event, KEYS, Key};
use catcard_ui::scroll::Line as Row;
use core::fmt::Write as _;
use zeroize::Zeroize as _;

use crate::display;
use crate::menu::{self, DocExit, Working};
use crate::ui::Ui;

const HEAD: &str = "Secure Notes";

/// Unescaped text, leased while a screen is up: one item's fields, or every title.
const TEXT_LEN: usize = 2 * 1024;

/// One rendered item, escaped: every field at its bound, each byte possibly escaped.
const ITEM_LEN: usize = 2 * 1024;

/// The export or import file, plain or as an archive.
const FILE_LEN: usize = 8 * 1024;

/// Key-derivation rounds between redraws: fixed in advance, as [`crate::backup`] does it.
const KDF_SLICE: u32 = 2048;

/// The one file inside an encrypted export.
const INNER_FILE: &str = "notes.json";
const PLAIN_FILE: &str = "/notes.json";
const SEALED_FILE: &str = "/notes.7z";

/// Rows the list screen can hold: our items, stock's, and the actions.
const MAX_ROWS: usize = 2 * notes::MAX_NOTES + 8;

/// Row ids on the list screen.
const STOCK_BASE: u32 = 100;
const NEW_NOTE: u32 = 200;
const NEW_PW: u32 = 201;
const EXPORT_ALL: u32 = 202;
const SORT: u32 = 203;
const IMPORT: u32 = 204;
const DISABLE: u32 = 205;

/// Room a slot must keep past the notes list: the `_age` bump and the identity keys a
/// first save adds. Conservative on purpose -- refusing a note that would have fitted is
/// annoying; a save that fails after typing five hundred characters is worse.
const SLOT_MARGIN: usize = 160;

// ---------------------------------------------------------------------------
// The session clock
// ---------------------------------------------------------------------------

/// The wall clock, if the owner set it this session: Unix seconds, and the kernel tick
/// at that moment. Sixteen bytes of `.bss`; nothing to lease.
static mut CLOCK: Option<(u64, u32)> = None;

/// Start the session clock at `unix` seconds, now.
fn set_clock(unix: u64) {
    // SAFETY: foreground only, single core; the write finishes within this statement.
    unsafe { *core::ptr::addr_of_mut!(CLOCK) = Some((unix, catcard_kernel::ticks())) };
}

/// Unix seconds now, if the clock was set this session.
fn now() -> Option<u64> {
    // SAFETY: foreground only; `Option<(u64, u32)>` is `Copy` and read in one statement.
    let (unix, at) = unsafe { *core::ptr::addr_of!(CLOCK) }?;
    // One wrap of the 32-bit tick is 49 days; a session does not last that.
    let ms = catcard_kernel::ticks().wrapping_sub(at) as u64 * catcard_kernel::TICK_MS as u64;
    Some(unix + ms / 1000)
}

// ---------------------------------------------------------------------------
// The list
// ---------------------------------------------------------------------------

/// What the list screen asked for. Nothing here borrows the settings buffer, so acting on
/// it can read and write the settings again.
enum Then {
    Leave,
    NewNote,
    NewPassword,
    Open(usize),
    ExportAll,
    Import,
    Sort,
    Disable,
}

/// The feature: opt in if it is off, then the list.
pub(crate) fn screen(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) {
    if !ensure_enabled(gate, login, ui) {
        return;
    }
    loop {
        menu::blocking_screen(ui.panel, HEAD, "reading");
        let next = {
            let (Some(mut doc), Some(mut text)) =
                (crate::heap::take(SCRATCH), crate::heap::take(TEXT_LEN))
            else {
                return say(ui, "not enough memory");
            };
            let doc_buf = doc.bytes();
            let mut arena: &mut [u8] = text.bytes();
            let mut ours = [""; notes::MAX_NOTES];
            let mut stock = [""; notes::MAX_NOTES];
            let (have, have_stock) =
                match read_lists(gate, login, ui.panel, doc_buf, &mut ours, &mut stock) {
                    Ok(l) => (l.ours, l.stock),
                    Err(why) => return say(ui, why),
                };

            let mut rows: heapless::Vec<Row, MAX_ROWS> = heapless::Vec::new();
            let _ = rows.push(Row::title(HEAD));
            if have == 0 && have_stock == 0 {
                let _ = rows.push(Row::body("(nothing saved yet)").centered());
            }
            for (i, raw) in ours[..have].iter().enumerate() {
                let title = title_text(&mut arena, raw).unwrap_or("(untitled)");
                let _ = rows.push(Row::item(title, i as u32));
            }
            for (i, raw) in stock[..have_stock].iter().enumerate() {
                let label = stock_label(&mut arena, raw).unwrap_or("(stock note)");
                let _ = rows.push(Row::item(label, STOCK_BASE + i as u32));
            }
            let _ = rows.push(Row::item("New Note", NEW_NOTE));
            let _ = rows.push(Row::item("New Password", NEW_PW));
            if have > 0 {
                let _ = rows.push(Row::item("Export All", EXPORT_ALL));
            }
            if have > 1 {
                let _ = rows.push(Row::item("Sort By Title", SORT));
            }
            let _ = rows.push(Row::item("Import", IMPORT));
            if have == 0 {
                let _ = rows.push(Row::item("Disable Feature", DISABLE));
            }

            match menu::show_doc(ui, &rows, false, false) {
                DocExit::Selected(NEW_NOTE) => Then::NewNote,
                DocExit::Selected(NEW_PW) => Then::NewPassword,
                DocExit::Selected(EXPORT_ALL) => Then::ExportAll,
                DocExit::Selected(SORT) => Then::Sort,
                DocExit::Selected(IMPORT) => Then::Import,
                DocExit::Selected(DISABLE) => Then::Disable,
                DocExit::Selected(i) if (i as usize) < have => Then::Open(i as usize),
                DocExit::Selected(i)
                    if i >= STOCK_BASE && ((i - STOCK_BASE) as usize) < have_stock =>
                {
                    view_stock(ui, stock[(i - STOCK_BASE) as usize]);
                    continue;
                }
                _ => Then::Leave,
            }
        };

        match next {
            Then::Leave => return,
            Then::NewNote => new_note(gate, login, ui),
            Then::NewPassword => new_password(gate, login, ui),
            Then::Open(i) => open(gate, login, ui, i),
            Then::ExportAll => export(gate, login, ui, None),
            Then::Import => import(gate, login, ui),
            Then::Sort => match save(gate, login, ui, Change::Sort) {
                Ok(()) => {}
                Err(why) => say(ui, why),
            },
            Then::Disable => {
                if disable(gate, login, ui) {
                    return;
                }
            }
        }
    }
}

/// The opt-in story, if the feature is not on. True once it is.
///
/// Source: hw-reference/help-and-warning-screens.md §16 "First use of Secure Notes" [C]
fn ensure_enabled(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) -> bool {
    if crate::prefs::current().notes == Some(true) {
        return true;
    }
    let rows = [
        Row::title(HEAD),
        Row::body(
            "Keeps short notes and passwords on this device, encrypted with the wallet's \
             settings and included in its backups.",
        )
        .wrapped(),
        Row::body("ENTER turns it on; CANCEL leaves it off.")
            .small()
            .wrapped(),
    ];
    if !matches!(menu::show_doc(ui, &rows, false, false), DocExit::Confirmed) {
        return false;
    }
    set_enabled(gate, login, ui, true)
}

/// Store the switch and put it in force. Says so if it could not be stored.
fn set_enabled(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    on: bool,
) -> bool {
    let mut next = crate::prefs::current();
    next.notes = Some(on);
    let raw = if on { "\"1\"" } else { "\"0\"" };
    let ok = crate::prefs::save(
        gate,
        login,
        ui,
        HEAD,
        (catcard_settings::prefs::NOTES, raw),
        next,
    );
    if !ok {
        say(ui, "could not save the setting");
    }
    ok
}

/// Hide the feature. Only offered when nothing is stored, so nothing is lost; still asks,
/// because the tile disappearing is a surprise otherwise. True if it was hidden.
fn disable(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) -> bool {
    menu::ask(ui.panel, HEAD, "hide Secure Notes", "from the main menu?");
    if !menu::confirmed(ui) {
        return false;
    }
    if !set_enabled(gate, login, ui, false) {
        return false;
    }
    menu::message(
        ui.panel,
        HEAD,
        "hidden: Settings >",
        "Secure notes brings it back",
    );
    menu::wait_for_any_key(ui);
    true
}

/// What a read of the settings found.
struct Lists {
    /// How many of ours were read.
    ours: usize,
    /// How many of stock's were read.
    stock: usize,
    /// The whole settings document's length, for the room check before a save.
    doc_len: usize,
    /// The bytes our list takes in it now, which a save replaces.
    ours_len: usize,
}

/// Read both lists into `doc_buf`; the entries borrow it.
fn read_lists<'a>(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    panel: &mut display::Panel,
    doc_buf: &'a mut [u8],
    ours: &mut [&'a str],
    stock: &mut [&'a str],
) -> Result<Lists, &'static str> {
    let key = crate::settings::wallet_key(gate, login, panel, HEAD)?;
    // SAFETY: the region is mapped and readable; nothing is written through this.
    let mut files =
        unsafe { crate::settings::Files::mount_read_only() }.map_err(|_| "no settings store")?;
    let n = store::read(&mut files, &key, doc_buf).unwrap_or(0);
    let doc = Doc::parse(&doc_buf[..n]).unwrap_or_default();
    Ok(Lists {
        ours: notes::list(&doc, notes::KEY, ours),
        stock: notes::list(&doc, notes::STOCK_KEY, stock),
        doc_len: n,
        ours_len: doc.get(notes::KEY).map_or(0, |v| v.len()),
    })
}

/// A raw item's title as text, in the arena.
fn title_text<'b>(arena: &mut &'b mut [u8], raw: &str) -> Option<&'b str> {
    let item = Item::parse(raw)?;
    keep(arena, item.title)
}

/// `title (stock)`, in the arena, for a note stock wrote.
fn stock_label<'b>(arena: &mut &'b mut [u8], raw: &str) -> Option<&'b str> {
    const SUFFIX: &str = " (stock)";
    let item = Item::parse(raw)?;
    let n = json::unescape(item.title, arena).ok()?;
    let taken = core::mem::take(arena);
    if taken.len() < n + SUFFIX.len() {
        *arena = taken;
        return None;
    }
    taken[n..n + SUFFIX.len()].copy_from_slice(SUFFIX.as_bytes());
    let (mine, rest) = taken.split_at_mut(n + SUFFIX.len());
    *arena = rest;
    core::str::from_utf8(mine).ok()
}

/// Copy a raw quoted string into the arena with its escapes undone.
fn keep<'b>(arena: &mut &'b mut [u8], raw: &str) -> Option<&'b str> {
    let n = json::unescape(raw, arena).ok()?;
    let taken = core::mem::take(arena);
    let (mine, rest) = taken.split_at_mut(n);
    *arena = rest;
    core::str::from_utf8(mine).ok()
}

/// Show a note stock wrote, every field under its own name. Read-only: the shape is
/// stock's, and this firmware does not write stock's shape.
fn view_stock(ui: &mut Ui<'_>, raw: &str) {
    let Some(mut text) = crate::heap::take(TEXT_LEN) else {
        return say(ui, "not enough memory");
    };
    let mut arena: &mut [u8] = text.bytes();
    let Ok(note) = Doc::parse(raw.as_bytes()) else {
        return say(ui, "that note did not parse");
    };
    let mut rows: heapless::Vec<Row, 24> = heapless::Vec::new();
    let _ = rows.push(Row::title(HEAD));
    let _ = rows.push(Row::body("written by stock: read-only").small().centered());
    for e in note.entries() {
        let Some(value) = keep(&mut arena, e.raw) else {
            let _ = rows.push(Row::body(e.key).small());
            let _ = rows.push(Row::body("(too long to show)").small());
            continue;
        };
        let _ = rows.push(Row::body(e.key).small());
        let secret = matches!(e.key, "password" | "pw" | "pass" | "secret" | "pin");
        let row = Row::body(value).wrapped();
        let _ = rows.push(if secret { row.secret() } else { row });
    }
    let _ = menu::show_doc(ui, &rows, true, false);
}

// ---------------------------------------------------------------------------
// One item
// ---------------------------------------------------------------------------

/// Row ids on an item's screen.
const VIEW_PW: u32 = 0;
const TOTP: u32 = 1;
const EDIT: u32 = 2;
const EDIT_META: u32 = 3;
const CHANGE_PW: u32 = 4;
const DELETE: u32 = 5;
const EXPORT_ONE: u32 = 6;
const SIGN: u32 = 7;
const APPLY_PP: u32 = 8;
const SEND_PW: u32 = 9;

/// One of ours: show it and offer everything that can be done with it.
fn open(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    index: usize,
) {
    loop {
        menu::blocking_screen(ui.panel, HEAD, "reading");
        // The item's text outlives the settings buffer it was read from: the arena is what
        // every action below borrows, and the buffer goes back before any of them writes.
        let Some(mut text) = crate::heap::take(TEXT_LEN) else {
            return say(ui, "not enough memory");
        };
        let mut arena: &mut [u8] = text.bytes();
        let item = {
            let Some(mut doc) = crate::heap::take(SCRATCH) else {
                return say(ui, "not enough memory");
            };
            let doc_buf = doc.bytes();
            let mut ours = [""; notes::MAX_NOTES];
            let mut stock = [""; notes::MAX_NOTES];
            let have = match read_lists(gate, login, ui.panel, doc_buf, &mut ours, &mut stock) {
                Ok(l) => l.ours,
                Err(why) => return say(ui, why),
            };
            if index >= have {
                return say(ui, "no such item");
            }
            let Some(raw) = Item::parse(ours[index]) else {
                return say(ui, "that item did not parse");
            };
            let Some(item) = raw.unescape(&mut arena) else {
                return say(ui, "that item is too long to show");
            };
            item
        };

        let words_wallet = !matches!(
            crate::key::loaded(),
            Some(crate::key::Loaded::Xprv | crate::key::Loaded::Wif)
        );
        let mut rows: heapless::Vec<Row, 24> = heapless::Vec::new();
        let _ = rows.push(Row::title(item.title));
        match item.kind {
            Kind::Note => {
                let _ = rows.push(Row::body(item.body).wrapped());
                let _ = rows.push(Row::item("Edit", EDIT));
            }
            Kind::Password => {
                if !item.user.is_empty() {
                    let _ = rows.push(Row::body("user").small());
                    let _ = rows.push(Row::body(item.user).wrapped());
                }
                if !item.site.is_empty() {
                    let _ = rows.push(Row::body("site").small());
                    let _ = rows.push(Row::body(item.site).wrapped());
                }
                if !item.body.is_empty() {
                    let _ = rows.push(Row::body("notes").small());
                    let _ = rows.push(Row::body(item.body).wrapped());
                }
                let _ = rows.push(Row::item("View Password", VIEW_PW));
                // Always offered, as stock offers it; the screen says so if the
                // keyboard is off. Source: menu-map §N "Password detail" [C]
                let _ = rows.push(Row::item("Send Password", SEND_PW));
                if !item.totp.is_empty() {
                    let _ = rows.push(Row::item("TOTP code", TOTP));
                }
                let _ = rows.push(Row::item("Edit Metadata", EDIT_META));
                let _ = rows.push(Row::item("Change Password", CHANGE_PW));
            }
        }
        let _ = rows.push(Row::item("Delete", DELETE));
        let _ = rows.push(Row::item("Export", EXPORT_ONE));
        let _ = rows.push(Row::item("Sign Note Text", SIGN));
        if item.kind == Kind::Password && words_wallet {
            let _ = rows.push(Row::item("Apply as BIP-39 Passphrase", APPLY_PP));
        }

        let outcome = match menu::show_doc(ui, &rows, false, false) {
            DocExit::Selected(VIEW_PW) => {
                view_password(ui, &item);
                Ok(())
            }
            DocExit::Selected(SEND_PW) => {
                send_password(ui, &item);
                Ok(())
            }
            DocExit::Selected(TOTP) => {
                totp_screen(ui, item.totp, item.digits);
                Ok(())
            }
            DocExit::Selected(EDIT) => edit_note(gate, login, ui, index, &item),
            DocExit::Selected(EDIT_META) => edit_metadata(gate, login, ui, index, &item),
            DocExit::Selected(CHANGE_PW) => change_password(gate, login, ui, index, &item),
            DocExit::Selected(DELETE) => {
                // Source: help-and-warning-screens.md §16 "Delete a note/password" [C]
                menu::ask(
                    ui.panel,
                    HEAD,
                    "delete it? everything",
                    "about it is removed",
                );
                if !menu::confirmed(ui) {
                    continue;
                }
                match save(gate, login, ui, Change::Remove(index)) {
                    Ok(()) => {
                        say(ui, "deleted");
                        return;
                    }
                    Err(why) => Err(why),
                }
            }
            DocExit::Selected(EXPORT_ONE) => {
                export(gate, login, ui, Some(index));
                Ok(())
            }
            DocExit::Selected(SIGN) => {
                sign_note(gate, login, ui, item.title, item.body);
                Ok(())
            }
            DocExit::Selected(APPLY_PP) => {
                apply_passphrase(gate, login, ui, &item);
                Ok(())
            }
            _ => return,
        };
        if let Err(why) = outcome {
            say(ui, why);
        }
    }
}

/// The password itself, scrambled until revealed on purpose, as a seed word is.
///
/// Source: help-and-warning-screens.md §16 "View / send password" [C]
fn view_password(ui: &mut Ui<'_>, item: &Item<'_>) {
    let rows = [
        Row::title(item.title),
        Row::body("password").small(),
        Row::body(item.password).secret().wrapped(),
    ];
    let _ = menu::show_doc(ui, &rows, true, false);
}

/// Type the password into the host as keystrokes. The keyboard screen asks first, offers
/// Enter after it, and says why if it cannot; the text is never logged.
///
/// Source: help-and-warning-screens.md §16 "View / send password" [C]
fn send_password(ui: &mut Ui<'_>, item: &Item<'_>) {
    if item.password.is_empty() {
        return say(ui, "no password stored");
    }
    crate::usbkbd::send_screen(ui, "Send password", item.title, item.password);
}

/// Main menu → Type Passwords, the Secure Notes half: the password items alone, and the
/// chosen one typed into the host.
///
/// Reads the list the way [`screen`] does but shows only the items that hold a password,
/// so a login form is two selections away rather than five.
pub(crate) fn type_passwords(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) {
    const HEAD: &str = "Type Passwords";
    if crate::prefs::current().notes != Some(true) {
        return say(ui, "Secure Notes is off");
    }
    loop {
        menu::blocking_screen(ui.panel, HEAD, "reading");
        let (Some(mut doc), Some(mut text)) =
            (crate::heap::take(SCRATCH), crate::heap::take(TEXT_LEN))
        else {
            return say(ui, "not enough memory");
        };
        let doc_buf = doc.bytes();
        let mut arena: &mut [u8] = text.bytes();
        let mut ours = [""; notes::MAX_NOTES];
        let mut stock = [""; notes::MAX_NOTES];
        let have = match read_lists(gate, login, ui.panel, doc_buf, &mut ours, &mut stock) {
            Ok(l) => l.ours,
            Err(why) => return say(ui, why),
        };

        // The password items, by their place in the full list, so the pick maps back.
        let mut rows: heapless::Vec<Row, { notes::MAX_NOTES + 2 }> = heapless::Vec::new();
        let _ = rows.push(Row::title(HEAD));
        let mut listed = 0usize;
        for (i, raw) in ours[..have].iter().enumerate() {
            let Some(item) = Item::parse(raw) else {
                continue;
            };
            if item.kind != Kind::Password {
                continue;
            }
            let title = keep(&mut arena, item.title).unwrap_or("(untitled)");
            let _ = rows.push(Row::item(title, i as u32));
            listed += 1;
        }
        if listed == 0 {
            let _ = rows.push(Row::body("(no passwords saved)").centered());
        }
        let DocExit::Selected(index) = menu::show_doc(ui, &rows, false, false) else {
            return;
        };
        let index = index as usize;
        if index >= have {
            return say(ui, "no such item");
        }
        // Unescaped into the arena, which outlives the settings buffer; the typing
        // screen borrows nothing else.
        let Some(item) = Item::parse(ours[index]).and_then(|raw| raw.unescape(&mut arena)) else {
            return say(ui, "that item did not parse");
        };
        send_password(ui, &item);
    }
}

// ---------------------------------------------------------------------------
// Creating and editing
// ---------------------------------------------------------------------------

/// Type a note and store it.
fn new_note(gate: &catcard_callgate::Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    let Some(title) = read_text::<{ notes::MAX_TITLE }>(ui, "New Note", "title", "", "") else {
        return;
    };
    let Some(body) = read_text::<{ notes::MAX_BODY }>(ui, "New Note", "note", "", "") else {
        return;
    };
    let item = Item {
        kind: Kind::Note,
        title: &title,
        body: &body,
        ..Item::default()
    };
    match store_item(gate, login, ui, None, &item) {
        Ok(()) => say(ui, "note saved"),
        Err(why) => say(ui, why),
    }
}

/// Type a credential and store it.
fn new_password(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) {
    const H: &str = "New Password";
    let Some(title) = read_text::<{ notes::MAX_TITLE }>(ui, H, "title", "", "") else {
        return;
    };
    let Some(user) = read_text::<{ notes::MAX_USER }>(ui, H, "user", "", "empty is fine") else {
        return;
    };
    let Some(password) = read_text::<{ notes::MAX_PASSWORD }>(ui, H, "password", "", "") else {
        return;
    };
    let Some(site) = read_text::<{ notes::MAX_SITE }>(ui, H, "site / URL", "", "empty is fine")
    else {
        return;
    };
    let Some(body) = read_text::<{ notes::MAX_BODY }>(ui, H, "notes", "", "empty is fine") else {
        return;
    };
    let Some((totp, digits)) = read_totp(ui, H, "") else {
        return;
    };
    let item = Item {
        kind: Kind::Password,
        title: &title,
        body: &body,
        user: &user,
        password: &password,
        site: &site,
        totp: &totp,
        digits,
    };
    match store_item(gate, login, ui, None, &item) {
        Ok(()) => say(ui, "password saved"),
        Err(why) => say(ui, why),
    }
}

/// The optional TOTP secret and, if there is one, its digit count.
fn read_totp(
    ui: &mut Ui<'_>,
    head: &str,
    initial: &str,
) -> Option<(heapless::String<{ notes::MAX_TOTP }>, u8)> {
    let totp = read_text::<{ notes::MAX_TOTP }>(
        ui,
        head,
        "TOTP secret",
        initial,
        "base32, or empty for none",
    )?;
    if totp.is_empty() {
        return Some((totp, 6));
    }
    let pick = menu::pick_row(ui, head, "code length", &["6 digits", "8 digits"])?;
    Some((totp, if pick == 1 { 8 } else { 6 }))
}

/// Edit a note's title and body, showing what changed before it is stored.
fn edit_note(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    index: usize,
    old: &Item<'_>,
) -> Result<(), &'static str> {
    let Some(title) = read_text::<{ notes::MAX_TITLE }>(ui, "Edit", "title", old.title, "") else {
        return Ok(());
    };
    let Some(body) = read_text::<{ notes::MAX_BODY }>(ui, "Edit", "note", old.body, "") else {
        return Ok(());
    };
    let new = Item {
        title: &title,
        body: &body,
        ..*old
    };
    if !confirm_change(
        ui,
        &[
            ("title", old.title, new.title),
            ("note", old.body, new.body),
        ],
    ) {
        return Ok(());
    }
    store_item(gate, login, ui, Some(index), &new)?;
    say(ui, "saved");
    Ok(())
}

/// Edit everything about a credential but the password itself.
fn edit_metadata(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    index: usize,
    old: &Item<'_>,
) -> Result<(), &'static str> {
    const H: &str = "Edit Metadata";
    let Some(title) = read_text::<{ notes::MAX_TITLE }>(ui, H, "title", old.title, "") else {
        return Ok(());
    };
    let Some(user) = read_text::<{ notes::MAX_USER }>(ui, H, "user", old.user, "") else {
        return Ok(());
    };
    let Some(site) = read_text::<{ notes::MAX_SITE }>(ui, H, "site / URL", old.site, "") else {
        return Ok(());
    };
    let Some(body) = read_text::<{ notes::MAX_BODY }>(ui, H, "notes", old.body, "") else {
        return Ok(());
    };
    let Some((totp, digits)) = read_totp(ui, H, old.totp) else {
        return Ok(());
    };
    let new = Item {
        title: &title,
        user: &user,
        site: &site,
        body: &body,
        totp: &totp,
        digits,
        ..*old
    };
    let changes = [
        ("title", old.title, new.title),
        ("user", old.user, new.user),
        ("site", old.site, new.site),
        ("notes", old.body, new.body),
        ("TOTP secret", old.totp, new.totp),
    ];
    if !confirm_change(ui, &changes) {
        return Ok(());
    }
    store_item(gate, login, ui, Some(index), &new)?;
    say(ui, "saved");
    Ok(())
}

/// Replace the password, showing old and new (scrambled) before it is stored.
fn change_password(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    index: usize,
    old: &Item<'_>,
) -> Result<(), &'static str> {
    let Some(password) =
        read_text::<{ notes::MAX_PASSWORD }>(ui, "Change Password", "new password", "", "")
    else {
        return Ok(());
    };
    let new = Item {
        password: &password,
        ..*old
    };
    if !confirm_secret_change(ui, old.password, new.password) {
        return Ok(());
    }
    store_item(gate, login, ui, Some(index), &new)?;
    say(ui, "password changed");
    Ok(())
}

/// The fields that changed, old against new. True if the owner said save.
///
/// Source: help-and-warning-screens.md §16 "Confirm password/field change" [C]
fn confirm_change(ui: &mut Ui<'_>, changes: &[(&str, &str, &str)]) -> bool {
    let mut rows: heapless::Vec<Row, 20> = heapless::Vec::new();
    let _ = rows.push(Row::title("Save changes?"));
    let mut any = false;
    for (label, old, new) in changes {
        if old == new {
            continue;
        }
        any = true;
        let _ = rows.push(Row::body(label).small());
        let _ = rows.push(Row::body(if old.is_empty() { "(empty)" } else { old }).wrapped());
        let _ = rows.push(Row::body("becomes").small().centered());
        let _ = rows.push(Row::body(if new.is_empty() { "(empty)" } else { new }).wrapped());
    }
    if !any {
        say(ui, "nothing changed");
        return false;
    }
    let _ = rows.push(Row::body("ENTER saves, CANCEL discards").small().centered());
    matches!(menu::show_doc(ui, &rows, false, false), DocExit::Confirmed)
}

/// [`confirm_change`] for the password, which stays scrambled until revealed.
fn confirm_secret_change(ui: &mut Ui<'_>, old: &str, new: &str) -> bool {
    if old == new {
        say(ui, "nothing changed");
        return false;
    }
    let rows = [
        Row::title("Change password?"),
        Row::body("old").small(),
        Row::body(old).secret().wrapped(),
        Row::body("new").small(),
        Row::body(new).secret().wrapped(),
        Row::body("ENTER saves, CANCEL discards").small().centered(),
    ];
    matches!(menu::show_doc(ui, &rows, true, false), DocExit::Confirmed)
}

/// Render a text item and store it: appended, or in place of the item at `replace`.
fn store_item(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    replace: Option<usize>,
    item: &Item<'_>,
) -> Result<(), &'static str> {
    let Some(mut held) = crate::heap::take(ITEM_LEN) else {
        return Err("not enough memory");
    };
    let buf = held.bytes();
    let n = item.render(buf).map_err(describe)?;
    let raw = core::str::from_utf8(&buf[..n]).map_err(|_| "not text")?;
    let change = match replace {
        Some(i) => Change::Replace(i, raw),
        None => Change::Append(raw),
    };
    save(gate, login, ui, change)
}

// ---------------------------------------------------------------------------
// Saving
// ---------------------------------------------------------------------------

/// What a save does to the list. Raw objects throughout.
enum Change<'a> {
    Append(&'a str),
    Replace(usize, &'a str),
    Remove(usize),
    Sort,
    /// An import: these are added, and these replace the items at their indices.
    Merge {
        add: &'a [&'a str],
        replace: &'a [(usize, &'a str)],
    },
}

/// Rebuild the list with `change` applied and write it back.
///
/// Reads the list again rather than trusting one a screen holds: the screen's copy was
/// read before the owner spent a minute typing, and nothing else writes this key, but
/// re-reading costs nothing and makes that an observation rather than an assumption.
fn save(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    change: Change<'_>,
) -> Result<(), &'static str> {
    menu::blocking_screen(ui.panel, HEAD, "saving");
    let (Some(mut doc), Some(mut list_blk), Some(mut seal)) = (
        crate::heap::take(SCRATCH),
        crate::heap::take(SCRATCH),
        crate::heap::take(SCRATCH),
    ) else {
        return Err("not enough memory");
    };
    let doc_buf = doc.bytes();
    let list_buf = list_blk.bytes();
    // Scoped: the entries borrow `doc_buf`, which the write below reuses as scratch.
    let (len, room) = {
        let mut existing = [""; notes::MAX_NOTES];
        let mut stock = [""; notes::MAX_NOTES];
        let lists = read_lists(gate, login, ui.panel, doc_buf, &mut existing, &mut stock)?;
        let have = lists.ours;
        let existing = &existing[..have];

        let mut next: heapless::Vec<&str, { 2 * notes::MAX_NOTES }> = heapless::Vec::new();
        match change {
            Change::Append(raw) => {
                next.extend_from_slice(existing).ok();
                next.push(raw).map_err(|_| "store full (20 items)")?;
            }
            Change::Replace(i, raw) => {
                if i >= have {
                    return Err("no such item");
                }
                next.extend_from_slice(existing).ok();
                next[i] = raw;
            }
            Change::Remove(i) => {
                if i >= have {
                    return Err("no such item");
                }
                for (j, r) in existing.iter().enumerate() {
                    if j != i {
                        let _ = next.push(r);
                    }
                }
            }
            Change::Sort => {
                let mut order = [0usize; notes::MAX_NOTES];
                let n = notes::sorted(existing, &mut order);
                for &i in &order[..n] {
                    let _ = next.push(existing[i]);
                }
            }
            Change::Merge { add, replace } => {
                next.extend_from_slice(existing).ok();
                for &(i, raw) in replace {
                    if i < have {
                        next[i] = raw;
                    }
                }
                for raw in add {
                    next.push(raw).map_err(|_| "store full (20 items)")?;
                }
            }
        }
        let len = notes::render_list(&next, list_buf).map_err(describe)?;

        // Will it fit the slot? The document as it stands, less the list it holds now,
        // plus the new list, has to leave the margin. Said here, as "store full", rather
        // than found as a failed seal after the typing is done.
        let room = lists.doc_len.saturating_sub(lists.ours_len) + len + SLOT_MARGIN
            <= catcard_settings::nvstore::BODY_LEN;
        (len, room)
    };
    if !room {
        list_buf[..len].zeroize();
        return Err("store full");
    }
    let text = core::str::from_utf8(&list_buf[..len]).map_err(|_| "not text")?;
    let result = crate::settings::save_wallet(
        gate,
        login,
        ui,
        HEAD,
        (notes::KEY, text),
        doc_buf,
        seal.bytes(),
    );
    list_buf[..len].zeroize();
    result
}

/// Why an item could not be stored, in the words a screen has.
fn describe(e: notes::Error) -> &'static str {
    match e {
        notes::Error::TooMany => "store full (20 items)",
        notes::Error::NoTitle => "a title is needed",
        notes::Error::TooLong => "too long",
        notes::Error::NotStorable => "cannot store that text",
        notes::Error::BadTotp => "TOTP secret is not base32",
        notes::Error::Overflow => "store full",
        notes::Error::NotAnExport => "not a notes export",
    }
}

// ---------------------------------------------------------------------------
// TOTP
// ---------------------------------------------------------------------------

/// The current code, refreshed every second, until a key is pressed.
fn totp_screen(ui: &mut Ui<'_>, secret: &str, digits: u8) {
    let mut key = [0u8; notes::MAX_TOTP_BYTES];
    let Some(n) = notes::base32_decode(secret, &mut key) else {
        return say(ui, "the secret is not base32");
    };
    if now().is_none() && !ask_clock(ui) {
        key.zeroize();
        return;
    }
    menu::wait_for_release(ui);
    while let Some(t) = now() {
        let (code, left) = notes::totp(&key[..n], t, notes::TOTP_STEP, digits);
        let code = notes::format_code(code, digits);
        let mut left_text: heapless::String<16> = heapless::String::new();
        let _ = write!(left_text, "{left} s left");
        {
            use catcard_ui::scroll::{ScrollView, render};
            let rows = [
                Row::title("TOTP code"),
                Row::body(code.as_str()).large().centered(),
                Row::body(left_text.as_str()).small().centered(),
                Row::body("any key to go back").small().centered(),
            ];
            let view =
                ScrollView::build(&rows, display::SCREEN_W, display::SCREEN_H, display::FONTS);
            display::draw(ui.panel, |c| render(c, &view));
        }
        if key_within(ui, 1000) {
            break;
        }
    }
    key.zeroize();
}

/// Ask for the Unix time and start the session clock. False if the owner backed out, or
/// there is no tick to carry the time from.
fn ask_clock(ui: &mut Ui<'_>) -> bool {
    if !catcard_kernel::running() {
        say(ui, "no clock source on this build");
        return false;
    }
    menu::message(
        ui.panel,
        "Clock not set",
        "type the Unix time",
        "once per session",
    );
    menu::wait_for_any_key(ui);
    let Some(t) = menu::ask_number(ui, "Unix time", None, "seconds", "e.g. 1790000000") else {
        return false;
    };
    // Below the first TOTP anyone issued: a typo, not a time.
    if t < 1_000_000_000 {
        say(ui, "that is not a current time");
        return false;
    }
    set_clock(t as u64);
    true
}

/// Poll the keypad for up to `ms` milliseconds. True if any key was pressed.
///
/// Bounded by the tick, so a dead keypad ends the wait rather than the session.
fn key_within(ui: &mut Ui<'_>, ms: u32) -> bool {
    let start = catcard_kernel::ticks();
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        let _ = crate::usbtask::pump();
        crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
        if !keys.is_empty() {
            return true;
        }
        if catcard_kernel::ticks().wrapping_sub(start) >= ms {
            return false;
        }
        display::idle(ui.panel);
    }
}

// ---------------------------------------------------------------------------
// Export and import
// ---------------------------------------------------------------------------

/// Write the list -- or the one item at `only` -- as JSON, plain or sealed in a 7-Zip
/// archive under a typed password, to the card or the Virtual Disk.
fn export(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    only: Option<usize>,
) {
    const H: &str = "Export notes";
    let Some(mut file) = crate::heap::take(FILE_LEN) else {
        return say(ui, "not enough memory");
    };
    let buf = file.bytes();
    // The JSON goes where an archive's body sits, so sealing needs no second copy.
    let json_len = {
        let Some(mut doc) = crate::heap::take(SCRATCH) else {
            return say(ui, "not enough memory");
        };
        let mut ours = [""; notes::MAX_NOTES];
        let mut stock = [""; notes::MAX_NOTES];
        let have = match read_lists(gate, login, ui.panel, doc.bytes(), &mut ours, &mut stock) {
            Ok(l) => l.ours,
            Err(why) => return say(ui, why),
        };
        let items = match only {
            Some(i) if i < have => &ours[i..=i],
            Some(_) => return say(ui, "no such item"),
            None => &ours[..have],
        };
        match notes::export(items, &mut buf[sevenz::BODY_OFFSET..]) {
            Ok(n) => n,
            Err(_) => return say(ui, "too much to export"),
        }
    };

    menu::ask(ui.panel, H, "encrypt the file", "with a password?");
    let (path, start, len) = if menu::confirmed(ui) {
        let Some(password) = read_text::<64>(ui, H, "password", "", "for the .7z file") else {
            return;
        };
        if password.is_empty() {
            return say(ui, "no password, no file");
        }
        // A fresh IV per archive, from the protocol DRBG as the backup takes its own.
        let mut iv = [0u8; 16];
        if ui.protocol.generate(&mut iv).is_err() {
            return say(ui, "no random IV");
        }
        let key = match stretch(ui, &password, H, "sealing the file") {
            Ok(k) => k,
            Err(why) => return say(ui, why),
        };
        let sealed = sevenz::seal_at(
            buf,
            json_len,
            INNER_FILE,
            &key,
            &iv,
            &[],
            kdf::DEFAULT_CYCLES_POWER,
        );
        match sealed {
            Ok(a) => (SEALED_FILE, 0, a.len()),
            Err(_) => return say(ui, "could not seal the file"),
        }
    } else {
        (PLAIN_FILE, sevenz::BODY_OFFSET, json_len)
    };

    let Some(storage) = menu::pick_storage(ui, H) else {
        return;
    };
    menu::card_wait(ui.panel, H, "writing");
    match menu::write_storage_file(storage, path, &buf[start..start + len]) {
        Ok(()) => {
            crate::catlog!("notes: exported {} to {}", path, storage.medium());
            menu::message(ui.panel, "Exported", &path[1..], "any key to go back");
        }
        Err(why) => {
            crate::catlog!("notes: export failed: {}", why);
            menu::message(ui.panel, "Write failed", why, "any key to go back");
        }
    }
    menu::wait_for_any_key(ui);
}

/// Derive the archive key from a password, with the bar ticking on a fixed round count.
fn stretch(
    ui: &mut Ui<'_>,
    password: &str,
    head: &str,
    note: &str,
) -> Result<kdf::Key, &'static str> {
    let mut kd = kdf::KeyDerivation::new(password, &[], kdf::DEFAULT_CYCLES_POWER)
        .map_err(|_| "that cannot be a password")?;
    let mut busy = Working::new(ui.panel, head, note);
    while !kd.step(KDF_SLICE) {
        busy.tick(ui.panel);
    }
    kd.finish().map_err(|_| "key derivation failed")
}

/// Read an export back and merge it: new titles are added, identical items skipped, and
/// a title that is already here with different contents is asked about.
fn import(gate: &catcard_callgate::Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    const H: &str = "Import notes";
    let Some(kind) = menu::pick_row(
        ui,
        H,
        "which file?",
        &["notes.json (plain)", "notes.7z (encrypted)"],
    ) else {
        return;
    };
    let sealed = kind == 1;
    let Some(storage) = menu::pick_storage(ui, H) else {
        return;
    };
    let filter = if sealed { "7z" } else { "json" };
    let Some(path) = menu::browse_storage(
        ui,
        storage,
        "Pick the file",
        Some(filter),
        menu::Browse::File,
    ) else {
        return;
    };
    let Some(mut file) = crate::heap::take(FILE_LEN) else {
        return say(ui, "not enough memory");
    };
    let buf = file.bytes();
    menu::card_wait(ui.panel, H, "reading");
    let len = match crate::signtx::read_source_file(storage, &path, buf) {
        Ok(n) => n,
        Err(why) => return say(ui, why),
    };
    let json_len = if sealed {
        match unseal(ui, buf, len) {
            Ok(n) => n,
            Err(why) => return say(ui, why),
        }
    } else {
        len
    };
    let raw = match notes::exported(&buf[..json_len]) {
        Ok(r) => r,
        Err(_) => return say(ui, "not a notes export"),
    };

    // The plan, made against the list as it is now; the settings buffer goes back before
    // the save re-reads it. Additions and replacements borrow the file, which stays.
    let mut add: heapless::Vec<&str, { notes::MAX_NOTES }> = heapless::Vec::new();
    let mut replace: heapless::Vec<(usize, &str), { notes::MAX_NOTES }> = heapless::Vec::new();
    let mut skipped = 0u32;
    let mut unreadable = 0u32;
    let mut overflow = false;
    {
        let (Some(mut doc), Some(mut text)) =
            (crate::heap::take(SCRATCH), crate::heap::take(TEXT_LEN))
        else {
            return say(ui, "not enough memory");
        };
        let mut ours = [""; notes::MAX_NOTES];
        let mut stock = [""; notes::MAX_NOTES];
        let have = match read_lists(gate, login, ui.panel, doc.bytes(), &mut ours, &mut stock) {
            Ok(l) => l.ours,
            Err(why) => return say(ui, why),
        };
        let existing = &ours[..have];
        let Ok(elements) = json::elements(raw) else {
            return say(ui, "not a notes export");
        };
        for element in elements {
            let Ok(obj) = element else { break };
            // Bounded and storable, or not taken: the file is not this device's typing.
            let mut arena: &mut [u8] = text.bytes();
            let ok = Item::parse(obj)
                .and_then(|r| r.unescape(&mut arena))
                .is_some_and(|i| i.check().is_ok());
            if !ok {
                unreadable += 1;
                continue;
            }
            match notes::merge(existing, obj) {
                None => unreadable += 1,
                Some(Merge::Same) => skipped += 1,
                Some(Merge::Add) => {
                    if add.push(obj).is_err() {
                        overflow = true;
                    }
                }
                Some(Merge::Conflict(i)) => {
                    let mut arena: &mut [u8] = text.bytes();
                    let title = title_text(&mut arena, obj).unwrap_or("(untitled)");
                    menu::ask(ui.panel, "Replace?", title, "differs from the stored one");
                    if menu::confirmed(ui) {
                        let _ = replace.push((i, obj));
                    } else {
                        skipped += 1;
                    }
                }
            }
        }
    }
    if add.is_empty() && replace.is_empty() {
        return say(ui, "nothing new in that file");
    }
    match save(
        gate,
        login,
        ui,
        Change::Merge {
            add: &add,
            replace: &replace,
        },
    ) {
        Ok(()) => {
            let mut a = heapless::String::<32>::new();
            let mut b = heapless::String::<32>::new();
            let _ = write!(a, "added {}, replaced {}", add.len(), replace.len());
            let _ = write!(b, "skipped {}, unreadable {}", skipped, unreadable);
            crate::catlog!("notes: import {}; {}", a.as_str(), b.as_str());
            if overflow {
                b.clear();
                let _ = b.push_str("some left out: store full");
            }
            menu::message(ui.panel, "Imported", a.as_str(), b.as_str());
            menu::wait_for_any_key(ui);
        }
        Err(why) => say(ui, why),
    }
}

/// Open an archive in `buf[..len]` under a typed password, leaving the JSON at the front.
///
/// Source: help-and-warning-screens.md §16 "Encrypted (.7z) notes import" [C] -- stock
/// also offers its twelve-word style; only a typed password is offered here.
fn unseal(ui: &mut Ui<'_>, buf: &mut [u8], len: usize) -> Result<usize, &'static str> {
    const H: &str = "Import notes";
    let found = sevenz::open(&buf[..len]).map_err(|_| "not a 7-Zip archive we can read")?;
    // A cleartext archive has no key to derive and no password to ask for: the notes
    // are read straight out, as a plain `.json` would be.
    if let sevenz::Found::Clear(plain) = &found {
        return Ok(sevenz::extract_in_place(&mut buf[..len], plain)
            .map_err(|_| "damaged archive")?
            .len());
    }
    let password = read_text::<64>(ui, H, "password", "", "of the .7z file").ok_or("cancelled")?;
    let key = stretch(ui, &password, H, "unlocking the file")?;
    let stream = match found {
        sevenz::Found::File(s) => s,
        sevenz::Found::Header(hdr) => {
            // An encrypted header is decrypted into its own block, then dropped, so the
            // save later never sees two file-sized blocks at once.
            let mut header = crate::heap::take(FILE_LEN).ok_or("not enough memory")?;
            let n = sevenz::decrypt(&buf[..len], &hdr, &key, header.bytes())
                .map_err(|_| "wrong password")?
                .len();
            sevenz::file_in(&header.bytes()[..n]).map_err(|_| "not a single-file archive")?
        }
        // Handled above, before a password was asked; an error rather than a panic.
        sevenz::Found::Clear(_) => return Err("not encrypted"),
    };
    Ok(sevenz::decrypt_in_place(&mut buf[..len], &stream, &key)
        .map_err(|_| "wrong password")?
        .len())
}

// ---------------------------------------------------------------------------
// Signing, and the passphrase
// ---------------------------------------------------------------------------

/// Sign the note's text as a Bitcoin message and write the armoured file to the chosen
/// storage.
///
/// The signing is `crate::signmsg`'s, format, address type and path asked as they are
/// for a typed message. A note is one line: the message form's second and third lines
/// are a path and an address type, and a body with line breaks is not a request but a
/// note that cannot be signed, which is what the ASCII check says.
fn sign_note(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    title: &str,
    text: &str,
) {
    const H: &str = "Sign note";
    if text.len() < 2 {
        return say(ui, "nothing to sign");
    }
    if let Some(why) = crate::signmsg::unshowable(text) {
        return say(ui, why);
    }
    let Some(file) = crate::signmsg::sign_to_file(gate, login, ui, H, text) else {
        return;
    };
    let Some(storage) = menu::pick_storage(ui, H) else {
        return;
    };
    let path = file_name(title, "-signed.txt");
    menu::card_wait(ui.panel, H, "writing");
    match menu::write_storage_file(storage, &path, file.as_bytes()) {
        Ok(()) => {
            crate::catlog!("notes: signed note written");
            menu::message(ui.panel, "Signed", &path[1..], "any key to go back");
        }
        Err(why) => menu::message(ui.panel, "Write failed", why, "any key to go back"),
    }
    menu::wait_for_any_key(ui);
}

/// `/<title><suffix>`, with the title reduced to what a FAT name takes.
fn file_name(title: &str, suffix: &str) -> heapless::String<64> {
    let mut out: heapless::String<64> = heapless::String::new();
    let _ = out.push('/');
    for c in title.chars().take(notes::MAX_TITLE) {
        let _ = out.push(if c.is_ascii_alphanumeric() { c } else { '_' });
    }
    if out.len() == 1 {
        let _ = out.push_str("note");
    }
    let _ = out.push_str(suffix);
    out
}

/// Use the stored password as the session's BIP-39 passphrase.
///
/// Applied as a typed one is ([`crate::passphrase::apply`]): the wallet it opens is
/// shown by fingerprint and first address before the owner agrees to work in it, and it
/// lives in RAM until reboot. Asked once here first, because the row sits beside `Delete`
/// and a passphrase applied by a slip is a different wallet on screen with no word said.
///
/// Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §N "Apply as BIP-39 Passphrase" [C]
fn apply_passphrase(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    item: &Item<'_>,
) {
    if item.password.is_empty() {
        return say(ui, "no password stored");
    }
    menu::ask(
        ui.panel,
        "As passphrase",
        "open the wallet this",
        "password names?",
    );
    if !menu::confirmed(ui) {
        return;
    }
    if crate::passphrase::apply(gate, login, ui, item.password) {
        crate::catlog!("notes: password applied as passphrase");
    }
}

// ---------------------------------------------------------------------------
// Typing
// ---------------------------------------------------------------------------

/// Type one field on the keyboard, pre-filled with `initial` when editing.
///
/// `None` if the owner backed out (Cancel on an empty field). Confirm on an empty field
/// is an empty value, which some fields allow and the item check refuses for the rest.
///
/// Generic only in what it hands back: the screen itself is [`read_into`], one copy over
/// one field-sized buffer, so six field lengths do not make six screens in the image.
fn read_text<const N: usize>(
    ui: &mut Ui<'_>,
    head: &str,
    label: &str,
    initial: &str,
    note: &str,
) -> Option<heapless::String<N>> {
    let mut input = Input::<{ notes::MAX_BODY }>::new(Accept::Text, N);
    if !read_into(ui, head, label, initial, note, &mut input) {
        return None;
    }
    let mut out: heapless::String<N> = heapless::String::new();
    let _ = out.push_str(input.as_str());
    Some(out)
}

/// The typing screen behind [`read_text`]. True on Confirm, false if backed out.
fn read_into(
    ui: &mut Ui<'_>,
    head: &str,
    label: &str,
    initial: &str,
    note: &str,
    input: &mut Input<{ notes::MAX_BODY }>,
) -> bool {
    use catcard_ui::canvas::Canvas as _;
    use catcard_ui::text::{centred, draw_text};

    // A line break in a stored body has no key here, so an edit shows it as what the
    // field can take; the body is one paragraph after that.
    for c in initial.chars() {
        let _ = input.put(if c == '\n' || c == '\t' { ' ' } else { c });
    }
    let lines = match input.max() {
        0..=40 => 1,
        41..=100 => 2,
        _ => 5,
    };
    let top_y = display::FIELD_TOP;
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    let mut complaint = "";

    loop {
        {
            let fields = [Field::text(label, input.as_str()).lines(lines).live(true)];
            let body = display::LAYOUT.body;
            let foot = if !complaint.is_empty() {
                complaint
            } else if !note.is_empty() {
                note
            } else {
                "type, then ENTER"
            };
            display::draw_field_page(ui.panel, |c| {
                c.clear();
                let hx = centred(body, head, c.width());
                draw_text(
                    c,
                    body,
                    hx,
                    top_y.saturating_sub(body.line_height() + 6),
                    head,
                );
                let below = field::stack(
                    c,
                    &display::LAYOUT,
                    top_y,
                    &fields,
                    display::FIELD_SKIN,
                    true,
                );
                let fx = centred(body, foot, c.width());
                draw_text(c, body, fx, below + 6, foot);
            });
        }
        menu::wait_for_release(ui);

        let mut redraw = false;
        while !redraw {
            let _ = crate::usbtask::pump();
            crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
            for k in keys.iter() {
                match k {
                    Key::Confirm => return true,
                    Key::Cancel => {
                        if !input.backspace() {
                            return false;
                        }
                        complaint = "";
                        redraw = true;
                    }
                    Key::Digit(d) => {
                        if !input.put((b'0' + d) as char) {
                            complaint = "that is as long as it goes";
                        }
                        redraw = true;
                    }
                    Key::Qr => {}
                    Key::Char(c) => {
                        if !input.put(*c as char) {
                            complaint = "that is as long as it goes";
                        }
                        redraw = true;
                    }
                }
            }
            if !redraw {
                display::idle(ui.panel);
            }
        }
    }
}

/// A one-line message screen that waits for a key.
fn say(ui: &mut Ui<'_>, what: &str) {
    menu::message(ui.panel, HEAD, what, "any key to go back");
    menu::wait_for_any_key(ui);
}
