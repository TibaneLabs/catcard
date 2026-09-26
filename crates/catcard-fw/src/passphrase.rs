//! The BIP-39 passphrase: a second wallet from the same words.
//!
//! A passphrase is not a password on the seed. Every passphrase gives a *valid* wallet, so
//! there is nothing to be wrong about and nothing the device can check: a typo does not
//! fail, it silently opens a different, empty wallet. The only defence is showing the owner
//! which wallet they landed in -- the master fingerprint and the first receive address --
//! before anything is done with it, which is what [`apply`] does.
//!
//! It is never stored on the device. It lives in RAM for this session, is wiped when
//! cleared or when the device reboots, and is mixed into the seed on every derivation
//! ([`crate::menu::unlock_master`]), so the address explorer, the wallet export and the
//! signing path all follow it without knowing it exists.
//!
//! # Saved to the card, if asked
//!
//! Stock offers, once a passphrase is applied, to save it to the microSD encrypted so it
//! can be restored without typing; so does this. The file is [`catcard_wallet::pwsave`]'s:
//! AES-256-GCM under a key that is an HMAC of the seed's entropy, made inside the masked
//! region, so only a device holding these words opens it -- and a card that walks off
//! holds nothing anyone else can read. `Restore saved` lists the entries by the
//! fingerprint of the wallet each opens, applies one exactly as typing it would (the same
//! fingerprint and address check, and a warning if the fingerprint is not the one saved),
//! and deletes one on request. The passphrase's bytes are wiped on every path out.
//! Source: hw-reference/help-and-warning-screens.md §5 [C]

use catcard_callgate::Callgate;
use catcard_ui::keypad::{Event, KEYS, Key};
use catcard_ui::textentry::{Entry, MAX_LEN};
use catcard_wallet::pwsave;
use core::fmt::Write as _;
use zeroize::{Zeroize, Zeroizing};

use crate::display;
use crate::menu;
use crate::ui::Ui;

const HEAD: &str = "Passphrase";

/// Where the saved passphrases live on the card. Ours, not stock's: the format is our
/// own, and a name of our own keeps a stock device from trying to read it.
const PATH: &str = "/catcard-passphrases.bin";

/// The passphrase in force, empty for none. Foreground only, single core.
static mut ACTIVE: heapless::String<MAX_LEN> = heapless::String::new();

/// The passphrase every derivation this session uses.
pub(crate) fn active() -> &'static str {
    // SAFETY: foreground only; the menu is the sole writer and never holds a borrow across
    // a write.
    unsafe { (*core::ptr::addr_of!(ACTIVE)).as_str() }
}

/// Whether a passphrase is in force.
pub(crate) fn is_set() -> bool {
    !active().is_empty()
}

/// Replace the passphrase in force, wiping what was there.
fn set(text: &str) {
    // SAFETY: as in `active`.
    let slot = unsafe { &mut *core::ptr::addr_of_mut!(ACTIVE) };
    wipe(slot);
    let _ = slot.push_str(text);
    // Anything derived under the previous passphrase belongs to a different wallet.
    crate::pubkeys::forget();
}

/// Forget the passphrase, wiping it.
pub(crate) fn clear() {
    // SAFETY: as in `active`.
    wipe(unsafe { &mut *core::ptr::addr_of_mut!(ACTIVE) });
    // As in `set`: the cached keys are the passphrase's wallet, not this one.
    crate::pubkeys::forget();
}

/// Empty a string and wipe the bytes it held, tail included.
///
/// In place: `heapless::String::zeroize` writes the whole backing buffer and the length.
/// Taking the string out first would leave the wipe to a moved copy while the slot --
/// a static, here -- kept whatever the compiler chose not to overwrite.
fn wipe(s: &mut heapless::String<MAX_LEN>) {
    s.zeroize();
    s.clear();
}

/// A fingerprint as the screen writes it.
fn xfp_text(fp: [u8; 4]) -> heapless::String<12> {
    let [a, b, c, d] = fp;
    let mut s = heapless::String::new();
    let _ = write!(s, "{a:02X}{b:02X}{c:02X}{d:02X}");
    s
}

/// Settings -> Passphrase: type one, or restore one saved to the card.
pub(crate) fn screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    // A passphrase changes the seed that words stretch to. An XPRV or a single key has
    // no words, so there is nothing for one to change -- said, rather than taking a
    // passphrase that would silently do nothing.
    use crate::key::Loaded;
    if let Some(kind @ (Loaded::Xprv | Loaded::Wif)) = crate::key::loaded() {
        let what = if kind == Loaded::Xprv {
            "an XPRV has no words"
        } else {
            "a WIF key has no words"
        };
        menu::message(ui.panel, HEAD, what, "for a passphrase to change");
        menu::wait_for_any_key(ui);
        return;
    }

    // Stock goes straight to typing unless a saved-passphrase file is on the card; a
    // card read on every open is a mount and a wait, so the choice is asked instead.
    // Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §S2 [C]
    match menu::pick_row(ui, HEAD, "", &["Enter passphrase", "Restore saved"]) {
        Some(0) => enter(gate, login, ui),
        Some(_) => restore(gate, login, ui),
        None => {}
    }
}

/// Type a passphrase, see which wallet it opens, apply it -- and offer to save it.
fn enter(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    let Some(mut entry) = read(ui, HEAD) else {
        return;
    };
    if entry.is_empty() {
        // An empty passphrase is the plain wallet, which is what clearing means.
        clear();
        crate::catlog!("passphrase: cleared");
        // The status bar names the wallet in force, and the plain one's fingerprint is
        // not what was cached a moment ago. Derive it rather than leave the bar blank.
        #[cfg(feature = "board-q1")]
        crate::pubkeys::warm_fingerprint(gate, login, ui.panel);
        menu::message(ui.panel, HEAD, "cleared", "the plain wallet");
        menu::wait_for_any_key(ui);
        return;
    }

    let applied = apply(gate, login, ui, entry.as_str(), None);
    if let Some(fp) = applied {
        // Stock's "(1) = use AND save encrypted to MicroSD", asked as a question of its
        // own once the wallet is in force. Source: help-and-warning-screens.md §5 [C]
        menu::ask(
            ui.panel,
            "Save to card?",
            "encrypted; only",
            "these words open it",
        );
        if menu::confirmed(ui) {
            save(gate, login, ui, entry.as_str(), fp);
        }
    }
    // `Entry` wipes itself on drop as well; this is the explicit one.
    entry.clear();
}

/// Put `text` in force, show the wallet it opens, and keep it if the owner says so.
///
/// `expect`, when given, is the fingerprint a saved entry was labelled with: a wallet
/// that comes out differently is said before the question, as stock says it, since the
/// words in force may not be the ones the passphrase was saved under.
///
/// The fingerprint of the wallet now in force, or `None` if it was not applied.
fn apply(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    text: &str,
    expect: Option<[u8; 4]>,
) -> Option<[u8; 4]> {
    // What the status bar is naming now, to put back if this is not applied.
    #[cfg(feature = "board-q1")]
    let previous = crate::pubkeys::known_fingerprint();

    // Derive with it and show where it lands, before it is in force anywhere else.
    set(text);
    let Some(master) = menu::unlock_master(gate, login, ui, HEAD) else {
        // The seed could not be read, so nothing was proven: leave no passphrase in force.
        clear();
        #[cfg(feature = "board-q1")]
        crate::pubkeys::note_fingerprint(previous);
        return None;
    };
    let fingerprint = crate::keywork::run(|kw| master.fingerprint(kw));
    let mut busy = menu::Working::new(ui.panel, HEAD, "deriving");
    let address = menu::first_receive_address(&master, &mut busy, ui.panel);
    drop(master);

    let head = xfp_text(fingerprint);
    let shown = address.as_deref().unwrap_or("(no address)");
    // The event, never the fingerprint: the log is readable by any host, and a
    // fingerprint would let one match this passphrase wallet against PSBTs later.
    crate::catlog!("passphrase: set");

    if let Some(saved) = expect.filter(|&e| e != fingerprint) {
        // Not the wallet it was saved for: different words are in force, or the
        // entry was made elsewhere. The choice is still the owner's, once told.
        let mut said = heapless::String::<24>::new();
        let _ = write!(said, "saved as {}", xfp_text(saved));
        menu::message(
            ui.panel,
            "Not the same wallet",
            &said,
            "check the words in force",
        );
        menu::wait_for_any_key(ui);
    }

    menu::ask(ui.panel, head.as_str(), shown, "use this wallet?");
    if menu::confirmed(ui) {
        // This wallet is the one in force now, and its fingerprint was just derived --
        // so the bar gets it without a second stretch.
        #[cfg(feature = "board-q1")]
        crate::pubkeys::note_fingerprint(Some(fingerprint));
        #[cfg(not(feature = "board-mk3"))]
        crate::settings::open_wallet(gate, login, ui.panel, HEAD, fingerprint);
        menu::message(ui.panel, HEAD, "in force", "until reboot");
        menu::wait_for_any_key(ui);
        Some(fingerprint)
    } else {
        clear();
        #[cfg(feature = "board-q1")]
        crate::pubkeys::note_fingerprint(previous);
        menu::message(ui.panel, HEAD, "not applied", "the plain wallet");
        menu::wait_for_any_key(ui);
        None
    }
}

/// The file's key for the words in force, made where the entropy cannot be timed.
///
/// The entropy of the wallet the passphrase sits on -- the stored seed's, or a child's or
/// a loaded seed's -- read with the reading-seed screen in front of it, and wiped once
/// the key is out.
fn file_key(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) -> Option<pwsave::FileKey> {
    let (mut ent, len) = match menu::seed_entropy(gate, login, ui.panel, HEAD) {
        Ok(got) => got,
        Err(why) => {
            menu::message(ui.panel, HEAD, why, "any key to go back");
            menu::wait_for_any_key(ui);
            return None;
        }
    };
    let key = crate::keywork::run(|kw| pwsave::file_key(&ent[..len], kw));
    ent.zeroize();
    Some(key)
}

/// The file off the card, into a leased buffer: the buffer and how much of it is file.
///
/// `None` with a reason said if the card could not be read; a card with no such file is
/// an empty file, which is what "nothing saved yet" is.
fn read_file(ui: &mut Ui<'_>) -> Option<(crate::heap::Block, usize)> {
    let Some(mut held) = crate::heap::take(pwsave::FILE_MAX) else {
        menu::message(
            ui.panel,
            HEAD,
            "no memory for the file",
            "any key to go back",
        );
        menu::wait_for_any_key(ui);
        return None;
    };
    menu::card_wait(ui.panel, HEAD, "reading the card");
    let len = match crate::signtx::read_card_file(PATH, held.bytes()) {
        Ok(n) => n,
        Err("could not open file") => 0,
        Err(why) => {
            menu::message(ui.panel, HEAD, why, "any key to go back");
            menu::wait_for_any_key(ui);
            return None;
        }
    };
    Some((held, len))
}

/// Write the file back, or remove it once it holds nothing.
fn write_file(ui: &mut Ui<'_>, file: &[u8]) -> bool {
    menu::card_wait(ui.panel, HEAD, "writing the card");
    let res = if pwsave::entries(file).count() == 0 {
        menu::mount_card().and_then(|mut vol| {
            vol.remove_file(PATH)
                .and_then(|()| vol.flush())
                .map_err(|_| "could not remove the file")
        })
    } else {
        menu::write_card_file(PATH, file)
    };
    match res {
        Ok(()) => true,
        Err(why) => {
            menu::message(ui.panel, HEAD, why, "any key to go back");
            menu::wait_for_any_key(ui);
            false
        }
    }
}

/// Seal `text` into the card's file under the words in force, labelled `fp`.
fn save(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>, text: &str, fp: [u8; 4]) {
    let Some((mut held, len)) = read_file(ui) else {
        return;
    };
    let Some(key) = file_key(gate, login, ui) else {
        return;
    };
    // A fresh nonce from the generator whose outputs leave the device: GCM under a
    // repeated nonce would give away the XOR of two passphrases.
    let mut nonce = [0u8; pwsave::NONCE_LEN];
    if ui.protocol.generate(&mut nonce).is_err() {
        menu::message(ui.panel, HEAD, "no randomness", "for the file; not saved");
        menu::wait_for_any_key(ui);
        return;
    }
    // Sealed inside the masked region: the passphrase is half of the wallet.
    let sealed =
        crate::keywork::run(|_kw| pwsave::append(held.bytes(), len, &key, fp, &nonce, text));
    drop(key);
    let new_len = match sealed {
        Ok(n) => n,
        Err(pwsave::Error::Full) => {
            menu::message(ui.panel, HEAD, "the file is full", "delete one first");
            menu::wait_for_any_key(ui);
            return;
        }
        Err(pwsave::Error::BadMagic) => {
            menu::message(ui.panel, HEAD, "another file has", "that name on the card");
            menu::wait_for_any_key(ui);
            return;
        }
        Err(_) => {
            menu::message(ui.panel, HEAD, "could not seal it", "not saved");
            menu::wait_for_any_key(ui);
            return;
        }
    };
    if write_file(ui, &held.bytes()[..new_len]) {
        crate::catlog!("passphrase: saved to card");
        menu::message(ui.panel, "Saved", "to the card, under", "these words only");
        menu::wait_for_any_key(ui);
    }
}

/// Restore saved: the entries by fingerprint, then restore or delete the one chosen.
fn restore(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    let Some((mut held, len)) = read_file(ui) else {
        return;
    };
    let count = pwsave::entries(&held.bytes()[..len]).count();
    if count == 0 {
        menu::message(ui.panel, HEAD, "nothing saved", "on this card");
        menu::wait_for_any_key(ui);
        return;
    }
    // The labels, then the pick: `pick_row` wants `&str`s, so the text lives here.
    let mut labels: heapless::Vec<heapless::String<12>, { pwsave::MAX_ENTRIES }> =
        heapless::Vec::new();
    for e in pwsave::entries(&held.bytes()[..len]) {
        let mut l = heapless::String::new();
        let _ = write!(l, "[{}]", xfp_text(e.xfp));
        let _ = labels.push(l);
    }
    let rows: heapless::Vec<&str, { pwsave::MAX_ENTRIES }> =
        labels.iter().map(|l| l.as_str()).collect();
    let Some(i) = menu::pick_row(ui, "Restore saved", "by wallet fingerprint", &rows) else {
        return;
    };
    let Some(row) = menu::pick_row(ui, rows[i], "", &["Restore", "Delete"]) else {
        return;
    };
    if row == 1 {
        menu::ask(ui.panel, "Delete it?", rows[i], "the wallet is not touched");
        if !menu::confirmed(ui) {
            return;
        }
        let Ok(new_len) = pwsave::remove(held.bytes(), len, i) else {
            menu::message(ui.panel, HEAD, "could not remove it", "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        };
        if write_file(ui, &held.bytes()[..new_len]) {
            crate::catlog!("passphrase: saved entry deleted");
            menu::message(ui.panel, "Deleted", rows[i], "any key to go back");
            menu::wait_for_any_key(ui);
        }
        return;
    }

    let Some(key) = file_key(gate, login, ui) else {
        return;
    };
    // Opened inside the masked region, into a buffer wiped on every path out.
    let mut text = Zeroizing::new([0u8; pwsave::MAX_PASSPHRASE]);
    let opened = crate::keywork::run(|_kw| {
        let file = &held.bytes()[..len];
        let entry = pwsave::entry(file, i).ok_or(pwsave::Error::NoSuchEntry)?;
        let n = pwsave::open(&entry, &key, &mut text[..])?;
        Ok::<([u8; 4], usize), pwsave::Error>((entry.xfp, n))
    });
    drop(key);
    drop(held);
    let (saved_fp, n) = match opened {
        Ok(got) => got,
        Err(pwsave::Error::WrongKey) => {
            menu::message(ui.panel, HEAD, "not saved under", "the words in force");
            menu::wait_for_any_key(ui);
            return;
        }
        Err(_) => {
            menu::message(ui.panel, HEAD, "could not open it", "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        }
    };
    let Ok(passphrase) = core::str::from_utf8(&text[..n]) else {
        menu::message(ui.panel, HEAD, "could not open it", "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    };
    crate::catlog!("passphrase: restored from card");
    apply(gate, login, ui, passphrase, Some(saved_fp));
}

/// Type text. `None` if the owner backed out.
///
/// On a board with a keyboard the characters arrive as they are typed. On a numeric keypad
/// each key walks its own characters -- press `2` for `a`, again for `b` -- and moving to
/// another key, or confirming, settles the one before it. Cancel removes a character, and
/// cancel on an empty field backs out.
pub(crate) fn read(ui: &mut Ui<'_>, head: &str) -> Option<Entry> {
    let mut entry = Entry::new();
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();

    loop {
        draw(ui, head, &entry);
        menu::wait_for_release(ui);
        let mut redraw = false;
        while !redraw {
            let _ = crate::usbtask::pump();
            crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
            for k in keys.iter() {
                match k {
                    Key::Confirm => {
                        entry.commit();
                        return Some(entry);
                    }
                    Key::Cancel => {
                        if !entry.backspace() {
                            return None;
                        }
                        redraw = true;
                    }
                    // A keyboard's letters and symbols.
                    Key::Qr => {}
                    Key::Char(c) => {
                        entry.put(*c as char);
                        redraw = true;
                    }
                    Key::Digit(d) => {
                        #[cfg(feature = "board-q1")]
                        {
                            // The number row means digits here, not letters: this board has
                            // letters of its own.
                            entry.put((b'0' + *d) as char);
                        }
                        #[cfg(not(feature = "board-q1"))]
                        entry.press(*d);
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

/// The typing screen: what has been typed, and what the keys do.
///
/// The same card every other typing screen on this device draws
/// ([`catcard_ui::field`]), given three lines: a passphrase is long, and the widget
/// keeps the *end* of it on screen, which is where the typing is.
///
/// **Shown, not masked.** Whoever holds the device is the one typing, and a passphrase
/// typed blind on a keypad is a passphrase lost -- there is nothing to check it against
/// and no second entry to catch a slip. A wrong one silently opens a different wallet.
fn draw(ui: &mut Ui<'_>, head: &str, entry: &Entry) {
    use catcard_ui::canvas::Canvas as _;
    use catcard_ui::field::{self, Field};
    use catcard_ui::text::{centred, draw_text};

    /// Lines of the passphrase kept on screen at once.
    const LINES: usize = 3;
    let top_y = display::FIELD_TOP;
    let mut count = heapless::String::<24>::new();
    let _ = write!(count, "{} of {} characters", entry.len(), MAX_LEN);

    let body = display::LAYOUT.body;
    let fields = [Field::text("", entry.as_str()).lines(LINES).live(true)];

    display::draw_field_page(ui.panel, |c| {
        c.clear();
        let hx = centred(body, head, c.width());
        draw_text(
            c,
            body,
            hx,
            top_y.saturating_sub(body.line_height() + 4),
            head,
        );
        let mut y = field::stack(
            c,
            &display::LAYOUT,
            top_y,
            &fields,
            display::FIELD_SKIN,
            true,
        ) + 4;
        // What is on the keys, where the keys do not say. Only the numeric pad needs
        // it: the Q1 has the letters printed on it.
        #[cfg(not(feature = "board-q1"))]
        for line in [
            "2abc 3def 4ghi 5jkl",
            "6mno 7pqrs 8tuv 9wxyz",
            "0 space 1 symbols",
        ] {
            draw_text(c, body, centred(body, line, c.width()), y, line);
            y += body.line_height();
        }
        // The OLED has room for the legend or the count, not both, and someone typing
        // blind on a numeric keypad needs the legend.
        #[cfg(feature = "board-q1")]
        {
            draw_text(c, body, centred(body, &count, c.width()), y, &count);
            y += body.line_height();
        }
        #[cfg(not(feature = "board-q1"))]
        let _ = &count;
        let mut hint = heapless::String::<48>::new();
        let _ = write!(
            hint,
            "{} done   {} back",
            display::CONFIRM_KEY,
            display::CANCEL_KEY
        );
        draw_text(c, body, centred(body, &hint, c.width()), y, &hint);
    });
}
