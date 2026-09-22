//! The BIP-39 passphrase: a second wallet from the same words.
//!
//! A passphrase is not a password on the seed. Every passphrase gives a *valid* wallet, so
//! there is nothing to be wrong about and nothing the device can check: a typo does not
//! fail, it silently opens a different, empty wallet. The only defence is showing the owner
//! which wallet they landed in -- the master fingerprint and the first receive address --
//! before anything is done with it, which is what [`screen`] does.
//!
//! It is never stored. It lives in RAM for this session, is wiped when cleared or when the
//! device reboots, and is mixed into the seed on every derivation
//! ([`crate::menu::unlock_master`]), so the address explorer, the wallet export and the
//! signing path all follow it without knowing it exists.

use catcard_callgate::Callgate;
use catcard_ui::keypad::{Event, KEYS, Key};
use catcard_ui::textentry::{Entry, MAX_LEN};
use core::fmt::Write as _;
use zeroize::Zeroize;

use crate::display;
use crate::menu;
use crate::ui::Ui;

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
fn wipe(s: &mut heapless::String<MAX_LEN>) {
    let mut bytes = core::mem::take(s).into_bytes();
    bytes.zeroize();
}

/// Type a passphrase, see which wallet it opens, and apply it.
pub(crate) fn screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    const HEAD: &str = "Passphrase";

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

    // What the status bar is naming now, to put back if this is not applied.
    #[cfg(feature = "board-q1")]
    let previous = crate::pubkeys::known_fingerprint();

    // Derive with it and show where it lands, before it is in force anywhere else.
    set(entry.as_str());
    entry.clear();
    let Some(master) = menu::unlock_master(gate, login, ui, HEAD) else {
        // The seed could not be read, so nothing was proven: leave no passphrase in force.
        clear();
        #[cfg(feature = "board-q1")]
        crate::pubkeys::note_fingerprint(previous);
        return;
    };
    let fingerprint = crate::keywork::run(|kw| master.fingerprint(kw));
    let mut busy = menu::Working::new(ui.panel, HEAD, "deriving");
    let address = menu::first_receive_address(&master, &mut busy, ui.panel);
    drop(master);

    let [a, b, c, d] = fingerprint;
    let mut head = heapless::String::<32>::new();
    let _ = write!(head, "{a:02X}{b:02X}{c:02X}{d:02X}");
    let shown = address.as_deref().unwrap_or("(no address)");
    crate::catlog!("passphrase: set, fingerprint {}", head.as_str());

    menu::ask(ui.panel, head.as_str(), shown, "use this wallet?");
    if menu::confirmed(ui) {
        // This wallet is the one in force now, and its fingerprint was just derived --
        // so the bar gets it without a second stretch.
        #[cfg(feature = "board-q1")]
        crate::pubkeys::note_fingerprint(Some(fingerprint));
        #[cfg(not(feature = "board-mk3"))]
        crate::settings::open_wallet(gate, login, ui.panel, HEAD, fingerprint);
        menu::message(ui.panel, HEAD, "in force", "until reboot");
    } else {
        clear();
        #[cfg(feature = "board-q1")]
        crate::pubkeys::note_fingerprint(previous);
        menu::message(ui.panel, HEAD, "not applied", "the plain wallet");
    }
    menu::wait_for_any_key(ui);
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
