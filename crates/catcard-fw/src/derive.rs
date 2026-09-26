//! BIP-85: children of the seed, shown -- and the ones that are keys, put in force.
//!
//! The seed is backed up once; everything else comes out of it on demand. This screen
//! derives one child, shows it, and for the three that are wallets -- words, an XPRV, a
//! WIF key -- offers to work in it. Nothing is stored: the same seed gives the same child
//! again whenever it is asked for.
//!
//! Every child comes from the **root** without its passphrase ([`menu::bip85_parent`]),
//! whichever wallet is in force when it is asked for. So the child shown here is the one
//! the key menu loads, and the same one again from anywhere.
//!
//! A child is shown, not exported to a card. What is on screen here -- words, a key, a
//! password -- is the whole secret of another wallet or another account, and writing it to
//! removable media is a decision with different consequences from writing a descriptor.
//! Copying it down is the owner's move to make.
//!
//! # The index is capped
//!
//! A child is reproducible only by its path, and the index is the part of the path the
//! owner has to remember. So the index is refused past 9999 unless the owner has lifted
//! the cap in Danger zone -> `B85 Idx Values` ([`index_values_screen`]), after a warning,
//! as stock does; lifted, it reaches `2^31 - 1`, which is as far as BIP-32 hardens.
//! Source: hw-reference/firmware-features.md §2 "BIP-85" [C]

use catcard_callgate::Callgate;
use catcard_wallet::bip85;
use core::fmt::Write as _;
use zeroize::{Zeroize, Zeroizing};

use crate::display;
use crate::menu;
use crate::ui::Ui;

const HEAD: &str = "BIP-85";

/// What can be derived.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum Kind {
    /// A BIP-39 phrase of this many words.
    Words(u32),
    Xprv,
    Wif,
    /// A base64 password of this many characters, 20 to 86.
    Password(u32),
    /// This many bytes as hex: 32 or 64, the two stock offers.
    Hex(u32),
}

/// The list, in the order it is shown. Every word count BIP-39 defines: the BIP names 12,
/// 18 and 24, and 15 and 21 derive by the same rule -- fewer wallets will reproduce them.
/// Then the key shapes, a password -- whose length is asked next, 21 unless said otherwise
/// -- and the two hex sizes stock offers.
/// Source: hw-reference/firmware-features.md §2 "BIP-85 ... hex (32/64 B), and passwords" [C]
const ROWS: &[&str] = &[
    "12 words",
    "15 words",
    "18 words",
    "21 words",
    "24 words",
    "XPRV",
    "WIF key",
    "Password",
    "32 bytes hex",
    "64 bytes hex",
];
const KINDS: [Kind; 10] = [
    Kind::Words(12),
    Kind::Words(15),
    Kind::Words(18),
    Kind::Words(21),
    Kind::Words(24),
    Kind::Xprv,
    Kind::Wif,
    Kind::Password(bip85::PWD_DEFAULT_LEN),
    Kind::Hex(32),
    Kind::Hex(64),
];
const _: () = assert!(ROWS.len() == KINDS.len());

impl Kind {
    /// The BIP-85 path this uses, for the screen to show.
    fn path(self, index: u32) -> heapless::String<48> {
        let mut s = heapless::String::new();
        let _ = match self {
            Kind::Words(n) => write!(s, "m/83696968h/39h/0h/{n}h/{index}h"),
            Kind::Xprv => write!(s, "m/83696968h/32h/{index}h"),
            Kind::Wif => write!(s, "m/83696968h/2h/{index}h"),
            Kind::Password(len) => write!(s, "m/83696968h/707764h/{len}h/{index}h"),
            Kind::Hex(n) => write!(s, "m/83696968h/128169h/{n}h/{index}h"),
        };
        s
    }
}

/// Whether an index past the cap may be typed, as the wallet in force's settings say.
///
/// The mk3 has no settings store, so there the cap is simply the cap.
fn index_unlimited() -> bool {
    crate::prefs::current().b85_unlimited
}

/// The index of a child, typed and checked against the cap.
///
/// Refused past 9999 unless the cap is lifted, and past `2^31 - 1` regardless -- said on
/// screen, then asked again, rather than letting a mistyped digit derive a child at an
/// index nobody wrote down. `None` if the owner backed out.
fn ask_capped_index(ui: &mut Ui<'_>, what: &str) -> Option<u32> {
    loop {
        let index = menu::ask_index(ui, HEAD, what)?;
        if bip85::index_allowed(index, index_unlimited()) {
            return Some(index);
        }
        let mut said = heapless::String::<48>::new();
        let _ = write!(said, "index over {}", bip85::INDEX_CAP);
        let (a, b) = if index > bip85::INDEX_MAX {
            ("past what BIP-32", "can harden")
        } else {
            (said.as_str(), "lift it: Danger zone")
        };
        menu::message(ui.panel, HEAD, a, b);
        menu::wait_for_any_key(ui);
    }
}

/// The length of a password child: 20 to 86, and 21 when nothing is typed.
///
/// Asked after the kind, before the index, so the path on screen carries both. `None` if
/// the owner backed out.
fn ask_password_length(ui: &mut Ui<'_>) -> Option<u32> {
    loop {
        let len = menu::ask_number(
            ui,
            HEAD,
            Some(("child", "Password")),
            "length",
            "empty = 21 characters",
        )?;
        let len = if len == 0 {
            bip85::PWD_DEFAULT_LEN
        } else {
            len
        };
        if (bip85::PWD_MIN_LEN..=bip85::PWD_MAX_LEN).contains(&len) {
            return Some(len);
        }
        let mut said = heapless::String::<48>::new();
        let _ = write!(
            said,
            "{} to {} characters",
            bip85::PWD_MIN_LEN,
            bip85::PWD_MAX_LEN
        );
        menu::message(ui.panel, HEAD, "a password is", &said);
        menu::wait_for_any_key(ui);
    }
}

/// A child the owner chose to work in. Wiped when dropped.
pub(crate) enum Chosen {
    /// Words: loaded by their place in the tree, as [`crate::key::Source::Bip85`], and
    /// derived again from the root whenever a screen needs the seed.
    Words { words: u32, index: u32 },
    /// An XPRV: the chain code, then the key.
    Xprv { chain_code: [u8; 32], key: [u8; 32] },
    /// A WIF key.
    Wif { key: [u8; 32] },
}

impl Drop for Chosen {
    fn drop(&mut self) {
        match self {
            Chosen::Words { .. } => {}
            Chosen::Xprv { chain_code, key } => {
                chain_code.zeroize();
                key.zeroize();
            }
            Chosen::Wif { key } => key.zeroize(),
        }
    }
}

/// Characters the longest answer needs: a 24-word phrase.
const MAX_OUT: usize = catcard_wallet::bip39::MAX_PHRASE_LEN;

/// What a child is written as, and the key it is if it is one.
type Derived = (Zeroizing<[u8; MAX_OUT]>, usize, Option<Chosen>);

/// Pick a child, derive it and show it. `Some` if the owner chose to work in it.
pub(crate) fn bip85(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) -> Option<Chosen> {
    let (row, kind, index) = loop {
        let row = menu::pick_row(ui, HEAD, "derive a child", ROWS)?;
        // A password's length is part of its path, so it is asked with the kind.
        let kind = match KINDS[row] {
            Kind::Password(_) => match ask_password_length(ui) {
                Some(len) => Kind::Password(len),
                None => continue,
            },
            other => other,
        };
        // Backing out of the index goes back to the list, not out of BIP-85: they are a
        // pair, and getting the second wrong should not cost the first.
        if let Some(index) = ask_capped_index(ui, ROWS[row]) {
            break (row, kind, index);
        }
    };

    let master = match menu::bip85_parent(gate, login, ui.panel, HEAD) {
        Ok(m) => m,
        Err(why) => {
            menu::message(ui.panel, HEAD, why, "any key to go back");
            menu::wait_for_any_key(ui);
            return None;
        }
    };
    // Derived and written out inside one masked region: what comes out is a secret in its
    // own right, and the derivation is private-key work.
    let derived = crate::keywork::run(|kw| derive(&master, kind, index, kw));
    drop(master);

    let (text, len, chosen) = match derived {
        Ok(d) => d,
        Err(why) => {
            crate::catlog!("bip85: {} at {}: {}", ROWS[row], index, why);
            menu::message(ui.panel, HEAD, why, "any key to go back");
            menu::wait_for_any_key(ui);
            return None;
        }
    };
    crate::catlog!("bip85: {} at index {}", ROWS[row], index);
    let text = core::str::from_utf8(&text[..len]).unwrap_or("");
    // A password can go out as keystrokes instead of being copied down, with the
    // keyboard on: Confirm on its screen is "type into host", as stock's (6) is.
    // Source: help-and-warning-screens.md "BIP-85 result / switch" [C]
    let typeable = matches!(kind, Kind::Password(_)) && keyboard_on();
    let take = show(ui, kind, ROWS[row], index, text, chosen.is_some(), typeable);
    #[cfg(not(feature = "board-mk3"))]
    if take && typeable {
        crate::usbkbd::send_screen(ui, HEAD, &kind.path(index), text);
    }
    // `text` borrows the `Zeroizing` buffer, wiped as it goes out of scope here.
    chosen.filter(|_| take)
}

/// Whether `Keyboard EMU` is on. The mk3 has no settings store to turn it on with, and
/// no keyboard interface built, so there it never is.
fn keyboard_on() -> bool {
    #[cfg(not(feature = "board-mk3"))]
    {
        crate::usbtask::keyboard_on()
    }
    #[cfg(feature = "board-mk3")]
    {
        false
    }
}

/// Main menu → Type Passwords: a BIP-85 password child typed into the host, not shown.
///
/// Stock's row, on the menu only while `Keyboard EMU` is on. The length and the index are
/// asked as the BIP-85 screen asks them and the child is derived from the root the same
/// way; the keyboard screen then asks before a keystroke goes out. On the Q1 the Secure
/// Notes passwords are offered beside it, since they are the other thing a host's login
/// form wants.
/// Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §B3 "Type Passwords" [C]
#[cfg(not(feature = "board-mk3"))]
pub(crate) fn type_password_screen(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) {
    const TYPE_HEAD: &str = "Type Passwords";
    #[cfg(feature = "board-q1")]
    if crate::prefs::current().notes == Some(true) {
        match menu::pick_row(ui, TYPE_HEAD, "", &["BIP-85 password", "Secure Notes"]) {
            Some(0) => {}
            Some(_) => return crate::notes::type_passwords(gate, login, ui),
            None => return,
        }
    }
    let Some(len) = ask_password_length(ui) else {
        return;
    };
    let Some(index) = ask_capped_index(ui, "Password") else {
        return;
    };
    let master = match menu::bip85_parent(gate, login, ui.panel, TYPE_HEAD) {
        Ok(m) => m,
        Err(why) => {
            menu::message(ui.panel, TYPE_HEAD, why, "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        }
    };
    let kind = Kind::Password(len);
    let derived = crate::keywork::run(|kw| derive(&master, kind, index, kw));
    drop(master);
    let (text, n, _) = match derived {
        Ok(d) => d,
        Err(why) => {
            menu::message(ui.panel, TYPE_HEAD, why, "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        }
    };
    crate::catlog!("bip85: password child at index {} to the keyboard", index);
    let password = core::str::from_utf8(&text[..n]).unwrap_or("");
    crate::usbkbd::send_screen(ui, TYPE_HEAD, &kind.path(index), password);
    // `text` is the `Zeroizing` buffer; it is wiped here, typed or not.
}

fn derive(
    master: &catcard_wallet::bip32::ExtendedPrivKey,
    kind: Kind,
    index: u32,
    kw: &catcard_wallet::KeyWork,
) -> Result<Derived, &'static str> {
    const BAD: &str = "could not derive it";
    let mut buf = Zeroizing::new([0u8; MAX_OUT]);
    let out = &mut buf[..];
    let (len, chosen) = match kind {
        Kind::Words(words) => {
            let (entropy, n) = bip85::words_entropy(master, words, index, kw).map_err(|_| BAD)?;
            let mnemonic =
                catcard_wallet::bip39::Mnemonic::from_entropy(&entropy.as_bytes()[..n], kw)
                    .map_err(|_| BAD)?;
            (mnemonic.render(out), Some(Chosen::Words { words, index }))
        }
        Kind::Xprv => {
            let child = bip85::xprv(master, index, kw).map_err(|_| BAD)?;
            let len = child.write_base58(out, kw).map_err(|_| BAD)?;
            let chosen = Chosen::Xprv {
                chain_code: child.chain_code,
                key: *child.secret_bytes(),
            };
            (len, Some(chosen))
        }
        Kind::Wif => {
            let chosen = Chosen::Wif {
                key: bip85::wif_secret(master, index, kw).map_err(|_| BAD)?,
            };
            let Chosen::Wif { key } = &chosen else {
                return Err(BAD);
            };
            (
                bip85::encode_wif(key, out, kw).map_err(|_| BAD)?,
                Some(chosen),
            )
        }
        Kind::Password(len) => (
            bip85::password(master, len, index, out, kw).map_err(|_| BAD)?,
            None,
        ),
        Kind::Hex(n) => (
            bip85::hex(master, n, index, out, kw).map_err(|_| BAD)?,
            None,
        ),
    };
    Ok((buf, len, chosen))
}

/// Danger zone -> B85 Idx Values: lift the index cap from 9999 to `2^31 - 1`, or put it
/// back.
///
/// Warned before it is lifted, as stock warns: the cap is what keeps a child at an index
/// its owner will remember, and the switch is kept in the wallet's own settings file, so
/// it follows the wallet rather than the device. Not on the mk3, which has no settings
/// store: there the cap is simply the cap.
/// Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §DZ "B85 Idx Values" [C]
#[cfg(not(feature = "board-mk3"))]
pub(crate) fn index_values_screen(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) {
    const SWITCH: &str = "B85 Idx Values";
    let now = crate::prefs::current();
    let Some(want) = menu::pick_switch(ui, SWITCH, now.b85_unlimited) else {
        return;
    };
    if want {
        menu::ask(
            ui.panel,
            SWITCH,
            "any index up to 2^31-1;",
            "one you forget is lost",
        );
        if !menu::confirmed(ui) {
            return;
        }
    }
    menu::save_pref(
        gate,
        login,
        ui,
        SWITCH,
        (
            catcard_settings::prefs::B85_INDEX,
            if want { "1" } else { "0" },
        ),
        crate::prefs::Prefs {
            b85_unlimited: want,
            ..now
        },
        if want { "cap lifted" } else { "capped at 9999" },
    );
}

/// Show the child, scrollable. True if the owner chose to act on it: to work in it when
/// `loadable`, or to type it into the host when `typeable`. A hex string is neither, and
/// its screen only says to write it down.
fn show(
    ui: &mut Ui<'_>,
    kind: Kind,
    label: &str,
    index: u32,
    text: &str,
    loadable: bool,
    typeable: bool,
) -> bool {
    use catcard_ui::scroll::{Line, ScrollView};
    let path = kind.path(index);
    let mut hint = heapless::String::<48>::new();
    if loadable {
        let _ = write!(
            hint,
            "{} work in it   {} back",
            display::CONFIRM_KEY,
            display::CANCEL_KEY
        );
    } else if typeable {
        let _ = write!(
            hint,
            "{} type into host   {} back",
            display::CONFIRM_KEY,
            display::CANCEL_KEY
        );
    } else {
        let _ = hint.push_str("write it down; it is not stored");
    }
    let mut doc: heapless::Vec<Line, 8> = heapless::Vec::new();
    let _ = doc.push(Line::title(label));
    let _ = doc.push(Line::body(text).wrapped());
    let _ = doc.push(Line::body(path.as_str()).small().wrapped());
    let _ = doc.push(Line::body(hint.as_str()).small().wrapped());
    let mut view = ScrollView::build(&doc, display::SCREEN_W, display::SCREEN_H, display::FONTS);
    menu::scroll_choice(ui, &mut view) && (loadable || typeable)
}
