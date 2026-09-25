//! Does this address belong to this device?
//!
//! The question a wallet cannot answer for you honestly: a watch-only wallet on a computer
//! shows an address and says it is yours, and the computer is the thing you do not trust.
//! So the address is typed in here and the device walks its own derivations looking for it.
//! A match comes back with the path that produced it; no match comes back as no match,
//! never as a shrug.
//!
//! The search is bounded and says what it covered. An address further out than
//! [`INDEX_LIMIT`], or in an account past [`ACCOUNT_LIMIT`], is not found -- and the screen
//! says how far it looked, because "not mine" and "not looked at" are different answers.

use catcard_callgate::Callgate;
use catcard_ui::keypad::{Event, KEYS, Key};
use catcard_ui::textentry::Entry;
use catcard_wallet::address::{self, AddressKind};
use catcard_wallet::bip32::{ChildNumber, ExtendedPubKey};
use core::fmt::Write as _;

use crate::display;
use crate::menu;
use crate::ui::Ui;

/// Addresses searched per chain, from zero.
///
/// A hundred each way is a wide gap by any wallet's standards; the cost is one elliptic
/// curve multiplication per address, and the screen shows it progressing.
pub const INDEX_LIMIT: u32 = 100;

/// Accounts searched, from zero.
pub const ACCOUNT_LIMIT: u32 = 3;

/// Address types searched, in the order most wallets use them.
const KINDS: [AddressKind; 4] = [
    AddressKind::P2wpkh,
    AddressKind::P2shP2wpkh,
    AddressKind::P2pkh,
    AddressKind::P2tr,
];

/// Where an address was found.
struct Found {
    kind: AddressKind,
    account: u32,
    chain: u32,
    index: u32,
}

/// Type an address and say whether this wallet can spend it.
pub(crate) fn screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    const HEAD: &str = "Verify address";

    let Some(typed) = read_address(ui, HEAD) else {
        return;
    };
    let wanted = typed.as_str().trim();
    if wanted.is_empty() {
        return;
    }
    // Bech32 is case-insensitive and usually written lower case; base58 is not, so the
    // comparison is done on what the device produces against what was typed, with only
    // bech32 folded.
    let mut lower: heapless::String<{ address::MAX_ADDRESS_LEN }> = heapless::String::new();
    for c in wanted.chars() {
        let _ = lower.push(c.to_ascii_lowercase());
    }

    let Some(master) = menu::unlock_master(gate, login, ui, HEAD) else {
        return;
    };

    let mut busy = menu::Working::new(ui.panel, HEAD, "searching");
    let mut found = None;
    'search: for kind in KINDS {
        for account in 0..ACCOUNT_LIMIT {
            for chain in 0..2 {
                let Some(chain_key) =
                    menu::chain_key(&master, kind, account, chain, &mut busy, ui.panel)
                else {
                    continue;
                };
                if let Some(index) = walk(&chain_key, kind, &lower, wanted) {
                    found = Some(Found {
                        kind,
                        account,
                        chain,
                        index,
                    });
                    break 'search;
                }
                busy.tick(ui.panel);
            }
        }
    }
    drop(master);

    match found {
        Some(f) => {
            let mut path = heapless::String::<48>::new();
            let _ = write!(
                path,
                "m/{}h/0h/{}h/{}/{}",
                f.kind.bip44_purpose(),
                f.account,
                f.chain,
                f.index
            );
            crate::catlog!("verify: found at {}", path.as_str());
            menu::message(
                ui.panel,
                "Yours",
                path.as_str(),
                if f.chain == 1 { "change" } else { "receive" },
            );
        }
        None => {
            let mut note = heapless::String::<48>::new();
            let _ = write!(note, "searched {} per chain", INDEX_LIMIT);
            crate::catlog!("verify: no match within the search");
            menu::message(ui.panel, "Not found", note.as_str(), "not this wallet's");
        }
    }
    menu::wait_for_any_key(ui);
}

/// Walk one chain's addresses looking for `wanted` (or its lower-case form for bech32).
fn walk(chain_key: &ExtendedPubKey, kind: AddressKind, lower: &str, exact: &str) -> Option<u32> {
    let mut buf = [0u8; address::MAX_ADDRESS_LEN];
    for index in 0..INDEX_LIMIT {
        let Ok(child) = ChildNumber::normal(index).and_then(|c| chain_key.derive_child(c)) else {
            continue;
        };
        let Ok(n) = address::encode(kind, crate::prefs::network(), &child.public_key, &mut buf) else {
            continue;
        };
        let made = core::str::from_utf8(&buf[..n]).unwrap_or("");
        let hit = if kind.is_bech32() {
            made.eq_ignore_ascii_case(lower)
        } else {
            made == exact
        };
        if hit {
            return Some(index);
        }
    }
    None
}

/// Type an address. `None` if the owner backed out.
///
/// Addresses are long, so this takes them a character at a time the same way the passphrase
/// screen does -- and on a board with a keyboard, straight from it.
fn read_address(ui: &mut Ui<'_>, head: &str) -> Option<Entry> {
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
                    Key::Qr => {}
                    Key::Char(c) => {
                        entry.put(*c as char);
                        redraw = true;
                    }
                    Key::Digit(d) => {
                        #[cfg(feature = "board-q1")]
                        entry.put((b'0' + *d) as char);
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

fn draw(ui: &mut Ui<'_>, head: &str, entry: &Entry) {
    use catcard_ui::scroll::{Line, ScrollView, render};

    let mut hint = heapless::String::<48>::new();
    let _ = write!(
        hint,
        "{} search   {} back",
        display::CONFIRM_KEY,
        display::CANCEL_KEY
    );
    let mut doc: heapless::Vec<Line, 8> = heapless::Vec::new();
    let _ = doc.push(Line::title(head));
    let _ = doc.push(Line::body(entry.as_str()).wrapped());
    #[cfg(not(feature = "board-q1"))]
    {
        let _ = doc.push(Line::body("2abc 3def 4ghi 5jkl").small());
        let _ = doc.push(Line::body("6mno 7pqrs 8tuv 9wxyz").small());
        let _ = doc.push(Line::body("same key again to cycle").small());
    }
    let _ = doc.push(Line::body(hint.as_str()).small());
    let view = ScrollView::build(&doc, display::SCREEN_W, display::SCREEN_H, display::FONTS);
    display::draw(ui.panel, |c| render(c, &view));
}
