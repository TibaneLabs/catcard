//! BIP-85: showing a child of the seed.
//!
//! The seed is backed up once; everything else comes out of it on demand. This screen
//! derives one child and shows it, and nothing is stored: the same words give the same
//! child again whenever it is asked for.
//!
//! A child is shown, not exported to a card. What is on screen here -- words, a key, a
//! password -- is the whole secret of another wallet or another account, and writing it to
//! removable media is a decision with different consequences from writing a descriptor.
//! Copying it down is the owner's move to make.

use catcard_callgate::Callgate;
use catcard_wallet::bip85;
use core::fmt::Write as _;
use zeroize::Zeroize;

use crate::display;
use crate::menu;
use crate::ui::Ui;

/// What can be derived, in the order the menu lists them.
#[derive(Copy, Clone, PartialEq, Eq)]
pub(crate) enum Kind {
    Words24,
    Words12,
    Xprv,
    Wif,
    Password,
    Hex32,
}

impl Kind {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Kind::Words24 => "24 words",
            Kind::Words12 => "12 words",
            Kind::Xprv => "XPRV",
            Kind::Wif => "WIF key",
            Kind::Password => "Password",
            Kind::Hex32 => "32 bytes hex",
        }
    }

    /// The BIP-85 path this uses, for the screen to show.
    fn path(self, index: u32) -> heapless::String<48> {
        let mut s = heapless::String::new();
        let _ = match self {
            Kind::Words24 => write!(s, "m/83696968h/39h/0h/24h/{index}h"),
            Kind::Words12 => write!(s, "m/83696968h/39h/0h/12h/{index}h"),
            Kind::Xprv => write!(s, "m/83696968h/32h/{index}h"),
            Kind::Wif => write!(s, "m/83696968h/2h/{index}h"),
            Kind::Password => write!(s, "m/83696968h/707764h/21h/{index}h"),
            Kind::Hex32 => write!(s, "m/83696968h/128169h/32h/{index}h"),
        };
        s
    }
}

/// Characters the longest answer needs: a 24-word phrase.
const MAX_OUT: usize = catcard_wallet::bip39::MAX_PHRASE_LEN;

/// Derive `kind` at `index` and show it.
pub(crate) fn screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>, kind: Kind) {
    const HEAD: &str = "Derive";

    let index = match pick_index(ui, kind) {
        Some(i) => i,
        None => return,
    };
    let Some(master) = menu::unlock_master(gate, login, ui, HEAD) else {
        return;
    };

    let mut busy = menu::Working::new(ui.panel, HEAD, kind.label());
    // The child is derived and rendered inside one masked region: what comes out is a
    // secret in its own right, and the derivation is private-key work.
    let shown = crate::keywork::run(|kw| {
        let mut out: heapless::String<MAX_OUT> = heapless::String::new();
        let mut buf = [0u8; MAX_OUT];
        let written = match kind {
            Kind::Words24 | Kind::Words12 => {
                let words = if kind == Kind::Words24 { 24 } else { 12 };
                let (entropy, len) = bip85::words_entropy(&master, words, index, kw)
                    .map_err(|_| "could not derive it")?;
                let mnemonic =
                    catcard_wallet::bip39::Mnemonic::from_entropy(&entropy.as_bytes()[..len], kw)
                        .map_err(|_| "could not derive it")?;
                Ok(mnemonic.render(&mut buf))
            }
            Kind::Xprv => {
                let child = bip85::xprv(&master, index, kw).map_err(|_| "could not derive it")?;
                child
                    .write_base58(&mut buf, kw)
                    .map_err(|_| "could not derive it")
            }
            Kind::Wif => {
                bip85::wif(&master, index, &mut buf, kw).map_err(|_| "could not derive it")
            }
            Kind::Password => {
                bip85::password(&master, 21, index, &mut buf, kw).map_err(|_| "could not derive it")
            }
            Kind::Hex32 => {
                bip85::hex(&master, 32, index, &mut buf, kw).map_err(|_| "could not derive it")
            }
        }?;
        let text = core::str::from_utf8(&buf[..written]).map_err(|_| "could not show it")?;
        let _ = out.push_str(text);
        buf.zeroize();
        Ok(out)
    });
    busy.tick(ui.panel);
    drop(master);

    let mut shown = match shown {
        Ok(s) => s,
        Err(why) => {
            crate::catlog!("derive: {}", why);
            menu::message(ui.panel, HEAD, why, "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        }
    };
    crate::catlog!("derive: {} at index {}", kind.label(), index);
    show(ui, kind, index, shown.as_str());
    // The answer leaves no copy behind on the way out.
    let mut bytes = core::mem::take(&mut shown).into_bytes();
    bytes.zeroize();
}

/// Choose the index. Up and down move it, confirm accepts, cancel backs out.
fn pick_index(ui: &mut Ui<'_>, kind: Kind) -> Option<u32> {
    use catcard_ui::keypad::{Event, KEYS, Key};
    use catcard_ui::scroll::{Line, ScrollView, render};

    let mut index: u32 = 0;
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        let path = kind.path(index);
        let mut line = heapless::String::<32>::new();
        let _ = write!(line, "index {index}");
        let mut hint = heapless::String::<48>::new();
        let _ = write!(
            hint,
            "{} derive   {} back",
            display::CONFIRM_KEY,
            display::CANCEL_KEY
        );
        let mut doc: heapless::Vec<Line, 6> = heapless::Vec::new();
        let _ = doc.push(Line::title(kind.label()));
        let _ = doc.push(Line::body(line.as_str()));
        let _ = doc.push(Line::body(path.as_str()).small().wrapped());
        let _ = doc.push(Line::body("up/down index").small());
        let _ = doc.push(Line::body(hint.as_str()).small());
        let view = ScrollView::build(&doc, display::SCREEN_W, display::SCREEN_H, display::FONTS);
        display::draw(ui.panel, |c| render(c, &view));

        menu::wait_for_release(ui);
        loop {
            let _ = crate::usbtask::pump();
            crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
            let mut moved = false;
            for k in keys.iter() {
                match k {
                    Key::Confirm => return Some(index),
                    Key::Cancel => return None,
                    Key::Digit(8) => {
                        index = index.saturating_add(1);
                        moved = true;
                    }
                    Key::Digit(5) => {
                        index = index.saturating_sub(1);
                        moved = true;
                    }
                    _ => {}
                }
            }
            if moved {
                break;
            }
            display::idle(ui.panel);
        }
    }
}

/// Show the child, scrollable, until a key is pressed.
fn show(ui: &mut Ui<'_>, kind: Kind, index: u32, text: &str) {
    use catcard_ui::scroll::{Line, ScrollView};
    let path = kind.path(index);
    let mut doc: heapless::Vec<Line, 8> = heapless::Vec::new();
    let _ = doc.push(Line::title(kind.label()));
    let _ = doc.push(Line::body(text).wrapped());
    let _ = doc.push(Line::body(path.as_str()).small().wrapped());
    let _ = doc.push(
        Line::body("write it down; it is not stored")
            .small()
            .wrapped(),
    );
    let mut view = ScrollView::build(&doc, display::SCREEN_W, display::SCREEN_H, display::FONTS);
    let _ = menu::scroll_choice(ui, &mut view);
}
