//! Signing a message with one of the wallet's addresses.
//!
//! Proof of control without a transaction: the owner types a message, the device signs it
//! with the key behind one of its addresses, and the result is written in the armoured form
//! every verifier reads. Nothing here can move coins -- the signed digest carries the
//! "Bitcoin Signed Message" prefix, so it can never be a transaction's digest.
//!
//! Before the signature is shown, the device recovers the public key from it and checks it
//! against the key that signed. A signature that does not verify is not handed to anyone.

use catcard_callgate::Callgate;
use catcard_ui::keypad::{Event, KEYS, Key};
use catcard_ui::textentry::Entry;
use catcard_wallet::address::{self, AddressKind};
use catcard_wallet::bip32::{ChildNumber, Network};
use catcard_wallet::message;
use core::fmt::Write as _;
use zeroize::Zeroize;

use crate::display;
use crate::menu;
use crate::ui::Ui;

/// Where the signed message is written.
const FILE_NAME: &str = "/SIGNED.TXT";

/// The address the message is signed with: the wallet's first native-segwit receive
/// address, `m/84h/0h/0h/0/0`.
///
/// One address rather than a choice, for now: it is the one a watch-only wallet shows
/// first, and the file says which address signed, so a verifier needs no more. Choosing a
/// path belongs with the custom-path work in the address explorer.
const PATH: [u32; 5] = [84 | 0x8000_0000, 0x8000_0000, 0x8000_0000, 0, 0];
const KIND: AddressKind = AddressKind::P2wpkh;

/// Type a message, sign it, and write it to the card.
pub(crate) fn screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    const HEAD: &str = "Sign message";

    let Some(typed) = read_message(ui, HEAD) else {
        return;
    };
    let text = typed.as_str();
    if text.is_empty() {
        return;
    }
    let Some(master) = menu::unlock_master(gate, login, ui, HEAD) else {
        return;
    };

    let mut busy = menu::Working::new(ui.panel, HEAD, "signing");
    let signed = crate::keywork::run(|kw| {
        let mut here = master.clone();
        for &step in &PATH {
            here = match here.derive_child(ChildNumber(step), kw) {
                Ok(k) => k,
                Err(_) => return Err("key derivation failed"),
            };
        }
        let mut secret = *here.secret_bytes();
        let sig = message::sign(text, &secret, KIND, kw);
        secret.zeroize();
        let sig = sig.map_err(describe)?;
        // Check our own work: recover the key from the signature and compare it with the
        // one that signed. A signature that does not recover is worse than none.
        let pubkey = here.public_key(kw);
        match message::recover(text, &sig) {
            Ok((recovered, _)) if recovered == pubkey => {}
            _ => return Err("signature did not verify"),
        }
        let mut buf = [0u8; address::MAX_ADDRESS_LEN];
        let n = address::encode(KIND, Network::Mainnet, &pubkey, &mut buf)
            .map_err(|_| "address failed")?;
        let mut addr: heapless::String<{ address::MAX_ADDRESS_LEN }> = heapless::String::new();
        addr.push_str(core::str::from_utf8(&buf[..n]).unwrap_or(""))
            .map_err(|_| "address failed")?;
        Ok((sig, addr))
    });
    busy.tick(ui.panel);
    drop(master);

    let (sig, addr) = match signed {
        Ok(v) => v,
        Err(why) => {
            crate::catlog!("message: {}", why);
            menu::message(ui.panel, HEAD, why, "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        }
    };
    let mut armoured = [0u8; message::MAX_ARMOURED];
    let Ok(n) = message::armour(&sig, &mut armoured) else {
        menu::message(ui.panel, HEAD, "could not encode it", "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    };
    let armoured = core::str::from_utf8(&armoured[..n]).unwrap_or("");

    // Show it, then offer the card: the signature is long, so a screen is for checking the
    // message and address, and the file is what gets used.
    show(ui, text, addr.as_str(), armoured);
    menu::ask(ui.panel, HEAD, "write it to the", "SD card?");
    if !menu::confirmed(ui) {
        return;
    }
    let mut file: heapless::String<512> = heapless::String::new();
    let _ = write!(
        file,
        "-----BEGIN BITCOIN SIGNED MESSAGE-----\n{text}\n\
         -----BEGIN SIGNATURE-----\n{}\n{armoured}\n\
         -----END BITCOIN SIGNED MESSAGE-----\n",
        addr.as_str()
    );
    menu::message(ui.panel, HEAD, "writing to the card", "");
    match menu::write_card_file(FILE_NAME, file.as_bytes()) {
        Ok(()) => {
            crate::catlog!("message: signed with {}", addr.as_str());
            menu::message(ui.panel, "Signed", &FILE_NAME[1..], "any key to go back");
        }
        Err(why) => {
            crate::catlog!("message: write failed: {}", why);
            menu::message(ui.panel, "Write failed", why, "any key to go back");
        }
    }
    menu::wait_for_any_key(ui);
}

/// Why a message could not be signed, in the words a screen has.
fn describe(e: message::Error) -> &'static str {
    match e {
        message::Error::TooLong { .. } => "message too long",
        message::Error::NotPrintable => "plain ASCII only",
        message::Error::UnsupportedKind => "not for this address type",
        message::Error::BadKey => "key unusable",
        message::Error::BufferTooSmall => "no room for it",
    }
}

/// The message, the address that signed, and the signature, scrollable.
fn show(ui: &mut Ui<'_>, text: &str, addr: &str, armoured: &str) {
    use catcard_ui::scroll::{Line, ScrollView};
    let mut doc: heapless::Vec<Line, 8> = heapless::Vec::new();
    let _ = doc.push(Line::title("Signed"));
    let _ = doc.push(Line::body(text).wrapped());
    let _ = doc.push(Line::body("signed with").small());
    let _ = doc.push(Line::body(addr).small().wrapped());
    let _ = doc.push(Line::body(armoured).small().wrapped());
    let mut view = ScrollView::build(&doc, display::SCREEN_W, display::SCREEN_H, display::FONTS);
    let _ = menu::scroll_choice(ui, &mut view);
}

/// Type the message. `None` if the owner backed out.
fn read_message(ui: &mut Ui<'_>, head: &str) -> Option<Entry> {
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
        "{} sign   {} back",
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
        let _ = doc.push(Line::body("0 space  1 symbols").small());
    }
    let _ = doc.push(Line::body(hint.as_str()).small());
    let view = ScrollView::build(&doc, display::SCREEN_W, display::SCREEN_H, display::FONTS);
    display::draw(ui.panel, |c| render(c, &view));
}
