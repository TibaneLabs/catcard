//! Signing a message with one of the wallet's addresses.
//!
//! Proof of control without a transaction: a message comes from the keypad or off a text
//! file on the card, the device signs it with the key behind one of its addresses, and the
//! result is written in the armoured form every verifier reads. Nothing here can move
//! coins -- a legacy signature commits to the "Bitcoin Signed Message" prefix, and a
//! BIP-322 one to a transaction that spends an output which does not exist.
//!
//! Two formats, because both are asked for:
//!
//! - **legacy** ([`message`]), the 65-byte recoverable signature every wallet has read
//!   since 2011;
//! - **BIP-322** ([`bip322`]), the standard one, which is what a verifier that wants a
//!   proof for a segwit address rather than a convention about one will ask for.
//!
//! The owner picks, on a screen that names both. Nothing guesses: a file written in the
//! wrong format is a file the other side rejects, and the two are not distinguishable by
//! looking at the address.
//!
//! Before any signature is shown, the device checks its own work -- the legacy one by
//! recovering the public key from it and comparing, the BIP-322 one by running the
//! verifier over it. A signature that does not verify is not handed to anyone.

use catcard_callgate::Callgate;
use catcard_ui::keypad::{Event, KEYS, Key};
use catcard_ui::textentry::Entry;
use catcard_wallet::address::{self, AddressKind};
use catcard_wallet::bip32::{ChildNumber, ExtendedPrivKey};
use catcard_wallet::{bip322, message, signfile};
use core::fmt::Write as _;
use zeroize::Zeroize;

use crate::display;
use crate::menu;
use crate::ui::Ui;

/// Where a typed message's signature is written.
const FILE_NAME: &str = "/SIGNED.TXT";

/// What is appended to a text file's name for the signature beside it.
const SIGNED_SUFFIX: &str = "-signed.txt";

/// Longest text file this reads. A message is at most [`message::MAX_MESSAGE`]; the rest
/// is room for the trailing newline an editor leaves and for saying "too long" about a
/// file that is, rather than silently signing its first 240 characters.
const MAX_FILE: usize = 2048;

/// Longest path this builds for the file it writes back.
const PATH_MAX: usize = 176;

/// Room for the whole armoured file: three marker lines, the message, the address and the
/// signature, each on its own line.
///
/// Sized from the parts rather than guessed at, because the overflow of a fixed-size
/// buffer here would be a file that is written, looks right on screen, and ends in the
/// middle of a signature.
const FILE_TEXT: usize = signfile::BEGIN.len()
    + signfile::SEPARATOR.len()
    + signfile::END.len()
    + message::MAX_MESSAGE
    + address::MAX_ADDRESS_LEN
    + bip322::MAX_ARMOURED
    + 8;

/// The address the message is signed with: the wallet's first native-segwit receive
/// address, `m/84h/0h/0h/0/0`.
///
/// One address rather than a choice, for now: it is the one a watch-only wallet shows
/// first, and the file says which address signed, so a verifier needs no more. Choosing a
/// path belongs with the custom-path work in the address explorer.
const PATH: [u32; 5] = [84 | 0x8000_0000, 0x8000_0000, 0x8000_0000, 0, 0];
const KIND: AddressKind = AddressKind::P2wpkh;

/// Which signature the file will carry.
#[derive(Copy, Clone, PartialEq, Eq)]
enum Format {
    /// The "Bitcoin Signed Message" digest and a recoverable signature.
    Legacy,
    /// BIP-322, simple variant.
    Bip322,
}

/// What signing produced: the armoured signature, and the address it speaks for.
struct Signed {
    armoured: heapless::String<{ bip322::MAX_ARMOURED }>,
    address: heapless::String<{ address::MAX_ADDRESS_LEN }>,
}

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
    let format = ask_format(ui, HEAD);
    let Some(master) = menu::unlock_master(gate, login, ui, HEAD) else {
        return;
    };

    let mut busy = menu::Working::new(ui.panel, HEAD, "signing");
    let signed = sign_message(&master, text, format);
    busy.tick(ui.panel);
    drop(master);

    let signed = match signed {
        Ok(v) => v,
        Err(why) => return complain(ui, HEAD, why),
    };

    // Show it, then offer the card: the signature is long, so a screen is for checking the
    // message and address, and the file is what gets used.
    show(ui, text, &signed);
    menu::ask(ui.panel, HEAD, "write it to the", "SD card?");
    if !menu::confirmed(ui) {
        return;
    }
    let mut file: heapless::String<FILE_TEXT> = heapless::String::new();
    if signfile::write(&mut file, text, &signed.address, &signed.armoured).is_err() {
        return complain(ui, HEAD, "no room for it");
    }
    menu::card_wait(ui.panel, HEAD, "writing to the card");
    match menu::write_card_file(FILE_NAME, file.as_bytes()) {
        Ok(()) => {
            crate::catlog!("message: signed with {}", signed.address.as_str());
            menu::message(ui.panel, "Signed", &FILE_NAME[1..], "any key to go back");
        }
        Err(why) => {
            crate::catlog!("message: write failed: {}", why);
            menu::message(ui.panel, "Write failed", why, "any key to go back");
        }
    }
    menu::wait_for_any_key(ui);
}

/// Sign the text in a file on the card, and write the signature beside it.
///
/// The message is the file's contents, so what is shown before the key is used is the
/// whole of what will be signed -- a file is not a thing anyone reads carefully before
/// handing it to a wallet, and the screen is the only place the two can be compared.
pub(crate) fn text_file(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    const HEAD: &str = "Sign text file";

    let Some(path) = menu::browse_sd(ui, "Pick a .txt", Some("txt"), menu::Browse::File) else {
        return;
    };
    let mut raw = [0u8; MAX_FILE];
    menu::card_wait(ui.panel, HEAD, "reading the card");
    let len = match crate::signtx::read_card_file(&path, &mut raw) {
        Ok(n) => n,
        Err(why) => return complain(ui, HEAD, why),
    };
    let Ok(text) = core::str::from_utf8(&raw[..len]) else {
        return complain(ui, HEAD, "not text");
    };
    // The trailing newline is the editor's, not the owner's: a file that ends with one and
    // a file that does not are the same message, and signing the difference would produce
    // two signatures nobody can tell apart on screen. What is left is what gets signed and
    // what is written into the armoured file, so the two always agree.
    let text = text.trim_end();
    if let Some(why) = unshowable(text) {
        return complain(ui, HEAD, why);
    }
    sign_text(gate, login, ui, HEAD, &path, text);
}

/// Why this text cannot be signed from a file, if it cannot be.
fn unshowable(text: &str) -> Option<&'static str> {
    if text.is_empty() {
        return Some("nothing in that file");
    }
    if text.len() > message::MAX_MESSAGE {
        return Some("message too long");
    }
    // Printable ASCII only, as the typed path is. A message with a tab, a line break or a
    // non-ASCII character in it is one the screen cannot show faithfully -- and the owner
    // would be signing something other than what they read.
    if !text.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        return Some("plain ASCII only");
    }
    None
}

/// The rest of the card flow, once the file has been read and checked.
fn sign_text(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    head: &str,
    path: &str,
    text: &str,
) {
    let format = ask_format(ui, head);
    let Some(master) = menu::unlock_master(gate, login, ui, head) else {
        return;
    };

    // The address before the signature: what the owner is asked to approve is this text
    // signed by *that* address, and it is the last moment either can still be refused.
    let mut busy = menu::Working::new(ui.panel, head, "deriving");
    let address = crate::keywork::run(|kw| address_at(&master, kw));
    busy.tick(ui.panel);
    let address = match address {
        Ok(a) => a,
        Err(why) => {
            drop(master);
            return complain(ui, head, why);
        }
    };
    if !confirm(ui, head, text, &address) {
        drop(master);
        return;
    }

    let mut busy = menu::Working::new(ui.panel, head, "signing");
    let signed = sign_message(&master, text, format);
    busy.tick(ui.panel);
    drop(master);
    let signed = match signed {
        Ok(v) => v,
        Err(why) => return complain(ui, head, why),
    };

    let mut file: heapless::String<FILE_TEXT> = heapless::String::new();
    if signfile::write(&mut file, text, &signed.address, &signed.armoured).is_err() {
        return complain(ui, head, "no room for it");
    }
    let Some(out) = beside(path) else {
        return complain(ui, head, "path too long");
    };
    menu::card_wait(ui.panel, head, "writing to the card");
    match menu::write_card_file(&out, file.as_bytes()) {
        Ok(()) => {
            crate::catlog!("message: {} signed with {}", out.as_str(), signed.address);
            let name = out.strip_prefix('/').unwrap_or(&out);
            menu::message(ui.panel, "Signed", name, "any key to go back");
        }
        Err(why) => {
            crate::catlog!("message: write failed: {}", why);
            menu::message(ui.panel, "Write failed", why, "any key to go back");
        }
    }
    menu::wait_for_any_key(ui);
}

/// The name the signature is written under: the source file's, with its extension
/// replaced. `FOO.TXT` becomes `FOO-signed.txt`, in the same directory.
fn beside(path: &str) -> Option<heapless::String<PATH_MAX>> {
    // Only an extension in the last path element counts; a dot in a directory name is
    // part of that name.
    let cut = match path.rfind('.') {
        Some(dot) if !path[dot..].contains('/') => dot,
        _ => path.len(),
    };
    let mut out: heapless::String<PATH_MAX> = heapless::String::new();
    out.push_str(&path[..cut]).ok()?;
    out.push_str(SIGNED_SUFFIX).ok()?;
    Some(out)
}

/// Derive the signing key's address, without signing anything.
fn address_at(
    master: &ExtendedPrivKey,
    kw: &catcard_wallet::KeyWork,
) -> Result<heapless::String<{ address::MAX_ADDRESS_LEN }>, &'static str> {
    let here = derive(master, kw)?;
    let pubkey = here.public_key(kw);
    let mut buf = [0u8; address::MAX_ADDRESS_LEN];
    let n =
        address::encode(KIND, crate::prefs::network(), &pubkey, &mut buf).map_err(|_| "address failed")?;
    let mut addr: heapless::String<{ address::MAX_ADDRESS_LEN }> = heapless::String::new();
    addr.push_str(core::str::from_utf8(&buf[..n]).unwrap_or(""))
        .map_err(|_| "address failed")?;
    Ok(addr)
}

/// Walk [`PATH`] from the master key.
fn derive(
    master: &ExtendedPrivKey,
    kw: &catcard_wallet::KeyWork,
) -> Result<ExtendedPrivKey, &'static str> {
    let mut here = master.clone();
    for &step in &PATH {
        here = here
            .derive_child(ChildNumber(step), kw)
            .map_err(|_| "key derivation failed")?;
    }
    Ok(here)
}

/// Derive, sign, and check the signature against the key that made it.
///
/// Everything from the private key onwards happens inside [`crate::keywork::run`], so no
/// interrupt runs in the middle of it: the derivation, the signature and the self-check
/// are one masked region, and the secret is zeroized before it ends.
fn sign_message(
    master: &ExtendedPrivKey,
    text: &str,
    format: Format,
) -> Result<Signed, &'static str> {
    crate::keywork::run(|kw| {
        let here = derive(master, kw)?;
        let pubkey = here.public_key(kw);
        let mut secret = *here.secret_bytes();

        let mut armoured: heapless::String<{ bip322::MAX_ARMOURED }> = heapless::String::new();
        let mut buf = [0u8; bip322::MAX_ARMOURED];
        let written = match format {
            Format::Legacy => {
                let sig = message::sign(text, &secret, KIND, kw);
                secret.zeroize();
                let sig = sig.map_err(describe)?;
                // Check our own work: recover the key from the signature and compare it
                // with the one that signed. A signature that does not recover is worse
                // than none.
                match message::recover(text, &sig) {
                    Ok((recovered, _)) if recovered == pubkey => {}
                    _ => return Err("signature did not verify"),
                }
                message::armour(&sig, &mut buf).map_err(describe)?
            }
            Format::Bip322 => {
                let sig = bip322::sign(text.as_bytes(), &secret, KIND, kw);
                secret.zeroize();
                let sig = sig.map_err(describe322)?;
                // The same self-check, through the same verifier a counterparty would
                // use: the signature has to satisfy the script this address stands for.
                let mut script = [0u8; bip322::MAX_SCRIPT];
                let n = bip322::challenge(KIND, &pubkey, &mut script).map_err(describe322)?;
                bip322::verify(text.as_bytes(), &script[..n], sig.as_bytes())
                    .map_err(|_| "signature did not verify")?;
                sig.armour(&mut buf).map_err(describe322)?
            }
        };
        armoured
            .push_str(core::str::from_utf8(&buf[..written]).unwrap_or(""))
            .map_err(|_| "no room for it")?;

        let mut address = [0u8; address::MAX_ADDRESS_LEN];
        let n = address::encode(KIND, crate::prefs::network(), &pubkey, &mut address)
            .map_err(|_| "address failed")?;
        let mut addr: heapless::String<{ address::MAX_ADDRESS_LEN }> = heapless::String::new();
        addr.push_str(core::str::from_utf8(&address[..n]).unwrap_or(""))
            .map_err(|_| "address failed")?;
        Ok(Signed {
            armoured,
            address: addr,
        })
    })
}

/// Which format to write.
///
/// Asked before the PIN rather than after, so a change of mind costs nothing. Both
/// answers are a choice and neither is a way out: backing out is what the screen before
/// this one is for.
fn ask_format(ui: &mut Ui<'_>, head: &str) -> Format {
    menu::ask(ui.panel, head, "sign it as BIP-322?", "no = legacy format");
    if menu::confirmed(ui) {
        Format::Bip322
    } else {
        Format::Legacy
    }
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

/// The same, for the BIP-322 side.
fn describe322(e: bip322::Error) -> &'static str {
    match e {
        bip322::Error::UnsupportedKind | bip322::Error::UnsupportedScript => {
            "not for this address type"
        }
        bip322::Error::BadKey => "key unusable",
        bip322::Error::Malformed | bip322::Error::Invalid => "signature did not verify",
        bip322::Error::BufferTooSmall => "no room for it",
    }
}

fn complain(ui: &mut Ui<'_>, head: &str, why: &str) {
    crate::catlog!("message: {}", why);
    menu::message(ui.panel, head, why, "any key to go back");
    menu::wait_for_any_key(ui);
}

/// The message and the address that will sign it. True if the owner said go ahead.
fn confirm(ui: &mut Ui<'_>, head: &str, text: &str, address: &str) -> bool {
    use catcard_ui::scroll::{Line, ScrollView};
    let mut doc: heapless::Vec<Line, 8> = heapless::Vec::new();
    let _ = doc.push(Line::title(head));
    let _ = doc.push(Line::body(text).wrapped());
    let _ = doc.push(Line::body("will be signed by").small());
    let _ = doc.push(Line::body(address).small().wrapped());
    let mut view = ScrollView::build(&doc, display::SCREEN_W, display::SCREEN_H, display::FONTS);
    menu::scroll_choice(ui, &mut view)
}

/// The message, the address that signed, and the signature, scrollable.
fn show(ui: &mut Ui<'_>, text: &str, signed: &Signed) {
    use catcard_ui::scroll::{Line, ScrollView};
    let mut doc: heapless::Vec<Line, 8> = heapless::Vec::new();
    let _ = doc.push(Line::title("Signed"));
    let _ = doc.push(Line::body(text).wrapped());
    let _ = doc.push(Line::body("signed with").small());
    let _ = doc.push(Line::body(&signed.address).small().wrapped());
    let _ = doc.push(Line::body(&signed.armoured).small().wrapped());
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
