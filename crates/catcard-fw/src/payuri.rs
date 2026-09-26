//! Payment URIs on the device: BIP-21, both ways.
//!
//! **Out**: the Address Explorer's share actions -- the QR and the tag -- can put an
//! amount and a label on the address they show, so the phone that reads it opens its
//! wallet with the amount filled in. The default stays the bare address: a URI is only
//! worth writing when there is something to say beyond "here".
//!
//! **In**: a `bitcoin:` URI that arrived by camera or by tag is read out in full --
//! address, amount, label, message -- and offered to the one check that matters for an
//! address somebody else is showing: is it this wallet's? (`crate::verify`). A URI that
//! asks for something this cannot honour (`req-*`) is refused as BIP-21 says, by name.
//!
//! The format itself is `catcard_wallet::address::bip21`; this is the screens.

use catcard_ui::keypad::{Event, KEYS, Key};
use catcard_wallet::address::bip21;
use core::fmt::Write as _;

use crate::display;
use crate::menu;
use crate::ui::Ui;

/// What the owner chose to attach to an address being shared.
pub(crate) struct Extras {
    /// The amount, in satoshis. `None` when the field was left at zero: an `amount=0`
    /// would ask the payer's wallet for nothing, which is not what leaving it blank means.
    pub sats: Option<u64>,
    /// The label, possibly empty.
    pub label: heapless::String<{ bip21::LABEL_MAX }>,
}

impl Extras {
    /// The URI: the address, and whatever of the extras is there to write.
    pub(crate) fn uri(&self, address: &str) -> Option<heapless::String<{ bip21::MAX_URI }>> {
        let mut out = heapless::String::new();
        bip21::write(
            &mut out,
            address,
            self.sats,
            Some(self.label.as_str()),
            None,
        )
        .ok()?;
        Some(out)
    }
}

/// Ask whether to attach an amount and a label, and take them.
///
/// `None` if the owner backed out of any of it; `Some(None)` for the bare address, which
/// is the first row and the default; `Some(Some(_))` with what was typed.
pub(crate) fn ask_extras(ui: &mut Ui<'_>) -> Option<Option<Extras>> {
    const HEAD: &str = "Share";
    let rows = ["Address only", "Amount and label"];
    if menu::choose(ui, HEAD, "attach an amount and label?", &rows)? == 0 {
        return Some(None);
    }
    let sats = ask_amount(ui)?;
    let label = loop {
        let typed = crate::passphrase::read(ui, "Label (optional)")?;
        let mut label: heapless::String<{ bip21::LABEL_MAX }> = heapless::String::new();
        if label.push_str(typed.as_str().trim()).is_ok() {
            break label;
        }
        let mut note = heapless::String::<32>::new();
        let _ = write!(note, "{} characters at most", bip21::LABEL_MAX);
        menu::message(ui.panel, "Label", "too long", note.as_str());
        menu::wait_for_any_key(ui);
    };
    Some(Some(Extras {
        sats: (sats > 0).then_some(sats),
        label,
    }))
}

/// Type an amount in the display units in force.
///
/// **Digits fill in from the right, the point stays where the unit puts it.** Every
/// unit this device shows -- BTC, mBTC, bits, sats -- is a power of ten of satoshis, so
/// the digits typed are always a satoshi count and the unit only decides where the
/// point is drawn: five presses of `1` read `0.00011111 BTC`, `0.11111 mBTC`, `111.11
/// bits` or `11111 sats`, and mean the same thing. It is the one way to type a decimal
/// on a keypad that has no point key, and on the Q1 it is what the same digits do.
///
/// Bounded at the supply: a digit that would take the amount past 21M BTC is ignored.
/// `None` if the owner backed out (cancel on an empty field); `Some(0)` if they accepted
/// nothing, which the caller reads as "no amount".
fn ask_amount(ui: &mut Ui<'_>) -> Option<u64> {
    const HEAD: &str = "Amount";
    let units = crate::prefs::current().units;
    let mut sats: u64 = 0;
    let mut typed: u32 = 0;
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();

    loop {
        {
            use catcard_ui::scroll::{Line, ScrollView, render};
            let mut shown = heapless::String::<32>::new();
            let _ = units.write(sats, &mut shown);
            let mut hint = heapless::String::<48>::new();
            let _ = write!(
                hint,
                "{} accept   {} erase",
                display::CONFIRM_KEY,
                display::CANCEL_KEY
            );
            let mut doc: heapless::Vec<Line, 5> = heapless::Vec::new();
            let _ = doc.push(Line::title(HEAD));
            let _ = doc.push(Line::body(shown.as_str()));
            let _ = doc.push(Line::body("digits fill in from the right").small());
            let _ = doc.push(Line::body("leave at zero for no amount").small());
            let _ = doc.push(Line::body(hint.as_str()).small());
            let view =
                ScrollView::build(&doc, display::SCREEN_W, display::SCREEN_H, display::FONTS);
            display::draw(ui.panel, |c| render(c, &view));
        }
        menu::wait_for_release(ui);
        let mut redraw = false;
        while !redraw {
            let _ = crate::usbtask::pump();
            crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
            for k in keys.iter() {
                match k {
                    Key::Confirm => return Some(sats),
                    Key::Cancel => {
                        if typed == 0 {
                            return None;
                        }
                        sats /= 10;
                        typed -= 1;
                        redraw = true;
                    }
                    Key::Digit(d) => {
                        // A leading zero is nothing typed: the field reads the same and
                        // the erase count should not have to skip over it.
                        if sats == 0 && *d == 0 {
                            continue;
                        }
                        if let Some(next) = sats
                            .checked_mul(10)
                            .and_then(|v| v.checked_add(u64::from(*d)))
                            .filter(|v| *v <= bip21::MAX_SATS)
                        {
                            sats = next;
                            typed += 1;
                            redraw = true;
                        }
                    }
                    Key::Char(_) | Key::Qr => {}
                }
            }
            if !redraw {
                display::idle(ui.panel);
            }
        }
    }
}

/// Show the address as a QR, bare or as a URI with what the owner chose to attach.
///
/// The bare form is [`menu::address_qr_of`]'s -- upper-cased bech32 without a scheme,
/// or `bitcoin:` and a base58 address -- and is what a wallet expects to scan. With an
/// amount or a label the payload is a URI in byte mode either way, so the address goes
/// in as it is written and the text beside the symbol is still the address alone.
pub(crate) fn share_qr(ui: &mut Ui<'_>, address: &str, bech32: bool) {
    match ask_extras(ui) {
        None => {}
        Some(None) => menu::address_qr_of(ui, address, bech32),
        Some(Some(extras)) => match extras.uri(address) {
            Some(uri) => menu::qr_screen(ui, uri.as_str(), address),
            None => {
                menu::message(ui.panel, "QR", "too long to encode", "");
                menu::wait_for_any_key(ui);
            }
        },
    }
}

/// A URI arrived: read it out, and offer to check the address against this wallet.
///
/// The check is [`crate::verify::owned`], the same search the typed path runs. A match
/// ends on a screen that says so in as many words -- the URI was shown by someone
/// claiming this wallet's address, and "yours" in small type beside a path is not the
/// answer that question deserves.
#[cfg(not(feature = "board-mk3"))]
pub(crate) fn received(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    text: &str,
) {
    use catcard_ui::scroll::Line;

    const HEAD: &str = "Payment request";
    /// Room for a decoded label, message or `wallet=` value on screen.
    const TEXT_MAX: usize = 96;

    let uri = match bip21::parse(text.trim()) {
        Ok(uri) => uri,
        Err(why) => {
            // The required parameter's name is the useful half of the refusal: it says
            // which wallet feature the sender wanted, which is what the owner will go
            // and look up.
            let name = match why {
                bip21::Error::UnknownRequired(name) => name,
                _ => "any key to go back",
            };
            crate::catlog!("payuri: refused: {} {}", why.describe(), name);
            menu::message(ui.panel, HEAD, why.describe(), name);
            menu::wait_for_any_key(ui);
            return;
        }
    };
    crate::catlog!(
        "payuri: {} amount {:?} label {:?}",
        uri.address,
        uri.amount,
        uri.label
    );

    let mut amount = heapless::String::<32>::new();
    match uri.amount {
        Some(sats) => {
            let _ = crate::prefs::current().units.write(sats, &mut amount);
        }
        None => {
            let _ = amount.push_str("no amount");
        }
    }
    let mut label_buf = [0u8; TEXT_MAX];
    let mut message_buf = [0u8; TEXT_MAX];
    let mut wallet_buf = [0u8; TEXT_MAX];
    let label = uri.label.map(|l| shown(l, &mut label_buf));
    let message = uri.message.map(|m| shown(m, &mut message_buf));
    let wallet = uri.wallet.map(|w| shown(w, &mut wallet_buf));

    let mut hint = heapless::String::<48>::new();
    let _ = write!(hint, "{} verify it is mine", display::CONFIRM_KEY);

    let mut doc: heapless::Vec<Line, 12> = heapless::Vec::new();
    let _ = doc.push(Line::title(HEAD));
    let _ = doc.push(Line::body(uri.address).small().wrapped());
    let _ = doc.push(Line::body(amount.as_str()));
    if let Some(label) = label {
        let _ = doc.push(Line::body("label").small());
        let _ = doc.push(Line::body(label).wrapped());
    }
    if let Some(message) = message {
        let _ = doc.push(Line::body("message").small());
        let _ = doc.push(Line::body(message).wrapped());
    }
    if let Some(wallet) = wallet {
        // Stock's extension. What it means is not documented, so it is shown and not
        // acted on: docs/HARDWARE-OPEN-ITEMS.md §"BIP-21 wallet= parameter".
        let _ = doc.push(Line::body("wallet= (Coldcard extension)").small());
        let _ = doc.push(Line::body(wallet).wrapped());
    }
    let _ = doc.push(Line::body(hint.as_str()).small());
    if !matches!(
        menu::show_doc(ui, &doc, false, false),
        menu::DocExit::Confirmed
    ) {
        return;
    }

    if crate::verify::owned(gate, login, ui, uri.address) {
        menu::message(
            ui.panel,
            "OUR address",
            "this wallet is paid",
            "at the address shown",
        );
        menu::wait_for_any_key(ui);
    }
}

/// A parameter's value as it goes on screen: decoded, or a note about why it cannot be.
#[cfg(not(feature = "board-mk3"))]
fn shown<'a>(encoded: &str, buf: &'a mut [u8]) -> &'a str {
    match bip21::decode(encoded, buf) {
        Ok(text) => text,
        Err(bip21::Error::TooLong) => "(too long to show)",
        Err(_) => "(not readable)",
    }
}
