//! The NFC tag: handing a phone a URL by tap.
//!
//! An ST25DV64KC sits on I²C1 beside the Q1's co-processor -- 8192 bytes of EEPROM the
//! MCU writes over the bus and a phone reads over RF. Writing an NFC Forum Type 5 image
//! into it ([`catcard_nfc`]) makes the tag one a phone opens as a link.
//!
//! What this is for is **broadcasting**: a signed transaction leaves here as a URL whose
//! query holds the transaction's own bytes, so a phone that taps the device can hand it to
//! a block explorer. Nothing is sent by this device, which has no network of any kind; the
//! phone does the sending, and the owner sees the address before it does.
//!
//! # What is confirmed
//!
//! - Device select `0xA6`/`0xA7` -- 7-bit `0x53` -- for user memory, two address bytes,
//!   most significant first; sequential write of up to 256 bytes provided they stay in one
//!   area; user memory organised in rows of 16, one write time `tW` (5 ms, 5.5 ms over
//!   85 °C) per row touched.
//!   Source: hw-reference/datasheets/ST25DV64KC-st.pdf §6.3, §6.4.2, Tables 89, 249-251 [C]
//! - The part is an ST25DV64KC, 8192 bytes, on `NFC_SCL`/`NFC_SDA`, and mk3 has none.
//!   Source: hw-reference/secure-elements.md §NFC [C]
//!
//! Writes here go a row at a time and wait out `tW` afterwards, which is the slow and
//! obviously-correct reading of the above.

use catcard_hal::softi2c::{GpioLines, SoftI2c};

use crate::menu;
use crate::ui::Ui;
use catcard_board::BOARD;

/// User memory, dynamic registers and the mailbox. `0xA6 >> 1`. [C]
const USER: u8 = 0x53;
/// The part's user memory. [C]
const USER_MEMORY: usize = 8192;
/// The row an EEPROM write programs at once. [C]
const ROW: usize = 16;
/// Write time for one row, rounded up from the datasheet's 5.5 ms. [C]
const ROW_MS: u32 = 6;

/// The tag's bus, or `None` on a board without one.
fn bus() -> Option<SoftI2c<GpioLines>> {
    let nfc = BOARD.nfc?;
    // SAFETY: I²C1's two pins; the co-processor driver takes the same bus the same way,
    // and the menu runs one screen at a time.
    Some(SoftI2c::new(unsafe { GpioLines::new(nfc.scl, nfc.sda?) }))
}

/// Write `bytes` into user memory from address zero.
///
/// A row at a time: each write carries its own address, so a row that is refused stops the
/// whole thing rather than leaving the tag holding half of one image and half of another.
fn write_user_memory(bytes: &[u8]) -> Result<(), &'static str> {
    if bytes.len() > USER_MEMORY {
        return Err("too big for the tag");
    }
    let mut i2c = bus().ok_or("no NFC on this board")?;
    let mut buf = [0u8; 2 + ROW];
    for (n, chunk) in bytes.chunks(ROW).enumerate() {
        let at = (n * ROW) as u16;
        buf[0] = (at >> 8) as u8;
        buf[1] = at as u8;
        buf[2..2 + chunk.len()].copy_from_slice(chunk);
        i2c.write(USER, &buf[..2 + chunk.len()])
            .map_err(|_| "the tag did not answer")?;
        // The write is in EEPROM: programming starts at the stop condition and the tag
        // answers nothing until it finishes.
        // SAFETY: reads RCC only.
        unsafe { catcard_hal::dwt::delay_ms(ROW_MS) };
    }
    Ok(())
}

/// Whether a tag answers at all: the address pointer set to zero, and one byte read back.
pub(crate) fn present() -> bool {
    let Some(mut i2c) = bus() else {
        return false;
    };
    let mut one = [0u8; 1];
    i2c.write(USER, &[0, 0]).is_ok() && i2c.read(USER, &mut one).is_ok()
}

/// Where a tapped phone is sent. The path is the explorer's own, and the chain segment is
/// the one it uses for Bitcoin `[?]` -- nothing here can check it, and a wrong segment
/// gives a page that does not know the transaction rather than a wrong broadcast.
const HOST_AND_PATH: &str = "blockexplorer.com";
/// The chain segment for what this device signs.
const CHAIN: &str = "btc";

/// The most a transaction can be and still fit the tag, in bytes.
///
/// Every byte becomes two of hex inside the URL, and the rest of the image is the
/// container, the record and the address around it.
pub(crate) fn max_transaction() -> usize {
    let around = catcard_nfc::image_len(HOST_AND_PATH.len() + CHAIN.len() + 24);
    (USER_MEMORY - around) / 2
}

/// Offer to put a signed transaction on the tag, and hold the screen while a phone reads
/// it. `raw` is the network transaction, exactly as it would be broadcast.
///
/// Asked rather than done: the URL carries the whole transaction, so tapping a phone to
/// this hands it to whoever that phone talks to. A device that wrote it unasked would be
/// publishing a transaction its owner had only signed.
pub(crate) fn offer_broadcast(ui: &mut Ui<'_>, raw: &[u8]) {
    const HEAD: &str = "Broadcast";
    if BOARD.nfc.is_none() {
        return;
    }
    if raw.len() > max_transaction() {
        crate::catlog!("nfc: {} bytes is too big for the tag", raw.len());
        return;
    }
    menu::ask(
        ui.panel,
        "Broadcast by NFC?",
        "a phone that taps this",
        "sends the transaction",
    );
    if !menu::confirmed(ui) {
        return;
    }
    if !present() {
        menu::message(ui.panel, HEAD, "no tag answered", "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    }

    // The image is built in the heap: a transaction's hex is far more than a screen's
    // stack has, and it is given back as soon as the tag has it.
    let Some(mut held) = crate::heap::take(USER_MEMORY) else {
        menu::message(ui.panel, HEAD, "not enough memory", "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    };
    let out = held.bytes();
    let n = match build(out, raw) {
        Ok(n) => n,
        Err(why) => {
            menu::message(ui.panel, HEAD, why, "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        }
    };
    menu::blocking_screen(ui.panel, HEAD, "writing the tag");
    match write_user_memory(&out[..n]) {
        Ok(()) => {
            crate::catlog!("nfc: {} bytes on the tag", n);
            drop(held);
            menu::message(
                ui.panel,
                "Tap your phone",
                "to send it",
                "any key when done",
            );
            menu::wait_for_any_key(ui);
        }
        Err(why) => {
            crate::catlog!("nfc: write failed: {}", why);
            drop(held);
            menu::message(ui.panel, HEAD, why, "any key to go back");
            menu::wait_for_any_key(ui);
        }
    }
}

/// Build the tag image for `raw`: the URL, with the transaction as hex in its query.
fn build(out: &mut [u8], raw: &[u8]) -> Result<usize, &'static str> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    // `https://www.` is one byte in an NDEF URI, so the text starts at the host.
    let text_len = HOST_AND_PATH.len() + 1 + CHAIN.len() + "/broadcast?tx=".len() + raw.len() * 2;
    let mut at = catcard_nfc::begin(out, text_len, catcard_nfc::prefix::HTTPS_WWW)
        .map_err(|_| "too big for the tag")?;
    let mut put = |s: &[u8], at: &mut usize| {
        out[*at..*at + s.len()].copy_from_slice(s);
        *at += s.len();
    };
    put(HOST_AND_PATH.as_bytes(), &mut at);
    put(b"/", &mut at);
    put(CHAIN.as_bytes(), &mut at);
    put(b"/broadcast?tx=", &mut at);
    for b in raw {
        out[at] = HEX[(b >> 4) as usize];
        out[at + 1] = HEX[(b & 15) as usize];
        at += 2;
    }
    catcard_nfc::finish(out, at).map_err(|_| "too big for the tag")
}

/// Debug: write a fixed URL to the tag, so the driver can be tried without a transaction.
pub(crate) fn probe_screen(ui: &mut Ui<'_>) {
    const HEAD: &str = "NFC test";
    if BOARD.nfc.is_none() {
        menu::message(ui.panel, HEAD, "no NFC on this board", "");
        menu::wait_for_any_key(ui);
        return;
    }
    if !present() {
        menu::message(ui.panel, HEAD, "no tag answered", "check the bus");
        menu::wait_for_any_key(ui);
        return;
    }
    let mut image = [0u8; 96];
    let n = match catcard_nfc::uri_image(
        "catcard.example/nfc-test",
        catcard_nfc::prefix::HTTPS,
        &mut image,
    ) {
        Ok(n) => n,
        Err(_) => return,
    };
    match write_user_memory(&image[..n]) {
        Ok(()) => {
            crate::catlog!("nfc: test tag written, {} bytes", n);
            menu::message(ui.panel, HEAD, "written: tap a phone", "any key when done");
        }
        Err(why) => {
            crate::catlog!("nfc: test write failed: {}", why);
            menu::message(ui.panel, HEAD, why, "any key to go back");
        }
    }
    menu::wait_for_any_key(ui);
}
