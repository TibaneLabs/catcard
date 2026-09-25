//! The NFC tag: what a phone reads off this device, and what it writes back.
//!
//! An ST25DV64KC sits on I²C1 beside the Q1's co-processor -- 8192 bytes of EEPROM the
//! MCU writes over the bus and a phone reads over RF. Writing an NFC Forum Type 5 image
//! into it ([`catcard_nfc`]) makes the tag one a phone opens as a link; reading the same
//! memory back is how a transaction a phone wrote arrives here.
//!
//! Three things go through it:
//!
//! - **Broadcast**: a signed transaction leaves here as a URL whose query holds the
//!   transaction's own bytes, so a phone that taps the device can hand it to a block
//!   explorer. Nothing is sent by this device, which has no network of any kind; the phone
//!   does the sending, and the owner sees the address before it does.
//! - **Share an address**: the address on the explorer's screen, as a `bitcoin:` URI, so a
//!   phone tapped on it can pay to it without anyone reading out 42 characters.
//! - **Receive**: the tag is marked ready, a phone writes an NDEF message to it, and what
//!   arrives goes to the same offer the scanner's does ([`crate::sniff`]) -- which in
//!   practice means a PSBT goes to the signing screen.
//!
//! Every one of them is a menu action. Nothing here runs at boot, and nothing is written
//! to the tag that the owner did not ask for.
//!
//! # What is confirmed
//!
//! - Device select `0xA6`/`0xA7` -- 7-bit `0x53` -- for user memory, two address bytes,
//!   most significant first; sequential write of up to 256 bytes provided they stay in one
//!   area; user memory organised in rows of 16, one write time `tW` (5 ms, 5.5 ms over
//!   85 °C) per row touched.
//!   Source: hw-reference/datasheets/ST25DV64KC-st.pdf §6.3, §6.4.2, Tables 89, 249-251 [C]
//! - A read is a dummy write of the two address bytes, a **repeated** start, and then
//!   bytes out until the controller does not acknowledge one. The counter walks forwards
//!   on its own and does not roll over at the end of user memory.
//!   Source: same, §6.5.1 "Random address read", §6.5.3 "Sequential read access" [C]
//! - The part is an ST25DV64KC, 8192 bytes, on `NFC_SCL`/`NFC_SDA`, and mk3 has none.
//!   Source: hw-reference/secure-elements.md §NFC [C]
//!
//! Writes here go a row at a time and wait out `tW` afterwards, which is the slow and
//! obviously-correct reading of the above.
//!
//! # Why receiving polls the memory instead of asking the tag
//!
//! The part has two mechanisms that would say "a phone just wrote", and neither is usable
//! without first reprogramming the tag:
//!
//! - The **fast transfer mode mailbox** is a 256-byte RAM buffer shared between the two
//!   interfaces. It is too small for a transaction, it is only reachable from RF through
//!   ST's own custom commands rather than through anything a phone's NDEF stack does, and
//!   it works only while fast transfer mode is enabled in the `FTM` **system** register.
//!   Source: same, §4.5 "Fast transfer mode mailbox", Table 15 [C]
//! - The **`RF_WRITE` interrupt** is reported in `IT_STS_Dyn` only when it has been
//!   enabled in `GPO1`, whose factory value for that bit is 0 -- and `GPO1` is system
//!   memory, writable over I²C only with the security session open, which means presenting
//!   the I²C password.
//!   Source: same, Table 31 (GPO1, factory values), Table 37 (IT_STS_Dyn) and its notes,
//!   §5.4.5 "Configuring GPO" [C]
//!
//! Both would have this firmware write configuration registers on a part nobody here has
//! tried, to save a poll of a memory it is already able to read. So the tag is left exactly
//! as it was found, and the receive screen watches the first bytes of user memory change.
//! `[I]` -- that a phone's write lands in user memory in a way this poll notices is
//! reasoning from the format, not something measured; see `docs/HARDWARE-OPEN-ITEMS.md`.

use catcard_hal::softi2c::{GpioLines, SoftI2c};

use crate::menu;
use crate::sniff::{Content, sniff};
use crate::ui::Ui;
use catcard_board::BOARD;
use catcard_callgate::Callgate;

/// User memory, dynamic registers and the mailbox. `0xA6 >> 1`. [C]
const USER: u8 = 0x53;
/// The part's user memory. [C]
const USER_MEMORY: usize = 8192;
/// The T5T area a phone is told it has: everything past the capability container.
const AREA: usize = USER_MEMORY - catcard_nfc::CC_LEN;
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

/// Fill `out` from user memory, starting at `at`.
///
/// One transfer: the address goes out as a dummy write, a repeated start turns the bus
/// around, and the tag's own counter walks forwards from there.
fn read_user_memory(at: u16, out: &mut [u8]) -> Result<(), &'static str> {
    if at as usize + out.len() > USER_MEMORY {
        return Err("past the end of the tag");
    }
    let mut i2c = bus().ok_or("no NFC on this board")?;
    i2c.write_read(USER, &[(at >> 8) as u8, at as u8], out)
        .map_err(|_| "the tag did not answer")
}

/// Whether a tag answers at all: one byte read from address zero.
pub(crate) fn present() -> bool {
    let mut one = [0u8; 1];
    read_user_memory(0, &mut one).is_ok()
}

/// Leave the tag formatted and empty.
///
/// Called when a screen that put something on the tag is done with it. An address or a
/// signed transaction left sitting there is readable by the next phone that comes near the
/// device, for as long as it stays there -- which is until something else overwrites it,
/// and nothing might.
fn clear() {
    let mut blank = [0u8; catcard_nfc::CC_LEN + 3];
    let Ok(n) = catcard_nfc::empty_image(&mut blank, AREA) else {
        return;
    };
    if let Err(why) = write_user_memory(&blank[..n]) {
        crate::catlog!("nfc: could not clear the tag: {}", why);
    }
}

/// Where a tapped phone is sent `[?]`. The host is the one given with the request and the
/// chain segment is the one it uses for Bitcoin, and nothing here can check either: no
/// tag has been tapped yet. A wrong host or segment gives a page that does not know the
/// transaction rather than a wrong broadcast. The phone's owner sees the address before
/// anything is sent, and the tap tells that host the transaction and the phone's IP --
/// see `docs/HARDWARE-OPEN-ITEMS.md` §"The broadcast URL".
const HOST_AND_PATH: &str = "blockexplorer.com";
/// The chain segment Bitcoin goes out under.
pub(crate) const CHAIN: &str = "btc";

/// The most a transaction can be and still fit the tag, in bytes.
///
/// Every byte becomes two of hex inside the URL, and the rest of the image is the
/// container, the record and the address around it.
pub(crate) fn max_transaction() -> usize {
    // The longest chain segment this build writes, so the answer does not depend on
    // which chain is asking.
    const SEGMENT: usize = 12;
    let around = catcard_nfc::image_len(HOST_AND_PATH.len() + SEGMENT + 24);
    (USER_MEMORY - around) / 2
}

/// Offer to put a signed transaction on the tag, and hold the screen while a phone reads
/// it. `raw` is the network transaction, exactly as it would be broadcast.
///
/// Asked rather than done: the URL carries the whole transaction, so tapping a phone to
/// this hands it to whoever that phone talks to. A device that wrote it unasked would be
/// publishing a transaction its owner had only signed.
pub(crate) fn offer_broadcast(ui: &mut Ui<'_>, chain: &str, raw: &[u8]) {
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
    let n = match build(out, chain, raw) {
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
            clear();
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
fn build(out: &mut [u8], chain: &str, raw: &[u8]) -> Result<usize, &'static str> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    // `https://www.` is one byte in an NDEF URI, so the text starts at the host.
    let text_len = HOST_AND_PATH.len() + 1 + chain.len() + "/broadcast?tx=".len() + raw.len() * 2;
    let mut at = catcard_nfc::begin(out, AREA, text_len, catcard_nfc::prefix::HTTPS_WWW)
        .map_err(|_| "too big for the tag")?;
    let mut put = |s: &[u8], at: &mut usize| {
        out[*at..*at + s.len()].copy_from_slice(s);
        *at += s.len();
    };
    put(HOST_AND_PATH.as_bytes(), &mut at);
    put(b"/", &mut at);
    put(chain.as_bytes(), &mut at);
    put(b"/broadcast?tx=", &mut at);
    for b in raw {
        out[at] = HEX[(b >> 4) as usize];
        out[at + 1] = HEX[(b & 15) as usize];
        at += 2;
    }
    catcard_nfc::finish(out, at).map_err(|_| "too big for the tag")
}

/// Offer to put a Solana transaction on the tag as a link, and hold the screen while a
/// phone reads it.
///
/// The same tap as [`offer_broadcast`], and a different bargain. That one puts the
/// transaction in a URL's *query*, so the host it names sees it the moment the phone
/// opens the link. This one puts it after a `#`, and a fragment is never sent: the phone
/// opens a page, the page reads the transaction out of its own address bar, and nothing
/// leaves the phone until somebody there says to send it. `raw` is the transaction
/// exactly as it would be submitted.
///
/// A transaction still waiting for signatures is worth passing on too -- that is how it
/// reaches whoever signs next -- so this offers either way and says which it is.
#[cfg(feature = "multichain")]
pub(crate) fn offer_solana_link(ui: &mut Ui<'_>, raw: &[u8], missing: usize) {
    use catcard_solana::link;

    const HEAD: &str = "Link";
    if BOARD.nfc.is_none() {
        return;
    }
    if raw.len() > link::PACKET_MAX || catcard_nfc::image_len(link::link_len(raw.len())) > AREA {
        crate::catlog!("nfc: {} bytes is too big for the tag", raw.len());
        return;
    }
    menu::ask(
        ui.panel,
        "Hand it to a phone?",
        "a phone that taps this",
        if missing == 0 {
            "can send the transaction"
        } else {
            "gets it to sign"
        },
    );
    if !menu::confirmed(ui) {
        return;
    }
    if !present() {
        menu::message(ui.panel, HEAD, "no tag answered", "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    }

    // Sized to this link rather than to the tag: the transaction that arrived is still
    // in memory while this runs, and a whole second copy of the user area on top of it
    // is how a screen runs out of heap for no reason.
    let Some(mut held) = crate::heap::take(catcard_nfc::image_len(link::link_len(raw.len())))
    else {
        menu::message(ui.panel, HEAD, "not enough memory", "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    };
    let out = held.bytes();
    let n = match build_solana_link(out, raw) {
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
                "to take it",
                "any key when done",
            );
            menu::wait_for_any_key(ui);
            clear();
        }
        Err(why) => {
            crate::catlog!("nfc: write failed: {}", why);
            drop(held);
            menu::message(ui.panel, HEAD, why, "any key to go back");
            menu::wait_for_any_key(ui);
        }
    }
}

/// Build the tag image for `raw`: the studio link, with the transaction base64'd in its
/// fragment.
#[cfg(feature = "multichain")]
fn build_solana_link(out: &mut [u8], raw: &[u8]) -> Result<usize, &'static str> {
    use catcard_solana::link;

    // `https://www.` is one byte in an NDEF URI, so the text starts at the host -- which
    // is where [`link::write_link`] starts too.
    let mut at = catcard_nfc::begin(
        out,
        AREA,
        link::link_len(raw.len()),
        catcard_nfc::prefix::HTTPS_WWW,
    )
    .map_err(|_| "too big for the tag")?;
    at += link::write_link(raw, &mut out[at..]).ok_or("too big for the tag")?;
    catcard_nfc::finish(out, at).map_err(|_| "too big for the tag")
}

// ---------------------------------------------------------------------------
// Sharing an address
// ---------------------------------------------------------------------------

/// The longest tag image an address can make: the BIP-21 scheme and the longest address
/// this wallet encodes, in one URI record.
const SHARE_MAX: usize = catcard_nfc::image_len(
    catcard_wallet::address::QR_SCHEME.len() + catcard_wallet::address::MAX_ADDRESS_LEN,
);

/// Put the address on screen onto the tag, and hold the screen while a phone reads it.
///
/// **A `bitcoin:` URI record, not a plain text record.** A phone reading a text record can
/// only show the characters, which leaves the address still to be typed or copied by hand
/// -- and a hand-copied address is exactly the failure this is meant to remove. A URI
/// record the phone can act on: it opens a wallet with the address already filled in. The
/// reason the QR path goes the other way and writes bech32 addresses bare
/// ([`catcard_wallet::address::qr_payload`]) does not apply here: it is about QR's
/// alphanumeric mode, and an NDEF payload is bytes whatever is in it, so the scheme costs
/// eight bytes of an eight-kilobyte tag and nothing else.
///
/// The tag is blanked when the screen is left, so an address is not left on a device's
/// doorstep for the next phone that passes.
pub(crate) fn share_address(ui: &mut Ui<'_>, address: &str) {
    const HEAD: &str = "Share";
    if BOARD.nfc.is_none() {
        return;
    }
    if !present() {
        menu::message(ui.panel, HEAD, "no tag answered", "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    }
    let mut uri: heapless::String<{ catcard_wallet::address::MAX_QR_PAYLOAD }> =
        heapless::String::new();
    if uri
        .push_str(catcard_wallet::address::QR_SCHEME)
        .and_then(|()| uri.push_str(address))
        .is_err()
    {
        menu::message(ui.panel, HEAD, "address too long", "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    }

    let mut image = [0u8; SHARE_MAX];
    let n = match catcard_nfc::uri_image(&mut image, AREA, &uri, catcard_nfc::prefix::NONE) {
        Ok(n) => n,
        Err(_) => {
            menu::message(ui.panel, HEAD, "too big for the tag", "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        }
    };
    menu::blocking_screen(ui.panel, HEAD, "writing the tag");
    match write_user_memory(&image[..n]) {
        Ok(()) => {
            crate::catlog!("nfc: an address on the tag, {} bytes", n);
            menu::message(
                ui.panel,
                "Tap your phone",
                "to read the address",
                "any key when done",
            );
            menu::wait_for_any_key(ui);
            clear();
        }
        Err(why) => {
            crate::catlog!("nfc: address write failed: {}", why);
            menu::message(ui.panel, HEAD, why, "any key to go back");
            menu::wait_for_any_key(ui);
        }
    }
}

// ---------------------------------------------------------------------------
// Receiving
// ---------------------------------------------------------------------------

/// What the tag is marked with while it waits for a phone. Also the baseline the poll
/// compares against, so it has to be something no phone would write by accident.
const READY_TEXT: &str = "CatCard: write a transaction here";

/// How many bytes of the tag the poll watches.
///
/// The container, the message TLV's length and the start of the first record all sit in
/// here, and a phone writing anything of its own changes at least one of them. Reading
/// more each round would cost bus time for no more certainty.
const WATCH: usize = 24;

/// How long the screen waits for a phone before giving up, in milliseconds.
///
/// Bounded because every wait here is: a screen that waits for ever on a tag nobody is
/// going to tap is a device that has to be power-cycled.
const WAIT_MS: u32 = 120_000;

/// Milliseconds between two looks at the tag.
const POLL_MS: u32 = 200;

/// Rounds the bytes must stay unchanged, after a change, before they are read in full.
///
/// A phone writes a message in several RF blocks, and the poll can land in the middle of
/// one. Two quiet rounds is a little under half a second of nothing moving, which is far
/// longer than the gap between two blocks of one write and far shorter than the gap
/// between two taps.
const SETTLE_ROUNDS: u32 = 2;

/// Reads in a row that may fail before the tag is called gone.
///
/// One failure is not news here: a phone in the field is what this is waiting for, and it
/// can hold the part's other side busy across a poll. Two seconds of nothing answering is.
const MISSES_ALLOWED: u32 = 10;

/// Take a transaction in by NFC: mark the tag, wait for a phone to write to it, and offer
/// whatever arrived.
///
/// The offer is [`crate::sniff`]'s, the same one the Q1's scanner uses -- so a PSBT that
/// arrives by tap gets the review and the signatures a PSBT read off a card or a camera
/// does, and something that is not a PSBT says so in the same words.
pub(crate) fn receive_screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    const HEAD: &str = "By NFC";
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

    // Mark the tag ready. This is also the baseline: what the poll below is watching for
    // is these bytes stopping being what was just written.
    let mut marker = [0u8; catcard_nfc::text_image_len(READY_TEXT.len())];
    let Ok(n) = catcard_nfc::text_image(&mut marker, AREA, READY_TEXT) else {
        return;
    };
    menu::blocking_screen(ui.panel, HEAD, "marking the tag");
    if let Err(why) = write_user_memory(&marker[..n]) {
        crate::catlog!("nfc: could not mark the tag: {}", why);
        menu::message(ui.panel, HEAD, why, "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    }
    let mut baseline = [0u8; WATCH];
    let keep = n.min(WATCH);
    baseline[..keep].copy_from_slice(&marker[..keep]);

    match wait_for_write(ui, HEAD, &baseline) {
        Waited::Written => {}
        Waited::Cancelled => {
            clear();
            return;
        }
        Waited::TimedOut => {
            clear();
            menu::message(ui.panel, HEAD, "no phone wrote to it", "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        }
        Waited::Failed(why) => {
            menu::message(ui.panel, HEAD, why, "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        }
    }

    // The whole of user memory, in the heap: it is eight kilobytes, which no screen's
    // stack has, and the records parsed out of it borrow it until the payload is copied
    // somewhere the signer can use.
    let Some(mut held) = crate::heap::take(USER_MEMORY) else {
        menu::message(ui.panel, HEAD, "not enough memory", "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    };
    menu::blocking_screen(ui.panel, HEAD, "reading the tag");
    if let Err(why) = read_user_memory(0, held.bytes()) {
        crate::catlog!("nfc: read failed: {}", why);
        drop(held);
        menu::message(ui.panel, HEAD, why, "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    }
    // The tag has been read; whatever a phone left on it does not need to stay there.
    clear();

    let Some((what, at, len)) = first_usable(held.bytes()) else {
        drop(held);
        menu::message(ui.panel, HEAD, "nothing this can use", "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    };
    crate::catlog!("nfc: {} bytes received, {:?}", len, what);
    offer(gate, login, ui, HEAD, held, at, len, what);
}

/// How the wait for a phone ended.
enum Waited {
    /// The watched bytes changed and then stopped changing.
    Written,
    /// The owner pressed cancel.
    Cancelled,
    /// [`WAIT_MS`] passed with the tag untouched.
    TimedOut,
    /// The tag stopped answering partway through.
    Failed(&'static str),
}

/// Watch the head of user memory until it is not `baseline` any more and has stopped
/// moving, or the owner leaves, or the budget runs out.
fn wait_for_write(ui: &mut Ui<'_>, head: &str, baseline: &[u8; WATCH]) -> Waited {
    menu::blocking_screen(ui.panel, head, "tap your phone to write");
    let mut last = *baseline;
    let mut quiet = 0u32;
    let mut missed = 0u32;
    let mut changed = false;
    // A fixed number of rounds rather than a clock read: the budget is the same either
    // way, and this cannot run away if the timer is not what it was thought to be.
    for _ in 0..(WAIT_MS / POLL_MS) {
        // SAFETY: reads RCC only.
        unsafe { catcard_hal::dwt::delay_ms(POLL_MS) };
        if menu::cancel_pressed(ui) {
            return Waited::Cancelled;
        }
        let mut now = [0u8; WATCH];
        if let Err(why) = read_user_memory(0, &mut now) {
            // A phone holding the tag's RF side busy is a read that did not happen, not a
            // tag that has gone -- and a phone is exactly what this is waiting for. Only a
            // run of them says the part has stopped answering.
            crate::catlog!("nfc: poll: {}", why);
            quiet = 0;
            missed += 1;
            if missed >= MISSES_ALLOWED {
                return Waited::Failed(why);
            }
            continue;
        }
        missed = 0;
        if now != last {
            last = now;
            changed = true;
            quiet = 0;
            continue;
        }
        if changed {
            quiet += 1;
            if quiet >= SETTLE_ROUNDS {
                return Waited::Written;
            }
        }
    }
    Waited::TimedOut
}

/// The first record on the tag this device can do anything with, as a range into `image`.
///
/// Records come out of [`catcard_nfc::read`], which refuses a length that runs past what
/// was read rather than handing back a short slice. What is inside a record still has to
/// be identified, and that is [`sniff`]'s job -- the same one the scanner uses.
///
/// A range rather than a slice, because the caller has to hand the bytes to the signer and
/// cannot do that while a borrow of the buffer is still alive.
fn first_usable(image: &[u8]) -> Option<(Content, usize, usize)> {
    let base = image.as_ptr() as usize;
    let mut fallback = None;
    for record in catcard_nfc::read(image).ok()? {
        let Ok(record) = record else {
            // A malformed record stops the walk: after a length that cannot be trusted,
            // where the next record starts is a guess.
            break;
        };
        // A text record's text, a URI record's URI, or -- for a MIME or external record --
        // the payload exactly as it is. A phone handing over a `.psbt` uses one of the
        // three depending on which app it is.
        let bytes = match (record.text(), record.uri()) {
            // What this screen wrote a moment ago, still on the tag because a phone added
            // a record rather than replacing the message. Offering it back would be the
            // device reading out its own note.
            (Some(READY_TEXT), _) => continue,
            (Some(text), _) => text.as_bytes(),
            (_, Some(("", tail))) => tail.as_bytes(),
            // An abbreviated URI keeps its scheme in one byte of the record, and the
            // two halves are never joined -- that would need a buffer. The tail alone is
            // enough for the one link this device reads: a transaction lives after the
            // `#`, so what identifies it is in the half the record spells out.
            (_, Some((_, tail))) => tail.as_bytes(),
            _ => record.payload,
        };
        if bytes.is_empty() {
            continue;
        }
        let at = bytes.as_ptr() as usize - base;
        match sniff(bytes) {
            // Text is the weakest match -- base64 that is not a PSBT is text, and so is
            // the marker this screen wrote. Kept in case nothing better turns up.
            Content::Text if fallback.is_none() => {
                fallback = Some((Content::Text, at, bytes.len()));
            }
            Content::Text | Content::Unknown => {}
            what => return Some((what, at, bytes.len())),
        }
    }
    fallback
}

/// Say what arrived and do the one thing worth doing with it.
#[allow(clippy::too_many_arguments)]
fn offer(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    head: &str,
    mut held: crate::heap::Block,
    at: usize,
    len: usize,
    what: Content,
) {
    // The same list the scanner offers, from the same place: what this firmware makes of
    // the bytes, and keeping them whatever they are.
    let choices = what.choices();
    if choices.is_empty() {
        drop(held);
        menu::message(ui.panel, head, what.note(), "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    }
    let mut rows: heapless::Vec<&str, 2> = heapless::Vec::new();
    for (label, _) in &choices {
        let _ = rows.push(label);
    }
    let Some(chosen) = menu::choose(ui, head, what.note(), &rows) else {
        return;
    };
    if choices[chosen].1 == crate::sniff::Act::Save {
        crate::sniff::save_to_card(ui, &held.bytes()[at..at + len], what);
        return;
    }
    match what {
        Content::Psbt => sign(gate, login, ui, held, at, len),
        // As on the scanner: read and named, and honest that the screen which lays the
        // whole of it out -- and the signing behind that -- are not built yet.
        #[cfg(feature = "multichain")]
        Content::EvmTx { .. } => {
            crate::evmtx::screen(ui, &held.bytes()[at..at + len]);
        }
        #[cfg(feature = "multichain")]
        Content::SolanaTx { base64 } => {
            crate::solanatx::screen(gate, login, ui, &held.bytes()[at..at + len], base64);
        }
        Content::Text => {
            let text = core::str::from_utf8(&held.bytes()[at..at + len]).unwrap_or("(not text)");
            let mut rows: heapless::Vec<catcard_ui::scroll::Line, 4> = heapless::Vec::new();
            let _ = rows.push(catcard_ui::scroll::Line::title("From the tag"));
            let _ = rows.push(catcard_ui::scroll::Line::body(text).small());
            let _ = menu::show_doc(ui, &rows, false, false);
        }
        // A firmware image is a quarter of a megabyte and the tag holds eight kilobytes,
        // so `sniff` cannot have said this; the arm exists so that a new `Content` has to
        // be thought about here rather than silently doing nothing. A seed offers no
        // action at all (`Content::offer`), so it is answered above and never arrives
        // here either -- loading one is the scanner's path, where the payload is copied
        // out and the memory it came through is wiped before any screen goes up.
        Content::Firmware | Content::Seed(_) | Content::Unknown => {
            drop(held);
            menu::message(ui.panel, head, "not over NFC", "any key to go back");
            menu::wait_for_any_key(ui);
        }
    }
}

/// Hand a received transaction to the signer.
///
/// The bytes are copied out of the heap block and into the signing workspace, because that
/// is where every signature is written and it is megabytes rather than kilobytes: the same
/// two alternating buffers the card and scanner paths use, since each signature rewrites
/// the whole container.
///
/// **The block is given back as soon as the copy is done**, before the review starts. The
/// heap is 32 KiB and the review's own screens want most of it -- a card browser alone
/// takes 16 -- so holding eight kilobytes of tag across it would turn a signature into a
/// screen apologising for memory.
fn sign(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    mut held: crate::heap::Block,
    at: usize,
    len: usize,
) {
    const HEAD: &str = "Sign";
    let mut lease = match crate::psram::take(crate::psram::Use::Signing) {
        Ok(l) => l,
        Err(why) => {
            menu::message(ui.panel, HEAD, why.message(), "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        }
    };
    let all = lease.bytes();
    // A word-aligned split, because everything writing this region writes whole words.
    let half = (all.len() / 2) & !3;
    let (buf, spare) = all.split_at_mut(half);
    if len > buf.len() {
        drop(lease);
        menu::message(
            ui.panel,
            HEAD,
            "too big for this board",
            "any key to go back",
        );
        menu::wait_for_any_key(ui);
        return;
    }
    buf[..len].copy_from_slice(&held.bytes()[at..at + len]);
    drop(held);
    let len = match crate::signtx::as_psbt_bytes(buf, len, spare) {
        Ok(n) => n,
        Err(why) => {
            drop(lease);
            menu::message(ui.panel, HEAD, why, "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        }
    };
    crate::signtx::review_and_sign(gate, login, ui, buf, spare, len, &crate::signtx::SignDest::SINGLE);
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
        &mut image,
        AREA,
        "catcard.example/nfc-test",
        catcard_nfc::prefix::HTTPS,
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
