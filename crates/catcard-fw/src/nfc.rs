//! The NFC tag: what a phone reads off this device, and what it writes back.
//!
//! An ST25DV64KC sits on I²C1 beside the Q1's co-processor -- 8192 bytes of EEPROM the
//! MCU writes over the bus and a phone reads over RF. Writing an NFC Forum Type 5 image
//! into it ([`catcard_nfc`]) makes the tag one a phone opens as a link; reading the same
//! memory back is how a transaction a phone wrote arrives here.
//!
//! What goes through it:
//!
//! - **Broadcast**: a signed transaction leaves here as a PushTx link -- a URL whose
//!   *fragment* holds the transaction, so the phone that taps the device opens a page
//!   that can send it. Nothing is sent by this device, which has no network of any kind;
//!   the phone does the sending, and its owner sees the page before it does. Which page
//!   is Settings → NFC Push Tx: Coldcard's, mempool.space's, one the owner typed, or none.
//! - **Share an address**: the address on the explorer's screen, as a `bitcoin:` URI, so a
//!   phone tapped on it can pay to it without anyone reading out 42 characters.
//! - **Receive**: the tag is marked ready, a phone writes an NDEF message to it, and what
//!   arrives goes to the same offer the scanner's does ([`crate::sniff`]) -- which in
//!   practice means a PSBT goes to the signing screen, and the signed result comes back
//!   out on the tag.
//! - **The tools**: Utils → NFC Tools, stock's drawer of the same name: a message to sign
//!   or a signed one to check, a multisig descriptor, a seed phrase to work in for the
//!   session, a `.txn` file from the card to push, and any file to share.
//!
//! Every one of them is a menu action. Nothing here runs at boot, nothing is written to
//! the tag that the owner did not ask for, and **all of it is behind one switch**:
//! Settings → Hardware On/Off → NFC Sharing ([`enabled`]). Off, every entry point says
//! so in one line and the tag is neither written nor read.
//!
//! # What is confirmed
//!
//! - The tag sits on I²C1, which the MCU bit-bangs rather than drives from the I²C
//!   peripheral: `NFC_SCL=PB6`, `NFC_SDA=PB7`, open drain with external pull-ups, 7-bit
//!   address `0x53` for user memory. Its event line is `NFC_ED=PC4` on mk4/mk5 and `PD6`
//!   on the Q1, and the Q1 alone has an `NFC_ACTIVE=PE4` LED output; neither is driven
//!   here. mk3 has no tag.
//!   Source: hw-reference/gpio.md §"I²C buses (mk4 / mk5 / Q1)", §"Indicator LEDs" [C];
//!   hw-reference/generations-mk2-q-mk5.md §"Bill-of-materials" [C];
//!   hw-reference/secure-elements.md §NFC [C]
//! - Device select `0xA6`/`0xA7` -- 7-bit `0x53` -- for user memory, two address bytes,
//!   most significant first; sequential write of up to 256 bytes provided they stay in one
//!   area; user memory organised in rows of 16, one write time `tW` (5 ms, 5.5 ms over
//!   85 °C) per row touched.
//!   Source: hw-reference/datasheets/ST25DV64KC-st.pdf §6.3, §6.4.2, Tables 89, 249-251 [C]
//! - A read is a dummy write of the two address bytes, a **repeated** start, and then
//!   bytes out until the controller does not acknowledge one. The counter walks forwards
//!   on its own and does not roll over at the end of user memory.
//!   Source: same, §6.5.1 "Random address read", §6.5.3 "Sequential read access" [C]
//!
//! Writes here go a row at a time and wait out `tW` afterwards, which is the slow and
//! obviously-correct reading of the above -- and then the whole image is read back and
//! compared, so a write the part silently dropped is reported rather than tapped.
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
//!
//! # What a shared file goes out as `[?]`
//!
//! A PSBT goes out as its base64 in a text record, a UTF-8 file as a text record, and
//! anything else as a MIME record of `application/octet-stream`. Those are the record
//! types any phone's reader shows and this device's own receive path takes back; which
//! record a given wallet app registers for has not been checked against one. See
//! `docs/HARDWARE-OPEN-ITEMS.md`.

use catcard_hal::softi2c::{GpioLines, SoftI2c};

use crate::menu;
use crate::sniff::{Content, sniff};
use crate::ui::Ui;
use catcard_board::BOARD;
use catcard_callgate::Callgate;
use catcard_nfc::pushtx;
use catcard_settings::prefs::PushTx;
use zeroize::Zeroize as _;

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
/// Bytes compared per read while checking a write. Any size works; this keeps the stack
/// buffer small and the number of transfers reasonable.
const VERIFY_CHUNK: usize = 64;

/// The most a shared file can be: the tag itself. Whether a given file fits depends on
/// the record around it and is answered by the builder, not guessed here.
pub(crate) const SHARE_MAX: usize = USER_MEMORY;

/// The tag's bus, or `None` on a board without one.
fn bus() -> Option<SoftI2c<GpioLines>> {
    let nfc = BOARD.nfc?;
    // SAFETY: I²C1's two pins; the co-processor driver takes the same bus the same way,
    // and the menu runs one screen at a time.
    Some(SoftI2c::new(unsafe { GpioLines::new(nfc.scl, nfc.sda?) }))
}

/// Write `bytes` into user memory from address zero, and read them back.
///
/// A row at a time: each write carries its own address, so a row that is refused stops the
/// whole thing rather than leaving the tag holding half of one image and half of another.
/// Then every byte is read back and compared, because an EEPROM write the part did not
/// take -- a phone in the field holding the RF side, a row that timed out -- looks exactly
/// like one it did until somebody taps it.
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
    let mut back = [0u8; VERIFY_CHUNK];
    for (n, chunk) in bytes.chunks(VERIFY_CHUNK).enumerate() {
        let at = (n * VERIFY_CHUNK) as u16;
        i2c.write_read(USER, &[(at >> 8) as u8, at as u8], &mut back[..chunk.len()])
            .map_err(|_| "the tag did not answer")?;
        if back[..chunk.len()] != *chunk {
            return Err("the tag did not take the write");
        }
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

// ---------------------------------------------------------------------------
// The switch
// ---------------------------------------------------------------------------

/// Whether the owner has NFC switched on: Settings → Hardware On/Off → NFC Sharing.
///
/// The one thing every entry point below checks first. A tag that is "off" is not
/// powered down -- the part answers RF on its own -- but nothing is put on it and nothing
/// is read off it, which is what the switch promises.
pub(crate) fn enabled() -> bool {
    crate::prefs::current().nfc_sharing
}

/// Say the tag is off and wait for a key. `true` when the caller should stop.
fn refused_off(ui: &mut Ui<'_>, head: &str) -> bool {
    if enabled() {
        return false;
    }
    menu::message(ui.panel, head, "NFC Sharing is off", "see Hardware On/Off");
    menu::wait_for_any_key(ui);
    true
}

/// Say the board has no tag, or none answered, and wait for a key. `true` to stop.
fn refused_absent(ui: &mut Ui<'_>, head: &str) -> bool {
    if BOARD.nfc.is_none() {
        menu::message(ui.panel, head, "no NFC on this board", "");
        menu::wait_for_any_key(ui);
        return true;
    }
    if !present() {
        menu::message(ui.panel, head, "no tag answered", "any key to go back");
        menu::wait_for_any_key(ui);
        return true;
    }
    false
}

/// Put `image` on the tag, hold the screen while a phone reads it, then blank the tag.
///
/// `note` is the second line of the "tap your phone" screen: what the phone gets.
fn present_image(ui: &mut Ui<'_>, head: &str, image: &[u8], note: &str) {
    menu::blocking_screen(ui.panel, head, "writing the tag");
    match write_user_memory(image) {
        Ok(()) => {
            crate::catlog!("nfc: {} bytes on the tag", image.len());
            menu::message(ui.panel, "Tap your phone", note, "any key when done");
            menu::wait_for_any_key(ui);
            clear();
        }
        Err(why) => {
            crate::catlog!("nfc: write failed: {}", why);
            menu::message(ui.panel, head, why, "any key to go back");
            menu::wait_for_any_key(ui);
        }
    }
}

// ---------------------------------------------------------------------------
// PushTx
// ---------------------------------------------------------------------------

/// The chain segment the signer names when it hands a transaction here. PushTx is a
/// Bitcoin service; anything else is refused with a log line rather than pushed to a
/// page that would not know it.
pub(crate) const CHAIN: &str = "btc";

/// The network the wallet in force is on, as the PushTx `n` parameter spells it.
fn network() -> pushtx::Network {
    use catcard_settings::prefs::Chain;
    match crate::prefs::current().net {
        Chain::Mainnet => pushtx::Network::Mainnet,
        Chain::Testnet => pushtx::Network::Testnet,
        Chain::Regtest => pushtx::Network::Regtest,
    }
}

/// The most a transaction can be and still fit both the tag and the specification's
/// URL length, for a service URL of `service_len` bytes.
///
/// The record abbreviates `https://` to one byte, so the tag has a little more room than
/// the URL's own length says; the bound is taken on the longer spelling, which is what the
/// specification's 8,000-byte limit counts.
fn max_transaction(service_len: usize) -> usize {
    let room = (USER_MEMORY - catcard_nfc::image_len(0)).min(pushtx::URL_MAX);
    pushtx::max_tx_len(room, service_len, network())
}

/// Offer to put a signed transaction on the tag as a PushTx link, and hold the screen
/// while a phone reads it. `raw` is the network transaction, exactly as it would be
/// broadcast.
///
/// Asked rather than done: the link carries the whole transaction, so tapping a phone to
/// this hands it to whoever that phone talks to. A device that wrote it unasked would be
/// publishing a transaction its owner had only signed. Silent -- a log line, no screen --
/// when NFC is off, when the PushTx setting is Disabled, or when `chain` is not Bitcoin:
/// this is an offer after a signature, not something the owner asked for, and a refusal
/// screen after every signature would be the switch nagging.
pub(crate) fn offer_broadcast(ui: &mut Ui<'_>, chain: &str, raw: &[u8]) {
    const HEAD: &str = "Broadcast";
    if BOARD.nfc.is_none() {
        return;
    }
    if !enabled() {
        crate::catlog!("nfc: sharing is off, no broadcast offered");
        return;
    }
    if chain != CHAIN {
        crate::catlog!("nfc: pushtx is for bitcoin, not {}", chain);
        return;
    }
    let prefs = crate::prefs::current();
    let Some(service) = prefs.pushtx.service() else {
        crate::catlog!("nfc: pushtx is disabled, no broadcast offered");
        return;
    };
    if raw.len() > max_transaction(service.len()) {
        crate::catlog!("nfc: {} bytes is too big for the tag", raw.len());
        return;
    }
    let mut via: heapless::String<32> = heapless::String::new();
    let _ = via.push_str("sends it via ");
    let _ = via.push_str(prefs.pushtx.label());
    menu::ask(
        ui.panel,
        "Broadcast by NFC?",
        "a phone that taps this",
        via.as_str(),
    );
    if !menu::confirmed(ui) {
        return;
    }
    if refused_absent(ui, HEAD) {
        return;
    }
    push_raw(ui, HEAD, service, raw);
}

/// Build the PushTx link for `raw` under `service`, write it, and hold the screen.
///
/// The image is built in the heap: a transaction's base64 is far more than a screen's
/// stack has, and it is given back as soon as the tag has it.
fn push_raw(ui: &mut Ui<'_>, head: &str, service: &str, raw: &[u8]) {
    let Some(mut held) = crate::heap::take(USER_MEMORY) else {
        menu::message(ui.panel, head, "not enough memory", "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    };
    let out = held.bytes();
    let n = match build_pushtx(out, service, raw) {
        Ok(n) => n,
        Err(why) => {
            drop(held);
            menu::message(ui.panel, head, why, "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        }
    };
    present_image(ui, head, &out[..n], "to send it");
}

/// Build the tag image for `raw`: the service URL with the transaction in its fragment,
/// per the PushTx specification.
fn build_pushtx(out: &mut [u8], service: &str, raw: &[u8]) -> Result<usize, &'static str> {
    pushtx::check_service(service).map_err(|_| "bad PushTx URL")?;
    // `https://` is one byte in an NDEF URI, so the text starts after the scheme.
    let rest = service.strip_prefix("https://").ok_or("bad PushTx URL")?;
    let net = network();
    let text_len = rest.len() + pushtx::params_len(raw.len(), net);
    let mut at = catcard_nfc::begin(out, AREA, text_len, catcard_nfc::prefix::HTTPS)
        .map_err(|_| "too big for the tag")?;
    out[at..at + rest.len()].copy_from_slice(rest.as_bytes());
    at += rest.len();
    at += pushtx::write_params(raw, net, &mut out[at..]).map_err(|_| "too big for the tag")?;
    catcard_nfc::finish(out, at).map_err(|_| "too big for the tag")
}

/// NFC Tools → Push Transaction: a `.txn` file from the card or the Virtual Disk, as a
/// PushTx link.
///
/// The file is the hex this device writes as `FINAL.TXN` -- or any hex transaction
/// another tool wrote. It is decoded and checked for size before anything is asked, and
/// nothing about it is verified beyond being hex: what is pushed is the owner's file,
/// and the page the phone opens shows the transaction before it sends.
pub(crate) fn push_file_screen(ui: &mut Ui<'_>) {
    const HEAD: &str = "Push Tx";
    if refused_off(ui, HEAD) {
        return;
    }
    let prefs = crate::prefs::current();
    let Some(service) = prefs.pushtx.service() else {
        menu::message(ui.panel, HEAD, "PushTx is disabled", "see Settings");
        menu::wait_for_any_key(ui);
        return;
    };
    let Some(storage) = menu::pick_storage(ui, HEAD) else {
        return;
    };
    let Some(path) =
        menu::browse_storage(ui, storage, "Pick a .txn", Some("txn"), menu::Browse::File)
    else {
        return;
    };
    // Room for the hex of the largest transaction that would fit, plus a little for the
    // line ending an editor leaves. A bigger file is refused by the read.
    let most = max_transaction(service.len());
    let Some(mut held) = crate::heap::take(most * 2 + 16) else {
        menu::message(ui.panel, HEAD, "not enough memory", "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    };
    menu::card_wait(ui.panel, HEAD, "reading the file");
    let len = match crate::signtx::read_source_file(storage, &path, held.bytes()) {
        Ok(n) => n,
        Err(why) => {
            drop(held);
            menu::message(ui.panel, HEAD, why, "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        }
    };
    let raw_len = match unhex_in_place(&mut held.bytes()[..len]) {
        Some(n) => n,
        None => {
            drop(held);
            menu::message(
                ui.panel,
                HEAD,
                "not a hex transaction",
                "any key to go back",
            );
            menu::wait_for_any_key(ui);
            return;
        }
    };
    if raw_len == 0 || raw_len > most {
        drop(held);
        menu::message(ui.panel, HEAD, "too big for the tag", "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    }
    let mut what: heapless::String<32> = heapless::String::new();
    let _ = core::fmt::Write::write_fmt(&mut what, format_args!("{raw_len} bytes via"));
    menu::ask(
        ui.panel,
        "Push by NFC?",
        what.as_str(),
        prefs.pushtx.label(),
    );
    if !menu::confirmed(ui) {
        return;
    }
    if refused_absent(ui, HEAD) {
        return;
    }
    // Copied out of the heap block into the PSRAM lease, so the image built from it can
    // take the block the transaction is in. Not signing, but the same shared scratch.
    let mut lease = match crate::psram::take(crate::psram::Use::Signing) {
        Ok(l) => l,
        Err(why) => {
            drop(held);
            menu::message(ui.panel, HEAD, why.message(), "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        }
    };
    let raw = &mut lease.bytes()[..raw_len];
    raw.copy_from_slice(&held.bytes()[..raw_len]);
    drop(held);
    push_raw(ui, HEAD, service, raw);
}

/// Decode hex text in place, ignoring surrounding whitespace. The byte count, or `None`
/// for anything that is not an even run of hex digits.
fn unhex_in_place(buf: &mut [u8]) -> Option<usize> {
    let text = core::str::from_utf8(buf).ok()?.trim();
    let start = text.as_ptr() as usize - buf.as_ptr() as usize;
    let len = text.len();
    if len == 0 || len % 2 != 0 {
        return None;
    }
    fn nib(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    for i in 0..len / 2 {
        let hi = nib(buf[start + 2 * i])?;
        let lo = nib(buf[start + 2 * i + 1])?;
        buf[i] = (hi << 4) | lo;
    }
    Some(len / 2)
}

/// Offer to put a Solana transaction on the tag as a link, and hold the screen while a
/// phone reads it.
///
/// The same tap as [`offer_broadcast`], and the same bargain: the transaction goes after
/// a `#`, a fragment is never sent, the phone opens a page which reads the transaction
/// out of its own address bar, and nothing leaves the phone until somebody there says to
/// send it. `raw` is the transaction exactly as it would be submitted.
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
    if !enabled() {
        crate::catlog!("nfc: sharing is off, no link offered");
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
    if refused_absent(ui, HEAD) {
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
    present_image(ui, HEAD, &out[..n], "to take it");
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
const SHARE_ADDRESS_MAX: usize = catcard_nfc::image_len(
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
    if refused_off(ui, HEAD) || refused_absent(ui, HEAD) {
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

    let mut image = [0u8; SHARE_ADDRESS_MAX];
    let n = match catcard_nfc::uri_image(&mut image, AREA, &uri, catcard_nfc::prefix::NONE) {
        Ok(n) => n,
        Err(_) => {
            menu::message(ui.panel, HEAD, "too big for the tag", "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        }
    };
    present_image(ui, HEAD, &image[..n], "to read the address");
}

// ---------------------------------------------------------------------------
// Sharing a file, or any bytes
// ---------------------------------------------------------------------------

/// Read `path` off an already-mounted volume into `buf`, whole. Its length, or why not:
/// a file longer than `buf` is refused, not read in part.
///
/// The file browser's reader for the share rows -- it holds the volume open while the
/// listing is up, so the read has to go through that mount rather than a fresh one.
pub(crate) fn read_for_share<D: catcard_sd::fat::SectorDriver>(
    vol: &mut catcard_sd::AnyVolume<D, 512>,
    path: &str,
    buf: &mut [u8],
) -> Result<usize, &'static str> {
    let mut file = vol.open_file(path).map_err(|_| "could not open file")?;
    let len = file.len();
    if len > buf.len() as u64 {
        return Err("too large for the tag");
    }
    let len = len as usize;
    let mut got = 0usize;
    while got < len {
        match file.read(vol, &mut buf[got..len]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(()) => return Err("read failed"),
        }
    }
    if got != len {
        return Err("file changed while reading");
    }
    Ok(got)
}

/// Put `bytes` on the tag as whatever record suits them, and hold the screen.
///
/// A PSBT goes as its base64 in a text record, so any reader shows it and a wallet can
/// paste it; UTF-8 text goes as a text record; anything else as a MIME record of
/// `application/octet-stream`. `name` is what the screen calls it. Says "too large for
/// the tag" rather than sending part of a file.
pub(crate) fn share_bytes(ui: &mut Ui<'_>, name: &str, bytes: &[u8]) {
    const HEAD: &str = "Share by NFC";
    if refused_off(ui, HEAD) {
        return;
    }
    if bytes.is_empty() {
        menu::message(ui.panel, HEAD, "nothing in that file", "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    }
    let what = sniff(bytes);
    let is_psbt = matches!(what, Content::Psbt) && bytes.starts_with(b"psbt\xff");
    let text = if is_psbt {
        None
    } else {
        core::str::from_utf8(bytes).ok()
    };
    let image_len = if is_psbt {
        catcard_nfc::text_image_len(bytes.len().div_ceil(3) * 4)
    } else if let Some(t) = text {
        catcard_nfc::text_image_len(t.len())
    } else {
        catcard_nfc::mime_image_len(catcard_nfc::OCTET_STREAM.len(), bytes.len())
    };
    if image_len > USER_MEMORY {
        menu::message(
            ui.panel,
            HEAD,
            "too large for the tag",
            "any key to go back",
        );
        menu::wait_for_any_key(ui);
        return;
    }
    menu::ask(
        ui.panel,
        "Share by NFC?",
        name,
        "a phone that taps reads it",
    );
    if !menu::confirmed(ui) {
        return;
    }
    if refused_absent(ui, HEAD) {
        return;
    }
    let Some(mut held) = crate::heap::take(image_len) else {
        menu::message(ui.panel, HEAD, "not enough memory", "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    };
    let out = held.bytes();
    let built = if is_psbt {
        let chars = bytes.len().div_ceil(3) * 4;
        catcard_nfc::begin_text(out, AREA, chars).and_then(|at| {
            let n = outscript::base64::encode_to_slice(bytes, &mut out[at..at + chars]).map_err(
                |_| catcard_nfc::Error::TooLong {
                    needed: chars,
                    room: 0,
                },
            )?;
            catcard_nfc::finish(out, at + n)
        })
    } else if let Some(t) = text {
        catcard_nfc::text_image(out, AREA, t)
    } else {
        catcard_nfc::mime_image(out, AREA, catcard_nfc::OCTET_STREAM, bytes)
    };
    let n = match built {
        Ok(n) => n,
        Err(_) => {
            drop(held);
            menu::message(
                ui.panel,
                HEAD,
                "too large for the tag",
                "any key to go back",
            );
            menu::wait_for_any_key(ui);
            return;
        }
    };
    present_image(ui, HEAD, &out[..n], "to read the file");
}

/// NFC Tools → File Share: the file browser, whose file screen has the share rows.
pub(crate) fn file_share_screen(ui: &mut Ui<'_>) {
    const HEAD: &str = "File Share";
    if refused_off(ui, HEAD) {
        return;
    }
    let Some(storage) = menu::pick_storage(ui, HEAD) else {
        return;
    };
    let _ = menu::browse_storage(
        ui,
        storage,
        "Pick a file to share",
        None,
        menu::Browse::View,
    );
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

/// What a phone wrote: the whole tag in the heap, and where the usable payload is in it.
///
/// A range rather than a slice, because the bytes have to be handed on to a signer and
/// that cannot happen while a borrow of the block is still alive.
struct Received {
    held: crate::heap::Block,
    at: usize,
    len: usize,
    what: Content,
}

impl Received {
    /// The payload.
    fn bytes(&mut self) -> &[u8] {
        &self.held.bytes()[self.at..self.at + self.len]
    }

    /// The payload as text, if it is.
    fn text(&mut self) -> Option<&str> {
        core::str::from_utf8(self.bytes()).ok()
    }

    /// Wipe the whole block: for a payload that turned out to be a seed.
    fn wipe(&mut self) {
        self.held.bytes().zeroize();
    }
}

/// Mark the tag, wait for a phone to write to it, read it, blank it, and say what the
/// first usable record holds. `None` after saying why not.
///
/// Every wait in here is bounded: [`WAIT_MS`] of polling, a read of at most the part's
/// memory, and record lengths checked by [`catcard_nfc::read`] against what was read.
fn receive(ui: &mut Ui<'_>, head: &str) -> Option<Received> {
    if refused_off(ui, head) || refused_absent(ui, head) {
        return None;
    }

    // Mark the tag ready. This is also the baseline: what the poll below is watching for
    // is these bytes stopping being what was just written.
    let mut marker = [0u8; catcard_nfc::text_image_len(READY_TEXT.len())];
    let Ok(n) = catcard_nfc::text_image(&mut marker, AREA, READY_TEXT) else {
        return None;
    };
    menu::blocking_screen(ui.panel, head, "marking the tag");
    if let Err(why) = write_user_memory(&marker[..n]) {
        crate::catlog!("nfc: could not mark the tag: {}", why);
        menu::message(ui.panel, head, why, "any key to go back");
        menu::wait_for_any_key(ui);
        return None;
    }
    let mut baseline = [0u8; WATCH];
    let keep = n.min(WATCH);
    baseline[..keep].copy_from_slice(&marker[..keep]);

    match wait_for_write(ui, head, &baseline) {
        Waited::Written => {}
        Waited::Cancelled => {
            clear();
            return None;
        }
        Waited::TimedOut => {
            clear();
            menu::message(ui.panel, head, "no phone wrote to it", "any key to go back");
            menu::wait_for_any_key(ui);
            return None;
        }
        Waited::Failed(why) => {
            menu::message(ui.panel, head, why, "any key to go back");
            menu::wait_for_any_key(ui);
            return None;
        }
    }

    // The whole of user memory, in the heap: it is eight kilobytes, which no screen's
    // stack has, and the records parsed out of it borrow it until the payload is copied
    // somewhere the signer can use.
    let Some(mut held) = crate::heap::take(USER_MEMORY) else {
        menu::message(ui.panel, head, "not enough memory", "any key to go back");
        menu::wait_for_any_key(ui);
        return None;
    };
    menu::blocking_screen(ui.panel, head, "reading the tag");
    if let Err(why) = read_user_memory(0, held.bytes()) {
        crate::catlog!("nfc: read failed: {}", why);
        drop(held);
        menu::message(ui.panel, head, why, "any key to go back");
        menu::wait_for_any_key(ui);
        return None;
    }
    // The tag has been read; whatever a phone left on it does not need to stay there.
    clear();

    let Some((what, at, len)) = first_usable(held.bytes()) else {
        drop(held);
        menu::message(ui.panel, head, "nothing this can use", "any key to go back");
        menu::wait_for_any_key(ui);
        return None;
    };
    crate::catlog!("nfc: {} bytes received, {:?}", len, what);
    Some(Received {
        held,
        at,
        len,
        what,
    })
}

/// Take a transaction in by NFC: mark the tag, wait for a phone to write to it, and offer
/// whatever arrived.
///
/// The offer is [`crate::sniff`]'s, the same one the Q1's scanner uses -- so a PSBT that
/// arrives by tap gets the review and the signatures a PSBT read off a card or a camera
/// does, and something that is not a PSBT says so in the same words.
pub(crate) fn receive_screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    const HEAD: &str = "By NFC";
    let Some(got) = receive(ui, HEAD) else {
        return;
    };
    offer(gate, login, ui, HEAD, got);
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
fn offer(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    head: &str,
    mut got: Received,
) {
    // A seed phrase written as text is answered before anything is shown: the scanner
    // has the same rule for a SeedQR, and "here is what you tapped" on the glass is not
    // what someone handing over their words asked for.
    if got.what == Content::Text && got.text().and_then(phrase_word_count).is_some() {
        load_words(gate, login, ui, head, got);
        return;
    }
    // The same list the scanner offers, from the same place: what this firmware makes of
    // the bytes, and keeping them whatever they are.
    let choices = got.what.choices();
    if choices.is_empty() {
        let note = got.what.note();
        drop(got);
        menu::message(ui.panel, head, note, "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    }
    let mut rows: heapless::Vec<&str, 2> = heapless::Vec::new();
    for (label, _) in &choices {
        let _ = rows.push(label);
    }
    let Some(chosen) = menu::choose(ui, head, got.what.note(), &rows) else {
        return;
    };
    if choices[chosen].1 == crate::sniff::Act::Save {
        let what = got.what;
        crate::sniff::save_to_card(ui, got.bytes(), what);
        return;
    }
    match got.what {
        Content::Psbt => sign(gate, login, ui, got),
        // As on the scanner: read and named, and honest that the screen which lays the
        // whole of it out -- and the signing behind that -- are not built yet.
        #[cfg(feature = "multichain")]
        Content::EvmTx { .. } => {
            crate::evmtx::screen(ui, got.bytes());
        }
        #[cfg(feature = "multichain")]
        Content::SolanaTx { base64 } => {
            crate::solanatx::screen(gate, login, ui, got.bytes(), base64);
        }
        Content::Text => {
            let text = got.text().unwrap_or("(not text)");
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
            drop(got);
            menu::message(ui.panel, head, "not over NFC", "any key to go back");
            menu::wait_for_any_key(ui);
        }
    }
}

/// Where the NFC path writes what it signed: its own names on the Virtual Disk, so the
/// result can be read back and put on the tag without a card, and without touching the
/// `SIGNED.PSB` a card flow may have left there.
const NFC_SIGNED: &str = "/NFC-SIGNED.PSB";
const NFC_FINAL: &str = "/NFC-FINAL.TXN";
const NFC_DEST: crate::signtx::SignDest<'static> = crate::signtx::SignDest {
    signed_name: NFC_SIGNED,
    final_name: NFC_FINAL,
    offer_transports: true,
};

/// Hand a received transaction to the signer, then offer the signed result back on the
/// tag.
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
///
/// The signer writes to the Virtual Disk under [`NFC_DEST`]'s names, and offers the
/// finalised transaction as a PushTx link itself. What this adds is the other case: a
/// PSBT still waiting on a cosigner, read back off the disk and put on the tag for the
/// phone that brought it.
fn sign(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>, mut got: Received) {
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
    let len = got.len;
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
    buf[..len].copy_from_slice(got.bytes());
    drop(got);
    let len = match crate::signtx::as_psbt_bytes(buf, len, spare) {
        Ok(n) => n,
        Err(why) => {
            drop(lease);
            menu::message(ui.panel, HEAD, why, "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        }
    };
    // Whatever a previous tap left under these names goes first, so that what is read
    // back afterwards is this signature or nothing.
    let _ = menu::with_vdisk(|vol| {
        let _ = vol.remove_file(NFC_SIGNED);
        let _ = vol.remove_file(NFC_FINAL);
        vol.flush().map_err(|_| "flush failed")
    });
    crate::signtx::review_and_sign(
        gate,
        login,
        ui,
        buf,
        spare,
        len,
        &NFC_DEST,
        // Caught over the air, not from a file: the result goes to the Virtual Disk,
        // which every board with a tag has, and from there back onto the tag.
        menu::Storage::Vdisk,
    );
    drop(lease);
    offer_signed_back(ui);
}

/// If the signer left a PSBT under [`NFC_SIGNED`], offer it on the tag.
///
/// Only the PSBT: a transaction that finalised was offered as a PushTx link by the signer
/// already, and a PSBT beside it is one a coordinator wallet will want back as well.
fn offer_signed_back(ui: &mut Ui<'_>) {
    const HEAD: &str = "Signed";
    let Some(mut held) = crate::heap::take(SHARE_MAX) else {
        return;
    };
    let read = menu::with_vdisk(|vol| read_for_share(vol, NFC_SIGNED, held.bytes()));
    let n = match read {
        Ok(n) => n,
        Err("could not open file") => {
            // Nothing was signed, or the write failed and said so.
            return;
        }
        Err(why) => {
            crate::catlog!("nfc: signed psbt not read back: {}", why);
            menu::message(ui.panel, HEAD, why, "it is on the Virtual Disk");
            menu::wait_for_any_key(ui);
            return;
        }
    };
    // `share_bytes` builds its image in a second block, sized to the record; the tag is
    // eight kilobytes and the heap holds both.
    share_bytes(ui, "signed PSBT", &held.bytes()[..n]);
}

// ---------------------------------------------------------------------------
// The tools
// ---------------------------------------------------------------------------

/// Run the NFC Tools row `row` of [`menu::NFC_TOOLS_ITEMS`] that is a routine.
///
/// By name, not by number: the menu hands over the cursor, and the table is what says
/// which row that is, so reordering the table cannot silently swap two tools. The two
/// rows that are screens of their own (`Sign PSBT`, `Show Address`) never arrive here.
pub(crate) fn tool(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>, row: u8) {
    match menu::NFC_TOOLS_ITEMS.get(row as usize).copied() {
        Some("Sign Message") => sign_message_screen(gate, login, ui),
        Some("Verify Sig File") => verify_sig_screen(ui),
        Some("File Share") => file_share_screen(ui),
        Some("Import Multisig") => import_multisig_screen(gate, login, ui),
        Some("Push Transaction") => push_file_screen(ui),
        Some("Import Words") => import_words_screen(gate, login, ui),
        Some("Sign PSBT") => receive_screen(gate, login, ui),
        _ => {}
    }
}

/// NFC Tools → Sign Message: a message a phone writes to the tag, signed, and the
/// armoured signature put back on the tag for the phone to read.
pub(crate) fn sign_message_screen(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) {
    const HEAD: &str = "Sign message";
    let Some(mut got) = receive(ui, HEAD) else {
        return;
    };
    let Some(text) = got.text() else {
        menu::message(ui.panel, HEAD, "not text", "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    };
    // The trailing newline is the phone's, not the owner's, as with a file.
    let text = text.trim_end();
    if let Some(why) = crate::signmsg::unshowable(text) {
        menu::message(ui.panel, HEAD, why, "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    }
    // The message is a few hundred bytes at most; copied to the stack so the tag block
    // is free before the signer's own screens want the heap.
    let mut message: heapless::String<{ catcard_wallet::message::MAX_MESSAGE }> =
        heapless::String::new();
    if message.push_str(text).is_err() {
        menu::message(ui.panel, HEAD, "message too long", "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    }
    drop(got);
    // TODO(integrator): `sign_to_file` is the one text-taking entry point signmsg has
    // today; if the message-signing work replaces it, this is the call to follow.
    let Some(file) = crate::signmsg::sign_to_file(gate, login, ui, HEAD, message.as_str()) else {
        return;
    };
    share_bytes(ui, "the signature", file.as_bytes());
}

/// NFC Tools → Verify Sig File: a signed-message file a phone writes to the tag, checked.
pub(crate) fn verify_sig_screen(ui: &mut Ui<'_>) {
    const HEAD: &str = "Verify sig";
    let Some(mut got) = receive(ui, HEAD) else {
        return;
    };
    let Some(text) = got.text() else {
        menu::message(ui.panel, HEAD, "not text", "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    };
    crate::verifysig::verify_text(ui, HEAD, "nfc", text);
}

/// Where a multisig descriptor a phone wrote is put for the importer to pick up.
const NFC_MULTISIG: &str = "/NFC-MULTISIG.TXT";

/// NFC Tools → Import Multisig: a descriptor or config a phone writes to the tag.
///
/// The importer reads from the card, so what arrived is written there under one name and
/// the importer is opened on it: two screens where stock has one, but the same review and
/// the same store.
// TODO(integrator): route the text straight into `msimport` once it has a text-taking
// entry point (the `sniff::Content::MultisigConfig` work), and drop the card round trip.
pub(crate) fn import_multisig_screen(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) {
    const HEAD: &str = "Import multisig";
    let Some(mut got) = receive(ui, HEAD) else {
        return;
    };
    let Some(text) = got.text() else {
        menu::message(ui.panel, HEAD, "not text", "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    };
    if !looks_like_multisig(text) {
        menu::message(
            ui.panel,
            HEAD,
            "not a multisig descriptor",
            "any key to go back",
        );
        menu::wait_for_any_key(ui);
        return;
    }
    menu::card_wait(ui.panel, HEAD, "writing to the card");
    if let Err(why) = menu::write_card_file(NFC_MULTISIG, got.bytes()) {
        menu::message(ui.panel, HEAD, why, "needs a card to import");
        menu::wait_for_any_key(ui);
        return;
    }
    drop(got);
    menu::message(
        ui.panel,
        HEAD,
        "saved as NFC-MULTISIG.TXT",
        "pick it to import",
    );
    menu::wait_for_any_key(ui);
    crate::msimport::import(gate, login, ui);
}

/// Whether `text` has the shape of a multisig descriptor or a Coldcard-style config: a
/// `multi(`/`sortedmulti(` somewhere, or the config's `Policy:` line.
fn looks_like_multisig(text: &str) -> bool {
    text.contains("multi(") || text.lines().any(|l| l.trim_start().starts_with("Policy:"))
}

/// NFC Tools → Import Words: a 12/18/24-word phrase a phone writes to the tag, put in
/// force for this session as a temporary seed.
pub(crate) fn import_words_screen(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) {
    const HEAD: &str = "Import words";
    let Some(mut got) = receive(ui, HEAD) else {
        return;
    };
    if got.text().and_then(phrase_word_count).is_none() {
        got.wipe();
        menu::message(ui.panel, HEAD, "not a 12/18/24 word", "phrase");
        menu::wait_for_any_key(ui);
        return;
    }
    load_words(gate, login, ui, HEAD, got);
}

/// How many words `text` is, if it is shaped like a BIP-39 phrase: 12, 18 or 24
/// lowercase words of three to eight letters. Whether they are *the* words, with a
/// checksum that adds up, is the parser's question and is asked masked.
fn phrase_word_count(text: &str) -> Option<usize> {
    let mut n = 0;
    for w in text.split_ascii_whitespace() {
        if !(3..=8).contains(&w.len()) || !w.bytes().all(|b| b.is_ascii_lowercase()) {
            return None;
        }
        n += 1;
    }
    matches!(n, 12 | 18 | 24).then_some(n)
}

/// Parse the phrase in `got`, wipe it, and work in the seed for the session.
///
/// The same steps as reading a SeedQR: parse masked, copy the entropy out, wipe the memory
/// it came through, ask, load, and name the wallet by its fingerprint so the owner can
/// tell whether it is the one that was meant.
fn load_words(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    head: &str,
    mut got: Received,
) {
    use catcard_wallet::bip39::{MAX_ENTROPY_LEN, Mnemonic};
    use core::fmt::Write as _;

    let parsed = {
        let Some(text) = got.text() else {
            got.wipe();
            return;
        };
        crate::keywork::run(|kw| {
            Mnemonic::parse(text, kw).map(|m| {
                let mut ent = [0u8; MAX_ENTROPY_LEN];
                let e = m.entropy();
                ent[..e.len()].copy_from_slice(e);
                (ent, e.len(), m.word_count())
            })
        })
    };
    // The words were on the tag (blanked in `receive`) and are in this block: gone before
    // any screen goes up.
    got.wipe();
    drop(got);

    let (mut ent, len, words) = match parsed {
        Ok(v) => v,
        Err(_) => {
            menu::message(ui.panel, head, "not a valid phrase", "checksum failed");
            menu::wait_for_any_key(ui);
            return;
        }
    };
    let mut what: heapless::String<32> = heapless::String::new();
    let _ = write!(what, "{words} words, checksum ok");
    menu::ask(ui.panel, "Work in this?", &what, "the stored seed stays");
    if !menu::confirmed(ui) {
        ent.zeroize();
        return;
    }
    let was = crate::key::in_force();
    if !crate::key::set_temporary(&ent[..len], "NFC") {
        ent.zeroize();
        menu::message(ui.panel, head, "that seed length", "is not usable");
        menu::wait_for_any_key(ui);
        return;
    }
    ent.zeroize();
    match menu::master_quietly(gate, login, ui.panel, head) {
        Ok(master) => {
            let [a, b, c, d] = crate::keywork::run(|kw| master.fingerprint(kw));
            drop(master);
            let mut said: heapless::String<24> = heapless::String::new();
            let _ = write!(said, "{a:02X}{b:02X}{c:02X}{d:02X}");
            crate::catlog!("nfc: loaded {} words", words);
            crate::settings::open_wallet(gate, login, ui.panel, head, [a, b, c, d]);
            menu::message(ui.panel, "Loaded", &said, "in force until reboot");
            menu::wait_for_any_key(ui);
        }
        Err(why) => {
            crate::key::set(was);
            menu::message(ui.panel, head, why, "unchanged");
            menu::wait_for_any_key(ui);
        }
    }
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

/// Settings → Hardware On/Off → NFC Sharing.
///
/// Honoured by [`enabled`], which every entry point in this module checks first: off,
/// nothing is put on the tag and nothing read from it.
pub(crate) fn sharing_screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    const HEAD: &str = "NFC Sharing";
    let now = crate::prefs::current();
    let Some(want) = menu::pick_switch(ui, HEAD, now.nfc_sharing) else {
        return;
    };
    menu::save_pref(
        gate,
        login,
        ui,
        HEAD,
        (
            catcard_settings::prefs::NFC_SHARING,
            if want { "1" } else { "0" },
        ),
        crate::prefs::Prefs {
            nfc_sharing: want,
            ..now
        },
        if want { "on" } else { "off" },
    );
}

/// The rows of the PushTx chooser, in stock's order: the suppliers, a custom URL, off.
/// Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §SET "NFC Push Tx" [C]
const PUSHTX_ROWS: &[&str] = &["coldcard.com", "mempool.space", "Custom URL", "Disabled"];

/// Settings → NFC Push Tx: where the link after a signed transaction points.
///
/// Stock warns on the way in, and so does this: the service the phone opens learns the
/// transaction and the phone's address together, and the phone has to be online for the
/// page to send anything. Source: hw-reference/help-and-warning-screens.md §17 "PushTx
/// setup" [C]
pub(crate) fn pushtx_screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    const HEAD: &str = "NFC Push Tx";
    let now = crate::prefs::current();
    let mut note: heapless::String<40> = heapless::String::new();
    let _ = note.push_str("now ");
    let _ = note.push_str(now.pushtx.label());
    let Some(row) = menu::pick_row(ui, HEAD, note.as_str(), PUSHTX_ROWS) else {
        return;
    };
    let want = match row {
        0 => PushTx::Coldcard,
        1 => PushTx::Mempool,
        2 => {
            menu::message(ui.panel, HEAD, "https://... ending in", "? or # or &");
            menu::wait_for_any_key(ui);
            let Some(typed) = crate::passphrase::read(ui, "Service URL") else {
                return;
            };
            let mut url: heapless::String<{ catcard_settings::prefs::PUSHTX_URL_MAX }> =
                heapless::String::new();
            if url.push_str(typed.as_str().trim()).is_err() {
                menu::message(ui.panel, HEAD, "URL too long", "unchanged");
                menu::wait_for_any_key(ui);
                return;
            }
            // A URL typed without the separator gets the one the public services use.
            if !url.ends_with(['?', '#', '&']) {
                let _ = url.push('#');
            }
            let Some(service) = catcard_settings::prefs::ServiceUrl::new(url.as_str()) else {
                menu::message(ui.panel, HEAD, "not an https:// URL", "unchanged");
                menu::wait_for_any_key(ui);
                return;
            };
            PushTx::Custom(service)
        }
        _ => PushTx::Disabled,
    };
    if want == now.pushtx {
        menu::message(ui.panel, HEAD, "unchanged", note.as_str());
        menu::wait_for_any_key(ui);
        return;
    }
    if want != PushTx::Disabled {
        menu::ask(
            ui.panel,
            "Privacy note",
            "the service sees the tx",
            "and the phone's address",
        );
        if !menu::confirmed(ui) {
            return;
        }
    }
    // Quoted here rather than through `prefs::quoted`, whose buffer is sized for a word,
    // not a URL.
    let value = want.value();
    let mut raw: heapless::String<{ catcard_settings::prefs::PUSHTX_URL_MAX + 2 }> =
        heapless::String::new();
    let _ = raw.push('"');
    let _ = raw.push_str(value.as_str());
    let _ = raw.push('"');
    let saved = crate::prefs::save(
        gate,
        login,
        ui,
        HEAD,
        (catcard_settings::prefs::PUSHTX, raw.as_str()),
        crate::prefs::Prefs {
            pushtx: want,
            ..now
        },
    );
    if saved {
        menu::message(ui.panel, HEAD, want.label(), "saved");
    } else {
        menu::message(ui.panel, HEAD, "could not save", "unchanged");
    }
    menu::wait_for_any_key(ui);
}

/// Debug: write a fixed URL to the tag, so the driver can be tried without a transaction.
pub(crate) fn probe_screen(ui: &mut Ui<'_>) {
    const HEAD: &str = "NFC test";
    if refused_off(ui, HEAD) || refused_absent(ui, HEAD) {
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
