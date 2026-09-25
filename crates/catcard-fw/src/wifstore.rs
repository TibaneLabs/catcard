//! The WIF store: up to thirty individual private keys, kept in the wallet's settings.
//!
//! Stock keeps a store of standalone keys that are not derived from the seed -- a swept
//! paper wallet, a key generated for one purpose -- and lets each one sign an input that
//! pays its own address. This is that store: import a WIF or generate one, list them, view
//! an entry's address and (behind a warning) its WIF, delete one, and -- through the normal
//! signing screen -- have any stored key sign a matching PSBT input.
//!
//! Source: hw-reference/firmware-features.md §7 "WIF Store (up to 30 individual keys, which
//! can sign matching inputs)", §11 "WIF store: up to 30 keys" [C]
//!
//! # Where the keys live, and how they are protected
//!
//! Each key is stored as a WIF string in the wallet-in-force's own settings file, under
//! [`wifs::KEY`], so a store made under a passphrase wallet or a BIP-85 child belongs to
//! that wallet and not to the root. The settings slot is sealed on the medium, so the WIF
//! is encrypted at rest; in RAM every buffer that holds one is a leased [`crate::heap`]
//! block, wiped when the screen ends, and a decoded key is a [`WifKey`] (`ZeroizeOnDrop`).
//!
//! # Masking
//!
//! Decoding a WIF, encoding one, and deriving a key's public key are Base58/EC work over
//! the private scalar, so they run inside [`crate::keywork::run`]. Drawing addresses and
//! screens is public and stays outside it.

use catcard_settings::json::Doc;
use catcard_settings::store::{self, SCRATCH};
use catcard_settings::wifs::{self, WifEntry};
use catcard_wallet::address::{self, AddressKind};
use catcard_wallet::bip32::Network;
use catcard_wallet::wif::{MAX_WIF_LEN, WifKey};
use catcard_ui::scroll::Line as Row;
use zeroize::Zeroize as _;

use crate::menu;
use crate::ui::Ui;

const HEAD: &str = "WIF Store";

/// How the settings key is named when a save adds the store to a fresh file.
const SETTINGS_HEAD: &str = HEAD;

/// The decoded keys of the store in force, filled for the signing screen.
///
/// The signer needs both the compressed public key (to recognise which input a key pays)
/// and the scalar (to sign it), so it takes the whole [`WifKey`]. Reading it costs a
/// settings mount and a login-secret fetch, so [`crate::signtx`] reads it once per
/// transaction rather than once per input.
///
/// Returns how many keys were loaded. An empty result is the honest answer for a device
/// with no store, a settings volume that will not mount, or a wallet (a loaded WIF) that
/// keeps no settings: in every case there is simply no stored key to add as a signer.
pub(crate) fn load_keys(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    panel: &mut crate::display::Panel,
    out: &mut heapless::Vec<WifKey, { wifs::MAX_KEYS }>,
) -> usize {
    out.clear();
    let Some(mut doc) = crate::heap::take(SCRATCH) else {
        crate::catlog!("wifstore: no scratch, so no stored keys");
        return 0;
    };
    let key = match crate::settings::wallet_key(gate, login, panel, SETTINGS_HEAD) {
        Ok(k) => k,
        Err(why) => {
            crate::catlog!("wifstore: {}, so no stored keys", why);
            return 0;
        }
    };
    // SAFETY: the region is mapped and readable; nothing is written through this.
    let mut files = match unsafe { crate::settings::Files::mount_read_only() } {
        Ok(f) => f,
        Err(_) => return 0,
    };
    let n = store::read(&mut files, &key, doc.bytes()).unwrap_or(0);
    let parsed = Doc::parse(&doc.bytes()[..n]).unwrap_or_default();
    let mut entries = [WifEntry { label: "", wif: "" }; wifs::MAX_KEYS];
    let have = wifs::list(&parsed, &mut entries);
    // Decoding the WIF reconstructs the scalar, so it is private-key work.
    crate::keywork::run(|kw| {
        for e in &entries[..have] {
            match WifKey::decode(e.wif, kw) {
                Ok(k) => {
                    let _ = out.push(k);
                }
                Err(why) => crate::catlog!("wifstore: skipping a stored key: {:?}", why),
            }
        }
    });
    crate::catlog!("wifstore: {} stored key(s)", out.len());
    out.len()
}

/// The management screen: list, view, delete, generate, import.
pub(crate) fn manage(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) {
    /// Row ids past any key index.
    const GENERATE: u32 = 1000;
    const IMPORT: u32 = 1001;

    /// What the list screen asked for. Nothing here borrows the settings buffer, so acting
    /// on it can read and write the settings again.
    enum Then {
        Leave,
        Generate,
        Import,
        Delete(usize),
    }

    loop {
        menu::blocking_screen(ui.panel, HEAD, "reading");
        let next = {
            let Some(mut doc) = crate::heap::take(SCRATCH) else {
                return say(ui, "not enough memory");
            };
            let doc_buf = doc.bytes();
            let mut entries = [WifEntry { label: "", wif: "" }; wifs::MAX_KEYS];
            let have = match read_entries(gate, login, ui.panel, doc_buf, &mut entries) {
                Ok(n) => n,
                Err(why) => return say(ui, why),
            };

            // A positional label per key, plus its own name where it has one. The WIF is
            // not shown here -- a list is glanced at, and a secret does not belong on a
            // screen someone is only glancing at.
            let mut labels: heapless::Vec<heapless::String<48>, { wifs::MAX_KEYS }> =
                heapless::Vec::new();
            for (i, e) in entries[..have].iter().enumerate() {
                let _ = labels.push(list_label(i, e));
            }

            let exit = {
                let mut rows: heapless::Vec<Row, { wifs::MAX_KEYS + 4 }> = heapless::Vec::new();
                let _ = rows.push(Row::title(HEAD));
                if have == 0 {
                    let _ = rows.push(Row::body("(no keys stored)").centered());
                }
                for (i, l) in labels.iter().enumerate() {
                    let _ = rows.push(Row::item(l.as_str(), i as u32));
                }
                if have < wifs::MAX_KEYS {
                    let _ = rows.push(Row::item("Generate new key", GENERATE));
                    let _ = rows.push(Row::item("Import from SD", IMPORT));
                } else {
                    let _ = rows.push(Row::body("store full (30 keys)").small().centered());
                }
                menu::show_doc(ui, &rows, false, false)
            };

            match exit {
                menu::DocExit::Selected(GENERATE) => Then::Generate,
                menu::DocExit::Selected(IMPORT) => Then::Import,
                menu::DocExit::Selected(i) if (i as usize) < have => {
                    if detail(ui, &entries[i as usize]) {
                        Then::Delete(i as usize)
                    } else {
                        continue;
                    }
                }
                _ => Then::Leave,
            }
        };

        match next {
            Then::Leave => return,
            Then::Generate => generate(gate, login, ui),
            Then::Import => import(gate, login, ui),
            Then::Delete(index) => match remove(gate, login, ui, index) {
                Ok(()) => say(ui, "the key is gone"),
                Err(why) => say(ui, why),
            },
        }
    }
}

/// Read the stored entries into `doc_buf`. The entries borrow it, so a later write must let
/// that borrow end first -- which is why the buffer is passed in.
fn read_entries<'a>(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    panel: &mut crate::display::Panel,
    doc_buf: &'a mut [u8],
    out: &mut [WifEntry<'a>],
) -> Result<usize, &'static str> {
    let key = crate::settings::wallet_key(gate, login, panel, SETTINGS_HEAD)?;
    // SAFETY: the region is mapped and readable; nothing is written through this.
    let mut files =
        unsafe { crate::settings::Files::mount_read_only() }.map_err(|_| "no settings store")?;
    let n = store::read(&mut files, &key, doc_buf).unwrap_or(0);
    let doc = Doc::parse(&doc_buf[..n]).unwrap_or_default();
    Ok(wifs::list(&doc, out))
}

/// One row for the list: `Key NN`, plus the owner's name where there is one.
fn list_label(index: usize, entry: &WifEntry<'_>) -> heapless::String<48> {
    use core::fmt::Write as _;
    let mut text = heapless::String::new();
    let _ = write!(text, "Key {:02}", index + 1);
    if !entry.label.is_empty() {
        let _ = write!(text, "  {}", entry.label);
    }
    text
}

/// Show one key's addresses, and offer to reveal the WIF or delete the key.
///
/// Returns whether the owner asked to delete it.
fn detail(ui: &mut Ui<'_>, entry: &WifEntry<'_>) -> bool {
    /// Row ids for the two actions, past nothing selectable above them.
    const REVEAL: u32 = 0;
    const DELETE: u32 = 1;

    // Decode once: the addresses come from the public key, the reveal from the WIF itself.
    // Both are private-key work, so the decode and the derivation run masked.
    let key = crate::keywork::run(|kw| WifKey::decode(entry.wif, kw).ok());
    let Some(key) = key else {
        say(ui, "this key will not decode");
        return false;
    };
    let network = key.network();

    // The three single-signature address forms this key can be paid at. A P2TR address is
    // not offered: a lone key spent through taproot is unusual and the three below are what
    // a swept or generated key is paid to in practice.
    let pubkey = crate::keywork::run(|kw| key.public_key(kw));
    let mut addr_bufs = [[0u8; address::MAX_ADDRESS_LEN]; 3];
    let mut addr_lens = [0usize; 3];
    let kinds = [
        ("Segwit", AddressKind::P2wpkh),
        ("Nested", AddressKind::P2shP2wpkh),
        ("Legacy", AddressKind::P2pkh),
    ];
    if let Some(pubkey) = pubkey {
        for (i, (_, kind)) in kinds.iter().enumerate() {
            addr_lens[i] = address::encode(*kind, network, &pubkey, &mut addr_bufs[i]).unwrap_or(0);
        }
    }

    loop {
        let mut rows: heapless::Vec<Row, 12> = heapless::Vec::new();
        let _ = rows.push(Row::title(HEAD));
        if !entry.label.is_empty() {
            let _ = rows.push(Row::body(entry.label).centered());
        }
        if network == Network::Testnet {
            let _ = rows.push(Row::body("testnet key").small().centered());
        }
        if pubkey.is_some() {
            for (i, (name, _)) in kinds.iter().enumerate() {
                let _ = rows.push(Row::body(name).small());
                if let Ok(a) = core::str::from_utf8(&addr_bufs[i][..addr_lens[i]]) {
                    let _ = rows.push(Row::body(a).wrapped());
                }
            }
        } else {
            let _ = rows.push(Row::body("could not derive addresses"));
        }
        let _ = rows.push(Row::item("Reveal WIF", REVEAL));
        let _ = rows.push(Row::item("Delete key", DELETE));

        match menu::show_doc(ui, &rows, false, false) {
            menu::DocExit::Selected(REVEAL) => reveal(ui, entry),
            menu::DocExit::Selected(DELETE) => {
                menu::ask(ui.panel, HEAD, "delete this key?", "it cannot be undone");
                if menu::confirmed(ui) {
                    return true;
                }
            }
            _ => return false,
        }
    }
}

/// Show the WIF itself, behind the same warning the seed words get.
fn reveal(ui: &mut Ui<'_>, entry: &WifEntry<'_>) {
    menu::ask(ui.panel, HEAD, "shows a private key", "check nobody can see");
    if !menu::confirmed(ui) {
        return;
    }
    // The stored string is already the WIF; showing it copies no secret through any
    // computation, so no masking is needed here -- but it is a secret on the screen, so it
    // is drawn scrambled and revealed on purpose, exactly as a seed word is.
    let lines = [
        Row::title("WIF key"),
        Row::body("this is the private key").small(),
        Row::body(entry.wif).secret().wrapped(),
    ];
    menu::show_doc(ui, &lines, true, false);
}

/// Generate a new key from the DRBG and store it.
fn generate(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) {
    menu::blocking_screen(ui.panel, HEAD, "generating");

    // Secret randomness comes from the UI DRBG (HMAC-DRBG), never a public source. A draw
    // that is not a usable scalar is redrawn -- vanishingly rare, and bounded so a stuck
    // DRBG cannot spin here forever.
    let mut wif_text: heapless::String<MAX_WIF_LEN> = heapless::String::new();
    let made = crate::keywork::run(|kw| {
        for _ in 0..8 {
            let mut secret = [0u8; 32];
            if ui.drbg.generate(&mut secret).is_err() {
                secret.zeroize();
                return false;
            }
            let Ok(key) = WifKey::from_secret(&secret, true, Network::Mainnet) else {
                secret.zeroize();
                continue;
            };
            secret.zeroize();
            let mut buf = [0u8; MAX_WIF_LEN];
            if let Ok(n) = key.encode(&mut buf, kw)
                && let Ok(text) = core::str::from_utf8(&buf[..n])
            {
                let _ = wif_text.push_str(text);
            }
            buf.zeroize();
            return !wif_text.is_empty();
        }
        false
    });
    if !made {
        return say(ui, "could not generate a key");
    }

    match store_added(gate, login, ui, "", wif_text.as_str()) {
        Ok(()) => {
            menu::message(ui.panel, HEAD, "new key stored", "any key to go back");
            menu::wait_for_any_key(ui);
        }
        Err(why) => say(ui, why),
    }
    wif_text.zeroize();
}

/// Import a WIF from a file on the card.
fn import(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) {
    let Some(path) = menu::browse_sd(ui, "Pick a WIF file", None, menu::Browse::File) else {
        return;
    };
    // A WIF is at most 53 characters; the file may have a trailing newline or a little
    // whitespace, so read a small buffer and trim. A larger file is not a WIF file.
    let mut buf = [0u8; 128];
    let read = crate::signtx::read_card_file(path.as_str(), &mut buf);
    let len = match read {
        Ok(n) => n,
        Err(why) => {
            buf.zeroize();
            return say(ui, why);
        }
    };
    let mut wif_text: heapless::String<MAX_WIF_LEN> = heapless::String::new();
    let ok = crate::keywork::run(|kw| {
        let Ok(text) = core::str::from_utf8(&buf[..len]) else {
            return false;
        };
        let text = text.trim();
        // Decode to validate (and to reject a file that is not a WIF), then keep the
        // canonical string the key re-encodes to rather than trusting the file's bytes.
        let Ok(key) = WifKey::decode(text, kw) else {
            return false;
        };
        let mut out = [0u8; MAX_WIF_LEN];
        let stored = if let Ok(n) = key.encode(&mut out, kw)
            && let Ok(s) = core::str::from_utf8(&out[..n])
        {
            wif_text.push_str(s).is_ok()
        } else {
            false
        };
        out.zeroize();
        stored
    });
    buf.zeroize();
    if !ok {
        return say(ui, "not a valid WIF");
    }

    match store_added(gate, login, ui, "", wif_text.as_str()) {
        Ok(()) => {
            menu::message(ui.panel, HEAD, "key imported", "any key to go back");
            menu::wait_for_any_key(ui);
        }
        Err(why) => say(ui, why),
    }
    wif_text.zeroize();
}

/// Add `wif` (with optional `label`) to the store and save it.
fn store_added(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    label: &str,
    wif: &str,
) -> Result<(), &'static str> {
    menu::blocking_screen(ui.panel, HEAD, "saving");
    // Three leased slots: the settings scratch, the rendered list, and the seal the write
    // needs. All wiped on drop at the end of this call.
    let (Some(mut doc), Some(mut list_blk), Some(mut seal)) = (
        crate::heap::take(SCRATCH),
        crate::heap::take(SCRATCH),
        crate::heap::take(SCRATCH),
    ) else {
        return Err("not enough memory");
    };
    let doc_buf = doc.bytes();
    let list_buf = list_blk.bytes();
    // Scoped: the entries borrow `doc_buf`, which the write below reuses as scratch.
    let len = {
        let mut existing = [WifEntry { label: "", wif: "" }; wifs::MAX_KEYS];
        let have = read_entries(gate, login, ui.panel, doc_buf, &mut existing)?;
        let mut merged = [WifEntry { label: "", wif: "" }; wifs::MAX_KEYS];
        let n = wifs::with_added(&existing[..have], WifEntry { label, wif }, &mut merged)
            .map_err(|e| match e {
                wifs::Error::TooMany => "store full (30 keys)",
                wifs::Error::LabelTooLong => "label too long",
                wifs::Error::NotStorable | wifs::Error::Overflow => "could not store that",
            })?;
        wifs::render(&merged[..n], list_buf).map_err(|_| "too long")?
    };
    // `list_buf` now owns the JSON text; the entry borrows on `doc_buf` have ended, so the
    // save may reuse it as scratch. The buffer holds a private key, so wipe it after.
    let text = core::str::from_utf8(&list_buf[..len]).map_err(|_| "not text")?;
    let result = crate::settings::save_wallet(
        gate,
        login,
        ui,
        SETTINGS_HEAD,
        (wifs::KEY, text),
        doc_buf,
        seal.bytes(),
    );
    list_buf[..len].zeroize();
    result
}

/// Remove the key at `index` and save.
fn remove(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    index: usize,
) -> Result<(), &'static str> {
    menu::blocking_screen(ui.panel, HEAD, "saving");
    let (Some(mut doc), Some(mut list_blk), Some(mut seal)) = (
        crate::heap::take(SCRATCH),
        crate::heap::take(SCRATCH),
        crate::heap::take(SCRATCH),
    ) else {
        return Err("not enough memory");
    };
    let doc_buf = doc.bytes();
    let list_buf = list_blk.bytes();
    let len = {
        let mut existing = [WifEntry { label: "", wif: "" }; wifs::MAX_KEYS];
        let have = read_entries(gate, login, ui.panel, doc_buf, &mut existing)?;
        if index >= have {
            return Err("no such key");
        }
        let mut left = [WifEntry { label: "", wif: "" }; wifs::MAX_KEYS];
        let n = wifs::without_index(&existing[..have], index, &mut left);
        wifs::render(&left[..n], list_buf).map_err(|_| "too long")?
    };
    let text = core::str::from_utf8(&list_buf[..len]).map_err(|_| "not text")?;
    let result = crate::settings::save_wallet(
        gate,
        login,
        ui,
        SETTINGS_HEAD,
        (wifs::KEY, text),
        doc_buf,
        seal.bytes(),
    );
    list_buf[..len].zeroize();
    result
}

/// A one-line message screen that waits for a key.
fn say(ui: &mut Ui<'_>, what: &str) {
    menu::message(ui.panel, HEAD, what, "any key to go back");
    menu::wait_for_any_key(ui);
}
