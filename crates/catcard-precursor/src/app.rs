//! What the device does: the menus and the flows behind them.
//!
//! Built on the portable crates, not on catcard-fw's menus, which are written against the
//! Coldcard boards; see docs/PRECURSOR.md for why and for what is missing. A wallet lives
//! for the power cycle (`session.rs`) unless the owner stores it, sealed under a
//! passphrase and the key ROM's device secret (`store.rs`, docs/PRECURSOR-KEYS.md).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use catcard_wallet::address::{self, AddressKind};
use catcard_wallet::bip32::{ChildNumber, Network};
use catcard_wallet::bip39::Mnemonic;
use zeroize::{Zeroize, Zeroizing};

use crate::session::Session;
use crate::store;
use crate::ui::Ui;

/// Addresses shown per type.
const ADDRESSES: u32 = 20;

/// Address types, with the account each conventionally lives under.
const KINDS: [(&str, u32, AddressKind); 4] = [
    ("Segwit  bc1q...", 84, AddressKind::P2wpkh),
    ("Taproot bc1p...", 86, AddressKind::P2tr),
    ("Nested  3...", 49, AddressKind::P2shP2wpkh),
    ("Legacy  1...", 44, AddressKind::P2pkh),
];

/// The key ROM's device secret, read at boot before the slot was locked. `None` on an
/// unprovisioned unit.
pub type DeviceSecret = Option<Zeroizing<[u8; 32]>>;

/// The secret Argon2 is keyed with: `DS`, or on an unprovisioned unit a public all-zero
/// stand-in, which leaves the passphrase as the only protection (the screens say so).
fn ds_or_zero(ds: &DeviceSecret) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(ds.as_deref().copied().unwrap_or([0; 32]))
}

pub fn run(ui: &mut Ui, ds: DeviceSecret) -> ! {
    let mut session: Option<Session> = if store::present() {
        unlock(ui, &ds)
    } else {
        None
    };
    loop {
        match &session {
            None => match ui.menu(
                "CatCard",
                "no seed",
                &["New", "Import", "Utils", "Settings", "Help"],
            ) {
                Some(0) => session = new_wallet(ui),
                Some(1) => session = import(ui),
                Some(2) => utils(ui),
                Some(3) => settings(ui, &mut session, &ds),
                Some(4) => help(ui),
                _ => {}
            },
            Some(s) => {
                let note = format!("[{}]", hex(&s.fingerprint()));
                match ui.menu(
                    "CatCard",
                    &note,
                    &[
                        "Sign PSBT",
                        "Addresses",
                        "Export xpub",
                        "Utils",
                        "Settings",
                        "Help",
                        "Logout",
                    ],
                ) {
                    Some(0) => crate::sign::run(ui, s),
                    Some(1) => addresses(ui, s),
                    Some(2) => export_xpub(ui, s),
                    Some(3) => utils(ui),
                    Some(4) => settings(ui, &mut session, &ds),
                    Some(5) => help(ui),
                    Some(6) if ui.ask("Logout", "forget this wallet?", "enter: yes  bksp: no") => {
                        session = None; // zeroizes
                    }
                    _ => {}
                }
            }
        }
    }
}

fn hex(b: &[u8]) -> String {
    let mut s = String::new();
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

fn word_count(ui: &mut Ui, title: &str) -> Option<usize> {
    ui.menu(title, "how many words?", &["12 words", "24 words"])
        .map(|i| if i == 0 { 12 } else { 24 })
}

fn new_wallet(ui: &mut Ui) -> Option<Session> {
    let words = word_count(ui, "New seed")?;
    ui.notice("New seed", "collecting entropy", "from both sources");
    let mnemonic = match crate::newseed::mnemonic(words) {
        Ok(m) => m,
        Err(e) => {
            let _ = writeln!(ui.out, "new seed refused: {e}");
            ui.ask("Refused", "entropy check failed", &e);
            return None;
        }
    };
    loop {
        if !show_words(ui, "Write down", &mnemonic) {
            if ui.ask("Discard?", "these words are lost", "enter: discard") {
                return None;
            }
            continue;
        }
        if ui.ask("Written down?", "the words are the", "only backup") {
            break;
        }
    }
    start(ui, mnemonic, "not stored: Settings")
}

/// The words, numbered, a page at a time. Never sent to the UART.
fn show_words(ui: &mut Ui, title: &str, m: &Mnemonic) -> bool {
    let mut lines: Vec<String> = m
        .words()
        .enumerate()
        .map(|(i, w)| format!("{:>2}. {w}", i + 1))
        .collect();
    let ok = ui.pages(title, &lines);
    for l in lines.iter_mut() {
        // SAFETY of meaning: overwrite the copies of the words before freeing them.
        // SAFETY: (not unsafe) -- zeroize works on the String's bytes in place.
        l.zeroize();
    }
    ok
}

fn import(ui: &mut Ui) -> Option<Session> {
    let words = word_count(ui, "Import")?;
    let mut picked: Vec<&'static str> = Vec::with_capacity(words);
    while picked.len() < words {
        let title = format!("Word {} of {words}", picked.len() + 1);
        match ui.pick_word(&title) {
            Ok(w) => picked.push(w),
            Err(()) if picked.is_empty() => return None,
            Err(()) => {
                picked.pop();
            }
        }
    }
    let mut phrase = picked.join(" ");
    let parsed = crate::keywork::run(|kw| Mnemonic::parse(&phrase, kw));
    phrase.zeroize();
    // The list holds references into the public word list, but their order is the seed.
    picked.iter_mut().for_each(|w| *w = "");
    picked.clear();
    match parsed {
        Ok(m) => start(ui, m, "not stored: Settings"),
        Err(_) => {
            ui.ask("Not valid", "checksum does not match", "check the words");
            None
        }
    }
}

fn start(ui: &mut Ui, mnemonic: Mnemonic, note: &str) -> Option<Session> {
    ui.notice("Wallet", "deriving keys", "");
    match Session::new(mnemonic) {
        Ok(s) => {
            let fp = hex(&s.fingerprint());
            let _ = writeln!(ui.out, "wallet ready, fingerprint {fp}");
            ui.ask("Wallet ready", &format!("fingerprint {fp}"), note);
            Some(s)
        }
        Err(e) => {
            ui.ask("Failed", e, "");
            None
        }
    }
}

fn addresses(ui: &mut Ui, s: &Session) {
    let labels: Vec<&str> = KINDS.iter().map(|k| k.0).collect();
    while let Some(k) = ui.menu("Addresses", "account 0", &labels) {
        let (_, purpose, kind) = KINDS[k];
        ui.notice("Addresses", "deriving", "");
        let list = match derive(s, purpose, kind) {
            Ok(l) => l,
            Err(e) => {
                ui.ask("Failed", e, "");
                continue;
            }
        };
        for (i, a) in list.iter().enumerate() {
            let _ = writeln!(ui.out, "addr m/{purpose}'/0'/0'/0/{i} {a}");
        }
        let items: Vec<String> = list
            .iter()
            .enumerate()
            .map(|(i, a)| format!("{i:>2} {}..{}", &a[..8], &a[a.len() - 6..]))
            .collect();
        let refs: Vec<&str> = items.iter().map(String::as_str).collect();
        let title = format!("m/{purpose}'/0'/0'/0");
        while let Some(i) = ui.menu(&title, "enter: QR", &refs) {
            ui.qr("Address", &list[i]);
        }
    }
}

/// Receive addresses `0..ADDRESSES` of account 0, from the account xpub: public derivation
/// only past the account level.
fn derive(s: &Session, purpose: u32, kind: AddressKind) -> Result<Vec<String>, &'static str> {
    let account = s.account(purpose)?;
    let chain = account
        .derive_child(ChildNumber::normal(0).map_err(|_| "bad index")?)
        .map_err(|_| "derivation failed")?;
    (0..ADDRESSES)
        .map(|i| {
            let child = chain
                .derive_child(ChildNumber::normal(i).map_err(|_| "bad index")?)
                .map_err(|_| "derivation failed")?;
            let mut buf = [0u8; address::MAX_ADDRESS_LEN];
            let n = address::encode(kind, Network::Mainnet, &child.public_key, &mut buf)
                .map_err(|_| "encoding failed")?;
            core::str::from_utf8(&buf[..n])
                .map(String::from)
                .map_err(|_| "encoding failed")
        })
        .collect()
}

fn export_xpub(ui: &mut Ui, s: &Session) {
    let labels: Vec<&str> = KINDS.iter().map(|k| k.0).collect();
    while let Some(k) = ui.menu("Export xpub", "account 0", &labels) {
        let purpose = KINDS[k].1;
        match s.account(purpose) {
            Ok(x) => {
                let mut buf = [0u8; catcard_wallet::bip32::serialize::MAX_BASE58_LEN];
                let Ok(n) = x.write_base58(&mut buf) else {
                    ui.ask("Failed", "could not encode", "");
                    continue;
                };
                let text = core::str::from_utf8(&buf[..n]).unwrap_or("");
                let _ = writeln!(ui.out, "xpub m/{purpose}'/0'/0' {text}");
                ui.qr("xpub", text);
            }
            Err(e) => {
                ui.ask("Failed", e, "");
            }
        }
    }
}

fn utils(ui: &mut Ui) {
    while let Some(i) = ui.menu("Utils", "", &["Entropy check"]) {
        if i == 0 {
            ui.notice("Entropy", "checking", "both sources");
            let summary = crate::rngcheck::run(&mut ui.out);
            let lines = crate::screens::entropy_lines(&summary);
            ui.pages("Entropy", &lines);
        }
    }
}

fn settings(ui: &mut Ui, session: &mut Option<Session>, ds: &DeviceSecret) {
    loop {
        let stored = store::present();
        let mut items: Vec<&str> = alloc::vec!["About"];
        if session.is_some() {
            items.push("View seed words");
            items.push("Store seed");
        }
        if stored {
            items.push("Erase stored seed");
        }
        let Some(i) = ui.menu("Settings", "", &items) else {
            return;
        };
        match items[i] {
            "About" => about(ui, ds),
            "View seed words" => {
                if let Some(s) = session.as_ref()
                    && ui.ask("Danger", "show the seed words?", "enter: show")
                {
                    let mut lines: Vec<String> = s
                        .words()
                        .enumerate()
                        .map(|(i, w)| format!("{:>2}. {w}", i + 1))
                        .collect();
                    ui.pages("Seed words", &lines);
                    lines.iter_mut().for_each(Zeroize::zeroize);
                }
            }
            "Store seed" => {
                if let Some(s) = session.as_ref() {
                    store_seed(ui, s, ds, stored);
                }
            }
            "Erase stored seed"
                if ui.ask("Erase?", "stored seed goes;", "words needed after")
                    && ui.ask("Really erase?", "this can't be undone", "enter: erase") =>
            {
                let r = store::erase();
                let _ = writeln!(ui.out, "stored seed erase: {r:?}");
                match r {
                    Ok(()) => ui.ask("Erased", "nothing stored now", ""),
                    Err(e) => ui.ask("Failed", e, ""),
                };
            }
            _ => {}
        }
    }
}

/// Asks for the passphrase until the stored seed opens, or the owner skips.
fn unlock(ui: &mut Ui, ds: &DeviceSecret) -> Option<Session> {
    let key = ds_or_zero(ds);
    loop {
        let Some(pass) = ui.passphrase("Unlock", "passphrase:") else {
            if ui.ask("Skip unlock?", "the seed stays", "stored. enter: skip") {
                return None;
            }
            continue;
        };
        ui.notice("Unlock", "checking", "");
        let t0 = crate::timer::now_ms();
        let opened = store::open(pass.as_bytes(), &key);
        drop(pass);
        let ms = crate::timer::now_ms() - t0;
        match opened {
            Ok(c) => {
                let _ = writeln!(ui.out, "unlock: ok in {ms} ms");
                let m = crate::keywork::run(|kw| Mnemonic::from_entropy(c.entropy(), kw));
                drop(c);
                match m {
                    Ok(m) => return start(ui, m, "unlocked from flash"),
                    Err(_) => {
                        ui.ask("Failed", "stored seed unusable", "");
                        return None;
                    }
                }
            }
            Err(catcard_sealed::Error::WrongPassphrase) => {
                let _ = writeln!(ui.out, "unlock: wrong passphrase ({ms} ms)");
                ui.ask("Wrong", "passphrase", "enter: try again");
            }
            Err(e) => {
                let _ = writeln!(ui.out, "unlock: {e}");
                ui.ask("Can't unlock", &format!("{e}"), "");
                return None;
            }
        }
    }
}

fn store_seed(ui: &mut Ui, s: &Session, ds: &DeviceSecret, stored: bool) {
    if stored && !ui.ask("Replace?", "a seed is stored;", "enter: replace it") {
        return;
    }
    if ds.is_none()
        && !ui.ask(
            "Unprovisioned",
            "only the passphrase",
            "protects it. enter: ok",
        )
    {
        return;
    }
    let Some(first) = ui.passphrase("Store seed", "choose a passphrase") else {
        return;
    };
    if first.is_empty() {
        ui.ask("Refused", "the passphrase", "can't be empty");
        return;
    }
    let Some(again) = ui.passphrase("Store seed", "type it again") else {
        return;
    };
    if *first != *again {
        ui.ask("Mismatch", "the two passphrases", "differ: not stored");
        return;
    }
    drop(again);
    let contents = match catcard_sealed::Contents::bip39(s.entropy()) {
        Ok(c) => c,
        Err(_) => {
            ui.ask("Failed", "can't store this seed", "");
            return;
        }
    };
    let key = ds_or_zero(ds);
    ui.notice("Store seed", "sealing and writing", "");
    let t0 = crate::timer::now_ms();
    if let Err(e) = store::save(&contents, first.as_bytes(), &key) {
        let _ = writeln!(ui.out, "store: {e}");
        ui.ask("Failed", e, "nothing changed?");
        return;
    }
    let t1 = crate::timer::now_ms();
    // Read it back the way unlock will: from flash, through Argon2.
    ui.notice("Store seed", "checking", "");
    let ok = matches!(store::open(first.as_bytes(), &key), Ok(c) if c == contents);
    let t2 = crate::timer::now_ms();
    let _ = writeln!(
        ui.out,
        "store: sealed+written in {} ms, reopened in {} ms: {}",
        t1 - t0,
        t2 - t1,
        if ok { "ok" } else { "MISMATCH" }
    );
    if ok {
        ui.ask("Stored", "unlock at power-on", "with the passphrase");
    } else {
        ui.ask("Failed", "stored seed doesn't", "read back: erase it");
    }
}

fn about(ui: &mut Ui, ds: &DeviceSecret) {
    let lines = [
        format!("CatCard {}", env!("CARGO_PKG_VERSION")),
        String::from("for Precursor pvt2"),
        String::new(),
        String::from("gateware"),
        format!(" {}", crate::csr::GATEWARE_REV),
        String::new(),
        format!("heap in use {} KB", crate::heap::used() / 1024),
        format!("uptime {} s", crate::timer::now_ms() / 1000),
        String::new(),
        String::from(if store::present() {
            "seed: stored, sealed"
        } else {
            "seed: none stored"
        }),
        String::from(if ds.is_some() {
            "key ROM: provisioned"
        } else {
            "key ROM: unprovisioned"
        }),
    ];
    ui.pages("About", &lines);
}

fn help(ui: &mut Ui) {
    let lines = [
        "pad up/down: move",
        "pad centre, enter: OK",
        "backspace: back",
        "",
        "New: fresh 12 or 24",
        " words from both TRNG",
        " sources",
        "Import: type words,",
        " pick from the list",
        "",
        "Settings > Store seed",
        " keeps it in flash,",
        " sealed under a",
        " passphrase asked at",
        " power-on. Otherwise",
        " it's forgotten at",
        " reset or Logout.",
    ];
    ui.pages("Help", &lines);
}
