//! What the device does: the menus and the flows behind them.
//!
//! Built on the portable crates, not on catcard-fw's menus, which are written against the
//! Coldcard boards; see docs/PRECURSOR.md for why and for what is missing. The wallet is
//! per power cycle (`session.rs`): nothing is stored yet.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use catcard_wallet::address::{self, AddressKind};
use catcard_wallet::bip32::{ChildNumber, Network};
use catcard_wallet::bip39::Mnemonic;
use zeroize::Zeroize;

use crate::session::Session;
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

pub fn run(ui: &mut Ui) -> ! {
    let mut session: Option<Session> = None;
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
                Some(3) => settings(ui, &mut session),
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
                    Some(4) => settings(ui, &mut session),
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
        if ui.ask("Written down?", "they are not stored:", "lost at reset") {
            break;
        }
    }
    start(ui, mnemonic)
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
        Ok(m) => start(ui, m),
        Err(_) => {
            ui.ask("Not valid", "checksum does not match", "check the words");
            None
        }
    }
}

fn start(ui: &mut Ui, mnemonic: Mnemonic) -> Option<Session> {
    ui.notice("Wallet", "deriving keys", "");
    match Session::new(mnemonic) {
        Ok(s) => {
            let fp = hex(&s.fingerprint());
            let _ = writeln!(ui.out, "wallet ready, fingerprint {fp}");
            ui.ask(
                "Wallet ready",
                &format!("fingerprint {fp}"),
                "this session only",
            );
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

fn settings(ui: &mut Ui, session: &mut Option<Session>) {
    loop {
        let items: &[&str] = if session.is_some() {
            &["About", "View seed words"]
        } else {
            &["About"]
        };
        match ui.menu("Settings", "", items) {
            Some(0) => about(ui),
            Some(1) => {
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
            _ => return,
        }
    }
}

fn about(ui: &mut Ui) {
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
        String::from("wallet: this session"),
        String::from("only, nothing stored"),
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
        "No storage yet: the",
        "wallet is forgotten",
        "at reset or Logout.",
    ];
    ui.pages("Help", &lines);
}
