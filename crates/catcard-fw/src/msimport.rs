//! Registering a multisig wallet from a descriptor on the card.
//!
//! This screen is where the owner's check happens, and it is the only one there will be: a
//! wallet registered here decides, from then on, which addresses this device calls its own
//! and which spends it will sign. So it shows what a person needs in order to compare this
//! device's reading against the other cosigners' -- the threshold, the script form, the
//! sortedness, and every cosigner's fingerprint -- before anything is stored.
//!
//! Two things are deliberately *not* asked of the owner:
//!
//! - **Whether the checksum matters.** A descriptor with a bad one is refused before this
//!   screen draws. It is eight characters that turn a mistyped wallet into a stopped
//!   import rather than an address nobody can spend from.
//! - **Whether our key is in it.** That is checked and shown, not asked. A wallet this
//!   device is not part of can still be registered -- watching one is legitimate -- but a
//!   person who thought they were registering *their* wallet should see that it is not.

use catcard_settings::store::SCRATCH;
use catcard_settings::wallets::{self, Wallet};
use catcard_wallet::multisig::{self, Kind, Multisig};

use crate::menu;
use crate::ui::Ui;

/// Longest descriptor file this will read.
///
/// Fifteen cosigners with origins and 111-character keys is about 1.9 KB; this leaves
/// room around that. A larger file is refused with its size rather than truncated into
/// something that might still parse.
const MAX_FILE: usize = 4096;

/// Import a wallet: pick the file, read it, show it, and store it if the owner agrees.
pub(crate) fn import(gate: &catcard_callgate::Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    let Some(path) = menu::browse_sd(ui, "Pick a descriptor", None, true) else {
        return;
    };

    let mut file = [0u8; MAX_FILE];
    let len = match crate::signtx::read_card_file(&path, &mut file) {
        Ok(n) => n,
        Err(why) => return say(ui, "Import", why),
    };
    let Ok(text) = core::str::from_utf8(&file[..len]) else {
        return say(ui, "Import", "not text");
    };
    // A descriptor file may carry comment lines and a name, as an exported one does. The
    // descriptor is the line that parses; nothing here guesses at the rest.
    let Some((line, name)) = pick_descriptor(text) else {
        return say(ui, "Import", "no descriptor in that file");
    };
    let wallet = match multisig::parse(line) {
        Ok(w) => w,
        Err(why) => return say(ui, "Import", describe(why)),
    };

    // The fingerprint of this device, to say which cosigner is us.
    let ours = crate::menu::unlock_master(gate, login, ui, "Import").map(|master| {
        let fp = crate::keywork::run(|kw| master.fingerprint(kw));
        drop(master);
        fp
    });
    let Some(ours) = ours else { return };

    if !confirm(ui, &wallet, line, ours) {
        return;
    }
    match save(gate, login, ui, name, line) {
        Ok(()) => say(ui, "Registered", "the wallet is stored"),
        Err(why) => say(ui, "Import", why),
    }
}

/// The descriptor line in a file, and a name if one was given.
///
/// An exported multisig file carries comments (`#`), a `Name:` line and the descriptor.
/// The descriptor is recognised by parsing, not by position, so a file with the lines in
/// another order still imports.
fn pick_descriptor(text: &str) -> Option<(&str, &str)> {
    let mut name = "";
    let mut found = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line
            .strip_prefix("Name:")
            .or_else(|| line.strip_prefix("# Name:"))
        {
            name = rest.trim();
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        if found.is_none() && multisig::parse(line).is_ok() {
            found = Some(line);
        }
    }
    found.map(|line| (line, name))
}

/// Show the wallet and ask. Returns whether the owner accepted it.
fn confirm(ui: &mut Ui<'_>, wallet: &Multisig, descriptor: &str, ours: [u8; 4]) -> bool {
    use catcard_ui::scroll::Line as Row;
    use core::fmt::Write as _;

    type Text = heapless::String<48>;
    let mut lines: heapless::Vec<Text, { multisig::MAX_COSIGNERS + 6 }> = heapless::Vec::new();

    let mut head = Text::new();
    let _ = write!(
        head,
        "{}-of-{} {}{}",
        wallet.m,
        wallet.n(),
        match wallet.kind {
            Kind::P2sh => "P2SH",
            Kind::P2wsh => "P2WSH",
            Kind::P2shP2wsh => "P2SH-P2WSH",
        },
        if wallet.sorted { "" } else { ", unsorted" }
    );
    let _ = lines.push(head);

    // Unsorted is not wrong, and it is rare enough that a person who did not choose it
    // should be told rather than left to notice.
    if !wallet.sorted {
        let mut warn = Text::new();
        let _ = write!(warn, "keys are NOT sorted (multi)");
        let _ = lines.push(warn);
    }

    let mut mine = false;
    for (i, c) in wallet.cosigners().iter().enumerate() {
        let is_ours = c.fingerprint == ours;
        mine |= is_ours;
        let mut line = Text::new();
        let _ = write!(
            line,
            "{}: {:02x}{:02x}{:02x}{:02x}{}",
            i + 1,
            c.fingerprint[0],
            c.fingerprint[1],
            c.fingerprint[2],
            c.fingerprint[3],
            if is_ours { "  (this device)" } else { "" }
        );
        let _ = lines.push(line);
    }
    if !mine {
        let mut warn = Text::new();
        // Legitimate -- watching someone else's wallet is a real thing to do -- and worth
        // saying plainly, because it is also what a wallet imported from the wrong file
        // looks like.
        let _ = write!(warn, "this device is NOT a cosigner");
        let _ = lines.push(warn);
    }

    let mut sum = Text::new();
    let checksum = descriptor.rsplit_once('#').map(|(_, s)| s).unwrap_or("");
    let _ = write!(sum, "checksum {checksum}");
    let _ = lines.push(sum);

    // Declared before the rows that borrow it.
    let mut hint = Text::new();
    let _ = write!(
        hint,
        "{} register   {} cancel",
        crate::display::CONFIRM_KEY,
        crate::display::CANCEL_KEY
    );
    let mut rows: heapless::Vec<Row, { multisig::MAX_COSIGNERS + 8 }> = heapless::Vec::new();
    let _ = rows.push(Row::title("Register wallet"));
    for l in lines.iter() {
        let _ = rows.push(Row::body(l.as_str()).small());
    }
    let _ = rows.push(Row::body(hint.as_str()).small());
    matches!(
        menu::show_doc(ui, &rows, false, false),
        menu::DocExit::Confirmed
    )
}

/// Store the wallet in the settings, under the wallet key.
fn save(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    name: &str,
    descriptor: &str,
) -> Result<(), &'static str> {
    use catcard_settings::json::Doc;
    use catcard_settings::nvstore;
    use catcard_settings::store;
    use catcard_settings::json::RawJson;
    use zeroize::Zeroize as _;

    menu::blocking_screen(ui.panel, "Register wallet", "saving");
    // SAFETY: foreground only; the menu waits for this screen, and nothing else touches
    // the settings region.
    let mut files = unsafe { crate::settings::Files::mount() }.map_err(|_| "no settings store")?;

    let pin_gate = crate::pinentry::BootloaderGate::new(gate);
    let mut secret = login
        .fetch_secret(&pin_gate)
        .map_err(|_| "could not read the secret")?;
    let key = crate::keywork::run(|_| nvstore::hash_key(&secret));
    secret.zeroize();

    // Three full-slot buffers: the settings as they are, the rendered list, and the seal.
    // Static, because a screen has an 8 KB stack.
    static mut DOC: [u8; SCRATCH] = [0; SCRATCH];
    static mut LIST: [u8; SCRATCH] = [0; SCRATCH];
    static mut SEAL: [u8; SCRATCH] = [0; SCRATCH];
    // SAFETY: as above -- one settings screen at a time, foreground only.
    let doc_buf: &mut [u8; SCRATCH] = unsafe { &mut *core::ptr::addr_of_mut!(DOC) };
    // SAFETY: as above.
    let list_buf: &mut [u8; SCRATCH] = unsafe { &mut *core::ptr::addr_of_mut!(LIST) };
    // SAFETY: as above.
    let seal: &mut [u8; SCRATCH] = unsafe { &mut *core::ptr::addr_of_mut!(SEAL) };

    // The read and the edit share nothing with the write: `doc_buf` is the settings as
    // they are here, and the sealing pass below reuses it, so the borrow has to end first.
    let len = {
        let n = store::read(&mut files, &key, doc_buf).unwrap_or(0);
        let doc = Doc::parse(&doc_buf[..n]).unwrap_or_default();
        let mut current = [Wallet {
            name: "",
            descriptor: "",
        }; wallets::MAX_WALLETS];
        let have = wallets::list(&doc, &mut current);

        let mut next = [Wallet {
            name: "",
            descriptor: "",
        }; wallets::MAX_WALLETS];
        let added =
            wallets::with_added(&current[..have], Wallet { name, descriptor }, &mut next).map_err(
                |e| match e {
                    wallets::Error::TooMany => "no room for another wallet",
                    wallets::Error::NotStorable => "that descriptor cannot be stored",
                    wallets::Error::NoChecksum => "no checksum",
                    wallets::Error::Overflow => "too long",
                },
            )?;
        crate::catlog!("multisig: registering, {} wallet(s) after this", added);
        wallets::render(&next[..added], list_buf).map_err(|_| "too long")?
    };
    let text = core::str::from_utf8(&list_buf[..len]).map_err(|_| "not text")?;

    let choose = ui.drbg.below(crate::settings::SLOT_COUNT).unwrap_or(0);
    store::set(
        &mut files,
        &key,
        wallets::KEY,
        &RawJson(text),
        choose,
        doc_buf,
        seal,
    )
    .map_err(|_| "could not save")?;
    Ok(())
}

/// Why a descriptor was refused, in words rather than a variant name.
fn describe(why: multisig::Error) -> &'static str {
    match why {
        multisig::Error::BadChecksum => "checksum does not match",
        multisig::Error::NotMultisig => "not a multisig descriptor",
        multisig::Error::BadThreshold => "threshold is impossible",
        multisig::Error::BadKey { .. } => "a key is malformed",
        multisig::Error::CosignerCount { .. } => "too many cosigners",
        multisig::Error::DuplicateKey => "the same key appears twice",
        multisig::Error::Overflow => "too long",
    }
}

fn say(ui: &mut Ui<'_>, head: &str, what: &str) {
    menu::message(ui.panel, head, what, "any key to go back");
    menu::wait_for_any_key(ui);
}
