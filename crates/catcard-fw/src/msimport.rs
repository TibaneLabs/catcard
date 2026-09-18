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

/// Three full-slot buffers: the settings as they are, the rendered list, and the seal.
///
/// Static, because a screen has an 8 KB stack and a settings slot is four kilobytes. Only
/// one settings screen is ever open, so importing and reading back share these.
static mut DOC: [u8; SCRATCH] = [0; SCRATCH];
static mut LIST: [u8; SCRATCH] = [0; SCRATCH];
static mut SEAL: [u8; SCRATCH] = [0; SCRATCH];

/// The parsed wallets, kept between calls so a slice of them can outlive [`registered`].
///
/// A `Multisig` is around two kilobytes -- fifteen extended keys and their origins -- so
/// eight of them do not go on a stack either.
static mut PARSED: heapless::Vec<Multisig, { wallets::MAX_WALLETS }> = heapless::Vec::new();

/// The multisig wallets this device has registered.
///
/// Read once per transaction rather than once per input: it costs a settings mount and a
/// callgate fetch of the login secret. **An empty slice is a meaningful answer** -- it is
/// what a device with nothing registered returns, and it makes every multisig input refuse
/// rather than be signed on the host's word about who the other cosigners are. So a
/// settings store that will not mount reads as "none registered", never as "allow".
///
/// A descriptor that no longer parses is skipped rather than failing the list: one entry
/// written by a version that stores more must not hide the wallets beside it.
pub(crate) fn registered(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
) -> &'static [Multisig] {
    // SAFETY: foreground only; one settings screen at a time.
    let parsed: &'static mut heapless::Vec<Multisig, { wallets::MAX_WALLETS }> =
        unsafe { &mut *core::ptr::addr_of_mut!(PARSED) };
    parsed.clear();

    let mut list = [Wallet {
        name: "",
        descriptor: "",
    }; wallets::MAX_WALLETS];
    // SAFETY: foreground only, and the signing screen holds the display while this runs.
    let doc_buf = unsafe { doc_scratch() };
    let have = match load(gate, login, doc_buf, &mut list) {
        Ok(n) => n,
        Err(why) => {
            crate::catlog!("multisig: {}, so no registered wallets", why);
            return parsed;
        }
    };
    for w in &list[..have] {
        match multisig::parse(w.descriptor) {
            Ok(m) => {
                let _ = parsed.push(m);
            }
            Err(why) => crate::catlog!("multisig: skipping {}: {:?}", w.name, why),
        }
    }
    crate::catlog!("multisig: {} wallet(s) registered", parsed.len());
    parsed
}

/// The stored wallet records, read into `doc_buf`. Returns how many `out` received.
///
/// The records borrow `doc_buf`, which is also the scratch a later write needs, so a
/// caller that goes on to store something must let that borrow end first -- which is why
/// the buffer is passed in rather than taken from [`DOC`] here.
fn load<'a>(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    doc_buf: &'a mut [u8; SCRATCH],
    out: &mut [Wallet<'a>],
) -> Result<usize, &'static str> {
    use catcard_settings::json::Doc;
    use catcard_settings::nvstore;
    use catcard_settings::store;
    use zeroize::Zeroize as _;

    // SAFETY: foreground only; the caller holds the display while this runs.
    let mut files = unsafe { crate::settings::Files::mount() }.map_err(|_| "no settings store")?;
    let pin_gate = crate::pinentry::BootloaderGate::new(gate);
    let mut secret = login
        .fetch_secret(&pin_gate)
        .map_err(|_| "could not read the secret")?;
    let key = crate::keywork::run(|_| nvstore::hash_key(&secret));
    secret.zeroize();

    let n = store::read(&mut files, &key, doc_buf).unwrap_or(0);
    let doc = Doc::parse(&doc_buf[..n]).unwrap_or_default();
    Ok(wallets::list(&doc, out))
}

/// The DOC scratch buffer.
///
/// # Safety
/// Foreground only, one settings screen at a time, and the returned borrow must end
/// before another call.
unsafe fn doc_scratch() -> &'static mut [u8; SCRATCH] {
    // SAFETY: the caller's contract.
    unsafe { &mut *core::ptr::addr_of_mut!(DOC) }
}

/// The Multisig screen: what is registered, and what can be done about it.
///
/// A registration decides which spends this device will sign, so it cannot be write-only.
/// A wallet imported from the wrong file has to be findable and removable, and the only
/// way to notice one is to be able to look.
pub(crate) fn manage(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) {
    use catcard_ui::scroll::Line as Row;

    /// The "Import from SD" row, numbered past any wallet.
    const IMPORT: u32 = 1000;

    /// What the list screen came back with. Nothing here borrows the settings buffer, so
    /// acting on it can read and write the settings again.
    enum Then {
        Leave,
        Import,
        Delete(heapless::String<8>),
    }

    loop {
        menu::blocking_screen(ui.panel, "Multisig", "reading");
        // Scoped: the wallet records borrow the settings buffer, and deleting one reads
        // the settings afresh.
        let next = {
            // SAFETY: foreground only; the menu waits for this screen.
            let doc_buf = unsafe { doc_scratch() };
            let mut list = [Wallet {
                name: "",
                descriptor: "",
            }; wallets::MAX_WALLETS];
            let have = match load(gate, login, doc_buf, &mut list) {
                Ok(n) => n,
                Err(why) => return say(ui, "Multisig", why),
            };

            // A label per wallet: its name if it has one, otherwise its shape, and its
            // checksum -- which is what a person compares against the other cosigners.
            let mut labels: heapless::Vec<heapless::String<40>, { wallets::MAX_WALLETS }> =
                heapless::Vec::new();
            for w in &list[..have] {
                let _ = labels.push(label(w));
            }

            let exit = {
                let mut rows: heapless::Vec<Row, { wallets::MAX_WALLETS + 3 }> =
                    heapless::Vec::new();
                let _ = rows.push(Row::title("Multisig"));
                if have == 0 {
                    let _ = rows.push(Row::body("(none registered)").centered());
                }
                for (i, l) in labels.iter().enumerate() {
                    let _ = rows.push(Row::item(l.as_str(), i as u32));
                }
                let _ = rows.push(Row::item("Import from SD", IMPORT));
                menu::show_doc(ui, &rows, false, false)
            };

            match exit {
                menu::DocExit::Selected(IMPORT) => Then::Import,
                menu::DocExit::Selected(i) if (i as usize) < have => {
                    let w = &list[i as usize];
                    let mut sum: heapless::String<8> = heapless::String::new();
                    let _ = sum.push_str(w.checksum().unwrap_or(""));
                    if detail(ui, w) && !sum.is_empty() {
                        Then::Delete(sum)
                    } else {
                        continue;
                    }
                }
                _ => Then::Leave,
            }
        };

        match next {
            Then::Leave => return,
            Then::Import => import(gate, login, ui),
            Then::Delete(sum) => match remove(gate, login, ui, &sum) {
                Ok(()) => say(ui, "Multisig", "the wallet is gone"),
                Err(why) => say(ui, "Multisig", why),
            },
        }
    }
}

/// One line for the list: the owner's name for the wallet, or its shape, plus the checksum.
fn label(w: &Wallet<'_>) -> heapless::String<40> {
    use core::fmt::Write as _;
    let mut text = heapless::String::new();
    let shape = match multisig::parse(w.descriptor) {
        Ok(m) => {
            let mut s: heapless::String<16> = heapless::String::new();
            let _ = write!(s, "{}-of-{}", m.m, m.n());
            s
        }
        // A descriptor this build cannot read is still shown, so it can be deleted.
        Err(_) => heapless::String::try_from("unreadable").unwrap_or_default(),
    };
    let name = if w.name.is_empty() {
        shape.as_str()
    } else {
        w.name
    };
    let _ = write!(text, "{name}  {}", w.checksum().unwrap_or("?"));
    text
}

/// Show one registered wallet. Returns whether the owner asked to delete it.
fn detail(ui: &mut Ui<'_>, w: &Wallet<'_>) -> bool {
    use catcard_ui::scroll::Line as Row;
    use core::fmt::Write as _;

    type Text = heapless::String<48>;
    let mut lines: heapless::Vec<Text, { multisig::MAX_COSIGNERS + 4 }> = heapless::Vec::new();
    match multisig::parse(w.descriptor) {
        Ok(m) => {
            let mut head = Text::new();
            let _ = write!(
                head,
                "{}-of-{} {}{}",
                m.m,
                m.n(),
                kind_name(m.kind),
                if m.sorted { "" } else { ", unsorted" }
            );
            let _ = lines.push(head);
            for (i, c) in m.cosigners().iter().enumerate() {
                let mut line = Text::new();
                let _ = write!(
                    line,
                    "{}: {:02x}{:02x}{:02x}{:02x}",
                    i + 1,
                    c.fingerprint[0],
                    c.fingerprint[1],
                    c.fingerprint[2],
                    c.fingerprint[3]
                );
                let _ = lines.push(line);
            }
        }
        Err(why) => {
            let mut line = Text::new();
            let _ = write!(line, "cannot read: {}", describe(why));
            let _ = lines.push(line);
        }
    }
    let mut sum = Text::new();
    let _ = write!(sum, "checksum {}", w.checksum().unwrap_or("none"));
    let _ = lines.push(sum);

    let mut hint = Text::new();
    let _ = write!(
        hint,
        "{} delete   {} back",
        crate::display::CONFIRM_KEY,
        crate::display::CANCEL_KEY
    );

    let title = if w.name.is_empty() { "Wallet" } else { w.name };
    let mut rows: heapless::Vec<Row, { multisig::MAX_COSIGNERS + 6 }> = heapless::Vec::new();
    let _ = rows.push(Row::title(title));
    for l in lines.iter() {
        let _ = rows.push(Row::body(l.as_str()).small());
    }
    let _ = rows.push(Row::body(hint.as_str()).small());
    if !matches!(
        menu::show_doc(ui, &rows, false, false),
        menu::DocExit::Confirmed
    ) {
        return false;
    }
    // Deleting is not destroying coins -- the wallet can be imported again -- but it does
    // stop this device signing for it until that happens, so it is asked once.
    menu::ask(
        ui.panel,
        "Delete wallet?",
        "this device will refuse",
        "its spends until re-imported",
    );
    menu::confirmed(ui)
}

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::P2sh => "P2SH",
        Kind::P2wsh => "P2WSH",
        Kind::P2shP2wsh => "P2SH-P2WSH",
    }
}

/// Store the wallet list without the one whose checksum is `sum`.
fn remove(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    sum: &str,
) -> Result<(), &'static str> {
    menu::blocking_screen(ui.panel, "Multisig", "saving");
    // SAFETY: foreground only; the menu waits for this screen.
    let doc_buf = unsafe { doc_scratch() };
    // Scoped: the records borrow `doc_buf`, which the write below reuses as scratch.
    let len = {
        let mut list = [Wallet {
            name: "",
            descriptor: "",
        }; wallets::MAX_WALLETS];
        let have = load(gate, login, doc_buf, &mut list)?;
        let mut left = [Wallet {
            name: "",
            descriptor: "",
        }; wallets::MAX_WALLETS];
        let n = wallets::without(&list[..have], sum, &mut left);
        if n == have {
            return Err("no such wallet");
        }
        // SAFETY: as above.
        let list_buf: &mut [u8; SCRATCH] = unsafe { &mut *core::ptr::addr_of_mut!(LIST) };
        wallets::render(&left[..n], list_buf).map_err(|_| "too long")?
    };
    store_list(gate, login, ui, doc_buf, len)
}

/// Write the wallet list rendered into [`LIST`] into the settings.
///
/// `doc_buf` is the scratch the edit needs, and it must no longer be lent to any wallet
/// record by the time this is called -- which is what the scopes above are for.
fn store_list(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    doc_buf: &mut [u8; SCRATCH],
    len: usize,
) -> Result<(), &'static str> {
    use catcard_settings::json::RawJson;
    use catcard_settings::nvstore;
    use catcard_settings::store;
    use zeroize::Zeroize as _;

    // SAFETY: foreground only; one settings screen at a time.
    let list_buf: &[u8; SCRATCH] = unsafe { &*core::ptr::addr_of!(LIST) };
    let text = core::str::from_utf8(&list_buf[..len]).map_err(|_| "not text")?;

    // SAFETY: as above.
    let mut files = unsafe { crate::settings::Files::mount() }.map_err(|_| "no settings store")?;
    let pin_gate = crate::pinentry::BootloaderGate::new(gate);
    let mut secret = login
        .fetch_secret(&pin_gate)
        .map_err(|_| "could not read the secret")?;
    let key = crate::keywork::run(|_| nvstore::hash_key(&secret));
    secret.zeroize();

    // SAFETY: as above.
    let seal: &mut [u8; SCRATCH] = unsafe { &mut *core::ptr::addr_of_mut!(SEAL) };
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

/// Import a wallet: pick the file, read it, show it, and store it if the owner agrees.
pub(crate) fn import(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) {
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

    // The fingerprint of this device, to say which cosigner is us. Public, and this
    // session may already have paid for it -- registering several wallets in a row should
    // not mean stretching the seed once per wallet.
    let Some(ours) = crate::pubkeys::fingerprint(gate, login, ui, "Import") else {
        return;
    };

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
    menu::blocking_screen(ui.panel, "Register wallet", "saving");
    // SAFETY: foreground only; the menu waits for this screen, and nothing else touches
    // the settings region.
    let doc_buf = unsafe { doc_scratch() };

    // Scoped: the records read here borrow `doc_buf`, and the write below reuses it as
    // scratch, so the borrow has to end first.
    let len = {
        let mut current = [Wallet {
            name: "",
            descriptor: "",
        }; wallets::MAX_WALLETS];
        let have = load(gate, login, doc_buf, &mut current)?;

        let mut next = [Wallet {
            name: "",
            descriptor: "",
        }; wallets::MAX_WALLETS];
        let added = wallets::with_added(&current[..have], Wallet { name, descriptor }, &mut next)
            .map_err(|e| match e {
            wallets::Error::TooMany => "no room for another wallet",
            wallets::Error::NotStorable => "that descriptor cannot be stored",
            wallets::Error::NoChecksum => "no checksum",
            wallets::Error::Overflow => "too long",
        })?;
        crate::catlog!("multisig: registering, {} wallet(s) after this", added);
        // SAFETY: as above.
        let list_buf: &mut [u8; SCRATCH] = unsafe { &mut *core::ptr::addr_of_mut!(LIST) };
        wallets::render(&next[..added], list_buf).map_err(|_| "too long")?
    };
    store_list(gate, login, ui, doc_buf, len)
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
