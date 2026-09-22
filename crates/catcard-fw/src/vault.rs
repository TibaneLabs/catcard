//! The Seed Vault screen: keys the owner kept, and the one they are in.
//!
//! [`catcard_settings::vault`] is the format and the list arithmetic, tested on the host.
//! This is the screen: what is in the vault, putting the current key into it, and taking
//! one back out to work in.
//!
//! # What goes in, and what comes back
//!
//! An entry is a wallet's own BIP-39 entropy -- a BIP-85 child, a seed joined from XOR
//! parts -- held as the secure element would hold it, in the settings file of the wallet
//! in force. Loading one makes it the session's temporary key, exactly as joining the XOR
//! parts by hand would have.
//!
//! # Every wallet has its own vault
//!
//! Each wallet's settings are a file of their own, encrypted under that wallet's stash
//! ([`crate::settings::wallet_key`]). So the vault seen from the root is the root's; load
//! a key from it, open the vault again, and what is listed is *that* key's vault -- which
//! can hold keys of its own.
//!
//! A **passphrase** wallet cannot go in. Its master is words plus a passphrase, and there
//! is no BIP-39 entropy that reproduces it, so there is nothing of the right shape to
//! store; the screen says so rather than storing the words underneath and quietly handing
//! back a different wallet.
//!
//! # It is not a backup
//!
//! The vault lives in this device's settings, under this device's seed. Wipe the device
//! and it goes with it. What it saves is the typing, not the words.

use catcard_callgate::Callgate;
use catcard_settings::store::SCRATCH;
use catcard_settings::vault::{self, MAX_SEEDS, Seed};
use core::fmt::Write as _;
use zeroize::Zeroize as _;

use crate::menu;
use crate::ui::Ui;

const HEAD: &str = "Key vault";

/// The most bytes a stored secret takes: the marker and 32 of entropy.
const RAW_MAX: usize = 1 + catcard_wallet::bip39::MAX_ENTROPY_LEN;

/// A fingerprint as it is written in the vault and on screen.
type Xfp = heapless::String<8>;

/// What the list screen decided, once the settings buffer it read has been let go.
enum Then {
    Leave,
    Store,
    Use {
        raw: [u8; RAW_MAX],
        len: usize,
        method: heapless::String<16>,
    },
    Rename(Xfp),
    Forget(Xfp),
}

/// Show the vault, and do what the owner picks.
pub(crate) fn screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    loop {
        let next = list_screen(gate, login, ui);
        match next {
            Then::Leave => return,
            Then::Store => store_current(gate, login, ui),
            Then::Use { raw, len, method } => {
                let mut raw = raw;
                use_seed(gate, login, ui, &raw[..len], &method);
                raw.zeroize();
                // The key changed under them; going back to a list that says "store the
                // current key" about a key that is now in it would be a lie.
                return;
            }
            Then::Rename(xfp) => rename(gate, login, ui, &xfp),
            Then::Forget(xfp) => forget(gate, login, ui, &xfp),
        }
    }
}

/// Draw the list and turn a choice into something that no longer borrows the settings.
fn list_screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) -> Then {
    use catcard_ui::scroll::Line as Row;

    /// Row ids past any entry.
    const STORE: u32 = 1000;

    menu::blocking_screen(ui.panel, HEAD, "reading");
    let Some(mut held) = crate::heap::take(SCRATCH) else {
        return say(ui, "not enough memory");
    };
    let doc_buf = held.bytes();
    let n = match read_doc(gate, login, ui.panel, doc_buf) {
        Ok(n) => n,
        Err(why) => return say(ui, why),
    };
    let doc = catcard_settings::json::Doc::parse(&doc_buf[..n]).unwrap_or_default();
    let mut seeds = [Seed::default(); MAX_SEEDS];
    let have = vault::list(&doc, &mut seeds);

    // Whether the key in force can be kept, and whether it already is. Its fingerprint
    // is free if any screen this session has derived it; otherwise this pays for it
    // once, which is the price of answering "is this one already here" honestly.
    let storable = matches!(
        crate::key::in_force(),
        crate::key::Source::Bip85 { .. } | crate::key::Source::Temporary
    );
    let mine = if storable {
        crate::pubkeys::fingerprint(gate, login, ui, HEAD).map(hex_xfp)
    } else {
        None
    };
    let offer_store = mine
        .as_ref()
        .is_some_and(|x| !vault::holds(&seeds[..have], x));

    let mut labels: heapless::Vec<heapless::String<40>, MAX_SEEDS> = heapless::Vec::new();
    for s in &seeds[..have] {
        let mut line: heapless::String<40> = heapless::String::new();
        let name = if s.label.is_empty() { s.xfp } else { s.label };
        let _ = write!(line, "{name}  [{}]", s.xfp);
        let _ = labels.push(line);
    }

    let mut doc_rows: heapless::Vec<Row, { MAX_SEEDS + 3 }> = heapless::Vec::new();
    let _ = doc_rows.push(Row::title(HEAD));
    if have == 0 {
        let _ = doc_rows.push(Row::body("nothing kept yet").small());
    }
    if offer_store {
        let _ = doc_rows.push(Row::item("+ keep the current key", STORE));
    }
    for (i, l) in labels.iter().enumerate() {
        let _ = doc_rows.push(Row::item(l, i as u32));
    }

    match menu::show_doc(ui, &doc_rows, false, false) {
        menu::DocExit::Selected(STORE) => Then::Store,
        menu::DocExit::Selected(i) => {
            let Some(s) = seeds.get(i as usize).filter(|_| (i as usize) < have) else {
                return Then::Leave;
            };
            what_with(ui, s)
        }
        _ => Then::Leave,
    }
}

/// Use, rename or forget one entry.
fn what_with(ui: &mut Ui<'_>, s: &Seed<'_>) -> Then {
    let mut head: heapless::String<40> = heapless::String::new();
    let name = if s.label.is_empty() { s.xfp } else { s.label };
    let _ = write!(head, "{name}  [{}]", s.xfp);
    let method = if s.method.is_empty() {
        "kept key"
    } else {
        s.method
    };
    let Some(row) = menu::pick_row(ui, &head, method, &["Work in it", "Rename", "Forget it"])
    else {
        return Then::Leave;
    };
    let mut xfp: Xfp = heapless::String::new();
    let _ = xfp.push_str(s.xfp);
    match row {
        0 => {
            let mut raw = [0u8; RAW_MAX];
            let Some(len) = vault::decode_secret(s.secret, &mut raw) else {
                return say(ui, "that entry is damaged");
            };
            let mut method_owned: heapless::String<16> = heapless::String::new();
            let _ = method_owned.push_str(&s.method[..s.method.len().min(16)]);
            Then::Use {
                raw,
                len,
                method: method_owned,
            }
        }
        1 => Then::Rename(xfp),
        _ => Then::Forget(xfp),
    }
}

/// Work in a kept key for the rest of the session.
fn use_seed(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    raw: &[u8],
    method: &str,
) {
    // The marker says what the rest is. Only a BIP-39 wallet has entropy this can put in
    // force; an xprv entry is somebody else's firmware's, and saying so beats deriving
    // something that is not the wallet the entry names.
    let Some(entropy) = bip39_part(raw) else {
        return drop(say(ui, "not a words wallet"));
    };
    let was = crate::key::in_force();
    if !crate::key::set_temporary(entropy, method) {
        return drop(say(ui, "that seed length is not usable"));
    }
    match menu::master_quietly(gate, login, ui.panel, HEAD) {
        Ok(master) => {
            let [a, b, c, d] = crate::keywork::run(|kw| master.fingerprint(kw));
            drop(master);
            let mut said: Xfp = heapless::String::new();
            let _ = write!(said, "{a:02X}{b:02X}{c:02X}{d:02X}");
            crate::catlog!("vault: now in {} ({})", said.as_str(), crate::key::label());
            #[cfg(feature = "board-q1")]
            crate::pubkeys::note_fingerprint(Some([a, b, c, d]));
            menu::message(ui.panel, HEAD, &said, "in force until reboot");
        }
        Err(why) => {
            crate::key::set(was);
            menu::message(ui.panel, HEAD, why, "unchanged");
        }
    }
    menu::wait_for_any_key(ui);
}

/// The entropy inside a stash whose marker says BIP-39, if that is what it is.
///
/// Source: hw-reference/secret-stash-format.md §Layout [C] -- `0x80 | ((len/8) - 2)`.
fn bip39_part(raw: &[u8]) -> Option<&[u8]> {
    let marker = *raw.first()?;
    if marker & 0x80 == 0 {
        return None;
    }
    let len = (((marker & 0x7F) as usize) + 2) * 8;
    let body = raw.get(1..1 + len)?;
    catcard_wallet::bip39::words_for_entropy(len).map(|_| body)
}

/// Keep the key in force, under a label.
fn store_current(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    // The passphrase is not in the entropy, so an entry made here reaches the wallet
    // without it. Said before it is stored, not after it fails to open something.
    if crate::passphrase::is_set() {
        menu::ask(
            ui.panel,
            HEAD,
            "keeps the WORDS only",
            "your passphrase is not in them",
        );
        if !menu::confirmed(ui) {
            return;
        }
    }

    let (mut ent, len) = match menu::seed_entropy(gate, login, ui.panel, HEAD) {
        Ok(got) => got,
        Err(why) => return drop(say(ui, why)),
    };
    let Some(fp) = crate::pubkeys::fingerprint(gate, login, ui, HEAD) else {
        ent.zeroize();
        return;
    };
    let xfp = hex_xfp(fp);

    // The stash as the secure element would hold it: the marker, then the entropy.
    let mut raw = [0u8; RAW_MAX];
    raw[0] = 0x80 | ((len / 8) as u8).saturating_sub(2);
    raw[1..1 + len].copy_from_slice(&ent[..len]);
    ent.zeroize();
    let mut hex = [0u8; 2 * RAW_MAX];
    let secret = vault::encode_secret(&raw[..1 + len], &mut hex).unwrap_or("");
    let method = crate::key::method();

    // The default label is the fingerprint in brackets, which is what the list shows
    // when there is nothing better -- and what stock writes.
    let mut label: heapless::String<{ vault::MAX_LABEL }> = heapless::String::new();
    let _ = write!(label, "[{xfp}]");
    if let Some(typed) = ask_label(ui, &label) {
        label = typed;
    }

    let saved = save(
        gate,
        login,
        ui,
        Change::Add(Seed {
            xfp: &xfp,
            secret,
            label: &label,
            method,
        }),
    );
    raw.zeroize();
    hex.zeroize();
    match saved {
        Ok(()) => {
            crate::catlog!("vault: kept {} as {}", xfp.as_str(), method);
            menu::message(ui.panel, HEAD, &label, "kept");
        }
        Err(why) => menu::message(ui.panel, HEAD, why, "nothing kept"),
    }
    menu::wait_for_any_key(ui);
}

/// Ask for a label, offering `current` as what it is now. `None` to keep that.
fn ask_label(ui: &mut Ui<'_>, current: &str) -> Option<heapless::String<{ vault::MAX_LABEL }>> {
    menu::ask(ui.panel, "Name it?", current, "y to type a name");
    if !menu::confirmed(ui) {
        return None;
    }
    let mut entry = crate::passphrase::read(ui, "Label")?;
    let text = entry.as_str();
    let mut out: heapless::String<{ vault::MAX_LABEL }> = heapless::String::new();
    for c in text.chars().take(vault::MAX_LABEL) {
        // The store holds plain ASCII; anything else is dropped rather than refusing a
        // name that is almost right.
        if vault::storable(c.encode_utf8(&mut [0u8; 4])) {
            let _ = out.push(c);
        }
    }
    entry.clear();
    (!out.is_empty()).then_some(out)
}

/// Rename one entry.
fn rename(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>, xfp: &str) {
    let mut current: heapless::String<{ vault::MAX_LABEL }> = heapless::String::new();
    let _ = write!(current, "[{xfp}]");
    let Some(label) = ask_label(ui, &current) else {
        return;
    };
    let saved = save(gate, login, ui, Change::Rename { xfp, label: &label });
    match saved {
        Ok(()) => menu::message(ui.panel, HEAD, &label, "renamed"),
        Err(why) => menu::message(ui.panel, HEAD, why, "unchanged"),
    }
    menu::wait_for_any_key(ui);
}

/// Take one entry out of the vault.
fn forget(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>, xfp: &str) {
    menu::ask(ui.panel, "Forget this key?", xfp, "the words are not here");
    if !menu::confirmed(ui) {
        return;
    }
    let saved = save(gate, login, ui, Change::Forget(xfp));
    match saved {
        Ok(()) => {
            crate::catlog!("vault: forgot {}", xfp);
            menu::message(ui.panel, HEAD, xfp, "forgotten");
        }
        Err(why) => menu::message(ui.panel, HEAD, why, "unchanged"),
    }
    menu::wait_for_any_key(ui);
}

/// What a save does to the list.
///
/// A description rather than a closure: the entries a closure would be handed borrow the
/// settings document, which is read *inside* the save, so the two lifetimes only meet
/// here.
enum Change<'a> {
    /// Add it, or replace the entry with the same fingerprint.
    Add(Seed<'a>),
    /// Give one entry a new label.
    Rename { xfp: &'a str, label: &'a str },
    /// Take one out.
    Forget(&'a str),
}

/// Read the vault, apply `change`, and save what comes back.
///
/// Read again here rather than reusing what the list screen had: a save rewrites the
/// whole key, and the document it rewrites should be the one on the device now.
fn save(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    change: Change<'_>,
) -> Result<(), &'static str> {
    menu::blocking_screen(ui.panel, HEAD, "saving");
    let (Some(mut doc_held), Some(mut seal_held)) =
        (crate::heap::take(SCRATCH), crate::heap::take(SCRATCH))
    else {
        return Err("not enough memory");
    };
    let doc_buf = doc_held.bytes();
    let n = read_doc(gate, login, ui.panel, doc_buf)?;

    // The new list is rendered into its own buffer before the document is touched: the
    // entries borrow the document, so the rendering has to finish before the editor
    // starts moving it about.
    let mut out_buf = [0u8; 1024];
    let len = {
        let doc = catcard_settings::json::Doc::parse(&doc_buf[..n]).unwrap_or_default();
        let mut seeds = [Seed::default(); MAX_SEEDS];
        let have = vault::list(&doc, &mut seeds);
        let mut next = [Seed::default(); MAX_SEEDS];
        let kept = match change {
            Change::Add(seed) => vault::with_added(&seeds[..have], seed, &mut next)
                .map_err(|_| "the vault is full")?,
            Change::Rename { xfp, label } => {
                next[..have].copy_from_slice(&seeds[..have]);
                for s in &mut next[..have] {
                    if s.xfp == xfp {
                        s.label = label;
                    }
                }
                have
            }
            Change::Forget(xfp) => vault::without(&seeds[..have], xfp, &mut next),
        };
        vault::render(&next[..kept], &mut out_buf).map_err(|_| "could not write the list")?
    };
    let text = core::str::from_utf8(&out_buf[..len]).map_err(|_| "not text")?;

    crate::settings::save_wallet(
        gate,
        login,
        ui,
        HEAD,
        (vault::KEY, text),
        doc_buf,
        seal_held.bytes(),
    )
}

/// The settings document of the wallet in force, into `buf`. Returns its length.
///
/// That wallet's **own** file ([`crate::settings::wallet_key`]): a BIP-85 child has a
/// vault of its own, and the keys kept in it are not the root's.
fn read_doc(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    panel: &mut crate::display::Panel,
    buf: &mut [u8],
) -> Result<usize, &'static str> {
    use catcard_settings::store;

    let key = crate::settings::wallet_key(gate, login, panel, HEAD)?;
    // SAFETY: foreground only; the caller holds the display while this runs.
    let mut files = unsafe { crate::settings::Files::mount() }.map_err(|_| "no settings store")?;
    Ok(store::read(&mut files, &key, buf).unwrap_or(0))
}

/// A fingerprint as the vault writes it.
fn hex_xfp(fp: [u8; 4]) -> Xfp {
    let [a, b, c, d] = fp;
    let mut s: Xfp = heapless::String::new();
    let _ = write!(s, "{a:02X}{b:02X}{c:02X}{d:02X}");
    s
}

/// Say why, wait, and leave.
fn say(ui: &mut Ui<'_>, why: &str) -> Then {
    menu::message(ui.panel, HEAD, why, "any key to go back");
    menu::wait_for_any_key(ui);
    Then::Leave
}
