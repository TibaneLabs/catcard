//! Codex32 on the device: generate, import, split, recover, and derive more shares.
//!
//! The arithmetic is [`catcard_wallet::codex32`], tested on the host against BIP-93's
//! vectors and Coldcard's extension vectors. This is the part that needs a person: which
//! operation, where a string comes from, what to write down, and what to do with a secret
//! once it is whole.
//!
//! # Where it sits
//!
//! - **Blank device:** Import → Codex32. What comes out can be stored as the wallet or
//!   used for the session, as a TAPSIGNER backup can.
//! - **Device with a wallet:** Derive → Codex32. Everything that comes out is a
//!   temporary seed; Split works on the wallet in force.
//!
//! Stock puts a top-level menu on the blank device and Split under Seed Functions; here
//! the blank device's way in is the Import cell it already has, and Split lives beside
//! Seed XOR's split under Derive, where this firmware keeps that one.
//! Source: hw-reference/codex32-format.md §Device operations "Where they are" [C]
//!
//! # What becomes a wallet
//!
//! Only an `s` string. `cw1` is stored as words, `ms1` as a raw master seed, `cx1` as an
//! xprv; the identifier, threshold and padding are dropped, so View words never shows the
//! string again. A *temporary* `ms1` seed is held as the xprv it makes -- the session key
//! has no raw-master shape, and the keys are the same keys.
//! Source: hw-reference/secret-stash-format.md §Codex32 [C]
//!
//! # A set proves nothing about itself
//!
//! Any *k* shares with matching headers interpolate to *some* valid wallet. A swapped
//! share gives a different wallet, not an error, and Derive Shares carries a swap
//! forward. So a recovered wallet is named by fingerprint and the owner is told to check
//! an address they recorded, before it is used. Source: as above, last paragraph [C]

use catcard_callgate::Callgate;
use catcard_callgate::pin::SECRET_LEN;
use catcard_wallet::codex32::{
    self as c32, Error as CError, Hrp, MAX_STRING, SECRET_INDEX, SHARE_ORDER, Set, Share,
};
use core::fmt::Write as _;
use zeroize::Zeroize as _;

use crate::menu::{self, Line, ask, confirmed, message, pick_row, wait_for_any_key};
use crate::ui::Ui;

const HEAD: &str = "Codex32";
const SPLIT: &str = "Shamir split";

/// Where the screen was opened from, which decides where a secret goes.
#[derive(Copy, Clone, PartialEq, Eq)]
pub(crate) enum Place {
    /// The blank device's Import menu: a secret may be stored as the wallet.
    Blank,
    /// Derive: a secret is only ever in force for the session.
    Derive,
}

/// Where a secret goes once it is whole.
#[derive(Copy, Clone, PartialEq, Eq)]
enum Target {
    Store,
    Session,
}

/// The menu: the operations this place offers, one of them run.
///
/// Generate, Split and Derive Shares make new secret material from the wallet or the
/// pool, which a spending policy freezes; Import and Recover only bring in what the owner
/// already holds, as any other temporary seed does.
/// Source: hw-reference/codex32-format.md §Device operations "Not available while a
/// Spending Policy is in force" [C]
pub(crate) fn screen(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    pool: Option<&mut catcard_entropy::EntropyPool>,
    place: Place,
) {
    const GENERATE: &str = "Generate";
    const IMPORT: &str = "Import";
    const RECOVER: &str = "Recover";
    const DERIVE: &str = "Derive shares";
    const SPLIT_ROW: &str = "Split this wallet";
    let free = !crate::policy::hobbled();
    let mut rows: heapless::Vec<&str, 5> = heapless::Vec::new();
    if place == Place::Derive && free {
        let _ = rows.push(SPLIT_ROW);
    }
    let _ = rows.push(RECOVER);
    let _ = rows.push(IMPORT);
    if free {
        let _ = rows.push(GENERATE);
        let _ = rows.push(DERIVE);
    }
    let Some(row) = pick_row(ui, HEAD, "BIP-93 secret sharing", &rows) else {
        return;
    };
    match rows[row] {
        SPLIT_ROW => split(gate, login, ui, pool),
        RECOVER => recover(gate, login, ui, place),
        IMPORT => import(gate, login, ui, place),
        GENERATE => generate(gate, login, ui, pool, place),
        _ => derive(gate, login, ui),
    }
}

// ---------------------------------------------------------------------------------------
// Bringing a string in
// ---------------------------------------------------------------------------------------

/// A string as it arrived: typed, read from a file or scanned. Wiped on drop -- a share
/// is secret material until it has been checked and dropped.
struct Text(heapless::String<MAX_STRING>);

impl Drop for Text {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Ask where the string is, and bring it in. `None` if the owner backed out or the
/// source had nothing usable (already said).
#[inline(never)]
fn read_text(ui: &mut Ui<'_>, head: &str) -> Option<Text> {
    let mut rows: heapless::Vec<&str, 3> = heapless::Vec::new();
    let _ = rows.push("Type it");
    let _ = rows.push("From a file");
    #[cfg(feature = "board-q1")]
    let _ = rows.push("Scan QR");
    let mut out = Text(heapless::String::new());
    match pick_row(ui, head, "where is the string?", &rows)? {
        0 => {
            let entry = crate::passphrase::read_at_most(ui, head, MAX_STRING)?;
            let _ = out.0.push_str(entry.as_str());
        }
        1 => {
            let storage = menu::pick_storage(ui, head)?;
            let path = menu::browse_storage(ui, storage, head, Some("txt"), menu::Browse::File)?;
            let mut buf = [0u8; 512];
            let read = crate::signtx::read_source_file(storage, &path, &mut buf);
            let got = read.map(|n| first_codex32_line(&buf[..n], &mut out));
            buf.zeroize();
            match got {
                Ok(true) => {}
                Ok(false) => {
                    say(ui, head, "no codex32 string", "in that file");
                    return None;
                }
                Err(why) => {
                    say(ui, head, "cannot read it", why);
                    return None;
                }
            }
        }
        _ => {
            #[cfg(feature = "board-q1")]
            {
                let mut seen = [0u8; 512];
                let mut len = 0;
                let scanned = crate::qrscan::scan_many(ui, head, &mut |_, line| {
                    len = line.len().min(seen.len());
                    seen[..len].copy_from_slice(&line[..len]);
                    crate::qrscan::Next::Done
                });
                let found = scanned.is_ok() && first_codex32_line(&seen[..len], &mut out);
                seen.zeroize();
                if !found {
                    say(ui, head, "no codex32 string", "in that code");
                    return None;
                }
            }
        }
    }
    Some(out)
}

/// The first line starting `ms1`, `cw1` or `cx1` (any case, spaces removed) into `out`.
///
/// One string per file, no labels: a file holding a set is several files.
/// Source: hw-reference/codex32-format.md §Input and output channels [C]
fn first_codex32_line(bytes: &[u8], out: &mut Text) -> bool {
    for line in bytes.split(|&b| b == b'\n' || b == b'\r') {
        out.0.clear();
        for &b in line {
            if b != b' ' && b != b'\t' && out.0.push(b as char).is_err() {
                break;
            }
        }
        let head = out.0.as_bytes();
        if head.len() >= 3
            && head[2] == b'1'
            && matches!(
                [head[0].to_ascii_lowercase(), head[1].to_ascii_lowercase()],
                [b'm', b's'] | [b'c', b'w'] | [b'c', b'x']
            )
            && out.0.is_ascii()
        {
            return true;
        }
    }
    out.0.clear();
    false
}

/// Bring a string in and check it, until it parses or the owner backs out.
fn read_share(ui: &mut Ui<'_>, head: &str) -> Option<Share> {
    loop {
        let text = read_text(ui, head)?;
        let parsed = crate::keywork::run(|kw| Share::parse(&text.0, kw));
        drop(text);
        match parsed {
            Ok(share) => return Some(share),
            Err(e) => say(ui, head, "not a valid string:", describe(e)),
        }
    }
}

/// A refusal, in the words a screen has room for.
fn describe(e: CError) -> &'static str {
    match e {
        CError::Prefix => "no ms1/cw1/cx1 prefix",
        CError::MixedCase => "upper and lower case",
        CError::Length => "not a length it carries",
        CError::Character => "a character is not valid",
        CError::Threshold => "bad threshold",
        CError::Checksum => "checksum is wrong",
        CError::Mismatch => "not from this set",
        CError::Duplicate => "that share is already in",
        CError::SecretNotShare => "that is the secret",
        CError::NotSecret => "that is a share",
        CError::Full => "the set is complete",
        CError::Incomplete => "not enough shares",
        CError::Invalid => "not a usable key",
    }
}

fn say(ui: &mut Ui<'_>, head: &str, a: &str, b: &str) {
    message(ui.panel, head, a, b);
    wait_for_any_key(ui);
}

// ---------------------------------------------------------------------------------------
// Showing a string
// ---------------------------------------------------------------------------------------

/// A string in uppercase, as shown and saved. Wiped on drop.
struct Written {
    buf: [u8; MAX_STRING],
    len: usize,
}

impl Drop for Written {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

impl Written {
    fn of(share: &Share) -> Self {
        let mut w = Written {
            buf: [0; MAX_STRING],
            len: 0,
        };
        w.len = crate::keywork::run(|kw| share.write(true, &mut w.buf, kw).len());
        w
    }

    fn bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    fn text(&self) -> &str {
        core::str::from_utf8(self.bytes()).unwrap_or("")
    }

    /// The numbered groups of four, as the quiz refers to them.
    fn groups(&self) -> heapless::Vec<&str, 32> {
        self.bytes()
            .chunks(4)
            .map(|g| core::str::from_utf8(g).unwrap_or(""))
            .collect()
    }
}

/// Show a string in numbered groups of four, with the marker every secret line carries,
/// then offer it as a QR or a file. The owner cannot leave until every group has been on
/// screen. Source: hw-reference/codex32-format.md §Input and output channels "Export" [C]
#[inline(never)]
fn show(ui: &mut Ui<'_>, title: &str, share: &Share, export: bool) {
    use catcard_ui::scroll::Line as DLine;
    let w = Written::of(share);
    let mut numbered: heapless::Vec<Line, 32> = heapless::Vec::new();
    for (i, g) in w.groups().iter().enumerate() {
        let mut l = Line::new();
        let _ = write!(l, "{:2}  {g}", i + 1);
        let _ = numbered.push(l);
    }
    let mut lines: heapless::Vec<DLine, 34> = heapless::Vec::new();
    let _ = lines.push(DLine::title(title));
    for l in &numbered {
        let _ = lines.push(DLine::body(l).secret());
    }
    menu::show_doc(ui, &lines, true, true);
    drop(lines);
    for l in numbered.iter_mut() {
        l.zeroize();
    }
    if !export {
        return;
    }
    loop {
        match pick_row(ui, title, "", &["Done", "Show as QR", "Save to a file"]) {
            Some(1) => menu::qr_screen_bytes(ui, w.bytes(), ""),
            Some(2) => save_file(ui, title, share, &w),
            _ => break,
        }
    }
}

/// Write a string to a card or the disk as `<id>_share_<index>.txt`. Plaintext: the file
/// is the share. Source: hw-reference/codex32-format.md §Input and output channels [C]
fn save_file(ui: &mut Ui<'_>, head: &str, share: &Share, w: &Written) {
    let Some(storage) = menu::pick_storage(ui, head) else {
        return;
    };
    let mut name: heapless::String<24> = heapless::String::new();
    let id = share.id();
    let _ = write!(
        name,
        "{}_share_{}.txt",
        core::str::from_utf8(&id).unwrap_or("c32"),
        share.index_char() as char
    );
    let mut body: heapless::String<{ MAX_STRING + 1 }> = heapless::String::new();
    let _ = body.push_str(w.text());
    let _ = body.push('\n');
    let r = menu::write_storage_file(storage, &name, body.as_bytes());
    body.zeroize();
    match r {
        Ok(()) => say(ui, head, "written as", &name),
        Err(why) => say(ui, head, "not written:", why),
    }
}

/// The group quiz: three groups asked back, decoys of four random characters.
/// Source: hw-reference/codex32-format.md §Device operations "Generate" (group quiz) [C]
fn quiz(ui: &mut Ui<'_>, share: &Share) -> bool {
    let w = Written::of(share);
    let groups = w.groups();
    crate::newseed::quiz_items(ui, "group", &groups, &mut |ui| {
        let mut d = crate::newseed::Pick::new();
        for _ in 0..4 {
            let v = ui.drbg.below(32).ok()?;
            let _ = d.push(c32::ALPHABET[v as usize].to_ascii_uppercase() as char);
        }
        Some(d)
    })
}

// ---------------------------------------------------------------------------------------
// A whole secret into force
// ---------------------------------------------------------------------------------------

/// Where this secret goes: asked on a blank device, the session anywhere else.
fn target(ui: &mut Ui<'_>, place: Place, head: &str) -> Option<Target> {
    if place == Place::Derive {
        return Some(Target::Session);
    }
    match pick_row(
        ui,
        head,
        "use it",
        &["Store as the wallet", "This session only"],
    )? {
        0 => Some(Target::Store),
        _ => Some(Target::Session),
    }
}

/// Turn an `s` string into a wallet, name it, and store it or put it in force.
#[inline(never)]
fn activate(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    head: &str,
    share: &Share,
    to: Target,
) {
    use catcard_callgate::pin::{encode_bip39, encode_raw_master, encode_xprv};
    // The stash the secret would be stored as, built masked; also what names it.
    let made = crate::keywork::run(|kw| {
        let secret = share.secret(kw)?;
        let b = secret.as_bytes();
        let stash = match secret.hrp() {
            Hrp::Cw => encode_bip39(b).map_err(|_| CError::Length)?,
            Hrp::Ms => encode_raw_master(b).map_err(|_| CError::Length)?,
            Hrp::Cx => {
                let (mut cc, mut k) = ([0u8; 32], [0u8; 32]);
                cc.copy_from_slice(&b[..32]);
                k.copy_from_slice(&b[32..]);
                let s = encode_xprv(&cc, &k);
                cc.zeroize();
                k.zeroize();
                s
            }
        };
        Ok::<_, CError>((stash, secret.hrp(), b.len()))
    });
    let (mut stash, hrp, len) = match made {
        Ok(m) => m,
        Err(e) => return say(ui, head, "cannot use it:", describe(e)),
    };
    let _busy = menu::blocking_screen(ui.panel, head, "deriving the key");
    let Some([a, b, c, d]) = crate::backup::fingerprint_of(&stash) else {
        stash.zeroize();
        return say(ui, head, "cannot use it:", "not a usable key");
    };
    drop(_busy);
    let mut fp: heapless::String<24> = heapless::String::new();
    let _ = write!(fp, "{a:02X}{b:02X}{c:02X}{d:02X}");
    let mut kind = Line::new();
    match hrp {
        Hrp::Cw => {
            let words = catcard_wallet::bip39::words_for_entropy(len).unwrap_or(0);
            let _ = write!(kind, "{words} words");
        }
        Hrp::Ms => {
            let _ = write!(kind, "{}-bit master seed", len * 8);
        }
        Hrp::Cx => {
            let _ = kind.push_str("XPRV, no words");
        }
    }
    ask(ui.panel, "Use this wallet?", &fp, &kind);
    if !confirmed(ui) {
        stash.zeroize();
        return say(ui, head, "cancelled", "nothing changed");
    }

    match to {
        Target::Store => {
            store(gate, login, ui, head, &stash, hrp == Hrp::Ms, [a, b, c, d]);
            stash.zeroize();
        }
        Target::Session => {
            let was = crate::key::in_force();
            let loaded = load_session(&stash, hrp);
            stash.zeroize();
            if !loaded {
                return say(ui, head, "cannot use it:", "not a usable key");
            }
            crate::catlog!("codex32: {} in force for the session", hrp.text());
            menu::announce_key(gate, login, ui, head, was);
        }
    }
}

/// Put a stash in force for the session. A raw master goes in as the node it makes.
fn load_session(stash: &[u8; SECRET_LEN], hrp: Hrp) -> bool {
    use catcard_callgate::pin::{bip39_entropy, raw_master, xprv_parts};
    const METHOD: &str = "Codex32";
    match hrp {
        Hrp::Cw => bip39_entropy(stash).is_some_and(|e| crate::key::set_temporary(e, METHOD)),
        Hrp::Cx => {
            xprv_parts(stash).is_some_and(|(cc, k)| crate::key::set_temporary_xprv(cc, k, METHOD))
        }
        Hrp::Ms => {
            let net = crate::prefs::network();
            let node = crate::keywork::run(|kw| {
                let seed = raw_master(stash)?;
                let m = catcard_wallet::bip32::ExtendedPrivKey::from_seed(seed, net, kw).ok()?;
                Some((m.chain_code, *m.secret_bytes()))
            });
            let Some((cc, mut k)) = node else {
                return false;
            };
            let ok = crate::key::set_temporary_xprv(&cc, &k, METHOD);
            k.zeroize();
            ok
        }
    }
}

/// Store as the device's wallet, after the destructive-case warning, and mark a raw master
/// with `c32` in its settings as stock does.
fn store(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    head: &str,
    stash: &[u8; SECRET_LEN],
    raw: bool,
    fp: [u8; 4],
) {
    if crate::key::stored_wallet(login) {
        ask(
            ui.panel,
            "Wallet exists",
            "an import DESTROYS",
            "the one stored now",
        );
        if !confirmed(ui) {
            return say(ui, head, "cancelled", "nothing was stored");
        }
    }
    if let Err(why) = crate::backup::store_secret(gate, login, ui, stash) {
        return say(ui, "Not stored", why, "any key to go back");
    }
    crate::key::to_root();
    crate::pubkeys::note_fingerprint(Some(fp));
    crate::catlog!("codex32: wallet stored");
    if raw {
        // Best effort: the flag only steers a later split's prefix, which this firmware
        // reads from the stash anyway. Source: hw-reference/settings-nvstore-format.md
        // §5 `c32` [C]
        let saved = save(
            gate,
            login,
            ui,
            head,
            catcard_settings::codex32::RAW_KEY,
            "true",
        );
        crate::catlog!(
            "codex32: c32 flag {}",
            if saved { "saved" } else { "not saved" }
        );
    }
    say(ui, "Wallet stored", "it is the master now", "");
}

/// Save one value into the master's settings file.
fn save(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    head: &str,
    key: &str,
    raw: &str,
) -> bool {
    use catcard_settings::store::SCRATCH;
    let (Some(mut doc), Some(mut seal)) = (crate::heap::take(SCRATCH), crate::heap::take(SCRATCH))
    else {
        return false;
    };
    crate::settings::save_master(gate, login, ui, head, (key, raw), doc.bytes(), seal.bytes())
        .is_ok()
}

// ---------------------------------------------------------------------------------------
// Generate and import
// ---------------------------------------------------------------------------------------

/// A new raw master seed from the device's generator, shown as `ms1` with identifier
/// `seed`, threshold 0 and zero padding, quizzed, then stored or put in force.
///
/// The bytes come from the same collection and draw as a new wallet's words
/// ([`crate::newseed::gather_and_draw`]): every hardware source topped up, the owner's own
/// entropy offered, the pool's policy checked. Stock makes the owner's entropy mandatory
/// here; this firmware offers it everywhere and requires it nowhere, because a pool that
/// met its policy does not need it and one that did not is refused outright.
/// Source: hw-reference/codex32-format.md §Device operations "Generate" [C];
/// docs/ENTROPY.md
fn generate(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    pool: Option<&mut catcard_entropy::EntropyPool>,
    place: Place,
) {
    const GEN: &str = "New ms1 seed";
    let Some(pool) = pool else {
        return say(ui, GEN, "the pool missed its", "policy at boot");
    };
    let Some(bits) = pick_row(ui, GEN, "how strong", &["256-bit", "128-bit"]) else {
        return;
    };
    let len = if bits == 0 { 32 } else { 16 };
    let Some(to) = target(ui, place, GEN) else {
        return;
    };
    let made = crate::newseed::gather_and_draw(gate, ui, pool, len, |b, kw| {
        Share::from_bytes(Hrp::Ms, 0, c32::seed_id(), SECRET_INDEX, b, kw)
    });
    let Some(Ok(share)) = made else {
        return;
    };
    // Shown and quizzed before anything is stored: a failed quiz costs only time.
    loop {
        show(ui, "Write this down", &share, false);
        if quiz(ui, &share) {
            break;
        }
        ask(ui.panel, "Not confirmed", "read it again", "and retry?");
        if !confirmed(ui) {
            return say(ui, GEN, "nothing was stored", "");
        }
    }
    activate(gate, login, ui, GEN, &share, to);
}

/// Import a secret (`s`) string. Shares are refused: they need Recover.
/// Source: hw-reference/codex32-format.md §Device operations "Import Codex32" [C]
fn import(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>, place: Place) {
    const IMP: &str = "Import Codex32";
    let Some(share) = read_share(ui, IMP) else {
        return;
    };
    if !share.is_secret() {
        return say(ui, IMP, "that is one share:", "use Recover");
    }
    let Some(to) = target(ui, place, IMP) else {
        return;
    };
    activate(gate, login, ui, IMP, &share, to);
}

// ---------------------------------------------------------------------------------------
// Recover and derive: collecting a set
// ---------------------------------------------------------------------------------------

/// Collect shares into `set` until it reaches its threshold. `false` if the owner left,
/// having saved the set or not.
///
/// A set saved earlier ("Save & Exit") is offered first; it is shared between Recover and
/// Derive, lives in the master's settings, and is cleared as soon as a threshold is
/// reached -- whether or not what follows succeeds.
/// Source: hw-reference/codex32-format.md §Storage "Saved partial sets" [C]
#[inline(never)]
fn collect(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    head: &str,
    set: &mut Set,
) -> bool {
    let had_saved = resume(gate, login, ui, head, set);
    while !set.is_complete() {
        let mut note: heapless::String<32> = heapless::String::new();
        match set.threshold() {
            Some(k) => {
                let _ = write!(note, "{} of {} shares in", set.len(), k);
            }
            None => {
                let _ = note.push_str("no shares yet");
            }
        }
        let rows: &[&str] = if set.is_empty() {
            &["Add a share"]
        } else {
            &["Add a share", "Save & Exit"]
        };
        match pick_row(ui, head, &note, rows) {
            Some(0) => {
                let Some(share) = read_share(ui, head) else {
                    continue;
                };
                let index = share.index_char().to_ascii_uppercase() as char;
                match set.add(share) {
                    Ok(_) => crate::catlog!("codex32: share {} in", index),
                    Err(e) => say(ui, head, "not added:", describe(e)),
                }
            }
            Some(_) => {
                save_set(gate, login, ui, head, set);
                return false;
            }
            None => {
                ask(ui.panel, head, "leave without", "saving these shares?");
                if confirmed(ui) {
                    return false;
                }
            }
        }
    }
    if had_saved {
        let cleared = save(
            gate,
            login,
            ui,
            head,
            catcard_settings::codex32::SHARES_KEY,
            "[]",
        );
        crate::catlog!(
            "codex32: saved set {}",
            if cleared { "cleared" } else { "NOT cleared" }
        );
    }
    // Said before the result is used, because the result cannot say it.
    ask(
        ui.panel,
        "Shares in",
        "matching shares are not",
        "proof: check an address",
    );
    confirmed(ui)
}

/// Offer a saved set and load it into `set`. Whether one was saved at all.
fn resume(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    head: &str,
    set: &mut Set,
) -> bool {
    use catcard_settings::codex32::{self as keys, MAX_SHARES};
    use catcard_settings::store::SCRATCH;
    let Ok(key) = crate::settings::master_key(gate, login, ui.panel, head) else {
        return false;
    };
    let Some(mut held) = crate::heap::take(SCRATCH) else {
        return false;
    };
    let buf = held.bytes();
    let n = crate::settings::read_slot(&key, buf).unwrap_or(0);
    let Some(doc) = crate::settings::parse_doc(&buf[..n]) else {
        return false;
    };
    let mut saved = [""; MAX_SHARES];
    let count = keys::list(&doc, &mut saved);
    if count == 0 {
        return false;
    }
    let mut note: heapless::String<32> = heapless::String::new();
    let _ = write!(note, "{count} saved shares");
    if pick_row(ui, head, &note, &["Continue with them", "Start over"]) == Some(0) {
        for s in &saved[..count] {
            let parsed = crate::keywork::run(|kw| Share::parse(s, kw));
            match parsed.and_then(|share| set.add(share)) {
                Ok(_) => {}
                Err(e) => crate::catlog!("codex32: a saved share was skipped: {:?}", e),
            }
        }
    }
    true
}

/// "Save & Exit": the shares in, written into the master's settings.
fn save_set(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    head: &str,
    set: &Set,
) {
    use catcard_settings::codex32::{self as keys, MAX_RENDERED, MAX_SHARES};
    let written: heapless::Vec<Written, MAX_SHARES> =
        set.shares().iter().map(Written::of).collect();
    let texts: heapless::Vec<&str, MAX_SHARES> = written.iter().map(Written::text).collect();
    let Some(mut held) = crate::heap::take(MAX_RENDERED) else {
        return say(ui, head, "not saved:", "no memory");
    };
    let Ok(n) = keys::render(&texts, held.bytes()) else {
        return say(ui, head, "not saved:", "cannot write them");
    };
    let raw = core::str::from_utf8(&held.bytes()[..n]).unwrap_or("[]");
    let ok = save(gate, login, ui, head, keys::SHARES_KEY, raw);
    if !ok {
        return say(ui, head, "not saved", "any key to go back");
    }
    // On a blank device the settings key comes from an all-zero secret.
    // Source: hw-reference/settings-nvstore-format.md §5 `c32_shares` [C]
    if crate::key::stored_wallet(login) {
        say(ui, head, "shares saved", "for next time");
    } else {
        say(ui, head, "saved, NOT encrypted:", "no wallet is stored");
    }
}

/// Recover: collect a set, interpolate `s`, and use the wallet it is.
/// Source: hw-reference/codex32-format.md §Device operations "Shamir Recover" [C]
fn recover(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>, place: Place) {
    const REC: &str = "Recover";
    let mut set = Set::new();
    if !collect(gate, login, ui, REC, &mut set) {
        return;
    }
    let got = crate::keywork::run(|kw| set.recover(kw));
    drop(set);
    let share = match got {
        Ok(s) => s,
        Err(e) => return say(ui, REC, "cannot recover:", describe(e)),
    };
    let Some(to) = target(ui, place, REC) else {
        return;
    };
    activate(gate, login, ui, REC, &share, to);
}

/// Derive Shares: collect a set, then make further shares of it at unused indices. They
/// keep the set's prefix, identifier, threshold and length, so they join the original set.
/// Source: hw-reference/codex32-format.md §Device operations "Derive Shares" [C]
fn derive(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    const DER: &str = "Derive shares";
    let mut set = Set::new();
    if !collect(gate, login, ui, DER, &mut set) {
        return;
    }
    let mut made: heapless::Vec<u8, 9> = heapless::Vec::new();
    loop {
        let mut letters: heapless::Vec<[u8; 1], 9> = heapless::Vec::new();
        for &i in SHARE_ORDER.iter() {
            if !set.holds(i) && !made.contains(&i) {
                let _ = letters.push([c32::ALPHABET[i as usize].to_ascii_uppercase()]);
            }
        }
        let rows: heapless::Vec<&str, 9> = letters
            .iter()
            .map(|l| core::str::from_utf8(l).unwrap_or("?"))
            .collect();
        if rows.is_empty() {
            return say(ui, DER, "every index", "has a share");
        }
        let Some(row) = pick_row(ui, DER, "which new share?", &rows) else {
            return;
        };
        let index = SHARE_ORDER
            .iter()
            .copied()
            .find(|&i| c32::ALPHABET[i as usize].to_ascii_uppercase() == letters[row][0])
            .unwrap_or(SHARE_ORDER[0]);
        let share = match crate::keywork::run(|kw| set.interpolate(index, kw)) {
            Ok(s) => s,
            Err(e) => return say(ui, DER, "cannot derive:", describe(e)),
        };
        let _ = made.push(index);
        let mut title: heapless::String<16> = heapless::String::new();
        let _ = write!(title, "Share {}", letters[row][0] as char);
        show(ui, &title, &share, true);
    }
}

// ---------------------------------------------------------------------------------------
// Split
// ---------------------------------------------------------------------------------------

/// The wallet in force as the secret a split encodes: its prefix and bytes.
///
/// Words become `cw1`, a stored raw master `ms1`, and everything else `cx1` -- an xprv,
/// and any wallet with a passphrase, whose keys are its master node. A WIF key is one key
/// with no master and cannot be split. Source: hw-reference/codex32-format.md §What a
/// split encodes [C]
fn wallet_secret(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) -> Result<(Hrp, [u8; 64], usize), &'static str> {
    use crate::key::{Loaded, Source};
    use crate::menu::Stored;
    let mut out = [0u8; 64];
    let words = |out: &mut [u8; 64], e: &[u8]| {
        out[..e.len()].copy_from_slice(e);
        (Hrp::Cw, e.len())
    };
    let node =
        |gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>, out: &mut [u8; 64]| {
            let m = menu::master_quietly(gate, login, ui.panel, SPLIT)?;
            out[..32].copy_from_slice(&m.chain_code);
            out[32..].copy_from_slice(m.secret_bytes());
            Ok::<_, &'static str>((Hrp::Cx, 64))
        };
    let (hrp, len) = if crate::passphrase::is_set() {
        node(gate, login, ui, &mut out)?
    } else {
        match crate::key::loaded() {
            Some(Loaded::Wif) => return Err("a WIF key cannot split"),
            Some(Loaded::Xprv) => node(gate, login, ui, &mut out)?,
            Some(Loaded::Words) => words(&mut out, crate::key::temporary().ok_or("no key")?),
            None if crate::key::in_force() != Source::Root => {
                let (mut e, n) = menu::seed_entropy(gate, login, ui.panel, SPLIT)?;
                let r = words(&mut out, &e[..n]);
                e.zeroize();
                r
            }
            // By reference: `Stored` wipes itself, and a by-value match would leave
            // copies of the secret behind that nothing wipes.
            None => match &menu::root_stored(gate, login, ui.panel, SPLIT)? {
                Stored::Words { entropy, len } => words(&mut out, &entropy[..*len]),
                Stored::Raw { bytes, len } if Hrp::Ms.carries(*len) => {
                    out[..*len].copy_from_slice(&bytes[..*len]);
                    (Hrp::Ms, *len)
                }
                Stored::Raw { .. } => return Err("that seed length"),
                Stored::Xprv { chain_code, key } => {
                    out[..32].copy_from_slice(chain_code);
                    out[32..].copy_from_slice(key);
                    (Hrp::Cx, 64)
                }
            },
        }
    };
    Ok((hrp, out, len))
}

/// Split the wallet in force into `n` shares, any `k` of which recover it.
///
/// A fresh identifier and the `k - 1` free shares come from the boot entropy pool, which
/// is the only thing on this device allowed to hand out seed material -- and which refuses
/// when it did not meet its policy. The free shares are the whole of the secrecy: with a
/// predictable generator a single share gives the wallet away, so a refusal is the
/// answer, not a reason to reach for something weaker. Nothing is stored, and the set
/// cannot be made again. Source: hw-reference/codex32-format.md §Shamir Split randomness,
/// §For an independent implementation item 4 [C]; docs/ENTROPY.md
#[inline(never)]
fn split(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    pool: Option<&mut catcard_entropy::EntropyPool>,
) {
    // Delta mode: showing the seed erases it instead. See `crate::trickpin`.
    #[cfg(not(feature = "board-mk3"))]
    crate::trickpin::seed_reveal(gate);
    let Some(pool) = pool else {
        return say(ui, SPLIT, "the pool missed its", "policy at boot");
    };
    ask(ui.panel, SPLIT, "any K shares are", "the whole wallet");
    if !confirmed(ui) {
        return;
    }
    let n = match menu::ask_number(ui, SPLIT, Some(("shares", "2 to 9")), "how many", "") {
        Some(n @ 2..=9) => n as u8,
        Some(_) => return say(ui, SPLIT, "2 to 9 shares", "nothing was split"),
        None => return,
    };
    let mut range: heapless::String<16> = heapless::String::new();
    let _ = write!(range, "2 to {n}");
    let k = match menu::ask_number(ui, SPLIT, Some(("needed", &range)), "threshold", "") {
        Some(k) if (2..=u32::from(n)).contains(&k) => k as u8,
        Some(_) => return say(ui, SPLIT, "threshold must be", &range),
        None => return,
    };
    if k == n {
        ask(ui.panel, SPLIT, "EVERY share needed:", "lose one, lose all");
        if !confirmed(ui) {
            return;
        }
    }

    let (hrp, mut bytes, len) = match wallet_secret(gate, login, ui) {
        Ok(s) => s,
        Err(why) => return say(ui, SPLIT, why, "nothing was split"),
    };
    if hrp == Hrp::Cx && crate::passphrase::is_set() {
        // The node is split, not the words: the shares bring back this wallet's keys,
        // with no words and no way to apply another passphrase.
        ask(ui.panel, SPLIT, "splits this wallet's", "XPRV: no words");
        if !confirmed(ui) {
            bytes.zeroize();
            return;
        }
    }

    // Drawn and split in one masked region, the noise wiped before it closes.
    let made = crate::keywork::run(|kw| {
        let secret = Share::from_bytes(hrp, 0, c32::seed_id(), SECRET_INDEX, &bytes[..len], kw)?;
        let mut noise = [0u8; 520];
        let need = c32::noise_len(&secret, k).min(noise.len());
        let mut drawn = Ok(());
        for chunk in noise[..need].chunks_mut(64) {
            drawn = drawn.and_then(|()| pool.draw(chunk));
        }
        let set = match drawn {
            Ok(()) => c32::split(&secret, k, &noise[..need], kw).map(Some),
            Err(_) => Ok(None),
        };
        noise.zeroize();
        // A split is a backup only if it recombines: the last k shares, which are the
        // computed ones, must give the secret back before any is shown.
        let set = set?.map(|set| {
            let mut check = Set::new();
            let mut good = true;
            for &i in SHARE_ORDER[usize::from(n - k)..usize::from(n)].iter() {
                good &= set.interpolate(i, kw).and_then(|s| check.add(s)).is_ok();
            }
            let back = check.recover(kw).and_then(|s| s.secret(kw));
            good &= back.is_ok_and(|b| b.as_bytes() == &bytes[..len]);
            (set, good)
        });
        Ok::<_, CError>(set)
    });
    bytes.zeroize();
    let set = match made {
        Ok(Some((set, true))) => set,
        Ok(Some((_, false))) => {
            crate::catlog!("codex32: split did not recombine; refused");
            return say(ui, SPLIT, "the shares do not", "add back up");
        }
        Ok(None) => return say(ui, SPLIT, "not enough entropy", "for a split"),
        Err(e) => return say(ui, SPLIT, "cannot split:", describe(e)),
    };

    for (i, &index) in SHARE_ORDER[..usize::from(n)].iter().enumerate() {
        let Ok(share) = crate::keywork::run(|kw| set.interpolate(index, kw)) else {
            continue;
        };
        let mut title: heapless::String<24> = heapless::String::new();
        let _ = write!(title, "Share {} of {}", i + 1, n);
        message(ui.panel, &title, "write it down,", "then any key");
        wait_for_any_key(ui);
        show(ui, &title, &share, true);
    }
    drop(set);
    crate::catlog!("codex32: split {}-of-{} as {}", k, n, hrp.text());
    say(ui, SPLIT, "all shares shown", "nothing was stored");
}
