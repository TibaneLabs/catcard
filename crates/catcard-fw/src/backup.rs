//! Backup and restore: the wallet in a 7-Zip archive, encrypted under twelve words.
//!
//! The one thing this device makes that carries the seed off it. The format is
//! [`catcard_backup`] -- a `key = value` body inside an AES-256 archive, so a laptop
//! with p7zip and the words can read it years from now without this firmware. What is
//! here is the screens around that, and the two decisions they encode.
//!
//! # The password is not derived from the seed
//!
//! The twelve backup words come from the **UI DRBG**, never from the seed pool and never
//! from the seed itself. A backup whose password can be recomputed from the thing it
//! protects is not encrypted, it is obfuscated -- anyone holding the file would hold the
//! wallet.
//!
//! Which means the words are the only copy, and losing them loses the backup. So they go
//! on screen, paged, before the file is written: a card that fails to write costs
//! nothing, and a word list nobody wrote down costs everything. The owner also confirms
//! before the words are shown at all, because putting a seed's password on a screen is
//! not something to do by accident.
//!
//! They are a real BIP-39 phrase rather than twelve arbitrary words, which buys the
//! restore side a checksum: a typo is caught by [`crate::menu::read_phrase`] in a
//! second, instead of by a minute of key derivation ending in "wrong words".
//!
//! # One buffer, and it holds the seed
//!
//! A backup is a few kilobytes and the device has no room for two copies of it. So the
//! body is built where it will be encrypted ([`catcard_backup::sevenz::BODY_OFFSET`])
//! and sealed in place, and a restore decrypts back over the bytes it read. The buffer
//! is a local, zeroized on every path out -- it is not `heap::take`, because a seed in a
//! freed block is a seed nobody is tracking.
//!
//! # The key derivation is slow, and that is the format
//!
//! 7-Zip's KDF is 2^19 rounds of SHA-256 over the password. That is the better part of a
//! minute here. It is sliced on a fixed round count so the progress bar can move --
//! never on anything derived from the words -- exactly as `bip39::Stretch` is.

use catcard_backup::{body, kdf, sevenz};
use catcard_callgate::Callgate;
use catcard_callgate::pin::{SECRET_LEN, bip39_entropy, encode_bip39, encode_xprv, xprv_parts};
use catcard_wallet::bip32::{ExtendedPrivKey, serialize::MAX_BASE58_LEN};
use catcard_wallet::bip39::{MAX_PHRASE_LEN, Mnemonic};
use core::fmt::Write as _;
use zeroize::Zeroize as _;

use crate::menu::{self, Working};
use crate::ui::Ui;

const SAVE_HEAD: &str = "Backup";
const RESTORE_HEAD: &str = "Restore backup";

/// The archive on the card.
///
/// One name, not a dated one: `write_card_export` finds the next free `-2`, `-3` for us,
/// so a card accumulates backups without either overwriting one or needing a clock.
const CARD_FILE: &str = "/backup.7z";

/// The one file inside the archive. Its name is not load-bearing -- the reader takes
/// whatever single file it finds -- but it should say what it is to whoever opens it.
const INNER_FILE: &str = "backup.txt";

/// The whole archive, and the body inside it before sealing.
///
/// Four kilobytes on the stack. Everything the wallet itself needs is about one
/// kilobyte; the rest is room for the preferences, and if they do not fit they are left
/// out **and said to be left out** rather than silently cut short.
const BUF: usize = 4096;

/// Key-derivation rounds between redraws.
///
/// A constant, fixed in advance and independent of the words -- see the module docs of
/// [`catcard_backup::kdf`]. 2^19 rounds in slices of this is about 256 ticks of the bar.
const KDF_SLICE: u32 = 2048;

/// Backup words: twelve, so 128 bits of entropy.
const WORD_ENTROPY: usize = 16;

/// A backup buffer that wipes itself.
///
/// Its own type so that every path out of every screen below goes through one `Drop`
/// rather than an easily-forgotten `zeroize()` before each `return`.
struct Scratch([u8; BUF]);

impl Drop for Scratch {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Scratch {
    fn new() -> Self {
        Scratch([0u8; BUF])
    }
}

// ---------------------------------------------------------------------------
// Save
// ---------------------------------------------------------------------------

/// Write an encrypted backup of the stored wallet to the microSD card.
pub(crate) fn save(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    // The wallet first: a device with nothing to back up should say so before it asks
    // the owner to write twelve words down.
    let mut secret = match fetch(gate, login, ui, SAVE_HEAD) {
        Some(s) => s,
        None => return,
    };

    let Some(words) = draw_words(ui) else {
        secret.zeroize();
        return;
    };

    menu::ask(
        ui.panel,
        "Backup words",
        "twelve words, the",
        "ONLY key to the file",
    );
    if !menu::confirmed(ui) {
        secret.zeroize();
        return;
    }
    menu::show_words(ui, &words);

    // The phrase is the password: the words joined by single spaces, which is what
    // every 7-Zip on the other end will be given.
    let mut phrase = [0u8; MAX_PHRASE_LEN];
    let n = words.render(&mut phrase);
    let outcome = write_archive(ui, &secret, &phrase[..n]);
    phrase.zeroize();
    secret.zeroize();

    match outcome {
        Ok((name, left_out)) => {
            crate::catlog!("backup: wrote {}", name.as_str());
            // Say when the preferences did not fit. The wallet is in there either way,
            // but "your settings are not in this file" is not something to find out
            // when the backup is the only copy left.
            let note = if left_out {
                "wallet only: no settings"
            } else {
                "keep the words safe"
            };
            menu::message(ui.panel, "Backed up", &name[1..], note);
        }
        Err(why) => {
            crate::catlog!("backup: failed: {}", why);
            menu::message(ui.panel, "Backup failed", why, "any key to go back");
        }
    }
    menu::wait_for_any_key(ui);
}

/// Twelve words from the protocol DRBG.
///
/// The protocol one, not the UI one: these words are the key to the backup, and the UI
/// generator's outputs are on the screen as the keypad's scramble order. One instance
/// per purpose, so the two never share a state.
///
/// Refusing is the answer if the DRBG will not give them: a backup password from a
/// generator that cannot say it is healthy is worse than no backup.
fn draw_words(ui: &mut Ui<'_>) -> Option<Mnemonic> {
    let mut entropy = [0u8; WORD_ENTROPY];
    if ui.protocol.generate(&mut entropy).is_err() {
        entropy.zeroize();
        menu::message(
            ui.panel,
            "No backup words",
            "the generator",
            "would not give any",
        );
        menu::wait_for_any_key(ui);
        return None;
    }
    let words = crate::keywork::run(|kw| Mnemonic::from_entropy(&entropy, kw));
    entropy.zeroize();
    match words {
        Ok(m) => Some(m),
        Err(_) => {
            menu::message(ui.panel, "No backup words", "could not build", "a phrase");
            menu::wait_for_any_key(ui);
            None
        }
    }
}

/// Build the body, seal it under `phrase`, and put it on the card.
fn write_archive(
    ui: &mut Ui<'_>,
    secret: &[u8; SECRET_LEN],
    phrase: &[u8],
) -> Result<(heapless::String<{ menu::EXPORT_NAME_MAX }>, bool), &'static str> {
    let phrase = core::str::from_utf8(phrase).map_err(|_| "bad phrase")?;
    let mut scratch = Scratch::new();

    // With the preferences if they fit, without them if they do not. Nothing is
    // truncated either way: `BodyWriter` refuses rather than cutting a line in half, so
    // a body that did not fit is rebuilt from the start with less in it -- over a
    // cleared buffer, because the abandoned attempt left the seed in there and only the
    // bytes the second attempt writes are accounted for.
    let mut left_out = false;
    let mut body_len = match build_body(&mut scratch.0, secret, true) {
        Ok(n) => n,
        Err(catcard_backup::Error::BufferTooSmall) => {
            left_out = true;
            scratch.0.zeroize();
            build_body(&mut scratch.0, secret, false).map_err(|_| "backup too large")?
        }
        Err(_) => return Err("could not build the backup"),
    };
    if left_out {
        crate::catlog!("backup: preferences left out, no room");
    }

    // A fresh IV per archive: reusing one under the same key would let two backups be
    // compared block for block. From the protocol DRBG, with the words it goes with.
    let mut iv = [0u8; 16];
    ui.protocol.generate(&mut iv).map_err(|_| "no random IV")?;

    // The body is the seed in plaintext and it sits here for the whole derivation,
    // which is the better part of a minute. Unavoidable with one buffer, and the
    // buffer wipes itself on the way out however this ends.
    let key = stretch(ui, phrase, SAVE_HEAD, "sealing the backup")?;
    let archive = sevenz::seal_at(
        &mut scratch.0,
        body_len,
        INNER_FILE,
        &key,
        &iv,
        &[],
        kdf::DEFAULT_CYCLES_POWER,
    )
    .map_err(|_| "could not seal the backup")?;
    body_len = archive.len();

    menu::card_wait(ui.panel, SAVE_HEAD, "writing to the card");
    let name = menu::write_card_export(CARD_FILE, &scratch.0[..body_len], None)?;
    Ok((name, left_out))
}

/// Lay the body out in `buf` at the offset the sealer expects, and return its length.
fn build_body(
    buf: &mut [u8; BUF],
    secret: &[u8; SECRET_LEN],
    preferences: bool,
) -> Result<usize, catcard_backup::Error> {
    // The network in force decides the label, the `chain` ticker and the version bytes of
    // the xprv/xpub below: a testnet wallet's backup reads `Bitcoin Testnet 4` / `XTN` /
    // `tprv`, so it restores as the same wallet it was saved from.
    // Source: hw-reference/wallet-export-formats.md §"Chain parameters" [C].
    let chain = crate::prefs::current().net;
    let net = crate::prefs::network();
    let mut header: heapless::String<40> = heapless::String::new();
    let _ = write!(header, "Private key details: {}", chain.long_name());

    let mut w = body::BodyWriter::new(&mut buf[sevenz::BODY_OFFSET..]);
    w.preamble();
    w.section(header.as_str());

    // Everything below is computed from the stash, so it is all inside one masked
    // region: no interrupt runs between deriving the key and rendering it.
    crate::keywork::run(|kw| {
        let mut xprv = [0u8; MAX_BASE58_LEN];
        let mut master = None;

        if let Some(entropy) = bip39_entropy(secret).filter(|e| e.len() <= 32)
            && let Ok(m) = Mnemonic::from_entropy(entropy, kw)
        {
            let mut phrase = [0u8; MAX_PHRASE_LEN];
            let n = m.render(&mut phrase);
            if let Ok(text) = core::str::from_utf8(&phrase[..n]) {
                w.text("mnemonic", text);
            }
            phrase.zeroize();
            master = menu::plain_master(entropy, kw).ok();
        } else if let Some((chain_code, key)) = xprv_parts(secret) {
            // No usable key means no xprv/xpub lines; the raw stash below still goes out.
            master = ExtendedPrivKey::root_from_parts(net, *chain_code, *key, kw).ok();
        } else if let Some(raw) = catcard_callgate::pin::raw_master(secret) {
            master = ExtendedPrivKey::from_seed(raw, net, kw).ok();
        }

        w.text("chain", chain.ticker());
        if let Some(master) = &master {
            if let Ok(n) = master.write_base58(&mut xprv, kw)
                && let Ok(text) = core::str::from_utf8(&xprv[..n])
            {
                w.text("xprv", text);
            }
            let pubkey = master.to_extended_pub(kw);
            let mut xpub = [0u8; MAX_BASE58_LEN];
            if let Ok(n) = pubkey.write_base58(&mut xpub)
                && let Ok(text) = core::str::from_utf8(&xpub[..n])
            {
                w.text("xpub", text);
            }
        }
        xprv.zeroize();
        // The stash exactly as the secure element holds it. Enough on its own to put
        // the wallet back, whatever shape it is in -- including the shapes that have no
        // words and no `mnemonic` line above.
        w.hex("raw_secret", secret);
    });

    w.section("Firmware version (informational)");
    w.text("fw_version", crate::VERSION);

    w.section("Coldcard Hardware");
    // SAFETY: the unique-ID words are read-only factory data at a fixed address; this
    // reads them and nothing else.
    let uid = unsafe { catcard_hal::uid::read() };
    w.hex("serial", &uid);
    w.text("hardware", catcard_board::BOARD.name);

    if preferences {
        w.section("User preferences");
        write_preferences(&mut w, secret);
    }

    w.eof();
    w.finish().map(|b| b.len())
}

/// The root wallet's settings, one `setting.<name>` line each.
///
/// Values go out as the **raw JSON they were stored as**, so a preference this firmware
/// has never heard of comes back byte-identical.
/// The key is [`catcard_settings::nvstore::hash_key`] over the stash we already hold,
/// so this costs no second trip to the secure element.
#[cfg(not(feature = "board-mk3"))]
fn write_preferences(w: &mut body::BodyWriter<'_>, secret: &[u8; SECRET_LEN]) {
    use catcard_settings::json::Doc;
    use catcard_settings::nvstore;
    use catcard_settings::store::{self, SCRATCH};

    let key = crate::keywork::run(|_| nvstore::hash_key(secret));
    // The settings blob is preferences, not key material, so the heap is the right
    // place for its four kilobytes.
    let Some(mut held) = crate::heap::take(SCRATCH) else {
        crate::catlog!("backup: no memory for the preferences");
        return;
    };
    let buf = held.bytes();
    // SAFETY: the region is mapped and readable; nothing is written to it here.
    let Ok(mut files) = (unsafe { crate::settings::Files::mount_read_only() }) else {
        return;
    };
    let Ok(n) = store::read(&mut files, &key, buf) else {
        return;
    };
    let Ok(doc) = Doc::parse(&buf[..n]) else {
        return;
    };
    for e in doc.entries() {
        w.setting(e.key, e.raw);
    }
}

/// The mk3 keeps no settings blob: its medium is not wired up (`settings.rs`), so there
/// is nothing to carry and no section to write.
#[cfg(feature = "board-mk3")]
fn write_preferences(_w: &mut body::BodyWriter<'_>, _secret: &[u8; SECRET_LEN]) {}

// ---------------------------------------------------------------------------
// Restore
// ---------------------------------------------------------------------------

/// Read a backup off the card and put its wallet back.
pub(crate) fn restore(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    // The destructive case, and the only warning: this replaces whatever is stored.
    if crate::key::stored_wallet(login) {
        menu::ask(
            ui.panel,
            "Wallet exists",
            "a restore DESTROYS",
            "the one stored now",
        );
        if !menu::confirmed(ui) {
            return;
        }
    }

    let Some(path) = menu::browse_sd(ui, "Pick a backup", Some("7z"), menu::Browse::File) else {
        return;
    };

    let mut scratch = Scratch::new();
    menu::card_wait(ui.panel, RESTORE_HEAD, "reading the card");
    let len = match crate::signtx::read_card_file(&path, &mut scratch.0) {
        Ok(n) => n,
        Err(why) => return say(ui, "Cannot read", why),
    };

    // The archive's own structure first, before the owner is asked for anything: a file
    // that is compressed, or holds more than one thing, is refused now rather than after
    // a minute of key derivation.
    let found = match sevenz::open(&scratch.0[..len]) {
        Ok(f) => f,
        Err(e) => return say(ui, "Not a backup", describe(e)),
    };

    menu::message(
        ui.panel,
        "Backup words",
        "enter each word,",
        "then y y to finish",
    );
    menu::wait_for_any_key(ui);
    let Some(words) = menu::read_phrase(ui) else {
        return say(ui, "Restore cancelled", "nothing was stored");
    };

    let mut phrase = [0u8; MAX_PHRASE_LEN];
    let n = words.render(&mut phrase);
    let got = open_body(ui, &mut scratch.0, len, found, &phrase[..n]);
    phrase.zeroize();

    let body_len = match got {
        Ok(n) => n,
        Err(why) => return say(ui, "Cannot open it", why),
    };

    match apply(gate, login, ui, &scratch.0[..body_len]) {
        Ok(what) => {
            crate::catlog!("backup: restored {}", what);
            menu::message(ui.panel, "Wallet restored", what, "from the backup");
        }
        Err(why) => menu::message(ui.panel, "Not restored", why, "any key to go back"),
    }
    menu::wait_for_any_key(ui);
}

/// Derive the key and decrypt, leaving the body at the front of `buf`.
///
/// An encrypted header costs no second derivation: 7-Zip gives both streams the same
/// salt and round count and varies only the IV, so the one key opens both.
fn open_body(
    ui: &mut Ui<'_>,
    buf: &mut [u8; BUF],
    len: usize,
    found: sevenz::Found,
    phrase: &[u8],
) -> Result<usize, &'static str> {
    let phrase = core::str::from_utf8(phrase).map_err(|_| "bad phrase")?;
    let key = stretch(ui, phrase, RESTORE_HEAD, "unlocking the backup")?;

    let file = match found {
        sevenz::Found::File(s) => s,
        sevenz::Found::Header(hdr) => {
            // The header has to be decrypted before the file inside it can be located,
            // and it must not land on top of the archive -- so this one goes into its
            // own buffer, which is also the only moment two are alive.
            let mut header = Scratch::new();
            let n = sevenz::decrypt(&buf[..len], &hdr, &key, &mut header.0)
                .map_err(describe)?
                .len();
            sevenz::file_in(&header.0[..n]).map_err(describe)?
        }
    };

    let n = sevenz::decrypt_in_place(&mut buf[..len], &file, &key)
        .map_err(describe)?
        .len();
    Ok(n)
}

/// Read the body and store the wallet it describes.
fn apply(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    body: &[u8],
) -> Result<&'static str, &'static str> {
    let text = core::str::from_utf8(body).map_err(|_| "the file is not text")?;
    let scan = body::scan(text).map_err(describe)?;

    // `raw_secret` is preferred over `mnemonic`: it is the stash byte for byte, so it
    // restores an xprv or a raw master as faithfully as it restores words, and for a
    // words wallet the two agree anyway.
    let mut secret = [0u8; SECRET_LEN];
    let what = if let Some(hex) = scan.details.raw_secret {
        let n = body::unhex(hex, &mut secret)
            .map_err(|_| "the stored secret is not hex")?
            .len();
        if n != SECRET_LEN {
            secret.zeroize();
            return Err("the stored secret is the wrong length");
        }
        "the stored wallet"
    } else if let Some(phrase) = scan.details.mnemonic {
        let encoded = crate::keywork::run(|kw| {
            Mnemonic::parse(phrase, kw)
                .ok()
                .and_then(|m| encode_bip39(m.entropy()).ok())
        });
        match encoded {
            Some(s) => secret = s,
            None => return Err("the words in it do not check out"),
        }
        "the words in it"
    } else if let Some(text) = scan.details.xprv {
        let encoded = crate::keywork::run(|kw| {
            ExtendedPrivKey::from_base58(text, kw)
                .ok()
                .map(|k| encode_xprv(&k.chain_code, k.secret_bytes()))
        });
        match encoded {
            Some(s) => secret = s,
            None => return Err("the XPRV in it does not parse"),
        }
        "the XPRV in it"
    } else {
        return Err("no wallet in that backup");
    };

    menu::message(ui.panel, "Applying", "do not disconnect", "");
    let pin_gate = crate::pinentry::BootloaderGate::new(gate);
    let stored = login.set_secret(&pin_gate, &secret);
    // Written, then read back and compared, before anything claims it worked -- the
    // same order `import_seed` uses, and for the same reason.
    let kept = stored.is_ok() && login.verify_secret(&pin_gate, &secret).unwrap_or(false);
    secret.zeroize();
    if stored.is_err() {
        return Err("the secure element refused it");
    }
    if !kept {
        return Err("the slot did not keep what was written");
    }
    Ok(what)
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

/// Run the key derivation to the end, ticking the bar between slices.
fn stretch(
    ui: &mut Ui<'_>,
    phrase: &str,
    head: &str,
    note: &str,
) -> Result<kdf::Key, &'static str> {
    let mut kd = kdf::KeyDerivation::new(phrase, &[], kdf::DEFAULT_CYCLES_POWER)
        .map_err(|_| "those words cannot be a password")?;
    let mut busy = Working::new(ui.panel, head, note);
    while !kd.step(KDF_SLICE) {
        busy.tick(ui.panel);
    }
    kd.finish().map_err(|_| "key derivation failed")
}

/// The stash the secure element holds, with the wait screen in front of it.
fn fetch(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    head: &str,
) -> Option<[u8; SECRET_LEN]> {
    menu::reading_seed(ui.panel, head);
    let pin_gate = crate::pinentry::BootloaderGate::new(gate);
    match login.fetch_secret(&pin_gate) {
        Ok(s) if s.iter().any(|b| *b != 0) => Some(s),
        Ok(mut s) => {
            s.zeroize();
            say(ui, "Nothing to back up", "no wallet is stored");
            None
        }
        Err(_) => {
            say(ui, "Cannot read it", "the seed would not come back");
            None
        }
    }
}

fn say(ui: &mut Ui<'_>, head: &str, why: &str) {
    menu::message(ui.panel, head, why, "any key to go back");
    menu::wait_for_any_key(ui);
}

/// The few words a screen has for a format error.
///
/// Each one is something the owner can act on -- a different file, the other word list,
/// a laptop -- rather than a name from the specification.
fn describe(e: catcard_backup::Error) -> &'static str {
    use catcard_backup::Error as E;
    match e {
        E::BadChecksum => "wrong words, or a damaged file",
        E::Compressed => "it is compressed; not readable here",
        E::NotOneFile => "it holds more than one file",
        E::NotSevenZip => "that is not a 7z archive",
        E::NotEncrypted => "it is not encrypted",
        E::KdfTooExpensive => "it asks for too much work",
        E::Truncated | E::BufferTooSmall => "too big, or cut short",
        E::NotABackup => "no backup inside it",
        _ => "the file did not make sense",
    }
}
