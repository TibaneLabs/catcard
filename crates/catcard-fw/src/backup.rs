//! Backup, verify and restore: the wallet in a 7-Zip archive.
//!
//! The one thing this device makes that carries the seed off it. The format is
//! [`catcard_backup`] -- a `key = value` body inside an AES-256 archive, so a laptop
//! with p7zip and the password can read it years from now without this firmware. What is
//! here is the screens around that, and the decisions they encode.
//!
//! # Three ways to protect it, and the safe one is the default
//!
//! Stock offers a twelve-word backup password, a custom passphrase, or an explicit
//! cleartext file. Source: hw-reference/firmware-features.md §7 [C]. So does this:
//!
//! - **Twelve words**, the default: drawn from the **protocol DRBG**, never from the seed
//!   pool and never from the seed itself. A backup whose password can be recomputed from
//!   the thing it protects is not encrypted, it is obfuscated -- anyone holding the file
//!   would hold the wallet. They are a real BIP-39 phrase rather than twelve arbitrary
//!   words, which buys the restore side a checksum: a typo is caught by
//!   [`crate::menu::read_phrase`] in a second, instead of by a minute of key derivation
//!   ending in "wrong words".
//! - **A typed passphrase**: the same derivation over a string the owner chose. Easier to
//!   remember and easier to guess, which the screen says; too short is refused.
//! - **Cleartext**: no encryption at all, for a card that lives in a vault. Asked for
//!   twice, labelled as dangerous both times, and the last row of the list -- an
//!   irreversible exposure is never a default.
//!
//! Which of the three a file is comes out of its header, so a restore never asks a
//! question the archive already answers: a cleartext backup is read straight in, and an
//! encrypted one asks whether it was words or a passphrase.
//!
//! Whatever the mode, the password is the only copy and losing it loses the backup. So
//! the words go on screen, paged, before the file is written: a card that fails to write
//! costs nothing, and a word list nobody wrote down costs everything. The owner also
//! confirms before the words are shown at all, because putting a seed's password on a
//! screen is not something to do by accident.
//!
//! # One buffer, and it holds the seed
//!
//! A backup is a few kilobytes and the device has no room for two copies of it. So the
//! body is built where it will be encrypted ([`catcard_backup::sevenz::BODY_OFFSET`])
//! and sealed in place, and a restore decrypts back over the bytes it read. The buffer
//! is a local, zeroized on every path out -- it is not `heap::take`, because a seed in a
//! freed block is a seed nobody is tracking. Verify and the temporary load read into the
//! same kind of buffer and it dies with the screen: neither writes anything anywhere.
//!
//! # The key derivation is slow, and that is the format
//!
//! 7-Zip's KDF is 2^19 rounds of SHA-256 over the password. That is the better part of a
//! minute here. It is sliced on a fixed round count so the progress bar can move --
//! never on anything derived from the password -- exactly as `bip39::Stretch` is.
//!
//! # The file is named for the wallet
//!
//! `backup-<XFP>.7z`, the master fingerprint in the name as stock does it, so two devices'
//! backups on one card do not land on the same name -- and a card with three of them says
//! whose each one is without opening any. It goes to the storage the owner picks, the SD
//! card or the Virtual Disk, through the chooser every export uses.

use catcard_backup::{body, clone, kdf, sevenz};
use catcard_callgate::Callgate;
use catcard_callgate::pin::{
    SECRET_LEN, bip39_entropy, encode_bip39, encode_xprv, raw_master, xprv_parts,
};
use catcard_wallet::bip32::{ExtendedPrivKey, serialize::MAX_BASE58_LEN};
use catcard_wallet::bip39::{MAX_PHRASE_LEN, Mnemonic};
use core::fmt::Write as _;
use zeroize::Zeroize as _;

use crate::menu::{self, Storage, Working};
use crate::ui::Ui;

const SAVE_HEAD: &str = "Backup";
const RESTORE_HEAD: &str = "Restore backup";
const VERIFY_HEAD: &str = "Verify backup";
const TEMP_HEAD: &str = "Coldcard backup";

/// The archive's name, with the master fingerprint in it: `/backup-1A2B3C4D.7z`.
///
/// `write_storage_export` finds the next free `-2`, `-3` for us, so a card accumulates
/// backups of one wallet without either overwriting one or needing a clock, and two
/// wallets' backups never share a name at all. Source: stock's `backup-{xfp}.7z` naming,
/// hw-reference/wallet-export-formats.md §"Filenames" [I].
const CARD_FILE_HEAD: &str = "/backup-";
const CARD_FILE_TAIL: &str = ".7z";
/// The name when the stash has no key to take a fingerprint of.
const CARD_FILE_ANON: &str = "/backup.7z";

/// The two files a clone leaves on the card.
///
/// The blank device writes the start file (its ephemeral public key); the device with a
/// wallet reads it and writes the clone file (its public key, then the encrypted archive).
/// Both are `.bin`, so the file picker's `bin` filter shows them and the magic bytes tell
/// them apart -- picking the wrong one is a clear refusal, not a silent misread.
const CLONE_START_FILE: &str = "/ccbk-start.bin";
const CLONE_FILE: &str = "/ccbk-clone.bin";
const CLONE_HEAD: &str = "Clone Coldcard";

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
/// A constant, fixed in advance and independent of the password -- see the module docs
/// of [`catcard_backup::kdf`]. 2^19 rounds in slices of this is about 256 ticks of the bar.
const KDF_SLICE: u32 = 2048;

/// Backup words: twelve, so 128 bits of entropy.
const WORD_ENTROPY: usize = 16;

/// The shortest typed passphrase accepted.
///
/// Stock enforces a minimum without publishing the number; eight is this firmware's,
/// chosen so a passphrase is at least not a PIN. [I] It is a floor, not advice: the
/// screen says a short one is easier to guess than twelve words.
const MIN_TYPED: usize = 8;

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

/// The password as the KDF will see it, wiped when it goes.
///
/// Twelve words joined by single spaces, or the passphrase as typed: one buffer, sized
/// for the longer of the two, so the three modes meet the archive as one `&str`.
struct Phrase {
    buf: [u8; MAX_PHRASE_LEN],
    len: usize,
}

impl Drop for Phrase {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

impl Phrase {
    /// The words joined by single spaces, which is what every 7-Zip on the other end
    /// will be given.
    fn from_words(words: &Mnemonic) -> Self {
        let mut p = Phrase {
            buf: [0u8; MAX_PHRASE_LEN],
            len: 0,
        };
        p.len = words.render(&mut p.buf);
        p
    }

    /// The text as typed, spaces and all: a passphrase's spaces are part of it.
    fn from_text(text: &str) -> Option<Self> {
        if text.len() > MAX_PHRASE_LEN {
            return None;
        }
        let mut p = Phrase {
            buf: [0u8; MAX_PHRASE_LEN],
            len: text.len(),
        };
        p.buf[..text.len()].copy_from_slice(text.as_bytes());
        Some(p)
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

/// How a backup being written is protected.
///
/// `phrase` is the password -- the words or a typed passphrase, already one string --
/// or `None` for **no encryption at all**, reached only through two confirmations and
/// never by default. A struct rather than an enum only because the phrase is two hundred
/// bytes and the other case is none, which clippy rightly dislikes in a variant.
struct Protect {
    phrase: Option<Phrase>,
}

// ---------------------------------------------------------------------------
// Save
// ---------------------------------------------------------------------------

/// Write a backup of the stored wallet to the card or the Virtual Disk.
pub(crate) fn save(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    // The wallet first: a device with nothing to back up should say so before it asks
    // the owner to write twelve words down.
    let mut secret = match fetch(gate, login, ui, SAVE_HEAD) {
        Some(s) => s,
        None => return,
    };

    // The backup is of the stored seed. With something else in force -- a passphrase,
    // a BIP-85 child, a loaded key -- say so, as stock does, so nobody walks away
    // believing the wallet they were just using is in the file.
    // Source: hw-reference/help-and-warning-screens.md §9 "Backup of a temp seed" [C]
    if !crate::key::is_root() || crate::passphrase::is_set() {
        menu::message(
            ui.panel,
            SAVE_HEAD,
            "of the STORED seed,",
            "not the one in force",
        );
        menu::wait_for_any_key(ui);
    }

    // Where, then how: both cheap, both cancellable, and neither should have cost a word
    // list if the owner backs out of the other.
    let Some(storage) = menu::pick_storage(ui, SAVE_HEAD) else {
        secret.zeroize();
        return;
    };
    let Some(protect) = choose_protection(ui) else {
        secret.zeroize();
        return;
    };

    let outcome = write_archive(ui, storage, &secret, &protect);
    drop(protect);
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
                "keep the password safe"
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

/// Ask how the file is to be protected, and collect the password for it.
///
/// The list is in order of safety and the cursor starts on the words, so the default is
/// the strong one. `None` if the owner backed out of any step.
/// Source: hw-reference/firmware-features.md §7 [C]; the warnings from
/// hw-reference/help-and-warning-screens.md §9 [C].
fn choose_protection(ui: &mut Ui<'_>) -> Option<Protect> {
    const ROWS: &[&str] = &[
        "12 words (default)",
        "Typed passphrase",
        "Cleartext: NOT encrypted",
    ];
    match menu::pick_row(ui, SAVE_HEAD, "protect the file with", ROWS)? {
        0 => {
            let words = draw_words(ui)?;
            menu::ask(
                ui.panel,
                "Backup words",
                "twelve words, the",
                "ONLY key to the file",
            );
            if !menu::confirmed(ui) {
                return None;
            }
            menu::show_words(ui, &words);
            Some(Protect {
                phrase: Some(Phrase::from_words(&words)),
            })
        }
        1 => typed_passphrase(ui).map(|p| Protect { phrase: Some(p) }),
        _ => cleartext(ui).then_some(Protect { phrase: None }),
    }
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

/// A passphrase typed on the keypad, at least [`MIN_TYPED`] characters.
///
/// Warned before it is typed: it is the only key, and a short or obvious one is easier
/// to guess than twelve words. Typed once -- the entry screen shows it as it is built --
/// and then its length is confirmed, so a slip caught here does not become a file that
/// nothing opens.
fn typed_passphrase(ui: &mut Ui<'_>) -> Option<Phrase> {
    menu::ask(
        ui.panel,
        "Typed passphrase",
        "the ONLY key; a short",
        "one is easily guessed",
    );
    if !menu::confirmed(ui) {
        return None;
    }
    loop {
        let entry = crate::passphrase::read(ui, "Backup passphrase")?;
        if entry.len() < MIN_TYPED {
            let mut why: heapless::String<32> = heapless::String::new();
            let _ = write!(why, "at least {MIN_TYPED} characters");
            menu::message(ui.panel, "Too short", &why, "any key to retype");
            menu::wait_for_any_key(ui);
            continue;
        }
        let mut count: heapless::String<32> = heapless::String::new();
        let _ = write!(count, "{} characters typed", entry.len());
        menu::ask(
            ui.panel,
            "Use this passphrase?",
            &count,
            "y yes, x to retype",
        );
        if menu::confirmed(ui) {
            return Phrase::from_text(entry.as_str());
        }
    }
}

/// Two confirmations for a file with no encryption at all.
///
/// Both screens name the exposure. The second exists because the first can be a reflex;
/// a wallet written in plain text should never be the result of one extra key press.
/// Source: hw-reference/help-and-warning-screens.md §9 "Choose cleartext" [C]
fn cleartext(ui: &mut Ui<'_>) -> bool {
    menu::ask(
        ui.panel,
        "NOT ENCRYPTED",
        "anyone with the file",
        "has the whole wallet",
    );
    if !menu::confirmed(ui) {
        return false;
    }
    menu::ask(
        ui.panel,
        "REALLY cleartext?",
        "the seed in plain text",
        "y = yes, x = encrypt",
    );
    menu::confirmed(ui)
}

/// Build the body, seal it as `protect` says, and put it on `storage`.
fn write_archive(
    ui: &mut Ui<'_>,
    storage: Storage,
    secret: &[u8; SECRET_LEN],
    protect: &Protect,
) -> Result<(heapless::String<{ menu::EXPORT_NAME_MAX }>, bool), &'static str> {
    let mut scratch = Scratch::new();

    // With the preferences if they fit, without them if they do not. Nothing is
    // truncated either way: `BodyWriter` refuses rather than cutting a line in half, so
    // a body that did not fit is rebuilt from the start with less in it -- over a
    // cleared buffer, because the abandoned attempt left the seed in there and only the
    // bytes the second attempt writes are accounted for.
    let mut left_out = false;
    let (mut body_len, fingerprint) = match build_body(&mut scratch.0, secret, true) {
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

    body_len = match &protect.phrase {
        Some(phrase) => {
            // A fresh IV per archive: reusing one under the same key would let two
            // backups be compared block for block. From the protocol DRBG, with the
            // words it goes with.
            let mut iv = [0u8; 16];
            ui.protocol.generate(&mut iv).map_err(|_| "no random IV")?;

            // The body is the seed in plaintext and it sits here for the whole
            // derivation, which is the better part of a minute. Unavoidable with one
            // buffer, and the buffer wipes itself on the way out however this ends.
            let key = stretch(ui, phrase.as_str(), SAVE_HEAD, "sealing the backup")?;
            sevenz::seal_at(
                &mut scratch.0,
                body_len,
                INNER_FILE,
                &key,
                &iv,
                &[],
                kdf::DEFAULT_CYCLES_POWER,
            )
            .map_err(|_| "could not seal the backup")?
            .len()
        }
        None => {
            crate::catlog!("backup: CLEARTEXT, by the owner's choice");
            sevenz::seal_clear_at(&mut scratch.0, body_len, INNER_FILE)
                .map_err(|_| "could not pack the backup")?
                .len()
        }
    };

    let name = file_name(fingerprint);
    let mut note: heapless::String<24> = heapless::String::new();
    let _ = write!(note, "writing to {}", storage.medium());
    menu::card_wait(ui.panel, SAVE_HEAD, &note);
    let written = menu::write_storage_export(storage, &name, &scratch.0[..body_len], None)?;
    Ok((written, left_out))
}

/// `/backup-<XFP>.7z`, or the anonymous name when the stash gave no fingerprint.
fn file_name(fingerprint: Option<[u8; 4]>) -> heapless::String<{ menu::EXPORT_NAME_MAX }> {
    let mut name = heapless::String::new();
    match fingerprint {
        Some([a, b, c, d]) => {
            let _ = write!(
                name,
                "{CARD_FILE_HEAD}{a:02X}{b:02X}{c:02X}{d:02X}{CARD_FILE_TAIL}"
            );
        }
        None => {
            let _ = name.push_str(CARD_FILE_ANON);
        }
    }
    name
}

/// Lay the body out in `buf` at the offset the sealer expects.
///
/// Returns its length and the master fingerprint of the wallet in it, when the stash
/// holds a key to take one from -- the fingerprint is public and goes in the file name.
fn build_body(
    buf: &mut [u8; BUF],
    secret: &[u8; SECRET_LEN],
    preferences: bool,
) -> Result<(usize, Option<[u8; 4]>), catcard_backup::Error> {
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
    let fingerprint = crate::keywork::run(|kw| {
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
        } else if let Some(raw) = raw_master(secret) {
            master = ExtendedPrivKey::from_seed(raw, net, kw).ok();
        }

        w.text("chain", chain.ticker());
        let mut fingerprint = None;
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
            fingerprint = Some(master.fingerprint(kw));
        }
        xprv.zeroize();
        // The stash exactly as the secure element holds it. Enough on its own to put
        // the wallet back, whatever shape it is in -- including the shapes that have no
        // words and no `mnemonic` line above.
        w.hex("raw_secret", secret);
        fingerprint
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
    w.finish().map(|b| (b.len(), fingerprint))
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
// Opening a backup: the half that restore, verify and the temporary load share
// ---------------------------------------------------------------------------

/// Pick a backup off the card or the disk, open it, and leave its body at the front of
/// `scratch`. Returns the body's length.
///
/// Every failure has been shown by the time this returns `None`. The archive's own
/// structure is checked before the owner is asked for anything: a file that is
/// compressed, or holds more than one thing, is refused now rather than after a minute
/// of key derivation. And a cleartext archive asks for nothing at all -- the header
/// says it needs no key, and asking for words it would not use would only teach the
/// owner that the words do not matter.
fn open_backup(ui: &mut Ui<'_>, head: &str, scratch: &mut Scratch) -> Option<usize> {
    let storage = menu::pick_storage(ui, head)?;
    let path = menu::browse_storage(ui, storage, "Pick a backup", Some("7z"), menu::Browse::File)?;

    let mut note: heapless::String<24> = heapless::String::new();
    let _ = write!(note, "reading {}", storage.medium());
    menu::card_wait(ui.panel, head, &note);
    let len = match crate::signtx::read_source_file(storage, &path, &mut scratch.0) {
        Ok(n) => n,
        Err(why) => {
            say(ui, "Cannot read", why);
            return None;
        }
    };

    let found = match sevenz::open(&scratch.0[..len]) {
        Ok(f) => f,
        Err(e) => {
            say(ui, "Not a backup", describe(e));
            return None;
        }
    };

    let got = match found {
        sevenz::Found::Clear(plain) => {
            crate::catlog!("backup: the file is cleartext");
            sevenz::extract_in_place(&mut scratch.0[..len], &plain)
                .map(|b| b.len())
                .map_err(describe)
        }
        sevenz::Found::File(_) | sevenz::Found::Header(_) => {
            let phrase = ask_password(ui)?;
            open_body(ui, &mut scratch.0, len, found, phrase.as_str(), head)
        }
    };
    match got {
        Ok(n) => Some(n),
        Err(why) => {
            say(ui, "Cannot open it", why);
            None
        }
    }
}

/// Which kind of password the file was written under, and then the password.
///
/// The archive cannot say -- a phrase and a passphrase derive the same way -- so this is
/// the one question a restore has to ask. Words go through the checksummed reader;
/// a passphrase is taken exactly as typed.
fn ask_password(ui: &mut Ui<'_>) -> Option<Phrase> {
    const ROWS: &[&str] = &["12 words", "Typed passphrase"];
    match menu::pick_row(ui, "Backup password", "how was it protected?", ROWS)? {
        0 => {
            menu::message(
                ui.panel,
                "Backup words",
                "enter each word,",
                "then y y to finish",
            );
            menu::wait_for_any_key(ui);
            let words = menu::read_phrase(ui)?;
            Some(Phrase::from_words(&words))
        }
        _ => {
            let entry = crate::passphrase::read(ui, "Backup passphrase")?;
            Phrase::from_text(entry.as_str())
        }
    }
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
    phrase: &str,
    head: &str,
) -> Result<usize, &'static str> {
    let key = stretch(ui, phrase, head, "unlocking the backup")?;

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
        // Routed around this by the caller; a cleartext file has no key to derive.
        sevenz::Found::Clear(_) => return Err("it is not encrypted"),
    };

    let n = sevenz::decrypt_in_place(&mut buf[..len], &file, &key)
        .map_err(describe)?
        .len();
    Ok(n)
}

/// The wallet a body describes, as a 72-byte stash, and what it was read from.
///
/// `raw_secret` is preferred over `mnemonic`: it is the stash byte for byte, so it
/// restores an xprv or a raw master as faithfully as it restores words, and for a words
/// wallet the two agree anyway. The caller owns the stash and zeroizes it.
fn decode_secret(body: &[u8]) -> Result<([u8; SECRET_LEN], &'static str, u32), &'static str> {
    let text = core::str::from_utf8(body).map_err(|_| "the file is not text")?;
    let scan = body::scan(text).map_err(describe)?;

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
    Ok((secret, what, scan.settings))
}

// ---------------------------------------------------------------------------
// Restore
// ---------------------------------------------------------------------------

/// Read a backup off the card or the disk and put its wallet back.
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

    let mut scratch = Scratch::new();
    let Some(body_len) = open_backup(ui, RESTORE_HEAD, &mut scratch) else {
        return;
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

/// Read the body and store the wallet it describes.
fn apply(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    body: &[u8],
) -> Result<&'static str, &'static str> {
    let (mut secret, what, _) = decode_secret(body)?;
    let res = store_secret(gate, login, ui, &secret);
    secret.zeroize();
    res.map(|()| what)
}

/// Write a 72-byte stash into the secure element and confirm it stuck.
///
/// The committing half every restore path shares -- a decrypted backup, a clone, a
/// TAPSIGNER master -- so they cannot drift apart in the one place where drifting apart
/// loses a wallet. **Write, read back, then claim**: a slot that did not keep what was
/// written is reported, not assumed, because the owner is about to trust it. The caller
/// owns `secret` and zeroizes it; this only reads it.
pub(crate) fn store_secret(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    secret: &[u8; SECRET_LEN],
) -> Result<(), &'static str> {
    menu::message(ui.panel, "Applying", "do not disconnect", "");
    let pin_gate = crate::pinentry::BootloaderGate::new(gate);
    let stored = login.set_secret(&pin_gate, secret);
    // Written, then read back and compared, before anything claims it worked -- the
    // same order `import_seed` uses, and for the same reason.
    let kept = stored.is_ok() && login.verify_secret(&pin_gate, secret).unwrap_or(false);
    if stored.is_err() {
        return Err("the secure element refused it");
    }
    if !kept {
        return Err("the slot did not keep what was written");
    }
    // The stored slot holds a wallet now, whatever the menu last believed.
    crate::key::note_stored_seed(true);
    Ok(())
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

/// Open a backup and report what is in it, changing nothing.
///
/// Stock's own verify only checks the CRC and says so; this one goes the whole way --
/// decrypt, parse, derive -- because "the file opens and it is this wallet" is what an
/// owner standing at a safe wants to know, and a CRC cannot say it. Nothing is stored
/// and nothing in force changes; the buffer dies with the screen.
/// Source: hw-reference/help-and-warning-screens.md §9 "Verify backup file" [C]
pub(crate) fn verify(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    let mut scratch = Scratch::new();
    let Some(body_len) = open_backup(ui, VERIFY_HEAD, &mut scratch) else {
        return;
    };

    // Decrypted and checksummed. Now: does it parse, and whose wallet is it?
    let (mut secret, what, settings) = match decode_secret(&scratch.0[..body_len]) {
        Ok(d) => d,
        Err(why) => return say(ui, "Opens, but", why),
    };
    drop(scratch);

    let mut busy = Working::seed(ui.panel, VERIFY_HEAD, "checking the wallet");
    let theirs = fingerprint_of(&secret);
    secret.zeroize();
    busy.tick(ui.panel);

    let Some([a, b, c, d]) = theirs else {
        return say(ui, "Opens and parses", "but no key to name it");
    };
    let mut xfp: heapless::String<16> = heapless::String::new();
    let _ = write!(xfp, "XFP {a:02X}{b:02X}{c:02X}{d:02X}");

    // Against the wallet in force. A blank device has none, and says so rather than
    // calling a good backup a mismatch.
    let verdict = match fingerprint_in_force(gate, login, ui) {
        Some(ours) if ours == [a, b, c, d] => "same as this wallet",
        Some(_) => "NOT the wallet in force",
        None => "no wallet here to compare",
    };
    crate::catlog!("backup: verified: {}; {} settings", verdict, settings);
    menu::message(ui.panel, "Backup opens", &xfp, verdict);
    menu::wait_for_any_key(ui);

    let mut detail: heapless::String<32> = heapless::String::new();
    let _ = write!(detail, "{settings} settings inside");
    menu::message(ui.panel, "Backup holds", what, &detail);
    menu::wait_for_any_key(ui);
}

/// The master fingerprint of a stash, whatever shape it is in. Inside the masked region:
/// it derives the master key to get there.
fn fingerprint_of(secret: &[u8; SECRET_LEN]) -> Option<[u8; 4]> {
    let net = crate::prefs::network();
    crate::keywork::run(|kw| {
        let master = if let Some(entropy) = bip39_entropy(secret).filter(|e| e.len() <= 32) {
            menu::plain_master(entropy, kw).ok()
        } else if let Some((chain_code, key)) = xprv_parts(secret) {
            ExtendedPrivKey::root_from_parts(net, *chain_code, *key, kw).ok()
        } else {
            raw_master(secret).and_then(|raw| ExtendedPrivKey::from_seed(raw, net, kw).ok())
        };
        master.map(|m| m.fingerprint(kw))
    })
}

/// The fingerprint of the wallet in force, from the session if it already knows it and
/// from the seed otherwise. `None` on a device with nothing to compare against.
fn fingerprint_in_force(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) -> Option<[u8; 4]> {
    if let Some(fp) = crate::pubkeys::known_fingerprint() {
        return Some(fp);
    }
    let master = menu::master_quietly(gate, login, ui.panel, VERIFY_HEAD).ok()?;
    Some(crate::keywork::run(|kw| master.fingerprint(kw)))
}

// ---------------------------------------------------------------------------
// A backup as a temporary seed
// ---------------------------------------------------------------------------

/// Derive → Import key → Coldcard backup: open a backup and work in its wallet for this
/// session, storing nothing.
///
/// Stock's Temporary Seed → Coldcard Backup. The stored seed is untouched and a reboot
/// comes up in it again; [`restore`] is the deliberate step for someone who meant to
/// replace it. Words and an XPRV can be held this way; a raw master has no temporary
/// form here and is refused by name.
/// Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §D2 "Coldcard Backup" [C]
///
/// Returns whether a key is now in force; the caller names it.
pub(crate) fn load_temporary(ui: &mut Ui<'_>) -> bool {
    let mut scratch = Scratch::new();
    let Some(body_len) = open_backup(ui, TEMP_HEAD, &mut scratch) else {
        return false;
    };
    let (mut secret, what, _) = match decode_secret(&scratch.0[..body_len]) {
        Ok(d) => d,
        Err(why) => {
            say(ui, "Not loaded", why);
            return false;
        }
    };
    drop(scratch);

    menu::ask(ui.panel, "Work in this?", what, "the stored seed stays");
    if !menu::confirmed(ui) {
        secret.zeroize();
        return false;
    }

    let loaded = if let Some(entropy) = bip39_entropy(&secret) {
        crate::key::set_temporary(entropy, "Backup")
    } else if let Some((chain_code, key)) = xprv_parts(&secret) {
        crate::key::set_temporary_xprv(chain_code, key, "Backup")
    } else {
        false
    };
    secret.zeroize();
    if !loaded {
        say(ui, TEMP_HEAD, "that wallet shape cannot be loaded");
    }
    loaded
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
        .map_err(|_| "that cannot be a password")?;
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
        E::BadChecksum => "wrong password, or damaged",
        E::Compressed => "it is compressed; not readable here",
        E::NotOneFile => "it holds more than one file",
        E::NotSevenZip => "that is not a 7z archive",
        E::NotEncrypted => "it mixes encryption oddly",
        E::KdfTooExpensive => "it asks for too much work",
        E::Truncated | E::BufferTooSmall => "too big, or cut short",
        E::NotABackup => "no backup inside it",
        E::CloneBadMagic => "not a clone file from a Coldcard",
        E::CloneKeyAgreement => "the two devices could not agree a key",
        _ => "the file did not make sense",
    }
}

// ---------------------------------------------------------------------------
// Clone Coldcard
// ---------------------------------------------------------------------------
//
// Device-to-device migration with no memorized password. The wallet travels in the same
// AES-256 archive a backup uses, but the key is an ephemeral X25519 agreement between the
// two devices rather than twelve words -- see [`catcard_backup::clone`]. Two trips of one
// microSD card: the blank device writes a start file, the device with the wallet answers
// with an encrypted clone file, and the blank device opens it.

/// Export the stored wallet as a clone file, answering a blank device's start file.
///
/// The source side: it already holds a wallet, so it needs a target's public key (the
/// start file) before it can seal anything. Nothing here is destructive -- it only reads
/// the wallet out -- so there is no warning to show.
pub(crate) fn clone_export(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    let mut secret = match fetch(gate, login, ui, CLONE_HEAD) {
        Some(s) => s,
        None => return,
    };

    // The target's public key, out of the start file it left on the card.
    let Some(path) = menu::browse_sd(ui, "Pick clone start", Some("bin"), menu::Browse::File)
    else {
        secret.zeroize();
        return;
    };
    let mut start = [0u8; 64];
    let target_pub = match crate::signtx::read_card_file(&path, &mut start) {
        Ok(n) => match clone::read_start(&start[..n]) {
            Ok(p) => p,
            Err(e) => {
                secret.zeroize();
                return say(ui, "Not a clone start", describe(e));
            }
        },
        Err(why) => {
            secret.zeroize();
            return say(ui, "Cannot read", why);
        }
    };

    let outcome = write_clone(ui, &secret, &target_pub);
    secret.zeroize();
    match outcome {
        Ok(name) => {
            crate::catlog!("clone: wrote {}", name.as_str());
            menu::message(
                ui.panel,
                "Clone written",
                &name[1..],
                "put it in the new one",
            );
        }
        Err(why) => {
            crate::catlog!("clone: export failed: {}", why);
            menu::message(ui.panel, "Clone failed", why, "any key to go back");
        }
    }
    menu::wait_for_any_key(ui);
}

/// Agree a key with the target, seal the wallet, and write the clone file.
fn write_clone(
    ui: &mut Ui<'_>,
    secret: &[u8; SECRET_LEN],
    target_pub: &[u8; clone::PUBKEY_LEN],
) -> Result<heapless::String<{ menu::EXPORT_NAME_MAX }>, &'static str> {
    // A fresh ephemeral for this clone, from the protocol DRBG -- never the seed pool, and
    // never reused. The scalar dies with `source`; the public key goes in the file so the
    // target can complete the same agreement.
    let mut scalar = [0u8; clone::PUBKEY_LEN];
    ui.protocol
        .generate(&mut scalar)
        .map_err(|_| "no random key")?;
    let source = clone::Ephemeral::new(&scalar);
    scalar.zeroize();

    let (key, iv) = source
        .agree(target_pub, source.public(), target_pub)
        .map_err(|_| "clone key agreement failed")?;

    let mut scratch = Scratch::new();

    // The body, with preferences if they fit and without them if they do not -- rebuilt
    // over a cleared buffer, exactly as `write_archive` does and for the same reason.
    let (body_len, _) = match build_body(&mut scratch.0, secret, true) {
        Ok(n) => n,
        Err(catcard_backup::Error::BufferTooSmall) => {
            scratch.0.zeroize();
            build_body(&mut scratch.0, secret, false).map_err(|_| "clone too large")?
        }
        Err(_) => return Err("could not build the clone"),
    };

    let archive_len = sevenz::seal_at(
        &mut scratch.0,
        body_len,
        INNER_FILE,
        &key,
        &iv,
        &[],
        kdf::DEFAULT_CYCLES_POWER,
    )
    .map_err(|_| "could not seal the clone")?
    .len();

    // Prepend the header (magic + our public key). The archive is at the front of the
    // buffer; slide it right by the header, then write the header in front of it.
    let total = clone::HEADER_LEN
        .checked_add(archive_len)
        .filter(|&t| t <= scratch.0.len())
        .ok_or("clone too large")?;
    scratch.0.copy_within(0..archive_len, clone::HEADER_LEN);
    clone::write_header(&mut scratch.0, source.public()).map_err(|_| "clone too large")?;

    menu::card_wait(ui.panel, CLONE_HEAD, "writing to the card");
    menu::write_card_export(CLONE_FILE, &scratch.0[..total], None)
}

/// Import a clone file onto a blank device, publishing a start file first.
///
/// The target side, and the destructive one: it replaces whatever is stored, so the same
/// warning `restore` shows guards it. The ephemeral private key stays in RAM in this one
/// function for the whole two-trip exchange, and is wiped when the function returns.
pub(crate) fn clone_import(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    if crate::key::stored_wallet(login) {
        menu::ask(
            ui.panel,
            "Wallet exists",
            "a clone DESTROYS",
            "the one stored now",
        );
        if !menu::confirmed(ui) {
            return;
        }
    }

    // Our ephemeral. Held here until the archive is open, then dropped (and wiped).
    let mut scalar = [0u8; clone::PUBKEY_LEN];
    if ui.protocol.generate(&mut scalar).is_err() {
        scalar.zeroize();
        return say(ui, "No clone key", "the generator would not give one");
    }
    let target = clone::Ephemeral::new(&scalar);
    scalar.zeroize();

    // Publish the start file: our public key, for the other device to seal against.
    let mut start = [0u8; clone::START_LEN];
    if clone::write_start(&mut start, target.public()).is_err() {
        return say(ui, "Clone start", "could not be built");
    }
    menu::card_wait(ui.panel, CLONE_HEAD, "writing the start file");
    let start_name = match menu::write_card_export(CLONE_START_FILE, &start[..], None) {
        Ok(n) => n,
        Err(why) => return say(ui, "Cannot write", why),
    };
    crate::catlog!("clone: start file {}", start_name.as_str());

    menu::message(
        ui.panel,
        "Clone started",
        "take card to the",
        "old Coldcard",
    );
    menu::wait_for_any_key(ui);
    menu::message(ui.panel, "Then return here", "and pick the", "clone file");
    menu::wait_for_any_key(ui);

    let Some(path) = menu::browse_sd(ui, "Pick clone file", Some("bin"), menu::Browse::File) else {
        return;
    };

    let mut scratch = Scratch::new();
    menu::card_wait(ui.panel, CLONE_HEAD, "reading the card");
    let len = match crate::signtx::read_card_file(&path, &mut scratch.0) {
        Ok(n) => n,
        Err(why) => return say(ui, "Cannot read", why),
    };

    let source_pub = match clone::read_header(&scratch.0[..len]) {
        Ok(p) => p,
        Err(e) => return say(ui, "Not a clone", describe(e)),
    };
    let (key, _iv) = match target.agree(&source_pub, &source_pub, target.public()) {
        Ok(k) => k,
        Err(e) => return say(ui, "Clone failed", describe(e)),
    };

    let body_len = match open_clone(&mut scratch.0, len, &key) {
        Ok(n) => n,
        Err(why) => return say(ui, "Cannot open it", why),
    };

    match apply(gate, login, ui, &scratch.0[..body_len]) {
        Ok(what) => {
            crate::catlog!("clone: imported {}", what);
            menu::message(ui.panel, "Wallet cloned", what, "from the other device");
        }
        Err(why) => menu::message(ui.panel, "Not cloned", why, "any key to go back"),
    }
    menu::wait_for_any_key(ui);
}

/// Open the archive inside a clone file with the agreed key, leaving the body at the
/// front of `buf`.
///
/// The archive sits after the [`clone::HEADER_LEN`] header; it is decrypted in place there
/// and the plaintext body then slid to the front so [`apply`] reads it the same way it
/// reads a decrypted backup.
fn open_clone(buf: &mut [u8; BUF], len: usize, key: &kdf::Key) -> Result<usize, &'static str> {
    let file = match sevenz::open(&buf[clone::HEADER_LEN..len]).map_err(describe)? {
        sevenz::Found::File(s) => s,
        // Clone never writes an encrypted header, and never a cleartext file; anything
        // that claims to be either is not ours.
        sevenz::Found::Header(_) => return Err("that clone has an encrypted header"),
        sevenz::Found::Clear(_) => return Err("that clone is not encrypted"),
    };
    let n = sevenz::decrypt_in_place(&mut buf[clone::HEADER_LEN..len], &file, key)
        .map_err(describe)?
        .len();
    buf.copy_within(clone::HEADER_LEN..clone::HEADER_LEN + n, 0);
    Ok(n)
}
