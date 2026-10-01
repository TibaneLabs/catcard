//! Import a TAPSIGNER card backup: as this device's seed, or for this session only.
//!
//! A TAPSIGNER is an NFC signing card. A phone or a desktop reader takes an encrypted
//! backup off it; the owner has the **Backup Password** printed on the card. This device
//! never talks to the card: the backup arrives as a file on the card slot (or the Virtual
//! Disk), as a record a phone writes to the NFC tag, or -- on the Q1 -- as a QR code, and
//! the owner picks which. Then the password, and if it opens the backup, the BIP-32 node
//! inside it. The format and each channel's limits are [`catcard_backup::tapsigner`]; what
//! is here is the screens around them.
//! Source: hw-reference/tapsigner-backup-import.md §"Getting it onto the Coldcard" [C]
//!
//! # Two outcomes
//!
//! From the Import menu the node is offered two ways, as stock offers it under Import
//! Existing and again under Temporary Seed: **stored** as the wallet, or **in force for
//! this session** -- a temporary key like one typed in under Derive -> Import key, gone
//! at reboot unless it is locked down. From Derive it is only ever the second. Either way
//! it is an xprv-type secret with no words, and it is used **as the master**: the
//! fingerprint and every path start from it.
//! Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §B1 "Tapsigner Backup", §S1 [C];
//! hw-reference/tapsigner-backup-import.md §"Decryption and acceptance" steps 5-6 [C]
//!
//! # What the owner is shown that stock does not
//!
//! Stock reads the card's derivation path and drops it, and does not look at the node's
//! depth. Both decide whether this device shows the card's addresses, so both are put in
//! front of the owner before anything is used: the path the card was on (still not
//! stored -- the owner picks paths here as for any wallet), a warning when the node is not
//! a master, and one when its chain is not the one this device is set to.
//! Source: hw-reference/tapsigner-backup-import.md §"Consequences worth knowing",
//! §"For an independent implementation" [C]
//!
//! # Storing replaces the wallet, so it warns first
//!
//! Storing a seed over an existing one is destructive and irreversible. Like every other
//! import, this asks before it touches the slot. The session outcome touches the slot not
//! at all, so it does not warn.
//!
//! # The decrypt is private-key work
//!
//! The decrypted backup is a private key, so the whole decrypt-and-parse -- and the
//! fingerprint taken from it -- runs inside [`crate::keywork::run`], and every buffer that
//! held the plaintext is wiped on the way out.

use core::fmt::Write as _;

use catcard_backup::tapsigner;
use catcard_callgate::Callgate;
use catcard_callgate::pin::encode_xprv;
use catcard_ui::scroll::Line;
use catcard_wallet::bip32::ExtendedPrivKey;
use zeroize::{Zeroize as _, Zeroizing};

use crate::menu;
use crate::ui::Ui;

const HEAD: &str = "TAPSIGNER";

/// Room for the ciphertext and, separately, its plaintext: the most any channel delivers.
const BUF: usize = tapsigner::MAX_CIPHERTEXT;

/// A buffer that wipes itself, so every path out goes through one `Drop` -- the decrypted
/// plaintext passes through one and is key material.
struct Scratch([u8; BUF]);

impl Drop for Scratch {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The node a backup held: the chain code, then the key. Wiped when dropped.
type Node = Zeroizing<([u8; 32], [u8; 32])>;

/// What a backup opened to: the node, and the public facts the owner is shown about it.
struct Opened {
    node: Node,
    /// The node's own fingerprint, which is the wallet's once it is used as the master.
    fp: [u8; 4],
    /// Zero for a master. Anything else is used as a master all the same, as stock does.
    depth: u8,
    /// The chain its version prefix names: `xprv` mainnet, `tprv` testnet.
    mainnet: bool,
    /// The card's path, when the line is shaped like one; empty otherwise.
    path: heapless::String<40>,
}

/// Import -> TAPSIGNER: take a backup in, open it, and store its node -- or, if the owner
/// chooses, work in it for this session only.
pub(crate) fn import(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    let Some(opened) = decrypt(ui) else {
        return;
    };
    match review(
        ui,
        &opened,
        &[("Store as the wallet", 0), ("This session only", 1)],
    ) {
        Some(0) => store(gate, login, ui, &opened.node),
        Some(_) => {
            let was = crate::key::in_force();
            if load_session(ui, &opened.node) {
                menu::announce_key(gate, login, ui, HEAD, was);
            }
        }
        None => say(ui, "Import cancelled", "nothing was stored"),
    }
}

/// Derive -> Import key -> TAPSIGNER: the same backup, in force for this session and
/// never stored. Returns whether a key is now in force; the Derive menu names it.
#[inline(never)]
pub(crate) fn import_temporary(ui: &mut Ui<'_>) -> bool {
    let Some(opened) = decrypt(ui) else {
        return false;
    };
    review(ui, &opened, &[("Use it this session", 0)]).is_some() && load_session(ui, &opened.node)
}

/// Write the node to the secure element, after the destructive-case warning.
fn store(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>, node: &Node) {
    // The destructive case, warned once -- as `import_seed` and `restore` do.
    if crate::key::stored_wallet(login) {
        menu::ask(
            ui.panel,
            "Wallet exists",
            "an import DESTROYS",
            "the one stored now",
        );
        if !menu::confirmed(ui) {
            return say(ui, "Import cancelled", "nothing was stored");
        }
    }
    // Packed inside the masked region: the stash is the private key in another spelling.
    // An xprv-type secret, the same as Import XPRV stores.
    // Source: hw-reference/tapsigner-backup-import.md §"Decryption and acceptance"
    // step 5 [C]; hw-reference/secret-stash-format.md §Layout [C]
    let (chain_code, key) = &**node;
    let mut secret = crate::keywork::run(|_kw| encode_xprv(chain_code, key));
    let res = crate::backup::store_secret(gate, login, ui, &secret);
    secret.zeroize();
    match res {
        Ok(()) => {
            crate::key::to_root();
            crate::catlog!("tapsigner: imported master");
            menu::message(ui.panel, "Wallet imported", "from the TAPSIGNER", "backup");
        }
        Err(why) => menu::message(ui.panel, "Not imported", why, "any key to go back"),
    }
    menu::wait_for_any_key(ui);
}

/// Put the node in force for this session. True if it is; a key outside the curve order
/// is refused and said.
fn load_session(ui: &mut Ui<'_>, node: &Node) -> bool {
    let (chain_code, key) = &**node;
    if !crate::key::set_temporary_xprv(chain_code, key, "TAPSIGNER") {
        say(ui, "Cannot use it", "that key is not usable");
        return false;
    }
    crate::catlog!("tapsigner: master in force for this session");
    true
}

/// Show what the backup opened to -- the fingerprint, the card's path, and a warning for
/// each way the result would not match the card -- with `items` to choose from under it.
/// The chosen item's id, or `None` if the owner backed out.
fn review(ui: &mut Ui<'_>, o: &Opened, items: &[(&str, u32)]) -> Option<u32> {
    let [a, b, c, d] = o.fp;
    let mut xfp: heapless::String<24> = heapless::String::new();
    let _ = write!(xfp, "Master {a:02X}{b:02X}{c:02X}{d:02X}");
    let mut path: heapless::String<56> = heapless::String::new();
    let _ = write!(
        path,
        "Card path {}",
        if o.path.is_empty() {
            "unreadable"
        } else {
            &o.path
        }
    );

    let mut lines: heapless::Vec<Line<'_>, 10> = heapless::Vec::new();
    let _ = lines.push(Line::title(HEAD));
    let _ = lines.push(Line::body(&xfp));
    let _ = lines.push(Line::body(&path).small());
    // The card's path is dropped, as stock drops it: addresses follow the path chosen
    // here. On the card's default they are the ones this device shows by default.
    if !is_card_default(&o.path) {
        let _ = lines.push(
            Line::body(
                "The card's path is not kept: pick it when exporting or looking up addresses.",
            )
            .small()
            .wrapped(),
        );
    }
    if o.depth != 0 {
        let _ = lines.push(
            Line::body(
                "Not a master key. It is used as one, so addresses will not match the card's.",
            )
            .small()
            .wrapped(),
        );
    }
    if o.mainnet != crate::prefs::network().is_mainnet() {
        let _ = lines.push(
            Line::body(if o.mainnet {
                "A mainnet key, and this device is set to a testnet. See Testnet mode."
            } else {
                "A testnet key, and this device is set to mainnet. See Testnet mode."
            })
            .small()
            .wrapped(),
        );
    }
    for &(text, id) in items {
        let _ = lines.push(Line::item(text, id));
    }
    match menu::show_doc(ui, &lines, false, false) {
        menu::DocExit::Selected(id) => Some(id),
        _ => None,
    }
}

/// Whether `path` is the card's default, `m/84h/0h/0h` in either hardened spelling: the
/// path whose addresses this device's default single-sig account also shows.
/// Source: hw-reference/tapsigner-backup-import.md §"Consequences worth knowing" [C]
fn is_card_default(path: &str) -> bool {
    path.bytes()
        .map(|b| if b == b'\'' { b'h' } else { b })
        .eq(*b"m/84h/0h/0h")
}

/// Where a backup can come from on this board.
#[derive(Copy, Clone)]
enum Channel {
    Storage(menu::Storage),
    #[cfg(not(feature = "board-mk3"))]
    Nfc,
    #[cfg(feature = "board-q1")]
    Qr,
}

/// Offer every channel this board has; the mk3 has the card alone and is not asked.
/// Source: hw-reference/tapsigner-backup-import.md §"Getting it onto the Coldcard":
/// "a prompt offers every channel the device has" [C]
#[cfg_attr(feature = "board-mk3", allow(unused_variables))]
fn pick_channel(ui: &mut Ui<'_>) -> Option<Channel> {
    #[cfg(feature = "board-mk3")]
    return Some(Channel::Storage(menu::Storage::Sd));
    #[cfg(not(feature = "board-mk3"))]
    {
        use catcard_board::BOARD;
        let mut rows: heapless::Vec<&str, 4> = heapless::Vec::new();
        let mut ways: heapless::Vec<Channel, 4> = heapless::Vec::new();
        let mut offer = |row, way| {
            let _ = rows.push(row);
            let _ = ways.push(way);
        };
        offer("SD card", Channel::Storage(menu::Storage::Sd));
        if BOARD.psram.is_some() {
            offer("Virtual Disk", Channel::Storage(menu::Storage::Vdisk));
        }
        if BOARD.nfc.is_some() {
            offer("NFC", Channel::Nfc);
        }
        #[cfg(feature = "board-q1")]
        if BOARD.qr.is_some() {
            offer("Scan QR", Channel::Qr);
        }
        let i = menu::choose(ui, HEAD, "where is the backup?", &rows)?;
        ways.get(i).copied()
    }
}

/// Take the ciphertext in over the channel the owner picks, each held to its own limits.
/// Its length in `buf`, or `None` once the owner has been told why not.
#[inline(never)]
fn take(ui: &mut Ui<'_>, buf: &mut [u8; BUF]) -> Option<usize> {
    match pick_channel(ui)? {
        // A `.aes` file of 100-160 bytes, the raw ciphertext.
        Channel::Storage(storage) => {
            let path = menu::browse_storage(
                ui,
                storage,
                "Pick .aes backup",
                Some("aes"),
                menu::Browse::File,
            )?;
            menu::card_wait(ui.panel, HEAD, "reading the backup");
            match crate::signtx::read_source_file(storage, &path, buf) {
                Ok(n) if tapsigner::FILE_LEN.contains(&n) => Some(n),
                Ok(_) => {
                    say(ui, "Not a backup", "it is 100-160 bytes");
                    None
                }
                Err(why) => {
                    say(ui, "Cannot read", why);
                    None
                }
            }
        }
        // The first record of 150-280 bytes, as Base64.
        #[cfg(not(feature = "board-mk3"))]
        Channel::Nfc => {
            let mut text = [0u8; *tapsigner::NFC_RECORD_LEN.end()];
            let n = crate::nfc::receive_sized(ui, HEAD, tapsigner::NFC_RECORD_LEN, &mut text)?;
            match tapsigner::from_nfc(&text[..n], buf) {
                Ok(n) => Some(n),
                Err(_) => {
                    say(ui, "Not a backup", "not Base64 text");
                    None
                }
            }
        }
        #[cfg(feature = "board-q1")]
        Channel::Qr => scan(ui, buf),
    }
}

/// A QR code, hex or Base64: one that is neither asks for another scan.
#[cfg(feature = "board-q1")]
fn scan(ui: &mut Ui<'_>, buf: &mut [u8; BUF]) -> Option<usize> {
    // Hex is the longer of the two spellings; a little over for whitespace around it.
    let mut text = [0u8; 2 * BUF + 8];
    loop {
        let mut sink = crate::qrload::SliceSink::new(&mut text);
        let got = crate::qrload::collect_any(ui, HEAD, &mut sink);
        let held = sink.len;
        let len = match got {
            Ok(got) => got.len.min(held),
            Err(None) => return None,
            Err(Some(why)) => {
                say(ui, "Cannot scan", why);
                return None;
            }
        };
        if let Ok(n) = tapsigner::from_scanned(&text[..len], buf) {
            return Some(n);
        }
        menu::ask(ui.panel, HEAD, "not a TAPSIGNER backup", "scan another?");
        if !menu::confirmed(ui) {
            return None;
        }
    }
}

/// What one try of a Backup Password came to.
enum Outcome {
    Opened(Opened),
    /// The acceptance check failed: the password is wrong.
    WrongKey,
    /// It passed, but is not an `xprv` line and a path line.
    NotBackup,
    /// Two lines, but the first is not an extended private key.
    NoKey,
}

/// Take the backup in, ask for the Backup Password, and decrypt: the node inside, if the
/// password opened it. A wrong password, or a result that does not unpack, asks again --
/// as many times as the owner likes, until they back out. `None` means the owner has
/// already been told why.
/// Source: hw-reference/tapsigner-backup-import.md §"Decryption and acceptance" [C]
#[inline(never)]
fn decrypt(ui: &mut Ui<'_>) -> Option<Opened> {
    // Ciphertext, not a secret; zeroed anyway on the way out like every buffer here.
    let mut cipher = Scratch([0u8; BUF]);
    let len = take(ui, &mut cipher.0)?;

    loop {
        menu::ask(
            ui.panel,
            HEAD,
            "have the card at hand",
            "for its Backup Password",
        );
        if !menu::confirmed(ui) {
            say(ui, "Import cancelled", "nothing was changed");
            return None;
        }
        let Some(entry) = crate::passphrase::read_at_most(ui, "Backup Password", 32) else {
            say(ui, "Import cancelled", "nothing was changed");
            return None;
        };
        let mut key = [0u8; tapsigner::KEY_LEN];
        if let Err(e) = tapsigner::parse_key(entry.as_str(), &mut key) {
            key.zeroize();
            say(ui, "Bad password", describe(e));
            continue;
        }
        drop(entry);

        // Decrypt and parse inside the masked region: the plaintext, the node and its
        // fingerprint are private-key work, computed where a host cannot time them.
        let mut plain = Scratch([0u8; BUF]);
        let outcome = crate::keywork::run(|kw| {
            let o = match tapsigner::decrypt(&cipher.0[..len], &key, &mut plain.0) {
                Ok(o) => o,
                Err(catcard_backup::Error::NoXprv) => return Outcome::WrongKey,
                Err(_) => return Outcome::NotBackup,
            };
            let Ok(node) = ExtendedPrivKey::from_base58(o.xprv, kw) else {
                return Outcome::NoKey;
            };
            let mut path = heapless::String::new();
            let _ = path.push_str(o.shown_path().unwrap_or(""));
            Outcome::Opened(Opened {
                fp: node.fingerprint(kw),
                depth: node.depth,
                mainnet: node.network.is_mainnet(),
                path,
                node: Zeroizing::new((node.chain_code, *node.secret_bytes())),
            })
        });
        key.zeroize();
        drop(plain);

        match outcome {
            Outcome::Opened(o) => return Some(o),
            Outcome::WrongKey => say(ui, "Decryption failed", "wrong key?"),
            Outcome::NotBackup => say(ui, "Cannot unpack", "not a TAPSIGNER backup"),
            Outcome::NoKey => {
                say(ui, "Cannot import", "no valid extended private key");
                return None;
            }
        }
    }
}

fn say(ui: &mut Ui<'_>, head: &str, why: &str) {
    menu::message(ui.panel, head, why, "any key to go back");
    menu::wait_for_any_key(ui);
}

/// The few words a screen has for a password-entry error.
fn describe(e: catcard_backup::Error) -> &'static str {
    use catcard_backup::Error as E;
    match e {
        E::BadBackupKey => "it is 32 hex digits",
        E::NotHex => "only 0-9 and a-f are hex",
        _ => "that cannot be used",
    }
}
