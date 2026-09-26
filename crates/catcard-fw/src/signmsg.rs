//! Signing a message with one of the wallet's addresses.
//!
//! Proof of control without a transaction: a message comes from the keypad, off a text
//! file on the card, or out of a scanned code, the device signs it with the key behind one
//! of its addresses, and the result is written in the armoured form every verifier reads.
//! Nothing here can move coins -- a legacy signature commits to the "Bitcoin Signed
//! Message" prefix, and a BIP-322 one to a transaction that spends an output which does
//! not exist.
//!
//! Three formats, because all are asked for:
//!
//! - **legacy** ([`message`]), the 65-byte recoverable signature every wallet has read
//!   since 2011, for P2PKH, P2SH-P2WPKH and P2WPKH addresses;
//! - **BIP-322 simple** ([`bip322`]), the standard one, which is what a verifier that
//!   wants a proof for a native-segwit or taproot address rather than a convention about
//!   one will ask for;
//! - **BIP-322 full** ([`bip322::full`]), the whole `to_sign` transaction: the only form
//!   a nested-segwit address has, and the one a multisig cosigner's share travels in.
//!
//! The owner picks the address type, then the format from those the type allows, on a
//! screen that names each. Nothing guesses: a file written in the wrong format is a file
//! the other side rejects, and the formats are not distinguishable by looking at the
//! address.
//!
//! A registered multisig wallet can sign too, where this device is one of its cosigners:
//! the witness script is rebuilt from the wallet's own record, this device's key is
//! proven to be in it, and the result is a partial signature -- one of `M` -- in the full
//! format, which `Sign → Verify` reports as needing the other cosigners.
//!
//! # Which key
//!
//! An address type and a derivation path, both chosen. The default is the first receive
//! address of the matching account on the network in force -- `m/84h/0h/0h/0/0` for a
//! native-segwit signature on mainnet, `m/84h/1h/0h/0/0` on testnet -- because it is the
//! one a watch-only wallet shows first. A custom path is typed (Q1) or built a level at a
//! time (numpad boards), through the same entry the address explorer uses.
//!
//! # The request file
//!
//! A `.txt` on the card may carry the request in the public three-line form Sparrow and
//! stock's documentation use: the message, then an optional derivation path, then an
//! optional address format ([`message::parse_request`]). What the file asked for is shown
//! for confirmation before any key is touched; what it left out is asked. The same parser
//! reads a scanned code, which is how a request arrives without a card.
//!
//! Source: hw-reference/firmware-features.md §6 [C].
//!
//! Before any signature is shown, the device checks its own work -- the legacy one by
//! recovering the public key from it and comparing, the BIP-322 one by running the
//! verifier over it. A signature that does not verify is not handed to anyone.

use catcard_callgate::Callgate;
use catcard_ui::keypad::{Event, KEYS, Key};
use catcard_ui::textentry::Entry;
use catcard_wallet::address::{self, AddressKind};
use catcard_wallet::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, Network};
use catcard_wallet::bip322::full;
use catcard_wallet::{bip322, message, signfile};
use core::fmt::Write as _;
use zeroize::Zeroize;

use crate::display;
use crate::menu;
use crate::ui::Ui;

/// Where a typed or scanned message's signature is written.
const FILE_NAME: &str = "/SIGNED.TXT";

/// What is appended to a text file's name for the signature beside it.
const SIGNED_SUFFIX: &str = "-signed.txt";

/// Longest text file this reads. A message is at most [`message::MAX_MESSAGE`]; the rest
/// is room for the path and format lines, the trailing newline an editor leaves, and for
/// saying "too long" about a file that is, rather than silently signing its first 240
/// characters.
const MAX_FILE: usize = 2048;

/// Longest path this builds for the file it writes back.
const PATH_MAX: usize = 176;

/// Characters a derivation path takes on screen: `m/` and twelve levels of up to ten
/// digits, a marker and a separator each.
const PATH_CHARS: usize = 2 + catcard_wallet::bip32::MAX_PATH_DEPTH * 12;

/// Longest armoured signature this writes: a cosigner's partial in the full format,
/// which is longer than any single-key signature in any format.
pub(crate) const SIG_TEXT: usize = full::MAX_PARTIAL_ARMOURED;

/// Room for the whole armoured file: three marker lines, the message, the address and the
/// signature, each on its own line.
///
/// Sized from the parts rather than guessed at, because the overflow of a fixed-size
/// buffer here would be a file that is written, looks right on screen, and ends in the
/// middle of a signature.
const FILE_TEXT: usize = signfile::BEGIN.len()
    + signfile::SEPARATOR.len()
    + signfile::END.len()
    + message::MAX_MESSAGE
    + address::MAX_ADDRESS_LEN
    + SIG_TEXT
    + 8;

/// Which signature the file will carry.
#[derive(Copy, Clone, PartialEq, Eq)]
pub(crate) enum Format {
    /// The "Bitcoin Signed Message" digest and a recoverable signature.
    Legacy,
    /// BIP-322, simple variant: the witness stack.
    Bip322,
    /// BIP-322, full variant: the whole `to_sign` transaction.
    Bip322Full,
}

impl Format {
    const fn name(self) -> &'static str {
        match self {
            Format::Legacy => "legacy signature",
            Format::Bip322 => "BIP-322 simple",
            Format::Bip322Full => "BIP-322 full",
        }
    }
}

/// The formats an address type can be signed in, the usual one first.
///
/// Legacy has no header range for taproot (BIP-137 stops at P2WPKH); the simple variant
/// has nowhere to put the `scriptSig` a nested address needs, so nested segwit gets the
/// full one; P2PKH has the legacy format, which every verifier reads, and nothing to gain
/// from a transaction around it.
fn formats_for(kind: AddressKind) -> &'static [Format] {
    match kind {
        AddressKind::P2wpkh => &[Format::Legacy, Format::Bip322, Format::Bip322Full],
        AddressKind::P2shP2wpkh => &[Format::Legacy, Format::Bip322Full],
        AddressKind::P2pkh => &[Format::Legacy],
        AddressKind::P2tr => &[Format::Bip322, Format::Bip322Full],
    }
}

/// Which key signs, and how: an address type, the path to it, and the format.
#[derive(Clone)]
struct Choice {
    kind: AddressKind,
    path: DerivationPath,
    format: Format,
}

/// Who signs: one of this wallet's own keys, or this device's share of a registered
/// multisig wallet.
#[derive(Clone)]
enum Who {
    Key(Choice),
    /// The wallet at this index of `msimport::registered`, at `branch`/`index`. The
    /// index rather than the record: the registry's slice is re-read when it is needed,
    /// as its contract asks, and a fifteen-cosigner record is not something to carry.
    #[cfg(not(feature = "board-mk3"))]
    Cosigner {
        at: usize,
        branch: u32,
        index: u32,
    },
}

/// What signing produced: the armoured signature, and the address it speaks for.
pub(crate) struct Signed {
    pub(crate) armoured: heapless::String<SIG_TEXT>,
    pub(crate) address: heapless::String<{ address::MAX_ADDRESS_LEN }>,
}

/// Where a finished signature goes.
pub(crate) enum Target<'a> {
    /// Beside the file it came from, as `<name>-signed.txt`, on the medium it was read
    /// from.
    Beside {
        storage: menu::Storage,
        path: &'a str,
    },
    /// Wherever the owner says: a file called `SIGNED.TXT` on the card or the disk, or --
    /// on the Q1 -- animated BBQr on the glass.
    Fresh,
}

/// Type a message, sign it, and write it to the card.
pub(crate) fn screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    const HEAD: &str = "Sign message";

    let Some(typed) = read_message(ui, HEAD) else {
        return;
    };
    let text = typed.as_str();
    if text.is_empty() {
        return;
    }
    let Some(choice) = ask_choice(gate, login, ui, HEAD, None, None) else {
        return;
    };
    sign_and_deliver(gate, login, ui, HEAD, text, &choice, Target::Fresh);
}

/// Sign the request in a text file on the card or the disk, and write the signature
/// beside it.
///
/// The file is read as a request ([`message::parse_request`]): its first line is the
/// message, and what the second and third lines ask for is shown before the key is used.
/// What is shown is the whole of what will be signed -- a file is not a thing anyone reads
/// carefully before handing it to a wallet, and the screen is the only place the two can
/// be compared.
pub(crate) fn text_file(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    const HEAD: &str = "Sign text file";

    // Pick the medium first, then browse and read it there; the signature is written beside
    // the source on the same medium. On the mk3 this is the card with no prompt.
    let Some(storage) = menu::pick_storage(ui, HEAD) else {
        return;
    };
    let Some(path) =
        menu::browse_storage(ui, storage, "Pick a .txt", Some("txt"), menu::Browse::File)
    else {
        return;
    };
    let mut raw = [0u8; MAX_FILE];
    menu::card_wait(ui.panel, HEAD, "reading the file");
    let len = match crate::signtx::read_source_file(storage, &path, &mut raw) {
        Ok(n) => n,
        Err(why) => return complain(ui, HEAD, why),
    };
    let Ok(text) = core::str::from_utf8(&raw[..len]) else {
        return complain(ui, HEAD, "not text");
    };
    let request = match message::parse_request(text) {
        Ok(r) => r,
        Err(why) => return complain(ui, HEAD, describe_request(why)),
    };
    let Some(choice) = ask_choice(gate, login, ui, HEAD, request.kind, request.path) else {
        return;
    };
    sign_and_deliver(
        gate,
        login,
        ui,
        HEAD,
        request.message,
        &choice,
        Target::Beside {
            storage,
            path: &path,
        },
    );
}

/// Sign a request that arrived as text -- a scanned code, or a tag's payload.
///
/// The same three-line form a file carries, read with the same parser; the signature is
/// offered as a file or, on the Q1, as BBQr, because the request came without a card and
/// may want to leave the same way.
///
/// Reached from the Q1's scanner today (`crate::qrscan`, `sniff::Act::Sign`); the NFC
/// receive screen is the other path that gets text without asking for it and is the
/// intended second caller, so the boards without a scanner carry this unused for now.
#[cfg_attr(not(feature = "board-q1"), allow(dead_code))]
pub(crate) fn sign_request_text(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    text: &str,
) {
    const HEAD: &str = "Sign request";

    let request = match message::parse_request(text) {
        Ok(r) => r,
        Err(why) => return complain(ui, HEAD, describe_request(why)),
    };
    let Some(choice) = ask_choice(gate, login, ui, HEAD, request.kind, request.path) else {
        return;
    };
    sign_and_deliver(
        gate,
        login,
        ui,
        HEAD,
        request.message,
        &choice,
        Target::Fresh,
    );
}

/// Why a request could not be read, in the words a screen has.
fn describe_request(e: message::RequestError) -> &'static str {
    match e {
        message::RequestError::Empty => "nothing to sign in that",
        message::RequestError::Message(m) => describe(m),
        message::RequestError::BadPath(_) => "line 2 is not a path",
        message::RequestError::BadFormat => "line 3: unknown format",
        message::RequestError::TooManyLines => "more than three lines",
    }
}

/// Settle who signs and how, asking for whatever the request left open. Asked before the
/// PIN rather than after, so a change of mind costs nothing.
///
/// The address type first, then the format from those the type allows -- asked only
/// when there is more than one -- then the path. A request that names a type has
/// settled the first question; one that names a path, the last. On a board with a
/// settings store, a registered multisig wallet is offered beside the four single-key
/// types, and signs as a cosigner.
fn ask_choice(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    head: &str,
    kind: Option<AddressKind>,
    path: Option<DerivationPath>,
) -> Option<Who> {
    let kind = match kind {
        Some(k) => k,
        None => match ask_kind(gate, login, ui, head)? {
            Picked::Kind(k) => k,
            #[cfg(not(feature = "board-mk3"))]
            Picked::Wallet(at) => return ask_cosigner(ui, head, at),
        },
    };
    let format = ask_format(ui, head, kind)?;
    let path = match path {
        Some(p) => p,
        None => ask_path(ui, head, kind)?,
    };
    Some(Who::Key(Choice { kind, path, format }))
}

/// Which format to write, from those the address type allows.
///
/// One allowed format is not a question. Otherwise a list, with each format named as it
/// will be named on the confirmation screen: the difference between the three is what
/// the other side can read, and the owner is the one who knows what that is.
fn ask_format(ui: &mut Ui<'_>, head: &str, kind: AddressKind) -> Option<Format> {
    let formats = formats_for(kind);
    if let [only] = formats {
        return Some(*only);
    }
    let mut names: heapless::Vec<&str, 3> = heapless::Vec::new();
    for f in formats {
        let _ = names.push(f.name());
    }
    let at = menu::choose(ui, head, "signature format", &names)?;
    formats.get(at).copied()
}

/// What the address-type question was answered with.
enum Picked {
    Kind(AddressKind),
    /// A registered multisig wallet, by its index in the registry.
    #[cfg(not(feature = "board-mk3"))]
    Wallet(usize),
}

/// The four single-signature types, native segwit first because it is the one nearly
/// everyone wants.
const KINDS: [AddressKind; 4] = [
    AddressKind::P2wpkh,
    AddressKind::P2shP2wpkh,
    AddressKind::P2pkh,
    AddressKind::P2tr,
];

/// Pick the address type, or a registered multisig wallet.
#[cfg_attr(feature = "board-mk3", allow(unused_variables))]
fn ask_kind(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    head: &str,
) -> Option<Picked> {
    const MOST: usize = 4 + catcard_settings::wallets::MAX_WALLETS;
    let mut names: heapless::Vec<heapless::String<24>, MOST> = heapless::Vec::new();
    for k in KINDS {
        let mut name = heapless::String::new();
        let _ = name.push_str(kind_label(k));
        let _ = names.push(name);
    }
    // The registered wallets, past the four types, each named by its threshold and
    // script form: a `sh(multi)` wallet is listed too, and refused by name if picked,
    // rather than silently missing from a list the owner is comparing with the importer's.
    #[cfg(not(feature = "board-mk3"))]
    for w in crate::msimport::registered(gate, login, ui.panel) {
        let mut name = heapless::String::new();
        let form = match w.kind {
            catcard_wallet::multisig::Kind::P2wsh => "wsh",
            catcard_wallet::multisig::Kind::P2shP2wsh => "sh-wsh",
            catcard_wallet::multisig::Kind::P2sh => "sh",
        };
        let _ = write!(name, "{}-of-{} {}", w.m, w.n(), form);
        let _ = names.push(name);
    }
    let mut rows: heapless::Vec<&str, MOST> = heapless::Vec::new();
    for n in &names {
        let _ = rows.push(n.as_str());
    }
    let at = menu::choose(ui, head, "address type", &rows)?;
    match KINDS.get(at) {
        Some(k) => Some(Picked::Kind(*k)),
        #[cfg(not(feature = "board-mk3"))]
        None => Some(Picked::Wallet(at - KINDS.len())),
        #[cfg(feature = "board-mk3")]
        None => None,
    }
}

/// Which address of a registered wallet to sign for: the branch and the index.
#[cfg(not(feature = "board-mk3"))]
fn ask_cosigner(ui: &mut Ui<'_>, head: &str, at: usize) -> Option<Who> {
    let branch = menu::choose(
        ui,
        head,
        "which branch",
        &["Receive address", "Change address"],
    )? as u32;
    let index = menu::ask_index(ui, head, "address index")?;
    Some(Who::Cosigner { at, branch, index })
}

/// What to call an address type on screen.
pub(crate) const fn kind_label(kind: AddressKind) -> &'static str {
    match kind {
        AddressKind::P2wpkh => "Native segwit",
        AddressKind::P2shP2wpkh => "Nested segwit",
        AddressKind::P2pkh => "Legacy",
        AddressKind::P2tr => "Taproot",
    }
}

/// The first receive address of `kind`'s account on the network in force:
/// `m/{purpose}h/{coin}h/0h/0/0`. The coin type follows the network, as it does for the
/// address explorer and the exports -- not a hardcoded 0.
fn default_path(kind: AddressKind) -> Option<DerivationPath> {
    let coin = crate::prefs::network().coin_type();
    DerivationPath::from_slice(&[
        ChildNumber::hardened(kind.bip44_purpose()).ok()?,
        ChildNumber::hardened(coin).ok()?,
        ChildNumber::hardened(0).ok()?,
        ChildNumber::normal(0).ok()?,
        ChildNumber::normal(0).ok()?,
    ])
    .ok()
}

/// The default path for `kind`, or one the owner builds.
fn ask_path(ui: &mut Ui<'_>, head: &str, kind: AddressKind) -> Option<DerivationPath> {
    let default = default_path(kind)?;
    let mut shown: heapless::String<PATH_CHARS> = heapless::String::new();
    let _ = write!(shown, "{default}");
    match menu::choose(ui, head, shown.as_str(), &["Use that path", "Custom path"])? {
        0 => Some(default),
        _ => menu::ask_path(ui, head),
    }
}

/// Unlock, derive, confirm, sign, show, deliver: the whole of the flow past the choice.
fn sign_and_deliver(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    head: &str,
    text: &str,
    choice: &Who,
    target: Target<'_>,
) {
    let Some(signed) = sign_with(gate, login, ui, head, text, choice) else {
        return;
    };
    // Show it, then say where it goes: the signature is long, so the screen is for
    // checking the message and address, and the file (or the code) is what gets used.
    show(ui, text, &signed);
    deliver(ui, head, text, &signed, target);
}

/// Sign `text` -- a bare message, or the three-line request form -- and hand back the
/// armoured file instead of writing it anywhere, for a caller with its own way out: the
/// NFC tag today, which puts the file back where the message came from.
#[cfg_attr(feature = "board-mk3", allow(dead_code))]
pub(crate) fn sign_to_file(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    head: &str,
    text: &str,
) -> Option<heapless::String<FILE_TEXT>> {
    let request = match message::parse_request(text) {
        Ok(r) => r,
        Err(why) => {
            complain(ui, head, describe_request(why));
            return None;
        }
    };
    let choice = ask_choice(gate, login, ui, head, request.kind, request.path)?;
    let signed = sign_with(gate, login, ui, head, request.message, &choice)?;
    show(ui, request.message, &signed);
    let mut file: heapless::String<FILE_TEXT> = heapless::String::new();
    if signfile::write(
        &mut file,
        request.message,
        &signed.address,
        &signed.armoured,
    )
    .is_err()
    {
        complain(ui, head, "no room for it");
        return None;
    }
    Some(file)
}

/// Why `text` cannot be shown as a message to sign, before any key is touched: empty,
/// too long, or holding a character the screen cannot show faithfully -- the owner would
/// be signing something other than what they read.
#[cfg_attr(feature = "board-mk3", allow(dead_code))]
pub(crate) fn unshowable(text: &str) -> Option<&'static str> {
    if text.is_empty() {
        return Some("nothing to sign in that");
    }
    if text.len() > message::MAX_MESSAGE {
        return Some("message too long");
    }
    if !text.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        return Some("plain ASCII only");
    }
    None
}

/// Unlock, derive, confirm, sign: the flow past the choice, up to the signature.
///
/// `None` when the owner backed out or something refused; every refusal has already been
/// said on screen.
fn sign_with(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    head: &str,
    text: &str,
    who: &Who,
) -> Option<Signed> {
    match who {
        Who::Key(choice) => sign_with_key(gate, login, ui, head, text, choice),
        #[cfg(not(feature = "board-mk3"))]
        Who::Cosigner { at, branch, index } => {
            sign_as_cosigner(gate, login, ui, head, text, *at, *branch, *index)
        }
    }
}

/// [`sign_with`] for one of this wallet's own keys.
fn sign_with_key(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    head: &str,
    text: &str,
    choice: &Choice,
) -> Option<Signed> {
    let master = menu::unlock_master(gate, login, ui, head)?;

    // Only the leaf is kept past this point: the master is the whole wallet, and the
    // screens that follow can stand there for as long as nobody is in the room.
    let mut busy = menu::Working::new(ui.panel, head, "deriving");
    let leaf = crate::keywork::run(|kw| derive(&master, &choice.path, kw));
    drop(master);
    busy.tick(ui.panel);
    let leaf = match leaf {
        Ok(k) => k,
        Err(why) => {
            complain(ui, head, why);
            return None;
        }
    };
    let network = crate::prefs::network();

    // The address before the signature: what the owner is asked to approve is this text
    // signed by *that* address, and it is the last moment either can still be refused.
    let pubkey = crate::keywork::run(|kw| leaf.public_key(kw));
    let address = match address_of(&pubkey, choice.kind, network) {
        Ok(a) => a,
        Err(why) => {
            drop(leaf);
            complain(ui, head, why);
            return None;
        }
    };
    let mut path: heapless::String<PATH_CHARS> = heapless::String::new();
    let _ = write!(path, "{}", choice.path);
    let mut how: heapless::String<48> = heapless::String::new();
    let _ = write!(how, "{}, {}", kind_label(choice.kind), choice.format.name());
    if !confirm(ui, head, text, &address, &path, &how) {
        drop(leaf);
        return None;
    }

    let mut busy = menu::Working::new(ui.panel, head, "signing");
    let signed = crate::keywork::run(|kw| {
        let mut secret = *leaf.secret_bytes();
        sign_secret(
            &mut secret,
            &pubkey,
            network,
            text,
            choice.kind,
            choice.format,
            kw,
        )
    });
    drop(leaf);
    busy.tick(ui.panel);
    match signed {
        Ok(v) => Some(v),
        Err(why) => {
            complain(ui, head, why);
            None
        }
    }
}

/// [`sign_with`] as this device's share of a registered multisig wallet.
///
/// The address is rebuilt from the wallet's record and shown before the seed is touched.
/// The signature is a partial one in the full format; the self-check that follows
/// expects exactly that -- every signature in it good, and `M - 1` short -- unless the
/// wallet is 1-of-N, in which case it has to verify outright.
#[cfg(not(feature = "board-mk3"))]
#[allow(clippy::too_many_arguments)]
fn sign_as_cosigner(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    head: &str,
    text: &str,
    at: usize,
    branch: u32,
    index: u32,
) -> Option<Signed> {
    use catcard_wallet::multisig::Kind;

    let wallets = crate::msimport::registered(gate, login, ui.panel);
    let Some(wallet) = wallets.get(at) else {
        complain(ui, head, "wallet no longer registered");
        return None;
    };
    if wallet.kind == Kind::P2sh {
        // A bare `sh(multi)` message needs the legacy signature hash, which nothing in
        // this device computes.
        complain(ui, head, "not for sh(multi) wallets");
        return None;
    }
    let network = crate::prefs::network();
    let mut spk = [0u8; bip322::MAX_SCRIPT];
    let mut buf = [0u8; address::MAX_ADDRESS_LEN];
    let shown = wallet
        .script_pubkey(branch, index, &mut spk)
        .ok()
        .and_then(|n| address::from_script(&spk[..n], network, &mut buf));
    let Some(n) = shown else {
        complain(ui, head, "address failed");
        return None;
    };
    let mut address: heapless::String<{ address::MAX_ADDRESS_LEN }> = heapless::String::new();
    let _ = address.push_str(core::str::from_utf8(&buf[..n]).unwrap_or(""));
    let mut path: heapless::String<PATH_CHARS> = heapless::String::new();
    let _ = write!(path, ".../{branch}/{index}");
    let mut how: heapless::String<48> = heapless::String::new();
    let _ = write!(
        how,
        "{}-of-{} multisig, {}",
        wallet.m,
        wallet.n(),
        Format::Bip322Full.name()
    );
    if !confirm(ui, head, text, &address, &path, &how) {
        return None;
    }

    let master = menu::unlock_master(gate, login, ui, head)?;
    let mut busy = menu::Working::new(ui.panel, head, "signing");
    let mut challenge = [0u8; bip322::MAX_SCRIPT];
    let signed = crate::keywork::run(|kw| {
        full::sign_cosigner(
            text.as_bytes(),
            wallet,
            branch,
            index,
            &master,
            &mut challenge,
            kw,
        )
    });
    drop(master);
    busy.tick(ui.panel);
    let (sig, cn) = match signed {
        Ok(v) => v,
        Err(e) => {
            complain(ui, head, describe322(e));
            return None;
        }
    };
    // Our own work, through the verifier a counterparty would use: a partial signature
    // is short of the threshold and nothing else is wrong with it.
    let check = full::verify_full(text.as_bytes(), &challenge[..cn], sig.as_bytes());
    let expected = if wallet.m == 1 {
        Ok(())
    } else {
        Err(bip322::Error::NeedsCosigners {
            have: 1,
            need: wallet.m,
        })
    };
    if check != expected {
        complain(ui, head, "signature did not verify");
        return None;
    }
    let mut out = [0u8; SIG_TEXT];
    let Ok(written) = sig.armour(&mut out) else {
        complain(ui, head, "no room for it");
        return None;
    };
    let mut armoured: heapless::String<SIG_TEXT> = heapless::String::new();
    let _ = armoured.push_str(core::str::from_utf8(&out[..written]).unwrap_or(""));
    crate::catlog!(
        "message: cosigner share for {}, {} more needed",
        address,
        wallet.m.saturating_sub(1)
    );
    Some(Signed { armoured, address })
}

/// Write the armoured file where `target` says, or show it as a code.
pub(crate) fn deliver(
    ui: &mut Ui<'_>,
    head: &str,
    text: &str,
    signed: &Signed,
    target: Target<'_>,
) {
    let mut file: heapless::String<FILE_TEXT> = heapless::String::new();
    if signfile::write(&mut file, text, &signed.address, &signed.armoured).is_err() {
        return complain(ui, head, "no room for it");
    }
    match target {
        Target::Beside { storage, path } => {
            let Some(out) = beside(path) else {
                return complain(ui, head, "path too long");
            };
            write_signed(ui, head, storage, &out, file.as_bytes(), &signed.address);
        }
        Target::Fresh => fresh(ui, head, file.as_bytes(), &signed.address),
    }
}

/// The owner's choice of where a fresh signature lands.
///
/// On the Q1 a list: the card, the disk, or BBQr on the glass -- the last because a
/// request that arrived by camera may want to leave the same way. A PSRAM board without a
/// scanner offers the card or the disk; the mk3 has only the card, so it asks yes or no.
#[cfg(feature = "board-q1")]
fn fresh(ui: &mut Ui<'_>, head: &str, file: &[u8], address: &str) {
    const WAYS: &[&str] = &["SD card", "Virtual Disk", "BBQr"];
    match menu::choose(ui, head, "where to put it", WAYS) {
        Some(0) => write_signed(ui, head, menu::Storage::Sd, FILE_NAME, file, address),
        Some(1) => write_signed(ui, head, menu::Storage::Vdisk, FILE_NAME, file, address),
        Some(2) => {
            crate::catlog!("message: signed with {}, shown as BBQr", address);
            crate::qrshow::animate_bbqr(ui, head, file, catcard_bbqr::FileType::UNICODE);
        }
        _ => {}
    }
}

#[cfg(all(not(feature = "board-q1"), not(feature = "board-mk3")))]
fn fresh(ui: &mut Ui<'_>, head: &str, file: &[u8], address: &str) {
    let Some(storage) = menu::pick_storage(ui, head) else {
        return;
    };
    write_signed(ui, head, storage, FILE_NAME, file, address);
}

#[cfg(feature = "board-mk3")]
fn fresh(ui: &mut Ui<'_>, head: &str, file: &[u8], address: &str) {
    menu::ask(ui.panel, head, "write it to the", "SD card?");
    if !menu::confirmed(ui) {
        return;
    }
    write_signed(ui, head, menu::Storage::Sd, FILE_NAME, file, address);
}

/// Write the armoured file and say so.
fn write_signed(
    ui: &mut Ui<'_>,
    head: &str,
    storage: menu::Storage,
    path: &str,
    file: &[u8],
    address: &str,
) {
    let mut note: heapless::String<32> = heapless::String::new();
    let _ = write!(note, "writing to {}", storage.medium());
    menu::card_wait(ui.panel, head, note.as_str());
    match menu::write_storage_file(storage, path, file) {
        Ok(()) => {
            crate::catlog!("message: {} signed with {}", path, address);
            let name = path.strip_prefix('/').unwrap_or(path);
            menu::message(ui.panel, "Signed", name, "any key to go back");
        }
        Err(why) => {
            crate::catlog!("message: write failed: {}", why);
            menu::message(ui.panel, "Write failed", why, "any key to go back");
        }
    }
    menu::wait_for_any_key(ui);
}

/// The name the signature is written under: the source file's, with its extension
/// replaced. `FOO.TXT` becomes `FOO-signed.txt`, in the same directory.
fn beside(path: &str) -> Option<heapless::String<PATH_MAX>> {
    // Only an extension in the last path element counts; a dot in a directory name is
    // part of that name.
    let cut = match path.rfind('.') {
        Some(dot) if !path[dot..].contains('/') => dot,
        _ => path.len(),
    };
    let mut out: heapless::String<PATH_MAX> = heapless::String::new();
    out.push_str(&path[..cut]).ok()?;
    out.push_str(SIGNED_SUFFIX).ok()?;
    Some(out)
}

/// The address a public key is written as.
fn address_of(
    pubkey: &[u8; 33],
    kind: AddressKind,
    network: Network,
) -> Result<heapless::String<{ address::MAX_ADDRESS_LEN }>, &'static str> {
    let mut buf = [0u8; address::MAX_ADDRESS_LEN];
    let n = address::encode(kind, network, pubkey, &mut buf).map_err(|_| "address failed")?;
    let mut addr: heapless::String<{ address::MAX_ADDRESS_LEN }> = heapless::String::new();
    addr.push_str(core::str::from_utf8(&buf[..n]).unwrap_or(""))
        .map_err(|_| "address failed")?;
    Ok(addr)
}

/// Walk `path` from the master key.
fn derive(
    master: &ExtendedPrivKey,
    path: &DerivationPath,
    kw: &catcard_wallet::KeyWork,
) -> Result<ExtendedPrivKey, &'static str> {
    let mut here = master.clone();
    for step in path.iter() {
        here = here
            .derive_child(step, kw)
            .map_err(|_| "key derivation failed")?;
    }
    Ok(here)
}

/// Sign `text` with a private key, and check the signature against the key that made it.
///
/// Private-key work: it takes the [`catcard_wallet::KeyWork`] of the masked region it
/// runs in, and it zeroizes `secret` before it returns, whichever way it returns. The
/// wallet path and the WIF store both come through here, so a stored key signs exactly as
/// a derived one does.
pub(crate) fn sign_secret(
    secret: &mut [u8; 32],
    pubkey: &[u8; 33],
    network: Network,
    text: &str,
    kind: AddressKind,
    format: Format,
    kw: &catcard_wallet::KeyWork,
) -> Result<Signed, &'static str> {
    let mut armoured: heapless::String<SIG_TEXT> = heapless::String::new();
    let mut buf = [0u8; SIG_TEXT];
    let written = match format {
        Format::Legacy => {
            let sig = message::sign(text, secret, kind, kw);
            secret.zeroize();
            let sig = sig.map_err(describe)?;
            // Check our own work: recover the key from the signature and compare it
            // with the one that signed. A signature that does not recover is worse
            // than none.
            match message::recover(text, &sig) {
                Ok((recovered, _)) if recovered == *pubkey => {}
                _ => return Err("signature did not verify"),
            }
            message::armour(&sig, &mut buf).map_err(describe)?
        }
        Format::Bip322 => {
            let sig = bip322::sign(text.as_bytes(), secret, kind, kw);
            secret.zeroize();
            let sig = sig.map_err(describe322)?;
            // The same self-check, through the same verifier a counterparty would
            // use: the signature has to satisfy the script this address stands for.
            let mut script = [0u8; bip322::MAX_SCRIPT];
            let n = bip322::challenge(kind, pubkey, &mut script).map_err(describe322)?;
            bip322::verify(text.as_bytes(), &script[..n], sig.as_bytes())
                .map_err(|_| "signature did not verify")?;
            sig.armour(&mut buf).map_err(describe322)?
        }
        Format::Bip322Full => {
            let sig = full::sign_full(text.as_bytes(), secret, kind, kw);
            secret.zeroize();
            let sig = sig.map_err(describe322)?;
            // The same self-check, over the whole transaction this time.
            let mut script = [0u8; bip322::MAX_SCRIPT];
            let n = full::challenge(kind, pubkey, &mut script).map_err(describe322)?;
            full::verify_full(text.as_bytes(), &script[..n], sig.as_bytes())
                .map_err(|_| "signature did not verify")?;
            sig.armour(&mut buf).map_err(describe322)?
        }
    };
    armoured
        .push_str(core::str::from_utf8(&buf[..written]).unwrap_or(""))
        .map_err(|_| "no room for it")?;
    let address = address_of(pubkey, kind, network)?;
    Ok(Signed { armoured, address })
}

/// Why a message could not be signed, in the words a screen has.
fn describe(e: message::Error) -> &'static str {
    match e {
        message::Error::TooLong { .. } => "message too long",
        message::Error::NotPrintable => "plain ASCII only",
        message::Error::UnsupportedKind => "not for this address type",
        message::Error::BadKey => "key unusable",
        message::Error::BufferTooSmall => "no room for it",
    }
}

/// The same, for the BIP-322 side.
fn describe322(e: bip322::Error) -> &'static str {
    match e {
        bip322::Error::UnsupportedKind | bip322::Error::UnsupportedScript => {
            "not for this address type"
        }
        bip322::Error::BadKey => "key unusable",
        bip322::Error::NeedsCosigners { .. } => "needs more cosigners",
        bip322::Error::Malformed
        | bip322::Error::Invalid
        | bip322::Error::Inconclusive
        | bip322::Error::NotAProof
        | bip322::Error::TooManyInputs
        | bip322::Error::MissingUtxo => "signature did not verify",
        bip322::Error::BufferTooSmall => "no room for it",
    }
}

fn complain(ui: &mut Ui<'_>, head: &str, why: &str) {
    crate::catlog!("message: {}", why);
    menu::message(ui.panel, head, why, "any key to go back");
    menu::wait_for_any_key(ui);
}

/// The message, the address that will sign it, the path to it and how -- the address
/// type and the format, by name. True if the owner said go ahead.
fn confirm(ui: &mut Ui<'_>, head: &str, text: &str, address: &str, path: &str, how: &str) -> bool {
    use catcard_ui::scroll::{Line, ScrollView};
    let mut doc: heapless::Vec<Line, 8> = heapless::Vec::new();
    let _ = doc.push(Line::title(head));
    let _ = doc.push(Line::body(text).wrapped());
    let _ = doc.push(Line::body("will be signed by").small());
    let _ = doc.push(Line::body(address).small().wrapped());
    let _ = doc.push(Line::body(path).small().wrapped());
    let _ = doc.push(Line::body(how).small().wrapped());
    let mut view = ScrollView::build(&doc, display::SCREEN_W, display::SCREEN_H, display::FONTS);
    menu::scroll_choice(ui, &mut view)
}

/// The message, the address that signed, and the signature, scrollable.
pub(crate) fn show(ui: &mut Ui<'_>, text: &str, signed: &Signed) {
    use catcard_ui::scroll::{Line, ScrollView};
    let mut doc: heapless::Vec<Line, 8> = heapless::Vec::new();
    let _ = doc.push(Line::title("Signed"));
    let _ = doc.push(Line::body(text).wrapped());
    let _ = doc.push(Line::body("signed with").small());
    let _ = doc.push(Line::body(&signed.address).small().wrapped());
    let _ = doc.push(Line::body(&signed.armoured).small().wrapped());
    let mut view = ScrollView::build(&doc, display::SCREEN_W, display::SCREEN_H, display::FONTS);
    let _ = menu::scroll_choice(ui, &mut view);
}

/// Type the message. `None` if the owner backed out.
pub(crate) fn read_message(ui: &mut Ui<'_>, head: &str) -> Option<Entry> {
    let mut entry = Entry::new();
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();

    loop {
        draw(ui, head, &entry);
        menu::wait_for_release(ui);
        let mut redraw = false;
        while !redraw {
            let _ = crate::usbtask::pump();
            crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
            for k in keys.iter() {
                match k {
                    Key::Confirm => {
                        entry.commit();
                        return Some(entry);
                    }
                    Key::Cancel => {
                        if !entry.backspace() {
                            return None;
                        }
                        redraw = true;
                    }
                    Key::Qr => {}
                    Key::Char(c) => {
                        entry.put(*c as char);
                        redraw = true;
                    }
                    Key::Digit(d) => {
                        #[cfg(feature = "board-q1")]
                        entry.put((b'0' + *d) as char);
                        #[cfg(not(feature = "board-q1"))]
                        entry.press(*d);
                        redraw = true;
                    }
                }
            }
            if !redraw {
                display::idle(ui.panel);
            }
        }
    }
}

fn draw(ui: &mut Ui<'_>, head: &str, entry: &Entry) {
    use catcard_ui::scroll::{Line, ScrollView, render};
    let mut hint = heapless::String::<48>::new();
    let _ = write!(
        hint,
        "{} sign   {} back",
        display::CONFIRM_KEY,
        display::CANCEL_KEY
    );
    let mut doc: heapless::Vec<Line, 8> = heapless::Vec::new();
    let _ = doc.push(Line::title(head));
    let _ = doc.push(Line::body(entry.as_str()).wrapped());
    #[cfg(not(feature = "board-q1"))]
    {
        let _ = doc.push(Line::body("2abc 3def 4ghi 5jkl").small());
        let _ = doc.push(Line::body("6mno 7pqrs 8tuv 9wxyz").small());
        let _ = doc.push(Line::body("0 space  1 symbols").small());
    }
    let _ = doc.push(Line::body(hint.as_str()).small());
    let view = ScrollView::build(&doc, display::SCREEN_W, display::SCREEN_H, display::FONTS);
    display::draw(ui.panel, |c| render(c, &view));
}
