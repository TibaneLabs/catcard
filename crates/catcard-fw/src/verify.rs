//! Does this address belong to this device?
//!
//! The question a wallet cannot answer for you honestly: a watch-only wallet on a computer
//! shows an address and says it is yours, and the computer is the thing you do not trust.
//! So the address is typed in here -- or, on a board with a scanner, read off a code --
//! and the device walks its own derivations looking for it. A match comes back with the
//! path that produced it; no match comes back as no match, never as a shrug.
//!
//! # What is searched
//!
//! Everything this device could be paid at, as stock does. [C] hw-reference/
//! firmware-features.md §3 "Verify Address / Ownership: across single-sig accounts,
//! registered multisig wallets, and the WIF store".
//!
//! - **The WIF store** first: at most thirty keys and four encodings of each, no
//!   derivation at all, so a hit there costs nothing and saves the walk below.
//! - **Single-signature accounts**: every address type, [`ACCOUNT_LIMIT`] accounts,
//!   receive and change, [`INDEX_LIMIT`] addresses each -- one elliptic curve
//!   multiplication per address, from the seed.
//! - **Registered multisig wallets**: receive and change, [`INDEX_LIMIT`] addresses each,
//!   built from the cosigners' keys in the wallet record. No seed is touched, but every
//!   address costs one derivation per cosigner.
//!
//! The address's own shape narrows the search first ([`Shape`]): a `bc1q` address of
//! forty-two characters can only have come from a P2WPKH key, so the P2PKH accounts and
//! the P2WSH wallets are not walked for it. That is what keeps "search everything" from
//! being a ten-minute wait, and it can only skip what could never match -- an address
//! whose shape this does not recognise is searched everywhere.
//!
//! The search is bounded and says what it covered. An address further out than
//! [`INDEX_LIMIT`], or in an account past [`ACCOUNT_LIMIT`], is not found -- and the screen
//! says how far it looked, because "not mine" and "not looked at" are different answers.

use catcard_callgate::Callgate;
use catcard_ui::keypad::{Event, KEYS, Key};
use catcard_ui::textentry::Entry;
use catcard_wallet::address::{self, AddressKind, NetworkParams as _};
use catcard_wallet::bip32::{ChildNumber, ExtendedPubKey, Network};
use core::fmt::Write as _;

use crate::display;
use crate::menu;
use crate::ui::Ui;

const HEAD: &str = "Verify address";

/// Addresses searched per chain, from zero.
///
/// A hundred each way is a wide gap by any wallet's standards; the cost is one elliptic
/// curve multiplication per address, and the screen shows it progressing.
pub const INDEX_LIMIT: u32 = 100;

/// Accounts searched, from zero.
pub const ACCOUNT_LIMIT: u32 = 3;

/// Address types searched, in the order most wallets use them.
const KINDS: [AddressKind; 4] = [
    AddressKind::P2wpkh,
    AddressKind::P2shP2wpkh,
    AddressKind::P2pkh,
    AddressKind::P2tr,
];

/// The bar is nudged this often while walking one chain, so a multisig wallet's slower
/// addresses do not hold a frame for seconds.
const TICK_EVERY: u32 = 10;

/// What the address looks like, and so which scripts could have produced it.
///
/// Read off the string, not decoded: the first character of a Base58Check address is
/// fixed by its version byte, and a bech32 address names its witness version and program
/// length outright. Nothing here decides an address *is* something -- a shape only rules
/// out the searches that could never match it, and [`Shape::Unknown`] rules out none.
///
/// Sources: version bytes 0x00/0x05 on mainnet and 0x6f/0xc4 on testnet and regtest, as
/// `address::encode` writes them, give leading `1`/`3` and `m`,`n`/`2` in base58
/// [C] hw-reference/wallet-export-formats.md §"Chain parameters". A bech32 segwit
/// address is the HRP, `1`, one version character, then the program in 5-bit groups
/// (32 characters for 20 bytes, 52 for 32) and a 6-character checksum. [C] BIP-173
/// §"Segwit address format", BIP-350.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum Shape {
    /// Witness v0, 20-byte program: P2WPKH.
    Wpkh,
    /// Witness v0, 32-byte program: P2WSH -- a multisig wallet's, never a single key's.
    Wsh,
    /// Witness v1: P2TR.
    Tr,
    /// Base58 with the P2PKH version byte.
    Pkh,
    /// Base58 with the P2SH version byte: nested segwit, or a P2SH / P2SH-P2WSH wallet.
    Sh,
    /// None of the above -- or another network's. Everything is searched.
    Unknown,
}

impl Shape {
    /// The shape of `lower` (the address folded to lower case) on `network`.
    fn of(lower: &str, network: Network) -> Shape {
        let hrp = network.bech32_hrp();
        if let Some(rest) = lower.strip_prefix(hrp).and_then(|r| r.strip_prefix('1')) {
            // Version character, then data and checksum.
            let data = rest.len().saturating_sub(1);
            return match (rest.as_bytes().first(), data) {
                (Some(b'q'), 38) => Shape::Wpkh,
                (Some(b'q'), 58) => Shape::Wsh,
                (Some(b'p'), 58) => Shape::Tr,
                _ => Shape::Unknown,
            };
        }
        match (network.is_mainnet(), lower.as_bytes().first()) {
            (true, Some(b'1')) => Shape::Pkh,
            (true, Some(b'3')) => Shape::Sh,
            (false, Some(b'm' | b'n')) => Shape::Pkh,
            (false, Some(b'2')) => Shape::Sh,
            _ => Shape::Unknown,
        }
    }

    /// Whether a single-signature key of `kind` could have produced this shape.
    fn admits(self, kind: AddressKind) -> bool {
        match self {
            Shape::Wpkh => kind == AddressKind::P2wpkh,
            Shape::Sh => kind == AddressKind::P2shP2wpkh,
            Shape::Pkh => kind == AddressKind::P2pkh,
            Shape::Tr => kind == AddressKind::P2tr,
            Shape::Wsh => false,
            Shape::Unknown => true,
        }
    }

    /// Whether any single-signature search is worth the seed.
    fn admits_any_single(self) -> bool {
        KINDS.iter().any(|k| self.admits(*k))
    }

    /// Whether a multisig wallet of `kind` could have produced this shape.
    #[cfg(not(feature = "board-mk3"))]
    fn admits_multisig(self, kind: catcard_wallet::multisig::Kind) -> bool {
        use catcard_wallet::multisig::Kind;
        match self {
            Shape::Wsh => kind == Kind::P2wsh,
            Shape::Sh => matches!(kind, Kind::P2sh | Kind::P2shP2wsh),
            Shape::Unknown => true,
            Shape::Wpkh | Shape::Tr | Shape::Pkh => false,
        }
    }
}

/// Where an address was found.
enum Found {
    /// A single-signature account of this seed.
    Single {
        kind: AddressKind,
        account: u32,
        chain: u32,
        index: u32,
    },
    /// A registered multisig wallet, by its position in the list.
    #[cfg(not(feature = "board-mk3"))]
    Multisig {
        wallet: usize,
        m: u8,
        n: usize,
        kind: catcard_wallet::multisig::Kind,
        chain: u32,
        index: u32,
    },
    /// A key in the WIF store, by its position, paid at this address type.
    #[cfg(not(feature = "board-mk3"))]
    Wif { key: usize, kind: AddressKind },
}

/// Type an address and say whether this wallet can spend it.
pub(crate) fn screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    let Some(typed) = read_address(ui, HEAD) else {
        return;
    };
    let wanted = typed.as_str().trim();
    if wanted.is_empty() {
        return;
    }
    owned(gate, login, ui, wanted);
}

/// Search this wallet for `wanted`, say what was found, and wait for a key.
///
/// The screen's search, for an address that arrived some other way -- in a payment URI
/// off a code or a tag (`crate::payuri`). The answer on screen is the same one; the
/// return value is for a caller with something to add to it.
pub(crate) fn owned(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    wanted: &str,
) -> bool {
    let network = crate::prefs::network();
    // Bech32 is case-insensitive and usually written lower case; base58 is not, so the
    // comparison is done on what the device produces against what was typed, with only
    // bech32 folded.
    let mut lower: heapless::String<{ address::MAX_ADDRESS_LEN }> = heapless::String::new();
    for c in wanted.chars() {
        let _ = lower.push(c.to_ascii_lowercase());
    }
    let shape = Shape::of(lower.as_str(), network);
    crate::catlog!("verify: shape {:?}", shape);

    // The cheap store first, then the seed, then the wallets that cost a derivation per
    // cosigner. Each stage is skipped when the shape says it could not match.
    #[cfg(not(feature = "board-mk3"))]
    let mut found = search_wifs(gate, login, ui, shape, lower.as_str(), wanted);
    #[cfg(feature = "board-mk3")]
    let mut found: Option<Found> = None;

    if found.is_none() && shape.admits_any_single() {
        let Some(master) = menu::unlock_master(gate, login, ui, HEAD) else {
            return false;
        };
        let mut busy = menu::Working::new(ui.panel, HEAD, "searching accounts");
        found = search_single(&master, shape, lower.as_str(), wanted, &mut busy, ui.panel);
        drop(master);
    }

    #[cfg(not(feature = "board-mk3"))]
    if found.is_none() {
        found = search_multisig(gate, login, ui, shape, network, lower.as_str(), wanted);
    }

    let hit = found.is_some();
    report(ui, found, network);
    menu::wait_for_any_key(ui);
    hit
}

/// Say what was found, or how far the search went.
fn report(ui: &mut Ui<'_>, found: Option<Found>, network: Network) {
    let mut line = heapless::String::<48>::new();
    match found {
        Some(Found::Single {
            kind,
            account,
            chain,
            index,
        }) => {
            // The coin level is the one `menu::chain_key` derived under.
            let _ = write!(
                line,
                "m/{}h/{}h/{}h/{}/{}",
                kind.bip44_purpose(),
                network.coin_type(),
                account,
                chain,
                index
            );
            crate::catlog!("verify: found at {}", line.as_str());
            menu::message(ui.panel, "Yours", line.as_str(), chain_name(chain));
        }
        #[cfg(not(feature = "board-mk3"))]
        Some(Found::Multisig {
            wallet,
            m,
            n,
            kind,
            chain,
            index,
        }) => {
            let _ = write!(
                line,
                "wallet {}: {}-of-{} {}",
                wallet + 1,
                m,
                n,
                multisig_name(kind)
            );
            let mut at = heapless::String::<24>::new();
            let _ = write!(at, ".../{chain}/{index} {}", chain_name(chain));
            crate::catlog!("verify: found in {} at {}", line.as_str(), at.as_str());
            menu::message(ui.panel, "Yours", line.as_str(), at.as_str());
        }
        #[cfg(not(feature = "board-mk3"))]
        Some(Found::Wif { key, kind }) => {
            let _ = write!(line, "WIF store key {:02}", key + 1);
            crate::catlog!("verify: found as {} ({})", line.as_str(), kind_name(kind));
            menu::message(ui.panel, "Yours", line.as_str(), kind_name(kind));
        }
        None => {
            let _ = write!(line, "searched {} per chain", INDEX_LIMIT);
            crate::catlog!("verify: no match within the search");
            menu::message(ui.panel, "Not found", line.as_str(), "not this wallet's");
        }
    }
}

fn chain_name(chain: u32) -> &'static str {
    if chain == 1 { "change" } else { "receive" }
}

#[cfg(not(feature = "board-mk3"))]
fn kind_name(kind: AddressKind) -> &'static str {
    match kind {
        AddressKind::P2wpkh => "native segwit",
        AddressKind::P2shP2wpkh => "nested segwit",
        AddressKind::P2pkh => "legacy",
        AddressKind::P2tr => "taproot",
    }
}

#[cfg(not(feature = "board-mk3"))]
fn multisig_name(kind: catcard_wallet::multisig::Kind) -> &'static str {
    use catcard_wallet::multisig::Kind;
    match kind {
        Kind::P2sh => "P2SH",
        Kind::P2wsh => "P2WSH",
        Kind::P2shP2wsh => "P2SH-P2WSH",
    }
}

/// Whether `made` is the address that was asked for: folded for bech32, exact otherwise.
fn is_wanted(made: &str, bech32: bool, lower: &str, exact: &str) -> bool {
    if bech32 {
        made.eq_ignore_ascii_case(lower)
    } else {
        made == exact
    }
}

/// The single-signature accounts of `master`, in the order wallets use them.
fn search_single(
    master: &catcard_wallet::bip32::ExtendedPrivKey,
    shape: Shape,
    lower: &str,
    exact: &str,
    busy: &mut menu::Working<'_>,
    panel: &mut display::Panel,
) -> Option<Found> {
    for kind in KINDS {
        if !shape.admits(kind) {
            continue;
        }
        for account in 0..ACCOUNT_LIMIT {
            for chain in 0..2 {
                let Some(chain_key) = menu::chain_key(master, kind, account, chain, busy, panel)
                else {
                    continue;
                };
                if let Some(index) = walk(&chain_key, kind, lower, exact, busy, panel) {
                    return Some(Found::Single {
                        kind,
                        account,
                        chain,
                        index,
                    });
                }
                busy.tick(panel);
            }
        }
    }
    None
}

/// Walk one chain's addresses looking for `exact` (or its lower-case form for bech32).
fn walk(
    chain_key: &ExtendedPubKey,
    kind: AddressKind,
    lower: &str,
    exact: &str,
    busy: &mut menu::Working<'_>,
    panel: &mut display::Panel,
) -> Option<u32> {
    let mut buf = [0u8; address::MAX_ADDRESS_LEN];
    for index in 0..INDEX_LIMIT {
        if index % TICK_EVERY == TICK_EVERY - 1 {
            busy.tick(panel);
        }
        let Ok(child) = ChildNumber::normal(index).and_then(|c| chain_key.derive_child(c)) else {
            continue;
        };
        let Ok(n) = address::encode(kind, crate::prefs::network(), &child.public_key, &mut buf)
        else {
            continue;
        };
        let made = core::str::from_utf8(&buf[..n]).unwrap_or("");
        if is_wanted(made, kind.is_bech32(), lower, exact) {
            return Some(index);
        }
    }
    None
}

/// The registered multisig wallets: receive and change, [`INDEX_LIMIT`] addresses each.
///
/// No seed is involved -- the wallet record holds every cosigner's account key, and the
/// address is that script's -- so nothing here is masked. It is slow instead: each
/// address is two public derivations per cosigner, which is why the shape filter and
/// the bar both matter here.
#[cfg(not(feature = "board-mk3"))]
fn search_multisig(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    shape: Shape,
    network: Network,
    lower: &str,
    exact: &str,
) -> Option<Found> {
    use catcard_wallet::multisig::Kind;

    // Taken and used here, and nothing below reads the registered wallets again -- the
    // rule `msimport::registered` sets for its slice.
    let wallets = crate::msimport::registered(gate, login, ui.panel);
    if wallets.is_empty() || !wallets.iter().any(|w| shape.admits_multisig(w.kind)) {
        return None;
    }
    let mut busy = menu::Working::new(ui.panel, HEAD, "searching multisig");
    // The longest scriptPubKey a wallet writes is P2WSH's 34 bytes.
    let mut spk = [0u8; 34];
    let mut buf = [0u8; address::MAX_ADDRESS_LEN];
    for (w, wallet) in wallets.iter().enumerate() {
        if !shape.admits_multisig(wallet.kind) {
            continue;
        }
        for chain in 0..2 {
            for index in 0..INDEX_LIMIT {
                if index % TICK_EVERY == TICK_EVERY - 1 {
                    busy.tick(ui.panel);
                }
                let Ok(n) = wallet.script_pubkey(chain, index, &mut spk) else {
                    continue;
                };
                let Some(len) = address::from_script(&spk[..n], network, &mut buf) else {
                    continue;
                };
                let made = core::str::from_utf8(&buf[..len]).unwrap_or("");
                if is_wanted(made, wallet.kind == Kind::P2wsh, lower, exact) {
                    return Some(Found::Multisig {
                        wallet: w,
                        m: wallet.m,
                        n: wallet.n(),
                        kind: wallet.kind,
                        chain,
                        index,
                    });
                }
            }
            busy.tick(ui.panel);
        }
    }
    None
}

/// The WIF store: each key's four address forms.
///
/// The keys are decoded by `wifstore::load_keys` (masked, as the scalar is rebuilt) and
/// each public key is taken masked as well; the encodings are public. A key is compared
/// on its own network -- a testnet WIF is paid at a testnet address whatever the device
/// is set to, which is how the store's own detail screen shows it.
#[cfg(not(feature = "board-mk3"))]
fn search_wifs(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    shape: Shape,
    lower: &str,
    exact: &str,
) -> Option<Found> {
    use catcard_wallet::wif::WifKey;

    if !shape.admits_any_single() {
        return None;
    }
    menu::blocking_screen(ui.panel, HEAD, "reading key store");
    let mut keys: heapless::Vec<WifKey, { catcard_settings::wifs::MAX_KEYS }> =
        heapless::Vec::new();
    if crate::wifstore::load_keys(gate, login, ui.panel, &mut keys) == 0 {
        return None;
    }
    let mut buf = [0u8; address::MAX_ADDRESS_LEN];
    for (i, key) in keys.iter().enumerate() {
        let Some(pubkey) = crate::keywork::run(|kw| key.public_key(kw)) else {
            continue;
        };
        for kind in KINDS {
            if !shape.admits(kind) {
                continue;
            }
            let Ok(n) = address::encode(kind, key.network(), &pubkey, &mut buf) else {
                continue;
            };
            let made = core::str::from_utf8(&buf[..n]).unwrap_or("");
            if is_wanted(made, kind.is_bech32(), lower, exact) {
                return Some(Found::Wif { key: i, kind });
            }
        }
    }
    // `keys` drops here, and each `WifKey` zeroizes itself.
    None
}

/// Type an address. `None` if the owner backed out.
///
/// Addresses are long, so this takes them a character at a time the same way the passphrase
/// screen does -- and on a board with a keyboard, straight from it. On the Q1 the QR key
/// reads one off a code instead, which is how an address usually arrives: on the screen
/// of the wallet that is claiming it.
fn read_address(ui: &mut Ui<'_>, head: &str) -> Option<Entry> {
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
                    Key::Qr => {
                        #[cfg(feature = "board-q1")]
                        if let Some(text) = scan_address(ui, head) {
                            entry.clear();
                            for c in text.chars() {
                                entry.put(c);
                            }
                            entry.commit();
                            return Some(entry);
                        }
                        // The scan screen was up, or nothing happened: either way draw
                        // this one again.
                        redraw = true;
                    }
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

/// Read an address off a QR code.
///
/// The first code that is a plausible address wins: the payload with any BIP-21
/// `bitcoin:` scheme stripped (in either case -- a QR in alphanumeric mode is all upper
/// case) and its `?amount=...` parameters cut off, if what is left is alphanumeric and
/// no longer than an address can be. Anything else is some other code in shot, and the
/// scan goes on. `None` if the owner cancelled, or after the fault has been shown.
#[cfg(feature = "board-q1")]
fn scan_address(
    ui: &mut Ui<'_>,
    head: &str,
) -> Option<heapless::String<{ address::MAX_ADDRESS_LEN }>> {
    use crate::qrscan::{self, Fault, Next};

    let mut got: heapless::String<{ address::MAX_ADDRESS_LEN }> = heapless::String::new();
    let outcome = qrscan::scan_many(ui, head, &mut |_, line| {
        let Ok(text) = core::str::from_utf8(line) else {
            return Next::More;
        };
        let text = text.trim();
        // A BIP-21 URI gives up its address; anything else is taken as it is.
        let text = address::bip21::address_of(text).unwrap_or(text);
        if text.is_empty()
            || text.len() > address::MAX_ADDRESS_LEN
            || !text.bytes().all(|b| b.is_ascii_alphanumeric())
        {
            return Next::More;
        }
        got.clear();
        let _ = got.push_str(text);
        Next::Done
    });
    match outcome {
        Ok(()) if !got.is_empty() => Some(got),
        Ok(()) | Err(Fault::Cancelled) => None,
        Err(why) => {
            menu::message(ui.panel, head, qrscan::describe(why), "any key to go back");
            menu::wait_for_any_key(ui);
            None
        }
    }
}

fn draw(ui: &mut Ui<'_>, head: &str, entry: &Entry) {
    use catcard_ui::scroll::{Line, ScrollView, render};

    let mut hint = heapless::String::<48>::new();
    let _ = write!(
        hint,
        "{} search   {} back",
        display::CONFIRM_KEY,
        display::CANCEL_KEY
    );
    #[cfg(feature = "board-q1")]
    let _ = hint.push_str("   QR scan");
    let mut doc: heapless::Vec<Line, 8> = heapless::Vec::new();
    let _ = doc.push(Line::title(head));
    let _ = doc.push(Line::body(entry.as_str()).wrapped());
    #[cfg(not(feature = "board-q1"))]
    {
        let _ = doc.push(Line::body("2abc 3def 4ghi 5jkl").small());
        let _ = doc.push(Line::body("6mno 7pqrs 8tuv 9wxyz").small());
        let _ = doc.push(Line::body("same key again to cycle").small());
    }
    let _ = doc.push(Line::body(hint.as_str()).small());
    let view = ScrollView::build(&doc, display::SCREEN_W, display::SCREEN_H, display::FONTS);
    display::draw(ui.panel, |c| render(c, &view));
}
