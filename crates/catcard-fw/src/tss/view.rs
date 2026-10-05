//! One kept share: what wallet it is a share of, its addresses and descriptor, setting
//! its pairs up again, and deleting it or taking a copy.
//!
//! Everything shown is public and comes from the record's header
//! (`catcard_tss::summary`): the wallet's key, its chain code, its origin. No DKLs share
//! is decoded to show it.
//!
//! # The wallet's extended public key
//!
//! - **Created together**: the joint key and the chain code tsslib derived from it, at
//!   depth 0. Receive and change are `0/*` and `1/*` under it, native SegWit, and a
//!   watch-only wallet imports `wpkh([fingerprint]xpub/<0;1>/*)`.
//! - **Split from a wallet**: the account key at `m/purpose'/coin'/account'` and that
//!   account's chain code, so the addresses are the wallet's own. The record does not
//!   carry the fingerprint of the account's parent, so the xpub's parent-fingerprint field
//!   is zero: the key and every address are the account's, the xpub's text differs from
//!   the one the whole wallet exports. Descriptors carry the origin themselves.

use catcard_tss::Summary;
use catcard_wallet::address::AddressKind;
use catcard_wallet::bip32::serialize::{MAX_BASE58_LEN, Slip132};
use catcard_wallet::bip32::{ChildNumber, ExtendedPubKey, Network};
use catcard_wallet::descriptor::{self, SingleSig};
use core::fmt::Write as _;

use super::store::{self, Kept};
use super::{approve, card, hex4, rebuild, restore, say};
use crate::menu::{self, Line};
use crate::ui::Ui;

const HEAD: &str = "TSS wallet";

/// A kept share's row: `2-of-3 #2 1A2B3C4D`.
pub(super) fn label(s: &Summary) -> Line {
    let mut l = Line::new();
    let _ = write!(
        l,
        "{}-of-{} #{} {}",
        s.t,
        s.n,
        s.member,
        hex4(s.fingerprint)
    );
    l
}

/// Where the wallet comes from, in a line.
pub(super) fn origin_line(s: &Summary) -> Line {
    let mut l = Line::new();
    if s.created {
        let _ = write!(l, "Created together, key {}", hex4(s.fingerprint));
    } else {
        let _ = write!(l, "Split from {} ", hex4(s.fingerprint));
        let _ = write_path(&mut l, &s.path);
    }
    l
}

fn write_path(out: &mut impl core::fmt::Write, path: &[u32]) -> core::fmt::Result {
    out.write_str("m")?;
    for &step in path {
        if step >= 0x8000_0000 {
            write!(out, "/{}h", step - 0x8000_0000)?;
        } else {
            write!(out, "/{step}")?;
        }
    }
    Ok(())
}

/// The address type, and the network the wallet's path says.
fn kind_and_network(s: &Summary) -> (AddressKind, Network) {
    if s.created {
        return (AddressKind::P2wpkh, crate::prefs::network());
    }
    let kind = match s.path.first().map(|p| p & 0x7FFF_FFFF) {
        Some(49) => AddressKind::P2shP2wpkh,
        Some(44) => AddressKind::P2pkh,
        _ => AddressKind::P2wpkh,
    };
    let net = match s.path.get(1).map(|c| c & 0x7FFF_FFFF) {
        Some(0) => Network::Mainnet,
        // Coin type 1 covers testnet and regtest, which differ only in the HRP: the
        // network in force says which.
        _ if !crate::prefs::network().is_mainnet() => crate::prefs::network(),
        _ => Network::Testnet,
    };
    (kind, net)
}

/// The wallet's extended public key (see the module documentation).
pub(crate) fn xpub(s: &Summary) -> ExtendedPubKey {
    let (_, network) = kind_and_network(s);
    ExtendedPubKey {
        network,
        depth: s.path.len() as u8,
        parent_fingerprint: [0; 4],
        child_number: ChildNumber(s.path.last().copied().unwrap_or(0)),
        chain_code: s.chain_code,
        public_key: s.joint_public,
    }
}

/// The descriptor a watch-only wallet imports: both chains, checksummed.
#[inline(never)]
fn descriptor_of(s: &Summary, out: &mut [u8]) -> Option<usize> {
    let mut raw = [0u8; MAX_BASE58_LEN];
    let n = xpub(s).write_base58_as(Slip132::Classic, &mut raw).ok()?;
    let x = core::str::from_utf8(&raw[..n]).ok()?;
    if s.created {
        let mut body: heapless::String<{ descriptor::MAX_LEN }> = heapless::String::new();
        let [a, b, c, d] = s.fingerprint;
        write!(body, "wpkh([{a:02x}{b:02x}{c:02x}{d:02x}]{x}/<0;1>/*)").ok()?;
        let sum = descriptor::checksum(&body)?;
        let len = body.len();
        out.get_mut(..len)?.copy_from_slice(body.as_bytes());
        out.get_mut(len)?.clone_from(&b'#');
        out.get_mut(len + 1..len + 1 + sum.len())?
            .copy_from_slice(&sum);
        return Some(len + 1 + sum.len());
    }
    let (kind, _) = kind_and_network(s);
    let [_, coin, account] = s.path[..] else {
        return None;
    };
    SingleSig {
        kind,
        fingerprint: s.fingerprint,
        coin: coin & 0x7FFF_FFFF,
        account: account & 0x7FFF_FFFF,
    }
    .write(x, out)
    .ok()
}

/// The wallet's details: who holds what, its key and its descriptor. Its addresses are in
/// the Address Explorer, with the wallet in force ("Use this wallet").
#[inline(never)]
fn details(ui: &mut Ui<'_>, title: &str, s: &Summary, closing: &str) {
    use catcard_ui::scroll::Line as Row;
    let mut shape: Line = Line::new();
    let _ = write!(shape, "{} of {} members sign", s.t, s.n);
    let mut mine: Line = Line::new();
    let _ = write!(mine, "This device: member {}", s.member);
    let origin = origin_line(s);
    let mut raw = [0u8; MAX_BASE58_LEN];
    let xn = xpub(s)
        .write_base58_as(Slip132::Classic, &mut raw)
        .unwrap_or(0);
    let x = core::str::from_utf8(&raw[..xn]).unwrap_or("");
    let mut desc = [0u8; descriptor::MAX_LEN];
    let dn = descriptor_of(s, &mut desc).unwrap_or(0);
    let mut rows: heapless::Vec<Row<'_>, 16> = heapless::Vec::new();
    let _ = rows.push(Row::title(title));
    let _ = rows.push(Row::body(shape.as_str()));
    let _ = rows.push(Row::body(mine.as_str()).small());
    let _ = rows.push(Row::body(origin.as_str()).small().wrapped());
    let _ = rows.push(Row::body("Extended public key:").small());
    let _ = rows.push(Row::body(x).small().wrapped());
    let _ = rows.push(Row::body("Watch-only descriptor:").small());
    let _ = rows.push(
        Row::body(core::str::from_utf8(&desc[..dn]).unwrap_or(""))
            .small()
            .wrapped(),
    );
    if !closing.is_empty() {
        let _ = rows.push(Row::body(closing).small().wrapped());
    }
    let _ = menu::show_doc(ui, &rows, false, false);
}

/// After a create: switch to the new wallet, and name it, to compare across the members'
/// devices. Its addresses are the Address Explorer's from here.
#[inline(never)]
pub(super) fn created(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    s: &Summary,
) {
    let mut wallet: Line = Line::new();
    let _ = write!(wallet, "TSS wallet {}", hex4(s.fingerprint));
    let index = store::list(gate, login, ui)
        .ok()
        .and_then(|k| k.into_iter().find(|k| store::same_member(&k.summary, s)));
    match index {
        Some(kept) if use_wallet(gate, login, ui, &kept) => say(
            ui,
            &wallet,
            "in force: the same number",
            "on every member's device",
        ),
        _ => say(ui, "Share kept", &wallet, "compare on every device"),
    }
}

/// Put `kept`'s wallet in force: the status bar (or the mono home menu) says `TSS` and
/// its fingerprint, the Address Explorer walks its addresses, and a signature is made
/// together. Its settings stay those of the wallet keeping the share. `false` if the
/// keeping wallet's settings key cannot be had (said).
#[inline(never)]
pub(super) fn use_wallet(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    kept: &Kept,
) -> bool {
    let keeper = match crate::settings::wallet_key(gate, login, ui.panel, HEAD) {
        Ok(k) => k,
        Err(why) => {
            say(ui, HEAD, "cannot switch:", why);
            return false;
        }
    };
    crate::key::set_tss(kept.summary.clone(), kept.index);
    crate::settings::enter_tss(keeper);
    crate::pubkeys::note_fingerprint(Some(kept.summary.fingerprint));
    crate::catlog!("key: now {}", crate::key::label());
    true
}

/// What the Export menu writes for the TSS wallet in force.
#[derive(Copy, Clone, PartialEq, Eq)]
pub(crate) enum Export {
    /// The generic JSON a watch-only wallet imports (Sparrow, and the others that read
    /// it), with this wallet's one address type.
    Json,
    /// The watch-only descriptor.
    Descriptor,
    /// The extended public key.
    Xpub,
}

/// Write the export `what` of the TSS wallet in force and offer it, under `file` (the
/// row's own name for JSON; the others are named by the wallet). Everything in it is
/// public and comes from the share's header: no member, card or session is involved,
/// and nothing is signed -- the file signature an export carries is made with a
/// private key, which a TSS wallet has nowhere.
pub(crate) fn export_in_force(ui: &mut Ui<'_>, head: &str, what: Export, file: &str) {
    let Some((s, _)) = crate::key::tss() else {
        return;
    };
    let mut text: heapless::String<{ crate::export::MAX_LEN }> = heapless::String::new();
    let mut name: heapless::String<32> = heapless::String::new();
    let built = match what {
        Export::Json => {
            let _ = name.push_str(file);
            json(s, &mut text)
        }
        Export::Descriptor => {
            let _ = write!(name, "/tss-{}.txt", hex4(s.fingerprint));
            let mut desc = [0u8; descriptor::MAX_LEN];
            descriptor_of(s, &mut desc).and_then(|n| {
                text.push_str(core::str::from_utf8(&desc[..n]).ok()?).ok()?;
                text.push('\n').ok()
            })
        }
        Export::Xpub => {
            let _ = write!(name, "/tss-{}-xpub.txt", hex4(s.fingerprint));
            let mut raw = [0u8; MAX_BASE58_LEN];
            xpub(s)
                .write_base58_as(Slip132::Classic, &mut raw)
                .ok()
                .and_then(|n| {
                    text.push_str(core::str::from_utf8(&raw[..n]).ok()?).ok()?;
                    text.push('\n').ok()
                })
        }
    };
    if built.is_none() {
        return say(ui, head, "cannot write", "this wallet's export");
    }
    let kind = match what {
        Export::Json => catcard_bbqr::FileType::JSON,
        Export::Descriptor | Export::Xpub => catcard_bbqr::FileType::UNICODE,
    };
    menu::offer_export(ui, head, &name, text.as_bytes(), kind, None);
}

/// The generic JSON (`hw-reference/wallet-export-formats.md` §A) for a TSS wallet: the
/// top level names the wallet's fingerprint and key, and one entry -- the address type
/// its descriptor names -- carries the origin path (`m` for a key created together), the
/// xpub, the descriptor and the first receive address.
fn json(s: &Summary, out: &mut heapless::String<{ crate::export::MAX_LEN }>) -> Option<()> {
    let (kind, net) = kind_and_network(s);
    let key = xpub(s);
    let mut raw = [0u8; MAX_BASE58_LEN];
    let n = key.write_base58_as(Slip132::Classic, &mut raw).ok()?;
    let x = core::str::from_utf8(&raw[..n]).ok()?;
    let [a, b, c, d] = s.fingerprint;
    let ticker = crate::prefs::current().net.ticker();
    let account = s.path.get(2).map_or(0, |p| p & 0x7FFF_FFFF);
    write!(
        out,
        "{{\"chain\":\"{ticker}\",\"xfp\":\"{a:02X}{b:02X}{c:02X}{d:02X}\",\"account\":{account},\"xpub\":\"{x}\""
    )
    .ok()?;
    let (entry, name) = match kind {
        AddressKind::P2shP2wpkh => ("bip49", "p2sh-p2wpkh"),
        AddressKind::P2pkh => ("bip44", "p2pkh"),
        _ => ("bip84", "p2wpkh"),
    };
    let [e, f, g, h] = key.fingerprint();
    let mut deriv = Line::new();
    write_path(&mut deriv, &s.path).ok()?;
    write!(
        out,
        ",\"{entry}\":{{\"name\":\"{name}\",\"xfp\":\"{e:02X}{f:02X}{g:02X}{h:02X}\",\"deriv\":\"{deriv}\",\"xpub\":\"{x}\",\"desc\":\""
    )
    .ok()?;
    let mut desc = [0u8; descriptor::MAX_LEN];
    let dn = descriptor_of(s, &mut desc)?;
    out.push_str(core::str::from_utf8(&desc[..dn]).ok()?).ok()?;
    out.push('"').ok()?;
    let first = key
        .derive_child(ChildNumber::normal(0).ok()?)
        .and_then(|k| k.derive_child(ChildNumber(0)))
        .ok()?;
    let mut addr = [0u8; catcard_wallet::address::MAX_ADDRESS_LEN];
    let an = catcard_wallet::address::encode(kind, net, &first.public_key, &mut addr).ok()?;
    write!(
        out,
        ",\"first\":\"{}\"}}}}",
        core::str::from_utf8(&addr[..an]).ok()?
    )
    .ok()
}

/// The key the TSS wallet in force gives a chain other than Bitcoin, and its path as text:
/// its own unhardened branch at the chain's SLIP-44 `coin` type, then `account` --
/// `{origin}/{coin}/{account}`, with change and index below it as for any account. A
/// convention of this firmware's: a TSS key has no hardened steps to follow, so each
/// chain is kept apart by an unhardened one instead, and every address is still made on
/// the device from the public key alone.
#[cfg(feature = "multichain")]
pub(crate) fn chain_key(coin: u32, account: u32) -> Option<(ExtendedPubKey, Line)> {
    let (s, _) = crate::key::tss()?;
    let (coin_step, account_step) = (
        ChildNumber::normal(coin).ok()?,
        ChildNumber::normal(account).ok()?,
    );
    let key = xpub(s)
        .derive_child(coin_step)
        .and_then(|k| k.derive_child(account_step))
        .ok()?;
    let mut path = Line::new();
    write_path(&mut path, &s.path).ok()?;
    write!(path, "/{coin}/{account}").ok()?;
    Some((key, path))
}

/// What the Address Explorer needs of the TSS wallet in force: the key the addresses are
/// below (non-hardened only), the one address type its descriptor names, the network
/// its path says, and the path to that key as text (`m` when created together).
pub(crate) fn explorer() -> Option<(ExtendedPubKey, AddressKind, Network, Line)> {
    let (s, _) = crate::key::tss()?;
    let (kind, net) = kind_and_network(s);
    let mut path = Line::new();
    write_path(&mut path, &s.path).ok()?;
    Some((xpub(s), kind, net, path))
}

/// One kept share: its details, and what can be done with it.
#[inline(never)]
pub(super) fn wallet(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    kept: &Kept,
    mut pool: Option<&mut catcard_entropy::EntropyPool>,
) {
    const USE: &str = "Use this wallet";
    const DETAILS: &str = "Details";
    const REBUILD: &str = "Rebuild setup";
    const DESCRIPTOR: &str = "Descriptor to file";
    const COPY: &str = "Copy share to file";
    const COMBINE: &str = "Restore the whole key";
    const DELETE: &str = "Delete this share";
    let s = &kept.summary;
    let title = label(s);
    let mut rows: heapless::Vec<&str, 7> = heapless::Vec::new();
    for r in [USE, DETAILS, REBUILD, DESCRIPTOR, COPY] {
        let _ = rows.push(r);
    }
    if s.created {
        let _ = rows.push(COMBINE);
    }
    let _ = rows.push(DELETE);
    loop {
        let Some(pick) = menu::pick_row(ui, &title, "", &rows) else {
            return;
        };
        match rows[pick] {
            USE => {
                if use_wallet(gate, login, ui, kept) {
                    let mut l: Line = Line::new();
                    let _ = write!(l, "TSS wallet {}", hex4(s.fingerprint));
                    say(ui, HEAD, &l, "in force until reboot");
                    return;
                }
            }
            DETAILS => details(ui, &title, s, ""),
            REBUILD => rebuild::rebuild(gate, login, ui, kept, pool.as_deref_mut()),
            DESCRIPTOR => descriptor_to_file(ui, s),
            COPY => copy_to_file(gate, login, ui, kept),
            COMBINE => {
                restore::combine(gate, login, ui, kept);
                return;
            }
            _ => {
                if delete(gate, login, ui, kept) {
                    return;
                }
            }
        }
    }
}

/// `tss-<fingerprint>.txt`: the descriptor, for a watch-only wallet.
#[inline(never)]
fn descriptor_to_file(ui: &mut Ui<'_>, s: &Summary) {
    let mut desc = [0u8; descriptor::MAX_LEN + 1];
    let Some(n) = descriptor_of(s, &mut desc[..descriptor::MAX_LEN]) else {
        return say(ui, HEAD, "no descriptor", "for this wallet");
    };
    desc[n] = b'\n';
    let mut name: heapless::String<24> = heapless::String::new();
    let _ = write!(name, "tss-{}.txt", hex4(s.fingerprint));
    let Some(storage) = menu::pick_storage(ui, HEAD) else {
        return;
    };
    card::wait(ui.panel, HEAD, storage, true);
    match menu::write_storage_file(storage, &name, &desc[..n + 1]) {
        Ok(()) => say(ui, HEAD, "written as", &name),
        Err(why) => say(ui, HEAD, "not written:", why),
    }
}

/// Copy the share -- its key core -- to a file, to take it into another CatCard (Import
/// a share) or to put a created-together key back together on one.
#[inline(never)]
fn copy_to_file(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    kept: &Kept,
) {
    let s = &kept.summary;
    if !approve(
        ui,
        "Copy this share?",
        "To a file. Whoever holds the file holds this member's share.",
        &["Give it a password, and keep the file apart from the other shares."],
        "copy",
        "back",
    ) {
        return;
    }
    let Some(storage) = menu::pick_storage(ui, HEAD) else {
        return;
    };
    let Some(protect) = card::ask_protection(ui, HEAD) else {
        return;
    };
    let mut record = match store::read(gate, login, ui, kept.index) {
        Ok(r) => r,
        Err(why) => return say(ui, HEAD, "cannot read it:", why),
    };
    let fp = hex4(s.fingerprint);
    let mut name: heapless::String<40> = heapless::String::new();
    let _ = write!(name, "tss-{fp}-m{}.7z", s.member);
    let mut inner: heapless::String<24> = heapless::String::new();
    let _ = write!(inner, "member-{}.tss", s.member);
    match card::write_share(
        ui,
        storage,
        HEAD,
        &name,
        &inner,
        record.as_slice(),
        &protect,
    ) {
        Ok(()) => say(ui, HEAD, "written as", &name),
        Err(why) => say(ui, HEAD, "not written:", why),
    }
}

/// Delete a kept share, after asking. Whether it is gone.
#[inline(never)]
fn delete(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    kept: &Kept,
) -> bool {
    let s = &kept.summary;
    let mut main: Line = Line::new();
    let _ = write!(
        main,
        "Member {} of {}, wallet {}",
        s.member,
        s.n,
        hex4(s.fingerprint)
    );
    let mut rest: Line = Line::new();
    if s.t < s.n {
        let _ = write!(rest, "Any {} of the other {} still sign.", s.t, s.n - 1);
    } else {
        let _ = rest.push_str("Every share is needed: the wallet can no longer sign.");
    }
    if !approve(
        ui,
        "Delete this share?",
        &main,
        &[
            "This device can no longer sign for the wallet.",
            rest.as_str(),
        ],
        "delete",
        "keep",
    ) {
        return false;
    }
    match store::delete(gate, login, ui, kept.index) {
        Ok(()) => {
            say(ui, HEAD, "share deleted", "");
            true
        }
        Err(why) => {
            say(ui, HEAD, "not deleted:", why);
            false
        }
    }
}
