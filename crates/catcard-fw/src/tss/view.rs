//! One kept share: what wallet it is a share of, its addresses and descriptor, and
//! deleting it or taking a copy.
//!
//! Everything shown is public and comes from the record's header
//! (`catcard_settings::tss::summary`): the wallet's key, its chain code, its origin. No
//! DKLs share is decoded to show it.
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

use catcard_settings::tss::{FileKey, Summary};
use catcard_wallet::address::{self, AddressKind, MAX_ADDRESS_LEN};
use catcard_wallet::bip32::serialize::{MAX_BASE58_LEN, Slip132};
use catcard_wallet::bip32::{ChildNumber, ExtendedPubKey, Network};
use catcard_wallet::descriptor::{self, SingleSig};
use core::fmt::Write as _;

use super::store::{self, Kept};
use super::{approve, card, hex4, restore, say};
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
fn xpub(s: &Summary) -> ExtendedPubKey {
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

/// Receive address `index` (`0/index`).
#[inline(never)]
fn address(s: &Summary, index: u32, out: &mut [u8; MAX_ADDRESS_LEN]) -> Option<usize> {
    let (kind, net) = kind_and_network(s);
    let key = xpub(s)
        .derive_child(ChildNumber::normal(0).ok()?)
        .and_then(|k| k.derive_child(ChildNumber(index)))
        .ok()?;
    address::encode(kind, net, &key.public_key, out).ok()
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

/// The wallet's details: who holds what, its key, its first addresses, its descriptor.
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
    let mut addrs = [[0u8; MAX_ADDRESS_LEN]; 3];
    let mut lens = [0usize; 3];
    for (i, (a, l)) in addrs.iter_mut().zip(lens.iter_mut()).enumerate() {
        *l = address(s, i as u32, a).unwrap_or(0);
    }
    let mut desc = [0u8; descriptor::MAX_LEN];
    let dn = descriptor_of(s, &mut desc).unwrap_or(0);
    let mut rows: heapless::Vec<Row<'_>, 16> = heapless::Vec::new();
    let _ = rows.push(Row::title(title));
    let _ = rows.push(Row::body(shape.as_str()));
    let _ = rows.push(Row::body(mine.as_str()).small());
    let _ = rows.push(Row::body(origin.as_str()).small().wrapped());
    let _ = rows.push(Row::body("Receive addresses:").small());
    for (a, &l) in addrs.iter().zip(lens.iter()) {
        let _ = rows.push(
            Row::body(core::str::from_utf8(&a[..l]).unwrap_or(""))
                .small()
                .wrapped(),
        );
    }
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

/// After a create: the new wallet, to compare across the members' devices.
#[inline(never)]
pub(super) fn created(ui: &mut Ui<'_>, record: &[u8]) {
    let Some(s) = catcard_settings::tss::summary(record) else {
        return say(ui, "Share kept", "", "");
    };
    let mut wallet: Line = Line::new();
    let _ = write!(wallet, "wallet {}", hex4(s.fingerprint));
    say(ui, "Share kept", &wallet, "compare on every device");
    details(
        ui,
        "New TSS wallet",
        &s,
        "Every member's device must show this same key and these addresses.",
    );
}

/// One kept share: its details, and what can be done with it.
#[inline(never)]
pub(super) fn wallet(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    key: &FileKey,
    kept: &Kept,
) {
    const DETAILS: &str = "Details";
    const DESCRIPTOR: &str = "Descriptor to card";
    const COPY: &str = "Copy share to card";
    const COMBINE: &str = "Restore the whole key";
    const DELETE: &str = "Delete this share";
    let s = &kept.summary;
    let title = label(s);
    let mut rows: heapless::Vec<&str, 5> = heapless::Vec::new();
    for r in [DETAILS, DESCRIPTOR, COPY] {
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
            DETAILS => details(ui, &title, s, ""),
            DESCRIPTOR => descriptor_to_card(ui, s),
            COPY => copy_to_card(ui, key, kept),
            COMBINE => {
                restore::combine(gate, login, ui, key, kept);
                return;
            }
            _ => {
                if delete(ui, kept) {
                    return;
                }
            }
        }
    }
}

/// `tss-<fingerprint>.txt`: the descriptor, for a watch-only wallet.
#[inline(never)]
fn descriptor_to_card(ui: &mut Ui<'_>, s: &Summary) {
    let mut desc = [0u8; descriptor::MAX_LEN + 1];
    let Some(n) = descriptor_of(s, &mut desc[..descriptor::MAX_LEN]) else {
        return say(ui, HEAD, "no descriptor", "for this wallet");
    };
    desc[n] = b'\n';
    let mut name: heapless::String<24> = heapless::String::new();
    let _ = write!(name, "tss-{}.txt", hex4(s.fingerprint));
    menu::card_wait(ui.panel, HEAD, "writing to the card");
    match menu::write_card_file(&name, &desc[..n + 1]) {
        Ok(()) => say(ui, HEAD, "written as", &name),
        Err(why) => say(ui, HEAD, "not written:", why),
    }
}

/// Copy the share to a card, to take it into another CatCard (Import a share) or to put
/// a created-together key back together on one.
#[inline(never)]
fn copy_to_card(ui: &mut Ui<'_>, key: &FileKey, kept: &Kept) {
    let s = &kept.summary;
    if !approve(
        ui,
        "Copy this share?",
        "To a file on the card. Whoever holds the file holds this member's share.",
        &["Give it a password, and keep the card apart from the other shares."],
        "copy",
        "back",
    ) {
        return;
    }
    let Some(protect) = card::ask_protection(ui, HEAD) else {
        return;
    };
    let mut record = match store::read(key, &kept.path) {
        Ok(r) => r,
        Err(why) => return say(ui, HEAD, "cannot read it:", why),
    };
    let fp = hex4(s.fingerprint);
    let mut name: heapless::String<40> = heapless::String::new();
    let _ = write!(name, "tss-{fp}-m{}.7z", s.member);
    let mut inner: heapless::String<24> = heapless::String::new();
    let _ = write!(inner, "member-{}.tss", s.member);
    match card::write_share(ui, HEAD, &name, &inner, record.as_slice(), &protect) {
        Ok(()) => say(ui, HEAD, "written as", &name),
        Err(why) => say(ui, HEAD, "not written:", why),
    }
}

/// Delete a kept share, after asking. Whether it is gone.
#[inline(never)]
fn delete(ui: &mut Ui<'_>, kept: &Kept) -> bool {
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
    match store::delete(&kept.path) {
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
