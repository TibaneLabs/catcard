//! Shares coming in: one taken into this device to sign with, `t` of a split put back
//! into its words, `t` of a created-together wallet put back into its key.

use alloc::string::String;
use alloc::vec::Vec;
use catcard_callgate::Callgate;
use catcard_tss::{CombinePart, ShareRecord, bundle_parts, summary};
use core::fmt::Write as _;
use zeroize::{Zeroize as _, Zeroizing};

use super::store::{self, Kept, same_wallet};
use super::{Room, Work, approve, card, describe, hex4, say, view};
use crate::menu::{self, Line};
use crate::ui::Ui;

/// The record a share file holds: the whole of a lone record, or a bundle's signing half.
fn record_of(file: &[u8]) -> Option<&[u8]> {
    if let Some(parts) = bundle_parts(file) {
        return Some(parts.record);
    }
    summary(file).map(|_| file)
}

/// Import a share: read a share file and keep its record -- the key core -- to sign with.
///
/// Nothing about pairs comes in: a bundle carries none, and a record copied from another
/// device names a cache only that device can open. The member sets its pairs up with its
/// co-signers before it first signs (Rebuild setup).
#[inline(never)]
pub(super) fn import(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    const HEAD: &str = "Import a share";
    let Some(_room) = Room::take(ui, HEAD) else {
        return;
    };
    let Some(mut file) = card::read_share(ui, HEAD) else {
        return;
    };
    let bytes = file.as_slice();
    let Some(record) = record_of(bytes) else {
        return say(ui, HEAD, "not a TSS share", "");
    };
    let Some(s) = summary(record) else {
        return say(ui, HEAD, "not a TSS share", "");
    };
    if store::holds(gate, login, ui, &s) {
        return say(ui, HEAD, "this share is", "kept here already");
    }
    let mut main: Line = Line::new();
    let _ = write!(main, "Member {} of {}, {} needed", s.member, s.n, s.t);
    let wallet = view::origin_line(&s);
    if !approve(
        ui,
        "Keep this share?",
        &main,
        &[
            wallet.as_str(),
            "Kept in this wallet's settings. Before it first signs, Rebuild setup with the members signing with it.",
        ],
        "keep",
        "back",
    ) {
        return;
    }
    if !Room::fits(ui, HEAD, Work::Decode, s.n, 2 * record.len()) {
        return;
    }
    // The secret half is checked before it is kept: a share that will not sign is
    // refused now, not when the others are waiting for it. What is kept is the record
    // as this device writes it, naming no pair cache.
    let mut busy = Some(menu::blocking_screen(ui.panel, HEAD, "checking the share"));
    let checked = crate::keywork::run(|kw| {
        let mut r = ShareRecord::from_bytes(record, kw)?;
        r.forget_cache();
        r.to_bytes(kw)
    });
    busy.take();
    let kept = match checked {
        Ok(k) => k,
        Err(e) => return say(ui, HEAD, "refused:", describe(&e)),
    };
    drop(file);
    match store::save(gate, login, ui, &kept) {
        Ok(()) => say(ui, HEAD, "share kept: set up", "pairs before signing"),
        Err(why) => say(ui, HEAD, "not kept:", why),
    }
}

/// The blank device's Import -> TSS shares: the words back from a split's share files.
pub(crate) fn restore_screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    restore_words(gate, login, ui);
}

/// Restore from shares: read `t` share files of one split, one card after another, put
/// the words back together from their Codex32 halves, and store them as the wallet.
///
/// Only the Codex32 halves are read (`catcard_tss::bundle_parts`); nothing here decodes a
/// DKLs share, so this needs no more memory than a Codex32 recovery.
#[inline(never)]
pub(super) fn restore_words(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    const HEAD: &str = "Restore from shares";
    let mut texts: Vec<Zeroizing<String>> = Vec::new();
    let mut members: heapless::Vec<u8, 9> = heapless::Vec::new();
    let mut needed: Option<u8> = None;
    while needed.is_none_or(|t| texts.len() < usize::from(t)) {
        let mut note: Line = Line::new();
        match needed {
            Some(t) => {
                let _ = write!(note, "{} of {} shares in", texts.len(), t);
            }
            None => {
                let _ = note.push_str("insert a card with a share");
            }
        }
        match menu::pick_row(ui, HEAD, &note, &["Read a share file", "Stop"]) {
            Some(0) => {}
            _ => return,
        }
        let Some(mut file) = card::read_share(ui, HEAD) else {
            continue;
        };
        let bytes = file.as_slice();
        let Some(parts) = bundle_parts(bytes) else {
            if summary(bytes).is_some_and(|s| s.created) {
                say(
                    ui,
                    HEAD,
                    "a created-together share",
                    "has no words to restore",
                );
            } else {
                say(ui, HEAD, "not a share file", "of a split wallet");
            }
            continue;
        };
        if needed.is_some_and(|t| t != parts.t) {
            say(ui, HEAD, "that share is from", "another split");
            continue;
        }
        if members.contains(&parts.member) {
            say(ui, HEAD, "that share is", "in already");
            continue;
        }
        needed = Some(parts.t);
        let _ = members.push(parts.member);
        texts.push(Zeroizing::new(String::from(parts.codex32)));
        crate::catlog!("tss: restore, share {} in", parts.member);
    }

    let refs: Vec<&str> = texts.iter().map(|s| s.as_str()).collect();
    let got = crate::keywork::run(|kw| catcard_tss::restore_entropy_from_codex32(&refs, kw));
    drop(refs);
    drop(texts);
    let entropy = match got {
        Ok(e) => e,
        Err(e) => return say(ui, HEAD, "cannot restore:", describe(&e)),
    };
    let Ok(mut stash) = catcard_callgate::pin::encode_bip39(&entropy) else {
        return say(ui, HEAD, "cannot restore:", "not a length of words");
    };
    let busy = menu::blocking_screen(ui.panel, HEAD, "deriving the key");
    let fp = crate::backup::fingerprint_of(&stash);
    drop(busy);
    stash.zeroize();
    let Some(fp) = fp else {
        return say(ui, HEAD, "cannot restore:", "not a usable key");
    };
    // Matching headers do not prove the shares belong together (BIP-93): the owner
    // checks the fingerprint, and an address, before using the wallet.
    let fps = hex4(fp);
    let mut words: Line = Line::new();
    let words_n = catcard_wallet::bip39::words_for_entropy(entropy.len()).unwrap_or(0);
    let _ = write!(words, "{words_n} words: check an address");
    menu::ask(ui.panel, "Store this wallet?", &fps, &words);
    if !menu::confirmed(ui) {
        return say(ui, HEAD, "cancelled", "nothing was stored");
    }
    if crate::key::stored_wallet(login) {
        menu::ask(
            ui.panel,
            "Wallet exists",
            "an import DESTROYS",
            "the one stored now",
        );
        if !menu::confirmed(ui) {
            return say(ui, HEAD, "cancelled", "nothing was stored");
        }
    }
    if !menu::store_seed(gate, login, ui, &entropy) {
        // It has already said why.
        return;
    }
    crate::key::to_root();
    #[cfg(feature = "board-q1")]
    crate::pubkeys::note_fingerprint(Some(fp));
    crate::catlog!("tss: wallet {} restored from shares", fps.as_str());
    say(ui, "Wallet stored", &fps, "is the master now");
}

/// Put a created-together wallet's key back together from `t` shares -- this device's
/// and others read from cards -- and store it as this device's wallet, an XPRV.
///
/// **This ends the "nobody holds the key" property**, and the owner is told so twice,
/// in plain words, before anything is read (docs/TSS.md, "Restore a created-together
/// wallet").
#[inline(never)]
pub(super) fn combine(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    kept: &Kept,
) {
    const HEAD: &str = "Restore the key";
    let s = &kept.summary;
    if !s.created {
        return say(ui, HEAD, "a split wallet comes", "back from its words");
    }
    let mut need: Line = Line::new();
    let _ = write!(
        need,
        "It needs {} shares: this one, and the rest from cards.",
        s.t
    );
    if !approve(
        ui,
        "Put the key together?",
        "Then nobody holding a share is needed: this device alone holds the whole key.",
        &[
            need.as_str(),
            "That ends what a TSS wallet is for, and cannot be undone.",
        ],
        "go on",
        "back",
    ) {
        return;
    }
    menu::ask(
        ui.panel,
        "Are you sure?",
        "this device will hold",
        "the whole key: 3 = yes",
    );
    if !menu::confirmed_by_digit(ui, 3) {
        return;
    }
    let Some(_room) = Room::take(ui, HEAD) else {
        return;
    };
    let t = usize::from(s.t);
    // One record at a time: each is decoded as it comes in, its Shamir share kept and the
    // rest dropped before the next is read. Records are cores, a kilobyte at most.
    if !Room::fits(ui, HEAD, Work::Decode, s.n, 4096) {
        return;
    }

    // Every share of this wallet kept here, then the rest from files.
    let mut parts: Vec<CombinePart> = Vec::new();
    if let Ok(all) = store::list(gate, login, ui) {
        for k in all.iter().filter(|k| same_wallet(&k.summary, s)) {
            if let Ok(mut r) = store::read(gate, login, ui, k.index) {
                match take_part(ui, HEAD, r.as_slice()) {
                    Some(p) => parts.push(p),
                    None => return,
                }
            }
        }
    }
    while parts.len() < t {
        let mut note: Line = Line::new();
        let _ = write!(note, "{} of {} shares in", parts.len(), t);
        match menu::pick_row(ui, HEAD, &note, &["Read a share file", "Stop"]) {
            Some(0) => {}
            _ => return,
        }
        let Some(mut file) = card::read_share(ui, HEAD) else {
            continue;
        };
        let Some(record) = record_of(file.as_slice()) else {
            say(ui, HEAD, "not a TSS share", "");
            continue;
        };
        match summary(record) {
            Some(r) if !same_wallet(&r, s) => say(ui, HEAD, "a share of", "another wallet"),
            Some(r) if parts.iter().any(|p| p.member() == r.member) => {
                say(ui, HEAD, "that share is", "in already")
            }
            Some(_) => match take_part(ui, HEAD, record) {
                Some(p) => parts.push(p),
                None => return,
            },
            None => say(ui, HEAD, "not a TSS share", ""),
        }
    }

    let mut busy = Some(menu::blocking_screen(
        ui.panel,
        HEAD,
        "putting the key together",
    ));
    let joined = crate::keywork::run(|kw| {
        let secret = catcard_tss::combine_parts(&parts, kw)?;
        Ok::<_, catcard_tss::Error>(catcard_callgate::pin::encode_xprv(
            secret.chain_code(),
            secret.private_key(),
        ))
    });
    busy.take();
    drop(parts);
    let mut stash = match joined {
        Ok(x) => x,
        Err(e) => return say(ui, HEAD, "cannot put it together:", describe(&e)),
    };
    let fps = hex4(s.fingerprint);
    menu::ask(ui.panel, "Store as the wallet?", &fps, "an XPRV, no words");
    if !menu::confirmed(ui) {
        stash.zeroize();
        return say(ui, HEAD, "cancelled", "nothing was stored");
    }
    if crate::key::stored_wallet(login) {
        menu::ask(
            ui.panel,
            "Wallet exists",
            "this DESTROYS",
            "the one stored now",
        );
        if !menu::confirmed(ui) {
            stash.zeroize();
            return say(ui, HEAD, "cancelled", "nothing was stored");
        }
    }
    let res = crate::backup::store_secret(gate, login, ui, &stash);
    stash.zeroize();
    match res {
        Ok(()) => {
            crate::key::to_root();
            #[cfg(feature = "board-q1")]
            crate::pubkeys::note_fingerprint(Some(s.fingerprint));
            crate::catlog!(
                "tss: created wallet {} put together and stored",
                fps.as_str()
            );
            // Its addresses are the master's own 0/* and 1/*, not an account's.
            say(ui, "Wallet stored", "its addresses are", "m/0/* and m/1/*");
        }
        Err(why) => say(ui, "Not stored", why, "any key to go back"),
    }
}

/// Decode one record and keep only what recombining needs of it. `None`, said on
/// screen, for a record that will not decode.
fn take_part(ui: &mut Ui<'_>, head: &str, record: &[u8]) -> Option<CombinePart> {
    let mut busy = Some(menu::blocking_screen(ui.panel, head, "reading the share"));
    let part =
        crate::keywork::run(|kw| ShareRecord::from_bytes(record, kw).map(|r| r.combine_part(kw)));
    busy.take();
    match part {
        Ok(p) => Some(p),
        Err(e) => {
            say(ui, head, "refused:", describe(&e));
            None
        }
    }
}
