//! Rebuild setup: make this member's pairs again with the other members, one at a time
//! (docs/TSS.md, "Where things live").
//!
//! Signing needs, between every two signers, the pairwise state their two devices set up
//! together. A member keeps its own in a pair cache on a card or the Virtual Disk, so it
//! is lost with the card, at every power-off on the disk, and never there at all for a
//! share taken in from an export. None of that is a failure: two members make their pair
//! again in a short session of their own, which changes no share, no address and no other
//! pair.
//!
//! The owner picks another member -- or every one this device has no pair with -- and
//! that member's device runs the same action and picks this one. Of the two, the lower
//! member number starts the session and writes its invitation; the other finds it. The
//! session is the same as any other (`super::drive`): commitments, identities, a session
//! code compared on both screens, signed and encrypted messages, over the card or the
//! Virtual Disk. After each pair the cache is written again and the record's digest of it
//! saved, so a pair that is made is kept even if the next one is not.

use alloc::vec::Vec;
use catcard_tss::{CacheKey, CacheRefused, Error, SESSION_ID_LEN, Session, ShareRecord};
use core::fmt::Write as _;

use super::card::{self, Invitation};
use super::rand::{Drbg, Fresh};
use super::store::{self, Kept};
use super::{Room, Work, approve, describe, drive, keep, say};
use crate::menu::{self, Line, Storage};
use crate::ui::Ui;

const HEAD: &str = "Rebuild setup";

/// What a look for this member's pair cache found.
pub(super) enum Loaded {
    /// Pairs with these members, from the current cache.
    Pairs(Vec<u8>),
    /// No cache on that medium, or none written yet.
    Nothing,
    /// A cache that is not the current one, or not this device's.
    Refused(CacheRefused),
}

/// Read `record`'s pair cache from `storage` into it, if it is there and current.
#[inline(never)]
pub(super) fn load_cache(
    ui: &mut Ui<'_>,
    storage: Storage,
    record: &mut ShareRecord,
    key: &CacheKey,
) -> Result<Loaded, &'static str> {
    if record.cache_digest().is_none() {
        return Ok(Loaded::Nothing);
    }
    let path = catcard_tss::cache::file_name(record);
    card::wait(ui.panel, HEAD, storage, false);
    let Some(mut file) = card::read_cache(storage, &path)? else {
        return Ok(Loaded::Nothing);
    };
    let mut busy = Some(menu::blocking_screen(ui.panel, HEAD, "opening the setup"));
    let len = file.as_slice().len();
    let got = crate::keywork::run(|kw| record.read_pair_cache(&mut file.space()[..len], key, kw));
    busy.take();
    drop(file);
    match got {
        Ok(peers) => Ok(Loaded::Pairs(peers)),
        Err(Error::Cache(r)) => Ok(Loaded::Refused(r)),
        Err(e) => Err(describe(&e)),
    }
}

/// What a refused cache is, in a line.
pub(super) fn refusal(r: CacheRefused) -> &'static str {
    match r {
        CacheRefused::NotCurrent => "an older setup, not the current one",
        CacheRefused::Foreign => "another device's setup",
        CacheRefused::Damaged => "a damaged setup file",
    }
}

/// The members `record` has no pair with.
fn missing(record: &ShareRecord) -> Vec<u8> {
    let all: Vec<u8> = (1..=record.n()).collect();
    record.missing_pairs(&all)
}

/// `2, 3 and 5`.
fn members_text(out: &mut heapless::String<64>, members: &[u8]) {
    for (i, m) in members.iter().enumerate() {
        let sep = match i {
            0 => "",
            _ if i + 1 == members.len() => " and ",
            _ => ", ",
        };
        let _ = write!(out, "{sep}{m}");
    }
}

/// The whole flow, for the kept record `kept`.
#[inline(never)]
pub(super) fn rebuild(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    kept: &Kept,
    pool: Option<&mut catcard_entropy::EntropyPool>,
) {
    let Some(pool) = pool else {
        return say(ui, HEAD, "the pool missed its", "policy at boot");
    };
    let Some(_room) = Room::take(ui, HEAD) else {
        return;
    };
    let n = kept.summary.n;
    if !Room::fits(ui, HEAD, Work::Rebuild, n, 0) {
        return;
    }
    let Some(storage) = menu::pick_storage(ui, HEAD) else {
        return;
    };
    let mut bytes = match store::read(gate, login, ui, kept.index) {
        Ok(b) => b,
        Err(why) => return say(ui, HEAD, "cannot read it:", why),
    };
    let decoded = crate::keywork::run(|kw| ShareRecord::from_bytes(bytes.as_slice(), kw));
    drop(bytes);
    let mut record = match decoded {
        Ok(r) => r,
        Err(e) => return say(ui, HEAD, "refused:", describe(&e)),
    };
    let key = match store::cache_key(gate, login, ui, &record) {
        Ok(k) => k,
        Err(why) => return say(ui, HEAD, "cannot reach the key:", why),
    };
    // The pairs this member already has, so only the missing ones need a session. A
    // cache that is gone or out of date is the usual case here, not an error.
    match load_cache(ui, storage, &mut record, &key) {
        Ok(Loaded::Pairs(peers)) => {
            crate::catlog!("tss: setup read, pairs with {} members", peers.len());
        }
        Ok(Loaded::Nothing) => {}
        Ok(Loaded::Refused(r)) => say(ui, HEAD, "the setup found is", refusal(r)),
        Err(why) => say(ui, HEAD, "no setup read:", why),
    }

    loop {
        let lacking = missing(&record);
        let mut note: heapless::String<64> = heapless::String::new();
        if lacking.is_empty() {
            let _ = note.push_str("set up with every member");
        } else {
            let _ = note.push_str("missing with ");
            members_text(&mut note, &lacking);
        }
        const ALL: &str = "Every missing member";
        let mut labels: heapless::Vec<Line, 9> = heapless::Vec::new();
        let mut peers: heapless::Vec<u8, 9> = heapless::Vec::new();
        for m in (1..=n).filter(|&m| m != record.member()) {
            let mut l = Line::new();
            let state = if lacking.contains(&m) {
                "missing"
            } else {
                "redo"
            };
            let _ = write!(l, "With member {m} ({state})");
            let _ = labels.push(l);
            let _ = peers.push(m);
        }
        let mut rows: heapless::Vec<&str, 10> = heapless::Vec::new();
        if !lacking.is_empty() {
            let _ = rows.push(ALL);
        }
        for l in labels.iter() {
            let _ = rows.push(l.as_str());
        }
        let Some(pick) = menu::pick_row(ui, HEAD, &note, &rows) else {
            return;
        };
        let chosen: Vec<u8> = if rows[pick] == ALL {
            lacking
        } else {
            let at = pick - usize::from(rows[0] == ALL);
            alloc::vec![peers[at]]
        };
        for peer in chosen {
            if !with_peer(gate, login, ui, storage, &mut record, peer, pool) {
                break;
            }
        }
    }
}

/// One pair setup with `peer`, then the cache written and the record saved. Whether it
/// was all done (already said, either way).
#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn with_peer(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    storage: Storage,
    record: &mut ShareRecord,
    peer: u8,
    pool: &mut catcard_entropy::EntropyPool,
) -> bool {
    let me = record.member();
    let (a, b) = (me.min(peer), me.max(peer));
    let wallet = record.wallet_id();
    let mut short = [0u8; 8];
    short.copy_from_slice(&wallet[..8]);
    let invitation = Invitation::Pair {
        wallet: short,
        a,
        b,
    };
    let Some((id, start)) = find_or_start(ui, storage, invitation, me, peer) else {
        return false;
    };
    // The pair's new OT seeds are secret: gathered from every chip as for a new wallet.
    let Some(mut fresh) = Fresh::gather(gate, ui, pool) else {
        return false;
    };
    let mut busy = Some(menu::blocking_screen(
        ui.panel,
        HEAD,
        "making this member's keys",
    ));
    let made = crate::keywork::run(|kw| Session::pair_setup(id, record, peer, &mut fresh, kw));
    drop(fresh);
    busy.take();
    let mut session = match made {
        Ok(s) => s,
        Err(e) => {
            say(ui, HEAD, "cannot start:", describe(&e));
            return false;
        }
    };
    crate::catlog!(
        "tss: pair setup {} member {} with {}",
        card::short_id(&id).as_str(),
        me,
        peer
    );
    if !drive::run(ui, storage, &mut session, start.then_some(invitation)) {
        return false;
    }
    let installed = crate::keywork::run(|kw| session.install_pair(record, kw));
    drop(session);
    if let Err(e) = installed {
        say(ui, HEAD, "not installed:", describe(&e));
        return false;
    }
    let kept = keep(gate, login, ui, storage, record, HEAD);
    drive::pass_on(ui, storage, peer);
    match kept {
        Ok(_) => {
            let mut a: Line = Line::new();
            let _ = write!(a, "set up with member {peer}");
            say(ui, HEAD, &a, "and kept");
            true
        }
        Err(why) => {
            say(ui, HEAD, why, "set it up again");
            false
        }
    }
}

/// The session to run with `peer`: the lower member starts one, the higher finds it on
/// the medium. `(id, whether this device starts it)`.
#[inline(never)]
fn find_or_start(
    ui: &mut Ui<'_>,
    storage: Storage,
    invitation: Invitation,
    me: u8,
    peer: u8,
) -> Option<([u8; SESSION_ID_LEN], bool)> {
    if me < peer {
        let id = catcard_tss::new_session_id(&mut Drbg(ui.drbg)).ok()?;
        let mut main: Line = Line::new();
        let _ = write!(main, "Session {}", card::short_id(&id));
        let mut a: Line = Line::new();
        let _ = write!(a, "With member {peer}, who picks member {me} there.");
        return approve(
            ui,
            "Start the setup?",
            &main,
            &[a.as_str(), "This device starts it."],
            "start",
            "back",
        )
        .then_some((id, true));
    }
    loop {
        card::wait(ui.panel, HEAD, storage, false);
        let found = card::sessions(storage).unwrap_or_default();
        let ids: heapless::Vec<[u8; SESSION_ID_LEN], { card::MAX_SESSIONS }> = found
            .iter()
            .filter(|s| s.invite == invitation && s.taken & (1 << me) == 0)
            .map(|s| s.id)
            .collect();
        if ids.len() == 1 {
            return Some((ids[0], false));
        }
        if ids.len() > 1 {
            let labels: heapless::Vec<heapless::String<8>, { card::MAX_SESSIONS }> =
                ids.iter().map(card::short_id).collect();
            let rows: heapless::Vec<&str, { card::MAX_SESSIONS }> =
                labels.iter().map(|l| l.as_str()).collect();
            let pick = menu::pick_row(ui, HEAD, "which session? (on its screen)", &rows)?;
            return Some((ids[pick], false));
        }
        let mut wait: heapless::String<96> = heapless::String::new();
        let _ = write!(
            wait,
            "Member {peer} starts it: run Rebuild setup there, pick member {me}, then bring the files here."
        );
        match menu::pick_row(ui, HEAD, &wait, &["Look again", "Back"]) {
            Some(0) => continue,
            _ => return None,
        }
    }
}
