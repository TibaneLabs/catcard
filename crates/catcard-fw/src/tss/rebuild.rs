//! Rebuild setup: make this member's pairs again with the other members present, all in
//! one session (docs/TSS.md, "Where things live").
//!
//! Signing needs, between every two signers, the pairwise state their two devices set up
//! together. A member keeps its own in a pair cache on a card or the Virtual Disk, so it
//! is lost with the card, at every power-off on the disk, and never there at all for a
//! share taken in from an export. None of that is a failure: two members make their pair
//! again in a short session of their own, which changes no share, no address and no other
//! pair.
//!
//! One member starts it and ticks who is here -- every other member to begin with; the
//! others join, each with the member number its share already says. Every pair among
//! them is made again in the one session (`catcard_tss::Session::pairs_setup`): each its
//! own two-party base-OT exchange, all under one set of introductions and one session
//! code, every pair's messages for a round in the same pass of the card or code. At the
//! end each member installs its new pairs and writes its cache once.

use alloc::vec::Vec;
use catcard_tss::{CacheKey, CacheRefused, Error, Session, ShareRecord};
use core::fmt::Write as _;

use super::card::{self, Invitation};
use super::drive::Way;
use super::rand::{Drbg, Fresh};
use super::store::{self, Kept};
use super::{Room, Work, describe, drive, keep, say};
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
    let Some(way) = drive::pick_way(ui, HEAD) else {
        return;
    };
    // Where this member's pair cache is: on the card passed round, or by QR on this
    // device's own Virtual Disk.
    let storage = way.files();
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

    let me = record.member();
    let lacking = missing(&record);
    let mut note: heapless::String<64> = heapless::String::new();
    if lacking.is_empty() {
        let _ = note.push_str("set up with every member");
    } else {
        let _ = note.push_str("missing with ");
        members_text(&mut note, &lacking);
    }
    let mut wallet = [0u8; 8];
    wallet.copy_from_slice(&record.wallet_id()[..8]);
    let (id, members, start, mut medium) = match menu::pick_row(
        ui,
        HEAD,
        &note,
        &["Start: choose who is here", "Join a session"],
    ) {
        Some(0) => {
            let Some(members) = choose_members(ui, &record) else {
                return;
            };
            let Some(id) = catcard_tss::new_session_id(&mut Drbg(ui.drbg)).ok() else {
                return;
            };
            let invite = Invitation::Pairs {
                wallet,
                members: drive::set_of(&members),
            };
            (id, members, true, drive::start_medium(way, id, invite))
        }
        Some(_) => {
            let Some((id, set, medium)) = drive::join(ui, HEAD, way, me, |inv| match inv {
                Invitation::Pairs { wallet: w, members } if w == wallet => Some(members),
                _ => None,
            }) else {
                return;
            };
            (id, drive::members_of(set), false, medium)
        }
        None => return,
    };

    // The pairs' new OT seeds are secret: gathered from every chip as for a new wallet.
    let Some(mut fresh) = Fresh::gather(gate, ui, pool) else {
        return;
    };
    let mut busy = Some(menu::blocking_screen(
        ui.panel,
        HEAD,
        "making this member's keys",
    ));
    let made =
        crate::keywork::run(|kw| Session::pairs_setup(id, &record, &members, &mut fresh, kw));
    drop(fresh);
    busy.take();
    let mut session = match made {
        Ok(s) => s,
        Err(e) => return say(ui, HEAD, "cannot start:", describe(&e)),
    };
    crate::catlog!(
        "tss: pair setup {} member {} of {} members",
        card::short_id(&id).as_str(),
        me,
        members.len()
    );
    let invite = start.then_some(Invitation::Pairs {
        wallet,
        members: drive::set_of(&members),
    });
    if !drive::run(ui, &mut medium, &mut session, invite) {
        return;
    }
    let installed = crate::keywork::run(|kw| session.install_pairs(&mut record, kw));
    drop(session);
    let peers = match installed {
        Ok(p) => p,
        Err(e) => return say(ui, HEAD, "not installed:", describe(&e)),
    };
    let kept = keep(gate, login, ui, storage, &mut record, HEAD);
    if way == Way::Sd
        && let Some(&next) = members.iter().find(|&&m| m > me).or(members.first())
    {
        drive::pass_on(ui, next);
    }
    match kept {
        Ok(_) => {
            let mut a: heapless::String<64> = heapless::String::new();
            let _ = a.push_str("set up with ");
            members_text(&mut a, &peers);
            say(ui, HEAD, &a, "and kept");
        }
        Err(why) => say(ui, HEAD, why, "set it up again"),
    }
}

/// Who takes part: this member and those ticked -- every other member to begin with,
/// untick the ones not here. At least one other.
fn choose_members(ui: &mut Ui<'_>, record: &ShareRecord) -> Option<Vec<u8>> {
    let me = record.member();
    let others: heapless::Vec<u8, 9> = (1..=record.n()).filter(|&m| m != me).collect();
    let labels: heapless::Vec<Line, 9> = others
        .iter()
        .map(|m| {
            let mut l = Line::new();
            let _ = write!(l, "Member {m}");
            l
        })
        .collect();
    let mut rows: heapless::Vec<menu::Toggle<'_>, 9> = labels
        .iter()
        .map(|l| menu::Toggle {
            line: catcard_ui::scroll::Line::body(l.as_str()),
            on: true,
        })
        .collect();
    loop {
        menu::toggle_list(ui, HEAD, "who is here", &mut rows, "Start")?;
        let mut chosen: Vec<u8> = alloc::vec![me];
        chosen.extend(
            others
                .iter()
                .zip(rows.iter())
                .filter(|(_, r)| r.on)
                .map(|(&m, _)| m),
        );
        if chosen.len() >= 2 {
            chosen.sort_unstable();
            return Some(chosen);
        }
        say(ui, HEAD, "choose at least one", "other member");
    }
}
