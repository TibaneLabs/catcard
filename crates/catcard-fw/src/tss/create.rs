//! Create together: `n` devices make a new key between them (docs/TSS.md, "Create
//! together"), passing an SD card from one to the next -- or, between Q1s, showing and
//! scanning QR codes (`super::qr`). Never the Virtual Disk: it cannot move between
//! devices.
//!
//! Member 1 starts the session and writes its invitation in the session's folder (by QR,
//! in every code it shows); the others find it on the card, or scan member 1's first
//! code, and choose their member number. From then on every member runs the same loop
//! (`super::drive`).
//!
//! At the end each member keeps its key core in its settings and writes its pair cache
//! beside the session's files on the card, or by QR on its own Virtual Disk until the
//! power goes off -- either way a lost cache is set up again before the next signature,
//! not a lost wallet. The session lives in this device's memory only:
//! leaving the screen abandons it, and the members start again with a new one.

use catcard_tss::{SESSION_ID_LEN, Session};
use core::fmt::Write as _;

use super::card::{self, Invitation};
use super::drive::{Medium, Way};
use super::rand::{Drbg, Fresh};
use super::{Room, Work, approve, describe, drive, keep, say, view};
use crate::menu::{self, Line, Storage};
use crate::ui::Ui;

const HEAD: &str = "Create together";

/// The whole flow, from the first question to the kept record.
#[inline(never)]
pub(super) fn create(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    pool: Option<&mut catcard_entropy::EntropyPool>,
) {
    let Some(pool) = pool else {
        return say(ui, HEAD, "the pool missed its", "policy at boot");
    };
    let Some(_room) = Room::take(ui, HEAD) else {
        return;
    };
    let Some(way) = drive::pick_way(ui, HEAD) else {
        return;
    };
    let Some((id, n, t, me, start, mut medium)) = setup(ui, way) else {
        return;
    };
    if !Room::fits(ui, HEAD, Work::Create, n, 0) {
        return;
    }
    // This member's randomness -- its share of the new key among it -- gathered from
    // every chip as for a new wallet.
    let Some(mut fresh) = Fresh::gather(gate, ui, pool) else {
        return;
    };
    let mut busy = Some(menu::blocking_screen(
        ui.panel,
        HEAD,
        "making this member's keys",
    ));
    let made = crate::keywork::run(|kw| Session::keygen(id, n, t, me, &mut fresh, kw));
    drop(fresh);
    busy.take();
    let mut session = match made {
        Ok(s) => s,
        Err(e) => return say(ui, HEAD, "cannot start:", describe(&e)),
    };
    crate::catlog!(
        "tss: session {} member {} of {}, {} needed",
        card::short_id(&id).as_str(),
        me,
        n,
        t
    );
    let invite = start.then_some(Invitation::Create { n, t });
    if !drive::run(ui, &mut medium, &mut session, invite) {
        return;
    }
    let record = crate::keywork::run(|kw| session.take_share(kw));
    drop(session);
    let Some(mut record) = record else {
        return say(ui, HEAD, "the session ended", "with no share");
    };
    let kept = keep(gate, login, ui, way.files(), &mut record, HEAD);
    // The pair cache is on the card now: it can move on. (By QR the last codes were
    // shown before the session ended.)
    if way == Way::Sd {
        drive::pass_on(ui, me % n + 1);
    }
    match kept {
        Ok(summary) => view::created(gate, login, ui, &summary),
        Err(why) => say(ui, "Not kept", why, "the share is lost"),
    }
}

/// What [`setup`] settles: the session's id, `n`, `t`, this member's number, whether this
/// device starts it, and the medium its messages go by.
type Setup = ([u8; SESSION_ID_LEN], u8, u8, u8, bool, Medium);

/// The medium for a session this device starts.
fn medium(way: Way, id: [u8; SESSION_ID_LEN], invite: Invitation) -> Medium {
    match way {
        Way::Sd => {
            let _ = (id, invite);
            Medium::Sd
        }
        #[cfg(feature = "board-q1")]
        Way::Qr => Medium::Qr(super::qr::Exchange::new(id, Some(invite))),
    }
}

/// Start a session or join one.
#[inline(never)]
fn setup(ui: &mut Ui<'_>, way: Way) -> Option<Setup> {
    let most = Room::most_members(Work::Create, |_| 0);
    if most < 3 {
        say(ui, HEAD, "not enough memory", "for a new wallet");
        return None;
    }
    loop {
        match menu::pick_row(
            ui,
            HEAD,
            "every member does this",
            &["Start: I am member 1", "Join a session", "How it works"],
        )? {
            0 => {
                let (n, t) = ask_shape(ui, most)?;
                let id = catcard_tss::new_session_id(&mut Drbg(ui.drbg)).ok()?;
                let mut main: Line = Line::new();
                let _ = write!(main, "Session {}", card::short_id(&id));
                let mut a: Line = Line::new();
                let _ = write!(a, "{n} members, {t} needed to sign.");
                let small = [
                    a.as_str(),
                    "You are member 1. Your first message tells the others.",
                ];
                if approve(ui, "Start session?", &main, &small, "start", "back") {
                    let m = medium(way, id, Invitation::Create { n, t });
                    return Some((id, n, t, 1, true, m));
                }
            }
            1 => {
                let joined = match way {
                    Way::Sd => join(ui, Storage::Sd)
                        .map(|(id, n, t, me, start)| (id, n, t, me, start, Medium::Sd)),
                    #[cfg(feature = "board-q1")]
                    Way::Qr => join_by_qr(ui),
                };
                if let Some(joined) = joined {
                    return Some(joined);
                }
            }
            _ => explain(ui),
        }
    }
}

#[inline(never)]
fn explain(ui: &mut Ui<'_>) {
    use catcard_ui::scroll::Line as Row;
    let rows = [
        Row::title(HEAD),
        Row::body(
            "Every member's CatCard runs this screen at the same time. One SD card \
             goes from device to device; each writes its messages to it and reads the \
             others'. Between Q1s, each can show its messages as a QR code and scan \
             the others' instead.",
        )
        .small()
        .wrapped(),
        Row::body(
            "Member 1 starts the session. The others join it, each with its own \
             member number.",
        )
        .small()
        .wrapped(),
        Row::body(
            "When every member is in, each device shows the same eight words. Check \
             they match on every device before going on.",
        )
        .small()
        .wrapped(),
        Row::body(
            "Then pass the card, or show and scan the codes, as the screen says until \
             every device has its share. Keep every device on this screen until then.",
        )
        .small()
        .wrapped(),
    ];
    let _ = menu::show_doc(ui, &rows, false, false);
}

/// `n` and `t`, refusing the shapes colluding members could bias.
#[inline(never)]
fn ask_shape(ui: &mut Ui<'_>, most: u8) -> Option<(u8, u8)> {
    let mut range: heapless::String<16> = heapless::String::new();
    let _ = write!(range, "3 to {most}");
    let n = match menu::ask_number(ui, HEAD, Some(("members", &range)), "how many", "")? {
        n if (3..=u32::from(most)).contains(&n) => n as u8,
        2 => {
            say(ui, HEAD, "2-of-3 is the usual", "minimum to create");
            return None;
        }
        _ => {
            say(ui, HEAD, "members must be", &range);
            return None;
        }
    };
    // The largest t a DKG of n members can safely have (`can_create_together`).
    let top = (2..=n)
        .rev()
        .find(|&t| catcard_tss::can_create_together(n, t))
        .unwrap_or(2);
    let mut range: heapless::String<16> = heapless::String::new();
    let _ = write!(range, "2 to {top}");
    let t = menu::ask_number(ui, HEAD, Some(("needed to sign", &range)), "how many", "")?;
    match t {
        t if (2..=u32::from(top)).contains(&t) => Some((n, t as u8)),
        // More needed than a DKG can make safely: colluders who move last could bias
        // the new key (`can_create_together`).
        t if t > u32::from(top) && t <= u32::from(n) => {
            say(ui, HEAD, "too many needed:", "a few could bias the key");
            None
        }
        _ => {
            say(ui, HEAD, "needed must be", &range);
            None
        }
    }
}

/// Join by scanning member 1's first code: the session and its shape are in it; the
/// member number is chosen here, as nothing shows which are taken.
#[cfg(feature = "board-q1")]
#[inline(never)]
fn join_by_qr(ui: &mut Ui<'_>) -> Option<Setup> {
    let mut found = match super::qr::find(ui, HEAD) {
        Ok(Some(f)) => f,
        Ok(None) => return None,
        Err(why) => {
            say(ui, HEAD, "not read:", why);
            return None;
        }
    };
    let Invitation::Create { n, t } = found.invite else {
        say(ui, HEAD, "not a new-wallet", "session's code");
        return None;
    };
    if !catcard_tss::can_create_together(n, t) {
        say(ui, HEAD, "not a shape this", "device creates");
        return None;
    }
    let me = pick_number(ui, &found.id, n, t, 0)?;
    Some((found.id, n, t, me, false, Medium::Qr(found.exchange(me))))
}

/// Pick a session on the medium and a free member number in it.
#[inline(never)]
fn join(ui: &mut Ui<'_>, storage: Storage) -> Option<([u8; SESSION_ID_LEN], u8, u8, u8, bool)> {
    card::wait(ui.panel, HEAD, storage, false);
    let found = match card::sessions(storage) {
        Ok(f) => f,
        Err(why) => {
            say(ui, HEAD, "cannot read the files:", why);
            return None;
        }
    };
    let mut ids: heapless::Vec<([u8; SESSION_ID_LEN], u8, u8, u16), { card::MAX_SESSIONS }> =
        heapless::Vec::new();
    for s in found.iter() {
        if let Invitation::Create { n, t } = s.invite {
            let _ = ids.push((s.id, n, t, s.taken));
        }
    }
    if ids.is_empty() {
        say(ui, HEAD, "no session here:", "member 1 starts one");
        return None;
    }
    let mut labels: heapless::Vec<Line, { card::MAX_SESSIONS }> = heapless::Vec::new();
    for (id, n, t, _) in ids.iter() {
        let mut l = Line::new();
        let _ = write!(l, "{}: {} of {}", card::short_id(id), t, n);
        let _ = labels.push(l);
    }
    let rows: heapless::Vec<&str, { card::MAX_SESSIONS }> =
        labels.iter().map(|l| l.as_str()).collect();
    let pick = menu::pick_row(ui, HEAD, "which session?", &rows)?;
    let (id, n, t, taken) = ids[pick];
    let me = pick_number(ui, &id, n, t, taken)?;
    Some((id, n, t, me, false))
}

/// This member's number in session `id` (`n` members, `t` needed): one of `2..=n` not in
/// `taken` (bit `m` set: member `m` has joined), confirmed with the session's shape.
#[inline(never)]
fn pick_number(ui: &mut Ui<'_>, id: &[u8; SESSION_ID_LEN], n: u8, t: u8, taken: u16) -> Option<u8> {
    let mut numbers: heapless::Vec<heapless::String<4>, 9> = heapless::Vec::new();
    let mut members: heapless::Vec<u8, 9> = heapless::Vec::new();
    for m in 2..=n {
        if taken & (1 << m) == 0 {
            let mut l = heapless::String::new();
            let _ = write!(l, "{m}");
            let _ = numbers.push(l);
            let _ = members.push(m);
        }
    }
    if members.is_empty() {
        say(ui, HEAD, "every member of that", "session has joined");
        return None;
    }
    let rows: heapless::Vec<&str, 9> = numbers.iter().map(|l| l.as_str()).collect();
    let me = members[menu::pick_row(ui, HEAD, "your member number", &rows)?];
    let mut main: Line = Line::new();
    let _ = write!(main, "Session {}", card::short_id(id));
    let mut a: Line = Line::new();
    let _ = write!(a, "{n} members, {t} needed to sign.");
    let mut b: Line = Line::new();
    let _ = write!(b, "You are member {me}.");
    if !approve(
        ui,
        "Join session?",
        &main,
        &[a.as_str(), b.as_str()],
        "join",
        "back",
    ) {
        return None;
    }
    Some(me)
}
