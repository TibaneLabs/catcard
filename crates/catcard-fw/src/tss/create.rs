//! Create together: `n` devices make a new key between them (docs/TSS.md, "Create
//! together"), passing an SD card -- or several, or the files on their Virtual Disks --
//! from one to the next.
//!
//! Member 1 starts the session and writes its invitation in the session's folder; the
//! others find it on the medium and choose their member number. From then on every
//! member runs the same loop (`super::drive`).
//!
//! At the end each member keeps its key core in its settings and writes its pair cache
//! beside the session's files: on a card it is kept until a card is lost, on the Virtual
//! Disk until the power goes off -- either way a lost cache is set up again before the
//! next signature, not a lost wallet. The session lives in this device's memory only:
//! leaving the screen abandons it, and the members start again with a new one.

use catcard_tss::{SESSION_ID_LEN, Session};
use core::fmt::Write as _;

use super::card::{self, Invitation};
use super::rand::{Drbg, Pool};
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
    let Some(storage) = menu::pick_storage(ui, HEAD) else {
        return;
    };
    let Some((id, n, t, me, start)) = setup(ui, storage) else {
        return;
    };
    if !Room::fits(ui, HEAD, Work::Create, n, 0) {
        return;
    }
    let mut busy = Some(menu::blocking_screen(
        ui.panel,
        HEAD,
        "making this member's keys",
    ));
    let made = crate::keywork::run(|kw| Session::keygen(id, n, t, me, &mut Pool { pool }, kw));
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
    if !drive::run(ui, storage, &mut session, invite) {
        return;
    }
    let record = crate::keywork::run(|kw| session.take_share(kw));
    drop(session);
    let Some(mut record) = record else {
        return say(ui, HEAD, "the session ended", "with no share");
    };
    let kept = keep(gate, login, ui, storage, &mut record, HEAD);
    // The pair cache is on the medium now: it can move on.
    drive::pass_on(ui, storage, me % n + 1);
    match kept {
        Ok(summary) => view::created(ui, &summary),
        Err(why) => say(ui, "Not kept", why, "the share is lost"),
    }
}

/// Start a session or join one: its id, `n`, `t`, this member's number, and whether
/// this device starts it.
#[inline(never)]
fn setup(ui: &mut Ui<'_>, storage: Storage) -> Option<([u8; SESSION_ID_LEN], u8, u8, u8, bool)> {
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
                    "You are member 1. The invitation in the files tells the others.",
                ];
                if approve(ui, "Start session?", &main, &small, "start", "back") {
                    return Some((id, n, t, 1, true));
                }
            }
            1 => {
                if let Some(joined) = join(ui, storage) {
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
             others'. Without a card, the files can go between the devices' Virtual \
             Disks instead.",
        )
        .small(),
        Row::body(
            "Member 1 starts the session. The others join it, each with its own \
             member number.",
        )
        .small(),
        Row::body(
            "When every member is in, each device shows the same eight words. Check \
             they match on every device before going on.",
        )
        .small(),
        Row::body(
            "Then pass the files round as the screen says until every device has its \
             share. Keep every device on this screen until then.",
        )
        .small(),
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
    let _ = write!(main, "Session {}", card::short_id(&id));
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
    Some((id, n, t, me, false))
}
