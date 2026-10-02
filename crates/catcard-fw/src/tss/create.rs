//! Create together: `n` devices make a new key between them (docs/TSS.md, "Create
//! together"), passing an SD card -- or several -- from one to the next.
//!
//! Member 1 starts the session and writes its invitation in the session's folder; the
//! others find it on the card and choose their member number. From then on every member
//! runs the same loop, driven by the session alone and never by round numbers:
//!
//! 1. write what the session has to say (`take_outbox`) to the card;
//! 2. read every file the session is waiting for (`awaiting`) that is on the card, and
//!    hand each to it;
//! 3. when every identity is in, show the session code and go on only once the owner
//!    says it is the same on every device;
//! 4. when nothing more can be read, say whom to pass the card to, and wait for it.
//!
//! The session lives in this device's memory only: leaving the screen abandons it, and
//! the members start again with a new one.

use alloc::vec::Vec;
use catcard_settings::tss::FileKey;
use catcard_tss::{Outgoing, SESSION_ID_LEN, Session, Status};
use core::fmt::Write as _;

use super::rand::{Drbg, Pool};
use super::{Room, Work, approve, card, describe, record_len, say, store, view};
use crate::menu::{self, Line};
use crate::ui::Ui;

const HEAD: &str = "Create together";

/// The whole flow, from the first question to the kept share.
#[inline(never)]
pub(super) fn create(
    ui: &mut Ui<'_>,
    key: &FileKey,
    pool: Option<&mut catcard_entropy::EntropyPool>,
) {
    let Some(pool) = pool else {
        return say(ui, HEAD, "the pool missed its", "policy at boot");
    };
    let Some(_room) = Room::take(ui, HEAD) else {
        return;
    };
    let Some((id, n, t, me, start)) = setup(ui) else {
        return;
    };
    if !Room::fits(ui, HEAD, Work::Encode, n, 2 * record_len(n)) {
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
    let invite = start.then_some((n, t));
    let Some(mut record) = run(ui, &mut session, invite) else {
        return;
    };
    drop(session);
    match store::save(ui, key, record.as_slice()) {
        Ok(()) => view::created(ui, record.as_slice()),
        Err(why) => say(ui, "Not kept", why, "the share is lost"),
    }
}

/// Start a session or join one: its id, `n`, `t`, this member's number, and whether
/// this device starts it.
#[inline(never)]
fn setup(ui: &mut Ui<'_>) -> Option<([u8; SESSION_ID_LEN], u8, u8, u8, bool)> {
    let most = Room::most_members(Work::Encode, |n| 2 * record_len(n));
    if most < 3 {
        say(ui, HEAD, "not enough memory", "for a new wallet");
        return None;
    }
    loop {
        match menu::pick_row(
            ui,
            HEAD,
            "every member does this",
            &[
                "Start: I am member 1",
                "Join a session on card",
                "How it works",
            ],
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
                    "You are member 1. The card's invitation tells the others.",
                ];
                if approve(ui, "Start session?", &main, &small, "start", "back") {
                    return Some((id, n, t, 1, true));
                }
            }
            1 => {
                if let Some(joined) = join(ui) {
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
             others'.",
        )
        .small(),
        Row::body(
            "Member 1 starts the session. The others insert the card and join it, \
             each with its own member number.",
        )
        .small(),
        Row::body(
            "When every member is in, each device shows the same eight words. Check \
             they match on every device before going on.",
        )
        .small(),
        Row::body(
            "Then pass the card round as the screen says until every device has its \
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

/// Pick a session from the card and a free member number in it.
#[inline(never)]
fn join(ui: &mut Ui<'_>) -> Option<([u8; SESSION_ID_LEN], u8, u8, u8, bool)> {
    menu::card_wait(ui.panel, HEAD, "looking for sessions");
    let found = match card::sessions() {
        Ok(f) => f,
        Err(why) => {
            say(ui, HEAD, "cannot read the card:", why);
            return None;
        }
    };
    if found.is_empty() {
        say(ui, HEAD, "no session on this card:", "member 1 starts one");
        return None;
    }
    let mut labels: heapless::Vec<Line, { card::MAX_SESSIONS }> = heapless::Vec::new();
    for s in found.iter() {
        let mut l = Line::new();
        let _ = write!(l, "{}: {} of {}", card::short_id(&s.id), s.t, s.n);
        let _ = labels.push(l);
    }
    let rows: heapless::Vec<&str, { card::MAX_SESSIONS }> =
        labels.iter().map(|l| l.as_str()).collect();
    let pick = menu::pick_row(ui, HEAD, "which session?", &rows)?;
    let s = &found[pick];

    let mut numbers: heapless::Vec<heapless::String<4>, 9> = heapless::Vec::new();
    let mut members: heapless::Vec<u8, 9> = heapless::Vec::new();
    for m in 2..=s.n {
        if s.taken & (1 << m) == 0 {
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
    let _ = write!(main, "Session {}", card::short_id(&s.id));
    let mut a: Line = Line::new();
    let _ = write!(a, "{} members, {} needed to sign.", s.n, s.t);
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
    Some((s.id, s.n, s.t, me, false))
}

/// Run the session over the card to its end: the share record, encoded, or `None` when
/// it failed or the owner left (already said).
#[inline(never)]
fn run(ui: &mut Ui<'_>, s: &mut Session, mut invite: Option<(u8, u8)>) -> Option<super::Buf> {
    let id = *s.id();
    let n = s.members().len() as u8;
    let me = s.me();
    let mut who: heapless::String<24> = heapless::String::new();
    let _ = write!(who, "Member {me} of {n}");
    // Written to the card before anything else happens: the outbox is taken once, so
    // what could not be written waits here for the next try.
    let mut pending: Vec<Outgoing> = Vec::new();
    let mut refused: Line = Line::new();
    // Bounded: every pass either moves the session, or waits for the owner, who can
    // abandon it. A session has a handful of rounds; this is far more passes than one
    // can use.
    for _ in 0..256 {
        pending.extend(s.take_outbox());
        if !pending.is_empty() {
            menu::card_wait(ui.panel, &who, "writing to the card");
            match card::write_messages(&id, &pending, invite) {
                Ok(()) => {
                    pending.clear();
                    invite = None;
                }
                Err(why) => {
                    if !retry(ui, &who, "cannot write the card:", why) {
                        return None;
                    }
                    continue;
                }
            }
        }
        match s.status() {
            Status::Finished => {
                let mut busy = Some(menu::blocking_screen(ui.panel, &who, "saving the share"));
                let bytes = crate::keywork::run(|kw| s.share().map(|r| r.to_bytes(kw)));
                busy.take();
                return match bytes {
                    Some(Ok(b)) => super::Buf::copy_of(&b).or_else(|| {
                        say(ui, &who, "no memory", "to keep the share");
                        None
                    }),
                    _ => {
                        say(ui, &who, "the share would not", "encode");
                        None
                    }
                };
            }
            Status::Failed => {
                crate::catlog!("tss: session failed: {}", s.failure().unwrap_or("?"));
                say(ui, &who, "the session failed:", "start a new one");
                return None;
            }
            Status::Comparing => {
                if !compare(ui, s, &who) {
                    return None;
                }
                continue;
            }
            Status::Introducing | Status::Running => {}
        }
        let wanted = s.awaiting();
        if wanted.is_empty() {
            continue;
        }
        menu::card_wait(ui.panel, &who, "reading the card");
        refused.clear();
        let got = match card::read_messages(&id, &wanted) {
            Ok(g) => g,
            Err(why) => {
                // No card, or one that will not mount: said on the waiting screen.
                refused.clear();
                let _ = write!(refused, "the card: {why}");
                Vec::new()
            }
        };
        let mut moved = false;
        for (name, mut bytes) in got {
            let mut busy = Some(menu::blocking_screen(
                ui.panel,
                &who,
                "working: a few seconds",
            ));
            let taken = crate::keywork::run(|kw| s.receive(bytes.as_slice(), kw));
            busy.take();
            match taken {
                Ok(()) => moved = true,
                Err(e) => {
                    let (r, f, t) = name;
                    crate::catlog!("tss: r{}-{}-{} refused: {}", r, f, t, describe(&e));
                    refused.clear();
                    let _ = write!(refused, "member {f}'s file: {}", describe(&e));
                    if s.status() == Status::Failed {
                        break;
                    }
                }
            }
        }
        if moved || s.status() == Status::Failed {
            refused.clear();
            continue;
        }
        if !wait_for_card(ui, s, &who, &wanted, &refused) {
            return None;
        }
    }
    say(ui, &who, "the session did not", "finish");
    None
}

/// The session code, and the owner's word that it is the same on every device.
#[inline(never)]
fn compare(ui: &mut Ui<'_>, s: &mut Session, who: &str) -> bool {
    use catcard_ui::scroll::Line as Row;
    let Some(code) = s.code() else {
        return false;
    };
    let words = code.words();
    let mut pairs: heapless::Vec<Line, 4> = heapless::Vec::new();
    for (i, w) in words.chunks(2).enumerate() {
        let mut l = Line::new();
        let _ = write!(
            l,
            "{}. {}  {}. {}",
            2 * i + 1,
            w[0],
            2 * i + 2,
            w.get(1).unwrap_or(&"")
        );
        let _ = pairs.push(l);
    }
    let mut rows: heapless::Vec<Row<'_>, 8> = heapless::Vec::new();
    let _ = rows.push(Row::title("Session code"));
    for l in pairs.iter() {
        let _ = rows.push(Row::body(l.as_str()));
    }
    let _ = rows.push(
        Row::body("Every member's device must show these same words, in this order.").small(),
    );
    loop {
        let _ = menu::show_doc(ui, &rows, false, false);
        match menu::pick_row(
            ui,
            who,
            "same words on every device?",
            &[
                "Yes, the same on all",
                "Show them again",
                "No: stop the session",
            ],
        ) {
            Some(0) => break,
            Some(1) => continue,
            _ => {
                if approve(
                    ui,
                    "Stop the session?",
                    "The words differ, or you are not sure.",
                    &["Someone may be between the devices. Start a new session."],
                    "stop",
                    "back",
                ) {
                    return false;
                }
            }
        }
    }
    let mut busy = Some(menu::blocking_screen(
        ui.panel,
        who,
        "working: a few seconds",
    ));
    let done = crate::keywork::run(|kw| s.confirm(kw));
    busy.take();
    match done {
        Ok(()) => true,
        Err(e) => {
            say(ui, who, "cannot go on:", describe(&e));
            false
        }
    }
}

/// Nothing more on the card for now: say whom it goes to next, and wait for it to come
/// back. `false` if the owner abandons the session.
#[inline(never)]
fn wait_for_card(
    ui: &mut Ui<'_>,
    s: &Session,
    who: &str,
    wanted: &[(u8, u8, u8)],
    refused: &str,
) -> bool {
    let me = s.me();
    // Who still has to write, each once, ascending.
    let mut from: heapless::Vec<u8, 9> = heapless::Vec::new();
    for m in 1..=catcard_tss::MAX_MEMBERS {
        if wanted.iter().any(|w| w.1 == m) {
            let _ = from.push(m);
        }
    }
    // The next member after this one who still has to write, round the circle.
    let next = from
        .iter()
        .copied()
        .find(|&m| m > me)
        .or_else(|| from.first().copied())
        .unwrap_or(1);
    let step = wanted.first().map_or(0, |w| w.0) + 1;
    let mut note: heapless::String<120> = heapless::String::new();
    let _ = write!(
        note,
        "Step {step} of {}. Pass the card to member {next}",
        s.rounds() + 1
    );
    if from.len() > 1 {
        let _ = note.push_str(" (waiting for members");
        for m in from.iter() {
            let _ = write!(note, " {m}");
        }
        let _ = note.push(')');
    }
    let _ = note.push_str(", then put it back here.");
    if !refused.is_empty() {
        let _ = write!(note, " Note: {refused}.");
    }
    loop {
        match menu::pick_row(ui, who, &note, &["The card is back", "Leave the session"]) {
            Some(0) => return true,
            _ => {
                if approve(
                    ui,
                    "Leave the session?",
                    "Every member will have to start again.",
                    &["Nothing is kept from this session."],
                    "leave",
                    "stay",
                ) {
                    return false;
                }
            }
        }
    }
}

/// A card that would not take what was written: try again, or give up.
#[inline(never)]
fn retry(ui: &mut Ui<'_>, who: &str, what: &str, why: &str) -> bool {
    menu::message(ui.panel, who, what, why);
    menu::wait_for_any_key(ui);
    menu::pick_row(
        ui,
        who,
        "check the card",
        &["Try again", "Leave the session"],
    ) == Some(0)
}
