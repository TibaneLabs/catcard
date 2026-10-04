//! Driving a session to its end over a medium: the same loop for create together and
//! for a pair setup, run by every member, driven by the session alone and never by round
//! numbers:
//!
//! 1. write what the session has to say (`take_outbox`) to the medium;
//! 2. read every file the session is waiting for (`awaiting`) that is on it, and hand
//!    each to it;
//! 3. when every identity is in, show the session code and go on only once the owner
//!    says it is the same on every device;
//! 4. when nothing more can be read, say whom the files go to next, and wait for them.
//!
//! The session only ever sees envelope bytes and the names they travel under; which
//! medium carries them is [`Storage`]'s business, here and nowhere else in the loop. A
//! QR transport (stage 2) is another way of doing steps 1, 2 and 4.

use alloc::vec::Vec;
use catcard_tss::{Outgoing, Session, Status};
use core::fmt::Write as _;

use super::card::{self, Invitation};
use super::{approve, describe, say};
use crate::menu::{self, Line, Storage};
use crate::ui::Ui;

/// Run `s` over `storage` until it finishes: `true` then, `false` when it failed or the
/// owner left (already said). `invite` is written with the first messages, by the member
/// who starts the session.
#[inline(never)]
pub(super) fn run(
    ui: &mut Ui<'_>,
    storage: Storage,
    s: &mut Session,
    mut invite: Option<Invitation>,
) -> bool {
    let id = *s.id();
    let me = s.me();
    let mut who: heapless::String<24> = heapless::String::new();
    match s.peer() {
        Some(peer) => {
            let _ = write!(who, "Member {me} with {peer}");
        }
        None => {
            let _ = write!(who, "Member {me} of {}", s.members().len());
        }
    }
    // Written to the medium before anything else happens: the outbox is taken once, so
    // what could not be written waits here for the next try.
    let mut pending: Vec<Outgoing> = Vec::new();
    let mut refused: Line = Line::new();
    // Bounded: every pass either moves the session, or waits for the owner, who can
    // abandon it. A session has a handful of rounds; this is far more passes than one
    // can use.
    for _ in 0..256 {
        pending.extend(s.take_outbox());
        if !pending.is_empty() {
            card::wait(ui.panel, &who, storage, true);
            match card::write_messages(storage, &id, &pending, invite) {
                Ok(()) => {
                    pending.clear();
                    invite = None;
                }
                Err(why) => {
                    if !retry(ui, &who, "cannot write the files:", why) {
                        return false;
                    }
                    continue;
                }
            }
        }
        match s.status() {
            Status::Finished => return true,
            Status::Failed => {
                crate::catlog!("tss: session failed: {}", s.failure().unwrap_or("?"));
                say(ui, &who, "the session failed:", "start a new one");
                return false;
            }
            Status::Comparing => {
                if !compare(ui, s, &who) {
                    return false;
                }
                continue;
            }
            Status::Introducing | Status::Running => {}
        }
        let wanted = s.awaiting();
        if wanted.is_empty() {
            continue;
        }
        card::wait(ui.panel, &who, storage, false);
        refused.clear();
        let got = match card::read_messages(storage, &id, &wanted) {
            Ok(g) => g,
            Err(why) => {
                // No card, or one that will not mount: said on the waiting screen.
                refused.clear();
                let _ = write!(refused, "{}: {why}", storage.medium());
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
        if !wait_for_files(ui, storage, s, &who, &wanted, &refused) {
            return false;
        }
    }
    say(ui, &who, "the session did not", "finish");
    false
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

/// Nothing more to read for now: say whom the files go to next, and wait for them to
/// come back. `false` if the owner abandons the session.
#[inline(never)]
fn wait_for_files(
    ui: &mut Ui<'_>,
    storage: Storage,
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
    let mut note: heapless::String<160> = heapless::String::new();
    let _ = write!(note, "Step {step} of {}. ", s.rounds() + 1);
    match storage {
        Storage::Sd => {
            let _ = write!(note, "Pass the card to member {next}");
        }
        Storage::Vdisk => {
            let _ = write!(
                note,
                "Copy the TSS folder between this Virtual Disk and member {next}'s"
            );
        }
    }
    if from.len() > 1 {
        let _ = note.push_str(" (waiting for members");
        for m in from.iter() {
            let _ = write!(note, " {m}");
        }
        let _ = note.push(')');
    }
    let _ = note.push_str(match storage {
        Storage::Sd => ", then put it back here.",
        Storage::Vdisk => ", then go on here.",
    });
    if !refused.is_empty() {
        let _ = write!(note, " Note: {refused}.");
    }
    let back = match storage {
        Storage::Sd => "The card is back",
        Storage::Vdisk => "The files are back",
    };
    loop {
        match menu::pick_row(ui, who, &note, &[back, "Leave the session"]) {
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

/// A medium that would not take what was written: try again, or give up.
#[inline(never)]
fn retry(ui: &mut Ui<'_>, who: &str, what: &str, why: &str) -> bool {
    menu::message(ui.panel, who, what, why);
    menu::wait_for_any_key(ui);
    menu::pick_row(
        ui,
        who,
        "check the card or disk",
        &["Try again", "Leave the session"],
    ) == Some(0)
}
