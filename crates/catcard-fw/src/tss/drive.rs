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
//! medium carries them is [`Medium`]'s business, here and nowhere else in the loop. A
//! QR transport (stage 2) is another way of doing steps 1, 2 and 4.

use alloc::vec::Vec;
use catcard_tss::{Outgoing, Session, Status};
use core::fmt::Write as _;

use super::card::{self, Invitation};
use super::{approve, describe, say};
use crate::menu::{self, Line, Storage};
use crate::ui::Ui;

/// How a session's messages move between the members' devices. Never the Virtual Disk:
/// it cannot go from one device to another, so it is only where a member keeps its own
/// files ([`Medium::files`]).
pub(super) enum Medium {
    /// One SD card, passed from device to device.
    Sd,
    /// Shown and scanned between Q1s (`super::qr`).
    #[cfg(feature = "board-q1")]
    Qr(super::qr::Exchange),
}

/// Which way, before a session exists to make a [`Medium`] of.
#[derive(Copy, Clone, PartialEq, Eq)]
pub(super) enum Way {
    Sd,
    #[cfg(feature = "board-q1")]
    Qr,
}

impl Way {
    /// Where this member keeps files of its own, its pair cache: the card it passes
    /// round, or -- by QR, with no card -- its Virtual Disk, which is gone at power off
    /// (the pairs are then set up again before signing).
    pub(super) fn files(self) -> Storage {
        match self {
            Way::Sd => Storage::Sd,
            #[cfg(feature = "board-q1")]
            Way::Qr => Storage::Vdisk,
        }
    }
}

/// Ask how the members' devices will exchange messages: the SD card, or on the Q1 also
/// QR codes. The mono boards have the card only, and are not asked.
pub(super) fn pick_way(ui: &mut Ui<'_>, head: &str) -> Option<Way> {
    #[cfg(feature = "board-q1")]
    {
        match menu::pick_row(ui, head, "between the devices", &["SD card", "By QR code"])? {
            0 => Some(Way::Sd),
            _ => Some(Way::Qr),
        }
    }
    #[cfg(not(feature = "board-q1"))]
    {
        let _ = (ui, head);
        Some(Way::Sd)
    }
}

/// Run `s` over `medium` until it finishes: `true` then, `false` when it failed or the
/// owner left (already said). `invite` is written with the first messages to the card,
/// by the member who starts the session (by QR, the exchange carries it).
#[inline(never)]
pub(super) fn run(
    ui: &mut Ui<'_>,
    medium: &mut Medium,
    s: &mut Session,
    mut invite: Option<Invitation>,
) -> bool {
    let storage = Storage::Sd;
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
        #[cfg(feature = "board-q1")]
        if let Medium::Qr(ex) = medium {
            ex.sent(&pending);
            pending.clear();
        }
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
            Status::Finished => {
                // By QR the others may still be owed this member's last messages, which
                // nothing but this screen can give them.
                #[cfg(feature = "board-q1")]
                if let Medium::Qr(ex) = medium {
                    super::qr::hand_over(ui, ex, s, &who);
                }
                return true;
            }
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
        refused.clear();
        let got = match medium {
            #[cfg(feature = "board-q1")]
            Medium::Qr(ex) => ex.take(&wanted),
            Medium::Sd => {
                card::wait(ui.panel, &who, storage, false);
                match card::read_messages(storage, &id, &wanted) {
                    Ok(g) => g,
                    Err(why) => {
                        // No card, or one that will not mount: said on the waiting screen.
                        let _ = write!(refused, "{}: {why}", storage.medium());
                        Vec::new()
                    }
                }
            }
        };
        let mut moved = false;
        for (name, mut bytes) in got {
            let mut busy = Some(menu::blocking_screen(
                ui.panel,
                &who,
                "working: a few seconds",
            ));
            let t0 = catcard_kernel::ticks();
            let taken = crate::keywork::run(|kw| s.receive(bytes.as_slice(), kw));
            busy.take();
            // How long each message took, to find where a session spends its time.
            crate::catlog!(
                "tss: r{}-{}-{} took {} ms",
                name.0,
                name.1,
                name.2,
                catcard_kernel::ticks()
                    .wrapping_sub(t0)
                    .wrapping_mul(catcard_kernel::TICK_MS)
            );
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
        let go_on = match medium {
            #[cfg(feature = "board-q1")]
            Medium::Qr(ex) => super::qr::wait(ui, ex, s, &who, &wanted, &refused),
            Medium::Sd => wait_for_files(ui, s, &who, &wanted, &refused),
        };
        if !go_on {
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
    // Numbered, two a line on the Q1; one a line on the mono boards, whose screen is too
    // narrow for two.
    #[cfg(feature = "board-q1")]
    const PER_LINE: usize = 2;
    #[cfg(not(feature = "board-q1"))]
    const PER_LINE: usize = 1;
    let mut lines: heapless::Vec<Line, 8> = heapless::Vec::new();
    for (i, w) in words.chunks(PER_LINE).enumerate() {
        let mut l = Line::new();
        for (j, word) in w.iter().enumerate() {
            let sep = if j == 0 { "" } else { "  " };
            let _ = write!(l, "{sep}{}. {word}", PER_LINE * i + j + 1);
        }
        let _ = lines.push(l);
    }
    let mut rows: heapless::Vec<Row<'_>, 11> = heapless::Vec::new();
    let _ = rows.push(Row::title("Session code"));
    for l in lines.iter() {
        let _ = rows.push(Row::body(l.as_str()));
    }
    // The devices reach this one at a time, as the card comes round: the first cannot
    // be compared with anything yet. Its words are written down, and every later device
    // is checked against them before it sends anything secret. A device that went on
    // ahead of a mismatch has only sent its part of a session that then stops.
    let _ = rows.push(
        Row::body(
            "The first device to show these words: write them down. Every other device \
             must show the same words, in this order, when the card reaches it.",
        )
        .small()
        .wrapped(),
    );
    loop {
        let _ = menu::show_doc(ui, &rows, false, false);
        match menu::pick_row(
            ui,
            who,
            "same as written down?",
            &[
                "Yes, or written now",
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
                    &[
                        "Someone may be between the devices. Leave it on every device and start a new session.",
                    ],
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
    let t0 = catcard_kernel::ticks();
    let done = crate::keywork::run(|kw| s.confirm(kw));
    busy.take();
    crate::catlog!(
        "tss: confirm took {} ms",
        catcard_kernel::ticks()
            .wrapping_sub(t0)
            .wrapping_mul(catcard_kernel::TICK_MS)
    );
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
    // Where the card goes first, so it is what a small screen shows before anything else.
    let mut note: heapless::String<160> = heapless::String::new();
    let _ = write!(
        note,
        "Step {step} of {}. Pass the card to member {next}, then put it back here.",
        s.rounds() + 1
    );
    if from.len() > 1 {
        let _ = note.push_str(" Waiting for members");
        for m in from.iter() {
            let _ = write!(note, " {m}");
        }
        let _ = note.push('.');
    }
    if !refused.is_empty() {
        let _ = write!(note, " Note: {refused}.");
    }
    loop {
        match menu::pick_row(ui, who, &note, &["The card is back", "Leave the session"]) {
            Some(0) => return true,
            _ => {
                if leave(ui) {
                    return false;
                }
            }
        }
    }
}

/// Whether the owner confirms leaving the session.
pub(super) fn leave(ui: &mut Ui<'_>) -> bool {
    approve(
        ui,
        "Leave the session?",
        "Every member will have to start again.",
        &["Nothing is kept from this session."],
        "leave",
        "stay",
    )
}

/// This member is done, but the others may still be waiting for the card: say where it
/// goes next. `next` is the next member round the circle.
#[inline(never)]
pub(super) fn pass_on(ui: &mut Ui<'_>, next: u8) {
    use catcard_ui::scroll::Line as Row;
    let mut note: heapless::String<120> = heapless::String::new();
    let _ = write!(
        note,
        "Pass the card to member {next}, then on to any member still showing a step."
    );
    let rows = [
        Row::title("Done here"),
        Row::body(note.as_str()).small().wrapped(),
    ];
    let _ = menu::show_doc(ui, &rows, false, false);
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
