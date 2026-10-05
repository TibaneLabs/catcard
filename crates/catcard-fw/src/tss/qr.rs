//! A session's messages between Q1s by QR: the camera in place of the card
//! (docs/TSS.md, "By QR code").
//!
//! The SD card is a shared mailbox: each device writes its messages to it and reads the
//! others'. A QR code is not shared -- it is one screen shown to one camera -- so here
//! each device keeps both halves of the mailbox in memory:
//!
//! - **what it has sent** ([`Exchange::sent`]), every envelope of the session, from which
//!   a *code for member m* is made on demand: the broadcasts and m's own unicasts of the
//!   last two rounds this device produced. Two, because the members move in step but not
//!   in lockstep: a member that has not yet scanned this device's round `r` is still
//!   owed it after this device has gone on to `r + 1`.
//! - **what it has scanned** ([`Exchange::take`]), every envelope addressed to it or to
//!   everyone, handed to the session when it asks for it -- as the card's files are.
//!
//! A code carries the session's id, and the invitation when it comes from the member
//! who started, so a member joining learns the session by scanning member 1's first code.
//! Nothing in it is trusted: each envelope is signed, and the session refuses one out of
//! place (`catcard_tss::envelope`).
//!
//! # The code
//!
//! One BBQr of type `B` (binary): `CTQ1`, the session id (8 bytes), the invitation (a
//! kind byte: 0 none, 1 create `n t`, 2 pair setup `wallet[8] members`, 3 signing
//! `wallet[8] signers` -- each set a u16, bit `m` for member `m`), the number of
//! envelopes, then each as `round from to`, its length (u32, little-endian) and its
//! bytes.

use alloc::vec::Vec;
use catcard_tss::{Outgoing, SESSION_ID_LEN};

use super::Buf;
use super::card::{Invitation, Message};
use crate::ui::Ui;

const MAGIC: &[u8; 4] = b"CTQ1";
/// Largest code read or made. A member's last keygen round to one other member is about
/// 9 KB, and a code holds two rounds.
const MAX_CODE: usize = 48 * 1024;

/// One device's half of a session by QR. See the module notes.
pub(super) struct Exchange {
    pub(super) id: [u8; SESSION_ID_LEN],
    /// Shown in every code this device makes, when it started the session.
    invite: Option<Invitation>,
    sent: Vec<Outgoing>,
    inbox: Vec<((u8, u8, u8), Vec<u8>)>,
}

impl Exchange {
    pub(super) fn new(id: [u8; SESSION_ID_LEN], invite: Option<Invitation>) -> Self {
        Exchange {
            id,
            invite,
            sent: Vec::new(),
            inbox: Vec::new(),
        }
    }

    /// Keep what the session has to say, to show it.
    pub(super) fn sent(&mut self, out: &[Outgoing]) {
        self.sent.extend_from_slice(out);
    }

    /// Whether anything has been sent to show.
    pub(super) fn has_sent(&self) -> bool {
        !self.sent.is_empty()
    }

    /// The scanned messages among `wanted`, as the card would hand them over.
    pub(super) fn take(&mut self, wanted: &[(u8, u8, u8)]) -> Vec<Message> {
        let mut got = Vec::new();
        for w in wanted {
            if let Some(i) = self.inbox.iter().position(|(n, _)| n == w) {
                let (_, bytes) = self.inbox.swap_remove(i);
                if let Some(mut b) = Buf::with_capacity(bytes.len()) {
                    b.space()[..bytes.len()].copy_from_slice(&bytes);
                    b.set_len(bytes.len());
                    got.push((*w, b));
                }
            }
        }
        got
    }

    /// The code for member `to`: see the module notes.
    fn code_for(&self, to: u8) -> Vec<u8> {
        let last = self.sent.iter().map(|o| o.round).max().unwrap_or(0);
        let picked: Vec<&Outgoing> = self
            .sent
            .iter()
            .filter(|o| o.round + 1 >= last && (o.to == 0 || o.to == to))
            .collect();
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.id);
        match self.invite {
            None => out.push(0),
            Some(Invitation::Create { n, t }) => out.extend_from_slice(&[1, n, t]),
            Some(Invitation::Pairs { wallet, members }) => {
                out.push(2);
                out.extend_from_slice(&wallet);
                out.extend_from_slice(&members.to_le_bytes());
            }
            Some(Invitation::Sign { wallet, signers }) => {
                out.push(3);
                out.extend_from_slice(&wallet);
                out.extend_from_slice(&signers.to_le_bytes());
            }
        }
        out.push(picked.len() as u8);
        for o in picked {
            out.extend_from_slice(&[o.round, o.from, o.to]);
            out.extend_from_slice(&(o.bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(&o.bytes);
        }
        out
    }

    /// Show the code for member `to`, until the owner presses a key.
    pub(super) fn show(&self, ui: &mut Ui<'_>, head: &str, to: u8) {
        let code = self.code_for(to);
        crate::qrshow::animate_bbqr(ui, head, &code, catcard_bbqr::FileType::BINARY);
    }

    /// Scan another member's code into the inbox. Only this session's, and only what is
    /// addressed to `me` or to everyone. `Ok(false)` if the owner backed out.
    pub(super) fn scan(
        &mut self,
        ui: &mut Ui<'_>,
        head: &str,
        me: u8,
    ) -> Result<bool, &'static str> {
        let Some(mut code) = read(ui, head)? else {
            return Ok(false);
        };
        let parsed = parse(code.as_slice())?;
        if parsed.id != self.id {
            return Err("a code of another session");
        }
        for (name, bytes) in parsed.envelopes {
            if (name.2 == 0 || name.2 == me) && !self.inbox.iter().any(|(n, _)| *n == name) {
                self.inbox.push((name, bytes.to_vec()));
            }
        }
        Ok(true)
    }
}

/// A session found by scanning a member's code: its id, its invitation, and an
/// exchange holding what the code carried for `me`.
pub(super) struct Found {
    pub(super) id: [u8; SESSION_ID_LEN],
    pub(super) invite: Invitation,
    code: Buf,
}

impl Found {
    /// The exchange for member `me` of the session found, holding what its first code
    /// already carried.
    pub(super) fn exchange(&mut self, me: u8) -> Exchange {
        let mut ex = Exchange::new(self.id, None);
        if let Ok(parsed) = parse(self.code.as_slice()) {
            for (name, bytes) in parsed.envelopes {
                if name.2 == 0 || name.2 == me {
                    ex.inbox.push((name, bytes.to_vec()));
                }
            }
        }
        ex
    }
}

/// Scan the code of the member who started a session, to join it. `Ok(None)` if the
/// owner backed out.
pub(super) fn find(ui: &mut Ui<'_>, head: &str) -> Result<Option<Found>, &'static str> {
    let Some(mut code) = read(ui, head)? else {
        return Ok(None);
    };
    let parsed = parse(code.as_slice())?;
    let invite = parsed.invite.ok_or("not the starting member's code")?;
    let id = parsed.id;
    Ok(Some(Found { id, invite, code }))
}

/// One code, read whole. `Ok(None)` if the owner backed out.
fn read(ui: &mut Ui<'_>, head: &str) -> Result<Option<Buf>, &'static str> {
    let mut buf = Buf::with_capacity(MAX_CODE).ok_or("no memory")?;
    let mut sink = crate::qrload::SliceSink::new(buf.space());
    let got = match crate::qrload::collect_any(ui, head, &mut sink) {
        Ok(got) => got,
        Err(Some(why)) => return Err(why),
        Err(None) => return Ok(None),
    };
    if got.compressed || got.file_type != Some('B') {
        return Err("not a TSS session code");
    }
    let len = got.len.min(sink.len);
    buf.set_len(len);
    Ok(Some(buf))
}

struct Parsed<'a> {
    id: [u8; SESSION_ID_LEN],
    invite: Option<Invitation>,
    envelopes: Vec<((u8, u8, u8), &'a [u8])>,
}

fn parse(code: &[u8]) -> Result<Parsed<'_>, &'static str> {
    const BAD: &str = "not a TSS session code";
    let rest = code.strip_prefix(MAGIC).ok_or(BAD)?;
    let (id, mut rest) = rest.split_at_checked(SESSION_ID_LEN).ok_or(BAD)?;
    let id: [u8; SESSION_ID_LEN] = id.try_into().map_err(|_| BAD)?;
    let mut take = |n: usize| -> Result<&[u8], &'static str> {
        let (a, b) = rest.split_at_checked(n).ok_or(BAD)?;
        rest = b;
        Ok(a)
    };
    let invite = match take(1)?[0] {
        0 => None,
        1 => {
            let v = take(2)?;
            Some(Invitation::Create { n: v[0], t: v[1] })
        }
        2 => {
            let v = take(10)?;
            let mut wallet = [0u8; 8];
            wallet.copy_from_slice(&v[..8]);
            Some(Invitation::Pairs {
                wallet,
                members: u16::from_le_bytes([v[8], v[9]]),
            })
        }
        3 => {
            let v = take(10)?;
            let mut wallet = [0u8; 8];
            wallet.copy_from_slice(&v[..8]);
            Some(Invitation::Sign {
                wallet,
                signers: u16::from_le_bytes([v[8], v[9]]),
            })
        }
        _ => return Err(BAD),
    };
    let count = take(1)?[0];
    let mut envelopes = Vec::new();
    for _ in 0..count {
        let h = take(7)?;
        let len = u32::from_le_bytes([h[3], h[4], h[5], h[6]]) as usize;
        envelopes.push(((h[0], h[1], h[2]), take(len)?));
    }
    Ok(Parsed {
        id,
        invite,
        envelopes,
    })
}

/// The other members of `s`, ascending.
fn others(s: &catcard_tss::Session) -> heapless::Vec<u8, 9> {
    s.members()
        .iter()
        .copied()
        .filter(|&m| m != s.me())
        .collect()
}

/// "Show my code for member m", one row per other member.
fn show_rows(s: &catcard_tss::Session) -> heapless::Vec<crate::menu::Line, 9> {
    use core::fmt::Write as _;
    others(s)
        .iter()
        .map(|m| {
            let mut l = crate::menu::Line::new();
            let _ = write!(l, "Show my code to {m}");
            l
        })
        .collect()
}

/// Nothing more to read for now: scan the others' codes, show them this member's.
/// `true` once a code was scanned (the session may move); `false` if the owner leaves.
#[inline(never)]
pub(super) fn wait(
    ui: &mut Ui<'_>,
    ex: &mut Exchange,
    s: &catcard_tss::Session,
    who: &str,
    wanted: &[(u8, u8, u8)],
    refused: &str,
) -> bool {
    use core::fmt::Write as _;
    let mut from: heapless::Vec<u8, 9> = heapless::Vec::new();
    for m in 1..=catcard_tss::MAX_MEMBERS {
        if wanted.iter().any(|w| w.1 == m) {
            let _ = from.push(m);
        }
    }
    let step = wanted.first().map_or(0, |w| w.0) + 1;
    let mut note: heapless::String<160> = heapless::String::new();
    let _ = write!(
        note,
        "Step {step} of {}. Scan the code of member",
        s.rounds() + 1
    );
    if from.len() > 1 {
        let _ = note.push('s');
    }
    for m in from.iter() {
        let _ = write!(note, " {m}");
    }
    let _ = note.push_str(", and show them yours.");
    if !refused.is_empty() {
        let _ = write!(note, " Note: {refused}.");
    }
    let shows = show_rows(s);
    let peers = others(s);
    loop {
        let mut rows: heapless::Vec<&str, 11> = heapless::Vec::new();
        let _ = rows.push("Scan a code");
        if ex.has_sent() {
            for l in shows.iter() {
                let _ = rows.push(l.as_str());
            }
        }
        let _ = rows.push("Leave the session");
        let Some(pick) = crate::menu::pick_row(ui, who, &note, &rows) else {
            if super::drive::leave(ui) {
                return false;
            }
            continue;
        };
        if pick == 0 {
            match ex.scan(ui, who, s.me()) {
                Ok(true) => return true,
                Ok(false) => {}
                Err(why) => super::say(ui, who, "not read:", why),
            }
        } else if pick + 1 == rows.len() {
            if super::drive::leave(ui) {
                return false;
            }
        } else if let Some(&m) = peers.get(pick - 1) {
            ex.show(ui, who, m);
        }
    }
}

/// This member is done; the others may still need its last messages, which only its
/// screen can give them. Shown until the owner says everyone is done.
#[inline(never)]
pub(super) fn hand_over(ui: &mut Ui<'_>, ex: &Exchange, s: &catcard_tss::Session, who: &str) {
    let shows = show_rows(s);
    let peers = others(s);
    loop {
        let mut rows: heapless::Vec<&str, 10> = heapless::Vec::new();
        for l in shows.iter() {
            let _ = rows.push(l.as_str());
        }
        let _ = rows.push("Everyone is done");
        match crate::menu::pick_row(
            ui,
            who,
            "Done here. Show your code to any member still showing a step.",
            &rows,
        ) {
            Some(i) if i < peers.len() => ex.show(ui, who, peers[i]),
            _ => return,
        }
    }
}
