//! The SD card: a session's message files, and share files.
//!
//! # A session's folder
//!
//! `TSS/<session id>/` (`catcard_tss::session_dir`), one file per message named
//! `r<round>-<from>-<to>.msg` (`catcard_tss::file_name`), and `invite.txt`, which the
//! member who started the session writes so the others can find it: the number of
//! members and how many are needed, as text a person can read too. The invitation is not
//! trusted -- `n` and `t` are part of the session code every member compares -- it only
//! saves typing them on each device.
//!
//! # Share files
//!
//! A share leaves the device as a 7-Zip archive holding one stored file, the share
//! bundle or record: AES-256 under a password the owner types, or in the clear if the
//! owner insists, twice. The container and the password stretch are the backup's
//! (`catcard_backup::sevenz`, `crate::backup::stretch`), so a share file opens on a
//! computer with 7-Zip as a backup does.

use alloc::vec::Vec;
use catcard_backup::{kdf, sevenz};
use catcard_tss::{Outgoing, SESSION_ID_LEN};
use core::fmt::Write as _;

use super::{Buf, say};
use crate::menu;
use crate::ui::Ui;

/// The invitation's name in a session's folder.
const INVITE: &str = "invite.txt";
/// Largest message file read. A 3-member DKG's largest is about 9 KB; this only bounds
/// what a damaged card can ask for.
const MAX_MESSAGE: usize = 256 * 1024;
/// Largest share file read: a 9-member bundle in its archive.
const MAX_SHARE_FILE: usize = 160 * 1024;
/// Most sessions offered from one card.
pub(super) const MAX_SESSIONS: usize = 8;

/// A session's folder: `TSS/` and the id in hex.
pub(super) fn folder(id: &[u8; SESSION_ID_LEN]) -> heapless::String<24> {
    let mut s = heapless::String::new();
    let _ = s.push_str(&catcard_tss::session_dir(id));
    s
}

/// The first eight hex digits of a session's id: how the screens name it.
pub(super) fn short_id(id: &[u8; SESSION_ID_LEN]) -> heapless::String<8> {
    let mut s = heapless::String::new();
    for b in &id[..4] {
        let _ = write!(s, "{b:02X}");
    }
    s
}

fn path_in(dir: &str, name: &str) -> heapless::String<48> {
    let mut p = heapless::String::new();
    let _ = write!(p, "{dir}/{name}");
    p
}

/// Read the whole of `path` from a mounted volume. `None` if there is no such file.
fn read_whole(
    vol: &mut menu::CardVolume,
    path: &str,
    cap: usize,
) -> Result<Option<Buf>, &'static str> {
    let len = match vol.open_file(path) {
        Ok(f) => f.len() as usize,
        Err(()) => return Ok(None),
    };
    if len > cap {
        return Err("a file on the card is too large");
    }
    let mut buf = Buf::with_capacity(len).ok_or("no memory for the file")?;
    let n = crate::signtx::read_file(vol, path, &mut buf.space()[..len])?;
    buf.set_len(n);
    Ok(Some(buf))
}

/// Write a session's outgoing messages, making its folder if it is new.
#[inline(never)]
pub(super) fn write_messages(
    id: &[u8; SESSION_ID_LEN],
    out: &[Outgoing],
    invite: Option<(u8, u8)>,
) -> Result<(), &'static str> {
    let dir = folder(id);
    let mut vol = menu::mount_card()?;
    vol.ensure_dir("TSS")
        .map_err(|_| "cannot make the TSS folder")?;
    vol.ensure_dir(&dir)
        .map_err(|_| "cannot make the session folder")?;
    if let Some((n, t)) = invite {
        let mut text: heapless::String<64> = heapless::String::new();
        let _ = write!(text, "CatCard TSS session\nmembers {n}\nneeded {t}\n");
        menu::write_into(&mut vol, &path_in(&dir, INVITE), text.as_bytes())?;
    }
    for o in out {
        menu::write_into(&mut vol, &path_in(&dir, &o.file_name()), &o.bytes)?;
    }
    vol.flush().map_err(|_| "flush failed")
}

/// A message read off the card: its (round, from, to), and its bytes.
pub(super) type Message = ((u8, u8, u8), Buf);

/// The messages among `wanted` that are on the card, read. What is missing is left out.
#[inline(never)]
pub(super) fn read_messages(
    id: &[u8; SESSION_ID_LEN],
    wanted: &[(u8, u8, u8)],
) -> Result<Vec<Message>, &'static str> {
    let dir = folder(id);
    let mut vol = menu::mount_card()?;
    let mut got = Vec::new();
    for &(r, f, t) in wanted {
        let path = path_in(&dir, &catcard_tss::file_name(r, f, t));
        if let Some(b) = read_whole(&mut vol, &path, MAX_MESSAGE)? {
            got.push(((r, f, t), b));
        }
    }
    Ok(got)
}

/// A session found on the card.
pub(super) struct Invite {
    pub(super) id: [u8; SESSION_ID_LEN],
    pub(super) n: u8,
    pub(super) t: u8,
    /// Bit `m` set: member `m` has written its first message already.
    pub(super) taken: u16,
}

/// The sessions on the card that an invitation describes.
#[inline(never)]
pub(super) fn sessions() -> Result<heapless::Vec<Invite, MAX_SESSIONS>, &'static str> {
    let mut vol = menu::mount_card()?;
    let mut ids: heapless::Vec<[u8; SESSION_ID_LEN], MAX_SESSIONS> = heapless::Vec::new();
    // No folder at all is no session, not an error.
    let _ = vol.enumerate("TSS", |name, dir, _| {
        if let (true, Some(id)) = (dir, parse_id(name)) {
            let _ = ids.push(id);
        }
    });
    let mut out = heapless::Vec::new();
    for id in ids {
        let dir = folder(&id);
        let Ok(Some(mut text)) = read_whole(&mut vol, &path_in(&dir, INVITE), 256) else {
            continue;
        };
        let Some((n, t)) = parse_invite(text.as_slice()) else {
            continue;
        };
        let mut taken = 0u16;
        let _ = vol.enumerate(&dir, |name, _, _| {
            if let Some((0, from, 0)) = catcard_tss::parse_file_name(name)
                && from <= n
            {
                taken |= 1 << from;
            }
        });
        let _ = out.push(Invite { id, n, t, taken });
    }
    Ok(out)
}

fn parse_id(name: &str) -> Option<[u8; SESSION_ID_LEN]> {
    if name.len() != 2 * SESSION_ID_LEN {
        return None;
    }
    let mut id = [0u8; SESSION_ID_LEN];
    for (i, b) in id.iter_mut().enumerate() {
        *b = u8::from_str_radix(name.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(id)
}

fn parse_invite(text: &[u8]) -> Option<(u8, u8)> {
    let text = core::str::from_utf8(text).ok()?;
    let mut lines = text.lines();
    if lines.next()? != "CatCard TSS session" {
        return None;
    }
    let mut n = None;
    let mut t = None;
    for l in lines {
        if let Some(v) = l.strip_prefix("members ") {
            n = v.trim().parse::<u8>().ok();
        } else if let Some(v) = l.strip_prefix("needed ") {
            t = v.trim().parse::<u8>().ok();
        }
    }
    let (n, t) = (n?, t?);
    catcard_tss::can_create_together(n, t).then_some((n, t))
}

// ---------------------------------------------------------------------------------------
// Share files
// ---------------------------------------------------------------------------------------

/// How a share file is protected.
pub(super) enum Protect {
    Password(kdf::Key),
    Clear,
}

/// Ask how to protect the share files about to be written: a password, typed twice and
/// stretched once for all of them, or -- asked twice, never the default -- none.
#[inline(never)]
pub(super) fn ask_protection(ui: &mut Ui<'_>, head: &str) -> Option<Protect> {
    loop {
        let pick = menu::pick_row(
            ui,
            head,
            "protect the share files",
            &["With a password", "No password"],
        )?;
        if pick == 1 {
            menu::ask(
                ui.panel,
                "No password?",
                "whoever holds a card",
                "holds that share",
            );
            if menu::confirmed(ui) {
                return Some(Protect::Clear);
            }
            continue;
        }
        let first = crate::passphrase::read(ui, "Share password")?;
        if first.as_str().is_empty() {
            say(ui, head, "an empty password", "protects nothing");
            continue;
        }
        let again = crate::passphrase::read(ui, "Once more")?;
        if first.as_str() != again.as_str() {
            say(ui, head, "the two passwords", "are not the same");
            continue;
        }
        drop(again);
        match crate::backup::stretch(ui, first.as_str(), head, "sealing with the password") {
            Ok(key) => return Some(Protect::Password(key)),
            Err(why) => say(ui, head, "cannot use it:", why),
        }
    }
}

/// Write `body` to the card as `name`, a 7-Zip archive holding it as `inner`.
#[inline(never)]
pub(super) fn write_share(
    ui: &mut Ui<'_>,
    head: &str,
    name: &str,
    inner: &str,
    body: &[u8],
    protect: &Protect,
) -> Result<(), &'static str> {
    let mut buf = Buf::with_capacity(sevenz::len_bound(inner, body.len())).ok_or("no memory")?;
    let space = buf.space();
    space[sevenz::BODY_OFFSET..sevenz::BODY_OFFSET + body.len()].copy_from_slice(body);
    let len = match protect {
        Protect::Password(key) => {
            // A fresh IV per file: the key is the same for every file of one export.
            let mut iv = [0u8; 16];
            ui.protocol.generate(&mut iv).map_err(|_| "no random IV")?;
            sevenz::seal_at(
                buf.space(),
                body.len(),
                inner,
                key,
                &iv,
                &[],
                kdf::DEFAULT_CYCLES_POWER,
            )
            .map_err(|_| "could not seal it")?
            .len()
        }
        Protect::Clear => sevenz::seal_clear_at(buf.space(), body.len(), inner)
            .map_err(|_| "could not pack it")?
            .len(),
    };
    buf.set_len(len);
    menu::card_wait(ui.panel, head, "writing to the card");
    menu::write_card_file(name, buf.as_slice())
}

/// Pick a share file on the card and open it: the bundle or record inside, in the clear.
/// `None` when the owner backed out or it would not open (already said).
#[inline(never)]
pub(super) fn read_share(ui: &mut Ui<'_>, head: &str) -> Option<Buf> {
    let path = menu::browse_sd(ui, "Pick a share file", Some("7z"), menu::Browse::File)?;
    menu::card_wait(ui.panel, head, "reading the card");
    let read = menu::mount_card().and_then(|mut vol| read_whole(&mut vol, &path, MAX_SHARE_FILE));
    let mut buf = match read {
        Ok(Some(b)) => b,
        Ok(None) => {
            say(ui, head, "cannot read", "that file");
            return None;
        }
        Err(why) => {
            say(ui, head, "cannot read it:", why);
            return None;
        }
    };
    let len = buf.as_slice().len();
    let found = match sevenz::open(buf.as_slice()) {
        Ok(f) => f,
        Err(_) => {
            say(ui, head, "not a share file", "");
            return None;
        }
    };
    let opened = match found {
        sevenz::Found::Clear(p) => sevenz::extract_in_place(&mut buf.space()[..len], &p)
            .map(|f| f.len())
            .map_err(|_| "the file is damaged"),
        sevenz::Found::File(s) => {
            let phrase = crate::passphrase::read(ui, "Share password")?;
            match crate::backup::stretch(ui, phrase.as_str(), head, "opening the share") {
                Ok(key) => sevenz::decrypt_in_place(&mut buf.space()[..len], &s, &key)
                    .map(|f| f.len())
                    .map_err(|_| "wrong password, or damaged"),
                Err(why) => Err(why),
            }
        }
        sevenz::Found::Header(_) => Err("not a share file"),
    };
    match opened {
        Ok(n) => {
            buf.set_len(n);
            Some(buf)
        }
        Err(why) => {
            say(ui, head, "cannot open it:", why);
            None
        }
    }
}
