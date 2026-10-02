//! The shares this device keeps: one sealed file each in the settings volume, beside the
//! settings slots (`catcard_settings::tss` has the format and the keys).
//!
//! Sealed under the root wallet's settings key, whichever wallet is in force: the shares
//! belong to the device's stored wallet as its multisig registrations do, and a device
//! with no stored wallet has no key worth sealing them under (its settings key is all
//! zeros), so it keeps none.

use catcard_settings::tss::{self as fmt, FileKey, Summary};

use super::{Buf, say};
use crate::ui::Ui;

/// Most shares listed at once.
pub(super) const MAX_KEPT: usize = 12;

/// Largest share file read: a 9-member record and the seal.
const MAX_FILE: usize = 128 * 1024;

/// One kept share: where it is, and what its header says.
pub(super) struct Kept {
    pub(super) path: heapless::String<{ fmt::NAME_LEN }>,
    pub(super) summary: Summary,
}

/// The key the root wallet's shares are sealed under. `None`, said on screen, when no
/// wallet is stored or its settings key cannot be had.
#[inline(never)]
pub(super) fn key(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    head: &str,
) -> Option<FileKey> {
    if !crate::key::stored_wallet(login) {
        say(
            ui,
            head,
            "store a wallet first:",
            "shares are kept under it",
        );
        return None;
    }
    match crate::settings::master_key(gate, login, ui.panel, head) {
        Ok(k) => Some(FileKey::new(&k)),
        Err(why) => {
            say(ui, head, "cannot reach the settings:", why);
            None
        }
    }
}

/// Every share this wallet keeps, by its header. Files sealed under another wallet are
/// passed over.
#[inline(never)]
pub(super) fn list(key: &FileKey) -> Result<heapless::Vec<Kept, MAX_KEPT>, &'static str> {
    let mut names: heapless::Vec<heapless::String<{ fmt::NAME_LEN }>, 32> = heapless::Vec::new();
    {
        // SAFETY: the region is mapped and readable; nothing is written through this.
        let mut files = unsafe { crate::settings::Files::mount_read_only() }
            .map_err(|_| "the settings will not mount")?;
        files
            .each_root_file(|name| {
                if fmt::is_share_file(name) {
                    let mut p = heapless::String::new();
                    let _ = p.push('/');
                    let _ = p.push_str(name.trim_start_matches('/'));
                    let _ = names.push(p);
                }
            })
            .map_err(|_| "the settings will not list")?;
    }
    let mut out = heapless::Vec::new();
    for path in names {
        let Ok(mut rec) = read(key, &path) else {
            continue;
        };
        if let Some(summary) = fmt::summary(rec.as_slice()) {
            let _ = out.push(Kept { path, summary });
        }
    }
    Ok(out)
}

/// The record in `path`, opened. An error for a file of another wallet, or damaged.
#[inline(never)]
pub(super) fn read(key: &FileKey, path: &str) -> Result<Buf, &'static str> {
    // SAFETY: the region is mapped and readable; nothing is written through this.
    let mut files = unsafe { crate::settings::Files::mount_read_only() }
        .map_err(|_| "the settings will not mount")?;
    let len = files.file_len(path).ok_or("no such share")?;
    if len > MAX_FILE {
        return Err("too large to be a share");
    }
    let mut buf = Buf::with_capacity(len).ok_or("no memory")?;
    match files.read_file(path, buf.space()) {
        Ok(Some(n)) if n == len => buf.set_len(n),
        _ => return Err("the share will not read"),
    }
    drop(files);
    let mut file = buf;
    let opened = {
        let bytes = &mut file.space()[..len];
        fmt::open(bytes, key)
    };
    opened.map_err(|_| "not this wallet's share")?;
    // The record, moved to the front so the buffer is just the record.
    let space = file.space();
    space.copy_within(fmt::HEAD_LEN..len, 0);
    space[len - fmt::HEAD_LEN..len].fill(0);
    file.set_len(len - fmt::HEAD_LEN);
    Ok(file)
}

/// Whether a share of this wallet for this member is kept already.
#[inline(never)]
pub(super) fn holds(key: &FileKey, summary: &Summary) -> bool {
    let path = fmt::file_name(key, &summary.joint_public, summary.member);
    // SAFETY: the region is mapped and readable; nothing is written through this.
    unsafe { crate::settings::Files::mount_read_only() }
        .ok()
        .and_then(|mut f| f.file_len(&path))
        .is_some()
}

/// Seal `record` and keep it. Its header names the file.
#[inline(never)]
pub(super) fn save(ui: &mut Ui<'_>, key: &FileKey, record: &[u8]) -> Result<(), &'static str> {
    let summary = fmt::summary(record).ok_or("not a share record")?;
    let path = fmt::file_name(key, &summary.joint_public, summary.member);
    let mut iv = [0u8; 16];
    ui.protocol.generate(&mut iv).map_err(|_| "no random IV")?;
    let mut buf = Buf::with_capacity(fmt::HEAD_LEN + record.len()).ok_or("no memory")?;
    buf.space()[fmt::HEAD_LEN..fmt::HEAD_LEN + record.len()].copy_from_slice(record);
    let n = fmt::seal(buf.space(), record.len(), key, &iv);
    buf.set_len(n);
    // SAFETY: foreground only; the screen holds the display while this runs.
    let mut files =
        unsafe { crate::settings::Files::mount() }.map_err(|_| "the settings will not mount")?;
    files
        .write_file(&path, buf.as_slice())
        .map_err(|_| "no room in the settings")?;
    crate::catlog!("tss: share kept as {}", path.as_str());
    Ok(())
}

/// Remove a kept share.
#[inline(never)]
pub(super) fn delete(path: &str) -> Result<(), &'static str> {
    // SAFETY: foreground only; the screen holds the display while this runs.
    let mut files =
        unsafe { crate::settings::Files::mount() }.map_err(|_| "the settings will not mount")?;
    files.remove_file(path).map_err(|_| "could not remove it")?;
    crate::catlog!("tss: share {} removed", path);
    Ok(())
}
