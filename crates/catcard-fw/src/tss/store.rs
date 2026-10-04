//! The TSS wallets this device is a member of: one share record each -- the key core, a
//! few hundred bytes -- in the settings of the wallet in force (`catcard_settings::tss`
//! has the shape, `catcard_tss` the record), under the settings encryption like
//! everything else there.
//!
//! What signing also needs, the pairs, is not here: it is a sealed cache on the card or
//! the Virtual Disk (`super::card`), opened with [`cache_key`] and checked against the
//! digest the record keeps. A device keeps no TSS wallet without a stored wallet: the
//! caches are sealed under the stored wallet's secret, and a blank device has none.

use catcard_settings::nvstore::BODY_LEN;
use catcard_settings::store::{self as slots, SCRATCH};
use catcard_settings::tss as fmt;
use catcard_tss::{CacheKey, ShareRecord, Summary};
use zeroize::Zeroize as _;

use super::{Buf, say};
use crate::ui::Ui;

/// Most records listed at once.
pub(super) const MAX_KEPT: usize = fmt::MAX_KEPT;

/// Largest record: a 9-member core (919 bytes measured) behind the deepest header
/// (113 bytes and 4 per path step, 10 steps at most), rounded up.
const MAX_RECORD: usize = 1152;
/// Its base64.
const MAX_TEXT: usize = MAX_RECORD.div_ceil(3) * 4;

/// Shown when the settings cannot be had.
const HEAD: &str = "TSS wallets";

/// One kept record: where it is in the list, and what its header says.
pub(super) struct Kept {
    pub(super) index: usize,
    pub(super) summary: Summary,
}

/// Whether this device can keep TSS wallets now; says why not.
pub(super) fn ready(login: &mut catcard_pin::Login, ui: &mut Ui<'_>, head: &str) -> bool {
    if crate::key::stored_wallet(login) {
        return true;
    }
    say(
        ui,
        head,
        "store a wallet first:",
        "TSS wallets are kept under it",
    );
    false
}

/// The settings object of the wallet in force, read into `buf`: its length.
fn read_doc(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    buf: &mut [u8],
) -> Result<usize, &'static str> {
    let key = crate::settings::wallet_key(gate, login, ui.panel, HEAD)?;
    // SAFETY: the region is mapped and readable; nothing is written through this.
    let mut files = unsafe { crate::settings::Files::mount_read_only() }
        .map_err(|_| "the settings will not mount")?;
    Ok(slots::read(&mut files, &key, buf).unwrap_or(0))
}

/// Decode one entry's base64 into `out`: the record's length.
fn decode(text: &str, out: &mut Buf) -> Option<usize> {
    let n = outscript::base64::decode_to_slice(text, out.space()).ok()?;
    out.set_len(n);
    Some(n)
}

/// Every record kept, by its header. An entry that will not read is passed over.
#[inline(never)]
pub(super) fn list(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) -> Result<heapless::Vec<Kept, MAX_KEPT>, &'static str> {
    let mut doc = crate::heap::take(SCRATCH).ok_or("no memory")?;
    let mut rec = Buf::with_capacity(MAX_RECORD).ok_or("no memory")?;
    let n = read_doc(gate, login, ui, doc.bytes())?;
    let json = &doc.bytes()[..n];
    let parsed = crate::settings::parse_doc(json).ok_or("no memory")?;
    let mut entries = [""; MAX_KEPT];
    let have = fmt::list(&parsed, &mut entries);
    let mut out = heapless::Vec::new();
    for (index, e) in entries[..have].iter().enumerate() {
        if decode(e, &mut rec).is_none() {
            continue;
        }
        if let Some(summary) = catcard_tss::summary(rec.as_slice()) {
            let _ = out.push(Kept { index, summary });
        }
    }
    Ok(out)
}

/// The record at `index` of the list, decoded from its base64. Wiped when dropped.
#[inline(never)]
pub(super) fn read(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    index: usize,
) -> Result<Buf, &'static str> {
    let mut doc = crate::heap::take(SCRATCH).ok_or("no memory")?;
    let mut rec = Buf::with_capacity(MAX_RECORD).ok_or("no memory")?;
    let n = read_doc(gate, login, ui, doc.bytes())?;
    let json = &doc.bytes()[..n];
    let parsed = crate::settings::parse_doc(json).ok_or("no memory")?;
    let mut entries = [""; MAX_KEPT];
    let have = fmt::list(&parsed, &mut entries);
    let text = entries[..have].get(index).ok_or("no such wallet")?;
    decode(text, &mut rec).ok_or("a damaged entry")?;
    Ok(rec)
}

/// Whether two headers are the same member of the same wallet.
pub(super) fn same_member(a: &Summary, b: &Summary) -> bool {
    a.member == b.member && same_wallet(a, b)
}

/// Whether two headers are of the same wallet.
pub(super) fn same_wallet(a: &Summary, b: &Summary) -> bool {
    a.joint_public == b.joint_public
        && a.chain_code == b.chain_code
        && a.n == b.n
        && a.t == b.t
        && a.path == b.path
}

/// Whether this member's record of this wallet is kept already.
pub(super) fn holds(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    s: &Summary,
) -> bool {
    list(gate, login, ui).is_ok_and(|all| all.iter().any(|k| same_member(&k.summary, s)))
}

/// Keep `record`: in place of this member's record of the same wallet if there is one
/// (a new pair-cache digest), else added to the list.
#[inline(never)]
pub(super) fn save(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    record: &[u8],
) -> Result<(), &'static str> {
    edit(gate, login, ui, Edit::Put(record))
}

/// Remove the record at `index` of the list.
#[inline(never)]
pub(super) fn delete(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    index: usize,
) -> Result<(), &'static str> {
    edit(gate, login, ui, Edit::Remove(index))
}

enum Edit<'a> {
    Put(&'a [u8]),
    Remove(usize),
}

/// The list with one change, written back in one settings save.
fn edit(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    change: Edit<'_>,
) -> Result<(), &'static str> {
    let _busy = crate::menu::blocking_screen(ui.panel, HEAD, "saving");
    // The settings scratch, the rendered list, the seal the write needs, the new
    // record's base64 and one decoded record: all wiped on drop.
    let (Some(mut doc), Some(mut list_blk), Some(mut seal)) = (
        crate::heap::take(SCRATCH),
        crate::heap::take(SCRATCH),
        crate::heap::take(SCRATCH),
    ) else {
        return Err("not enough memory");
    };
    let mut text = Buf::with_capacity(MAX_TEXT).ok_or("not enough memory")?;
    let mut rec = Buf::with_capacity(MAX_RECORD).ok_or("not enough memory")?;
    let new_summary = match change {
        Edit::Put(record) => {
            if record.len() > MAX_RECORD {
                return Err("too large to keep");
            }
            let n = outscript::base64::encode_to_slice(record, text.space())
                .map_err(|_| "too large to keep")?;
            text.set_len(n);
            Some(catcard_tss::summary(record).ok_or("not a share record")?)
        }
        Edit::Remove(_) => None,
    };
    let doc_buf = doc.bytes();
    let list_buf = list_blk.bytes();
    // Scoped: the entries borrow `doc_buf`, which the save below reuses as scratch.
    let (len, room) = {
        let n = read_doc(gate, login, ui, doc_buf)?;
        let parsed = crate::settings::parse_doc(&doc_buf[..n]).ok_or("not enough memory")?;
        let old_len = parsed.get(fmt::KEY).map_or(0, str::len);
        let mut entries = [""; MAX_KEPT];
        let have = fmt::list(&parsed, &mut entries);
        let mut next: heapless::Vec<&str, MAX_KEPT> = heapless::Vec::new();
        let new_text = core::str::from_utf8(text.as_slice()).map_err(|_| "not text")?;
        let mut placed = false;
        for (i, e) in entries[..have].iter().enumerate() {
            match (&change, &new_summary) {
                (Edit::Remove(at), _) if *at == i => continue,
                (Edit::Put(_), Some(s)) => {
                    let same = decode(e, &mut rec)
                        .and_then(|_| catcard_tss::summary(rec.as_slice()))
                        .is_some_and(|k| same_member(&k, s));
                    if same && !placed {
                        placed = true;
                        let _ = next.push(new_text);
                        continue;
                    }
                }
                _ => {}
            }
            next.push(e).map_err(|_| "too many TSS wallets")?;
        }
        if matches!(change, Edit::Put(_)) && !placed {
            next.push(new_text).map_err(|_| "too many TSS wallets")?;
        }
        let len = fmt::render(&next, list_buf).map_err(|e| match e {
            fmt::Error::TooMany => "too many TSS wallets",
            fmt::Error::NotStorable | fmt::Error::Overflow => "could not keep it",
        })?;
        // The whole object is one slot: say so rather than fail the save.
        (len, n - old_len + len + 64 <= BODY_LEN)
    };
    if !room {
        list_buf[..len].zeroize();
        return Err("no room in the settings");
    }
    let text = core::str::from_utf8(&list_buf[..len]).map_err(|_| "not text")?;
    let result = crate::settings::save_wallet(
        gate,
        login,
        ui,
        HEAD,
        (fmt::KEY, text),
        doc_buf,
        seal.bytes(),
    );
    list_buf[..len].zeroize();
    result
}

/// The keys `record`'s pair caches are sealed under on this device: from the stored
/// wallet's settings key -- made from the secret the secure element holds -- and the
/// wallet's id.
#[inline(never)]
pub(super) fn cache_key(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    record: &ShareRecord,
) -> Result<CacheKey, &'static str> {
    let root = crate::settings::master_key(gate, login, ui.panel, HEAD)?;
    Ok(crate::keywork::run(|kw| {
        CacheKey::new(root.as_bytes(), record, kw)
    }))
}
