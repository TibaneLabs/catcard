//! Threshold signing (TSS) on the device, stage 1: the screens of docs/TSS.md over the SD
//! card. Signing a PSBT with a share, and QR as a transport, are stage 2.
//!
//! [`screen`] is Settings -> `TSS wallets`: the shares this device keeps, and the ways to
//! make, take in, split and put back a TSS wallet. [`restore_screen`] is the blank
//! device's Import -> `TSS shares`, which puts a wallet's words back from `t` share files.
//!
//! The protocol -- sessions, envelopes, share records, export and restore -- is
//! `catcard_tss`; this is the person, the card and the settings volume around it:
//!
//! - [`create`]: create together, `n` devices running a DKG over one card or several;
//! - [`export`]: split this wallet into `n` share files;
//! - [`restore`]: take a share in, put words back from `t` shares, recombine a
//!   created-together key;
//! - [`view`]: the kept shares, one wallet's details, its descriptor, deleting one;
//! - [`store`]: the share files in the settings volume, sealed under the root wallet;
//! - [`card`]: the session's message files and the share files on the SD card;
//! - [`rand`]: the entropy pool and the UI DRBG, as `catcard_tss` draws from them.
//!
//! # Memory
//!
//! A DKLs key holds about 12.5 KB of pairwise OT state per other member, and everything
//! that handles one grows with `n`: on the host, with 32-bit pointers and this heap's
//! block headers, a member's whole create-together session peaks at 128 KB for 3 members
//! and 382 KB for 9, and an export -- which holds every member's key at once -- at 155 KB
//! for 3 and 398 KB for 5 (docs/TSS.md, "Memory"). The device's heap is 216 KB in three
//! pieces, so every flow that touches a DKLs key first borrows the app area ([`Room`],
//! `crate::heap::borrow_app_area`), which joins the pieces either side of it into one
//! 440 KB run, and checks what the work needs against what is free -- saying so on screen
//! rather than letting an allocation fail, which on this device is the panic handler.
//! The lease wipes every free byte of the heap when it ends, which also clears what
//! tsslib freed without wiping; that is why even the shapes that would fit without it
//! (3 or 4 members creating together, an export to 3) take it.

use catcard_ui::approval::Approval;

use crate::display;
use crate::menu;
use crate::ui::Ui;

mod card;
mod create;
mod export;
mod rand;
mod restore;
mod store;
mod view;

pub(crate) use restore::restore_screen;

const HEAD: &str = "TSS wallets";

/// Settings -> TSS wallets: the kept shares, then what can be done.
#[inline(never)]
pub(crate) fn screen(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    mut pool: Option<&mut catcard_entropy::EntropyPool>,
) {
    const CREATE: &str = "Create together";
    const IMPORT: &str = "Import a share";
    const EXPORT: &str = "Split this wallet";
    const RESTORE: &str = "Restore from shares";
    const ABOUT: &str = "What is this?";
    let Some(key) = store::key(gate, login, ui, HEAD) else {
        return;
    };
    loop {
        let kept = match store::list(&key) {
            Ok(k) => k,
            Err(why) => return say(ui, HEAD, "cannot read the shares:", why),
        };
        let mut labels: heapless::Vec<menu::Line, { store::MAX_KEPT }> = heapless::Vec::new();
        for k in kept.iter() {
            let _ = labels.push(view::label(&k.summary));
        }
        let mut rows: heapless::Vec<&str, { store::MAX_KEPT + 5 }> = heapless::Vec::new();
        for l in labels.iter() {
            let _ = rows.push(l.as_str());
        }
        for r in [CREATE, IMPORT, EXPORT, RESTORE, ABOUT] {
            let _ = rows.push(r);
        }
        let note = if kept.is_empty() {
            "no shares kept here"
        } else {
            "shares kept here"
        };
        let Some(row) = menu::pick_row(ui, HEAD, note, &rows) else {
            return;
        };
        if let Some(k) = kept.get(row) {
            view::wallet(gate, login, ui, &key, k);
            continue;
        }
        match rows[row] {
            CREATE => create::create(ui, &key, pool.as_deref_mut()),
            IMPORT => restore::import(ui, &key),
            EXPORT => export::export(gate, login, ui, pool.as_deref_mut()),
            RESTORE => restore::restore_words(gate, login, ui),
            _ => about(ui),
        }
    }
}

/// What a TSS wallet is, in a screen.
#[inline(never)]
fn about(ui: &mut Ui<'_>) {
    use catcard_ui::scroll::Line as Row;
    let rows = [
        Row::title("TSS wallets"),
        Row::body(
            "A wallet whose key is held in shares by several CatCards. Any t of the n \
             shares sign together; the key is never put back together to do it.",
        )
        .small(),
        Row::body(
            "Create together: n devices make a new key between them. No device ever \
             holds the whole key.",
        )
        .small(),
        Row::body(
            "Split this wallet: this device splits its words into n share files. Any t \
             of them can sign, and any t give the words back.",
        )
        .small(),
        Row::body(
            "No Taproot: a threshold key here signs ECDSA, so the addresses are native \
             SegWit, nested SegWit or legacy.",
        )
        .small(),
    ];
    let _ = menu::show_doc(ui, &rows, false, false);
}

/// A message, and a key to go on.
pub(super) fn say(ui: &mut Ui<'_>, head: &str, a: &str, b: &str) {
    menu::message(ui.panel, head, a, b);
    menu::wait_for_any_key(ui);
}

/// A question on the approval page: yes with the confirm key, no with cancel.
pub(super) fn approve(
    ui: &mut Ui<'_>,
    head: &str,
    main: &str,
    small: &[&str],
    yes: &str,
    no: &str,
) -> bool {
    let page = Approval {
        head,
        art: None,
        main,
        small,
        yes: (display::CONFIRM, yes),
        no: (display::CANCEL, no),
    };
    display::draw_field_page(ui.panel, |c| {
        catcard_ui::approval::draw(c, &display::FONTS, &page)
    });
    menu::confirmed(ui)
}

/// The fingerprint as the screens write it.
pub(super) fn hex4(fp: [u8; 4]) -> heapless::String<8> {
    use core::fmt::Write as _;
    let mut s = heapless::String::new();
    let [a, b, c, d] = fp;
    let _ = write!(s, "{a:02X}{b:02X}{c:02X}{d:02X}");
    s
}

// ---------------------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------------------

/// A share record's size per member besides the holder: the pairwise OT state, measured
/// at 12,778 bytes (docs/TSS.md, "Measured"), rounded up.
const RECORD_PER_PEER: usize = 12_800;

/// A share record's size for an `n`-member wallet: 13,120 bytes at 2 members, 102,562 at
/// 9 (measured), and this rounds up.
pub(super) const fn record_len(n: u8) -> usize {
    512 + RECORD_PER_PEER * (n as usize).saturating_sub(1)
}

/// A flow's work on an `n`-member key, by what sets its peak.
#[derive(Copy, Clone)]
pub(super) enum Work {
    /// This member's whole create-together session: its DKG rounds, and the record
    /// encoded and copied at the end while the session still lives.
    Create,
    /// An export: tsslib's reshare to `n` members, then every member's bundle held while
    /// each in turn is encoded and sealed for its card.
    Export,
    /// Decoding one member's record.
    Decode,
}

/// The heap `work` takes at its peak on an `n`-member key, besides what the caller holds.
///
/// Measured on the host with 32-bit pointers (wasm32, a tagging allocator that charges
/// each block as this heap does: a two-word header and the payload rounded to a word),
/// 2026-10-04, tsslib 0.2.12 and its binary key encoding, 2 to 9 members (the shapes of
/// docs/TSS.md, "Memory"). Rounded up to the next KB. Create together has no 2-member
/// shape (`catcard_tss::can_create_together`).
const fn peak(work: Work, n: u8) -> usize {
    const CREATE: [usize; 8] = [0, 126, 165, 207, 249, 291, 331, 374];
    const EXPORT: [usize; 8] = [71, 152, 259, 389, 544, 724, 928, 1156];
    const DECODE: [usize; 8] = [45, 65, 85, 105, 125, 145, 165, 185];
    let i = (n as usize).wrapping_sub(2);
    if i >= 8 {
        return usize::MAX / 2;
    }
    1024 * match work {
        Work::Create if n >= 3 => CREATE[i],
        Work::Create => return usize::MAX / 2,
        Work::Export => EXPORT[i],
        Work::Decode => DECODE[i],
    }
}

/// Held besides tsslib's peak: the card, the screens, the settings volume.
const MARGIN: usize = 32 * 1024;

/// What `work` on an `n`-member key needs with `held` bytes already in use for it.
const fn need(work: Work, n: u8, held: usize) -> usize {
    peak(work, n) + held + MARGIN
}

/// The app area, lent to the heap for one flow, and the check that it is enough.
pub(super) struct Room {
    _area: crate::heap::AppArea,
}

impl Room {
    /// Borrow the app area. `None`, said on screen, if an app holds it.
    pub(super) fn take(ui: &mut Ui<'_>, head: &str) -> Option<Room> {
        match crate::heap::borrow_app_area() {
            Some(area) => Some(Room { _area: area }),
            None => {
                say(ui, head, "memory in use:", "restart, then try again");
                None
            }
        }
    }

    /// The most members `work` can have with `held(n)` bytes in use besides, given what
    /// is free now. Zero when not even two fit.
    pub(super) fn most_members(work: Work, held: impl Fn(u8) -> usize) -> u8 {
        let (free, _) = crate::heap::free();
        (2..=catcard_tss::MAX_MEMBERS)
            .rev()
            .find(|&n| need(work, n, held(n)) <= free)
            .unwrap_or(0)
    }

    /// Whether `work` on an `n`-member key fits with `held` bytes besides; says why not.
    pub(super) fn fits(ui: &mut Ui<'_>, head: &str, work: Work, n: u8, held: usize) -> bool {
        let (free, _) = crate::heap::free();
        let need = need(work, n, held);
        if need <= free {
            return true;
        }
        crate::catlog!("tss: {} members need {} B, {} B free", n, need, free);
        say(ui, head, "too many members", "for this device's memory");
        false
    }
}

/// A buffer from the heap, wiped when dropped: the bytes of a record, a file, a message.
pub(super) struct Buf {
    block: crate::heap::Block,
    len: usize,
}

impl Buf {
    /// Room for `cap` bytes, empty. `None` when the heap has none.
    pub(super) fn with_capacity(cap: usize) -> Option<Buf> {
        Some(Buf {
            block: crate::heap::take(cap.max(1))?,
            len: 0,
        })
    }

    /// A copy of `bytes`.
    pub(super) fn copy_of(bytes: &[u8]) -> Option<Buf> {
        let mut b = Buf::with_capacity(bytes.len())?;
        b.block.bytes()[..bytes.len()].copy_from_slice(bytes);
        b.len = bytes.len();
        Some(b)
    }

    pub(super) fn as_slice(&mut self) -> &[u8] {
        &self.block.bytes()[..self.len]
    }

    /// The whole block, to fill; then [`set_len`](Self::set_len).
    pub(super) fn space(&mut self) -> &mut [u8] {
        self.block.bytes()
    }

    pub(super) fn set_len(&mut self, len: usize) {
        self.len = len.min(self.block.bytes().len());
    }
}

/// A refusal, in the words a screen has room for.
pub(super) fn describe(e: &catcard_tss::Error) -> &'static str {
    use catcard_tss::{Error as E, Refused as R};
    match e {
        E::Parameters => "the numbers do not fit",
        E::Randomness => "no randomness",
        E::Refused(r) => match r {
            R::Malformed => "a damaged message",
            R::Version => "another firmware's message",
            R::WrongProtocol | R::WrongSession => "another session's message",
            R::UnknownMember => "not from a member",
            R::FromSelf => "this device's own message",
            R::NotForMe => "for another member",
            R::BadRound => "a step this has not got",
            R::Unsigned | R::BadSignature => "a message not signed by its member",
            R::Undecryptable => "a message that does not decrypt",
            R::Replayed => "a message already taken",
            R::Early => "a message too early",
            R::UnexpectedContent => "an unexpected message",
            R::CommitmentMismatch => "a key that was not the one promised",
        },
        E::Format(_) => "not a share this reads",
        E::State(_) => "out of order",
        E::Protocol(_) => "a member's message was wrong",
        E::Codex32(_) => "a share string is not valid",
        E::NotEnoughShares => "not enough shares",
        E::Mismatch => "shares of different wallets",
        E::BiasedShape => "not a safe shape to create",
    }
}
