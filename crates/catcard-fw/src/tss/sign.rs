//! Signing together with the TSS wallet in force (docs/TSS.md, "Sign").
//!
//! A TSS wallet's key is on no device, so a signature is a session among `t` of its
//! members, each on its own CatCard, each having reviewed the same thing on its own
//! screen. What is signed is a list of digests with the path below the wallet's key each
//! is for ([`SignRequest`]); [`together`] runs the session for any such list -- a
//! transaction's inputs ([`sign_psbt`]), a message (`crate::signmsg`).
//!
//! # The session
//!
//! One member starts it and chooses who signs: itself and `t - 1` others. The others
//! join -- from the card, or by scanning the starting member's first code -- and must
//! be among those chosen. Every member's session code covers the wallet, the signers and
//! every digest and path (`catcard_tss::Session::sign`), so members holding different
//! transactions compare different words and the session stops before any signing round.
//!
//! The pairs between the signers have to be set up, kept in the cache on the card (or,
//! by QR, the device's own Virtual Disk); one that is missing is said, and is made again
//! with Rebuild setup first.
//!
//! The session's randomness -- its identity key and every nonce -- comes from a pool of
//! its own, gathered from every chip for this session ([`Fresh::gather_own`]).

use alloc::vec::Vec;
use catcard_tss::{EcdsaSignature, Session, ShareRecord, SignMode, SignRequest};
use catcard_wallet::psbtview;
use catcard_wallet::signer::{self, Digest, Keys};
use core::fmt::Write as _;
use outscript::psbt::Psbt;

use super::card::{self, Invitation};
use super::drive::{self, Medium, Way};
use super::rand::{Drbg, Fresh};
use super::{Buf, Room, Work, describe, rebuild, say, store};
use crate::menu::{self, Line, Storage};
use crate::signtx::Sink;
use crate::ui::Ui;

const HEAD: &str = "Sign together";

/// Most inputs signed together at once: the session's limit.
const MAX_INPUTS: usize = catcard_tss::MAX_REQUESTS;

/// What a signing session signs, as the starter writes it beside the invitation and every
/// other signer reads and reviews it: a PSBT, or a message request
/// (`signmsg::tss_request`).
#[derive(Copy, Clone, PartialEq, Eq)]
pub(crate) enum Kind {
    Psbt,
    Message,
}

impl Kind {
    /// Its byte, first in a request a code carries (a card names it by file instead).
    #[cfg(feature = "board-q1")]
    fn code(self) -> u8 {
        match self {
            Kind::Psbt => 1,
            Kind::Message => 2,
        }
    }
    fn of(code: u8) -> Option<Kind> {
        match code {
            1 => Some(Kind::Psbt),
            2 => Some(Kind::Message),
            _ => None,
        }
    }
}

/// How this member comes to a signing session.
pub(crate) enum How<'a> {
    /// It starts one for `body`, of `kind`: what every signer will review.
    Start { kind: Kind, body: &'a [u8] },
    /// It joins one another member started ([`join_signing`]), whose request it has just
    /// reviewed here.
    Join(alloc::boxed::Box<Joining>),
}

/// A session found to join, and everything already read with it.
pub(crate) struct Joining {
    way: Way,
    id: [u8; catcard_tss::SESSION_ID_LEN],
    needed: u8,
    starter: u8,
    /// The set the starter chose, by QR; 0 on a card, where it is who joins first.
    signers: u16,
    medium: Medium,
    record: ShareRecord,
}

/// The way messages move and this member's record with its pairs, for a session about
/// to start or be joined.
fn prepare(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) -> Option<(Way, ShareRecord)> {
    let (_, index) = crate::key::tss()?;
    let index = *index;
    let way = drive::pick_way(ui, HEAD)?;
    let record = record_with_pairs(gate, login, ui, index, way.files())?;
    Some((way, record))
}

/// Sign `requests` together with the other members of the TSS wallet in force, starting
/// the session or joining one ([`How`]): the signatures, in the order of `requests`, or
/// `None` once the reason has been said.
///
/// On a card the starter names no signers: it writes the request and waits, and the
/// first `t - 1` members to join -- each having reviewed the request on its own screen --
/// sign with it ([`lobby`]). By QR the starter has chosen them, and its code carries the
/// request.
#[inline(never)]
pub(crate) fn together(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    requests: &[SignRequest],
    how: How<'_>,
) -> Option<Vec<EcdsaSignature>> {
    let (summary, _) = crate::key::tss()?.clone();
    let _room = Room::take(ui, HEAD)?;
    if !Room::fits(ui, HEAD, Work::Create, summary.n, 0) {
        return None;
    }
    let (way, id, signers, mut medium, mut record) = match how {
        How::Start { kind, body } => {
            let (way, record) = prepare(gate, login, ui)?;
            let me = record.member();
            let mut wallet = [0u8; 8];
            wallet.copy_from_slice(&record.wallet_id()[..8]);
            let id = catcard_tss::new_session_id(&mut Drbg(ui.drbg)).ok()?;
            match way {
                Way::Sd => {
                    let invite = Invitation::Sign {
                        wallet,
                        needed: record.t(),
                        starter: me,
                        signers: 0,
                    };
                    card::wait(ui.panel, HEAD, Storage::Sd, true);
                    if let Err(why) = card::write_request(Storage::Sd, &id, invite, kind, body) {
                        say(ui, HEAD, "cannot write it:", why);
                        return None;
                    }
                    let signers = lobby(ui, &id, me, me, record.t())?;
                    (way, id, signers, Medium::Sd, record)
                }
                #[cfg(feature = "board-q1")]
                Way::Qr => {
                    let signers = choose_signers(ui, &record)?;
                    let invite = Invitation::Sign {
                        wallet,
                        needed: record.t(),
                        starter: me,
                        signers: drive::set_of(&signers),
                    };
                    let mut request = alloc::vec![kind.code()];
                    request.extend_from_slice(body);
                    let ex = super::qr::Exchange::new(id, Some(invite)).with_request(request);
                    (way, id, signers, Medium::Qr(ex), record)
                }
            }
        }
        How::Join(j) => {
            let j = *j;
            let me = j.record.member();
            let signers = if j.signers != 0 {
                drive::members_of(j.signers)
            } else {
                // Join on the card: the next mark, unless this member is in already.
                card::wait(ui.panel, HEAD, Storage::Sd, true);
                let have = match card::joined(Storage::Sd, &j.id) {
                    Ok(h) => h,
                    Err(why) => {
                        say(ui, HEAD, "cannot read the card:", why);
                        return None;
                    }
                };
                if !have.contains(&me) {
                    if have.len() + 1 >= usize::from(j.needed) {
                        say(ui, HEAD, "enough signers", "have joined already");
                        return None;
                    }
                    if let Err(why) = card::write_joined(Storage::Sd, &j.id, have.len() + 1, me) {
                        say(ui, HEAD, "cannot write it:", why);
                        return None;
                    }
                }
                lobby(ui, &j.id, j.starter, me, j.needed)?
            };
            (j.way, j.id, signers, j.medium, j.record)
        }
    };
    let me = record.member();

    let missing = record.missing_pairs(&signers);
    if !missing.is_empty() {
        let mut l: Line = Line::new();
        let _ = l.push_str("with member");
        for m in &missing {
            let _ = write!(l, " {m}");
        }
        say(ui, HEAD, "no setup yet", &l);
        say(ui, HEAD, "run Rebuild setup", "with them first");
        return None;
    }

    let mut fresh = Fresh::gather_own(gate, ui)?;
    let mut busy = Some(menu::blocking_screen(
        ui.panel,
        HEAD,
        "making this member's keys",
    ));
    let made = crate::keywork::run(|kw| {
        Session::sign(
            id,
            &record,
            &signers,
            requests,
            SignMode::default(),
            &mut fresh,
            kw,
        )
    });
    drop(fresh);
    busy.take();
    record.drop_pairs();
    drop(record);
    let mut session = match made {
        Ok(s) => s,
        Err(e) => {
            say(ui, HEAD, "cannot start:", describe(&e));
            return None;
        }
    };
    crate::catlog!(
        "tss: signing {} as member {} of {} signers, {} digests",
        card::short_id(&id).as_str(),
        me,
        signers.len(),
        requests.len()
    );
    // The invitation is on the card already, or in the starter's codes.
    if !drive::run(ui, &mut medium, &mut session, None) {
        return None;
    }
    if way == Way::Sd
        && let Some(&next) = signers.iter().find(|&&m| m > me).or(signers.first())
    {
        drive::pass_on(ui, next);
    }
    let sigs = session.signatures();
    if sigs.as_ref().is_none_or(|s| s.len() != requests.len()) {
        say(ui, HEAD, "the session ended", "with no signatures");
        return None;
    }
    sigs
}

/// On the card, until the starter and `needed - 1` joined members are known: the signer
/// set, ascending, once it is -- `None` if the owner leaves, or the set filled without
/// this member.
fn lobby(
    ui: &mut Ui<'_>,
    id: &[u8; catcard_tss::SESSION_ID_LEN],
    starter: u8,
    me: u8,
    needed: u8,
) -> Option<Vec<u8>> {
    let needed = usize::from(needed);
    // Bounded: each pass waits for the owner, who can leave.
    for _ in 0..256 {
        card::wait(ui.panel, HEAD, Storage::Sd, false);
        let have = card::joined(Storage::Sd, id).unwrap_or_default();
        let mut set: Vec<u8> = alloc::vec![starter];
        set.extend(
            have.iter()
                .copied()
                .filter(|&m| m != starter)
                .take(needed - 1),
        );
        if set.len() == needed {
            if !set.contains(&me) {
                say(ui, HEAD, "enough signers", "have joined already");
                return None;
            }
            set.sort_unstable();
            return Some(set);
        }
        let mut note: heapless::String<120> = heapless::String::new();
        let more = needed - set.len();
        let _ = write!(
            note,
            "Waiting for {more} more signer{}. Pass the card to them -- each chooses Sign, \
             Join signing -- then put it back here.",
            if more == 1 { "" } else { "s" }
        );
        match menu::pick_row(ui, HEAD, &note, &["The card is back", "Leave"]) {
            Some(0) => {}
            _ => {
                if drive::leave(ui) {
                    return None;
                }
            }
        }
    }
    None
}

/// Sign -> Join signing, with a TSS wallet in force: find the session another member
/// started, read what it signs, review it here exactly as if this device had been handed
/// it, and sign it together (`How::Join`).
#[inline(never)]
pub(crate) fn join_signing(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) {
    let Some((way, record)) = prepare(gate, login, ui) else {
        return;
    };
    let me = record.member();
    let mut wallet = [0u8; 8];
    wallet.copy_from_slice(&record.wallet_id()[..8]);
    let found: Option<(Joining, Buf)> = match way {
        Way::Sd => join_from_card(ui, wallet, me, record),
        #[cfg(feature = "board-q1")]
        Way::Qr => join_from_code(ui, wallet, me, record),
    };
    let Some((joining, mut request)) = found else {
        return;
    };
    let bytes = request.as_slice();
    let Some((&code, body)) = bytes.split_first() else {
        return say(ui, HEAD, "an empty request", "");
    };
    match Kind::of(code) {
        Some(Kind::Psbt) => join_psbt(gate, login, ui, body, joining),
        Some(Kind::Message) => crate::signmsg::tss_join(gate, login, ui, body, joining),
        None => say(ui, HEAD, "a request this", "does not know"),
    }
}

/// A signing session on the card for this wallet that this member can join, and its
/// request (kind byte first).
fn join_from_card(
    ui: &mut Ui<'_>,
    wallet: [u8; 8],
    me: u8,
    record: ShareRecord,
) -> Option<(Joining, Buf)> {
    card::wait(ui.panel, HEAD, Storage::Sd, false);
    let found = match card::sessions(Storage::Sd) {
        Ok(f) => f,
        Err(why) => {
            say(ui, HEAD, "cannot read the files:", why);
            return None;
        }
    };
    let open: heapless::Vec<([u8; catcard_tss::SESSION_ID_LEN], u8, u8), { card::MAX_SESSIONS }> =
        found
            .iter()
            .filter_map(|s| match s.invite {
                Invitation::Sign {
                    wallet: w,
                    needed,
                    starter,
                    signers: 0,
                } if w == wallet && starter != me => Some((s.id, needed, starter)),
                _ => None,
            })
            .collect();
    let (id, needed, starter) = match open.len() {
        0 => {
            say(ui, HEAD, "no signing session", "on this card");
            return None;
        }
        1 => open[0],
        _ => {
            let labels: heapless::Vec<heapless::String<8>, { card::MAX_SESSIONS }> =
                open.iter().map(|(id, _, _)| card::short_id(id)).collect();
            let rows: heapless::Vec<&str, { card::MAX_SESSIONS }> =
                labels.iter().map(|l| l.as_str()).collect();
            open[menu::pick_row(ui, HEAD, "which session?", &rows)?]
        }
    };
    let request = match card::read_request(Storage::Sd, &id) {
        Ok(Some(r)) => r,
        Ok(None) => {
            say(ui, HEAD, "the session has", "no request");
            return None;
        }
        Err(why) => {
            say(ui, HEAD, "cannot read it:", why);
            return None;
        }
    };
    Some((
        Joining {
            way: Way::Sd,
            id,
            needed,
            starter,
            signers: 0,
            medium: Medium::Sd,
            record,
        },
        request,
    ))
}

/// The starting member's first code, for this wallet with this member among the
/// signers it chose, and the request it carries.
#[cfg(feature = "board-q1")]
fn join_from_code(
    ui: &mut Ui<'_>,
    wallet: [u8; 8],
    me: u8,
    record: ShareRecord,
) -> Option<(Joining, Buf)> {
    let mut found = match super::qr::find(ui, HEAD) {
        Ok(Some(f)) => f,
        Ok(None) => return None,
        Err(why) => {
            say(ui, HEAD, "not read:", why);
            return None;
        }
    };
    let Invitation::Sign {
        wallet: w,
        needed,
        starter,
        signers,
    } = found.invite
    else {
        say(ui, HEAD, "not a signing", "session's code");
        return None;
    };
    if w != wallet || signers & (1 << me) == 0 {
        say(ui, HEAD, "not a session this", "member signs in");
        return None;
    }
    let Some(bytes) = found.request() else {
        say(ui, HEAD, "the code has", "no request");
        return None;
    };
    let mut request = Buf::with_capacity(bytes.len())?;
    request.space()[..bytes.len()].copy_from_slice(&bytes);
    request.set_len(bytes.len());
    let medium = Medium::Qr(found.exchange(me));
    Some((
        Joining {
            way: Way::Qr,
            id: found.id,
            needed,
            starter,
            signers,
            medium,
            record,
        },
        request,
    ))
}

/// The kept record at `index`, decoded, with its pairs from the cache on `storage`.
fn record_with_pairs(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    index: usize,
    storage: Storage,
) -> Option<ShareRecord> {
    let bytes = match store::read(gate, login, ui, index) {
        Ok(b) => b,
        Err(why) => {
            say(ui, HEAD, "cannot read the share:", why);
            return None;
        }
    };
    let mut bytes = bytes;
    let decoded = crate::keywork::run(|kw| ShareRecord::from_bytes(bytes.as_slice(), kw));
    drop(bytes);
    let mut record = match decoded {
        Ok(r) => r,
        Err(e) => {
            say(ui, HEAD, "the share is refused:", describe(&e));
            return None;
        }
    };
    match store::cache_key(gate, login, ui, &record) {
        Ok(key) => match rebuild::load_cache(ui, storage, &mut record, &key) {
            Ok(rebuild::Loaded::Refused(r)) => {
                say(ui, HEAD, "the setup found is", rebuild::refusal(r))
            }
            Ok(_) => {}
            Err(why) => crate::catlog!("tss: no setup read: {}", why),
        },
        Err(why) => crate::catlog!("tss: no setup key: {}", why),
    }
    Some(record)
}

/// This member and `t - 1` others, chosen one at a time, ascending: by QR, where there is
/// no card for signers to join on.
#[cfg(feature = "board-q1")]
fn choose_signers(ui: &mut Ui<'_>, record: &ShareRecord) -> Option<Vec<u8>> {
    let me = record.member();
    let mut chosen: Vec<u8> = alloc::vec![me];
    while chosen.len() < usize::from(record.t()) {
        let left: heapless::Vec<u8, 9> = (1..=record.n()).filter(|m| !chosen.contains(m)).collect();
        let labels: heapless::Vec<Line, 9> = left
            .iter()
            .map(|m| {
                let mut l = Line::new();
                let _ = write!(l, "Member {m}");
                l
            })
            .collect();
        let rows: heapless::Vec<&str, 9> = labels.iter().map(|l| l.as_str()).collect();
        let mut note: Line = Line::new();
        let _ = write!(note, "co-signer {} of {}", chosen.len(), record.t() - 1);
        let pick = menu::pick_row(ui, HEAD, &note, &rows)?;
        chosen.push(left[pick]);
    }
    chosen.sort_unstable();
    Some(chosen)
}

/// Sign a PSBT with the TSS wallet in force: reviewed here exactly as the seed's are --
/// the inputs this wallet's key is in, the outputs, change only where this key rebuilds
/// the script -- then each input's digest signed [`together`] and written into the PSBT,
/// which goes out as any signed PSBT does (`signtx::deliver`).
#[inline(never)]
pub(crate) fn sign_psbt(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    buf: &mut [u8],
    spare: &mut [u8],
    len: usize,
    sink: &mut Sink<'_, '_>,
) {
    psbt_flow(gate, login, ui, buf, spare, len, sink, None);
}

/// Join signing a PSBT another member started: its bytes from the session into the
/// signing workspace, then the same review and the same delivery as any PSBT.
fn join_psbt(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    body: &[u8],
    joining: Joining,
) {
    let mut work = match crate::signtx::Workspace::take() {
        Ok(w) => w,
        Err(why) => return say(ui, HEAD, why, ""),
    };
    let (buf, spare) = work.split();
    if body.len() > buf.len() {
        return say(ui, HEAD, "too big for", "this board");
    }
    buf[..body.len()].copy_from_slice(body);
    let mut sink = Sink::Files {
        dest: &crate::signtx::SignDest::SINGLE,
        storage: Storage::Sd,
    };
    psbt_flow(
        gate,
        login,
        ui,
        buf,
        spare,
        body.len(),
        &mut sink,
        Some(joining),
    );
}

/// [`sign_psbt`], starting the session (`joining` none) or joining one.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn psbt_flow(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    buf: &mut [u8],
    spare: &mut [u8],
    len: usize,
    sink: &mut Sink<'_, '_>,
    joining: Option<Joining>,
) {
    let refuse = |ui: &mut Ui<'_>, sink: &mut Sink<'_, '_>, why: &'static str| {
        sink.refuse(why);
        say(ui, HEAD, why, "");
    };
    // A computer cannot wait for the other members' devices, and nothing is signed here
    // without them.
    if sink.host().is_some() {
        return refuse(ui, sink, "signs at the devices");
    }
    if catcard_wallet::psbtv2::is_v2(&buf[..len]) {
        return refuse(ui, sink, "PSBT v2: save as v0");
    }
    let Some((s, _)) = crate::key::tss() else {
        return;
    };
    let key = super::view::xpub(s);
    let origin = s.path.clone();
    let keys = Keys::Public {
        key: &key,
        origin: &origin,
    };
    let fingerprint = s.fingerprint;
    let owner = psbtview::Owner {
        keys,
        fingerprint,
        wallets: &[],
        bare_keys: &[],
    };
    let psbt = match Psbt::parse(&buf[..len]) {
        Ok(p) => p,
        Err(_) => return refuse(ui, sink, "not a PSBT this reads"),
    };
    let policy = psbtview::Policy {
        max_fee_percent: crate::prefs::current().fee_cap.percent_limit(),
        sighash: signer::SighashPolicy::Block,
        ..psbtview::Policy::default()
    };
    let mut busy = menu::Working::new(ui.panel, HEAD, "checking the transaction");
    let summary = crate::signtx::summarise(&psbt, &owner, &policy);
    busy.tick(ui.panel);
    let summary = match summary {
        Ok(sum) => sum,
        Err(r) => return refuse(ui, sink, crate::signtx::refusal_text(r)),
    };
    let mut ours = [0usize; MAX_INPUTS];
    let signable =
        crate::keywork::run(|kw| psbtview::our_inputs(&psbt, keys, fingerprint, &mut ours, kw));
    if signable == 0 {
        return refuse(ui, sink, "no input of this wallet");
    }
    drop(busy);
    let mut fill = |start: usize, page: &mut [psbtview::Destination]| {
        crate::keywork::run(|kw| {
            psbtview::destinations_with(
                &psbt,
                &owner,
                crate::prefs::network(),
                &summary.spent(),
                start,
                page,
                kw,
            )
        })
    };
    if !crate::signtx::review(ui, &psbt, &summary, signable, 0, &mut fill) {
        sink.decline();
        return say(ui, HEAD, "not signed", "");
    }

    // Each input's digest, as `outscript` would sign it; `spare` is its scratch.
    let mut digests: Vec<(usize, Digest)> = Vec::with_capacity(signable);
    for &index in &ours[..signable] {
        let d = crate::keywork::run(|kw| {
            signer::digest_for_input(&psbt, index, keys, fingerprint, spare, kw)
        });
        match d {
            Ok(d) => digests.push((index, d)),
            Err(e) => {
                let _ = e;
                crate::catlog!("tss: input {} not signable", index);
                return refuse(ui, sink, "an input cannot be signed together");
            }
        }
    }
    let requests: Vec<SignRequest> = digests
        .iter()
        .map(|(_, d)| SignRequest {
            path: d.steps().to_vec(),
            sighash: d.digest,
        })
        .collect();

    let how = match joining {
        Some(j) => How::Join(alloc::boxed::Box::new(j)),
        None => How::Start {
            kind: Kind::Psbt,
            body: &buf[..len],
        },
    };
    let Some(sigs) = together(gate, login, ui, &requests, how) else {
        sink.decline();
        return;
    };

    let (mut from, mut into) = (buf, spare);
    let mut at = len;
    for ((index, d), sig) in digests.iter().zip(&sigs) {
        if sig.child_public_key != d.pubkey {
            crate::catlog!("tss: input {}: signed under another key", index);
            return refuse(ui, sink, "a signature is for another key");
        }
        let Ok(psbt) = Psbt::parse(&from[..at]) else {
            return refuse(ui, sink, "the PSBT did not reparse");
        };
        match signer::apply_signature(&psbt, *index, &d.pubkey, &sig.der, into) {
            Ok(n) => {
                core::mem::swap(&mut from, &mut into);
                at = n;
            }
            Err(_) => return refuse(ui, sink, "a signature did not fit"),
        }
    }
    crate::catlog!("tss: {} inputs signed together", digests.len());
    crate::signtx::deliver(ui, sink, None, from, into, at, digests.len(), signable);
}
