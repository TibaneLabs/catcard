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
use super::drive::{self, Way};
use super::rand::{Drbg, Fresh};
use super::{Room, Work, describe, rebuild, say, store};
use crate::menu::{self, Line, Storage};
use crate::signtx::Sink;
use crate::ui::Ui;

const HEAD: &str = "Sign together";

/// Most inputs signed together at once: the session's limit.
const MAX_INPUTS: usize = catcard_tss::MAX_REQUESTS;

/// Sign `requests` together with the other members of the TSS wallet in force: the
/// signatures, in the order of `requests`, or `None` once the reason has been said.
#[inline(never)]
pub(crate) fn together(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    requests: &[SignRequest],
) -> Option<Vec<EcdsaSignature>> {
    let (summary, index) = crate::key::tss()?.clone();
    let _room = Room::take(ui, HEAD)?;
    if !Room::fits(ui, HEAD, Work::Create, summary.n, 0) {
        return None;
    }
    let way = drive::pick_way(ui, HEAD)?;
    let mut record = record_with_pairs(gate, login, ui, index, way.files())?;
    let me = record.member();
    let mut wallet = [0u8; 8];
    wallet.copy_from_slice(&record.wallet_id()[..8]);

    let (id, signers, start, mut medium) = match menu::pick_row(
        ui,
        HEAD,
        "every signer does this",
        &["Start: choose co-signers", "Join a session"],
    )? {
        0 => {
            let signers = choose_signers(ui, &record)?;
            let id = catcard_tss::new_session_id(&mut Drbg(ui.drbg)).ok()?;
            let invite = Invitation::Sign {
                wallet,
                signers: drive::set_of(&signers),
            };
            (id, signers, true, drive::start_medium(way, id, invite))
        }
        _ => {
            let (id, set, medium) = drive::join(ui, HEAD, way, me, |inv| match inv {
                Invitation::Sign { wallet: w, signers } if w == wallet => Some(signers),
                _ => None,
            })?;
            (id, drive::members_of(set), false, medium)
        }
    };

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
    let invite = start.then_some(Invitation::Sign {
        wallet,
        signers: drive::set_of(&signers),
    });
    if !drive::run(ui, &mut medium, &mut session, invite) {
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

/// This member and `t - 1` others, chosen one at a time, ascending.
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
                crate::catlog!("tss: input {} not signable: {:?}", index, e);
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

    let Some(sigs) = together(gate, login, ui, &requests) else {
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
