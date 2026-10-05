//! A session: one run of a protocol among members, driven by the bytes handed to it.
//!
//! ```text
//!   new ──► outbox: round-0 commitment ──► receive every member's commitment
//!       ──► outbox: round-1 identity   ──► receive every member's identity
//!       ──► code() shown on every device, the user compares ──► confirm()
//!       ──► outbox: round 2 ──► receive round 2 ──► outbox: round 3 ──► ...
//!       ──► Finished: share() / signatures() / install_pair()
//! ```
//!
//! Rounds 0 and 1 are commit-then-reveal (see `crate::code`): a member's identity key
//! leaves it only once it holds every other member's commitment, and an identity that
//! arrives before then is refused ([`Refused::Early`]) rather than held, so the session
//! never stores bytes it has not checked. [`Session::awaiting`] does not ask for
//! identities until the commitments are complete, so a driver that follows it never
//! sees that refusal.
//!
//! The session never waits and never does I/O. [`Session::receive`] takes one envelope,
//! checks it (framing, session, member, round, replay, signature, decryption, content)
//! and hands its tsslib messages to the protocol, which may answer at once; whatever it
//! answers is sealed into envelopes and queued for [`Session::take_outbox`].
//! [`Session::awaiting`] says which messages the current round still needs, by the names
//! their files have.
//!
//! A refused message ([`Error::Refused`]) leaves the session as it was. A message that
//! passes every check and is then rejected by tsslib ends it ([`Status::Failed`]): it was
//! signed by a member, so that member is cheating or broken, and the protocol cannot
//! continue around it.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use catcard_wallet::KeyWork;
use purecrypto::ec::secp256k1::Scalar;
use purecrypto::ec::secp256k1::ecdsa::{Secp256k1EcdsaPublicKey, Secp256k1EcdsaSignature};
use purecrypto::hash::{Digest, Sha256};
use tsslib::dklstss::{
    CheckedSigningParty, KeygenParty, PairOTState, PairSetupParty, SigningParty,
};
use tsslib::tss::{Message as TssMessage, MessageBroker, Parameters, PartyId, Payload, WireFormat};
use zeroize::{Zeroize, Zeroizing};

use crate::broker::Mailbox;
use crate::code::{COMMITMENT_LEN, Context, NONCE_LEN, SessionCode, commitment};
use crate::envelope::{
    COMMIT_ROUND, Envelope, FIRST_PROTOCOL_ROUND, HEADER_LEN, Header, Protocol, REVEAL_ROUND,
    Refused, SESSION_ID_LEN, SIG_LEN, file_name, frame, signed_digest,
};
use crate::identity::{IdentityKey, UnicastContext, valid_public, verify};
use crate::rng::{Armed, Entropy, draw};
use crate::share::{Origin, SecretKey, SecretPair, ShareRecord, check_params, compress};
use crate::{Error, PUBKEY_LEN, member_id};

/// Most sighashes one signing session carries.
pub const MAX_REQUESTS: usize = 64;

/// The bytes of the header the unicast encryption authenticates: everything but the
/// payload length, which the ciphertext fixes anyway.
const AAD_LEN: usize = HEADER_LEN - 4;

/// A fresh session id from `source` (the UI DRBG).
pub fn new_session_id(source: &mut dyn Entropy) -> Result<[u8; SESSION_ID_LEN], Error> {
    let mut id = [0u8; SESSION_ID_LEN];
    draw(source, &mut id)?;
    Ok(id)
}

/// Which DKLs signing protocol a signing session runs. Every signer must use the same;
/// it is part of the session code.
///
/// [`SignMode::default()`] is [`Checked`](SignMode::Checked): a caller that does not
/// choose gets the mode that catches a cheating co-signer. [`Plain`](SignMode::Plain)
/// stays available for whoever decides half the wire and work is worth more.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum SignMode {
    /// tsslib's default `SigningParty`.
    Plain = 1,
    /// tsslib's `CheckedSigningParty`: each multiplication twice with a consistency
    /// check, catching one form of selective-failure attack and naming the culprit.
    /// About twice the messages and the work. The default.
    #[default]
    Checked = 2,
}

/// One thing to sign: a sighash, under the key at a non-hardened `path` below the
/// wallet key (`[0, i]` for receive address `i`, `[1, i]` for change).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignRequest {
    pub path: Vec<u32>,
    pub sighash: [u8; 32],
}

/// A finished threshold signature: standard ECDSA, low-S.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcdsaSignature {
    /// `r || s`, 32 bytes each.
    pub compact: [u8; 64],
    /// DER `SEQUENCE { INTEGER r, INTEGER s }`, without a sighash-type byte.
    pub der: Vec<u8>,
    /// The key it verifies under: the wallet key at the request's path.
    pub child_public_key: [u8; PUBKEY_LEN],
}

/// Where a session is.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// Waiting for members' commitments (round 0), then their identities (round 1).
    Introducing,
    /// Every identity is in: show [`Session::code`] and wait for [`Session::confirm`].
    Comparing,
    /// Protocol rounds under way.
    Running,
    /// Done: [`Session::share`] or [`Session::signatures`].
    Finished,
    /// Ended by a failure: [`Session::failure`].
    Failed,
}

/// A sealed envelope to deliver.
#[derive(Clone, Debug)]
pub struct Outgoing {
    pub round: u8,
    pub from: u8,
    /// A member, or 0 for every member.
    pub to: u8,
    pub bytes: Vec<u8>,
}

impl Outgoing {
    /// The name of the file it travels in.
    pub fn file_name(&self) -> String {
        file_name(self.round, self.from, self.to)
    }
}

// ---------------------------------------------------------------------------------------
// The tsslib message types, by protocol and round
// ---------------------------------------------------------------------------------------

#[derive(Copy, Clone, PartialEq, Eq)]
enum Family {
    Keygen,
    Sign,
    CheckedSign,
    PairSetup,
}

struct MsgType {
    family: Family,
    /// What the type is called inside an envelope.
    code: u8,
    name: &'static str,
    round: u8,
    broadcast: bool,
}

/// tsslib's message types and their order.
/// Source: tsslib 0.2.14 `src/dklstss/keygen_party.rs`, `signing_party.rs`,
/// `signing_checked_party.rs` and `pair_setup_party.rs` (`TYPE_*` constants and the
/// module docs' round lists).
/// `round` is the envelope's, after the two rounds of identities: tsslib's message
/// rounds in order from round 2. Since 0.2.14 the keygen base-OT responses (`r2`) travel
/// with the echo, and so do the signing Alice envelopes (`r2`): one round fewer for
/// each. The `broadcast` flags are what each party sends with `to == None`; a message
/// that disagrees fails the session rather than being sealed under the wrong address.
#[rustfmt::skip]
const TYPES: &[MsgType] = &[
    MsgType { family: Family::Keygen, code: 1, name: "dkls:keygen:r1bc", round: 2, broadcast: true },
    MsgType { family: Family::Keygen, code: 2, name: "dkls:keygen:r1uc", round: 2, broadcast: false },
    MsgType { family: Family::Keygen, code: 3, name: "dkls:keygen:echo", round: 3, broadcast: true },
    MsgType { family: Family::Keygen, code: 4, name: "dkls:keygen:r2", round: 3, broadcast: false },
    MsgType { family: Family::Sign, code: 1, name: "dkls:sign:r1", round: 2, broadcast: true },
    MsgType { family: Family::Sign, code: 2, name: "dkls:sign:r1echo", round: 3, broadcast: true },
    MsgType { family: Family::Sign, code: 3, name: "dkls:sign:r2", round: 3, broadcast: false },
    MsgType { family: Family::Sign, code: 4, name: "dkls:sign:r3", round: 4, broadcast: false },
    MsgType { family: Family::Sign, code: 5, name: "dkls:sign:r4", round: 5, broadcast: true },
    MsgType { family: Family::Sign, code: 6, name: "dkls:sign:r4echo", round: 6, broadcast: true },
    MsgType { family: Family::CheckedSign, code: 1, name: "dkls:csign:r1", round: 2, broadcast: true },
    MsgType { family: Family::CheckedSign, code: 2, name: "dkls:csign:r1echo", round: 3, broadcast: true },
    MsgType { family: Family::CheckedSign, code: 3, name: "dkls:csign:r2", round: 3, broadcast: false },
    MsgType { family: Family::CheckedSign, code: 4, name: "dkls:csign:r3", round: 4, broadcast: false },
    MsgType { family: Family::CheckedSign, code: 5, name: "dkls:csign:r4", round: 5, broadcast: true },
    MsgType { family: Family::CheckedSign, code: 6, name: "dkls:csign:r4echo", round: 6, broadcast: true },
    MsgType { family: Family::PairSetup, code: 1, name: "dkls:pairsetup:r1", round: 2, broadcast: false },
    MsgType { family: Family::PairSetup, code: 2, name: "dkls:pairsetup:r2", round: 3, broadcast: false },
];

impl Family {
    fn types(self) -> impl Iterator<Item = &'static MsgType> {
        TYPES.iter().filter(move |t| t.family == self)
    }
    fn by_name(self, name: &str) -> Option<&'static MsgType> {
        self.types().find(|t| t.name == name)
    }
    fn by_code(self, code: u8) -> Option<&'static MsgType> {
        self.types().find(|t| t.code == code)
    }
    fn rounds(self) -> u8 {
        self.types().map(|t| t.round).max().unwrap_or(0)
    }
    /// Whether `round` has broadcast types, unicast types.
    fn shape(self, round: u8) -> (bool, bool) {
        let mut shape = (false, false);
        for t in self.types().filter(|t| t.round == round) {
            if t.broadcast {
                shape.0 = true;
            } else {
                shape.1 = true;
            }
        }
        shape
    }
    fn protocol(self) -> Protocol {
        match self {
            Family::Keygen => Protocol::Keygen,
            Family::Sign | Family::CheckedSign => Protocol::Sign,
            Family::PairSetup => Protocol::PairSetup,
        }
    }
}

// ---------------------------------------------------------------------------------------
// The payload of a protocol round: tsslib messages, one per (instance, type)
// ---------------------------------------------------------------------------------------
//
//   count u16 LE, then per message: instance u16 LE, type code u8, length u32 LE,
//   the message's payload in tsslib's binary encoding (`tsslib::wire`, as every
//   session's parties run with `WireFormat::Binary`).
//
// The rest of tsslib's `Message` is not sent: its type name travels as the one-byte
// code, and `from` and `to` are not repeated -- tsslib is told the envelope's, which are
// the ones the signature vouches for.

/// A received message: (instance, type, binary payload).
type Message<'p> = (u16, &'static MsgType, &'p [u8]);

struct Entry {
    instance: u16,
    code: u8,
    data: Zeroizing<Vec<u8>>,
}

fn encode_entries(entries: &[Entry]) -> Zeroizing<Vec<u8>> {
    let len = 2 + entries.iter().map(|e| 7 + e.data.len()).sum::<usize>();
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    for e in entries {
        out.extend_from_slice(&e.instance.to_le_bytes());
        out.push(e.code);
        out.extend_from_slice(&(e.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&e.data);
    }
    Zeroizing::new(out)
}

fn decode_entries(mut p: &[u8]) -> Option<Vec<(u16, u8, &[u8])>> {
    fn take<'a>(p: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
        if p.len() < n {
            return None;
        }
        let (h, t) = p.split_at(n);
        *p = t;
        Some(h)
    }
    let count = u16::from_le_bytes(take(&mut p, 2)?.try_into().ok()?);
    let mut out = Vec::new();
    for _ in 0..count {
        let instance = u16::from_le_bytes(take(&mut p, 2)?.try_into().ok()?);
        let code = take(&mut p, 1)?[0];
        let len = u32::from_le_bytes(take(&mut p, 4)?.try_into().ok()?) as usize;
        out.push((instance, code, take(&mut p, len)?));
    }
    p.is_empty().then_some(out)
}

// ---------------------------------------------------------------------------------------
// The session
// ---------------------------------------------------------------------------------------

enum Party {
    Keygen(KeygenParty),
    Sign(SigningParty),
    CheckedSign(CheckedSigningParty),
    Pair(PairSetupParty),
}

enum Outcome {
    Key(tsslib::dklstss::Key),
    Signature(tsslib::dklstss::Signature),
    Pair(PairOTState),
}

impl Party {
    fn poll(&self) -> Option<Result<Outcome, String>> {
        let err = |e: tsslib::dklstss::Error| format!("{e}");
        match self {
            Party::Keygen(p) => p.try_result().map(|r| r.map(Outcome::Key).map_err(err)),
            Party::Sign(p) => p
                .try_result()
                .map(|r| r.map(Outcome::Signature).map_err(err)),
            Party::CheckedSign(p) => p
                .try_result()
                .map(|r| r.map(Outcome::Signature).map_err(err)),
            Party::Pair(p) => p.try_result().map(|r| r.map(Outcome::Pair).map_err(err)),
        }
    }
}

/// One tsslib party and its mailbox: the whole of a keygen, or one sighash of a signing.
struct Lane {
    mailbox: Arc<Mailbox>,
    party: Option<Party>,
}

/// What a signing session signs with and checks against.
struct SignJob {
    mode: SignMode,
    record: ShareRecord,
    requests: Vec<SignRequest>,
    tweaks: Vec<Scalar>,
    children: Vec<[u8; PUBKEY_LEN]>,
    results: Vec<Option<EcdsaSignature>>,
}

/// What a pair-setup session sets up, and what it ends with.
struct PairJob {
    /// The member's record, core only: the session reads its public half.
    record: ShareRecord,
    peer: u8,
    result: Option<SecretPair>,
}

/// What a session is for, besides its members.
enum Job {
    Keygen,
    Sign(SignJob),
    Pair(PairJob),
}

/// A member's round-0 message: the commitment, and the envelope's signature, which
/// can only be checked once the key it is by has been revealed.
#[derive(Copy, Clone)]
struct Commitment {
    hash: [u8; COMMITMENT_LEN],
    /// What the round-0 signature covers, and the signature; `None` for our own.
    signed: Option<([u8; 32], [u8; SIG_LEN])>,
}

/// One run of create-together, sign or pair setup, from this member's side.
pub struct Session {
    family: Family,
    id: [u8; SESSION_ID_LEN],
    n: u8,
    t: u8,
    me: u8,
    /// Who takes part, ascending: `1..=n` for keygen, the signers for a signature.
    members: Vec<u8>,
    params: [u8; 32],
    identity: IdentityKey,
    /// The random bytes this member's commitment hides its key behind.
    nonce: [u8; NONCE_LEN],
    /// Every member's round-0 commitment, in `members` order.
    commitments: Vec<Option<Commitment>>,
    /// Every member's identity key, once it has opened its commitment.
    roster: Vec<Option<[u8; PUBKEY_LEN]>>,
    code: Option<SessionCode>,
    confirmed: bool,
    /// (round, from, to) of every message taken.
    seen: Vec<(u8, u8, u8)>,
    /// (round, to) of every envelope sealed.
    sealed: Vec<(u8, u8)>,
    outbox: Vec<Outgoing>,
    lanes: Vec<Lane>,
    job: Job,
    share: Option<ShareRecord>,
    finished: bool,
    failure: Option<String>,
    _armed: Armed,
}

impl Session {
    /// Create together: member `me` of `n`, threshold `t`.
    ///
    /// `source` arms the protocol DRBG (see [`crate::rng`]): it must be seed-grade, as
    /// what the DRBG draws in a DKG is this member's share of the new key. It also makes
    /// the identity key.
    pub fn keygen(
        id: [u8; SESSION_ID_LEN],
        n: u8,
        t: u8,
        me: u8,
        source: &mut dyn Entropy,
        _kw: &KeyWork,
    ) -> Result<Self, Error> {
        check_params(n, t)?;
        if !crate::can_create_together(n, t) {
            return Err(Error::BiasedShape);
        }
        if me == 0 || me > n {
            return Err(Error::Parameters);
        }
        Session::start(
            Family::Keygen,
            id,
            n,
            t,
            me,
            (1..=n).collect(),
            [0; 32],
            Job::Keygen,
            source,
        )
    }

    /// Sign `requests` with `record`'s share, together with the other `signers`.
    ///
    /// `signers` is exactly `t` distinct member numbers, this member's among them; every
    /// signer passes the same set, the same requests in the same order and the same
    /// mode, or the session codes differ. `source` arms the protocol DRBG for nonces and
    /// makes the identity key.
    ///
    /// `record` must hold a pair with every other signer ([`ShareRecord::missing_pairs`]):
    /// without one the session is refused with [`Error::MissingPairs`] before anything
    /// is sent, and the missing pairs are set up with [`Session::pair_setup`] first.
    pub fn sign(
        id: [u8; SESSION_ID_LEN],
        record: &ShareRecord,
        signers: &[u8],
        requests: &[SignRequest],
        mode: SignMode,
        source: &mut dyn Entropy,
        _kw: &KeyWork,
    ) -> Result<Self, Error> {
        let mut members = signers.to_vec();
        members.sort_unstable();
        members.dedup();
        if members.len() != signers.len()
            || members.len() != usize::from(record.t)
            || members.iter().any(|&m| m == 0 || m > record.n)
            || !members.contains(&record.member)
            || requests.is_empty()
            || requests.len() > MAX_REQUESTS
        {
            return Err(Error::Parameters);
        }
        let missing = record.missing_pairs(&members);
        if !missing.is_empty() {
            return Err(Error::MissingPairs(missing));
        }
        let mut tweaks = Vec::with_capacity(requests.len());
        let mut children = Vec::with_capacity(requests.len());
        let mut h = Sha256::new();
        h.update(b"CatCard TSS sign parameters v1\0");
        h.update(&[mode as u8]);
        h.update(&record.joint_public);
        h.update(&record.chain_code);
        h.update(&(requests.len() as u16).to_be_bytes());
        for r in requests {
            if r.path.len() > crate::MAX_PATH {
                return Err(Error::Parameters);
            }
            let (tweak, child) = tsslib::dklstss::derive_child(&record.key.0, &r.path)
                .map_err(|_| Error::Parameters)?;
            tweaks.push(tweak);
            children.push(compress(&child).ok_or(Error::Parameters)?);
            h.update(&[r.path.len() as u8]);
            for i in &r.path {
                h.update(&i.to_be_bytes());
            }
            h.update(&r.sighash);
        }
        let family = match mode {
            SignMode::Plain => Family::Sign,
            SignMode::Checked => Family::CheckedSign,
        };
        let job = SignJob {
            mode,
            record: record.clone(),
            requests: requests.to_vec(),
            tweaks,
            children,
            results: alloc::vec![None; requests.len()],
        };
        Session::start(
            family,
            id,
            record.n,
            record.t,
            record.member,
            members,
            h.finalize(),
            Job::Sign(job),
            source,
        )
    }

    /// Set up the pair between `record`'s member and `peer` again: both run this, each
    /// naming the other, and each ends with a fresh pairwise OT state for the other
    /// ([`Self::install_pair`]). No share, no other pair and no public key changes.
    ///
    /// For a pair lost with its cache, or one that should not be trusted any more. Both
    /// members must install the result: a pair is usable only when the two hold the
    /// states of the same run. `source` arms the protocol DRBG -- the new OT seeds are
    /// secret -- and makes the identity key.
    pub fn pair_setup(
        id: [u8; SESSION_ID_LEN],
        record: &ShareRecord,
        peer: u8,
        source: &mut dyn Entropy,
        _kw: &KeyWork,
    ) -> Result<Self, Error> {
        if peer == 0 || peer > record.n || peer == record.member {
            return Err(Error::Parameters);
        }
        let members = alloc::vec![record.member.min(peer), record.member.max(peer)];
        let mut h = Sha256::new();
        h.update(b"CatCard TSS pair setup parameters v1\0");
        h.update(&record.wallet_id());
        h.update(&members);
        let job = PairJob {
            record: record.core_clone(),
            peer,
            result: None,
        };
        Session::start(
            Family::PairSetup,
            id,
            record.n,
            record.t,
            record.member,
            members,
            h.finalize(),
            Job::Pair(job),
            source,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn start(
        family: Family,
        id: [u8; SESSION_ID_LEN],
        n: u8,
        t: u8,
        me: u8,
        members: Vec<u8>,
        params: [u8; 32],
        job: Job,
        source: &mut dyn Entropy,
    ) -> Result<Self, Error> {
        let armed = Armed::new(source)?;
        let identity = IdentityKey::generate(source)?;
        let mut nonce = [0u8; NONCE_LEN];
        draw(source, &mut nonce)?;
        let mut roster = alloc::vec![None; members.len()];
        let mut commitments = alloc::vec![None; members.len()];
        let mine = members
            .iter()
            .position(|&m| m == me)
            .ok_or(Error::Parameters)?;
        roster[mine] = Some(*identity.public());
        let ctx = Context {
            protocol: family.protocol(),
            session: &id,
            n,
            t,
            members: &members,
            params: &params,
        };
        let hash = commitment(&ctx, me, identity.public(), &nonce);
        commitments[mine] = Some(Commitment { hash, signed: None });
        let mut s = Session {
            family,
            id,
            n,
            t,
            me,
            members,
            params,
            identity,
            nonce,
            commitments,
            roster,
            code: None,
            confirmed: false,
            seen: Vec::new(),
            sealed: Vec::new(),
            outbox: Vec::new(),
            lanes: Vec::new(),
            job,
            share: None,
            finished: false,
            failure: None,
            _armed: armed,
        };
        let commit = s.seal(COMMIT_ROUND, 0, hash.to_vec())?;
        s.outbox.push(commit);
        Ok(s)
    }

    // --- what the UI asks ---------------------------------------------------------

    pub fn protocol(&self) -> Protocol {
        self.family.protocol()
    }
    pub fn id(&self) -> &[u8; SESSION_ID_LEN] {
        &self.id
    }
    /// This member's number.
    pub fn me(&self) -> u8 {
        self.me
    }
    /// The members taking part, ascending.
    pub fn members(&self) -> &[u8] {
        &self.members
    }
    /// Rounds after round 0, which is also the number of the last one: round 1 is the
    /// identities, rounds 2 and on the protocol's own.
    pub fn rounds(&self) -> u8 {
        self.family.rounds()
    }

    pub fn status(&self) -> Status {
        if self.failure.is_some() {
            Status::Failed
        } else if self.finished {
            Status::Finished
        } else if self.confirmed {
            Status::Running
        } else if self.code.is_some() {
            Status::Comparing
        } else {
            Status::Introducing
        }
    }

    /// The session code, once every member's identity is in and has opened its
    /// commitment.
    pub fn code(&self) -> Option<&SessionCode> {
        self.code.as_ref()
    }

    pub fn failure(&self) -> Option<&str> {
        self.failure.as_deref()
    }

    /// Envelopes to deliver, oldest first. Each is returned once.
    pub fn take_outbox(&mut self) -> Vec<Outgoing> {
        core::mem::take(&mut self.outbox)
    }

    /// The messages this member is waiting for, as (round, from, to): the commitments
    /// still missing; once they are all in, the identities still missing; after that
    /// the rest of the earliest protocol round not complete. Empty while the code is
    /// being compared and once the session has ended.
    pub fn awaiting(&self) -> Vec<(u8, u8, u8)> {
        let mut out = Vec::new();
        if self.failure.is_some() || self.finished {
            return out;
        }
        if !self.all_committed() {
            for (i, c) in self.commitments.iter().enumerate() {
                if c.is_none() {
                    out.push((COMMIT_ROUND, self.members[i], 0));
                }
            }
            return out;
        }
        if self.code.is_none() {
            for (i, k) in self.roster.iter().enumerate() {
                if k.is_none() {
                    out.push((REVEAL_ROUND, self.members[i], 0));
                }
            }
            return out;
        }
        if !self.confirmed {
            return out;
        }
        for round in FIRST_PROTOCOL_ROUND..=self.rounds() {
            let (bc, uc) = self.family.shape(round);
            for &from in self.members.iter().filter(|&&m| m != self.me) {
                for (wanted, to) in [(bc, 0), (uc, self.me)] {
                    if wanted && !self.seen.contains(&(round, from, to)) {
                        out.push((round, from, to));
                    }
                }
            }
            if !out.is_empty() {
                break;
            }
        }
        out
    }

    /// A created-together wallet's share, once finished. Store it, then drop the
    /// session.
    pub fn share(&self) -> Option<&ShareRecord> {
        self.share.as_ref()
    }

    /// [`Self::share`], moved out rather than copied: one copy of the key with all its
    /// pairs, not two. Once only.
    pub fn take_share(&mut self, _kw: &KeyWork) -> Option<ShareRecord> {
        self.share.take()
    }

    /// A signing session's signatures, in request order, once finished.
    pub fn signatures(&self) -> Option<Vec<EcdsaSignature>> {
        let Job::Sign(job) = &self.job else {
            return None;
        };
        if !self.finished {
            return None;
        }
        job.results.iter().cloned().collect()
    }

    /// A pair-setup session's other member.
    pub fn peer(&self) -> Option<u8> {
        match &self.job {
            Job::Pair(job) => Some(job.peer),
            _ => None,
        }
    }

    /// A finished pair setup: install the new pair into `record` -- the same member of
    /// the same wallet the session was started with -- replacing (and wiping) any it
    /// had with the peer. The record's pair cache is then out of date: write a new one
    /// ([`ShareRecord::write_pair_cache`]). Returns the peer. Once only.
    pub fn install_pair(&mut self, record: &mut ShareRecord, _kw: &KeyWork) -> Result<u8, Error> {
        let Job::Pair(job) = &mut self.job else {
            return Err(Error::State("not a pair setup"));
        };
        if !self.finished {
            return Err(Error::State("pair setup not finished"));
        }
        if record.member != job.record.member || record.wallet_id() != job.record.wallet_id() {
            return Err(Error::Mismatch);
        }
        let state = job
            .result
            .as_mut()
            .and_then(|p| p.0.take())
            .ok_or(Error::State("pair already installed"))?;
        record.set_pair(job.peer, state)?;
        Ok(job.peer)
    }

    // --- driving it ---------------------------------------------------------------

    /// The user saw the same code on every device: start the protocol. Round 2, its
    /// first, is in the outbox when this returns.
    pub fn confirm(&mut self, _kw: &KeyWork) -> Result<(), Error> {
        if self.code.is_none() || self.confirmed || self.failure.is_some() {
            return Err(Error::State("confirm"));
        }
        self.confirmed = true;
        let threshold = usize::from(self.t) - 1;
        let parties: Vec<PartyId> =
            PartyId::sort(self.members.iter().map(|&m| member_id(m)).collect(), 0);
        let me = member_id(self.me);
        let started: Result<Vec<Lane>, String> = match &self.job {
            Job::Pair(job) => {
                let mailbox = Arc::new(Mailbox::default());
                // Two parties; pair setup does not read the threshold.
                let params = Parameters::new(parties, &me, 1, broker(&mailbox))
                    .with_wire_format(WireFormat::Binary);
                PairSetupParty::new(params, &job.record.key.0)
                    .map(|p| {
                        alloc::vec![Lane {
                            mailbox,
                            party: Some(Party::Pair(p)),
                        }]
                    })
                    .map_err(|e| format!("{e}"))
            }
            Job::Keygen => {
                let mailbox = Arc::new(Mailbox::default());
                let params = Parameters::new(parties, &me, threshold, broker(&mailbox))
                    .with_wire_format(WireFormat::Binary);
                KeygenParty::new(params)
                    .map(|p| {
                        alloc::vec![Lane {
                            mailbox,
                            party: Some(Party::Keygen(p)),
                        }]
                    })
                    .map_err(|e| format!("{e}"))
            }
            Job::Sign(job) => {
                let mut lanes = Vec::with_capacity(job.requests.len());
                let mut err = None;
                for (req, tweak) in job.requests.iter().zip(&job.tweaks) {
                    let mailbox = Arc::new(Mailbox::default());
                    let params = Parameters::new(parties.clone(), &me, threshold, broker(&mailbox))
                        .with_wire_format(WireFormat::Binary);
                    // tsslib takes the key by value; its copy lives in the party.
                    let key = job.record.key.0.clone();
                    let hash = req.sighash.to_vec();
                    let made = match job.mode {
                        SignMode::Plain => SigningParty::new(
                            params,
                            key,
                            hash,
                            parties.clone(),
                            Some(tweak.clone()),
                        )
                        .map(Party::Sign),
                        SignMode::Checked => CheckedSigningParty::new(
                            params,
                            key,
                            hash,
                            parties.clone(),
                            Some(tweak.clone()),
                        )
                        .map(Party::CheckedSign),
                    };
                    match made {
                        Ok(p) => lanes.push(Lane {
                            mailbox,
                            party: Some(p),
                        }),
                        Err(e) => {
                            mailbox.clear();
                            err = Some(format!("{e}"));
                            break;
                        }
                    }
                }
                match err {
                    None => Ok(lanes),
                    Some(e) => {
                        for l in &lanes {
                            l.mailbox.clear();
                        }
                        Err(e)
                    }
                }
            }
        };
        match started {
            Ok(lanes) => {
                self.lanes = lanes;
                self.advance()
            }
            Err(e) => Err(self.fail(e)),
        }
    }

    /// Take one envelope.
    pub fn receive(&mut self, bytes: &[u8], _kw: &KeyWork) -> Result<(), Error> {
        if self.failure.is_some() || self.finished {
            return Err(Error::State("session over"));
        }
        let env = Envelope::parse(bytes)?;
        let h = env.header;
        if h.protocol != self.family.protocol() {
            return Err(Refused::WrongProtocol.into());
        }
        if h.session != self.id {
            return Err(Refused::WrongSession.into());
        }
        let from = self
            .members
            .iter()
            .position(|&m| m == h.from)
            .ok_or(Refused::UnknownMember)?;
        if h.from == self.me {
            return Err(Refused::FromSelf.into());
        }
        if h.to != 0 && h.to != self.me {
            return Err(Refused::NotForMe.into());
        }
        if h.round == COMMIT_ROUND {
            return self.receive_commitment(from, &env);
        }
        if h.round == REVEAL_ROUND {
            return self.receive_identity(from, &env);
        }
        if h.round > self.rounds() {
            return Err(Refused::BadRound.into());
        }
        if !self.confirmed {
            return Err(Refused::Early.into());
        }
        if self.seen.contains(&(h.round, h.from, h.to)) {
            return Err(Refused::Replayed.into());
        }
        let roster = *self.code.as_ref().ok_or(Error::State("roster"))?.digest();
        let peer = self.roster[from].ok_or(Error::State("roster"))?;
        let sig = env.signature.ok_or(Refused::Unsigned)?;
        if !verify(&peer, &signed_digest(&roster, env.signed), sig) {
            return Err(Refused::BadSignature.into());
        }
        let payload = if h.to == 0 {
            Zeroizing::new(env.payload.to_vec())
        } else {
            let ctx = UnicastContext {
                session: &self.id,
                roster: &roster,
                round: h.round,
                from: h.from,
                to: h.to,
            };
            let aad = &env.signed[..AAD_LEN];
            Zeroizing::new(
                self.identity
                    .open(&peer, &ctx, aad, env.payload)?
                    .ok_or(Refused::Undecryptable)?,
            )
        };
        let entries = self.check_entries(&h, &payload)?;
        self.seen.push((h.round, h.from, h.to));

        let sender = member_id(h.from);
        let recipient = (h.to != 0).then(|| member_id(self.me));
        for (instance, ty, data) in entries {
            let mut msg = TssMessage {
                typ: String::from(ty.name),
                from: Some(sender.clone()),
                to: recipient.clone(),
                data: Payload::Binary(data.to_vec()),
            };
            let delivered = self.lanes[usize::from(instance)].mailbox.deliver(&msg);
            // A DKG's round-2 unicasts are Shamir shares: wipe our copy.
            if let Some(b) = binary_mut(&mut msg.data) {
                b.zeroize();
            }
            if let Err(e) = delivered {
                return Err(self.fail(format!("{e}")));
            }
        }
        self.advance()
    }

    // --- inside ---------------------------------------------------------------

    fn all_committed(&self) -> bool {
        self.commitments.iter().all(Option::is_some)
    }

    fn context(&self) -> Context<'_> {
        Context {
            protocol: self.family.protocol(),
            session: &self.id,
            n: self.n,
            t: self.t,
            members: &self.members,
            params: &self.params,
        }
    }

    /// Round 0: a member's commitment. Its signature is by a key nobody has seen yet,
    /// so it is kept and checked when the key arrives in round 1. The last commitment
    /// in releases this member's own identity.
    fn receive_commitment(&mut self, from: usize, env: &Envelope<'_>) -> Result<(), Error> {
        if env.header.to != 0 || env.payload.len() != COMMITMENT_LEN {
            return Err(Refused::Malformed.into());
        }
        let sig = env.signature.ok_or(Refused::Unsigned)?;
        if self.commitments[from].is_some() {
            return Err(Refused::Replayed.into());
        }
        let mut hash = [0u8; COMMITMENT_LEN];
        hash.copy_from_slice(env.payload);
        self.commitments[from] = Some(Commitment {
            hash,
            signed: Some((signed_digest(&[0; 32], env.signed), *sig)),
        });
        if self.all_committed() {
            let mut reveal = Vec::with_capacity(PUBKEY_LEN + NONCE_LEN);
            reveal.extend_from_slice(self.identity.public());
            reveal.extend_from_slice(&self.nonce);
            let env = self.seal(REVEAL_ROUND, 0, reveal)?;
            self.outbox.push(env);
        }
        Ok(())
    }

    /// Round 1: a member's identity key and the bytes that open its commitment.
    fn receive_identity(&mut self, from: usize, env: &Envelope<'_>) -> Result<(), Error> {
        if env.header.to != 0
            || env.payload.len() != PUBKEY_LEN + NONCE_LEN
            || !valid_public(&env.payload[..PUBKEY_LEN])
        {
            return Err(Refused::Malformed.into());
        }
        if !self.all_committed() {
            return Err(Refused::Early.into());
        }
        let mut key = [0u8; PUBKEY_LEN];
        key.copy_from_slice(&env.payload[..PUBKEY_LEN]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&env.payload[PUBKEY_LEN..]);
        let sig = env.signature.ok_or(Refused::Unsigned)?;
        if !verify(&key, &signed_digest(&[0; 32], env.signed), sig) {
            return Err(Refused::BadSignature.into());
        }
        if self.roster[from].is_some() {
            return Err(Refused::Replayed.into());
        }
        let committed = self.commitments[from].ok_or(Error::State("commitment"))?;
        if commitment(&self.context(), env.header.from, &key, &nonce) != committed.hash {
            return Err(Refused::CommitmentMismatch.into());
        }
        // The commitment opened, so its envelope must be by the same key.
        if let Some((digest, sig)) = &committed.signed
            && !verify(&key, digest, sig)
        {
            return Err(Refused::BadSignature.into());
        }
        self.roster[from] = Some(key);
        if self.roster.iter().all(Option::is_some) {
            let keys: Vec<[u8; PUBKEY_LEN]> = self.roster.iter().flatten().copied().collect();
            let hashes: Vec<[u8; COMMITMENT_LEN]> =
                self.commitments.iter().flatten().map(|c| c.hash).collect();
            self.code = Some(SessionCode::compute(&self.context(), &hashes, &keys));
        }
        Ok(())
    }

    /// The payload's messages, if they are exactly this round's: one of each of its
    /// types for this direction, per instance.
    fn check_entries<'p>(&self, h: &Header, payload: &'p [u8]) -> Result<Vec<Message<'p>>, Error> {
        let bad = Error::Refused(Refused::UnexpectedContent);
        let raw = decode_entries(payload).ok_or(bad.clone())?;
        let broadcast = h.to == 0;
        let wanted: Vec<&MsgType> = self
            .family
            .types()
            .filter(|t| t.round == h.round && t.broadcast == broadcast)
            .collect();
        if raw.len() != wanted.len() * self.lanes.len() {
            return Err(bad);
        }
        let mut out: Vec<Message<'p>> = Vec::with_capacity(raw.len());
        for (instance, code, data) in raw {
            let ty = self.family.by_code(code).ok_or(bad.clone())?;
            if ty.round != h.round
                || ty.broadcast != broadcast
                || usize::from(instance) >= self.lanes.len()
                || out.iter().any(|(i, t, _)| *i == instance && t.code == code)
            {
                return Err(bad);
            }
            out.push((instance, ty, data));
        }
        Ok(out)
    }

    /// Seal what the parties sent, collect what they finished with.
    fn advance(&mut self) -> Result<(), Error> {
        // Outbound, grouped by (round, to).
        let mut groups: Vec<((u8, u8), Vec<Entry>)> = Vec::new();
        for (lane_no, lane) in self.lanes.iter().enumerate() {
            if let Some(e) = lane.mailbox.take_late_error() {
                return Err(self.fail(e));
            }
            for mut msg in lane.mailbox.take_outbound() {
                let Some(ty) = self.family.by_name(&msg.typ) else {
                    return Err(self.fail(format!("unknown message type {}", msg.typ)));
                };
                let to = match &msg.to {
                    None => 0,
                    Some(p) => match p.key.as_slice() {
                        [m] if self.members.contains(m) => *m,
                        _ => return Err(self.fail(String::from("message to a non-member"))),
                    },
                };
                if (to == 0) != ty.broadcast {
                    return Err(self.fail(format!("{} sent with the wrong address", ty.name)));
                }
                // Moved out rather than copied, so the one copy is the one wiped.
                let data = match binary_mut(&mut msg.data) {
                    Some(b) => Zeroizing::new(core::mem::take(b)),
                    None => return Err(self.fail(String::from("message not in binary"))),
                };
                let entry = Entry {
                    instance: lane_no as u16,
                    code: ty.code,
                    data,
                };
                match groups.iter_mut().find(|(k, _)| *k == (ty.round, to)) {
                    Some((_, v)) => v.push(entry),
                    None => groups.push(((ty.round, to), alloc::vec![entry])),
                }
            }
        }
        groups.sort_by_key(|(k, _)| *k);
        for ((round, to), entries) in groups {
            if self.sealed.contains(&(round, to)) {
                return Err(self.fail(format!("round {round} sent twice")));
            }
            let payload = encode_entries(&entries);
            let env = self.seal(round, to, payload.to_vec())?;
            self.sealed.push((round, to));
            self.outbox.push(env);
        }

        // Results.
        let mut outcomes = Vec::new();
        for (i, lane) in self.lanes.iter_mut().enumerate() {
            if let Some(party) = &lane.party
                && let Some(r) = party.poll()
            {
                lane.party = None;
                lane.mailbox.clear();
                outcomes.push((i, r));
            }
        }
        for (i, r) in outcomes {
            match r {
                Ok(Outcome::Key(key)) => {
                    let record = ShareRecord::from_key(
                        Origin::Created,
                        self.t,
                        None,
                        Vec::new(),
                        SecretKey(key),
                    );
                    match record {
                        Ok(r) => self.share = Some(r),
                        Err(_) => {
                            return Err(self.fail(String::from("keygen produced a bad share")));
                        }
                    }
                }
                Ok(Outcome::Signature(sig)) => {
                    let Job::Sign(job) = &mut self.job else {
                        return Err(self.fail(String::from("signature from a keygen")));
                    };
                    match finish_signature(&sig, &job.requests[i].sighash, &job.children[i]) {
                        Some(s) => job.results[i] = Some(s),
                        None => {
                            return Err(self.fail(String::from("signature does not verify")));
                        }
                    }
                }
                Ok(Outcome::Pair(state)) => {
                    let pair = SecretPair(Some(state));
                    let Job::Pair(job) = &mut self.job else {
                        return Err(self.fail(String::from("a pair from another protocol")));
                    };
                    job.result = Some(pair);
                }
                Err(e) => return Err(self.fail(e)),
            }
        }
        if !self.lanes.is_empty() && self.lanes.iter().all(|l| l.party.is_none()) {
            self.finished = true;
        }
        Ok(())
    }

    fn seal(&self, round: u8, to: u8, payload: Vec<u8>) -> Result<Outgoing, Error> {
        let header = Header {
            protocol: self.family.protocol(),
            session: self.id,
            round,
            from: self.me,
            to,
        };
        let roster = match &self.code {
            _ if round < FIRST_PROTOCOL_ROUND => [0u8; 32],
            Some(c) => *c.digest(),
            None => return Err(Error::State("roster")),
        };
        let payload = if round >= FIRST_PROTOCOL_ROUND && to != 0 {
            let peer = self
                .members
                .iter()
                .position(|&m| m == to)
                .and_then(|i| self.roster[i])
                .ok_or(Error::State("roster"))?;
            let ctx = UnicastContext {
                session: &self.id,
                roster: &roster,
                round,
                from: self.me,
                to,
            };
            let aad = frame(&header, &[]);
            self.identity.seal(&peer, &ctx, &aad[..AAD_LEN], payload)?
        } else {
            payload
        };
        let mut bytes = frame(&header, &payload);
        let sig = self.identity.sign(&signed_digest(&roster, &bytes))?;
        bytes.extend_from_slice(&sig);
        Ok(Outgoing {
            round,
            from: self.me,
            to,
            bytes,
        })
    }

    /// End the session: drop every party (and with it its copy of the share).
    fn fail(&mut self, why: String) -> Error {
        for lane in &mut self.lanes {
            lane.party = None;
            lane.mailbox.clear();
        }
        let e = Error::Protocol(why.clone());
        if self.failure.is_none() {
            self.failure = Some(why);
        }
        e
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        for lane in &mut self.lanes {
            lane.party = None;
            lane.mailbox.clear();
        }
    }
}

/// A payload's bytes, when it is in the binary encoding every session asks for.
fn binary_mut(p: &mut Payload) -> Option<&mut Vec<u8>> {
    match p {
        Payload::Binary(b) => Some(b),
        // `Payload::Json`, should anything turn tsslib's `json` feature on.
        #[allow(unreachable_patterns)]
        _ => None,
    }
}

fn broker(m: &Arc<Mailbox>) -> Arc<dyn MessageBroker + Send + Sync> {
    Arc::clone(m) as Arc<dyn MessageBroker + Send + Sync>
}

/// tsslib's signature as standard ECDSA, checked independently of tsslib: low-S, and
/// valid under the child key with purecrypto's verifier.
fn finish_signature(
    sig: &tsslib::dklstss::Signature,
    sighash: &[u8; 32],
    child: &[u8; PUBKEY_LEN],
) -> Option<EcdsaSignature> {
    let mut compact = [0u8; 64];
    let (r, s) = (strip(&sig.r), strip(&sig.s));
    if r.len() > 32 || s.len() > 32 {
        return None;
    }
    compact[32 - r.len()..32].copy_from_slice(r);
    compact[64 - s.len()..].copy_from_slice(s);
    let parsed = Secp256k1EcdsaSignature::from_bytes(&compact);
    let key = Secp256k1EcdsaPublicKey::from_sec1(child).ok()?;
    if !parsed.is_low_s() || key.verify_prehash(sighash, &parsed).is_err() {
        return None;
    }
    Some(EcdsaSignature {
        der: der(&compact),
        compact,
        child_public_key: *child,
    })
}

fn strip(b: &[u8]) -> &[u8] {
    let i = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[i..]
}

/// DER `SEQUENCE { INTEGER r, INTEGER s }` (X.690 §8.3, minimal two's complement; the
/// form BIP-66 requires).
fn der(compact: &[u8; 64]) -> Vec<u8> {
    fn integer(out: &mut Vec<u8>, v: &[u8]) {
        let v = strip(v);
        let pad = v.first().is_none_or(|&b| b & 0x80 != 0);
        out.push(0x02);
        out.push((v.len() + usize::from(pad)) as u8);
        if pad {
            out.push(0);
        }
        out.extend_from_slice(v);
    }
    let mut body = Vec::with_capacity(70);
    integer(&mut body, &compact[..32]);
    integer(&mut body, &compact[32..]);
    let mut out = Vec::with_capacity(body.len() + 2);
    out.push(0x30);
    out.push(body.len() as u8);
    out.extend_from_slice(&body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_pads_high_bits_and_strips_zeros() {
        let mut c = [0u8; 64];
        c[0] = 0x80;
        c[31] = 1;
        c[63] = 0x7f;
        let d = der(&c);
        assert_eq!(&d[..4], &[0x30, 2 + 33 + 2 + 1, 0x02, 33]);
        assert_eq!(d[4], 0);
        assert_eq!(&d[d.len() - 3..], &[0x02, 1, 0x7f]);
    }

    #[test]
    fn every_round_of_every_protocol_has_messages() {
        for f in [
            Family::Keygen,
            Family::Sign,
            Family::CheckedSign,
            Family::PairSetup,
        ] {
            for r in FIRST_PROTOCOL_ROUND..=f.rounds() {
                assert_ne!(f.shape(r), (false, false));
            }
            // Rounds 0 and 1 are the identities': no tsslib message travels in them.
            assert!(f.types().all(|t| t.round >= FIRST_PROTOCOL_ROUND));
        }
        assert_eq!(Family::Keygen.rounds(), 3);
        assert_eq!(Family::Sign.rounds(), 6);
        assert_eq!(Family::CheckedSign.rounds(), 6);
        assert_eq!(Family::PairSetup.rounds(), 3);
    }

    #[test]
    fn checked_signing_is_the_default() {
        assert_eq!(SignMode::default(), SignMode::Checked);
    }
}
