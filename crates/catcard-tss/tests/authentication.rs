//! Rounds 0 and 1 and what they buy: every message after them is signed by its sender
//! for this session and this group, unicasts are sealed to their recipient, and each is
//! taken once. Each test is one attack, and the session must refuse it and carry on.

mod common;

use catcard_tss::envelope::{HEADER_LEN, SIG_LEN};
use catcard_tss::{
    COMMIT_ROUND, Error, FIRST_PROTOCOL_ROUND, REVEAL_ROUND, Refused, Session, SignMode,
    SignRequest, Status, file_name,
};
use common::*;

const ID: [u8; 8] = *b"authtest";
/// The first protocol round: the DKG's shares.
const R1: u8 = FIRST_PROTOCOL_ROUND;

fn members(id: [u8; 8], label: &str) -> Vec<Session> {
    (1..=3)
        .map(|m| {
            Session::keygen(id, 3, 2, m, &mut TestRng::new(&format!("{label}/{m}")), &KW).unwrap()
        })
        .collect()
}

/// Every member reads every other member's file of `round`, from `card`.
fn exchange(s: &mut [Session], card: &mut Card, round: u8) {
    for x in s.iter_mut() {
        card.put(x);
    }
    for x in s.iter_mut() {
        let me = x.me();
        for &from in x.members().to_vec().iter().filter(|&&f| f != me) {
            let b = card.get(&file_name(round, from, 0)).unwrap().to_vec();
            x.receive(&b, &KW).unwrap();
        }
    }
    for x in s.iter_mut() {
        card.put(x);
    }
}

/// Rounds 0 and 1, honestly: commitments, then identities.
fn introduce(s: &mut [Session], card: &mut Card) {
    exchange(s, card, COMMIT_ROUND);
    exchange(s, card, REVEAL_ROUND);
}

/// Three members of a 2-of-3 DKG, codes compared and confirmed; every identity and
/// first-protocol-round file on the card, none of the protocol round read yet.
fn at_round_one(label: &str) -> (Vec<Session>, Card) {
    let mut s = members(ID, label);
    let mut card = Card::default();
    introduce(&mut s, &mut card);
    let code = s[0].code().unwrap().words();
    for x in s.iter_mut() {
        assert_eq!(x.code().unwrap().words(), code);
        x.confirm(&KW).unwrap();
        card.put(x);
    }
    (s, card)
}

fn file(card: &Card, round: u8, from: u8, to: u8) -> Vec<u8> {
    card.get(&file_name(round, from, to)).unwrap().to_vec()
}

fn refused(r: Result<(), Error>) -> Refused {
    match r {
        Err(Error::Refused(why)) => why,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// After the attacks, the honest messages still go through and the DKG finishes.
fn finishes(mut s: Vec<Session>, mut card: Card) {
    run(&mut s, &mut card);
    for x in &s {
        assert_eq!(x.status(), Status::Finished, "{:?}", x.failure());
    }
    assert_eq!(
        s[0].share().unwrap().joint_public_key(),
        s[2].share().unwrap().joint_public_key()
    );
}

#[test]
fn an_unsigned_message_is_refused() {
    let (mut s, card) = at_round_one("unsigned");
    let mut b = file(&card, R1, 2, 0);
    b.truncate(b.len() - SIG_LEN);
    assert_eq!(refused(s[0].receive(&b, &KW)), Refused::Unsigned);
    // A commitment without its signature, and an identity without its.
    let mut fresh = members(*b"fresh-id", "unsigned-0");
    let mut card0 = Card::default();
    for x in fresh.iter_mut() {
        card0.put(x);
    }
    let mut commit = file(&card0, COMMIT_ROUND, 2, 0);
    commit.truncate(commit.len() - SIG_LEN);
    assert_eq!(refused(fresh[0].receive(&commit, &KW)), Refused::Unsigned);
    exchange(&mut fresh, &mut card0, COMMIT_ROUND);
    let mut reveal = file(&card0, REVEAL_ROUND, 2, 0);
    reveal.truncate(reveal.len() - SIG_LEN);
    assert_eq!(refused(fresh[0].receive(&reveal, &KW)), Refused::Unsigned);
    finishes(s, card);
}

#[test]
fn a_message_signed_by_another_member_is_refused() {
    let (mut s, card) = at_round_one("impostor");
    // Member 3's genuine broadcast, relabelled as member 2's: signed, but not by 2.
    let mut b = file(&card, R1, 3, 0);
    b[15] = 2;
    assert_eq!(refused(s[0].receive(&b, &KW)), Refused::BadSignature);
    // And a unicast member 3 sent to member 1, passed off as member 2's.
    let mut u = file(&card, R1, 3, 1);
    u[15] = 2;
    assert_eq!(refused(s[0].receive(&u, &KW)), Refused::BadSignature);
    finishes(s, card);
}

#[test]
fn a_message_of_another_session_is_refused() {
    let (mut s, card) = at_round_one("this");
    // Another session's id.
    let (_, other) = {
        let mut o = members(*b"othersid", "other");
        let mut c = Card::default();
        run(&mut o, &mut c);
        (o, c)
    };
    let b = other.get(&file_name(R1, 2, 0)).unwrap().to_vec();
    assert_eq!(refused(s[0].receive(&b, &KW)), Refused::WrongSession);
    // The same id, but another group of identities -- a session an attacker ran in
    // parallel under a copied id: its signatures are over another roster.
    let (_, twin) = {
        let mut o = members(ID, "twin");
        let mut c = Card::default();
        run(&mut o, &mut c);
        (o, c)
    };
    let b = twin.get(&file_name(R1, 2, 0)).unwrap().to_vec();
    assert_eq!(refused(s[0].receive(&b, &KW)), Refused::BadSignature);
    let u = twin.get(&file_name(R1, 2, 1)).unwrap().to_vec();
    assert_eq!(refused(s[0].receive(&u, &KW)), Refused::BadSignature);
    // A signing session's message in a keygen session.
    let records = create(3, 2, "proto");
    let req = [SignRequest {
        path: vec![0, 0],
        sighash: [1; 32],
    }];
    let mut signers = signing_sessions(&records, &[1, 2], &req, SignMode::Plain, "proto");
    let commit = signers[1].take_outbox().remove(0).bytes;
    assert_eq!(refused(s[0].receive(&commit, &KW)), Refused::WrongProtocol);
    finishes(s, card);
}

#[test]
fn a_replayed_message_is_refused() {
    let (mut s, mut card) = at_round_one("replay");
    let r1 = file(&card, R1, 2, 0);
    s[0].receive(&r1, &KW).unwrap();
    assert_eq!(refused(s[0].receive(&r1, &KW)), Refused::Replayed);
    // Commitments and identities are fixed once taken: a second, different one for
    // member 2 is refused.
    let mut other = members(ID, "replay-other");
    let mut other_card = Card::default();
    introduce(&mut other, &mut other_card);
    let commit = file(&other_card, COMMIT_ROUND, 2, 0);
    assert_eq!(refused(s[0].receive(&commit, &KW)), Refused::Replayed);
    let reveal = file(&other_card, REVEAL_ROUND, 2, 0);
    assert_eq!(refused(s[0].receive(&reveal, &KW)), Refused::Replayed);
    // A round already consumed, offered again once the session has moved past it.
    for x in s.iter_mut() {
        for (r, f, to) in x.awaiting() {
            if let Some(m) = card.get(&file_name(r, f, to)) {
                let m = m.to_vec();
                x.receive(&m, &KW).unwrap();
            }
        }
    }
    for x in s.iter_mut() {
        card.put(x);
    }
    assert!(!s[0].awaiting().is_empty());
    assert!(s[0].awaiting().iter().all(|&(r, _, _)| r == R1 + 1));
    assert_eq!(refused(s[0].receive(&r1, &KW)), Refused::Replayed);
    assert_eq!(
        refused(s[0].receive(&file(&card, R1, 3, 1), &KW)),
        Refused::Replayed
    );
    finishes(s, card);
}

#[test]
fn messages_out_of_place_are_refused() {
    let (mut s, card) = at_round_one("place");
    // Addressed to member 3.
    assert_eq!(
        refused(s[0].receive(&file(&card, R1, 2, 3), &KW)),
        Refused::NotForMe
    );
    // Our own broadcast, reflected.
    assert_eq!(
        refused(s[0].receive(&file(&card, R1, 1, 0), &KW)),
        Refused::FromSelf
    );
    // A sender who is not a member.
    let mut b = file(&card, R1, 2, 0);
    b[15] = 7;
    assert_eq!(refused(s[0].receive(&b, &KW)), Refused::UnknownMember);
    // A unicast re-addressed to someone else: the header is signed.
    let mut u = file(&card, R1, 2, 3);
    u[16] = 1;
    assert_eq!(refused(s[0].receive(&u, &KW)), Refused::BadSignature);
    // A round the protocol does not have.
    let mut r = file(&card, R1, 2, 0);
    r[14] = 9;
    assert_eq!(refused(s[0].receive(&r, &KW)), Refused::BadRound);
    // A payload altered in transit.
    let mut p = file(&card, R1, 2, 0);
    p[HEADER_LEN + 3] ^= 0x40;
    assert_eq!(refused(s[0].receive(&p, &KW)), Refused::BadSignature);
    // Not an envelope at all.
    assert_eq!(refused(s[0].receive(b"hello", &KW)), Refused::Malformed);
    finishes(s, card);
}

#[test]
fn protocol_messages_before_the_code_is_confirmed_are_refused() {
    let (_, card) = at_round_one("early-src");
    let mut s = members(ID, "early-src");
    // Same labels: these sessions have the identities whose round 2 is on the card.
    let mut c2 = Card::default();
    introduce(&mut s, &mut c2);
    assert_eq!(s[0].status(), Status::Comparing);
    assert_eq!(
        refused(s[0].receive(&file(&card, R1, 2, 0), &KW)),
        Refused::Early
    );
}

#[test]
fn every_member_sees_the_same_code_and_it_is_fresh_per_session() {
    // The honest flow, for several group sizes and both protocols: one code on every
    // device, shown only once every commitment has been opened.
    for (n, t) in [(3u8, 2u8), (5, 3)] {
        let id = [n, t, 0x0c, 0x0d, 0, 0, 0, 3];
        let mut s: Vec<Session> = (1..=n)
            .map(|m| {
                Session::keygen(id, n, t, m, &mut TestRng::new(&format!("same/{m}")), &KW).unwrap()
            })
            .collect();
        let mut card = Card::default();
        exchange(&mut s, &mut card, COMMIT_ROUND);
        for x in &s {
            assert_eq!(x.status(), Status::Introducing);
            assert!(x.code().is_none());
            assert!(x.awaiting().iter().all(|&(r, _, _)| r == REVEAL_ROUND));
        }
        exchange(&mut s, &mut card, REVEAL_ROUND);
        let code = s[0].code().unwrap().words();
        for x in &s {
            assert_eq!(x.status(), Status::Comparing);
            assert_eq!(x.code().unwrap().words(), code);
        }
        // Same members, same parameters, same id, fresh randomness: another code.
        let mut again: Vec<Session> = (1..=n)
            .map(|m| {
                Session::keygen(id, n, t, m, &mut TestRng::new(&format!("again/{m}")), &KW).unwrap()
            })
            .collect();
        introduce(&mut again, &mut Card::default());
        assert_ne!(again[0].code().unwrap(), s[0].code().unwrap());
    }
    let records = create(3, 2, "same-sign");
    let req = [SignRequest {
        path: vec![0, 4],
        sighash: [4; 32],
    }];
    let mut signers = signing_sessions(&records, &[1, 3], &req, SignMode::default(), "same");
    introduce(&mut signers, &mut Card::default());
    assert_eq!(signers[0].code().unwrap(), signers[1].code().unwrap());
}

#[test]
fn an_identity_before_every_commitment_is_refused_not_held() {
    let mut s = members(ID, "early-reveal");
    let mut card = Card::default();
    for x in s.iter_mut() {
        card.put(x);
    }
    // Members 2 and 3 have each other's and member 1's commitments, and reveal.
    for i in [1usize, 2] {
        for from in (1..=3u8).filter(|&f| f != i as u8 + 1) {
            s[i].receive(&file(&card, COMMIT_ROUND, from, 0), &KW)
                .unwrap();
        }
        card.put(&mut s[i]);
    }
    // Member 1 has only member 2's commitment: member 2's identity is too soon, and
    // member 1 has not revealed its own.
    s[0].receive(&file(&card, COMMIT_ROUND, 2, 0), &KW).unwrap();
    assert!(s[0].take_outbox().is_empty());
    let reveal = file(&card, REVEAL_ROUND, 2, 0);
    assert_eq!(refused(s[0].receive(&reveal, &KW)), Refused::Early);
    assert_eq!(s[0].awaiting(), vec![(COMMIT_ROUND, 3, 0)]);
    // Nothing was kept: once the last commitment is in, the same bytes are taken.
    s[0].receive(&file(&card, COMMIT_ROUND, 3, 0), &KW).unwrap();
    assert_eq!(s[0].take_outbox()[0].round, REVEAL_ROUND);
    s[0].receive(&reveal, &KW).unwrap();
    s[0].receive(&file(&card, REVEAL_ROUND, 3, 0), &KW).unwrap();
    assert_eq!(s[0].status(), Status::Comparing);
}

#[test]
fn an_identity_that_does_not_open_its_commitment_is_refused() {
    // The attacker carrying the card has seen every honest commitment. It hands member
    // 1 its own key for member 2 -- a well-formed identity, properly signed by that key,
    // under member 2's number -- and it is refused: it does not open member 2's
    // commitment. The genuine identity is still taken afterwards.
    let mut s = members(ID, "mismatch");
    let mut mallory = members(ID, "mismatch-mallory");
    let mut card = Card::default();
    exchange(&mut s, &mut card, COMMIT_ROUND);
    let mut mcard = Card::default();
    exchange(&mut mallory, &mut mcard, COMMIT_ROUND);
    let fake = file(&mcard, REVEAL_ROUND, 2, 0);
    assert_eq!(
        refused(s[0].receive(&fake, &KW)),
        Refused::CommitmentMismatch
    );
    // A genuine identity whose random bytes were altered does not open it either; its
    // signature is checked first.
    let mut bent = file(&card, REVEAL_ROUND, 2, 0);
    bent[HEADER_LEN + 40] ^= 1;
    assert_eq!(refused(s[0].receive(&bent, &KW)), Refused::BadSignature);
    for from in [2u8, 3] {
        s[0].receive(&file(&card, REVEAL_ROUND, from, 0), &KW)
            .unwrap();
    }
    for i in [1usize, 2] {
        for from in (1..=3u8).filter(|&f| f != i as u8 + 1) {
            s[i].receive(&file(&card, REVEAL_ROUND, from, 0), &KW)
                .unwrap();
        }
    }
    let code = s[0].code().unwrap().words();
    assert!(s.iter().all(|x| x.code().unwrap().words() == code));
    for x in s.iter_mut() {
        x.confirm(&KW).unwrap();
    }
    finishes(s, card);
}

#[test]
fn a_commitment_altered_in_transit_blocks_its_senders_identity() {
    // Round 0 is signed by a key nobody knows yet; the signature is checked when the key
    // arrives. A commitment whose hash or signature was changed on the way is taken --
    // and then nothing its sender reveals is accepted, so the session cannot reach a
    // code: the users start again.
    let mut s = members(ID, "altered");
    let mut card = Card::default();
    for x in s.iter_mut() {
        card.put(x);
    }
    let mut hash_bent = file(&card, COMMIT_ROUND, 2, 0);
    hash_bent[HEADER_LEN] ^= 1;
    let mut sig_bent = file(&card, COMMIT_ROUND, 3, 0);
    let last = sig_bent.len() - 1;
    sig_bent[last] ^= 1;
    s[0].receive(&hash_bent, &KW).unwrap();
    s[0].receive(&sig_bent, &KW).unwrap();
    for i in [1usize, 2] {
        for from in (1..=3u8).filter(|&f| f != i as u8 + 1) {
            s[i].receive(&file(&card, COMMIT_ROUND, from, 0), &KW)
                .unwrap();
        }
        card.put(&mut s[i]);
    }
    assert_eq!(
        refused(s[0].receive(&file(&card, REVEAL_ROUND, 2, 0), &KW)),
        Refused::CommitmentMismatch
    );
    assert_eq!(
        refused(s[0].receive(&file(&card, REVEAL_ROUND, 3, 0), &KW)),
        Refused::BadSignature
    );
    assert_eq!(s[0].status(), Status::Introducing);
    assert!(s[0].code().is_none());
}

#[test]
fn a_man_in_the_middle_must_commit_before_seeing_keys_and_the_codes_then_differ() {
    // Member 1 is shown an attacker's commitment and identity for member 2; members 2
    // and 3 see the real ones. The attacker can substitute -- but only a key it
    // committed to before member 1 revealed anything, so it cannot have searched for
    // one that makes the two sides' codes agree. They differ, and the user sees it.
    let mut s = members(ID, "mitm");
    let mut mallory = members(ID, "mallory");
    let mut card = Card::default();
    for x in s.iter_mut() {
        card.put(x);
    }
    let mut mcard = Card::default();
    exchange(&mut mallory, &mut mcard, COMMIT_ROUND);
    s[0].receive(&file(&mcard, COMMIT_ROUND, 2, 0), &KW)
        .unwrap();
    s[0].receive(&file(&card, COMMIT_ROUND, 3, 0), &KW).unwrap();
    for i in [1usize, 2] {
        for from in (1..=3u8).filter(|&f| f != i as u8 + 1) {
            s[i].receive(&file(&card, COMMIT_ROUND, from, 0), &KW)
                .unwrap();
        }
    }
    for x in s.iter_mut() {
        card.put(x);
    }
    // Having now seen every honest key, the attacker would like member 1 to take
    // member 2's real identity after all, or another key of its choosing: neither opens
    // the commitment member 1 holds for member 2.
    assert_eq!(
        refused(s[0].receive(&file(&card, REVEAL_ROUND, 2, 0), &KW)),
        Refused::CommitmentMismatch
    );
    let mut other = members(ID, "mallory-late");
    let mut ocard = Card::default();
    exchange(&mut other, &mut ocard, COMMIT_ROUND);
    assert_eq!(
        refused(s[0].receive(&file(&ocard, REVEAL_ROUND, 2, 0), &KW)),
        Refused::CommitmentMismatch
    );
    // So it reveals what it committed to.
    s[0].receive(&file(&mcard, REVEAL_ROUND, 2, 0), &KW)
        .unwrap();
    s[0].receive(&file(&card, REVEAL_ROUND, 3, 0), &KW).unwrap();
    for i in [1usize, 2] {
        for from in (1..=3u8).filter(|&f| f != i as u8 + 1) {
            s[i].receive(&file(&card, REVEAL_ROUND, from, 0), &KW)
                .unwrap();
        }
    }
    let codes: Vec<_> = s.iter().map(|x| x.code().unwrap().words()).collect();
    assert_eq!(codes[1], codes[2]);
    assert_ne!(codes[0], codes[1]);
}

#[test]
fn unicasts_are_unreadable_to_other_members() {
    // Whoever holds the card sees member 2's first unicast to member 1, which carries a
    // Shamir share. Payload field names travel as text, so the broadcast's are visible
    // -- and the unicast's are not: it is ciphertext.
    let (_, card) = at_round_one("sealed");
    let has = |b: &[u8], word: &[u8]| b.windows(word.len()).any(|w| w == word);
    assert!(has(&file(&card, R1, 2, 0), b"vss_commitments"));
    let u = file(&card, R1, 2, 1);
    assert!(!has(&u, b"share"));
    assert!(!has(&u, b"ot_sender"));
}
