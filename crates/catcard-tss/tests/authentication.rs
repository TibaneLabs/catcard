//! Round 0 and what it buys: every message after it is signed by its sender for this
//! session and this group, unicasts are sealed to their recipient, and each is taken
//! once. Each test is one attack, and the session must refuse it and carry on.

mod common;

use catcard_tss::envelope::{HEADER_LEN, SIG_LEN};
use catcard_tss::{Error, Refused, Session, SignMode, SignRequest, Status, file_name};
use common::*;

const ID: [u8; 8] = *b"authtest";

fn members(id: [u8; 8], label: &str) -> Vec<Session> {
    (1..=3)
        .map(|m| {
            Session::keygen(id, 3, 2, m, &mut TestRng::new(&format!("{label}/{m}")), &KW).unwrap()
        })
        .collect()
}

/// Three members of a 2-of-3 DKG, codes compared and confirmed; every identity and
/// round-1 file on the card, none of round 1 read yet.
fn at_round_one(label: &str) -> (Vec<Session>, Card) {
    let mut s = members(ID, label);
    let mut card = Card::default();
    for x in s.iter_mut() {
        card.put(x);
    }
    for x in s.iter_mut() {
        let me = x.me();
        for from in (1..=3u8).filter(|&f| f != me) {
            let b = card.get(&file_name(0, from, 0)).unwrap().to_vec();
            x.receive(&b, &KW).unwrap();
        }
    }
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
    let mut b = file(&card, 1, 2, 0);
    b.truncate(b.len() - SIG_LEN);
    assert_eq!(refused(s[0].receive(&b, &KW)), Refused::Unsigned);
    // An identity without its signature, too.
    let mut fresh = members(*b"fresh-id", "unsigned-0");
    let mut hello = fresh[1].take_outbox().remove(0).bytes;
    hello.truncate(hello.len() - SIG_LEN);
    assert_eq!(refused(fresh[0].receive(&hello, &KW)), Refused::Unsigned);
    finishes(s, card);
}

#[test]
fn a_message_signed_by_another_member_is_refused() {
    let (mut s, card) = at_round_one("impostor");
    // Member 3's genuine broadcast, relabelled as member 2's: signed, but not by 2.
    let mut b = file(&card, 1, 3, 0);
    b[15] = 2;
    assert_eq!(refused(s[0].receive(&b, &KW)), Refused::BadSignature);
    // And a unicast member 3 sent to member 1, passed off as member 2's.
    let mut u = file(&card, 1, 3, 1);
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
    let b = other.get(&file_name(1, 2, 0)).unwrap().to_vec();
    assert_eq!(refused(s[0].receive(&b, &KW)), Refused::WrongSession);
    // The same id, but another group of identities -- a session an attacker ran in
    // parallel under a copied id: its signatures are over another roster.
    let (_, twin) = {
        let mut o = members(ID, "twin");
        let mut c = Card::default();
        run(&mut o, &mut c);
        (o, c)
    };
    let b = twin.get(&file_name(1, 2, 0)).unwrap().to_vec();
    assert_eq!(refused(s[0].receive(&b, &KW)), Refused::BadSignature);
    let u = twin.get(&file_name(1, 2, 1)).unwrap().to_vec();
    assert_eq!(refused(s[0].receive(&u, &KW)), Refused::BadSignature);
    // A signing session's message in a keygen session.
    let records = create(3, 2, "proto");
    let req = [SignRequest {
        path: vec![0, 0],
        sighash: [1; 32],
    }];
    let mut signers = signing_sessions(&records, &[1, 2], &req, SignMode::Plain, "proto");
    let hello = signers[1].take_outbox().remove(0).bytes;
    assert_eq!(refused(s[0].receive(&hello, &KW)), Refused::WrongProtocol);
    finishes(s, card);
}

#[test]
fn a_replayed_message_is_refused() {
    let (mut s, mut card) = at_round_one("replay");
    let r1 = file(&card, 1, 2, 0);
    s[0].receive(&r1, &KW).unwrap();
    assert_eq!(refused(s[0].receive(&r1, &KW)), Refused::Replayed);
    // Identities are fixed once taken: a second, different one for member 2 is refused.
    let mut other = members(ID, "replay-other");
    let hello = other[1].take_outbox().remove(0).bytes;
    assert_eq!(refused(s[0].receive(&hello, &KW)), Refused::Replayed);
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
    assert!(s[0].awaiting().iter().all(|&(r, _, _)| r == 2));
    assert_eq!(refused(s[0].receive(&r1, &KW)), Refused::Replayed);
    assert_eq!(
        refused(s[0].receive(&file(&card, 1, 3, 1), &KW)),
        Refused::Replayed
    );
    finishes(s, card);
}

#[test]
fn messages_out_of_place_are_refused() {
    let (mut s, card) = at_round_one("place");
    // Addressed to member 3.
    assert_eq!(
        refused(s[0].receive(&file(&card, 1, 2, 3), &KW)),
        Refused::NotForMe
    );
    // Our own broadcast, reflected.
    assert_eq!(
        refused(s[0].receive(&file(&card, 1, 1, 0), &KW)),
        Refused::FromSelf
    );
    // A sender who is not a member.
    let mut b = file(&card, 1, 2, 0);
    b[15] = 7;
    assert_eq!(refused(s[0].receive(&b, &KW)), Refused::UnknownMember);
    // A unicast re-addressed to someone else: the header is signed.
    let mut u = file(&card, 1, 2, 3);
    u[16] = 1;
    assert_eq!(refused(s[0].receive(&u, &KW)), Refused::BadSignature);
    // A round the protocol does not have.
    let mut r = file(&card, 1, 2, 0);
    r[14] = 9;
    assert_eq!(refused(s[0].receive(&r, &KW)), Refused::BadRound);
    // A payload altered in transit.
    let mut p = file(&card, 1, 2, 0);
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
    // Same labels: these sessions have the identities whose round 1 is on the card.
    let mut c2 = Card::default();
    for x in s.iter_mut() {
        c2.put(x);
    }
    for from in [2u8, 3] {
        let b = c2.get(&file_name(0, from, 0)).unwrap().to_vec();
        s[0].receive(&b, &KW).unwrap();
    }
    assert_eq!(s[0].status(), Status::Comparing);
    assert_eq!(
        refused(s[0].receive(&file(&card, 1, 2, 0), &KW)),
        Refused::Early
    );
}

#[test]
fn a_substituted_identity_shows_up_in_the_session_code() {
    // Member 1 is handed an attacker's identity for member 2; members 2 and 3 see the
    // real one. Everyone completes round 0 -- and member 1's code differs.
    let mut s = members(ID, "mitm");
    let mut mallory = members(ID, "mallory");
    let mut card = Card::default();
    for x in s.iter_mut() {
        card.put(x);
    }
    let fake = mallory[1].take_outbox().remove(0).bytes;
    s[0].receive(&fake, &KW).unwrap();
    s[0].receive(&file(&card, 0, 3, 0), &KW).unwrap();
    for i in [1usize, 2] {
        for from in 1..=3u8 {
            if from != i as u8 + 1 {
                s[i].receive(&file(&card, 0, from, 0), &KW).unwrap();
            }
        }
    }
    let codes: Vec<_> = s.iter().map(|x| x.code().unwrap().words()).collect();
    assert_eq!(codes[1], codes[2]);
    assert_ne!(codes[0], codes[1]);
}

#[test]
fn unicasts_are_unreadable_to_other_members() {
    // Whoever holds the card sees member 2's round-1 unicast to member 1, which carries
    // a Shamir share. Payload field names travel as text, so the broadcast's are
    // visible -- and the unicast's are not: it is ciphertext.
    let (_, card) = at_round_one("sealed");
    let has = |b: &[u8], word: &[u8]| b.windows(word.len()).any(|w| w == word);
    assert!(has(&file(&card, 1, 2, 0), b"vss_commitments"));
    let u = file(&card, 1, 2, 1);
    assert!(!has(&u, b"share"));
    assert!(!has(&u, b"ot_sender"));
}
