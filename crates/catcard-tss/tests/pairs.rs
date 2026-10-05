//! Every pair among a set of members, set up again in one session over one card.

mod common;

use catcard_tss::{Session, SignMode, SignRequest, Status};
use common::*;

#[test]
fn every_pair_is_set_up_again_in_one_session() {
    let mut records = create(3, 2, "pairs");
    for r in records.iter_mut() {
        r.drop_pairs();
        assert_eq!(r.pairs(), Vec::<u8>::new());
    }
    let id = [0x9b, 1, 2, 3, 0, 0, 0, 4];
    let mut sessions: Vec<Session> = records
        .iter()
        .map(|r| {
            Session::pairs_setup(
                id,
                r,
                &[1, 2, 3],
                &mut TestRng::new(&format!("pairs/{}", r.member())),
                &KW,
            )
            .unwrap()
        })
        .collect();
    let mut card = Card::default();
    run(&mut sessions, &mut card);
    for (s, r) in sessions.iter_mut().zip(records.iter_mut()) {
        assert_eq!(s.status(), Status::Finished, "{:?}", s.failure());
        let mut peers = s.install_pairs(r, &KW).unwrap();
        peers.sort_unstable();
        let want: Vec<u8> = (1..=3).filter(|&m| m != r.member()).collect();
        assert_eq!(peers, want);
        assert_eq!(r.pairs(), want);
    }
    // Every two of the three can sign with the pairs just made.
    let req = [SignRequest {
        path: vec![0, 0],
        sighash: sighash("pairs"),
    }];
    let key = records[0].child_public_key(&[0, 0]).unwrap();
    for signers in [[1u8, 2], [1, 3], [2, 3]] {
        let sigs = sign(&records, &signers, &req, SignMode::Checked);
        assert!(verifies(&key, &req[0].sighash, &sigs[0]), "{signers:?}");
    }
}

/// The members must agree on the set: one naming a different set computes a different
/// session code, and the sessions stop before any pair is made.
#[test]
fn members_naming_different_sets_do_not_agree() {
    let mut records = create(3, 2, "pairs-differ");
    for r in records.iter_mut() {
        r.drop_pairs();
    }
    let id = [0x9b, 9, 9, 9, 0, 0, 0, 4];
    let a = Session::pairs_setup(id, &records[0], &[1, 2, 3], &mut TestRng::new("a"), &KW).unwrap();
    let b = Session::pairs_setup(id, &records[1], &[1, 2], &mut TestRng::new("b"), &KW).unwrap();
    let mut sessions = [a, b];
    let mut card = Card::default();
    // Bounded by `run`; neither can finish.
    for s in sessions.iter_mut() {
        card.put(s);
    }
    for s in sessions.iter_mut() {
        for (r, f, t) in s.awaiting() {
            if let Some(bytes) = card.get(&catcard_tss::file_name(r, f, t)) {
                let bytes = bytes.to_vec();
                let _ = s.receive(&bytes, &KW);
            }
        }
    }
    assert!(sessions.iter().all(|s| s.status() != Status::Finished));
    assert!(sessions.iter().all(|s| s.code().is_none()));
}
