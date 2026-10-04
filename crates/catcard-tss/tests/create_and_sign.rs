//! Create together, then sign: members that only ever exchange envelope files.

mod common;

use catcard_tss::{Error, Origin, Session, SignMode, SignRequest, Status, combine};
use common::*;

fn request(path: &[u32], label: &str) -> SignRequest {
    SignRequest {
        path: path.to_vec(),
        sighash: sighash(label),
    }
}

/// Every t-subset of 1..=n, ascending.
fn subsets(n: u8, t: u8) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for mask in 0u32..(1 << n) {
        if mask.count_ones() == u32::from(t) {
            out.push((1..=n).filter(|m| mask & (1 << (m - 1)) != 0).collect());
        }
    }
    out
}

fn every_member_agrees(n: u8, t: u8) -> Vec<catcard_tss::ShareRecord> {
    let records = create(n, t, &format!("agree-{n}-{t}"));
    assert_eq!(records.len(), usize::from(n));
    for (i, r) in records.iter().enumerate() {
        assert_eq!(r.member(), i as u8 + 1);
        assert_eq!((r.n(), r.t(), r.origin()), (n, t, Origin::Created));
        assert_eq!(r.joint_public_key(), records[0].joint_public_key());
        assert_eq!(r.chain_code(), records[0].chain_code());
        assert_eq!(r.fingerprint(), records[0].fingerprint());
        assert!(r.path().is_empty());
    }
    records
}

#[test]
fn shapes_whose_key_colluders_could_bias_are_not_created_together() {
    // tsslib's DKG can be biased by colluding members when n <= 2t - 2. Those shapes are
    // refused before anything is sent; the usual ones are not.
    for (n, t) in [(2, 2), (3, 3), (4, 3), (4, 4), (6, 4)] {
        assert!(!catcard_tss::can_create_together(n, t), "{t}-of-{n}");
        let refused = Session::keygen([7; 8], n, t, 1, &mut TestRng::new("shape"), &KW);
        assert!(matches!(refused, Err(Error::BiasedShape)), "{t}-of-{n}");
    }
    for (n, t) in [(3, 2), (4, 2), (5, 3), (7, 4), (9, 5)] {
        assert!(catcard_tss::can_create_together(n, t), "{t}-of-{n}");
    }
}

#[test]
fn two_of_three_signs_with_every_pair() {
    let records = every_member_agrees(3, 2);
    for signers in subsets(3, 2) {
        let req = [request(&[0, 7], &format!("pair {signers:?}"))];
        let sigs = sign(&records, &signers, &req, SignMode::Plain);
        let child = records[0].child_public_key(&[0, 7]).unwrap();
        assert!(verifies(&child, &req[0].sighash, &sigs[0]), "{signers:?}");
    }
}

#[test]
fn three_of_five_signs_with_any_three() {
    let records = every_member_agrees(5, 3);
    // Ten subsets; a spread of them, including the two ends and a non-contiguous one.
    for signers in [vec![1, 2, 3], vec![3, 4, 5], vec![1, 3, 5], vec![2, 4, 5]] {
        let req = [request(&[1, 3], &format!("3-of-5 {signers:?}"))];
        let sigs = sign(&records, &signers, &req, SignMode::Plain);
        let child = records[0].child_public_key(&[1, 3]).unwrap();
        assert!(verifies(&child, &req[0].sighash, &sigs[0]), "{signers:?}");
    }
}

#[test]
fn one_session_signs_many_sighashes_in_the_same_rounds() {
    let records = create(3, 2, "many");
    let reqs: Vec<SignRequest> = (0..4)
        .map(|i| request(&[i % 2, i], &format!("input {i}")))
        .collect();
    let sigs = sign(&records, &[1, 3], &reqs, SignMode::Plain);
    assert_eq!(sigs.len(), reqs.len());
    for (r, s) in reqs.iter().zip(&sigs) {
        let child = records[0].child_public_key(&r.path).unwrap();
        assert_eq!(s.child_public_key, child);
        assert!(verifies(&child, &r.sighash, s));
    }
}

#[test]
fn the_default_checked_signing_mode_also_produces_valid_signatures() {
    assert_eq!(SignMode::default(), SignMode::Checked);
    let records = create(3, 2, "checked");
    let req = [request(&[0, 1], "checked")];
    let sigs = sign(&records, &[2, 3], &req, SignMode::default());
    let child = records[0].child_public_key(&[0, 1]).unwrap();
    assert!(verifies(&child, &req[0].sighash, &sigs[0]));
}

#[test]
fn fewer_than_t_signers_cannot_finish() {
    let records = create(3, 2, "short");
    let req = [request(&[0, 0], "short")];
    // A signer set below the threshold is refused outright...
    assert!(matches!(
        Session::sign(
            [9; 8],
            &records[0],
            &[1],
            &req,
            SignMode::Plain,
            &mut TestRng::new("x"),
            &KW
        ),
        Err(Error::Parameters)
    ));
    // ...and a session of t where one member never turns up never finishes: the one
    // present waits for the other's identity, forever, and has nothing to sign with.
    let mut alone = signing_sessions(&records, &[1, 2], &req, SignMode::Plain, "alone");
    alone.truncate(1);
    let mut card = Card::default();
    run(&mut alone, &mut card);
    assert_eq!(alone[0].status(), Status::Introducing);
    assert_eq!(alone[0].awaiting(), vec![(0, 2, 0)]);
    assert!(alone[0].signatures().is_none());

    // Same at a higher threshold: two of a 3-of-5 cannot sign.
    let records = create(5, 3, "short5");
    assert!(matches!(
        Session::sign(
            [9; 8],
            &records[0],
            &[1, 2],
            &req,
            SignMode::Plain,
            &mut TestRng::new("y"),
            &KW
        ),
        Err(Error::Parameters)
    ));
}

#[test]
fn a_record_survives_its_own_serialisation() {
    let records = create(3, 2, "bytes");
    for r in &records {
        let bytes = r.to_bytes(&KW).unwrap();
        let back = catcard_tss::ShareRecord::from_bytes(&bytes, &KW).unwrap();
        assert_eq!(back.member(), r.member());
        assert_eq!(back.joint_public_key(), r.joint_public_key());
        assert_eq!(*back.to_bytes(&KW).unwrap(), *bytes);
        // Any change to the stored bytes is caught, not loaded as a different share.
        for at in [0usize, 5, 9, 42, bytes.len() - 1] {
            let mut bad = bytes.to_vec();
            bad[at] ^= 1;
            assert!(
                catcard_tss::ShareRecord::from_bytes(&bad, &KW).is_err(),
                "flip at {at}"
            );
        }
        // Formats 1 (tsslib's JSON) and 2 (the whole key, pairs and all), never deployed,
        // and anything later are refused, not misread; so is a record cut anywhere in its
        // key core.
        for v in [0u8, 1, 2, 4] {
            let mut old = bytes.to_vec();
            old[4] = v;
            assert!(matches!(
                catcard_tss::ShareRecord::from_bytes(&old, &KW),
                Err(Error::Format(_))
            ));
        }
        for cut in [90, bytes.len() / 2, bytes.len() - 1] {
            assert!(catcard_tss::ShareRecord::from_bytes(&bytes[..cut], &KW).is_err());
        }
    }
    // A record is the core: reloaded, it holds no pairs until its cache is read back.
    let mut records = records;
    let mut reloaded = Vec::new();
    for r in records.iter_mut() {
        let key = catcard_tss::CacheKey::new(&[9; 32], r, &KW);
        let mut cache = r.write_pair_cache(&key, &[r.member(); 16], &KW).unwrap();
        let mut back =
            catcard_tss::ShareRecord::from_bytes(&r.to_bytes(&KW).unwrap(), &KW).unwrap();
        assert!(back.pairs().is_empty());
        back.read_pair_cache(&mut cache, &key, &KW).unwrap();
        reloaded.push(back);
    }
    let req = [request(&[0, 2], "reloaded")];
    let sigs = sign(&reloaded, &[1, 2], &req, SignMode::Plain);
    assert!(verifies(
        &records[0].child_public_key(&[0, 2]).unwrap(),
        &req[0].sighash,
        &sigs[0]
    ));
}

#[test]
fn t_created_shares_combine_into_the_joint_key_and_t_minus_one_do_not() {
    use purecrypto::ec::secp256k1::ecdsa::Secp256k1EcdsaPrivateKey;
    let records = create(5, 3, "combine");
    for pick in [[0usize, 1, 2], [0, 2, 4], [4, 3, 1]] {
        let set: Vec<_> = pick.iter().map(|&i| &records[i]).collect();
        let joint = combine(&set, &KW).unwrap();
        let key = Secp256k1EcdsaPrivateKey::from_bytes(joint.private_key()).unwrap();
        assert_eq!(
            &key.public_key().to_sec1_compressed(),
            records[0].joint_public_key()
        );
        assert_eq!(joint.chain_code(), records[0].chain_code());
        // The same from parts, each taken from a record decoded on its own and dropped.
        let parts: Vec<_> = pick
            .iter()
            .map(|&i| {
                let bytes = records[i].to_bytes(&KW).unwrap();
                catcard_tss::ShareRecord::from_bytes(&bytes, &KW)
                    .unwrap()
                    .combine_part(&KW)
            })
            .collect();
        let again = catcard_tss::combine_parts(&parts, &KW).unwrap();
        assert_eq!(again.private_key(), joint.private_key());
        assert_eq!(again.chain_code(), joint.chain_code());
    }
    let two: Vec<_> = records.iter().take(2).collect();
    assert!(matches!(combine(&two, &KW), Err(Error::NotEnoughShares)));
    // A member twice is not two members.
    let dup = [&records[0], &records[0], &records[1]];
    assert!(matches!(combine(&dup, &KW), Err(Error::Mismatch)));
    // Shares of another wallet do not mix in.
    let other = create(5, 3, "combine-other");
    let mixed = [&records[0], &records[1], &other[2]];
    assert!(matches!(combine(&mixed, &KW), Err(Error::Mismatch)));
}
