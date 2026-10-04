//! The key core and the pairs: a record keeps the core, a sealed cache keeps the pairs,
//! and two members can set up a lost pair again without touching anything else.

mod common;

use catcard_tss::cache::{self, CacheKey};
use catcard_tss::{CacheRefused, Error, Session, ShareRecord, SignMode, SignRequest};
use common::*;

fn request(path: &[u32], label: &str) -> SignRequest {
    SignRequest {
        path: path.to_vec(),
        sighash: sighash(label),
    }
}

/// A device's root secret, for the tests: one per device.
fn root(device: u8) -> [u8; 32] {
    [device; 32]
}

fn signs(records: &[ShareRecord], signers: &[u8], label: &str) -> bool {
    let req = [request(&[0, 3], label)];
    let sigs = sign(records, signers, &req, SignMode::Plain);
    let child = records[0].child_public_key(&[0, 3]).unwrap();
    verifies(&child, &req[0].sighash, &sigs[0])
}

#[test]
fn a_key_split_into_its_core_and_its_pair_cache_and_put_back_together_signs() {
    let mut records = create(3, 2, "split");
    let mut back = Vec::new();
    for r in records.iter_mut() {
        let key = CacheKey::new(&root(r.member()), r, &KW);
        let mut file = r.write_pair_cache(&key, &[r.member(); 16], &KW).unwrap();
        // The core is what a device keeps in its settings: a few hundred bytes, no pairs,
        // and the digest of the cache it goes with.
        let core = r.to_bytes(&KW).unwrap();
        assert!(core.len() < 600, "core of 3 members: {} bytes", core.len());
        assert!(file.len() > 2 * 12_000, "two pairs: {} bytes", file.len());
        let mut kept = ShareRecord::from_bytes(&core, &KW).unwrap();
        assert!(kept.pairs().is_empty());
        assert_eq!(kept.cache_digest(), Some(cache::digest(&file)));
        let loaded = kept.read_pair_cache(&mut file, &key, &KW).unwrap();
        let others: Vec<u8> = (1..=3).filter(|&m| m != r.member()).collect();
        assert_eq!(loaded, others);
        assert_eq!(kept.pairs(), others);
        for &m in &others {
            assert_eq!(kept.pair_digest(m), r.pair_digest(m));
        }
        back.push(kept);
    }
    for signers in [[1u8, 2], [1, 3], [2, 3]] {
        assert!(signs(&back, &signers, &format!("put back {signers:?}")));
    }
}

#[test]
fn a_member_with_no_cache_cannot_sign_until_it_sets_up_the_pairs_it_needs() {
    let mut records = create(3, 2, "no cache");
    // Member 1 has its core and nothing else: its cache was on a disk that is gone.
    records[0] = core_only(&records[0]);
    let req = [request(&[0, 1], "no cache")];
    for (signers, missing) in [([1u8, 3], vec![3u8]), ([1, 2], vec![2])] {
        let refused = Session::sign(
            [4; 8],
            &records[0],
            &signers,
            &req,
            SignMode::Plain,
            &mut TestRng::new("refused"),
            &KW,
        );
        assert_eq!(refused.err(), Some(Error::MissingPairs(missing)));
    }
    // Members 2 and 3 still sign together: a pair with a non-signer is never needed.
    assert!(signs(&records, &[2, 3], "without member 1"));

    // Member 1 sets up its pair with member 3 alone, and can sign with member 3 ...
    pair_setup(&mut records, 1, 3, "no cache");
    assert_eq!(records[0].missing_pairs(&[1, 3]), Vec::<u8>::new());
    assert!(signs(&records, &[1, 3], "after the setup"));
    assert!(signs(&records, &[3, 1], "after the setup, other order"));
    // ... but not yet with member 2.
    assert_eq!(records[0].missing_pairs(&[1, 2]), vec![2]);
    set_up_missing(&mut records, &[1, 2], "no cache");
    assert!(signs(&records, &[1, 2], "with member 2 too"));
}

#[test]
fn a_pair_setup_changes_no_share_no_other_pair_and_no_address() {
    let mut records = create(4, 2, "unchanged");
    let paths: [&[u32]; 3] = [&[0, 0], &[0, 7], &[1, 2]];
    let cores: Vec<_> = records.iter().map(|r| r.to_bytes(&KW).unwrap()).collect();
    let children: Vec<_> = paths
        .iter()
        .map(|p| records[0].child_public_key(p).unwrap())
        .collect();
    let digests = |records: &[ShareRecord]| -> Vec<(u8, u8, Option<[u8; 32]>)> {
        let mut out = Vec::new();
        for r in records {
            for peer in 1..=4 {
                if peer != r.member() {
                    out.push((r.member(), peer, r.pair_digest(peer)));
                }
            }
        }
        out
    };
    let before = digests(&records);

    pair_setup(&mut records, 2, 4, "unchanged");

    // Every core -- share, joint key, chain code, public shares -- byte for byte.
    for (r, core) in records.iter().zip(&cores) {
        assert_eq!(*r.to_bytes(&KW).unwrap(), **core, "member {}", r.member());
    }
    // The wallet's keys and addresses.
    for r in &records {
        for (p, c) in paths.iter().zip(&children) {
            assert_eq!(&r.child_public_key(p).unwrap(), c);
        }
    }
    // Only the pair 2-4 is new, on both sides; every other pair is as it was.
    for (b, a) in before.iter().zip(digests(&records)) {
        let rebuilt = matches!((a.0, a.1), (2, 4) | (4, 2));
        assert_eq!(b.2 != a.2, rebuilt, "pair {}-{}", a.0, a.1);
        assert!(a.2.is_some());
    }
    // And all of them still sign: the new pair, and pairs nobody touched.
    for signers in [[2u8, 4], [1, 3], [1, 2], [3, 4]] {
        assert!(signs(&records, &signers, &format!("after 2-4 {signers:?}")));
    }
}

#[test]
fn a_stale_tampered_or_cut_cache_is_refused_by_the_digest_its_record_keeps() {
    let mut records = create(3, 2, "stale");
    let key = CacheKey::new(&root(1), &records[0], &KW);
    let old = records[0].write_pair_cache(&key, &[1; 16], &KW).unwrap();
    // Member 1 sets up its pair with member 2 again and keeps a new cache; the record now
    // names the new one.
    pair_setup(&mut records, 1, 2, "stale");
    let new = records[0].write_pair_cache(&key, &[2; 16], &KW).unwrap();
    assert_ne!(cache::digest(&old), cache::digest(&new));
    let core = records[0].to_bytes(&KW).unwrap();

    let refused = |file: &[u8]| {
        let mut kept = ShareRecord::from_bytes(&core, &KW).unwrap();
        let mut file = file.to_vec();
        let r = kept.read_pair_cache(&mut file, &key, &KW);
        if r.is_err() {
            assert!(
                kept.pairs().is_empty(),
                "nothing taken from a refused cache"
            );
        }
        r.err()
    };
    let stale = Some(Error::Cache(CacheRefused::NotCurrent));
    // The old cache is authentic -- this device sealed it for this wallet -- and refused.
    assert_eq!(refused(&old), stale);
    // Any byte changed, anywhere: header, IV, tag, ciphertext.
    for at in [
        0usize,
        5,
        10,
        30,
        cache::HEAD_LEN,
        new.len() / 2,
        new.len() - 1,
    ] {
        let mut bad = new.to_vec();
        bad[at] ^= 0x40;
        assert_eq!(refused(&bad), stale, "byte {at}");
    }
    // Cut short, or with bytes added.
    assert_eq!(refused(&new[..new.len() - 1]), stale);
    assert_eq!(refused(&new[..cache::HEAD_LEN]), stale);
    let mut longer = new.to_vec();
    longer.push(0);
    assert_eq!(refused(&longer), stale);
    // A record that names no cache takes none.
    let mut forgot = ShareRecord::from_bytes(&core, &KW).unwrap();
    forgot.forget_cache();
    let mut file = new.to_vec();
    assert_eq!(forgot.read_pair_cache(&mut file, &key, &KW).err(), stale);
    // The current one is taken.
    assert_eq!(refused(&new), None);
}

#[test]
fn a_cache_opens_only_on_the_device_and_for_the_wallet_it_was_written_for() {
    let mut records = create(3, 2, "bound");
    let mine = CacheKey::new(&root(1), &records[0], &KW);
    let file = records[0].write_pair_cache(&mine, &[7; 16], &KW).unwrap();
    let core = records[0].to_bytes(&KW).unwrap();

    // The same record on another device -- its core copied, digest and all -- with the
    // cache on the card: the digest matches, the keys do not.
    let mut copied = ShareRecord::from_bytes(&core, &KW).unwrap();
    let theirs = CacheKey::new(&root(2), &copied, &KW);
    let mut f = file.to_vec();
    assert_eq!(
        copied.read_pair_cache(&mut f, &theirs, &KW).err(),
        Some(Error::Cache(CacheRefused::Foreign))
    );
    assert!(copied.pairs().is_empty());

    // Member 1 of another wallet on the same device, whose record is made to name this
    // cache: the same root, another wallet's keys.
    let other = create(3, 2, "bound other");
    let mut other_core = other[0].to_bytes(&KW).unwrap().to_vec();
    // A created-together record has no origin path, so its digest is at offset 79 (the
    // layout in `share.rs`).
    let at = 79;
    other_core[at..at + 32].copy_from_slice(&cache::digest(&file));
    let mut other1 = ShareRecord::from_bytes(&other_core, &KW).unwrap();
    assert_eq!(other1.cache_digest(), Some(cache::digest(&file)));
    let key = CacheKey::new(&root(1), &other1, &KW);
    let mut f = file.to_vec();
    assert_eq!(
        other1.read_pair_cache(&mut f, &key, &KW).err(),
        Some(Error::Cache(CacheRefused::Foreign))
    );
    assert!(other1.pairs().is_empty());

    // And it is named apart: one card holds every member's, of every wallet.
    let names: Vec<String> = records
        .iter()
        .chain(other.iter())
        .map(cache::file_name)
        .collect();
    for (i, a) in names.iter().enumerate() {
        assert!(a.starts_with("TSS/") && a.ends_with(".pairs"), "{a}");
        assert!(!names[i + 1..].contains(a), "{a} twice");
    }

    // Its own device takes it.
    let mut kept = ShareRecord::from_bytes(&core, &KW).unwrap();
    let mut f = file.to_vec();
    assert_eq!(
        kept.read_pair_cache(&mut f, &mine, &KW).unwrap(),
        vec![2, 3]
    );
}

#[test]
fn a_pair_setup_session_is_only_between_two_members_of_one_wallet() {
    let records = create(3, 2, "setup shape");
    let mut rng = TestRng::new("shape");
    for peer in [0u8, 1, 4] {
        assert!(matches!(
            Session::pair_setup([1; 8], &records[0], peer, &mut rng, &KW),
            Err(Error::Parameters)
        ));
    }
    // Two members who name each other but hold different wallets never get as far as a
    // code: the wallet is in what each commits to, so the other's key does not open.
    let other = create(3, 2, "setup shape other");
    let id = [0x77; 8];
    let mut sessions = [
        Session::pair_setup(id, &records[0], 2, &mut TestRng::new("a"), &KW).unwrap(),
        Session::pair_setup(id, &other[1], 1, &mut TestRng::new("b"), &KW).unwrap(),
    ];
    let mut card = Card::default();
    let mut refusals = Vec::new();
    for _ in 0..4 {
        for s in sessions.iter_mut() {
            card.put(s);
        }
        for s in sessions.iter_mut() {
            for (r, f, t) in s.awaiting() {
                if let Some(bytes) = card.get(&catcard_tss::file_name(r, f, t)) {
                    let bytes = bytes.to_vec();
                    if let Err(e) = s.receive(&bytes, &KW) {
                        refusals.push(e);
                    }
                }
            }
        }
    }
    assert!(sessions.iter().all(|s| s.code().is_none()));
    assert!(refusals.contains(&Error::Refused(catcard_tss::Refused::CommitmentMismatch)));
    // And a finished session's pair is not installed into another wallet's record.
    let mut records = records;
    let mut done = vec![
        Session::pair_setup(id, &records[0], 2, &mut TestRng::new("c"), &KW).unwrap(),
        Session::pair_setup(id, &records[1], 1, &mut TestRng::new("d"), &KW).unwrap(),
    ];
    let mut card = Card::default();
    run(&mut done, &mut card);
    let mut stranger = other[0].clone();
    assert_eq!(
        done[0].install_pair(&mut stranger, &KW).err(),
        Some(Error::Mismatch)
    );
    assert_eq!(done[0].install_pair(&mut records[0], &KW).unwrap(), 2);
    assert!(
        done[0].install_pair(&mut records[0], &KW).is_err(),
        "once only"
    );
}
