//! How big things are: share records (settings space), pair caches (card space) and
//! messages per round (QR parts, SD files). `cargo test -p catcard-tss --test sizes -- --nocapture` prints the table.
//!
//! The assertions are loose ceilings, there to notice a format change that multiplies a
//! size, not to pin today's numbers.

mod common;

use catcard_tss::{AccountKey, ShareRecord, SignMode, SignRequest, export};
use common::*;

/// Envelope sizes on `card`, sent by member `from`: per round, (broadcast, each unicast).
fn per_round(card: &Card, from: u8) -> Vec<(u8, Option<usize>, Option<usize>)> {
    let mut out: Vec<(u8, Option<usize>, Option<usize>)> = Vec::new();
    for (name, bytes) in &card.files {
        let (r, f, t) = catcard_tss::parse_file_name(name).unwrap();
        if f != from {
            continue;
        }
        let i = match out.iter().position(|x| x.0 == r) {
            Some(i) => i,
            None => {
                out.push((r, None, None));
                out.len() - 1
            }
        };
        if t == 0 {
            out[i].1 = Some(bytes.len());
        } else {
            out[i].2 = Some(out[i].2.unwrap_or(0).max(bytes.len()));
        }
    }
    out.sort();
    out
}

fn show(label: &str, rows: &[(u8, Option<usize>, Option<usize>)], peers: usize) -> usize {
    let mut total = 0;
    for &(r, bc, uc) in rows {
        let b = bc.unwrap_or(0);
        let u = uc.unwrap_or(0);
        total += b + u * peers;
        println!(
            "  {label} round {r}: broadcast {:>6}  unicast {:>6} x{peers}",
            bc.map_or("-".into(), |v| v.to_string()),
            uc.map_or("-".into(), |v| v.to_string()),
        );
    }
    println!("  {label} total sent by one member: {total} bytes");
    total
}

#[test]
fn print_sizes() {
    println!();
    // Shapes that can be created together (2-of-2 cannot; see `can_create_together`),
    // for 3, 4, 5 and 7 members.
    for (n, t) in [(3u8, 2u8), (4, 2), (5, 3), (7, 4)] {
        let mut records = create(n, t, &format!("sizes-{n}-{t}"));
        let key = catcard_tss::CacheKey::new(&[1; 32], &records[0], &KW);
        let cache = records[0].write_pair_cache(&key, &[2; 16], &KW).unwrap();
        let rec = records[0].to_bytes(&KW).unwrap();
        println!(
            "{t}-of-{n}: share record (core) {} bytes, pair cache {} bytes",
            rec.len(),
            cache.len()
        );
        assert!(rec.len() < 300 + 100 * usize::from(n));
        assert!(cache.len() < 13_000 * usize::from(n));

        // Keygen messages, re-run to keep the card.
        let id = [n, t, 0, 0, 0, 0, 0, 9];
        let mut sessions: Vec<_> = (1..=n)
            .map(|m| {
                catcard_tss::Session::keygen(id, n, t, m, &mut TestRng::new(&format!("kg{m}")), &KW)
                    .unwrap()
            })
            .collect();
        let mut card = Card::default();
        run(&mut sessions, &mut card);
        let total = show("keygen", &per_round(&card, 1), usize::from(n) - 1);
        assert!(total < 40_000 * usize::from(n));

        // Signing, one sighash and four, both modes, with the first t members.
        let signers: Vec<u8> = (1..=t).collect();
        for mode in [SignMode::Plain, SignMode::Checked] {
            for count in [1u32, 4] {
                let reqs: Vec<SignRequest> = (0..count)
                    .map(|i| SignRequest {
                        path: vec![0, i],
                        sighash: sighash(&format!("{i}")),
                    })
                    .collect();
                let mut s = signing_sessions(&records, &signers, &reqs, mode, "sizes");
                let mut card = Card::default();
                run(&mut s, &mut card);
                assert!(s[0].signatures().is_some());
                let total = show(
                    &format!("sign {mode:?} x{count}"),
                    &per_round(&card, 1),
                    usize::from(t) - 1,
                );
                assert!(total < 60_000 * count as usize * usize::from(t));
            }
        }
    }
}

#[test]
fn print_pair_setup_sizes() {
    let records = create(3, 2, "sizes-pair");
    let id = [0x9a, 1, 2, 0, 0, 0, 0, 9];
    let mut sessions: Vec<_> = [(1u8, 2u8), (2, 1)]
        .iter()
        .map(|&(me, peer)| {
            catcard_tss::Session::pair_setup(
                id,
                &records[usize::from(me) - 1],
                peer,
                &mut TestRng::new(&format!("ps{me}")),
                &KW,
            )
            .unwrap()
        })
        .collect();
    let mut card = Card::default();
    run(&mut sessions, &mut card);
    assert!(
        sessions
            .iter()
            .all(|s| s.status() == catcard_tss::Status::Finished)
    );
    let total = show("pair setup", &per_round(&card, 1), 1);
    assert!(total < 40_000);
}

#[test]
fn print_bundle_sizes() {
    let key = AccountKey::new(
        &[0x11; 32],
        &[0x22; 32],
        [1, 2, 3, 4],
        &[0x8000_0054, 0x8000_0000, 0x8000_0000],
    );
    for (n, t) in [(2u8, 2u8), (3, 2), (5, 3), (9, 5)] {
        let bundles = export(&[0x33; 16], &key, n, t, &mut TestRng::new("bundles"), &KW).unwrap();
        let b = bundles[0].to_bytes(&KW).unwrap();
        let r: &ShareRecord = bundles[0].record();
        println!(
            "{t}-of-{n}: share bundle {} bytes (record {}, codex32 {} chars)",
            b.len(),
            r.to_bytes(&KW).unwrap().len(),
            bundles[0].codex32().len()
        );
    }
}
