//! The 166 published vectors, and what this refuses.
//!
//! `vectors.json` is Bitcoin Knots' own `src/test/data/unified_sighash.json`, kept
//! verbatim (MIT; see `THIRD-PARTY-NOTICES.md`) rather than transformed into a table, so
//! what is checked here is the file the specification points at.
//!
//! Each row is `[scriptCode, rawTx, inIdx, hashType, scriptType, [[value, spk], ...],
//! sighash]`, hashes in raw byte order. For the tapscript rows the scriptCode column is
//! the leaf script, with no annex and no executed `OP_CODESEPARATOR`.

use super::*;
use crate::address::tagged_hash;

const VECTORS: &str = include_str!("vectors.json");

/// One row, as the file has it.
struct Vector {
    script_code: Vec<u8>,
    raw_tx: Vec<u8>,
    input_index: usize,
    hash_type: u8,
    script_type: u8,
    spent: Vec<(u64, Vec<u8>)>,
    expected: [u8; 32],
}

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex: {s}");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

/// Read the file. It is an array of arrays holding only strings, numbers and arrays, so
/// a full JSON parser is not wanted here -- this walks it with a cursor and would rather
/// panic than accept something it did not understand.
fn vectors() -> Vec<Vector> {
    let b = VECTORS.as_bytes();
    let mut at = 0usize;

    fn skip_space(b: &[u8], at: &mut usize) {
        while *at < b.len() && b[*at].is_ascii_whitespace() {
            *at += 1;
        }
    }
    fn expect(b: &[u8], at: &mut usize, c: u8) {
        skip_space(b, at);
        assert_eq!(b[*at], c, "wanted {} at {}", c as char, at);
        *at += 1;
    }
    fn peek(b: &[u8], at: &mut usize) -> u8 {
        skip_space(b, at);
        b[*at]
    }
    fn string(b: &[u8], at: &mut usize) -> String {
        expect(b, at, b'"');
        let start = *at;
        while b[*at] != b'"' {
            *at += 1;
        }
        let s = core::str::from_utf8(&b[start..*at])
            .expect("utf8")
            .to_owned();
        *at += 1;
        s
    }
    fn number(b: &[u8], at: &mut usize) -> u64 {
        skip_space(b, at);
        let start = *at;
        while *at < b.len() && b[*at].is_ascii_digit() {
            *at += 1;
        }
        core::str::from_utf8(&b[start..*at])
            .expect("utf8")
            .parse()
            .expect("a number")
    }

    let mut out = Vec::new();
    expect(b, &mut at, b'[');
    // The first row names the columns: seven strings, and then the vectors.
    expect(b, &mut at, b'[');
    while peek(b, &mut at) != b']' {
        if peek(b, &mut at) == b',' {
            at += 1;
            continue;
        }
        let _ = string(b, &mut at);
    }
    expect(b, &mut at, b']');
    loop {
        if peek(b, &mut at) == b',' {
            at += 1;
            continue;
        }
        if peek(b, &mut at) == b']' {
            break;
        }
        expect(b, &mut at, b'[');
        let script_code = hex(&string(b, &mut at));
        expect(b, &mut at, b',');
        let raw_tx = hex(&string(b, &mut at));
        expect(b, &mut at, b',');
        let input_index = number(b, &mut at) as usize;
        expect(b, &mut at, b',');
        let hash_type = number(b, &mut at) as u8;
        expect(b, &mut at, b',');
        let script_type = number(b, &mut at) as u8;
        expect(b, &mut at, b',');
        expect(b, &mut at, b'[');
        let mut spent = Vec::new();
        while peek(b, &mut at) != b']' {
            if peek(b, &mut at) == b',' {
                at += 1;
                continue;
            }
            expect(b, &mut at, b'[');
            let value = number(b, &mut at);
            expect(b, &mut at, b',');
            let spk = hex(&string(b, &mut at));
            expect(b, &mut at, b']');
            spent.push((value, spk));
        }
        expect(b, &mut at, b']');
        expect(b, &mut at, b',');
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&hex(&string(b, &mut at)));
        expect(b, &mut at, b']');
        if peek(b, &mut at) == b',' {
            at += 1;
        }
        out.push(Vector {
            script_code,
            raw_tx,
            input_index,
            hash_type,
            script_type,
            spent,
            expected,
        });
    }
    out
}

/// BIP-341's leaf hash for a tapscript, at the only leaf version there is.
fn tapleaf(script: &[u8]) -> [u8; 32] {
    let mut data = vec![0xc0u8];
    let mut size = [0u8; 9];
    let n = VarInt::write(script.len() as u64, &mut size).unwrap();
    data.extend_from_slice(&size[..n]);
    data.extend_from_slice(script);
    tagged_hash(b"TapLeaf", &data)
}

/// Every vector in the specification's own file, all four script types.
#[test]
fn the_published_vectors_all_reproduce() {
    let all = vectors();
    assert_eq!(all.len(), 166, "the file should hold 166 vectors");
    let mut by_type = [0usize; 4];
    for (n, v) in all.iter().enumerate() {
        let tx = Transaction::parse(&v.raw_tx).expect("a vector's transaction parses");
        let spent: Vec<SpentOutput<'_>> = v
            .spent
            .iter()
            .map(|(value, spk)| SpentOutput {
                value: *value,
                script_pubkey: spk,
            })
            .collect();
        let spend = match v.script_type {
            0 => Spend::Legacy {
                script_code: &v.script_code,
            },
            1 => Spend::SegwitV0 {
                script_code: &v.script_code,
            },
            2 => Spend::KeyPath { annex: None },
            _ => Spend::Tapscript {
                annex: None,
                tapleaf_hash: tapleaf(&v.script_code),
                codesep: NO_CODESEPARATOR,
            },
        };
        by_type[v.script_type as usize] += 1;
        let aggregates = Aggregates::compute(&tx, &spent).expect("aggregates");
        let got = unified(&tx, &aggregates, v.input_index, &spent, spend, v.hash_type)
            .unwrap_or_else(|e| panic!("vector {n} (type {}): {e:?}", v.script_type));
        assert_eq!(got, v.expected, "vector {n}, script type {}", v.script_type);
    }
    assert!(
        by_type.iter().all(|&n| n > 0),
        "every script type should be covered: {by_type:?}"
    );
}

/// The aggregates commit to every spent output, so the list has to be the transaction's
/// own. A short one is refused rather than padded.
#[test]
fn the_spent_outputs_must_match_the_inputs() {
    let v = &vectors()[0];
    let tx = Transaction::parse(&v.raw_tx).unwrap();
    let spent: Vec<SpentOutput<'_>> = v
        .spent
        .iter()
        .map(|(value, spk)| SpentOutput {
            value: *value,
            script_pubkey: spk,
        })
        .collect();
    assert!(matches!(
        Aggregates::compute(&tx, &spent[..spent.len() - 1]),
        Err(Error::SpentOutputCount { .. })
    ));
}

/// A change in any spent output changes the message -- which is the whole point of the
/// algorithm, and what closes CVE-2020-14199: a device lied to about *another* input's
/// amount produces a signature that does not verify.
#[test]
fn another_inputs_amount_changes_the_message() {
    let v = vectors()
        .into_iter()
        .find(|v| v.spent.len() > 1 && v.hash_type & 0x80 == 0)
        .expect("a vector with more than one input");
    let tx = Transaction::parse(&v.raw_tx).unwrap();
    let mut spent: Vec<SpentOutput<'_>> = v
        .spent
        .iter()
        .map(|(value, spk)| SpentOutput {
            value: *value,
            script_pubkey: spk,
        })
        .collect();
    let other = (v.input_index + 1) % spent.len();
    spent[other].value += 1;
    let aggregates = Aggregates::compute(&tx, &spent).unwrap();
    let spend = match v.script_type {
        0 => Spend::Legacy {
            script_code: &v.script_code,
        },
        1 => Spend::SegwitV0 {
            script_code: &v.script_code,
        },
        2 => Spend::KeyPath { annex: None },
        _ => Spend::Tapscript {
            annex: None,
            tapleaf_hash: tapleaf(&v.script_code),
            codesep: NO_CODESEPARATOR,
        },
    };
    let got = unified(&tx, &aggregates, v.input_index, &spent, spend, v.hash_type).unwrap();
    assert_ne!(got, v.expected);
}

/// The script type byte separates the four, so a signature made for one is not valid for
/// another even where the rest of the message is identical.
#[test]
fn the_script_type_separates_the_messages() {
    let v = vectors()
        .into_iter()
        .find(|v| v.script_type == 0)
        .expect("a bare vector");
    let tx = Transaction::parse(&v.raw_tx).unwrap();
    let spent: Vec<SpentOutput<'_>> = v
        .spent
        .iter()
        .map(|(value, spk)| SpentOutput {
            value: *value,
            script_pubkey: spk,
        })
        .collect();
    let aggregates = Aggregates::compute(&tx, &spent).unwrap();
    let as_legacy = unified(
        &tx,
        &aggregates,
        v.input_index,
        &spent,
        Spend::Legacy {
            script_code: &v.script_code,
        },
        v.hash_type,
    )
    .unwrap();
    let as_segwit = unified(
        &tx,
        &aggregates,
        v.input_index,
        &spent,
        Spend::SegwitV0 {
            script_code: &v.script_code,
        },
        v.hash_type,
    )
    .unwrap();
    assert_eq!(as_legacy, v.expected);
    assert_ne!(as_legacy, as_segwit);
}
