//! What the review screen states, against PSBTs built to lie about it.
//!
//! The wallet is BIP-84's test mnemonic again, and a second mnemonic stands in for a
//! stranger, so "ours" and "not ours" are both real keys rather than flags.

use outscript::btcraw::{RawTx, RawTxIn, RawTxOut};
use outscript::psbt::{Psbt, input as in_key};

use super::*;
use crate::bip32::ChildNumber;
use crate::bip39::{Mnemonic, SEED_LEN};

const OURS: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const STRANGER: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";
const OUR_FP: [u8; 4] = [0x73, 0xc5, 0xda, 0x0a];
const RECEIVE: [u32; 5] = [84 | 0x8000_0000, 0x8000_0000, 0x8000_0000, 0, 0];
const CHANGE: [u32; 5] = [84 | 0x8000_0000, 0x8000_0000, 0x8000_0000, 1, 0];

fn kw() -> KeyWork {
    KeyWork::host()
}

fn master_of(phrase: &str) -> ExtendedPrivKey {
    let m = Mnemonic::parse(phrase, &kw()).unwrap();
    let mut seed = [0u8; SEED_LEN];
    m.to_seed("", &mut seed, &kw()).unwrap();
    ExtendedPrivKey::from_seed(&seed, Network::Mainnet, &kw()).unwrap()
}

fn fingerprint_of(phrase: &str) -> [u8; 4] {
    master_of(phrase).fingerprint(&kw())
}

fn pubkey_at(phrase: &str, steps: &[u32]) -> [u8; 33] {
    let mut here = master_of(phrase);
    for &s in steps {
        here = here.derive_child(ChildNumber(s), &kw()).unwrap();
    }
    here.public_key(&kw())
}

fn p2wpkh_script(pubkey: &[u8; 33]) -> [u8; 22] {
    let mut s = [0u8; 22];
    let n = address::script_pubkey(AddressKind::P2wpkh, pubkey, &mut s).unwrap();
    assert_eq!(n, 22);
    s
}

/// How an input is described to the device.
struct Spend {
    /// Whose key it pays to.
    phrase: &'static str,
    steps: [u32; 5],
    amount: u64,
    /// The fingerprint the PSBT claims, which need not be the truthful one.
    claim: [u8; 4],
    sighash: Option<u32>,
}

/// How an output is described.
struct Pay {
    phrase: &'static str,
    steps: [u32; 5],
    amount: u64,
    /// Whether to record a derivation for it, i.e. claim it as this wallet's.
    claim_ours: bool,
}

/// Build a PSBT with these inputs and outputs. `buf` holds the result.
fn build(spends: &[Spend], pays: &[Pay], buf: &mut [u8]) -> usize {
    let ins: Vec<RawTxIn<'_>> = (0..spends.len())
        .map(|i| RawTxIn {
            txid: [i as u8 + 1; 32],
            vout: 0,
            script_sig: &[],
            sequence: 0xffff_ffff,
            witness: &[],
        })
        .collect();
    let out_scripts: Vec<[u8; 22]> = pays
        .iter()
        .map(|p| p2wpkh_script(&pubkey_at(p.phrase, &p.steps)))
        .collect();
    let outs: Vec<RawTxOut<'_>> = pays
        .iter()
        .zip(&out_scripts)
        .map(|(p, s)| RawTxOut {
            amount: p.amount,
            script: s,
        })
        .collect();
    let tx = RawTx {
        version: 2,
        inputs: &ins,
        outputs: &outs,
        locktime: 0,
    };

    let mut a = vec![0u8; 8192];
    let mut b = vec![0u8; 8192];
    let mut n = Psbt::create_to_slice(&tx, &mut a).unwrap();
    // Each updater step rewrites the whole PSBT, so this ping-pongs between two buffers.
    macro_rules! step {
        ($f:expr) => {{
            let psbt = Psbt::parse(&a[..n]).unwrap();
            let m = $f(&psbt, &mut b).unwrap();
            a[..m].copy_from_slice(&b[..m]);
            n = m;
        }};
    }
    for (i, s) in spends.iter().enumerate() {
        let pk = pubkey_at(s.phrase, &s.steps);
        let spk = p2wpkh_script(&pk);
        step!(|p: &Psbt<'_>, out: &mut [u8]| p.set_witness_utxo(i, s.amount, &spk, out));
        step!(|p: &Psbt<'_>, out: &mut [u8]| p
            .add_input_bip32_derivation(i, &pk, s.claim, &s.steps, out));
        if let Some(kind) = s.sighash {
            step!(|p: &Psbt<'_>, out: &mut [u8]| p.set_sighash_type(i, kind, out));
        }
    }
    for (i, p) in pays.iter().enumerate() {
        if !p.claim_ours {
            continue;
        }
        let pk = pubkey_at(p.phrase, &p.steps);
        step!(|ps: &Psbt<'_>, out: &mut [u8]| ps
            .add_output_bip32_derivation(i, &pk, OUR_FP, &p.steps, out));
    }
    buf[..n].copy_from_slice(&a[..n]);
    n
}

fn ours_spend(amount: u64) -> Spend {
    Spend {
        phrase: OURS,
        steps: RECEIVE,
        amount,
        claim: OUR_FP,
        sighash: None,
    }
}

fn summary_of(bytes: &[u8]) -> Result<Summary, Refusal> {
    let psbt = Psbt::parse(bytes).unwrap();
    summarise(&psbt, &master_of(OURS), OUR_FP, &Policy::default(), &kw())
}

#[test]
fn the_fee_change_and_destination_come_out_of_the_transaction() {
    let mut buf = vec![0u8; 8192];
    let n = build(
        &[ours_spend(100_000)],
        &[
            Pay {
                phrase: STRANGER,
                steps: RECEIVE,
                amount: 70_000,
                claim_ours: false,
            },
            Pay {
                phrase: OURS,
                steps: CHANGE,
                amount: 25_000,
                claim_ours: true,
            },
        ],
        &mut buf,
    );
    let s = summary_of(&buf[..n]).unwrap();
    assert_eq!((s.inputs, s.ours, s.outputs), (1, 1, 2));
    assert_eq!((s.total_in, s.total_out), (100_000, 95_000));
    assert_eq!((s.sending, s.change, s.fee), (70_000, 25_000, 5_000));
    // 5 000 of 70 000 sent is 7%: above the warning, below the cap.
    assert_eq!(s.fee_percent, 7);
    assert!(s.fee_warn);

    let psbt = Psbt::parse(&buf[..n]).unwrap();
    let mut dests = [Destination {
        index: 0,
        amount: 0,
        change: false,
        address: [0; address::MAX_ADDRESS_LEN],
        address_len: 0,
    }; 4];
    let found = destinations(
        &psbt,
        &master_of(OURS),
        OUR_FP,
        Network::Mainnet,
        &mut dests,
        &kw(),
    );
    assert_eq!(found, 2);
    assert!(!dests[0].change);
    assert!(dests[1].change, "our own change is recognised");
    assert!(dests[0].address().starts_with("bc1q"));
    // The stranger's address is the one their key really produces.
    let mut expect = [0u8; address::MAX_ADDRESS_LEN];
    let m = address::encode(
        AddressKind::P2wpkh,
        Network::Mainnet,
        &pubkey_at(STRANGER, &RECEIVE),
        &mut expect,
    )
    .unwrap();
    assert_eq!(dests[0].address().as_bytes(), &expect[..m]);
}

#[test]
fn an_output_that_only_claims_to_be_ours_is_not_change() {
    // The host records our fingerprint and one of our paths on an output that actually pays
    // a stranger: the amount must show as sent, not hidden as change.
    let mut buf = vec![0u8; 8192];
    let n = build(
        &[ours_spend(100_000)],
        &[Pay {
            phrase: STRANGER,
            steps: CHANGE,
            amount: 95_000,
            claim_ours: true,
        }],
        &mut buf,
    );
    let s = summary_of(&buf[..n]).unwrap();
    assert_eq!(s.change, 0, "a claim is not proof");
    assert_eq!(s.sending, 95_000);
    assert_eq!(s.fee, 5_000);
}

#[test]
fn an_input_that_is_not_ours_is_counted_but_not_signable() {
    let mut buf = vec![0u8; 8192];
    let n = build(
        &[
            ours_spend(60_000),
            Spend {
                phrase: STRANGER,
                steps: RECEIVE,
                amount: 40_000,
                claim: fingerprint_of(STRANGER),
                sighash: None,
            },
        ],
        &[Pay {
            phrase: STRANGER,
            steps: RECEIVE,
            amount: 99_000,
            claim_ours: false,
        }],
        &mut buf,
    );
    let s = summary_of(&buf[..n]).unwrap();
    assert_eq!((s.inputs, s.ours), (2, 1), "one of the two is ours");
    assert_eq!(s.total_in, 100_000, "the fee needs both amounts");
    assert_eq!(s.fee, 1_000);

    let psbt = Psbt::parse(&buf[..n]).unwrap();
    let mut ours = [0usize; 4];
    let n_ours = our_inputs(&psbt, &master_of(OURS), OUR_FP, &mut ours, &kw());
    assert_eq!(&ours[..n_ours], &[0]);
}

#[test]
fn a_transaction_with_nothing_of_ours_is_refused() {
    let mut buf = vec![0u8; 8192];
    let n = build(
        &[Spend {
            phrase: STRANGER,
            steps: RECEIVE,
            amount: 50_000,
            claim: fingerprint_of(STRANGER),
            sighash: None,
        }],
        &[Pay {
            phrase: STRANGER,
            steps: CHANGE,
            amount: 49_000,
            claim_ours: false,
        }],
        &mut buf,
    );
    assert_eq!(summary_of(&buf[..n]), Err(Refusal::NothingOfOurs));
}

#[test]
fn a_fee_above_the_cap_is_refused_and_the_cap_is_configurable() {
    let mut buf = vec![0u8; 8192];
    // 20 000 fee on 80 000 sent: 25%.
    let n = build(
        &[ours_spend(100_000)],
        &[Pay {
            phrase: STRANGER,
            steps: RECEIVE,
            amount: 80_000,
            claim_ours: false,
        }],
        &mut buf,
    );
    assert_eq!(
        summary_of(&buf[..n]),
        Err(Refusal::FeeTooHigh {
            percent: 25,
            cap: 10
        })
    );
    // The same transaction passes under a policy that allows it, still flagged.
    let psbt = Psbt::parse(&buf[..n]).unwrap();
    let s = summarise(
        &psbt,
        &master_of(OURS),
        OUR_FP,
        &Policy {
            max_fee_percent: 50,
            warn_fee_percent: 5,
        },
        &kw(),
    )
    .unwrap();
    assert!(s.fee_warn);
    assert_eq!(s.fee_percent, 25);
}

#[test]
fn a_sighash_type_we_do_not_produce_stops_the_signing() {
    let mut buf = vec![0u8; 8192];
    let n = build(
        &[Spend {
            sighash: Some(0x02), // SIGHASH_NONE: the outputs would not be signed at all
            ..ours_spend(100_000)
        }],
        &[Pay {
            phrase: STRANGER,
            steps: RECEIVE,
            amount: 99_000,
            claim_ours: false,
        }],
        &mut buf,
    );
    assert_eq!(
        summary_of(&buf[..n]),
        Err(Refusal::Sighash {
            input: 0,
            kind: 0x02
        })
    );
    // SIGHASH_ALL, stated explicitly, is fine.
    let n = build(
        &[Spend {
            sighash: Some(SIGHASH_ALL),
            ..ours_spend(100_000)
        }],
        &[Pay {
            phrase: STRANGER,
            steps: RECEIVE,
            amount: 99_000,
            claim_ours: false,
        }],
        &mut buf,
    );
    assert!(summary_of(&buf[..n]).is_ok());
}

#[test]
fn an_input_with_no_amount_is_refused_rather_than_priced_at_zero() {
    // Build normally, then strip the witness UTXO: without it the fee is unknowable, and a
    // transaction signed blind to amounts can pay everything to fees.
    let mut buf = vec![0u8; 8192];
    let n = build(
        &[ours_spend(100_000)],
        &[Pay {
            phrase: STRANGER,
            steps: RECEIVE,
            amount: 99_000,
            claim_ours: false,
        }],
        &mut buf,
    );
    let psbt = Psbt::parse(&buf[..n]).unwrap();
    let mut stripped = vec![0u8; 8192];
    let m = psbt
        .remove_input_record(0, &[in_key::WITNESS_UTXO as u8], &mut stripped)
        .unwrap();
    assert_eq!(
        summary_of(&stripped[..m]),
        Err(Refusal::UnknownAmount { input: 0 })
    );
}

/// A PSBT paying `CHANGE`, with `junk` decoy derivation records ahead of the real one.
/// Each decoy names our fingerprint, so each costs a derivation; the real record is last,
/// so a cap that fires hides it.
fn change_with_decoys(junk: usize, buf: &mut [u8]) -> usize {
    let mut a = vec![0u8; 1 << 17];
    let mut b = vec![0u8; 1 << 17];
    let mut n = build(
        &[ours_spend(100_000)],
        &[
            Pay {
                phrase: OURS,
                steps: CHANGE,
                amount: 60_000,
                claim_ours: false,
            },
            // So `sending` is never zero, whichever way the change output is counted.
            Pay {
                phrase: STRANGER,
                steps: RECEIVE,
                amount: 39_000,
                claim_ours: false,
            },
        ],
        &mut a,
    );
    for j in 0..junk {
        // Ours, so it derives, but not the key this output pays to.
        let pk = pubkey_at(OURS, &[900 + j as u32]);
        let steps = [84 | 0x8000_0000, 0x8000_0000, 0x8000_0000, 9, j as u32];
        let psbt = Psbt::parse(&a[..n]).unwrap();
        let m = psbt
            .add_output_bip32_derivation(0, &pk, OUR_FP, &steps, &mut b)
            .unwrap();
        a[..m].copy_from_slice(&b[..m]);
        n = m;
    }
    let pk = pubkey_at(OURS, &CHANGE);
    let psbt = Psbt::parse(&a[..n]).unwrap();
    let m = psbt
        .add_output_bip32_derivation(0, &pk, OUR_FP, &CHANGE, &mut b)
        .unwrap();
    buf[..m].copy_from_slice(&b[..m]);
    m
}

#[test]
fn change_is_still_found_behind_a_few_decoy_records() {
    let mut buf = vec![0u8; 1 << 17];
    let n = change_with_decoys(MAX_CHANGE_KEYS - 1, &mut buf);
    let psbt = Psbt::parse(&buf[..n]).unwrap();
    let script = p2wpkh_script(&pubkey_at(OURS, &CHANGE));
    assert!(is_change(
        &psbt,
        0,
        &script,
        &master_of(OURS),
        OUR_FP,
        &kw()
    ));
}

#[test]
fn an_output_cannot_ask_for_unbounded_derivation() {
    // Uncapped this is one masked derivation per record, for as many as the file holds.
    let mut buf = vec![0u8; 1 << 17];
    let n = change_with_decoys(MAX_CHANGE_KEYS, &mut buf);
    let psbt = Psbt::parse(&buf[..n]).unwrap();
    let script = p2wpkh_script(&pubkey_at(OURS, &CHANGE));
    assert!(!is_change(
        &psbt,
        0,
        &script,
        &master_of(OURS),
        OUR_FP,
        &kw()
    ));
}

#[test]
fn the_cap_shows_a_stuffed_change_output_as_money_leaving() {
    // Through the callers the firmware uses, which walk every output inside the masked
    // region, rather than `is_change` alone.
    let mut buf = vec![0u8; 1 << 17];
    let n = change_with_decoys(MAX_CHANGE_KEYS, &mut buf);
    let psbt = Psbt::parse(&buf[..n]).unwrap();
    let master = master_of(OURS);

    let sum = summarise(&psbt, &master, OUR_FP, &Policy::default(), &kw()).unwrap();
    assert_eq!(sum.change, 0);
    assert_eq!(sum.sending, 99_000);

    let mut dests = [Destination {
        index: 0,
        amount: 0,
        change: false,
        address: [0; address::MAX_ADDRESS_LEN],
        address_len: 0,
    }; 4];
    let found = destinations(&psbt, &master, OUR_FP, Network::Mainnet, &mut dests, &kw());
    assert_eq!(found, 2);
    assert!(!dests[0].change, "a stuffed output was still folded into change");
    assert!(!dests[0].address().is_empty(), "shown without an address");
}

#[test]
fn a_signature_already_on_an_input_is_visible() {
    let mut buf = vec![0u8; 8192];
    let n = build(
        &[ours_spend(100_000)],
        &[Pay {
            phrase: STRANGER,
            steps: RECEIVE,
            amount: 99_000,
            claim_ours: false,
        }],
        &mut buf,
    );
    let psbt = Psbt::parse(&buf[..n]).unwrap();
    let master = master_of(OURS);
    assert!(!already_signed(&psbt, 0, &master, OUR_FP, &kw()));

    let mut signed = vec![0u8; 8192];
    let len = crate::signer::sign_input(&psbt, 0, &master, OUR_FP, &mut signed, &kw()).unwrap();
    let signed = Psbt::parse(&signed[..len]).unwrap();
    assert!(already_signed(&signed, 0, &master, OUR_FP, &kw()));
}
