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

/// The accounts a spend draws on, as `summarise` works them out. `destinations` takes them
/// rather than deriving them again, so a test has to hand over the same list.
fn accounts_of(psbt: &Psbt<'_>, master: &ExtendedPrivKey) -> Vec<Account> {
    match summarise(psbt, &owner(master, &[]), &Policy::default(), &kw()) {
        Ok(s) => s.accounts[..s.account_count].to_vec(),
        // A transaction this refuses has no accounts to speak of; the caller is testing
        // something else about it.
        Err(_) => Vec::new(),
    }
}

/// This device, as the review functions want it: the seed, its fingerprint, and whichever
/// multisig wallets the test has registered.
fn owner<'a>(master: &'a ExtendedPrivKey, wallets: &'a [crate::multisig::Multisig]) -> Owner<'a> {
    Owner {
        master,
        fingerprint: OUR_FP,
        wallets,
        bare_keys: &[],
    }
}

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
    /// Withhold the previous transaction, leaving the amount as the host's word alone.
    no_prev_tx: bool,
    /// What the witness UTXO claims, when that is not what was really paid. The previous
    /// transaction always carries `amount`, so a lie here does not move the outpoint.
    declared: Option<u64>,
}

/// How an output is described.
struct Pay {
    phrase: &'static str,
    steps: [u32; 5],
    amount: u64,
    /// Whether to record a derivation for it, i.e. claim it as this wallet's.
    claim_ours: bool,
}

/// Build a PSBT whose inputs are all BIP-84 `wpkh` scripts.
fn build(spends: &[Spend], pays: &[Pay], buf: &mut [u8]) -> usize {
    let kinds = vec![AddressKind::P2wpkh; spends.len()];
    build_as(spends, &kinds, pays, buf)
}

/// The script an input's previous output pays to, from the key it is derived at.
fn script_of(kind: AddressKind, pubkey: &[u8; 33]) -> Vec<u8> {
    let mut s = [0u8; 34];
    let n = address::script_pubkey(kind, pubkey, &mut s).unwrap();
    s[..n].to_vec()
}

/// Build a PSBT, `kinds` saying which script kind each input's previous output pays to --
/// so a test can spend a BIP-49 `sh(wpkh(...))` input as well as a native one.
fn build_as(spends: &[Spend], kinds: &[AddressKind], pays: &[Pay], buf: &mut [u8]) -> usize {
    // A previous transaction per input, paying `amount` at its output 0, whose txid the
    // input then spends.
    let prev_scripts: Vec<Vec<u8>> = spends
        .iter()
        .zip(kinds)
        .map(|(s, kind)| script_of(*kind, &pubkey_at(s.phrase, &s.steps)))
        .collect();
    let built: Vec<(Vec<u8>, [u8; 32])> = spends
        .iter()
        .zip(&prev_scripts)
        .enumerate()
        .map(|(i, (s, spk))| {
            let ins = [RawTxIn {
                txid: [i as u8 + 0xA0; 32],
                vout: 0,
                script_sig: &[],
                sequence: 0xffff_ffff,
                witness: &[],
            }];
            let outs = [RawTxOut {
                amount: s.amount,
                script: spk.as_slice(),
            }];
            let tx = RawTx {
                version: 2,
                inputs: &ins,
                outputs: &outs,
                locktime: 0,
            };
            let mut raw = vec![0u8; tx.serialized_len()];
            let n = tx.serialize_to_slice(&mut raw).unwrap();
            raw.truncate(n);
            (raw, tx.txid())
        })
        .collect();
    let prevs: Vec<&[u8]> = built.iter().map(|(raw, _)| raw.as_slice()).collect();
    let ins: Vec<RawTxIn<'_>> = built
        .iter()
        .map(|(_, txid)| txid)
        .map(|txid| RawTxIn {
            txid: *txid,
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
        let spk = script_of(kinds[i], &pk);
        let claimed = s.declared.unwrap_or(s.amount);
        step!(|p: &Psbt<'_>, out: &mut [u8]| p.set_witness_utxo(i, claimed, &spk, out));
        if !s.no_prev_tx {
            step!(|p: &Psbt<'_>, out: &mut [u8]| p.set_non_witness_utxo(i, prevs[i], out));
        }
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
        no_prev_tx: false,
        declared: None,
    }
}

fn summary_of(bytes: &[u8]) -> Result<Summary, Refusal> {
    let psbt = Psbt::parse(bytes).unwrap();
    summarise(
        &psbt,
        &owner(&master_of(OURS), &[]),
        &Policy::default(),
        &kw(),
    )
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
    let master = master_of(OURS);
    let found = destinations(
        &psbt,
        &owner(&master, &[]),
        Network::Mainnet,
        &accounts_of(&psbt, &master),
        &[],
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
                no_prev_tx: false,
                declared: None,
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
            no_prev_tx: false,
            declared: None,
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
fn a_wif_store_key_makes_its_input_ours_in_the_review() {
    // The very transaction the previous test refuses: it spends a key the seed does not
    // own, so with no WIF store it is "nothing of ours". Add that key's public key to the
    // store and the same input is ours -- which is what lets a swept paper wallet be
    // reviewed and signed.
    let mut buf = vec![0u8; 8192];
    let n = build(
        &[Spend {
            phrase: STRANGER,
            steps: RECEIVE,
            amount: 50_000,
            claim: fingerprint_of(STRANGER),
            sighash: None,
            no_prev_tx: false,
            declared: None,
        }],
        &[Pay {
            phrase: STRANGER,
            steps: CHANGE,
            amount: 49_000,
            claim_ours: false,
        }],
        &mut buf,
    );
    let psbt = Psbt::parse(&buf[..n]).unwrap();
    let master = master_of(OURS);
    let bare = [pubkey_at(STRANGER, &RECEIVE)];

    // Without the store: refused.
    assert_eq!(
        summarise(&psbt, &owner(&master, &[]), &Policy::default(), &kw()),
        Err(Refusal::NothingOfOurs)
    );

    // With the store: the input is ours, and no change account is invented for it -- the
    // output paying STRANGER's own change key is money leaving, not change.
    let owner = Owner {
        master: &master,
        fingerprint: OUR_FP,
        wallets: &[],
        bare_keys: &bare,
    };
    let s = summarise(&psbt, &owner, &Policy::default(), &kw()).unwrap();
    assert_eq!((s.inputs, s.ours), (1, 1));
    assert_eq!(s.change, 0, "a WIF key's receive is not change of this wallet");

    // And the WIF-input finder agrees on which input it is.
    let mut hits = [0usize; 4];
    assert_eq!(wif_inputs(&psbt, &bare[0], &mut hits), 1);
    assert_eq!(hits[0], 0);
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
        &owner(&master_of(OURS), &[]),
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
    // The previous transaction is what prices an input: losing the witness UTXO changes
    // nothing, losing the previous transaction is a refusal.
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

    let mut without_witness = vec![0u8; 8192];
    let m = psbt
        .remove_input_record(0, &[in_key::WITNESS_UTXO as u8], &mut without_witness)
        .unwrap();
    assert!(summary_of(&without_witness[..m]).is_ok());

    let mut without_prev = vec![0u8; 8192];
    let m = psbt
        .remove_input_record(0, &[in_key::NON_WITNESS_UTXO as u8], &mut without_prev)
        .unwrap();
    assert_eq!(
        summary_of(&without_prev[..m]),
        Err(Refusal::UnverifiedAmount { input: 0 })
    );
}

#[test]
fn an_amount_the_host_merely_asserts_is_refused() {
    // One honest input of 1.0 BTC and one declared at a single satoshi. Unrefused, the
    // fee reads as 0.05 BTC against a 0.95 BTC payment on a transaction that burns 1.05.
    let mut buf = vec![0u8; 16384];
    let n = build(
        &[
            ours_spend(100_000_000),
            Spend {
                phrase: OURS,
                steps: [84 | 0x8000_0000, 0x8000_0000, 0x8000_0000, 0, 1],
                amount: 1,
                claim: OUR_FP,
                sighash: None,
                // The lie: an amount with no transaction behind it.
                no_prev_tx: true,
                declared: None,
            },
        ],
        &[Pay {
            phrase: STRANGER,
            steps: RECEIVE,
            amount: 95_000_000,
            claim_ours: false,
        }],
        &mut buf,
    );
    assert_eq!(
        summary_of(&buf[..n]),
        Err(Refusal::UnverifiedAmount { input: 1 })
    );
}

#[test]
fn a_witness_utxo_that_disagrees_with_the_previous_transaction_does_not_move_the_fee() {
    // `Psbt::utxo` reads the amount out of the transaction whose txid it just checked, so
    // a different number in the witness UTXO changes nothing.
    let mut buf = vec![0u8; 16384];
    let n = build(
        &[Spend {
            phrase: OURS,
            steps: RECEIVE,
            amount: 100_000,
            claim: OUR_FP,
            sighash: None,
            no_prev_tx: false,
            declared: Some(1),
        }],
        &[Pay {
            phrase: STRANGER,
            steps: RECEIVE,
            amount: 99_000,
            claim_ours: false,
        }],
        &mut buf,
    );
    let sum = summary_of(&buf[..n]).unwrap();
    assert_eq!(sum.total_in, 100_000);
    assert_eq!(sum.fee, 1_000);
}

#[test]
fn a_signature_does_not_depend_on_another_inputs_declared_amount() {
    // Why the refusal above is load-bearing. BIP-143 binds the amount of the input being
    // *signed*, so a host that lies about the others still gets a usable signature for
    // the one it told the truth about: one session per input collects the whole set.
    // Nothing downstream stops it -- signing never looks at the other inputs.
    use crate::signer;

    const REAL: u64 = 100_000_000;
    let other: [u32; 5] = [84 | 0x8000_0000, 0x8000_0000, 0x8000_0000, 0, 1];
    let spend = |steps: [u32; 5], lie: bool| Spend {
        phrase: OURS,
        steps,
        amount: REAL,
        claim: OUR_FP,
        sighash: None,
        // No previous transaction, so `utxo` has nothing to check the claim against.
        no_prev_tx: lie,
        declared: lie.then_some(1),
    };
    let pays = |amount: u64| Pay {
        phrase: STRANGER,
        steps: RECEIVE,
        amount,
        claim_ours: false,
    };

    let (mut hb, mut s0b, mut s1b) = (vec![0u8; 16384], vec![0u8; 16384], vec![0u8; 16384]);
    let hn = build(
        &[spend(RECEIVE, false), spend(other, false)],
        &[pays(95_000_000)],
        &mut hb,
    );
    let s0n = build(
        &[spend(RECEIVE, false), spend(other, true)],
        &[pays(95_000_000)],
        &mut s0b,
    );
    let s1n = build(
        &[spend(RECEIVE, true), spend(other, false)],
        &[pays(95_000_000)],
        &mut s1b,
    );
    let honest = Psbt::parse(&hb[..hn]).unwrap();
    let s0 = Psbt::parse(&s0b[..s0n]).unwrap();
    let s1 = Psbt::parse(&s1b[..s1n]).unwrap();

    // One transaction, three descriptions of it.
    assert_eq!(honest.unsigned_tx().txid(), s0.unsigned_tx().txid());
    assert_eq!(honest.unsigned_tx().txid(), s1.unsigned_tx().txid());

    // The signatures a host would collect, one truthful input per session.
    let sign = |p: &Psbt<'_>, i: usize, steps: &[u32; 5]| -> Vec<u8> {
        let mut out = vec![0u8; 32768];
        let n = signer::sign_input(p, i, &master_of(OURS), OUR_FP, &mut out, &kw()).unwrap();
        let signed = Psbt::parse(&out[..n]).unwrap();
        signed
            .input(i)
            .unwrap()
            .partial_sig(&pubkey_at(OURS, steps))
            .unwrap()
            .to_vec()
    };
    assert_eq!(sign(&s0, 0, &RECEIVE), sign(&honest, 0, &RECEIVE));
    assert_eq!(sign(&s1, 1, &other), sign(&honest, 1, &other));

    // The only thing between a host and that set: each session is refused
    // before a person is ever shown a fee computed from the lie.
    assert_eq!(
        summary_of(&s0b[..s0n]),
        Err(Refusal::UnverifiedAmount { input: 1 })
    );
    assert_eq!(
        summary_of(&s1b[..s1n]),
        Err(Refusal::UnverifiedAmount { input: 0 })
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
    let master = master_of(OURS);
    assert!(is_change(
        &psbt,
        0,
        &script,
        &owner(&master, &[]),
        &accounts_of(&psbt, &master),
        &[],
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
    let master = master_of(OURS);
    assert!(!is_change(
        &psbt,
        0,
        &script,
        &owner(&master, &[]),
        &accounts_of(&psbt, &master),
        &[],
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

    let sum = summarise(&psbt, &owner(&master, &[]), &Policy::default(), &kw()).unwrap();
    assert_eq!(sum.change, 0);
    assert_eq!(sum.sending, 99_000);

    let mut dests = [Destination {
        index: 0,
        amount: 0,
        change: false,
        address: [0; address::MAX_ADDRESS_LEN],
        address_len: 0,
    }; 4];
    let found = destinations(
        &psbt,
        &owner(&master, &[]),
        Network::Mainnet,
        &accounts_of(&psbt, &master),
        &[],
        &mut dests,
        &kw(),
    );
    assert_eq!(found, 2);
    assert!(
        !dests[0].change,
        "a stuffed output was still folded into change"
    );
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

/// Change parked where no recovery will find it is not change.
///
/// Reported as issue #8. The key derives to the script, so the seed does own the output --
/// and that is all it proves. A host with the account xpub, which the exported descriptor
/// publishes, can put any non-hardened descendant on an output and call it change. The
/// damage is not only that nobody finds the coins: `sending` shrinks, so the fee cap is
/// measured against whatever payment is left rather than against the transaction.
#[test]
fn change_at_an_index_no_scan_reaches_is_shown_as_leaving() {
    let mut buf = vec![0u8; 1 << 16];
    let hidden = [84 | 0x8000_0000, 0x8000_0000, 0x8000_0000, 1, 1_900_000_000];
    let n = build(
        &[ours_spend(100_000_000)],
        &[
            Pay {
                phrase: OURS,
                steps: hidden,
                amount: 98_900_000,
                claim_ours: true,
            },
            Pay {
                phrase: STRANGER,
                steps: RECEIVE,
                amount: 1_000_000,
                claim_ours: false,
            },
        ],
        &mut buf,
    );
    let psbt = Psbt::parse(&buf[..n]).unwrap();
    let master = master_of(OURS);
    let summary = summarise(&psbt, &owner(&master, &[]), &Policy::default(), &kw());

    // Priced as what it is: 98.9M leaving, not 98.9M folded away as change. The fee is
    // then measured against the whole spend, which is what the cap is for.
    let summary = summary.expect("the transaction is otherwise fine");
    assert_eq!(summary.change, 0, "an unfindable index is not change");
    assert_eq!(summary.sending, 99_900_000);
    assert_eq!(summary.fee, 100_000);
}

/// Ordinary change still counts, at both branches and up to the bound.
#[test]
fn real_change_is_still_change() {
    for steps in [
        CHANGE,
        [84 | 0x8000_0000, 0x8000_0000, 0x8000_0000, 0, 7],
        [
            84 | 0x8000_0000,
            0x8000_0000,
            0x8000_0000,
            1,
            MAX_CHANGE_INDEX,
        ],
    ] {
        let mut buf = vec![0u8; 1 << 16];
        let n = build(
            &[ours_spend(100_000)],
            &[
                Pay {
                    phrase: OURS,
                    steps,
                    amount: 60_000,
                    claim_ours: true,
                },
                Pay {
                    phrase: STRANGER,
                    steps: RECEIVE,
                    amount: 39_000,
                    claim_ours: false,
                },
            ],
            &mut buf,
        );
        let psbt = Psbt::parse(&buf[..n]).unwrap();
        let summary = summarise(
            &psbt,
            &owner(&master_of(OURS), &[]),
            &Policy::default(),
            &kw(),
        )
        .expect("a plain spend with change");
        assert_eq!(summary.change, 60_000, "{steps:?} is this wallet's change");
        assert_eq!(summary.sending, 39_000);
    }
}

/// Change has to belong to an account these inputs actually spend from.
///
/// A different account of the same seed is the seed's money and is not this transaction's
/// change: the wallet that spends account 0 does not find account 5's coins, and folding
/// them into "change" hides the amount leaving this account.
#[test]
fn another_account_of_the_same_seed_is_not_this_spends_change() {
    let mut buf = vec![0u8; 1 << 16];
    let elsewhere = [84 | 0x8000_0000, 0x8000_0000, 5 | 0x8000_0000, 1, 0];
    let n = build(
        &[ours_spend(100_000)],
        &[Pay {
            phrase: OURS,
            steps: elsewhere,
            amount: 99_000,
            claim_ours: true,
        }],
        &mut buf,
    );
    let psbt = Psbt::parse(&buf[..n]).unwrap();
    let summary = summarise(
        &psbt,
        &owner(&master_of(OURS), &[]),
        &Policy::default(),
        &kw(),
    )
    .expect("the transaction is otherwise fine");
    assert_eq!(summary.change, 0, "account 5 is not account 0's change");
    assert_eq!(summary.sending, 99_000);
}

/// A branch that is neither receive nor change is not change either.
#[test]
fn a_branch_outside_receive_and_change_is_not_change() {
    let mut buf = vec![0u8; 1 << 16];
    let odd = [84 | 0x8000_0000, 0x8000_0000, 0x8000_0000, 9, 0];
    let n = build(
        &[ours_spend(100_000)],
        &[Pay {
            phrase: OURS,
            steps: odd,
            amount: 99_000,
            claim_ours: true,
        }],
        &mut buf,
    );
    let psbt = Psbt::parse(&buf[..n]).unwrap();
    let summary = summarise(
        &psbt,
        &owner(&master_of(OURS), &[]),
        &Policy::default(),
        &kw(),
    )
    .expect("the transaction is otherwise fine");
    assert_eq!(summary.change, 0, "branch 9 is not a change branch");
}

// -- multisig ---------------------------------------------------------------

/// A 2-of-2 P2WSH wallet of `OURS` and `STRANGER`, at `m/48h/0h/0h/2h`.
///
/// `sorted` picks `sortedmulti` or `multi`, which are two different wallets over the same
/// cosigners: BIP-67 ordering changes the script and so changes every address.
fn two_of_two(sorted: bool) -> crate::multisig::Multisig {
    use crate::bip32::ChildNumber;

    let mut keys: Vec<String> = Vec::new();
    for phrase in [OURS, STRANGER] {
        let master = master_of(phrase);
        let fp = master.fingerprint(&kw());
        let mut key = master;
        for step in [48u32, 0, 0, 2] {
            key = key
                .derive_child(ChildNumber::hardened(step).unwrap(), &kw())
                .unwrap();
        }
        keys.push(format!(
            "[{:02x}{:02x}{:02x}{:02x}/48h/0h/0h/2h]{}/0/*",
            fp[0],
            fp[1],
            fp[2],
            fp[3],
            key.to_extended_pub(&kw()).to_base58()
        ));
    }
    let func = if sorted { "sortedmulti" } else { "multi" };
    let body = format!("wsh({func}(2,{},{}))", keys[0], keys[1]);
    let sum = crate::descriptor::checksum(&body).unwrap();
    let text = format!("{body}#{}", core::str::from_utf8(&sum).unwrap());
    crate::multisig::parse(&text).unwrap()
}

/// Our key inside that wallet, at `branch`/`index`.
fn ms_key(branch: u32, index: u32) -> ([u8; 33], [u32; 6]) {
    use crate::bip32::ChildNumber;
    let mut key = master_of(OURS);
    let steps = [
        48 | 0x8000_0000,
        0x8000_0000,
        0x8000_0000,
        2 | 0x8000_0000,
        branch,
        index,
    ];
    for step in steps {
        let child = if step & 0x8000_0000 != 0 {
            ChildNumber::hardened(step & 0x7FFF_FFFF).unwrap()
        } else {
            ChildNumber::normal(step).unwrap()
        };
        key = key.derive_child(child, &kw()).unwrap();
    }
    (key.public_key(&kw()), steps)
}

/// A PSBT spending one output of the 2-of-2 wallet, paying a stranger.
///
/// With `change`, a second output pays back to the wallet's own change address, described
/// the way a host describes change: our derivation record at `.../1/0`.
fn multisig_spend(wallet: &crate::multisig::Multisig, change: bool, buf: &mut [u8]) -> usize {
    let mut spk = [0u8; 34];
    let spk_len = wallet.script_pubkey(0, 0, &mut spk).unwrap();
    let spk = &spk[..spk_len];
    let mut witness_script = [0u8; crate::multisig::MAX_SCRIPT];
    let ws_len = wallet.script(0, 0, &mut witness_script).unwrap();

    let prev_ins = [RawTxIn {
        txid: [0xC0; 32],
        vout: 0,
        script_sig: &[],
        sequence: 0xffff_ffff,
        witness: &[],
    }];
    let prev_outs = [RawTxOut {
        amount: 100_000,
        script: spk,
    }];
    let prev = RawTx {
        version: 2,
        inputs: &prev_ins,
        outputs: &prev_outs,
        locktime: 0,
    };
    let mut prev_raw = vec![0u8; prev.serialized_len()];
    let n = prev.serialize_to_slice(&mut prev_raw).unwrap();
    prev_raw.truncate(n);

    let ins = [RawTxIn {
        txid: prev.txid(),
        vout: 0,
        script_sig: &[],
        sequence: 0xffff_ffff,
        witness: &[],
    }];
    let pay = p2wpkh_script(&pubkey_at(STRANGER, &RECEIVE));
    let mut back = [0u8; 34];
    let back_len = wallet.script_pubkey(1, 0, &mut back).unwrap();
    let mut outs = vec![RawTxOut {
        amount: if change { 60_000 } else { 99_000 },
        script: &pay,
    }];
    if change {
        outs.push(RawTxOut {
            amount: 39_000,
            script: &back[..back_len],
        });
    }
    let tx = RawTx {
        version: 2,
        inputs: &ins,
        outputs: &outs,
        locktime: 0,
    };

    let mut a = vec![0u8; 8192];
    let mut b = vec![0u8; 8192];
    let mut n = Psbt::create_to_slice(&tx, &mut a).unwrap();
    macro_rules! step {
        ($f:expr) => {{
            let psbt = Psbt::parse(&a[..n]).unwrap();
            let m = $f(&psbt, &mut b).unwrap();
            a[..m].copy_from_slice(&b[..m]);
            n = m;
        }};
    }
    let (pk, steps) = ms_key(0, 0);
    step!(|p: &Psbt<'_>, out: &mut [u8]| p.set_witness_utxo(0, 100_000, spk, out));
    step!(|p: &Psbt<'_>, out: &mut [u8]| p.set_non_witness_utxo(0, &prev_raw, out));
    step!(|p: &Psbt<'_>, out: &mut [u8]| p.set_witness_script(0, &witness_script[..ws_len], out));
    step!(|p: &Psbt<'_>, out: &mut [u8]| p.add_input_bip32_derivation(0, &pk, OUR_FP, &steps, out));
    if change {
        let (pk, steps) = ms_key(1, 0);
        step!(|p: &Psbt<'_>, out: &mut [u8]| p
            .add_output_bip32_derivation(1, &pk, OUR_FP, &steps, out));
    }
    buf[..n].copy_from_slice(&a[..n]);
    n
}

/// A multisig input belonging to no registered wallet is refused, not signed.
///
/// The chain pins *which* script the coin is locked to -- the witness script has to hash
/// to the scriptPubKey -- but not whose wallet it is. Signing one this device was never
/// shown means trusting the host that the other cosigners are who it says, which is the
/// whole thing registration exists to stop.
#[test]
fn a_multisig_input_from_an_unregistered_wallet_is_refused() {
    let wallet = two_of_two(true);
    let mut buf = vec![0u8; 1 << 16];
    let n = multisig_spend(&wallet, false, &mut buf);
    let psbt = Psbt::parse(&buf[..n]).unwrap();

    assert_eq!(
        summarise(
            &psbt,
            &owner(&master_of(OURS), &[]),
            &Policy::default(),
            &kw()
        ),
        Err(Refusal::UnknownMultisig { input: 0 }),
        "an unknown multisig wallet was priced as if it were ours"
    );
}

/// The same transaction, once the wallet is registered.
#[test]
fn a_multisig_input_from_a_registered_wallet_is_read() {
    let wallet = two_of_two(true);
    let mut buf = vec![0u8; 1 << 16];
    let n = multisig_spend(&wallet, false, &mut buf);
    let psbt = Psbt::parse(&buf[..n]).unwrap();

    let summary = summarise(
        &psbt,
        &owner(&master_of(OURS), &[wallet]),
        &Policy::default(),
        &kw(),
    )
    .expect("a registered wallet's own spend");
    assert_eq!(summary.inputs, 1);
    assert_eq!(summary.ours, 1, "our key in the wallet was not recognised");
    assert_eq!(summary.total_in, 100_000);
    assert_eq!(summary.sending, 99_000);
    assert_eq!(summary.fee, 1_000);
}

/// A *different* registered wallet does not vouch for this input.
///
/// Registering one wallet must not make every multisig input acceptable: the script is
/// rebuilt from each wallet's own cosigners and has to equal the one the coin is locked
/// to, so a wallet with other keys simply does not match.
#[test]
fn another_registered_wallet_does_not_vouch_for_this_input() {
    let wallet = two_of_two(true);
    let mut buf = vec![0u8; 1 << 16];
    let n = multisig_spend(&wallet, false, &mut buf);
    let psbt = Psbt::parse(&buf[..n]).unwrap();

    // The same two cosigners, unsorted: a different wallet, with different addresses.
    let other = two_of_two(false);
    assert_eq!(
        summarise(
            &psbt,
            &owner(&master_of(OURS), &[other]),
            &Policy::default(),
            &kw()
        ),
        Err(Refusal::UnknownMultisig { input: 0 }),
        "a different wallet vouched for someone else's script"
    );
}

/// Change back to the registered wallet is change, and is not counted as leaving.
#[test]
fn change_to_a_registered_multisig_wallet_is_recognised() {
    let wallet = two_of_two(true);
    let mut buf = vec![0u8; 1 << 16];
    let n = multisig_spend(&wallet, true, &mut buf);
    let psbt = Psbt::parse(&buf[..n]).unwrap();
    let wallets = [wallet];

    let summary = summarise(
        &psbt,
        &owner(&master_of(OURS), &wallets),
        &Policy::default(),
        &kw(),
    )
    .expect("our own multisig spend");
    assert_eq!(summary.total_in, 100_000);
    assert_eq!(
        summary.change, 39_000,
        "the change output was read as leaving"
    );
    assert_eq!(summary.sending, 60_000);
    assert_eq!(summary.fee, 1_000);
}

/// A single-signature spend of ours paying the registered wallet's change address, with
/// the output described exactly as change would be: our derivation record at `.../1/0`.
fn single_sig_spend_to_multisig(wallet: &crate::multisig::Multisig, buf: &mut [u8]) -> usize {
    let pk = pubkey_at(OURS, &RECEIVE);
    let spk = script_of(AddressKind::P2wpkh, &pk);

    let prev_ins = [RawTxIn {
        txid: [0xD0; 32],
        vout: 0,
        script_sig: &[],
        sequence: 0xffff_ffff,
        witness: &[],
    }];
    let prev_outs = [RawTxOut {
        amount: 100_000,
        script: &spk,
    }];
    let prev = RawTx {
        version: 2,
        inputs: &prev_ins,
        outputs: &prev_outs,
        locktime: 0,
    };
    let mut prev_raw = vec![0u8; prev.serialized_len()];
    let n = prev.serialize_to_slice(&mut prev_raw).unwrap();
    prev_raw.truncate(n);

    let ins = [RawTxIn {
        txid: prev.txid(),
        vout: 0,
        script_sig: &[],
        sequence: 0xffff_ffff,
        witness: &[],
    }];
    let mut to_wallet = [0u8; 34];
    let to_len = wallet.script_pubkey(1, 0, &mut to_wallet).unwrap();
    let outs = [RawTxOut {
        amount: 99_000,
        script: &to_wallet[..to_len],
    }];
    let tx = RawTx {
        version: 2,
        inputs: &ins,
        outputs: &outs,
        locktime: 0,
    };

    let mut a = vec![0u8; 8192];
    let mut b = vec![0u8; 8192];
    let mut n = Psbt::create_to_slice(&tx, &mut a).unwrap();
    macro_rules! step {
        ($f:expr) => {{
            let psbt = Psbt::parse(&a[..n]).unwrap();
            let m = $f(&psbt, &mut b).unwrap();
            a[..m].copy_from_slice(&b[..m]);
            n = m;
        }};
    }
    step!(|p: &Psbt<'_>, out: &mut [u8]| p.set_witness_utxo(0, 100_000, &spk, out));
    step!(|p: &Psbt<'_>, out: &mut [u8]| p.set_non_witness_utxo(0, &prev_raw, out));
    step!(
        |p: &Psbt<'_>, out: &mut [u8]| p.add_input_bip32_derivation(0, &pk, OUR_FP, &RECEIVE, out)
    );
    let (ms_pk, ms_steps) = ms_key(1, 0);
    step!(|p: &Psbt<'_>, out: &mut [u8]| p
        .add_output_bip32_derivation(0, &ms_pk, OUR_FP, &ms_steps, out));
    buf[..n].copy_from_slice(&a[..n]);
    n
}

/// Paying a registered multisig wallet from a single-signature input is *sending* to it,
/// not change: the wallet is registered here and one of its keys is ours, but this spend
/// is not from it. Labelling it change would show a transfer of the whole balance into
/// the multisig as a fee-only transaction.
#[test]
fn a_single_sig_spend_to_a_registered_multisig_wallet_is_not_change() {
    let wallet = two_of_two(true);
    let mut buf = vec![0u8; 1 << 16];
    let n = single_sig_spend_to_multisig(&wallet, &mut buf);
    let psbt = Psbt::parse(&buf[..n]).unwrap();
    let master = master_of(OURS);
    let wallets = [wallet];
    let me = owner(&master, &wallets);

    let summary = summarise(&psbt, &me, &Policy::default(), &kw()).expect("our own spend");
    assert_eq!(
        summary.wallet_count, 0,
        "no input is from the multisig wallet"
    );
    assert_eq!(
        summary.change, 0,
        "a payment into another wallet was folded into change"
    );
    assert_eq!(summary.sending, 99_000);
    assert_eq!(summary.fee, 1_000);

    let mut dests = [Destination {
        index: 0,
        amount: 0,
        change: false,
        address: [0; address::MAX_ADDRESS_LEN],
        address_len: 0,
    }; 2];
    let found = destinations(
        &psbt,
        &me,
        Network::Mainnet,
        &summary.accounts[..summary.account_count],
        &summary.wallets[..summary.wallet_count],
        &mut dests,
        &kw(),
    );
    assert_eq!(found, 1);
    assert!(
        !dests[0].change,
        "the screen would have hidden the destination"
    );
}

/// Without the registration, that output is money leaving -- if the spend is shown at all.
///
/// This is the shape that matters: "looks like our multisig" is not a reason to subtract an
/// amount from what the owner is told they are sending. Here the input is refused first, so
/// the question never reaches the screen; [`is_change`] is asked directly to show that the
/// output alone does not vouch for itself either.
#[test]
fn an_unregistered_multisig_output_is_not_change() {
    let wallet = two_of_two(true);
    let mut buf = vec![0u8; 1 << 16];
    let n = multisig_spend(&wallet, true, &mut buf);
    let psbt = Psbt::parse(&buf[..n]).unwrap();

    let mut spk = [0u8; 34];
    let len = wallet.script_pubkey(1, 0, &mut spk).unwrap();
    let accounts = [Account {
        prefix: [48 | 0x8000_0000, 0x8000_0000, 0x8000_0000],
        kind: AddressKind::P2wpkh,
    }];
    assert!(
        !is_change(
            &psbt,
            1,
            &spk[..len],
            &owner(&master_of(OURS), &[]),
            &accounts,
            &[],
            &kw()
        ),
        "an unregistered wallet's output was subtracted from the amount sent"
    );
}

/// The whole path, end to end: reviewed, listed as signable, and signed.
///
/// A 2-of-2 is only half-signed by this device, which is the point -- what has to be right
/// here is that the digest commits to the *witness script*, not to a P2PKH template, so the
/// other cosigner's software accepts the signature and the two combine.
#[test]
fn a_registered_multisig_input_signs() {
    let wallet = two_of_two(true);
    let mut buf = vec![0u8; 1 << 16];
    let n = multisig_spend(&wallet, true, &mut buf);
    let psbt = Psbt::parse(&buf[..n]).unwrap();
    let master = master_of(OURS);
    let wallets = [wallet];
    let me = owner(&master, &wallets);

    summarise(&psbt, &me, &Policy::default(), &kw()).expect("reviewed");

    let mut ours = [0usize; 4];
    let signable = our_inputs(&psbt, &master, OUR_FP, &mut ours, &kw());
    assert_eq!(
        &ours[..signable],
        &[0],
        "our share of the wallet was missed"
    );
    assert!(!already_signed(&psbt, 0, &master, OUR_FP, &kw()));

    let mut out = vec![0u8; 1 << 16];
    let len = signer::sign_input(&psbt, 0, &master, OUR_FP, &mut out, &kw()).unwrap();
    let signed = Psbt::parse(&out[..len]).unwrap();

    let (pk, _) = ms_key(0, 0);
    let sig = signed
        .input(0)
        .unwrap()
        .partial_sig(&pk)
        .expect("no signature under our key in the wallet");
    assert_eq!(sig.last(), Some(&0x01), "not SIGHASH_ALL");
    assert!(already_signed(&signed, 0, &master, OUR_FP, &kw()));

    // Only our share: the wallet still needs the other cosigner.
    let (theirs, _) = {
        let mut key = master_of(STRANGER);
        let steps = [
            48 | 0x8000_0000,
            0x8000_0000,
            0x8000_0000,
            2 | 0x8000_0000,
            0,
            0,
        ];
        for step in steps {
            key = key.derive_child(ChildNumber(step), &kw()).unwrap();
        }
        (key.public_key(&kw()), steps)
    };
    assert!(
        signed.input(0).unwrap().partial_sig(&theirs).is_none(),
        "this device signed for a key it does not hold"
    );
}

/// A BIP-49 single-signature input: `sh(wpkh(...))`, whose scriptPubKey is a script hash
/// like a multisig one's. It was refused as an unregistered multisig wallet, which made
/// the account this device offers unspendable (issue #13).
#[test]
fn a_bip49_single_sig_input_is_not_an_unknown_multisig() {
    const NESTED: [u32; 5] = [49 | 0x8000_0000, 0x8000_0000, 0x8000_0000, 0, 0];
    let spend = Spend {
        steps: NESTED,
        ..ours_spend(100_000)
    };
    let mut buf = vec![0u8; 8192];
    let n = build_as(
        &[spend],
        &[AddressKind::P2shP2wpkh],
        &[Pay {
            phrase: STRANGER,
            steps: RECEIVE,
            amount: 99_000,
            claim_ours: false,
        }],
        &mut buf,
    );
    let summary = summary_of(&buf[..n]).expect("a BIP-49 input of ours must be spendable");
    assert_eq!(summary.sending, 99_000);
    assert_eq!(
        summary.accounts[..summary.account_count]
            .iter()
            .map(|a| a.kind)
            .collect::<Vec<_>>(),
        vec![AddressKind::P2shP2wpkh],
        "the account is recorded as nested segwit"
    );
}

/// `SIGHASH_ALL | SIGHASH_UNIFIED` is read, and the summary says the transaction opted
/// in -- it is valid only on a chain that implements that rule, which the screen says.
#[cfg(feature = "multichain")]
#[test]
fn an_opted_in_input_is_read_and_flagged() {
    let mut buf = vec![0u8; 8192];
    let n = build(
        &[Spend {
            sighash: Some(0x21),
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
    let summary = summary_of(&buf[..n]).expect("an opted-in input is signable");
    assert!(summary.opted_in);
    assert_eq!(summary.sending, 99_000);
}

/// The opt-in bit does not excuse the types this review cannot price: NONE leaves the
/// outputs unsigned whichever algorithm hashes them.
#[cfg(feature = "multichain")]
#[test]
fn the_opt_in_bit_does_not_admit_none_or_single() {
    for kind in [0x22, 0x23, 0xa1] {
        let mut buf = vec![0u8; 8192];
        let n = build(
            &[Spend {
                sighash: Some(kind),
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
        assert!(
            matches!(summary_of(&buf[..n]), Err(Refusal::Sighash { .. })),
            "{kind:#x} should be refused"
        );
    }
}

/// A plain transaction is not flagged, so the screen only says it where it is true.
#[cfg(feature = "multichain")]
#[test]
fn a_plain_transaction_is_not_flagged_as_opted_in() {
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
    assert!(!summary_of(&buf[..n]).unwrap().opted_in);
}
