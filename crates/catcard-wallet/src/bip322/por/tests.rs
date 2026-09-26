//! A proof of reserves built the way a host would build one, over the BIP-84 test
//! wallet: recognised, inspected, signed with the ordinary signer, finalised, and then
//! verified by the crate's own proof-of-funds verifier. And the shapes that must not be
//! taken for one.

use super::*;
use crate::KeyWork;
use crate::bip32::{ChildNumber, ExtendedPrivKey, Network};
use crate::bip39::{Mnemonic, SEED_LEN};
use crate::bip322::full::verify_pof;
use crate::bip322::{Error, Variant, message_hash};
use crate::signer;
use outscript::btcraw::{RawTx, RawTxIn, RawTxOut};

const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const FINGERPRINT: [u8; 4] = [0x73, 0xc5, 0xda, 0x0a];
const H: u32 = 0x8000_0000;
const MESSAGE: &[u8] = b"CatCard holds these coins on 2026-09-26";

fn master() -> ExtendedPrivKey {
    let kw = KeyWork::host();
    let m = Mnemonic::parse(PHRASE, &kw).unwrap();
    let mut seed = [0u8; SEED_LEN];
    m.to_seed("", &mut seed, &kw).unwrap();
    ExtendedPrivKey::from_seed(&seed, Network::Mainnet, &kw).unwrap()
}

/// The P2WPKH script of `m/84h/0h/0h/0/{index}`, and the path.
fn receive(index: u32) -> ([u8; 22], [u32; 5], [u8; 33]) {
    let kw = KeyWork::host();
    let path = [84 | H, H, H, 0, index];
    let mut here = master();
    for &s in &path {
        here = here.derive_child(ChildNumber(s), &kw).unwrap();
    }
    let pk = here.public_key(&kw);
    let mut spk = [0u8; 22];
    spk[..2].copy_from_slice(&[0x00, 0x14]);
    spk[2..].copy_from_slice(&crate::bip32::hash160(&pk));
    (spk, path, pk)
}

/// The unsigned PSBT of a proof over `utxos` P2WPKH outputs of the wallet, with the
/// challenge address at index 0; `outputs` extra real outputs turn it into a spend.
fn build(message: &[u8], utxos: u32, extra_outputs: usize, out: &mut [u8]) -> usize {
    let (challenge, path0, pk0) = receive(0);
    let mut to_spend = [0u8; 128];
    let n = write_to_spend(message, &challenge, &mut to_spend).unwrap();
    let to_spend = &to_spend[..n];
    let (hash, script) = parse_to_spend(to_spend).unwrap();
    assert_eq!(hash, message_hash(message));
    assert_eq!(script, &challenge[..]);
    let prev = crate::bip322::to_spend_txid(message, &challenge);

    let mut inputs = vec![RawTxIn {
        txid: prev,
        vout: 0,
        script_sig: &[],
        sequence: 0,
        witness: &[],
    }];
    for i in 0..utxos {
        inputs.push(RawTxIn {
            txid: [0x40 + i as u8; 32],
            vout: i,
            script_sig: &[],
            sequence: 0xffff_ffff,
            witness: &[],
        });
    }
    let pay = [
        0x00, 0x14, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    ];
    let mut outputs = vec![RawTxOut {
        amount: 0,
        script: &OP_RETURN,
    }];
    for _ in 0..extra_outputs {
        outputs.push(RawTxOut {
            amount: 1_000,
            script: &pay,
        });
    }
    let tx = RawTx {
        version: 2,
        inputs: &inputs,
        outputs: &outputs,
        locktime: 0,
    };
    let mut a = vec![0u8; 8192];
    let mut b = vec![0u8; 8192];
    let mut n = Psbt::create_to_slice(&tx, &mut a).unwrap();
    // Input 0: `to_spend` itself, and our key.
    n = Psbt::parse(&a[..n])
        .unwrap()
        .set_non_witness_utxo(0, to_spend, &mut b)
        .unwrap();
    n = Psbt::parse(&b[..n])
        .unwrap()
        .add_input_bip32_derivation(0, &pk0, FINGERPRINT, &path0, &mut a)
        .unwrap();
    // The real outputs, each with its amount and our key.
    for i in 0..utxos {
        let (spk, path, pk) = receive(i + 1);
        n = Psbt::parse(&a[..n])
            .unwrap()
            .set_witness_utxo(1 + i as usize, 100_000 * u64::from(i + 1), &spk, &mut b)
            .unwrap();
        n = Psbt::parse(&b[..n])
            .unwrap()
            .add_input_bip32_derivation(1 + i as usize, &pk, FINGERPRINT, &path, &mut a)
            .unwrap();
    }
    out[..n].copy_from_slice(&a[..n]);
    n
}

#[test]
fn a_proof_over_two_of_our_coins_is_recognised_reviewed_signed_and_verified() {
    let kw = KeyWork::host();
    let mut buf = vec![0u8; 8192];
    let n = build(MESSAGE, 2, 0, &mut buf);
    let psbt = Psbt::parse(&buf[..n]).unwrap();

    assert!(is_proof(&psbt));
    let proof = inspect(&psbt).unwrap();
    assert_eq!(proof.utxos, 2);
    assert_eq!(proof.inputs, 3);
    assert_eq!(proof.total, 100_000 + 200_000);
    assert_eq!(proof.message_hash, Some(message_hash(MESSAGE)));
    assert_eq!(proof.challenge(), &receive(0).0[..]);
    assert_eq!(confirm_message(&proof, MESSAGE), Ok(()));
    assert_eq!(
        confirm_message(&proof, b"some other message"),
        Err(Refusal::WrongMessage)
    );

    // Signed input by input with the ordinary signer, then finalised: what the device
    // does, minus the screens.
    let master = master();
    let mut from = buf[..n].to_vec();
    let mut into = vec![0u8; 8192];
    for index in 0..3 {
        let psbt = Psbt::parse(&from).unwrap();
        let len = signer::sign_input(&psbt, index, &master, FINGERPRINT, &mut into, &kw).unwrap();
        from = into[..len].to_vec();
    }
    let psbt = Psbt::parse(&from).unwrap();
    let (len, count) = psbt.finalize_to_slice(&mut into).unwrap();
    assert_eq!(count, 3);
    let done = &into[..len];
    assert!(Psbt::parse(done).unwrap().is_finalized());

    // The finalised PSBT is the proof, and the verifier reads out what it proves.
    assert_eq!(
        verify_pof(MESSAGE, proof.challenge(), done),
        Ok(Variant::Proof {
            utxos: 2,
            total: 300_000
        })
    );
    assert_eq!(
        verify_pof(b"another message", proof.challenge(), done),
        Err(Error::Invalid)
    );
    // The unsigned one is not a proof yet.
    assert_eq!(
        verify_pof(MESSAGE, proof.challenge(), &buf[..n]),
        Err(Error::NotAProof)
    );
    // And the finalised one is not something to sign again.
    assert_eq!(
        inspect(&Psbt::parse(done).unwrap()),
        Err(Refusal::AlreadyFinal)
    );
}

#[test]
fn a_transaction_that_pays_anyone_is_not_a_proof() {
    let mut buf = vec![0u8; 8192];
    let n = build(MESSAGE, 2, 1, &mut buf);
    let psbt = Psbt::parse(&buf[..n]).unwrap();
    assert!(!is_proof(&psbt));
    assert_eq!(inspect(&psbt), Err(Refusal::NotAProof));
}

#[test]
fn a_proof_with_no_real_output_is_still_a_proof_of_the_key() {
    let mut buf = vec![0u8; 8192];
    let n = build(MESSAGE, 0, 0, &mut buf);
    let psbt = Psbt::parse(&buf[..n]).unwrap();
    assert!(is_proof(&psbt));
    let proof = inspect(&psbt).unwrap();
    assert_eq!(proof.utxos, 0);
    assert_eq!(proof.total, 0);
}

/// `ANYONECANPAY` on a proof's input would let the host drop input 0 and broadcast the
/// rest as a real transaction paying everything to fees. Refused before the message is
/// even asked.
#[test]
fn a_sighash_other_than_all_is_refused_whatever_the_policy() {
    let mut buf = vec![0u8; 8192];
    let n = build(MESSAGE, 2, 0, &mut buf);
    let mut out = vec![0u8; 8192];
    for kind in [0x81u32, 0x02, 0x83, 0x00] {
        let m = Psbt::parse(&buf[..n])
            .unwrap()
            .set_sighash_type(1, kind, &mut out)
            .unwrap();
        let psbt = Psbt::parse(&out[..m]).unwrap();
        assert!(is_proof(&psbt));
        assert_eq!(inspect(&psbt), Err(Refusal::Sighash { input: 1, kind }));
    }
    // An explicit `SIGHASH_ALL` is fine.
    let m = Psbt::parse(&buf[..n])
        .unwrap()
        .set_sighash_type(1, 0x01, &mut out)
        .unwrap();
    assert!(inspect(&Psbt::parse(&out[..m]).unwrap()).is_ok());
}

/// A host that writes a real outpoint where `to_spend` should be is asking for a burn.
/// The outpoint is recomputed from the message, so the substitution is caught.
#[test]
fn an_input_zero_that_is_not_to_spend_for_the_message_is_refused() {
    let mut buf = vec![0u8; 8192];
    let n = build(b"the message the host claims", 2, 0, &mut buf);
    let psbt = Psbt::parse(&buf[..n]).unwrap();
    let proof = inspect(&psbt).unwrap();
    // The owner types the message they were told; the PSBT was built for it, so the
    // carried `to_spend` agrees -- and so does the outpoint.
    assert_eq!(
        confirm_message(&proof, b"the message the host claims"),
        Ok(())
    );
    // But a `to_spend` whose hash is right and whose outpoint is not cannot pass: the
    // outpoint is what the signatures commit to.
    let mut forged = proof;
    forged.to_spend_txid = [0x99; 32];
    assert_eq!(
        confirm_message(&forged, b"the message the host claims"),
        Err(Refusal::WrongMessage)
    );
}

#[test]
fn a_carried_to_spend_that_is_not_one_is_refused() {
    let mut buf = vec![0u8; 8192];
    let n = build(MESSAGE, 1, 0, &mut buf);
    // Replace input 0's previous transaction with one of version 1: a real-looking
    // transaction, not `to_spend`. `utxo` still finds output 0 in it (the txid no longer
    // matches the outpoint, so it is refused there first).
    let mut prev = [0u8; 128];
    let m = write_to_spend(MESSAGE, &receive(0).0, &mut prev).unwrap();
    prev[0] = 1;
    let mut out = vec![0u8; 8192];
    let k = Psbt::parse(&buf[..n])
        .unwrap()
        .set_non_witness_utxo(0, &prev[..m], &mut out)
        .unwrap();
    let psbt = Psbt::parse(&out[..k]).unwrap();
    assert!(matches!(
        inspect(&psbt),
        Err(Refusal::NotAProof | Refusal::BadToSpend | Refusal::MissingUtxo { input: 0 })
    ));
}

#[test]
fn to_spend_is_read_back_exactly_and_nothing_looser() {
    let (spk, _, _) = receive(0);
    let mut buf = [0u8; 128];
    let n = write_to_spend(MESSAGE, &spk, &mut buf).unwrap();
    let (hash, script) = parse_to_spend(&buf[..n]).unwrap();
    assert_eq!(hash, message_hash(MESSAGE));
    assert_eq!(script, &spk[..]);
    // Any single change to the fixed fields is not a `to_spend`.
    for (at, name) in [
        (0, "version"),
        (4 + 1 + 36, "sequence"),
        (n - 4, "locktime"),
    ] {
        let mut bad = buf;
        bad[at] ^= 1;
        assert!(parse_to_spend(&bad[..n]).is_none(), "{name}");
    }
    let mut bad = buf;
    bad[4 + 1 + 32] ^= 1; // vout no longer 0xFFFFFFFF
    assert!(parse_to_spend(&bad[..n]).is_none());
    assert!(parse_to_spend(&buf[..n - 1]).is_none());
}
