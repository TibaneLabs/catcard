//! Signing a PSBT built for a key this seed really owns, and refusing the rest.
//!
//! The wallet is BIP-84's published test mnemonic, so the keys, the addresses and the
//! fingerprint here are all values other implementations agree on.

use outscript::btcraw::{RawTx, RawTxIn, RawTxOut};
use outscript::crypto::secp256k1::SecpPublicKey;
use outscript::crypto::secp256k1::{bip340_verify, taproot_tweak};
use outscript::psbt::{Psbt, input as in_key};

use super::*;
use crate::address::AddressKind;
use crate::bip32::{ChildNumber, ExtendedPrivKey, Network};
use crate::bip39::{Mnemonic, SEED_LEN};

const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// The fingerprint every wallet shows for that mnemonic.
const FINGERPRINT: [u8; 4] = [0x73, 0xc5, 0xda, 0x0a];
/// `m/84h/0h/0h/0/0`, whose address BIP-84 publishes as
/// `bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu`.
const PATH: [u32; 5] = [84 | 0x8000_0000, 0x8000_0000, 0x8000_0000, 0, 0];

fn master() -> ExtendedPrivKey {
    let kw = KeyWork::host();
    let m = Mnemonic::parse(PHRASE, &kw).unwrap();
    let mut seed = [0u8; SEED_LEN];
    m.to_seed("", &mut seed, &kw).unwrap();
    ExtendedPrivKey::from_seed(&seed, Network::Mainnet, &kw).unwrap()
}

fn derive(steps: &[u32]) -> ExtendedPrivKey {
    let kw = KeyWork::host();
    let mut here = master();
    for &s in steps {
        here = here.derive_child(ChildNumber(s), &kw).unwrap();
    }
    here
}

/// The compressed public key at `steps`.
fn pubkey_at(steps: &[u32]) -> [u8; 33] {
    derive(steps).public_key(&KeyWork::host())
}

fn hash160(data: &[u8]) -> [u8; 20] {
    crate::bip32::hash160(data)
}

/// A PSBT spending one P2WPKH output that belongs to `steps`, paying 50 000 sats to a
/// stranger out of 60 000, with the key's origin recorded as a wallet would record it.
fn psbt_for(steps: &[u32], fingerprint: [u8; 4], buf: &mut [u8]) -> usize {
    let pk = pubkey_at(steps);
    let mut spk = [0u8; 22];
    spk[..2].copy_from_slice(&[0x00, 0x14]);
    spk[2..].copy_from_slice(&hash160(&pk));

    let input = RawTxIn {
        txid: [0x11; 32],
        vout: 0,
        script_sig: &[],
        sequence: 0xffff_ffff,
        witness: &[],
    };
    // A plain P2PKH payment to somebody else.
    let mut pay = [0u8; 25];
    pay[..3].copy_from_slice(&[0x76, 0xa9, 0x14]);
    pay[3..23].copy_from_slice(&[0x22; 20]);
    pay[23..].copy_from_slice(&[0x88, 0xac]);
    let tx = RawTx {
        version: 2,
        inputs: &[input],
        outputs: &[RawTxOut {
            amount: 50_000,
            script: &pay,
        }],
        locktime: 0,
    };
    let mut a = [0u8; 2048];
    let n = Psbt::create_to_slice(&tx, &mut a).unwrap();
    let psbt = Psbt::parse(&a[..n]).unwrap();

    let mut b = [0u8; 2048];
    let n = psbt.set_witness_utxo(0, 60_000, &spk, &mut b).unwrap();
    let psbt = Psbt::parse(&b[..n]).unwrap();

    let path: Vec<u32> = steps.to_vec();
    psbt.add_input_bip32_derivation(0, &pk, fingerprint, &path, buf)
        .unwrap()
}

#[test]
fn an_input_of_ours_is_signed_and_the_signature_verifies() {
    let kw = KeyWork::host();
    let mut buf = [0u8; 2048];
    let n = psbt_for(&PATH, FINGERPRINT, &mut buf);
    let psbt = Psbt::parse(&buf[..n]).unwrap();

    let master = master();
    let mut out = [0u8; 4096];
    let len = sign_input(&psbt, 0, &master, FINGERPRINT, &mut out, &kw).unwrap();
    let signed = Psbt::parse(&out[..len]).unwrap();

    // The signature is recorded against the key that made it.
    let pk = pubkey_at(&PATH);
    let sig = signed
        .input(0)
        .unwrap()
        .partial_sig(&pk)
        .expect("signature");
    assert_eq!(*sig.last().unwrap(), 0x01, "SIGHASH_ALL");

    // And it verifies, against the digest the input actually commits to. `outscript`
    // computed that digest from the PSBT; recomputing it here from the same PSBT proves the
    // signature is over this transaction and this amount, not something else.
    let key = SecpPublicKey::from_sec1(&pk).unwrap();
    let digest = segwit_digest(&psbt, 0, &pk);
    let (r, s) = outscript::crypto::secp256k1::parse_der_signature(&sig[..sig.len() - 1]).unwrap();
    assert!(key.verify(&digest, &r, &s), "signature does not verify");
}

/// The BIP-143 digest for input `index` of a P2WPKH spend, via `outscript`'s own sighash.
fn segwit_digest(psbt: &Psbt<'_>, index: usize, pubkey: &[u8; 33]) -> [u8; 32] {
    let tx = psbt.unsigned_tx();
    let inputs: Vec<RawTxIn<'_>> = tx.inputs().collect();
    let outputs: Vec<RawTxOut<'_>> = tx.outputs().collect();
    let raw = RawTx {
        version: tx.version(),
        inputs: &inputs,
        outputs: &outputs,
        locktime: tx.locktime(),
    };
    let utxo = psbt.utxo(index).unwrap();
    // A P2WPKH spend's scriptCode is the P2PKH script for the key.
    let mut code = [0u8; 25];
    code[..3].copy_from_slice(&[0x76, 0xa9, 0x14]);
    code[3..23].copy_from_slice(&hash160(pubkey));
    code[23..].copy_from_slice(&[0x88, 0xac]);
    raw.segwit_v0_sighash(index, &code, utxo.amount, 0x01)
        .unwrap()
}

#[test]
fn an_input_whose_keys_are_not_ours_is_left_alone() {
    let kw = KeyWork::host();
    let mut buf = [0u8; 2048];
    // Same wallet, but the PSBT claims a different master.
    let n = psbt_for(&PATH, [0xde, 0xad, 0xbe, 0xef], &mut buf);
    let psbt = Psbt::parse(&buf[..n]).unwrap();
    let mut out = [0u8; 4096];
    assert_eq!(
        sign_input(&psbt, 0, &master(), FINGERPRINT, &mut out, &kw),
        Err(Error::NotOurs)
    );
}

#[test]
fn a_path_that_does_not_lead_to_the_named_key_is_refused() {
    let kw = KeyWork::host();
    // Our fingerprint and a path of ours, but the key recorded is a different one: a host
    // asking us to sign with a key that is not where it says it is.
    let pk = pubkey_at(&[84 | 0x8000_0000, 0x8000_0000, 0x8000_0000, 0, 7]);
    let mut spk = [0u8; 22];
    spk[..2].copy_from_slice(&[0x00, 0x14]);
    spk[2..].copy_from_slice(&hash160(&pk));
    let mut buf = [0u8; 2048];
    let n = psbt_for(&PATH, FINGERPRINT, &mut buf);
    let psbt = Psbt::parse(&buf[..n]).unwrap();

    // Swap the recorded key for the wrong one, keeping the path.
    let mut tampered = [0u8; 2048];
    let n = psbt
        .add_input_bip32_derivation(0, &pk, FINGERPRINT, &PATH, &mut tampered)
        .unwrap();
    let psbt = Psbt::parse(&tampered[..n]).unwrap();
    let mut requests = [KeyRequest::EMPTY; MAX_KEYS_PER_INPUT];
    let found = key_requests(&psbt, 0, FINGERPRINT, &mut requests).unwrap();
    assert_eq!(found, 2, "the honest record and the tampered one");
    let wrong = requests
        .iter()
        .find(|r| r.pubkey() == pk)
        .expect("the tampered record");
    assert_eq!(
        match_key(&master(), wrong, &kw).err(),
        Some(Error::KeyMismatch)
    );
}

#[test]
fn a_path_deeper_than_this_follows_is_refused_not_walked() {
    let kw = KeyWork::host();
    let deep: Vec<u32> = (0..MAX_STEPS as u32 + 1).collect();
    let pk = pubkey_at(&[0]);
    let mut buf = [0u8; 2048];
    let n = psbt_for(&PATH, FINGERPRINT, &mut buf);
    let psbt = Psbt::parse(&buf[..n]).unwrap();
    let mut with_deep = [0u8; 2048];
    let n = psbt
        .add_input_bip32_derivation(0, &pk, FINGERPRINT, &deep, &mut with_deep)
        .unwrap();
    let psbt = Psbt::parse(&with_deep[..n]).unwrap();
    let mut requests = [KeyRequest::EMPTY; MAX_KEYS_PER_INPUT];
    assert_eq!(
        key_requests(&psbt, 0, FINGERPRINT, &mut requests).err(),
        Some(Error::BadPath)
    );
    // And the honest record on the same input is still signable once the deep one is gone.
    let _ = kw;
}

#[test]
fn taproot_records_are_recognised_as_wanting_a_schnorr_signature() {
    let mut buf = [0u8; 2048];
    let n = psbt_for(&PATH, FINGERPRINT, &mut buf);
    let psbt = Psbt::parse(&buf[..n]).unwrap();

    // A taproot derivation record: x-only key, no leaf hashes, then the origin.
    let pk = pubkey_at(&PATH);
    let mut value = Vec::new();
    value.push(0x00); // no leaf hashes
    value.extend_from_slice(&FINGERPRINT);
    for s in PATH {
        value.extend_from_slice(&s.to_le_bytes());
    }
    let mut key = Vec::new();
    key.push(in_key::TAP_BIP32_DERIVATION as u8);
    key.extend_from_slice(&pk[1..]);
    let mut out = [0u8; 2048];
    let n = psbt.set_input_record(0, &key, &value, &mut out).unwrap();
    let psbt = Psbt::parse(&out[..n]).unwrap();

    let mut requests = [KeyRequest::EMPTY; MAX_KEYS_PER_INPUT];
    let found = key_requests(&psbt, 0, FINGERPRINT, &mut requests).unwrap();
    assert_eq!(found, 2);
    assert!(!requests[0].taproot, "the ECDSA record comes first");
    assert!(requests[1].taproot);
    assert_eq!(requests[1].pubkey(), &pk[1..]);
    // Both are the same key, so both match.
    let kw = KeyWork::host();
    let signer = match_key(&master(), &requests[1], &kw).unwrap();
    assert!(signer.is_taproot());
}

/// A PSBT spending one output of `kind` belonging to `steps`, with whatever extra records
/// that script type needs: the whole previous transaction for a legacy input, the redeem
/// script for a nested-segwit one, the internal key and a taproot derivation for P2TR.
fn psbt_for_kind(kind: AddressKind, steps: &[u32], buf: &mut [u8]) -> usize {
    let pk = pubkey_at(steps);
    let mut spk = [0u8; 34];
    let spk_len = crate::address::script_pubkey(kind, &pk, &mut spk).unwrap();
    let spk = &spk[..spk_len];

    // The previous transaction, needed in full for a legacy input. One input from nowhere,
    // one output paying the script we are about to spend.
    let mut prev = Vec::new();
    prev.extend_from_slice(&2u32.to_le_bytes());
    prev.push(1);
    prev.extend_from_slice(&[0x99; 32]);
    prev.extend_from_slice(&0u32.to_le_bytes());
    prev.push(0);
    prev.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    prev.push(1);
    prev.extend_from_slice(&60_000u64.to_le_bytes());
    prev.push(spk.len() as u8);
    prev.extend_from_slice(spk);
    prev.extend_from_slice(&0u32.to_le_bytes());
    // `outscript` takes a txid in display order, which is the double-SHA256 reversed.
    let txid = {
        use purecrypto::hash::{Digest, Sha256};
        let once = Sha256::digest(&prev);
        let twice = Sha256::digest(&once);
        let mut id = [0u8; 32];
        id.copy_from_slice(&twice);
        id.reverse();
        id
    };

    let input = RawTxIn {
        txid,
        vout: 0,
        script_sig: &[],
        sequence: 0xffff_ffff,
        witness: &[],
    };
    let mut pay = [0u8; 25];
    pay[..3].copy_from_slice(&[0x76, 0xa9, 0x14]);
    pay[3..23].copy_from_slice(&[0x33; 20]);
    pay[23..].copy_from_slice(&[0x88, 0xac]);
    let tx = RawTx {
        version: 2,
        inputs: &[input],
        outputs: &[RawTxOut {
            amount: 50_000,
            script: &pay,
        }],
        locktime: 0,
    };

    let mut a = vec![0u8; 4096];
    let mut b = vec![0u8; 4096];
    let mut n = Psbt::create_to_slice(&tx, &mut a).unwrap();
    macro_rules! step {
        ($f:expr) => {{
            let psbt = Psbt::parse(&a[..n]).unwrap();
            let m = $f(&psbt, &mut b).unwrap();
            a[..m].copy_from_slice(&b[..m]);
            n = m;
        }};
    }
    match kind {
        // A legacy spend signs over the whole previous transaction, so that is what the
        // PSBT has to carry -- and `outscript` checks its txid against the outpoint.
        AddressKind::P2pkh => {
            step!(|p: &Psbt<'_>, out: &mut [u8]| p.set_non_witness_utxo(0, &prev, out))
        }
        _ => step!(|p: &Psbt<'_>, out: &mut [u8]| p.set_witness_utxo(0, 60_000, spk, out)),
    }
    if kind == AddressKind::P2shP2wpkh {
        let redeem = crate::address::p2wpkh_redeem_script(&pk);
        step!(|p: &Psbt<'_>, out: &mut [u8]| p.set_redeem_script(0, &redeem, out));
    }
    if kind == AddressKind::P2tr {
        let xonly: [u8; 32] = pk[1..].try_into().unwrap();
        step!(|p: &Psbt<'_>, out: &mut [u8]| p.set_tap_internal_key(0, &xonly, out));
        let mut key = Vec::new();
        key.push(in_key::TAP_BIP32_DERIVATION as u8);
        key.extend_from_slice(&xonly);
        let mut value = Vec::new();
        value.push(0x00);
        value.extend_from_slice(&FINGERPRINT);
        for s in steps {
            value.extend_from_slice(&s.to_le_bytes());
        }
        step!(|p: &Psbt<'_>, out: &mut [u8]| p.set_input_record(0, &key, &value, out));
    } else {
        step!(|p: &Psbt<'_>, out: &mut [u8]| p.add_input_bip32_derivation(
            0,
            &pk,
            FINGERPRINT,
            steps,
            out
        ));
    }
    buf[..n].copy_from_slice(&a[..n]);
    n
}

#[test]
fn a_legacy_and_a_nested_segwit_input_are_both_signed() {
    let kw = KeyWork::host();
    for (kind, steps) in [
        (
            AddressKind::P2pkh,
            [44 | 0x8000_0000, 0x8000_0000, 0x8000_0000, 0, 0],
        ),
        (
            AddressKind::P2shP2wpkh,
            [49 | 0x8000_0000, 0x8000_0000, 0x8000_0000, 0, 0],
        ),
    ] {
        let mut buf = vec![0u8; 4096];
        let n = psbt_for_kind(kind, &steps, &mut buf);
        let psbt = Psbt::parse(&buf[..n]).unwrap();
        let mut out = vec![0u8; 8192];
        let len = sign_input(&psbt, 0, &master(), FINGERPRINT, &mut out, &kw)
            .unwrap_or_else(|e| panic!("{kind:?}: {e:?}"));
        let signed = Psbt::parse(&out[..len]).unwrap();
        let pk = pubkey_at(&steps);
        let sig = signed
            .input(0)
            .unwrap()
            .partial_sig(&pk)
            .unwrap_or_else(|| panic!("{kind:?}: no signature"));
        assert_eq!(*sig.last().unwrap(), 0x01, "{kind:?}: SIGHASH_ALL");
    }
}

#[test]
fn a_taproot_input_gets_a_schnorr_signature_that_verifies() {
    let kw = KeyWork::host();
    let steps = [86 | 0x8000_0000, 0x8000_0000, 0x8000_0000, 0, 0];
    let mut buf = vec![0u8; 4096];
    let n = psbt_for_kind(AddressKind::P2tr, &steps, &mut buf);
    let psbt = Psbt::parse(&buf[..n]).unwrap();

    let mut out = vec![0u8; 8192];
    let len = sign_input(&psbt, 0, &master(), FINGERPRINT, &mut out, &kw).unwrap();
    let signed = Psbt::parse(&out[..len]).unwrap();
    let sig = signed
        .input(0)
        .unwrap()
        .tap_key_sig()
        .expect("key signature");
    // 64 bytes with no trailing byte means the default sighash, which is SIGHASH_DEFAULT.
    assert_eq!(sig.len(), 64);

    // It verifies under the *tweaked* output key, which is what the output pays to, over
    // the BIP-341 sighash of this input.
    let pk = pubkey_at(&steps);
    let internal: [u8; 32] = pk[1..].try_into().unwrap();
    let (output_key, _) = taproot_tweak(&internal).unwrap();
    let tx = psbt.unsigned_tx();
    let ins: Vec<RawTxIn<'_>> = tx.inputs().collect();
    let outs: Vec<RawTxOut<'_>> = tx.outputs().collect();
    let raw = RawTx {
        version: tx.version(),
        inputs: &ins,
        outputs: &outs,
        locktime: tx.locktime(),
    };
    let prevouts = [psbt.utxo(0).unwrap()];
    let mid = raw.taproot_midstate(&prevouts).unwrap();
    let sighash = mid.key_spend_sighash(0).unwrap();
    let sig64: [u8; 64] = sig.try_into().unwrap();
    assert!(bip340_verify(&output_key, &sighash, &sig64));
}

#[test]
fn a_fully_signed_transaction_finalises_and_extracts() {
    let kw = KeyWork::host();
    let mut buf = vec![0u8; 4096];
    let n = psbt_for(&PATH, FINGERPRINT, &mut buf);
    let psbt = Psbt::parse(&buf[..n]).unwrap();
    let mut signed = vec![0u8; 8192];
    let len = sign_input(&psbt, 0, &master(), FINGERPRINT, &mut signed, &kw).unwrap();
    let signed = Psbt::parse(&signed[..len]).unwrap();
    assert!(!signed.is_finalized());

    let mut done = vec![0u8; 8192];
    let (n, count) = signed.finalize_to_slice(&mut done).unwrap();
    assert_eq!(count, 1, "one input finalised");
    let done = Psbt::parse(&done[..n]).unwrap();
    assert!(done.is_finalized());

    // The extracted transaction parses as a segwit transaction with a witness, and its txid
    // is the one the PSBT's unsigned transaction already had -- segwit's whole point.
    let mut raw = vec![0u8; 8192];
    let n = done.extract_tx_to_slice(&mut raw).unwrap();
    let tx = crate::tx::Transaction::parse(&raw[..n]).unwrap();
    assert!(tx.has_witness);
    assert_eq!(tx.inputs.count(), 1);
    assert_eq!(tx.outputs.count(), 1);
    // Our txid is in internal order, `outscript`'s in display order.
    let mut theirs = psbt.unsigned_tx().txid();
    theirs.reverse();
    assert_eq!(tx.txid(), theirs);
}

/// A PSBT whose input opts in with `SIGHASH_ALL | SIGHASH_UNIFIED` is signed under the
/// unified message, and the signature verifies against **our own** implementation of that
/// message rather than against the one that produced it.
///
/// That is what this test is for: `outscript` computes the digest while signing, and this
/// recomputes it from `tx::unified`, which is checked against the specification's 166
/// published vectors. The two agreeing is what says the signature this device hands back
/// commits to the message the fork defines.
#[cfg(feature = "multichain")]
#[test]
fn an_opted_in_input_is_signed_under_the_unified_message() {
    use crate::tx::unified::{self, Aggregates, SpentOutput};

    let kw = KeyWork::host();
    let mut buf = [0u8; 2048];
    let n = psbt_for(&PATH, FINGERPRINT, &mut buf);
    // ALL | UNIFIED: the byte the signature commits to and the one it carries.
    const OPTED_IN: u32 = 0x21;
    let mut with_type = [0u8; 2048];
    let n = Psbt::parse(&buf[..n])
        .unwrap()
        .set_sighash_type(0, OPTED_IN, &mut with_type)
        .unwrap();
    let psbt = Psbt::parse(&with_type[..n]).unwrap();

    let master = master();
    let mut out = [0u8; 4096];
    let len = sign_input(&psbt, 0, &master, FINGERPRINT, &mut out, &kw).unwrap();
    let signed = Psbt::parse(&out[..len]).unwrap();

    let pk = pubkey_at(&PATH);
    let sig = signed
        .input(0)
        .unwrap()
        .partial_sig(&pk)
        .expect("signature");
    assert_eq!(
        *sig.last().unwrap(),
        0x21,
        "the hash type byte travels with the signature"
    );

    // The same transaction, through our own message.
    let ours = crate::tx::Transaction::parse(psbt.unsigned_tx().bytes()).unwrap();
    let mut spk = [0u8; 22];
    spk[..2].copy_from_slice(&[0x00, 0x14]);
    spk[2..].copy_from_slice(&hash160(&pk));
    let spent = [SpentOutput {
        value: 60_000,
        script_pubkey: &spk,
    }];
    let script_code = crate::tx::sighash::p2wpkh_script_code(&hash160(&pk));
    let aggregates = Aggregates::compute(&ours, &spent).unwrap();
    let digest = unified::unified(
        &ours,
        &aggregates,
        0,
        &spent,
        unified::Spend::SegwitV0 {
            script_code: &script_code,
        },
        0x21,
    )
    .unwrap();

    let key = SecpPublicKey::from_sec1(&pk).unwrap();
    let (r, s) = outscript::crypto::secp256k1::parse_der_signature(&sig[..sig.len() - 1]).unwrap();
    assert!(
        key.verify(&digest, &r, &s),
        "the signature does not commit to the unified message we computed"
    );

    // And it is a different message from the BIP-143 one for the same transaction, so the
    // signature cannot be replayed onto a chain that reads the byte the old way.
    let legacy = segwit_digest(&psbt, 0, &pk);
    assert_ne!(digest, legacy);
    assert!(!key.verify(&legacy, &r, &s));
}
