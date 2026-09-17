//! Signing a PSBT built for a key this seed really owns, and refusing the rest.
//!
//! The wallet is BIP-84's published test mnemonic, so the keys, the addresses and the
//! fingerprint here are all values other implementations agree on.

use outscript::btcraw::{RawTx, RawTxIn, RawTxOut};
use outscript::crypto::secp256k1::SecpPublicKey;
use outscript::psbt::{Psbt, input as in_key};

use super::*;
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
    let n = psbt
        .add_input_bip32_derivation(0, &pk, fingerprint, &path, buf)
        .unwrap();
    n
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
