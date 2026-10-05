//! A PSBT signed together, end to end, the way the firmware does it: the wallet's public
//! half finds the input and asks `outscript` for the digest (`signer::digest_for_input`),
//! two members sign that digest in a session, and the signature goes into the PSBT
//! (`signer::apply_signature`) and verifies under the key the input pays.

mod common;

use catcard_tss::{SignMode, SignRequest};
use catcard_wallet::bip32::{ChildNumber, ExtendedPubKey, Network};
use catcard_wallet::signer::{Keys, apply_signature, digest_for_input};
use common::*;
use outscript::btcraw::{RawTx, RawTxIn, RawTxOut};
use outscript::psbt::Psbt;

#[test]
fn a_psbt_input_of_a_tss_wallet_is_signed_together() {
    let records = create(3, 2, "psbt");
    let r = &records[0];
    // The wallet's extended public key, as the device builds it from the share's header.
    let key = ExtendedPubKey {
        network: Network::Mainnet,
        depth: 0,
        parent_fingerprint: [0; 4],
        child_number: ChildNumber(0),
        chain_code: *r.chain_code(),
        public_key: *r.joint_public_key(),
    };
    let fp = r.fingerprint();
    let path = [0u32, 1];
    let child = key
        .derive_child(ChildNumber(0))
        .and_then(|k| k.derive_child(ChildNumber(1)))
        .unwrap();
    assert_eq!(child.public_key, r.child_public_key(&path).unwrap());

    // One P2WPKH input paying that key, recorded as a watch-only wallet would record it.
    let mut spk = [0u8; 22];
    spk[..2].copy_from_slice(&[0x00, 0x14]);
    spk[2..].copy_from_slice(&catcard_wallet::bip32::hash160(&child.public_key));
    let input = RawTxIn {
        txid: [0x11; 32],
        vout: 0,
        script_sig: &[],
        sequence: 0xffff_fffd,
        witness: &[],
    };
    let pay = [
        0x00, 0x14, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    ];
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
    let mut b = [0u8; 2048];
    let n = Psbt::parse(&a[..n])
        .unwrap()
        .set_witness_utxo(0, 60_000, &spk, &mut b)
        .unwrap();
    let mut c = [0u8; 2048];
    let n = Psbt::parse(&b[..n])
        .unwrap()
        .add_input_bip32_derivation(0, &child.public_key, fp, &path, &mut c)
        .unwrap();
    let psbt = Psbt::parse(&c[..n]).unwrap();

    // The digest, from the public half alone.
    let keys = Keys::Public {
        key: &key,
        origin: &[],
    };
    let mut scratch = [0u8; 4096];
    let d = digest_for_input(&psbt, 0, keys, fp, &mut scratch, &KW).unwrap();
    assert_eq!(d.steps(), &path);
    assert_eq!(d.pubkey, child.public_key);

    // Members 1 and 3 sign it together.
    let req = [SignRequest {
        path: d.steps().to_vec(),
        sighash: d.digest,
    }];
    let sigs = sign(&records, &[1, 3], &req, SignMode::Checked);
    assert_eq!(sigs[0].child_public_key, d.pubkey);
    assert!(verifies(&d.pubkey, &d.digest, &sigs[0]));

    // Into the PSBT, where it is the input's partial signature under that key.
    let mut out = [0u8; 4096];
    let m = apply_signature(&psbt, 0, &d.pubkey, &sigs[0].der, &mut out).unwrap();
    let signed = Psbt::parse(&out[..m]).unwrap();
    let ps = signed.input(0).unwrap().partial_sig(&d.pubkey).unwrap();
    assert_eq!(&ps[..ps.len() - 1], &sigs[0].der[..]);
    assert_eq!(ps[ps.len() - 1], 1, "SIGHASH_ALL");
}
