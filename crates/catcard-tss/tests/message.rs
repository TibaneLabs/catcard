//! Messages signed together, end to end, in every format the firmware offers a TSS
//! wallet: the digest from the public key, a session of two members, and the signature
//! assembled and then checked by the verifier a counterparty would use.

mod common;

use catcard_tss::{SignMode, SignRequest};
use catcard_wallet::address::AddressKind;
use catcard_wallet::bip322::{self, full};
use catcard_wallet::message;
use common::*;

const TEXT: &str = "CatCard signs together";

/// Members 1 and 3 sign `digest` at `path`; the signature.
fn together(
    records: &[catcard_tss::ShareRecord],
    path: &[u32],
    digest: [u8; 32],
) -> catcard_tss::EcdsaSignature {
    let req = [SignRequest {
        path: path.to_vec(),
        sighash: digest,
    }];
    sign(records, &[1, 3], &req, SignMode::Checked).remove(0)
}

#[test]
fn every_message_format_is_signed_together_and_verifies() {
    let records = create(3, 2, "message");
    let path = [0u32, 0];
    let pubkey = records[0].child_public_key(&path).unwrap();

    // Legacy (BIP-137), every kind: recovers to the key, with the kind's header.
    let digest = message::digest(TEXT).unwrap();
    let sig = together(&records, &path, digest);
    for kind in [
        AddressKind::P2wpkh,
        AddressKind::P2shP2wpkh,
        AddressKind::P2pkh,
    ] {
        let s = message::from_signature(&digest, &sig.compact, &pubkey, kind).unwrap();
        assert_eq!(message::recover(TEXT, &s).unwrap(), (pubkey, kind));
    }

    // BIP-322 simple, P2WPKH.
    let digest = bip322::simple_digest(TEXT.as_bytes(), &pubkey).unwrap();
    let sig = together(&records, &path, digest);
    let simple = bip322::simple_from_der(&pubkey, &sig.der).unwrap();
    let mut script = [0u8; bip322::MAX_SCRIPT];
    let n = bip322::challenge(AddressKind::P2wpkh, &pubkey, &mut script).unwrap();
    bip322::verify(TEXT.as_bytes(), &script[..n], simple.as_bytes()).unwrap();

    // BIP-322 full, native and nested.
    for kind in [AddressKind::P2wpkh, AddressKind::P2shP2wpkh] {
        let digest = full::full_digest(TEXT.as_bytes(), &pubkey, kind).unwrap();
        let sig = together(&records, &path, digest);
        let whole = full::full_from_der(TEXT.as_bytes(), &pubkey, kind, &sig.der).unwrap();
        let n = full::challenge(kind, &pubkey, &mut script).unwrap();
        full::verify_full(TEXT.as_bytes(), &script[..n], whole.as_bytes()).unwrap();
    }
}
