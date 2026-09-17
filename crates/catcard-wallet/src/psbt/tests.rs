//! BIP-174's test vectors, plus what a signer has to be able to read out of a PSBT.

use super::test_vectors::{INVALID, VALID};
use super::*;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn every_invalid_vector_is_refused() {
    for (name, bytes) in INVALID {
        let bytes = hex(bytes);
        assert!(
            Psbt::parse(&bytes).is_err(),
            "accepted an invalid PSBT: {name}"
        );
    }
}

#[test]
fn every_valid_vector_is_accepted_with_the_right_shape() {
    for (name, bytes) in VALID {
        let bytes = hex(bytes);
        let psbt = Psbt::parse(&bytes).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        // The maps are there and walkable: every record of every map parses.
        let tx = psbt.tx();
        assert_eq!(psbt.input_count() as u64, tx.inputs.count(), "{name}");
        assert_eq!(psbt.output_count() as u64, tx.outputs.count(), "{name}");
        for i in 0..psbt.input_count() {
            for rec in psbt.input(i).unwrap().records() {
                rec.unwrap_or_else(|e| panic!("{name} input {i}: {e:?}"));
            }
        }
        for i in 0..psbt.output_count() {
            for rec in psbt.output(i).unwrap().records() {
                rec.unwrap_or_else(|e| panic!("{name} output {i}: {e:?}"));
            }
        }
        assert!(psbt.input(psbt.input_count()).is_none(), "{name}");
        assert!(psbt.output(psbt.output_count()).is_none(), "{name}");
    }
}

/// The valid vector whose name starts with `starts`, by name rather than by position.
fn vector(starts: &str) -> Vec<u8> {
    let (_, bytes) = VALID
        .iter()
        .find(|(name, _)| name.starts_with(starts))
        .unwrap_or_else(|| panic!("no vector named {starts}"));
    hex(bytes)
}

/// The BIP's "one P2PKH input and one P2SH-P2WPKH input both with non-final scriptSigs"
/// case: what a signer reads before it can sign either input.
fn two_input_case() -> Vec<u8> {
    vector("PSBT with one P2PKH input and one P2SH-P2WPKH input both with non-final")
}

#[test]
fn a_signer_can_read_the_utxos_scripts_and_keys_it_needs() {
    let bytes = two_input_case();
    let psbt = Psbt::parse(&bytes).unwrap();
    assert_eq!(psbt.version(), 0);
    assert_eq!((psbt.input_count(), psbt.output_count()), (2, 2));

    // Input 0 spends a legacy output, so the whole previous transaction is provided; the
    // txid of that transaction is what the unsigned transaction's prevout names.
    let in0 = psbt.input(0).unwrap();
    let prev = in0.keyless(input::NON_WITNESS_UTXO).unwrap().unwrap();
    let prev_tx = Transaction::parse(prev).unwrap();
    let spent = psbt.tx().inputs.get(0).unwrap().previous_output;
    assert_eq!(prev_tx.txid(), spent.txid);
    assert!(in0.keyless(input::WITNESS_UTXO).unwrap().is_none());

    // Input 1 spends a nested-segwit output: the output itself, and the redeem script whose
    // hash the output pays to.
    let in1 = psbt.input(1).unwrap();
    let utxo = in1.keyless(input::WITNESS_UTXO).unwrap().unwrap();
    // `<64-bit value> <compact size len> <scriptPubKey>`
    assert_eq!(utxo.len(), 8 + 1 + 23);
    assert_eq!(utxo[8], 23);
    assert_eq!(utxo[9], 0xa9, "a P2SH scriptPubKey starts OP_HASH160");
    let redeem = in1.keyless(input::REDEEM_SCRIPT).unwrap().unwrap();
    assert_eq!(redeem.len(), 22, "P2WPKH: OP_0 <20-byte hash>");
    assert_eq!(&redeem[..2], &[0x00, 0x14]);

    // This vector's inputs carry no key paths -- the updater left them out -- and both of
    // its outputs carry one, which is what change detection reads.
    for i in 0..2 {
        assert_eq!(
            psbt.input(i)
                .unwrap()
                .derivations(input::BIP32_DERIVATION, input::TAP_BIP32_DERIVATION)
                .count(),
            0,
            "input {i}"
        );
        let outs: Vec<KeyOrigin<'_>> = psbt
            .output(i)
            .unwrap()
            .derivations(output::BIP32_DERIVATION, output::TAP_BIP32_DERIVATION)
            .map(|k| k.unwrap())
            .collect();
        assert_eq!(outs.len(), 1, "output {i}");
        assert_eq!(outs[0].pubkey.len(), 33);
        assert_eq!(outs[0].origin.depth(), 3);
    }
}

#[test]
fn an_inputs_keys_are_read_with_their_paths() {
    // The 2-of-2 P2SH-P2WSH case: "redeemScript, witnessScript, and keypaths are
    // available", so this is the shape a signer looks for -- which of these keys is mine.
    let bytes = vector("PSBT with one P2SH-P2WSH input of a 2-of-2 multisig");
    let psbt = Psbt::parse(&bytes).unwrap();
    let in0 = psbt.input(0).unwrap();
    assert!(in0.keyless(input::REDEEM_SCRIPT).unwrap().is_some());
    assert!(in0.keyless(input::WITNESS_SCRIPT).unwrap().is_some());
    let keys: Vec<KeyOrigin<'_>> = in0
        .derivations(input::BIP32_DERIVATION, input::TAP_BIP32_DERIVATION)
        .map(|k| k.unwrap())
        .collect();
    assert_eq!(keys.len(), 2, "both cosigners' keys");
    for k in &keys {
        assert_eq!(k.pubkey.len(), 33);
        assert!(k.origin.depth() >= 1);
        // The path's leading steps are hardened (an account), the last ones are not.
        let steps: Vec<u32> = k.origin.steps().collect();
        assert!(steps[0] & 0x8000_0000 != 0, "{steps:08x?}");
    }
    // Both keys in this vector come from one master, at different paths -- which is why a
    // signer matches on the path as well as the fingerprint.
    assert_eq!(keys[0].origin.fingerprint, keys[1].origin.fingerprint);
    assert_ne!(
        keys[0].origin.steps().collect::<Vec<_>>(),
        keys[1].origin.steps().collect::<Vec<_>>()
    );
    assert_ne!(keys[0].pubkey, keys[1].pubkey);
}

#[test]
fn a_sighash_type_is_read_as_a_little_endian_u32() {
    // The BIP's case with a sighash type specified.
    let bytes = vector("PSBT with one P2PKH input which has a non-final scriptSig");
    let psbt = Psbt::parse(&bytes).unwrap();
    let v = psbt
        .input(0)
        .unwrap()
        .keyless(input::SIGHASH_TYPE)
        .unwrap()
        .unwrap();
    assert_eq!(v.len(), 4);
    assert_eq!(u32::from_le_bytes(v.try_into().unwrap()), 1, "SIGHASH_ALL");
}

#[test]
fn a_finalized_input_is_visible_as_such() {
    // "First input is signed and finalized."
    let bytes =
        vector("PSBT with one P2PKH input and one P2SH-P2WPKH input. First input is signed");
    let psbt = Psbt::parse(&bytes).unwrap();
    let in0 = psbt.input(0).unwrap();
    assert!(in0.keyless(input::FINAL_SCRIPTSIG).unwrap().is_some());
    let in1 = psbt.input(1).unwrap();
    assert!(in1.keyless(input::FINAL_SCRIPTSIG).unwrap().is_none());
}

#[test]
fn partial_signatures_are_listed_with_the_keys_that_made_them() {
    // The 2-of-2 P2SH-P2WSH case "contains one signature".
    let bytes = vector("PSBT with one P2SH-P2WSH input of a 2-of-2 multisig");
    let psbt = Psbt::parse(&bytes).unwrap();
    let sigs: Vec<Record<'_>> = psbt
        .input(0)
        .unwrap()
        .all(input::PARTIAL_SIG)
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].keydata.len(), 33, "the signing key");
    assert!(sigs[0].value.len() >= 70, "a DER signature plus hash byte");
    assert_eq!(*sigs[0].value.last().unwrap(), 0x01, "SIGHASH_ALL");
}

#[test]
fn global_xpubs_carry_their_origin() {
    // The `PSBT_GLOBAL_XPUB` case.
    let bytes = vector("PSBT with `PSBT_GLOBAL_XPUB`");
    let psbt = Psbt::parse(&bytes).unwrap();
    let xpubs: Vec<Record<'_>> = psbt.globals.all(global::XPUB).map(|r| r.unwrap()).collect();
    assert!(!xpubs.is_empty());
    for x in xpubs {
        assert_eq!(x.keydata.len(), 78, "a serialised extended key");
        let origin = parse_origin(global::XPUB, x.value).unwrap();
        // The depth in the key must match the number of path elements given.
        assert_eq!(origin.depth(), x.keydata[4] as usize);
    }
}

#[test]
fn unknown_fields_are_carried_not_refused() {
    // "PSBT with unknown types in the inputs" -- a signer must not choke on fields it does
    // not know, only on malformed ones.
    let bytes = vector("PSBT with unknown types in the inputs");
    let psbt = Psbt::parse(&bytes).unwrap();
    let recs: Vec<Record<'_>> = psbt
        .input(0)
        .unwrap()
        .records()
        .map(|r| r.unwrap())
        .collect();
    assert!(recs.iter().any(|r| r.keytype > input::TAP_INTERNAL_KEY));
}

#[test]
fn a_version_2_psbt_says_so_rather_than_looking_broken() {
    // A minimal v2 container: magic, version 2, no unsigned transaction.
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(&[0x01, 0xFB, 0x04]);
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.push(0x00);
    assert_eq!(
        Psbt::parse(&bytes).err(),
        Some(Error::UnsupportedVersion { version: 2 })
    );
}

#[test]
fn trailing_bytes_and_a_missing_terminator_are_both_refused() {
    let bytes = two_input_case();
    let mut extra = bytes.clone();
    extra.push(0x00);
    assert_eq!(Psbt::parse(&extra).err(), Some(Error::TrailingData));
    let short = &bytes[..bytes.len() - 1];
    assert!(Psbt::parse(short).is_err());
}
