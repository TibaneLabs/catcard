//! BIP-370 against its own vectors, and a v2 spend against its v0 twin.
//!
//! The vectors are the BIP's, verbatim (`bip370_vectors.rs`). The twin test builds one
//! transaction both ways and shows the signature is the same bytes either way: a v2
//! container is a different way of writing the transaction, not a different transaction.

use outscript::btcraw::{RawTx, RawTxIn, RawTxOut};
use outscript::psbt::{Psbt, input as v0_in};

use super::*;
use crate::KeyWork;
use crate::bip32::{ChildNumber, ExtendedPrivKey, Network};
use crate::bip39::{Mnemonic, SEED_LEN};
use crate::signer::{SighashPolicy, sign_input, sign_input_under};

#[path = "bip370_vectors.rs"]
mod bip370_vectors;
use bip370_vectors as vectors;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Every record of every map, as sorted `(key, value)` lists, so two containers can be
/// compared as the sets they are rather than by byte order.
fn record_sets(bytes: &[u8]) -> Vec<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut c = Cursor::new(bytes, MAGIC.len());
    let mut maps = Vec::new();
    while !c.is_empty() {
        let map = read_map(&mut c).unwrap();
        let mut recs: Vec<(Vec<u8>, Vec<u8>)> = records(map)
            .map(|r| r.unwrap())
            .map(|r| (r.key.to_vec(), r.value.to_vec()))
            .collect();
        recs.sort();
        maps.push(recs);
    }
    maps
}

/// The invalid vectors: half are v0 files carrying a v2 field, which the v0 parser
/// refuses; half are v2 files missing or misusing one, which this refuses. Neither parser
/// accepts any of them.
#[test]
fn every_invalid_vector_is_refused() {
    for (case, hex) in vectors::INVALID {
        let bytes = unhex(hex);
        let v0 = Psbt::parse(&bytes);
        let v2 = V2::parse(&bytes);
        assert!(v0.is_err(), "v0 parser accepted: {case}");
        assert!(v2.is_err(), "v2 parser accepted: {case}");
        let why = v2.unwrap_err();
        // The v2 ones are refused for the reason the case names, not for something
        // incidental.
        let expected: Option<Error> = match *case {
            "PSBTv0 but with PSBT_GLOBAL_VERSION set to 2." => Some(Error::UnsignedTxPresent),
            "PSBTv2 but with PSBT_GLOBAL_UNSIGNED_TX." => Some(Error::UnsignedTxPresent),
            "PSBTv2 missing PSBT_GLOBAL_INPUT_COUNT." => {
                Some(Error::MissingGlobal(global::INPUT_COUNT))
            }
            "PSBTv2 missing PSBT_GLOBAL_OUTPUT_COUNT." => {
                Some(Error::MissingGlobal(global::OUTPUT_COUNT))
            }
            "PSBTv2 missing PSBT_GLOBAL_TX_VERSION." => {
                Some(Error::MissingGlobal(global::TX_VERSION))
            }
            "PSBTv2 missing PSBT_IN_PREVIOUS_TXID." => Some(Error::MissingInputField {
                input: 0,
                key: input::PREVIOUS_TXID,
            }),
            "PSBTv2 missing PSBT_IN_OUTPUT_INDEX." => Some(Error::MissingInputField {
                input: 0,
                key: input::OUTPUT_INDEX,
            }),
            "PSBTv2 missing PSBT_OUT_AMOUNT." => Some(Error::MissingOutputField {
                output: 0,
                key: output::AMOUNT,
            }),
            "PSBTv2 missing PSBT_OUT_SCRIPT." => Some(Error::MissingOutputField {
                output: 0,
                key: output::SCRIPT,
            }),
            "PSBTv2 with PSBT_IN_REQUIRED_TIME_LOCKTIME less than 500000000." => {
                Some(Error::BadInputField {
                    input: 0,
                    key: input::REQUIRED_TIME_LOCKTIME,
                })
            }
            "PSBTv2 with PSBT_IN_REQUIRED_HEIGHT_LOCKTIME greater than or equal to 500000000."
            | "PSBTv2 with PSBT_IN_REQUIRED_HEIGHT_LOCKTIME of 0." => Some(Error::BadInputField {
                input: 0,
                key: input::REQUIRED_HEIGHT_LOCKTIME,
            }),
            // The remaining v0-with-a-v2-field cases: not v2 at all, as far as this is
            // concerned, and the v0 parser's business (checked above).
            _ => Some(Error::NotV2),
        };
        if let Some(e) = expected {
            assert_eq!(why, e, "{case}");
        }
    }
}

/// Every valid vector parses, converts to a v0 the v0 parser accepts, and merges back
/// into a v2 holding exactly the records it started with.
#[test]
fn every_valid_vector_parses_and_round_trips() {
    for (case, hex) in vectors::VALID {
        let bytes = unhex(hex);
        let v2 = V2::parse(&bytes).unwrap_or_else(|e| panic!("{case}: {e:?}"));
        assert_eq!(v2.input_count(), 1, "{case}");
        assert_eq!(v2.output_count(), 2, "{case}");
        assert_eq!(v2.tx_version(), 2, "{case}");

        let mut v0 = vec![0u8; v2.v0_len_bound()];
        let n = v2
            .to_v0(&mut v0)
            .unwrap_or_else(|e| panic!("{case}: {e:?}"));
        let view = Psbt::parse(&v0[..n]).unwrap();
        let tx = view.unsigned_tx();
        assert_eq!(tx.input_count(), 1);
        assert_eq!(tx.output_count(), 2);
        assert_eq!(tx.version(), 2);
        assert_eq!(tx.locktime(), v2.locktime());
        // The input the v2 fields name is the input the transaction has, txid in the
        // order a transaction writes it.
        let inp = v2.input(0).unwrap();
        let raw = tx.inputs().next().unwrap();
        let mut display = inp.txid;
        display.reverse();
        assert_eq!(raw.txid, display, "{case}");
        assert_eq!(raw.vout, inp.vout);
        assert_eq!(raw.sequence, inp.sequence);
        for (i, out) in tx.outputs().enumerate() {
            let o = v2.output(i).unwrap();
            assert_eq!(out.amount, o.amount);
            assert_eq!(out.script, o.script);
        }

        let mut back = vec![0u8; bytes.len() + 64];
        let m = v2.write_back(&view, &mut back).unwrap();
        assert!(is_v2(&back[..m]));
        assert_eq!(record_sets(&back[..m]), record_sets(&bytes), "{case}");
    }
}

/// Parsing takes every flags byte the BIP calls valid; signing takes fewer.
#[test]
fn the_modifiable_flags_are_read_and_the_dangerous_ones_refused() {
    for (case, hex) in vectors::VALID {
        let bytes = unhex(hex);
        let v2 = V2::parse(&bytes).unwrap();
        let flags = v2.modifiable();
        let verdict = v2.check_for_signing();
        match *case {
            c if c.contains("undefined flag") || c.contains("all possible") => {
                assert!(matches!(verdict, Err(Error::UnknownFlags(_))), "{case}");
            }
            c if c.contains("Inputs Modifiable") || c.contains("Outputs Modifiable") => {
                assert!(matches!(verdict, Err(Error::StillModifiable(_))), "{case}");
            }
            c if c.contains("all defined") || c.contains("all PSBTv2 fields") => {
                assert!(matches!(verdict, Err(Error::StillModifiable(_))), "{case}");
            }
            c if c.contains("Has SIGHASH_SINGLE") => {
                assert_eq!(flags, Some(Flags(Flags::HAS_SIGHASH_SINGLE)), "{case}");
                assert_eq!(verdict, Ok(()), "{case}");
            }
            _ => assert_eq!(verdict, Ok(()), "{case}"),
        }
    }
}

/// BIP-370's lock-time vectors, each group to the value the BIP states.
#[test]
fn the_lock_time_is_determined_as_the_bip_says() {
    for (expect, group) in [
        (0u32, vectors::LOCKTIME_0),
        (10_000, vectors::LOCKTIME_10000),
        (1_657_048_460, vectors::LOCKTIME_1657048460),
    ] {
        for (case, hex) in group {
            let bytes = unhex(hex);
            let v2 = V2::parse(&bytes).unwrap_or_else(|e| panic!("{case}: {e:?}"));
            assert_eq!(v2.locktime(), expect, "{case}");
        }
    }
    for (case, hex) in vectors::LOCKTIME_CONFLICT {
        assert_eq!(
            V2::parse(&unhex(hex)),
            Err(Error::LocktimeConflict),
            "{case}"
        );
    }
}

/// A count that does not match the maps is refused, whichever way it is wrong.
#[test]
fn counts_that_disagree_with_the_maps_are_refused() {
    let (_, hex) = vectors::VALID[0];
    let bytes = unhex(hex);
    // The one-input vector's `PSBT_GLOBAL_INPUT_COUNT` record is `01 04 01 01`; say two.
    let at = bytes
        .windows(4)
        .position(|w| w == [0x01, 0x04, 0x01, 0x01])
        .unwrap();
    let mut two = bytes.clone();
    two[at + 3] = 2;
    // The first output map is read as the second input, and has no txid to give: the
    // lie is caught at the first map that is not what the count said it would be.
    assert_eq!(
        V2::parse(&two),
        Err(Error::MissingInputField {
            input: 1,
            key: input::PREVIOUS_TXID
        })
    );
    // Or zero: the input map is then read as the first output, which has no amount.
    let mut zero = bytes.clone();
    zero[at + 3] = 0;
    assert_eq!(
        V2::parse(&zero),
        Err(Error::MissingOutputField {
            output: 0,
            key: output::AMOUNT
        })
    );
    // The output count (`01 05 01 02`) past the maps there are, or short of them: the
    // count itself is what is refused.
    let at = bytes
        .windows(4)
        .position(|w| w == [0x01, 0x05, 0x01, 0x02])
        .unwrap();
    let mut three = bytes.clone();
    three[at + 3] = 3;
    assert_eq!(V2::parse(&three), Err(Error::CountMismatch));
    let mut one = bytes.clone();
    one[at + 3] = 1;
    assert_eq!(V2::parse(&one), Err(Error::CountMismatch));
    // A truncated last map is a truncation, not a count.
    assert!(matches!(
        V2::parse(&bytes[..bytes.len() - 1]),
        Err(Error::Truncated | Error::CountMismatch)
    ));
}

// --- the v0 twin ---

const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const FINGERPRINT: [u8; 4] = [0x73, 0xc5, 0xda, 0x0a];
const PATH: [u32; 5] = [84 | 0x8000_0000, 0x8000_0000, 0x8000_0000, 0, 0];

fn master() -> ExtendedPrivKey {
    let kw = KeyWork::host();
    let m = Mnemonic::parse(PHRASE, &kw).unwrap();
    let mut seed = [0u8; SEED_LEN];
    m.to_seed("", &mut seed, &kw).unwrap();
    ExtendedPrivKey::from_seed(&seed, Network::Mainnet, &kw).unwrap()
}

fn pubkey_at(steps: &[u32]) -> [u8; 33] {
    let kw = KeyWork::host();
    let mut here = master();
    for &s in steps {
        here = here.derive_child(ChildNumber(s), &kw).unwrap();
    }
    here.public_key(&kw)
}

/// A v0 PSBT spending one P2WPKH output of ours, with a sequence and a locktime so the
/// v2 twin has every field to carry.
fn v0_spend(sighash: Option<u32>) -> Vec<u8> {
    let pk = pubkey_at(&PATH);
    let mut spk = [0u8; 22];
    spk[..2].copy_from_slice(&[0x00, 0x14]);
    spk[2..].copy_from_slice(&crate::bip32::hash160(&pk));
    let input = RawTxIn {
        txid: [0x11; 32],
        vout: 3,
        script_sig: &[],
        sequence: 0xffff_fffd,
        witness: &[],
    };
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
        locktime: 850_000,
    };
    let mut a = vec![0u8; 2048];
    let n = Psbt::create_to_slice(&tx, &mut a).unwrap();
    let mut b = vec![0u8; 2048];
    let n = Psbt::parse(&a[..n])
        .unwrap()
        .set_witness_utxo(0, 60_000, &spk, &mut b)
        .unwrap();
    let n = Psbt::parse(&b[..n])
        .unwrap()
        .add_input_bip32_derivation(0, &pk, FINGERPRINT, &PATH, &mut a)
        .unwrap();
    let n = match sighash {
        Some(kind) => {
            let m = Psbt::parse(&a[..n])
                .unwrap()
                .set_sighash_type(0, kind, &mut b)
                .unwrap();
            a[..m].copy_from_slice(&b[..m]);
            m
        }
        None => n,
    };
    a.truncate(n);
    a
}

/// Whether two inputs name the same v2 fields, whatever else their maps hold.
fn same_fields(a: Input<'_>, b: Input<'_>) -> bool {
    a.txid == b.txid
        && a.vout == b.vout
        && a.sequence == b.sequence
        && a.required_time == b.required_time
        && a.required_height == b.required_height
}

fn put_rec(out: &mut Vec<u8>, key: &[u8], value: &[u8]) {
    out.push(key.len() as u8);
    out.extend_from_slice(key);
    let mut len = [0u8; 9];
    let n = VarInt::write(value.len() as u64, &mut len).unwrap();
    out.extend_from_slice(&len[..n]);
    out.extend_from_slice(value);
}

/// The v2 form of a v0 PSBT: what a v2-speaking host would have written for the same
/// transaction. `flags` adds `PSBT_GLOBAL_TX_MODIFIABLE`; `extra_global` and `extra_input`
/// are records to carry, for showing they survive.
fn v0_to_v2(
    v0: &[u8],
    flags: Option<u8>,
    extra_global: &[(&[u8], &[u8])],
    extra_input: &[(&[u8], &[u8])],
) -> Vec<u8> {
    let psbt = Psbt::parse(v0).unwrap();
    let tx = psbt.unsigned_tx();
    let mut out = MAGIC.to_vec();
    put_rec(&mut out, &[0xfb], &2u32.to_le_bytes());
    put_rec(&mut out, &[0x02], &tx.version().to_le_bytes());
    put_rec(&mut out, &[0x03], &tx.locktime().to_le_bytes());
    put_rec(&mut out, &[0x04], &[tx.input_count() as u8]);
    put_rec(&mut out, &[0x05], &[tx.output_count() as u8]);
    if let Some(f) = flags {
        put_rec(&mut out, &[0x06], &[f]);
    }
    for rec in psbt.global().records() {
        if rec.key_type() != 0x00 {
            put_rec(&mut out, rec.key, rec.value);
        }
    }
    for (k, v) in extra_global {
        put_rec(&mut out, k, v);
    }
    out.push(0);
    for (i, (inp, raw)) in psbt.inputs().zip(tx.inputs()).enumerate() {
        for rec in inp.map().records() {
            put_rec(&mut out, rec.key, rec.value);
        }
        let mut txid = raw.txid;
        txid.reverse();
        put_rec(&mut out, &[0x0e], &txid);
        put_rec(&mut out, &[0x0f], &raw.vout.to_le_bytes());
        put_rec(&mut out, &[0x10], &raw.sequence.to_le_bytes());
        if i == 0 {
            for (k, v) in extra_input {
                put_rec(&mut out, k, v);
            }
        }
        out.push(0);
    }
    for (o, raw) in psbt.outputs().zip(tx.outputs()) {
        for rec in o.map().records() {
            put_rec(&mut out, rec.key, rec.value);
        }
        put_rec(&mut out, &[0x03], &raw.amount.to_le_bytes());
        put_rec(&mut out, &[0x04], raw.script);
        out.push(0);
    }
    out
}

/// The same transaction written as v0 and as v2 signs to the same bytes, and the v2
/// container comes back as v2 with the signature in it.
#[test]
fn a_v2_spend_signs_byte_for_byte_like_its_v0_twin() {
    let kw = KeyWork::host();
    let v0 = v0_spend(None);
    let v2 = v0_to_v2(&v0, None, &[], &[]);
    let parsed = V2::parse(&v2).unwrap();
    assert_eq!(parsed.check_for_signing(), Ok(()));
    assert_eq!(parsed.locktime(), 850_000);

    // The view is the v0 twin, transaction and all.
    let mut view = vec![0u8; parsed.v0_len_bound()];
    let n = parsed.to_v0(&mut view).unwrap();
    let view = &view[..n];
    assert_eq!(
        Psbt::parse(view).unwrap().unsigned_tx().bytes(),
        Psbt::parse(&v0).unwrap().unsigned_tx().bytes(),
        "the rebuilt transaction differs from the one the v0 carried"
    );

    let master = master();
    let mut signed_v0 = vec![0u8; 4096];
    let a = sign_input(
        &Psbt::parse(&v0).unwrap(),
        0,
        &master,
        FINGERPRINT,
        &mut signed_v0,
        &kw,
    )
    .unwrap();
    let mut signed_view = vec![0u8; 4096];
    let b = sign_input(
        &Psbt::parse(view).unwrap(),
        0,
        &master,
        FINGERPRINT,
        &mut signed_view,
        &kw,
    )
    .unwrap();
    let pk = pubkey_at(&PATH);
    let sig_v0 = Psbt::parse(&signed_v0[..a])
        .unwrap()
        .input(0)
        .unwrap()
        .partial_sig(&pk)
        .unwrap()
        .to_vec();
    let sig_v2 = Psbt::parse(&signed_view[..b])
        .unwrap()
        .input(0)
        .unwrap()
        .partial_sig(&pk)
        .unwrap()
        .to_vec();
    assert_eq!(
        sig_v0, sig_v2,
        "the two containers signed different digests"
    );

    // Back to v2: the signature is there, every v2 field is as it was, and it is v2.
    let signed = Psbt::parse(&signed_view[..b]).unwrap();
    let mut back = vec![0u8; 4096];
    let m = parsed.write_back(&signed, &mut back).unwrap();
    let back = &back[..m];
    assert!(is_v2(back));
    let again = V2::parse(back).unwrap();
    assert!(same_fields(
        again.input(0).unwrap(),
        parsed.input(0).unwrap()
    ));
    assert_eq!(again.output(0), parsed.output(0));
    assert_eq!(again.locktime(), 850_000);
    let mut view2 = vec![0u8; again.v0_len_bound()];
    let n2 = again.to_v0(&mut view2).unwrap();
    let sig_back = Psbt::parse(&view2[..n2])
        .unwrap()
        .input(0)
        .unwrap()
        .partial_sig(&pk)
        .unwrap()
        .to_vec();
    assert_eq!(sig_back, sig_v0);
    // No flags were present and nothing needed one, so none was invented.
    assert_eq!(again.modifiable(), None);

    // Finalised: the v0 view finalises as any v0 does, extracts a transaction, and the v2
    // written back carries the final witness with the v2 fields still in place.
    let mut fin = vec![0u8; 4096];
    let (f, count) = signed.finalize_to_slice(&mut fin).unwrap();
    assert_eq!(count, 1);
    let done = Psbt::parse(&fin[..f]).unwrap();
    assert!(done.is_finalized());
    let mut tx_out = vec![0u8; 1024];
    let t = done.extract_tx_to_slice(&mut tx_out).unwrap();
    assert!(t > 100);
    let mut back2 = vec![0u8; 4096];
    let m2 = parsed.write_back(&done, &mut back2).unwrap();
    let again = V2::parse(&back2[..m2]).unwrap();
    assert!(same_fields(
        again.input(0).unwrap(),
        parsed.input(0).unwrap()
    ));
    let mut view3 = vec![0u8; again.v0_len_bound()];
    let n3 = again.to_v0(&mut view3).unwrap();
    let v = Psbt::parse(&view3[..n3]).unwrap();
    assert!(v.is_finalized());
    assert!(v.input(0).unwrap().final_script_witness().is_some());
}

/// Records neither version defines, and proprietary ones, travel through the view and
/// the write-back untouched.
#[test]
fn unknown_and_proprietary_records_are_kept() {
    let kw = KeyWork::host();
    let v0 = v0_spend(None);
    let prop_key: &[u8] = &[0xfc, 0x03, b'c', b'a', b't', 0x01];
    let odd_global: &[u8] = &[0xf0];
    let odd_input: &[u8] = &[0xe7, 0xaa];
    let v2 = v0_to_v2(
        &v0,
        None,
        &[(odd_global, b"hello")],
        &[(prop_key, b"world"), (odd_input, b"!")],
    );
    let parsed = V2::parse(&v2).unwrap();
    let mut view = vec![0u8; parsed.v0_len_bound()];
    let n = parsed.to_v0(&mut view).unwrap();
    let psbt = Psbt::parse(&view[..n]).unwrap();
    assert_eq!(psbt.global().get(odd_global), Some(&b"hello"[..]));
    assert_eq!(
        psbt.input(0).unwrap().map().get(prop_key),
        Some(&b"world"[..])
    );
    assert_eq!(psbt.input(0).unwrap().map().get(odd_input), Some(&b"!"[..]));

    let mut signed = vec![0u8; 4096];
    let m = sign_input(&psbt, 0, &master(), FINGERPRINT, &mut signed, &kw).unwrap();
    let mut back = vec![0u8; 4096];
    let b = parsed
        .write_back(&Psbt::parse(&signed[..m]).unwrap(), &mut back)
        .unwrap();
    let sets = record_sets(&back[..b]);
    assert!(sets[0].contains(&(odd_global.to_vec(), b"hello".to_vec())));
    assert!(sets[1].contains(&(prop_key.to_vec(), b"world".to_vec())));
    assert!(sets[1].contains(&(odd_input.to_vec(), b"!".to_vec())));
    // And the signature is in the same map.
    assert!(
        sets[1]
            .iter()
            .any(|(k, _)| k[0] == v0_in::PARTIAL_SIG as u8)
    );
}

/// The Signer role's flag updates: `ALL` leaves a clean byte alone, and a `SINGLE`
/// signature sets Has SIGHASH_SINGLE -- adding the field when the container had none.
#[test]
fn signing_updates_the_modifiable_flags_as_the_signer_role_requires() {
    let kw = KeyWork::host();
    // A present-but-clear byte stays as it is under an ALL signature.
    let v0 = v0_spend(None);
    let v2 = v0_to_v2(&v0, Some(0), &[], &[]);
    let parsed = V2::parse(&v2).unwrap();
    let mut view = vec![0u8; parsed.v0_len_bound()];
    let n = parsed.to_v0(&mut view).unwrap();
    let mut signed = vec![0u8; 4096];
    let m = sign_input(
        &Psbt::parse(&view[..n]).unwrap(),
        0,
        &master(),
        FINGERPRINT,
        &mut signed,
        &kw,
    )
    .unwrap();
    let mut back = vec![0u8; 4096];
    let b = parsed
        .write_back(&Psbt::parse(&signed[..m]).unwrap(), &mut back)
        .unwrap();
    assert_eq!(V2::parse(&back[..b]).unwrap().modifiable(), Some(Flags(0)));

    // A SINGLE signature (admitted under the warn policy) sets bit 2, field or no field.
    let v0 = v0_spend(Some(0x03));
    for had in [None, Some(0u8)] {
        let v2 = v0_to_v2(&v0, had, &[], &[]);
        let parsed = V2::parse(&v2).unwrap();
        let mut view = vec![0u8; parsed.v0_len_bound()];
        let n = parsed.to_v0(&mut view).unwrap();
        let mut signed = vec![0u8; 4096];
        let m = sign_input_under(
            &Psbt::parse(&view[..n]).unwrap(),
            0,
            &master(),
            FINGERPRINT,
            SighashPolicy::Warn,
            &mut signed,
            &kw,
        )
        .unwrap();
        let mut back = vec![0u8; 4096];
        let b = parsed
            .write_back(&Psbt::parse(&signed[..m]).unwrap(), &mut back)
            .unwrap();
        assert_eq!(
            V2::parse(&back[..b]).unwrap().modifiable(),
            Some(Flags(Flags::HAS_SIGHASH_SINGLE)),
            "had {had:?}"
        );
    }
}

/// A v2 still open to changes is refused for signing, and says so by name.
#[test]
fn a_still_modifiable_transaction_is_refused_for_signing() {
    let v0 = v0_spend(None);
    for (flags, want) in [
        (0x01u8, Err(Error::StillModifiable(Flags(0x01)))),
        (0x02, Err(Error::StillModifiable(Flags(0x02)))),
        (0x03, Err(Error::StillModifiable(Flags(0x03)))),
        (0x04, Ok(())),
        (0x08, Err(Error::UnknownFlags(0x08))),
        (0x80, Err(Error::UnknownFlags(0x80))),
    ] {
        let v2 = v0_to_v2(&v0, Some(flags), &[], &[]);
        assert_eq!(
            V2::parse(&v2).unwrap().check_for_signing(),
            want,
            "{flags:#x}"
        );
    }
}

/// The version peek: v0, v2, and the ones in between and beyond.
#[test]
fn the_version_is_read_from_the_global_map_alone() {
    let v0 = v0_spend(None);
    assert_eq!(version(&v0), Ok(0));
    assert!(!is_v2(&v0));
    assert_eq!(V2::parse(&v0), Err(Error::NotV2));
    let v2 = v0_to_v2(&v0, None, &[], &[]);
    assert_eq!(version(&v2), Ok(2));
    assert!(is_v2(&v2));
    // Version 3: named, not guessed at.
    let mut v3 = v2.clone();
    let at = v3.windows(3).position(|w| w == [0xfb, 0x04, 0x02]).unwrap();
    v3[at + 2] = 3;
    assert_eq!(V2::parse(&v3), Err(Error::UnsupportedVersion(3)));
    assert_eq!(version(b"nope"), Err(Error::Magic));
}
