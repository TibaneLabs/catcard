//! The *full* and *proof of funds* variants against BIP-322's published vectors, and the
//! hashing engine against `outscript`.
//!
//! Every constant here is copied from `bip-0322/generated-test-vectors.json` in the BIPs
//! repository. The `full` vectors there were made with version 2, lock time 2016 and
//! sequence 2016 -- none of them the default -- which is the point of the variant, and
//! what makes them a test of reading a transaction as found rather than assuming one.
//! This signer writes the default `to_sign`, so its output is checked by verifying it,
//! not by comparing bytes; the vectors' bytes are checked by verifying *them*.

use super::*;
use crate::address::AddressKind;
use crate::bip322::{Error, Variant, verify_armoured, verify_armoured_in};
use crate::encoding::base58;

fn wif(text: &str) -> [u8; 32] {
    let mut buf = [0u8; 64];
    let n = base58::decode_check(text, &mut buf).expect("vector WIF decodes");
    assert_eq!(n, 34);
    let mut key = [0u8; 32];
    key.copy_from_slice(&buf[1..33]);
    key
}

fn script_of(address: &str) -> Vec<u8> {
    outscript::address::decode_bitcoin_based_address("bitcoin", address)
        .expect("vector address decodes")
        .script
        .to_vec()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn dearmour_full(text: &str) -> Vec<u8> {
    assert!(text.starts_with("ful"));
    let mut out = vec![0u8; text.len()];
    let n = outscript::base64::decode_to_slice(&text[3..], &mut out).unwrap();
    out.truncate(n);
    out
}

/// `(message, address, witness script hex, signature)` -- the single-input full vectors
/// for the scripts this reads.
const FULL: &[(&str, &str, &str)] = &[
    (
        "KLE5MMJBTNF4AVZXIO3GIL5UWF",
        "bc1qrqtlzcq86850yzgsyq9sssawx2qxlx5yq3xpkd",
        "fulAgAAAAABAUrfzHHOLAKmgCIFSTT3krp+cQxj1BDPBN4GBg3tRmFXAAAAAADgBwAAAQAAAAAAAAAAAWoCSDBFAiEAjYj85zyhQKa9DbMO0reDwdhkNwKJkF3q2qFcijXDgMUCIAaQ75s3fwqrCeYIUJugLvhxZFxQIVquGN90vIKCW3QLASEDMurnDzvc0zABUwVwCADfGXoDx/M3SQnYt7e3IHDoU3PgBwAA",
    ),
    (
        "XQMVC3YR6AOGZIHLSUQ2NSSBI2",
        "bc1pve87s3l2levjmhetzr2f9xvep3y266xty0hnefmyv8tkxc3e4qssll2kdu",
        "fulAgAAAAABAROFPNY6Zt8hFK0YQq5Wb6wk/CnUYEPtQ0HTHDyzNROrAAAAAADgBwAAAQAAAAAAAAAAAWoBQNRdLOo5XZY0SBqAsLZNr/z3Bqrmo3OxVn7e4tD/OOD4H9U/L1unq5Nmdz+S1w7SHtt46bFwnd8xnRVan8BofFfgBwAA",
    ),
    (
        "EMYGZHEY3LIANYKCR7XJF3NMFQ",
        "32Utb7Seg6EXq7UesMNJXhQ1gdohYNyzQ9",
        "fulAgAAAAABAe5xLNMlYQH4OGjJ3h4lqQaVp0Cic7mwxkvyWswqFMXeAAAAABcWABSy/hpDH/KLAi4x25Tmb2UaO1xtWeAHAAABAAAAAAAAAAABagJHMEQCIDEleqb0n1R5c21TGkWRXNFae98wbwI0QOyh/YmRuQX1AiAcv1MhyTzPOVgZ1VIwuu0tDxrVJUHK8lhOUOXpsZnGwwEhAsjeDEoWX8hvEC8A/692yGQsPh6JBO8Zf4aITEQsKAcJ4AcAAA==",
    ),
    (
        "QXYOWYWO7ZGJC4OPNC367HBUQF",
        "bc1qg8r3cl47rrr75dwvr7jhzdukptegnmq8v0nmjd2jdn4qvlczqkts0rqtav",
        "fulAgAAAAABAXshuDM6YKy1LClwk1ZOM5egX7RTFPOCvtxJkYFYk/FEAAAAAADgBwAAAQAAAAAAAAAAAWoEAEgwRQIhAI9uOxvqmBV0pldOoKWnSYhjobNhP4F+gxO0QlOdGtxFAiBROcNruLigZE4lj1DJEh8yGrqS00MeW463EO78TsaRFgFIMEUCIQCAhIqYuU4wDA2AYsU+QDVyucH4Tm/NSDP2+txyPMKEkAIgfuGlSh7ncxb2yV3S3aOF5uwHGqtIZjp3b4HW0d35EckBR1IhAkT3y4QqTOTzUs5AYq5eCl1g1vqgsHtiwgY0hKpSl7vOIQI07tYZDvxHcWuVOgULVj+LK1I63eqVWuQzUd0qkqpJ9FKu4AcAAA==",
    ),
    (
        "3VJANNKSXPLND6YRKG6CUEUZXX",
        "bc1q8vy6jhfe8ca0uruvr4aqkjk75dpg5m30rnwatg60uhya00dhlyqs2xvt2a",
        "fulAgAAAAABAU2vSmP5XYqecVKygaRRribDp5piMoVxUkxUnFSff8kRAAAAAADgBwAAAQAAAAAAAAAAAWoFAEgwRQIhAKBSw74gHlx272y4RzyU/ap7iNO5rmB6XXgBOy3Qsc/EAiBUnSrF/XhvuvAwi/mMme0JDpuCvl+oZ9C4f3H8OemXCAFIMEUCIQDK3wH0l2AvJ5FZ923ZMJkY1z0MBh1Nee9wjK7tVxFz5gIgdC1XBD/IdBPtx1xmyvSFhbIJlvnz98fPTm50K6KaXpEBSDBFAiEAyP3nXTzXrTmzq54x8jAY02ERHycEYzYqT9cpRTeEWg4CIHxRk3e3oPrM9oCZ8xcgNQ3lRhyc+G0qdDIl6qa8SN4AAWlTIQIlBvEshNuT7T6Ja01YgHs0G31etR15oRdjg2JJs6Hf5CEDBbFTr8NwzY8uUi5qQ1z16XJjdr9VZ1LBpDcElWryIwUhAkLyDL4FQMvj0TI89hZZ8ja4nCrlk9235CCAWXmU0hbgU67gBwAA",
    ),
    (
        "NQVRV3DJYLKBANM3OPTNBULEU3",
        "3PGZjFkYBL1m9WBWkWbCW5FEFTaS1Hj4EB",
        "fulAgAAAAABAVscdBvYDFN98A//Rt/fAWcN7mdM0x2yWzBjC33c7X5HAAAAACMiACDkkR/DseXy+GXBPtxHvHehUjHt+9XjRmZAgxuuomAC4eAHAAABAAAAAAAAAAABagQASDBFAiEA47YK5XeIGBMQC9bCfWb+IIfirIWlqAzQVc6E/lgBPZICIA0k/EO2t3YhqmYR5WdXUBGgAzR+IqgZ5/mxvj+4UoDTAUgwRQIhAPCIVZCSoIaOjY9BzYIXWEvbhpOl4JR88p/xYVoZObd6AiADyJXNqpDg/Lc2viPX14N2d0jQdEjamY4SmiU7GNbIOgFHUiED+4JBU/wACiE8VFbQF4DR8pKgz7+8X2+PHccTcGxVGdEhA9uIzp+4CB5QRgvrN1OXQbBmfW8kOd0cooPWMYJCHBCxUq7gBwAA",
    ),
];

#[test]
fn every_published_full_signature_verifies() {
    for (message, address, sig) in FULL {
        let script = script_of(address);
        assert_eq!(
            verify_armoured(message.as_bytes(), &script, sig),
            Ok(()),
            "{message}"
        );
        let mut scratch = [0u8; MAX_MULTISIG_TX];
        assert_eq!(
            verify_armoured_in(message.as_bytes(), &script, sig, &mut scratch),
            Ok(Variant::Full),
            "{message}"
        );
    }
}

/// The vectors' `to_sign`s carry version 2, lock time 2016 and sequence 2016: read as
/// found, and part of what is signed.
#[test]
fn a_full_signature_is_hashed_with_the_fields_it_was_written_with() {
    let (message, address, sig) = FULL[0];
    let bytes = dearmour_full(sig);
    let tx = ToSignBytes::parse(&bytes).unwrap();
    assert_eq!(tx.version(), 2);
    assert_eq!(tx.locktime(), 2016);
    assert_eq!(tx.input(0).unwrap().sequence, 2016);

    // Rewriting the lock time changes what was signed, so the same witness no longer
    // verifies: the verifier is not silently assuming the default transaction.
    let mut changed = bytes.clone();
    let n = changed.len();
    changed[n - 4..].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(
        verify_full(message.as_bytes(), &script_of(address), &changed),
        Err(Error::Invalid)
    );
}

/// `(message, address, signature)` from the `error` list, for the scripts this reads:
/// the signature of one row offered with another's message, or another's address.
const BAD: &[(&str, &str, &str)] = &[
    (
        "VENQMXVEGEJAAXJV5V24T6G5UU",
        "bc1qrqtlzcq86850yzgsyq9sssawx2qxlx5yq3xpkd",
        "fulAgAAAAABAUrfzHHOLAKmgCIFSTT3krp+cQxj1BDPBN4GBg3tRmFXAAAAAADgBwAAAQAAAAAAAAAAAWoCSDBFAiEAjYj85zyhQKa9DbMO0reDwdhkNwKJkF3q2qFcijXDgMUCIAaQ75s3fwqrCeYIUJugLvhxZFxQIVquGN90vIKCW3QLASEDMurnDzvc0zABUwVwCADfGXoDx/M3SQnYt7e3IHDoU3PgBwAA",
    ),
    (
        "KLE5MMJBTNF4AVZXIO3GIL5UWF",
        "bc1q55chmwm4x8aeye0h9c0mryra2ly8k8fh3scqgj",
        "fulAgAAAAABAUrfzHHOLAKmgCIFSTT3krp+cQxj1BDPBN4GBg3tRmFXAAAAAADgBwAAAQAAAAAAAAAAAWoCSDBFAiEAjYj85zyhQKa9DbMO0reDwdhkNwKJkF3q2qFcijXDgMUCIAaQ75s3fwqrCeYIUJugLvhxZFxQIVquGN90vIKCW3QLASEDMurnDzvc0zABUwVwCADfGXoDx/M3SQnYt7e3IHDoU3PgBwAA",
    ),
    (
        "P2RQWD264CW7Z5ZSSSDRW2JEDB",
        "bc1pve87s3l2levjmhetzr2f9xvep3y266xty0hnefmyv8tkxc3e4qssll2kdu",
        "fulAgAAAAABAROFPNY6Zt8hFK0YQq5Wb6wk/CnUYEPtQ0HTHDyzNROrAAAAAADgBwAAAQAAAAAAAAAAAWoBQNRdLOo5XZY0SBqAsLZNr/z3Bqrmo3OxVn7e4tD/OOD4H9U/L1unq5Nmdz+S1w7SHtt46bFwnd8xnRVan8BofFfgBwAA",
    ),
    (
        "XQMVC3YR6AOGZIHLSUQ2NSSBI2",
        "bc1py2f3exluva2yqa877qnsj3vk4lm8yatw0up4fhrx04hf8ns87weswck94p",
        "fulAgAAAAABAROFPNY6Zt8hFK0YQq5Wb6wk/CnUYEPtQ0HTHDyzNROrAAAAAADgBwAAAQAAAAAAAAAAAWoBQNRdLOo5XZY0SBqAsLZNr/z3Bqrmo3OxVn7e4tD/OOD4H9U/L1unq5Nmdz+S1w7SHtt46bFwnd8xnRVan8BofFfgBwAA",
    ),
    (
        "CPVOBEXDTFAXS6N4YASD753CZV",
        "32Utb7Seg6EXq7UesMNJXhQ1gdohYNyzQ9",
        "fulAgAAAAABAe5xLNMlYQH4OGjJ3h4lqQaVp0Cic7mwxkvyWswqFMXeAAAAABcWABSy/hpDH/KLAi4x25Tmb2UaO1xtWeAHAAABAAAAAAAAAAABagJHMEQCIDEleqb0n1R5c21TGkWRXNFae98wbwI0QOyh/YmRuQX1AiAcv1MhyTzPOVgZ1VIwuu0tDxrVJUHK8lhOUOXpsZnGwwEhAsjeDEoWX8hvEC8A/692yGQsPh6JBO8Zf4aITEQsKAcJ4AcAAA==",
    ),
    (
        "EMYGZHEY3LIANYKCR7XJF3NMFQ",
        "3QMEQj2LTUtKKR1UatUK44z1NwrWrcVSGh",
        "fulAgAAAAABAe5xLNMlYQH4OGjJ3h4lqQaVp0Cic7mwxkvyWswqFMXeAAAAABcWABSy/hpDH/KLAi4x25Tmb2UaO1xtWeAHAAABAAAAAAAAAAABagJHMEQCIDEleqb0n1R5c21TGkWRXNFae98wbwI0QOyh/YmRuQX1AiAcv1MhyTzPOVgZ1VIwuu0tDxrVJUHK8lhOUOXpsZnGwwEhAsjeDEoWX8hvEC8A/692yGQsPh6JBO8Zf4aITEQsKAcJ4AcAAA==",
    ),
    (
        "OANRY57VZNHOXZNYGCGZM5ADYG",
        "bc1qg8r3cl47rrr75dwvr7jhzdukptegnmq8v0nmjd2jdn4qvlczqkts0rqtav",
        "fulAgAAAAABAXshuDM6YKy1LClwk1ZOM5egX7RTFPOCvtxJkYFYk/FEAAAAAADgBwAAAQAAAAAAAAAAAWoEAEgwRQIhAI9uOxvqmBV0pldOoKWnSYhjobNhP4F+gxO0QlOdGtxFAiBROcNruLigZE4lj1DJEh8yGrqS00MeW463EO78TsaRFgFIMEUCIQCAhIqYuU4wDA2AYsU+QDVyucH4Tm/NSDP2+txyPMKEkAIgfuGlSh7ncxb2yV3S3aOF5uwHGqtIZjp3b4HW0d35EckBR1IhAkT3y4QqTOTzUs5AYq5eCl1g1vqgsHtiwgY0hKpSl7vOIQI07tYZDvxHcWuVOgULVj+LK1I63eqVWuQzUd0qkqpJ9FKu4AcAAA==",
    ),
    (
        "QXYOWYWO7ZGJC4OPNC367HBUQF",
        "bc1qan5sys8u4cpvgutt70fn2tgweu7as9aw0slljuz86x4nyr8myvjsgz3q2v",
        "fulAgAAAAABAXshuDM6YKy1LClwk1ZOM5egX7RTFPOCvtxJkYFYk/FEAAAAAADgBwAAAQAAAAAAAAAAAWoEAEgwRQIhAI9uOxvqmBV0pldOoKWnSYhjobNhP4F+gxO0QlOdGtxFAiBROcNruLigZE4lj1DJEh8yGrqS00MeW463EO78TsaRFgFIMEUCIQCAhIqYuU4wDA2AYsU+QDVyucH4Tm/NSDP2+txyPMKEkAIgfuGlSh7ncxb2yV3S3aOF5uwHGqtIZjp3b4HW0d35EckBR1IhAkT3y4QqTOTzUs5AYq5eCl1g1vqgsHtiwgY0hKpSl7vOIQI07tYZDvxHcWuVOgULVj+LK1I63eqVWuQzUd0qkqpJ9FKu4AcAAA==",
    ),
    (
        "UZQGB4YTYIS3PRT3UUOCO3YCX3",
        "bc1q8vy6jhfe8ca0uruvr4aqkjk75dpg5m30rnwatg60uhya00dhlyqs2xvt2a",
        "fulAgAAAAABAU2vSmP5XYqecVKygaRRribDp5piMoVxUkxUnFSff8kRAAAAAADgBwAAAQAAAAAAAAAAAWoFAEgwRQIhAKBSw74gHlx272y4RzyU/ap7iNO5rmB6XXgBOy3Qsc/EAiBUnSrF/XhvuvAwi/mMme0JDpuCvl+oZ9C4f3H8OemXCAFIMEUCIQDK3wH0l2AvJ5FZ923ZMJkY1z0MBh1Nee9wjK7tVxFz5gIgdC1XBD/IdBPtx1xmyvSFhbIJlvnz98fPTm50K6KaXpEBSDBFAiEAyP3nXTzXrTmzq54x8jAY02ERHycEYzYqT9cpRTeEWg4CIHxRk3e3oPrM9oCZ8xcgNQ3lRhyc+G0qdDIl6qa8SN4AAWlTIQIlBvEshNuT7T6Ja01YgHs0G31etR15oRdjg2JJs6Hf5CEDBbFTr8NwzY8uUi5qQ1z16XJjdr9VZ1LBpDcElWryIwUhAkLyDL4FQMvj0TI89hZZ8ja4nCrlk9235CCAWXmU0hbgU67gBwAA",
    ),
    (
        "3VJANNKSXPLND6YRKG6CUEUZXX",
        "bc1qma94rw0f5t4l64wc6xfrjuuatqn6klcwmxvls86y9k4rjvva40wqr8u0cq",
        "fulAgAAAAABAU2vSmP5XYqecVKygaRRribDp5piMoVxUkxUnFSff8kRAAAAAADgBwAAAQAAAAAAAAAAAWoFAEgwRQIhAKBSw74gHlx272y4RzyU/ap7iNO5rmB6XXgBOy3Qsc/EAiBUnSrF/XhvuvAwi/mMme0JDpuCvl+oZ9C4f3H8OemXCAFIMEUCIQDK3wH0l2AvJ5FZ923ZMJkY1z0MBh1Nee9wjK7tVxFz5gIgdC1XBD/IdBPtx1xmyvSFhbIJlvnz98fPTm50K6KaXpEBSDBFAiEAyP3nXTzXrTmzq54x8jAY02ERHycEYzYqT9cpRTeEWg4CIHxRk3e3oPrM9oCZ8xcgNQ3lRhyc+G0qdDIl6qa8SN4AAWlTIQIlBvEshNuT7T6Ja01YgHs0G31etR15oRdjg2JJs6Hf5CEDBbFTr8NwzY8uUi5qQ1z16XJjdr9VZ1LBpDcElWryIwUhAkLyDL4FQMvj0TI89hZZ8ja4nCrlk9235CCAWXmU0hbgU67gBwAA",
    ),
    (
        "FOQHOIFXJVPFSGGBRLAX53D6R2",
        "3PGZjFkYBL1m9WBWkWbCW5FEFTaS1Hj4EB",
        "fulAgAAAAABAVscdBvYDFN98A//Rt/fAWcN7mdM0x2yWzBjC33c7X5HAAAAACMiACDkkR/DseXy+GXBPtxHvHehUjHt+9XjRmZAgxuuomAC4eAHAAABAAAAAAAAAAABagQASDBFAiEA47YK5XeIGBMQC9bCfWb+IIfirIWlqAzQVc6E/lgBPZICIA0k/EO2t3YhqmYR5WdXUBGgAzR+IqgZ5/mxvj+4UoDTAUgwRQIhAPCIVZCSoIaOjY9BzYIXWEvbhpOl4JR88p/xYVoZObd6AiADyJXNqpDg/Lc2viPX14N2d0jQdEjamY4SmiU7GNbIOgFHUiED+4JBU/wACiE8VFbQF4DR8pKgz7+8X2+PHccTcGxVGdEhA9uIzp+4CB5QRgvrN1OXQbBmfW8kOd0cooPWMYJCHBCxUq7gBwAA",
    ),
    (
        "NQVRV3DJYLKBANM3OPTNBULEU3",
        "3DA7VZKYcuiaJFsDnzWjBDvh4VhBFZk6jg",
        "fulAgAAAAABAVscdBvYDFN98A//Rt/fAWcN7mdM0x2yWzBjC33c7X5HAAAAACMiACDkkR/DseXy+GXBPtxHvHehUjHt+9XjRmZAgxuuomAC4eAHAAABAAAAAAAAAAABagQASDBFAiEA47YK5XeIGBMQC9bCfWb+IIfirIWlqAzQVc6E/lgBPZICIA0k/EO2t3YhqmYR5WdXUBGgAzR+IqgZ5/mxvj+4UoDTAUgwRQIhAPCIVZCSoIaOjY9BzYIXWEvbhpOl4JR88p/xYVoZObd6AiADyJXNqpDg/Lc2viPX14N2d0jQdEjamY4SmiU7GNbIOgFHUiED+4JBU/wACiE8VFbQF4DR8pKgz7+8X2+PHccTcGxVGdEhA9uIzp+4CB5QRgvrN1OXQbBmfW8kOd0cooPWMYJCHBCxUq7gBwAA",
    ),
];

#[test]
fn every_published_bad_full_signature_is_refused() {
    for (message, address, sig) in BAD {
        assert_eq!(
            verify_armoured(message.as_bytes(), &script_of(address), sig),
            Err(Error::Invalid),
            "{message} for {address}"
        );
    }
}

/// The scripts this does not read are refused as unsupported, never accepted: a P2PKH
/// `to_sign` (a legacy sighash), a bare `sh(multi)`, and the two time-lock scripts.
#[test]
fn the_scripts_without_an_interpreter_here_are_refused_as_such() {
    let cases: &[(&str, &str, &str)] = &[
        (
            "MOISC5NCQ42ADH2SUXLELUJOWH",
            "13vU5PUSuArDXJdCWZvUFEbgJ2wcmtSJWn",
            "fulAgAAAAGn3Z6t/gsHNyHdgZTOVro0Hej+qbd/ilU1ACalKoHX3gAAAABqRzBEAiB+8t/tm8Jm6zYv9JGZZVlAUjmqg7ZglIA39U+bim8EKQIgDv3E5cHOagN+xYgN3ZQjTYlAJp/WyslwJWuFP1TmM3IBIQJcPK2h9SY+Ki1oussvHnMdFAhJgsYBFPl+rNcMv9P1ROAHAAABAAAAAAAAAAABauAHAAA=",
        ),
        (
            "7OKFLKRXSP6J42VQOMSG7MVXEP",
            "3Nye4j1GUFqCEBR3do2KEFZAs9oLe8NZ6X",
            "fulAgAAAAEvAyd4zsoz8gcVU5H19GLYokTAN5PxuKCBlEPjODJ86gAAAADaAEcwRAIgT6rcfxgCmG6b3DpzNV6UG0jiCQGclG9sfiSpV45HDXMCIGgtqjFBuJ7rbi+cgnG0TZiKZaxMk0KI+gQd0pHJfEYCAUgwRQIhANCvCLjGMuZMzH+nCEkNhWhR45T6QRYMLin8utpuF9r1AiBTjG2NLjkre7ec+HPg8UUhK1jL1vgq7YKjq5ROv+h07AFHUiEDhKjcb/Pv1/7AYutzOXwgec08wwD/VwiPm58Lc0xjohghAhycjpwdBuP33orQXAH1CAsrgSkuspxM2+FPQ4OCVhQWUq7gBwAAAQAAAAAAAAAAAWrgBwAA",
        ),
        (
            "AY2VOQOXYI5CN2EHZKLOX7ZI37",
            "bc1p6vffkx7vcyezrjq7pg9qqdjv7vmtanfhk8ukwsn4syejwmarmhxqp0rw5x",
            "fulAgAAAAABAaza7/ukfX9ZdxCUvK7CPJgADDdPdF7ikXVKWctd5EHrAAAAAADgBwAAAQAAAAAAAAAAAWoEQPvuT0enYGwsab2lsPZU0U3OcRkGng+o/PAt4QU2lc8hG7lTUmflkt0To+eoipv2vptf0TlGOBCsKU5xE3kXKcMAS2MgrYfXhOkh0CvwuJpB+O3tal2ECfO0v7k1/A4PTlGcQiBnAuAHsnUgJjLn4tl5ytgC8CNTyITXmg4rx9ctxPedwRMPEBvfoUBorCHBJjLn4tl5ytgC8CNTyITXmg4rx9ctxPedwRMPEBvfoUDgBwAA",
        ),
        (
            "MGKMA2MJUBDHT55J7MHOLM7UPE",
            "bc1qhqcmw7ud03vqde3pe6hzajaylhucmlatrkcztzpnk8vpgvhg9dzq5ydark",
            "fulAgAAAAABAYYJeOOOi3c33O+dholAwiF51Amy/E0qIf3ew2vFtDtTAAAAAADgBwAAAQAAAAAAAAAAAWoDSDBFAiEA64MwD2HkJjPLPAc2u5ia6ZdwCVO3okzVqGPEXnuJGZQCIE27BGOBQTdwJ2M/Wdsm6nFVunqaj+xZBSG/g/64FMbtAQBNYyEDrYfXhOkh0CvwuJpB+O3tal2ECfO0v7k1/A4PTlGcQiBnAuAHsnUhA4ZGGvodKgqeg/ZYffm6miaKaG57VkCSjmmRprCa+ulyaKzgBwAA",
        ),
    ];
    for (message, address, sig) in cases {
        let got = verify_armoured(message.as_bytes(), &script_of(address), sig);
        assert!(
            matches!(got, Err(Error::UnsupportedScript) | Err(Error::Malformed)),
            "{address}: {got:?}"
        );
    }
}

/// `(message, WIF, address)` for the single-key kinds this signs in the full variant.
const SIGNERS: &[(&str, &str, &str, AddressKind)] = &[
    (
        "KLE5MMJBTNF4AVZXIO3GIL5UWF",
        "L35XkdYZZ9u9hj6hqDzc3iuRGGXx1GhmaMMr6sVAMMrd4AKBkhUp",
        "bc1qrqtlzcq86850yzgsyq9sssawx2qxlx5yq3xpkd",
        AddressKind::P2wpkh,
    ),
    (
        "XQMVC3YR6AOGZIHLSUQ2NSSBI2",
        "L5CuoheLtRPk2uVtg2Ph55QpJ3Q5yvsM3hm3ThuGdCuBwA1KS6ua",
        "bc1pve87s3l2levjmhetzr2f9xvep3y266xty0hnefmyv8tkxc3e4qssll2kdu",
        AddressKind::P2tr,
    ),
    (
        "EMYGZHEY3LIANYKCR7XJF3NMFQ",
        "L1n3XXc2AAVq8puHyQNL9NmVNRDUox1ENeuk7muALGrEo85wGQag",
        "32Utb7Seg6EXq7UesMNJXhQ1gdohYNyzQ9",
        AddressKind::P2shP2wpkh,
    ),
];

#[test]
fn a_full_signature_this_makes_verifies_for_the_vector_address_and_nowhere_else() {
    let kw = KeyWork::host();
    for (message, key, address, kind) in SIGNERS {
        let script = script_of(address);
        let sig = sign_full(message.as_bytes(), &wif(key), *kind, &kw).unwrap();
        assert_eq!(
            verify_full(message.as_bytes(), &script, sig.as_bytes()),
            Ok(()),
            "{address}"
        );
        // Through the armour too, and the file says which variant it is.
        let mut text = [0u8; MAX_FULL_ARMOURED];
        let n = sig.armour(&mut text).unwrap();
        let text = core::str::from_utf8(&text[..n]).unwrap();
        assert!(text.starts_with("ful"));
        assert_eq!(verify_armoured(message.as_bytes(), &script, text), Ok(()));
        // Not for another message, and not for another address of the same kind.
        assert_eq!(
            verify_full(b"another message", &script, sig.as_bytes()),
            Err(Error::Invalid)
        );
        let other = match kind {
            AddressKind::P2wpkh => "bc1q55chmwm4x8aeye0h9c0mryra2ly8k8fh3scqgj",
            AddressKind::P2tr => "bc1py2f3exluva2yqa877qnsj3vk4lm8yatw0up4fhrx04hf8ns87weswck94p",
            _ => "3QMEQj2LTUtKKR1UatUK44z1NwrWrcVSGh",
        };
        assert_eq!(
            verify_full(message.as_bytes(), &script_of(other), sig.as_bytes()),
            Err(Error::Invalid)
        );
        // The witness stack of this `to_sign` is also a valid *simple* signature where
        // the address has one: the two variants are one proof in two envelopes.
        if *kind != AddressKind::P2shP2wpkh {
            let tx = ToSignBytes::parse(sig.as_bytes()).unwrap();
            let inp = tx.input(0).unwrap();
            assert_eq!(
                crate::bip322::verify(message.as_bytes(), &script, inp.witness),
                Ok(())
            );
        }
    }
    // P2PKH has the legacy format and no full signature here.
    assert_eq!(
        sign_full(b"x", &wif(SIGNERS[0].1), AddressKind::P2pkh, &kw),
        Err(Error::UnsupportedKind)
    );
}

#[test]
fn a_nested_segwit_signature_carries_its_redeem_script_in_the_script_sig() {
    let kw = KeyWork::host();
    let (message, key, address, kind) = SIGNERS[2];
    let sig = sign_full(message.as_bytes(), &wif(key), kind, &kw).unwrap();
    let tx = ToSignBytes::parse(sig.as_bytes()).unwrap();
    let inp = tx.input(0).unwrap();
    // The vector file publishes the redeem script this address commits to.
    assert_eq!(inp.script_sig[0], 22);
    assert_eq!(
        inp.script_sig[1..],
        unhex("0014b2fe1a431ff28b022e31db94e66f651a3b5c6d59")[..]
    );
    // The same witness offered without the scriptSig is not a signature for the address.
    let mut bare = [0u8; MAX_SINGLE_TX];
    let n = write_to_sign(&inp.txid, &[], &decoded(inp.witness), &mut bare).unwrap();
    assert_eq!(
        verify_full(message.as_bytes(), &script_of(address), &bare[..n]),
        Err(Error::UnsupportedKind)
    );
}

fn decoded(witness: &[u8]) -> Vec<&[u8]> {
    decode_witness(witness).unwrap().items().to_vec()
}

// --- multisig ---------------------------------------------------------------------

/// `(message, WIFs, address, witness script hex, kind, published signature)`.
const MULTISIG: &[(&str, &[&str], &str, &str, multisig::Kind, &str)] = &[
    (
        "QXYOWYWO7ZGJC4OPNC367HBUQF",
        &[
            "L14bn1tSDZUKYLLiTConCRHbqzGef8eqB2tU5PBPFBkyPLUyob7V",
            "KyJnWYygb7P2P8khWyDMW9yFGA3dUe7kpkEHtLbzY6cfvvn9T5CS",
        ],
        "bc1qg8r3cl47rrr75dwvr7jhzdukptegnmq8v0nmjd2jdn4qvlczqkts0rqtav",
        "52210244f7cb842a4ce4f352ce4062ae5e0a5d60d6faa0b07b62c2063484aa5297bbce210234eed6190efc47716b953a050b563f8b2b523addea955ae43351dd2a92aa49f452ae",
        multisig::Kind::P2wsh,
        FULL[3].2,
    ),
    (
        "3VJANNKSXPLND6YRKG6CUEUZXX",
        &[
            "L5QcX4UxGQByfgW6YTVWovLUxSSWSyQksGNfAJAhP36hTRRGWyiU",
            "Kzp3Vm4kEdakPrfPfGDq3SEeSeBhX3GPwqacMf1wLFLPEZaMjy57",
            "L3xZwreL3S4C5V3wLaNYSFTsZiC2YW7ao94y2omZvpkBEyP5y3PY",
        ],
        "bc1q8vy6jhfe8ca0uruvr4aqkjk75dpg5m30rnwatg60uhya00dhlyqs2xvt2a",
        "5321022506f12c84db93ed3e896b4d58807b341b7d5eb51d79a11763836249b3a1dfe4210305b153afc370cd8f2e522e6a435cf5e9726376bf556752c1a43704956af22305210242f20cbe0540cbe3d1323cf61659f236b89c2ae593ddb7e42080597994d216e053ae",
        multisig::Kind::P2wsh,
        FULL[4].2,
    ),
    (
        "NQVRV3DJYLKBANM3OPTNBULEU3",
        &[
            "L246N8J5x5ehwjoz97ZfHXBCELxGcK2jqRFinReMBcRnqH1X4zdc",
            "L1WzdMN476EHhwsDLHJwVHZKrwVLFFsdvNoZFsZVk2Mb5rKst2Et",
        ],
        "3PGZjFkYBL1m9WBWkWbCW5FEFTaS1Hj4EB",
        "522103fb824153fc000a213c5456d01780d1f292a0cfbfbc5f6f8f1dc713706c5519d12103db88ce9fb8081e50460beb37539741b0667d6f2439dd1ca283d63182421c10b152ae",
        multisig::Kind::P2shP2wsh,
        FULL[5].2,
    ),
];

/// Each cosigner signs alone; the partials say how many more they need; merged in any
/// order, the result verifies for the vector's address.
#[test]
fn cosigners_sign_separately_and_the_merged_signature_verifies() {
    let kw = KeyWork::host();
    for (message, keys, address, script_hex, kind, _) in MULTISIG {
        let m = message.as_bytes();
        let script = script_of(address);
        let ws = unhex(script_hex);
        let n = keys.len() as u8;
        let mut partials = Vec::new();
        for key in *keys {
            let p = sign_multisig_partial(m, *kind, &ws, &wif(key), &kw).unwrap();
            assert_eq!(
                verify_full(m, &script, p.as_bytes()),
                Err(Error::NeedsCosigners { have: 1, need: n }),
                "{address}"
            );
            partials.push(p);
        }
        // Merged last-first, so the order the signatures arrive in is not the order the
        // script wants them in.
        let mut merged = partials.last().unwrap().as_bytes().to_vec();
        for p in partials.iter().rev().skip(1) {
            let (next, short) = merge(m, &script, &merged, p.as_bytes()).unwrap();
            merged = next.as_bytes().to_vec();
            let _ = short;
        }
        assert_eq!(verify_full(m, &script, &merged), Ok(()), "{address}");
        assert_eq!(verify_full(b"other", &script, &merged), Err(Error::Invalid));
    }
}

/// Split the vector's own witness into one-signature partials and merge them back: the
/// bytes have to come out exactly as published, which pins the key ordering and the
/// preservation of the vector's version, sequence and lock time.
#[test]
fn merging_reproduces_the_published_multisig_signature_byte_for_byte() {
    for (message, _, address, _, _, published) in MULTISIG {
        let m = message.as_bytes();
        let script = script_of(address);
        let bytes = dearmour_full(published);
        let tx = ToSignBytes::parse(&bytes).unwrap();
        let inp = tx.input(0).unwrap();
        let items = decoded(inp.witness);
        let ws = *items.last().unwrap();
        let sigs = &items[1..items.len() - 1];
        let partial = |sig: &[u8]| -> Vec<u8> {
            let mut buf = [0u8; MAX_MULTISIG_TX];
            let n = write_to_sign_with(
                tx.version(),
                &inp.txid,
                inp.sequence,
                inp.script_sig,
                &[&[], sig, ws],
                tx.locktime(),
                &mut buf,
            )
            .unwrap();
            buf[..n].to_vec()
        };
        // Reverse order, so the merge has to sort them.
        let mut merged = partial(sigs[sigs.len() - 1]);
        for sig in sigs.iter().rev().skip(1) {
            let (next, short) = merge(m, &script, &merged, &partial(sig)).unwrap();
            merged = next.as_bytes().to_vec();
            if core::ptr::eq(sig, &sigs[0]) {
                assert_eq!(short, None);
            }
        }
        assert_eq!(merged, bytes, "{address}");
    }
}

#[test]
fn a_key_the_script_does_not_name_cannot_sign_for_it() {
    let kw = KeyWork::host();
    let (message, _, _, script_hex, kind, _) = MULTISIG[0];
    let stranger = wif(SIGNERS[0].1);
    assert_eq!(
        sign_multisig_partial(message.as_bytes(), kind, &unhex(script_hex), &stranger, &kw),
        Err(Error::BadKey)
    );
}

/// The simple-variant P2WSH vector from `basic-test-vectors.json` -- a 3-of-3 -- now
/// verifies, since the witness carries the script and this reads `multi`.
#[test]
fn the_simple_multisig_vector_verifies_too() {
    let script = script_of("bc1qp0ahvfh83088w49k405szqgg4f3pptr7p2g06tdxfjcd40z4lh4q95lsz9");
    let sig = "smpBQBHMEQCIFX9aaqPJWq2Ff2kpen5bFDTid+ehgUOpHV0LfjncXy4AiA3GNicF7aKPzdpa9PCpmaYQs3pHd+qbvvhXdxOCKCAMAFIMEUCIQD/ELXg6CNYyUQijCg96JtgvgjZb9dsl1Ctof4QAeyTcQIgVM/1AAblFl/DCt6A1gJg+T/i2qU5SQD09+chFJzolRwBSDBFAiEAlqRfSFyWNVQhvaCnmeV5tyneiCWMTcFbuujoD/pFa3wCIGnZjfQb8NolSYq9asV+ZeBSkCGHJcqnaV4JYS5MYPEGAWlTIQJ1aLEfEi/4p7wcV+XHZCBVvGGJZ7L3v+jhH+mZA8lN0yECCovfec+kIdllXpKCgA8RX/HZ2x5yHOtCSKP8/sf6pnwhAwxSng6kCgCXXSAmJOOZFdr3vdK3HzGqCFloOHgc5fM6U64=";
    let message = "This will be a p2wsh 3-of-3 multisig BIP 322 signed message";
    assert_eq!(verify_armoured(message.as_bytes(), &script, sig), Ok(()));
    assert_eq!(
        verify_armoured(b"This is not the message that was signed", &script, sig),
        Err(Error::Invalid)
    );
}

// --- proof of funds ---------------------------------------------------------------

/// The taproot proof of funds from `generated-test-vectors.json`: three P2TR outputs of
/// 345 678 sats each, proven by the address's key with version 2, lock time 123 and
/// sequence 456.
const POF_P2TR: (&str, &str, &str) = (
    "FUYMQWKYGS7HJEN7YFEZU5SNR5",
    "bc1pk3vq3wpn4txexwq4dj0k2dugzp6kfwllvs89w49cvtk3j2cndcds3l9kw9",
    "pofcHNidP8BALgCAAAABDzMFysa2DX0k4ZymoVfzNzTIL3gsWlu03HcfI+NxhOxAAAAAADIAQAAVd4moQMhq/rd+2ecRsJ0Xeg6/SdhA+owjzyzg/Fqd/oAAAAAAAAAAABuZFRaqjWRO6kKy5hrEHAg+T12/Iuz+FZBwwMt/FQvkgAAAAAAAAAAAG5kVFqqNZE7qQrLmGsQcCD5PXb8i7P4VkHDAy38VC+SAQAAAAAAAAAAAQAAAAAAAAAAAWp7AAAAAAEBKwAAAAAAAAAAIlEgtFgIuDOqzZM4FWyfZTeIEHVku/9kDldUuGLtGSsTbhsBCEIBQKoTEBqEPkib1fLnELbmsbDVlmWGzOdiiN/XJefU3tF9AEi7PszYEPguomxXp7X2rL0dP0xkV6LbBcVz7oAEeKkAAQErTkYFAAAAAAAiUSB4i5DCtSPHOkI30E30ayMoWL47vA5l2NBJp/pZ1XGduAEIQgFAic0muhAJNc4ZlRWeJGRgkN+oE/ptV4Znyli19VAnSsHM/Pb9Mp02dd3zk3RmuT6VgjBxdJn2yURGKOka3l9cugABAStORgUAAAAAACJRIMoNyg9Pai/pn4PHTOMEsDHkuUAHt5riqU81NVVj+fXKAQhCAUCL3W2Jh3ImNRSpbp0bLe+rBE4GJw5AjwJEhakHsm83YfuQKeY1syBFrmNV2ZvLv8R8uTLcmkJ1s/lWUxZ9o4qJAAEBK05GBQAAAAAAIlEgXCutuyDOvc4hiADdov7VmOUfq4ww6HES7JZ6NAucMJkBCEIBQDqu/4oik+J+eAbvUhzzuBkoVoOgD5RySjpvJQqTKNieBda8dMTkH2avx6ghs7zd6puujlBCQw3r/NiG4VX7wAEAAA==",
);

#[test]
fn the_published_taproot_proof_of_funds_verifies_and_says_what_it_proves() {
    let (message, address, sig) = POF_P2TR;
    let script = script_of(address);
    let mut scratch = [0u8; 2048];
    assert_eq!(
        verify_armoured_in(message.as_bytes(), &script, sig, &mut scratch),
        Ok(Variant::Proof {
            utxos: 3,
            total: 3 * 345_678
        })
    );
    // Another message: the same PSBT proves nothing about it.
    assert_eq!(
        verify_armoured_in(b"FUYMQWKYGS7HJEN7YFEZU5SNR4", &script, sig, &mut scratch),
        Err(Error::Invalid)
    );
    // The fixed-size entry point has no room for a PSBT and says so rather than
    // guessing.
    assert_eq!(
        verify_armoured(message.as_bytes(), &script, sig),
        Err(Error::BufferTooSmall)
    );
}

/// The other two published proofs are for P2PKH addresses, which need the legacy
/// signature hash: refused as unsupported, not read as anything else.
#[test]
fn a_legacy_proof_of_funds_is_refused_as_unsupported() {
    let script = script_of("1PgwDB9w9vKjqhXMaqDiZyktC4x2eC7Wkw");
    let mut scratch = [0u8; 2048];
    assert_eq!(
        verify_armoured_in(
            b"2JNEDD7IJDSYLREMJ6Q7PTCQJD",
            &script,
            "pofcHNidP8BAI8CAAAAA3UzG05Nmq3GQGeM4RuOvKR3OzsxeY3Iv7WeRpsFNQM0AAAAAADIAQAADCbiUkASpwj6kUReXXcYBQYbAO9L5G7WGpFwwoySY+UAAAAAAAAAAAA3p26yqXE6EPnIIn3fG72TA/ogmgx628m04thl4j0g/gAAAAAAAAAAAAEAAAAAAAAAAAFqewAAAAABAHcAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////yIAIB2Ij79goPLYV23iushdHloX5BnvTP3sLOG1x4L5uCYKAAAAAAEAAAAAAAAAABl2qRT44D3t4ciLKM9Jqw/cQWbMKcrdMYisAAAAAAEHa0gwRQIhAMQa+hYcQZ+v/rcrR4/cn7MthXgjlI9vdOyWaff0ytI1AiBzwJB5Sa7Gg5o5l1YRo2kvPGVjPEXlcDSRXkY/m5pEGAEhAg/lEKOLDqGSy/dJvtUFqV+b0Ibfnat6xQVm3TFbRMUHAAEAVQAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABTkYFAAAAAAAZdqkUXAydgFhnOc1o76l++wzhjwbeADKIrAAAAAABB2pHMEQCIEN2q/Y9n1JliYceYA/Lcb+lab84iq5FRGEw0QDZvCthAiBbgsbUfkt5y4PN7iBLpuW8zBARbHVBfsX/vIRcAewd8wEhAl+mkzpSHsor/2HKnlhZQjD88o2fj45Xj+PLeO0vHShBAAEBIE5GBQAAAAAAF6kUmkCp3fSiSKNrfA9wZKySQBbrBJeHAQcXFgAUYWYrEU/y0qj1P/GYS2Yc7nhhe8MBCGsCRzBEAiACr5bTFlzWGiXis1Y01AMVGVlPBEgO8G/g+6c4cNbx5wIgYqXaNnAPVNWVjfaJ8DhIuOiAUiTHeNdjdYH9IpXjK1oBIQMs7LIzDohxaDGLK3Jxlyxu/lnEh3YdmVbtOwi/9/IvuQAA",
            &mut scratch
        ),
        Err(Error::UnsupportedScript)
    );
}

// --- the engine against outscript -------------------------------------------------

/// A three-input, two-output transaction with mixed prevouts.
fn sample_tx() -> (Vec<u8>, Vec<(u64, Vec<u8>)>) {
    let ins: Vec<RawTxIn<'_>> = (0..3u8)
        .map(|i| RawTxIn {
            txid: [i + 1; 32],
            vout: u32::from(i) * 7,
            script_sig: &[],
            sequence: 0xffff_fffe - u32::from(i),
            witness: &[],
        })
        .collect();
    let out_a = unhex("00140102030405060708090a0b0c0d0e0f1011121314");
    let out_b = [0x6a];
    let outs = [
        RawTxOut {
            amount: 12_345,
            script: &out_a,
        },
        RawTxOut {
            amount: 0,
            script: &out_b,
        },
    ];
    let tx = RawTx {
        version: 2,
        inputs: &ins,
        outputs: &outs,
        locktime: 900_000,
    };
    let mut buf = [0u8; 512];
    let n = tx.serialize_to_slice(&mut buf).unwrap();
    let prevouts = vec![
        (1_000, unhex("0014aabbccddeeff00112233445566778899aabbccdd")),
        (
            2_000,
            unhex("5120aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ),
        (
            3_000,
            unhex("0020bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        ),
    ];
    (buf[..n].to_vec(), prevouts)
}

struct Given<'a>(&'a [(u64, Vec<u8>)]);

impl<'a> Prevouts<'a> for Given<'a> {
    fn prevout(&self, index: usize) -> Option<(u64, &'a [u8])> {
        self.0.get(index).map(|(a, s)| (*a, s.as_slice()))
    }
}

#[test]
fn the_streaming_digests_agree_with_outscript_on_every_input() {
    let (bytes, prevouts) = sample_tx();
    let view = ToSignBytes::parse(&bytes).unwrap();
    let given = Given(&prevouts);

    // outscript's view of the same transaction.
    let ins: Vec<RawTxIn<'_>> = (0..3)
        .map(|i| {
            let v = view.input(i).unwrap();
            RawTxIn {
                txid: v.txid,
                vout: v.vout,
                script_sig: &[],
                sequence: v.sequence,
                witness: &[],
            }
        })
        .collect();
    let outs: Vec<RawTxOut<'_>> = (0..2)
        .map(|j| {
            let (amount, script) = view.output(j).unwrap();
            RawTxOut { amount, script }
        })
        .collect();
    let raw = RawTx {
        version: 2,
        inputs: &ins,
        outputs: &outs,
        locktime: 900_000,
    };
    let prev: Vec<outscript::btcraw::PrevOut<'_>> = prevouts
        .iter()
        .map(|(a, s)| RawTxOut {
            amount: *a,
            script: s,
        })
        .collect();
    let mid = raw.taproot_midstate(&prev).unwrap();
    let code = unhex("76a914aabbccddeeff00112233445566778899aabbccdd88ac");
    for i in 0..3 {
        let theirs = raw
            .segwit_v0_sighash(i, &code, prevouts[i].0, 0x01)
            .unwrap();
        assert_eq!(
            segwit_v0(&view, &given, i, &code).unwrap(),
            theirs,
            "bip143 {i}"
        );
        for hash_type in [0x00u8, 0x01] {
            let theirs = mid.key_spend_sighash_with_type(i, hash_type).unwrap();
            assert_eq!(
                taproot(&view, &given, i, hash_type).unwrap(),
                theirs,
                "bip341 {i} type {hash_type}"
            );
        }
    }
    // A prevout it was not given is an error, not a zero.
    let short = Given(&prevouts[..2]);
    assert_eq!(taproot(&view, &short, 0, 0), Err(Error::MissingUtxo));
    assert_eq!(segwit_v0(&view, &short, 2, &code), Err(Error::MissingUtxo));
}

#[test]
fn a_transaction_is_read_strictly() {
    let (bytes, _) = sample_tx();
    assert!(ToSignBytes::parse(&bytes).is_ok());
    // Every truncation is refused, never read as something shorter.
    for n in 0..bytes.len() {
        assert!(
            ToSignBytes::parse(&bytes[..n]).is_err(),
            "prefix {n} parsed"
        );
    }
    // And so is a trailing byte.
    let mut long = bytes.clone();
    long.push(0);
    assert_eq!(ToSignBytes::parse(&long).err(), Some(Error::Malformed));
}

#[test]
fn a_to_sign_with_a_version_bip322_does_not_define_is_inconclusive() {
    let (message, address, sig) = FULL[0];
    let mut bytes = dearmour_full(sig);
    bytes[0] = 3;
    assert_eq!(
        verify_full(message.as_bytes(), &script_of(address), &bytes),
        Err(Error::Inconclusive)
    );
}
