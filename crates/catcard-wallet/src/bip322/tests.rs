//! BIP-322's own published test vectors.
//!
//! Every constant in this file is copied from the BIP's vector files --
//! `bip-0322/basic-test-vectors.json` and `bip-0322/generated-test-vectors.json` in the
//! BIPs repository -- and nothing in it was computed by this implementation. That is the
//! point: a signed message format is only worth anything if a *different* program reads
//! what this one writes, and the vectors are the other program.
//!
//! The `error` cases matter as much as the signing ones. A verifier that says yes to a
//! signature made over another message is worse than no verifier at all, so the same
//! signature is re-checked against the wrong message and the wrong address, and both have
//! to be refused.

use super::*;
use crate::KeyWork;
use crate::encoding::base58;
use purecrypto::hash::{Digest, Sha256};

/// A WIF private key, as the vectors give them, reduced to its 32 bytes.
///
/// `0x80 || key || 0x01` -- the trailing byte says the key is used compressed, which every
/// vector here does. Source: the Bitcoin WIF convention [C]
fn wif(text: &str) -> [u8; 32] {
    let mut buf = [0u8; 64];
    let n = base58::decode_check(text, &mut buf).expect("vector WIF decodes");
    assert_eq!(n, 34, "compressed-key WIF");
    assert_eq!(buf[0], 0x80, "mainnet private key");
    assert_eq!(buf[33], 0x01, "compressed");
    let mut key = [0u8; 32];
    key.copy_from_slice(&buf[1..33]);
    key
}

/// The scriptPubKey an address pays to: `message_challenge`.
fn script_of(address: &str) -> Vec<u8> {
    let decoded = outscript::address::decode_bitcoin_based_address("bitcoin", address)
        .expect("vector address decodes");
    decoded.script.to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn armoured(sig: &Simple) -> String {
    let mut out = [0u8; MAX_ARMOURED];
    let n = sig.armour(&mut out).unwrap();
    String::from_utf8(out[..n].to_vec()).unwrap()
}

// --- basic-test-vectors.json, "tx_hashes" -----------------------------------------
//
// The address is the same in all three; only the message changes.
const ADDR_A: &str = "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l";
const KEY_A: &str = "L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k";

/// `(message, message_hash, to_spend_tx_hash, to_sign_tx_hash)`.
const TX_HASHES: &[(&str, &str, &str, &str)] = &[
    (
        "",
        "c90c269c4f8fcbe6880f72a721ddfbf1914268a794cbb21cfafee13770ae19f1",
        "c5680aa69bb8d860bf82d4e9cd3504b55dde018de765a91bb566283c545a99a7",
        "1e9654e951a5ba44c8604c4de6c67fd78a27e81dcadcfe1edf638ba3aaebaed6",
    ),
    (
        "Hello World",
        "f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a",
        "b79d196740ad5217771c1098fc4a4b51e0535c32236c71f1ea4d61a2d603352b",
        "88737ae86f2077145f93cc4b153ae9a1cb8d56afa511988c149c5c8c9d93bddf",
    ),
    // The vector file writes this one with a surrogate pair for the emoji; it is the
    // same text, and what is hashed is its UTF-8 bytes.
    (
        "UTF-8 support: öäüéàè 测试文本 \u{1F604}",
        "43936b237ea38c7794eb5d755e0d220b6db92ebfc5c8f482759d22b1286376d7",
        "c8f4f525fe8afb1bc09b44175bd2096f079c98425e8a1be676b712add1fb62f0",
        "8f488e06b89eafd019ec528109eafaf7f1d1811fd617aa1eeb9658f1c1be6586",
    ),
];

#[test]
fn the_message_hash_is_the_bip340_tagged_hash() {
    for (message, hash, _, _) in TX_HASHES {
        assert_eq!(hex(&message_hash(message.as_bytes())), *hash, "{message:?}");
    }
    // The tag is what keeps this hash away from every other use of SHA-256: the same
    // bytes hashed plainly are a different digest entirely.
    assert_ne!(
        message_hash(b"Hello World"),
        <[u8; 32]>::try_from(&Sha256::digest(b"Hello World")[..]).unwrap()
    );
}

#[test]
fn both_virtual_transactions_hash_to_what_the_bip_publishes() {
    let script = script_of(ADDR_A);
    for (message, _, to_spend, to_sign) in TX_HASHES {
        let m = message.as_bytes();
        assert_eq!(hex(&to_spend_txid(m, &script)), *to_spend, "{message:?}");
        assert_eq!(hex(&to_sign_txid(m, &script)), *to_sign, "{message:?}");
    }
}

// --- basic-test-vectors.json / generated-test-vectors.json, "simple" ----------------

/// `(message, WIF, address, every published signature)` for the single-key cases.
///
/// Each row lists every signature the BIP's vector file gives for it. Two implementations
/// that both sign deterministically can still disagree: RFC 6979 fixes the nonce given a
/// key and a message, but not every signer derives it the same way, and the P2WPKH rows of
/// `basic-test-vectors.json` carry two signatures each for exactly that reason. So what is
/// asserted is that this signer's output is *one of the published ones* -- and, separately,
/// that all of them verify.
const SIMPLE: &[(&str, &str, &str, &[&str])] = &[
    (
        "",
        KEY_A,
        ADDR_A,
        &[
            "smpAkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=",
            "smpAkgwRQIhAPkJ1Q4oYS0htvyuSFHLxRQpFAY56b70UvE7Dxazen0ZAiAtZfFz1S6T6I23MWI2lK/pcNTWncuyL8UL+oMdydVgzAEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy",
        ],
    ),
    (
        "Hello World",
        KEY_A,
        ADDR_A,
        &[
            "smpAkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=",
            "smpAkgwRQIhAOzyynlqt93lOKJr+wmmxIens//zPzl9tqIOua93wO6MAiBi5n5EyAcPScOjf1lAqIUIQtr3zKNeavYabHyR8eGhowEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy",
        ],
    ),
    // generated-test-vectors.json
    (
        "2V6TUTMSH4VQ3Z7WZWKYD7DFNH",
        "KySmn2yeCukjHXnSu3M6vX7tNok4weu1FKbNEuVvm2b3ZidKhB4L",
        "bc1qqthe0hz8klx90e7stf6shclhsvqd5ly96pn53v",
        &[
            "smpAkgwRQIhALC6hdfxNy1n45d7UXSskRBdfZW0Al259E1kDMpipdYkAiAJPfZqb+WurZuf1apU5xeE6Igui9dvt5tihQLDvxlY1AEhAqbnruyo677ktQjio7XOchO3w51Dh9AbRVngha5jtNfT",
        ],
    ),
    (
        "PURVOQ544B6HUATVBJZN5EZJUU",
        "L5XqN6ckPPsDiTbRxcsthwiWpDBfWLo4uquUEydsPt8rSMoTpqpc",
        "bc1pcquvhrqv0q68t4m0hfq6tpn006qrskyc7yrqnp2uyrf2emg3wynsdjyk38",
        &[
            "smpAUB6B2Rbupzua8LTQIF06516wzl+cwKy1be8RgoiW0riyXdKwe6GTz/5Hnb37m67pJwIKCh+D5jDueG6KpvYpmu8",
        ],
    ),
];

/// The vector that predates the `smp` prefix: a P2TR signature written as bare base64,
/// which a verifier is told to read as the simple variant.
const NO_PREFIX: (&str, &str, &str, &str) = (
    "No prefix fallback",
    "KyrSGCFPhqZMjCe5fNTYddiLMp4tMj4gLKuJ26TsB2rvr1VJGPbt",
    "bc1pss0zhytly75awhm6x2hhvd5lnzv3vssgrf9axfheq8ldyzn88ges79fler",
    "AUCJYOwOjxYAvatTAGYaVlNXBVyFuc4MwNQkOuK2tl8xhfKDONd0NjfYyNSYcRqeCp8hsAnCEPHAVEkO9h6vbQ/R",
);

fn kind_of(address: &str) -> AddressKind {
    if address.starts_with("bc1p") {
        AddressKind::P2tr
    } else {
        AddressKind::P2wpkh
    }
}

#[test]
fn ecdsa_signing_reproduces_a_published_signature_byte_for_byte() {
    let kw = KeyWork::host();
    for (message, key, address, published) in SIMPLE {
        if kind_of(address) != AddressKind::P2wpkh {
            continue;
        }
        let sig = sign(message.as_bytes(), &wif(key), AddressKind::P2wpkh, &kw).unwrap();
        let mine = armoured(&sig);
        assert!(
            published.contains(&mine.as_str()),
            "{message:?} for {address}: {mine} is none of {published:?}"
        );
    }
}

/// Why the taproot rows are not compared byte for byte.
///
/// BIP-340 signing takes auxiliary randomness, and the signature it produces depends on
/// it. Passing zeros -- which is what this does, because the device has no randomness it
/// would rather trust than none -- makes *this* signer reproducible, but it does not make
/// its output equal to another implementation's, and the BIP does not say it should. What
/// a taproot vector can therefore pin down is that the signature checks out against the
/// address the vector names, which is the property anyone relying on one cares about.
#[test]
fn schnorr_signing_produces_a_signature_the_vector_address_accepts() {
    let kw = KeyWork::host();
    for (message, key, address, _) in SIMPLE {
        if kind_of(address) != AddressKind::P2tr {
            continue;
        }
        let script = script_of(address);
        let sig = sign(message.as_bytes(), &wif(key), AddressKind::P2tr, &kw).unwrap();
        assert_eq!(
            verify(message.as_bytes(), &script, sig.as_bytes()),
            Ok(()),
            "{message:?} for {address}"
        );
        // 64 bytes, pushed as the single item of the witness: SIGHASH_DEFAULT, with no
        // type byte to disagree about.
        assert_eq!(sig.as_bytes().len(), 1 + 1 + 64);
        assert_eq!(sig.as_bytes()[..2], [0x01, 0x40]);
    }
    let (message, key, address, _) = NO_PREFIX;
    let sig = sign(message.as_bytes(), &wif(key), AddressKind::P2tr, &kw).unwrap();
    assert_eq!(
        verify(message.as_bytes(), &script_of(address), sig.as_bytes()),
        Ok(())
    );
}

#[test]
fn a_signer_writes_the_prefix_a_verifier_may_do_without() {
    let kw = KeyWork::host();
    let (message, key, _, published) = NO_PREFIX;
    let sig = sign(message.as_bytes(), &wif(key), AddressKind::P2tr, &kw).unwrap();
    // Everything this writes carries `smp`, which BIP-322 requires of a signer; the
    // vector predates the prefix and is read anyway.
    assert!(armoured(&sig).starts_with(PREFIX));
    assert!(!published.starts_with(PREFIX));
    let mut plain = [0u8; MAX_WITNESS];
    let mut with = [0u8; MAX_WITNESS];
    let n = dearmour(published, &mut plain).unwrap();
    let m = dearmour(&format!("{PREFIX}{published}"), &mut with).unwrap();
    assert_eq!(plain[..n], with[..m]);
}

#[test]
fn a_signature_this_made_is_the_address_it_claims() {
    let kw = KeyWork::host();
    for (message, key, address, _) in SIMPLE {
        let script = script_of(address);
        let sig = sign(message.as_bytes(), &wif(key), kind_of(address), &kw).unwrap();
        // The challenge this signed for is rebuilt from the key alone; that it matches
        // the vector's address is the whole claim a signature makes.
        let mut mine = [0u8; MAX_SCRIPT];
        let secret = wif(key);
        let pubkey = outscript::crypto::secp256k1::SecpPrivateKey::from_bytes(&secret)
            .unwrap()
            .public_key()
            .serialize_compressed();
        let n = challenge(kind_of(address), &pubkey, &mut mine).unwrap();
        assert_eq!(&mine[..n], &script[..], "{address}");
        assert_eq!(verify(message.as_bytes(), &script, sig.as_bytes()), Ok(()));
    }
}

#[test]
fn every_published_simple_signature_verifies() {
    for (message, _, address, published) in SIMPLE {
        let script = script_of(address);
        for sig in *published {
            assert_eq!(
                verify_armoured(message.as_bytes(), &script, sig),
                Ok(()),
                "{message:?}"
            );
        }
    }
    let (message, _, address, sig) = NO_PREFIX;
    assert_eq!(
        verify_armoured(message.as_bytes(), &script_of(address), sig),
        Ok(())
    );
}

#[test]
fn signing_is_deterministic() {
    let kw = KeyWork::host();
    for (message, key, address, _) in SIMPLE {
        let a = sign(message.as_bytes(), &wif(key), kind_of(address), &kw).unwrap();
        let b = sign(message.as_bytes(), &wif(key), kind_of(address), &kw).unwrap();
        assert_eq!(a, b, "{message:?}");
    }
}

// --- the error vectors --------------------------------------------------------------

/// `(description, message, address, signature)` from the two vector files' `error`
/// lists, for the address types this implements. Each one must be refused.
const BAD: &[(&str, &str, &str, &str)] = &[
    (
        "wrong message for valid simple p2wpkh signature (empty message was signed)",
        "Wrong message that was not signed",
        ADDR_A,
        "smpAkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=",
    ),
    (
        "empty witness stack (single zero byte)",
        "",
        ADDR_A,
        "smpAA==",
    ),
    (
        "wrong message for p2wpkh simple signature",
        "EFGJ4AZYXDV7NDUDSUDB3NCDUC",
        "bc1qqthe0hz8klx90e7stf6shclhsvqd5ly96pn53v",
        "smpAkgwRQIhALC6hdfxNy1n45d7UXSskRBdfZW0Al259E1kDMpipdYkAiAJPfZqb+WurZuf1apU5xeE6Igui9dvt5tihQLDvxlY1AEhAqbnruyo677ktQjio7XOchO3w51Dh9AbRVngha5jtNfT",
    ),
    (
        "wrong signer for p2wpkh simple signature",
        "2V6TUTMSH4VQ3Z7WZWKYD7DFNH",
        "bc1qgg6lpr05az2l5kz402ddz5ez7fdu25kgmd40lf",
        "smpAkgwRQIhALC6hdfxNy1n45d7UXSskRBdfZW0Al259E1kDMpipdYkAiAJPfZqb+WurZuf1apU5xeE6Igui9dvt5tihQLDvxlY1AEhAqbnruyo677ktQjio7XOchO3w51Dh9AbRVngha5jtNfT",
    ),
    (
        "wrong message for p2tr simple signature",
        "56VM6YK6Y76XTBXNPITF232EPX",
        "bc1pcquvhrqv0q68t4m0hfq6tpn006qrskyc7yrqnp2uyrf2emg3wynsdjyk38",
        "smpAUB6B2Rbupzua8LTQIF06516wzl+cwKy1be8RgoiW0riyXdKwe6GTz/5Hnb37m67pJwIKCh+D5jDueG6KpvYpmu8",
    ),
    (
        "wrong signer for p2tr simple signature",
        "PURVOQ544B6HUATVBJZN5EZJUU",
        "bc1pltvk000nd54v3hrrcn7lsffdra72hphpm40rhzf9hn8arqkgermq2p9029",
        "smpAUB6B2Rbupzua8LTQIF06516wzl+cwKy1be8RgoiW0riyXdKwe6GTz/5Hnb37m67pJwIKCh+D5jDueG6KpvYpmu8",
    ),
];

#[test]
fn every_published_bad_signature_is_refused() {
    for (what, message, address, sig) in BAD {
        assert!(
            verify_armoured(message.as_bytes(), &script_of(address), sig).is_err(),
            "accepted: {what}"
        );
    }
}

#[test]
fn a_signature_is_not_readable_as_another_variant_or_another_encoding() {
    let script = script_of(ADDR_A);
    // "invalid base64 encoding" and "empty signature" from basic-test-vectors.json.
    assert_eq!(
        verify_armoured(b"", &script, "not-valid-base64!!!"),
        Err(Error::Malformed)
    );
    assert_eq!(verify_armoured(b"", &script, ""), Err(Error::Malformed));
    // "incorrect prefix type": a witness stack behind a `ful` prefix, which says the
    // bytes are a whole transaction. They are read as one, and are not one -- here the
    // "input count" lands on a byte of the signature.
    assert!(matches!(
        verify_armoured(
            b"incorrect prefix",
            &script,
            "fulAUDZwFXUp+adN+/UZj5dVrGAbB3zKs1Vcalz5fCF9srxS63eSWNGvH1NYbrBkPt1BJDUyWUz9zgUxfc63/QheT6M"
        ),
        Err(Error::Malformed | Error::TooManyInputs)
    ));
    // The simple decoder itself refuses the other variants by name.
    let mut out = [0u8; MAX_WITNESS];
    assert_eq!(dearmour("fulAA==", &mut out), Err(Error::UnsupportedKind));
    assert_eq!(dearmour("pofAA==", &mut out), Err(Error::UnsupportedKind));
}

#[test]
fn the_address_types_without_a_simple_signature_are_refused() {
    let kw = KeyWork::host();
    let secret = wif(KEY_A);
    for kind in [AddressKind::P2pkh, AddressKind::P2shP2wpkh] {
        assert_eq!(
            sign(b"CatCard", &secret, kind, &kw),
            Err(Error::UnsupportedKind),
            "{kind:?}"
        );
    }
}

#[test]
fn a_witness_stack_with_bytes_left_over_is_malformed() {
    let kw = KeyWork::host();
    let secret = wif(KEY_A);
    let sig = sign(b"CatCard", &secret, AddressKind::P2wpkh, &kw).unwrap();
    let script = script_of(ADDR_A);
    assert_eq!(verify(b"CatCard", &script, sig.as_bytes()), Ok(()));

    let mut trailing = sig.as_bytes().to_vec();
    trailing.push(0);
    assert_eq!(
        verify(b"CatCard", &script, &trailing),
        Err(Error::Malformed)
    );
    let short = &sig.as_bytes()[..sig.as_bytes().len() - 1];
    assert_eq!(verify(b"CatCard", &script, short), Err(Error::Malformed));
}

#[test]
fn a_high_s_signature_is_not_accepted_back() {
    // Flip `s` to `n - s`: the same curve equation, the other half of the pair, and not
    // a signature Bitcoin considers valid. A verifier that took it would let anyone turn
    // one signature into two.
    const ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];
    let kw = KeyWork::host();
    let secret = wif(KEY_A);
    let sig = sign(b"CatCard", &secret, AddressKind::P2wpkh, &kw).unwrap();
    let script = script_of(ADDR_A);

    let bytes = sig.as_bytes();
    let der_len = bytes[1] as usize;
    let der = &bytes[2..2 + der_len - 1];
    let (r, s) = parse_der_signature(der).unwrap();
    assert!(is_low_s(&s), "this signer emits low-S");

    // n - s, big-endian, by hand: no borrow past the top byte because s < n.
    let mut high = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = ORDER[i] as i16 - s[i] as i16 - borrow;
        if d < 0 {
            high[i] = (d + 256) as u8;
            borrow = 1;
        } else {
            high[i] = d as u8;
            borrow = 0;
        }
    }
    assert!(!is_low_s(&high));

    // Re-encode the pair as DER, with the same key and sighash byte after it.
    let mut der_high = Vec::new();
    let put_int = |out: &mut Vec<u8>, v: &[u8; 32]| {
        let mut start = 0;
        while start < 31 && v[start] == 0 {
            start += 1;
        }
        let body = &v[start..];
        out.push(0x02);
        if body[0] & 0x80 != 0 {
            out.push(body.len() as u8 + 1);
            out.push(0x00);
        } else {
            out.push(body.len() as u8);
        }
        out.extend_from_slice(body);
    };
    let mut inner = Vec::new();
    put_int(&mut inner, &r);
    put_int(&mut inner, &high);
    der_high.push(0x30);
    der_high.push(inner.len() as u8);
    der_high.extend_from_slice(&inner);
    der_high.push(0x01);

    let pubkey = &bytes[bytes.len() - 33..];
    let mut witness = vec![0x02, der_high.len() as u8];
    witness.extend_from_slice(&der_high);
    witness.push(33);
    witness.extend_from_slice(pubkey);
    assert_eq!(verify(b"CatCard", &script, &witness), Err(Error::Invalid));
}
