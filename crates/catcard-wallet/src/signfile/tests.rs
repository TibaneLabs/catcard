//! What a verifier must say yes and no to.
//!
//! The file under test is the one this device writes, and the signatures in it are either
//! its own or BIP-322's published ones. Every "yes" case is paired with the same file
//! spoiled in one place -- a character of the message, a character of the address -- and
//! the pair is the test: a verifier that cannot tell those apart is not a verifier.

use super::*;
use crate::KeyWork;
use crate::encoding::base58;

/// BIP-84's `m/84h/0h/0h/0/0`, the key [`crate::message`]'s tests sign with.
const SECRET: [u8; 32] = [
    0x46, 0x04, 0xb4, 0xb7, 0x10, 0xfe, 0x91, 0xf5, 0x84, 0xff, 0xf0, 0x84, 0xe1, 0xa9, 0x15, 0x9f,
    0xe4, 0xf8, 0x40, 0x8f, 0xff, 0x38, 0x05, 0x96, 0xa6, 0x04, 0x94, 0x84, 0x74, 0xce, 0x4f, 0xa3,
];

fn wif(text: &str) -> [u8; 32] {
    let mut buf = [0u8; 64];
    let n = base58::decode_check(text, &mut buf).unwrap();
    assert_eq!(n, 34);
    let mut key = [0u8; 32];
    key.copy_from_slice(&buf[1..33]);
    key
}

fn address_of(secret: &[u8; 32], kind: AddressKind) -> String {
    let pubkey = outscript::crypto::secp256k1::SecpPrivateKey::from_bytes(secret)
        .unwrap()
        .public_key()
        .serialize_compressed();
    let mut buf = [0u8; address::MAX_ADDRESS_LEN];
    let n = address::encode(kind, Network::Mainnet, &pubkey, &mut buf).unwrap();
    String::from_utf8(buf[..n].to_vec()).unwrap()
}

/// A file signed the legacy way, as the device writes it.
fn legacy_file(text: &str, kind: AddressKind) -> String {
    let kw = KeyWork::host();
    let sig = message::sign(text, &SECRET, kind, &kw).unwrap();
    let mut armour = [0u8; message::MAX_ARMOURED];
    let n = message::armour(&sig, &mut armour).unwrap();
    let mut out = String::new();
    write(
        &mut out,
        text,
        &address_of(&SECRET, kind),
        core::str::from_utf8(&armour[..n]).unwrap(),
    )
    .unwrap();
    out
}

/// The same, signed under BIP-322.
fn bip322_file(text: &str, kind: AddressKind) -> String {
    let kw = KeyWork::host();
    let sig = bip322::sign(text.as_bytes(), &SECRET, kind, &kw).unwrap();
    let mut armour = [0u8; bip322::MAX_ARMOURED];
    let n = sig.armour(&mut armour).unwrap();
    let mut out = String::new();
    write(
        &mut out,
        text,
        &address_of(&SECRET, kind),
        core::str::from_utf8(&armour[..n]).unwrap(),
    )
    .unwrap();
    out
}

#[test]
fn a_file_this_device_wrote_reads_back_field_for_field() {
    let file = legacy_file("CatCard", AddressKind::P2wpkh);
    let parsed = parse(&file).unwrap();
    assert_eq!(parsed.message, "CatCard");
    assert_eq!(parsed.address, address_of(&SECRET, AddressKind::P2wpkh));
    assert_eq!(parsed.signature.len(), message::MAX_ARMOURED);
}

#[test]
fn both_schemes_verify_as_themselves() {
    for kind in [
        AddressKind::P2pkh,
        AddressKind::P2shP2wpkh,
        AddressKind::P2wpkh,
    ] {
        let file = legacy_file("CatCard", kind);
        assert_eq!(
            verify(&parse(&file).unwrap()),
            Ok(Scheme::Legacy),
            "{kind:?}"
        );
    }
    for kind in [AddressKind::P2wpkh, AddressKind::P2tr] {
        let file = bip322_file("CatCard", kind);
        assert_eq!(
            verify(&parse(&file).unwrap()),
            Ok(Scheme::Bip322Simple),
            "{kind:?}"
        );
    }
}

#[test]
fn a_message_changed_by_one_character_is_refused() {
    for file in [
        legacy_file("CatCard", AddressKind::P2wpkh),
        bip322_file("CatCard", AddressKind::P2wpkh),
        bip322_file("CatCard", AddressKind::P2tr),
    ] {
        let spoiled = file.replace("CatCard", "CatCarD");
        assert_eq!(verify(&parse(&spoiled).unwrap()), Err(Error::Invalid));
    }
}

#[test]
fn a_signature_under_another_address_is_refused() {
    // The file says one address and carries a signature made by another key. The legacy
    // scheme catches it by recovering a key that builds a different address; BIP-322 by
    // checking the signature against the script the file's address stands for.
    let other = address_of(&[0x11; 32], AddressKind::P2wpkh);
    for file in [
        legacy_file("CatCard", AddressKind::P2wpkh),
        bip322_file("CatCard", AddressKind::P2wpkh),
    ] {
        let mine = address_of(&SECRET, AddressKind::P2wpkh);
        let spoiled = file.replace(&mine, &other);
        assert_eq!(verify(&parse(&spoiled).unwrap()), Err(Error::Invalid));
    }
}

#[test]
fn a_legacy_header_that_lies_about_the_address_type_is_refused() {
    // The header byte carries the address type the signer used. Rewriting it to claim
    // P2PKH leaves a signature that still recovers a key -- to a *different* key, or to
    // the same key rendered as a different address -- and neither is the address in the
    // file.
    let file = legacy_file("CatCard", AddressKind::P2wpkh);
    let parsed = parse(&file).unwrap();
    let mut raw = [0u8; 192];
    let n = outscript::base64::decode_to_slice(parsed.signature, &mut raw).unwrap();
    assert_eq!(n, message::SIG_LEN);
    // 39..42 is P2WPKH, 31..34 is P2PKH: the same recovery id, another claim.
    raw[0] -= 8;
    let mut armour = [0u8; message::MAX_ARMOURED];
    let m = outscript::base64::encode_to_slice(&raw[..n], &mut armour).unwrap();
    let mut spoiled = String::new();
    write(
        &mut spoiled,
        parsed.message,
        parsed.address,
        core::str::from_utf8(&armour[..m]).unwrap(),
    )
    .unwrap();
    assert_eq!(verify(&parse(&spoiled).unwrap()), Err(Error::Invalid));
}

#[test]
fn a_published_bip322_signature_verifies_out_of_a_file() {
    // basic-test-vectors.json, the "Hello World" P2WPKH row, wrapped in the armour a file
    // would carry it in.
    let mut file = String::new();
    write(
        &mut file,
        "Hello World",
        "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l",
        "smpAkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=",
    )
    .unwrap();
    assert_eq!(verify(&parse(&file).unwrap()), Ok(Scheme::Bip322Simple));

    // The same signature is not "Hello World " -- a trailing space is a different message.
    let spoiled = file.replace("Hello World", "Hello World ");
    assert_eq!(verify(&parse(&spoiled).unwrap()), Err(Error::Invalid));
}

#[test]
fn a_signature_written_before_the_prefix_existed_is_read_as_simple() {
    let key = wif("KyrSGCFPhqZMjCe5fNTYddiLMp4tMj4gLKuJ26TsB2rvr1VJGPbt");
    assert_eq!(
        address_of(&key, AddressKind::P2tr),
        "bc1pss0zhytly75awhm6x2hhvd5lnzv3vssgrf9axfheq8ldyzn88ges79fler"
    );
    let mut file = String::new();
    write(
        &mut file,
        "No prefix fallback",
        "bc1pss0zhytly75awhm6x2hhvd5lnzv3vssgrf9axfheq8ldyzn88ges79fler",
        "AUCJYOwOjxYAvatTAGYaVlNXBVyFuc4MwNQkOuK2tl8xhfKDONd0NjfYyNSYcRqeCp8hsAnCEPHAVEkO9h6vbQ/R",
    )
    .unwrap();
    assert_eq!(verify(&parse(&file).unwrap()), Ok(Scheme::Bip322Simple));
}

#[test]
fn the_variants_this_cannot_check_say_so_rather_than_invalid() {
    // "I cannot check this" must not read as "this is forged" on a screen. A witness
    // stack behind a `ful` prefix is not a transaction, and is refused as such.
    let mut file = String::new();
    write(
        &mut file,
        "incorrect prefix",
        "bc1pyrgrm6cu6n54jrvkdjd9rvyd3xfyu84s2623awu2srn6mxhscwpsm5644w",
        "fulAUDZwFXUp+adN+/UZj5dVrGAbB3zKs1Vcalz5fCF9srxS63eSWNGvH1NYbrBkPt1BJDUyWUz9zgUxfc63/QheT6M",
    )
    .unwrap();
    assert_eq!(verify(&parse(&file).unwrap()), Err(Error::Unsupported));

    // A P2PKH address has no BIP-322 signature here: the legacy format is its own.
    let mut file = String::new();
    write(
        &mut file,
        "MOISC5NCQ42ADH2SUXLELUJOWH",
        "13vU5PUSuArDXJdCWZvUFEbgJ2wcmtSJWn",
        "fulAgAAAAGn3Z6t/gsHNyHdgZTOVro0Hej+qbd/ilU1ACalKoHX3gAAAABqRzBEAiB+8t/tm8Jm6zYv9JGZZVlAUjmqg7ZglIA39U+bim8EKQIgDv3E5cHOagN+xYgN3ZQjTYlAJp/WyslwJWuFP1TmM3IBIQJcPK2h9SY+Ki1oussvHnMdFAhJgsYBFPl+rNcMv9P1ROAHAAABAAAAAAAAAAABauAHAAA=",
    )
    .unwrap();
    assert_eq!(verify(&parse(&file).unwrap()), Err(Error::Unsupported));
}

/// The P2WSH 3-of-3 from `basic-test-vectors.json`: the witness carries the script, so
/// a multisig address is checked like any other.
#[test]
fn a_multisig_signature_verifies_out_of_a_file() {
    let mut file = String::new();
    write(
        &mut file,
        "This will be a p2wsh 3-of-3 multisig BIP 322 signed message",
        "bc1qp0ahvfh83088w49k405szqgg4f3pptr7p2g06tdxfjcd40z4lh4q95lsz9",
        "smpBQBHMEQCIFX9aaqPJWq2Ff2kpen5bFDTid+ehgUOpHV0LfjncXy4AiA3GNicF7aKPzdpa9PCpmaYQs3pHd+qbvvhXdxOCKCAMAFIMEUCIQD/ELXg6CNYyUQijCg96JtgvgjZb9dsl1Ctof4QAeyTcQIgVM/1AAblFl/DCt6A1gJg+T/i2qU5SQD09+chFJzolRwBSDBFAiEAlqRfSFyWNVQhvaCnmeV5tyneiCWMTcFbuujoD/pFa3wCIGnZjfQb8NolSYq9asV+ZeBSkCGHJcqnaV4JYS5MYPEGAWlTIQJ1aLEfEi/4p7wcV+XHZCBVvGGJZ7L3v+jhH+mZA8lN0yECCovfec+kIdllXpKCgA8RX/HZ2x5yHOtCSKP8/sf6pnwhAwxSng6kCgCXXSAmJOOZFdr3vdK3HzGqCFloOHgc5fM6U64=",
    )
    .unwrap();
    assert_eq!(verify(&parse(&file).unwrap()), Ok(Scheme::Bip322Simple));

    // A cosigner's share alone, from the `full` 2-of-2 vector cut down to one
    // signature: every signature in it is good, and it is not yet a proof.
    let mut file = String::new();
    write(
        &mut file,
        "QXYOWYWO7ZGJC4OPNC367HBUQF",
        "bc1qg8r3cl47rrr75dwvr7jhzdukptegnmq8v0nmjd2jdn4qvlczqkts0rqtav",
        "fulAgAAAAABAXshuDM6YKy1LClwk1ZOM5egX7RTFPOCvtxJkYFYk/FEAAAAAADgBwAAAQAAAAAAAAAAAWoDAEgwRQIhAI9uOxvqmBV0pldOoKWnSYhjobNhP4F+gxO0QlOdGtxFAiBROcNruLigZE4lj1DJEh8yGrqS00MeW463EO78TsaRFgFHUiECRPfLhCpM5PNSzkBirl4KXWDW+qCwe2LCBjSEqlKXu84hAjTu1hkO/Edxa5U6BQtWP4srUjrd6pVa5DNR3SqSqkn0Uq7gBwAA",
    )
    .unwrap();
    assert_eq!(
        verify(&parse(&file).unwrap()),
        Err(Error::NeedsCosigners { have: 1, need: 2 })
    );
}

/// A `full` signature and a proof of reserves, each from the BIP's vectors, read out of
/// the armoured file and named for what they are.
#[test]
fn the_full_and_proof_variants_verify_out_of_a_file() {
    let mut file = String::new();
    write(
        &mut file,
        "EMYGZHEY3LIANYKCR7XJF3NMFQ",
        "32Utb7Seg6EXq7UesMNJXhQ1gdohYNyzQ9",
        "fulAgAAAAABAe5xLNMlYQH4OGjJ3h4lqQaVp0Cic7mwxkvyWswqFMXeAAAAABcWABSy/hpDH/KLAi4x25Tmb2UaO1xtWeAHAAABAAAAAAAAAAABagJHMEQCIDEleqb0n1R5c21TGkWRXNFae98wbwI0QOyh/YmRuQX1AiAcv1MhyTzPOVgZ1VIwuu0tDxrVJUHK8lhOUOXpsZnGwwEhAsjeDEoWX8hvEC8A/692yGQsPh6JBO8Zf4aITEQsKAcJ4AcAAA==",
    )
    .unwrap();
    assert_eq!(verify(&parse(&file).unwrap()), Ok(Scheme::Bip322Full));

    let mut file = String::new();
    write(
        &mut file,
        "FUYMQWKYGS7HJEN7YFEZU5SNR5",
        "bc1pk3vq3wpn4txexwq4dj0k2dugzp6kfwllvs89w49cvtk3j2cndcds3l9kw9",
        "pofcHNidP8BALgCAAAABDzMFysa2DX0k4ZymoVfzNzTIL3gsWlu03HcfI+NxhOxAAAAAADIAQAAVd4moQMhq/rd+2ecRsJ0Xeg6/SdhA+owjzyzg/Fqd/oAAAAAAAAAAABuZFRaqjWRO6kKy5hrEHAg+T12/Iuz+FZBwwMt/FQvkgAAAAAAAAAAAG5kVFqqNZE7qQrLmGsQcCD5PXb8i7P4VkHDAy38VC+SAQAAAAAAAAAAAQAAAAAAAAAAAWp7AAAAAAEBKwAAAAAAAAAAIlEgtFgIuDOqzZM4FWyfZTeIEHVku/9kDldUuGLtGSsTbhsBCEIBQKoTEBqEPkib1fLnELbmsbDVlmWGzOdiiN/XJefU3tF9AEi7PszYEPguomxXp7X2rL0dP0xkV6LbBcVz7oAEeKkAAQErTkYFAAAAAAAiUSB4i5DCtSPHOkI30E30ayMoWL47vA5l2NBJp/pZ1XGduAEIQgFAic0muhAJNc4ZlRWeJGRgkN+oE/ptV4Znyli19VAnSsHM/Pb9Mp02dd3zk3RmuT6VgjBxdJn2yURGKOka3l9cugABAStORgUAAAAAACJRIMoNyg9Pai/pn4PHTOMEsDHkuUAHt5riqU81NVVj+fXKAQhCAUCL3W2Jh3ImNRSpbp0bLe+rBE4GJw5AjwJEhakHsm83YfuQKeY1syBFrmNV2ZvLv8R8uTLcmkJ1s/lWUxZ9o4qJAAEBK05GBQAAAAAAIlEgXCutuyDOvc4hiADdov7VmOUfq4ww6HES7JZ6NAucMJkBCEIBQDqu/4oik+J+eAbvUhzzuBkoVoOgD5RySjpvJQqTKNieBda8dMTkH2avx6ghs7zd6puujlBCQw3r/NiG4VX7wAEAAA==",
    )
    .unwrap();
    assert_eq!(
        verify(&parse(&file).unwrap()),
        Ok(Scheme::Bip322Proof {
            utxos: 3,
            total: 3 * 345_678
        })
    );
    // Too small a scratch buffer is a clean refusal, not a truncated read.
    let mut small = [0u8; 512];
    assert_eq!(
        verify_with(&parse(&file).unwrap(), &mut small),
        Err(Error::Malformed)
    );
}

#[test]
fn a_file_that_made_a_round_trip_through_a_text_editor_still_reads() {
    let file = legacy_file("CatCard", AddressKind::P2wpkh);
    // Windows line endings, a note above the block, trailing blank lines, and a signature
    // wrapped at 64 characters -- all of which a mail client or an editor will do.
    let parsed = parse(&file).unwrap();
    let (head, tail) = parsed.signature.split_at(64);
    let mut rewrapped = String::new();
    write(
        &mut rewrapped,
        parsed.message,
        parsed.address,
        &format!("{head}\n{tail}"),
    )
    .unwrap();
    let mangled = format!("a note above it\n{}\n\n", rewrapped.replace('\n', "\r\n"));
    assert_eq!(verify(&parse(&mangled).unwrap()), Ok(Scheme::Legacy));
}

#[test]
fn something_that_is_not_an_armoured_file_is_said_to_be_that() {
    assert_eq!(parse("hello"), Err(Error::NotArmoured));
    assert_eq!(parse(BEGIN), Err(Error::NotArmoured));
    assert_eq!(
        parse(&format!("{BEGIN}\nmessage\n")),
        Err(Error::NotArmoured)
    );
    // Markers in the wrong order: the closing one before the separator.
    assert_eq!(
        parse(&format!("{BEGIN}\nmessage\n{END}\n{SEPARATOR}\n")),
        Err(Error::NotArmoured)
    );
    // Every marker, and no signature under the address.
    assert_eq!(
        parse(&format!(
            "{BEGIN}\nmessage\n{SEPARATOR}\nbc1qaddress\n{END}\n"
        )),
        Err(Error::Malformed)
    );
}

#[test]
fn a_message_the_screen_cannot_show_gets_no_verdict() {
    // A real signature over a message with a line break in it. The signature is sound and
    // this still refuses: a device that answers about text it cannot put in front of
    // someone is answering about a different string.
    let kw = KeyWork::host();
    let text = "two\nlines";
    let sig = bip322::sign(text.as_bytes(), &SECRET, AddressKind::P2wpkh, &kw).unwrap();
    let mut armour = [0u8; bip322::MAX_ARMOURED];
    let n = sig.armour(&mut armour).unwrap();
    let address = address_of(&SECRET, AddressKind::P2wpkh);
    let script = challenge_of(&address).unwrap();
    // Sound, as BIP-322 sees it...
    assert_eq!(
        bip322::verify(text.as_bytes(), script.as_slice(), sig.as_bytes()),
        Ok(())
    );

    let mut file = String::new();
    write(
        &mut file,
        text,
        &address,
        core::str::from_utf8(&armour[..n]).unwrap(),
    )
    .unwrap();
    // ...and still no verdict here. The message runs past the separator line when it is
    // parsed back, so what a reader would see is not what was signed either.
    assert!(matches!(
        parse(&file).map(|f| verify(&f)),
        Ok(Err(Error::Unshowable)) | Err(_)
    ));

    // Longer than the screen shows, on one line: the same answer.
    let long = "x".repeat(MAX_MESSAGE + 1);
    let sig = bip322::sign(long.as_bytes(), &SECRET, AddressKind::P2wpkh, &kw).unwrap();
    let n = sig.armour(&mut armour).unwrap();
    let mut file = String::new();
    write(
        &mut file,
        &long,
        &address,
        core::str::from_utf8(&armour[..n]).unwrap(),
    )
    .unwrap();
    assert_eq!(verify(&parse(&file).unwrap()), Err(Error::Unshowable));
}

#[test]
fn an_address_this_cannot_decode_is_not_an_invalid_signature() {
    let mut file = String::new();
    write(
        &mut file,
        "CatCard",
        "not-an-address",
        "smpAkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=",
    )
    .unwrap();
    assert_eq!(verify(&parse(&file).unwrap()), Err(Error::BadAddress));
}

// ---------------------------------------------------------------------------
// The detached `.sig` sidecar.
// ---------------------------------------------------------------------------

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use purecrypto::hash::{Digest as _, Sha256};
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(bytes));
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The sidecar is the documented template, byte for byte: the generic JSON export's
/// signing address (BIP-44, classic) over `<hex sha256>  <basename>`, every line ending
/// in a newline, the last one included.
///
/// Source: hw-reference/wallet-export-formats.md §"Detached signature file" [C].
#[test]
fn the_sidecar_matches_the_documented_template_byte_for_byte() {
    let kw = KeyWork::host();
    let contents = b"{\"chain\":\"BTC\",\"xfp\":\"0F056943\"}";
    let basename = "coldcard-export.json";
    let digest = sha256(contents);

    let mut out = String::new();
    sign_detached(
        &[(digest, basename)],
        &SECRET,
        AddressKind::P2pkh,
        Network::Mainnet,
        &kw,
        &mut out,
    )
    .unwrap();

    // Assembled independently from the parts the reference names: the body line, the
    // address, and a plain legacy signature over that body -- which is what any verifier
    // that never heard of this firmware computes.
    let body = format!("{}  {basename}", hex(&digest));
    let sig = message::sign(&body, &SECRET, AddressKind::P2pkh, &kw).unwrap();
    let mut armour = [0u8; message::MAX_ARMOURED];
    let n = message::armour(&sig, &mut armour).unwrap();
    let expected = format!(
        "-----BEGIN BITCOIN SIGNED MESSAGE-----\n\
         {body}\n\
         -----BEGIN BITCOIN SIGNATURE-----\n\
         {}\n\
         {}\n\
         -----END BITCOIN SIGNATURE-----\n",
        address_of(&SECRET, AddressKind::P2pkh),
        core::str::from_utf8(&armour[..n]).unwrap(),
    );
    assert_eq!(out, expected);
    assert_eq!(body.len(), 64 + 2 + basename.len());
    assert!(body.contains("  "), "two spaces between digest and name");
}

#[test]
fn a_sidecar_reads_back_as_its_file_list_and_verifies() {
    let kw = KeyWork::host();
    let digest = sha256(b"descriptor text\n");
    let mut out = String::new();
    sign_detached(
        &[(digest, "descriptor.txt")],
        &SECRET,
        AddressKind::P2wpkh,
        Network::Mainnet,
        &kw,
        &mut out,
    )
    .unwrap();

    let parsed = parse(&out).unwrap();
    assert_eq!(parsed.address, address_of(&SECRET, AddressKind::P2wpkh));
    let files: Vec<_> = listed_files(parsed.message).unwrap().collect();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, "descriptor.txt");
    assert_eq!(files[0].digest, digest);
    assert_eq!(verify(&parsed), Ok(Scheme::Legacy));

    // The same sidecar with one hex digit of the digest changed: the file list still
    // reads, and the signature no longer covers it.
    let spoiled = out.replacen(
        &hex(&digest)[..1],
        if &hex(&digest)[..1] == "0" { "1" } else { "0" },
        1,
    );
    let parsed = parse(&spoiled).unwrap();
    assert!(listed_files(parsed.message).is_some());
    assert_eq!(verify(&parsed), Err(Error::Invalid));
}

#[test]
fn a_sidecar_over_several_files_is_one_line_each_and_still_verifies() {
    let kw = KeyWork::host();
    let files = [
        (sha256(b"one"), "one.txt"),
        (sha256(b"two"), "two.json"),
        (sha256(b"three"), "three.sig"),
    ];
    let mut out = String::new();
    sign_detached(
        &files,
        &SECRET,
        AddressKind::P2pkh,
        Network::Testnet,
        &kw,
        &mut out,
    )
    .unwrap();
    let parsed = parse(&out).unwrap();
    // Three lines joined by `\n`, and the message runs past the single-line bound's
    // spirit without tripping it: a file list is showable as a list.
    assert_eq!(parsed.message.matches('\n').count(), 2);
    let listed = listed_files(parsed.message).unwrap();
    assert_eq!(listed.total(), 3);
    let names: Vec<&str> = listed.map(|f| f.name).collect();
    assert_eq!(names, ["one.txt", "two.json", "three.sig"]);
    assert_eq!(verify(&parsed), Ok(Scheme::Legacy));
}

#[test]
fn a_file_list_is_all_or_nothing_and_never_leaves_its_directory() {
    let line = format!("{}  export.json", hex(&sha256(b"x")));
    assert_eq!(listed_files(&line).unwrap().total(), 1);
    // A note above a listing is not a listing.
    assert!(listed_files(&format!("hello\n{line}")).is_none());
    // Upper-case hex is not the documented form.
    assert!(listed_files(&line.to_uppercase()).is_none());
    // One space, not two.
    assert!(listed_files(&line.replacen("  ", " ", 1)).is_none());
    // A name that would read outside the sidecar's own directory.
    for bad in ["../x", "a/b", "a\\b", ".."] {
        let l = format!("{}  {bad}", hex(&sha256(b"x")));
        assert!(listed_files(&l).is_none(), "{bad:?}");
    }
    // Empty, or too many.
    assert!(listed_files("").is_none());
    let many: Vec<String> = (0..=MAX_FILES)
        .map(|i| format!("{}  f{i}", hex(&sha256(b"x"))))
        .collect();
    assert!(listed_files(&many.join("\n")).is_none());

    // The writer refuses the same names rather than signing them.
    let kw = KeyWork::host();
    let mut out = String::new();
    assert_eq!(
        sign_detached(
            &[(sha256(b"x"), "dir/file")],
            &SECRET,
            AddressKind::P2pkh,
            Network::Mainnet,
            &kw,
            &mut out
        ),
        Err(DetachedError::BadList)
    );
    assert_eq!(
        sign_detached(
            &[],
            &SECRET,
            AddressKind::P2pkh,
            Network::Mainnet,
            &kw,
            &mut out
        ),
        Err(DetachedError::BadList)
    );
}

#[test]
fn a_signed_message_file_still_parses_with_its_own_markers() {
    // Both marker sets read; the older format's separator is not mistaken for the
    // sidecar's, nor the other way round.
    let file = legacy_file("CatCard", AddressKind::P2wpkh);
    assert!(file.contains(SEPARATOR) && !file.contains(SIG_BEGIN));
    assert_eq!(verify(&parse(&file).unwrap()), Ok(Scheme::Legacy));
}
