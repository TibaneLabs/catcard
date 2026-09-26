//! The spec's own vector, reproduced exactly, and the failure modes around it.
//! Source: hw-reference/key-teleport-protocol.md §7 [C]

use super::*;
use crate::KeyWork;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn arr<const N: usize>(s: &str) -> [u8; N] {
    unhex(s).try_into().unwrap()
}

const RX_PRIV: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const TX_PRIV: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const NOID: &str = "a1b2c3d4e5";
const BODY: &str = "6e68656c6c6f20776f726c64";
const RX_PUB: &str = "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
const R_PAYLOAD: &str = "bb361d0dbb0fd2e805cc51aaf90ccd5cf03f999f9937c24444106474f677a06724";
const R_BBQR: &str = "B$2R0100XM3B2DN3B7JOQBOMKGVPSDGNLTYD7GM7TE34ERCECBSHJ5TXUBTSI===";
const SESSION: &str = "3b2265dac86fe15fdaa31b1273fb3f8cbfc54663a7298f5e36ddac38e22dd993";
const S_PAYLOAD: &str = "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27d90f070f1c6331563bcfbfb1df344900";
const S_BBQR: &str =
    "B$2S0100AJDG276K4VR6LSYJUDIYOC5VQA2EQBDBPB42CSKJZ4RCQXY3VY7SPWIPA4HRYYZRKY547P5R342ESAA=";

#[test]
fn receiver_side_matches_the_vector() {
    let kw = KeyWork::host();
    let code = rx_code(&arr(RX_PRIV), &kw).unwrap();
    assert_eq!(code.digits_str(), "82566564");
    assert_eq!(code.payload, arr::<33>(R_PAYLOAD));
    assert_eq!(public_key(&arr(RX_PRIV), &kw).unwrap(), arr::<33>(RX_PUB));

    let mut out = [0u8; 128];
    let n = short_bbqr(Wire::Rx, &code.payload, &mut out).unwrap();
    assert_eq!(core::str::from_utf8(&out[..n]).unwrap(), R_BBQR);
}

#[test]
fn sender_recovers_the_receiver_key_from_the_digits() {
    let got = decrypt_rx_pubkey(b"82566564", &arr(R_PAYLOAD)).unwrap();
    assert_eq!(got, arr::<33>(RX_PUB));
}

#[test]
fn about_half_of_wrong_digits_are_caught_on_the_curve() {
    // Not a property of one code: over a run of wrong ones, roughly half decode to a
    // point and half do not. Neither end of that is a bug; both at once is the design.
    let payload = arr::<33>(R_PAYLOAD);
    let caught = (0..200u32)
        .filter(|i| decrypt_rx_pubkey(&format_code(10_000_000 + i), &payload).is_none())
        .count();
    assert!((60..=140).contains(&caught), "caught {caught} of 200");
}

#[test]
fn session_key_matches_the_vector_from_both_ends() {
    let kw = KeyWork::host();
    let tx_pub = public_key(&arr(TX_PRIV), &kw).unwrap();
    let a = ecdh(&arr(TX_PRIV), &arr(RX_PUB), &kw).unwrap();
    let b = ecdh(&arr(RX_PRIV), &tx_pub, &kw).unwrap();
    assert_eq!(a.as_bytes(), &arr::<32>(SESSION));
    assert_eq!(b.as_bytes(), &arr::<32>(SESSION));
}

#[test]
fn sealed_payload_matches_the_vector_byte_for_byte() {
    let kw = KeyWork::host();
    let session = Key32::from_bytes(arr(SESSION));
    let noid: [u8; 5] = arr(NOID);
    assert_eq!(&noid_text(&noid), b"UGZMHVHF");
    let inner = inner_key(&session, &noid, &kw);

    let body = unhex(BODY);
    let mut buf = [0u8; 64];
    buf[..body.len()].copy_from_slice(&body);
    let n = seal(&session, &inner, &mut buf, body.len()).unwrap();

    let mut payload = public_key(&arr(TX_PRIV), &kw).unwrap().to_vec();
    payload.extend_from_slice(&buf[..n]);
    assert_eq!(payload, unhex(S_PAYLOAD));
    // The outer checksum is the last two bytes, `4900` as the vector's hex has it. (The
    // document's prose calls it `d900`; its hex, which this whole payload matches, and the
    // round trip below both say `4900`, so the prose is the typo.)
    assert_eq!(&payload[47..], &[0x49, 0x00]);

    let mut text = [0u8; 128];
    let t = short_bbqr(Wire::Tx, &payload, &mut text).unwrap();
    assert_eq!(core::str::from_utf8(&text[..t]).unwrap(), S_BBQR);
}

#[test]
fn receiver_opens_the_vector() {
    let kw = KeyWork::host();
    let mut raw = [0u8; 64];
    let (wire, n) = parse_short(S_BBQR, &mut raw).unwrap();
    assert_eq!(wire, Wire::Tx);
    let (sender, sealed) = split_tx(&raw[..n]).unwrap();
    let session = ecdh(&arr(RX_PRIV), &sender, &kw).unwrap();
    let mut b2 = sealed.to_vec();
    let b1 = open_outer(&session, &mut b2).unwrap();
    let noid = noid_parse("ugzm-hvhf").unwrap();
    let inner = inner_key(&session, &noid, &kw);
    let len = open_inner(&inner, &mut b2[..b1]).unwrap();
    assert_eq!(&b2[..len], unhex(BODY).as_slice());
    assert_eq!(Dtype::from_byte(b2[0]), Some(Dtype::Notes));
}

#[test]
fn a_wrong_teleport_password_is_refused_and_leaves_the_bytes_alone() {
    let kw = KeyWork::host();
    let session = Key32::from_bytes(arr(SESSION));
    let (_, sealed) = split_tx(&unhex(S_PAYLOAD))
        .map(|(k, s)| (k, s.to_vec()))
        .unwrap();
    let mut b2 = sealed.clone();
    let b1 = open_outer(&session, &mut b2).unwrap();
    let before = b2[..b1].to_vec();
    let wrong = inner_key(&session, &noid_parse("AAAAAAAA").unwrap(), &kw);
    assert_eq!(open_inner(&wrong, &mut b2[..b1]), Err(Error::Inner));
    assert_eq!(&b2[..b1], before.as_slice());
}

#[test]
fn a_wrong_session_key_fails_the_outer_layer() {
    let wrong = Key32::from_bytes([7u8; 32]);
    let payload = unhex(S_PAYLOAD);
    let (_, sealed) = split_tx(&payload).unwrap();
    let mut b2 = sealed.to_vec();
    assert_eq!(open_outer(&wrong, &mut b2), Err(Error::Outer));
    assert_eq!(b2.as_slice(), sealed);
}

#[test]
fn the_checksums_are_unkeyed_and_that_is_stock_s_format() {
    // Documenting a weakness, not endorsing it: anyone can recompute the inner checksum
    // over a body they chose. What stops a forged payload is the session key over the
    // outer layer, not these two bytes.
    let body = unhex(BODY);
    let h = Sha256::digest(&body);
    assert_eq!(checksum(&body), [h[30], h[31]]);
}

#[test]
fn noid_parse_maps_confusable_glyphs_and_refuses_the_rest() {
    let k: [u8; 5] = arr(NOID);
    assert_eq!(noid_parse("UGZMHVHF"), Some(k));
    assert_eq!(noid_parse("ugzmhvhf"), Some(k));
    assert_eq!(noid_parse("UGZM HVHF"), Some(k));
    // 0 → O, 1 → L, 8 → B.
    assert_eq!(noid_parse("0000000L"), noid_parse("OOOOOOO1"));
    assert_eq!(noid_parse("8AAAAAAA"), noid_parse("BAAAAAAA"));
    assert_eq!(noid_parse("UGZMHVH"), None);
    assert_eq!(noid_parse("UGZMHVHFA"), None);
    assert_eq!(noid_parse("UGZMHVH9"), None);
    for i in 0..=255u8 {
        let k = [i, i ^ 0x5a, i.wrapping_mul(3), 0, 0xff];
        let t = noid_text(&k);
        assert_eq!(noid_parse(core::str::from_utf8(&t).unwrap()), Some(k));
    }
}

#[test]
fn stretch_in_slices_is_the_one_shot() {
    let kw = KeyWork::host();
    let session = Key32::from_bytes(arr(SESSION));
    let noid: [u8; 5] = arr(NOID);
    let whole = inner_key(&session, &noid, &kw);
    let mut s = Stretch::begin(&session, &noid, &kw);
    let mut slices = 0;
    while !s.step(333, &kw) {
        slices += 1;
    }
    assert_eq!(slices, (NOID_ROUNDS - 1).div_ceil(333) - 1);
    assert_eq!(s.finish(&kw).as_bytes(), whole.as_bytes());
}

#[test]
fn pbkdf2_matches_an_independent_implementation() {
    // The inner key against purecrypto's own PBKDF2, so the sliced loop is checked
    // against something that is not itself.
    let kw = KeyWork::host();
    let session = Key32::from_bytes(arr(SESSION));
    let noid: [u8; 5] = arr(NOID);
    let mut want = [0u8; 32];
    purecrypto::kdf::pbkdf2::<purecrypto::hash::Sha512>(
        session.as_bytes(),
        &noid,
        NOID_ROUNDS,
        &mut want,
    );
    assert_eq!(inner_key(&session, &noid, &kw).as_bytes(), &want);
}

#[test]
fn stash_trim_and_repad() {
    let mut stash = [0u8; STASH_LEN];
    stash[0] = 0x80;
    stash[1..17].copy_from_slice(&[0x11; 16]);
    stash[16] = 0; // a trailing zero in the entropy itself goes on the wire trimmed
    let n = stash_wire_len(&stash);
    assert_eq!(n, 16);
    let back = stash_from_wire(&stash[..n]).unwrap();
    assert_eq!(*back, stash);
    assert_eq!(stash_kind(0x80), Some(StashKind::Words(12)));
    assert_eq!(stash_kind(0x81), Some(StashKind::Words(18)));
    assert_eq!(stash_kind(0x82), Some(StashKind::Words(24)));
    assert_eq!(stash_kind(0x01), Some(StashKind::Xprv));
    assert_eq!(stash_kind(0x40), Some(StashKind::Raw(64)));
    assert_eq!(stash_kind(0x00), None);
    assert!(stash_from_wire(&[]).is_none());
    assert!(stash_from_wire(&[0u8; 3]).is_none());
    assert!(stash_from_wire(&[1u8; 73]).is_none());
}

#[test]
fn backup_body_loses_comments_and_blank_lines() {
    let text = b"# Coldcard backup\n\n# comment\nmnemonic = abandon\r\n  \nchain = BTC\n# end\n";
    let mut buf = text.to_vec();
    let n = strip_backup(&mut buf, text.len());
    assert_eq!(&buf[..n], b"mnemonic = abandon\nchain = BTC");
    assert!(buf[n..].iter().all(|&b| b == 0));
}

#[test]
fn links_and_bare_codes_are_recognised() {
    let mut out = [0u8; 256];
    let n = nfc_url(Wire::Tx, &unhex(S_PAYLOAD), &mut out).unwrap();
    let url = core::str::from_utf8(&out[..n]).unwrap();
    assert_eq!(n, nfc_url_len(49));
    assert!(url.starts_with("keyteleport.com/#B$2S0100"));
    assert_eq!(code_in(url), Some(S_BBQR));
    let full = format!("https://{url}");
    assert_eq!(wire_of(&full), Some(Wire::Tx));
    assert_eq!(wire_of(R_BBQR), Some(Wire::Rx));
    assert_eq!(wire_of("B$2P0100AAAA"), None);
    assert_eq!(wire_of("https://example.com/#B$2S0100"), None);
    // Unpadded is read too.
    let mut raw = [0u8; 64];
    let (w, n) = parse_short(R_BBQR.trim_end_matches('='), &mut raw).unwrap();
    assert_eq!((w, &raw[..n]), (Wire::Rx, unhex(R_PAYLOAD).as_slice()));
}

#[test]
fn psbt_keys_agree_between_co_signers() {
    use crate::bip32::{ExtendedPrivKey, Network};
    let kw = KeyWork::host();
    let alice = ExtendedPrivKey::from_seed(&[1u8; 32], Network::Mainnet, &kw).unwrap();
    let bob = ExtendedPrivKey::from_seed(&[2u8; 32], Network::Mainnet, &kw).unwrap();
    let ri = ri_from([0xff, 0x12, 0x34, 0x56]);
    assert_eq!(ri, 0x0f12_3456);
    // Alice sends to Bob with Bob's registered xpub; Bob receives with Alice's.
    let a_key = psbt_leg_key(&alice, ri, &kw).unwrap();
    let b_key = psbt_leg_key(&bob, ri, &kw).unwrap();
    let to_bob = psbt_rx_pubkey(&bob.to_extended_pub(&kw), ri).unwrap();
    let from_alice = psbt_rx_pubkey(&alice.to_extended_pub(&kw), ri).unwrap();
    assert_eq!(public_key(&b_key, &kw).unwrap(), to_bob);
    let s1 = ecdh(&a_key, &to_bob, &kw).unwrap();
    let s2 = ecdh(&b_key, &from_alice, &kw).unwrap();
    assert_eq!(s1.as_bytes(), s2.as_bytes());
    // And a different `ri` is a different key.
    assert_ne!(
        psbt_rx_pubkey(&bob.to_extended_pub(&kw), ri + 1).unwrap(),
        to_bob
    );
}

#[test]
fn xprv_body_is_read_with_or_without_its_checksum() {
    use crate::bip32::{ExtendedPrivKey, Network};
    let kw = KeyWork::host();
    let k = ExtendedPrivKey::from_seed(&[3u8; 32], Network::Mainnet, &kw).unwrap();
    let raw = k.to_raw(&kw);
    let got = xprv_from_wire(&raw[..], &kw).unwrap();
    assert_eq!(got.secret_bytes(), k.secret_bytes());
    let mut with = raw.to_vec();
    with.extend_from_slice(&crate::encoding::base58::checksum(&raw[..]));
    assert!(xprv_from_wire(&with, &kw).is_ok());
    with[80] ^= 1;
    assert_eq!(xprv_from_wire(&with, &kw).err(), Some(Error::Format));
}

#[test]
fn dtype_and_wire_letters() {
    for d in [
        Dtype::Secret,
        Dtype::Xprv,
        Dtype::Notes,
        Dtype::Vault,
        Dtype::Psbt,
        Dtype::Backup,
    ] {
        assert_eq!(Dtype::from_byte(d.byte()), Some(d));
    }
    assert_eq!(Dtype::from_byte(b'r'), None);
    for w in [Wire::Rx, Wire::Tx, Wire::Psbt] {
        assert_eq!(Wire::from_code(w.code()), Some(w));
    }
}
