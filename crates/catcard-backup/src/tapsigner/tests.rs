use super::*;
use catcard_wallet::KeyWork;
use catcard_wallet::bip32::{ExtendedPrivKey, Network};

/// The reference's test vector, verbatim: password `000102...0f`, zero IV.
/// Source: hw-reference/tapsigner-backup-import.md §"Test vector" [C]
const VECTOR_KEY: &str = "000102030405060708090a0b0c0d0e0f";
const VECTOR_XPRV: &str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LhYdeENBcLaiKTWE9kPPi7hhGmAZtnvjKr";
const VECTOR_HEX: &str = "bed14941befc69b3353dd02a90fceb32401747d1d9f4f8463e49fbd42db166393e9cd217abf5f1be8ddb115c13f5d2cdc09b485f0700926821375f1df4dcaa20462dfdb25a6b91c8d24725b5f025b9e6ffe7dcc72611cd202915778ada24bb4b8437cb3a00eec2ab9ba64791cb096468d41d172dae04088191e843";
const VECTOR_B64: &str = "vtFJQb78abM1PdAqkPzrMkAXR9HZ9PhGPkn71C2xZjk+nNIXq/Xxvo3bEVwT9dLNwJtIXwcAkmghN18d9NyqIEYt/bJaa5HI0kcltfAlueb/59zHJhHNICkVd4raJLtLhDfLOgDuwqubpkeRywlkaNQdFy2uBAiBkehD";

/// The BIP-32 test vector 1 master (seed `000102...0f`), whose fingerprint is `3442193e`.
const TV1_MASTER: &str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

fn key(hex: &str) -> [u8; KEY_LEN] {
    let mut k = [0u8; KEY_LEN];
    parse_key(hex, &mut k).unwrap();
    k
}

/// What a card would write: AES-128-CTR, zero IV, over `plain`. CTR is its own inverse.
fn encrypt(plain: &[u8], k: &[u8; KEY_LEN]) -> Vec<u8> {
    let mut ct = plain.to_vec();
    Ctr::new(Aes128::new(k), &IV).apply_keystream(&mut ct);
    ct
}

fn vector() -> Vec<u8> {
    let mut ct = [0u8; MAX_CIPHERTEXT];
    let n = from_scanned(VECTOR_HEX.as_bytes(), &mut ct).unwrap();
    ct[..n].to_vec()
}

fn fingerprint(xprv: &str) -> [u8; 4] {
    let kw = KeyWork::host();
    ExtendedPrivKey::from_base58(xprv, &kw)
        .unwrap()
        .fingerprint(&kw)
}

/// A password entered as hex becomes the 16 bytes the card encrypted with, case and stray
/// spaces notwithstanding; the wrong length or a non-hex digit is refused, not truncated.
#[test]
fn a_backup_password_is_exactly_32_hex_digits() {
    assert_eq!(key(VECTOR_KEY), core::array::from_fn(|i| i as u8));
    let u = key("  FFEEDDCCBBAA99887766554433221100 ");
    assert_eq!((u[0], u[15]), (0xFF, 0x00));

    let mut k = [0u8; KEY_LEN];
    assert_eq!(parse_key("00", &mut k), Err(Error::BadBackupKey));
    assert_eq!(
        parse_key("000102030405060708090a0b0c0d0e0f00", &mut k),
        Err(Error::BadBackupKey)
    );
    assert_eq!(
        parse_key("zz0102030405060708090a0b0c0d0e0f", &mut k),
        Err(Error::NotHex)
    );
}

/// The reference vector opens to its `xprv` and its path, and the sizes it gives fit
/// every channel's limits: the 123-byte file in the card's 100-160, the 164-character
/// Base64 in NFC's 150-280.
#[test]
fn the_reference_vector_opens_to_its_xprv_and_path() {
    let ct = vector();
    assert_eq!(ct.len(), 123);
    assert!(FILE_LEN.contains(&ct.len()));
    assert!(NFC_RECORD_LEN.contains(&VECTOR_B64.len()));

    let mut out = [0u8; MAX_CIPHERTEXT];
    let got = decrypt(&ct, &key(VECTOR_KEY), &mut out).unwrap();
    assert_eq!(got.xprv, VECTOR_XPRV);
    assert_eq!(got.path, "m/84h/0h/0h");
    assert_eq!(got.shown_path(), Some("m/84h/0h/0h"));
}

/// The vector's `xprv` parses as a mainnet depth-0 node -- what gets stored -- and its
/// fingerprint is `87adb3e5`.
///
/// **The reference is wrong about this one fact.** It calls the plaintext the BIP-32 test
/// vector 1 master and says the import "must produce master fingerprint `3442193e`". The
/// `xprv` it prints has that master's version, depth and chain code but a different key
/// -- valid Base58Check, a valid scalar, and not test vector 1 -- so it cannot produce
/// that master's fingerprint. Its ciphertext is consistent with the `xprv` it prints
/// (re-derived with OpenSSL), which is what a compatibility test needs; the fingerprint
/// claim is pinned below against the real test vector 1 master instead.
#[test]
fn the_reference_vector_is_a_mainnet_master_but_not_bip32_tv1() {
    let kw = KeyWork::host();
    let node = ExtendedPrivKey::from_base58(VECTOR_XPRV, &kw).unwrap();
    assert_eq!(node.network, Network::Mainnet);
    assert_eq!(node.depth, 0);
    assert_eq!(fingerprint(VECTOR_XPRV), [0x87, 0xad, 0xb3, 0xe5]);
    assert_ne!(VECTOR_XPRV, TV1_MASTER);
}

/// The fingerprint the reference meant: a backup of the BIP-32 test vector 1 master,
/// sealed the way a card seals it, opens to a node whose fingerprint is `3442193e`.
#[test]
fn a_backup_of_the_tv1_master_produces_fingerprint_3442193e() {
    let k = key(VECTOR_KEY);
    let ct = encrypt(format!("{TV1_MASTER}\nm/84h/0h/0h").as_bytes(), &k);
    let mut out = [0u8; MAX_CIPHERTEXT];
    let got = decrypt(&ct, &k, &mut out).unwrap();
    assert_eq!(fingerprint(got.xprv), [0x34, 0x42, 0x19, 0x3e]);
}

/// The two text forms are the same ciphertext: hex is tried first, then Base64, so a QR
/// of either decodes to the file's bytes -- and NFC's Base64 does too.
#[test]
fn hex_and_base64_text_decode_to_the_file_bytes() {
    let ct = vector();
    let mut a = [0u8; MAX_CIPHERTEXT];
    let n = from_scanned(VECTOR_B64.as_bytes(), &mut a).unwrap();
    assert_eq!(&a[..n], &ct[..]);

    let upper = VECTOR_HEX.to_ascii_uppercase();
    let n = from_scanned(format!("  {upper}\n").as_bytes(), &mut a).unwrap();
    assert_eq!(&a[..n], &ct[..]);

    let n = from_nfc(format!("{VECTOR_B64}\n").as_bytes(), &mut a).unwrap();
    assert_eq!(&a[..n], &ct[..]);
}

/// NFC takes Base64 only, as the reference says; hex there is not a backup. A QR that is
/// neither is refused with the error the scan screen answers by reading another code.
#[test]
fn text_that_is_neither_form_is_refused() {
    let mut a = [0u8; MAX_CIPHERTEXT];
    assert_eq!(
        from_scanned(b"hello, world", &mut a),
        Err(Error::NotBackupText)
    );
    assert_eq!(from_scanned(b"   ", &mut a), Err(Error::NotBackupText));
    assert_eq!(from_nfc(b"not base64!!", &mut a), Err(Error::NotBackupText));
    assert_eq!(from_nfc(&[0xff; 160], &mut a), Err(Error::NotBackupText));
    // Hex, but an odd digit short: not hex, and not Base64 either.
    assert_eq!(from_scanned(b"abc", &mut a), Err(Error::NotBackupText));
}

/// Text that decodes to more than any card's backup is refused for its size, not cut.
#[test]
fn text_decoding_past_the_largest_backup_is_refused() {
    let mut a = [0u8; MAX_CIPHERTEXT];
    let hex = "00".repeat(MAX_CIPHERTEXT + 1);
    assert_eq!(from_scanned(hex.as_bytes(), &mut a), Err(Error::BackupSize));
    // Not "AAAA": that is hex, and hex is tried first.
    let b64 = "////".repeat(MAX_CIPHERTEXT / 3 + 1);
    assert_eq!(from_scanned(b64.as_bytes(), &mut a), Err(Error::BackupSize));

    let mut big = [0u8; 512];
    assert_eq!(
        decrypt(&[0u8; MAX_CIPHERTEXT + 1], &key(VECTOR_KEY), &mut big).unwrap_err(),
        Error::BackupSize
    );
    assert_eq!(
        decrypt(&[], &key(VECTOR_KEY), &mut big).unwrap_err(),
        Error::BackupSize
    );
}

/// A wrong password decrypts to noise, and noise fails the acceptance check: the import
/// says "wrong key?" and asks again, never handing a scrambled key to the parse.
#[test]
fn a_wrong_password_fails_the_acceptance_check() {
    let ct = vector();
    let mut out = [0u8; MAX_CIPHERTEXT];
    let wrong = key("000102030405060708090a0b0c0d0e0e");
    assert_eq!(decrypt(&ct, &wrong, &mut out).unwrap_err(), Error::NoXprv);
}

/// The acceptance check is characters `1..4` being `prv` and nothing more: any SLIP-132
/// private prefix passes it, and a public key or a bare word does not.
#[test]
fn the_acceptance_check_is_prv_at_one_to_four() {
    let k = key(VECTOR_KEY);
    let mut out = [0u8; MAX_CIPHERTEXT];
    for good in ["tprvABC\nm", "zprvABC\nm", "Yprv\nm"] {
        let ct = encrypt(good.as_bytes(), &k);
        assert!(decrypt(&ct, &k, &mut out).is_ok(), "{good:?}");
    }
    for bad in ["xpubABC\nm", "prvx\nm", "x\nprv"] {
        let ct = encrypt(bad.as_bytes(), &k);
        assert_eq!(
            decrypt(&ct, &k, &mut out).unwrap_err(),
            Error::NoXprv,
            "{bad:?}"
        );
    }
}

/// Whitespace around the text is stripped before the check and the split, so a trailing
/// newline, or a leading space, changes nothing.
#[test]
fn surrounding_whitespace_is_stripped_first() {
    let k = key(VECTOR_KEY);
    let mut out = [0u8; MAX_CIPHERTEXT];
    let ct = encrypt(format!(" \n{VECTOR_XPRV}\nm/84h/0h/0h\n\n").as_bytes(), &k);
    let got = decrypt(&ct, &k, &mut out).unwrap();
    assert_eq!((got.xprv, got.path), (VECTOR_XPRV, "m/84h/0h/0h"));

    let ct = encrypt(format!("{VECTOR_XPRV}\r\nm\r\n").as_bytes(), &k);
    let got = decrypt(&ct, &k, &mut out).unwrap();
    assert_eq!((got.xprv, got.path), (VECTOR_XPRV, "m"));
}

/// A text that passes the check but is not exactly two lines is refused -- one line, or
/// three -- with the generic error rather than the wrong-key one.
#[test]
fn anything_but_exactly_two_lines_is_refused() {
    let k = key(VECTOR_KEY);
    let mut out = [0u8; MAX_CIPHERTEXT];
    for plain in [
        VECTOR_XPRV.to_string(),
        format!("{VECTOR_XPRV}\nm/84h\nextra"),
        format!("{VECTOR_XPRV}\n\nm/84h"),
    ] {
        let ct = encrypt(plain.as_bytes(), &k);
        assert_eq!(decrypt(&ct, &k, &mut out).unwrap_err(), Error::NotTwoLines);
    }
}

/// The path line is not checked -- stock reads and drops it -- so any second line opens.
/// What is shown of it is only what looks like a path; the rest is not put on screen.
#[test]
fn the_path_line_is_carried_but_only_shown_when_it_is_a_path() {
    let k = key(VECTOR_KEY);
    let mut out = [0u8; MAX_CIPHERTEXT];
    for (path, shown) in [
        ("m", Some("m")),
        ("m/44'/0'/0'/0'", Some("m/44'/0'/0'/0'")),
        ("m/84h/0h/0h", Some("m/84h/0h/0h")),
        ("hello", None),
        ("m/84h/0h/0h; drop", None),
    ] {
        let ct = encrypt(format!("{VECTOR_XPRV}\n{path}").as_bytes(), &k);
        let got = decrypt(&ct, &k, &mut out).unwrap();
        assert_eq!(got.path, path);
        assert_eq!(got.shown_path(), shown);
    }
}

/// A non-master `xprv` is not refused here or by the parse: its depth is the caller's to
/// see, and stock takes the node as the master whatever it is.
#[test]
fn a_non_master_xprv_still_opens_and_its_depth_is_visible() {
    let kw = KeyWork::host();
    let child = ExtendedPrivKey::from_base58(TV1_MASTER, &kw)
        .unwrap()
        .derive_path(&"m/84h/0h/0h".parse().unwrap(), &kw)
        .unwrap();
    let text = child.to_base58(&kw);
    let k = key(VECTOR_KEY);
    let ct = encrypt(format!("{text}\nm/84h/0h/0h").as_bytes(), &k);
    let mut out = [0u8; MAX_CIPHERTEXT];
    let got = decrypt(&ct, &k, &mut out).unwrap();
    let node = ExtendedPrivKey::from_base58(got.xprv, &kw).unwrap();
    assert_eq!(node.depth, 3);
}

/// A testnet backup carries its chain in its prefix: `tprv` reads back as testnet.
#[test]
fn the_chain_comes_from_the_version_prefix() {
    let kw = KeyWork::host();
    let mut node = ExtendedPrivKey::from_base58(TV1_MASTER, &kw).unwrap();
    node.network = Network::Testnet;
    let tprv = node.to_base58(&kw);
    assert!(tprv.starts_with("tprv"));
    let k = key(VECTOR_KEY);
    let ct = encrypt(format!("{tprv}\nm/84h/1h/0h").as_bytes(), &k);
    let mut out = [0u8; MAX_CIPHERTEXT];
    let got = decrypt(&ct, &k, &mut out).unwrap();
    let back = ExtendedPrivKey::from_base58(got.xprv, &kw).unwrap();
    assert_eq!(back.network, Network::Testnet);
}
