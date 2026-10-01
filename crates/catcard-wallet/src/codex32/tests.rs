//! What a codex32 implementation must agree with, and what it must refuse.
//!
//! The positive cases are BIP-93's published vectors and the Coldcard extension vectors
//! re-checked in hw-reference/codex32-format.md §Conformance vectors [C]. Each refusal is
//! a statement about one failure mode: a share from another set, the same paper twice,
//! a prefix swapped, a checksum off by one character.

use super::*;
use crate::KeyWork;
use crate::bip32::{ExtendedPrivKey, Network};

fn kw() -> KeyWork {
    KeyWork::host()
}

fn parse(s: &str) -> Result<Share, Error> {
    Share::parse(s, &kw())
}

fn ok(s: &str) -> Share {
    parse(s).unwrap_or_else(|e| panic!("{s}: {e:?}"))
}

fn text(share: &Share, upper: bool) -> String {
    let mut out = [0u8; MAX_STRING];
    share.write(upper, &mut out, &kw()).to_string()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn sym(c: u8) -> u8 {
    symbol_of(c.to_ascii_lowercase())
}

fn set_of(shares: &[&str]) -> Set {
    let mut set = Set::new();
    for s in shares {
        let share = ok(s);
        if share.is_secret() {
            set.push(share).unwrap();
        } else {
            set.add(share).unwrap();
        }
    }
    set
}

fn xprv_of_seed(seed: &[u8]) -> String {
    let k = kw();
    let master = ExtendedPrivKey::from_seed(seed, Network::Mainnet, &k).unwrap();
    let mut buf = [0u8; 120];
    let n = master.write_base58(&mut buf, &k).unwrap();
    String::from_utf8(buf[..n].to_vec()).unwrap()
}

// ---------------------------------------------------------------------------------------
// The field and the checksum
// ---------------------------------------------------------------------------------------

#[test]
fn every_nonzero_element_has_an_inverse() {
    for a in 1..32u8 {
        assert_eq!(mul(a, inv(a)), 1, "a = {a}");
    }
}

#[test]
fn the_ms_prefix_expands_to_bip93s_starting_residue() {
    // BIP-93's reference polymod starts at 0x23181b3, which is "ms" already mixed in. The
    // generalised start for cw/cx must reproduce it for ms, or every prefix is suspect.
    assert_eq!(Polymod::new(Hrp::Ms, false).residue, 0x23181b3);
    assert_eq!(Polymod::new(Hrp::Ms, true).residue, 0x23181b3);
}

#[test]
fn the_alphabet_round_trips_both_ways() {
    for v in 0..32u8 {
        assert_eq!(symbol_of(char_of(v)), v);
    }
    for c in *b"bio1A " {
        assert_eq!(symbol_of(c), 0xFF, "{}", c as char);
    }
}

// ---------------------------------------------------------------------------------------
// BIP-93 vectors
// ---------------------------------------------------------------------------------------

#[test]
fn bip93_vector_1_unshared_secret_with_nonzero_padding() {
    let s = ok("ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlw");
    assert_eq!(s.hrp(), Hrp::Ms);
    assert_eq!(s.threshold(), 0);
    assert_eq!(&s.id(), b"test");
    assert!(s.is_secret());
    let secret = s.secret(&kw()).unwrap();
    assert_eq!(hex(secret.as_bytes()), "318c6318c6318c6318c6318c6318c631");
    assert_eq!(
        xprv_of_seed(secret.as_bytes()),
        "xprv9s21ZrQH143K3taPNekMd9oV5K6szJ8ND7vVh6fxicRUMDcChr3bFFzuxY8qP3xFFBL6DWc2uEYCfBFZ2nFWbAqKPhtCLRjgv78EZJDEfpL"
    );
    // The padding (value 2) is kept: writing it back gives the same string.
    assert_eq!(
        text(&s, false),
        "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlw"
    );
}

#[test]
fn view_secret_regenerates_the_seed_id_zero_padded_form() {
    // hw-reference/codex32-format.md: the View Secret form of vector 1 [C].
    let s = ok("MS10TESTSXXXXXXXXXXXXXXXXXXXXXXXXXX4NZVCA9CMCZLW");
    let bytes = s.secret(&kw()).unwrap();
    let again =
        Share::from_bytes(Hrp::Ms, 0, seed_id(), SECRET_INDEX, bytes.as_bytes(), &kw()).unwrap();
    assert_eq!(
        text(&again, true),
        "MS10SEEDSXXXXXXXXXXXXXXXXXXXXXXXXXYXCV5FGVUZJQQ6"
    );
}

#[test]
fn bip93_vector_2_recovers_and_derives_from_two_shares() {
    let set = set_of(&[
        "MS12NAMEA320ZYXWVUTSRQPNMLKJHGFEDCAXRPP870HKKQRM",
        "MS12NAMECACDEFGHJKLMNPQRSTUVWXYZ023FTR2GDZMPY6PN",
    ]);
    assert!(set.is_complete());
    let d = set.interpolate(sym(b'd'), &kw()).unwrap();
    assert_eq!(
        text(&d, true),
        "MS12NAMEDLL4F8JLH4E5VDVULDLFXU2JHDNLSM97XVENRXEG"
    );
    let s = set.recover(&kw()).unwrap();
    assert_eq!(
        text(&s, true),
        "MS12NAMES6XQGUZTTXKEQNJSJZV4JV3NZ5K3KWGSPHUH6EVW"
    );
    let secret = s.secret(&kw()).unwrap();
    assert_eq!(hex(secret.as_bytes()), "d1808e096b35b209ca12132b264662a5");
    assert_eq!(
        xprv_of_seed(secret.as_bytes()),
        "xprv9s21ZrQH143K2NkobdHxXeyFDqE44nJYvzLFtsriatJNWMNKznGoGgW5UMTL4fyWtajnMYb5gEc2CgaKhmsKeskoi9eTimpRv2N11THhPTU"
    );
}

const V3_S: &str = "ms13cashsllhdmn9m42vcsamx24zrxgs3qqjzqud4m0d6nln";
const V3_A: &str = "ms13casha320zyxwvutsrqpnmlkjhgfedca2a8d0zehn8a0t";
const V3_C: &str = "ms13cashcacdefghjklmnpqrstuvwxyz023949xq35my48dr";
const V3_D: &str = "ms13cashd0wsedstcdcts64cd7wvy4m90lm28w4ffupqs7rm";
const V3_E: &str = "ms13casheekgpemxzshcrmqhaydlp6yhms3ws7320xyxsar9";
const V3_F: &str = "ms13cashf8jh6sdrkpyrsp5ut94pj8ktehhw2hfvyrj48704";

#[test]
fn bip93_vector_3_secret_encodes_from_its_master_seed() {
    let bytes = unhex("ffeeddccbbaa99887766554433221100");
    let id = [sym(b'c'), sym(b'a'), sym(b's'), sym(b'h')];
    let s = Share::from_bytes(Hrp::Ms, 3, id, SECRET_INDEX, &bytes, &kw()).unwrap();
    assert_eq!(text(&s, false), V3_S);
}

#[test]
fn bip93_vector_3_any_three_of_five_recover_the_secret() {
    let all = [V3_A, V3_C, V3_D, V3_E, V3_F];
    for i in 0..5 {
        for j in i + 1..5 {
            for k in j + 1..5 {
                let set = set_of(&[all[i], all[j], all[k]]);
                let s = set.recover(&kw()).unwrap();
                assert_eq!(text(&s, false), V3_S, "{i}{j}{k}");
            }
        }
    }
}

#[test]
fn bip93_vector_3_split_reproduces_the_published_shares() {
    // The vector's "random" shares a and c, fed in as the split's noise, must give back
    // the vector's derived d, e and f: the split is the published arithmetic exactly.
    let mut symbols = Vec::new();
    symbols.extend(b"cash".iter().map(|&c| sym(c)));
    for share in [V3_A, V3_C] {
        let s = ok(share);
        symbols.extend_from_slice(s.payload());
    }
    let mut noise = vec![0u8; (symbols.len() * 5).div_ceil(8)];
    let mut at = 0;
    for v in symbols {
        for b in (0..5).rev() {
            noise[at / 8] |= ((v >> b) & 1) << (7 - at % 8);
            at += 1;
        }
    }
    let secret = ok(V3_S);
    assert_eq!(noise.len(), noise_len(&secret, 3));
    let set = split(&secret, 3, &noise, &kw()).unwrap();
    let got: Vec<String> = SHARE_ORDER[..5]
        .iter()
        .map(|&i| text(&set.interpolate(i, &kw()).unwrap(), false))
        .collect();
    assert_eq!(got, [V3_A, V3_C, V3_D, V3_E, V3_F]);
}

#[test]
fn bip93_vector_3_other_paddings_are_valid_and_give_the_same_seed() {
    for s in [
        "ms13cashsllhdmn9m42vcsamx24zrxgs3qqjzqud4m0d6nln",
        "ms13cashsllhdmn9m42vcsamx24zrxgs3qpte35dvzkjpt0r",
        "ms13cashsllhdmn9m42vcsamx24zrxgs3qzfatvdwq5692k6",
        "ms13cashsllhdmn9m42vcsamx24zrxgs3qrsx6ydhed97jx2",
    ] {
        let secret = ok(s).secret(&kw()).unwrap();
        assert_eq!(hex(secret.as_bytes()), "ffeeddccbbaa99887766554433221100");
    }
}

#[test]
fn bip93_vector_4_256_bit_secret() {
    let s = ok("ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqqtum9pgv99ycma");
    let secret = s.secret(&kw()).unwrap();
    assert_eq!(
        hex(secret.as_bytes()),
        "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
    );
    assert_eq!(
        xprv_of_seed(secret.as_bytes()),
        "xprv9s21ZrQH143K3s41UCWxXTsU4TRrhkpD1t21QJETan3hjo8DP5LFdFcB5eaFtV8x6Y9aZotQyP8KByUjgLTbXCUjfu2iosTbMv98g8EQoqr"
    );
    // Sixteen paddings, one seed.
    for tail in ["pj82dp34u6lqtd", "0pgjxpzx0ysaam", "wcnrwpmlkmt9dt"] {
        let other = format!("ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyq{tail}");
        assert_eq!(
            ok(&other).secret(&kw()).unwrap().as_bytes(),
            secret.as_bytes()
        );
    }
}

#[test]
fn bip93_vector_5_long_string_with_the_long_checksum() {
    const V5: &str = "MS100C8VSM32ZXFGUHPCHTLUPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZYGSFJD6AN074RXVCEMLH8WU3TK925ACDEFGHJKLMNPQRSTUVWXY06FHPV80UNDVARHRAK";
    assert_eq!(V5.len(), 127);
    let s = ok(V5);
    let secret = s.secret(&kw()).unwrap();
    assert_eq!(
        hex(secret.as_bytes()),
        "dc5423251cb87175ff8110c8531d0952d8d73e1194e95b5f19d6f9df7c01111104c9baecdfea8cccc677fb9ddc8aec5553b86e528bcadfdcc201c17c638c47e9"
    );
    assert_eq!(
        xprv_of_seed(secret.as_bytes()),
        "xprv9s21ZrQH143K4UYT4rP3TZVKKbmRVmfRqTx9mG2xCy2JYipZbkLV8rwvBXsUbEv9KQiUD7oED1Wyi9evZzUn2rqK9skRgPkNaAzyw3YrpJN"
    );
    assert_eq!(text(&s, true), V5);
}

#[test]
fn bip93_vectors_6_to_8_verify_but_are_lengths_coldcard_refuses() {
    // 160/192/224-bit master seeds are valid BIP-93, and their checksums verify -- but a
    // Coldcard ms1 carries only 16, 32 or 64 bytes, so they are refused by length rather
    // than mistaken for a damaged string.
    for s in [
        "ms10seedsqqqsyqcyq5rqwzqfpg9scrgwpugpzysn9vaqzzvs20xnl",
        "ms10seedsyqsjygeyy5nzw2pf9g4jctfw9ucrzv3nxs6nvdau84gz0632s0xs",
        "ms10seedsgpq5ys6yg4rywjzfff95cn2wfag9z5jn2324v46ct9d9hrcduqw8c3lccl",
    ] {
        let symbols: Vec<u8> = s.as_bytes()[3..].iter().map(|&c| symbol_of(c)).collect();
        assert!(verifies(Hrp::Ms, &symbols), "{s}");
        assert_eq!(parse(s).err(), Some(Error::Length), "{s}");
    }
}

#[test]
fn bip93_invalid_checksums_are_refused() {
    let short = [
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxve740yyge2ghq",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxve740yyge2ghp",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxlk3yepcstwr",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxx6pgnv7jnpcsp",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxx0cpvr7n4geq",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxm5252y7d3lr",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxrd9sukzl05ej",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxc55srw5jrm0",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxgc7rwhtudwc",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxx4gy22afwghvs",
    ];
    let long = [
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxme084q0vpht7pe0",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxme084q0vpht7pew",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxqyadsp3nywm8a",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxzvg7ar4hgaejk",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxcznau0advgxqe",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxch3jrc6j5040j",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx52gxl6ppv40mcv",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx7g4g2nhhle8fk",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx63m45uj8ss4x8",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxy4r708q7kg65x",
    ];
    for s in short {
        assert!(parse(s).is_err(), "{s}");
    }
    for s in long {
        assert!(parse(s).is_err(), "{s}");
    }
    // Those of a length this firmware carries fail on the checksum and nothing earlier.
    for s in short
        .iter()
        .chain(&long)
        .filter(|s| s.len() == 48 || s.len() == 127)
    {
        assert_eq!(parse(s).err(), Some(Error::Checksum), "{s}");
    }
}

#[test]
fn bip93_wrong_checksum_kind_and_improper_lengths_are_refused() {
    for s in [
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxurfvwmdcmymdufv",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxw0a4c70rfefn4",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxk4pavy5n46nea",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxx9lrwar5zwng4w",
        "ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxzhddxw99w7xws",
        "ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxx42cux6um92rz",
        "ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxarja5kqukdhy9",
    ] {
        assert!(parse(s).is_err(), "{s}");
    }
}

#[test]
fn a_zero_threshold_on_a_share_and_a_letter_threshold_are_refused() {
    assert_eq!(
        parse("ms10fauxxxxxxxxxxxxxxxxxxxxxxxxxxxx0z26tfn0ulw3p").err(),
        Some(Error::Threshold)
    );
    assert_eq!(
        parse("ms1fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxda3kr3s0s2swg").err(),
        Some(Error::Threshold)
    );
}

#[test]
fn a_missing_prefix_or_separator_is_refused_as_such() {
    for s in [
        "0fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
        "10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
        "ms0fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
        "m10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
        "s10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
        "0fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxhkd4f70m8lgws",
        "10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxhkd4f70m8lgws",
        "m10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxx8t28z74x8hs4l",
        "s10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxh9d0fhnvfyx3x",
    ] {
        assert_eq!(parse(s).err(), Some(Error::Prefix), "{s}");
    }
}

#[test]
fn mixed_case_is_refused() {
    for s in [
        "Ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
        "mS10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
        "MS10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
        "ms10FAUXsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
        "ms10fauxSxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
        "ms10fauxsXXXXXXXXXXXXXXXXXXXXXXXXXXuqxkk05lyf3x2",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxUQXKK05LYF3X2",
    ] {
        assert_eq!(parse(s).err(), Some(Error::MixedCase), "{s}");
    }
}

#[test]
fn spaces_are_presentation_only() {
    // Shown as Coldcard shows it: uppercase, in groups of four.
    let grouped: String = "MS10TESTSXXXXXXXXXXXXXXXXXXXXXXXXXX4NZVCA9CMCZLW"
        .as_bytes()
        .chunks(4)
        .map(|c| core::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(" ");
    let s = ok(&grouped);
    assert_eq!(
        text(&s, false),
        "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlw"
    );
}

#[test]
fn a_character_outside_the_alphabet_is_refused() {
    // `b` in place of an `x`: the length is right, the character is not.
    let bad = "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlw".replacen("xx", "xb", 1);
    assert_eq!(parse(&bad).err(), Some(Error::Character));
}

// ---------------------------------------------------------------------------------------
// Coldcard's extension vectors (hw-reference/codex32-format.md §Conformance vectors [C])
// ---------------------------------------------------------------------------------------

const W7_S: &str = "MS12W7F2SXXXXXXXXXXXXXXXXXXXXXXXXXY9ML44VCLR4TFD";
const W7_A: &str = "MS12W7F2AQQQSYQCYQ5RQWZQFPG9SCRGWPUAM077H9XN5W88";
const W7_C: &str = "MS12W7F2CFFFGRFURFZ6FJVFTLA4GU6AJL3SM7JJ23UZRHJU";
const W7_D: &str = "MS12W7F2D777VW79W7UJ70K7N6H2V9JH06L7MDSSMHQ33LCV";

#[test]
fn ms_two_of_three_any_pair_reconstructs_and_c_d_rederive_a() {
    for pair in [[W7_A, W7_C], [W7_A, W7_D], [W7_C, W7_D]] {
        let s = set_of(&pair).recover(&kw()).unwrap();
        assert_eq!(text(&s, true), W7_S);
    }
    let a = set_of(&[W7_C, W7_D]).interpolate(sym(b'a'), &kw()).unwrap();
    assert_eq!(text(&a, true), W7_A);
}

#[test]
fn cw_shares_recover_the_abandon_about_wallet() {
    let s = set_of(&[
        "CW12W0RDAQQQSYQCYQ5RQWZQFPG9SCRGWPUZVSX8UXYXF6SF",
        "CW12W0RDDQQQJSQMSQZVQ3GQDYF5JMVF3YTUYQALM59R0UK0",
    ])
    .recover(&kw())
    .unwrap();
    assert_eq!(
        text(&s, true),
        "CW12W0RDSQQQQQQQQQQQQQQQQQQQQQQQQQQY7APCDMV8SRFS"
    );
    let secret = s.secret(&kw()).unwrap();
    assert_eq!(secret.hrp(), Hrp::Cw);
    assert_eq!(secret.as_bytes(), &[0u8; 16]);
    // Those bytes are words, not a seed: "abandon ... about", fingerprint 73C5DA0A.
    let k = kw();
    let m = crate::bip39::Mnemonic::from_entropy(secret.as_bytes(), &k).unwrap();
    let mut seed = [0u8; crate::bip39::SEED_LEN];
    m.to_seed("", &mut seed, &k).unwrap();
    let master = ExtendedPrivKey::from_seed(&seed, Network::Mainnet, &k).unwrap();
    assert_eq!(hex(&master.fingerprint(&k)), "73c5da0a");
}

#[test]
fn cx_secret_is_chain_code_then_key() {
    let s = ok(
        "CX12PASSS57YRW3K4CMGARHKLQAGJ8L5YGFJDVWG4YDZYY6TWU92LVR8T3VKRY7PJWSSYQ2DZ7KDJNVM3E06MRS2XZ6FDW37F6SL7MKSF75EWUWSGP3L3LSA0VKS82T",
    );
    let secret = s.secret(&kw()).unwrap();
    assert_eq!(secret.hrp(), Hrp::Cx);
    let b = secret.as_bytes();
    assert_eq!(
        hex(&b[..32]),
        "a7883746d5c6d1d1dedf075123fe844264d63915234442696ee155f60ceb8b2c"
    );
    assert_eq!(
        hex(&b[32..]),
        "32783274204029a2f59b29b371cbf5b1c1461692d747c9d43fedda09f532ee3a"
    );
}

#[test]
fn swapping_the_prefix_breaks_the_checksum() {
    assert_eq!(
        parse("CW10TESTSXXXXXXXXXXXXXXXXXXXXXXXXXX4NZVCA9CMCZLW").err(),
        Some(Error::Checksum)
    );
}

#[test]
fn each_prefix_carries_only_its_own_lengths() {
    let id = seed_id();
    let k = kw();
    for (hrp, good, bad) in [
        (Hrp::Ms, &[16usize, 32, 64][..], &[20usize, 24, 28][..]),
        (Hrp::Cw, &[16, 24, 32], &[20, 28, 64]),
        (Hrp::Cx, &[64], &[16, 32]),
    ] {
        for &n in good {
            let mut bytes = vec![0x5a; n];
            bytes[0] = 1;
            let s = Share::from_bytes(hrp, 0, id, SECRET_INDEX, &bytes, &k).unwrap();
            let written = text(&s, false);
            // ...and what is written parses back to the same bytes.
            let back = ok(&written).secret(&k).unwrap();
            assert_eq!(back.as_bytes(), &bytes[..], "{hrp:?} {n}");
        }
        for &n in bad {
            let bytes = vec![1u8; n];
            assert_eq!(
                Share::from_bytes(hrp, 0, id, SECRET_INDEX, &bytes, &k).err(),
                Some(Error::Length),
                "{hrp:?} {n}"
            );
        }
    }
}

#[test]
fn a_cx_key_outside_the_curve_order_is_not_a_wallet() {
    let k = kw();
    let mut bytes = [0x11u8; 64];
    bytes[32..].fill(0); // k = 0
    let zero = Share::from_bytes(Hrp::Cx, 0, seed_id(), SECRET_INDEX, &bytes, &k).unwrap();
    assert_eq!(zero.secret(&k).err(), Some(Error::Invalid));
    bytes[32..].fill(0xff); // k >= n
    let big = Share::from_bytes(Hrp::Cx, 0, seed_id(), SECRET_INDEX, &bytes, &k).unwrap();
    assert_eq!(big.secret(&k).err(), Some(Error::Invalid));
}

// ---------------------------------------------------------------------------------------
// Collecting a set
// ---------------------------------------------------------------------------------------

#[test]
fn a_share_is_not_a_wallet() {
    assert_eq!(ok(W7_A).secret(&kw()).err(), Some(Error::NotSecret));
}

#[test]
fn the_secret_is_refused_where_a_share_is_wanted() {
    let mut set = Set::new();
    assert_eq!(set.add(ok(W7_S)).err(), Some(Error::SecretNotShare));
    assert!(set.is_empty());
}

#[test]
fn the_same_share_twice_is_refused() {
    let mut set = Set::new();
    set.add(ok(W7_A)).unwrap();
    assert_eq!(set.add(ok(W7_A)).err(), Some(Error::Duplicate));
    assert_eq!(set.len(), 1);
}

#[test]
fn a_share_of_another_set_is_refused() {
    // Same prefix, threshold and length; different identifier.
    let mut set = Set::new();
    set.add(ok(W7_A)).unwrap();
    assert_eq!(
        set.add(ok("MS12NAMECACDEFGHJKLMNPQRSTUVWXYZ023FTR2GDZMPY6PN"))
            .err(),
        Some(Error::Mismatch)
    );
    // Same identifier, another prefix.
    let mut set = Set::new();
    set.add(ok("CW12W0RDAQQQSYQCYQ5RQWZQFPG9SCRGWPUZVSX8UXYXF6SF"))
        .unwrap();
    let ms_same_id = {
        let k = kw();
        let id = [sym(b'w'), sym(b'0'), sym(b'r'), sym(b'd')];
        Share::from_bytes(Hrp::Ms, 2, id, sym(b'c'), &[0u8; 16], &k).unwrap()
    };
    assert_eq!(set.add(ms_same_id).err(), Some(Error::Mismatch));
    // Same identifier, another threshold.
    let mut set = Set::new();
    set.add(ok(V3_A)).unwrap();
    let k = kw();
    let id = [sym(b'c'), sym(b'a'), sym(b's'), sym(b'h')];
    let two = Share::from_bytes(Hrp::Ms, 2, id, sym(b'c'), &[0u8; 16], &k).unwrap();
    assert_eq!(set.add(two).err(), Some(Error::Mismatch));
    // Same everything but length.
    let mut set = Set::new();
    set.add(ok(V3_A)).unwrap();
    let long = Share::from_bytes(Hrp::Ms, 3, id, sym(b'c'), &[0u8; 32], &k).unwrap();
    assert_eq!(set.add(long).err(), Some(Error::Mismatch));
}

#[test]
fn a_set_takes_no_more_than_its_threshold() {
    let mut set = Set::new();
    set.add(ok(W7_A)).unwrap();
    set.add(ok(W7_C)).unwrap();
    assert_eq!(set.add(ok(W7_D)).err(), Some(Error::Full));
}

#[test]
fn fewer_shares_than_the_threshold_recover_nothing() {
    let mut set = Set::new();
    set.add(ok(V3_A)).unwrap();
    set.add(ok(V3_C)).unwrap();
    assert_eq!(set.recover(&kw()).err(), Some(Error::Incomplete));
}

#[test]
fn derive_picks_the_first_unused_index_in_stock_order() {
    let set = set_of(&[W7_A, W7_D]);
    assert_eq!(set.unused_index(), Some(sym(b'c')));
    let c = set.interpolate(set.unused_index().unwrap(), &kw()).unwrap();
    assert_eq!(text(&c, true), W7_C);
}

// ---------------------------------------------------------------------------------------
// Splitting
// ---------------------------------------------------------------------------------------

/// Deterministic stand-in noise for round trips; the firmware's comes from the pool.
fn noise(n: usize, salt: u8) -> Vec<u8> {
    let mut x = 0x9e37_79b9u32 ^ u32::from(salt);
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

#[test]
fn every_threshold_subset_of_a_split_recovers_the_secret() {
    let k = kw();
    for (hrp, len) in [(Hrp::Cw, 24usize), (Hrp::Ms, 64), (Hrp::Cx, 64)] {
        let mut bytes = vec![0u8; len];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(1);
        }
        let secret = Share::from_bytes(hrp, 0, seed_id(), SECRET_INDEX, &bytes, &k).unwrap();
        for t in 2..=4u8 {
            let n = 5usize;
            let basis = split(&secret, t, &noise(noise_len(&secret, t), t), &k).unwrap();
            let shares: Vec<String> = SHARE_ORDER[..n]
                .iter()
                .map(|&i| text(&basis.interpolate(i, &k).unwrap(), false))
                .collect();
            // Every share carries the new threshold and the split's identifier.
            for s in &shares {
                let p = ok(s);
                assert_eq!(p.threshold(), t);
                assert_eq!(p.id(), ok(&shares[0]).id());
            }
            // Any t of the n.
            for mask in 0u32..(1 << n) {
                if mask.count_ones() != u32::from(t) {
                    continue;
                }
                let mut set = Set::new();
                for (i, s) in shares.iter().enumerate() {
                    if mask & (1 << i) != 0 {
                        set.add(ok(s)).unwrap();
                    }
                }
                let back = set.recover(&k).unwrap().secret(&k).unwrap();
                assert_eq!(back.as_bytes(), &bytes[..], "{hrp:?} t={t} mask={mask:b}");
            }
        }
    }
}

#[test]
fn a_split_needs_all_of_its_noise() {
    let k = kw();
    let secret = ok(W7_S);
    let short = noise(noise_len(&secret, 3) - 1, 0);
    assert_eq!(split(&secret, 3, &short, &k).err(), Some(Error::Invalid));
}

#[test]
fn a_split_of_a_share_or_at_a_bad_threshold_is_refused() {
    let k = kw();
    let secret = ok(W7_S);
    let n = noise(200, 1);
    assert_eq!(split(&ok(W7_A), 2, &n, &k).err(), Some(Error::NotSecret));
    for t in [0u8, 1, 10] {
        assert_eq!(
            split(&secret, t, &n, &k).err(),
            Some(Error::Threshold),
            "{t}"
        );
    }
}

#[test]
fn different_noise_gives_a_different_set_of_the_same_secret() {
    let k = kw();
    let secret = ok(W7_S);
    let a = split(&secret, 2, &noise(noise_len(&secret, 2), 1), &k).unwrap();
    let b = split(&secret, 2, &noise(noise_len(&secret, 2), 2), &k).unwrap();
    let a1 = text(&a.interpolate(SHARE_ORDER[0], &k).unwrap(), false);
    let b1 = text(&b.interpolate(SHARE_ORDER[0], &k).unwrap(), false);
    assert_ne!(a1, b1);
    assert_eq!(
        text(&a.recover(&k).unwrap(), false)[9..9 + 26],
        text(&b.recover(&k).unwrap(), false)[9..9 + 26]
    );
}
