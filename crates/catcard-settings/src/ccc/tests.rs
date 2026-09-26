use super::*;
use crate::policy::may_save;

const BTC: u64 = 100_000_000;
const A1: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
const A2: &str = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";

/// Key C for these tests: the BIP-39 vector `7f` x 16, "legal winner thank year wave
/// sausage worth useful legal winner thank yellow".
const PHRASE: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";
/// Its fingerprint and master xpub, worked out independently of this crate (a short
/// Python BIP-32 over hashlib, not this firmware's code).
const XFP: [u8; 4] = [0xB8, 0x68, 0x8D, 0xF1];
const XFP_LE: u32 = 4_052_576_440;
const XPUB: &str = "xpub661MyMwAqRbcFS99u1xBNnVxPAryKPgzZkXXUngFVKHWRx6uJMCLsz4U56FN7PxTSeVqL8tPJpiCrs1KZh1dV2Bh6QyAbmNmjFRPnkrZP52";

/// The value as stock would write it at setup: the words-type stash of key C with the
/// trailing padding stripped, `c_xfp` little-endian, the master xpub, the default policy
/// (`mag` 1 = one bitcoin). Key order is ujson's, which is not ours.
fn stock_value() -> String {
    format!(
        r#"{{"c_xpub":"{XPUB}","pol":{{"web2fa":"","addrs":[],"block_h":0,"vel":144,"mag":1}},"secret":"807F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F","c_xfp":{XFP_LE}}}"#
    )
}

fn settings(value: &str) -> String {
    format!(r#"{{"_age":3,"chain":"BTC","ccc":{value}}}"#)
}

fn read_value(value: &str) -> Read {
    let text = settings(value);
    // Leak for the test's lifetime: `Doc` borrows the text.
    let text: &'static str = Box::leak(text.into_boxed_str());
    read(&Doc::parse(text.as_bytes()).unwrap())
}

fn the_ccc(value: &str) -> Ccc {
    match read_value(value) {
        Read::Ccc(c) => c,
        other => panic!("{value}: {other:?}"),
    }
}

fn encoded(entropy: &[u8]) -> [u8; SECRET_LEN] {
    let mut out = [0u8; SECRET_LEN];
    out[0] = 0x80 | ((entropy.len() / 8 - 2) as u8);
    out[1..1 + entropy.len()].copy_from_slice(entropy);
    out
}

// ---------------------------------------------------------------------------------------
// The stored value
// ---------------------------------------------------------------------------------------

/// Stock's value reads field for field: the secret is a 12-word stash, `c_xfp` is the
/// fingerprint's bytes little-endian, `mag` 1 is one bitcoin, `block_h` is the last height.
#[test]
fn a_stock_value_reads_field_for_field() {
    let c = the_ccc(&stock_value());
    assert_eq!(c.secret()[0], 0x80);
    assert_eq!(c.entropy(), &[0x7F; 16]);
    assert!(
        c.secret()[17..].iter().all(|&b| b == 0),
        "padded to the slot"
    );
    assert_eq!(c.word_count(), 12);
    assert_eq!(c.xfp, XFP);
    assert_eq!(c.xfp_number(), XFP_LE);
    assert_eq!(c.xpub.as_str(), XPUB);
    assert_eq!(c.policy.magnitude, BTC);
    assert_eq!(c.policy.velocity, 144);
    assert_eq!(c.policy.last_height, 0);
    assert!(c.policy.whitelist.is_empty());
    assert!(c.web2fa.is_empty());
}

/// What we write is stock's shape with stock's names, and reads back as itself -- and a
/// fresh key C starts from exactly the policy stock's setup writes.
#[test]
fn a_rendered_value_is_stocks_shape_and_round_trips() {
    let c = Ccc::new(&encoded(&[0x7F; 16]), XFP, XPUB).unwrap();
    let mut buf = [0u8; RENDER_MAX];
    let text = c.render(&mut buf).unwrap();
    assert_eq!(
        text,
        format!(
            r#"{{"secret":"807F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F","c_xfp":{XFP_LE},"c_xpub":"{XPUB}","pol":{{"mag":100000000,"vel":144,"block_h":0,"web2fa":"","addrs":[]}}}}"#
        )
    );
    let back = the_ccc(text);
    assert_eq!(back.secret(), c.secret());
    assert_eq!(back.xfp, c.xfp);
    assert_eq!(back.xpub, c.xpub);
    assert_eq!(back.policy, c.policy);

    // The same policy as stock's own fresh value, whose `mag` is written as bitcoin.
    let stock = the_ccc(&stock_value());
    assert_eq!(stock.policy, c.policy);
    assert_eq!(stock.secret(), c.secret());
}

/// A full value -- 24 words, a whitelist, a height, a Web 2FA secret from stock -- round
/// trips, and the Web 2FA secret is carried, not dropped.
#[test]
fn every_field_survives_a_rewrite() {
    let mut c = Ccc::new(&encoded(&[0x5A; 32]), [1, 2, 3, 4], XPUB).unwrap();
    c.policy.magnitude = 12_345;
    c.policy.velocity = 6;
    c.policy.last_height = 850_000;
    c.policy.add_address(A1).unwrap();
    c.policy.add_address(A2).unwrap();
    c.web2fa.push_str("JBSWY3DPEHPK3PXP").unwrap();
    let mut buf = [0u8; RENDER_MAX];
    let text = c.render(&mut buf).unwrap().to_string();
    let back = the_ccc(&text);
    assert_eq!(back.word_count(), 24);
    assert_eq!(back.secret(), c.secret());
    assert_eq!(back.xfp_number(), 0x0403_0201);
    assert_eq!(back.policy, c.policy);
    assert_eq!(back.web2fa.as_str(), "JBSWY3DPEHPK3PXP");
}

/// Stock strips trailing zero bytes from the hex, which can eat into the entropy itself;
/// read back, the slot is padded out and the key is the same key.
#[test]
fn trailing_zero_entropy_survives_stocks_stripping() {
    let mut ent = [0x11u8; 16];
    ent[14] = 0;
    ent[15] = 0;
    let c = Ccc::new(&encoded(&ent), XFP, XPUB).unwrap();
    let mut buf = [0u8; RENDER_MAX];
    let text = c.render(&mut buf).unwrap().to_string();
    assert!(text.contains(r#""secret":"801111111111111111111111111111","#));
    let back = the_ccc(&text);
    assert_eq!(back.entropy(), &ent);
    assert!(back.matches(&encoded(&ent)));
}

/// No key C is absent; so is stock's removed key written back as `null`.
#[test]
fn nothing_there_is_absent() {
    let doc = Doc::parse(br#"{"_age":1}"#).unwrap();
    assert!(matches!(read(&doc), Read::Absent));
    for v in ["null", "false", "{}"] {
        assert!(matches!(read_value(v), Read::Absent), "{v}");
    }
}

/// Anything present and wrong is damaged -- never absent, never a policy that allows.
#[test]
fn anything_malformed_is_damaged() {
    let good = stock_value();
    for bad in [
        // Not hex, odd length, too long for the slot.
        good.replace("807F7F", "80ZZ7F"),
        good.replace("807F7F", "807F7"),
        good.replace(
            "807F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F",
            &"80".repeat(SECRET_LEN + 1),
        ),
        // An XPRV or a raw master is not a phrase: nothing to challenge for.
        good.replace("807F7F", "017F7F"),
        good.replace("807F7F", "107F7F"),
        // Missing or wrong fields.
        good.replace(&format!(r#","c_xfp":{XFP_LE}"#), ""),
        good.replace(&XFP_LE.to_string(), "4294967296"),
        good.replace(r#""vel":144"#, r#""vel":99999999"#),
        good.replace(r#""mag":1"#, r#""mag":-1"#),
        good.replace(r#""mag":1"#, r#""mag":"1""#),
        good.replace(r#""addrs":[]"#, r#""addrs":["not an address"]"#),
        good.replace(r#""web2fa":"""#, r#""web2fa":7"#),
        good.replace(
            r#""pol":{"web2fa":"","addrs":[],"block_h":0,"vel":144,"mag":1},"#,
            "",
        ),
        "[]".to_string(),
        r#""on""#.to_string(),
    ] {
        assert!(matches!(read_value(&bad), Read::Damaged), "{bad}");
    }
}

/// `mag` is bitcoin below 1000 and satoshis from 1000 up, as stock reads it -- fractions
/// and Python's exponent form included -- and what we write reads back to the same amount.
#[test]
fn magnitude_is_read_and_written_as_stock_reads_it() {
    for (text, sats) in [
        ("0", Some(0)),
        ("1", Some(BTC)),
        ("0.5", Some(BTC / 2)),
        ("1.0", Some(BTC)),
        ("999", Some(999 * BTC)),
        ("999.99999999", Some(99_999_999_999)),
        ("1000", Some(1000)),
        ("250000", Some(250_000)),
        ("1e-05", Some(1000)),
        ("5E-06", Some(500)),
        ("2.5e3", Some(2500)),
        ("1e8", Some(BTC)),
        // A fraction of a satoshi, either way.
        ("0.000000001", None),
        ("1500.5", None),
        ("", None),
        ("-1", None),
        ("1x", None),
        ("1e", None),
    ] {
        assert_eq!(parse_magnitude(text), sats, "{text}");
    }
    for sats in [0, 1, 500, 999, 1000, 1001, BTC, 21_000_000 * BTC] {
        let mut buf = [0u8; 24];
        let text = render_magnitude(sats, &mut buf);
        assert_eq!(parse_magnitude(text), Some(sats), "{sats} -> {text}");
    }
    let mut buf = [0u8; 24];
    assert_eq!(render_magnitude(500, &mut buf), "0.000005");
}

/// Stock's `c_xfp` is the fingerprint read little-endian; ours is written the same way.
#[test]
fn c_xfp_is_little_endian() {
    let c = Ccc::new(&encoded(&[0x7F; 16]), XFP, XPUB).unwrap();
    assert_eq!(c.xfp_number(), u32::from_le_bytes(XFP));
    assert_eq!(c.xfp_number(), 0xF18D_68B8);
}

/// A secret that is not a phrase's encoding cannot become key C.
#[test]
fn key_c_is_always_a_phrase() {
    let mut xprv = [0u8; SECRET_LEN];
    xprv[0] = 0x01;
    assert!(Ccc::new(&xprv, XFP, XPUB).is_none());
    assert!(Ccc::new(&encoded(&[1; 16]), XFP, "with \"quote").is_none());
    assert_eq!(words_of(&encoded(&[1; 24])), Some(18));
}

/// The secret never reaches a debug print.
#[test]
fn debug_does_not_print_the_secret() {
    let c = Ccc::new(&encoded(&[0xAB; 16]), XFP, XPUB).unwrap();
    let s = format!("{c:?}");
    assert!(
        !s.contains("171") && !s.to_lowercase().contains("abab"),
        "{s}"
    );
}

/// The co-signing key's object may be written while the single-signer policy hobbles the
/// device: a co-signature there still records its height.
#[test]
fn the_ccc_keys_may_be_saved_while_hobbled() {
    assert!(may_save(KEY));
    assert!(may_save(VIOLATION_KEY));
}

// ---------------------------------------------------------------------------------------
// The key-C challenge
// ---------------------------------------------------------------------------------------

/// The whole phrase is compared, not its ends: the same first and last word with one
/// word between them changed is not key C.
#[test]
fn the_challenge_compares_the_whole_key() {
    let c = Ccc::new(&encoded(&[0x7F; 16]), XFP, XPUB).unwrap();
    assert!(c.matches(&encoded(&[0x7F; 16])));
    let mut middle = [0x7F; 16];
    middle[8] ^= 0x01;
    assert!(!c.matches(&encoded(&middle)));
    // A 24-word phrase that begins with the same sixteen bytes is another key.
    let mut longer = [0x7F; 32];
    longer[31] = 0;
    assert!(!c.matches(&encoded(&longer)));
}

/// Three wrong phrases in a session restart the device; a right one in between does not
/// reset the count.
#[test]
fn three_wrong_phrases_restart() {
    let mut fails = 0u8;
    assert_eq!(challenge(false, &mut fails), Challenge::Wrong { left: 2 });
    assert_eq!(challenge(true, &mut fails), Challenge::Pass);
    assert_eq!(challenge(false, &mut fails), Challenge::Wrong { left: 1 });
    assert_eq!(challenge(false, &mut fails), Challenge::Shutdown);
    assert_eq!(challenge(false, &mut fails), Challenge::Shutdown);
}

// ---------------------------------------------------------------------------------------
// The co-signing decision
// ---------------------------------------------------------------------------------------

fn out(index: usize, amount: u64, change: bool, address: &str) -> Out<'_> {
    Out {
        index,
        amount,
        change,
        address,
    }
}

fn fresh() -> Ccc {
    Ccc::new(&encoded(&[0x7F; 16]), XFP, XPUB).unwrap()
}

/// The default policy: up to one bitcoin, one spend per 144 blocks by the lock-time height.
#[test]
fn a_fresh_key_c_co_signs_within_one_bitcoin_per_day() {
    let c = fresh();
    let outs = [out(0, BTC / 2, false, A1), out(1, 3 * BTC, true, A2)];
    assert_eq!(
        judge(&c, &outs, BTC / 2, Some(850_000), false),
        Ok(Cosign {
            record_height: Some(850_000)
        })
    );
    // Over the cap: change never counts, what leaves does.
    assert_eq!(
        judge(&c, &outs, 2 * BTC, Some(850_000), false),
        Err(Violation::Magnitude {
            sending: 2 * BTC,
            cap: BTC
        })
    );
    // No height to measure by.
    assert_eq!(
        judge(&c, &outs, BTC / 2, None, false),
        Err(Violation::NoHeight)
    );
}

/// Velocity counts from the last co-signature's height.
#[test]
fn velocity_counts_from_block_h() {
    let mut c = fresh();
    c.policy.last_height = 850_000;
    assert_eq!(
        judge(&c, &[], 1000, Some(850_143), false),
        Err(Violation::TooSoon {
            height: 850_143,
            allowed_at: 850_144
        })
    );
    // A height behind the last one is a rewind, and refused the same way.
    assert!(judge(&c, &[], 1000, Some(849_000), false).is_err());
    assert_eq!(
        judge(&c, &[], 1000, Some(850_144), false),
        Ok(Cosign {
            record_height: Some(850_144)
        })
    );
}

/// `block_h` only goes up, and is bumped on every co-signature even with velocity off.
#[test]
fn block_h_is_strictly_ascending() {
    let mut c = fresh();
    c.policy.velocity = 0;
    c.policy.last_height = 900_000;
    assert_eq!(
        judge(&c, &[], 1000, Some(900_001), false),
        Ok(Cosign {
            record_height: Some(900_001)
        })
    );
    assert_eq!(
        judge(&c, &[], 1000, Some(899_999), false),
        Ok(Cosign {
            record_height: None
        })
    );
    assert_eq!(
        judge(&c, &[], 1000, None, false),
        Ok(Cosign {
            record_height: None
        })
    );
}

/// Every paying output must be whitelisted; change and a bare `OP_RETURN` pass.
#[test]
fn the_whitelist_applies_to_co_signing() {
    let mut c = fresh();
    c.policy.velocity = 0;
    c.policy.add_address(A1).unwrap();
    let ok = [
        out(0, 1000, false, A1),
        out(1, 5000, true, A2),
        out(2, 0, false, ""),
    ];
    assert!(judge(&c, &ok, 1000, None, false).is_ok());
    let bad = [out(0, 1000, false, A1), out(1, 1000, false, A2)];
    assert_eq!(
        judge(&c, &bad, 2000, None, false),
        Err(Violation::NotWhitelisted { index: 1 })
    );
}

/// A review warning refuses the co-signature before anything else is looked at.
#[test]
fn warnings_refuse_the_co_signature() {
    let c = fresh();
    assert_eq!(
        judge(&c, &[], 1000, Some(850_000), true),
        Err(Violation::Warnings)
    );
}

/// A Web 2FA rule enrolled on stock can never be met here, so it never co-signs -- and it
/// says why.
#[test]
fn a_web2fa_rule_is_never_met() {
    let mut c = fresh();
    c.web2fa.push_str("JBSWY3DPEHPK3PXP").unwrap();
    assert_eq!(
        judge(&c, &[], 1000, Some(850_000), false),
        Err(Violation::Web2fa)
    );
    assert_eq!(Violation::Web2fa.describe(), "needs Web 2FA, not supported");
}

// ---------------------------------------------------------------------------------------
// Against the wallet code
// ---------------------------------------------------------------------------------------

mod wallet {
    use super::*;
    use catcard_wallet::KeyWork;
    use catcard_wallet::bip32::serialize::Slip132;
    use catcard_wallet::bip32::{ChildNumber, ExtendedPrivKey, Network};
    use catcard_wallet::bip39::{Mnemonic, SEED_LEN};
    use catcard_wallet::multisig::export;

    fn master_of(c: &Ccc) -> ExtendedPrivKey {
        let kw = KeyWork::host();
        let m = Mnemonic::from_entropy(c.entropy(), &kw).unwrap();
        let mut seed = [0u8; SEED_LEN];
        m.to_seed("", &mut seed, &kw).unwrap();
        ExtendedPrivKey::from_seed(&seed, Network::Mainnet, &kw).unwrap()
    }

    /// Stock's value names the key its secret holds: the phrase, the fingerprint, the
    /// master xpub.
    #[test]
    fn the_stored_secret_is_the_key_it_names() {
        let kw = KeyWork::host();
        let c = the_ccc(&stock_value());
        let m = Mnemonic::from_entropy(c.entropy(), &kw).unwrap();
        let words: Vec<&str> = m.words().collect();
        assert_eq!(words.join(" "), PHRASE);
        let master = master_of(&c);
        assert_eq!(master.fingerprint(&kw), c.xfp);
        let mut buf = [0u8; 128];
        let n = master.to_extended_pub(&kw).write_base58(&mut buf).unwrap();
        assert_eq!(core::str::from_utf8(&buf[..n]).unwrap(), c.xpub.as_str());

        // Typed back in, the phrase re-encodes to exactly what is stored.
        let typed = Mnemonic::parse(PHRASE, &kw).unwrap();
        assert!(c.matches(&encoded(typed.entropy())));
    }

    /// Export CCC XPUBs: key C's three legs as Format L, to the byte. The expected text
    /// was built from the reference's layout by an independent implementation.
    /// Source: hw-reference/wallet-export-formats.md §"Format L" [C];
    /// ccc-key-storage.md §2 "`ccxp-{C_XFP}.json`" [C]
    #[test]
    fn key_cs_ccxp_is_format_l_to_the_byte() {
        let kw = KeyWork::host();
        let c = the_ccc(&stock_value());
        let master = master_of(&c);
        let at = |steps: &[u32]| {
            let mut key = master.clone();
            for &s in steps {
                key = key
                    .derive_child(ChildNumber::hardened(s).unwrap(), &kw)
                    .unwrap();
            }
            key.to_extended_pub(&kw)
        };
        let (p2sh, p2sh_p2wsh, p2wsh) = (at(&[45]), at(&[48, 0, 0, 1]), at(&[48, 0, 0, 2]));
        let mut out = [0u8; 4096];
        let n = export::ccxp(
            &export::OurKeys {
                fingerprint: c.xfp,
                account: 0,
                coin: 0,
                p2sh: Some(&p2sh),
                p2sh_p2wsh: &p2sh_p2wsh,
                p2wsh: &p2wsh,
            },
            &mut out,
        )
        .unwrap();
        let want = "{\n  \"p2sh_deriv\": \"m/45h\",\n  \"p2sh\": \"xpub69F7Wq4sNAW5Pn3yZHGE4hygVRSHhM7uMpkD1Ah7amz8iiCcvX5ESpLSUafwHJZP64bz5Ls69RwRZpvTLbxVpc8M59KtYQpPHnsF2MoDZJY\",\n  \"p2sh_p2wsh_deriv\": \"m/48h/0h/0h/1h\",\n  \"p2sh_p2wsh\": \"Ypub6m9L12PdR4EsxaoFJqeHRTG91qyBwpFgpyYo1Nk4mmzv6KZEPtaEuyxa1fYPoTUaMmdL4SXeoYSj4mRFLts711LAwPTLZBs5XEoVHEZGzTF\",\n  \"p2sh_p2wsh_desc\": \"sh(wsh(sortedmulti(M,[b8688df1/48h/0h/0h/1h]xpub6FQya7zGhR92giSkXpPgPHpq85nUnqabbbNuJiae1zndR3B6Nq2QCoSWBkdLF7bkifSYSNvyTfhg4KBvKyJ94HXuEaeWZsabMnTyJiPz21N/0/*,...)))\",\n  \"p2wsh_deriv\": \"m/48h/0h/0h/2h\",\n  \"p2wsh\": \"Zpub75ybJh4YZjnMskAAUkpy6uLizWcTTRC91yDtz9RcRwtavi4wHpBPZDEYUu9LoAPb6NQZNqKd6eKqF4FhqgWSaWQdqSt4FmdQkQH9uMmHhSh\",\n  \"p2wsh_desc\": \"wsh(sortedmulti(M,[b8688df1/48h/0h/0h/2h]xpub6FQya7zGhR92kacYsNnjreouvnHJMpXYsUXnW6NJJAJRCKsa26TzDy4LdnGhEurr3d6y1J8PJ7EEMKQp74XTqYvmGJNogYXSKDszYHtF8mX/0/*,...))\",\n  \"account\": \"0\",\n  \"xfp\": \"B8688DF1\"\n}\n";
        assert_eq!(core::str::from_utf8(&out[..n]).unwrap(), want);
        // The SLIP-132 forms are the same keys the classic ones are.
        let mut a = [0u8; 128];
        let na = p2wsh.write_base58_as(Slip132::P2wsh, &mut a).unwrap();
        assert!(want.contains(core::str::from_utf8(&a[..na]).unwrap()));
    }
}
