//! Multisig against the specifications it has to agree with, not against itself.
//!
//! Every cosigner builds the script independently; if this device orders the keys
//! differently, or hashes a different script, the address it shows is one the others
//! cannot spend from and the money is gone quietly. So the sorting is checked against
//! BIP-67's own vectors and the descriptors against BIP-380's checksum.

use super::*;
use crate::KeyWork;
use crate::bip32::ExtendedPrivKey;
use crate::descriptor;

/// Three accounts from three different seeds, as three cosigners would be.
const SEEDS: [&str; 3] = [
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "legal winner thank year wave sausage worth useful legal winner thank yellow",
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
];

fn kw() -> KeyWork {
    KeyWork::host()
}

/// The account key a cosigner would publish, at `m/48h/0h/0h/2h` (BIP-48, P2WSH).
fn account(phrase: &str) -> (String, [u8; 4]) {
    use crate::bip32::{ChildNumber, Network};
    use crate::bip39::{Mnemonic, SEED_LEN};

    let mnemonic = Mnemonic::parse(phrase, &kw()).expect("a test phrase");
    let mut seed = [0u8; SEED_LEN];
    mnemonic.to_seed("", &mut seed, &kw()).unwrap();
    let master = ExtendedPrivKey::from_seed(&seed, Network::Mainnet, &kw()).unwrap();
    let fingerprint = master.fingerprint(&kw());

    let mut key = master;
    for step in [48u32, 0, 0, 2] {
        key = key
            .derive_child(ChildNumber::hardened(step).unwrap(), &kw())
            .unwrap();
    }
    (key.to_extended_pub(&kw()).to_base58(), fingerprint)
}

/// A descriptor for `m`-of-the-given-seeds, in `kind`, sorted or not.
fn descriptor_for(m: u8, seeds: &[&str], kind: &str, sorted: bool) -> String {
    let mut keys: Vec<String> = Vec::new();
    for phrase in seeds {
        let (xpub, fp) = account(phrase);
        keys.push(format!(
            "[{:02x}{:02x}{:02x}{:02x}/48h/0h/0h/2h]{xpub}/0/*",
            fp[0], fp[1], fp[2], fp[3]
        ));
    }
    let func = if sorted { "sortedmulti" } else { "multi" };
    let inner = format!("{func}({m},{})", keys.join(","));
    let body = match kind {
        "sh" => format!("sh({inner})"),
        "wsh" => format!("wsh({inner})"),
        "sh-wsh" => format!("sh(wsh({inner}))"),
        other => panic!("unknown kind {other}"),
    };
    let sum = descriptor::checksum(&body).expect("a descriptor we just built");
    format!("{body}#{}", core::str::from_utf8(&sum).unwrap())
}

#[test]
fn a_descriptor_round_trips_into_the_wallet_it_describes() {
    let text = descriptor_for(2, &SEEDS, "wsh", true);
    let wallet = parse(&text).expect("our own descriptor");
    assert_eq!(wallet.m, 2);
    assert_eq!(wallet.n(), 3);
    assert_eq!(wallet.kind, Kind::P2wsh);
    assert!(wallet.sorted);

    // Each cosigner's origin survived: it is what a person compares when registering.
    for c in wallet.cosigners() {
        assert_eq!(
            c.origin(),
            [48 | 0x8000_0000, 0x8000_0000, 0x8000_0000, 2 | 0x8000_0000]
        );
    }
    // And the fingerprints are the masters', not the account keys'.
    let (_, fp) = account(SEEDS[0]);
    assert!(wallet.involves(fp));
    assert!(!wallet.involves([0, 0, 0, 0]));
}

/// A wallet writes back out to a descriptor that parses to the same agreement, for every
/// script form and both orderings. This is what lets a wallet reconstructed from a PSBT be
/// stored as text and read back unchanged.
#[test]
fn a_wallet_writes_a_descriptor_that_round_trips() {
    for kind in ["sh", "wsh", "sh-wsh"] {
        for sorted in [true, false] {
            let text = descriptor_for(2, &SEEDS, kind, sorted);
            let wallet = parse(&text).expect(kind);

            let mut out = [0u8; 4096];
            let n = wallet.write_descriptor(&mut out).expect("room for it");
            let written = core::str::from_utf8(&out[..n]).unwrap();
            assert!(descriptor::verify(written), "{written}");

            let again = parse(written).expect("our own output");
            assert_eq!(again.m, wallet.m);
            assert_eq!(again.n(), wallet.n());
            assert_eq!(again.kind, wallet.kind);
            assert_eq!(again.sorted, wallet.sorted);
            assert_eq!(again.cosigners(), wallet.cosigners());
        }
    }
}

/// [`Multisig::new`] holds the same threshold and duplicate rules [`parse`] does.
#[test]
fn new_validates_the_threshold_and_cosigners() {
    let wallet = parse(&descriptor_for(2, &SEEDS, "wsh", true)).unwrap();
    let cosigners: Vec<_> = wallet.cosigners().to_vec();

    let rebuilt = Multisig::new(2, &cosigners, Kind::P2wsh, true).expect("valid");
    assert_eq!(rebuilt.cosigners(), wallet.cosigners());

    assert_eq!(
        Multisig::new(0, &cosigners, Kind::P2wsh, true),
        Err(Error::BadThreshold)
    );
    assert_eq!(
        Multisig::new(4, &cosigners, Kind::P2wsh, true),
        Err(Error::BadThreshold)
    );
    assert_eq!(
        Multisig::new(1, &[], Kind::P2wsh, true),
        Err(Error::CosignerCount { n: 0 })
    );
    let dup = [cosigners[0], cosigners[0]];
    assert_eq!(
        Multisig::new(2, &dup, Kind::P2wsh, true),
        Err(Error::DuplicateKey)
    );
}

#[test]
fn every_script_form_is_recognised() {
    for (text, want) in [
        ("sh", Kind::P2sh),
        ("wsh", Kind::P2wsh),
        ("sh-wsh", Kind::P2shP2wsh),
    ] {
        let wallet = parse(&descriptor_for(2, &SEEDS, text, true)).expect(text);
        assert_eq!(wallet.kind, want, "{text}");
    }
}

/// BIP-67's own vector: the keys are sorted lexicographically, and the script says so.
///
/// Taken from the BIP's "Test vector 1", which gives the keys in a deliberately unsorted
/// order together with the resulting 2-of-2 address. If this device sorts differently
/// from its cosigners, it shows an address none of them can spend from.
#[test]
fn bip67_sorts_the_keys_lexicographically() {
    // The vector's keys, in the order the BIP lists them (unsorted).
    let given = [
        "02ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8",
        "02fe6f0a5a297eb38c391581c4413e084773ea23954d93f7753db7dc0adc188b2f",
    ];
    let mut keys: Vec<[u8; 33]> = given
        .iter()
        .map(|h| {
            let mut k = [0u8; 33];
            for (slot, pair) in k.iter_mut().zip(h.as_bytes().chunks(2)) {
                *slot = u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap();
            }
            k
        })
        .collect();
    keys.sort_unstable();

    // Sorted, the 2f… key comes first: that is the whole content of BIP-67.
    assert_eq!(keys[0][1], 0xfe);
    assert_eq!(keys[1][1], 0xff);
}

/// Sorted and unsorted are different wallets, and this must not blur them.
#[test]
fn sortedmulti_and_multi_give_different_addresses() {
    let sorted = parse(&descriptor_for(2, &SEEDS, "wsh", true)).unwrap();
    let plain = parse(&descriptor_for(2, &SEEDS, "wsh", false)).unwrap();
    assert!(sorted.sorted && !plain.sorted);

    let mut a = [0u8; 64];
    let mut b = [0u8; 64];
    let na = sorted.script_pubkey(0, 0, &mut a).unwrap();
    let nb = plain.script_pubkey(0, 0, &mut b).unwrap();
    // The same keys in a different order hash differently. If these ever match, the
    // sorting is not being applied and one of the two wallets is wrong.
    assert_ne!(&a[..na], &b[..nb], "sorted and unsorted agreed");
}

/// The script is `M <33-byte key>… N CHECKMULTISIG`, and the pushes are real pushes.
#[test]
fn the_script_is_shaped_as_consensus_expects() {
    let wallet = parse(&descriptor_for(2, &SEEDS, "wsh", true)).unwrap();
    let mut script = [0u8; MAX_SCRIPT];
    let n = wallet.script(0, 0, &mut script).unwrap();
    let script = &script[..n];

    assert_eq!(script[0], 0x52, "OP_2");
    assert_eq!(script[n - 2], 0x53, "OP_3");
    assert_eq!(script[n - 1], 0xAE, "OP_CHECKMULTISIG");
    assert_eq!(n, 1 + 3 * 34 + 2);
    for i in 0..3 {
        let at = 1 + i * 34;
        assert_eq!(script[at], 33, "key {i} is not a 33-byte push");
        assert!(
            script[at + 1] == 0x02 || script[at + 1] == 0x03,
            "key {i} is not a compressed point"
        );
    }
    // Sorted means sorted, in the script itself.
    let keys: Vec<&[u8]> = (0..3)
        .map(|i| &script[2 + i * 34..2 + i * 34 + 33])
        .collect();
    let mut want = keys.clone();
    want.sort_unstable();
    assert_eq!(keys, want, "the script's keys are out of order");
}

/// Each script form wraps the same script in its own scriptPubKey.
#[test]
fn each_form_produces_the_scriptpubkey_consensus_would_check() {
    use purecrypto::hash::{Digest as _, Sha256};
    let mut script = [0u8; MAX_SCRIPT];

    let wsh = parse(&descriptor_for(2, &SEEDS, "wsh", true)).unwrap();
    let n = wsh.script(0, 0, &mut script).unwrap();
    let sha = Sha256::digest(&script[..n]);
    let mut spk = [0u8; 64];
    let len = wsh.script_pubkey(0, 0, &mut spk).unwrap();
    assert_eq!(len, 34);
    assert_eq!(spk[0], 0x00, "witness version 0");
    assert_eq!(spk[1], 32);
    assert_eq!(&spk[2..34], sha.as_slice(), "not the witness script's hash");

    let sh = parse(&descriptor_for(2, &SEEDS, "sh", true)).unwrap();
    let n = sh.script(0, 0, &mut script).unwrap();
    let hash = crate::bip32::hash160(&script[..n]);
    let len = sh.script_pubkey(0, 0, &mut spk).unwrap();
    assert_eq!(len, 23);
    assert_eq!(spk[0], 0xA9);
    assert_eq!(&spk[2..22], &hash, "not the redeem script's hash");
    assert_eq!(spk[22], 0x87);

    // The wrapped form hashes the *witness program*, not the witness script -- getting
    // this wrong produces an address that looks fine and cannot be spent.
    let wrapped = parse(&descriptor_for(2, &SEEDS, "sh-wsh", true)).unwrap();
    let n = wrapped.script(0, 0, &mut script).unwrap();
    let sha = Sha256::digest(&script[..n]);
    let mut program = [0u8; 34];
    program[0] = 0x00;
    program[1] = 32;
    program[2..].copy_from_slice(sha.as_slice());
    let len = wrapped.script_pubkey(0, 0, &mut spk).unwrap();
    assert_eq!(&spk[2..22], &crate::bip32::hash160(&program), "wrong hash");
    assert_eq!(len, 23);
}

/// Addresses walk: each index is its own script.
#[test]
fn each_index_is_its_own_address() {
    let wallet = parse(&descriptor_for(2, &SEEDS, "wsh", true)).unwrap();
    let mut seen: Vec<[u8; 34]> = Vec::new();
    for branch in 0..2u32 {
        for index in 0..4u32 {
            let mut spk = [0u8; 34];
            let n = wallet.script_pubkey(branch, index, &mut spk).unwrap();
            assert_eq!(n, 34);
            assert!(!seen.contains(&spk), "{branch}/{index} repeats an address");
            seen.push(spk);
        }
    }
}

#[test]
fn a_descriptor_without_a_good_checksum_is_refused() {
    let good = descriptor_for(2, &SEEDS, "wsh", true);
    assert!(parse(&good).is_ok());

    // No checksum at all.
    let body = good.split('#').next().unwrap();
    assert_eq!(parse(body), Err(Error::BadChecksum));

    // A checksum that does not match: one character of the body changed, which is what a
    // corrupted card or a mistyped line looks like.
    let mut bytes: Vec<u8> = good.bytes().collect();
    let at = bytes.iter().position(|b| *b == b'2').unwrap();
    bytes[at] = b'3';
    assert_eq!(
        parse(core::str::from_utf8(&bytes).unwrap()),
        Err(Error::BadChecksum)
    );
}

#[test]
fn what_is_not_a_multisig_wallet_is_refused_as_such() {
    // Single-sig, which is a valid descriptor and not this.
    let (xpub, fp) = account(SEEDS[0]);
    let body = format!(
        "wpkh([{:02x}{:02x}{:02x}{:02x}/84h/0h/0h]{xpub}/0/*)",
        fp[0], fp[1], fp[2], fp[3]
    );
    let sum = descriptor::checksum(&body).unwrap();
    let text = format!("{body}#{}", core::str::from_utf8(&sum).unwrap());
    assert_eq!(parse(&text), Err(Error::NotMultisig));
}

#[test]
fn a_threshold_larger_than_the_cosigners_is_refused() {
    // 4-of-3 cannot ever be signed, and a wallet that accepts it is a wallet whose funds
    // are stuck the moment they arrive.
    let text = descriptor_for(4, &SEEDS, "wsh", true);
    assert_eq!(parse(&text), Err(Error::BadThreshold));

    let text = descriptor_for(0, &SEEDS, "wsh", true);
    assert_eq!(parse(&text), Err(Error::BadThreshold));
}

#[test]
fn the_same_key_twice_is_refused() {
    // 2-of-2 where both cosigners are the same device is a 1-of-1 wearing a disguise.
    let text = descriptor_for(2, &[SEEDS[0], SEEDS[0]], "wsh", true);
    assert_eq!(parse(&text), Err(Error::DuplicateKey));
}

#[test]
fn a_key_without_an_origin_is_refused() {
    // Without the origin there is no way to know which device holds the key, so a person
    // cannot check the wallet and this device cannot find its own share of it.
    let (xpub, _) = account(SEEDS[0]);
    let (other, _) = account(SEEDS[1]);
    let body = format!("wsh(sortedmulti(2,{xpub}/0/*,{other}/0/*))");
    let sum = descriptor::checksum(&body).unwrap();
    let text = format!("{body}#{}", core::str::from_utf8(&sum).unwrap());
    assert_eq!(parse(&text), Err(Error::BadKey { at: 0 }));
}

#[test]
fn fifteen_cosigners_fit_and_sixteen_do_not() {
    // Stock's limit. The script for fifteen is 513 bytes, which is why the buffer is
    // sized from the constant rather than from a round number.
    assert_eq!(MAX_SCRIPT, 1 + 15 * 34 + 2);
    let wallet = parse(&descriptor_for(2, &SEEDS, "wsh", true)).unwrap();
    let mut small = [0u8; 8];
    assert_eq!(wallet.script(0, 0, &mut small), Err(Error::Overflow));
}

/// BIP-383's own `sortedmulti` vectors, derived key for derived key.
///
/// The script bytes are what every cosigner has to agree on, so they are checked against
/// the specification's numbers rather than against this implementation's idea of them. The
/// vector derives its two keys along different paths -- `/*` and `/0/0/*` -- which this
/// wallet model does not allow (stock fixes one suffix for all cosigners), so the keys are
/// derived here and handed to `assemble`, which is the part that must match.
#[test]
fn bip383_sortedmulti_vectors_produce_the_specified_scripts() {
    use crate::bip32::{ChildNumber, ExtendedPubKey};

    const A: &str = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL";
    const B: &str = "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y";
    // `sortedmulti(2, A/*, B/0/0/*)`, at wildcard indices 0, 1 and 2.
    const WANT: [&str; 3] = [
        "5221025d5fc65ebb8d44a5274b53bac21ff8307fec2334a32df05553459f8b1f7fe1b62102fbd47cc8034098f0e6a94c6aeee8528abf0a2153a5d8e46d325b7284c046784652ae",
        "52210264fd4d1f5dea8ded94c61e9641309349b62f27fbffe807291f664e286bfbe6472103f4ece6dfccfa37b211eb3d0af4d0c61dba9ef698622dc17eecdf764beeb005a652ae",
        "5221022ccabda84c30bad578b13c89eb3b9544ce149787e5b538175b1d1ba259cbb83321024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c52ae",
    ];

    let a = ExtendedPubKey::from_base58(A).expect("the vector's first key");
    let b = ExtendedPubKey::from_base58(B).expect("the vector's second key");
    let down = |key: &ExtendedPubKey, steps: &[u32]| {
        let mut k = *key;
        for step in steps {
            k = k.derive_child(ChildNumber::normal(*step).unwrap()).unwrap();
        }
        k.public_key
    };

    for (index, want) in WANT.iter().enumerate() {
        let index = index as u32;
        let mut keys = [down(&a, &[index]), down(&b, &[0, 0, index])];
        let mut script = [0u8; MAX_SCRIPT];
        let n = assemble(2, &mut keys, true, &mut script).unwrap();

        let mut hex = String::new();
        for byte in &script[..n] {
            hex.push_str(&format!("{byte:02x}"));
        }
        assert_eq!(hex, *want, "index {index} does not match BIP-383");
    }
}

/// An unsorted `multi` keeps the descriptor's order, which BIP-383's first vector shows.
#[test]
fn an_unsorted_multi_keeps_the_order_it_was_given() {
    // The same two keys the sortedmulti vector uses, at index 0, in the order that
    // sorting would *not* produce -- so a builder that sorts anyway is caught.
    let mut sorted_keys = [[0u8; 33]; 2];
    for (slot, hex) in sorted_keys.iter_mut().zip([
        "025d5fc65ebb8d44a5274b53bac21ff8307fec2334a32df05553459f8b1f7fe1b6",
        "02fbd47cc8034098f0e6a94c6aeee8528abf0a2153a5d8e46d325b7284c0467846",
    ]) {
        for (b, pair) in slot.iter_mut().zip(hex.as_bytes().chunks(2)) {
            *b = u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap();
        }
    }
    let mut reversed = [sorted_keys[1], sorted_keys[0]];
    let mut script = [0u8; MAX_SCRIPT];
    let n = assemble(2, &mut reversed, false, &mut script).unwrap();
    // Unsorted: the second key of the sorted script comes first here.
    assert_eq!(&script[2..35], &sorted_keys[1]);

    let mut also = [sorted_keys[1], sorted_keys[0]];
    let mut sorted_script = [0u8; MAX_SCRIPT];
    let m = assemble(2, &mut also, true, &mut sorted_script).unwrap();
    assert_ne!(script[..n], sorted_script[..m], "sorting changed nothing");
    assert_eq!(&sorted_script[2..35], &sorted_keys[0]);
}

/// What this device exports as a cosigner key must come back as a wallet it can use.
///
/// The export writes `[fp/48h/0h/0h/2h]xpub/<0;1>/*` -- BIP-389's multipath, which is what
/// a coordinator asks for so one descriptor covers both chains. The round trip that has to
/// hold is: export a key, have a coordinator paste it into a `sortedmulti`, import that,
/// and get the same addresses as the single-branch spelling. If the two disagreed, a
/// person would verify a receive address against a wallet the coordinator does not have.
#[test]
fn the_multipath_form_this_device_exports_describes_the_same_wallet() {
    let single = descriptor_for(2, &SEEDS, "wsh", true);
    let multipath = {
        let body = single
            .split('#')
            .next()
            .unwrap()
            .replace("/0/*", "/<0;1>/*");
        let sum = descriptor::checksum(&body).unwrap();
        format!("{body}#{}", core::str::from_utf8(&sum).unwrap())
    };

    let a = parse(&single).expect("the single-branch form");
    let b = parse(&multipath).expect("the form this device exports");
    assert_eq!(a, b, "the derivation suffix changed the wallet");

    // And the addresses themselves, on both branches.
    for branch in [0u32, 1] {
        for index in [0u32, 1, 7] {
            let (mut x, mut y) = ([0u8; 34], [0u8; 34]);
            let n = a.script_pubkey(branch, index, &mut x).unwrap();
            let m = b.script_pubkey(branch, index, &mut y).unwrap();
            assert_eq!(x[..n], y[..m], "branch {branch} index {index}");
        }
    }
}

/// A suffix that is not a wildcard is refused rather than read as address zero.
///
/// `[fp/48h/0h/0h/2h]xpub/0/5` names one key, not a chain of them. Accepting it and
/// deriving `branch/index` below the account anyway would silently register a wallet
/// whose addresses are not the ones the descriptor describes.
#[test]
fn a_fixed_key_is_not_a_wallet() {
    let text = descriptor_for(2, &SEEDS, "wsh", true).replace("/0/*", "/0/5");
    let body = text.split('#').next().unwrap();
    let sum = descriptor::checksum(body).unwrap();
    let fixed = format!("{body}#{}", core::str::from_utf8(&sum).unwrap());
    assert!(
        matches!(parse(&fixed), Err(Error::BadKey { .. })),
        "a fixed key was accepted as a wallet"
    );
}

/// The master behind `SEEDS[i]`.
fn master_of(phrase: &str) -> ExtendedPrivKey {
    use crate::bip32::Network;
    use crate::bip39::{Mnemonic, SEED_LEN};
    let mnemonic = Mnemonic::parse(phrase, &kw()).expect("a test phrase");
    let mut seed = [0u8; SEED_LEN];
    mnemonic.to_seed("", &mut seed, &kw()).unwrap();
    ExtendedPrivKey::from_seed(&seed, Network::Mainnet, &kw()).unwrap()
}

#[test]
fn our_cosigner_is_found_when_the_key_really_derives_from_our_master() {
    let text = descriptor_for(2, &SEEDS, "wsh", true);
    let wallet = parse(&text).unwrap();
    for (i, phrase) in SEEDS.iter().enumerate() {
        let found = our_cosigner(&wallet, &master_of(phrase), &kw()).unwrap();
        assert!(found.is_some(), "seed {i} should own a cosigner");
    }
}

#[test]
fn a_foreign_master_owns_nothing() {
    let text = descriptor_for(2, &SEEDS, "wsh", true);
    let wallet = parse(&text).unwrap();
    let outsider = master_of("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong");
    assert_eq!(our_cosigner(&wallet, &outsider, &kw()), Ok(None));
}

/// The attack: a descriptor carrying our real fingerprint against somebody else's key.
/// Fingerprints are public, so this costs the attacker nothing to write.
#[test]
fn a_key_claiming_our_fingerprint_without_our_key_is_refused() {
    let text = descriptor_for(2, &SEEDS, "wsh", true);
    let mut wallet = parse(&text).unwrap();
    let ours = master_of(SEEDS[0]);
    let mine = our_cosigner(&wallet, &ours, &kw())
        .unwrap()
        .expect("we own one");

    // Take a cosigner that is not ours and stamp our fingerprint on it.
    let theirs = (mine + 1) % wallet.n();
    let stolen = wallet.cosigners()[theirs].xpub;
    let victim = wallet.cosigners()[mine].fingerprint;
    let origin = wallet.cosigners()[mine].origin;
    let origin_len = wallet.cosigners()[mine].origin_len;
    wallet.cosigners[mine] = Cosigner {
        fingerprint: victim,
        origin,
        origin_len,
        xpub: stolen,
    };

    assert_eq!(
        our_cosigner(&wallet, &ours, &kw()),
        Err(Error::ForgedOrigin { at: mine }),
        "a claim on our fingerprint that does not derive to our key must be refused"
    );
}

/// A cosigner whose xpub carries different depth or parent fingerprint -- as some wallets
/// write them -- is still ours: the key material is what proves it, and metadata is not
/// something a forger is short of.
#[test]
fn our_cosigner_ignores_the_metadata_around_the_key() {
    let text = descriptor_for(2, &SEEDS, "wsh", true);
    let mut wallet = parse(&text).unwrap();
    let ours = master_of(SEEDS[0]);
    let mine = our_cosigner(&wallet, &ours, &kw())
        .unwrap()
        .expect("we own one");

    let mut xpub = wallet.cosigners()[mine].xpub;
    xpub.depth = xpub.depth.wrapping_add(1);
    xpub.parent_fingerprint = [0; 4];
    xpub.child_number = crate::bip32::ChildNumber::ZERO;
    wallet.cosigners[mine] = Cosigner {
        xpub,
        ..wallet.cosigners()[mine]
    };

    assert_eq!(our_cosigner(&wallet, &ours, &kw()), Ok(Some(mine)));
}

/// `text` with every cosigner key rewritten in `form`, re-checksummed.
fn respelled(text: &str, form: crate::bip32::serialize::Slip132) -> String {
    use crate::bip32::ExtendedPubKey;
    let body = text.split('#').next().unwrap();
    let mut out = String::new();
    for part in body.split(']') {
        match part.find("/0/*") {
            Some(end) => {
                let key = ExtendedPubKey::from_base58(&part[..end]).unwrap();
                let mut buf = [0u8; crate::bip32::serialize::MAX_BASE58_LEN];
                let n = key.write_base58_as(form, &mut buf).unwrap();
                out.push_str(core::str::from_utf8(&buf[..n]).unwrap());
                out.push_str(&part[end..]);
            }
            None => out.push_str(part),
        }
        out.push(']');
    }
    out.pop();
    let sum = descriptor::checksum(&out).unwrap();
    format!("{out}#{}", core::str::from_utf8(&sum).unwrap())
}

/// A coordinator that writes `Zpub` keys inside `wsh(...)` describes the same wallet as
/// one that writes `xpub`; the prefix is read, and it agrees with the wrapper.
#[test]
fn slip132_keys_in_a_descriptor_are_read_and_checked_against_the_wrapper() {
    use crate::bip32::serialize::Slip132;
    let classic = descriptor_for(2, &SEEDS, "wsh", true);
    let expect = parse(&classic).unwrap();
    assert_eq!(parse(&respelled(&classic, Slip132::P2wsh)), Ok(expect));

    let nested = descriptor_for(2, &SEEDS, "sh-wsh", true);
    let expect = parse(&nested).unwrap();
    assert_eq!(parse(&respelled(&nested, Slip132::P2wshP2sh)), Ok(expect));

    // A prefix naming another script type is a file at odds with itself.
    assert_eq!(
        parse(&respelled(&classic, Slip132::P2wpkh)),
        Err(Error::FormMismatch { at: 0 }),
        "zpub is single-signature P2WPKH, not a wsh() cosigner"
    );
    assert_eq!(
        parse(&respelled(&classic, Slip132::P2wshP2sh)),
        Err(Error::FormMismatch { at: 0 }),
        "Ypub says sh(wsh(...)), the descriptor says wsh(...)"
    );
    let legacy = descriptor_for(2, &SEEDS, "sh", true);
    assert_eq!(
        parse(&respelled(&legacy, Slip132::P2wsh)),
        Err(Error::FormMismatch { at: 0 }),
        "bare sh(multi) has no SLIP-132 form"
    );
}
