//! Export a wallet as share bundles; sign with them for the original wallet's
//! addresses; restore its words from them.

mod common;

use catcard_tss::{
    AccountKey, Error, Origin, ShareBundle, ShareRecord, SignMode, SignRequest, export,
    restore_entropy, restore_entropy_from_codex32,
};
use catcard_wallet::bip32::{ChildNumber, ExtendedPrivKey, HARDENED_OFFSET, Network};
use catcard_wallet::bip39::{Mnemonic, SEED_LEN};
use common::*;

const ENTROPY_16: [u8; 16] = [
    0x7f, 0x01, 0x22, 0x9b, 0xc4, 0x5e, 0x00, 0x13, 0xa8, 0x6d, 0xee, 0x31, 0x40, 0x07, 0x99, 0xf2,
];
const ENTROPY_32: [u8; 32] = [0x5a; 32];

/// The wallet behind `entropy`, as any BIP-39/32 wallet sees it: master, and the BIP-84
/// account `m/84'/0'/0'`.
fn wallet(entropy: &[u8]) -> (ExtendedPrivKey, ExtendedPrivKey, Vec<u32>) {
    let m = Mnemonic::from_entropy(entropy, &KW).unwrap();
    let mut seed = [0u8; SEED_LEN];
    m.to_seed("", &mut seed, &KW).unwrap();
    let master = ExtendedPrivKey::from_seed(&seed, Network::Mainnet, &KW).unwrap();
    let path = vec![84 | HARDENED_OFFSET, HARDENED_OFFSET, HARDENED_OFFSET];
    let mut account = master.clone();
    for &i in &path {
        account = account.derive_child(ChildNumber(i), &KW).unwrap();
    }
    (master, account, path)
}

fn do_export(entropy: &[u8], n: u8, t: u8) -> (Vec<ShareBundle>, ExtendedPrivKey) {
    let (master, account, path) = wallet(entropy);
    let key = AccountKey::new(
        account.secret_bytes(),
        &account.chain_code,
        master.fingerprint(&KW),
        &path,
    );
    let bundles = export(entropy, &key, n, t, &mut TestRng::new("export"), &KW).unwrap();
    (bundles, account)
}

#[test]
fn exported_shares_sign_for_the_original_wallets_addresses() {
    for (n, t) in [(2u8, 2u8), (3, 2), (5, 3)] {
        let (bundles, account) = do_export(&ENTROPY_16, n, t);
        assert_eq!(bundles.len(), usize::from(n));
        let records: Vec<ShareRecord> = bundles.iter().map(|b| b.record().clone()).collect();
        for r in &records {
            assert_eq!(r.origin(), Origin::Exported);
            assert_eq!(r.joint_public_key(), &account.public_key(&KW));
            assert_eq!(r.chain_code(), &account.chain_code);
            assert_eq!(
                r.path(),
                &[84 | HARDENED_OFFSET, HARDENED_OFFSET, HARDENED_OFFSET]
            );
        }
        // Receive address 5 and change address 2 of the original wallet: the key a
        // single-signature wallet derives from the words, by plain BIP-32.
        for path in [[0u32, 5], [1, 2]] {
            let expected = account
                .derive_child(ChildNumber(path[0]), &KW)
                .unwrap()
                .derive_child(ChildNumber(path[1]), &KW)
                .unwrap()
                .public_key(&KW);
            let signers: Vec<u8> = (n - t + 1..=n).collect();
            let req = [SignRequest {
                path: path.to_vec(),
                sighash: sighash(&format!("export {n} {t} {path:?}")),
            }];
            let sigs = sign(&records, &signers, &req, SignMode::Plain);
            assert_eq!(sigs[0].child_public_key, expected);
            assert!(verifies(&expected, &req[0].sighash, &sigs[0]));
        }
    }
}

#[test]
fn any_t_bundles_restore_the_exact_entropy_and_t_minus_one_do_not() {
    for entropy in [&ENTROPY_16[..], &ENTROPY_32[..]] {
        let (bundles, _) = do_export(entropy, 5, 3);
        for pick in [[0usize, 1, 2], [2, 3, 4], [4, 0, 2], [1, 3, 4]] {
            let set: Vec<&ShareBundle> = pick.iter().map(|&i| &bundles[i]).collect();
            assert_eq!(&*restore_entropy(&set, &KW).unwrap(), entropy);
        }
        let two: Vec<&ShareBundle> = bundles.iter().take(2).collect();
        assert!(matches!(
            restore_entropy(&two, &KW),
            Err(Error::NotEnoughShares)
        ));
        // Typed in from paper: the Codex32 strings alone are enough.
        let texts: Vec<&str> = bundles[1..4].iter().map(|b| b.codex32()).collect();
        assert_eq!(
            &*restore_entropy_from_codex32(&texts, &KW).unwrap(),
            entropy
        );
    }
}

#[test]
fn a_bundle_is_a_codex32_share_with_the_member_and_threshold_on_it() {
    let (bundles, _) = do_export(&ENTROPY_16, 3, 2);
    // BIP-93 share indices a, c, d for members 1, 2, 3; threshold digit 2; prefix cw1.
    for (b, index) in bundles.iter().zip(['a', 'c', 'd']) {
        let s = b.codex32();
        assert!(s.starts_with("cw12"), "{s}");
        assert_eq!(s.chars().nth(8), Some(index), "{s}");
        assert_eq!(b.member(), b.record().member());
    }
    // One identifier for the whole split.
    assert!(
        bundles
            .iter()
            .all(|b| b.codex32()[4..8] == bundles[0].codex32()[4..8])
    );
}

#[test]
fn bundles_round_trip_and_refuse_mismatched_halves() {
    let (bundles, _) = do_export(&ENTROPY_16, 3, 2);
    for b in &bundles {
        let bytes = b.to_bytes(&KW).unwrap();
        let back = ShareBundle::from_bytes(&bytes, &KW).unwrap();
        assert_eq!(back.codex32(), b.codex32());
        assert_eq!(
            back.record().joint_public_key(),
            b.record().joint_public_key()
        );
        assert_eq!(*back.to_bytes(&KW).unwrap(), *bytes);
    }
    // Member 1's Codex32 half glued onto member 2's DKLs half is not a bundle.
    let one = bundles[0].to_bytes(&KW).unwrap();
    let two = bundles[1].to_bytes(&KW).unwrap();
    let text_len = usize::from(one[8]);
    let mut glued = one[..9 + text_len].to_vec();
    glued[5] = 2;
    glued.extend_from_slice(&two[9 + text_len..]);
    assert!(ShareBundle::from_bytes(&glued, &KW).is_err());
}

#[test]
fn exported_records_combine_into_the_account_key() {
    let (bundles, account) = do_export(&ENTROPY_16, 3, 2);
    let set = [bundles[2].record(), bundles[0].record()];
    let joint = catcard_tss::combine(&set, &KW).unwrap();
    assert_eq!(joint.private_key(), account.secret_bytes());
    assert_eq!(joint.chain_code(), &account.chain_code);
}

#[test]
fn export_refuses_bad_parameters_and_a_dry_source() {
    let (master, account, path) = wallet(&ENTROPY_16);
    let key = AccountKey::new(
        account.secret_bytes(),
        &account.chain_code,
        master.fingerprint(&KW),
        &path,
    );
    let mut rng = TestRng::new("bad");
    for (n, t) in [(1u8, 1u8), (3, 1), (3, 4), (10, 2)] {
        assert!(
            matches!(
                export(&ENTROPY_16, &key, n, t, &mut rng, &KW),
                Err(Error::Parameters)
            ),
            "{n} {t}"
        );
    }
    assert!(matches!(
        export(&[0u8; 20], &key, 3, 2, &mut rng, &KW),
        Err(Error::Parameters)
    ));
    assert!(matches!(
        export(&ENTROPY_16, &key, 3, 2, &mut Empty, &KW),
        Err(Error::Randomness)
    ));
}
