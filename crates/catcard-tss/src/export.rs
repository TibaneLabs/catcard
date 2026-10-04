//! Export: one device that holds a wallet splits it into `n` share bundles; and the way
//! back, from `t` of them, to the wallet's words.
//!
//! Each bundle has two halves that share nothing but `n`, `t` and the member number
//! (docs/TSS.md, "Export"):
//!
//! - **Restore**: a Codex32 `cw1` share of the BIP-39 entropy (BIP-93 Shamir over
//!   GF(32), `catcard_wallet::codex32`). Any `t` give back the words.
//! - **Sign**: the core of a DKLs share of the *account* key -- no pairwise OT state,
//!   which its holder sets up with its co-signers (`Session::pair_setup`). The caller does the hardened steps
//!   (`m/84'/0'/0'` and so on) and hands over the account key and chain code; this module
//!   wraps it as a 1-of-1 DKLs key (`tsslib::dklstss::import_key`) and reshares it to a
//!   `t`-of-`n` committee, playing the old party and every new one itself. The chain
//!   code in every share is the account's, so non-hardened derivation below it --
//!   receive `0/*`, change `1/*` -- gives the addresses the original wallet already uses.
//!
//! Nothing is lost by one process knowing every party's setup: it held the whole key to
//! begin with. What matters is that the copies are gone afterwards, so every DKLs key
//! here is wrapped to be wiped on drop and the caller's buffers are not copied.

use alloc::string::String;
use alloc::vec::Vec;
use catcard_wallet::KeyWork;
use catcard_wallet::codex32::{self, Hrp, Set, Share};
use purecrypto::ec::secp256k1::{ProjectivePoint, Scalar};
use tsslib::tss::PartyId;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::rng::{Armed, Entropy, LocalDrbg, draw};
use crate::share::{MAX_PATH, Origin, SecretKey, ShareBundle, ShareRecord, check_params, compress};
use crate::{Error, member_ids};

/// The account key an export shares: the private key and chain code at the account
/// path, and where that path starts. Wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AccountKey {
    private: [u8; 32],
    chain_code: [u8; 32],
    master_fingerprint: [u8; 4],
    path: Vec<u32>,
}

impl AccountKey {
    /// `private` and `chain_code` are the BIP-32 key at `path` below the master whose
    /// fingerprint is `master_fingerprint`.
    pub fn new(
        private: &[u8; 32],
        chain_code: &[u8; 32],
        master_fingerprint: [u8; 4],
        path: &[u32],
    ) -> Self {
        AccountKey {
            private: *private,
            chain_code: *chain_code,
            master_fingerprint,
            path: path.to_vec(),
        }
    }
}

/// The Codex32 share index member `member` (1-based) is given: BIP-93's order `a c d e
/// f g h j k`, as Coldcard's Shamir Split hands them out.
pub(crate) fn codex32_index(member: u8) -> Result<u8, Error> {
    member
        .checked_sub(1)
        .and_then(|i| codex32::SHARE_ORDER.get(usize::from(i)).copied())
        .ok_or(Error::Parameters)
}

/// Split a wallet into `n` share bundles, any `t` of which sign for its account and
/// restore its words.
///
/// `entropy` is the wallet's BIP-39 entropy (16, 24 or 32 bytes). `source` must be
/// seed-grade: it supplies the Codex32 split's identifier and free shares, and seeds
/// the DRBG that draws the reshare's polynomials -- both are the whole secrecy of a
/// share.
pub fn export(
    entropy: &[u8],
    account: &AccountKey,
    n: u8,
    t: u8,
    source: &mut dyn Entropy,
    kw: &KeyWork,
) -> Result<Vec<ShareBundle>, Error> {
    check_params(n, t)?;
    if !Hrp::Cw.carries(entropy.len()) || account.path.len() > MAX_PATH {
        return Err(Error::Parameters);
    }

    // The restore half.
    let secret = Share::from_bytes(Hrp::Cw, 0, [0; 4], codex32::SECRET_INDEX, entropy, kw)
        .map_err(Error::Codex32)?;
    let mut noise = Zeroizing::new(alloc::vec![0u8; codex32::noise_len(&secret, t)]);
    draw(source, &mut noise)?;
    let set = codex32::split(&secret, t, &noise, kw).map_err(Error::Codex32)?;
    drop(noise);

    // The signing half.
    let scalar = Scalar::from_bytes_be(&account.private).map_err(|_| Error::Parameters)?;
    let account_public =
        compress(&ProjectivePoint::mul_generator(&scalar)).ok_or(Error::Parameters)?;
    // The dealer's party key only has to differ from every member's (1..=9).
    let dealer = PartyId::new("dealer", "", alloc::vec![1u8, 0]);
    let imported =
        SecretKey(tsslib::dklstss::import_key(&scalar, &dealer).map_err(|_| Error::Parameters)?);
    drop(scalar);
    let _armed = Armed::new(source)?;
    let mut drbg = LocalDrbg::new(source)?;
    let keys = tsslib::dklstss::reshare(
        core::slice::from_ref(&imported.0),
        &[0],
        &member_ids(n),
        usize::from(t) - 1,
        &mut drbg,
    )
    .map_err(|e| Error::Protocol(alloc::format!("{e}")))?;
    let keys: Vec<SecretKey> = keys.into_iter().map(SecretKey).collect();
    drop(imported);

    let mut out = Vec::with_capacity(usize::from(n));
    for mut key in keys {
        key.0.chain_code = account.chain_code;
        let mut record = ShareRecord::from_key(
            Origin::Exported,
            t,
            Some(account.master_fingerprint),
            account.path.clone(),
            key,
        )?;
        // A bundle carries the core alone: the pairs the reshare set up are wiped here,
        // and each holder sets up its own with its co-signers before it first signs.
        record.drop_pairs();
        if record.joint_public != account_public {
            return Err(Error::Protocol(String::from(
                "reshare changed the public key",
            )));
        }
        let member = record.member;
        let share = set
            .interpolate(codex32_index(member)?, kw)
            .map_err(Error::Codex32)?;
        let mut buf = [0u8; codex32::MAX_STRING];
        let codex32 = Zeroizing::new(String::from(share.write(false, &mut buf, kw)));
        buf.zeroize();
        out.push(ShareBundle {
            member,
            n,
            t,
            codex32,
            record,
        });
    }
    Ok(out)
}

/// The BIP-39 entropy back from `t` or more bundles of one export.
pub fn restore_entropy(
    bundles: &[&ShareBundle],
    kw: &KeyWork,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let texts: Vec<&str> = bundles.iter().map(|b| b.codex32()).collect();
    restore_entropy_from_codex32(&texts, kw)
}

/// The BIP-39 entropy back from `t` or more Codex32 `cw1` shares, typed or read from
/// bundles. Matching headers do not prove the shares belong together (BIP-93): the
/// caller shows what was recovered before storing it.
pub fn restore_entropy_from_codex32(
    shares: &[&str],
    kw: &KeyWork,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut set = Set::new();
    for text in shares {
        if set.is_complete() {
            break;
        }
        let share = Share::parse(text, kw).map_err(Error::Codex32)?;
        if share.hrp() != Hrp::Cw {
            return Err(Error::Mismatch);
        }
        set.add(share).map_err(Error::Codex32)?;
    }
    if !set.is_complete() {
        return Err(Error::NotEnoughShares);
    }
    let secret = set
        .recover(kw)
        .and_then(|s| s.secret(kw))
        .map_err(Error::Codex32)?;
    Ok(Zeroizing::new(secret.as_bytes().to_vec()))
}
