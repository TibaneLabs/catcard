//! The wallet for this power cycle: the mnemonic and the master key, in RAM only.
//!
//! Nothing here is stored. There is no PIN and no storage on this board yet (milestone 4,
//! docs/PRECURSOR.md), so a wallet lasts until logout or reset, and the screens say so.
//! Both halves zeroize on drop, so Logout is dropping the session.

use catcard_wallet::bip32::{
    ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey, Network,
};
use catcard_wallet::bip39::Mnemonic;
use zeroize::Zeroize;

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use catcard_wallet::psbtview::{self, Destination, Owner, Policy};
use catcard_wallet::signer::{self, Keys, SighashPolicy};
use outscript::psbt::Psbt;

use crate::keywork;

/// Outputs a review shows; a PSBT with more is refused here rather than half-reviewed.
const MAX_OUTPUTS: usize = 32;

/// What a person is asked to approve: every output, which are change, and the fee.
pub struct Review {
    pub outputs: Vec<(String, u64, bool)>,
    pub fee: u64,
    pub fee_percent: u32,
    pub fee_warn: bool,
    pub ours: usize,
    pub inputs: usize,
}

pub struct Session {
    mnemonic: Mnemonic,
    master: ExtendedPrivKey,
    fingerprint: [u8; 4],
}

impl Session {
    /// Stretches the mnemonic (no passphrase) and derives the master key, masked.
    pub fn new(mnemonic: Mnemonic) -> Result<Self, &'static str> {
        keywork::run(|kw| {
            let mut seed = [0u8; catcard_wallet::bip39::SEED_LEN];
            let r = mnemonic
                .to_seed("", &mut seed, kw)
                .map_err(|_| "could not stretch the words")
                .and_then(|()| {
                    ExtendedPrivKey::from_seed(&seed, Network::Mainnet, kw)
                        .map_err(|_| "unusable seed")
                });
            seed.zeroize();
            let master = r?;
            let fingerprint = master.fingerprint(kw);
            Ok(Self {
                mnemonic,
                master,
                fingerprint,
            })
        })
    }

    pub fn fingerprint(&self) -> [u8; 4] {
        self.fingerprint
    }

    pub fn words(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.mnemonic.words()
    }

    /// The account key `m/purpose'/0'/0'` (mainnet, account 0), as an xpub.
    pub fn account(&self, purpose: u32) -> Result<ExtendedPubKey, &'static str> {
        let hard = |i| ChildNumber::hardened(i).map_err(|_| "bad path");
        let path = DerivationPath::from_slice(&[hard(purpose)?, hard(0)?, hard(0)?])
            .map_err(|_| "bad path")?;
        keywork::run(|kw| {
            self.master
                .derive_path(&path, kw)
                .map(|k| k.to_extended_pub(kw))
                .map_err(|_| "derivation failed")
        })
    }

    fn owner(&self) -> Owner<'_> {
        Owner {
            keys: Keys::Master(&self.master),
            fingerprint: self.fingerprint,
            wallets: &[],
            bare_keys: &[],
        }
    }

    /// The review of `psbt`: catcard-wallet's `summarise` (amounts proven against the
    /// inputs, change proven by re-deriving it, the fee policy) and every destination.
    pub fn review(&self, psbt: &[u8]) -> Result<Review, String> {
        let psbt = Psbt::parse(psbt).map_err(|e| format!("not a PSBT ({e:?})"))?;
        let owner = self.owner();
        keywork::run(|kw| {
            let sum = psbtview::summarise(&psbt, &owner, &Policy::default(), kw)
                .map_err(|r| format!("refused: {r:?}"))?;
            if sum.outputs > MAX_OUTPUTS {
                return Err(format!("{} outputs, over {MAX_OUTPUTS}", sum.outputs));
            }
            let mut dests = [Destination::BLANK; MAX_OUTPUTS];
            let n = psbtview::destinations(
                &psbt,
                &owner,
                Network::Mainnet,
                &sum.accounts[..sum.account_count],
                &sum.wallets[..sum.wallet_count],
                &mut dests,
                kw,
            );
            if n != sum.outputs {
                return Err(String::from("could not list every output"));
            }
            let outputs = dests[..n]
                .iter()
                .map(|d| (String::from(d.address()), d.amount, d.change))
                .collect();
            Ok(Review {
                outputs,
                fee: sum.fee,
                fee_percent: sum.fee_percent,
                fee_warn: sum.fee_warn,
                ours: sum.ours,
                inputs: sum.inputs,
            })
        })
    }

    /// Signs every input this wallet owns. Returns the PSBT with the signatures added and
    /// how many inputs were signed. Inputs that are not ours are left as they were.
    pub fn sign(&self, psbt: &[u8]) -> Result<(Vec<u8>, usize), String> {
        let inputs = Psbt::parse(psbt)
            .map_err(|e| format!("not a PSBT ({e:?})"))?
            .unsigned_tx()
            .inputs()
            .count();
        let mut cur = psbt.to_vec();
        let mut signed = 0;
        for i in 0..inputs {
            let mut next = vec![0u8; cur.len() + 512];
            let r = keywork::run(|kw| {
                let p = Psbt::parse(&cur).map_err(|e| format!("re-parse ({e:?})"))?;
                match signer::sign_input_under(
                    &p,
                    i,
                    &self.master,
                    self.fingerprint,
                    SighashPolicy::Block,
                    &mut next,
                    kw,
                ) {
                    Ok(n) => Ok(Some(n)),
                    Err(signer::Error::NotOurs) => Ok(None),
                    Err(e) => Err(format!("input {i}: {e:?}")),
                }
            })?;
            if let Some(n) = r {
                next.truncate(n);
                cur = next;
                signed += 1;
            }
        }
        Ok((cur, signed))
    }
}
