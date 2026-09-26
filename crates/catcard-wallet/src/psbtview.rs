//! What a person is shown before signing, and the checks behind it.
//!
//! A hardware wallet's only real job is this screen. The host says what the transaction
//! does; the device has to state what the signature will actually authorise, using nothing
//! the host merely asserts. So everything here is derived from data the signature commits
//! to, or refused:
//!
//! - **Amounts in** come from the previous transaction each input spends, whose txid
//!   `outscript` checks against the outpoint. On an input of ours a witness UTXO alone is
//!   refused: BIP-143 binds the amount of the input being *signed*, so a wrong amount on
//!   any *other* input costs a host nothing and still moves the fee this screen states.
//! - **Amounts out** and their destinations come from the unsigned transaction, which every
//!   signature commits to.
//! - **The fee** is the difference, and a fee that cannot be computed -- a foreign input
//!   whose spent output was not given, or was given on the host's word alone -- is
//!   reported as unknown rather than as zero, as it is in a coinjoin.
//! - **Change** is an output this wallet can rebuild from its own key: the path the PSBT
//!   claims is derived, the script is recomputed, and it has to match byte for byte. An
//!   output that merely *claims* our fingerprint is not change.
//!
//! The policy limits ([`Policy`]) are the second half: a fee above the cap, or a sighash
//! this will not produce, stops the signing rather than being shown as a warning nobody
//! reads.

use outscript::psbt::{Psbt, global, input as in_key, output as out_key};

use crate::KeyWork;
use crate::address::{self, AddressKind};
use crate::bip32::{ExtendedPrivKey, ExtendedPubKey, FINGERPRINT_LEN, Network};
use crate::multisig::{self, Cosigner, Kind, MAX_COSIGNERS, MAX_ORIGIN, Multisig};
use crate::signer::{self, KeyRequest, MAX_KEYS_PER_INPUT};

pub use crate::signer::SighashPolicy;

pub mod timelock;

/// Sighash types this will sign.
///
/// `SIGHASH_ALL` alone: every other type leaves part of the transaction unsigned, which is
/// a thing to offer deliberately with its own warning, not to produce by default because a
/// PSBT asked. Source: BIP-174 "If a sighash type is not provided, the signer should sign
/// using SIGHASH_ALL" [C]
pub const SIGHASH_ALL: u32 = 0x01;

/// The limits a transaction has to pass.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Policy {
    /// Refuse when the fee is more than this percentage of the amount sent.
    pub max_fee_percent: u32,
    /// Warn above this percentage.
    pub warn_fee_percent: u32,
    /// What to do with an input asking for a sighash type other than `SIGHASH_ALL`.
    pub sighash: SighashPolicy,
}

impl Default for Policy {
    /// Stock's defaults: refuse above 10%, warn above 5%, block the unusual sighash types.
    /// Source: hw-reference/firmware-features.md §5 [C]
    fn default() -> Self {
        Self {
            max_fee_percent: 10,
            warn_fee_percent: 5,
            sighash: SighashPolicy::Block,
        }
    }
}

/// Why a transaction will not be signed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// No input in it belongs to this wallet.
    NothingOfOurs,
    /// An input asks for a sighash type this will not produce under the policy.
    Sighash { input: usize, kind: u32 },
    /// Under [`SighashPolicy::Warn`], an input asks for a non-`ALL` type on a transaction
    /// whose every output is our own change. Stock refuses this too: a consolidation has
    /// nobody outside the wallet to warn, and a `SIGHASH_NONE` signature over one is a
    /// blank cheque on the whole balance for no reason a consolidation could have.
    /// Source: hw-reference/help-and-warning-screens.md "consolidation TXs must be
    /// all-ALL" [C]
    SighashConsolidation { input: usize, kind: u32 },
    /// The fee is above the policy's cap.
    FeeTooHigh { percent: u32, cap: u32 },
    /// One of *our* inputs' spent output was not provided, or does not match its
    /// previous transaction, so its amount is nothing this can sign over. Signing blind to
    /// the amounts is how a transaction that pays everything to fees gets signed. A
    /// foreign input in the same state is not refused; it makes the fee unknown instead
    /// ([`Summary::fee_known`]).
    UnknownAmount { input: usize },
    /// One of our inputs gave an amount with no transaction behind it, so nothing checks
    /// it. BIP-143 binds the amount of the input being *signed*, so on our own inputs the
    /// previous transaction is the fee-inflation defence and is required.
    UnverifiedAmount { input: usize },
    /// The amounts do not add up: outputs exceed inputs.
    Unbalanced,
    /// A script-hash input belongs to no registered multisig wallet.
    ///
    /// The script the coin is locked to is pinned by the chain, so a host cannot invent
    /// one -- but whose wallet it is still has to be something this device was shown. An
    /// input it cannot account for is one whose cosigners nobody here has ever seen.
    UnknownMultisig { input: usize },
    /// The PSBT is already finalised; there is nothing to sign.
    AlreadyFinal,
}

/// One output, as it will be shown.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Destination {
    pub index: usize,
    pub amount: u64,
    /// True if this output is change back to this wallet, proven not claimed.
    pub change: bool,
    /// The address, and how many bytes of it are used. Empty for a script with no address.
    /// For a bare P2PK output ([`Self::p2pk`]) it holds the compressed key in hex instead:
    /// nothing encodes such a script as an address, and the key is what there is to show.
    pub address: [u8; address::MAX_ADDRESS_LEN],
    pub address_len: usize,
    /// True if the output is a bare `<key> OP_CHECKSIG` script, shown as "P2PK".
    pub p2pk: bool,
    /// For a change output, what is odd about where it sits, if anything: the warning the
    /// review prints under it. Proven change either way -- this is a heuristic on top of
    /// the proof, never a substitute for it. `None` for a non-change output.
    pub unusual: Option<Unusual>,
    /// For a change output, the derivation path it was proven at, for the warning to name.
    pub path: [u32; signer::MAX_STEPS],
    pub path_len: usize,
}

impl Destination {
    /// A slot nothing has been written into.
    pub const BLANK: Self = Self {
        index: 0,
        amount: 0,
        change: false,
        address: [0; address::MAX_ADDRESS_LEN],
        address_len: 0,
        p2pk: false,
        unusual: None,
        path: [0; signer::MAX_STEPS],
        path_len: 0,
    };

    pub fn address(&self) -> &str {
        core::str::from_utf8(&self.address[..self.address_len]).unwrap_or("")
    }

    /// The change path, as steps.
    pub fn path(&self) -> &[u32] {
        &self.path[..self.path_len]
    }

    /// Write [`Self::path`] as `m/84h/0h/0h/1/5`.
    pub fn write_path(&self, out: &mut dyn core::fmt::Write) -> core::fmt::Result {
        write_path(self.path(), out)
    }
}

/// Write `steps` as `m/84h/0h/0h/1/5`: hardened levels with an `h`.
pub fn write_path(steps: &[u32], out: &mut dyn core::fmt::Write) -> core::fmt::Result {
    out.write_str("m")?;
    for &step in steps {
        if step & HARDENED != 0 {
            write!(out, "/{}h", step & !HARDENED)?;
        } else {
            write!(out, "/{step}")?;
        }
    }
    Ok(())
}

/// The hardened bit of a derivation step.
const HARDENED: u32 = 0x8000_0000;

/// What is odd about a proven change output's path.
///
/// Stock's "suspicious change" heuristic: change that is provably ours can still sit
/// somewhere no wallet would put it, and that is worth a line on the review -- a host
/// that pays change to a corner of the key space the owner's software will never scan
/// has parked the coins rather than stolen them, which is a thing to know before
/// signing. A warning, not a refusal: the coins are recoverable from the seed, and the
/// owner may know why. Source: hw-reference/firmware-features.md §5 "a 'suspicious
/// change' heuristic warns on unusual change paths" [C]; the specific rules are this
/// firmware's [I].
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Unusual {
    /// The change is on an account none of the inputs spend from.
    OtherAccount,
    /// The change index is far past the highest index any input spends from: more than
    /// [`CHANGE_INDEX_MARGIN`] beyond it.
    FarIndex { index: u32, highest: u32 },
    /// The branch or the index level is hardened, where a wallet never hardens.
    Hardened,
    /// The change is on the receive branch (`.../0/i`), where a wallet would hand out the
    /// address to someone rather than pay itself.
    ReceiveBranch,
}

impl Unusual {
    /// The few words the review prints.
    pub fn text(self) -> &'static str {
        match self {
            Unusual::OtherAccount => "another account",
            Unusual::FarIndex { .. } => "index far past inputs",
            Unusual::Hardened => "hardened level",
            Unusual::ReceiveBranch => "receive branch",
        }
    }
}

/// How far past the highest input index a change index may sit before it is called
/// unusual.
///
/// A wallet's change counter runs ahead of its receive counter, so "past every input" is
/// normal; two hundred past is not a counter, it is a choice. A margin, not a proof; an
/// index this flags is still proven change and still shown as such. [I]
pub const CHANGE_INDEX_MARGIN: u32 = 200;

/// What is unusual about a change path, if anything; `None` for the ordinary shape.
///
/// `steps` is the proven path (five levels for single-signature change; the wallet's
/// origin plus branch and index for multisig), `accounts` the accounts the inputs spend
/// from, and `highest_index` the highest last-level index among the inputs' own paths,
/// when any input had one. The rules, in the order they are checked:
///
/// 1. [`Unusual::Hardened`]: the branch or the index level is hardened.
/// 2. [`Unusual::OtherAccount`]: a five-level path whose first three levels are not an
///    account the inputs spend from.
/// 3. [`Unusual::FarIndex`]: the index is more than [`CHANGE_INDEX_MARGIN`] past
///    `highest_index`.
/// 4. [`Unusual::ReceiveBranch`]: the branch is `0`.
///
/// Under this crate's change rules ([`account_for`]) the first two cannot reach a proven
/// change output -- such an output is not change at all, and shows as leaving -- so they
/// are stated here for the heuristic's completeness and for a future relaxation of those
/// rules, not because a screen will print them today.
pub fn unusual_change(
    steps: &[u32],
    accounts: &[Account],
    highest_index: Option<u32>,
) -> Option<Unusual> {
    let n = steps.len();
    if n < 2 {
        return None;
    }
    let (branch, index) = (steps[n - 2], steps[n - 1]);
    if branch & HARDENED != 0 || index & HARDENED != 0 {
        return Some(Unusual::Hardened);
    }
    if n == CHANGE_DEPTH {
        let prefix = [steps[0], steps[1], steps[2]];
        if !accounts.iter().any(|a| a.prefix == prefix) {
            return Some(Unusual::OtherAccount);
        }
    }
    if let Some(highest) = highest_index
        && index > highest.saturating_add(CHANGE_INDEX_MARGIN)
    {
        return Some(Unusual::FarIndex { index, highest });
    }
    if branch == 0 {
        return Some(Unusual::ReceiveBranch);
    }
    None
}

/// A proven change output's path, and what the heuristic says about it.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct ChangePath {
    pub steps: [u32; signer::MAX_STEPS],
    pub depth: usize,
    pub unusual: Option<Unusual>,
}

impl ChangePath {
    pub fn steps(&self) -> &[u32] {
        &self.steps[..self.depth]
    }
}

/// What [`summarise`] learnt from the inputs, as the output checks want it.
#[derive(Copy, Clone, Debug)]
pub struct Spent<'s> {
    /// The single-signature accounts the inputs spend from.
    pub accounts: &'s [Account],
    /// The registered multisig wallets they spend from, as indices into [`Owner::wallets`].
    pub wallets: &'s [usize],
    /// The highest last-level index among our inputs' paths, for [`unusual_change`];
    /// `None` when no input of ours named a path.
    pub highest_index: Option<u32>,
}

/// What the device will say about a transaction.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Summary {
    /// The accounts the inputs draw on, which is what an output must belong to before it
    /// may call itself change. Carried here so [`destinations`] need not derive them all
    /// again: every one of those is a scalar multiplication.
    pub accounts: [Account; MAX_ACCOUNTS],
    /// How many of [`Self::accounts`] are real.
    pub account_count: usize,
    /// The registered multisig wallets the inputs draw on, as indices into
    /// [`Owner::wallets`]. The multisig counterpart of [`Self::accounts`]: an output paying
    /// a registered wallet is change only when this spend is *from* that wallet. Otherwise
    /// it is money moving between wallets, which the owner should see as leaving.
    pub wallets: [usize; MAX_SPENT_WALLETS],
    /// How many of [`Self::wallets`] are real.
    pub wallet_count: usize,
    /// Inputs in total, and how many this wallet can sign.
    pub inputs: usize,
    pub ours: usize,
    pub outputs: usize,
    /// Total spent by the inputs we could price.
    pub total_in: u64,
    pub total_out: u64,
    /// Paid to someone other than us.
    pub sending: u64,
    pub change: u64,
    /// The fee, when [`Self::fee_known`]; zero otherwise, which a screen must not print.
    pub fee: u64,
    /// The fee as a percentage of what is being sent, rounded down.
    pub fee_percent: u32,
    /// True if the fee is above the policy's warning level but below its cap.
    pub fee_warn: bool,
    /// Whether every input's amount was settled by its previous transaction, so the fee is
    /// a fact. False when a foreign input -- one this wallet does not sign -- came with a
    /// witness UTXO alone, with nothing, or with a previous transaction that does not
    /// match its outpoint: a coinjoin, typically. The fee is then unknown, and shown as
    /// such rather than as a number the host chose. Our own inputs never leave this false;
    /// they are refused instead ([`Refusal::UnverifiedAmount`]).
    pub fee_known: bool,
    /// How many inputs could not be priced; zero when [`Self::fee_known`].
    pub unpriced: usize,
    /// Inputs of ours that ask for a sighash type other than `SIGHASH_ALL`, admitted under
    /// [`SighashPolicy::Warn`], for the warning screen to name. At most
    /// [`MAX_ODD_SIGHASH`] are kept; [`Self::odd_total`] counts them all.
    pub odd_sighash: [OddSighash; MAX_ODD_SIGHASH],
    /// How many of [`Self::odd_sighash`] are real.
    pub odd_count: usize,
    /// How many of our inputs ask for an unusual type in all.
    pub odd_total: usize,
    /// How many of our inputs spend a bare P2PK script, for the review to name: it is the
    /// one input form with no address, so the screen says what it is instead.
    pub p2pk_inputs: usize,
    /// The highest last-level index among our inputs' derivation paths, for the
    /// suspicious-change heuristic ([`unusual_change`]); `None` when no input named one.
    pub highest_input_index: Option<u32>,
    /// True if any input opted in to the unified signature hash, which only a multichain
    /// build signs. Such a transaction is valid on the chain that implements that rule and
    /// on no other, so the review screen says so.
    #[cfg(feature = "multichain")]
    pub opted_in: bool,
}

impl Summary {
    /// What the inputs said, for [`destinations_with`] and [`change_of`].
    pub fn spent(&self) -> Spent<'_> {
        Spent {
            accounts: &self.accounts[..self.account_count],
            wallets: &self.wallets[..self.wallet_count],
            highest_index: self.highest_input_index,
        }
    }
}

/// One of our inputs asking for an unusual sighash type.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct OddSighash {
    pub input: usize,
    pub kind: u32,
}

impl OddSighash {
    /// A slot nothing has been written into.
    pub const NONE: Self = Self {
        input: usize::MAX,
        kind: 0,
    };

    /// The type's name as the warning screen says it: `NONE`, `SINGLE|ANYONECANPAY`.
    pub fn name(self) -> &'static str {
        use crate::tx::sighash::{SIGHASH_ANYONECANPAY, SIGHASH_NONE, SIGHASH_SINGLE};
        let acp = self.kind & SIGHASH_ANYONECANPAY != 0;
        match (self.kind & !SIGHASH_ANYONECANPAY, acp) {
            (SIGHASH_ALL, false) => "ALL",
            (SIGHASH_ALL, true) => "ALL|ANYONECANPAY",
            (SIGHASH_NONE, false) => "NONE",
            (SIGHASH_NONE, true) => "NONE|ANYONECANPAY",
            (SIGHASH_SINGLE, false) => "SINGLE",
            (SIGHASH_SINGLE, true) => "SINGLE|ANYONECANPAY",
            _ => "unknown",
        }
    }

    /// Whether this type signs no output at all -- the one stock words as "Danger" rather
    /// than "Caution": the coins can go anywhere once the signature exists.
    /// Source: hw-reference/help-and-warning-screens.md "sighash NONE on our input" [C]
    pub fn signs_no_output(self) -> bool {
        self.kind & !crate::tx::sighash::SIGHASH_ANYONECANPAY == crate::tx::sighash::SIGHASH_NONE
    }
}

/// Unusual-sighash inputs the summary names; past this they are only counted.
pub const MAX_ODD_SIGHASH: usize = 4;

/// Who this device is, for the purpose of reading a transaction.
///
/// The seed and its fingerprint settle which single-signature addresses are ours. The
/// registered wallets settle which multisig ones are, because a script alone cannot: the
/// chain pins the script an input is locked to, but nothing on the chain says whose wallet
/// produced it. These travel together because every question here -- is this input ours,
/// is this output change -- needs both halves, and answering with one half is how a device
/// signs a stranger's script or prices someone else's output as change.
#[derive(Copy, Clone)]
pub struct Owner<'a> {
    pub master: &'a ExtendedPrivKey,
    pub fingerprint: [u8; FINGERPRINT_LEN],
    /// Multisig wallets the owner has registered on this device. Empty means this device
    /// signs no multisig input at all, which is the correct answer before any import.
    pub wallets: &'a [Multisig],
    /// Compressed public keys of the WIF store: standalone keys, not derived from the
    /// seed, that can each sign an input paying their own single-signature address. Empty
    /// on a device with no WIF store (every mono board, and any wallet that has stored
    /// none). An input paying one of these counts as ours in the review, so a spend of a
    /// stored key is not refused as "nothing of ours"; it adds no *change* account,
    /// because a WIF key names no derivation, so change paid back to one shows as leaving
    /// -- which overstates the spend rather than hiding it.
    pub bare_keys: &'a [[u8; address::PUBKEY_LEN]],
}

/// Examine `psbt` against this wallet and `policy`.
///
/// Derives one key per input and per claimed-change output, so it costs elliptic-curve work
/// proportional to the transaction's size; it runs inside a masked region like the signing
/// itself.
pub fn summarise(
    psbt: &Psbt<'_>,
    owner: &Owner<'_>,
    policy: &Policy,
    kw: &KeyWork,
) -> Result<Summary, Refusal> {
    let (master, fingerprint, wallets) = (owner.master, owner.fingerprint, owner.wallets);
    if psbt.is_finalized() {
        return Err(Refusal::AlreadyFinal);
    }
    let tx = psbt.unsigned_tx();
    let inputs = tx.input_count();
    let outputs = tx.output_count();

    let mut total_in = 0u64;
    let mut ours = 0usize;
    // The accounts this spend draws on, gathered as the inputs are walked. An output may
    // only call itself change if it belongs to one of them.
    let mut accounts = [Account::NONE; MAX_ACCOUNTS];
    let mut account_count = 0usize;
    // Likewise the registered multisig wallets it draws on.
    let mut spent_wallets = [usize::MAX; MAX_SPENT_WALLETS];
    let mut wallet_count = 0usize;
    #[cfg(feature = "multichain")]
    let mut opted_in = false;
    let mut unpriced = 0usize;
    let mut odd_sighash = [OddSighash::NONE; MAX_ODD_SIGHASH];
    let mut odd_count = 0usize;
    let mut odd_total = 0usize;
    let mut p2pk_inputs = 0usize;
    let mut highest_input_index: Option<u32> = None;
    for index in 0..inputs {
        let mut keys = [KeyRequest::EMPTY; MAX_KEYS_PER_INPUT];
        let found = signer::key_requests(psbt, index, fingerprint, &mut keys).unwrap_or(0);
        let mut mine = false;
        // Whether the script being spent is one *our own key makes on its own* -- a
        // single-signature input. It decides the multisig question below: P2SH is the
        // scriptPubKey of a BIP-49 single-sig address as much as of a multisig one, and
        // only rebuilding the script from our key tells them apart.
        let mut single_sig = false;
        for request in keys[..found].iter() {
            let Ok(signer) = signer::match_key(master, request, kw) else {
                continue;
            };
            mine = true;
            // The index this input sits at, for the change heuristic: the highest one
            // across our inputs is what a change index is measured against.
            if let Some(&last) = request.steps().last()
                && last & HARDENED == 0
            {
                highest_input_index = Some(highest_input_index.map_or(last, |h| h.max(last)));
            }
            // In which form. The kind is settled by rebuilding the script from our own key
            // and matching it against the output being spent -- which `utxo` has already
            // checked against the previous transaction's txid, so it is the chain's answer
            // rather than the host's.
            let Ok(spent) = psbt.utxo(index) else {
                continue;
            };
            let pubkey = signer.public_key_bytes();
            // Bare P2PK: single-signature, ours, and of no account -- a wallet does not
            // make P2PK change, so the path it was found at names nothing an output may
            // call itself change against. Source: hw-reference/firmware-features.md §3
            // (P2PK: sign yes, change detection no) [C]
            if signer::p2pk_pays(spent.script, &pubkey) {
                single_sig = true;
                continue;
            }
            let form = [
                AddressKind::P2wpkh,
                AddressKind::P2shP2wpkh,
                AddressKind::P2pkh,
                AddressKind::P2tr,
            ]
            .into_iter()
            .find(|kind| {
                let mut built = [0u8; 34];
                matches!(address::script_pubkey(*kind, &pubkey, &mut built),
                    Ok(n) if built[..n] == *spent.script)
            });
            let Some(kind) = form else {
                continue;
            };
            single_sig = true;
            // And which account, where the path has one to name and there is room left.
            let steps = request.steps();
            if steps.len() != CHANGE_DEPTH || account_count == MAX_ACCOUNTS {
                continue;
            }
            let prefix = [steps[0], steps[1], steps[2]];
            if accounts[..account_count].iter().any(|a| a.prefix == prefix) {
                continue;
            }
            accounts[account_count] = Account { prefix, kind };
            account_count += 1;
        }
        // A WIF-store key pays no derivation path, so it names no account and cannot be a
        // BIP-32 record; it is recognised only by the script the input actually pays. An
        // input paying one is ours and single-signature (so the script-hash branch below
        // does not mistake a WIF P2SH-P2WPKH for multisig), but it contributes no change
        // account -- a WIF key's own receive is not change of this wallet.
        if !mine
            && owner
                .bare_keys
                .iter()
                .any(|pk| signer::input_pays_key(psbt, index, pk))
        {
            mine = true;
            single_sig = true;
        }
        if mine {
            ours += 1;
            // A sighash type we will not produce stops the whole transaction: signing the
            // other inputs would hand back a PSBT that looks half-signed for no stated
            // reason.
            //
            // The policy itself is `signer::sighash_allowed_under`, shared with the
            // signature so the two cannot disagree. Under `Block` anything allowed other
            // than `SIGHASH_ALL` is the unified opt-in hash, over the same outputs
            // `SIGHASH_ALL` covers. Under `Warn` the other standard types pass, and are
            // listed for the warning screen: NONE and SINGLE leave outputs this review
            // cannot vouch for, and ANYONECANPAY leaves the inputs open -- the fee shown
            // is then a fee anyone can raise afterwards.
            match psbt.input(index).and_then(|i| i.sighash_type()) {
                None => {}
                Some(kind) if signer::sighash_allowed(kind) =>
                {
                    #[cfg(feature = "multichain")]
                    if kind != SIGHASH_ALL {
                        opted_in = true;
                    }
                }
                Some(kind) if signer::sighash_allowed_under(kind, policy.sighash) => {
                    odd_total += 1;
                    if odd_count < MAX_ODD_SIGHASH {
                        odd_sighash[odd_count] = OddSighash { input: index, kind };
                        odd_count += 1;
                    }
                }
                Some(kind) => return Err(Refusal::Sighash { input: index, kind }),
            }
        }
        // Every input's amount matters to the fee, ours or not, and only the previous
        // transaction settles it -- `utxo` checks its txid against this outpoint. On one
        // of *our* inputs a missing or unmatched previous transaction is a refusal: the
        // amount is what the signature commits to, and it must not be the host's word. On
        // a foreign input it makes the fee unknown, which is said as such; a coinjoin
        // carries other people's inputs with a witness UTXO alone, or with nothing, and
        // refusing it would refuse every coinjoin.
        let utxo = match psbt.input(index) {
            Some(inp) if inp.non_witness_utxo().is_some() => match psbt.utxo(index) {
                Ok(u) => Some(u),
                Err(_) if mine => return Err(Refusal::UnknownAmount { input: index }),
                Err(_) => None,
            },
            _ if mine => return Err(Refusal::UnverifiedAmount { input: index }),
            _ => None,
        };
        let Some(utxo) = utxo else {
            unpriced += 1;
            continue;
        };
        if mine && signer::p2pk_key(utxo.script).is_some() {
            p2pk_inputs += 1;
        }

        // A script-hash input of ours that is not single-signature is a multisig one. The
        // chain pins *which* script it is -- the witness or redeem script has to hash to
        // this scriptPubKey -- but not whose wallet it belongs to, and that is what a
        // registration says. An input no registered wallet produces is refused rather
        // than signed on the host's word that the other cosigners are who it claims.
        //
        // `single_sig` is what keeps BIP-49 out of this: `sh(wpkh(...))` is a script hash
        // too, and gating it on a multisig registration refused an account this device
        // offers -- our own key rebuilt the script, so no registration can be wanted.
        // A foreign script-hash input -- one naming none of our keys -- is somebody
        // else's multisig, which this neither signs nor needs to place: it is priced
        // and passed over, as a foreign single-signature input is.
        if mine && !single_sig && multisig::is_script_hash(utxo.script) {
            let Some((branch, at)) = ours_address(psbt, index, fingerprint) else {
                return Err(Refusal::UnknownMultisig { input: index });
            };
            let Some(found) = multisig::match_script(wallets, utxo.script, branch, at) else {
                return Err(Refusal::UnknownMultisig { input: index });
            };
            // Remember which wallet, so an output paying it back can call itself change.
            // Past the cap the wallet is still spent from, but its change shows as leaving,
            // which overstates the spend rather than hiding any of it.
            if !spent_wallets[..wallet_count].contains(&found.wallet)
                && wallet_count < MAX_SPENT_WALLETS
            {
                spent_wallets[wallet_count] = found.wallet;
                wallet_count += 1;
            }
        }
        total_in = total_in.saturating_add(utxo.amount);
    }
    if ours == 0 {
        return Err(Refusal::NothingOfOurs);
    }

    let mut total_out = 0u64;
    let mut change = 0u64;
    for (index, out) in tx.outputs().enumerate() {
        total_out = total_out.saturating_add(out.amount);
        if is_change(
            psbt,
            index,
            out.script,
            owner,
            &accounts[..account_count],
            &spent_wallets[..wallet_count],
            kw,
        ) {
            change = change.saturating_add(out.amount);
        }
    }
    let sending = total_out - change;
    // A consolidation -- every output back to ourselves -- under a non-ALL type is refused
    // whatever the policy says. Stock does the same; see `Refusal::SighashConsolidation`.
    if odd_count > 0 && outputs > 0 && change == total_out {
        return Err(Refusal::SighashConsolidation {
            input: odd_sighash[0].input,
            kind: odd_sighash[0].kind,
        });
    }

    // The fee, where every input was priced. With a foreign input unpriced the fee is
    // unknown -- not zero, and not whatever the host's witness UTXOs add up to -- so the
    // cap cannot be applied and the screen says "unknown" in its place. Our own inputs
    // are always priced, or the transaction was refused above.
    let fee_known = unpriced == 0;
    let (fee, fee_percent) = if fee_known {
        if total_out > total_in {
            return Err(Refusal::Unbalanced);
        }
        let fee = total_in - total_out;
        // Against what is being sent, not against the total: a consolidation that pays
        // itself would otherwise divide by nearly zero and read as a 0% fee.
        let fee_percent = match fee.saturating_mul(100).checked_div(sending) {
            Some(p) => u32::try_from(p).unwrap_or(u32::MAX),
            // Nothing is being sent: a consolidation back to ourselves. A fee against
            // zero has no percentage, so it counts as everything rather than as nothing.
            None if fee == 0 => 0,
            None => 100,
        };
        if fee_percent > policy.max_fee_percent {
            return Err(Refusal::FeeTooHigh {
                percent: fee_percent,
                cap: policy.max_fee_percent,
            });
        }
        (fee, fee_percent)
    } else {
        (0, 0)
    };

    Ok(Summary {
        accounts,
        account_count,
        wallets: spent_wallets,
        wallet_count,
        inputs,
        ours,
        outputs,
        total_in,
        total_out,
        sending,
        change,
        fee,
        fee_percent,
        fee_warn: fee_known && fee_percent > policy.warn_fee_percent,
        fee_known,
        unpriced,
        odd_sighash,
        odd_count,
        odd_total,
        p2pk_inputs,
        highest_input_index,
        #[cfg(feature = "multichain")]
        opted_in,
    })
}

/// An account this transaction spends from: the first three levels of a BIP-44-family
/// path, and the script kind the input it came from actually used.
///
/// Gathered from the inputs rather than assumed, because it is the inputs that say whose
/// money this is. An output claiming to be change has to belong to one of these.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Account {
    /// `purpose'`, `coin'`, `account'`, as written in the record (hardened bit included).
    pub prefix: [u32; 3],
    /// The script kind of the input, rebuilt from its key and matched against the output
    /// it spends -- not taken from anything the host says.
    pub kind: AddressKind,
}

impl Account {
    /// A slot nothing has been written into yet; its prefix matches no real path.
    pub const NONE: Self = Self {
        prefix: [u32::MAX; 3],
        kind: AddressKind::P2wpkh,
    };
}

/// Accounts one transaction may spend from before this stops counting them.
///
/// Four is more than a single-sig spend has any business using; past that the extra
/// accounts simply cannot claim change, which shows their outputs as leaving.
pub const MAX_ACCOUNTS: usize = 4;

/// Registered multisig wallets one transaction may spend from before this stops counting
/// them; the same bound as [`MAX_ACCOUNTS`], for the same reason.
pub const MAX_SPENT_WALLETS: usize = MAX_ACCOUNTS;

/// Levels a change path has: `purpose'/coin'/account'/branch/index`.
pub const CHANGE_DEPTH: usize = 5;

/// Highest change index this will call change.
///
/// A wallet finds its own change by scanning forward from zero with a gap limit, so change
/// parked at an arbitrary index is change nobody will ever find: `.../1/1900000000` spends
/// to the seed and to nothing a recovery can reach. Twenty thousand is far past any honest
/// wallet's counter and far short of hiding money.
///
/// Stock bounds this against the highest index it has seen rather than a flat number. That
/// wants somewhere to keep the highest index, which is what the settings store is for; the
/// flat cap is what stands until then.
pub const MAX_CHANGE_INDEX: u32 = 20_000;

/// Derivation records one output may ask this to follow.
///
/// The same bound, and for the same reason, as [`signer::MAX_KEYS_PER_INPUT`]: a record
/// naming our master fingerprint -- which every exported descriptor publishes -- costs a
/// walk of up to [`signer::MAX_STEPS`] elliptic-curve levels, and an output map holds as
/// many records as the file has room for. Past the cap the answer is "not change", which
/// shows the amount as leaving rather than hiding it as change.
pub const MAX_CHANGE_KEYS: usize = MAX_KEYS_PER_INPUT;

/// The `branch`/`index` an input's own derivation record claims for us.
///
/// A claim only: it says where to look, and the rebuilt script is what settles whether the
/// answer is right. Taken from a record naming our fingerprint, since that is the one
/// describing this device's share of the wallet.
fn ours_address(
    psbt: &Psbt<'_>,
    index: usize,
    fingerprint: [u8; FINGERPRINT_LEN],
) -> Option<(u32, u32)> {
    let map = psbt.input(index)?.map();
    for rec in map.records_of(in_key::BIP32_DERIVATION) {
        if let Some(request) = signer::request_from_record(rec, fingerprint, false) {
            let steps = request.steps();
            if steps.len() >= 2 {
                return Some((steps[steps.len() - 2], steps[steps.len() - 1]));
            }
        }
    }
    None
}

/// As [`ours_address`], for an output's map, with the whole record: the path is what
/// the change heuristic reads, not only its last two levels.
fn output_request(
    psbt: &Psbt<'_>,
    index: usize,
    fingerprint: [u8; FINGERPRINT_LEN],
) -> Option<KeyRequest> {
    let map = psbt.output(index)?.map();
    map.records_of(out_key::BIP32_DERIVATION)
        .filter_map(|rec| signer::request_from_record(rec, fingerprint, false))
        .find(|request| request.steps().len() >= 2)
}

/// The account a change path belongs to, if its shape allows it to be change at all.
///
/// `None` -- meaning "not change" -- when the path is not five levels, when its first three
/// are not an account these inputs spend from, when the branch is neither receive nor
/// change, when either of the last two levels is hardened, or when the index is past
/// [`MAX_CHANGE_INDEX`].
fn account_for(steps: &[u32], accounts: &[Account]) -> Option<Account> {
    if steps.len() != CHANGE_DEPTH {
        return None;
    }
    let (branch, index) = (steps[3], steps[4]);
    if branch & HARDENED != 0 || index & HARDENED != 0 {
        return None;
    }
    // Receive and change branches both: a wallet that pays itself on the receive branch is
    // unusual and not dishonest, and calling it "leaving" would overstate the spend.
    if branch > 1 || index > MAX_CHANGE_INDEX {
        return None;
    }
    let prefix = [steps[0], steps[1], steps[2]];
    accounts.iter().find(|a| a.prefix == prefix).copied()
}

/// Whether output `index` pays back to this wallet.
///
/// Not "does it claim our fingerprint": the key is derived down the claimed path and the
/// output's script is rebuilt from it. Only a byte-for-byte match counts. A host that
/// mislabels a stranger's output as change is trying to hide where the money goes.
///
/// `accounts` are the single-signature accounts the inputs spend from, and `wallets` the
/// registered multisig wallets they spend from, as indices into [`Owner::wallets`]; both
/// come from [`summarise`]. An output has to belong to one of them: a registered wallet
/// this spend is not drawing on is another wallet, and paying it is money leaving this one.
///
/// At most [`MAX_CHANGE_KEYS`] records are followed: this runs with interrupts masked.
///
/// [`change_of`] is the same test with the proven path and the heuristic's verdict on it.
pub fn is_change(
    psbt: &Psbt<'_>,
    index: usize,
    script: &[u8],
    owner: &Owner<'_>,
    accounts: &[Account],
    wallets: &[usize],
    kw: &KeyWork,
) -> bool {
    let spent = Spent {
        accounts,
        wallets,
        highest_index: None,
    };
    change_of(psbt, index, script, owner, &spent, kw).is_some()
}

/// As [`is_change`], returning the path the output was proven at and what
/// [`unusual_change`] makes of it. `None` is "not change".
///
/// The heuristic runs only on an output that *is* change: it changes nothing about what
/// counts as change, it only annotates it.
pub fn change_of(
    psbt: &Psbt<'_>,
    index: usize,
    script: &[u8],
    owner: &Owner<'_>,
    spent: &Spent<'_>,
    kw: &KeyWork,
) -> Option<ChangePath> {
    let (master, fingerprint) = (owner.master, owner.fingerprint);
    let map = psbt.output(index).map(|o| o.map())?;
    let (accounts, wallets) = (spent.accounts, spent.wallets);
    let found = |request: &KeyRequest| {
        let mut steps = [0u32; signer::MAX_STEPS];
        let depth = request.steps().len();
        steps[..depth].copy_from_slice(request.steps());
        ChangePath {
            steps,
            depth,
            unusual: unusual_change(request.steps(), accounts, spent.highest_index),
        }
    };

    // Change back to a registered multisig wallet, proven the same way an input is: the
    // script is rebuilt from the wallet's own record and has to equal this output's. The
    // shape rules that bound a single-signature change path apply here too -- an address
    // no recovery will scan to is not change, whoever co-signs it. And it has to be a
    // wallet the inputs spend from: a single-signature spend paying a registered multisig
    // wallet is sending to it, however many of its keys are ours.
    if multisig::is_script_hash(script)
        && let Some(request) = output_request(psbt, index, fingerprint)
        && let [.., branch, at] = *request.steps()
        && (branch <= 1 && at <= MAX_CHANGE_INDEX)
        && multisig::match_script(owner.wallets, script, branch, at)
            .is_some_and(|found| wallets.contains(&found.wallet))
    {
        return Some(found(&request));
    }
    let mut derived = 0usize;
    for taproot in [false, true] {
        let keytype = if taproot {
            out_key::TAP_BIP32_DERIVATION
        } else {
            out_key::BIP32_DERIVATION
        };
        for rec in map.records_of(keytype) {
            if derived == MAX_CHANGE_KEYS {
                return None;
            }
            let Some(request) = signer::request_from_record(rec, fingerprint, taproot) else {
                continue;
            };
            derived += 1;
            // The shape, before the arithmetic: the key deriving to the script proves the
            // seed owns the output, and nothing about *where*. An account we are not
            // spending from, a branch that is not a wallet branch, or an index no recovery
            // will scan to, is money leaving -- so it is shown as leaving.
            let Some(account) = account_for(request.steps(), accounts) else {
                continue;
            };
            let Ok(signer) = signer::match_key(master, &request, kw) else {
                continue;
            };
            // Only the kind that account's inputs used. A BIP-84 wallet does not make
            // P2PKH change, and a host saying otherwise is describing a different wallet.
            let pubkey = signer.public_key_bytes();
            let mut ours = [0u8; 34];
            if let Ok(n) = address::script_pubkey(account.kind, &pubkey, &mut ours)
                && ours[..n] == *script
            {
                return Some(found(&request));
            }
        }
    }
    None
}

/// The destinations of `psbt`, written into `out`; returns how many were filled.
///
/// `accounts` and `wallets` are what [`summarise`] worked out from the inputs, as for
/// [`is_change`]. Stops at `out`'s length; [`destinations_from`] takes the rest a page at
/// a time.
pub fn destinations(
    psbt: &Psbt<'_>,
    owner: &Owner<'_>,
    network: Network,
    accounts: &[Account],
    wallets: &[usize],
    out: &mut [Destination],
    kw: &KeyWork,
) -> usize {
    destinations_from(psbt, owner, network, accounts, wallets, 0, out, kw)
}

/// As [`destinations`], starting at output `start`: one page of a review that shows a
/// long transaction a screenful at a time. Returns how many were filled, which is fewer
/// than `out.len()` only on the last page.
///
/// Without the inputs' highest index, so the far-index rule of the change heuristic is
/// off; [`destinations_with`] takes the whole of what the summary learnt.
#[allow(clippy::too_many_arguments)]
pub fn destinations_from(
    psbt: &Psbt<'_>,
    owner: &Owner<'_>,
    network: Network,
    accounts: &[Account],
    wallets: &[usize],
    start: usize,
    out: &mut [Destination],
    kw: &KeyWork,
) -> usize {
    let spent = Spent {
        accounts,
        wallets,
        highest_index: None,
    };
    destinations_with(psbt, owner, network, &spent, start, out, kw)
}

/// [`destinations_from`] with everything [`summarise`] learnt from the inputs
/// ([`Summary::spent`]), so each change output carries the heuristic's verdict.
pub fn destinations_with(
    psbt: &Psbt<'_>,
    owner: &Owner<'_>,
    network: Network,
    spent: &Spent<'_>,
    start: usize,
    out: &mut [Destination],
    kw: &KeyWork,
) -> usize {
    let mut n = 0;
    for (index, txout) in psbt.unsigned_tx().outputs().enumerate().skip(start) {
        if n == out.len() {
            break;
        }
        let mut d = Destination {
            index,
            amount: txout.amount,
            ..Destination::BLANK
        };
        d.address_len = address::from_script(txout.script, network, &mut d.address).unwrap_or(0);
        // A bare P2PK output has no address; the key is shown in its compressed form,
        // which is the same point however the script pushed it.
        if d.address_len == 0
            && let Some(key) = signer::p2pk_key(txout.script)
        {
            d.p2pk = true;
            if let Ok(pk) = outscript::crypto::secp256k1::SecpPublicKey::from_sec1(key) {
                d.address_len = write_hex(&pk.serialize_compressed(), &mut d.address);
            }
        }
        if let Some(change) = change_of(psbt, index, txout.script, owner, spent, kw) {
            d.change = true;
            d.unusual = change.unusual;
            d.path = change.steps;
            d.path_len = change.depth;
        }
        out[n] = d;
        n += 1;
    }
    n
}

/// Lower-case hex of `bytes` into `out`; returns the length, or zero if it does not fit.
fn write_hex(bytes: &[u8], out: &mut [u8]) -> usize {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    if out.len() < bytes.len() * 2 {
        return 0;
    }
    for (i, b) in bytes.iter().enumerate() {
        out[i * 2] = HEX[usize::from(b >> 4)];
        out[i * 2 + 1] = HEX[usize::from(b & 0xf)];
    }
    bytes.len() * 2
}

/// Inputs of `psbt` this wallet can sign, written into `out` as indices; returns how many.
pub fn our_inputs(
    psbt: &Psbt<'_>,
    master: &ExtendedPrivKey,
    fingerprint: [u8; FINGERPRINT_LEN],
    out: &mut [usize],
    kw: &KeyWork,
) -> usize {
    let mut n = 0;
    for index in 0..psbt.unsigned_tx().input_count() {
        if n == out.len() {
            break;
        }
        let mut keys = [KeyRequest::EMPTY; MAX_KEYS_PER_INPUT];
        let found = signer::key_requests(psbt, index, fingerprint, &mut keys).unwrap_or(0);
        if keys[..found]
            .iter()
            .any(|r| signer::match_key(master, r, kw).is_ok())
        {
            out[n] = index;
            n += 1;
        }
    }
    n
}

/// How a listed-keys request divides this wallet's inputs.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Listed {
    /// Inputs one of the listed keys signs; their indices are what was written out.
    pub signable: usize,
    /// Inputs this wallet could sign, but only with a key the request did not list. They
    /// stay unsigned, and the review says how many.
    pub unlisted: usize,
}

/// [`our_inputs`], for a request that listed the keys it wants: the inputs a listed key
/// signs are written into `out`, and the ones only an unlisted key of ours could sign
/// are counted.
pub fn our_inputs_listed(
    psbt: &Psbt<'_>,
    master: &ExtendedPrivKey,
    fingerprint: [u8; FINGERPRINT_LEN],
    listed: &[crate::hostkeys::KeyPath],
    out: &mut [usize],
    kw: &KeyWork,
) -> Listed {
    let mut got = Listed::default();
    for index in 0..psbt.unsigned_tx().input_count() {
        let mut keys = [KeyRequest::EMPTY; MAX_KEYS_PER_INPUT];
        let found = signer::key_requests(psbt, index, fingerprint, &mut keys).unwrap_or(0);
        let mut ours = false;
        let mut asked = false;
        for r in &keys[..found] {
            if signer::match_key(master, r, kw).is_ok() {
                ours = true;
                if signer::is_listed(r, Some(listed)) {
                    asked = true;
                }
            }
        }
        if asked && got.signable < out.len() {
            out[got.signable] = index;
            got.signable += 1;
        } else if ours {
            got.unlisted += 1;
        }
    }
    got
}

/// Whether some input of `psbt` names `want` as ours: a derivation record claiming this
/// wallet's fingerprint at exactly that path, whose key really is the one the path leads
/// to.
fn names_key(
    psbt: &Psbt<'_>,
    master: &ExtendedPrivKey,
    fingerprint: [u8; FINGERPRINT_LEN],
    want: &crate::hostkeys::KeyPath,
    kw: &KeyWork,
) -> bool {
    (0..psbt.unsigned_tx().input_count()).any(|index| {
        let mut keys = [KeyRequest::EMPTY; MAX_KEYS_PER_INPUT];
        let found = signer::key_requests(psbt, index, fingerprint, &mut keys).unwrap_or(0);
        keys[..found]
            .iter()
            .any(|r| r.steps() == want.steps() && signer::match_key(master, r, kw).is_ok())
    })
}

/// The first listed key that no input of `psbt` names as ours, if there is one.
///
/// A listed key that matches nothing is a host asking for a signature the transaction has
/// no place for, and the request is refused whole rather than signed around it.
pub fn unmatched_key(
    psbt: &Psbt<'_>,
    master: &ExtendedPrivKey,
    fingerprint: [u8; FINGERPRINT_LEN],
    listed: &[crate::hostkeys::KeyPath],
    kw: &KeyWork,
) -> Option<usize> {
    listed
        .iter()
        .position(|want| !names_key(psbt, master, fingerprint, want, kw))
}

/// Inputs of `psbt` that a WIF-store key `pubkey` (compressed) can sign, as indices,
/// written into `out`; returns how many.
///
/// Public work -- it is only the key's addresses against the scripts the inputs pay -- so
/// it needs no [`KeyWork`]; the signature that follows does.
pub fn wif_inputs(psbt: &Psbt<'_>, pubkey: &[u8; address::PUBKEY_LEN], out: &mut [usize]) -> usize {
    let mut n = 0;
    for index in 0..psbt.unsigned_tx().input_count() {
        if n == out.len() {
            break;
        }
        if signer::input_pays_key(psbt, index, pubkey) {
            out[n] = index;
            n += 1;
        }
    }
    n
}

/// Whether input `index` already carries a signature from one of our keys, so a second
/// signing pass would add nothing.
pub fn already_signed(
    psbt: &Psbt<'_>,
    index: usize,
    master: &ExtendedPrivKey,
    fingerprint: [u8; FINGERPRINT_LEN],
    kw: &KeyWork,
) -> bool {
    let Some(inp) = psbt.input(index) else {
        return false;
    };
    let mut keys = [KeyRequest::EMPTY; MAX_KEYS_PER_INPUT];
    let found = signer::key_requests(psbt, index, fingerprint, &mut keys).unwrap_or(0);
    for request in &keys[..found] {
        if signer::match_key(master, request, kw).is_err() {
            continue;
        }
        if request.taproot {
            if inp.tap_key_sig().is_some() {
                return true;
            }
        } else if inp.partial_sig(request.pubkey()).is_some() {
            return true;
        }
    }
    false
}

/// How many more signatures the transaction needs after this pass, at most over its
/// inputs, or zero when it is complete or has no multisig input.
///
/// For the "pass this to the next cosigner" screen. Each multisig input's script -- the
/// witness or redeem script, which the chain pins to the coin -- says `M` in its first
/// byte, and the input's partial-signature records say how many are there. An input that
/// is already finalised needs nothing. Public work: nothing here touches a key.
pub fn more_signatures_needed(psbt: &Psbt<'_>) -> usize {
    let mut most = 0usize;
    for inp in psbt.inputs() {
        if inp.is_finalized() {
            continue;
        }
        let Some(script) = inp.witness_script().or(inp.redeem_script()) else {
            continue;
        };
        // `OP_M <keys...> OP_N OP_CHECKMULTISIG`, with `OP_M` in `OP_1..=OP_15`.
        let (Some(&first), Some(&last)) = (script.first(), script.last()) else {
            continue;
        };
        if !(0x51..=0x5f).contains(&first) || last != 0xae {
            continue;
        }
        let m = usize::from(first - 0x50);
        let have = inp.partial_sigs().count();
        most = most.max(m.saturating_sub(have));
    }
    most
}

/// Reconstruct the multisig wallet an input spends from, out of the definition the PSBT
/// carries, or `None` when it cannot be trusted to.
///
/// This is the machinery behind the multisig PSBT trust policy
/// ([`catcard_settings::prefs::MultisigTrust`]): a wallet the owner never registered may
/// still be signed for if -- and only if -- the PSBT itself proves what it is. `None` is
/// returned, and the input left to the ordinary "unregistered multisig" refusal, whenever
/// any of that proof is missing:
///
/// - the input is not a script-hash (multisig) output, or is one a `wallets` entry already
///   accounts for, so there is nothing to reconstruct;
/// - the PSBT does not name this device's own key on the input, so we cannot even place the
///   address, let alone tell whether the wallet is ours;
/// - the global xpubs, the redeem/witness script or the script form are missing or
///   malformed;
/// - **the rebuilt address does not equal the coin's scriptPubKey** -- the one check that
///   matters, since the global xpubs are the host's word until the script they produce is
///   the script the chain locked the coin to;
/// - the reconstructed wallet does not involve this device.
///
/// Public-key work only: the cosigners' account keys come straight from the PSBT and the
/// address is rebuilt by public derivation, so this needs no [`KeyWork`]. Proving that our
/// key is genuinely a cosigner (not merely a claimed fingerprint) is the caller's job,
/// through [`multisig::our_cosigner`], which does touch the seed.
pub fn reconstruct_for_input(
    psbt: &Psbt<'_>,
    index: usize,
    fingerprint: [u8; FINGERPRINT_LEN],
    wallets: &[Multisig],
) -> Option<Multisig> {
    let utxo = psbt.utxo(index).ok()?;
    if !multisig::is_script_hash(utxo.script) {
        return None;
    }
    // Our own record says which address this is. Without it the wallet cannot be placed,
    // and the rebuilt script cannot be checked against this coin's.
    let (branch, at) = ours_address(psbt, index, fingerprint)?;
    // Already one of the wallets in hand: nothing to reconstruct, and the normal path signs
    // it.
    if multisig::match_script(wallets, utxo.script, branch, at).is_some() {
        return None;
    }

    let inp = psbt.input(index)?;
    let (kind, ms_script) = script_form(utxo.script, inp.redeem_script(), inp.witness_script())?;
    // `OP_M` is `0x50 + M`; anything below `OP_1` is not a multisig script.
    let m = ms_script.first()?.checked_sub(0x50)?;

    // The cosigners are the PSBT's global xpubs -- account-level keys, each with the origin
    // that names its master. Collected as parsed; the count is what `N` must be, and the
    // rebuilt address is what proves it.
    let mut parsed: [Option<Cosigner>; MAX_COSIGNERS] = [None; MAX_COSIGNERS];
    let mut n = 0usize;
    for rec in psbt.global().records_of(global::XPUB) {
        if n == MAX_COSIGNERS {
            return None;
        }
        let Some(c) = cosigner_from_global(rec.key_data(), rec.value) else {
            continue;
        };
        parsed[n] = Some(c);
        n += 1;
    }
    if n == 0 {
        return None;
    }
    let mut cosigners = [parsed[0]?; MAX_COSIGNERS];
    for (slot, got) in cosigners.iter_mut().zip(parsed.iter()).take(n) {
        *slot = (*got)?;
    }
    let cosigners = &cosigners[..n];

    // Sorted first, because it is the default and by far the common case; then unsorted,
    // since `multi` and `sortedmulti` over the same keys are different wallets with
    // different addresses. Whichever rebuilds this exact scriptPubKey at this address is the
    // wallet; if neither does, the PSBT's keys do not describe this coin and it is refused.
    for sorted in [true, false] {
        let Ok(candidate) = Multisig::new(m, cosigners, kind, sorted) else {
            continue;
        };
        let mut built = [0u8; 34];
        let matches = matches!(
            candidate.script_pubkey(branch, at, &mut built),
            Ok(len) if built[..len] == *utxo.script
        );
        if matches && candidate.involves(fingerprint) {
            return Some(candidate);
        }
    }
    None
}

/// The script form of a script-hash output, and the multisig script to read `M` and `N`
/// from, settled by the scriptPubKey's shape and -- for P2SH -- its redeem script.
fn script_form<'a>(
    spk: &[u8],
    redeem: Option<&'a [u8]>,
    witness: Option<&'a [u8]>,
) -> Option<(Kind, &'a [u8])> {
    // Native P2WSH: `OP_0 <32-byte sha256(witnessScript)>`.
    if spk.len() == 34 && spk[0] == 0x00 && spk[1] == 32 {
        return Some((Kind::P2wsh, witness?));
    }
    // P2SH: `OP_HASH160 <20> OP_EQUAL`. The redeem script tells P2SH-wrapped segwit
    // (`sh(wsh(...))`, whose redeem script is a P2WSH program) from legacy `sh(...)`.
    if spk.len() == 23 && spk[0] == 0xA9 && spk[1] == 0x14 && spk[22] == 0x87 {
        let rs = redeem?;
        if rs.len() == 34 && rs[0] == 0x00 && rs[1] == 32 {
            return Some((Kind::P2shP2wsh, witness?));
        }
        return Some((Kind::P2sh, rs));
    }
    None
}

/// One cosigner from a global-xpub record: its 78-byte key data and its derivation-path
/// value (a master fingerprint followed by little-endian steps).
fn cosigner_from_global(key_data: &[u8], value: &[u8]) -> Option<Cosigner> {
    let xpub = ExtendedPubKey::from_raw(key_data).ok()?;
    // A derivation path is the fingerprint and whole 4-byte steps; BIP-174 already frames
    // it so, but this reads defensively.
    if value.len() < 4 || !value.len().is_multiple_of(4) {
        return None;
    }
    let mut fingerprint = [0u8; FINGERPRINT_LEN];
    fingerprint.copy_from_slice(&value[..4]);
    let steps = &value[4..];
    let count = steps.len() / 4;
    if count > MAX_ORIGIN {
        return None;
    }
    let mut origin = [0u32; MAX_ORIGIN];
    // `value.len()` was checked to be a multiple of four above, so there is no remainder.
    let (steps, _) = steps.as_chunks::<4>();
    for (slot, chunk) in origin.iter_mut().zip(steps) {
        *slot = u32::from_le_bytes(*chunk);
    }
    Some(Cosigner {
        fingerprint,
        origin,
        origin_len: count,
        xpub,
    })
}

#[cfg(test)]
mod tests;
