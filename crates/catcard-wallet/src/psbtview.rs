//! What a person is shown before signing, and the checks behind it.
//!
//! A hardware wallet's only real job is this screen. The host says what the transaction
//! does; the device has to state what the signature will actually authorise, using nothing
//! the host merely asserts. So everything here is derived from data the signature commits
//! to, or refused:
//!
//! - **Amounts in** come from the previous transaction each input spends, whose txid
//!   `outscript` checks against the outpoint. A witness UTXO alone is refused: BIP-143
//!   binds the amount of the input being *signed*, so a wrong amount on any *other* input
//!   costs a host nothing and still moves the fee this screen states.
//! - **Amounts out** and their destinations come from the unsigned transaction, which every
//!   signature commits to.
//! - **The fee** is the difference, and a fee that cannot be computed -- an input whose
//!   spent output was not given -- is reported as unknown rather than as zero.
//! - **Change** is an output this wallet can rebuild from its own key: the path the PSBT
//!   claims is derived, the script is recomputed, and it has to match byte for byte. An
//!   output that merely *claims* our fingerprint is not change.
//!
//! The policy limits ([`Policy`]) are the second half: a fee above the cap, or a sighash
//! this will not produce, stops the signing rather than being shown as a warning nobody
//! reads.

use outscript::psbt::{Psbt, input as in_key, output as out_key};

use crate::KeyWork;
use crate::address::{self, AddressKind};
use crate::bip32::{ExtendedPrivKey, FINGERPRINT_LEN, Network};
use crate::signer::{self, KeyRequest, MAX_KEYS_PER_INPUT};

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
}

impl Default for Policy {
    /// Stock's defaults: refuse above 10%, warn above 5%.
    /// Source: hw-reference/firmware-features.md §5 [C]
    fn default() -> Self {
        Self {
            max_fee_percent: 10,
            warn_fee_percent: 5,
        }
    }
}

/// Why a transaction will not be signed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// No input in it belongs to this wallet.
    NothingOfOurs,
    /// An input asks for a sighash type this will not produce.
    Sighash { input: usize, kind: u32 },
    /// The fee is above the policy's cap.
    FeeTooHigh { percent: u32, cap: u32 },
    /// An input's spent output was not provided, so the fee cannot be computed. Signing
    /// blind to the amounts is how a transaction that pays everything to fees gets signed.
    UnknownAmount { input: usize },
    /// An input gave an amount with no transaction behind it, so nothing checks it.
    UnverifiedAmount { input: usize },
    /// The amounts do not add up: outputs exceed inputs.
    Unbalanced,
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
    pub address: [u8; address::MAX_ADDRESS_LEN],
    pub address_len: usize,
}

impl Destination {
    pub fn address(&self) -> &str {
        core::str::from_utf8(&self.address[..self.address_len]).unwrap_or("")
    }
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
    pub fee: u64,
    /// The fee as a percentage of what is being sent, rounded down.
    pub fee_percent: u32,
    /// True if the fee is above the policy's warning level but below its cap.
    pub fee_warn: bool,
}

/// Examine `psbt` against this wallet and `policy`.
///
/// Derives one key per input and per claimed-change output, so it costs elliptic-curve work
/// proportional to the transaction's size; it runs inside a masked region like the signing
/// itself.
pub fn summarise(
    psbt: &Psbt<'_>,
    master: &ExtendedPrivKey,
    fingerprint: [u8; FINGERPRINT_LEN],
    policy: &Policy,
    kw: &KeyWork,
) -> Result<Summary, Refusal> {
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
    for index in 0..inputs {
        let mut keys = [KeyRequest::EMPTY; MAX_KEYS_PER_INPUT];
        let found = signer::key_requests(psbt, index, fingerprint, &mut keys).unwrap_or(0);
        let mut mine = false;
        for request in keys[..found].iter() {
            let Ok(signer) = signer::match_key(master, request, kw) else {
                continue;
            };
            mine = true;
            // Which account, and in which form. The kind is settled by rebuilding the
            // script from our own key and matching it against the output being spent --
            // which `utxo` has already checked against the previous transaction's txid,
            // so it is the chain's answer rather than the host's.
            let steps = request.steps();
            if steps.len() != CHANGE_DEPTH || account_count == MAX_ACCOUNTS {
                continue;
            }
            let prefix = [steps[0], steps[1], steps[2]];
            if accounts[..account_count].iter().any(|a| a.prefix == prefix) {
                continue;
            }
            let Ok(spent) = psbt.utxo(index) else {
                continue;
            };
            let pubkey = signer.public_key_bytes();
            for kind in [
                AddressKind::P2wpkh,
                AddressKind::P2shP2wpkh,
                AddressKind::P2pkh,
                AddressKind::P2tr,
            ] {
                let mut built = [0u8; 34];
                if let Ok(n) = address::script_pubkey(kind, &pubkey, &mut built)
                    && built[..n] == *spent.script
                {
                    accounts[account_count] = Account { prefix, kind };
                    account_count += 1;
                    break;
                }
            }
        }
        if mine {
            ours += 1;
            // A sighash type we will not produce stops the whole transaction: signing the
            // other inputs would hand back a PSBT that looks half-signed for no stated
            // reason.
            match psbt.input(index).and_then(|i| i.sighash_type()) {
                None => {}
                Some(SIGHASH_ALL) => {}
                Some(kind) => return Err(Refusal::Sighash { input: index, kind }),
            }
        }
        // Every input's amount matters to the fee, ours or not, and only the previous
        // transaction settles it -- `utxo` checks its txid against this outpoint.
        if psbt
            .input(index)
            .is_none_or(|i| i.non_witness_utxo().is_none())
        {
            return Err(Refusal::UnverifiedAmount { input: index });
        }
        let utxo = psbt
            .utxo(index)
            .map_err(|_| Refusal::UnknownAmount { input: index })?;
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
            master,
            fingerprint,
            &accounts[..account_count],
            kw,
        ) {
            change = change.saturating_add(out.amount);
        }
    }
    if total_out > total_in {
        return Err(Refusal::Unbalanced);
    }
    let fee = total_in - total_out;
    let sending = total_out - change;
    // Against what is being sent, not against the total: a consolidation that pays itself
    // would otherwise divide by nearly zero and read as a 0% fee.
    let fee_percent = match fee.saturating_mul(100).checked_div(sending) {
        Some(p) => u32::try_from(p).unwrap_or(u32::MAX),
        // Nothing is being sent: a consolidation back to ourselves. A fee against zero has
        // no percentage, so it counts as everything rather than as nothing.
        None if fee == 0 => 0,
        None => 100,
    };
    if fee_percent > policy.max_fee_percent {
        return Err(Refusal::FeeTooHigh {
            percent: fee_percent,
            cap: policy.max_fee_percent,
        });
    }

    Ok(Summary {
        accounts,
        account_count,
        inputs,
        ours,
        outputs,
        total_in,
        total_out,
        sending,
        change,
        fee,
        fee_percent,
        fee_warn: fee_percent > policy.warn_fee_percent,
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

/// The account a change path belongs to, if its shape allows it to be change at all.
///
/// `None` -- meaning "not change" -- when the path is not five levels, when its first three
/// are not an account these inputs spend from, when the branch is neither receive nor
/// change, when either of the last two levels is hardened, or when the index is past
/// [`MAX_CHANGE_INDEX`].
fn account_for(steps: &[u32], accounts: &[Account]) -> Option<Account> {
    const HARDENED: u32 = 0x8000_0000;
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
/// At most [`MAX_CHANGE_KEYS`] records are followed: this runs with interrupts masked.
pub fn is_change(
    psbt: &Psbt<'_>,
    index: usize,
    script: &[u8],
    master: &ExtendedPrivKey,
    fingerprint: [u8; FINGERPRINT_LEN],
    accounts: &[Account],
    kw: &KeyWork,
) -> bool {
    let Some(map) = psbt.output(index).map(|o| o.map()) else {
        return false;
    };
    let mut derived = 0usize;
    for taproot in [false, true] {
        let keytype = if taproot {
            out_key::TAP_BIP32_DERIVATION
        } else {
            out_key::BIP32_DERIVATION
        };
        for rec in map.records_of(keytype) {
            if derived == MAX_CHANGE_KEYS {
                return false;
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
                return true;
            }
        }
    }
    false
}

/// The destinations of `psbt`, written into `out`; returns how many were filled.
pub fn destinations(
    psbt: &Psbt<'_>,
    master: &ExtendedPrivKey,
    fingerprint: [u8; FINGERPRINT_LEN],
    network: Network,
    accounts: &[Account],
    out: &mut [Destination],
    kw: &KeyWork,
) -> usize {
    let mut n = 0;
    for (index, txout) in psbt.unsigned_tx().outputs().enumerate() {
        if n == out.len() {
            break;
        }
        let mut address = [0u8; address::MAX_ADDRESS_LEN];
        let address_len = address::from_script(txout.script, network, &mut address).unwrap_or(0);
        out[n] = Destination {
            index,
            amount: txout.amount,
            change: is_change(psbt, index, txout.script, master, fingerprint, accounts, kw),
            address,
            address_len,
        };
        n += 1;
    }
    n
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
    let _ = in_key::PARTIAL_SIG;
    false
}

#[cfg(test)]
mod tests;
