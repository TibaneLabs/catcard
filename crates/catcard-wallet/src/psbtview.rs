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
    for index in 0..inputs {
        let mut keys = [KeyRequest::EMPTY; MAX_KEYS_PER_INPUT];
        let found = signer::key_requests(psbt, index, fingerprint, &mut keys).unwrap_or(0);
        let mine = keys[..found]
            .iter()
            .any(|r| signer::match_key(master, r, kw).is_ok());
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
        if is_change(psbt, index, out.script, master, fingerprint, kw) {
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

/// Whether output `index` pays back to this wallet.
///
/// Not "does it claim our fingerprint": the key is derived down the claimed path and the
/// output's script is rebuilt from it. Only a byte-for-byte match counts. A host that
/// mislabels a stranger's output as change is trying to hide where the money goes.
pub fn is_change(
    psbt: &Psbt<'_>,
    index: usize,
    script: &[u8],
    master: &ExtendedPrivKey,
    fingerprint: [u8; FINGERPRINT_LEN],
    kw: &KeyWork,
) -> bool {
    let Some(map) = psbt.output(index).map(|o| o.map()) else {
        return false;
    };
    for taproot in [false, true] {
        let keytype = if taproot {
            out_key::TAP_BIP32_DERIVATION
        } else {
            out_key::BIP32_DERIVATION
        };
        for rec in map.records_of(keytype) {
            let Some(request) = signer::request_from_record(rec, fingerprint, taproot) else {
                continue;
            };
            let Ok(signer) = signer::match_key(master, &request, kw) else {
                continue;
            };
            // The script the key would produce, for whichever form this output takes.
            let pubkey = signer.public_key_bytes();
            for kind in [
                AddressKind::P2wpkh,
                AddressKind::P2shP2wpkh,
                AddressKind::P2pkh,
                AddressKind::P2tr,
            ] {
                let mut ours = [0u8; 34];
                if let Ok(n) = address::script_pubkey(kind, &pubkey, &mut ours)
                    && ours[..n] == *script
                {
                    return true;
                }
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
            change: is_change(psbt, index, txout.script, master, fingerprint, kw),
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
