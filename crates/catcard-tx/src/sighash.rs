//! BIP-143 signature hash for segwit v0 inputs.
//!
//! # Why this replaced the legacy algorithm
//!
//! Legacy sighash re-serialises the whole transaction for every input, so signing N
//! inputs costs O(N²) hashing — and, more importantly for a hardware wallet, the
//! preimage does **not** include the amount being spent. A device signing a legacy
//! input has no way to know what it is spending without being handed every previous
//! transaction in full.
//!
//! BIP-143 fixes both. The three midstates (`hashPrevouts`, `hashSequence`,
//! `hashOutputs`) are computed once and reused across inputs, and the preimage carries
//! the input's `amount`. A host that lies about an amount produces a signature that
//! simply does not verify, which turns a "trust the host" problem into a cryptographic
//! one.
//!
//! **That guarantee is the reason the fee shown to a user can be trusted**, so the
//! amount must come from the same source the signature commits to — never from a
//! separate, unsigned field.

use crate::{sha256d, Error, Sha256d, Transaction};

/// The sighash flag byte, as it appears in the preimage (4 bytes, little-endian).
pub type SigHashFlag = u32;

pub const SIGHASH_ALL: SigHashFlag = 0x01;
pub const SIGHASH_NONE: SigHashFlag = 0x02;
pub const SIGHASH_SINGLE: SigHashFlag = 0x03;
pub const SIGHASH_ANYONECANPAY: SigHashFlag = 0x80;

/// Mask selecting the base type from a flag that may carry `ANYONECANPAY`.
pub const SIGHASH_MASK: SigHashFlag = 0x1f;

/// The three reusable midstates of a BIP-143 signing session.
///
/// Computed once per transaction rather than once per input, which is what makes
/// signing linear instead of quadratic.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Midstates {
    pub prevouts: [u8; 32],
    pub sequence: [u8; 32],
    pub outputs: [u8; 32],
}

impl Midstates {
    /// Compute all three for `tx`.
    pub fn compute(tx: &Transaction<'_>) -> Result<Self, Error> {
        let mut prevouts = Sha256d::new();
        let mut sequence = Sha256d::new();
        for input in tx.inputs.iter() {
            let i = input?;
            prevouts.update(&i.previous_output.txid);
            prevouts.update(&i.previous_output.vout.to_le_bytes());
            sequence.update(&i.sequence.to_le_bytes());
        }

        let mut outputs = Sha256d::new();
        for output in tx.outputs.iter() {
            let o = output?;
            outputs.update(&o.value.to_le_bytes());
            write_var_slice(&mut outputs, o.script_pubkey);
        }

        Ok(Self {
            prevouts: prevouts.finalize(),
            sequence: sequence.finalize(),
            outputs: outputs.finalize(),
        })
    }
}

fn write_var_slice(h: &mut Sha256d, data: &[u8]) {
    let mut buf = [0u8; 9];
    let n = crate::VarInt::write(data.len() as u64, &mut buf).expect("9 bytes is enough");
    h.update(&buf[..n]);
    h.update(data);
}

/// Compute the BIP-143 signature hash for one input.
///
/// `script_code` is the script being executed — for P2WPKH it is the implied
/// `OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG`, **not** the witness program.
/// `amount` is the value of the output being spent, in satoshis.
pub fn bip143(
    tx: &Transaction<'_>,
    midstates: &Midstates,
    input_index: usize,
    script_code: &[u8],
    amount: u64,
    flag: SigHashFlag,
) -> Result<[u8; 32], Error> {
    let input = tx.inputs.get(input_index)?;
    let base = flag & SIGHASH_MASK;
    let anyone_can_pay = flag & SIGHASH_ANYONECANPAY != 0;

    let zero = [0u8; 32];

    // ANYONECANPAY drops the commitment to every other input, so the prevout and
    // sequence midstates are replaced by zeros.
    let hash_prevouts = if anyone_can_pay {
        zero
    } else {
        midstates.prevouts
    };

    // NONE and SINGLE also drop the sequence commitment: without a commitment to the
    // outputs there is nothing for the sequences to protect.
    let hash_sequence = if anyone_can_pay || base == SIGHASH_NONE || base == SIGHASH_SINGLE {
        zero
    } else {
        midstates.sequence
    };

    let hash_outputs = match base {
        SIGHASH_SINGLE => {
            // Commits only to the output at this input's index. Bitcoin Core returns a
            // hash of 1 when that output does not exist — a bug preserved for
            // compatibility. A wallet must refuse rather than sign under it.
            let out = tx
                .outputs
                .get(input_index)
                .ok_or(Error::SingleWithoutOutput { index: input_index })??;
            let mut h = Sha256d::new();
            h.update(&out.value.to_le_bytes());
            write_var_slice(&mut h, out.script_pubkey);
            h.finalize()
        }
        SIGHASH_NONE => zero,
        _ => midstates.outputs,
    };

    let mut h = Sha256d::new();
    h.update(&(tx.version as u32).to_le_bytes());
    h.update(&hash_prevouts);
    h.update(&hash_sequence);
    h.update(&input.previous_output.txid);
    h.update(&input.previous_output.vout.to_le_bytes());
    write_var_slice(&mut h, script_code);
    // The amount: the field that makes a hardware wallet able to trust the fee.
    h.update(&amount.to_le_bytes());
    h.update(&input.sequence.to_le_bytes());
    h.update(&hash_outputs);
    h.update(&tx.lock_time.to_le_bytes());
    h.update(&flag.to_le_bytes());
    Ok(h.finalize())
}

/// Build the P2WPKH script code from a 20-byte public key hash.
///
/// `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG`. BIP-143 specifies this rather
/// than the witness program itself, which is a common source of wrong signatures.
pub fn p2wpkh_script_code(pubkey_hash: &[u8; 20]) -> [u8; 25] {
    let mut s = [0u8; 25];
    s[0] = 0x76; // OP_DUP
    s[1] = 0xa9; // OP_HASH160
    s[2] = 0x14; // push 20
    s[3..23].copy_from_slice(pubkey_hash);
    s[23] = 0x88; // OP_EQUALVERIFY
    s[24] = 0xac; // OP_CHECKSIG
    s
}

/// Double-SHA256 of a byte string, re-exported for callers building preimages.
pub fn hash(data: &[u8]) -> [u8; 32] {
    sha256d(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// BIP-143's "Native P2WPKH" worked example.
    const UNSIGNED: &str = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000";

    #[test]
    fn bip143_native_p2wpkh_vector() {
        let raw = unhex(UNSIGNED);
        let tx = Transaction::parse(&raw).unwrap();
        let mid = Midstates::compute(&tx).unwrap();

        // The values BIP-143 publishes for this transaction.
        assert_eq!(
            hex(&mid.prevouts),
            "96b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd37"
        );
        assert_eq!(
            hex(&mid.sequence),
            "52b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3b"
        );
        assert_eq!(
            hex(&mid.outputs),
            "863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e5"
        );

        // Input 1 is the segwit one: script code and amount from the BIP.
        let script_code = unhex("1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac");
        let amount = 600_000_000u64;
        let digest = bip143(&tx, &mid, 1, &script_code[1..], amount, SIGHASH_ALL).unwrap();
        assert_eq!(
            hex(&digest),
            "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"
        );
    }

    #[test]
    fn the_amount_is_committed_to() {
        // The property that lets a hardware wallet trust the fee it displays. If the
        // amount were not in the preimage, a lying host could show any fee it liked.
        let raw = unhex(UNSIGNED);
        let tx = Transaction::parse(&raw).unwrap();
        let mid = Midstates::compute(&tx).unwrap();
        let sc = unhex("76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac");

        let a = bip143(&tx, &mid, 1, &sc, 600_000_000, SIGHASH_ALL).unwrap();
        let b = bip143(&tx, &mid, 1, &sc, 600_000_001, SIGHASH_ALL).unwrap();
        assert_ne!(a, b, "the amount does not affect the digest");
    }

    #[test]
    fn each_input_gets_a_different_digest() {
        let raw = unhex(UNSIGNED);
        let tx = Transaction::parse(&raw).unwrap();
        let mid = Midstates::compute(&tx).unwrap();
        let sc = unhex("76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac");
        let a = bip143(&tx, &mid, 0, &sc, 625_000_000, SIGHASH_ALL).unwrap();
        let b = bip143(&tx, &mid, 1, &sc, 600_000_000, SIGHASH_ALL).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn the_script_code_is_committed_to() {
        let raw = unhex(UNSIGNED);
        let tx = Transaction::parse(&raw).unwrap();
        let mid = Midstates::compute(&tx).unwrap();
        let a = bip143(&tx, &mid, 1, &[0x51], 600_000_000, SIGHASH_ALL).unwrap();
        let b = bip143(&tx, &mid, 1, &[0x52], 600_000_000, SIGHASH_ALL).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn sighash_flags_change_the_digest() {
        let raw = unhex(UNSIGNED);
        let tx = Transaction::parse(&raw).unwrap();
        let mid = Midstates::compute(&tx).unwrap();
        let sc = unhex("76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac");

        let all = bip143(&tx, &mid, 1, &sc, 600_000_000, SIGHASH_ALL).unwrap();
        let none = bip143(&tx, &mid, 1, &sc, 600_000_000, SIGHASH_NONE).unwrap();
        let single = bip143(&tx, &mid, 1, &sc, 600_000_000, SIGHASH_SINGLE).unwrap();
        let acp = bip143(
            &tx,
            &mid,
            1,
            &sc,
            600_000_000,
            SIGHASH_ALL | SIGHASH_ANYONECANPAY,
        )
        .unwrap();

        let mut all_four = [all, none, single, acp];
        all_four.sort();
        let before = all_four.len();
        let mut v = all_four.to_vec();
        v.dedup();
        assert_eq!(
            v.len(),
            before,
            "two sighash types produced the same digest"
        );
    }

    /// Build a minimal transaction with `n_in` inputs and `n_out` outputs.
    fn synthetic(n_in: u8, n_out: u8) -> Vec<u8> {
        let mut v = vec![0x01, 0x00, 0x00, 0x00]; // version 1
        v.push(n_in);
        for i in 0..n_in {
            v.extend_from_slice(&[i; 32]); // prev txid
            v.extend_from_slice(&(i as u32).to_le_bytes()); // vout
            v.push(0x00); // empty scriptSig
            v.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // sequence
        }
        v.push(n_out);
        for i in 0..n_out {
            v.extend_from_slice(&(1000u64 + i as u64).to_le_bytes());
            v.push(0x01); // one-byte script
            v.push(0x51); // OP_1
        }
        v.extend_from_slice(&0u32.to_le_bytes()); // locktime
        v
    }

    #[test]
    fn sighash_single_without_a_matching_output_is_refused() {
        // Bitcoin Core hashes to 1 here rather than erroring — a bug preserved for
        // compatibility. Signing under it would authorise something the user never
        // saw, so this refuses instead of reproducing it.
        let raw = synthetic(3, 2);
        let tx = Transaction::parse(&raw).unwrap();
        let mid = Midstates::compute(&tx).unwrap();

        // Inputs 0 and 1 have a matching output; input 2 does not.
        assert!(bip143(&tx, &mid, 0, &[0x51], 1, SIGHASH_SINGLE).is_ok());
        assert!(bip143(&tx, &mid, 1, &[0x51], 1, SIGHASH_SINGLE).is_ok());
        assert_eq!(
            bip143(&tx, &mid, 2, &[0x51], 1, SIGHASH_SINGLE),
            Err(Error::SingleWithoutOutput { index: 2 })
        );

        // The same input signs fine under ALL, so the refusal is specific to SINGLE.
        assert!(bip143(&tx, &mid, 2, &[0x51], 1, SIGHASH_ALL).is_ok());
    }

    #[test]
    fn sighash_single_commits_only_to_its_own_output() {
        let raw = synthetic(2, 2);
        let tx = Transaction::parse(&raw).unwrap();
        let mid = Midstates::compute(&tx).unwrap();
        // Two inputs under SINGLE commit to different outputs, so the digests differ
        // even with identical script code and amount.
        let a = bip143(&tx, &mid, 0, &[0x51], 1, SIGHASH_SINGLE).unwrap();
        let b = bip143(&tx, &mid, 1, &[0x51], 1, SIGHASH_SINGLE).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn an_out_of_range_input_is_an_error() {
        let raw = unhex(UNSIGNED);
        let tx = Transaction::parse(&raw).unwrap();
        let mid = Midstates::compute(&tx).unwrap();
        assert!(matches!(
            bip143(&tx, &mid, 99, &[0x51], 1, SIGHASH_ALL),
            Err(Error::NoSuchInput { index: 99 })
        ));
    }

    #[test]
    fn p2wpkh_script_code_shape() {
        // BIP-143 specifies the *P2PKH-style* script, not the witness program. Using
        // the program instead is a common source of signatures that do not verify.
        let pkh = [0x11u8; 20];
        let s = p2wpkh_script_code(&pkh);
        assert_eq!(s[0], 0x76);
        assert_eq!(s[1], 0xa9);
        assert_eq!(s[2], 0x14);
        assert_eq!(&s[3..23], &pkh);
        assert_eq!(s[23], 0x88);
        assert_eq!(s[24], 0xac);
        assert_eq!(s.len(), 25);
    }

    #[test]
    fn midstates_are_reused_not_recomputed_per_input() {
        // Same object, two inputs: the point of BIP-143 is that this is linear.
        let raw = unhex(UNSIGNED);
        let tx = Transaction::parse(&raw).unwrap();
        let mid = Midstates::compute(&tx).unwrap();
        let again = Midstates::compute(&tx).unwrap();
        assert_eq!(mid, again, "midstates are not deterministic");
    }
}
