//! The timelocks a transaction carries, read for the review screen.
//!
//! Two kinds, both decided by fields every signature commits to:
//!
//! - **Absolute**: `nLockTime`, a block height or a Unix time before which the
//!   transaction cannot be mined. It only counts when at least one input's `nSequence`
//!   is not `0xffffffff`; with every input final the field is ignored by consensus, and a
//!   locktime the network will not enforce is worth a warning rather than a promise.
//!   Source: Bitcoin consensus `IsFinalTx`; `LOCKTIME_THRESHOLD = 500000000` [C]
//! - **Relative** (BIP-68): per input, in `nSequence`, for a transaction of version 2 or
//!   more. Bit 31 disables it; bit 22 chooses seconds (in units of 512) over blocks; the
//!   low sixteen bits are the count. Source: BIP-68 "Specification" [C]
//!
//! Nothing here is refused. A timelock is a legitimate thing for a transaction to carry
//! and the owner may well have asked for it; what the screen owes them is to say so, in
//! the units it is written in, and to say when a locktime is set but cannot take effect.

use outscript::psbt::{Psbt, UnsignedTx};

/// Below this an `nLockTime` is a block height; at or above it, a Unix time.
/// Source: Bitcoin consensus `LOCKTIME_THRESHOLD` [C]
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// The `nSequence` value that opts an input out of every timelock.
pub const SEQUENCE_FINAL: u32 = 0xffff_ffff;

/// BIP-68's bits. Source: BIP-68 "Specification" [C]
const SEQUENCE_DISABLE_FLAG: u32 = 1 << 31;
const SEQUENCE_TYPE_FLAG: u32 = 1 << 22;
const SEQUENCE_MASK: u32 = 0x0000_ffff;
/// One unit of a time-based relative lock, in seconds.
const SEQUENCE_GRANULARITY: u32 = 512;

/// What an `nLockTime` names.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Absolute {
    /// Not before this block height.
    Height(u32),
    /// Not before this Unix time.
    Time(u32),
}

/// A transaction's absolute lock, if it has one.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Locktime {
    pub lock: Absolute,
    /// Whether the network will enforce it. False when every input is final, in which
    /// case the field is set and does nothing -- which stock warns about as an
    /// "ineffective locktime". Source: hw-reference/help-and-warning-screens.md
    /// "OP_RETURN / unknown-script / odd-locktime oddities" [C]
    pub effective: bool,
}

/// A BIP-68 relative lock on one input.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Relative {
    /// Not until the spent output is this many blocks deep.
    Blocks(u16),
    /// Not until the spent output is this many seconds old (a multiple of 512).
    Seconds(u32),
}

/// The `nLockTime` of `psbt`'s transaction, classified; `None` when it is zero.
pub fn absolute(psbt: &Psbt<'_>) -> Option<Locktime> {
    let tx = psbt.unsigned_tx();
    let raw = tx.locktime();
    if raw == 0 {
        return None;
    }
    let lock = if raw < LOCKTIME_THRESHOLD {
        Absolute::Height(raw)
    } else {
        Absolute::Time(raw)
    };
    let effective = tx.inputs().any(|i| i.sequence != SEQUENCE_FINAL);
    Some(Locktime { lock, effective })
}

/// The relative lock an input's `sequence` encodes under a transaction of `version`,
/// if any. Source: BIP-68 "Specification" [C]
pub fn relative(sequence: u32, version: u32) -> Option<Relative> {
    // BIP-68 applies to version 2 and above; the version is a signed field on the wire,
    // so a "negative" version (top bit set) is below 2 as well.
    if version < 2 || version & 0x8000_0000 != 0 {
        return None;
    }
    if sequence & SEQUENCE_DISABLE_FLAG != 0 {
        return None;
    }
    let count = sequence & SEQUENCE_MASK;
    if sequence & SEQUENCE_TYPE_FLAG != 0 {
        Some(Relative::Seconds(count * SEQUENCE_GRANULARITY))
    } else {
        Some(Relative::Blocks(count as u16))
    }
}

/// Every input of `tx` (a PSBT's unsigned transaction) with a relative lock, as
/// `(input index, lock)`.
pub fn relatives<'t, 'a: 't>(
    tx: &'t UnsignedTx<'a>,
) -> impl Iterator<Item = (usize, Relative)> + 't {
    let version = tx.version();
    tx.inputs()
        .enumerate()
        .filter_map(move |(i, inp)| relative(inp.sequence, version).map(|r| (i, r)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use outscript::btcraw::{RawTx, RawTxIn, RawTxOut};

    /// A PSBT around a transaction with the given version, locktime and input sequences.
    fn psbt_with(version: u32, locktime: u32, sequences: &[u32], buf: &mut [u8]) -> usize {
        let ins: Vec<RawTxIn<'_>> = sequences
            .iter()
            .map(|&sequence| RawTxIn {
                txid: [0x33; 32],
                vout: 0,
                script_sig: &[],
                sequence,
                witness: &[],
            })
            .collect();
        let outs = [RawTxOut {
            amount: 1000,
            script: &[
                0x00, 0x14, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44,
            ],
        }];
        let tx = RawTx {
            version,
            inputs: &ins,
            outputs: &outs,
            locktime,
        };
        Psbt::create_to_slice(&tx, buf).unwrap()
    }

    #[test]
    fn a_zero_locktime_is_no_lock() {
        let mut buf = vec![0u8; 512];
        let n = psbt_with(2, 0, &[SEQUENCE_FINAL], &mut buf);
        assert_eq!(absolute(&Psbt::parse(&buf[..n]).unwrap()), None);
    }

    #[test]
    fn a_locktime_is_a_height_below_the_threshold_and_a_time_from_it() {
        let mut buf = vec![0u8; 512];
        let n = psbt_with(2, 850_000, &[0xffff_fffe], &mut buf);
        assert_eq!(
            absolute(&Psbt::parse(&buf[..n]).unwrap()),
            Some(Locktime {
                lock: Absolute::Height(850_000),
                effective: true
            })
        );
        let n = psbt_with(2, LOCKTIME_THRESHOLD - 1, &[0xffff_fffe], &mut buf);
        assert!(matches!(
            absolute(&Psbt::parse(&buf[..n]).unwrap()),
            Some(Locktime {
                lock: Absolute::Height(_),
                ..
            })
        ));
        let n = psbt_with(2, 1_700_000_000, &[0xffff_fffe], &mut buf);
        assert_eq!(
            absolute(&Psbt::parse(&buf[..n]).unwrap()),
            Some(Locktime {
                lock: Absolute::Time(1_700_000_000),
                effective: true
            })
        );
    }

    /// Every input final: the field is set and consensus ignores it. Said, not hidden.
    #[test]
    fn a_locktime_with_every_input_final_is_ineffective() {
        let mut buf = vec![0u8; 512];
        let n = psbt_with(2, 850_000, &[SEQUENCE_FINAL, SEQUENCE_FINAL], &mut buf);
        assert_eq!(
            absolute(&Psbt::parse(&buf[..n]).unwrap()),
            Some(Locktime {
                lock: Absolute::Height(850_000),
                effective: false
            })
        );
        // One non-final input is enough to make it count.
        let n = psbt_with(2, 850_000, &[SEQUENCE_FINAL, 0], &mut buf);
        assert!(
            absolute(&Psbt::parse(&buf[..n]).unwrap())
                .unwrap()
                .effective
        );
    }

    /// BIP-68's own worked shapes: blocks, seconds in units of 512, the disable bit, and
    /// the version gate.
    #[test]
    fn relative_locks_follow_bip68() {
        assert_eq!(relative(10, 2), Some(Relative::Blocks(10)));
        assert_eq!(relative(0xffff, 2), Some(Relative::Blocks(0xffff)));
        // Type flag set: 3 units of 512 seconds.
        assert_eq!(relative((1 << 22) | 3, 2), Some(Relative::Seconds(1536)));
        // Bits above the low sixteen (other than the flags) are ignored.
        assert_eq!(relative(0x0010_0007, 2), Some(Relative::Blocks(7)));
        // The disable flag, and the final sequence, encode no lock.
        assert_eq!(relative((1 << 31) | 10, 2), None);
        assert_eq!(relative(SEQUENCE_FINAL, 2), None);
        // Version 1 has no relative locks at all, whatever the sequence says.
        assert_eq!(relative(10, 1), None);
        assert_eq!(relative(10, 0), None);
        assert_eq!(
            relative(10, 0xffff_fffe),
            None,
            "a negative version is below 2"
        );
        assert_eq!(relative(10, 3), Some(Relative::Blocks(10)));
    }

    #[test]
    fn relatives_name_the_inputs_that_carry_one() {
        let mut buf = vec![0u8; 512];
        let n = psbt_with(2, 0, &[SEQUENCE_FINAL, 144, (1 << 22) | 1], &mut buf);
        let psbt = Psbt::parse(&buf[..n]).unwrap();
        let tx = psbt.unsigned_tx();
        let got: Vec<_> = relatives(&tx).collect();
        assert_eq!(
            got,
            vec![(1, Relative::Blocks(144)), (2, Relative::Seconds(512))]
        );
        // Under version 1 the same sequences mean nothing.
        let n = psbt_with(1, 0, &[SEQUENCE_FINAL, 144, (1 << 22) | 1], &mut buf);
        let psbt = Psbt::parse(&buf[..n]).unwrap();
        let tx = psbt.unsigned_tx();
        assert_eq!(relatives(&tx).count(), 0);
    }
}
