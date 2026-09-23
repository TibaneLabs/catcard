//! What a Solana reader has to get right, written as the ways it could be wrong.
//!
//! The fixtures are built by `outscript`'s encoder -- the half of that crate this one
//! deliberately does not use -- so a transaction under test is not assembled by the code
//! reading it back.

extern crate alloc;
extern crate std;

use alloc::vec::Vec;

use outscript::solana::{
    SolanaAccountMeta, SolanaInstruction, create_ata_instruction, new_solana_tx,
    spl_transfer_instruction, transfer_instruction,
};

use super::*;

fn key(n: u8) -> SolanaKey {
    SolanaKey([n; 32])
}

/// Serialise a transaction with the given instructions, unsigned.
fn build(payer: SolanaKey, instructions: Vec<SolanaInstruction>) -> Vec<u8> {
    let tx = new_solana_tx(payer, SolanaKey([7; 32]), &instructions).expect("builds");
    tx.to_bytes().expect("serialises")
}

#[test]
fn a_sol_transfer_is_read_as_one() {
    let (from, to) = (key(1), key(2));
    let raw = build(
        from,
        std::vec![transfer_instruction(from, to, 1_500_000_000)],
    );
    let tx = parse(&raw).expect("a transaction");

    assert_eq!(tx.version(), Version::Legacy);
    assert_eq!(tx.fee_payer(), Some(from));
    assert_eq!(tx.instruction_count(), 1);
    match tx.action(0).expect("an action") {
        Action::TransferSol {
            from: f,
            to: t,
            lamports,
        } => {
            assert_eq!(f, Some(from));
            assert_eq!(t, Some(to));
            assert_eq!(lamports, 1_500_000_000);
            assert_eq!(lamports / LAMPORTS_PER_SOL, 1);
        }
        other => panic!("a SOL transfer read as {other:?}"),
    }
}

/// An unsigned transaction has its slots, and none of them filled.
#[test]
fn an_unsigned_transaction_says_what_it_is_waiting_for() {
    let raw = build(key(1), std::vec![transfer_instruction(key(1), key(2), 1)]);
    let tx = parse(&raw).expect("a transaction");
    let signing = tx.signing();
    assert_eq!(signing.required, 1, "the fee payer must sign");
    assert_eq!(signing.present, 0);
    assert_eq!(signing.missing(), 1);
    assert!(
        !signing.partly_signed(),
        "nothing is signed, so nothing is partly"
    );
}

/// A slot somebody has filled is counted, and the rest are still missing.
///
/// This is the state the whole "partly signed" idea is about: a transaction that has
/// been round one signer and is on its way to another.
#[test]
fn a_partly_signed_transaction_is_counted_not_refused() {
    let mut raw = build(key(1), std::vec![transfer_instruction(key(1), key(2), 1)]);
    // Two signature slots, the first filled.
    let mut two = std::vec![2u8];
    two.extend_from_slice(&[0xAB; 64]);
    two.extend_from_slice(&[0x00; 64]);
    two.extend_from_slice(&raw[1 + 64..]);
    // The header must agree that two signatures are required.
    let header_at = 1 + 128;
    two[header_at] = 2;
    raw = two;

    let tx = parse(&raw).expect("a transaction");
    let signing = tx.signing();
    assert_eq!(signing.required, 2);
    assert_eq!(signing.present, 1, "an all-zero slot is not a signature");
    assert_eq!(signing.missing(), 1);
    assert!(signing.partly_signed());
}

#[test]
fn an_spl_transfer_is_read_with_its_owner() {
    let (source, dest, owner) = (key(3), key(4), key(1));
    let ix = spl_transfer_instruction(source, dest, owner, 250_000);
    let raw = build(owner, std::vec![ix]);
    let tx = parse(&raw).expect("a transaction");
    match tx.action(0).expect("an action") {
        Action::TransferToken {
            from,
            to,
            owner: o,
            amount,
            decimals,
            mint,
            named,
        } => {
            assert!(named.is_none(), "an unnamed mint cannot be named");
            assert_eq!(from, Some(source));
            assert_eq!(to, Some(dest));
            assert_eq!(o, Some(owner));
            assert_eq!(amount, 250_000);
            // The unchecked form carries neither, and saying so is the point: without a
            // mint and its decimals, 250000 is a number of the smallest unit of a token
            // nobody has named, and a screen that showed "0.25" would be inventing both.
            assert_eq!(decimals, None);
            assert_eq!(mint, None);
        }
        other => panic!("an SPL transfer read as {other:?}"),
    }
}

/// The *checked* form carries the mint and its decimals, which is what lets a screen
/// scale the number instead of showing raw units.
#[test]
fn a_checked_spl_transfer_carries_its_mint_and_decimals() {
    let (source, mint, dest, owner) = (key(3), key(5), key(4), key(1));
    let mut data = std::vec![12u8];
    data.extend_from_slice(&250_000u64.to_le_bytes());
    data.push(6);
    let ix = SolanaInstruction {
        program_id: outscript::solana::token_program(),
        accounts: std::vec![
            SolanaAccountMeta {
                pubkey: source,
                is_signer: false,
                is_writable: true
            },
            SolanaAccountMeta {
                pubkey: mint,
                is_signer: false,
                is_writable: false
            },
            SolanaAccountMeta {
                pubkey: dest,
                is_signer: false,
                is_writable: true
            },
            SolanaAccountMeta {
                pubkey: owner,
                is_signer: true,
                is_writable: false
            },
        ],
        data,
    };
    let raw = build(owner, std::vec![ix]);
    let tx = parse(&raw).expect("a transaction");
    match tx.action(0).expect("an action") {
        Action::TransferToken {
            from,
            to,
            owner: o,
            amount,
            decimals,
            mint: m,
            named,
        } => {
            // A mint nobody listed stays unnamed: `key(5)` is not a real mint.
            assert!(named.is_none());
            assert_eq!(from, Some(source));
            assert_eq!(
                to,
                Some(dest),
                "the destination is the third account, not the second"
            );
            assert_eq!(o, Some(owner));
            assert_eq!(amount, 250_000);
            assert_eq!(decimals, Some(6));
            assert_eq!(m, Some(mint));
        }
        other => panic!("a checked SPL transfer read as {other:?}"),
    }
}

#[test]
fn creating_a_token_account_names_the_owner_and_the_mint() {
    let (payer, owner, mint) = (key(1), key(2), key(3));
    let ix = create_ata_instruction(payer, owner, mint).expect("builds");
    let raw = build(payer, std::vec![ix]);
    let tx = parse(&raw).expect("a transaction");
    match tx.action(0).expect("an action") {
        Action::CreateTokenAccount { owner: o, mint: m } => {
            assert_eq!(o, Some(owner));
            assert_eq!(m, Some(mint));
        }
        other => panic!("an ATA creation read as {other:?}"),
    }
}

/// A program this build does not decode is named and counted, never guessed at.
#[test]
fn an_unknown_program_is_named_and_counted() {
    let program = key(9);
    let ix = SolanaInstruction {
        program_id: program,
        accounts: std::vec![
            SolanaAccountMeta {
                pubkey: key(1),
                is_signer: true,
                is_writable: true,
            },
            SolanaAccountMeta {
                pubkey: key(2),
                is_signer: false,
                is_writable: false,
            },
        ],
        data: std::vec![0xDE, 0xAD, 0xBE, 0xEF],
    };
    let raw = build(key(1), std::vec![ix]);
    let tx = parse(&raw).expect("a transaction");
    match tx.action(0).expect("an action") {
        Action::Unknown {
            program: p,
            accounts,
            data_len,
        } => {
            assert_eq!(p, program);
            assert_eq!(accounts, 2);
            assert_eq!(data_len, 4);
        }
        other => panic!("an unknown program read as {other:?}"),
    }
}

/// Several instructions are all readable, in order.
#[test]
fn every_instruction_is_readable_in_order() {
    let payer = key(1);
    let raw = build(
        payer,
        std::vec![
            transfer_instruction(payer, key(2), 10),
            transfer_instruction(payer, key(3), 20),
        ],
    );
    let tx = parse(&raw).expect("a transaction");
    assert_eq!(tx.instruction_count(), 2);
    let lamports = |i| match tx.action(i) {
        Some(Action::TransferSol { lamports, .. }) => lamports,
        other => panic!("instruction {i} read as {other:?}"),
    };
    assert_eq!(lamports(0), 10);
    assert_eq!(lamports(1), 20);
    assert!(tx.action(2).is_none(), "there is no third instruction");
}

/// Truncation is truncation.
#[test]
fn a_truncated_transaction_is_refused() {
    let raw = build(key(1), std::vec![transfer_instruction(key(1), key(2), 1)]);
    for cut in 1..raw.len() {
        assert!(
            parse(&raw[..cut]).is_err(),
            "{cut} bytes of a transaction parsed as one"
        );
    }
}

/// An account index past the end of the key array is refused rather than shown blank.
#[test]
fn an_index_off_the_end_is_refused() {
    let mut raw = build(key(1), std::vec![transfer_instruction(key(1), key(2), 1)]);
    // The transfer's account indices sit just before its data, so find the data and
    // step back over the length byte.
    //
    // Searched from the *end*: the System program's key is thirty-two zero bytes, and
    // the key before it ends in 0x02, so `[2, 0, 0, 0]` also appears at that boundary.
    // The first match is that seam, not the instruction.
    let at = raw
        .windows(4)
        .rposition(|w| w == [2, 0, 0, 0])
        .expect("the transfer tag");
    // Immediately before: data length (1 byte), and before that the two account indices.
    raw[at - 2] = 0x7f;
    assert_eq!(
        parse(&raw).err(),
        Some(Error::BadAccountIndex),
        "an index past the key array was accepted"
    );
}

/// A key the message does not carry reads as absent rather than as some other key.
#[test]
fn an_address_not_carried_is_absent() {
    let raw = build(key(1), std::vec![transfer_instruction(key(1), key(2), 1)]);
    let tx = parse(&raw).expect("a transaction");
    assert!(tx.key(tx.key_count()).is_none());
}

/// Base58 is how these addresses are read and compared.
#[test]
fn an_address_is_shown_in_base58() {
    let raw = build(key(1), std::vec![transfer_instruction(key(1), key(2), 1)]);
    let tx = parse(&raw).expect("a transaction");
    let payer = tx.fee_payer().expect("a payer");
    let mut out = [0u8; ADDRESS_MAX];
    let text = address(&payer, &mut out);
    assert!(!text.is_empty() && text != "?");
    assert!(
        text.bytes().all(|b| b.is_ascii_alphanumeric()),
        "base58 has no punctuation: {text}"
    );
}

/// A checked transfer of a mint the table carries is named, with its decimals.
///
/// The end of the chain the whole table exists for: 12,500,000 of
/// `EPjFWdd5…` is "12.5 USDC", and the raw number is not an answer to what somebody is
/// about to approve.
#[test]
fn a_known_mint_is_named() {
    let usdc = SolanaKey(crate::literal::mint(
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    ));
    let (source, dest, owner) = (key(3), key(4), key(1));
    let mut data = std::vec![12u8];
    data.extend_from_slice(&12_500_000u64.to_le_bytes());
    data.push(6);
    let ix = SolanaInstruction {
        program_id: outscript::solana::token_program(),
        accounts: std::vec![
            SolanaAccountMeta {
                pubkey: source,
                is_signer: false,
                is_writable: true
            },
            SolanaAccountMeta {
                pubkey: usdc,
                is_signer: false,
                is_writable: false
            },
            SolanaAccountMeta {
                pubkey: dest,
                is_signer: false,
                is_writable: true
            },
            SolanaAccountMeta {
                pubkey: owner,
                is_signer: true,
                is_writable: false
            },
        ],
        data,
    };
    let raw = build(owner, std::vec![ix]);
    let tx = parse(&raw).expect("a transaction");
    let action = tx.action(0).expect("an action");
    match action {
        Action::TransferToken {
            named,
            decimals,
            amount,
            ..
        } => {
            let mint = named.expect("the table carries USDC");
            assert_eq!(mint.symbol, "USDC");
            assert_eq!(mint.decimals, 6);
            assert_eq!(decimals, Some(6));
            assert_eq!(amount, 12_500_000);
        }
        other => panic!("read as {other:?}"),
    }
    assert!(
        !action.decimals_disagree(),
        "the instruction and the table agree about USDC"
    );
}

/// When the instruction's decimals and the table's disagree, that is reported.
///
/// Both describe the same mint and the program enforces its own copy, so a disagreement
/// means this firmware's row is wrong -- and the amount on screen would be out by a
/// power of ten. Better said than silently resolved in favour of either.
#[test]
fn decimals_that_disagree_are_reported() {
    let usdc = SolanaKey(crate::literal::mint(
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    ));
    let mut data = std::vec![12u8];
    data.extend_from_slice(&1u64.to_le_bytes());
    data.push(9); // the table says six
    let ix = SolanaInstruction {
        program_id: outscript::solana::token_program(),
        accounts: std::vec![
            SolanaAccountMeta {
                pubkey: key(3),
                is_signer: false,
                is_writable: true
            },
            SolanaAccountMeta {
                pubkey: usdc,
                is_signer: false,
                is_writable: false
            },
            SolanaAccountMeta {
                pubkey: key(4),
                is_signer: false,
                is_writable: true
            },
            SolanaAccountMeta {
                pubkey: key(1),
                is_signer: true,
                is_writable: false
            },
        ],
        data,
    };
    let raw = build(key(1), std::vec![ix]);
    let tx = parse(&raw).expect("a transaction");
    assert!(tx.action(0).expect("an action").decimals_disagree());
}

/// Bytes after the end of a transaction mean these are not one.
///
/// Which is also what makes the parse usable as a test of "is this a Solana
/// transaction": a reader that stopped at the last instruction would accept anything
/// that merely began like one.
#[test]
fn trailing_bytes_are_refused() {
    let mut raw = build(key(1), std::vec![transfer_instruction(key(1), key(2), 1)]);
    assert!(parse(&raw).is_ok());
    raw.push(0);
    assert_eq!(parse(&raw).err(), Some(Error::NotATransaction));
}

/// A versioned transaction's lookup tables are read, and counted as what cannot be seen.
#[test]
fn a_versioned_transaction_reports_what_it_hides() {
    use outscript::solana::{SolanaAddressTableLookup, new_solana_tx_v0};

    let payer = key(1);
    let ix = transfer_instruction(payer, key(2), 5);
    // Two tables: one lending two writable accounts, one lending three read-only ones.
    let lookups = std::vec![
        SolanaAddressTableLookup {
            account_key: key(8),
            writable_indexes: std::vec![1, 2],
            readonly_indexes: std::vec![],
        },
        SolanaAddressTableLookup {
            account_key: key(9),
            writable_indexes: std::vec![],
            readonly_indexes: std::vec![3, 4, 5],
        },
    ];
    let tx = new_solana_tx_v0(payer, SolanaKey([7; 32]), lookups, &[ix]).expect("builds");
    let raw = tx.to_bytes().expect("serialises");

    let read = parse(&raw).expect("a transaction");
    assert_eq!(read.version(), Version::V0);
    // Five accounts this device cannot see, from two tables -- which is the number a
    // screen has to say out loud rather than showing a complete-looking list that is
    // not the whole list.
    assert_eq!(read.lookups(), (2, 5));
    match read.action(0).expect("an action") {
        Action::TransferSol { lamports, .. } => assert_eq!(lamports, 5),
        other => panic!("read as {other:?}"),
    }
}
