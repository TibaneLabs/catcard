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
            ..
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

/// Signing one transaction, all the way round.
///
/// The point of the test is that the four pieces agree with each other: the message this
/// reader hands out is the message the network's own rule says is signed, the slot it
/// names for a key is the slot that key's signature belongs in, and the transaction that
/// comes out the far side still parses -- now with one more signature on it than it had.
///
/// A real ed25519 key, and the signature verified with a verifier this crate does not
/// otherwise use, because "we signed something" is not the claim. The claim is that what
/// we signed is what a validator will check.
#[test]
fn a_transaction_signed_here_verifies_there() {
    use outscript::crypto::ed25519;

    let seed = [9u8; 32];
    let public = ed25519::public_from_seed(&seed);
    let payer = SolanaKey(public);
    let mut raw = build(
        payer,
        std::vec![transfer_instruction(payer, key(2), 5_000_000)],
    );

    let tx = parse(&raw).expect("a transaction");
    assert_eq!(
        tx.signing(),
        Signing {
            required: 1,
            present: 0
        }
    );
    let slot = tx.signer_index(&public).expect("our key signs this");
    assert_eq!(slot, 0);
    assert!(!tx.signed(slot));
    // The message is everything except the signature slots, and for a legacy
    // transaction that is one compact-u16 and one empty slot.
    assert_eq!(tx.message(), &raw[1 + 64..]);

    let signature = ed25519::sign(&seed, tx.message());
    assert!(ed25519::verify(&public, tx.message(), &signature));

    assert!(place_signature(&mut raw, slot, &signature));
    let tx = parse(&raw).expect("still a transaction");
    assert_eq!(
        tx.signing(),
        Signing {
            required: 1,
            present: 1
        }
    );
    assert!(tx.signed(0));
    // And the message did not move: a signature goes in a slot, never into the message,
    // which is what lets a second signer add theirs without breaking the first.
    assert!(ed25519::verify(&public, tx.message(), &signature));
}

/// A key that is not a signer gets no slot, and a slot that does not exist gets nothing.
#[test]
fn only_a_signer_is_given_a_slot() {
    let payer = key(1);
    let raw = build(payer, std::vec![transfer_instruction(payer, key(2), 1)]);
    let tx = parse(&raw).expect("a transaction");

    // The recipient is in the account list and authorises nothing.
    assert_eq!(tx.signer_index(&[2; 32]), None);
    // A key the transaction never mentions.
    assert_eq!(tx.signer_index(&[42; 32]), None);
    assert_eq!(tx.signer_index(&payer.0), Some(0));

    let mut raw = raw;
    assert!(!place_signature(&mut raw, 1, &[7; 64]));
    assert!(!place_signature(&mut [], 0, &[7; 64]));
    // And nothing was written on the way to saying no.
    assert_eq!(parse(&raw).expect("unchanged").signing().present, 0);
}

/// The message inside a real signing request, read as a transaction would be.
///
/// The bytes are the `signData` of the `sol-sign-request` in Keystone's own test for
/// that registry item -- a message, not a transaction, which is the thing worth pinning
/// down: a reader that expected signature slots in front would find a header where the
/// count should be and refuse the request every wallet actually sends.
const KEYSTONE_MESSAGE: &[u8] = &[
    0x01, 0x00, 0x01, 0x03, 0xc8, 0xd8, 0x42, 0xa2, 0xf1, 0x7f, 0xd7, 0xaa, 0xb6, 0x08, 0xce, 0x2e,
    0xa5, 0x35, 0xa6, 0xe9, 0x58, 0xdf, 0xfa, 0x20, 0xca, 0xf6, 0x69, 0xb3, 0x47, 0xb9, 0x11, 0xc4,
    0x17, 0x19, 0x65, 0x53, 0x0f, 0x95, 0x76, 0x20, 0xb2, 0x28, 0xba, 0xe2, 0xb9, 0x4c, 0x82, 0xdd,
    0xd4, 0xc0, 0x93, 0x98, 0x3a, 0x67, 0x36, 0x55, 0x55, 0xb7, 0x37, 0xec, 0x7d, 0xdc, 0x11, 0x17,
    0xe6, 0x1c, 0x72, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x10, 0x29, 0x5c, 0xc2, 0xf1, 0xf3, 0x9f, 0x36, 0x04, 0x71, 0x84, 0x96,
    0xea, 0x00, 0x67, 0x6d, 0x6a, 0x72, 0xec, 0x66, 0xad, 0x09, 0xd9, 0x26, 0xe3, 0xec, 0xe3, 0x4f,
    0x56, 0x5f, 0x18, 0xd2, 0x01, 0x02, 0x02, 0x00, 0x01, 0x0c, 0x02, 0x00, 0x00, 0x00, 0x00, 0xe1,
    0xf5, 0x05, 0x00, 0x00, 0x00, 0x00,
];

#[test]
fn a_signing_request_carries_a_message_not_a_transaction() {
    // A message does not parse as a transaction: the first byte is a signature count of
    // one, and what follows is a header rather than sixty-four bytes of signature.
    assert!(parse(KEYSTONE_MESSAGE).is_err());

    let tx = parse_message(KEYSTONE_MESSAGE).expect("a message");
    assert_eq!(tx.version(), Version::Legacy);
    assert_eq!(tx.key_count(), 3);
    assert_eq!(
        tx.signing(),
        Signing {
            required: 1,
            present: 0
        }
    );
    // The whole of it is what a signature covers.
    assert_eq!(tx.message(), KEYSTONE_MESSAGE);
    match tx.action(0).expect("an action") {
        Action::TransferSol { lamports, .. } => assert_eq!(lamports, 100_000_000),
        other => panic!("a SOL transfer read as {other:?}"),
    }
}

/// A message becomes a transaction by growing the slots it was missing.
#[test]
fn a_message_becomes_a_transaction_that_can_hold_signatures() {
    let tx = parse_message(KEYSTONE_MESSAGE).expect("a message");
    let mut out = [0u8; 512];
    let n = tx.to_transaction(&mut out).expect("room");
    assert_eq!(n, 1 + 64 + KEYSTONE_MESSAGE.len());

    let built = parse(&out[..n]).expect("a transaction now");
    assert_eq!(built.message(), KEYSTONE_MESSAGE);
    assert_eq!(
        built.signing(),
        Signing {
            required: 1,
            present: 0
        }
    );

    // And it holds one: the slot fills, the message does not move.
    assert!(place_signature(&mut out[..n], 0, &[3; 64]));
    let signed = parse(&out[..n]).expect("still a transaction");
    assert_eq!(signed.signing().present, 1);
    assert_eq!(signed.message(), KEYSTONE_MESSAGE);

    // A buffer one byte short is refused rather than filled part way.
    assert_eq!(tx.to_transaction(&mut out[..n - 1]), None);
}

/// A transaction written back out is the transaction that came in.
#[test]
fn a_transaction_round_trips_through_to_transaction() {
    let payer = key(1);
    let mut raw = build(payer, std::vec![transfer_instruction(payer, key(2), 9)]);
    assert!(place_signature(&mut raw, 0, &[5; 64]));

    let tx = parse(&raw).expect("a transaction");
    let mut out = [0u8; 512];
    let n = tx.to_transaction(&mut out).expect("room");
    assert_eq!(&out[..n], &raw[..]);
}

/// The compute budget is where a transaction says what it will cost.
///
/// Both numbers, and the fee they make together. The case that matters is the third
/// one: a price with no limit beside it is a fee this device cannot work out, and
/// reporting it as unknown is the difference between a screen that is silent about a
/// cost and one that quietly says zero.
#[test]
fn the_priority_fee_is_read_from_the_budget() {
    fn budget(tag: u8, payload: &[u8]) -> SolanaInstruction {
        let mut data = std::vec![tag];
        data.extend_from_slice(payload);
        SolanaInstruction {
            program_id: SolanaKey(crate::literal::mint(
                "ComputeBudget111111111111111111111111111111",
            )),
            accounts: std::vec![],
            data,
        }
    }

    // 200_000 units at 3_000 micro-lamports: 600_000_000 millionths, so 600 lamports.
    let raw = build(
        key(1),
        std::vec![
            budget(2, &200_000u32.to_le_bytes()),
            budget(3, &3_000u64.to_le_bytes()),
            transfer_instruction(key(1), key(2), 1),
        ],
    );
    let tx = parse(&raw).expect("a transaction");
    assert_eq!(
        tx.action(0),
        Some(Action::ComputeBudget(Budget::Limit { units: 200_000 }))
    );
    assert_eq!(
        tx.action(1),
        Some(Action::ComputeBudget(Budget::Price {
            micro_lamports: 3_000
        }))
    );
    assert_eq!(
        tx.fee(),
        Fee {
            base: LAMPORTS_PER_SIGNATURE,
            priority: Some(600),
            priority_unknown: false,
        }
    );

    // No budget at all: the signature fee, and nothing on top.
    let raw = build(key(1), std::vec![transfer_instruction(key(1), key(2), 1)]);
    assert_eq!(
        parse(&raw).expect("a transaction").fee(),
        Fee {
            base: LAMPORTS_PER_SIGNATURE,
            priority: Some(0),
            priority_unknown: false,
        }
    );

    // A price with no limit: the runtime picks the limit, so the fee is not in here.
    let raw = build(
        key(1),
        std::vec![
            budget(3, &1_000_000u64.to_le_bytes()),
            transfer_instruction(key(1), key(2), 1),
        ],
    );
    let fee = parse(&raw).expect("a transaction").fee();
    assert_eq!(fee.priority, None);
    assert!(fee.priority_unknown);

    // A payload of the wrong length is not decoded into a number.
    let raw = build(key(1), std::vec![budget(2, &[1, 2])]);
    assert_eq!(
        parse(&raw).expect("a transaction").action(0),
        Some(Action::ComputeBudget(Budget::Other))
    );
}

/// A durable nonce is read, not warned about.
///
/// A nonce is how a transaction stays valid long enough to be carried to an air-gapped
/// device and back: instead of a blockhash that expires in about a minute, the message
/// commits to a nonce held in an account, and the first instruction spends it. So it is
/// exactly what this device sees most often -- and calling it "a program this build
/// cannot read" would have put a warning on the mechanism that waited for us.
#[test]
fn a_durable_nonce_is_read_rather_than_warned_about() {
    let (nonce, authority, to) = (key(9), key(1), key(2));
    // AdvanceNonceAccount: tag 4, no parameters. Accounts are the nonce account, the
    // recent-blockhashes sysvar, and the authority.
    let advance = SolanaInstruction {
        program_id: SolanaKey([0u8; 32]),
        accounts: std::vec![
            SolanaAccountMeta {
                pubkey: nonce,
                is_signer: false,
                is_writable: true
            },
            SolanaAccountMeta {
                pubkey: key(7),
                is_signer: false,
                is_writable: false
            },
            SolanaAccountMeta {
                pubkey: authority,
                is_signer: true,
                is_writable: false
            },
        ],
        data: std::vec![4, 0, 0, 0],
    };
    let raw = build(
        authority,
        std::vec![advance, transfer_instruction(authority, to, 100_000_000)],
    );
    let tx = parse(&raw).expect("a transaction");

    assert_eq!(
        tx.action(0),
        Some(Action::AdvanceNonce {
            account: Some(nonce),
            authority: Some(authority),
        })
    );
    match tx.action(1).expect("the transfer") {
        Action::TransferSol { lamports, .. } => assert_eq!(lamports, 100_000_000),
        other => panic!("read as {other:?}"),
    }
}

/// A System instruction this build has no reader for is named and numbered.
///
/// Not decoded -- the screens say so -- but "System instruction 8" is something a person
/// can look up, and "a program this build cannot name" is not.
#[test]
fn an_unread_system_instruction_says_which_one_it_is() {
    let allocate = SolanaInstruction {
        program_id: SolanaKey([0u8; 32]),
        accounts: std::vec![SolanaAccountMeta {
            pubkey: key(1),
            is_signer: true,
            is_writable: true
        }],
        // Allocate: tag 8, then a u64 of space.
        data: std::vec![8, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
    };
    let raw = build(key(1), std::vec![allocate]);
    let tx = parse(&raw).expect("a transaction");
    match tx.action(0).expect("an action") {
        Action::Unknown {
            named,
            tag,
            accounts,
            ..
        } => {
            assert_eq!(named, Some("System"));
            assert_eq!(tag, Some(8));
            assert_eq!(accounts, 1);
        }
        other => panic!("read as {other:?}"),
    }
}

/// A message is not a transaction, even when it would parse as one.
///
/// This is the bug that reached the screen: a transaction opens with a compact-u16 count
/// of signature slots, and a message opens with `numRequiredSignatures`. Both are a small
/// number in the same place, so reading a message as a transaction eats its header and
/// its first account key as a "signature" and then finds a header in the middle of the
/// account list. Every length after that can still add up, and the device showed "1 of 40
/// signed" for a transaction needing one signature -- and would have signed the wrong
/// bytes, since the message it thought it was signing started 65 bytes into the real one.
///
/// What tells them apart is the rule a transaction must obey: it carries exactly as many
/// slots as its header asks for, empty ones included.
#[test]
fn a_message_is_not_read_as_a_transaction() {
    let payer = key(1);
    let raw = build(payer, std::vec![transfer_instruction(payer, key(2), 1)]);
    // The message inside it: everything past the one empty slot.
    let message = &raw[1 + 64..];

    let tx = parse_message(message).expect("a message");
    assert_eq!(tx.signing().required, 1);
    // And not a transaction, by the rule above.
    assert!(parse(message).is_err());
}

/// A header that asks for more signatures than the transaction has room for.
#[test]
fn slots_and_header_must_agree() {
    let payer = key(1);
    let mut raw = build(payer, std::vec![transfer_instruction(payer, key(2), 1)]);
    assert!(parse(&raw).is_ok());

    // One slot, a header asking for two.
    raw[1 + 64] = 2;
    assert_eq!(parse(&raw).err(), Some(Error::SignatureCount));

    // And a header asking for more signers than there are accounts at all. Under 0x80,
    // because the top bit of that byte is what marks a versioned message -- above it
    // this is a version number rather than a count, and a different refusal.
    raw[1 + 64] = 100;
    assert_eq!(parse(&raw).err(), Some(Error::SignatureCount));
}
