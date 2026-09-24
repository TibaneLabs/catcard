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

/// An instruction for `program` over `accounts`, with exactly these `data` bytes.
///
/// The bytes are written by hand in each test -- the point is the layout -- and the
/// last account is the one that signs, which is where every token instruction here puts
/// its authority.
fn instruction(program: SolanaKey, accounts: &[SolanaKey], data: Vec<u8>) -> SolanaInstruction {
    let last = accounts.len().saturating_sub(1);
    SolanaInstruction {
        program_id: program,
        accounts: accounts
            .iter()
            .enumerate()
            .map(|(i, &pubkey)| SolanaAccountMeta {
                pubkey,
                is_signer: i == last,
                is_writable: i != last,
            })
            .collect(),
        data,
    }
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
            program,
            from,
            to,
            owner: o,
            amount,
            decimals,
            mint,
            named,
        } => {
            assert_eq!(program, TokenProgram::Spl);
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
            program,
            from,
            to,
            owner: o,
            amount,
            decimals,
            mint: m,
            named,
        } => {
            assert_eq!(program, TokenProgram::Spl);
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

/// Whatever came in, what goes out is a transaction that parses.
///
/// The rebuild is what a signature is placed into, so a shape that survives the review
/// and then fails to parse is a device that says "it stopped parsing" *after* somebody
/// has agreed to sign. Both readings are covered: a transaction rebuilt from itself, and
/// a message grown the slots it never had -- legacy and versioned, since a versioned
/// message keeps a byte in front of its header and that byte is part of what is copied.
#[test]
fn every_shape_rebuilds_into_something_that_parses() {
    let payer = key(1);
    let mut out = [0u8; 1232];

    // A transaction, signed and unsigned.
    let mut raw = build(payer, std::vec![transfer_instruction(payer, key(2), 7)]);
    for signed in [false, true] {
        if signed {
            assert!(place_signature(&mut raw, 0, &[9; 64]));
        }
        let tx = parse(&raw).expect("a transaction");
        let n = tx.to_transaction(&mut out).expect("room");
        let back = parse(&out[..n]).expect("rebuilt, and still a transaction");
        assert_eq!(back.message(), tx.message());
        assert_eq!(back.signing().required, tx.signing().required);
    }

    // The message inside it, which is what a signing request carries.
    let message = &raw[1 + 64..];
    let tx = parse_message(message).expect("a message");
    let n = tx.to_transaction(&mut out).expect("room");
    let back = parse(&out[..n]).expect("a message rebuilds into a transaction");
    assert_eq!(back.message(), message);
    assert_eq!(back.signing().present, 0);

    // And a versioned message, whose first byte is the version marker rather than the
    // header -- the one shape where "copy the message" and "count the signers" read
    // different bytes.
    let v0 = outscript::solana::new_solana_tx_v0(
        payer,
        SolanaKey([7; 32]),
        Vec::new(),
        &[transfer_instruction(payer, key(2), 7)],
    )
    .expect("builds")
    .to_bytes()
    .expect("serialises");
    let message = &v0[1 + 64..];
    assert_eq!(message[0] & 0x80, 0x80, "the version marker is there");
    let tx = parse_message(message).expect("a versioned message");
    let n = tx.to_transaction(&mut out).expect("room");
    let back = parse(&out[..n]).expect("a versioned message rebuilds too");
    assert_eq!(back.version(), Version::V0);
    assert_eq!(back.message(), message);
}

/// A real USDC send, as a wallet built it: a durable nonce, 0.1 SOL, an associated
/// account created, and an unchecked SPL transfer of 1 USDC. Signed.
#[rustfmt::skip]
const USDC_SEND: &[u8] = &[
        0x01, 0x13, 0x2a, 0xfe, 0x46, 0x25, 0x6c, 0x6e, 0x12, 0x7e, 0xde, 0xbb, 0xbf, 0xdc, 0x6b,
        0x1a, 0x2d, 0x6a, 0x90, 0x49, 0x99, 0x20, 0x74, 0x6f, 0x93, 0xe0, 0xf0, 0x1f, 0xab, 0x2b,
        0x38, 0x46, 0x4d, 0xd7, 0x68, 0x8e, 0xcd, 0xe3, 0x08, 0xad, 0xb2, 0x14, 0x6c, 0x60, 0x26,
        0xf9, 0xee, 0xc0, 0xf8, 0xef, 0xe5, 0x6c, 0x5e, 0x71, 0xef, 0xf6, 0xe6, 0xc3, 0x15, 0x5f,
        0xcf, 0x3f, 0x9d, 0x2e, 0x01, 0x01, 0x00, 0x05, 0x08, 0x28, 0xc5, 0x81, 0xfb, 0xb6, 0xa3,
        0xaa, 0x26, 0x92, 0x91, 0xcf, 0x11, 0x80, 0x1a, 0x00, 0x44, 0xbf, 0x62, 0x01, 0x1a, 0xdc,
        0xa9, 0x69, 0x14, 0xa4, 0xf0, 0xbc, 0x4b, 0x0b, 0x36, 0x09, 0xde, 0x20, 0x15, 0xd0, 0xbe,
        0x5e, 0xc4, 0xda, 0x94, 0x37, 0x04, 0xb5, 0xd5, 0x7b, 0x03, 0x56, 0x05, 0xe6, 0xb5, 0x45,
        0xc7, 0x63, 0xaa, 0x16, 0xec, 0x25, 0x53, 0xae, 0xae, 0xf4, 0x88, 0x91, 0xad, 0x99, 0x65,
        0x55, 0x68, 0xf2, 0xfb, 0x0c, 0x8f, 0xec, 0x38, 0x0b, 0x2f, 0xf7, 0x46, 0x8c, 0xf6, 0x65,
        0xba, 0xd3, 0xd4, 0x10, 0x47, 0x96, 0x15, 0xa6, 0x06, 0x20, 0xf3, 0x29, 0x8a, 0xcd, 0x76,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x8c, 0x97, 0x25, 0x8f, 0x4e, 0x24, 0x89, 0xf1, 0xbb, 0x3d, 0x10, 0x29, 0x14,
        0x8e, 0x0d, 0x83, 0x0b, 0x5a, 0x13, 0x99, 0xda, 0xff, 0x10, 0x84, 0x04, 0x8e, 0x7b, 0xd8,
        0xdb, 0xe9, 0xf8, 0x59, 0xc6, 0xfa, 0x7a, 0xf3, 0xbe, 0xdb, 0xad, 0x3a, 0x3d, 0x65, 0xf3,
        0x6a, 0xab, 0xc9, 0x74, 0x31, 0xb1, 0xbb, 0xe4, 0xc2, 0xd2, 0xf6, 0xe0, 0xe4, 0x7c, 0xa6,
        0x02, 0x03, 0x45, 0x2f, 0x5d, 0x61, 0x06, 0xa7, 0xd5, 0x17, 0x19, 0x2c, 0x56, 0x8e, 0xe0,
        0x8a, 0x84, 0x5f, 0x73, 0xd2, 0x97, 0x88, 0xcf, 0x03, 0x5c, 0x31, 0x45, 0xb2, 0x1a, 0xb3,
        0x44, 0xd8, 0x06, 0x2e, 0xa9, 0x40, 0x00, 0x00, 0x06, 0xdd, 0xf6, 0xe1, 0xd7, 0x65, 0xa1,
        0x93, 0xd9, 0xcb, 0xe1, 0x46, 0xce, 0xeb, 0x79, 0xac, 0x1c, 0xb4, 0x85, 0xed, 0x5f, 0x5b,
        0x37, 0x91, 0x3a, 0x8c, 0xf5, 0x85, 0x7e, 0xff, 0x00, 0xa9, 0x86, 0xde, 0xdd, 0x18, 0x5f,
        0x9d, 0x92, 0x1c, 0x69, 0xe4, 0x87, 0x87, 0x9d, 0x7f, 0xda, 0x50, 0xd7, 0x16, 0xb9, 0xda,
        0xd9, 0x2f, 0xd2, 0x52, 0xb9, 0x50, 0x1b, 0x1c, 0xae, 0x0b, 0x0c, 0x06, 0x04, 0x03, 0x03,
        0x02, 0x06, 0x00, 0x04, 0x04, 0x00, 0x00, 0x00, 0x03, 0x02, 0x00, 0x00, 0x0c, 0x02, 0x00,
        0x00, 0x00, 0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00, 0x04, 0x06, 0x00, 0x01, 0x00,
        0x05, 0x03, 0x07, 0x01, 0x01, 0x07, 0x03, 0x01, 0x01, 0x00, 0x09, 0x03, 0x40, 0x42, 0x0f,
        0x00, 0x00, 0x00, 0x00, 0x00,
];

/// A real USDC send, as a wallet built it and a device read it back.
///
/// Four instructions: a durable nonce, 0.1 SOL, an associated-account create, and an
/// **unchecked** SPL transfer -- which is what wallets actually emit, and which names no
/// mint. The device showed "1000000 raw units" for what a person had just sent as 1
/// USDC, and that is the case this fixture holds down.
///
/// The mint is not taken from the create instruction sitting next to it. It is derived:
/// the source account is the associated token account of the signer for USDC, which is a
/// program-derived address anybody can work out, so the match is arithmetic rather than
/// a claim the transaction made about itself.
#[test]
fn a_real_usdc_send_is_named_without_being_told() {
    const SIGNED: &[u8] = USDC_SEND;

    let tx = parse(SIGNED).expect("a transaction");
    assert_eq!(
        tx.signing(),
        Signing {
            required: 1,
            present: 1
        }
    );
    assert_eq!(tx.instruction_count(), 4);

    // The nonce that let it be signed somewhere else, and the SOL beside it.
    assert!(matches!(tx.action(0), Some(Action::AdvanceNonce { .. })));
    assert!(matches!(
        tx.action(1),
        Some(Action::TransferSol {
            lamports: 100_000_000,
            ..
        })
    ));
    assert!(matches!(
        tx.action(2),
        Some(Action::CreateTokenAccount { .. })
    ));

    match tx.action(3).expect("the transfer") {
        Action::TransferToken {
            amount,
            decimals,
            mint,
            named,
            ..
        } => {
            assert_eq!(amount, 1_000_000);
            // The instruction carried no decimals, and that is still true -- what has
            // been worked out is which mint, and the table says the rest.
            assert_eq!(decimals, None);
            let named = named.expect("the mint was worked out");
            assert_eq!(named.symbol, "USDC");
            assert_eq!(named.decimals, 6);
            let mint = mint.expect("and its address");
            let mut out = [0u8; ADDRESS_MAX];
            assert_eq!(
                address(&mint, &mut out),
                "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
            );
        }
        other => panic!("read as {other:?}"),
    }
}

/// The real USDC send, added up: everything in it comes back, so only the fee is spent.
///
/// Both transfers in that transaction have the same account on each side -- the SOL goes
/// from the signer to the signer, and the USDC from the signer's token account to the
/// signer's token account. Read one instruction at a time it looks like 0.1 SOL and
/// 1 USDC leaving. Added up it is neither: the only thing that actually moves is the
/// five thousand lamports of signature fee.
///
/// This is the case a total exists for, and the one it would be worst to get wrong: a
/// screen that said "-0.1 SOL, -1 USDC" about a transaction that moves nothing would be
/// wrong in the direction that stops somebody signing something harmless -- and the same
/// arithmetic, one sign out, would wave through something that is not.
#[test]
fn a_round_trip_costs_only_the_fee() {
    let tx = parse(USDC_SEND).expect("a transaction");
    let signer = tx.key(0).expect("the fee payer").0;
    let effects = crate::effects::of(&tx, &[signer]);

    // Nothing that moves except the fee.
    let moving: std::vec::Vec<_> = effects.moving().collect();
    assert_eq!(moving.len(), 1, "more than the fee moved: {moving:?}");
    assert_eq!(moving[0].mint, None, "and it is SOL");
    assert_eq!(moving[0].delta, -(LAMPORTS_PER_SIGNATURE as i128));
    assert!(!effects.lost());

    // The USDC is in the totals and nets to nothing, which is a different statement from
    // not being there at all.
    let usdc = effects
        .entries()
        .iter()
        .find(|e| e.mint.is_some())
        .expect("the token was counted");
    assert_eq!(usdc.delta, 0);
    assert_eq!(usdc.named.expect("named").symbol, "USDC");

    // And for somebody else's keys, none of it is theirs -- not even the fee.
    let stranger = crate::effects::of(&tx, &[[9u8; 32]]);
    assert_eq!(stranger.moving().count(), 0);
}

/// One side ours and the other not: that is a real movement, and it is signed.
#[test]
fn a_send_to_somebody_else_is_counted() {
    let payer = key(1);
    let raw = build(
        payer,
        std::vec![transfer_instruction(payer, key(2), 250_000_000)],
    );
    let tx = parse(&raw).expect("a transaction");
    let effects = crate::effects::of(&tx, &[payer.0]);
    let moving: std::vec::Vec<_> = effects.moving().collect();
    assert_eq!(moving.len(), 1);
    assert_eq!(
        moving[0].delta,
        -(250_000_000 + LAMPORTS_PER_SIGNATURE as i128)
    );

    // From the recipient's side it is the amount and no fee: they are not paying it.
    let theirs = crate::effects::of(&tx, &[key(2).0]);
    assert_eq!(theirs.moving().count(), 1);
    assert_eq!(theirs.moving().next().expect("one").delta, 250_000_000);
}

/// A v0 message, written out by hand, whose one transfer sends to an address a lookup
/// table lends.
///
/// Hand-built rather than from outscript's encoder, which folds every account an
/// instruction names into the static keys and so cannot write an instruction that reaches
/// into a table. Two static keys -- the payer and the System program -- then one table
/// lending one writable address and one read-only one. The combined list is therefore
/// `[payer, system, lent-writable, lent-readonly]`, and index 2 is the first lent one.
/// [C] `solana-sdk`, `message/versions/v0`: `MessageAddressTableLookup`, `LoadedAddresses`.
fn v0_message_with_lent_accounts(to: u8, program: u8, lamports: u64) -> Vec<u8> {
    let mut m = std::vec![0x80u8]; // version 0
    m.extend_from_slice(&[1, 0, 1]); // one signer; the program is read-only, unsigned
    m.push(2); // static keys: the payer, the System program
    m.extend_from_slice(&[1u8; 32]);
    m.extend_from_slice(&[0u8; 32]);
    m.extend_from_slice(&[7u8; 32]); // blockhash
    m.push(1); // one instruction
    m.push(program);
    m.extend_from_slice(&[2, 0, to]); // two accounts: from, to
    m.push(12); // Transfer: tag 2, then the lamports
    m.extend_from_slice(&2u32.to_le_bytes());
    m.extend_from_slice(&lamports.to_le_bytes());
    m.push(1); // one lookup table
    m.extend_from_slice(&[8u8; 32]); // the table's address
    m.extend_from_slice(&[1, 5]); // one writable address, row 5 of the table
    m.extend_from_slice(&[1, 9]); // one read-only address, row 9
    m
}

/// An instruction may name an account a lookup table lends, and the device says it
/// cannot see it rather than refusing the message.
///
/// The first version refused every v0 message that used a table, which is most of what
/// a modern wallet builds: the account list an instruction indexes into is the static
/// keys and then the lent addresses, so an index past the static keys is ordinary. What
/// the device cannot do is *show* such an address, and `None` is how it says so.
#[test]
fn an_account_lent_by_a_table_is_unseen_not_refused() {
    let raw = v0_message_with_lent_accounts(2, 1, 40_000);
    let tx = parse_message(&raw).expect("a v0 message using a lookup table");
    assert_eq!(tx.version(), Version::V0);
    assert_eq!(tx.key_count(), 2);
    assert_eq!(tx.lookups(), (1, 2));
    // The lent address is real and unknown, in that order.
    assert_eq!(tx.key(2), None);
    match tx.action(0).expect("the transfer") {
        Action::TransferSol { from, to, lamports } => {
            assert_eq!(from, Some(key(1)));
            assert_eq!(to, None, "an address from a lookup table is not shown");
            assert_eq!(lamports, 40_000);
        }
        other => panic!("read as {other:?}"),
    }

    // The payer loses the lamports and the fee. Nothing is credited to the lent address:
    // the device does not know whose it is, and "unknown" is never "mine".
    let effects = crate::effects::of(&tx, &[[1u8; 32]]);
    let moving: std::vec::Vec<_> = effects.moving().collect();
    assert_eq!(moving.len(), 1);
    assert_eq!(moving[0].delta, -(40_000 + LAMPORTS_PER_SIGNATURE as i128));
    // And for a key that is not the payer, nothing at all -- not even for keys that
    // happen to equal the table's row numbers, which are indices and not addresses.
    assert_eq!(crate::effects::of(&tx, &[[5u8; 32]]).moving().count(), 0);
    assert_eq!(crate::effects::of(&tx, &[[9u8; 32]]).moving().count(), 0);

    // The read-only lent address is reachable too: it is the last of the four.
    assert!(parse_message(&v0_message_with_lent_accounts(3, 1, 1)).is_ok());
}

/// Past the lent addresses is still past the end.
#[test]
fn an_index_beyond_the_lent_accounts_is_refused() {
    // Two static keys and two lent: four accounts, so index 4 names nothing.
    assert_eq!(
        parse_message(&v0_message_with_lent_accounts(4, 1, 1)).err(),
        Some(Error::BadAccountIndex)
    );
}

/// A program cannot be lent by a table, so a program index is held to the static keys.
#[test]
fn a_program_is_never_taken_from_a_table() {
    assert_eq!(
        parse_message(&v0_message_with_lent_accounts(0, 2, 1)).err(),
        Some(Error::BadAccountIndex)
    );
}

/// The checked transfer's bytes: tag 12, the amount, the decimals.
fn transfer_checked(amount: u64, decimals: u8) -> Vec<u8> {
    let mut data = std::vec![12u8];
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    data
}

/// Token-2022 is read with the SPL Token program's layouts, and named as itself.
///
/// The same bytes under the other program id decode to the same action, with the
/// program carried; an instruction this build does not decode is named "Token-2022"
/// rather than left as an address.
#[test]
fn token_2022_is_read_like_the_token_program_and_named_as_itself() {
    let (source, mint, dest, owner) = (key(3), key(5), key(4), key(1));
    let accounts = [source, mint, dest, owner];
    for (program, expected) in [
        (outscript::solana::token_program(), TokenProgram::Spl),
        (token_2022_program(), TokenProgram::Token2022),
    ] {
        let raw = build(
            owner,
            std::vec![instruction(
                program,
                &accounts,
                transfer_checked(250_000, 6)
            )],
        );
        let tx = parse(&raw).expect("a transaction");
        match tx.action(0).expect("an action") {
            Action::TransferToken {
                program,
                from,
                to,
                owner: o,
                amount,
                decimals,
                mint: m,
                ..
            } => {
                assert_eq!(program, expected);
                assert_eq!((from, to, o), (Some(source), Some(dest), Some(owner)));
                assert_eq!((amount, decimals, m), (250_000, Some(6), Some(mint)));
            }
            other => panic!("read as {other:?}"),
        }
    }

    // MintTo, tag 7: not decoded, and said to be Token-2022's.
    let mut mint_to = std::vec![7u8];
    mint_to.extend_from_slice(&1u64.to_le_bytes());
    let raw = build(
        owner,
        std::vec![instruction(
            token_2022_program(),
            &[mint, dest, owner],
            mint_to
        )],
    );
    match parse(&raw).expect("a transaction").action(0) {
        Some(Action::Unknown { named, tag, .. }) => {
            assert_eq!(named, Some("Token-2022"));
            assert_eq!(tag, Some(7));
        }
        other => panic!("read as {other:?}"),
    }
}

/// An associated account is derived with its token program in the seeds, so the same
/// owner and mint have a different account under Token-2022 -- and a transfer into it
/// is credited only when derived with the right program.
#[test]
fn a_token_2022_account_is_attributed_with_its_own_derivation() {
    let owner = key(1);
    let usdc = SolanaKey(crate::literal::mint(
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    ));
    let spl = associated_account(owner, TokenProgram::Spl, usdc).expect("derives");
    let t22 = associated_account(owner, TokenProgram::Token2022, usdc).expect("derives");
    assert_ne!(spl, t22);
    // The SPL derivation is the one outscript already does.
    assert_eq!(
        Some(spl),
        outscript::solana::associated_token_address(owner, usdc).ok()
    );

    // A stranger sends us 2.5 "USDC" through Token-2022: our Token-2022 account gains
    // it, and nothing lands on the SPL account of the same name.
    let stranger = key(9);
    let from = key(3);
    let raw = build(
        stranger,
        std::vec![instruction(
            token_2022_program(),
            &[from, usdc, t22, stranger],
            transfer_checked(2_500_000, 6)
        )],
    );
    let tx = parse(&raw).expect("a transaction");
    let effects = crate::effects::of(&tx, &[owner.0]);
    let moving: std::vec::Vec<_> = effects.moving().collect();
    assert_eq!(moving.len(), 1);
    assert_eq!(moving[0].mint, Some(usdc));
    assert_eq!(moving[0].delta, 2_500_000);

    // The same transfer aimed at our *SPL* account, but through Token-2022, is aimed
    // at an address that program would never have made for us: not ours.
    let raw = build(
        stranger,
        std::vec![instruction(
            token_2022_program(),
            &[from, usdc, spl, stranger],
            transfer_checked(2_500_000, 6)
        )],
    );
    let tx = parse(&raw).expect("a transaction");
    assert_eq!(crate::effects::of(&tx, &[owner.0]).moving().count(), 0);
}
