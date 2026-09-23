//! What a transaction reader has to get right, written as the ways it could be wrong.
//!
//! The anchor is the worked example in **EIP-155 itself**: the exact bytes signed over,
//! whose fields this crate then has to read back as the ones that example describes. Its
//! Keccak is checked against an implementation sharing no code with this one.
//!
//! The rest of the fixtures are encoded by the little RLP writer below rather than by
//! the crate under test, so a transaction built for a test is not built by the thing it
//! is testing.

extern crate alloc;
extern crate std;

use alloc::vec::Vec;

use super::*;

/// Hex to bytes, for vectors that are quoted as hex in their standards.
fn hex(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

/// EIP-155's own example: nonce 9, 20 gwei, 21000 gas, 1 ETH to 0x3535…35, chain 1.
const EIP155_SIGNING: &str =
    "0xec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080";
/// Keccak-256 of those bytes.
///
/// Checked against an implementation that shares no code with this one -- a throwaway
/// Keccak written from the spec in Python, itself checked against the published digests
/// of the empty string and `"abc"`. The signing *payload* above is EIP-155's own worked
/// example, and the fields this crate reads out of it are the ones that example
/// describes, so the two halves pin each other.
const EIP155_HASH: &str = "0xdaf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53";

#[test]
fn the_eip155_example_parses_to_the_fields_it_describes() {
    let bytes = hex(EIP155_SIGNING);
    let tx = parse(&bytes).expect("a transaction");

    assert_eq!(tx.kind, Kind::Legacy);
    assert_eq!(tx.nonce, 9);
    assert_eq!(tx.gas_limit, 21_000);
    assert_eq!(tx.to, Some([0x35; 20]));
    assert_eq!(tx.chain_id, Some(1), "the chain id sits where `v` goes");
    assert!(!tx.signed(), "the signing form is not signed");
    assert!(tx.data.is_empty());
    assert_eq!(tx.selector(), None, "no calldata is no method");

    // 20 gwei, and 1 ETH, as 256-bit values.
    let mut gas_price = [0u8; 32];
    gas_price[27..].copy_from_slice(&20_000_000_000u64.to_be_bytes()[3..]);
    assert_eq!(tx.max_fee, gas_price);
    let mut one_eth = [0u8; 32];
    one_eth[24..].copy_from_slice(&1_000_000_000_000_000_000u64.to_be_bytes());
    assert_eq!(tx.value, one_eth);
}

/// The hash the signature is made over is Keccak-256 of the transaction as it arrived.
///
/// This is the whole crate in one assertion: the bytes are read as a transaction, handed
/// back as the bytes to sign, and hashed.
#[test]
fn the_signing_hash_is_keccak_of_exactly_what_arrived() {
    let bytes = hex(EIP155_SIGNING);
    let tx = parse(&bytes).expect("a transaction");
    let mut scratch = [0u8; 256];
    let got = tx
        .signing_hash(&mut scratch)
        .expect("unsigned, so hashable");
    assert_eq!(&got[..], &hex(EIP155_HASH)[..]);
}

/// A signed legacy transaction reports its signature, and the chain id folded into `v`.
#[test]
fn a_signed_legacy_transaction_gives_up_its_chain_and_signature() {
    // The same transaction, signed for chain 1: `v` is 37 or 38 under EIP-155.
    let items: Vec<Vec<u8>> = std::vec![
        hex("09"),
        hex("04a817c800"),
        hex("5208"),
        hex("3535353535353535353535353535353535353535"),
        hex("0de0b6b3a7640000"),
        Vec::new(),
        hex("25"), // v = 37 = 1 * 2 + 35
        hex("28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276"),
        hex("67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"),
    ];
    let refs: Vec<&[u8]> = items.iter().map(|v| v.as_slice()).collect();
    let mut out = [0u8; 256];
    let encoded = rlp::list_of(&refs, &mut out).expect("room");

    let tx = parse(encoded).expect("a transaction");
    assert!(tx.signed());
    assert_eq!(tx.chain_id, Some(1), "37 means chain 1");
    let sig = tx.signature.expect("a signature");
    assert_eq!(sig.v, 37);
    assert_eq!(&sig.r[..], &items[7][..]);

    // And it refuses to hand back signing bytes: those would be a different object.
    let mut scratch = [0u8; 256];
    assert!(tx.signing_hash(&mut scratch).is_err());
}

/// A transaction with no chain id at all is reported as such.
///
/// Pre-EIP-155 replay protection is the absence of a chain, which makes the signature
/// valid on every chain at once. A screen that cannot say so cannot warn about it.
#[test]
fn a_transaction_that_names_no_chain_says_so() {
    let items: Vec<Vec<u8>> = std::vec![
        hex("01"),
        hex("04a817c800"),
        hex("5208"),
        hex("3535353535353535353535353535353535353535"),
        hex("0de0b6b3a7640000"),
        Vec::new(),
    ];
    let refs: Vec<&[u8]> = items.iter().map(|v| v.as_slice()).collect();
    let mut out = [0u8; 256];
    let encoded = rlp::list_of(&refs, &mut out).expect("room");
    let tx = parse(encoded).expect("a transaction");
    assert_eq!(tx.chain_id, None);
    assert!(!tx.signed());
}

/// RLP for one byte string, written here so the fixtures do not lean on the code under
/// test for their own encoding.
fn rlp_string(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if b.len() == 1 && b[0] < 0x80 {
        out.extend_from_slice(b);
        return out;
    }
    if b.len() < 56 {
        out.push(0x80 + b.len() as u8);
    } else {
        let n = b.len();
        let bytes: Vec<u8> = n
            .to_be_bytes()
            .iter()
            .copied()
            .skip_while(|&c| c == 0)
            .collect();
        out.push(0xb7 + bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(b);
    out
}

/// RLP for a list whose payload is already encoded.
fn rlp_list(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if payload.len() < 56 {
        out.push(0xc0 + payload.len() as u8);
    } else {
        let n = payload.len();
        let bytes: Vec<u8> = n
            .to_be_bytes()
            .iter()
            .copied()
            .skip_while(|&c| c == 0)
            .collect();
        out.push(0xf7 + bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(payload);
    out
}

/// Build a type-2 (fee market) transaction on Polygon, unsigned.
fn fee_market(data: &[u8], to: Option<[u8; 20]>, access: usize) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    for field in [
        hex("89"),         // chain id 137
        hex("2a"),         // nonce 42
        hex("3b9aca00"),   // tip 1 gwei
        hex("0ba43b7400"), // cap 50 gwei
        hex("01d4c0"),     // gas 120000
        to.map(|t| t.to_vec()).unwrap_or_default(),
        hex("0de0b6b3a7640000"), // 1 ether
        data.to_vec(),
    ] {
        body.extend_from_slice(&rlp_string(&field));
    }
    // The access list: `access` entries of (address, no storage keys).
    let mut entries: Vec<u8> = Vec::new();
    for _ in 0..access {
        let mut one: Vec<u8> = Vec::new();
        one.extend_from_slice(&rlp_string(&[0x11; 20]));
        one.extend_from_slice(&rlp_list(&[]));
        entries.extend_from_slice(&rlp_list(&one));
    }
    body.extend_from_slice(&rlp_list(&entries));

    let mut out: Vec<u8> = std::vec![0x02];
    out.extend_from_slice(&rlp_list(&body));
    out
}

#[test]
fn a_fee_market_transaction_reports_its_chain_tip_and_cap() {
    let to = [0xAB; 20];
    let raw = fee_market(&[], Some(to), 0);
    let tx = parse(&raw).expect("a transaction");
    assert_eq!(tx.kind, Kind::FeeMarket);
    assert_eq!(tx.chain_id, Some(137), "Polygon");
    assert_eq!(tx.nonce, 42);
    assert_eq!(tx.gas_limit, 120_000);
    assert_eq!(tx.to, Some(to));
    assert!(tx.max_priority_fee.is_some(), "a tip is part of this form");
    assert!(!tx.signed());
}

#[test]
fn the_access_list_is_counted_not_ignored() {
    let raw = fee_market(&[], Some([0xAB; 20]), 3);
    let tx = parse(&raw).expect("a transaction");
    assert_eq!(tx.access_list_len, 3);
}

/// Calldata's first four bytes are the selector, and shorter calldata has none.
#[test]
fn calldata_gives_up_its_selector() {
    let mut data = hex("a9059cbb");
    data.extend_from_slice(&[0u8; 64]);
    let raw = fee_market(&data, Some([0xAB; 20]), 0);
    let tx = parse(&raw).expect("a transaction");
    assert_eq!(tx.selector(), Some([0xa9, 0x05, 0x9c, 0xbb]), "transfer");
    assert_eq!(tx.data.len(), 68);

    let raw = fee_market(&[1, 2, 3], Some([0xAB; 20]), 0);
    let tx = parse(&raw).expect("a transaction");
    assert_eq!(tx.selector(), None, "three bytes select nothing");
}

/// A contract creation has no destination, and says so rather than showing zeros.
#[test]
fn a_contract_creation_has_no_destination() {
    let raw = fee_market(&hex("60806040"), None, 0);
    let tx = parse(&raw).expect("a transaction");
    assert_eq!(tx.to, None);
    assert!(tx.creates_contract());
}

/// A type byte this firmware does not know is refused by number.
#[test]
fn an_unknown_transaction_type_is_refused_by_number() {
    let mut raw = fee_market(&[], Some([0xAB; 20]), 0);
    raw[0] = 0x7f;
    assert_eq!(parse(&raw), Err(Error::UnknownType(0x7f)));
}

/// The worst case fee is gas times the cap, and it saturates rather than wrapping.
#[test]
fn the_fee_shown_is_the_worst_case_and_never_wraps() {
    let bytes = hex(EIP155_SIGNING);
    let tx = parse(&bytes).expect("a transaction");
    // 21000 * 20 gwei = 420 microether = 420_000_000_000_000 wei.
    let mut want = [0u8; 32];
    want[24..].copy_from_slice(&420_000_000_000_000u64.to_be_bytes());
    assert_eq!(tx.max_fee_wei(), want);

    // A cap of 2^256-1 with any gas at all cannot be represented, so it pins at the top
    // rather than coming out small.
    let mut huge = tx;
    huge.max_fee = [0xFF; 32];
    huge.gas_limit = 2;
    assert_eq!(huge.max_fee_wei(), [0xFF; 32]);
}

/// RLP that is not in its one canonical form is refused.
///
/// Two encodings of one value is two transactions with one meaning, and the one that
/// gets signed is whichever the parser preferred. Both are refused instead.
#[test]
fn non_canonical_rlp_is_refused() {
    // A single byte below 0x80 written as a one-byte string.
    assert_eq!(rlp::item(&[0x81, 0x7f]), Err(rlp::Error::NotCanonical));
    // A long form used for a short payload.
    assert_eq!(
        rlp::item(&[0xb8, 0x02, 0x61, 0x62]),
        Err(rlp::Error::NotCanonical)
    );
    // A length with a leading zero.
    assert_eq!(
        rlp::item(&[0xb9, 0x00, 0x40]),
        Err(rlp::Error::NotCanonical)
    );
    // An integer with a leading zero.
    let mut out = [0u8; 16];
    let encoded = rlp::list_of(&[&[0x00, 0x01][..]], &mut out).expect("room");
    let mut l = rlp::List::open(encoded).expect("a list");
    assert_eq!(l.uint(), Err(rlp::Error::NotCanonical));
}

/// Truncation is truncation, not a short transaction.
#[test]
fn a_truncated_transaction_is_refused() {
    let bytes = hex(EIP155_SIGNING);
    for cut in 1..bytes.len() {
        assert!(
            parse(&bytes[..cut]).is_err(),
            "{cut} bytes of a transaction parsed as one"
        );
    }
}

/// What this crate writes, it reads back.
#[test]
fn the_writer_and_the_reader_agree() {
    let items: Vec<Vec<u8>> = std::vec![
        Vec::new(),
        std::vec![0x7f],
        std::vec![0x80],
        std::vec![0xff; 55],
        std::vec![0xaa; 56],
        std::vec![0x11; 1024],
    ];
    let refs: Vec<&[u8]> = items.iter().map(|v| v.as_slice()).collect();
    let mut out = [0u8; 2048];
    let encoded = rlp::list_of(&refs, &mut out).expect("room");
    let mut l = rlp::List::open(encoded).expect("a list");
    for want in &items {
        assert_eq!(l.bytes().expect("an item"), &want[..]);
    }
    assert!(l.done());
}

mod what_it_does {
    use super::*;
    use crate::summary::{self, Action};

    /// Polygon's USDC, from the baked table -- six decimals.
    const USDC_POLYGON: [u8; 20] = [
        0x3C, 0x49, 0x9C, 0x54, 0x2C, 0xEF, 0x5E, 0x38, 0x11, 0xE1, 0x19, 0x2C, 0xE7, 0x0D, 0x8C,
        0xC0, 0x3D, 0x5C, 0x33, 0x59,
    ];

    /// Calldata for a one-argument-address, one-argument-uint call.
    fn call2(selector: [u8; 4], addr: [u8; 20], amount: u64) -> Vec<u8> {
        let mut out = selector.to_vec();
        out.extend_from_slice(&[0u8; 12]);
        out.extend_from_slice(&addr);
        out.extend_from_slice(&[0u8; 24]);
        out.extend_from_slice(&amount.to_be_bytes());
        out
    }

    #[test]
    fn a_plain_send_is_a_send() {
        let bytes = hex(EIP155_SIGNING);
        let tx = parse(&bytes).expect("a transaction");
        match summary::summarise(&tx) {
            Action::Send { to, wei } => {
                assert_eq!(to, [0x35; 20]);
                let mut out = [0u8; summary::DECIMAL_MAX];
                assert_eq!(summary::decimal(&wei, 18, &mut out), "1");
            }
            other => panic!("a transfer of ether read as {other:?}"),
        }
    }

    /// A token transfer is named, with its decimals applied.
    ///
    /// This is the sentence the whole crate exists for: 12,500,000 units of
    /// `0x3c49…3359` on chain 137 is "12.5 USDC", and saying the first is not an
    /// answer to the question somebody is asking before they sign.
    #[test]
    fn a_token_transfer_is_named_and_scaled() {
        let to = [0x77; 20];
        let raw = fee_market(
            &call2(summary::TRANSFER, to, 12_500_000),
            Some(USDC_POLYGON),
            0,
        );
        let tx = parse(&raw).expect("a transaction");
        assert_eq!(tx.chain_id, Some(137));
        match summary::summarise(&tx) {
            Action::TokenSend { to: dest, amount } => {
                assert_eq!(dest, to);
                assert_eq!(amount.contract, USDC_POLYGON);
                let token = amount.token.expect("the table knows this one");
                assert_eq!(token.symbol, "USDC");
                assert_eq!(token.decimals, 6);
                let mut out = [0u8; summary::DECIMAL_MAX];
                assert_eq!(
                    summary::decimal(&amount.raw, token.decimals, &mut out),
                    "12.5"
                );
                assert!(!amount.unlimited());
            }
            other => panic!("a token transfer read as {other:?}"),
        }
    }

    /// The same contract on a chain the table does not cover stays unnamed.
    ///
    /// Not a failure -- the right answer. A label from the wrong chain would be a
    /// familiar name on a stranger's contract.
    #[test]
    fn a_token_on_another_chain_is_not_borrowed() {
        let mut raw = fee_market(
            &call2(summary::TRANSFER, [0x77; 20], 1),
            Some(USDC_POLYGON),
            0,
        );
        // Chain 137 -> 138, one byte, everything else identical.
        let at = raw.iter().position(|&b| b == 0x89).expect("the chain id");
        raw[at] = 0x8a;
        let tx = parse(&raw).expect("a transaction");
        assert_eq!(tx.chain_id, Some(138));
        match summary::summarise(&tx) {
            Action::TokenSend { amount, .. } => assert!(
                amount.token.is_none(),
                "a chain-137 label was applied to chain 138"
            ),
            other => panic!("read as {other:?}"),
        }
    }

    /// An unlimited approval is called what it is.
    #[test]
    fn an_unlimited_approval_says_so() {
        let mut data = summary::APPROVE.to_vec();
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(&[0x99; 20]);
        data.extend_from_slice(&[0xFF; 32]);
        let raw = fee_market(&data, Some(USDC_POLYGON), 0);
        let tx = parse(&raw).expect("a transaction");
        match summary::summarise(&tx) {
            Action::Approve { spender, amount } => {
                assert_eq!(spender, [0x99; 20]);
                assert!(amount.unlimited(), "2^256-1 is the infinite allowance");
            }
            other => panic!("an approval read as {other:?}"),
        }
    }

    /// A selector the table knows is named; one it does not is shown as a selector.
    #[test]
    fn calldata_is_named_where_it_can_be_and_never_guessed() {
        // `setApprovalForAll(address,bool)` -- named by the table rather than decoded
        // here, and in the small table as well as the big one, because handing an
        // operator every token in a collection is one of the two ways a wallet is
        // emptied by a signature its owner read as harmless.
        //
        // A build with no table at all names nothing, and the assertion below says so
        // rather than being switched off: "this build cannot name it" is a behaviour
        // worth pinning, not an absence of one.
        let mut data = hex("a22cb465");
        data.extend_from_slice(&[0u8; 64]);
        let raw = fee_market(&data, Some([0xAB; 20]), 0);
        let tx = parse(&raw).expect("a transaction");
        match summary::summarise(&tx) {
            #[cfg(any(feature = "common-signatures", feature = "full-signatures"))]
            Action::Call { method, .. } => assert!(
                method.starts_with("setApprovalForAll("),
                "expected setApprovalForAll, got {method}"
            ),
            #[cfg(not(any(feature = "common-signatures", feature = "full-signatures")))]
            Action::UnknownCall { selector, .. } => {
                assert_eq!(selector, [0xa2, 0x2c, 0xb4, 0x65]);
            }
            other => panic!("a known selector read as {other:?}"),
        }

        // A selector nothing knows stays a selector.
        let mut data = hex("deadbe01");
        data.extend_from_slice(&[0u8; 32]);
        let raw = fee_market(&data, Some([0xAB; 20]), 0);
        let tx = parse(&raw).expect("a transaction");
        match summary::summarise(&tx) {
            Action::UnknownCall {
                selector, data_len, ..
            } => {
                assert_eq!(selector, [0xde, 0xad, 0xbe, 0x01]);
                assert_eq!(data_len, 36);
            }
            other => panic!("an unknown selector read as {other:?}"),
        }
    }

    /// Calldata too short for the arguments it claims is not read as those arguments.
    #[test]
    fn a_truncated_transfer_is_not_read_as_a_transfer() {
        let mut data = summary::TRANSFER.to_vec();
        data.extend_from_slice(&[0u8; 40]); // one word and a bit, not two
        let raw = fee_market(&data, Some(USDC_POLYGON), 0);
        let tx = parse(&raw).expect("a transaction");
        assert!(
            !matches!(summary::summarise(&tx), Action::TokenSend { .. }),
            "half a transfer was read as a transfer"
        );
    }

    /// The decimal formatter, at the sizes money actually comes in.
    #[test]
    fn amounts_read_the_way_people_write_them() {
        let cases: [(u128, u8, &str); 8] = [
            (0, 18, "0"),
            (1, 18, "0.000000000000000001"),
            (1_000_000_000_000_000_000, 18, "1"),
            (1_500_000_000_000_000_000, 18, "1.5"),
            (12_500_000, 6, "12.5"),
            (1, 6, "0.000001"),
            (1_000_000, 6, "1"),
            (123_456_789, 0, "123456789"),
        ];
        for (v, decimals, want) in cases {
            let mut raw = [0u8; 32];
            raw[16..].copy_from_slice(&v.to_be_bytes());
            let mut out = [0u8; summary::DECIMAL_MAX];
            assert_eq!(
                summary::decimal(&raw, decimals, &mut out),
                want,
                "{v} at {decimals}"
            );
        }

        // The largest value there is, at 18 decimals: 78 digits, and it must not be cut.
        let mut out = [0u8; summary::DECIMAL_MAX];
        let text = summary::decimal(&[0xFF; 32], 18, &mut out);
        assert!(text.starts_with("115792089237316195423570985008687907853269984665640564039457"));
        assert!(text.contains('.'));
    }
}

mod the_token_table {
    use crate::tokens;

    /// Mainnet is in the table, and its entries carry the decimals they are quoted with.
    ///
    /// The address here is copied from the generated table, which the generator copied
    /// from the source list -- it is not written from memory anywhere along that path,
    /// which is the property the whole table depends on.
    #[test]
    fn a_mainnet_token_resolves() {
        let usdc = [
            0xA0, 0xB8, 0x69, 0x91, 0xC6, 0x21, 0x8B, 0x36, 0xC1, 0xD1, 0x9D, 0x4A, 0x2E, 0x9E,
            0xB0, 0xCE, 0x36, 0x06, 0xEB, 0x48,
        ];
        let token = tokens::lookup(1, &usdc).expect("mainnet USDC is in the table");
        assert_eq!(token.symbol, "USDC");
        assert_eq!(token.decimals, 6);
        assert!(tokens::knows_chain(1));
    }

    /// The same address on a chain the table does not carry resolves to nothing.
    #[test]
    fn an_address_is_only_named_on_the_chain_it_was_listed_for() {
        let usdc = [
            0xA0, 0xB8, 0x69, 0x91, 0xC6, 0x21, 0x8B, 0x36, 0xC1, 0xD1, 0x9D, 0x4A, 0x2E, 0x9E,
            0xB0, 0xCE, 0x36, 0x06, 0xEB, 0x48,
        ];
        // `u64::MAX` rather than some plausible number: this test used 999 until 999
        // turned out to be HyperEVM, and what it means to check is a chain the table
        // cannot ever carry -- not one it happens not to carry today.
        assert!(
            tokens::lookup(u64::MAX, &usdc).is_none(),
            "mainnet's USDC was named on a chain that does not exist"
        );
        assert!(!tokens::knows_chain(u64::MAX));
    }

    /// An address nothing listed is not named, on any chain.
    #[test]
    fn an_unlisted_address_is_never_named() {
        for chain in [1, 10, 56, 137, 999, 5000, 8453, 9745, 42161, 59144] {
            assert!(tokens::lookup(chain, &[0x42; 20]).is_none());
        }
    }
}

/// EIP-155's own worked example, from the unsigned bytes to the signed ones.
///
/// The one vector everything on this path can be checked against at once: the signing
/// hash, the deterministic signature, the `v` that folds in the chain id, and the RLP of
/// the result. All four are published, so agreeing with them is agreement with Ethereum
/// rather than with ourselves.
///
/// Source: EIP-155, §Example. [C]
#[test]
fn the_published_eip155_example_signs_byte_for_byte() {
    use outscript::crypto::secp256k1::SecpPrivateKey;

    const UNSIGNED: &str = "ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080";
    const HASH: &str = "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53";
    const SIGNED: &str = "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";

    let unsigned = hex(UNSIGNED);
    let tx = parse(&unsigned).expect("a transaction");
    assert_eq!(tx.chain_id, Some(1));
    assert_eq!(tx.nonce, 9);
    assert!(!tx.signed());

    let mut scratch = std::vec![0u8; unsigned.len() + 1];
    let hash = tx.signing_hash(&mut scratch).expect("a hash");
    assert_eq!(hash.to_vec(), hex(HASH));

    let key = SecpPrivateKey::from_bytes(&[0x46; 32]).expect("a key");
    let (r, s, recid) = key.sign_recoverable(&hash);

    let mut out = std::vec![0u8; unsigned.len() + crate::sign::OVERHEAD];
    let n = crate::sign::encode_signed(&tx, &r, &s, recid, &mut out).expect("room");
    assert_eq!(out[..n].to_vec(), hex(SIGNED));

    // And the result reads back as the same transaction, now carrying `v = 37`.
    let back = parse(&out[..n]).expect("still a transaction");
    assert_eq!(back.chain_id, Some(1));
    assert_eq!(back.to, tx.to);
    assert_eq!(back.value, tx.value);
    assert_eq!(back.signature.expect("signed").v, 37);
}

/// A typed transaction keeps the fields this build never decoded.
///
/// The access list is counted and not read, so signing one is where "rebuild it from
/// what I understood" would quietly drop it -- and the signature would then be over a
/// transaction nobody was shown. Signing appends rather than rebuilds, so what comes out
/// holds what went in.
#[test]
fn signing_a_typed_transaction_keeps_its_access_list() {
    use outscript::crypto::secp256k1::SecpPrivateKey;

    /// One byte string, encoded.
    fn string(b: &[u8]) -> Vec<u8> {
        let mut buf = std::vec![0u8; b.len() + 16];
        let list = crate::rlp::list_of(&[b], &mut buf).expect("room");
        crate::rlp::item(list).expect("a list").payload.to_vec()
    }
    /// A list of already-encoded items.
    fn list(items: &[Vec<u8>]) -> Vec<u8> {
        let mut payload = Vec::new();
        for i in items {
            payload.extend_from_slice(i);
        }
        let mut buf = std::vec![0u8; payload.len() + 16];
        crate::rlp::list_from(&payload, &[], &mut buf)
            .expect("room")
            .to_vec()
    }

    // One access-list entry: a contract and one storage key. [C] EIP-2930
    let keys = list(&[string(&[0x22u8; 32])]);
    let entry = list(&[string(&[0x11u8; 20]), keys]);
    let access = list(&[entry]);

    // chainId, nonce, maxPriority, maxFee, gas, to, value, data, accessList.
    let fields = [
        string(&[0x01]),
        string(&[0x02]),
        string(&[0x03]),
        string(&[0x04]),
        string(&[0x52, 0x08]),
        string(&[0x33u8; 20]),
        string(&[0x05]),
        string(&[]),
        access,
    ];
    let mut body = std::vec![0x02u8];
    body.extend_from_slice(&list(&fields));

    let tx = parse(&body).expect("a 1559 transaction");
    assert_eq!(tx.access_list_len, 1);
    assert!(!tx.signed());

    let mut scratch = std::vec![0u8; body.len() + 1];
    let hash = tx.signing_hash(&mut scratch).expect("a hash");
    let key = SecpPrivateKey::from_bytes(&[0x46; 32]).expect("a key");
    let (r, s, recid) = key.sign_recoverable(&hash);
    let mut out = std::vec![0u8; body.len() + crate::sign::OVERHEAD];
    let n = crate::sign::encode_signed(&tx, &r, &s, recid, &mut out).expect("room");

    let back = parse(&out[..n]).expect("still a transaction");
    assert_eq!(back.access_list_len, 1, "the access list survived");
    assert_eq!(back.chain_id, Some(1));
    assert_eq!(back.to, tx.to);
    assert_eq!(back.signature.expect("signed").r, r);
    assert_eq!(&out[..1], &[0x02], "still type 2");
    // yParity is 0 or 1 on a typed transaction, never 27 or a folded chain id.
    assert!(back.signature.expect("signed").v <= 1);
}
