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
