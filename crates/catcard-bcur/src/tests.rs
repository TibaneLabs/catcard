//! What a UR part must be, and what it must not be mistaken for.

use super::*;

extern crate alloc;
extern crate std;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// The four-letter words, needed only to encode in the tests.
const WORDS: &str = include_str!("words.txt");

fn pairs() -> Vec<[u8; 2]> {
    WORDS
        .split_whitespace()
        .map(|w| {
            let b = w.as_bytes();
            [b[0], b[3]]
        })
        .collect()
}

fn encode_bytewords(data: &[u8]) -> String {
    let p = pairs();
    let mut s = String::new();
    let full: Vec<u8> = data
        .iter()
        .copied()
        .chain(bytewords::crc32(data).to_be_bytes())
        .collect();
    for b in full {
        s.push(p[b as usize][0] as char);
        s.push(p[b as usize][1] as char);
    }
    s
}

/// CBOR: an unsigned integer, in the shortest form that holds it.
fn cbor_uint(n: u64, out: &mut Vec<u8>) {
    match n {
        0..=23 => out.push(n as u8),
        24..=0xFF => out.extend_from_slice(&[24, n as u8]),
        0x100..=0xFFFF => {
            out.push(25);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        0x1_0000..=0xFFFF_FFFF => {
            out.push(26);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
        _ => {
            out.push(27);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
}

fn cbor_bytes(data: &[u8], out: &mut Vec<u8>) {
    let n = data.len() as u64;
    match n {
        0..=23 => out.push(0x40 | n as u8),
        24..=0xFF => out.extend_from_slice(&[0x58, n as u8]),
        _ => {
            out.push(0x59);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
    }
    out.extend_from_slice(data);
}

/// One part of `message`, as a conforming encoder writes it.
fn part_line(message: &[u8], seq_len: u32, seq_num: u32) -> Vec<u8> {
    let fragment = message.len().div_ceil(seq_len as usize);
    let at = (seq_num - 1) as usize * fragment;
    // Every fragment is the same length; the last is padded with zeroes.
    let mut data = vec![0u8; fragment];
    let end = (at + fragment).min(message.len());
    if at < message.len() {
        data[..end - at].copy_from_slice(&message[at..end]);
    }

    let mut cbor = vec![0x85]; // array of five
    cbor_uint(seq_num as u64, &mut cbor);
    cbor_uint(seq_len as u64, &mut cbor);
    cbor_uint(message.len() as u64, &mut cbor);
    cbor_uint(bytewords::crc32(message) as u64, &mut cbor);
    cbor_bytes(&data, &mut cbor);

    format!(
        "ur:crypto-psbt/{seq_num}-{seq_len}/{}",
        encode_bytewords(&cbor)
    )
    .into_bytes()
}

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + i / 251) as u8).collect()
}

/// The spec's own vector, which is what says the word list is the right word list.
#[test]
fn the_spec_test_vector() {
    let data = [
        0xc7, 0x09, 0x85, 0x80, 0x12, 0x5e, 0x2a, 0xb0, 0x98, 0x12, 0x53, 0x46, 0x8b, 0x2d, 0xbc,
        0x52,
    ];
    assert_eq!(bytewords::crc32(&data), 0xfeac_0dea);
    let encoded = encode_bytewords(&data);
    assert_eq!(encoded, "staslplabghydrpfmkbggufgludprfgmzepsbtwd");

    let mut out = [0u8; 16];
    let n = bytewords::decode(encoded.as_bytes(), &mut out).unwrap();
    assert_eq!((&out[..n], n), (&data[..], 16));
}

/// Every one of the 256 bytes survives the round trip.
///
/// The test that was missing. The lookup table marked "no such word" with `0xFF`,
/// which is also the index of `zoom`, so the byte `0xFF` decoded as not-a-word -- and
/// the spec's own test vector happens to contain no `0xFF`, so it passed. A payload
/// that did contain one failed, which is to say almost every real payload.
#[test]
fn every_byte_survives() {
    let all: Vec<u8> = (0..=255u8).collect();
    let encoded = encode_bytewords(&all);
    assert_eq!(encoded.len(), (256 + 4) * 2);
    let mut out = vec![0u8; 256];
    let n = bytewords::decode(encoded.as_bytes(), &mut out).expect("all 256");
    assert_eq!(n, 256);
    assert_eq!(out, all);
}

/// And each byte on its own, so a failure names the byte rather than the payload.
#[test]
fn each_byte_on_its_own() {
    for b in 0..=255u8 {
        let encoded = encode_bytewords(&[b]);
        let mut out = [0u8; 1];
        let n = bytewords::decode(encoded.as_bytes(), &mut out)
            .unwrap_or_else(|e| panic!("byte {b} encodes to {encoded} and fails: {e:?}"));
        assert_eq!((n, out[0]), (1, b), "byte {b}");
    }
}

#[test]
fn a_damaged_sequence_fails_its_checksum() {
    let data = payload(32);
    let mut encoded = encode_bytewords(&data).into_bytes();
    // Change one character to another valid word: the decode succeeds, the CRC does not.
    let last = encoded.len() - 10;
    encoded[last] = if encoded[last] == b'a' { b'b' } else { b'a' };
    let mut out = [0u8; 64];
    match bytewords::decode(&encoded, &mut out) {
        Err(bytewords::Error::Checksum { .. }) | Err(bytewords::Error::NotAWord) => {}
        other => panic!("a changed character must not pass: {other:?}"),
    }
}

#[test]
fn what_is_not_bytewords() {
    let mut out = [0u8; 64];
    assert_eq!(
        bytewords::decode(b"abc", &mut out),
        Err(bytewords::Error::Length)
    );
    assert_eq!(
        bytewords::decode(b"", &mut out),
        Err(bytewords::Error::Length)
    );
    // 'q' begins no word; upper case is not the minimal alphabet.
    assert_eq!(
        bytewords::decode(b"qqaeadaoaxaaahamat", &mut out),
        Err(bytewords::Error::NotAWord)
    );
    assert_eq!(
        bytewords::decode(b"AEADAOAXAAAHAMAT", &mut out),
        Err(bytewords::Error::NotAWord)
    );
}

#[test]
fn a_message_in_order_reassembles() {
    let message = payload(1000);
    let n = 5u32;
    let mut out = vec![0u8; message.len()];
    let mut scratch = vec![0u8; 512];
    let mut c = Collector::new();

    for i in 1..=n {
        let line = part_line(&message, n, i);
        let p = c.accept(&line, &mut scratch).expect("a part");
        out[p.offset..p.offset + p.len].copy_from_slice(&scratch[p.at.start..p.at.start + p.len]);
        c.confirm(p);
    }
    assert!(c.complete());
    assert!(c.verify(&out));
    assert_eq!(out, message);
}

/// And in any order, which is the point of an animation that loops.
#[test]
fn a_message_out_of_order_reassembles() {
    let message = payload(1000);
    let n = 5u32;
    let mut out = vec![0u8; message.len()];
    let mut scratch = vec![0u8; 512];
    let mut c = Collector::new();

    for i in [4u32, 1, 5, 2, 3] {
        let line = part_line(&message, n, i);
        let p = c.accept(&line, &mut scratch).expect("a part");
        out[p.offset..p.offset + p.len].copy_from_slice(&scratch[p.at.start..p.at.start + p.len]);
        c.confirm(p);
    }
    assert!(c.verify(&out));
    assert_eq!(out, message);
}

/// The last fragment is padded, and the padding is not part of the message.
///
/// A message that does not divide evenly ends with a fragment whose tail is zeroes.
/// Writing those would append bytes nobody sent -- which for a PSBT means a document
/// that will not parse, and for anything signed means signing something else.
#[test]
fn the_padding_on_the_last_fragment_is_not_message() {
    // 1000 over 3 is 334 a fragment, so the last carries 332 real bytes and 2 of pad.
    let message = payload(1000);
    let line = part_line(&message, 3, 3);
    let mut scratch = vec![0u8; 512];
    let mut c = Collector::new();
    // A full fragment first, so the collector knows the shape.
    let first = c.accept(&part_line(&message, 3, 1), &mut scratch).unwrap();
    assert_eq!(first.len, 334);
    c.confirm(first);

    let p = c.accept(&line, &mut scratch).expect("the last part");
    assert_eq!(p.offset, 668);
    assert_eq!(p.len, 332, "the two padding bytes are not message");
    assert_eq!(p.at.len(), 334, "but the fragment itself is full length");
}

/// Fountain mixtures are skipped, not failed.
///
/// An encoder keeps going past `seqLen` with XOR combinations. They are perfectly
/// valid; this decoder waits for the pure ones instead of carrying a solver.
#[test]
fn a_fountain_mixture_is_skipped() {
    let message = payload(1000);
    let mut scratch = vec![0u8; 512];
    let mut c = Collector::new();

    // A part numbered past the end: the encoder's sixth frame of a five-part message.
    let mut cbor = vec![0x85];
    cbor_uint(6, &mut cbor);
    cbor_uint(5, &mut cbor);
    cbor_uint(message.len() as u64, &mut cbor);
    cbor_uint(bytewords::crc32(&message) as u64, &mut cbor);
    cbor_bytes(&[0u8; 200], &mut cbor);
    let line = format!("ur:crypto-psbt/6-5/{}", encode_bytewords(&cbor)).into_bytes();

    assert_eq!(
        c.accept(&line, &mut scratch),
        Err(Error::Mixture {
            seq_num: 6,
            seq_len: 5
        })
    );
    assert_eq!(c.have(), 0);
}

/// Parts of a different message are refused rather than mixed in.
#[test]
fn a_part_of_another_message_is_refused() {
    let a = payload(1000);
    let b = payload(900);
    let mut scratch = vec![0u8; 512];
    let mut c = Collector::new();

    let first = c.accept(&part_line(&a, 5, 1), &mut scratch).unwrap();
    c.confirm(first);
    assert_eq!(
        c.accept(&part_line(&b, 5, 2), &mut scratch),
        Err(Error::Mismatch),
        "same shape, different message"
    );
    assert_eq!(c.have(), 1);
}

/// A complete set whose bytes were corrupted on the way into the buffer is caught.
///
/// Each part proved its own bytewords checksum, which says the *part* arrived intact.
/// The message checksum is the separate claim that these are the parts of this message
/// and that all of them are here.
#[test]
fn the_message_checksum_is_checked_separately() {
    let message = payload(1000);
    let n = 5u32;
    let mut out = vec![0u8; message.len()];
    let mut scratch = vec![0u8; 512];
    let mut c = Collector::new();
    for i in 1..=n {
        let line = part_line(&message, n, i);
        let p = c.accept(&line, &mut scratch).unwrap();
        out[p.offset..p.offset + p.len].copy_from_slice(&scratch[p.at.start..p.at.start + p.len]);
        c.confirm(p);
    }
    assert!(c.verify(&out));
    out[500] ^= 1;
    assert!(!c.verify(&out), "a flipped bit in the assembled message");
}

#[test]
fn what_is_not_a_ur() {
    let mut scratch = vec![0u8; 512];
    let mut c = Collector::new();
    for line in [
        &b"hello"[..],
        b"ur:",
        b"ur:crypto-psbt",
        b"ur:crypto-psbt/1-2/3-4/aeae",
    ] {
        assert!(
            matches!(c.accept(line, &mut scratch), Err(Error::NotUr)),
            "{line:?} is not a UR"
        );
    }
    assert!(matches!(
        c.accept(b"ur:crypto-psbt/x-2/aeadaoax", &mut scratch),
        Err(Error::Numbering)
    ));
}

/// The CBOR reader takes the one shape a part has, and nothing else.
#[test]
fn the_cbor_must_be_a_five_element_part() {
    let mut scratch = vec![0u8; 512];
    let mut c = Collector::new();
    // An array of four, which is not a part.
    let mut cbor = vec![0x84];
    for n in [1u64, 1, 8, 0] {
        cbor_uint(n, &mut cbor);
    }
    let line = format!("ur:crypto-psbt/1-1/{}", encode_bytewords(&cbor)).into_bytes();
    assert!(matches!(
        c.accept(&line, &mut scratch),
        Err(Error::Cbor(CborError::NotAPart))
    ));
}
