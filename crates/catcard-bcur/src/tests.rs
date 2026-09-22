//! What a UR part must be, and what it must not be mistaken for.

use super::*;

extern crate alloc;
extern crate std;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use outscript::bcur::bytewords::Style;

/// Bytewords, through the real encoder -- the table and the checksum are outscript's,
/// and tested there. These are about what is done with the bytes afterwards.
fn encode_bytewords(data: &[u8]) -> String {
    let mut out = vec![0u8; bytewords::encoded_len(data.len(), Style::Minimal)];
    let n = bytewords::encode_to_slice(data, Style::Minimal, &mut out).expect("encodes");
    String::from_utf8(out[..n].to_vec()).expect("ascii")
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
fn part_line(message: &[u8], seq_len: u32, seq_num: u32) -> String {
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
    cbor_uint(crc32(message) as u64, &mut cbor);
    cbor_bytes(&data, &mut cbor);

    format!(
        "ur:crypto-psbt/{seq_num}-{seq_len}/{}",
        encode_bytewords(&cbor)
    )
}

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + i / 251) as u8).collect()
}

/// The spec's own vector, which is what says the word list is the right word list.
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
    cbor_uint(crc32(&message) as u64, &mut cbor);
    cbor_bytes(&[0u8; 200], &mut cbor);
    let line = format!("ur:crypto-psbt/6-5/{}", encode_bytewords(&cbor));

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
        "hello",
        "ur:",
        "ur:crypto-psbt",
        "ur:crypto-psbt/1-2/3-4/aeae",
    ] {
        assert!(
            matches!(c.accept(line, &mut scratch), Err(Error::NotUr)),
            "{line:?} is not a UR"
        );
    }
    // A sequence field that is not two numbers is not a UR either -- the codec rejects
    // the line before there is anything to number.
    assert!(matches!(
        c.accept("ur:crypto-psbt/x-2/aeadaoax", &mut scratch),
        Err(Error::NotUr)
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
    let line = format!("ur:crypto-psbt/1-1/{}", encode_bytewords(&cbor));
    assert!(matches!(
        c.accept(&line, &mut scratch),
        Err(Error::Cbor(CborError::NotAPart))
    ));
}

// --- the writing direction ----------------------------------------------------------

/// What this writes, its own reader reads back.
#[test]
fn a_written_ur_round_trips() {
    let message = payload(900);
    let seq_len = 5u32;
    let mut out = vec![0u8; message.len()];
    let mut scratch = vec![0u8; 1024];
    let mut line = vec![0u8; 4096];
    let mut c = Collector::new();

    for i in 1..=seq_len {
        let n = encode::part("bytes", &message, i, seq_len, &mut line).unwrap();
        let text = core::str::from_utf8(&line[..n]).expect("ascii");
        let p = c.accept(text, &mut scratch).expect("its own part");
        out[p.offset..p.offset + p.len].copy_from_slice(&scratch[p.at.start..p.at.start + p.len]);
        c.confirm(p);
    }
    assert!(c.complete());
    assert!(c.verify(&out));
    assert_eq!(out, message);
}

/// Every character written is one QR's alphanumeric mode covers.
///
/// The reason to upper-case a UR at all: alphanumeric holds 4,296 characters against
/// byte mode's 2,953, and a single lower-case letter costs the whole symbol that.
#[test]
fn a_written_ur_is_all_alphanumeric() {
    const QR_ALNUM: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
    let message = payload(500);
    let mut line = vec![0u8; 4096];
    let n = encode::part("bytes", &message, 1, 3, &mut line).unwrap();
    for &ch in &line[..n] {
        assert!(
            QR_ALNUM.as_bytes().contains(&ch),
            "{:?} is not in QR's alphanumeric set",
            ch as char
        );
    }
}

/// A reader must take either case, because both are legitimate: the lower case the
/// specification writes, and the upper case a UR is put into to stay in QR's
/// alphanumeric mode. Every UR this device ever shows is the upper one.
#[test]
fn either_case_is_read() {
    let message = payload(200);
    let line = part_line(&message, 2, 1);
    let mut scratch = vec![0u8; 512];

    let mut lower = Collector::new();
    let a = lower
        .accept(&line.to_ascii_lowercase(), &mut scratch)
        .expect("lower");
    let mut upper = Collector::new();
    let b = upper
        .accept(&line.to_ascii_uppercase(), &mut scratch)
        .expect("upper");
    assert_eq!((a.offset, a.len, a.total), (b.offset, b.len, b.total));
}

/// The size estimate is never short, which is what a caller allocates from.
#[test]
fn the_length_estimate_is_never_short() {
    let message = payload(1000);
    for seq_len in [1u32, 2, 5, 10, 99, 100] {
        let fragment = message.len().div_ceil(seq_len as usize);
        let mut line = vec![0u8; encode::encoded_len("bytes", fragment, seq_len, seq_len)];
        for i in [1, seq_len] {
            let n = encode::part("bytes", &message, i, seq_len, &mut line)
                .unwrap_or_else(|e| panic!("{seq_len} parts, part {i}: {e:?}"));
            assert!(
                n <= line.len(),
                "{seq_len} parts: wrote {n} into {}",
                line.len()
            );
        }
    }
}

/// And `fits` gives back a fragment whose line really does fit.
#[test]
fn fits_is_a_size_that_fits() {
    for chars in [200usize, 535, 1000, 4296] {
        let fragment = encode::fits("bytes", chars, 99);
        assert!(fragment > 0, "{chars} characters must hold something");
        let message = payload(fragment * 99);
        let mut line = vec![0u8; chars];
        let n = encode::part("bytes", &message, 99, 99, &mut line)
            .unwrap_or_else(|e| panic!("{chars} chars, fragment {fragment}: {e:?}"));
        assert!(n <= chars, "{chars} chars: wrote {n}");
    }
}

/// Numbering that cannot describe a message is refused.
#[test]
fn impossible_numbering_is_refused_when_writing() {
    let message = payload(100);
    let mut line = vec![0u8; 4096];
    for (num, len) in [(0u32, 3u32), (4, 3), (1, 0)] {
        assert_eq!(
            encode::part("bytes", &message, num, len, &mut line),
            Err(encode::Error::Numbering),
            "{num} of {len}"
        );
    }
}

// --- single-part URs ----------------------------------------------------------------

/// A UR with no sequence field is the whole message, and reads as one fragment.
///
/// Most `crypto-hdkey` and `crypto-account` URs, and a PSBT small enough for one
/// symbol, arrive this way; refusing them meant refusing most of what a wallet shows.
#[test]
fn a_single_part_ur_is_the_whole_message() {
    let message = payload(120);
    let mut line = vec![0u8; encode::single_len("crypto-psbt", message.len())];
    let n = encode::single("crypto-psbt", &message, &mut line).expect("room");
    let text = core::str::from_utf8(&line[..n]).expect("ascii");
    assert!(!text.contains("1-1"), "no sequence field at all");

    let mut scratch = vec![0u8; 512];
    let mut c = Collector::new();
    let p = c.accept(text, &mut scratch).expect("a UR");
    assert_eq!(
        (p.index, p.offset, p.len, p.total),
        (0, 0, message.len(), 1)
    );
    assert_eq!(&scratch[p.at.clone()], &message[..]);
    c.confirm(p);

    assert!(c.complete(), "one fragment is all of them");
    assert!(c.verify(&message));
}

/// A single-part UR is shorter than the same message as `1-1`, which is why it is
/// worth writing rather than always numbering.
#[test]
fn a_single_part_ur_is_shorter_than_a_one_part_animation() {
    let message = payload(120);
    let single = encode::single_len("crypto-psbt", message.len());
    let numbered = encode::encoded_len("crypto-psbt", message.len(), 1, 1);
    assert!(single < numbered, "{single} vs {numbered}");
}

/// The last fragment of a multi-part message carries padding; a single-part one never
/// does, because there is nothing to pad out to.
#[test]
fn a_single_part_ur_has_no_padding() {
    for len in [1usize, 23, 24, 255, 256, 1000] {
        let message = payload(len);
        let mut line = vec![0u8; encode::single_len("bytes", len)];
        let n = encode::single("bytes", &message, &mut line).unwrap();
        let mut scratch = vec![0u8; 2048];
        let mut c = Collector::new();
        let p = c
            .accept(core::str::from_utf8(&line[..n]).unwrap(), &mut scratch)
            .unwrap();
        assert_eq!(p.len, len, "{len} bytes");
        assert_eq!(p.at.len(), len, "{len} bytes, no pad");
    }
}

// --- the type is part of the message ------------------------------------------------

/// The collector says what it is collecting, lower-cased whatever the line's case.
#[test]
fn the_type_is_reported() {
    let message = payload(100);
    let mut scratch = vec![0u8; 512];

    let mut c = Collector::new();
    assert_eq!(c.ur_type(), None, "nothing seen yet");
    assert_eq!(c.kind(), None);

    let line = part_line(&message, 2, 1).to_ascii_uppercase();
    let p = c.accept(&line, &mut scratch).unwrap();
    c.confirm(p);
    assert_eq!(c.ur_type(), Some("crypto-psbt"));
    assert_eq!(c.kind(), Some(registry::Kind::Psbt));
}

/// A type nobody has registered still assembles; it simply has no kind.
///
/// The transport does not care what it is carrying, and a device that refused an
/// unknown type would refuse a payload it could still save to a card.
#[test]
fn an_unknown_type_still_collects() {
    let message = payload(100);
    let mut line = vec![0u8; 1024];
    let n = encode::single("something-else", &message, &mut line).unwrap();
    let mut scratch = vec![0u8; 512];
    let mut c = Collector::new();
    let p = c
        .accept(core::str::from_utf8(&line[..n]).unwrap(), &mut scratch)
        .expect("a UR");
    c.confirm(p);
    assert_eq!(c.ur_type(), Some("something-else"));
    assert_eq!(c.kind(), None);
}

/// A part whose type is not the type the others had is a different message.
///
/// Two animations in front of the camera at once, of the same length and with the
/// same checksum, would otherwise assemble into a document neither sender sent. The
/// type is checked the same way the checksum is.
#[test]
fn a_type_that_changes_mid_message_is_refused() {
    let message = payload(1000);
    let mut scratch = vec![0u8; 512];
    let mut c = Collector::new();

    let first = c.accept(&part_line(&message, 5, 1), &mut scratch).unwrap();
    c.confirm(first);

    // The very same part, relabelled. Everything the old reader looked at agrees.
    let relabelled = part_line(&message, 5, 2).replace("crypto-psbt", "bytes");
    assert_eq!(
        c.accept(&relabelled, &mut scratch),
        Err(Error::TypeMismatch)
    );
    assert_eq!(c.have(), 1, "and it is not counted");
}

/// `crypto-psbt` and `psbt` are the same registry item, but not the same animation:
/// a sender uses one name throughout, so a change of name mid-message is still a
/// second sender.
#[test]
fn even_two_names_for_one_kind_do_not_mix() {
    let message = payload(1000);
    let mut scratch = vec![0u8; 512];
    let mut c = Collector::new();
    let first = c.accept(&part_line(&message, 5, 1), &mut scratch).unwrap();
    c.confirm(first);
    let renamed = part_line(&message, 5, 2).replace("ur:crypto-psbt/", "ur:psbt/");
    assert_eq!(c.accept(&renamed, &mut scratch), Err(Error::TypeMismatch));
}

/// A single-part UR cannot be mixed into a multi-part one, or the other way round.
#[test]
fn a_single_part_and_a_multi_part_do_not_mix() {
    let message = payload(1000);
    let mut scratch = vec![0u8; 2048];

    let mut c = Collector::new();
    let first = c.accept(&part_line(&message, 5, 1), &mut scratch).unwrap();
    c.confirm(first);

    let mut whole = vec![0u8; 4096];
    let n = encode::single("crypto-psbt", &message, &mut whole).unwrap();
    assert_eq!(
        c.accept(core::str::from_utf8(&whole[..n]).unwrap(), &mut scratch),
        Err(Error::Mismatch),
        "one fragment against five"
    );
}

/// A type longer than there is room to remember is refused, not truncated.
///
/// A truncated type would compare equal to a different one, which is the whole failure
/// the type check exists to stop.
#[test]
fn a_type_too_long_is_refused() {
    let long: String = core::iter::repeat_n('a', MAX_TYPE + 1).collect();
    let mut scratch = vec![0u8; 512];
    let mut c = Collector::new();
    let line = format!("ur:{long}/aeadaolsrpdt");
    assert_eq!(c.accept(&line, &mut scratch), Err(Error::TypeTooLong));
    assert_eq!(c.ur_type(), None);
}

/// A part that is refused leaves an empty collector empty.
///
/// If the type were recorded before the part was believed, a bad line would lock the
/// collector to a type the sender never used, and every real part after it would be a
/// mismatch.
#[test]
fn a_refused_part_commits_nothing() {
    let mut scratch = vec![0u8; 512];
    let mut c = Collector::new();

    // A part numbered past `seq_len`: a fountain mixture, which is skipped.
    let message = payload(200);
    let mut cbor = vec![0x85];
    cbor_uint(3, &mut cbor);
    cbor_uint(2, &mut cbor);
    cbor_uint(message.len() as u64, &mut cbor);
    cbor_uint(crc32(&message) as u64, &mut cbor);
    cbor_bytes(&[0u8; 100], &mut cbor);
    let mixture = format!("ur:crypto-psbt/3-2/{}", encode_bytewords(&cbor));
    assert!(c.accept(&mixture, &mut scratch).is_err());
    assert_eq!(c.ur_type(), None);
    assert_eq!(c.about(), None);

    // And a real part is still taken afterwards.
    let p = c.accept(&part_line(&message, 2, 1), &mut scratch).unwrap();
    c.confirm(p);
    assert_eq!(c.ur_type(), Some("crypto-psbt"));
}
