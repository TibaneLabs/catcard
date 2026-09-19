//! What a part can be, and what it must not be taken for.

use super::*;

extern crate alloc;
extern crate std;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

const B32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The encoder the tests need, so a round trip proves the decoder against something
/// other than itself.
fn encode_base32(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in data {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn b36(n: u16) -> String {
    const D: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    format!(
        "{}{}",
        D[(n / 36) as usize] as char,
        D[(n % 36) as usize] as char
    )
}

/// Build one part the way the host tool will.
fn part(data: &[u8], total: u16, index: u16) -> Vec<u8> {
    format!("B$2B{}{}{}", b36(total), b36(index), encode_base32(data)).into_bytes()
}

/// Split `data` into `n` parts, as a sender does: equal parts, a short last one.
fn split(data: &[u8], n: u16) -> Vec<Vec<u8>> {
    let per = data.len().div_ceil(n as usize);
    (0..n)
        .map(|i| {
            let at = i as usize * per;
            part(&data[at..(at + per).min(data.len())], n, i)
        })
        .collect()
}

fn firmwareish(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| match i % 7 {
            0 => 0x00,
            1 => 0xF0,
            2 => (i / 7 % 251) as u8,
            _ => b"\x4f\xf0\x00\x0e"[i % 4],
        })
        .collect()
}

#[test]
fn a_header_says_which_part_of_what() {
    let (h, payload) = parse(b"B$2B0A05AAAA").expect("a valid header");
    assert_eq!(h.encoding, Encoding::Base32);
    assert_eq!(h.filetype, FileType::BINARY);
    assert_eq!(h.total, 10); // "0A" base36
    assert_eq!(h.index, 5);
    assert_eq!(payload, b"AAAA");
}

#[test]
fn what_is_not_a_part() {
    assert_eq!(parse(b""), Err(Error::NotBbqr));
    assert_eq!(parse(b"B$2B01"), Err(Error::NotBbqr)); // too short for a header
    assert_eq!(parse(b"XX2B0100"), Err(Error::NotBbqr));
    assert_eq!(parse(b"B$QB0100"), Err(Error::Encoding(b'Q')));
    assert_eq!(parse(b"B$2B0!00"), Err(Error::Numbering));
    // An index at or past the total describes a part that cannot exist.
    assert_eq!(parse(b"B$2B0101"), Err(Error::Numbering));
    assert_eq!(parse(b"B$2B0000"), Err(Error::Numbering));
}

/// The RFC 4648 vectors, which are what "base32" has to mean to interoperate.
#[test]
fn base32_matches_the_rfc() {
    for (plain, encoded) in [
        (&b""[..], ""),
        (b"f", "MY"),
        (b"fo", "MZXQ"),
        (b"foo", "MZXW6"),
        (b"foob", "MZXW6YQ"),
        (b"fooba", "MZXW6YTB"),
        (b"foobar", "MZXW6YTBOI"),
    ] {
        assert_eq!(encode_base32(plain), encoded, "encoding {plain:?}");
        let mut out = vec![0u8; plain.len()];
        let n = decode(Encoding::Base32, encoded.as_bytes(), &mut out).unwrap();
        assert_eq!(&out[..n], plain, "decoding {encoded}");
    }
}

#[test]
fn a_payload_that_is_not_base32_is_refused() {
    let mut out = [0u8; 8];
    // '1', '8', '0' and lower case are not in the alphabet.
    assert_eq!(
        decode(Encoding::Base32, b"MZXW6YT1", &mut out),
        Err(Error::Payload)
    );
    assert_eq!(
        decode(Encoding::Base32, b"mzxw6ytb", &mut out),
        Err(Error::Payload)
    );
    // A length that cannot come from whole bytes.
    assert_eq!(
        decode(Encoding::Base32, b"MZX", &mut out),
        Err(Error::Payload)
    );
}

/// Padding bits must be zero, or the characters did not come from this encoder.
///
/// Without this, several different strings decode to the same bytes -- and a part that
/// had been altered in its final character would be taken as genuine.
#[test]
fn non_zero_padding_bits_are_refused() {
    let mut out = [0u8; 1];
    // "MY" is `f`; the last character's spare bits are zero. "MZ" has one of them set.
    assert_eq!(decode(Encoding::Base32, b"MY", &mut out).unwrap(), 1);
    assert_eq!(
        decode(Encoding::Base32, b"MZ", &mut out),
        Err(Error::Payload)
    );
}

#[test]
fn hex_works_too() {
    let mut out = [0u8; 4];
    let n = decode(Encoding::Hex, b"DEADBEEF", &mut out).unwrap();
    assert_eq!((&out[..n], n), (&[0xDE, 0xAD, 0xBE, 0xEF][..], 4));
    assert_eq!(
        decode(Encoding::Hex, b"DEADBEE", &mut out),
        Err(Error::Payload)
    );
    assert_eq!(
        decode(Encoding::Hex, b"DEADBEEG", &mut out),
        Err(Error::Payload)
    );
}

/// A file arrives whole, in order.
#[test]
fn parts_in_order_reassemble() {
    let image = firmwareish(5000);
    let parts = split(&image, 7);
    let mut out = vec![0u8; image.len()];
    let mut c = Collector::new();
    for p in &parts {
        c.take(p, &mut out).expect("a part");
    }
    assert!(c.complete());
    assert_eq!(c.file_len(), Some(image.len()));
    assert_eq!(out, image);
}

/// And in any order, which is what makes a long scan practical: the animation loops
/// until every part has been caught, and nobody has to catch them in sequence.
#[test]
fn parts_out_of_order_reassemble() {
    let image = firmwareish(5000);
    let parts = split(&image, 7);
    let mut out = vec![0u8; image.len()];
    let mut c = Collector::new();
    // A deliberately awkward order: the last part is not first (see the test below),
    // but nothing else is where it belongs.
    for i in [3usize, 0, 5, 1, 6, 2, 4] {
        c.take(&parts[i], &mut out).expect("a part");
    }
    assert!(c.complete());
    assert_eq!(out, image);
}

/// The last part seen first cannot be placed, and says so instead of guessing.
///
/// Its length is short by however much the file does not divide evenly, so it says
/// nothing about where the full parts end. Placing it on that basis would write good
/// data to the wrong address, which is indistinguishable from corruption once staged.
#[test]
fn the_last_part_first_is_deferred_not_guessed() {
    let image = firmwareish(5000);
    let parts = split(&image, 7);
    let mut out = vec![0u8; image.len()];
    let mut c = Collector::new();

    assert_eq!(c.take(&parts[6], &mut out), Err(Error::PartLenUnknown));
    assert_eq!(
        c.have(),
        0,
        "a part that could not be placed is not counted"
    );
    assert!(out.iter().all(|&b| b == 0), "and nothing was written");

    // Any full part settles it, and the animation brings the last one round again.
    c.take(&parts[0], &mut out).expect("a full part");
    c.take(&parts[6], &mut out).expect("now placeable");
    for p in &parts[1..6] {
        c.take(p, &mut out).expect("the rest");
    }
    assert!(c.complete());
    assert_eq!(out, image);
}

/// A repeat changes nothing. The animation loops, so most parts are seen many times.
#[test]
fn repeats_are_free() {
    let image = firmwareish(3000);
    let parts = split(&image, 4);
    let mut out = vec![0u8; image.len()];
    let mut c = Collector::new();

    let first = c.take(&parts[2], &mut out).unwrap();
    assert!(first.fresh);
    let again = c.take(&parts[2], &mut out).unwrap();
    assert!(!again.fresh, "a second sighting is not a new part");
    assert_eq!((again.have, again.offset), (1, first.offset));
    assert!(!c.complete());
}

/// Parts of a different file are refused rather than mixed in.
///
/// Two animations in view at once is not a hypothetical -- a screen and a sheet of
/// paper on the same desk -- and splicing them produces an image that is wrong in a way
/// only the signature would catch.
#[test]
fn a_part_of_another_file_is_refused() {
    let a = firmwareish(3000);
    let b = firmwareish(2000);
    let mut out = vec![0u8; a.len()];
    let mut c = Collector::new();
    c.take(&split(&a, 4)[0], &mut out).expect("the first file");

    // Same shape, different total: a different file.
    assert_eq!(c.take(&split(&b, 3)[0], &mut out), Err(Error::Mismatch));
    // Same total, but its full parts are a different size.
    assert_eq!(c.take(&split(&b, 4)[1], &mut out), Err(Error::Mismatch));
    // A different file type, same numbering.
    let mut psbt = split(&a, 4)[1].clone();
    psbt[3] = b'P';
    assert_eq!(c.take(&psbt, &mut out), Err(Error::Mismatch));
    assert_eq!(c.have(), 1, "none of them counted");
}

/// A file that will not fit is refused before anything is written.
#[test]
fn a_part_past_the_end_of_the_buffer_is_refused() {
    let image = firmwareish(5000);
    let parts = split(&image, 7);
    let mut small = vec![0u8; 1000];
    let mut c = Collector::new();
    c.take(&parts[0], &mut small).expect("the first fits");
    assert_eq!(c.take(&parts[3], &mut small), Err(Error::TooLong));
}

/// The length is not known until the last part has been seen, however many others have.
#[test]
fn the_file_length_waits_for_the_last_part() {
    let image = firmwareish(5000);
    let parts = split(&image, 7);
    let mut out = vec![0u8; image.len()];
    let mut c = Collector::new();
    for p in &parts[..6] {
        c.take(p, &mut out).unwrap();
    }
    assert_eq!(
        c.file_len(),
        None,
        "six of seven says nothing about the total"
    );
    c.take(&parts[6], &mut out).unwrap();
    assert_eq!(c.file_len(), Some(image.len()));
}

/// A firmware-sized file at a realistic part size, scanned in a realistic order.
///
/// 537 KB at 2,685 bytes a code is about two hundred parts -- the number that decides
/// whether this is a feature or a stunt, so it is what the test uses.
#[test]
fn a_firmware_sized_file_reassembles() {
    let image = firmwareish(537_088);
    let per = 2685;
    let n = image.len().div_ceil(per) as u16;
    assert!((150..250).contains(&n), "expected ~200 parts, got {n}");
    let parts = split(&image, n);

    let mut out = vec![0u8; image.len()];
    let mut c = Collector::new();
    // Two passes of the animation with a third of the parts missed on the first, which
    // is what scanning two hundred codes off a screen actually looks like.
    for (i, p) in parts.iter().enumerate() {
        if i % 3 != 1 {
            c.take(p, &mut out).expect("first pass");
        }
    }
    assert!(!c.complete());
    for p in parts.iter() {
        c.take(p, &mut out).expect("second pass");
    }
    assert!(c.complete());
    assert_eq!(c.file_len(), Some(image.len()));
    assert_eq!(out, image);
}

/// A part that is accepted but never written does not count.
///
/// The firmware path decodes into the staging area, which can refuse. If that refusal
/// left the part counted, the collector would report a complete file with a hole in it
/// -- and for a firmware image the only thing left to notice would be the signature.
#[test]
fn an_accepted_part_counts_only_once_it_is_confirmed() {
    let image = firmwareish(3000);
    let parts = split(&image, 4);
    let mut c = Collector::new();

    let (placed, payload) = c.accept(&parts[1]).expect("a part");
    assert_eq!(placed.index, 1);
    assert_eq!(c.have(), 0, "accepting is not confirming");

    // The caller decides where it goes; only then does it count.
    let mut out = vec![0u8; placed.len];
    decode(Encoding::Base32, payload, &mut out).unwrap();
    let done = c.confirm(placed);
    assert!(done.fresh);
    assert_eq!(c.have(), 1);

    // And a second confirmation of the same part is not a second part.
    let (again, _) = c.accept(&parts[1]).unwrap();
    assert!(!c.confirm(again).fresh);
    assert_eq!(c.have(), 1);
}

/// Accepting the same part repeatedly without confirming never advances the count.
#[test]
fn accepting_without_confirming_never_completes() {
    let image = firmwareish(3000);
    let parts = split(&image, 4);
    let mut c = Collector::new();
    for _ in 0..10 {
        for p in &parts {
            let _ = c.accept(p);
        }
    }
    assert_eq!(c.have(), 0);
    assert!(
        !c.complete(),
        "a scan that is never confirmed never finishes"
    );
}

// --- the writing direction ----------------------------------------------------------

/// What this writes, it reads.
///
/// The decoder was checked against the RFC's own vectors, so a round trip through it is
/// a check on the encoder rather than the two agreeing on a private mistake.
#[test]
fn what_is_written_can_be_read() {
    let file = firmwareish(4001);
    let per = 300;
    let total = encode::parts_needed(file.len(), per) as u16;

    let mut out = vec![0u8; file.len()];
    let mut c = Collector::new();
    let mut line = vec![0u8; encode::encoded_len(per)];
    for i in 0..total {
        let at = i as usize * per;
        let chunk = &file[at..(at + per).min(file.len())];
        let n = encode::part(chunk, FileType::BINARY, total, i, &mut line).unwrap();
        c.take(&line[..n], &mut out).expect("its own part");
    }
    assert!(c.complete());
    assert_eq!(c.file_len(), Some(file.len()));
    assert_eq!(out, file);
}

/// Every character a part can contain is in QR's alphanumeric set.
///
/// The reason this format is worth preferring: alphanumeric mode holds 4,296 characters
/// against byte mode's 2,953, and a line that strays outside the set silently costs a
/// third of the capacity.
#[test]
fn every_character_is_alphanumeric() {
    const QR_ALNUM: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
    let file = firmwareish(1024);
    let mut line = vec![0u8; encode::encoded_len(256)];
    for i in 0..4u16 {
        let at = i as usize * 256;
        let n = encode::part(&file[at..at + 256], FileType::BINARY, 4, i, &mut line).unwrap();
        for &ch in &line[..n] {
            assert!(
                QR_ALNUM.as_bytes().contains(&ch),
                "{:?} is not in QR's alphanumeric set",
                ch as char
            );
        }
    }
}

/// The size arithmetic agrees with itself, which is what a screen sizes a symbol from.
#[test]
fn the_length_arithmetic_is_consistent() {
    for bytes in [0usize, 1, 2, 3, 4, 5, 6, 100, 255, 2684, 2685] {
        let mut line = vec![0u8; encode::encoded_len(bytes) + 8];
        let data = firmwareish(bytes);
        let n = encode::part(&data, FileType::BINARY, 1, 0, &mut line).unwrap();
        assert_eq!(n, encode::encoded_len(bytes), "{bytes} bytes");
        // And `fits` is its inverse: what it says fits, does.
        assert!(encode::encoded_len(encode::fits(n)) <= n, "{bytes} bytes");
    }
}

/// A part that will not fit the buffer is refused rather than truncated.
#[test]
fn a_part_that_does_not_fit_is_refused() {
    let data = firmwareish(100);
    let mut small = [0u8; 16];
    assert_eq!(
        encode::part(&data, FileType::BINARY, 1, 0, &mut small),
        Err(Error::TooLong)
    );
}

/// Numbering that cannot describe a file is refused.
#[test]
fn impossible_numbering_is_refused() {
    let data = firmwareish(10);
    let mut line = [0u8; 64];
    // No parts, an index at or past the total, and more parts than two base36 digits.
    assert_eq!(
        encode::part(&data, FileType::BINARY, 0, 0, &mut line),
        Err(Error::Numbering)
    );
    assert_eq!(
        encode::part(&data, FileType::BINARY, 3, 3, &mut line),
        Err(Error::Numbering)
    );
    assert_eq!(
        encode::part(&data, FileType::BINARY, 1297, 0, &mut line),
        Err(Error::Numbering)
    );
}

/// A wallet export, at the size it will really be, in symbols a screen can draw.
///
/// Two kilobytes of descriptors at three hundred bytes a part is seven codes of about
/// five hundred characters -- a version-12 symbol, sixty-five modules, which is three
/// screen pixels a module on a 320-wide panel.
#[test]
fn a_wallet_export_splits_into_readable_codes() {
    let export = firmwareish(2048);
    let per = 300;
    let total = encode::parts_needed(export.len(), per);
    assert_eq!(total, 7);
    assert!(
        encode::encoded_len(per) <= 535,
        "a part must fit a version-12 alphanumeric symbol"
    );

    let mut out = vec![0u8; export.len()];
    let mut c = Collector::new();
    let mut line = vec![0u8; encode::encoded_len(per)];
    // Shown as an animation, so read them in the order a camera happens to catch them.
    for i in [3usize, 6, 0, 4, 1, 5, 2] {
        let at = i * per;
        let chunk = &export[at..(at + per).min(export.len())];
        let n = encode::part(chunk, FileType::BINARY, total as u16, i as u16, &mut line).unwrap();
        c.take(&line[..n], &mut out).expect("a part");
    }
    assert!(c.complete());
    assert_eq!(out, export);
}
