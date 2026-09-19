//! Where a part belongs, and what must not be guessed about one.
//!
//! The codec is [`outscript::bbqr`]'s and is tested there. These are about the
//! bookkeeping: turning an index into an offset without having seen the parts in front
//! of it, and refusing to when it cannot be known.

use super::*;

extern crate alloc;
extern crate std;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// Build one part the way a sender does, through the real encoder -- so a round trip
/// here proves the two directions against each other rather than against a copy.
fn part_with(encoding: Encoding, data: &[u8], total: u16, index: u16) -> String {
    let header = Header {
        encoding,
        file_type: FileType::BINARY,
        num_parts: total,
        index,
    };
    let mut out = vec![0u8; part_len(encoding, data.len())];
    let n = encode_part_to_slice(&header, data, &mut out).expect("encodes");
    String::from_utf8(out[..n].to_vec()).expect("ascii")
}

fn part(data: &[u8], total: u16, index: u16) -> String {
    part_with(Encoding::Base32, data, total, index)
}

/// Split `data` into `n` parts, as a sender does: equal parts, a short last one.
fn split(data: &[u8], n: u16) -> Vec<String> {
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
            1 => 0xFF,
            n => (i / 7 + n) as u8,
        })
        .collect()
}

#[test]
fn parts_in_order_reassemble() {
    let file = firmwareish(1000);
    let mut out = vec![0u8; file.len()];
    let mut c = Collector::new();
    for line in split(&file, 4) {
        c.take(&line, &mut out).expect("a part");
    }
    assert!(c.complete());
    assert_eq!(c.file_len(), Some(file.len()));
    assert_eq!(out, file);
}

/// The whole point of the format: a part carries its own index, so which one the camera
/// catches next does not matter.
#[test]
fn parts_out_of_order_reassemble() {
    let file = firmwareish(1000);
    let mut out = vec![0u8; file.len()];
    let mut c = Collector::new();
    let parts = split(&file, 5);
    for i in [2usize, 0, 4, 1, 3] {
        c.take(&parts[i], &mut out).expect("a part");
    }
    assert!(c.complete());
    assert_eq!(out, file);
}

/// The last part is the only short one, so until a full part has been seen there is
/// nothing to measure it against -- and its offset is a multiple of that length. Placing
/// it on a guess puts the tail of the file in the wrong place, which a signature check
/// would later blame on the memory.
#[test]
fn the_last_part_first_is_deferred_not_guessed() {
    let file = firmwareish(1000);
    let parts = split(&file, 4);
    let mut out = vec![0u8; file.len()];
    let mut c = Collector::new();

    assert_eq!(c.take(&parts[3], &mut out), Err(Error::PartLenUnknown));
    assert_eq!(c.have(), 0);

    c.take(&parts[1], &mut out).expect("a full part");
    c.take(&parts[3], &mut out).expect("now placeable");
    c.take(&parts[0], &mut out).expect("a part");
    c.take(&parts[2], &mut out).expect("a part");
    assert!(c.complete());
    assert_eq!(out, file);
}

/// The animation loops, so almost every part arrives many times.
#[test]
fn repeats_are_free() {
    let file = firmwareish(400);
    let mut out = vec![0u8; file.len()];
    let mut c = Collector::new();
    let parts = split(&file, 3);
    for _ in 0..3 {
        for line in &parts {
            c.take(line, &mut out).expect("a part");
        }
    }
    assert_eq!(c.have(), 3);
    assert_eq!(out, file);
}

/// Two senders in shot at once, or one that was restarted with a different file.
#[test]
fn a_part_of_another_file_is_refused() {
    let mut out = vec![0u8; 1000];
    let mut c = Collector::new();
    c.take(&part(&[1, 2, 3, 4, 5], 4, 0), &mut out)
        .expect("a part");
    // Same file type and encoding, different number of parts.
    assert_eq!(
        c.take(&part(&[1, 2, 3, 4, 5], 5, 0), &mut out),
        Err(Error::Mismatch)
    );
    // Same numbering, a different part length.
    assert_eq!(
        c.take(&part(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 4, 1), &mut out),
        Err(Error::Mismatch)
    );
}

#[test]
fn a_part_past_the_end_of_the_buffer_is_refused() {
    let mut out = [0u8; 4];
    let mut c = Collector::new();
    assert_eq!(
        c.take(&part(&[1, 2, 3, 4, 5], 2, 0), &mut out),
        Err(Error::TooLong)
    );
    assert_eq!(c.have(), 0, "a refused part must not count");
}

#[test]
fn the_file_length_waits_for_the_last_part() {
    let file = firmwareish(1000);
    let parts = split(&file, 4);
    let mut out = vec![0u8; file.len()];
    let mut c = Collector::new();
    for line in &parts[..3] {
        c.take(line, &mut out).expect("a part");
    }
    assert_eq!(c.file_len(), None, "three of four is not a length");
    c.take(&parts[3], &mut out).expect("a part");
    assert_eq!(c.file_len(), Some(file.len()));
}

#[test]
fn a_firmware_sized_file_reassembles() {
    let file = firmwareish(300 * 1024);
    let mut out = vec![0u8; file.len()];
    let mut c = Collector::new();
    let parts = split(&file, 240);
    // Backwards, which is the order that breaks a collector that assumes anything.
    for line in parts.iter().rev() {
        match c.take(line, &mut out) {
            Ok(_) => {}
            Err(Error::PartLenUnknown) => {}
            Err(e) => panic!("{e:?}"),
        }
    }
    // The first pass deferred the last part; the loop comes round again in practice.
    for line in &parts {
        c.take(line, &mut out).expect("a part");
    }
    assert!(c.complete());
    assert_eq!(c.file_len(), Some(file.len()));
    assert_eq!(out, file);
}

/// A part is counted when it is stored, not when it is understood. A collector that
/// counted on sight would call a file complete after a write that failed, and for a
/// firmware image the only check left would be the signature.
#[test]
fn an_accepted_part_counts_only_once_it_is_confirmed() {
    let mut c = Collector::new();
    let line = part(&[1, 2, 3, 4, 5], 2, 0);
    let placed = c.accept(&line).expect("a part");
    assert!(placed.fresh);
    assert_eq!(c.have(), 0, "accept must not count it");
    let placed = c.confirm(placed);
    assert!(placed.fresh);
    assert_eq!(c.have(), 1);
    // A second sighting is not fresh and does not double-count.
    let again = c.accept(&line).expect("a part");
    assert!(!again.fresh);
    assert_eq!(c.confirm(again).have, 1);
}

#[test]
fn accepting_without_confirming_never_completes() {
    let file = firmwareish(400);
    let mut c = Collector::new();
    for _ in 0..10 {
        for line in split(&file, 3) {
            c.accept(&line).expect("a part");
        }
    }
    assert!(!c.complete(), "nothing was stored");
    assert_eq!(c.have(), 0);
}

#[test]
fn what_is_written_can_be_read() {
    let file = firmwareish(777);
    let per = fits(Encoding::Base32, 200);
    let total = parts_needed(file.len(), per) as u16;
    let mut out = vec![0u8; file.len()];
    let mut c = Collector::new();
    for i in 0..total {
        let at = i as usize * per;
        let line = part(&file[at..(at + per).min(file.len())], total, i);
        assert!(line.len() <= 200, "{} characters", line.len());
        c.take(&line, &mut out).expect("a part");
    }
    assert!(c.complete());
    assert_eq!(out, file);
}

/// QR's alphanumeric mode holds a third more than byte mode and covers only `0-9A-Z`
/// and a few symbols. A line that strays outside it silently costs that capacity.
#[test]
fn every_character_is_alphanumeric() {
    const ALNUM: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
    let file = firmwareish(512);
    for line in split(&file, 3) {
        for c in line.chars() {
            assert!(ALNUM.contains(c), "{c:?} is not in alphanumeric mode");
        }
    }
}

#[test]
fn hex_works_too() {
    let file = firmwareish(120);
    let mut out = vec![0u8; file.len()];
    let mut c = Collector::new();
    for i in 0..3u16 {
        let at = i as usize * 40;
        c.take(
            &part_with(Encoding::Hex, &file[at..at + 40], 3, i),
            &mut out,
        )
        .expect("a part");
    }
    assert!(c.complete());
    assert_eq!(out, file);
}

/// `Z` deflates the whole file before cutting it, so the parts place like any others
/// and what they reassemble into is the compressed stream. The collector says so and
/// leaves the expanding to whoever knows where the bytes went.
#[test]
fn compressed_parts_place_like_any_other() {
    let stream = firmwareish(200);
    let mut out = vec![0u8; stream.len()];
    let mut c = Collector::new();
    assert!(!c.compressed(), "nothing seen yet");
    for i in 0..2u16 {
        let at = i as usize * 100;
        c.take(
            &part_with(Encoding::Zlib, &stream[at..at + 100], 2, i),
            &mut out,
        )
        .expect("a part");
    }
    assert!(c.compressed());
    assert!(c.complete());
    // The reassembled bytes are the deflate stream, not the file.
    assert_eq!(c.file_len(), Some(stream.len()));
    assert_eq!(out, stream);
}

#[test]
fn the_length_arithmetic_is_consistent() {
    for encoding in [Encoding::Base32, Encoding::Hex] {
        for chars in [20usize, 64, 100, 255, 2048] {
            let per = fits(encoding, chars);
            assert!(
                part_len(encoding, per) <= chars,
                "{encoding:?} {chars}: {per} bytes is {} characters",
                part_len(encoding, per)
            );
            // And it is the most that fits: another whole group overflows. Base32
            // rounds to five-byte groups, so one more byte need not.
            let group = match encoding {
                Encoding::Hex => 1,
                _ => 5,
            };
            assert!(part_len(encoding, per + group) > chars);
        }
    }
    assert_eq!(parts_needed(0, 10), 1, "nothing is still one part");
    assert_eq!(parts_needed(10, 10), 1);
    assert_eq!(parts_needed(11, 10), 2);
    assert_eq!(parts_needed(10, 0), 0);
}

#[test]
fn impossible_numbering_is_refused() {
    let mut out = [0u8; 64];
    let mut c = Collector::new();
    // An index at or past the total.
    assert!(matches!(
        c.take("B$2B0101AAAAAAAA", &mut out),
        Err(Error::Codec(_))
    ));
    // No parts at all.
    assert!(matches!(
        c.take("B$2B0000AAAAAAAA", &mut out),
        Err(Error::Codec(_))
    ));
    // Not a header.
    assert!(matches!(c.take("", &mut out), Err(Error::Codec(_))));
    assert!(matches!(
        c.take("XX2B0100AA", &mut out),
        Err(Error::Codec(_))
    ));
}

/// A file small enough for one code is both the first part and the last, so there is no
/// full part to measure the short one against -- and its offset is zero anyway. Most
/// wallet exports are one code, so getting this wrong means they never read at all.
#[test]
fn a_wallet_export_splits_into_readable_codes() {
    let json = br#"{"chain":"BTC","xfp":"0F056943","account":0,"xpub":"xpub6C"}"#;
    let per = fits(Encoding::Base32, 224);
    let total = parts_needed(json.len(), per) as u16;
    assert_eq!(total, 1, "this one fits in a single code");

    let mut out = vec![0u8; json.len()];
    let mut c = Collector::new();
    let line = part(json, total, 0);
    c.take(&line, &mut out).expect("a part");
    assert!(c.complete());
    assert_eq!(out, json);
}
