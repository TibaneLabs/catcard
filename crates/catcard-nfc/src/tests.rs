//! The bytes, spelled out.
//!
//! A phone's NFC stack is not here to test against, so what these check is the format
//! itself: a short URI built by hand, the point where the record stops being short, and
//! that the pieces a caller assembles come out as one image.

use super::*;

/// A tag holding `https://a.example` -- short enough for every short form there is.
#[test]
fn a_short_uri_is_the_bytes_the_spec_describes() {
    let mut out = [0u8; 64];
    let n = uri_image("a.example", prefix::HTTPS, &mut out).unwrap();
    assert_eq!(
        &out[..n],
        &[
            // The container: eight-byte form, v1.0 read/write, multi-block read, and the
            // area in eight-byte blocks (64 - 8 = 56 bytes, so seven).
            0xE2, 0x40, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07,
            // NDEF TLV, holding fourteen bytes.
            0x03, 14, // One short record, well known, type 'U', ten bytes of payload.
            0xD1, 0x01, 10, b'U', // `https://` and the rest.
            0x04, b'a', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e', // Terminator.
            0xFE,
        ]
    );
    assert_eq!(n, image_len("a.example".len()));
}

/// Past 255 bytes of payload the record takes the four-byte length, and past 254 bytes of
/// record the TLV takes its escape. Both boundaries are where an off-by-one would stop a
/// phone reading the tag at all.
#[test]
fn the_long_forms_appear_exactly_where_they_should() {
    // 254 bytes of text: payload 255, still short; record 259, so the TLV escapes.
    let text = "x".repeat(254);
    let mut out = [0u8; 1024];
    let n = uri_image(&text, prefix::HTTPS, &mut out).unwrap();
    assert_eq!(out[CC_LEN], 0x03);
    assert_eq!(&out[CC_LEN + 1..CC_LEN + 4], &[0xFF, 0x01, 0x03]);
    assert_eq!(out[CC_LEN + 4] & 0x10, 0x10, "still a short record");
    assert_eq!(out[n - 1], 0xFE);

    // One more byte, and the record is no longer short.
    let text = "x".repeat(255);
    let n = uri_image(&text, prefix::HTTPS, &mut out).unwrap();
    let header = out[CC_LEN + 4];
    assert_eq!(header & 0x10, 0, "no longer short");
    assert_eq!(header, 0xC1);
    assert_eq!(&out[CC_LEN + 6..CC_LEN + 10], &256u32.to_be_bytes());
    assert_eq!(out[n - 1], 0xFE);
}

/// Every length agrees with what `image_len` promised, which is what the caller sizes its
/// buffer from.
#[test]
fn the_promised_length_is_the_length_written() {
    let mut out = [0u8; 4096];
    for len in [0usize, 1, 10, 253, 254, 255, 256, 700, 2000] {
        let text = "y".repeat(len);
        let n = uri_image(&text, prefix::HTTPS, &mut out).unwrap();
        assert_eq!(n, image_len(len), "{len}");
    }
}

/// A URI that does not fit is refused with what it needed, rather than writing a tag a
/// phone would read as a truncated address.
#[test]
fn a_uri_too_long_for_the_tag_is_refused() {
    let mut out = [0u8; 32];
    let text = "z".repeat(64);
    assert!(matches!(
        uri_image(&text, prefix::HTTPS, &mut out),
        Err(Error::TooLong { .. })
    ));
}

/// Assembling in two steps -- header, text, terminator -- gives the same bytes as one.
#[test]
fn building_it_in_pieces_matches_building_it_whole() {
    let uri = "www.example.com/path?x=1";
    let mut whole = [0u8; 128];
    let n = uri_image(uri, prefix::HTTPS, &mut whole).unwrap();

    let mut parts = [0u8; 128];
    let at = begin(&mut parts, uri.len(), prefix::HTTPS).unwrap();
    parts[at..at + uri.len()].copy_from_slice(uri.as_bytes());
    let m = finish(&mut parts, at + uri.len()).unwrap();
    assert_eq!((&whole[..n], n), (&parts[..m], m));
}

/// The container counts the area in eight-byte blocks, excluding itself: a 8192-byte part
/// carries 8184 bytes of area, which is 1023 blocks.
#[test]
fn the_container_counts_blocks_not_bytes() {
    assert_eq!(
        capability_container(8192 - CC_LEN),
        [0xE2, 0x40, 0x00, 0x01, 0x00, 0x00, 0x03, 0xFF]
    );
}
