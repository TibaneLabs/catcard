//! The bytes, spelled out.
//!
//! A phone's NFC stack is not here to test against, so what these check is the format
//! itself: a short URI built by hand, the point where the record stops being short, and
//! that the pieces a caller assembles come out as one image.
//!
//! The reading half is tested the other way round -- against tags this crate did *not*
//! write. A tag comes from a phone, so its lengths are someone else's numbers, and the
//! tests that matter are the ones where those numbers are wrong.

use super::*;

/// The area of the part this firmware has: 8192 bytes less the container.
const PART: usize = 8192 - CC_LEN;

/// A tag holding `https://a.example` -- short enough for every short form there is.
#[test]
fn a_short_uri_is_the_bytes_the_spec_describes() {
    let mut out = [0u8; 64];
    let n = uri_image(&mut out, 56, "a.example", prefix::HTTPS).unwrap();
    assert_eq!(
        &out[..n],
        &[
            // The container: eight-byte form, v1.0 read/write, multi-block read, and the
            // area in eight-byte blocks (56 bytes, so seven).
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

/// A text record: the status byte says UTF-8 and a two-letter language code, and the
/// language code itself comes before the text.
#[test]
fn a_text_record_carries_its_status_byte_and_language() {
    let mut out = [0u8; 64];
    let n = text_image(&mut out, 56, "hello").unwrap();
    assert_eq!(
        &out[..n],
        &[
            0xE2, 0x40, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, // NDEF TLV, twelve bytes.
            0x03, 12, // Short record, well known, type 'T', eight bytes of payload.
            0xD1, 0x01, 8, b'T', // UTF-8, language code two bytes long, then "en".
            0x02, b'e', b'n', b'h', b'e', b'l', b'l', b'o', 0xFE,
        ]
    );
    assert_eq!(n, text_image_len("hello".len()));
}

/// The container describes the **tag**, not the buffer the image was built in.
///
/// A phone decides from MLEN how much it may write back. Sizing that from a small buffer
/// would tell a phone holding a four-kilobyte transaction that the tag has forty bytes.
#[test]
fn the_container_describes_the_part_not_the_buffer() {
    let mut out = [0u8; 64];
    let n = text_image(&mut out, PART, "ready").unwrap();
    assert!(n < 32, "a short record in a big part is still short");
    assert_eq!(&out[6..8], &[0x03, 0xFF], "1023 blocks, the whole part");
}

/// Past 255 bytes of payload the record takes the four-byte length, and past 254 bytes of
/// record the TLV takes its escape. Both boundaries are where an off-by-one would stop a
/// phone reading the tag at all.
#[test]
fn the_long_forms_appear_exactly_where_they_should() {
    // 254 bytes of text: payload 255, still short; record 259, so the TLV escapes.
    let text = "x".repeat(254);
    let mut out = [0u8; 1024];
    let n = uri_image(&mut out, PART, &text, prefix::HTTPS).unwrap();
    assert_eq!(out[CC_LEN], 0x03);
    assert_eq!(&out[CC_LEN + 1..CC_LEN + 4], &[0xFF, 0x01, 0x03]);
    assert_eq!(out[CC_LEN + 4] & 0x10, 0x10, "still a short record");
    assert_eq!(out[n - 1], 0xFE);

    // One more byte, and the record is no longer short.
    let text = "x".repeat(255);
    let n = uri_image(&mut out, PART, &text, prefix::HTTPS).unwrap();
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
        let n = uri_image(&mut out, PART, &text, prefix::HTTPS).unwrap();
        assert_eq!(n, image_len(len), "uri {len}");
        let n = text_image(&mut out, PART, &text).unwrap();
        assert_eq!(n, text_image_len(len), "text {len}");
    }
}

/// A URI that does not fit is refused with what it needed, rather than writing a tag a
/// phone would read as a truncated address.
#[test]
fn a_uri_too_long_for_the_tag_is_refused() {
    let mut out = [0u8; 32];
    let text = "z".repeat(64);
    assert!(matches!(
        uri_image(&mut out, PART, &text, prefix::HTTPS),
        Err(Error::TooLong { .. })
    ));
    assert!(matches!(
        text_image(&mut out, PART, &text),
        Err(Error::TooLong { .. })
    ));
}

/// Assembling in two steps -- header, text, terminator -- gives the same bytes as one.
#[test]
fn building_it_in_pieces_matches_building_it_whole() {
    let uri = "www.example.com/path?x=1";
    let mut whole = [0u8; 128];
    let n = uri_image(&mut whole, PART, uri, prefix::HTTPS).unwrap();

    let mut parts = [0u8; 128];
    let at = begin(&mut parts, PART, uri.len(), prefix::HTTPS).unwrap();
    parts[at..at + uri.len()].copy_from_slice(uri.as_bytes());
    let m = finish(&mut parts, at + uri.len()).unwrap();
    assert_eq!((&whole[..n], n), (&parts[..m], m));
}

/// The container counts the area in eight-byte blocks, excluding itself: a 8192-byte part
/// carries 8184 bytes of area, which is 1023 blocks.
#[test]
fn the_container_counts_blocks_not_bytes() {
    assert_eq!(
        capability_container(PART),
        [0xE2, 0x40, 0x00, 0x01, 0x00, 0x00, 0x03, 0xFF]
    );
}

/// An empty image is a formatted tag holding nothing: the container, a zero-length NDEF
/// TLV, the terminator. A phone reads it as a blank tag rather than as the last thing this
/// device put there.
#[test]
fn an_empty_image_reads_back_as_no_records() {
    let mut out = [0u8; 16];
    let n = empty_image(&mut out, PART).unwrap();
    assert_eq!(
        &out[..n],
        &[0xE2, 0x40, 0, 1, 0, 0, 0x03, 0xFF, 0x03, 0x00, 0xFE]
    );
    assert_eq!(read(&out[..n]).unwrap().count(), 0);
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/// Collect every record, failing the test on the first parse error.
fn records(image: &[u8]) -> std::vec::Vec<Record<'_>> {
    read(image)
        .expect("a message")
        .map(|r| r.expect("a record"))
        .collect()
}

/// Why `read` refused these bytes. A tag it *accepts* here is the failure.
fn refusal(image: &[u8]) -> ReadError {
    match read(image) {
        Ok(_) => panic!("bytes that are not a message were taken for one"),
        Err(why) => why,
    }
}

/// What this crate writes is what it reads: the round trip is the cheapest statement that
/// the two halves agree about where every field sits.
#[test]
fn what_is_written_is_what_is_read_back() {
    let mut out = [0u8; 256];

    let n = uri_image(&mut out, PART, "a.example/x", prefix::HTTPS).unwrap();
    let got = records(&out[..n]);
    assert_eq!(got.len(), 1);
    assert!(got[0].last);
    assert_eq!(got[0].tnf, TNF_WELL_KNOWN);
    assert_eq!(got[0].uri(), Some(("https://", "a.example/x")));
    assert_eq!(got[0].text(), None, "a URI record is not a text record");

    let n = text_image(&mut out, PART, "tap to send").unwrap();
    let got = records(&out[..n]);
    assert_eq!(got[0].text(), Some("tap to send"));
    assert_eq!(got[0].uri(), None);
}

/// A `bitcoin:` URI has no abbreviation, so it is written whole under prefix zero and
/// comes back whole. This is the address-sharing record, end to end.
#[test]
fn an_unabbreviated_uri_comes_back_whole() {
    let mut out = [0u8; 128];
    let uri = "bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    let n = uri_image(&mut out, PART, uri, prefix::NONE).unwrap();
    assert_eq!(records(&out[..n])[0].uri(), Some(("", uri)));
}

/// The long forms parse too: a payload past 255 bytes carries a four-byte length and the
/// TLV around it carries the escape, and neither is a special case for the reader.
#[test]
fn the_long_forms_read_back_as_well() {
    let text = "q".repeat(1000);
    let mut out = [0u8; 2048];
    let n = text_image(&mut out, PART, &text).unwrap();
    assert_eq!(records(&out[..n])[0].text(), Some(text.as_str()));
}

/// Several records in one message, as a phone writes when it adds an Android
/// application record after the payload: each is returned, and the last one says so.
#[test]
fn a_message_of_several_records_yields_each_of_them() {
    // MB, one short record; then a plain one; then ME.
    let mut message = std::vec::Vec::new();
    message.extend_from_slice(&[0x91, 0x01, 0x01, b'T', 0x00]); // MB+SR, empty-ish text
    message.extend_from_slice(&[0x11, 0x01, 0x02, b'X', 1, 2]); // middle
    message.extend_from_slice(&[0x51, 0x01, 0x01, b'Y', 9]); // ME+SR

    let mut image = std::vec::Vec::from(capability_container(PART));
    image.push(0x03);
    image.push(message.len() as u8);
    image.extend_from_slice(&message);
    image.push(0xFE);

    let got = records(&image);
    assert_eq!(got.len(), 3);
    assert_eq!(got[0].kind, b"T");
    assert_eq!(got[1].payload, &[1, 2]);
    assert_eq!(got[2].payload, &[9]);
    assert!(!got[0].last && !got[1].last && got[2].last);
}

/// A record whose id length is set: the id is skipped and the payload still lands where it
/// should. A phone writing an Android application record produces these.
#[test]
fn a_record_with_an_id_still_finds_its_payload() {
    let mut image = std::vec::Vec::from(capability_container(PART));
    // MB+ME+SR+IL, TNF 2 (MIME): type len 1, payload len 3, id len 2.
    let record = [0xDA, 0x01, 0x03, 0x02, b'm', b'i', b'd', 7, 8, 9];
    image.push(0x03);
    image.push(record.len() as u8);
    image.extend_from_slice(&record);
    image.push(0xFE);

    let got = records(&image);
    assert_eq!(got[0].tnf, TNF_MIME);
    assert_eq!(
        (got[0].kind, got[0].id, got[0].payload),
        (&b"m"[..], &b"id"[..], &[7, 8, 9][..])
    );
}

/// **A record that claims more than is there is refused, not trusted.**
///
/// This is the whole reason the reader exists rather than a few slice indexes at the call
/// site. The payload length is a number a phone wrote; believing it would hand the signing
/// path a slice reaching past the buffer, and clamping it would hand over a transaction
/// that is not the one on the tag.
#[test]
fn a_payload_longer_than_the_buffer_is_refused() {
    let mut image = std::vec::Vec::from(capability_container(PART));
    // Six bytes of record follow, and the record says its payload is 200.
    let record = [0xD1, 0x01, 200, b'T', 0x02, b'e'];
    image.push(0x03);
    image.push(record.len() as u8);
    image.extend_from_slice(&record);
    image.push(0xFE);

    let mut it = read(&image).unwrap();
    assert_eq!(it.next(), Some(Err(ReadError::Truncated)));
    assert_eq!(
        it.next(),
        None,
        "it stops rather than guessing where the next one is"
    );
}

/// The same lie in the four-byte form, which can claim gigabytes.
#[test]
fn a_four_byte_length_claiming_gigabytes_is_refused() {
    let mut image = std::vec::Vec::from(capability_container(PART));
    let record = [0xC1, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, b'T', 0x02, b'e', b'n'];
    image.push(0x03);
    image.push(record.len() as u8);
    image.extend_from_slice(&record);
    image.push(0xFE);

    assert_eq!(
        read(&image).unwrap().next(),
        Some(Err(ReadError::Truncated))
    );
}

/// And the TLV's own length, one level up: a message TLV claiming more than was read is
/// refused before any record is looked at, because the rest of it was never seen.
#[test]
fn a_message_tlv_longer_than_what_was_read_is_refused() {
    let mut image = std::vec::Vec::from(capability_container(PART));
    image.extend_from_slice(&[0x03, 0x40, 0xD1, 0x01, 0x01, b'T']);
    assert_eq!(refusal(&image), ReadError::Truncated);

    // The escaped form too.
    let mut image = std::vec::Vec::from(capability_container(PART));
    image.extend_from_slice(&[0x03, 0xFF, 0x10, 0x00, 0xD1]);
    assert_eq!(refusal(&image), ReadError::Truncated);
}

/// A type or id length that runs off the end is the same refusal: a phone can lie about
/// any of the three, not only the payload.
#[test]
fn a_type_or_id_length_past_the_end_is_refused_too() {
    for record in [
        &[0xD1, 0x40, 0x00, b'T'][..], // type length 64, four bytes present
        &[0xD9, 0x01, 0x00, 0x40, b'T'][..], // id length 64
    ] {
        let mut image = std::vec::Vec::from(capability_container(PART));
        image.push(0x03);
        image.push(record.len() as u8);
        image.extend_from_slice(record);
        image.push(0xFE);
        assert_eq!(
            read(&image).unwrap().next(),
            Some(Err(ReadError::Truncated)),
            "{record:02x?}"
        );
    }
}

/// A text record whose status byte claims a language code longer than the payload does not
/// panic and does not return the wrong bytes as text.
#[test]
fn a_text_record_lying_about_its_language_code_yields_no_text() {
    let mut image = std::vec::Vec::from(capability_container(PART));
    // Payload is four bytes; the status byte claims a 63-byte language code.
    let record = [0xD1, 0x01, 0x04, b'T', 0x3F, b'e', b'n', b'x'];
    image.push(0x03);
    image.push(record.len() as u8);
    image.extend_from_slice(&record);
    image.push(0xFE);
    assert_eq!(records(&image)[0].text(), None);
}

/// Bytes that are not a tag, and a tag with nothing in it, are told apart. "Not formatted"
/// and "formatted and empty" are different things to tell a person.
#[test]
fn what_is_not_a_message_says_which_kind_of_not() {
    assert_eq!(refusal(&[]), ReadError::NoContainer);
    assert_eq!(refusal(&[0xFF; 32]), ReadError::NoContainer);

    // A container and nothing else.
    let mut image = std::vec::Vec::from(capability_container(PART));
    assert_eq!(refusal(&image), ReadError::NoMessage);

    // A container and a terminator: formatted, nothing on it.
    image.push(0xFE);
    assert_eq!(refusal(&image), ReadError::NoMessage);
}

/// The four-byte container form, which a phone may use on a small tag, is read as well --
/// and the TLVs before the message are stepped over rather than mistaken for it.
#[test]
fn the_short_container_and_the_control_tlvs_are_stepped_over() {
    let mut image = std::vec::Vec::from([0xE1, 0x40, 0x0C, 0x00]);
    image.extend_from_slice(&[0x00]); // a null TLV
    image.extend_from_slice(&[0x01, 0x03, 1, 2, 3]); // a lock control TLV
    image.extend_from_slice(&[0x02, 0x03, 4, 5, 6]); // a memory control TLV
    image.extend_from_slice(&[0x03, 0x08, 0xD1, 0x01, 0x04, b'T', 0x02, b'e', b'n', b'!']);
    image.push(0xFE);
    assert_eq!(records(&image)[0].text(), Some("!"));
}

/// A chunked record is refused rather than half-reassembled.
#[test]
fn a_chunked_record_is_refused() {
    let mut image = std::vec::Vec::from(capability_container(PART));
    image.extend_from_slice(&[0x03, 0x05, 0xB1, 0x01, 0x01, b'T', 0x00, 0xFE]);
    assert_eq!(read(&image).unwrap().next(), Some(Err(ReadError::Chunked)));
}

/// A MIME record: TNF 2, the type name spelled out, and the payload untouched. Read
/// back, it is the record the reader's `tnf`/`kind` say it is.
#[test]
fn a_mime_record_round_trips() {
    let mut out = [0u8; 96];
    let payload = [0x00u8, 0xff, 0x10, 0x20];
    let n = mime_image(&mut out, PART, OCTET_STREAM, &payload).unwrap();
    assert_eq!(n, mime_image_len(OCTET_STREAM.len(), payload.len()));
    // Header: MB, ME, SR, TNF 2; then the type length and the one-byte payload length.
    assert_eq!(out[CC_LEN + 2], 0xD2);
    assert_eq!(out[CC_LEN + 3] as usize, OCTET_STREAM.len());
    assert_eq!(out[CC_LEN + 4] as usize, payload.len());
    let mut records = read(&out[..n]).unwrap();
    let r = records.next().unwrap().unwrap();
    assert_eq!(r.tnf, TNF_MIME);
    assert_eq!(r.kind, OCTET_STREAM);
    assert_eq!(r.payload, &payload);
    assert!(r.last);
    assert!(records.next().is_none());
}

/// A type name longer than a byte's worth is refused, not truncated.
#[test]
fn a_type_name_over_255_bytes_is_refused() {
    let mut out = [0u8; 512];
    let long = [b'a'; 256];
    assert_eq!(
        mime_image(&mut out, PART, &long, b"x"),
        Err(Error::TypeTooLong)
    );
}
