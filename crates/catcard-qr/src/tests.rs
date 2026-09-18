//! The frame format, against the one worked example the reference gives.

use super::*;

/// The reference writes this frame out byte for byte, so it is the anchor for all of it.
///
/// `wrap('T_OUT_CVER')` = `5A 00 00 0A 54 5F 4F 55 54 5F 43 56 45 52 12 A5`. If the
/// checksum covered a different span, or the length went out little-endian, everything
/// here would still be self-consistent and the module would simply never answer — which
/// reads as dead hardware, not as a wrong frame. That is why this is pinned to the
/// reference rather than to our own encoder.
///
/// Source: hw-reference/input.md §"QR scanner (Q1)" [C]
#[test]
fn the_version_query_is_the_bytes_the_reference_prints() {
    const WANT: &[u8] = &[
        0x5A, 0x00, 0x00, 0x0A, 0x54, 0x5F, 0x4F, 0x55, 0x54, 0x5F, 0x43, 0x56, 0x45, 0x52, 0x12,
        0xA5,
    ];
    let mut out = [0u8; 64];
    let got = wrap(FID_COMMAND, cmd::VERSION, &mut out).unwrap();
    assert_eq!(got, WANT);
    // And the body really is the ASCII the reference says goes inside the frame.
    assert_eq!(&WANT[4..14], b"T_OUT_CVER");
}

/// The checksum excludes the delimiters. Reading it back proves the span agrees.
#[test]
fn a_frame_round_trips() {
    for body in [
        &b""[..],
        b"OKAY",
        cmd::SCAN_START,
        cmd::BAUD_57600,
        &[0xFFu8; 300][..],
    ] {
        let mut out = [0u8; MAX_PAYLOAD + OVERHEAD];
        let framed = wrap(FID_COMMAND, body, &mut out).unwrap().to_vec();
        let f = unwrap(&framed).unwrap();
        assert_eq!(f.body, body);
        assert_eq!(f.fid, FID_COMMAND);
        assert_eq!(f.used, framed.len());
    }
}

/// One flipped bit anywhere inside the frame is caught.
#[test]
fn a_corrupted_frame_is_refused_rather_than_read() {
    let mut out = [0u8; 64];
    let good = wrap(FID_COMMAND, cmd::VERSION, &mut out).unwrap().to_vec();
    for i in 1..good.len() - 1 {
        let mut bad = good.clone();
        bad[i] ^= 0x01;
        assert!(
            unwrap(&bad).is_err(),
            "a flipped bit at {i} was read as a valid frame"
        );
    }
}

/// A frame that has not all arrived is "not yet", not "broken".
///
/// The distinction is the whole of the read loop: on `Incomplete` it waits for more, and
/// on anything else it resynchronises. Getting it backwards either drops good frames or
/// hangs on bad ones.
#[test]
fn a_partial_frame_says_so() {
    let mut out = [0u8; 64];
    let good = wrap(FID_COMMAND, cmd::VERSION, &mut out).unwrap().to_vec();
    for n in 0..good.len() {
        assert_eq!(
            unwrap(&good[..n]),
            Err(Error::Incomplete),
            "{n} bytes of a {} byte frame should read as incomplete",
            good.len()
        );
    }
    assert!(unwrap(&good).is_ok());
}

/// Bytes that are not a frame at all are distinguished from a short one.
#[test]
fn rubbish_is_not_mistaken_for_a_short_frame() {
    assert_eq!(unwrap(&[0x00, 0x00, 0x00, 0x00]), Err(Error::NotAFrame));
    // Right length, wrong terminator.
    let mut f = [0u8; 16];
    let n = wrap(FID_COMMAND, cmd::VERSION, &mut f).unwrap().len();
    f[n - 1] = 0x00;
    assert_eq!(unwrap(&f[..n]), Err(Error::Unterminated));
}

/// A length past what the module can hold is refused before it is trusted.
#[test]
fn an_impossible_length_is_refused_before_it_is_believed() {
    let big = ((MAX_PAYLOAD + 1) as u16).to_be_bytes();
    let frame = [STX, FID_REPLY, big[0], big[1], 0, 0];
    assert_eq!(unwrap(&frame), Err(Error::TooLong));
    // And wrapping more than fits says so rather than truncating.
    let mut out = [0u8; 8];
    assert_eq!(
        wrap(FID_COMMAND, b"much too long", &mut out),
        Err(Error::TooLong)
    );
}

/// The acknowledgement is a reply-fid frame saying OKAY, and nothing else is.
#[test]
fn only_a_reply_saying_okay_is_an_acknowledgement() {
    let mut out = [0u8; 32];
    let ack = wrap(FID_REPLY, b"OKAY", &mut out).unwrap().to_vec();
    assert!(is_ack(&unwrap(&ack).unwrap()));

    // The same body from the wrong direction is our own command echoed, not an ack.
    let mut out = [0u8; 32];
    let echoed = wrap(FID_COMMAND, b"OKAY", &mut out).unwrap().to_vec();
    assert!(!is_ack(&unwrap(&echoed).unwrap()));

    let mut out = [0u8; 32];
    let other = wrap(FID_REPLY, b"NOPE", &mut out).unwrap().to_vec();
    assert!(!is_ack(&unwrap(&other).unwrap()));
}

/// Two frames back to back are read one at a time, by the length each declares.
#[test]
fn frames_are_read_one_at_a_time_from_a_stream() {
    let mut a = [0u8; 64];
    let mut b = [0u8; 64];
    let one = wrap(FID_REPLY, b"OKAY", &mut a).unwrap().to_vec();
    let two = wrap(FID_REPLY, cmd::VERSION, &mut b).unwrap().to_vec();
    let mut stream = one.clone();
    stream.extend_from_slice(&two);

    let f = unwrap(&stream).unwrap();
    assert_eq!(f.body, b"OKAY");
    let g = unwrap(&stream[f.used..]).unwrap();
    assert_eq!(g.body, cmd::VERSION);
    assert_eq!(f.used + g.used, stream.len());
}
