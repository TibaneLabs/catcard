//! Framing tests.
//!
//! The property that matters most is not that a good transfer reassembles — it is that
//! a bad one is *noticed*. A firmware image arrives as several thousand frames; one
//! dropped or duplicated frame produces an image that differs from the host's by 62
//! bytes, and if the framing does not catch it the only thing left is the signature
//! check, after a quarter of a megabyte has been transferred.

use super::*;

/// Reassemble a whole message, collecting the payload.
fn round_trip(opcode: u16, payload: &[u8]) -> (Message, Vec<u8>) {
    let frames = frames_for(opcode, payload);
    let mut r = Reassembler::new();
    let mut got = Vec::new();
    let mut header = None;
    let mut complete = false;
    for f in &frames {
        let p = r.feed(f).unwrap();
        if let Some(m) = p.started {
            header = Some(m);
        }
        got.extend_from_slice(p.payload);
        complete = p.complete;
    }
    assert!(complete, "never reported complete");
    assert!(!r.in_progress());
    (header.unwrap(), got)
}

/// Encode a message the way a host would.
fn frames_for(opcode: u16, payload: &[u8]) -> Vec<[u8; REPORT_LEN]> {
    let mut out = Vec::new();
    let mut seq = 0u8;
    let n = payload.len().min(START_PAYLOAD);
    let mut f = [0u8; REPORT_LEN];
    f[0] = KIND_START;
    f[1] = seq;
    f[2..4].copy_from_slice(&opcode.to_le_bytes());
    f[4..8].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    f[8..8 + n].copy_from_slice(&payload[..n]);
    out.push(f);
    let mut at = n;
    while at < payload.len() {
        seq = seq.wrapping_add(1);
        let n = (payload.len() - at).min(CONT_PAYLOAD);
        let mut f = [0u8; REPORT_LEN];
        f[0] = KIND_CONT;
        f[1] = seq;
        f[2..2 + n].copy_from_slice(&payload[at..at + n]);
        out.push(f);
        at += n;
    }
    out
}

#[test]
fn a_payload_that_fits_one_frame_needs_one_frame() {
    let (m, got) = round_trip(Opcode::Ping as u16, b"hello");
    assert_eq!(m.total, 5);
    assert_eq!(got, b"hello");
    assert_eq!(frames_for(1, b"hello").len(), 1);
}

#[test]
fn an_empty_payload_completes_on_the_first_frame() {
    // UpgradeCommit carries nothing. If an empty message never reported complete, the
    // device would wait forever for a frame the host is not going to send.
    let (m, got) = round_trip(Opcode::UpgradeCommit as u16, b"");
    assert_eq!(m.total, 0);
    assert!(got.is_empty());
}

#[test]
fn a_payload_exactly_filling_the_first_frame_does_not_ask_for_another() {
    // The boundary that off-by-one lives at.
    let payload: Vec<u8> = (0..START_PAYLOAD).map(|i| i as u8).collect();
    let frames = frames_for(1, &payload);
    assert_eq!(frames.len(), 1);
    let (_, got) = round_trip(1, &payload);
    assert_eq!(got, payload);
}

#[test]
fn one_byte_past_the_first_frame_takes_two() {
    let payload: Vec<u8> = (0..START_PAYLOAD + 1).map(|i| i as u8).collect();
    assert_eq!(frames_for(1, &payload).len(), 2);
    let (_, got) = round_trip(1, &payload);
    assert_eq!(got, payload);
}

#[test]
fn a_firmware_sized_message_reassembles_byte_for_byte() {
    // The real case: 256 KB is about 4,200 frames, and the sequence number wraps
    // sixteen times on the way.
    let payload: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
    let (m, got) = round_trip(Opcode::UpgradeOffer as u16, &payload);
    assert_eq!(m.total, payload.len() as u32);
    assert_eq!(got.len(), payload.len());
    assert_eq!(got, payload);
}

#[test]
fn a_dropped_frame_is_caught_rather_than_silently_shortening_the_image() {
    // Without the sequence check this would produce an image 62 bytes short of what the
    // host sent, and nothing would notice until the digest.
    let payload: Vec<u8> = (0..1000).map(|i| i as u8).collect();
    let frames = frames_for(1, &payload);
    let mut r = Reassembler::new();
    r.feed(&frames[0]).unwrap();
    r.feed(&frames[1]).unwrap();
    // frames[2] goes missing.
    assert_eq!(
        r.feed(&frames[3]),
        Err(FrameError::OutOfSequence {
            expected: 2,
            got: 3
        })
    );
}

#[test]
fn a_repeated_frame_is_caught_too() {
    let payload: Vec<u8> = (0..1000).map(|i| i as u8).collect();
    let frames = frames_for(1, &payload);
    let mut r = Reassembler::new();
    r.feed(&frames[0]).unwrap();
    r.feed(&frames[1]).unwrap();
    assert_eq!(
        r.feed(&frames[1]),
        Err(FrameError::OutOfSequence {
            expected: 2,
            got: 1
        })
    );
}

#[test]
fn a_continuation_with_no_message_open_is_refused() {
    let mut r = Reassembler::new();
    let mut f = [0u8; REPORT_LEN];
    f[0] = KIND_CONT;
    assert_eq!(r.feed(&f), Err(FrameError::NoMessage));
}

#[test]
fn a_new_message_cannot_start_on_top_of_one_in_progress() {
    // Restarting silently would let the front of one firmware image be spliced onto
    // another. The host has to abandon the transfer explicitly.
    let payload: Vec<u8> = (0..1000).map(|i| i as u8).collect();
    let frames = frames_for(1, &payload);
    let mut r = Reassembler::new();
    r.feed(&frames[0]).unwrap();
    assert_eq!(r.feed(&frames[0]), Err(FrameError::Interrupted));
}

#[test]
fn reset_clears_a_message_in_progress() {
    // What a USB reset or an abandoned transfer does. Without it the link would be
    // stuck until the device rebooted.
    let payload: Vec<u8> = (0..1000).map(|i| i as u8).collect();
    let frames = frames_for(1, &payload);
    let mut r = Reassembler::new();
    r.feed(&frames[0]).unwrap();
    assert!(r.in_progress());
    r.reset();
    assert!(!r.in_progress());
    assert!(r.feed(&frames[0]).is_ok());
}

#[test]
fn an_unknown_kind_byte_is_refused() {
    let mut r = Reassembler::new();
    let mut f = [0u8; REPORT_LEN];
    f[0] = 0x7F;
    assert_eq!(r.feed(&f), Err(FrameError::BadKind(0x7F)));
}

#[test]
fn payload_is_trimmed_to_the_declared_total() {
    // A frame is always 64 bytes on the wire, so the last one is padded. Handing the
    // padding to the caller would append junk to every message whose length is not a
    // multiple of the frame payload -- including a firmware image.
    let mut r = Reassembler::new();
    let mut f = [0xAAu8; REPORT_LEN];
    f[0] = KIND_START;
    f[1] = 0;
    f[2..4].copy_from_slice(&1u16.to_le_bytes());
    f[4..8].copy_from_slice(&3u32.to_le_bytes());
    f[8..11].copy_from_slice(b"abc");
    let p = r.feed(&f).unwrap();
    assert_eq!(p.payload, b"abc");
    assert!(p.complete);
}

#[test]
fn the_writer_and_the_reassembler_agree() {
    // The two halves of the protocol, checked against each other rather than against a
    // hand-written expectation of what the bytes should be.
    for len in [
        0usize,
        1,
        START_PAYLOAD - 1,
        START_PAYLOAD,
        START_PAYLOAD + 1,
        5000,
    ] {
        let payload: Vec<u8> = (0..len).map(|i| (i % 253) as u8).collect();
        let mut w = Writer::response(Status::Ok, &payload);
        let mut r = Reassembler::new();
        let mut out = [0u8; REPORT_LEN];
        let mut got = Vec::new();
        let mut complete = false;
        while w.next(&mut out) {
            let p = r.feed(&out).unwrap();
            if let Some(m) = p.started {
                assert_eq!(m.opcode, Status::Ok as u16);
                assert_eq!(m.total as usize, len);
            }
            got.extend_from_slice(p.payload);
            complete = p.complete;
        }
        assert!(complete, "len {len} never completed");
        assert_eq!(got, payload, "len {len}");
    }
}

#[test]
fn the_writer_zeroes_the_tail_of_every_report() {
    // A report is 64 bytes on the wire whatever the payload. Leaving the tail as it was
    // would send the host whatever the buffer previously held, which on a wallet is not
    // an academic concern.
    let mut out = [0xFFu8; REPORT_LEN];
    let mut w = Writer::response(Status::Ok, b"hi");
    assert!(w.next(&mut out));
    assert!(out[10..].iter().all(|&b| b == 0), "stale bytes in the tail");
}

#[test]
fn opcodes_round_trip_and_unknown_ones_stay_unknown() {
    for op in [
        Opcode::Ping,
        Opcode::Identify,
        Opcode::UpgradeOffer,
        Opcode::UpgradeCommit,
    ] {
        assert_eq!(Opcode::from_u16(op as u16), Some(op));
    }
    // An unknown opcode has to reach the caller as a number so it can be answered with
    // UnknownOpcode rather than dropped, which would hang the host.
    assert_eq!(Opcode::from_u16(0xBEEF), None);
    let (m, _) = round_trip(0xBEEF, b"");
    assert_eq!(m.opcode, 0xBEEF);
}
