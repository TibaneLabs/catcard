//! Tests for the stock-protocol module.
//!
//! The known-answer values below were computed outside this crate, from the formulas in
//! `hw-reference/usb-ckcc-protocol.md` §2, with python-ecdsa, pyaes and Python's own
//! `hashlib`/`hmac` (host scalar `0x22` × 32, device scalar `0x11` × 32). The host half
//! of each round trip is written here separately from [`Link`], so the two cannot share a
//! mistake. Beyond these, the module was driven by the real host library over its
//! simulator socket (`examples/ckcc_sim.rs`): v1, v2 and v3 sessions, a 1500-byte ping, a
//! PSBT upload/sign/download and a firmware upload.

use super::*;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

const HOST_K: [u8; 32] = [0x22; 32];
const DEV_K: [u8; 32] = [0x11; 32];
const HOST_PUB: &str = "466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27\
                        6728176c3c6431f8eeda4538dc37c865e2784f3a9e77d044f33e407797e1278a";
const DEV_PUB: &str = "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa\
                       385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1";
const SESSION: &str = "3b2265dac86fe15fdaa31b1273fb3f8cbfc54663a7298f5e36ddac38e22dd993";

fn host_pub() -> [u8; 64] {
    hex(HOST_PUB).try_into().unwrap()
}

fn linked(version: u32) -> Link {
    let mut l = Link::new();
    let dev = l.handshake(version, &host_pub(), &DEV_K).unwrap();
    assert_eq!(dev.to_vec(), hex(DEV_PUB));
    l
}

/// The host's side of a v1/v2 stream, built directly on the cipher rather than `Stream`.
fn host_ctr(key: &[u8; 32]) -> Ctr<Aes256> {
    Ctr::new(Aes256::new(key), &[0u8; 16])
}

#[test]
fn public_keys_and_the_session_key_match_an_independent_computation() {
    assert_eq!(public_key(&HOST_K).unwrap().to_vec(), hex(HOST_PUB));
    assert_eq!(public_key(&DEV_K).unwrap().to_vec(), hex(DEV_PUB));
    let dev_pub: [u8; 64] = hex(DEV_PUB).try_into().unwrap();
    // ECDH is symmetric: each side's scalar times the other's point.
    assert_eq!(
        session_key(&DEV_K, &host_pub()).unwrap().to_vec(),
        hex(SESSION)
    );
    assert_eq!(
        session_key(&HOST_K, &dev_pub).unwrap().to_vec(),
        hex(SESSION)
    );
    let l = linked(1);
    assert_eq!(l.session_key().unwrap().to_vec(), hex(SESSION));
}

#[test]
fn v1_decrypts_what_the_host_encrypted_and_the_stream_runs_on_across_messages() {
    let mut l = linked(1);
    // Two messages from the host, one keystream: the second starts where the first ended.
    let mut a = hex("4bbb9adc");
    assert_eq!(l.open(&mut a, 4, true), Ok(4));
    assert_eq!(&a, b"vers");
    let mut b = hex("42381d980f011b7c315c6666206cfd");
    assert_eq!(l.open(&mut b, 15, true), Ok(15));
    assert_eq!(&b, b"xpubm/84h/0h/0h");
}

#[test]
fn v1_replies_use_their_own_stream_from_counter_zero() {
    // Stock runs the two directions as two streams under one key, each from zero, so a
    // reply's first bytes use the same keystream the request's did. Weak, and the reason
    // v3 exists -- but it is what the host decrypts with.
    let mut l = linked(1);
    let mut req = hex("4bbb9adc");
    l.open(&mut req, 4, true).unwrap();
    let mut reply = *b"okay";
    assert_eq!(l.seal(&mut reply, 4), Ok(4));
    let key: [u8; 32] = hex(SESSION).try_into().unwrap();
    let mut host = host_ctr(&key);
    host.apply_keystream(&mut reply);
    assert_eq!(&reply, b"okay");
}

#[test]
fn v1_leaves_cleartext_alone_and_allows_a_second_ncry() {
    let mut l = linked(1);
    let mut m = *b"vers";
    assert_eq!(l.open(&mut m, 4, false), Ok(4));
    assert_eq!(&m, b"vers");
    assert!(!l.is_bound());
    // Re-keying is allowed under v1 -- every `ckcc` invocation does it.
    assert!(l.handshake(1, &host_pub(), &DEV_K).is_ok());
}

#[test]
fn v2_binds_the_link() {
    let mut l = linked(2);
    assert!(l.is_bound());
    let mut m = *b"vers";
    assert_eq!(l.open(&mut m, 4, false), Err(Fram::MustEncrypt));
    assert_eq!(
        l.handshake(2, &host_pub(), &DEV_K),
        Err(NcryError::Fram(Fram::AlreadySetUp))
    );
    // Same cipher as v1.
    let mut a = hex("4bbb9adc");
    assert_eq!(l.open(&mut a, 4, true), Ok(4));
    assert_eq!(&a, b"vers");
}

#[test]
fn v3_keys_match_the_independent_hkdf() {
    let sk: [u8; 32] = hex(SESSION).try_into().unwrap();
    let dev: [u8; 64] = hex(DEV_PUB).try_into().unwrap();
    let okm = v3_keys(&sk, &host_pub(), &dev);
    assert_eq!(
        okm.to_vec(),
        hex(concat!(
            "58ce3714691a421dbb6eaaa2a0cab274e73ce6c9365ccf7c11e21d371a0059ff",
            "92f809f312e4af211f539638e8288513f2e674e83a05d149c9a01afa560a4509",
            "57c8ad83483592d3d2b2f2b6b06ab5656c5e3d9c8547876ae5eba78d27f0ba81",
            "c7c8640cd136ea7bd0a78575fda2998ff04ed570073d4b64372a14e5df8adba1"
        ))
    );
}

#[test]
fn v3_opens_a_tagged_message_and_seals_a_tagged_reply() {
    let mut l = linked(3);
    assert!(l.is_bound());
    assert_eq!(l.max_wire(), MAX_WIRE_LEN);
    let mut wire = hex("64ae33f2f21ab402bd9b208ed0049a49f7da3771fd");
    assert_eq!(l.open(&mut wire, 21, true), Ok(5));
    assert_eq!(&wire[..5], b"xpubm");
    let mut reply = [0u8; 6 + TAG_LEN];
    reply[..6].copy_from_slice(b"asciok");
    assert_eq!(l.seal(&mut reply, 6), Ok(6 + TAG_LEN));
    assert_eq!(
        reply.to_vec(),
        hex("c380cbfb7df625f101f2f60d371b6aea98dd2035290b")
    );
}

#[test]
fn v3_refuses_a_tampered_a_replayed_and_a_short_message() {
    let good = hex("64ae33f2f21ab402bd9b208ed0049a49f7da3771fd");

    // One bit of ciphertext: the tag covers it.
    let mut l = linked(3);
    let mut w = good.clone();
    w[0] ^= 1;
    assert_eq!(l.open(&mut w, 21, true), Err(Fram::Auth));

    // One bit of tag.
    let mut l = linked(3);
    let mut w = good.clone();
    w[20] ^= 0x80;
    assert_eq!(l.open(&mut w, 21, true), Err(Fram::Auth));

    // The same message twice: the second is checked against sequence 1 and fails.
    let mut l = linked(3);
    let mut w = good.clone();
    assert!(l.open(&mut w, 21, true).is_ok());
    let mut w = good.clone();
    assert_eq!(l.open(&mut w, 21, true), Err(Fram::Auth));

    // Nothing past the tag, and less than an opcode past it.
    let mut l = linked(3);
    let mut w = [0u8; 16];
    assert_eq!(l.open(&mut w, 16, true), Err(Fram::Auth));
    let mut w = [0u8; 19];
    assert_eq!(l.open(&mut w, 19, true), Err(Fram::BadSz));
}

#[test]
fn a_v3_failure_ends_the_link_and_nothing_opens_after_it() {
    let mut l = linked(3);
    l.failed();
    assert!(l.is_dead());
    let mut w = hex("64ae33f2f21ab402bd9b208ed0049a49f7da3771fd");
    assert_eq!(l.open(&mut w, 21, true), Err(Fram::Auth));
    // A v1 link survives a framing error: stock only ends v3 sessions.
    let mut l = linked(1);
    l.failed();
    assert!(!l.is_dead());
}

#[test]
fn a_dropped_message_forgets_a_v1_session_and_ends_a_bound_one() {
    let mut l = linked(1);
    l.desync();
    assert!(!l.is_encrypted() && !l.is_dead());
    assert!(l.session_key().is_none());
    let mut m = *b"vers";
    assert_eq!(l.open(&mut m, 4, true), Err(Fram::NoKey));
    for v in [2, 3] {
        let mut l = linked(v);
        l.desync();
        assert!(l.is_dead(), "v{v}");
    }
}

#[test]
fn encrypted_without_a_session_is_no_key_and_bad_versions_are_refused() {
    let mut l = Link::new();
    let mut m = *b"vers";
    assert_eq!(l.open(&mut m, 4, true), Err(Fram::NoKey));
    for v in [0, 4, 0x8000_0001] {
        assert_eq!(
            l.handshake(v, &host_pub(), &DEV_K),
            Err(NcryError::Fram(Fram::BadNcryVersion))
        );
    }
    // A point that is not on the curve.
    assert_eq!(l.handshake(1, &[7u8; 64], &DEV_K), Err(NcryError::BadKey));
    assert!(!l.is_encrypted());
}

// ---- framing -------------------------------------------------------------------------

/// Split a message into reports the way the host does: 63 bytes each, the last flagged,
/// the encrypted bit on the last only.
fn host_reports(msg: &[u8], encrypted: bool) -> Vec<[u8; 64]> {
    let mut out = Vec::new();
    let mut at = 0;
    loop {
        let n = (msg.len() - at).min(63);
        let last = at + n == msg.len();
        let mut r = [0xEEu8; 64];
        r[0] = n as u8 | if last { 0x80 } else { 0 } | if last && encrypted { 0x40 } else { 0 };
        r[1..1 + n].copy_from_slice(&msg[at..at + n]);
        out.push(r);
        at += n;
        if last {
            return out;
        }
    }
}

#[test]
fn a_long_message_reassembles_and_its_padding_is_ignored() {
    let msg: Vec<u8> = (0..1500u32).map(|i| i as u8).collect();
    let mut rx = Rx::new();
    let mut buf = vec![0u8; MAX_WIRE_LEN];
    let reports = host_reports(&msg, true);
    assert_eq!(reports.len(), 24);
    for r in &reports[..23] {
        assert_eq!(rx.feed(r, &mut buf, MAX_MSG_LEN), Ok(RxEvent::More));
    }
    assert_eq!(
        rx.feed(&reports[23], &mut buf, MAX_MSG_LEN),
        Ok(RxEvent::Message {
            len: 1500,
            encrypted: true
        })
    );
    assert_eq!(&buf[..1500], &msg[..]);
    assert_eq!(rx.pending(), 0);
}

#[test]
fn an_empty_last_report_is_a_resync_that_drops_a_partial_message() {
    let mut rx = Rx::new();
    let mut buf = vec![0u8; MAX_WIRE_LEN];
    let msg = [0x55u8; 100];
    rx.feed(&host_reports(&msg, false)[0], &mut buf, MAX_MSG_LEN)
        .unwrap();
    assert_eq!(rx.pending(), 63);
    let mut resync = [0xFFu8; 64];
    resync[0] = 0x80;
    assert_eq!(rx.feed(&resync, &mut buf, MAX_MSG_LEN), Ok(RxEvent::Reset));
    assert_eq!(rx.pending(), 0);
}

#[test]
fn too_long_and_too_short_are_framing_errors() {
    let mut rx = Rx::new();
    let mut buf = vec![0u8; MAX_WIRE_LEN];
    // Longer than a v1 message may be.
    let big = vec![0u8; MAX_MSG_LEN + 1];
    let mut got = Ok(RxEvent::More);
    for r in host_reports(&big, false) {
        got = rx.feed(&r, &mut buf, MAX_MSG_LEN);
        if got.is_err() {
            break;
        }
    }
    assert_eq!(got, Err(Fram::XLong));
    assert_eq!(rx.pending(), 0);
    // ...but v3's limit takes its tag.
    let fits = vec![0u8; MAX_WIRE_LEN];
    let mut last = Ok(RxEvent::More);
    for r in host_reports(&fits, true) {
        last = rx.feed(&r, &mut buf, MAX_WIRE_LEN);
    }
    assert_eq!(
        last,
        Ok(RxEvent::Message {
            len: MAX_WIRE_LEN,
            encrypted: true
        })
    );
    // Shorter than an opcode.
    assert_eq!(
        rx.feed(&host_reports(b"ab", false)[0], &mut buf, MAX_MSG_LEN),
        Err(Fram::BadSz)
    );
}

#[test]
fn replies_frame_into_63_byte_reports_with_the_flags_on_the_last() {
    let msg: Vec<u8> = (0..130u8).collect();
    let mut tx = Tx::new();
    let mut r = [0u8; 64];
    let mut got = Vec::new();
    let mut flags = Vec::new();
    while tx.next(&msg, true, &mut r) {
        let n = (r[0] & flag::LEN_MASK) as usize;
        flags.push(r[0] & !flag::LEN_MASK);
        got.extend_from_slice(&r[1..1 + n]);
        // Nothing past the payload: a report never carries what the buffer last held.
        assert!(r[1 + n..].iter().all(|&b| b == 0));
    }
    assert_eq!(got, msg);
    assert_eq!(flags, vec![0, 0, flag::LAST | flag::ENCRYPTED]);
    // And it round-trips through the reassembler.
    let mut rx = Rx::new();
    let mut buf = vec![0u8; 256];
    let mut tx = Tx::new();
    let mut last = Ok(RxEvent::More);
    while tx.next(&msg, false, &mut r) {
        last = rx.feed(&r, &mut buf, 256);
    }
    assert_eq!(
        last,
        Ok(RxEvent::Message {
            len: 130,
            encrypted: false
        })
    );
}

#[test]
fn a_reply_of_exactly_one_report_is_one_report() {
    let mut tx = Tx::new();
    let mut r = [0u8; 64];
    let msg = [1u8; 63];
    assert!(tx.next(&msg, false, &mut r));
    assert_eq!(r[0], 63 | flag::LAST);
    assert!(!tx.next(&msg, false, &mut r));
}

// ---- requests ------------------------------------------------------------------------

#[test]
fn requests_parse_to_their_arguments() {
    let mut ncry = b"ncry".to_vec();
    ncry.extend_from_slice(&3u32.to_le_bytes());
    ncry.extend_from_slice(&host_pub());
    assert_eq!(
        Request::parse(&ncry),
        Ok(Ok(Request::Ncry {
            version: 3,
            host_pub: &host_pub()
        }))
    );

    let mut upld = b"upld".to_vec();
    upld.extend_from_slice(&256u32.to_le_bytes());
    upld.extend_from_slice(&1000u32.to_le_bytes());
    upld.extend_from_slice(b"data");
    assert_eq!(
        Request::parse(&upld),
        Ok(Ok(Request::Upload {
            offset: 256,
            total: 1000,
            data: b"data"
        }))
    );

    let mut smsg = b"smsg".to_vec();
    smsg.extend_from_slice(&af::P2WPKH.to_le_bytes());
    smsg.extend_from_slice(&3u32.to_le_bytes());
    smsg.extend_from_slice(&5u32.to_le_bytes());
    smsg.extend_from_slice(b"m/1hello");
    assert_eq!(
        Request::parse(&smsg),
        Ok(Ok(Request::SignMsg {
            addr_fmt: af::P2WPKH,
            path: "m/1",
            msg: b"hello"
        }))
    );
    // One byte more than the lengths say.
    smsg.push(0);
    assert_eq!(Request::parse(&smsg), Ok(Err(BadArgs::Length)));

    let mut stxn = b"stxn".to_vec();
    stxn.extend_from_slice(&100u32.to_le_bytes());
    stxn.extend_from_slice(&stxn::FINALIZE.to_le_bytes());
    stxn.extend_from_slice(&[9u8; 32]);
    assert_eq!(
        Request::parse(&stxn),
        Ok(Ok(Request::SignTx {
            len: 100,
            flags: stxn::FINALIZE,
            sha: &[9u8; 32]
        }))
    );

    assert_eq!(Request::parse(b"xpubm/84h"), Ok(Ok(Request::Xpub("m/84h"))));
    assert_eq!(Request::parse(b"vers"), Ok(Ok(Request::Version)));
    assert_eq!(Request::parse(b"hsts"), Ok(Ok(Request::HsmStatus)));
    assert_eq!(
        Request::parse(b"mslsname"),
        Ok(Ok(Request::NotDispatched(*b"msls")))
    );
    assert_eq!(Request::parse(b"XKEYy"), Ok(Ok(Request::Unknown(*b"XKEY"))));
}

#[test]
fn bad_shapes_are_refused_not_guessed() {
    assert_eq!(Request::parse(b"ncry"), Ok(Err(BadArgs::Length)));
    assert_eq!(Request::parse(b"dwld\0\0\0\0"), Ok(Err(BadArgs::Length)));
    assert_eq!(Request::parse(b"stxn\0"), Ok(Err(BadArgs::Length)));
    assert_eq!(Request::parse(b"xpub\xff"), Ok(Err(BadArgs::NotText)));
    assert_eq!(Request::parse(b"\x00\x01\x02\x03"), Err(Fram::Decode));
    assert_eq!(Request::parse(b"ab"), Err(Fram::BadSz));
    // A `smsg` whose declared lengths overflow is a length error, not a panic.
    let mut smsg = b"smsg".to_vec();
    smsg.extend_from_slice(&0u32.to_le_bytes());
    smsg.extend_from_slice(&u32::MAX.to_le_bytes());
    smsg.extend_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(Request::parse(&smsg), Ok(Err(BadArgs::Length)));
}

#[test]
fn paths_parse_in_every_spelling_the_host_tools_use() {
    let mut out = [0u32; 8];
    const H: u32 = 0x8000_0000;
    for s in ["m/84'/0'/0'", "m/84h/0h/0h", "84H/0p/0'", "M/84h/0h/0h"] {
        let n = parse_path(s, &mut out).unwrap();
        assert_eq!(&out[..n], &[84 | H, H, H], "{s}");
    }
    assert_eq!(parse_path("m", &mut out), Some(0));
    assert_eq!(parse_path("", &mut out), Some(0));
    let n = parse_path("m/0/1/2", &mut out).unwrap();
    assert_eq!(&out[..n], &[0, 1, 2]);
    for bad in ["m/x", "m//1", "m/1''", "m/2147483648", "m/-1", "m/1/"] {
        assert_eq!(parse_path(bad, &mut out), None, "{bad}");
    }
    let mut short = [0u32; 2];
    assert_eq!(parse_path("m/1/2/3", &mut short), None);
}

#[test]
fn uploads_must_be_aligned_in_order_and_inside_the_file() {
    let mut u = Upload::new();
    let max = 4096;
    assert_eq!(u.check(0, 0, 10, max), Err("File too big"));
    assert_eq!(u.check(0, max + 1, 10, max), Err("File too big"));
    assert_eq!(u.check(100, 1000, 10, max), Err("Offset not aligned"));
    assert_eq!(u.check(256, 1000, 10, max), Err("Out of order"));
    assert_eq!(u.check(0, 100, 101, max), Err("Past end"));
    assert_eq!(
        u.check(0, 3000, MAX_BLK_LEN + 1, max),
        Err("Block too long")
    );

    let a = [1u8; 2048];
    let b = [2u8; 952];
    assert!(u.check(0, 3000, a.len(), max).is_ok());
    u.accept(0, 3000, &a);
    assert!(!u.complete());
    assert_eq!(u.check(0x100, 3000, 10, max), Err("Out of order"));
    assert!(u.check(2048, 3000, b.len(), max).is_ok());
    u.accept(2048, 3000, &b);
    assert!(u.complete());
    let mut h = Sha256::new();
    h.update(&a);
    h.update(&b);
    assert_eq!(u.digest().to_vec(), h.finalize().to_vec());

    // A firmware upgrade appends the header after the image and raises the total: the
    // block is still the next one in order, so it is taken and hashed with the rest.
    assert!(
        u.check(2816, 3128, 128, max).is_err(),
        "not the next offset"
    );
    let mut u2 = Upload::new();
    u2.accept(0, 2048, &a);
    assert!(u2.check(2048, 2176, 128, max).is_ok());
    // ...but never shrunk.
    assert_eq!(u2.check(2048, 2000, 10, max), Err("Out of order"));
    // A new file at zero starts the hash again.
    u.accept(0, 4, b"abcd");
    let mut h = Sha256::new();
    h.update(b"abcd");
    assert_eq!(u.digest().to_vec(), h.finalize().to_vec());
}

#[test]
fn replies_encode_as_the_host_decodes_them() {
    let mut out = [0u8; 256];
    let n = reply::mypb(&mut out, &[7u8; 64], 0x0F05_6943, b"xpub123").unwrap();
    assert_eq!(&out[..4], b"mypb");
    assert_eq!(&out[4..68], &[7u8; 64]);
    assert_eq!(&out[68..72], &0x0F05_6943u32.to_le_bytes());
    assert_eq!(&out[72..76], &7u32.to_le_bytes());
    assert_eq!(&out[76..n], b"xpub123");

    let n = reply::smrx(&mut out, b"bc1q", &[3u8; 65]).unwrap();
    assert_eq!(&out[..8], b"smrx\x04\0\0\0");
    assert_eq!(&out[8..12], b"bc1q");
    assert_eq!(n, 12 + 65);

    let n = reply::strx(&mut out, 500, &[5u8; 32]).unwrap();
    assert_eq!(&out[..8], b"strx\xf4\x01\0\0");
    assert_eq!(n, 40);

    // An error is cut to eighty bytes after its tag, as stock cuts it.
    let long = "x".repeat(200);
    assert_eq!(reply::err(&mut out, &long), Some(4 + ERR_MAX));
    assert_eq!(reply::int1(&mut out, 9), Some(8));
    assert_eq!(&out[..8], b"int1\x09\0\0\0");
    // Too small a buffer is `None`, never a partial reply.
    assert_eq!(reply::asci(&mut [0u8; 6], b"abc"), None);
}
