//! The host-wallet layouts, pinned byte for byte, and every way a reader has to refuse.
//!
//! A host and the device agree on these through `docs/USB.md` and nothing else, so each
//! layout has one test that writes the exact bytes out: a change here is a change a host
//! has to make too, and should read as one in a diff.

use super::*;

const H: u32 = HARDENED;

fn path(steps: &[u32]) -> Path {
    Path::new(steps).unwrap()
}

// ---- paths ------------------------------------------------------------------------

#[test]
fn a_path_has_a_depth_between_one_and_the_bound() {
    assert!(Path::new(&[]).is_none());
    assert!(Path::new(&[0; MAX_DEPTH + 1]).is_none());
    let p = path(&[84 | H, H, H, 0, 3]);
    assert_eq!(p.steps(), &[84 | H, H, H, 0, 3]);
    assert_eq!(p.encoded_len(), 1 + 5 * 4);
}

// ---- requests ---------------------------------------------------------------------

#[test]
fn sign_begin_is_five_bytes_exactly() {
    let b = SignBegin {
        chain: 1,
        length: 0x0102_0304,
    };
    assert_eq!(b.encode(), [1, 4, 3, 2, 1]);
    assert_eq!(SignBegin::decode(&b.encode()), Ok(b));
    assert_eq!(SignBegin::decode(&[1, 4, 3, 2]), Err(Error::Truncated));
    assert_eq!(SignBegin::decode(&[1, 4, 3, 2, 1, 0]), Err(Error::Trailing));
    assert_eq!(SignBegin::decode(&[1, 0, 0, 0, 0]), Err(Error::BadValue));
}

#[test]
fn sign_data_carries_an_offset_and_at_least_one_byte() {
    let d = SignData::decode(&[8, 0, 0, 0, 0xAA, 0xBB]).unwrap();
    assert_eq!(d.offset, 8);
    assert_eq!(d.bytes, &[0xAA, 0xBB]);
    assert_eq!(SignData::decode(&[8, 0, 0, 0]), Err(Error::Truncated));
    assert_eq!(SignData::decode(&[8, 0, 0]), Err(Error::Truncated));

    let mut big = vec![0u8; 4 + DATA_MAX + 1];
    assert_eq!(SignData::decode(&big), Err(Error::TooLong));
    big.pop();
    assert!(SignData::decode(&big).is_ok());

    let mut out = [0u8; 16];
    let n = SignData {
        offset: 0x10,
        bytes: &[1, 2, 3],
    }
    .encode(&mut out)
    .unwrap();
    assert_eq!(&out[..n], &[0x10, 0, 0, 0, 1, 2, 3]);
}

#[test]
fn a_chunk_and_its_header_fit_the_sealed_bound() {
    // opcode + offset + data is the whole plaintext of the largest request.
    assert_eq!(2 + 4 + DATA_MAX, crate::ncry::PLAIN_MAX);
}

#[test]
fn result_offset_and_empty_requests_are_strict() {
    assert_eq!(decode_offset(&[1, 2, 0, 0]), Ok(0x0201));
    assert_eq!(decode_offset(&[1, 2, 0]), Err(Error::Truncated));
    assert_eq!(decode_offset(&[1, 2, 0, 0, 0]), Err(Error::Trailing));
    assert_eq!(decode_empty(&[]), Ok(()));
    assert_eq!(decode_empty(&[0]), Err(Error::Trailing));
}

// ---- the sign blob ----------------------------------------------------------------

#[test]
fn the_sign_blob_layout_is_pinned() {
    let keys = [path(&[84 | H, H, H, 0, 3])];
    let tx = [0x70, 0x73, 0x62, 0x74];
    let mut out = [0u8; 64];
    let n = SignBlob::encode(1, &keys, &tx, &mut out).unwrap();
    #[rustfmt::skip]
    let want: &[u8] = &[
        1,            // version
        1,            // chain: Bitcoin
        1,            // one key
        5,            // depth
        84, 0, 0, 0x80,  0, 0, 0, 0x80,  0, 0, 0, 0x80,  0, 0, 0, 0,  3, 0, 0, 0,
        4, 0, 0, 0,   // tx length
        0x70, 0x73, 0x62, 0x74,
    ];
    assert_eq!(&out[..n], want);

    let blob = SignBlob::decode(want).unwrap();
    assert_eq!(blob.chain, 1);
    assert_eq!(blob.keys(), &keys);
    assert_eq!(blob.tx, &tx);
    assert_eq!(&want[blob.tx_at..], &tx);
}

#[test]
fn the_sign_blob_refuses_what_a_host_got_wrong() {
    let keys = [
        path(&[44 | H, 60 | H, H, 0, 0]),
        path(&[44 | H, 60 | H, 1 | H]),
    ];
    let tx = [9u8; 10];
    let mut out = [0u8; 128];
    let n = SignBlob::encode(2, &keys, &tx, &mut out).unwrap();
    let good = &out[..n];
    assert!(SignBlob::decode(good).is_ok());

    // Every truncation of it.
    for cut in 0..n {
        assert!(SignBlob::decode(&good[..cut]).is_err(), "cut at {cut}");
    }
    // A trailing byte.
    let mut long = good.to_vec();
    long.push(0);
    assert_eq!(SignBlob::decode(&long).unwrap_err(), Error::Trailing);
    // A version this build does not read.
    let mut v = good.to_vec();
    v[0] = 2;
    assert_eq!(SignBlob::decode(&v).unwrap_err(), Error::Version);
    // No keys, and too many.
    let mut none = good.to_vec();
    none[2] = 0;
    assert_eq!(SignBlob::decode(&none).unwrap_err(), Error::KeyCount);
    let mut many = good.to_vec();
    many[2] = MAX_KEYS as u8 + 1;
    assert_eq!(SignBlob::decode(&many).unwrap_err(), Error::KeyCount);
    // A path of depth zero, and one too deep.
    let mut zero = good.to_vec();
    zero[3] = 0;
    assert_eq!(SignBlob::decode(&zero).unwrap_err(), Error::BadPath);
    let mut deep = good.to_vec();
    deep[3] = MAX_DEPTH as u8 + 1;
    assert_eq!(SignBlob::decode(&deep).unwrap_err(), Error::BadPath);
    // An empty transaction.
    assert_eq!(
        SignBlob::encode(2, &keys, &[], &mut out),
        Err(Error::BadValue)
    );
    // A buffer too small to write into.
    assert_eq!(
        SignBlob::encode(2, &keys, &tx, &mut [0u8; 8]),
        Err(Error::NoRoom)
    );
}

#[test]
fn the_sign_blob_takes_the_most_keys_and_no_more() {
    let keys = [path(&[86 | H, H, H, 0, 0]); MAX_KEYS];
    let mut out = vec![0u8; 4096];
    let n = SignBlob::encode(1, &keys, &[1], &mut out).unwrap();
    assert_eq!(SignBlob::decode(&out[..n]).unwrap().keys().len(), MAX_KEYS);
    let too_many = [path(&[86 | H]); MAX_KEYS + 1];
    assert_eq!(
        SignBlob::encode(1, &too_many, &[1], &mut out),
        Err(Error::KeyCount)
    );
}

// ---- paging -----------------------------------------------------------------------

#[test]
fn a_result_pages_out_whole_and_says_where_it_ends() {
    let result: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
    let mut out = [0u8; 4 + PAGE_MAX];
    let mut got = Vec::new();
    let mut offset = 0u32;
    let mut pages = 0;
    loop {
        let (n, last) = page(&result, offset, &mut out).unwrap();
        let (total, bytes) = read_page(&out[..n]).unwrap();
        assert_eq!(total, 1000);
        assert!(bytes.len() <= PAGE_MAX);
        got.extend_from_slice(bytes);
        offset += bytes.len() as u32;
        pages += 1;
        if last {
            break;
        }
    }
    assert_eq!(got, result);
    assert_eq!(pages, 3);
}

#[test]
fn a_page_is_bounded_by_its_buffer_and_by_the_end() {
    let result = [7u8; 100];
    // A buffer smaller than a page: the page shrinks to fit.
    let mut small = [0u8; 4 + 10];
    let (n, last) = page(&result, 0, &mut small).unwrap();
    assert_eq!(n, 14);
    assert!(!last);
    // Exactly at the end: an empty last page, not a refusal.
    let mut out = [0u8; 64];
    let (n, last) = page(&result, 100, &mut out).unwrap();
    assert_eq!(n, 4);
    assert!(last);
    // Past it: refused.
    assert_eq!(page(&result, 101, &mut out), Err(Error::BadValue));
    // No room even for the total.
    assert_eq!(page(&result, 0, &mut [0u8; 3]), Err(Error::NoRoom));
    // A reply claiming more than its total is refused on read.
    assert_eq!(read_page(&[1, 0, 0, 0, 9, 9]), Err(Error::TooLong));
    assert_eq!(read_page(&[1, 0, 0]), Err(Error::Truncated));
}

// ---- the address reply ------------------------------------------------------------

fn utxo_entry<'a>(xpub: &'a [u8], address: &'a [u8], pubkey: &'a [u8]) -> Entry<'a> {
    Entry {
        shape: shape::UTXO,
        chain: 1,
        format: format::P2WPKH,
        account_path: path(&[84 | H, H, H]),
        address_path: path(&[84 | H, H, H, 0, 0]),
        xpub,
        address,
        pubkey,
    }
}

#[test]
fn the_address_reply_layout_is_pinned() {
    let mut out = [0u8; 256];
    let mut w = AddressWriter::new(&mut out, [0xde, 0xad, 0xbe, 0xef], 7).unwrap();
    w.push(&utxo_entry(b"xpub", b"bc1q", &[2, 3])).unwrap();
    w.push(&Entry {
        shape: shape::ACCOUNT,
        chain: 3,
        format: format::SOLANA,
        account_path: path(&[44 | H, 501 | H, 7 | H]),
        address_path: path(&[44 | H, 501 | H, 7 | H, H]),
        xpub: &[],
        address: b"So1",
        pubkey: &[9],
    })
    .unwrap();
    let n = w.finish();
    #[rustfmt::skip]
    let want: &[u8] = &[
        kind::ADDRESSES, VERSION, 0xde, 0xad, 0xbe, 0xef, 7, 0, 0, 0, 2,
        // entry 1: UTXO, Bitcoin, P2WPKH
        shape::UTXO, 1, format::P2WPKH,
        3, 84, 0, 0, 0x80, 0, 0, 0, 0x80, 0, 0, 0, 0x80,
        5, 84, 0, 0, 0x80, 0, 0, 0, 0x80, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0,
        4, b'x', b'p', b'u', b'b',
        4, b'b', b'c', b'1', b'q',
        2, 2, 3,
        // entry 2: account, Solana: no xpub field at all
        shape::ACCOUNT, 3, format::SOLANA,
        3, 44, 0, 0, 0x80, 0xf5, 1, 0, 0x80, 7, 0, 0, 0x80,
        4, 44, 0, 0, 0x80, 0xf5, 1, 0, 0x80, 7, 0, 0, 0x80, 0, 0, 0, 0x80,
        3, b'S', b'o', b'1',
        1, 9,
    ];
    assert_eq!(&out[..n], want);

    let r = Addresses::decode(want).unwrap();
    assert_eq!(r.fingerprint, [0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(r.account, 7);
    let all: Vec<Entry<'_>> = r.entries().collect();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].xpub, b"xpub");
    assert_eq!(all[1].xpub, b"");
    assert_eq!(all[1].address_path.steps(), &[44 | H, 501 | H, 7 | H, H]);
}

#[test]
fn the_address_reply_refuses_truncation_and_trailing_bytes() {
    let mut out = [0u8; 256];
    let mut w = AddressWriter::new(&mut out, [1, 2, 3, 4], 0).unwrap();
    w.push(&utxo_entry(b"tpubX", b"tb1q", &[2; 33])).unwrap();
    let n = w.finish();
    let good = &out[..n];
    assert!(Addresses::decode(good).is_ok());
    for cut in 0..n {
        assert!(Addresses::decode(&good[..cut]).is_err(), "cut at {cut}");
    }
    let mut long = good.to_vec();
    long.push(0);
    assert_eq!(Addresses::decode(&long).unwrap_err(), Error::Trailing);
    let mut shape_bad = good.to_vec();
    shape_bad[ADDRESS_HEAD] = 9;
    assert_eq!(Addresses::decode(&shape_bad).unwrap_err(), Error::BadValue);
}

#[test]
fn a_utxo_entry_without_its_xpub_is_not_written() {
    let mut out = [0u8; 256];
    let mut w = AddressWriter::new(&mut out, [0; 4], 0).unwrap();
    assert_eq!(
        w.push(&utxo_entry(b"", b"bc1q", &[2])),
        Err(Error::BadValue)
    );
    assert_eq!(w.count(), 0);
}

#[test]
fn an_entry_that_does_not_fit_leaves_the_reply_whole() {
    let mut out = [0u8; ADDRESS_HEAD + 30];
    let mut w = AddressWriter::new(&mut out, [0; 4], 0).unwrap();
    assert_eq!(
        w.push(&utxo_entry(b"xpub", b"bc1q", &[2; 33])),
        Err(Error::NoRoom)
    );
    let n = w.finish();
    assert_eq!(n, ADDRESS_HEAD);
    let r = Addresses::decode(&out[..n]).unwrap();
    assert_eq!(r.count, 0);
}

// ---- sign results -----------------------------------------------------------------

#[test]
fn the_bitcoin_result_layout_is_pinned() {
    let mut out = [0u8; 32];
    let n = write_bitcoin(&mut out, 2, &[0xAA, 0xBB], &[0xCC]).unwrap();
    assert_eq!(n, bitcoin_len(2, 1));
    assert_eq!(
        &out[..n],
        &[kind::BITCOIN, 2, 2, 0, 0, 0, 0xAA, 0xBB, 1, 0, 0, 0, 0xCC]
    );
    assert_eq!(
        read_bitcoin(&out[..n]),
        Ok((2, &[0xAA, 0xBB][..], &[0xCC][..]))
    );
    // An unfinished transaction is an empty tx field, not a missing one.
    let n = write_bitcoin(&mut out, 0, &[1], &[]).unwrap();
    assert_eq!(read_bitcoin(&out[..n]), Ok((0, &[1][..], &[][..])));
    assert_eq!(write_bitcoin(&mut out, 1, &[1], &[]), Err(Error::BadValue));
    for cut in 0..n {
        assert!(read_bitcoin(&out[..cut]).is_err());
    }
    let mut long = out[..n].to_vec();
    long.push(0);
    assert_eq!(read_bitcoin(&long), Err(Error::Trailing));
}

#[test]
fn the_evm_result_layout_is_pinned() {
    let mut out = [0u8; 16];
    let n = write_evm(&mut out, &[2, 0xf8]).unwrap();
    assert_eq!(&out[..n], &[kind::EVM, 2, 0, 0, 0, 2, 0xf8]);
    assert_eq!(read_evm(&out[..n]), Ok(&[2, 0xf8][..]));
    assert_eq!(read_evm(&out[..n - 1]), Err(Error::Truncated));
    let mut long = out[..n].to_vec();
    long.push(0);
    assert_eq!(read_evm(&long), Err(Error::Trailing));
}

#[test]
fn the_solana_result_layout_is_pinned() {
    let sig = [0x55u8; 64];
    let mut out = [0u8; 128];
    let n = write_solana(&mut out, &[(1, sig)], &[0xEE]).unwrap();
    let mut want = vec![kind::SOLANA, 1, 1];
    want.extend_from_slice(&sig);
    want.extend_from_slice(&[1, 0, 0, 0, 0xEE]);
    assert_eq!(&out[..n], &want[..]);
    let (sigs, tx) = read_solana(&out[..n]).unwrap();
    assert_eq!(sigs.len(), 65);
    assert_eq!(sigs[0], 1);
    assert_eq!(tx, &[0xEE]);
    for cut in 0..n {
        assert!(read_solana(&out[..cut]).is_err());
    }
}

#[test]
fn results_refuse_a_buffer_too_small() {
    assert_eq!(write_evm(&mut [0u8; 4], &[1]), Err(Error::NoRoom));
    assert_eq!(
        write_bitcoin(&mut [0u8; 8], 0, &[1, 2, 3], &[]),
        Err(Error::NoRoom)
    );
    assert_eq!(
        write_solana(&mut [0u8; 8], &[(0, [0; 64])], &[1]),
        Err(Error::NoRoom)
    );
}

// ---- one address by its path --------------------------------------------------------

#[test]
fn the_address_at_request_layout_is_pinned() {
    let req = AddressAt {
        chain: 1,
        format: format::P2TR,
        flags: ask::SHOW,
        path: path(&[86 | H, H, H, 0, 5]),
    };
    let mut out = [0u8; 64];
    let n = req.encode(&mut out).unwrap();
    #[rustfmt::skip]
    let want: &[u8] = &[
        1, format::P2TR, 1,
        5, 86, 0, 0, 0x80, 0, 0, 0, 0x80, 0, 0, 0, 0x80, 0, 0, 0, 0, 5, 0, 0, 0,
    ];
    assert_eq!(&out[..n], want);
    assert_eq!(AddressAt::decode(want), Ok(req));
}

#[test]
fn the_address_at_request_refuses_what_a_host_got_wrong() {
    let good: &[u8] = &[2, format::EVM, 0, 1, 44, 0, 0, 0x80];
    assert!(AddressAt::decode(good).is_ok());
    // Every truncation, and one byte too many.
    for cut in 0..good.len() {
        assert!(AddressAt::decode(&good[..cut]).is_err(), "cut at {cut}");
    }
    let mut long = good.to_vec();
    long.push(0);
    assert_eq!(AddressAt::decode(&long), Err(Error::Trailing));
    // A flag bit this build does not read is refused, not ignored: a host that set it
    // meant something by it.
    let mut flagged = good.to_vec();
    flagged[2] = 0x02;
    assert_eq!(AddressAt::decode(&flagged), Err(Error::BadValue));
    // No path, and a path past the bound.
    assert_eq!(AddressAt::decode(&[2, 5, 0, 0]), Err(Error::BadPath));
    let mut deep = vec![2, 5, 0, (MAX_DEPTH + 1) as u8];
    deep.extend(core::iter::repeat_n(0u8, 4 * (MAX_DEPTH + 1)));
    assert_eq!(AddressAt::decode(&deep), Err(Error::BadPath));
}

#[test]
fn the_address_by_path_reply_layout_is_pinned() {
    let reply = AddressReply {
        fingerprint: [0xde, 0xad, 0xbe, 0xef],
        chain: 2,
        format: format::EVM,
        path: path(&[44 | H, 60 | H, H, 0, 9]),
        address: b"0xAb",
        pubkey: &[2, 7],
    };
    let mut out = [0u8; 64];
    let n = reply.encode(&mut out).unwrap();
    #[rustfmt::skip]
    let want: &[u8] = &[
        kind::ADDRESS, VERSION, 0xde, 0xad, 0xbe, 0xef, 2, format::EVM,
        5, 44, 0, 0, 0x80, 60, 0, 0, 0x80, 0, 0, 0, 0x80, 0, 0, 0, 0, 9, 0, 0, 0,
        4, b'0', b'x', b'A', b'b',
        2, 2, 7,
    ];
    assert_eq!(&out[..n], want);
    assert_eq!(AddressReply::decode(want), Ok(reply));
    for cut in 0..want.len() {
        assert!(AddressReply::decode(&want[..cut]).is_err(), "cut at {cut}");
    }
    let mut long = want.to_vec();
    long.push(0);
    assert_eq!(AddressReply::decode(&long), Err(Error::Trailing));
    // The many-address reply is a different kind, and is not read as this one.
    let mut other = want.to_vec();
    other[0] = kind::ADDRESSES;
    assert_eq!(AddressReply::decode(&other), Err(Error::BadValue));
}

// ---- messages -------------------------------------------------------------------------

#[test]
fn the_sign_message_request_layout_is_pinned() {
    let req = SignMessage {
        chain: 1,
        format: format::P2WPKH,
        scheme: scheme::BIP322,
        path: path(&[84 | H, H, H, 0, 3]),
        message: b"hi",
    };
    let mut out = [0u8; 64];
    let n = req.encode(&mut out).unwrap();
    #[rustfmt::skip]
    let want: &[u8] = &[
        VERSION, 1, format::P2WPKH, scheme::BIP322,
        5, 84, 0, 0, 0x80, 0, 0, 0, 0x80, 0, 0, 0, 0x80, 0, 0, 0, 0, 3, 0, 0, 0,
        2, 0, b'h', b'i',
    ];
    assert_eq!(&out[..n], want);
    assert_eq!(SignMessage::decode(want), Ok(req));
}

#[test]
fn the_sign_message_request_refuses_what_a_host_got_wrong() {
    #[rustfmt::skip]
    let good: &[u8] = &[
        VERSION, 2, format::EVM, scheme::EIP191,
        1, 44, 0, 0, 0x80,
        3, 0, b'a', b'\n', b'b',
    ];
    assert!(SignMessage::decode(good).is_ok());
    for cut in 0..good.len() {
        assert!(SignMessage::decode(&good[..cut]).is_err(), "cut at {cut}");
    }
    let mut long = good.to_vec();
    long.push(b'c');
    assert_eq!(SignMessage::decode(&long), Err(Error::Trailing));
    let mut v = good.to_vec();
    v[0] = VERSION + 1;
    assert_eq!(SignMessage::decode(&v), Err(Error::Version));
    // An empty message is not a message.
    #[rustfmt::skip]
    let empty: &[u8] = &[VERSION, 2, format::EVM, scheme::EIP191, 1, 44, 0, 0, 0x80, 0, 0];
    assert_eq!(SignMessage::decode(empty), Err(Error::BadValue));
}

#[test]
fn the_longest_message_fits_one_sealed_record_and_one_more_byte_is_refused() {
    let deep = path(&[H; MAX_DEPTH]);
    let text = vec![b'x'; MESSAGE_MAX + 1];
    let mut out = vec![0u8; 2048];
    let req = SignMessage {
        chain: 2,
        format: format::EVM,
        scheme: scheme::EIP191,
        path: deep,
        message: &text[..MESSAGE_MAX],
    };
    let n = req.encode(&mut out).unwrap();
    // The opcode travels in the same record.
    assert!(2 + n <= ncry::PLAIN_MAX);
    assert_eq!(SignMessage::decode(&out[..n]), Ok(req));

    let over = SignMessage {
        message: &text,
        ..req
    };
    assert_eq!(over.encode(&mut out), Err(Error::TooLong));
    // And a host that sends it anyway: the declared length alone refuses it.
    let mut raw = out[..n].to_vec();
    let at = 4 + deep.encoded_len();
    raw[at..at + 2].copy_from_slice(&((MESSAGE_MAX + 1) as u16).to_le_bytes());
    raw.push(b'x');
    assert_eq!(SignMessage::decode(&raw), Err(Error::TooLong));
}

#[test]
fn the_message_result_layout_is_pinned() {
    let reply = MessageReply {
        chain: 2,
        scheme: scheme::EIP191,
        path: path(&[44 | H, 60 | H, H, 0, 0]),
        address: b"0xAb",
        signature: &[0xAA, 0xBB, 27],
    };
    let mut out = [0u8; 64];
    let n = reply.encode(&mut out).unwrap();
    #[rustfmt::skip]
    let want: &[u8] = &[
        kind::MESSAGE, VERSION, 2, scheme::EIP191,
        5, 44, 0, 0, 0x80, 60, 0, 0, 0x80, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0,
        4, b'0', b'x', b'A', b'b',
        3, 0, 0xAA, 0xBB, 27,
    ];
    assert_eq!(&out[..n], want);
    assert_eq!(MessageReply::decode(want), Ok(reply));
    assert!(n <= MessageReply::max_len(4, 3));
    for cut in 0..want.len() {
        assert!(MessageReply::decode(&want[..cut]).is_err(), "cut at {cut}");
    }
    let mut long = want.to_vec();
    long.push(0);
    assert_eq!(MessageReply::decode(&long), Err(Error::Trailing));
    // Too small a buffer is an error, never a short write.
    assert_eq!(reply.encode(&mut out[..n - 1]), Err(Error::NoRoom));
}

// ---- what this build answers ----------------------------------------------------------

#[test]
fn the_info_reply_layout_is_pinned() {
    let mut out = [0u8; 64];
    let mut w = InfoWriter::new(
        &mut out,
        feature::ADDRESS_AT | feature::SIGN_MESSAGE,
        session::SHARED,
    )
    .unwrap();
    w.push(
        1,
        can::ADDRESSES | can::SIGN | can::MESSAGES,
        &[format::P2WPKH, format::P2TR],
    )
    .unwrap();
    w.push(9, can::ADDRESSES, &[format::TRON]).unwrap();
    let n = w.finish();
    #[rustfmt::skip]
    let want: &[u8] = &[
        VERSION, 0b11, 0b10, 0xC0, 0x03, 2,
        1, 0b111, 2, format::P2WPKH, format::P2TR,
        9, 0b001, 1, format::TRON,
    ];
    assert_eq!(MESSAGE_MAX, 0x03C0);
    assert_eq!(&out[..n], want);

    let r = Info::decode(want).unwrap();
    assert_eq!(r.features, 0b11);
    assert_eq!(r.session, session::SHARED);
    assert_eq!(r.message_max as usize, MESSAGE_MAX);
    let all: Vec<ChainInfo<'_>> = r.chains().collect();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].formats, &[format::P2WPKH, format::P2TR]);
    assert_eq!(all[1].can, can::ADDRESSES);

    for cut in 0..want.len() {
        assert!(Info::decode(&want[..cut]).is_err(), "cut at {cut}");
    }
    let mut long = want.to_vec();
    long.push(0);
    assert_eq!(Info::decode(&long).err(), Some(Error::Trailing));
}

#[test]
fn a_chain_that_does_not_fit_leaves_the_info_reply_whole() {
    let mut out = [0u8; INFO_HEAD + 4];
    let mut w = InfoWriter::new(&mut out, 0, 0).unwrap();
    w.push(1, can::ADDRESSES, &[format::P2WPKH]).unwrap();
    assert_eq!(
        w.push(2, can::ADDRESSES, &[format::EVM]),
        Err(Error::NoRoom)
    );
    let n = w.finish();
    let r = Info::decode(&out[..n]).unwrap();
    assert_eq!(r.count, 1);
}
