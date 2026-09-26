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
    let keys = [path(&[44 | H, 60 | H, H, 0, 0]), path(&[44 | H, 60 | H, 1 | H])];
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

#[test]
fn a_page_fits_a_sealed_reply() {
    // Status, total, page and tag, inside the device's 512-byte reply buffer.
    assert!(2 + 4 + PAGE_MAX + crate::ncry::TAG_LEN <= 512);
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
    assert_eq!(read_bitcoin(&out[..n]), Ok((2, &[0xAA, 0xBB][..], &[0xCC][..])));
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
