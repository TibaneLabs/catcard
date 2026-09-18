//! Round trips through a real deflate, and what a hostile block is told.

use super::*;

/// Compress with the same crate that will decompress, as the host tool will.
fn squash(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; data.len() + 1024];
    let mut table = vec![0u16; 4096];
    let n = minizlib::deflate(data, &mut table, Buffer::new(&mut out)).expect("deflate");
    out.truncate(n as usize);
    out
}

/// Firmware-shaped bytes: repetitive enough to compress, not uniform.
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
fn a_block_round_trips() {
    let original = firmwareish(BLOCK);
    let packed = squash(&original);
    assert!(
        packed.len() < original.len(),
        "the fixture does not compress, so this proves nothing"
    );

    let mut out = vec![0u8; BLOCK];
    let n = block(&packed, &mut out, BLOCK as u32).unwrap();
    assert_eq!(n, original.len());
    assert_eq!(&out[..n], &original[..]);
}

/// The last block is short, and is not padded out to a full one.
#[test]
fn a_final_short_block_produces_exactly_its_own_length() {
    let original = firmwareish(1234);
    let packed = squash(&original);
    let mut out = vec![0u8; BLOCK];
    let n = block(&packed, &mut out, 1234).unwrap();
    assert_eq!(n, 1234);
    assert_eq!(&out[..n], &original[..]);
}

/// A whole image, in blocks, reassembles byte for byte.
///
/// The property the transport depends on: blocks are independent, so they can be
/// inflated one at a time as they arrive and appended in order.
#[test]
fn an_image_in_blocks_reassembles_exactly() {
    let image = firmwareish(BLOCK * 3 + 517);
    let mut rebuilt = Vec::new();
    let mut out = vec![0u8; BLOCK];
    for piece in image.chunks(BLOCK) {
        let packed = squash(piece);
        let remaining = (image.len() - rebuilt.len()) as u32;
        let n = block(&packed, &mut out, remaining).unwrap();
        rebuilt.extend_from_slice(&out[..n]);
    }
    assert_eq!(rebuilt, image);
}

/// A block that would produce more than the image has left is refused, not truncated.
///
/// This is the one that matters. The image's length is what the signature was computed
/// over, so a decompressor that can be talked into writing past the end of what was
/// declared is worth more to an attacker than any firmware -- and silently truncating
/// would hide the attempt rather than stop it.
#[test]
fn a_block_that_overruns_the_image_is_refused() {
    let original = firmwareish(BLOCK);
    let packed = squash(&original);
    let mut out = vec![0u8; BLOCK];
    // Only 100 bytes of image left, but the block holds 8 KiB.
    assert_eq!(block(&packed, &mut out, 100), Err(Error::TooLong));
}

/// And a block larger than the output buffer cannot overrun it either.
#[test]
fn a_block_cannot_write_past_the_buffer_it_was_given() {
    let original = firmwareish(BLOCK);
    let packed = squash(&original);
    let mut small = vec![0u8; 512];
    // `remaining` says the image has plenty left; the buffer says otherwise, and the
    // smaller of the two has to win.
    assert_eq!(block(&packed, &mut small, u32::MAX), Err(Error::TooLong));
}

/// Rubbish is refused rather than producing rubbish.
#[test]
fn a_corrupt_block_is_refused() {
    let original = firmwareish(BLOCK);
    let packed = squash(&original);
    let mut out = vec![0u8; BLOCK];

    // Truncated part way.
    let cut = &packed[..packed.len() / 2];
    assert_eq!(block(cut, &mut out, BLOCK as u32), Err(Error::Corrupt));

    // Empty.
    assert_eq!(block(&[], &mut out, BLOCK as u32), Err(Error::Corrupt));

    // Bytes that are not deflate at all.
    let noise: Vec<u8> = (0..200u32).map(|i| (i.wrapping_mul(7)) as u8).collect();
    assert!(block(&noise, &mut out, BLOCK as u32).is_err());
}

/// A flipped bit in the compressed stream does not pass silently as different data.
///
/// Deflate is not a checksum, so some corruptions do decode -- to *something*. The
/// signature over the whole image is what actually catches that, and this records which
/// of the two is doing the work rather than implying this layer is enough.
#[test]
fn a_flipped_bit_is_caught_here_or_by_the_signature() {
    let original = firmwareish(BLOCK);
    let packed = squash(&original);
    let mut out = vec![0u8; BLOCK];
    let mut wrong = 0;
    for i in 0..packed.len().min(200) {
        let mut bad = packed.clone();
        bad[i] ^= 0x01;
        match block(&bad, &mut out, BLOCK as u32) {
            Err(_) => {}
            Ok(n) if out[..n] != original[..] => wrong += 1,
            Ok(_) => {}
        }
    }
    // Not an assertion that every flip is caught here -- it is not, and claiming so
    // would be the bug. It is that decoding to different bytes is a real outcome, which
    // is why the image's signature is checked over what was produced.
    println!("{wrong} of 200 flipped bits decoded to different data");
}

// --- the pushed side: a block taken in pieces, as the transport will take it ---

/// A block inflates the same whether it arrives whole or 62 bytes at a time.
///
/// 62 is what a HID report carries, so this is the real shape of the input.
#[test]
fn a_block_arriving_in_usb_frames_inflates_the_same() {
    let original = firmwareish(BLOCK);
    let packed = squash(&original);

    let mut out = vec![0u8; BLOCK];
    let n = {
        let mut decoder = Block::new(&mut out, BLOCK as u32);
        for frame in packed.chunks(62) {
            assert_eq!(decoder.write(frame).unwrap(), frame.len());
        }
        decoder.finish().unwrap()
    };
    assert_eq!(&out[..n], &original[..]);
}

/// A piece may split anywhere, including inside a symbol, and nothing is lost.
#[test]
fn a_block_split_at_every_offset_inflates_the_same() {
    let original = firmwareish(3000);
    let packed = squash(&original);

    for cut in [1, 2, 3, 7, 13, packed.len() / 2, packed.len() - 1] {
        let mut out = vec![0u8; BLOCK];
        let n = {
            let mut decoder = Block::new(&mut out, 3000);
            decoder.write(&packed[..cut]).unwrap();
            decoder.write(&packed[cut..]).unwrap();
            decoder.finish().unwrap()
        };
        assert_eq!(&out[..n], &original[..], "split at {cut}");
    }
}

/// Blocks delimit themselves, which is why the format carries no lengths.
///
/// The transport hands over whatever arrived; the decoder takes one block's worth and
/// says how much of the piece it used, and the rest starts the next block. If this did
/// not hold, the format would need a length prefix -- and a second opinion about where
/// a block ends is how a decoder gets talked past the end of its buffer.
#[test]
fn concatenated_blocks_split_themselves_without_any_framing() {
    let image = firmwareish(BLOCK * 2 + 517);
    let mut wire = Vec::new();
    for piece in image.chunks(BLOCK) {
        wire.extend_from_slice(&squash(piece));
    }

    let mut rebuilt: Vec<u8> = Vec::new();
    let mut left = &wire[..];
    let mut out = vec![0u8; BLOCK];
    while !left.is_empty() {
        let remaining = (image.len() - rebuilt.len()) as u32;
        let (n, used) = {
            let mut decoder = Block::new(&mut out, remaining);
            let mut used = 0;
            // Feed it in frames; stop the moment it says the stream ended.
            while used < left.len() && !decoder.is_done() {
                let frame = &left[used..(used + 62).min(left.len())];
                used += decoder.write(frame).unwrap();
            }
            (decoder.finish().unwrap(), used)
        };
        rebuilt.extend_from_slice(&out[..n]);
        left = &left[used..];
    }
    assert_eq!(rebuilt, image);
}

/// An upload that stops part way is refused, not accepted as a shorter image.
///
/// The tail of the slab is whatever the last upload left there. Passing a cut-short
/// block on as a complete one would stage that as firmware.
#[test]
fn a_block_that_stops_part_way_is_refused_at_the_end() {
    let original = firmwareish(BLOCK);
    let packed = squash(&original);

    let mut out = vec![0u8; BLOCK];
    let mut decoder = Block::new(&mut out, BLOCK as u32);
    decoder.write(&packed[..packed.len() / 2]).unwrap();
    assert!(!decoder.is_done());
    assert_eq!(decoder.finish(), Err(Error::Corrupt));
}

/// The cap is enforced while the bytes arrive, not once they have been written.
#[test]
fn a_pushed_block_cannot_overrun_the_image_either() {
    let original = firmwareish(BLOCK);
    let packed = squash(&original);

    let mut out = vec![0u8; BLOCK];
    let mut decoder = Block::new(&mut out, 100);
    let refused = packed
        .chunks(62)
        .find_map(|frame| decoder.write(frame).err())
        .expect("a block producing 8 KiB into a 100-byte cap must be refused");
    assert_eq!(refused, Error::TooLong);
}
