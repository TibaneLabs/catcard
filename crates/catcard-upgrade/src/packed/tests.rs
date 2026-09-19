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
    let len = BLOCK - 137; // a short final block, not a round number
    let original = firmwareish(len);
    let packed = squash(&original);

    for cut in [1, 2, 3, 7, 13, packed.len() / 2, packed.len() - 1] {
        let mut out = vec![0u8; BLOCK];
        let n = {
            let mut decoder = Block::new(&mut out, len as u32);
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

/// The bytes Python's zlib actually emits, decoded by the code that will meet them.
///
/// Every other test here compresses with `minizlib` and decompresses with `minizlib`,
/// which proves the two halves of one crate agree and nothing about the wire. The host
/// tool compresses with Python's zlib, and two conforming deflate encoders make quite
/// different streams -- different Huffman tables, different block types, different
/// choices about when to stop matching. This is that encoder's output, frozen: three
/// concatenated raw-deflate streams (`wbits=-15`) over 4613 bytes of firmware-shaped data,
/// split into [`BLOCK`]-sized pieces exactly as `pack_image` in `tools/usbclient.py`
/// splits them.
///
/// Made by feeding `firmwareish(BLOCK * 2 + 517)` through `pack_image` and dropping its
/// four-byte length prefix, which belongs to the USB message rather than to the format.
/// Regenerate it if [`BLOCK`] changes -- the fixture is blocks of that size.
#[rustfmt::skip]
const FROM_PYTHON_ZLIB: &[u8] = &[
    37, 201, 99, 24, 21, 6, 0, 133, 225, 155, 125, 179, 109, 108, 105, 153, 203, 181, 236, 182,
    220, 178, 177, 204, 101, 123, 217, 182, 91, 203, 110, 185, 101, 155, 203, 55, 227, 87, 120,
    127, 157, 239, 60, 111, 32, 20, 8, 86, 9, 5, 2, 161, 48, 223, 55, 20, 246, 219, 15, 132,
    194, 125, 237, 96, 32, 20, 158, 69, 96, 17, 89, 36, 22, 153, 69, 97, 81, 89, 52, 22, 157,
    197, 96, 65, 22, 147, 197, 98, 177, 89, 28, 22, 151, 197, 99, 241, 89, 2, 150, 144, 37, 98,
    137, 89, 18, 150, 148, 37, 99, 201, 89, 10, 150, 146, 165, 98, 169, 89, 26, 150, 150, 165,
    99, 233, 89, 6, 150, 145, 101, 98, 153, 89, 22, 246, 3, 251, 145, 101, 101, 217, 88, 118,
    150, 131, 229, 100, 63, 177, 92, 44, 55, 203, 195, 242, 178, 124, 44, 63, 43, 192, 10, 178,
    66, 172, 48, 43, 194, 138, 178, 159, 89, 49, 86, 156, 149, 96, 37, 89, 41, 86, 154, 149,
    97, 101, 89, 57, 246, 11, 43, 207, 42, 176, 138, 172, 18, 171, 204, 170, 176, 170, 172, 26,
    171, 206, 106, 176, 154, 172, 22, 171, 205, 234, 176, 95, 217, 111, 172, 46, 171, 199, 234,
    179, 6, 172, 33, 107, 196, 26, 179, 38, 236, 119, 214, 148, 53, 99, 205, 89, 11, 214, 146,
    181, 98, 173, 89, 27, 214, 150, 181, 99, 237, 89, 7, 214, 145, 117, 98, 157, 89, 23, 246,
    7, 235, 202, 186, 177, 238, 172, 7, 235, 201, 122, 177, 222, 172, 15, 235, 203, 250, 177,
    254, 108, 0, 251, 147, 13, 100, 131, 216, 96, 54, 132, 13, 101, 195, 216, 112, 54, 130,
    141, 100, 163, 216, 104, 54, 134, 141, 101, 227, 216, 120, 54, 129, 77, 100, 147, 216, 100,
    246, 23, 155, 194, 166, 178, 105, 108, 58, 155, 193, 102, 178, 89, 108, 54, 155, 195, 230,
    178, 121, 108, 62, 91, 192, 22, 178, 69, 108, 49, 91, 194, 150, 178, 101, 108, 57, 91, 193,
    86, 178, 85, 108, 53, 91, 195, 214, 178, 117, 108, 61, 219, 192, 54, 178, 77, 108, 51, 251,
    155, 109, 97, 255, 176, 173, 108, 27, 219, 206, 118, 176, 157, 108, 23, 219, 205, 246, 176,
    189, 108, 31, 219, 207, 14, 176, 131, 236, 16, 251, 151, 29, 102, 71, 216, 81, 118, 140,
    29, 103, 39, 216, 73, 118, 138, 253, 199, 78, 179, 51, 236, 44, 59, 199, 206, 179, 11, 236,
    34, 187, 196, 46, 179, 43, 236, 42, 187, 198, 174, 179, 27, 236, 38, 187, 197, 110, 179,
    59, 236, 46, 187, 199, 238, 179, 7, 236, 33, 123, 196, 254, 103, 143, 217, 19, 246, 148,
    61, 99, 207, 217, 11, 246, 146, 133, 216, 43, 246, 154, 189, 97, 111, 217, 59, 246, 158,
    125, 96, 31, 217, 39, 246, 153, 5, 88, 24, 22, 150, 133, 99, 225, 89, 4, 22, 145, 69, 98,
    145, 89, 20, 22, 149, 69, 99, 209, 89, 12, 22, 100, 49, 89, 44, 22, 155, 197, 97, 113, 89,
    60, 22, 159, 37, 96, 9, 89, 34, 150, 152, 37, 97, 73, 89, 50, 150, 156, 165, 96, 41, 89,
    42, 150, 154, 165, 97, 105, 89, 58, 150, 158, 101, 96, 25, 89, 38, 150, 57, 248, 5, 37,
    201, 119, 156, 207, 5, 0, 198, 241, 31, 217, 227, 72, 54, 153, 33, 123, 239, 113, 246, 184,
    195, 185, 179, 87, 246, 222, 43, 137, 80, 246, 46, 187, 148, 236, 189, 55, 37, 123, 43,
    202, 222, 179, 236, 124, 201, 254, 43, 188, 255, 122, 62, 175, 231, 29, 21, 132, 66, 65,
    158, 80, 88, 84, 16, 10, 242, 6, 111, 55, 20, 228, 123, 219, 97, 161, 32, 255, 187, 47, 20,
    20, 96, 5, 89, 33, 86, 152, 21, 97, 69, 89, 49, 86, 156, 149, 96, 37, 89, 41, 86, 154, 149,
    97, 101, 89, 57, 86, 158, 85, 96, 225, 172, 34, 171, 196, 42, 179, 42, 172, 42, 171, 198,
    170, 179, 26, 172, 38, 171, 197, 34, 88, 36, 171, 205, 234, 176, 186, 44, 138, 213, 99,
    209, 44, 134, 213, 103, 13, 88, 67, 214, 136, 53, 102, 77, 88, 83, 214, 140, 53, 103, 45,
    88, 75, 246, 25, 107, 197, 90, 179, 54, 172, 45, 107, 199, 218, 179, 14, 172, 35, 235, 196,
    58, 179, 46, 172, 43, 235, 198, 186, 179, 30, 172, 39, 235, 197, 122, 179, 62, 172, 47,
    235, 199, 250, 179, 1, 236, 115, 54, 144, 125, 193, 6, 177, 47, 217, 96, 54, 132, 125, 197,
    134, 178, 97, 108, 56, 251, 154, 125, 195, 70, 176, 145, 108, 20, 27, 205, 198, 176, 177,
    108, 28, 27, 207, 38, 176, 137, 108, 18, 155, 204, 166, 176, 111, 217, 119, 108, 42, 155,
    198, 166, 179, 25, 108, 38, 155, 197, 102, 179, 239, 217, 15, 108, 14, 251, 145, 253, 196,
    230, 178, 159, 217, 60, 54, 159, 45, 96, 11, 217, 34, 182, 152, 45, 97, 75, 217, 50, 182,
    156, 173, 96, 43, 217, 42, 182, 154, 173, 97, 107, 217, 58, 182, 158, 109, 96, 27, 217, 38,
    182, 153, 109, 97, 91, 217, 54, 182, 157, 237, 96, 191, 176, 95, 217, 78, 246, 27, 219,
    197, 118, 179, 61, 108, 47, 219, 199, 246, 179, 3, 236, 32, 59, 196, 14, 179, 35, 236, 40,
    59, 198, 142, 179, 223, 217, 31, 236, 4, 59, 201, 254, 100, 127, 177, 83, 236, 52, 59, 195,
    206, 178, 115, 236, 60, 187, 192, 46, 178, 75, 236, 50, 187, 194, 174, 178, 107, 236, 58,
    187, 193, 110, 178, 91, 236, 54, 251, 155, 253, 195, 238, 176, 187, 236, 30, 187, 207, 30,
    176, 135, 236, 17, 251, 151, 61, 102, 1, 123, 194, 158, 178, 255, 216, 51, 246, 156, 189,
    96, 47, 217, 43, 246, 154, 189, 97, 33, 22, 139, 197, 102, 31, 176, 56, 44, 46, 139, 199,
    226, 179, 4, 44, 33, 75, 196, 18, 179, 36, 44, 41, 11, 99, 201, 88, 114, 246, 33, 75, 193,
    62, 98, 41, 89, 42, 150, 154, 165, 97, 105, 89, 58, 150, 158, 101, 96, 25, 217, 199, 44,
    19, 203, 204, 178, 176, 172, 44, 27, 203, 206, 62, 97, 57, 88, 78, 150, 139, 125, 202, 114,
    179, 60, 44, 47, 203, 199, 242, 179, 2, 172, 32, 43, 196, 10, 179, 34, 172, 40, 43, 198,
    138, 179, 18, 172, 36, 43, 197, 74, 179, 50, 172, 44, 43, 199, 202, 179, 10, 44, 156, 85,
    100, 149, 88, 101, 86, 133, 85, 101, 213, 88, 117, 86, 131, 213, 100, 181, 88, 4, 139, 100,
    181, 89, 29, 86, 151, 69, 177, 122, 44, 154, 197, 188, 183, 255, 1, 37, 201, 217, 90, 1,
    80, 0, 133, 209, 243, 4, 94, 173, 11, 105, 82, 210, 92, 18, 210, 160, 153, 66, 153, 74,
    146, 132, 30, 242, 60, 66, 124, 235, 106, 255, 223, 94, 49, 25, 18, 75, 49, 196, 229, 56,
    223, 16, 83, 243, 78, 132, 184, 178, 248, 66, 92, 101, 107, 108, 157, 109, 176, 52, 219,
    100, 91, 44, 195, 182, 89, 150, 237, 176, 93, 182, 199, 246, 217, 1, 59, 100, 71, 236, 152,
    157, 176, 28, 59, 101, 121, 118, 198, 10, 172, 200, 74, 236, 156, 149, 217, 5, 187, 100,
    87, 236, 154, 85, 216, 13, 187, 101, 119, 236, 158, 61, 176, 71, 246, 196, 170, 172, 198,
    158, 217, 11, 171, 179, 6, 107, 178, 87, 246, 198, 90, 172, 205, 58, 172, 203, 122, 236,
    157, 125, 176, 62, 251, 100, 3, 246, 197, 134, 236, 155, 141, 216, 15, 27, 179, 95, 54, 97,
    83, 54, 99, 127, 11, 251, 7,
];

#[test]
fn the_streams_the_host_tool_emits_decode_here() {
    let image = firmwareish(BLOCK * 2 + 517);

    let mut rebuilt: Vec<u8> = Vec::new();
    let mut left = FROM_PYTHON_ZLIB;
    let mut out = vec![0u8; BLOCK];
    while !left.is_empty() {
        let remaining = (image.len() - rebuilt.len()) as u32;
        let (n, used) = {
            let mut decoder = Block::new(&mut out, remaining);
            let mut used = 0;
            while used < left.len() && !decoder.is_done() {
                let frame = &left[used..(used + 62).min(left.len())];
                used += decoder.write(frame).unwrap();
            }
            (decoder.finish().unwrap(), used)
        };
        rebuilt.extend_from_slice(&out[..n]);
        left = &left[used..];
    }
    assert_eq!(
        rebuilt, image,
        "the host tool's deflate did not survive the trip"
    );
}
