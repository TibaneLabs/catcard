//! A firmware image sent as independently-deflated blocks.
//!
//! Compressing the upload is worth doing because the transport is slow: a HID report
//! carries 62 bytes, so a half-megabyte image is eight thousand of them. Firmware is
//! mostly code and deflates to roughly two thirds, which comes straight off the wait.
//!
//! # Why blocks, and not one deflate stream
//!
//! A single stream would compress better -- matches could reach back across the whole
//! image rather than stopping at a boundary. It is the wrong shape for this transport
//! anyway.
//!
//! Decompression **pulls**: `minizlib` asks its input for the next byte. USB **pushes**:
//! frames arrive and the firmware is handed them. Reconciling those means one side
//! blocks, and the side that would have to is the USB task, sitting inside an inflate
//! call pumping its own endpoint to feed itself. That is a re-entrancy hazard in the one
//! place on the device where being wrong means writing the wrong firmware.
//!
//! Independent blocks turn the problem around: a block is buffered until it is whole,
//! and then inflated in one call from a slice that is entirely in hand. Nothing blocks,
//! nothing re-enters, and the memory is two fixed buffers rather than a 32 KiB history
//! window. The ratio lost at the boundaries buys all of that.
//!
//! # The format
//!
//! ```text
//! block := <compressed length: u16 little-endian> <deflate data>
//! ```
//!
//! Each block inflates to exactly [`BLOCK`] bytes, except the last, which inflates to
//! whatever is left of the image. Blocks appear in image order and the image's length is
//! already known from the offer, so nothing else needs framing: the decoder knows when
//! it is done because it has produced the bytes it was told to expect.
//!
//! A block that inflates to more than expected is refused rather than truncated. The
//! length is what the signature was computed over, and a decompressor that can be talked
//! into writing past its buffer is worth more to an attacker than any firmware.

use minizlib::{Buffer, inflate};

/// Bytes each block holds once inflated.
///
/// Sets both buffers: one for the compressed block on its way in, one for the inflated
/// bytes on their way out. Bigger compresses better and costs SRAM in a device that has
/// other uses for it; 8 KiB is most of the ratio for a fraction of the window a single
/// stream would need.
pub const BLOCK: usize = 8 * 1024;

/// The most a single compressed block may be.
///
/// Deflate can *grow* incompressible data slightly -- stored blocks carry five bytes of
/// header each -- so this is the block plus room for that, and a host that sends more
/// than this is not speaking the format.
pub const MAX_COMPRESSED: usize = BLOCK + 256;

/// Why a compressed upload could not be unpacked.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// The block did not inflate: truncated, corrupt, or not deflate at all.
    Corrupt,
    /// A block inflated to more than the image has room for. Refused rather than
    /// truncated -- see the module documentation.
    TooLong,
    /// The blocks together produced fewer bytes than the image was declared to be.
    Short { got: u32, want: u32 },
}

/// Inflate one block into `out`, returning how many bytes it produced.
///
/// `remaining` is how much of the image is still to come, and caps what this block may
/// produce: the last block is short, and any block claiming more than the image has left
/// is refused.
pub fn block(compressed: &[u8], out: &mut [u8], remaining: u32) -> Result<usize, Error> {
    let room = (remaining as usize).min(out.len());
    let produced = inflate(compressed, Buffer::new(&mut out[..room])).map_err(|e| match e {
        // The buffer filling up is the interesting one: it means the block wanted to
        // write past what the image can hold, which is the case worth its own name.
        minizlib::Error::OutputFull => Error::TooLong,
        _ => Error::Corrupt,
    })?;
    Ok(produced as usize)
}

#[cfg(test)]
mod tests;
