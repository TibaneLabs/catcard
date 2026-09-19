//! A firmware image sent as independently-deflated blocks.
//!
//! Compressing the upload is worth doing because the transport is slow: a HID report
//! carries 62 bytes, so a half-megabyte image is eight thousand of them. Firmware is
//! mostly code and deflates to roughly two thirds, which comes straight off the wait.
//!
//! # Why blocks, and not one deflate stream
//!
//! A single stream compresses better, and the gap is small enough to measure rather
//! than argue about: a real image goes to 64.4% in [`BLOCK`]-sized blocks against 63.7%
//! as one stream with deflate's full 32 KiB window.
//!
//! The reason is not that decompression cannot be fed a frame at a time -- it can, and
//! this module does exactly that. It is that **a decompressor owns its output and never
//! gives it back.** A single stream's decompressor would have to live across USB frames,
//! in the same session state that owns the staging area, writing into the staging area
//! through a sink it holds -- a value borrowing the thing stored beside it. That shape
//! is a self-reference, and the ways out of it are a global or a raw pointer, in the one
//! place on the device where being wrong means writing the wrong firmware.
//!
//! Independent blocks dissolve it. A block's output is bounded by construction, so it
//! can be a plain [`Buffer`] over a fixed slab: the decoder borrows the slab, the stream
//! ends, and the caller reads the bytes straight out of it. Nothing is self-referential,
//! nothing is global, and the memory is one slab rather than a 32 KiB history window --
//! which on this device is the whole argument, since the slab comes out of the stack's
//! headroom and there are only a few kilobytes of it.
//!
//! # The format
//!
//! ```text
//! image := <deflate stream> ...
//! ```
//!
//! Each stream inflates to exactly [`BLOCK`] bytes, except the last, which inflates to
//! whatever is left of the image. Nothing frames them: deflate marks its own final block,
//! so [`Block::write`] reports what it consumed and leaves the rest for the next one, and
//! the image's length -- already known from the offer -- says when the last one has been
//! seen. A length prefix would only be a second opinion about a boundary the data already
//! carries, and two sources of truth about a length is how a decoder gets talked past the
//! end of its buffer.
//!
//! A block that inflates to more than expected is refused rather than truncated. The
//! length is what the signature was computed over, and a decompressor that can be talked
//! into writing past its buffer is worth more to an attacker than any firmware.

use minizlib::{Buffer, Decompressor, Raw};

/// Bytes each block holds once inflated.
///
/// This is the output slab, and the window a block's matches may reach back into. Bigger
/// compresses better; it also comes straight out of the stack's headroom, and on the Q1
/// there is far less of that than the numbers suggest.
///
/// **2 KiB, and the reason is a bug this caused.** At 8 KiB the slab left the main stack
/// 5,996 bytes before it ran into the top of `.bss`, which is not enough for the seed
/// stretch: it overflowed, walked down over the statics living there, and the device
/// panicked in the middle of reading a wallet. The visible symptom was the status bar's
/// modifier flags flickering -- `MODIFIERS` sits 7,407 bytes below the stack top and was
/// simply being overwritten by whatever the stretch had on its stack.
///
/// The ratio this costs, measured on the real 535,040-byte Q1 image: **64.4% in 2 KiB
/// blocks against 60.4% in 8 KiB ones**. Four points, for six kilobytes of stack, in a
/// device with 192 KB of SRAM in total that had six thousand bytes of margin.
pub const BLOCK: usize = 2 * 1024;

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

impl From<minizlib::Error> for Error {
    fn from(error: minizlib::Error) -> Self {
        match error {
            // The slab filling up is the interesting one: it means the block wanted to
            // write past what the image can hold, which is the case worth its own name.
            minizlib::Error::OutputFull => Error::TooLong,
            // Everything else is a stream that does not decode, including one that
            // stopped early -- an upload cut short is corrupt, not a shorter image.
            _ => Error::Corrupt,
        }
    }
}

/// One block of the image, inflated into a caller-supplied slab as its bytes arrive.
///
/// The compressed side comes in pieces of any size, so a USB frame can be handed over
/// the moment it lands. The inflated side lands in the slab, and the caller reads it
/// once [`finish`](Self::finish) has said how much there is.
pub struct Block<'o> {
    decoder: Decompressor<Buffer<'o>, Raw>,
}

impl<'o> Block<'o> {
    /// Starts a block writing into `out`, which it may fill to at most `remaining`.
    ///
    /// `remaining` is how much of the image is still to come. It caps the block, so the
    /// last one stops at the image's end instead of running on into the slab.
    pub fn new(out: &'o mut [u8], remaining: u32) -> Self {
        let room = (remaining as usize).min(out.len());
        let (room, _) = out.split_at_mut(room);
        Block {
            decoder: Decompressor::new(Buffer::new(room)),
        }
    }

    /// Takes the next piece of compressed data, returning how much of it this block
    /// used. Anything left belongs to the next block.
    pub fn write(&mut self, data: &[u8]) -> Result<usize, Error> {
        Ok(self.decoder.write(data)?)
    }

    /// Whether this block's stream has ended and it wants no more input.
    pub fn is_done(&self) -> bool {
        self.decoder.is_done()
    }

    /// Ends the block, returning how many bytes of the slab it filled.
    ///
    /// Fails if the stream did not end: a block cut short is refused here rather than
    /// passed on as a shorter one, which would leave the image's tail as whatever the
    /// slab happened to hold.
    pub fn finish(mut self) -> Result<usize, Error> {
        Ok(self.decoder.finish()? as usize)
    }
}

/// Inflate one whole block into `out`, returning how many bytes it produced.
///
/// For a block that is already in hand. A caller taking it in pieces drives [`Block`].
pub fn block(compressed: &[u8], out: &mut [u8], remaining: u32) -> Result<usize, Error> {
    let mut decoder = Block::new(out, remaining);
    decoder.write(compressed)?;
    decoder.finish()
}

#[cfg(test)]
mod tests;
