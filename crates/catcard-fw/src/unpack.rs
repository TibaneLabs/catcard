//! Receiving a deflated firmware image, a USB frame at a time.
//!
//! The wire carries 62 bytes a report, so the third of an image that deflate removes is
//! a third of the wait. What arrives is a run of deflate streams, each inflating to
//! [`BLOCK`] bytes but the last; this drives them and hands the inflated bytes to the
//! staging area exactly as the uncompressed path does, so everything past this point --
//! the digest, the header checks, the signature, the approval screen -- is the same code
//! looking at the same bytes.
//!
//! **Nothing here is trusted.** The length the host declared is the one the signature was
//! computed over, so a stream that wants to produce more is refused rather than
//! truncated, and a transfer that ends early is refused rather than staged as a shorter
//! image. Compression is a smaller wire, not a second opinion about what the image is.

use catcard_upgrade::packed::{self, BLOCK, Block};
use catcard_upgrade::{Reject, Staged, StagingArea};

/// A deflated image arriving.
pub struct Unpack {
    /// Where a block's bytes land on the way from the wire to the staging area.
    ///
    /// Taken from the heap for the length of the transfer, not reserved for the life of
    /// the device: a Q1 spends almost none of its time being upgraded, and eight
    /// kilobytes of `.bss` is eight kilobytes the boot stack does not have.
    mem: crate::heap::Block,
    /// The block being inflated, absent only between the last block and the end.
    block: Option<Block<'static>>,
    /// How much of the image has reached the staging area.
    done: u32,
    /// How much the host said the image is, which is what was signed.
    want: u32,
}

impl Unpack {
    /// Starts an image of `want` uncompressed bytes, or `None` if the heap has no room
    /// for the inflate slab.
    ///
    /// `None` is not a refusal of the image. The caller answers
    /// [`Status::RetryUncompressed`](catcard_usb::Status::RetryUncompressed) and the
    /// same image arrives uncompressed, which needs no slab at all -- compression buys
    /// wire time and costs memory, and a device short of memory should spend the time.
    pub fn begin(want: u32) -> Option<Self> {
        let mut mem = crate::heap::take(BLOCK)?;
        // SAFETY: the slice points into the heap block stored beside it, which is
        // dropped with this struct and never earlier; the bytes do not move when the
        // struct does, because they live in the heap region and not in the struct. No
        // other reference to them exists -- this is the only call before `close`.
        let slab: &'static mut [u8] = unsafe { mem.leak_mut() };
        Some(Unpack {
            mem,
            block: Some(Block::new(slab, want)),
            done: 0,
            want,
        })
    }

    /// Takes the next piece of compressed data and stages whatever it completes.
    pub fn feed<A>(&mut self, staged: &mut Staged<'_, A>, mut data: &[u8]) -> Result<(), Reject>
    where
        A: StagingArea,
        A::Error: core::fmt::Debug,
    {
        while !data.is_empty() {
            let Some(block) = self.block.as_mut() else {
                // Every declared byte is already staged and here is more. The image's
                // length is what was signed, so this is not an image we were offered.
                return Err(Reject::Unpackable(packed::Error::TooLong));
            };
            let used = block.write(data).map_err(fault)?;
            data = &data[used..];
            if block.is_done() {
                self.close(staged)?;
            } else if used == 0 {
                // It took nothing and wants nothing: it would spin here rather than
                // make progress. Nothing in the format produces this, which is why it
                // is a refusal and not a retry.
                return Err(Reject::Unpackable(packed::Error::Corrupt));
            }
        }
        Ok(())
    }

    /// Ends the block in hand, stages what it produced, and opens the next.
    fn close<A>(&mut self, staged: &mut Staged<'_, A>) -> Result<(), Reject>
    where
        A: StagingArea,
        A::Error: core::fmt::Debug,
    {
        let Some(block) = self.block.take() else {
            return Ok(());
        };
        // Dropping the block here is what releases the slab for the read below and for
        // the block opened after it.
        let produced = block.finish().map_err(fault)? as u32;

        // SAFETY: the block that held the slab was consumed by `finish` above, so this
        // is the only live borrow of it.
        let bytes = unsafe { self.mem.leak_mut() };
        staged.write(self.done, &bytes[..produced as usize])?;
        self.done += produced;

        let left = self.want - self.done;
        self.block = (left > 0).then(|| {
            // SAFETY: the borrow taken for `bytes` ends here, and no other block exists.
            Block::new(unsafe { self.mem.leak_mut() }, left)
        });
        Ok(())
    }

    /// Ends the image, refusing one that stopped short.
    ///
    /// A transfer cut off part way would otherwise leave the tail of the staging area
    /// holding whatever the last upload put there, and that is what would be installed.
    pub fn finish(self) -> Result<(), Reject> {
        if self.done != self.want {
            return Err(Reject::Unpackable(packed::Error::Short {
                got: self.done,
                want: self.want,
            }));
        }
        Ok(())
    }
}

/// What a decoding failure means to the layer that stages images.
fn fault(error: packed::Error) -> Reject {
    Reject::Unpackable(error)
}
