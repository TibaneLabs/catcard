//! Expanding a deflate stream that is already sitting in a staging area.
//!
//! BBQr's `Z` encoding compresses a file and *then* cuts it into parts, so a scanner
//! collecting one ends up holding the compressed stream rather than the file. The saving
//! is in the codes: on a firmware image, roughly a quarter fewer of them, on a transport
//! where each one is a moment of somebody holding a device at a screen.
//!
//! # Nothing here ever holds a slice over the medium
//!
//! Inflating with plain slices would be four lines. It is not four lines because PSRAM
//! will not take it: inflate writes a byte at a time and reads its own history back, and
//! byte stores and unpaced reads are the two things that part mis-issues. So the window
//! lives in ordinary memory, and both ends of it cross to the medium in whole chunks
//! through [`StagingArea`], which is the only thing that knows the timing.
//! [`minizlib::Reader`] fetches compressed input a chunk at a time and
//! [`minizlib::Stream`] hands finished output back a window at a time; between them the
//! decompressor never touches the bus.
//!
//! # The two ends are the same area, so it is borrowed at runtime
//!
//! Reading the compressed stream and writing the expanded one are both the area, and the
//! two callbacks cannot each hold `&mut` to it. [`inflate`] drives them strictly in turn
//! and never nests, so a [`RefCell`] is honest about it -- and the borrow is *tried*,
//! not asserted, because a panic partway through writing a firmware image is the worst
//! place on this device to be wrong about a lifetime.

use core::cell::RefCell;

use minizlib::{Error as ZError, Reader, Stream};

use crate::StagingArea;

/// Why a stream could not be expanded.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// The medium refused a read or a write.
    Storage,
    /// The stream refers further back than the window given, so the bytes it wants are
    /// no longer held. A sender compressed with a wider window than this can serve.
    WindowTooSmall,
    /// It expands to more than `max`, which is where the caller stops it. A few
    /// kilobytes of deflate can become gigabytes, and a decompressor that can be talked
    /// into writing past what the caller expects is worth more to an attacker than any
    /// firmware.
    TooLong,
    /// The compressed data is malformed.
    Damaged,
    /// The stream does not sit where it can be expanded past: either it starts below
    /// what the expansion may write, or it runs off the end of the area.
    NoRoom,
}

/// Expand `len` compressed bytes at `from` into the same area, starting at zero.
///
/// Returns how many bytes came out. `window` is the decompressor's history and must be
/// at least as wide as the one the stream was made with; `chunk` is how much compressed
/// input is fetched per bus turnaround, and only affects how often that happens.
///
/// **`from` must be past `max` and the stream must fit the area.** Checked here rather
/// than assumed: it used to be a `debug_assert` on the first half only, which is absent
/// from a release build and said nothing about the second -- and the second is the one
/// that was wrong, by two megabytes, for as long as the staging area was mistaken for
/// the whole of the PSRAM part.
pub fn inflate<A: StagingArea>(
    area: &mut A,
    from: u32,
    len: u32,
    max: u32,
    window: &mut [u8],
    chunk: &mut [u8],
) -> Result<u32, Error> {
    let end = from.checked_add(len).ok_or(Error::NoRoom)?;
    if from < max || end > area.capacity() {
        return Err(Error::NoRoom);
    }

    let cell = RefCell::new(area);
    // How much of the stream has been handed over, and where the expanded bytes go
    // next. Plain counters: the two callbacks run in turn, never at once, so neither
    // can see the other half-done.
    let mut read_at = 0u32;
    let mut write_at = 0u32;
    // The tail of the last chunk, when it did not end on a word boundary.
    //
    // **The medium only ever sees whole aligned words.** A partial word would make the
    // area read the word back to merge with, and this is the one place in the transfer
    // where reads and writes really are interleaved at full speed rather than a part at
    // a time. The output is sequential, so three bytes of carry is the whole fix: the
    // odd tail waits for the front of the next chunk to complete its word.
    let mut carry = [0u8; 4];
    let mut carried = 0usize;

    let outcome = {
        let reader = Reader::new(chunk, |buf: &mut [u8]| {
            let want = (buf.len() as u32).min(len - read_at) as usize;
            if want == 0 {
                return Ok(0);
            }
            let mut area = cell.try_borrow_mut().map_err(|_| ZError::Io)?;
            area.read(from + read_at, &mut buf[..want])
                .map_err(|_| ZError::Io)?;
            read_at += want as u32;
            Ok(want)
        });
        let stream = Stream::new(window, max as u64, |data: &[u8]| {
            let mut area = cell.try_borrow_mut().map_err(|_| ZError::Io)?;
            let mut data = data;

            // Finish the word left over from last time before anything else.
            if carried > 0 {
                let take = data.len().min(4 - carried);
                carry[carried..carried + take].copy_from_slice(&data[..take]);
                carried += take;
                data = &data[take..];
                if carried < 4 {
                    return Ok(());
                }
                area.write(write_at, &carry).map_err(|_| ZError::Io)?;
                write_at += 4;
                carried = 0;
            }

            let whole = data.len() & !3;
            if whole > 0 {
                area.write(write_at, &data[..whole])
                    .map_err(|_| ZError::Io)?;
                write_at += whole as u32;
            }
            carried = data.len() - whole;
            carry[..carried].copy_from_slice(&data[whole..]);
            Ok(())
        });
        minizlib::inflate(reader, stream)
    };

    // The last few bytes of the image, if it does not end on a word boundary. Nothing
    // follows them, so the word they complete holds nothing that matters and the
    // padding is past the image's length.
    if outcome.is_ok() && carried > 0 {
        carry[carried..].fill(0);
        cell.borrow_mut()
            .write(write_at, &carry)
            .map_err(|_| Error::Storage)?;
    }

    match outcome {
        Ok(n) => Ok(n as u32),
        Err(ZError::WindowTooSmall) => Err(Error::WindowTooSmall),
        Err(ZError::OutputFull) => Err(Error::TooLong),
        Err(ZError::Io) => Err(Error::Storage),
        Err(_) => Err(Error::Damaged),
    }
}
