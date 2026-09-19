//! Reading a file that arrived as animated QR.
//!
//! The other direction from [`crate::qrshow`]. A payload too large for one symbol is
//! shown as a few hundred of them in a cycle; this catches whichever it can, in whatever
//! order they come, until it has them all.
//!
//! # Both formats, sniffed from the first line
//!
//! BBQr lines start `B$` and BC-UR lines start `ur:`, so nothing has to be chosen in
//! advance -- the first code that parses decides, and everything after it must agree.
//! That matters because the two are not interchangeable: BBQr is denser and is what
//! Bitcoin tooling emits, and BC-UR is what everything else does.
//!
//! # Why the destination is a trait
//!
//! A PSBT is collected into a buffer. A firmware image is collected into the staging
//! area, which takes whole words at an offset and must never be read back. Those have
//! nothing in common but "put these bytes there", so that is the whole of [`Sink`], and
//! the part that is genuinely shared -- sniffing, placing, counting, the progress screen
//! and the cancel -- is written once.

use crate::menu;
use crate::qrscan::{self, Next};
use crate::ui::Ui;

/// Where collected bytes go.
pub(crate) trait Sink {
    /// The payload's total length, once it is known.
    ///
    /// Called at most once, and not always before the first [`place`](Self::place):
    /// BBQr does not know the length until its last part has arrived, whenever that is.
    /// A sink that needs the length up front has to refuse a payload that overruns it in
    /// `place` as well.
    fn expect(&mut self, _total: usize) -> Result<(), &'static str> {
        Ok(())
    }

    /// Put `bytes` at `offset`. An error abandons the transfer.
    ///
    /// `tail` is true when nothing in the payload follows these bytes. A sink writing
    /// into PSRAM needs it: whole words only, except at the very end of the image where
    /// there is nothing after the short word to be disturbed by padding it out.
    fn place(&mut self, offset: usize, bytes: &[u8], tail: bool) -> Result<(), &'static str>;
}

/// A plain buffer, which is what a PSBT and every text payload want.
pub(crate) struct Buffer<'a> {
    pub out: &'a mut [u8],
}

impl Sink for Buffer<'_> {
    fn expect(&mut self, total: usize) -> Result<(), &'static str> {
        if total > self.out.len() {
            return Err("too large for this device");
        }
        Ok(())
    }

    fn place(&mut self, offset: usize, bytes: &[u8], _tail: bool) -> Result<(), &'static str> {
        let end = offset.checked_add(bytes.len()).ok_or("bad offset")?;
        let room = self
            .out
            .get_mut(offset..end)
            .ok_or("too large for this device")?;
        room.copy_from_slice(bytes);
        Ok(())
    }
}

/// What one code turned out to be worth.
struct Landed {
    /// Parts held now, and how many there are in all -- for the progress screen.
    have: u32,
    total: u32,
    /// The payload's length, once every part is in. `None` while any are missing.
    complete: Option<usize>,
}

/// Which format is being read, decided by the first line that parsed.
enum Which {
    Unknown,
    Bbqr(catcard_bbqr::Collector),
    Bcur(catcard_bcur::Collector),
}

/// Read an animated QR into `sink`, returning the payload's length.
///
/// `None` if the owner cancelled or the scanner could not be used; the reason has
/// already been shown in either case.
pub(crate) fn collect(ui: &mut Ui<'_>, head: &str, sink: &mut dyn Sink) -> Option<usize> {
    // Big enough for the largest line either format can hand over, decoded. BBQr's
    // base32 is five bits a character, so a line's payload is never more than five
    // eighths of it; BC-UR's bytewords are two characters a byte, so never more than a
    // half. Sized from the line rather than from a guess about part sizes.
    let scratch_len = qrscan::MAX_TEXT;
    let Some(mut scratch_mem) = crate::heap::take(scratch_len) else {
        menu::message(ui.panel, head, "not enough memory", "any key to go back");
        menu::wait_for_any_key(ui);
        return None;
    };

    let mut which = Which::Unknown;
    let mut failure: Option<&'static str> = None;
    // Redrawn only when a part lands that was not already held. Every other code is a
    // repeat of one already caught, and redrawing for those would make the screen flicker
    // through the whole animation without the count ever moving.
    let mut shown = (0u32, 0u32);
    let mut done = 0usize;

    let outcome = qrscan::scan_many(ui, head, &mut |ui, line| {
        let scratch = scratch_mem.bytes();
        match read_one(&mut which, line, scratch, sink) {
            Ok(Some(landed)) => {
                if (landed.have, landed.total) != shown {
                    shown = (landed.have, landed.total);
                    progress(ui, head, landed.have, landed.total);
                }
                match landed.complete {
                    Some(len) => {
                        done = len;
                        Next::Done
                    }
                    None => Next::More,
                }
            }
            // A line that is not part of this transfer: a stray code in shot, a fountain
            // mixture, a frame caught mid-refresh. Ignored, because the animation will
            // come round again with a clean one.
            Ok(None) => Next::More,
            Err(why) => {
                failure = Some(why);
                Next::Done
            }
        }
    });

    if let Some(why) = failure {
        menu::message(ui.panel, head, why, "any key to go back");
        menu::wait_for_any_key(ui);
        return None;
    }
    match outcome {
        Ok(()) if done > 0 => Some(done),
        Ok(()) => None,
        Err(qrscan::Fault::Cancelled) => None,
        Err(why) => {
            menu::message(ui.panel, head, qrscan::describe(why), "any key to go back");
            menu::wait_for_any_key(ui);
            None
        }
    }
}

/// Handle one decoded line.
///
/// `Ok(None)` means the line was not usable and the scan should carry on. `Err` is
/// fatal: the sink refused, or two different files are in shot.
fn read_one(
    which: &mut Which,
    line: &[u8],
    scratch: &mut [u8],
    sink: &mut dyn Sink,
) -> Result<Option<Landed>, &'static str> {
    // The first line that parses decides the format. `starts_with` rather than a full
    // parse, because a line that announces itself as BBQr and then fails to parse is a
    // damaged BBQr line, not an invitation to try it as BC-UR.
    if matches!(which, Which::Unknown) {
        if line.starts_with(b"B$") {
            *which = Which::Bbqr(catcard_bbqr::Collector::new());
        } else if starts_with_ur(line) {
            *which = Which::Bcur(catcard_bcur::Collector::new());
        } else {
            return Ok(None);
        }
    }

    match which {
        Which::Unknown => Ok(None),
        Which::Bbqr(collector) => {
            let Ok((placed, payload)) = collector.accept(line) else {
                return Ok(None);
            };
            if placed.fresh {
                let end = placed.len;
                let room = scratch.get_mut(..end).ok_or("a part was too long")?;
                let header = collector.header().ok_or("a part was too long")?;
                if catcard_bbqr::decode(header.encoding, payload, room).is_err() {
                    return Ok(None);
                }
                sink.place(placed.offset, room, placed.index + 1 == placed.total)?;
            }
            let placed = collector.confirm(placed);
            // Only now is the length knowable: BBQr's parts are all the same size except
            // the last, so until the last one has arrived there is nothing to add up.
            let len = collector.file_len();
            if let Some(len) = len {
                sink.expect(len)?;
            }
            Ok(Some(Landed {
                have: placed.have as u32,
                total: placed.total as u32,
                complete: len,
            }))
        }
        Which::Bcur(collector) => {
            let Ok(placed) = collector.accept(line, scratch) else {
                return Ok(None);
            };
            let (offset, total) = (placed.offset, placed.total);
            if placed.fresh {
                // `at` is a range into the scratch, and `len` stops before the last
                // fragment's padding -- which is not part of the message and must not be
                // written as if it were.
                let from = placed.at.start;
                let bytes = scratch
                    .get(from..from + placed.len)
                    .ok_or("a fragment was too long")?;
                sink.place(offset, bytes, placed.index + 1 == placed.total)?;
            }
            let placed = collector.confirm(placed);
            let have = placed.have;
            // BC-UR carries the message length in every fragment's header, so this is
            // known from the first one and the sink can refuse early.
            let total_len = collector.about().map(|p| p.message_len as usize);
            if let Some(total_len) = total_len {
                sink.expect(total_len)?;
            }
            Ok(Some(Landed {
                have,
                total,
                complete: collector.complete().then_some(total_len).flatten(),
            }))
        }
    }
}

/// Whether a line announces itself as a UR, in either case.
///
/// Upper case is the one that matters: a UR meant for a QR is upper-cased so the symbol
/// stays in alphanumeric mode, which is how every UR this will ever be shown arrives.
fn starts_with_ur(line: &[u8]) -> bool {
    line.len() > 3 && line[..3].eq_ignore_ascii_case(b"ur:")
}

/// The count, as a bar and a number.
///
/// A bar because the question anyone holding a phone at a screen has is whether this is
/// going anywhere, and a number because the last few parts of an animated transfer can
/// take longer than the first hundred and a bar that has stopped moving says nothing
/// about how much is left.
fn progress(ui: &mut Ui<'_>, head: &str, have: u32, total: u32) {
    let mut note: heapless::String<24> = heapless::String::new();
    use core::fmt::Write as _;
    let _ = write!(note, "{have} of {total}");
    menu::blocking_screen(ui.panel, head, &note);
}

/// The firmware staging area, for an image that arrived as QR.
///
/// # Word alignment is the whole of the difficulty
///
/// The staging area on every board but the mk3 is memory-mapped PSRAM, which takes
/// aligned whole-word stores and nothing else: a partial word makes the area read back
/// what is already there to merge with, and a read placed among writes is exactly what
/// corrupts this part. So a part's offset must be a multiple of four, and so must its
/// length -- except for the last part, where the short word can be padded out because
/// there is nothing after it to disturb.
///
/// A BBQr part is five bytes per eight characters, so its size is always a multiple of
/// five and only sometimes a multiple of four. **A sender must choose a part size that
/// is a multiple of twenty** to satisfy both. Rather than quietly merging, a sender that
/// did not is refused and told so.
pub(crate) struct Staging<'a> {
    pub area: &'a mut crate::staging::Area,
    /// What the area will hold, so an over-large image is refused when its length is
    /// learned rather than by a write running off the end.
    pub capacity: u32,
}

impl Sink for Staging<'_> {
    fn expect(&mut self, total: usize) -> Result<(), &'static str> {
        if total as u32 > self.capacity {
            return Err("image too large to stage");
        }
        Ok(())
    }

    fn place(&mut self, offset: usize, bytes: &[u8], tail: bool) -> Result<(), &'static str> {
        use catcard_upgrade::StagingArea as _;

        let offset: u32 = offset.try_into().map_err(|_| "bad offset")?;
        if !offset.is_multiple_of(4) {
            return Err("sender's parts are not word-aligned");
        }
        if bytes.len().is_multiple_of(4) {
            return self
                .area
                .write(offset, bytes)
                .map_err(|_| "staging write failed");
        }
        if !tail {
            return Err("sender's parts are not word-aligned");
        }
        // The last part, padded out to a whole word. The padding lands past the image's
        // end in an area that is megabytes bigger than any image, and the digest covers
        // the image's length rather than what was written.
        let mut word = [0u8; 4];
        let whole = bytes.len() & !3;
        if whole > 0 {
            self.area
                .write(offset, &bytes[..whole])
                .map_err(|_| "staging write failed")?;
        }
        let rest = &bytes[whole..];
        word[..rest.len()].copy_from_slice(rest);
        self.area
            .write(offset + whole as u32, &word)
            .map_err(|_| "staging write failed")
    }
}
