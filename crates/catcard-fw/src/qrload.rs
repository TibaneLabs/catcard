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
    /// About how long the payload is.
    ///
    /// Called as early as the transport can say -- for BC-UR that is the first fragment,
    /// for BBQr it is the first part's length times the count, which is an upper bound
    /// because the last part is short. Called again, exactly, when the payload is whole.
    ///
    /// So a sink may be told more than once and the first figure may be a little high.
    /// What it buys is the one decision that has to be made before any bytes land: how
    /// big this is going to be.
    fn expect(&mut self, _about: usize) -> Result<(), &'static str> {
        Ok(())
    }

    /// Put `bytes` at `offset`. An error abandons the transfer.
    ///
    /// `tail` is true when nothing in the payload follows these bytes. A sink writing
    /// into PSRAM needs it: whole words only, except at the very end of the image where
    /// there is nothing after the short word to be disturbed by padding it out.
    fn place(&mut self, offset: usize, bytes: &[u8], tail: bool) -> Result<(), &'static str>;
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
/// A first code that is neither BBQr nor a UR is taken as the whole payload: a single
/// code holding an address or a key is the common case, and the two cannot be told
/// apart before one has been read.
///
/// `None` if the owner cancelled or the scanner could not be used; the reason has
/// already been shown in either case.
pub(crate) fn collect_any(ui: &mut Ui<'_>, head: &str, sink: &mut dyn Sink) -> Option<usize> {
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
        // A lone code that announces neither format is its own payload, whole. Only the
        // first one: once a transfer has started, a stray code in shot must not end it.
        if matches!(which, Which::Unknown) && !announced(line) {
            return match sink.place(0, line, true) {
                Ok(()) => {
                    done = line.len();
                    Next::Done
                }
                Err(why) => {
                    failure = Some(why);
                    Next::Done
                }
            };
        }
        let Some(text) = as_text(line) else {
            return Next::More;
        };
        match read_one(&mut which, text, scratch, sink) {
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
    line: &str,
    scratch: &mut [u8],
    sink: &mut dyn Sink,
) -> Result<Option<Landed>, &'static str> {
    // The first line that parses decides the format. `starts_with` rather than a full
    // parse, because a line that announces itself as BBQr and then fails to parse is a
    // damaged BBQr line, not an invitation to try it as BC-UR.
    if matches!(which, Which::Unknown) {
        if line.as_bytes().starts_with(b"B$") {
            *which = Which::Bbqr(catcard_bbqr::Collector::new());
        } else if starts_with_ur(line.as_bytes()) {
            *which = Which::Bcur(catcard_bcur::Collector::new());
        } else {
            return Ok(None);
        }
    }

    match which {
        Which::Unknown => Ok(None),
        Which::Bbqr(collector) => {
            let placed = match collector.accept(line) {
                Ok(placed) => placed,
                // The one refusal worth a screen: the sender compressed the file, which
                // cannot be reassembled in place. Everything else is a bad frame.
                Err(catcard_bbqr::Error::Compressed) => return Err("send it uncompressed"),
                Err(_) => return Ok(None),
            };
            // An upper bound: every part but the last is this long, and the last is
            // shorter. Told before anything is written, because a sink that sizes itself
            // from this cannot be told after the fact.
            sink.expect(placed.len * placed.total as usize)?;
            if placed.fresh {
                let room = scratch.get_mut(..placed.len).ok_or("a part was too long")?;
                if catcard_bbqr::decode_part_to_slice(line, room).is_err() {
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
            // Exact from the first fragment: the message length is in every header.
            if let Some(about) = collector.about() {
                sink.expect(about.message_len as usize)?;
            }
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

/// Whether a line says it is part of a multi-code transfer.
fn announced(line: &[u8]) -> bool {
    line.starts_with(b"B$") || starts_with_ur(line)
}

/// A line as text, which both formats are: every character of a BBQr part and of a UR
/// is ASCII. Anything else is not one of them, whatever else it may be.
fn as_text(line: &[u8]) -> Option<&str> {
    core::str::from_utf8(line).ok()
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

/// The PSRAM staging area, which is where everything scanned goes.
///
/// # Why everything, and not just an image
///
/// The scanner cannot know what it is reading until it has read it, and by then the
/// bytes are wherever they were put. So they go somewhere that can hold the largest
/// thing they might be, through the driver that paces the part properly -- a plain slice
/// over the mapped region would write a quarter of a megabyte with whatever stores the
/// compiler felt like and none of the CE# timing the part needs.
///
/// # Strictness is decided by size
///
/// PSRAM takes aligned whole-word stores; a partial word makes the driver read back the
/// word to merge with, and a read placed among writes is what corrupts this part. For a
/// few stray words at the edges of a small payload that is a risk worth taking, because
/// there is no alternative -- another wallet's BBQr parts are whatever size that wallet
/// chose. For a firmware image it is not: that is hundreds of merges through a memory
/// this device has already lost data to once.
///
/// So a payload big enough to be an image is held to whole words and a sender that does
/// not is refused with the reason. **A BBQr part must be a multiple of twenty** to be
/// both five bytes per eight characters and a whole number of words; `catcard-image qr`
/// picks such a size.
pub(crate) struct Staging {
    area: crate::staging::Area,
    /// `None` until the transport says how big this is.
    strict: Option<bool>,
}

impl Staging {
    pub fn new(area: crate::staging::Area) -> Self {
        Staging { area, strict: None }
    }

    /// The area back, with whatever was written in it.
    pub fn into_area(self) -> crate::staging::Area {
        self.area
    }
}

impl Sink for Staging {
    fn expect(&mut self, about: usize) -> Result<(), &'static str> {
        use catcard_upgrade::StagingArea as _;

        if about as u32 > self.area.capacity() {
            return Err("too large for this device");
        }
        // Only an image is this big -- nothing else that arrives by camera comes close
        // to the bootloader's floor for a firmware length. Decided once, from the first
        // figure, because by the second there are already bytes in the area.
        self.strict
            .get_or_insert(about as u32 >= catcard_fwhdr::MIN_FIRMWARE_LENGTH);
        Ok(())
    }

    fn place(&mut self, offset: usize, bytes: &[u8], tail: bool) -> Result<(), &'static str> {
        use catcard_upgrade::StagingArea as _;

        let offset: u32 = offset.try_into().map_err(|_| "bad offset")?;
        // The end of the payload is the one place a partial word is always fine: nothing
        // follows it, so the word it completes holds nothing that matters.
        let whole = offset.is_multiple_of(4) && (bytes.len().is_multiple_of(4) || tail);
        if self.strict == Some(true) && !whole {
            return Err("sender's parts are not word-aligned");
        }
        self.area
            .write(offset, bytes)
            .map_err(|_| "staging write failed")
    }
}
