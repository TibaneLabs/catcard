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

use zeroize::Zeroize as _;

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
    fn place(&mut self, offset: usize, bytes: &[u8]) -> Result<(), &'static str>;

    /// What is arriving is a deflate stream, not the payload.
    ///
    /// Said once, before any bytes, because where a sink puts a stream it will have to
    /// expand is not where it puts a file it can use as it stands.
    fn compressed(&mut self) -> Result<(), &'static str> {
        Ok(())
    }
}

/// What a completed scan left behind.
pub(crate) struct Received {
    /// Bytes handed to the sink.
    pub len: usize,
    /// Whether they are a deflate stream rather than the payload itself.
    pub compressed: bool,
}

/// What one code turned out to be worth.
struct Landed {
    /// Parts held now, and how many there are in all -- for the progress screen.
    have: u32,
    total: u32,
    /// The payload's length, once every part is in. `None` while any are missing.
    complete: Option<usize>,
    /// Whether what is being placed is a deflate stream.
    compressed: bool,
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
/// **Nothing is shown on failure.** `Err(Some(why))` is a reason for the caller to show
/// and `Err(None)` is a cancel, which needs no words. That is not tidiness: the caller
/// is holding the staging area, and a message this function waited on would hold it for
/// as long as the screen stood there -- which is exactly how a scan that failed came to
/// refuse every USB upgrade until somebody walked back to the device.
pub(crate) fn collect_any(
    ui: &mut Ui<'_>,
    head: &str,
    sink: &mut dyn Sink,
) -> Result<Received, Option<&'static str>> {
    // Big enough for the largest line either format can hand over, decoded. BBQr's
    // base32 is five bits a character, so a line's payload is never more than five
    // eighths of it; BC-UR's bytewords are two characters a byte, so never more than a
    // half. Sized from the line rather than from a guess about part sizes.
    let scratch_len = qrscan::MAX_TEXT;
    let Some(mut scratch_mem) = crate::heap::take(scratch_len) else {
        return Err(Some("not enough memory"));
    };

    let mut which = Which::Unknown;
    // The sink is told once that a stream is coming, not once per part.
    let mut told = false;
    let mut failure: Option<&'static str> = None;
    // Redrawn only when a part lands that was not already held. Every other code is a
    // repeat of one already caught, and redrawing for those would make the screen flicker
    // through the whole animation without the count ever moving.
    let mut shown = (0u32, 0u32);
    let mut done = 0usize;
    let mut compressed = false;
    // The last unannounced line, kept only to see whether the next one agrees with it.
    let Some(mut seen_plain) = crate::heap::take(scratch_len) else {
        return Err(Some("not enough memory"));
    };
    let mut plain_len: Option<usize> = None;

    let outcome = qrscan::scan_many(ui, head, &mut |ui, line| {
        let scratch = scratch_mem.bytes();
        // A lone code that announces neither format is its own payload -- but not on
        // the strength of one sighting.
        //
        // **The first line read is the one most likely to be a fragment.** The module
        // is already transmitting when the read starts, so what comes back first is
        // whatever was left of a code in flight: a tail with no `B$` on the front,
        // which read as a payload of its own and ended the scan after one code. An
        // animated page then looked like a single static QR.
        //
        // A continuous scan repeats, so a real lone code arrives again, identical. Two
        // agreeing sightings is the whole test -- and any line that does announce
        // itself wins immediately, because a fragment cannot fake a header.
        if matches!(which, Which::Unknown) && !announced(line) {
            let held = seen_plain.bytes();
            if plain_len == Some(line.len()) && held[..line.len()] == *line {
                return match sink.place(0, line) {
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
            if line.len() <= held.len() {
                held[..line.len()].copy_from_slice(line);
                plain_len = Some(line.len());
            } else {
                plain_len = None;
            }
            return Next::More;
        }
        let Some(text) = as_text(line) else {
            return Next::More;
        };
        match read_one(&mut which, &mut told, text, scratch, sink) {
            Ok(Some(landed)) => {
                compressed = landed.compressed;
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

    // Both blocks have held whatever was scanned, and one of the things that can be
    // scanned is a seed. They go back to the heap wiped, for the reason `heap` gives:
    // key material in a freed block is key material nobody is tracking.
    scratch_mem.bytes().zeroize();
    seen_plain.bytes().zeroize();

    if let Some(why) = failure {
        return Err(Some(why));
    }
    match outcome {
        Ok(()) if done > 0 => Ok(Received {
            len: done,
            compressed,
        }),
        Ok(()) => Err(None),
        Err(qrscan::Fault::Cancelled) => Err(None),
        Err(why) => Err(Some(qrscan::describe(why))),
    }
}

/// Handle one decoded line.
///
/// `Ok(None)` means the line was not usable and the scan should carry on. `Err` is
/// fatal: the sink refused, or two different files are in shot.
fn read_one(
    which: &mut Which,
    told: &mut bool,
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
            let Ok(placed) = collector.accept(line) else {
                return Ok(None);
            };
            // An upper bound: every part but the last is this long, and the last is
            // shorter. Told before anything is written, because a sink that sizes itself
            // from this cannot be told after the fact.
            sink.expect(placed.len * placed.total as usize)?;
            // Before any bytes land, because it decides where they land.
            if collector.compressed() && !*told {
                sink.compressed()?;
                *told = true;
            }
            if placed.fresh {
                let room = scratch.get_mut(..placed.len).ok_or("a part was too long")?;
                if catcard_bbqr::decode_part_to_slice(line, room).is_err() {
                    return Ok(None);
                }
                sink.place(placed.offset, room)?;
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
                compressed: collector.compressed(),
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
                sink.place(offset, bytes)?;
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
                // BC-UR has no compressed form; a UR carries what it carries.
                compressed: false,
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
/// # A part's edges need not be word-aligned
///
/// PSRAM wants aligned whole-word stores, and a partial word makes the driver read the
/// word back to merge with. That read is the thing to be careful of in a *run* of
/// writes -- but there is no run here. A part arrives every few hundred milliseconds at
/// best, which is several thousand times the longest the part may be held selected, so
/// the two accesses at a part's edge have all the time in the world around them. The
/// pacing that matters is inside a burst, and the driver does that.
///
/// Which is why this takes whatever part size a sender chose. Requiring a multiple of
/// twenty -- five bytes per eight base32 characters, four for a word -- would have been
/// a rule only this device's staging imposed, and no other wallet's BBQr would have
/// satisfied it.
pub(crate) struct Staging {
    area: crate::staging::Area,
    /// Where offset zero of the payload goes. Zero for a file, and out of the way for a
    /// deflate stream, which has to survive being read while what it expands to is
    /// written over the front of the area.
    base: u32,
}

impl Staging {
    pub fn new(area: crate::staging::Area) -> Self {
        Staging { area, base: 0 }
    }

    /// The area back, with whatever was written in it.
    pub fn into_area(self) -> crate::staging::Area {
        self.area
    }
}

impl Sink for Staging {
    fn expect(&mut self, about: usize) -> Result<(), &'static str> {
        use catcard_upgrade::StagingArea as _;

        let end = self.base.checked_add(about as u32).ok_or("bad length")?;
        if end > self.area.capacity() {
            return Err("too large for this device");
        }
        Ok(())
    }

    fn compressed(&mut self) -> Result<(), &'static str> {
        self.base = crate::inflate::compressed_at();
        Ok(())
    }

    fn place(&mut self, offset: usize, bytes: &[u8]) -> Result<(), &'static str> {
        use catcard_upgrade::StagingArea as _;

        let offset: u32 = offset.try_into().map_err(|_| "bad offset")?;
        let at = self.base.checked_add(offset).ok_or("bad offset")?;
        self.area
            .write(at, bytes)
            .map_err(|_| "staging write failed")
    }
}
