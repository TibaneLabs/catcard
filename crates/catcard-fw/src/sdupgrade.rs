//! Installing a firmware from a microSD card.
//!
//! The card is a transport, nothing more. What it feeds is the same machinery a USB
//! upgrade feeds — `Staged::begin`, `write`, `inspect`, the approval screen, `commit`,
//! reboot — because the interesting parts of an upgrade are the header check, the
//! signature, the downgrade warning and the person pressing a key, and none of those
//! should have two implementations that can disagree about them.
//!
//! What the card adds is a container. A `.dfu` is what `catcard-image` writes and what
//! goes on a card, so the wrapper is unpacked here; over USB the host does that and the
//! device never sees one. See `catcard_upgrade::dfuse` for why the on-device version
//! reads fixed offsets and nothing else. A raw `.bin` is accepted too, because a card
//! holding one is a reasonable thing to meet and telling them apart costs one signature
//! check.
//!
//! Every failure is reported with the step it stopped at rather than as a flat "no", so a
//! bad card, a missing file and a broken container tell themselves apart on screen.

use catcard_board::BOARD;
use catcard_upgrade::{Approval, Staged, dfuse};

use crate::staging;

/// Bytes per read. A cluster would be fewer round trips; a sector is what the card layer
/// deals in, and the copy is not what makes this slow.
const CHUNK: usize = catcard_sd::BLOCK_LEN;

/// Names looked for in the card's root, in order.
///
/// A fixed list rather than "any `.dfu`". A card with two firmware files on it poses a
/// question this should not answer by itself, and a device that installs whichever was
/// listed first is a device that installs something nobody chose.
const CANDIDATES: &[&str] = &[
    "/catcard.dfu",
    "/CATCARD.DFU",
    "/firmware.dfu",
    "/FIRMWARE.DFU",
];

/// The reject, in the few words a screen has. The log carries the whole of it.
fn describe(why: catcard_upgrade::Reject) -> &'static str {
    use catcard_upgrade::Reject as R;
    match why {
        R::Length { .. } => "wrong size for this board",
        R::TooBigToStage { .. } => "too big to stage",
        R::OutOfOrder { .. } | R::PastEnd { .. } | R::Incomplete { .. } => "transfer went wrong",
        R::NotAnImage => "no firmware header",
        R::BadHeader(_) => "header is wrong",
        R::WrongBoard { .. } => "built for another board",
        R::BadSignature { .. } => "signature does not verify",
        R::StorageFault { .. } => "staging area failed",
        R::NoStagingArea => "nowhere to stage it",
        R::StagingBusy => "busy with another image",
    }
}

/// What an attempt produced.
// The staged-image arm is far bigger than the failure arm, and boxing it is not on the
// table: no allocator. One of these lives at a time, briefly, on the stack of the screen
// that asked -- and the alternative, returning the failure by another channel, would split
// a result that reads better whole.
#[allow(clippy::large_enum_variant)]
pub enum Outcome {
    /// An image is staged and inspected. Nothing is installed: the caller shows the
    /// approval and waits for a person, exactly as the USB path does.
    Offered(Staged<'static, staging::Area>, Approval),
    /// Stopped, with a reason short enough for the screen.
    Failed(&'static str),
}

/// Find a firmware on the card in `slot` and stage it.
///
/// `chosen` names a specific file (a full path the browser returned); `None` falls back to
/// the fixed [`CANDIDATES`] search, so the option still works without navigating.
///
/// `progress` is called with `(done, total)` as the image moves, so the screen can show how
/// far along it is. The length is known before the first byte is read, and a megabyte over a
/// 512-byte buffer takes long enough that a still screen reads as a hung device -- which,
/// today, is exactly how a hung device read too.
pub fn stage_from_card(
    slot: catcard_hal::sdmmc::Slot,
    chosen: Option<&str>,
    mut progress: impl FnMut(u32, u32),
) -> Outcome {
    if slot == catcard_hal::sdmmc::Slot::B && BOARD.sdmmc.slot_b.is_none() {
        return Outcome::Failed("no slot B on this board");
    }

    // Mount FAT or exFAT; `why` carries the specific bring-up failure out of the closure.
    let mut why = "card error";
    let mount: Result<catcard_sd::AnyVolume<_, 512>, _> = catcard_sd::AnyVolume::mount_with(|| {
        // SAFETY: nothing else has claimed SDMMC1 or its pins, and this is not re-entrant:
        // the menu waits for it to return before it can be chosen again.
        let mut dev = match unsafe { catcard_hal::sdmmc::Sdmmc::init_slot(&BOARD, slot) } {
            Ok(d) => d,
            Err(_) => {
                why = "controller failed";
                return Err(());
            }
        };
        let card = match catcard_sd::init(&mut dev) {
            Ok(c) => c,
            Err(catcard_sd::Error::NoCard) => {
                why = "no card in slot";
                return Err(());
            }
            Err(e) => {
                crate::catlog!("sd: card would not start: {:?}", e);
                why = "card would not start";
                return Err(());
            }
        };
        Ok(catcard_sd::Sectors::new(dev, card))
    });
    let mut vol = match mount {
        Ok(v) => v,
        Err(catcard_sd::MountError::Device) => return Outcome::Failed(why),
        Err(catcard_sd::MountError::NoFilesystem) => return Outcome::Failed("not FAT or exFAT"),
    };

    // A file the browser picked, or the first of the fixed names that opens.
    let name: &str = match chosen {
        Some(p) => p,
        None => match CANDIDATES.iter().find(|n| vol.open_file(n).is_ok()) {
            Some(n) => n,
            None => return Outcome::Failed("no catcard.dfu"),
        },
    };
    let Ok(mut file) = vol.open_file(name) else {
        return Outcome::Failed("could not open file");
    };
    // Firmware images are well under 4 GiB, so a u32 length is enough downstream.
    let file_len = file.len() as u32;

    // The header decides whether this is a container or a raw image. Read it first,
    // because the answer changes where the image starts and how long it is.
    let mut head = [0u8; dfuse::HEADER_LEN as usize];
    let mut got = 0usize;
    while got < head.len() {
        match file.read(&mut vol, &mut head[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(_) => return Outcome::Failed("read failed"),
        }
    }

    let (start, len) =
        match dfuse::locate(&head[..got], file_len as u64, BOARD.memory.firmware_base) {
            Ok(e) => (e.offset, e.len),
            // A raw image is a legitimate thing to find, and is its own case rather than a
            // broken container.
            Err(dfuse::NotDfuSe::NoSignature) => (0, file_len),
            Err(dfuse::NotDfuSe::TooShort) => return Outcome::Failed("file too short"),
            Err(dfuse::NotDfuSe::Version(_)) => return Outcome::Failed("unknown dfu version"),
            Err(dfuse::NotDfuSe::NotSingle { .. }) => return Outcome::Failed("multi-part dfu"),
            Err(dfuse::NotDfuSe::WrongAddress { address }) => {
                crate::catlog!("sd: dfu element 0 at {:#010x}, not this board's", address);
                return Outcome::Failed("dfu not for this board");
            }
            Err(dfuse::NotDfuSe::Truncated { .. }) => return Outcome::Failed("dfu is truncated"),
        };

    // The board's staging area: PSRAM on mk4/mk5/Q1, the SPI-NOR on mk3 (brought up here).
    // `None` means there is nowhere to put an image -- no PSRAM/SPI-NOR, or the SPI-NOR did
    // not answer -- which is a clearer stop than failing partway through the write.
    let area = match staging::area() {
        Ok(a) => a,
        // Two different answers: this board cannot stage at all, or something else is
        // partway through an image and this must not walk over it.
        Err(staging::Unavailable::NoMedium) => return Outcome::Failed("no staging area"),
        Err(staging::Unavailable::Busy) => return Outcome::Failed("busy with another image"),
    };
    let mut staged = match Staged::begin(area, &BOARD, len) {
        Ok(s) => s,
        Err(_) => return Outcome::Failed("image size refused"),
    };

    if file.seek(&mut vol, start as u64).is_err() {
        return Outcome::Failed("seek failed");
    }
    let mut at = 0u32;
    // Word-aligned, because it is copied into memory-mapped PSRAM where a misaligned store
    // is mis-issued. `repr(align(4))` on the buffer costs nothing and says why.
    #[repr(align(4))]
    struct Chunk([u8; CHUNK]);
    let mut chunk = Chunk([0u8; CHUNK]);
    let buf = &mut chunk.0;
    progress(0, len);
    while at < len {
        let want = ((len - at) as usize).min(CHUNK);
        let n = match file.read(&mut vol, &mut buf[..want]) {
            Ok(0) => return Outcome::Failed("file ended early"),
            Ok(n) => n,
            Err(_) => return Outcome::Failed("read failed"),
        };
        if let Err(why) = staged.write(at, &buf[..n]) {
            // The image ran past the area, or the area refused. Name it: "refused" alone
            // has already sent one person hunting for a reason nobody wrote down.
            crate::catlog!("sd: staging write refused: {:?}", why);
            return Outcome::Failed("staging write failed");
        }
        at += n as u32;
        progress(at, len);
    }

    // A staging area that needed a second look at what it had just written is worth a
    // line: it is the difference between a medium that settles slowly and one that loses
    // data, and only the log can tell the next person which this board does.
    let staged_len = len;
    let running = crate::own_header();
    // Verifying is a second pass over the whole image -- the same length again -- so it
    // gets the same bar rather than a still screen.
    progress(0, len);
    match staged.inspect_with(running.as_ref(), &mut progress) {
        Ok(approval) => Outcome::Offered(staged, approval),
        Err(why) => {
            // Which check refused matters: "refused" alone has already sent one person
            // hunting through a log for a reason that was never written down. With the
            // header's own claims beside it, a refusal can be chased without the card.
            crate::catlog!("sd: image refused: {:?}", why);
            // The staged bytes and their digest: with these in the log, a signature that
            // will not verify can be chased against the file on a computer, which is the
            // only way to tell "the wrong bytes arrived" from "the wrong key was used".
            if let Ok(d) = staged.digest() {
                crate::catlog!(
                    "sd: staged digest {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                    d[0],
                    d[1],
                    d[2],
                    d[3],
                    d[4],
                    d[5],
                    d[6],
                    d[7]
                );
            }
            // Per-128 KB digests, so the log says which block of the image is wrong rather
            // than only that the whole of it is. A boundary on a cluster edge points at how
            // the file's clusters were followed; a scattered one at the memory.
            // Fine blocks over the first 128 KB, coarse after: the head and the header
            // arrive intact while every 128 KB block differs, which is what a read that
            // drifts by a sector somewhere early looks like. Small blocks find where.
            let mut off = 0u32;
            while off < staged_len {
                let step = if off < 128 * 1024 {
                    16 * 1024
                } else {
                    128 * 1024
                };
                let n = (staged_len - off).min(step);
                use purecrypto::hash::{Digest as _, Sha256};
                let mut h = Sha256::new();
                let mut chunk = [0u8; 256];
                let mut at = 0u32;
                let mut ok = true;
                while at < n {
                    let want = chunk.len().min((n - at) as usize);
                    if staged.sample(off + at, &mut chunk[..want]).is_err() {
                        ok = false;
                        break;
                    }
                    h.update(&chunk[..want]);
                    at += want as u32;
                }
                if ok {
                    let d = h.finalize();
                    crate::catlog!(
                        "sd: block {:#08x} {:02x}{:02x}{:02x}{:02x}",
                        off,
                        d[0],
                        d[1],
                        d[2],
                        d[3]
                    );
                }
                off += n;
            }

            let mut head = [0u8; 8];
            if staged.sample(0, &mut head).is_ok() {
                crate::catlog!(
                    "sd: staged head {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                    head[0],
                    head[1],
                    head[2],
                    head[3],
                    head[4],
                    head[5],
                    head[6],
                    head[7]
                );
            }
            if let Some(h) = staged.header() {
                crate::catlog!(
                    "sd: header key {} len {} hw_compat {:#x} version {}",
                    h.pubkey_num,
                    h.firmware_length,
                    h.hw_compat,
                    h.version_str().unwrap_or("?")
                );
            }
            Outcome::Failed(describe(why))
        }
    }
}
