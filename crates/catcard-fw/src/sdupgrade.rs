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
//! **Nothing here has run on hardware.** The SDMMC driver underneath has never moved a
//! byte — the emulator models no SD data path — so every failure is reported with the
//! step it stopped at rather than as "no".

use catcard_board::BOARD;
use catcard_sd::fat;
use catcard_upgrade::psram::PsramArea;
use catcard_upgrade::{Approval, Staged, dfuse};

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

/// What an attempt produced.
pub enum Outcome {
    /// An image is staged and inspected. Nothing is installed: the caller shows the
    /// approval and waits for a person, exactly as the USB path does.
    Offered(Staged<'static, PsramArea>, Approval),
    /// Stopped, with a reason short enough for the screen.
    Failed(&'static str),
}

/// Find a firmware on the card and stage it.
pub fn stage_from_card() -> Outcome {
    let Some(psram) = BOARD.psram else {
        // mk3 stages in SPI-NOR, which this firmware cannot write.
        return Outcome::Failed("no staging area");
    };

    // SAFETY: nothing else has claimed SDMMC1 or its pins, and this is not re-entrant:
    // the menu waits for it to return before it can be chosen again.
    let mut dev = match unsafe { catcard_hal::sdmmc::Sdmmc::init(&BOARD) } {
        Ok(d) => d,
        Err(_) => return Outcome::Failed("controller failed"),
    };
    let card = match catcard_sd::init(&mut dev) {
        Ok(c) => c,
        Err(catcard_sd::Error::NoCard) => return Outcome::Failed("no card in slot"),
        Err(_) => return Outcome::Failed("card would not start"),
    };

    let mut vol = match fat::Volume::<_, 512>::mount_auto(catcard_sd::Sectors::new(dev, card)) {
        Ok(v) => v,
        Err(_) => return Outcome::Failed("not a FAT card"),
    };

    let Some(name) = CANDIDATES.iter().find(|n| vol.open_file(n).is_ok()) else {
        return Outcome::Failed("no catcard.dfu");
    };
    let Ok(mut file) = vol.open_file(name) else {
        return Outcome::Failed("no catcard.dfu");
    };
    let file_len = file.len();

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

    let (start, len) = match dfuse::locate(&head[..got], file_len as u64) {
        Ok(e) => (e.offset, e.len),
        // A raw image is a legitimate thing to find, and is its own case rather than a
        // broken container.
        Err(dfuse::NotDfuSe::NoSignature) => (0, file_len),
        Err(dfuse::NotDfuSe::TooShort) => return Outcome::Failed("file too short"),
        Err(dfuse::NotDfuSe::Version(_)) => return Outcome::Failed("unknown dfu version"),
        Err(dfuse::NotDfuSe::NotSingle { .. }) => return Outcome::Failed("multi-part dfu"),
        Err(dfuse::NotDfuSe::Truncated { .. }) => return Outcome::Failed("dfu is truncated"),
    };

    // SAFETY: `BOARD.psram` describes a memory-mapped region, and nothing else in this
    // firmware writes it. Whether it is *actually* mapped is the open question that
    // `Debug → PSRAM` answers; a region that is not backed shows up below as a staging
    // area that does not read back what was written.
    let area = unsafe { PsramArea::claim(&psram) };
    let mut staged = match Staged::begin(area, &BOARD, len) {
        Ok(s) => s,
        Err(_) => return Outcome::Failed("image size refused"),
    };

    if file.seek(&mut vol, start).is_err() {
        return Outcome::Failed("seek failed");
    }
    let mut at = 0u32;
    let mut buf = [0u8; CHUNK];
    while at < len {
        let want = ((len - at) as usize).min(CHUNK);
        let n = match file.read(&mut vol, &mut buf[..want]) {
            Ok(0) => return Outcome::Failed("file ended early"),
            Ok(n) => n,
            Err(_) => return Outcome::Failed("read failed"),
        };
        if staged.write(at, &buf[..n]).is_err() {
            // Either the image ran past the area or the area did not read back what was
            // written. On mk4/mk5 the second is what an unmapped PSRAM looks like.
            return Outcome::Failed("staging write failed");
        }
        at += n as u32;
    }

    let running = crate::own_header();
    match staged.inspect(running.as_ref()) {
        Ok(approval) => Outcome::Offered(staged, approval),
        Err(_) => Outcome::Failed("image refused"),
    }
}
