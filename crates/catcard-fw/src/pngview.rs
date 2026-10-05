//! Showing a PNG off the card.
//!
//! The decoding is [`catcard_png`], which never holds more of a picture than two
//! scanlines. This is the part that knows what this device can spend on it, where the
//! bytes come from, and what a person sees while it happens.
//!
//! # Rows go straight to the panel
//!
//! Each resized row is painted as soon as it is decoded; no frame is held. A whole frame
//! is 150 KB, which once came out of the spare SRAM bank -- until the apps' 256 KB area
//! was placed in the middle of it and no piece that size was left, and "not enough
//! memory" was all a picture got. The decode needs a few kilobytes: two scanlines, the
//! inflate window and one output row.
//!
//! The picture filling in from the top is what says the device is working. A file that
//! turns out to be damaged half way down leaves part of a picture, and the error screen
//! that follows is drawn whole over it (the row cache is invalidated when the picture
//! starts), so nothing of it stays behind.
//!
//! # Q1 only
//!
//! This is a colour screen feature. The other boards have a 128x64 panel of two
//! colours; a photograph on one would have to be dithered, which is a different piece
//! of work and not one anybody has asked for yet.

use catcard_png::{Buffers, Error};

use crate::display;
use crate::menu::{self, Storage};
use crate::ui::Ui;

/// The head every screen here carries.
const HEAD: &str = "Picture";

/// The panel, in pixels. The picture is fitted to all of it.
const PANEL_W: usize = catcard_ui::st7789::WIDTH;
const PANEL_H: usize = catcard_ui::st7789::HEIGHT;

/// Whether a name looks like something this can show.
///
/// By extension, because the browser is listing names and has not opened anything yet;
/// what the file actually is gets decided by its first eight bytes.
pub(crate) fn is_png(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() > 4 && bytes[bytes.len() - 4..].eq_ignore_ascii_case(b".png")
}

/// Read a PNG off the browsed storage and put it on the screen, then wait for a key.
///
/// `storage` is whichever volume the browser is on -- the card or the PSRAM-backed Virtual
/// Disk -- so the file is read back from where it was seen, not from the card by default.
pub(crate) fn view(ui: &mut Ui<'_>, storage: Storage, path: &str) {
    let outcome = match storage {
        Storage::Sd => menu::mount_card().and_then(|mut vol| show(ui, &mut vol, path)),
        // The Q1 always has PSRAM, so this variant exists in every build that compiles the
        // viewer; the disk is mounted (and formatted if never used) exactly as its browser
        // does it.
        Storage::Vdisk => menu::with_vdisk(|vol| show(ui, vol, path)),
    };
    if let Err(why) = outcome {
        crate::catlog!("png: {}: {}", path, why);
        menu::message(ui.panel, HEAD, why, "any key to go back");
        menu::wait_for_any_key(ui);
    }
}

/// Everything that can go wrong on the way, in one place, as words for a screen.
///
/// Generic over the backing driver so the card and the Virtual Disk share the one decode
/// path: the file is already open on the volume the browser handed over.
// Not inlined: `view` instantiates this twice, once per storage, and the two copies
// inlined side by side were summed into one frame under the file browser.
#[inline(never)]
fn show<D: catcard_sd::fat::SectorDriver>(
    ui: &mut Ui<'_>,
    vol: &mut catcard_sd::AnyVolume<D, 512>,
    path: &str,
) -> Result<(), &'static str> {
    let mut file = vol.open_file(path).map_err(|()| "cannot open that file")?;
    let total = file.len();

    // The header first, off the front of the file: it says what the picture is, and
    // everything below is sized from it. A file that is not a PNG costs this one read.
    let mut head = [0u8; catcard_png::HEADER_BYTES];
    read_exact(&mut file, vol, &mut head)?;
    let hdr = catcard_png::header(&head).map_err(Error::why)?;
    file.seek(vol, 0).map_err(|()| "cannot rewind the file")?;

    // The whole panel, status bar included: a picture is what the screen is for while
    // it is up, and the bar comes back with the menu behind it.
    let plan = catcard_png::fit(&hdr, PANEL_W, PANEL_H);
    crate::catlog!(
        "png: {}x{} depth {} -> {}x{}",
        hdr.width,
        hdr.height,
        hdr.depth,
        plan.w,
        plan.h
    );

    // Everything the decode needs, from the heap: no frame, the rows go to the panel.
    let (Some(mut window), Some(mut lines), Some(mut acc), Some(mut out)) = (
        crate::heap::take(catcard_png::WINDOW),
        crate::heap::take(hdr.lines_needed()),
        crate::heap::take(Buffers::acc_needed(plan.w) * 4),
        crate::heap::take(plan.w * 2),
    ) else {
        return Err("not enough memory for this picture");
    };

    // Centred, on the surround it was composited against, so the edges of a logo match
    // what is behind them.
    let x0 = (PANEL_W - plan.w) / 2;
    let y0 = (PANEL_H - plan.h) / 2;
    let mut at = 0u64;
    let mut shown = u8::MAX;
    // The bar until the first row: a large file can take a moment before one comes out.
    let started = core::cell::Cell::new(false);
    bar(ui, 0);
    {
        // Both callbacks draw, one at a time: the decoder calls them in turn, never
        // together, so the screen is shared rather than split between them.
        let screen = core::cell::RefCell::new(&mut *ui);
        let outcome = catcard_png::render(
            &hdr,
            &plan,
            Buffers {
                window: window.bytes(),
                lines: lines.bytes(),
                acc: acc.words(),
                out: out.pixels(),
            },
            background(),
            |buf| {
                let n = file.read(vol, buf)?;
                at += n as u64;
                // A frame per percent: the bar has a hundred positions and the panel is
                // slow, so redrawing it more often would cost more than the decode.
                // An empty file cannot be a picture and will fail below; the bar
                // just has nothing to say about it in the meantime.
                let pct = (at * 100)
                    .checked_div(total)
                    .map_or(100, |p| p.min(100) as u8);
                if !started.get() && pct != shown {
                    shown = pct;
                    bar(&mut screen.borrow_mut(), pct);
                }
                Ok(n)
            },
            |y, row| {
                // The renderer promises rows in range; this is the check that says so
                // rather than painting off the edge.
                if y >= plan.h || row.len() > plan.w {
                    return Err(());
                }
                let mut ui = screen.borrow_mut();
                if !started.replace(true) {
                    display::picture_start(ui.panel);
                }
                display::picture_row(ui.panel, x0, y0 + y, row);
                Ok(())
            },
        );
        outcome.map_err(Error::why)?;
    }
    menu::wait_for_any_key(ui);
    // The picture was painted behind the canvas's back; the caller's next draw has to
    // put the menu back, and `show_picture` invalidated the row cache so that it will.
    Ok(())
}

/// What a transparent pixel is composited onto, as the decoder wants it.
fn background() -> [u8; 3] {
    [0x30, 0x30, 0x30]
}

/// The loading screen: a bar that fills as the file is read.
///
/// What it measures is the file going by, not the decode: those are the same journey
/// -- every byte read is a byte inflated -- and bytes are the thing this can count.
fn bar(ui: &mut Ui<'_>, pct: u8) {
    display::draw(ui.panel, |c| {
        catcard_ui::widgets::info(c, &display::LAYOUT, HEAD, &["reading the picture"]);
        catcard_ui::splash::draw_progress(c, pct);
        crate::idle::note_progress();
    });
}

/// Fill `buf` completely, or say the file is too short for it.
fn read_exact<D: catcard_sd::fat::SectorDriver>(
    file: &mut catcard_sd::AnyFile,
    vol: &mut catcard_sd::AnyVolume<D, 512>,
    buf: &mut [u8],
) -> Result<(), &'static str> {
    let mut done = 0;
    while done < buf.len() {
        match file.read(vol, &mut buf[done..]) {
            Ok(0) => return Err("not a PNG file"),
            Ok(n) => done += n,
            Err(()) => return Err("the storage stopped responding"),
        }
    }
    Ok(())
}
