//! Showing a PNG off the card.
//!
//! The decoding is [`catcard_png`], which never holds more of a picture than two
//! scanlines. This is the part that knows what this device can spend on it, where the
//! bytes come from, and what a person sees while it happens.
//!
//! # The picture is finished before any of it is shown
//!
//! Rows could go straight to the panel as they are decoded, which would need no frame
//! buffer at all. They do not, for two reasons. A file that turns out to be damaged
//! half way down would leave half a picture on the glass with an error message over it,
//! and there is no honest way to take it back. And a photograph takes seconds to
//! inflate, during which something has to say that the device is working -- a bar that
//! fills is a better answer than a picture that creeps.
//!
//! So the resized picture is assembled in memory, at most 320x240 in 16-bit colour,
//! which is 150 KB. That is what the spare SRAM bank is for: it does not fit in the
//! linked heap, and asking for it is what makes the allocator go and claim the rest of
//! the RAM (see [`crate::heap`]).
//!
//! # Q1 only
//!
//! This is a colour screen feature. The other boards have a 128x64 panel of two
//! colours; a photograph on one would have to be dithered, which is a different piece
//! of work and not one anybody has asked for yet.

use catcard_png::{Buffers, Error};

use crate::display;
use crate::menu::{self, CardVolume};
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

/// Read a PNG off the card and put it on the screen, then wait for a key.
pub(crate) fn view(ui: &mut Ui<'_>, path: &str) {
    match show(ui, path) {
        Ok(()) => {}
        Err(why) => {
            crate::catlog!("png: {}: {}", path, why);
            menu::message(ui.panel, HEAD, why, "any key to go back");
            menu::wait_for_any_key(ui);
        }
    }
}

/// Everything that can go wrong on the way, in one place, as words for a screen.
fn show(ui: &mut Ui<'_>, path: &str) -> Result<(), &'static str> {
    let mut vol = menu::mount_card()?;
    let mut file = vol.open_file(path).map_err(|()| "cannot open that file")?;
    let total = file.len();

    // The header first, off the front of the file: it says what the picture is, and
    // everything below is sized from it. A file that is not a PNG costs this one read.
    let mut head = [0u8; catcard_png::HEADER_BYTES];
    read_exact(&mut file, &mut vol, &mut head)?;
    let hdr = catcard_png::header(&head).map_err(Error::why)?;
    file.seek(&mut vol, 0)
        .map_err(|()| "cannot rewind the file")?;

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

    // Everything the decode needs, from the heap. The frame is the large one and is
    // asked for first: if it cannot be had, nothing else was allocated for nothing.
    let frame_len = plan.w * plan.h * 2;
    let (Some(mut frame), Some(mut window), Some(mut lines), Some(mut acc), Some(mut out)) = (
        crate::heap::take(frame_len),
        crate::heap::take(catcard_png::WINDOW),
        crate::heap::take(hdr.lines_needed()),
        crate::heap::take(Buffers::acc_needed(plan.w) * 4),
        crate::heap::take(plan.w * 2),
    ) else {
        return Err("not enough memory for this picture");
    };

    let mut at = 0u64;
    let mut shown = u8::MAX;
    bar(ui, 0);
    {
        let frame = frame.pixels();
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
                let n = file.read(&mut vol, buf)?;
                at += n as u64;
                // A frame per percent: the bar has a hundred positions and the panel is
                // slow, so redrawing it more often would cost more than the decode.
                // An empty file cannot be a picture and will fail below; the bar
                // just has nothing to say about it in the meantime.
                let pct = (at * 100)
                    .checked_div(total)
                    .map_or(100, |p| p.min(100) as u8);
                if pct != shown {
                    shown = pct;
                    bar(ui, pct);
                }
                Ok(n)
            },
            |y, row| {
                let from = y * plan.w;
                match frame.get_mut(from..from + row.len()) {
                    Some(dst) => {
                        dst.copy_from_slice(row);
                        Ok(())
                    }
                    // The renderer promises rows in range; this is the check that says
                    // so rather than trusting it with a slice index.
                    None => Err(()),
                }
            },
        );
        outcome.map_err(Error::why)?;
    }

    // Centred, on the surround it was composited against, so the edges of a logo match
    // what is behind them.
    let x = (PANEL_W - plan.w) / 2;
    let y = (PANEL_H - plan.h) / 2;
    display::show_picture(ui.panel, x, y, plan.w, plan.h, frame.pixels());
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
    });
}

/// Fill `buf` completely, or say the file is too short for it.
fn read_exact(
    file: &mut catcard_sd::AnyFile,
    vol: &mut CardVolume,
    buf: &mut [u8],
) -> Result<(), &'static str> {
    let mut done = 0;
    while done < buf.len() {
        match file.read(vol, &mut buf[done..]) {
            Ok(0) => return Err("not a PNG file"),
            Ok(n) => done += n,
            Err(()) => return Err("the card stopped responding"),
        }
    }
    Ok(())
}
