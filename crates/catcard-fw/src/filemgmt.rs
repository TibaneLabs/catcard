//! Utils rows that work on whole files rather than on what is in them: deleting the
//! transactions a signing session leaves behind, and reformatting the RAM disk.
//!
//! Stock keeps both under `File Management`; this firmware's Utils is flat, so they sit
//! beside the other card housekeeping; `Format` asks which medium and comes here for the
//! Virtual Disk.
//!
//! Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §D2 FileMgmtMenu [C];
//! firmware-features.md §9 "Delete-and-blank spent PSBTs / Format SD or RAM disk" [C].

use crate::menu::{self, DocExit, Storage};
use crate::ui::Ui;
use catcard_sd::AnyVolume;
use catcard_sd::fat::SectorDriver;

/// How many spent files one pass lists and removes. A root with more than this many
/// is handled a page at a time by running the row again, which the closing message says.
const MAX_FILES: usize = 24;

/// The longest name kept per file. A FAT long name can be longer; one that is cut here
/// is skipped rather than deleted by a truncated path, and the closing message says so.
type Name = heapless::String<64>;

/// What a listing pass found: the names it kept, and how many matched in all.
struct Spent {
    names: heapless::Vec<Name, MAX_FILES>,
    total: usize,
}

/// Utils → Delete PSBTs: remove every PSBT and signed transaction in the root of the
/// chosen storage, blanking each one first.
///
/// "Blanking" is what makes this more than a delete: a FAT unlink only drops the
/// directory entry and frees the chain, and the bytes stay on the card for anyone with a
/// reader. So each file is overwritten with zeros to its full length, flushed, and only
/// then unlinked -- the flash under it may still keep a stale copy (wear levelling is the
/// card's business), but the filesystem no longer points at anything readable.
///
/// The files are listed before the question, and the question names the count: an
/// owner should see what goes before it goes.
pub(crate) fn delete_psbts(ui: &mut Ui<'_>) {
    const HEAD: &str = "Delete PSBTs";
    let Some(storage) = menu::pick_storage(ui, HEAD) else {
        return;
    };

    let found = match list_on(storage) {
        Ok(f) => f,
        Err(why) => {
            menu::message(ui.panel, HEAD, why, "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        }
    };
    if found.total == 0 {
        menu::message(ui.panel, HEAD, "nothing to delete", storage.medium());
        menu::wait_for_any_key(ui);
        return;
    }

    // The list, then the question. The list is a document so a long one scrolls.
    {
        use catcard_ui::scroll::Line as DLine;
        use core::fmt::Write as _;
        let mut note: heapless::String<48> = heapless::String::new();
        let _ = write!(
            note,
            "{} on {}, root folder:",
            found.total,
            storage.medium()
        );
        let mut lines: heapless::Vec<DLine<'_>, { MAX_FILES + 3 }> = heapless::Vec::new();
        let _ = lines.push(DLine::title(HEAD));
        let _ = lines.push(DLine::body(&note).small());
        for n in found.names.iter() {
            let _ = lines.push(DLine::body(n).small());
        }
        if found.total > found.names.len() {
            let _ = lines.push(DLine::body("...and more; run again after").small());
        }
        if !matches!(menu::show_doc(ui, &lines, false, false), DocExit::Confirmed) {
            return;
        }
    }
    let mut count: heapless::String<32> = heapless::String::new();
    let _ = core::fmt::Write::write_fmt(&mut count, format_args!("{} file(s)", found.names.len()));
    menu::ask(ui.panel, "Delete and blank?", &count, "cannot be undone");
    if !menu::confirmed(ui) {
        return;
    }

    menu::blocking_screen(ui.panel, HEAD, "blanking");
    let mut a: heapless::String<32> = heapless::String::new();
    let mut b: heapless::String<32> = heapless::String::new();
    match delete_on(storage, &found.names) {
        Ok((done, failed)) => {
            crate::catlog!(
                "filemgmt: deleted {} spent file(s), {} failed",
                done,
                failed
            );
            let _ = core::fmt::Write::write_fmt(&mut a, format_args!("{} deleted", done));
            if failed > 0 {
                let _ = core::fmt::Write::write_fmt(&mut b, format_args!("{} refused", failed));
            } else if found.total > done {
                let _ = b.push_str("run again for the rest");
            }
        }
        Err(why) => {
            let _ = a.push_str(why);
        }
    }
    menu::message(ui.panel, HEAD, &a, &b);
    menu::wait_for_any_key(ui);
}

/// The spent files in the root of `storage`.
fn list_on(storage: Storage) -> Result<Spent, &'static str> {
    match storage {
        Storage::Sd => {
            let mut vol = menu::mount_card()?;
            list_spent(&mut vol)
        }
        #[cfg(not(feature = "board-mk3"))]
        Storage::Vdisk => menu::with_vdisk(list_spent),
    }
}

/// Blank and unlink `names` in the root of `storage`; `(done, failed)`.
fn delete_on(
    storage: Storage,
    names: &heapless::Vec<Name, MAX_FILES>,
) -> Result<(usize, usize), &'static str> {
    match storage {
        Storage::Sd => {
            let mut vol = menu::mount_card()?;
            Ok(blank_and_delete(&mut vol, names))
        }
        #[cfg(not(feature = "board-mk3"))]
        Storage::Vdisk => menu::with_vdisk(|vol| Ok(blank_and_delete(vol, names))),
    }
}

/// The spent files in the root of `vol`: as many names as fit, and the whole count.
///
/// A name too long for [`Name`] is counted but not kept, so it is never deleted by a
/// path that is not its own.
fn list_spent<D: SectorDriver>(vol: &mut AnyVolume<D, 512>) -> Result<Spent, &'static str> {
    let mut found = Spent {
        names: heapless::Vec::new(),
        total: 0,
    };
    vol.enumerate("", |name, is_dir, _len| {
        if is_dir || !catcard_sd::name::is_spent_transaction(name) {
            return;
        }
        found.total += 1;
        if let Ok(nm) = Name::try_from(name) {
            let _ = found.names.push(nm);
        }
    })
    .map_err(|_| "could not list the folder")?;
    Ok(found)
}

/// Overwrite each named root file with zeros, then unlink it. Answers `(done, failed)`.
///
/// One file's failure does not stop the others: a file that will not open is skipped and
/// counted, and the rest still go.
fn blank_and_delete<D: SectorDriver>(
    vol: &mut AnyVolume<D, 512>,
    names: &heapless::Vec<Name, MAX_FILES>,
) -> (usize, usize) {
    let zeros = [0u8; 512];
    let (mut done, mut failed) = (0usize, 0usize);
    for name in names.iter() {
        let mut path: heapless::String<66> = heapless::String::new();
        let _ = path.push('/');
        let _ = path.push_str(name);
        let outcome = (|| -> Result<(), ()> {
            let mut file = vol.open_file(&path)?;
            let len = file.len();
            // Bounded by the file's own length, a sector at a time.
            let mut at = 0u64;
            while at < len {
                let n = (len - at).min(zeros.len() as u64) as usize;
                file.write_all(vol, &zeros[..n])?;
                at += n as u64;
            }
            file.flush(vol)?;
            vol.remove_file(&path)?;
            vol.flush()
        })();
        match outcome {
            Ok(()) => done += 1,
            Err(()) => {
                crate::catlog!("filemgmt: could not blank/delete {}", path);
                failed += 1;
            }
        }
    }
    (done, failed)
}

/// Utils → Format → Virtual Disk: blank it and lay a fresh filesystem on it.
///
/// Stock's `wipe_vdisk`: the region is zeroed end to end before the format, so nothing
/// staged on it earlier survives in the free space of the new volume. Asked first --
/// the disk is volatile, but "volatile" means a power cycle, not a menu row, and a PSBT
/// somebody staged an hour ago is still there until one or the other.
///
/// Source: hw-reference/help-and-warning-screens.md §15 "Wipe virtual/RAM disk" [C]
#[cfg(not(feature = "board-mk3"))]
pub(crate) fn format_ram_disk(ui: &mut Ui<'_>) {
    const HEAD: &str = "Format";
    if catcard_board::BOARD.psram.is_none() {
        menu::message(ui.panel, HEAD, "no Virtual Disk here", "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    }
    menu::ask(
        ui.panel,
        "Format Virtual Disk?",
        "erases what is on it",
        "(power-off would too)",
    );
    if !menu::confirmed(ui) {
        return;
    }
    menu::blocking_screen(ui.panel, HEAD, "blanking");
    match crate::vdisk::wipe_and_format() {
        Ok(()) => {
            crate::catlog!("vdisk: blanked and formatted from the menu");
            menu::message(ui.panel, HEAD, "done", "the disk is empty");
        }
        Err(why) => {
            crate::catlog!("vdisk: format failed: {}", why);
            menu::message(ui.panel, HEAD, why, "any key to go back");
        }
    }
    menu::wait_for_any_key(ui);
}
