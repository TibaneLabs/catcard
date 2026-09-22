//! Debug: put the whole settings region back from an image staged in PSRAM.
//!
//! For a device whose settings were damaged and whose state dump survives. The host
//! stages the dump's `settings` section into PSRAM with the memory monitor
//! (`tools/usbclient.py hid --stage-settings DUMP`); this checks it and writes it over
//! the region, page by page, reading each one back.
//!
//! # It replaces everything, so it checks everything first
//!
//! Every wallet's settings file is in this region, and after this they are whatever the
//! image holds. So before a page is erased:
//!
//! - the staged header must be ours, the length must be the region's, and the SHA-256
//!   the host put in the header must match what arrived -- a transfer that dropped a
//!   frame does not get written to flash;
//! - the image must mount as a LittleFS volume;
//! - and it must hold **this device's** settings: the root's file has to open under the
//!   key of the secret this device's secure element holds. A dump of some other device
//!   would replace every wallet's settings here with settings nobody here can read.
//!
//! Only then is the owner asked, on the device -- never from the host. A write that a
//! USB command could trigger would be a write anyone holding the cable could trigger.
//!
//! # Debug builds only
//!
//! It exists because the memory monitor exists: without `usb-debug-mem` there is no way
//! to stage the image, and no reason for this to be in the firmware.

use catcard_callgate::Callgate;
use catcard_settings::store::{self, MediumError, Slots};
use fstool::device::FlashDriver;
use zeroize::Zeroize as _;

use crate::menu;
use crate::ui::Ui;

const HEAD: &str = "Restore settings";

/// What the host writes at the front of the staged image. Eight bytes, written last, so
/// a transfer cut off part way never looks finished.
pub const MAGIC: [u8; 8] = *b"CCRSTOR1";

/// The header's size: magic, length, a reserved word, the SHA-256, and padding.
pub const HEADER: usize = 64;

/// Where in the PSRAM the host stages it: the upper half, which is the upgrade image's
/// area and which nothing else keeps anything in between uses.
fn staged_at() -> usize {
    catcard_board::BOARD.psram.map_or(0, |p| p.len as usize / 2)
}

/// The LittleFS block size the settings volume is formatted with.
const BLOCK: usize = crate::nvram::BLOCK;

/// A LittleFS volume in a byte slice, read-only: the staged image, mounted so it can be
/// checked before it is written anywhere.
struct Staged<'a>(&'a [u8]);

impl FlashDriver for Staged<'_> {
    type Error = ();
    fn block_size(&self) -> u32 {
        BLOCK as u32
    }
    fn block_count(&self) -> u32 {
        (self.0.len() / BLOCK) as u32
    }
    fn prog_size(&self) -> u32 {
        BLOCK as u32
    }
    fn read(&mut self, block: u32, off: u32, buf: &mut [u8]) -> Result<(), ()> {
        let at = block as usize * BLOCK + off as usize;
        let src = self.0.get(at..at + buf.len()).ok_or(())?;
        buf.copy_from_slice(src);
        Ok(())
    }
    fn prog(&mut self, _: u32, _: u32, _: &[u8]) -> Result<(), ()> {
        Err(())
    }
    fn erase(&mut self, _: u32) -> Result<(), ()> {
        Err(())
    }
}

/// The staged image's settings slots, as the store reads them.
struct StagedSlots<'a> {
    vol: fstool::fs::littlefs::Volume<Staged<'a>, BLOCK, BLOCK>,
}

impl Slots for StagedSlots<'_> {
    fn count(&self) -> u32 {
        crate::settings::SLOT_COUNT
    }
    fn pos(&self, index: u32) -> u32 {
        index
    }
    fn read(&mut self, index: u32, buf: &mut [u8]) -> Result<Option<usize>, MediumError> {
        let mut path = heapless::String::new();
        crate::settings::Files::path(index, &mut path);
        let Ok(mut file) = self.vol.open_file(&path) else {
            return Ok(None);
        };
        let len = (file.len() as usize).min(buf.len());
        let mut got = 0;
        while got < len {
            match file.read(&mut self.vol, &mut buf[got..len]) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(_) => return Err(MediumError),
            }
        }
        Ok(Some(got))
    }
    fn write(&mut self, _: u32, _: &[u8]) -> Result<(), MediumError> {
        Err(MediumError)
    }
    fn clear(&mut self, _: u32) -> Result<(), MediumError> {
        Err(MediumError)
    }
}

/// Check the staged image, ask, and write it over the settings region.
pub(crate) fn screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    let catcard_board::spec::SettingsArea::InternalFlash { start, len } =
        catcard_board::BOARD.settings
    else {
        return say(ui, "not this board");
    };
    let mut lease = match crate::psram::take(crate::psram::Use::Restore) {
        Ok(l) => l,
        Err(e) => return say(ui, e.message()),
    };
    let at = staged_at();
    let psram = lease.bytes();
    let Some(head) = psram.get(at..at + HEADER) else {
        return say(ui, "no staging area");
    };

    // The header: ours, the region's length, and a digest that holds.
    if head[..8] != MAGIC {
        crate::catlog!("restore: nothing staged");
        return say(ui, "nothing staged");
    }
    let staged_len = u32::from_le_bytes([head[8], head[9], head[10], head[11]]);
    if staged_len != len {
        crate::catlog!("restore: staged {} B, region is {} B", staged_len, len);
        return say(ui, "staged image is the wrong size");
    }
    let mut want = [0u8; 32];
    want.copy_from_slice(&head[16..48]);
    let image_at = at + HEADER;
    let Some(image) = psram.get(image_at..image_at + len as usize) else {
        return say(ui, "staged image does not fit");
    };

    menu::blocking_screen(ui.panel, HEAD, "checking the image");
    let got = {
        use purecrypto::hash::{Digest as _, Sha256};
        let mut h = Sha256::new();
        for chunk in image.chunks(4096) {
            h.update(chunk);
        }
        h.finalize()
    };
    if got.as_slice() != want {
        crate::catlog!("restore: staged image fails its SHA-256; not written");
        return say(ui, "image damaged in transfer");
    }

    // It is a volume, and it is this device's.
    let Ok(vol) = fstool::fs::littlefs::Volume::<_, BLOCK, BLOCK>::mount(Staged(image)) else {
        crate::catlog!("restore: staged image does not mount");
        return say(ui, "not a settings volume");
    };
    let mut slots = StagedSlots { vol };
    let Some(mut buf_held) = crate::heap::take(store::SCRATCH) else {
        return say(ui, "not enough memory");
    };
    let buf = buf_held.bytes();
    let pin_gate = crate::pinentry::BootloaderGate::new(gate);
    let mut secret = match login.fetch_secret(&pin_gate) {
        Ok(s) => s,
        Err(_) => return say(ui, "could not read the secret"),
    };
    let root = crate::keywork::run(|_| catcard_settings::nvstore::hash_key(&secret));
    secret.zeroize();
    let ours = store::census(&mut slots, &root, buf);
    let files = ours.files;
    if store::read(&mut slots, &root, buf).is_err() {
        crate::catlog!(
            "restore: image has {} files, none this device's root opens; refused",
            files
        );
        return say(ui, "not this device's settings");
    }
    crate::catlog!(
        "restore: image checks out: {} files, this device's root opens one",
        files
    );

    // Asked on the device. Every wallet's settings on this device become the image's.
    let mut note: heapless::String<32> = heapless::String::new();
    let _ =
        core::fmt::Write::write_fmt(&mut note, format_args!("with {files} files from the image"));
    menu::ask(
        ui.panel,
        "REPLACE all settings?",
        &note,
        "y to write the flash",
    );
    if !menu::confirmed(ui) {
        crate::catlog!("restore: declined");
        return;
    }

    write_region(ui, start, len, image);

    // Nothing staged any more: a second visit should not offer to write it again.
    // SAFETY: an aligned word inside the lease this function holds.
    unsafe { core::ptr::write_volatile(lease.bytes()[at..].as_mut_ptr() as *mut u32, 0) };
    menu::wait_for_any_key(ui);
}

/// Erase and program the region from `image`, a page at a time, reading each back.
///
/// Pages that already match are left alone: an erase is wear, and the part of the region
/// the owner's own settings never touched should not pay for this.
fn write_region(ui: &mut Ui<'_>, start: u32, len: u32, image: &[u8]) {
    let board = catcard_board::BOARD;
    // SAFETY: the settings region from the board table; nothing else has it open -- the
    // settings are mounted per operation and none is running.
    let mut flash = match unsafe {
        catcard_hal::iflash::Internal::open(board.mcu, start, len, board.memory.total_flash_len)
    } {
        Ok(f) => f,
        Err(e) => {
            crate::catlog!("restore: flash would not open: {:?}", e);
            return say(ui, "flash would not open");
        }
    };
    let page = flash.page_size() as usize;
    let pages = flash.pages();
    let Some(mut held) = crate::heap::take(page) else {
        return say(ui, "not enough memory");
    };
    let buf = held.bytes();

    let mut busy = menu::Working::new(ui.panel, HEAD, "writing");
    let (mut written, mut same) = (0u32, 0u32);
    for p in 0..pages {
        let off = p as usize * page;
        let want = &image[off..off + page];
        // SAFETY: inside the region this opened.
        if unsafe { flash.read(off as u32, &mut buf[..page]) }.is_ok() && &buf[..page] == want {
            same += 1;
            continue;
        }
        buf[..page].copy_from_slice(want);
        // SAFETY: page `p` of the settings region, which this is replacing on purpose,
        // after the owner said so.
        let ok = unsafe { flash.erase(p) }.is_ok()
            && unsafe { flash.program(off as u32, &buf[..page]) }.is_ok();
        // Read back what the flash now holds, not what was sent to it.
        // SAFETY: as above.
        let kept = ok
            && unsafe { flash.read(off as u32, &mut buf[..page]) }.is_ok()
            && &buf[..page] == want;
        if !kept {
            crate::catlog!("restore: page {} did not take; stopped", p);
            return say(ui, "a page did not take");
        }
        written += 1;
        busy.tick(ui.panel);
    }
    crate::catlog!(
        "restore: {} pages written, {} already matched",
        written,
        same
    );

    // What the device sees now, from the flash, the same way every read will.
    // SAFETY: read-only mount of the region just written.
    if let Ok(mut files) = unsafe { crate::settings::Files::mount_read_only() } {
        files.log_listing();
    }
    menu::message(ui.panel, HEAD, "settings restored", "restart to be sure");
}

fn say(ui: &mut Ui<'_>, why: &str) {
    menu::message(ui.panel, HEAD, why, "nothing written");
    menu::wait_for_any_key(ui);
}
