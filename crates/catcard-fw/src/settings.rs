//! The settings blob on this board's medium.
//!
//! The rules live in [`catcard_settings::store`]; the format in
//! [`catcard_settings::nvstore`]. This is the medium: on mk4/mk5/Q1 the slots are files in
//! the LittleFS volume on internal flash, named as stock names them, so a device that has
//! been either firmware still finds its own settings.
//!
//! The mk3 keeps its slots in raw SPI-NOR blocks instead, with the block's byte offset as
//! the `pos` in the counter; that medium is not wired up yet.

use catcard_settings::store::{MediumError, Slots};

use crate::nvram::Blocks;

/// Slots stock keeps on a LittleFS device, as `settings/000.aes` upwards.
/// Source: hw-reference/settings-nvstore-format.md §1 [C]
pub const SLOT_COUNT: u32 = 100;

/// The LittleFS volume, sized for the 512-byte blocks the region is formatted with.
type Volume =
    fstool::fs::littlefs::Volume<Blocks, { crate::nvram::BLOCK }, { crate::nvram::BLOCK }>;

/// Settings slots as files in the internal-flash volume.
pub struct Files {
    vol: Volume,
}

impl Files {
    /// Mount the settings volume.
    ///
    /// # Safety
    /// As [`Blocks::open`]: nothing else may touch the region, and each write stalls the bus.
    pub unsafe fn mount() -> Result<Self, &'static str> {
        // SAFETY: forwarding the caller's guarantee.
        let blocks = unsafe { Blocks::open() }.map_err(|_| "no settings region")?;
        let vol = Volume::mount(blocks).map_err(|_| "no filesystem there")?;
        Ok(Self { vol })
    }

    /// The path of slot `index`, as stock writes it: `settings/%03x.aes`.
    fn path(index: u32, out: &mut heapless::String<24>) {
        use core::fmt::Write as _;
        let _ = write!(out, "/settings/{index:03x}.aes");
    }
}

impl Slots for Files {
    fn count(&self) -> u32 {
        SLOT_COUNT
    }

    /// The file index, which is what stock puts in the counter on this medium.
    fn pos(&self, index: u32) -> u32 {
        index
    }

    fn read(&mut self, index: u32, buf: &mut [u8]) -> Result<Option<usize>, MediumError> {
        let mut path = heapless::String::new();
        Self::path(index, &mut path);
        // A slot that is not there is not an error: most of the hundred never are.
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

    fn write(&mut self, index: u32, bytes: &[u8]) -> Result<(), MediumError> {
        let mut path = heapless::String::new();
        Self::path(index, &mut path);
        let mut file = self
            .vol
            .open_or_create_file(&path)
            .map_err(|_| MediumError)?;
        file.write_all(&mut self.vol, bytes)
            .map_err(|_| MediumError)?;
        file.set_len(&mut self.vol, bytes.len() as u32)
            .map_err(|_| MediumError)?;
        file.sync(&mut self.vol).map_err(|_| MediumError)
    }

    fn clear(&mut self, index: u32) -> Result<(), MediumError> {
        let mut path = heapless::String::new();
        Self::path(index, &mut path);
        // Already gone is the outcome asked for.
        match self.vol.remove_file(&path) {
            Ok(()) => Ok(()),
            Err(_) => Ok(()),
        }
    }
}

/// Debug: mount the settings volume, read what is there, write a slot and read it back.
///
/// The settings store erases and programs internal flash, which is the one medium on this
/// device that cannot be undone by a power cycle. So it is exercised from the Debug menu
/// first -- under the **pre-login key**, which only ever holds a nickname and a few
/// preferences, never a seed's settings -- and only once that has been watched working
/// does anything on the boot path depend on it.
pub(crate) fn probe(ui: &mut crate::ui::Ui<'_>) {
    use catcard_settings::json::Doc;
    use catcard_settings::nvstore;
    use catcard_settings::store::{self, SCRATCH};
    use core::fmt::Write as _;

    type Line = heapless::String<48>;
    let mut lines: heapless::Vec<Line, 8> = heapless::Vec::new();

    // SAFETY: foreground only; the menu waits for this screen to return, and nothing else
    // touches the settings region.
    let mut files = match unsafe { Files::mount() } {
        Ok(f) => f,
        Err(why) => {
            let mut l = Line::new();
            let _ = write!(l, "mount: {why}");
            let _ = lines.push(l);
            crate::menu::info(ui.panel, "Settings", &lines);
            crate::menu::wait_for_any_key(ui);
            return;
        }
    };
    let mut l = Line::new();
    let _ = write!(l, "mounted, {} slots", Slots::count(&files));
    let _ = lines.push(l);

    let key = nvstore::prelogin_key();
    let mut buf = [0u8; SCRATCH];
    let mut l = Line::new();
    match store::read(&mut files, &key, &mut buf) {
        Ok(n) => {
            let age = Doc::parse(&buf[..n])
                .ok()
                .and_then(|d| d.get_u64("_age"))
                .unwrap_or(0);
            let _ = write!(l, "read {n} bytes, age {age}");
        }
        Err(e) => {
            let _ = write!(l, "read: {e:?}");
        }
    }
    let _ = lines.push(l);

    // Write one key and read it back. `_age` goes up, as a save must, so a later read
    // prefers this over whatever was there.
    let existing = store::read(&mut files, &key, &mut buf).unwrap_or(0);
    let age = Doc::parse(&buf[..existing])
        .map(|d| store::next_age(&d))
        .unwrap_or(1);
    let mut json: heapless::String<64> = heapless::String::new();
    let _ = write!(json, r#"{{"_age":{age},"probe":{age}}}"#);
    let mut scratch = [0u8; SCRATCH];
    let mut l = Line::new();
    match store::write(&mut files, &key, json.as_bytes(), age as u32, &mut scratch) {
        Ok(slot) => {
            let _ = write!(l, "wrote slot {slot:03x}");
            let _ = lines.push(l);
            let mut l = Line::new();
            match store::read(&mut files, &key, &mut buf) {
                Ok(n) if &buf[..n] == json.as_bytes() => {
                    let _ = write!(l, "read back: matches");
                }
                Ok(n) => {
                    let _ = write!(l, "read back: {n} bytes, differs");
                }
                Err(e) => {
                    let _ = write!(l, "read back: {e:?}");
                }
            }
            let _ = lines.push(l);
        }
        Err(e) => {
            let _ = write!(l, "write: {e:?}");
            let _ = lines.push(l);
        }
    }
    crate::catlog!("settings: probe age {}", age);
    crate::menu::info(ui.panel, "Settings", &lines);
    crate::menu::wait_for_any_key(ui);
}
