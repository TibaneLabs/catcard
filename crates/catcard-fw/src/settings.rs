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

/// Debug: read the settings blobs and show what is in them, decrypted.
///
/// Read-only, deliberately. This is the screen used to check our understanding of a store
/// another firmware wrote, and the settings on such a device are the owner's -- notes,
/// passwords, wallet records. Nothing here writes: the write path has its own tests, and a
/// diagnostic that can lose someone's data is not a diagnostic.
///
/// Two blobs are shown. The **pre-login** one is under a key of thirty-two zero bytes and
/// holds only a nickname and a few preferences. The **wallet** one is under
/// `hash_key(raw stash)` -- six SHA-256 rounds over the secret as the secure element
/// returns it -- and holds everything else.
pub(crate) fn inspect(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut crate::ui::Ui<'_>,
) {
    use catcard_settings::json::Doc;
    use catcard_settings::nvstore;
    use catcard_settings::store::{self, SCRATCH};
    use catcard_ui::scroll::Line as Row;
    use core::fmt::Write as _;
    use zeroize::Zeroize as _;

    // The decrypted blob outlives the document that borrows its values, so it is declared
    // first: the rows below point into it rather than copying it.
    let mut buf = [0u8; SCRATCH];

    type Note = heapless::String<64>;
    // Owned text the document borrows: the summary lines, which have to be formatted.
    let mut notes: heapless::Vec<Note, 6> = heapless::Vec::new();
    let mut rows: heapless::Vec<Row, 48> = heapless::Vec::new();

    // SAFETY: foreground only; the menu waits for this screen to return, and nothing else
    // touches the settings region.
    let mut files = match unsafe { Files::mount() } {
        Ok(f) => f,
        Err(why) => {
            let mut l = Note::new();
            let _ = write!(l, "mount: {why}");
            let _ = notes.push(l);
            let _ = rows.push(Row::title("Settings"));
            let _ = rows.push(Row::body(notes[0].as_str()));
            crate::menu::show_doc(ui, &rows, false, false);
            return;
        }
    };

    // The pre-login blob first: it needs no secret, so a device that cannot be logged into
    // still says something. Only its age and nickname are carried out, because the buffer
    // is needed again for the wallet blob.
    let mut pre = Note::new();
    match store::read(&mut files, &nvstore::prelogin_key(), &mut buf) {
        Ok(n) => {
            let doc = Doc::parse(&buf[..n]).ok();
            let age = doc.as_ref().and_then(|d| d.get_u64("_age")).unwrap_or(0);
            let nick = doc.as_ref().and_then(|d| d.get_str("nick")).unwrap_or("-");
            let _ = write!(pre, "pre-login: age {age}, {} keys, nick {nick}",
                doc.as_ref().map(|d| d.len()).unwrap_or(0));
        }
        Err(e) => {
            let _ = write!(pre, "pre-login: {e:?}");
        }
    }
    let _ = notes.push(pre);

    // Now the wallet blob, which needs the stash the secure element holds.
    crate::menu::blocking_screen(ui.panel, "Settings", "reading seed");
    let pin_gate = crate::pinentry::BootloaderGate::new(gate);
    let mut secret = match login.fetch_secret(&pin_gate) {
        Ok(s) => s,
        Err(_) => {
            let mut l = Note::new();
            let _ = write!(l, "wallet: could not read the secret");
            let _ = notes.push(l);
            show(ui, &notes, &rows);
            return;
        }
    };
    // Six hashes over the raw stash. Derived from the secret, so it runs with interrupts
    // masked; the slot scan below does not, because its shape is fixed -- a set number of
    // slots, a fixed slot length, and no branch that depends on a key byte.
    let key = crate::keywork::run(|_| nvstore::hash_key(&secret));
    secret.zeroize();

    let mut wallet = Note::new();
    let found = store::read(&mut files, &key, &mut buf);
    match found {
        Ok(n) => {
            let _ = write!(wallet, "wallet: {n} bytes");
        }
        Err(e) => {
            let _ = write!(wallet, "wallet: {e:?}");
        }
    }
    let _ = notes.push(wallet);

    // Header lines, then every key the wallet blob holds with its value underneath. The
    // key names are small and the values full size: the point of the screen is the values,
    // and a value is what tells us the decryption is right.
    let _ = rows.push(Row::title("Settings"));
    for n in notes.iter() {
        let _ = rows.push(Row::body(n.as_str()).small());
    }
    if let Ok(n) = found {
        if let Ok(doc) = Doc::parse(&buf[..n]) {
            for e in doc.entries() {
                let _ = rows.push(Row::body(e.key).small());
                let _ = rows.push(Row::body(e.raw));
            }
        } else {
            let _ = rows.push(Row::body("the blob decrypted but is not JSON"));
        }
    }
    crate::menu::show_doc(ui, &rows, false, false);
}

/// Show just the summary lines, for the paths that stop early.
fn show(
    ui: &mut crate::ui::Ui<'_>,
    notes: &[heapless::String<64>],
    _rows: &[catcard_ui::scroll::Line<'_>],
) {
    use catcard_ui::scroll::Line as Row;
    let mut rows: heapless::Vec<Row, 8> = heapless::Vec::new();
    let _ = rows.push(Row::title("Settings"));
    for n in notes {
        let _ = rows.push(Row::body(n.as_str()).small());
    }
    crate::menu::show_doc(ui, &rows, false, false);
}
