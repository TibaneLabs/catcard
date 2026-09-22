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

/// Why the settings volume would not mount.
///
/// The reason is kept rather than flattened to one sentence: "no settings region" covers a
/// board that keeps them elsewhere, a flash configured differently from the board table, and
/// an address that does not divide into pages -- and which of those it is decides what to do
/// next.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum MountFailed {
    /// The region could not be claimed; the flash driver says why.
    Region(crate::nvram::Error),
    /// The region was claimed but holds no filesystem this can read.
    NoFilesystem,
}

/// The settings key for the wallet in force, kept for the session.
///
/// Cleared by [`forget_key`] whenever the key changes.
static mut WALLET_KEY: Option<catcard_settings::nvstore::Key> = None;

/// Forget the cached settings key. Called whenever the wallet in force changes.
pub(crate) fn forget_key() {
    // SAFETY: foreground only, single core; the write finishes within this statement.
    unsafe { *core::ptr::addr_of_mut!(WALLET_KEY) = None };
}

/// The settings key of the wallet in force -- **its own file, not the master's**.
///
/// # Every key has its own settings
///
/// A slot is encrypted under six SHA-256 rounds over the 72-byte stash of the wallet it
/// belongs to, so the hundred `NNN.aes` files hold one object per wallet this device has
/// ever been in. Nothing indexes them: finding the right one is trying each in turn,
/// decrypting two bytes to see whether they come out as `{"` and only then hashing the
/// rest ([`catcard_settings::store::read`]). That is why the key is the whole of the
/// addressing, and why a wallet whose key we compute differently from stock's simply has
/// a different file rather than a broken one.
///
/// So a BIP-85 child has its own nickname, its own multisig registrations and its own
/// Seed Vault, and none of them follow the owner back to the root.
///
/// # Which stash
///
/// - **Words**, with no passphrase: the entropy packed as the secure element holds it.
///   For the root that is the stash it returned; for a BIP-85 child or a temporary seed
///   it is that wallet's own entropy in the same layout, which is what stock would have
///   stored had the owner made it permanent.
/// - **A passphrase in force**: the master node itself, as
///   [`encode_xprv`](catcard_callgate::pin::encode_xprv) -- there is no entropy that
///   reproduces a passphrase wallet, so there is nothing else of the right shape. `[?]`:
///   stock is known to keep per-wallet settings for passphrase wallets, but which stash
///   it hashes for them is not something this firmware can confirm. Being wrong here
///   costs interoperability for that wallet's settings and nothing else -- the file we
///   read is the file we wrote.
///
/// Deriving this can cost a stretch, so it is cached for the session and dropped by
/// [`forget_key`] the moment the wallet changes.
pub(crate) fn wallet_key(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    panel: &mut crate::display::Panel,
    head: &str,
) -> Result<catcard_settings::nvstore::Key, &'static str> {
    use catcard_settings::nvstore;
    use zeroize::Zeroize as _;

    // SAFETY: foreground only, single core; the borrow ends within this statement.
    if let Some(key) = unsafe { (*core::ptr::addr_of!(WALLET_KEY)).clone() } {
        return Ok(key);
    }

    let key = if crate::key::is_root() {
        // The stored wallet: the stash exactly as the secure element returns it, which
        // is what stock hashes and what every settings file this device already has was
        // written under.
        let pin_gate = crate::pinentry::BootloaderGate::new(gate);
        let mut secret = login
            .fetch_secret(&pin_gate)
            .map_err(|_| "could not read the secret")?;
        let key = crate::keywork::run(|_| nvstore::hash_key(&secret));
        secret.zeroize();
        key
    } else if crate::passphrase::is_set() {
        let master = crate::menu::master_quietly(gate, login, panel, head)?;
        let mut stash =
            catcard_callgate::pin::encode_xprv(&master.chain_code, master.secret_bytes());
        drop(master);
        let key = crate::keywork::run(|_| nvstore::hash_key(&stash));
        stash.zeroize();
        key
    } else {
        let (mut ent, len) = crate::menu::seed_entropy(gate, login, panel, head)?;
        let stash = catcard_callgate::pin::encode_bip39(&ent[..len]);
        ent.zeroize();
        let mut stash = stash.map_err(|_| "that seed length has no stash")?;
        let key = crate::keywork::run(|_| nvstore::hash_key(&stash));
        stash.zeroize();
        key
    };
    // SAFETY: as above.
    unsafe { *core::ptr::addr_of_mut!(WALLET_KEY) = Some(key.clone()) };
    Ok(key)
}

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
    pub unsafe fn mount() -> Result<Self, MountFailed> {
        // SAFETY: forwarding the caller's guarantee.
        let blocks = unsafe { Blocks::open() }.map_err(MountFailed::Region)?;
        let vol = Volume::mount(blocks).map_err(|_| MountFailed::NoFilesystem)?;
        Ok(Self { vol })
    }

    /// Mount it for reading only: nothing mounted this way can change what it reads.
    ///
    /// # Safety
    /// The region is mapped and readable; nothing is written.
    pub unsafe fn mount_read_only() -> Result<Self, MountFailed> {
        // SAFETY: forwarding the caller's guarantee.
        let blocks = unsafe { Blocks::open_read_only() }.map_err(MountFailed::Region)?;
        let vol = Volume::mount(blocks).map_err(|_| MountFailed::NoFilesystem)?;
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

/// Longest nickname kept.
///
/// Stock's own limit is not written down anywhere we can read, and a device turned up with
/// one far longer than the thirty-two bytes this used to allow -- which the reader then
/// refused, so the nickname silently did not appear. Long enough is better than tidy: the
/// screen wraps what it is given, and anything past this is shown cut rather than dropped.
pub const NICK_MAX: usize = 192;

/// The owner's nickname, read from the pre-login blob at boot.
static mut NICK: [u8; NICK_MAX] = [0; NICK_MAX];

/// Read the pre-login settings and keep the nickname, for the screen before the PIN prompt.
///
/// The pre-login blob is encrypted under **thirty-two zero bytes**, so this needs no secret
/// and can run before login -- which is the point: stock shows the nickname there, so the
/// owner can tell their device from someone else's before typing a PIN into it.
///
/// Every failure is silent and returns `None`. This is on the boot path, where a missing
/// nickname must cost nothing: no settings region, no filesystem, no blob, no `nick` key and
/// a corrupt blob all mean the same thing here -- draw the PIN prompt as before. The log
/// says which, for anyone asking why their nickname did not appear.
///
/// # Safety
/// Call once, from the boot path, before anything else uses the settings volume.
pub(crate) unsafe fn load_nickname() -> Option<&'static str> {
    use catcard_settings::json::{self, Doc};
    use catcard_settings::nvstore;
    use catcard_settings::store::{self, SCRATCH};

    // The blob, off the stack: boot has the least stack to spare and this is four
    // kilobytes. From the heap and given back on return, rather than four kilobytes
    // held for the life of a device to read one string once.
    let mut blob_held = crate::heap::take(SCRATCH)?;
    let blob: &mut [u8] = blob_held.bytes();

    // SAFETY: read-only: the mount's erase and program refuse, so nothing here can change
    // the settings of a device whose PIN has not even been entered yet.
    let mut files = match unsafe { Files::mount_read_only() } {
        Ok(f) => f,
        Err(why) => {
            crate::catlog!("nick: no settings store: {:?}", why);
            return None;
        }
    };
    let n = match store::read(&mut files, &nvstore::prelogin_key(), blob) {
        Ok(n) => n,
        Err(e) => {
            crate::catlog!("nick: pre-login settings: {:?}", e);
            return None;
        }
    };
    // Every way this can come to nothing says so. A nickname that does not appear is
    // otherwise indistinguishable from one that was never set, and the difference is
    // between "type it again" and "this firmware cannot read what stock wrote".
    let doc = match Doc::parse(&blob[..n]) {
        Ok(d) => d,
        Err(e) => {
            crate::catlog!("nick: {} bytes of settings would not parse: {:?}", n, e);
            return None;
        }
    };
    let Some(raw) = doc.get("nick") else {
        crate::catlog!("nick: not set ({} pre-login key(s))", doc.len());
        return None;
    };

    // SAFETY: as above; written once here and read-only afterwards.
    let nick: &'static mut [u8; NICK_MAX] = unsafe { &mut *core::ptr::addr_of_mut!(NICK) };
    let len = match json::unescape(raw, nick) {
        Ok(n) => n,
        Err(e) => {
            crate::catlog!("nick: {} byte(s) of it will not fit: {:?}", raw.len(), e);
            return None;
        }
    };
    if len == 0 {
        crate::catlog!("nick: set but empty");
        return None;
    }
    let text = core::str::from_utf8(&nick[..len]).ok()?;
    crate::catlog!("nick: {} byte(s) from the pre-login settings", len);
    Some(text)
}

/// Debug: draw the before-login nickname screen, and hold it.
///
/// The boot-path screen is up for three seconds between the bootloader's warning and the
/// PIN prompt, which is long enough to read and short enough to argue about. This draws the
/// same thing from the menu and waits, so what it looks like is a question that can be
/// answered rather than caught.
pub(crate) fn show_nickname_screen(ui: &mut crate::ui::Ui<'_>) {
    // SAFETY: foreground only, as the boot path's call is.
    let nick = unsafe { load_nickname() };
    match nick {
        Some(text) => {
            crate::pinentry::show_nickname(ui.panel, ui.matrix, ui.drbg, text);
            crate::menu::wait_for_any_key(ui);
        }
        None => {
            crate::menu::message(ui.panel, "Nickname", "none set", "or it would not read");
            crate::menu::wait_for_any_key(ui);
        }
    }
}

/// Copy the whole settings region to a card, byte for byte.
///
/// A settings volume holds things whose only copy is on this device -- notes, passwords,
/// multisig wallets. The store is built to survive losing power mid-save, but it is not
/// built to survive a bug in this firmware, and the write path is new. So there is a way to
/// take a copy first, and it is worth taking before letting anything write.
///
/// Nothing is decrypted: the slots go to the card exactly as they sit in flash, still
/// encrypted under keys this file never sees here. A card holding this is worth what an
/// attacker's copy of the flash is worth -- which is why the slots are encrypted.
///
/// The read is direct from memory-mapped flash, so a 512 KB region needs no buffer at all.
pub(crate) fn backup_to_card(ui: &mut crate::ui::Ui<'_>) {
    use core::fmt::Write as _;

    let (start, len) = match catcard_board::BOARD.settings {
        catcard_board::spec::SettingsArea::InternalFlash { start, len } => (start, len),
        _ => {
            crate::menu::message(ui.panel, "Settings to SD", "not this board", "");
            crate::menu::wait_for_any_key(ui);
            return;
        }
    };

    crate::menu::blocking_screen(ui.panel, "Settings to SD", "copying");
    // SAFETY: internal flash is memory-mapped and readable; the region is the board
    // table's, and this only reads it.
    let bytes = unsafe { core::slice::from_raw_parts(start as *const u8, len as usize) };

    let mut note = heapless::String::<48>::new();
    match crate::menu::write_card_file("/settings.img", bytes) {
        Ok(()) => {
            let _ = write!(note, "{} KB written", len / 1024);
            crate::catlog!("settings: {} bytes copied to /settings.img", len);
            crate::menu::message(ui.panel, "Settings to SD", "/settings.img", note.as_str());
        }
        Err(why) => {
            crate::catlog!("settings: backup failed: {}", why);
            crate::menu::message(ui.panel, "Settings to SD", why, "nothing written");
        }
    }
    crate::menu::wait_for_any_key(ui);
}

/// Set the nickname shown before the PIN prompt.
///
/// It goes in the **pre-login** blob, under a key of thirty-two zero bytes, which is where
/// stock keeps it and the only place it could be: the screen that shows it runs before
/// anyone has logged in, so it cannot be under a key derived from the seed.
///
/// This is the first thing in this firmware to *write* the settings store. Everything it
/// does not touch keeps its exact bytes -- see [`catcard_settings::store::set`] -- so a
/// device that has been stock keeps its stock settings.
pub(crate) fn edit_nickname(ui: &mut crate::ui::Ui<'_>) {
    use catcard_settings::nvstore;
    use catcard_settings::store::{self, SCRATCH};

    let Some(entry) = crate::passphrase::read(ui, "Nickname") else {
        return;
    };
    let text = entry.as_str();
    if text.len() > NICK_MAX {
        let mut why = heapless::String::<48>::new();
        let _ =
            core::fmt::Write::write_fmt(&mut why, format_args!("{NICK_MAX} characters at most"));
        crate::menu::message(ui.panel, "Nickname", "too long", why.as_str());
        crate::menu::wait_for_any_key(ui);
        return;
    }

    crate::menu::blocking_screen(ui.panel, "Nickname", "saving");
    // SAFETY: foreground only; the menu waits for this screen to return, and nothing else
    // touches the settings region. Writable, unlike everywhere else that opens this store.
    let mut files = match unsafe { Files::mount() } {
        Ok(f) => f,
        Err(why) => {
            crate::catlog!("nick: mount for writing failed: {:?}", why);
            crate::menu::message(ui.panel, "Nickname", "no settings store", "nothing saved");
            crate::menu::wait_for_any_key(ui);
            return;
        }
    };

    // Two full-slot buffers: one holds the settings while the key is changed, the other
    // seals them. Four kilobytes each, which is a screen's whole task stack, so they
    // come from the heap and go back when this returns.
    let (Some(mut doc_held), Some(mut seal_held)) =
        (crate::heap::take(SCRATCH), crate::heap::take(SCRATCH))
    else {
        crate::menu::message(ui.panel, "Nickname", "not enough", "memory");
        crate::menu::wait_for_any_key(ui);
        return;
    };
    let doc: &mut [u8] = doc_held.bytes();
    let seal: &mut [u8] = seal_held.bytes();

    // Which slot to write is drawn, so repeated saves spread over the hundred rather than
    // wearing one out. A DRBG that will not answer is not a reason to lose a nickname: the
    // spread is wear levelling, not a secret, so slot zero will do.
    let choose = ui.drbg.below(SLOT_COUNT).unwrap_or(0);
    let key = nvstore::prelogin_key();
    match store::set(&mut files, &key, "nick", text, choose, doc, seal) {
        Ok(slot) => {
            crate::catlog!("nick: saved to slot {:03x}", slot);
            crate::menu::message(ui.panel, "Nickname", text, "saved");
        }
        Err(e) => {
            crate::catlog!("nick: save failed: {:?}", e);
            crate::menu::message(ui.panel, "Nickname", "could not save", "nothing changed");
        }
    }
    crate::menu::wait_for_any_key(ui);
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
    let mut files = match unsafe { Files::mount_read_only() } {
        Ok(f) => f,
        Err(why) => {
            crate::catlog!("settings: mount failed: {:?}", why);
            let mut l = Note::new();
            let _ = write!(l, "mount: {why:?}");
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
            let _ = write!(
                pre,
                "pre-login: age {age}, {} keys",
                doc.as_ref().map(|d| d.len()).unwrap_or(0)
            );
            let _ = notes.push(pre.clone());
            // The nickname goes on its own line and is never squeezed into the summary: a
            // `heapless::String` that overflows drops the whole argument rather than
            // truncating it, so a long nickname rendered as nothing and read as "not set".
            pre.clear();
            let room = pre.capacity() - 6;
            let _ = write!(pre, "nick: {}", nick.get(..room).unwrap_or(nick));
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
