//! Signing a transaction from the SD card.
//!
//! The file comes off a card, so every byte of it is someone else's. What protects the
//! owner is not this module's parsing -- that is [`outscript`]'s, and strict -- but the
//! review in [`catcard_wallet::psbtview`]: the amounts, destinations and fee are worked out
//! from what the signature will commit to, the fee cap and the sighash policy can refuse
//! outright, and an output claimed as change has to be rebuildable from our own key.
//!
//! This is the part that moves bytes and draws screens: read the file, show what it does,
//! sign each of our inputs on a keypress, write the result back.
//!
//! # Where a PSBT lives while it is worked on
//!
//! Every signature rewrites the whole container, so two buffers are needed and the work
//! alternates between them. On mk4/mk5/Q1 they are windows in the 8 MB PSRAM, well clear of
//! the firmware-staging area; on mk3, which has none, they are static RAM and therefore
//! much smaller -- a transaction too big for them is refused with its size on screen rather
//! than truncated.

use catcard_callgate::Callgate;
use catcard_wallet::psbtv2::{self, V2};
use catcard_wallet::psbtview::{self, Policy, Refusal, SighashPolicy, timelock};
use catcard_wallet::signer;
use outscript::psbt::Psbt;

use crate::display;
use crate::menu::{self, Storage};
use crate::ui::Ui;

/// Where the signed PSBT is written back, and what the screen says it is called.
const SIGNED_NAME: &str = "/SIGNED.PSB";

/// Where a transaction that needs nothing further is written, as hex.
///
/// Hex rather than raw bytes because that is what a node or a block explorer takes to
/// broadcast: `bitcoin-cli sendrawtransaction <the file's contents>`.
const FINAL_NAME: &str = "/FINAL.TXN";

/// Where a signed transaction and its finalised form are written, and whether to offer the
/// on-device transports afterwards.
///
/// A single PSBT off the card writes the two fixed names ([`SIGNED_NAME`], [`FINAL_NAME`])
/// and, on a Q1, offers the signed bytes back as a QR -- the whole point being to hand one
/// transaction back through whatever the owner has. A batch writes one signed file *per
/// source* so the results do not overwrite each other, and skips the per-file QR and NFC
/// offers: a queue of them, one interrupting the next, is not what "sign all of these"
/// asks for.
pub(crate) struct SignDest<'a> {
    /// Where the signed PSBT is written, and what the screen calls it.
    pub signed_name: &'a str,
    /// Where a fully-signed transaction is written, as broadcast-ready hex.
    pub final_name: &'a str,
    /// Whether to offer the signed transaction back over QR (Q1) and NFC.
    pub offer_transports: bool,
}

impl SignDest<'static> {
    /// The single-PSBT destination: the two fixed names, transports offered.
    pub(crate) const SINGLE: SignDest<'static> = SignDest {
        signed_name: SIGNED_NAME,
        final_name: FINAL_NAME,
        offer_transports: true,
    };
}

/// Outputs on one page of the review, change included.
///
/// The review is paged, not capped: a transaction with more outputs than this shows them
/// a page at a time, each page read to its end before the next, and the Sign key is on
/// the last page only. An output the owner cannot see is one they cannot refuse, so every
/// output is on a screen before the key that signs them all is offered. Eight is what a
/// page's line budget holds comfortably; it is a screen fact, not a limit on the
/// transaction.
const PAGE: usize = 8;

/// The fewest bytes one output can occupy in a PSBT: an 8-byte amount, a 1-byte script
/// length (an empty script), and the 1-byte terminator of its empty output map.
///
/// The only limit on how many outputs a transaction may have is therefore the buffer the
/// PSBT sits in -- `buf.len() / MIN_OUTPUT_BYTES` -- which is the mk3's static buffer or
/// half the PSRAM lease. The screen imposes none. A parsed PSBT cannot exceed that
/// figure, so the check against it in [`review_and_sign`] is a statement of the bound
/// rather than a refusal anyone will see.
const MIN_OUTPUT_BYTES: usize = 8 + 1 + 1;

/// Most inputs signed in one pass.
const MAX_INPUTS: usize = 64;

/// The mk3's buffers, in static RAM. A single-key spend is a few hundred bytes; this holds
/// a transaction with a few dozen inputs, or a handful that carry whole previous
/// transactions.
#[cfg(feature = "board-mk3")]
const STATIC_BUF: usize = 16 * 1024;
#[cfg(feature = "board-mk3")]
static mut BUF_A: [u8; STATIC_BUF] = [0; STATIC_BUF];
#[cfg(feature = "board-mk3")]
static mut BUF_B: [u8; STATIC_BUF] = [0; STATIC_BUF];

/// The two working buffers and what keeps them ours.
///
/// On a board with PSRAM this is a lease on the whole region, which is released when the
/// screen returns however it returns. There is no reserved slice for signing: PSRAM is
/// scratch and whoever holds it has all of it, so the thing that keeps a staged firmware
/// image and a PSBT apart is that both are refused while the other is held, not an
/// address range each promises to stay inside.
///
/// On mk3, which has no PSRAM, they are two static buffers and there is nothing to hold:
/// nothing else on that board wants them.
enum Workspace {
    #[cfg(feature = "board-mk3")]
    Static,
    #[cfg(not(feature = "board-mk3"))]
    Psram(crate::psram::Lease),
}

impl Workspace {
    /// Take the memory, or say in a few words why not.
    fn take() -> Result<Self, &'static str> {
        #[cfg(feature = "board-mk3")]
        {
            Ok(Workspace::Static)
        }
        #[cfg(not(feature = "board-mk3"))]
        {
            // The refusal names what has it. "Busy" alone leaves someone power-cycling
            // a device that is doing exactly what they asked it to a minute ago.
            crate::psram::take(crate::psram::Use::Signing)
                .map(Workspace::Psram)
                .map_err(crate::psram::Unavailable::message)
        }
    }

    /// The two halves, for as long as the workspace lives.
    fn split(&mut self) -> (&mut [u8], &mut [u8]) {
        #[cfg(feature = "board-mk3")]
        {
            let Workspace::Static = self;
            // SAFETY: foreground only, one signing screen at a time, and the returned
            // borrows end with the workspace.
            unsafe {
                (
                    &mut *core::ptr::addr_of_mut!(BUF_A),
                    &mut *core::ptr::addr_of_mut!(BUF_B),
                )
            }
        }
        #[cfg(not(feature = "board-mk3"))]
        {
            let Workspace::Psram(lease) = self;
            let all = lease.bytes();
            // A word-aligned split, because everything that writes this region writes it
            // in whole words and a buffer starting mid-word would have its first store
            // straddle the boundary.
            let half = (all.len() / 2) & !3;
            all.split_at_mut(half)
        }
    }
}

/// Characters an amount can take, unit included.
///
/// A PSBT can claim any `u64`, and the widest rendering of `u64::MAX` is bits or mBTC at
/// 26 characters (18 whole digits, a point, two decimals, and ` bits`). Thirty-two leaves
/// room and keeps every amount buffer in this file one named size.
const AMOUNT_LEN: usize = 32;

/// An amount, written the way the owner asked for it: e.g. `0.00012345 BTC`, or
/// `12345 sats`.
///
/// **The only place in the firmware that turns satoshis into text**, which is what lets
/// the Display units setting be one setting rather than a rule every screen has to
/// remember. The unit's name comes out with the number, so a caller cannot print an
/// amount in bits and label it BTC.
///
/// The buffer is [`AMOUNT_LEN`] wide, which is what the longest unit needs for the
/// largest `u64` a PSBT can claim -- see the note there. A `write!` that ran out of room
/// would leave a *truncated number* on a signing screen, which is the one kind of display
/// bug that could cost someone their coins.
fn btc(sats: u64, out: &mut heapless::String<AMOUNT_LEN>) {
    let _ = crate::prefs::current().units.write(sats, out);
}

/// Mount the card and hand the volume to `f`.
///
/// Every entry point here needs the same bring-up, and the specific failure has to reach
/// the screen rather than a generic "card error".
fn with_card<T>(
    f: impl FnOnce(
        &mut catcard_sd::AnyVolume<catcard_sd::Sectors<catcard_hal::sdmmc::Sdmmc>, 512>,
    ) -> Result<T, &'static str>,
) -> Result<T, &'static str> {
    let mut why: &'static str = "card error";
    let mut vol: catcard_sd::AnyVolume<_, 512> = catcard_sd::AnyVolume::mount_with(|| {
        // SAFETY: nothing else has claimed SDMMC1 or its pins while this screen is open.
        let mut dev = match unsafe { catcard_hal::sdmmc::Sdmmc::init(&catcard_board::BOARD) } {
            Ok(d) => d,
            Err(_) => {
                why = "controller failed";
                return Err(());
            }
        };
        #[allow(unused_mut)]
        let mut card = match catcard_sd::init(&mut dev) {
            Ok(c) => c,
            Err(catcard_sd::Error::NoCard) => {
                why = "no card in slot";
                return Err(());
            }
            Err(_) => {
                why = "card would not start";
                return Err(());
            }
        };
        // Transparent decryption for the signing paths' file access, like `mount_card`.
        #[cfg(not(feature = "board-mk3"))]
        crate::sdcrypt::apply_to(&mut card);
        Ok(catcard_sd::Sectors::new(dev, card))
    })
    .map_err(|e| match e {
        catcard_sd::MountError::Device => why,
        catcard_sd::MountError::NoFilesystem => "not FAT or exFAT",
    })?;
    f(&mut vol)
}

/// The one `.psbt` in the card's root directory, if there is exactly one.
///
/// What "Ready to Sign" means: a card carrying a single transaction needs no file picker.
/// Two or more, and the owner picks -- signing the wrong one of two transactions is not a
/// choice to make on their behalf. Anything already written by a previous signing
/// (`SIGNED.PSB`) is skipped, so a finished transaction does not present itself again.
fn lone_psbt(storage: Storage) -> Option<heapless::String<{ PATH_MAX }>> {
    match storage {
        Storage::Sd => with_card(|vol| Ok(find_lone_psbt(vol))),
        #[cfg(not(feature = "board-mk3"))]
        Storage::Vdisk => menu::with_vdisk(|vol| Ok(find_lone_psbt(vol))),
    }
    .ok()
    .flatten()
}

/// The one `.psbt` in the root of an already-mounted volume, if there is exactly one.
///
/// Generic over the backing driver so the card and the Virtual Disk share it; the "exactly
/// one, and not our own `SIGNED.PSB`" rule is the same on both.
fn find_lone_psbt<D: catcard_sd::fat::SectorDriver>(
    vol: &mut catcard_sd::AnyVolume<D, 512>,
) -> Option<heapless::String<PATH_MAX>> {
    let mut found: Option<heapless::String<PATH_MAX>> = None;
    let mut several = false;
    let _ = vol.enumerate("", |name, is_dir, _| {
        if is_dir || several {
            return;
        }
        let lower = name.trim();
        // Split at the last dot rather than slice at a byte count: a long name is
        // UTF-8, and a byte offset can land inside a character, which panics.
        let is_psbt = lower
            .rsplit_once('.')
            .is_some_and(|(stem, ext)| !stem.is_empty() && ext.eq_ignore_ascii_case("psbt"))
            && !lower.eq_ignore_ascii_case(&SIGNED_NAME[1..]);
        if !is_psbt {
            return;
        }
        if found.is_some() {
            several = true;
            found = None;
            return;
        }
        let mut path: heapless::String<PATH_MAX> = heapless::String::new();
        if path.push('/').is_ok() && path.push_str(name).is_ok() {
            found = Some(path);
        }
    });
    found
}

/// Longest path this screen carries.
const PATH_MAX: usize = 160;

/// Read the picked file from the SD card into `buf`. Returns its length, or why not.
///
/// The SD-only entry point the rest of the firmware uses (2FA token, backups, verify, …).
/// The sign flow goes through [`read_source_file`], which can also read the Virtual Disk.
pub(crate) fn read_card_file(path: &str, buf: &mut [u8]) -> Result<usize, &'static str> {
    with_card(|vol| read_file(vol, path, buf))
}

/// Read the picked file from the chosen storage into `buf`. Returns its length, or why not.
pub(crate) fn read_source_file(
    storage: Storage,
    path: &str,
    buf: &mut [u8],
) -> Result<usize, &'static str> {
    match storage {
        Storage::Sd => read_card_file(path, buf),
        #[cfg(not(feature = "board-mk3"))]
        Storage::Vdisk => menu::with_vdisk(|vol| read_file(vol, path, buf)),
    }
}

/// Read `path` from an already-mounted volume into `buf`. Returns its length, or why not.
///
/// Generic over the backing driver so the card and the Virtual Disk share the one read
/// loop; the size cap is `buf`, which on a PSRAM board is a half of the signing lease.
fn read_file<D: catcard_sd::fat::SectorDriver>(
    vol: &mut catcard_sd::AnyVolume<D, 512>,
    path: &str,
    buf: &mut [u8],
) -> Result<usize, &'static str> {
    let mut file = vol.open_file(path).map_err(|_| "could not open file")?;
    let len = file.len() as usize;
    if len > buf.len() {
        return Err("too big for this board");
    }
    let mut got = 0usize;
    while got < len {
        match file.read(vol, &mut buf[got..len]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(_) => return Err("read failed"),
        }
    }
    if got != len {
        return Err("short read");
    }
    Ok(got)
}

/// Decode `bytes` in place if they are base64 (as a `.psbt` written as text is), and return
/// the PSBT's byte range within `buf`.
///
/// A binary PSBT starts with the magic; base64 of that magic starts `cHNidP`.
pub(crate) fn as_psbt_bytes(
    buf: &mut [u8],
    len: usize,
    scratch: &mut [u8],
) -> Result<usize, &'static str> {
    if buf[..len].starts_with(&outscript::psbt::MAGIC) {
        return Ok(len);
    }
    let text = core::str::from_utf8(&buf[..len])
        .map_err(|_| "not a PSBT")?
        .trim();
    let n = outscript::base64::decode_to_slice(text, scratch).map_err(|_| "not a PSBT")?;
    if !scratch[..n].starts_with(&outscript::psbt::MAGIC) {
        return Err("not a PSBT");
    }
    buf[..n].copy_from_slice(&scratch[..n]);
    Ok(n)
}

/// Why the parser refused the bytes, in the few words a screen has.
///
/// The one distinction worth making on screen is a PSBT version this firmware does not
/// speak against a file that is simply broken: "not a valid PSBT" would send its owner
/// looking for corruption that is not there. Version 2 (BIP-370) never reaches this --
/// [`review_and_sign`] routes it through [`V2`] first -- so what is left is a version
/// nobody has defined. Source: hw-reference/firmware-features.md §5 (stock accepts v0
/// and v2) [C]
fn parse_error_text(e: outscript::Error) -> &'static str {
    use outscript::Error as E;
    match e {
        E::UnsupportedPsbtVersion => "PSBT version not supported",
        E::InvalidMagic => "not a PSBT",
        E::MissingUnsignedTx => "PSBT has no transaction",
        E::InvalidUnsignedTx => "PSBT tx is malformed",
        E::DuplicateKey => "PSBT has a duplicate key",
        E::TrailingData => "PSBT has trailing bytes",
        _ => "PSBT is corrupt",
    }
}

/// Why a version-2 (BIP-370) file was refused, in the few words a screen has.
///
/// Each names what the host has to fix: a lock time no single `nLockTime` satisfies, a
/// transaction it has not finished constructing, a flag this firmware cannot read, a map
/// count that lies, a required field missing or malformed.
fn v2_error_text(e: psbtv2::Error) -> &'static str {
    use psbtv2::Error as E;
    match e {
        E::LocktimeConflict => "v2: no locktime fits all inputs",
        E::StillModifiable(_) => "v2: tx still modifiable",
        E::UnknownFlags(_) => "v2: unknown modifiable flags",
        E::CountMismatch => "v2: counts disagree with maps",
        E::MissingGlobal(_) | E::MissingInputField { .. } | E::MissingOutputField { .. } => {
            "v2: required field missing"
        }
        E::BadGlobal(_) | E::BadInputField { .. } | E::BadOutputField { .. } => {
            "v2: field malformed"
        }
        E::UnsignedTxPresent => "v2 carries an unsigned tx",
        E::UnsupportedVersion(_) => "PSBT version not supported",
        E::BufferTooSmall => "too big for this board",
        E::Psbt(inner) => parse_error_text(inner),
        E::Magic | E::NotV2 | E::Truncated | E::NonCanonical | E::DuplicateKey | E::Mismatch => {
            "PSBT is corrupt"
        }
    }
}

/// Merge the signed v0 view back into the original v2 container, into `out`.
///
/// The original parsed once already; parsing it again here is cheaper than carrying the
/// view across the signing loop's buffer swaps.
fn write_back_v2(original: &[u8], signed_v0: &[u8], out: &mut [u8]) -> Result<usize, &'static str> {
    let v2 = V2::parse(original).map_err(v2_error_text)?;
    let signed = Psbt::parse(signed_v0).map_err(parse_error_text)?;
    v2.write_back(&signed, out).map_err(v2_error_text)
}

/// Why the review stopped, in the few words a screen has.
fn refusal_text(r: Refusal) -> &'static str {
    match r {
        Refusal::NothingOfOurs => "no input is ours",
        Refusal::Sighash { .. } => "unsupported sighash",
        Refusal::SighashConsolidation { .. } => "consolidation needs ALL",
        Refusal::FeeTooHigh { .. } => "fee above the limit",
        Refusal::UnknownAmount { .. } => "an input has no amount",
        Refusal::UnverifiedAmount { .. } => "an input has no prev tx",
        Refusal::Unbalanced => "outputs exceed inputs",
        Refusal::AlreadyFinal => "already finalised",
        // Not "unsupported": the wallet is simply one this device was never shown, and
        // the cure is Utils -> Multisig -> Import.
        Refusal::UnknownMultisig { .. } => "multisig wallet not registered",
    }
}

/// Sign a transaction picked from the card.
pub(crate) fn sign_psbt(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    const HEAD: &str = "Sign";

    // Where the transaction comes from and where the result goes. On a PSRAM board the
    // owner is asked (card or Virtual Disk), matching the Browse Files / USB Drive chooser;
    // on the mk3, which has no disk, it is the card without a prompt.
    //
    // A transaction that arrives by camera comes in through `Scan QR`, which reads first and
    // offers afterwards -- it cannot know it is being handed a PSBT until it has one, so
    // asking in advance would be a second way to do the same thing with a worse answer when
    // the guess is wrong.
    let Some(storage) = menu::pick_storage(ui, HEAD) else {
        return;
    };

    // Picked before the workspace is taken: browsing the storage with the staging area held
    // would refuse a USB upload for as long as someone spent choosing a file.
    let path = match lone_psbt(storage) {
        // One transaction on the medium needs no picker; two or more, and the owner
        // says which.
        Some(p) => p,
        None => {
            let Some(p) = menu::browse_storage(
                ui,
                storage,
                "Pick a .psbt",
                Some("psbt"),
                menu::Browse::File,
            ) else {
                return;
            };
            let mut path: heapless::String<PATH_MAX> = heapless::String::new();
            if path.push_str(p.as_str()).is_err() {
                menu::message(ui.panel, HEAD, "path too long", "any key to go back");
                menu::wait_for_any_key(ui);
                return;
            }
            path
        }
    };
    // Held until this screen returns, and released by dropping whichever way it does.
    let mut work = match Workspace::take() {
        Ok(w) => w,
        Err(why) => {
            menu::message(ui.panel, HEAD, why, "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        }
    };
    let (buf, spare) = work.split();

    let mut wait: heapless::String<24> = heapless::String::new();
    let _ = core::fmt::Write::write_fmt(&mut wait, format_args!("reading {}", storage.medium()));
    menu::card_wait(ui.panel, HEAD, &wait);
    let len = match read_source_file(storage, &path, buf)
        .and_then(|len| as_psbt_bytes(buf, len, spare))
    {
        Ok(len) => len,
        Err(why) => {
            crate::catlog!("sign: {}: {}", path.as_str(), why);
            menu::message(ui.panel, HEAD, why, "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        }
    };
    crate::catlog!("sign: {} bytes from {}", len, path.as_str());

    review_and_sign(gate, login, ui, buf, spare, len, &SignDest::SINGLE, storage);
}

/// A path without its leading `/`, for a screen that names a file the card writes.
fn strip_slash(name: &str) -> &str {
    name.strip_prefix('/').unwrap_or(name)
}

/// Transactions a batch may hold in one pass. A card with more than this is signed up to
/// the cap and the summary says there are more, rather than a longer list going on the
/// stack: this whole screen is foreground, and the list sits beside the two PSBT buffers.
const MAX_BATCH: usize = 8;

/// The `.psbt` files on the card a batch should sign, as full `/name` paths.
///
/// Result files a previous signing wrote (`*-signed.psbt`, `SIGNED.PSB`) are skipped by
/// [`catcard_wallet::psbtfile::is_batch_source`], so running a batch twice does not sign its
/// own output. `Ok(true)` when every source fit `out`; `Ok(false)` when there were more than
/// [`MAX_BATCH`] and the list was capped.
fn enumerate_psbts(
    storage: Storage,
    out: &mut heapless::Vec<heapless::String<PATH_MAX>, MAX_BATCH>,
) -> Result<bool, &'static str> {
    match storage {
        Storage::Sd => with_card(|vol| Ok(collect_psbts(vol, out))),
        #[cfg(not(feature = "board-mk3"))]
        Storage::Vdisk => menu::with_vdisk(|vol| Ok(collect_psbts(vol, out))),
    }
}

/// Gather the batch-source `.psbt` files in the root of an already-mounted volume.
///
/// Generic over the backing driver, so the card and the Virtual Disk share it. `true` when
/// every source fit `out`; `false` when there were more than [`MAX_BATCH`] and the list was
/// capped.
fn collect_psbts<D: catcard_sd::fat::SectorDriver>(
    vol: &mut catcard_sd::AnyVolume<D, 512>,
    out: &mut heapless::Vec<heapless::String<PATH_MAX>, MAX_BATCH>,
) -> bool {
    let mut capped = false;
    let _ = vol.enumerate("", |name, is_dir, _| {
        if is_dir || !catcard_wallet::psbtfile::is_batch_source(name) {
            return;
        }
        if out.is_full() {
            capped = true;
            return;
        }
        let mut path: heapless::String<PATH_MAX> = heapless::String::new();
        if path.push('/').is_ok() && path.push_str(name).is_ok() {
            let _ = out.push(path);
        }
    });
    !capped
}

/// Sign every transaction on the card, one signed file per source.
///
/// The convenience over signing each from the picker is only that: the file is not chosen
/// one at a time. **Every transaction still gets the whole review** -- its amounts, its
/// destinations, its fee, and the Sign key gated on all of it -- because a batch that signed
/// without showing what it signed would be exactly the screen this device exists to avoid.
/// The owner can refuse any one of them and the batch moves on to the next.
///
/// Each result is written next to its source as `NAME-signed.psbt` (and `NAME-final.txn` if
/// it finalises), so the files do not overwrite one another. The per-file QR and NFC offers
/// are skipped: a queue of them is not what "sign all of these" asks for.
pub(crate) fn batch_sign(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    use core::fmt::Write as _;
    const HEAD: &str = "Batch sign";

    let Some(storage) = menu::pick_storage(ui, HEAD) else {
        return;
    };

    // Gathered before the workspace is taken, so browsing the storage does not hold the
    // staging area against a USB upload.
    let mut list: heapless::Vec<heapless::String<PATH_MAX>, MAX_BATCH> = heapless::Vec::new();
    let all = match enumerate_psbts(storage, &mut list) {
        Ok(all) => all,
        Err(why) => {
            menu::message(ui.panel, HEAD, why, "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        }
    };
    if list.is_empty() {
        let mut none: heapless::String<32> = heapless::String::new();
        let _ = write!(none, "no PSBT on {}", storage.medium());
        menu::message(ui.panel, HEAD, &none, "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    }
    crate::catlog!("batch: {} transaction(s) to sign", list.len());

    let mut work = match Workspace::take() {
        Ok(w) => w,
        Err(why) => {
            menu::message(ui.panel, HEAD, why, "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        }
    };
    let (buf, spare) = work.split();

    let total = list.len();
    let mut reviewed = 0usize;
    for (i, path) in list.iter().enumerate() {
        let mut note: heapless::String<24> = heapless::String::new();
        let _ = write!(note, "file {} of {}", i + 1, total);
        menu::card_wait(ui.panel, HEAD, &note);

        let len = match read_source_file(storage, path, buf)
            .and_then(|len| as_psbt_bytes(buf, len, spare))
        {
            Ok(len) => len,
            Err(why) => {
                crate::catlog!("batch: {}: {}", path.as_str(), why);
                menu::message(ui.panel, strip_slash(path), why, "any key to skip it");
                menu::wait_for_any_key(ui);
                continue;
            }
        };

        // Per-source result names, so one signed file does not overwrite the next. A name
        // too long for the buffer is skipped rather than written somewhere it would collide.
        let src = strip_slash(path);
        let mut sbuf = [0u8; PATH_MAX];
        let mut fbuf = [0u8; PATH_MAX];
        let (Some(sn), Some(fnl)) = (
            catcard_wallet::psbtfile::signed_name(src, &mut sbuf),
            catcard_wallet::psbtfile::final_name(src, &mut fbuf),
        ) else {
            menu::message(
                ui.panel,
                strip_slash(path),
                "name too long",
                "any key to skip it",
            );
            menu::wait_for_any_key(ui);
            continue;
        };
        let (Ok(signed), Ok(final_name)) = (
            core::str::from_utf8(&sbuf[..sn]),
            core::str::from_utf8(&fbuf[..fnl]),
        ) else {
            continue;
        };
        let dest = SignDest {
            signed_name: signed,
            final_name,
            offer_transports: false,
        };
        review_and_sign(gate, login, ui, buf, spare, len, &dest, storage);
        reviewed += 1;
    }

    let mut note: heapless::String<48> = heapless::String::new();
    let _ = write!(
        note,
        "reviewed {reviewed} of {total}{}",
        if all { "" } else { ", more remain" }
    );
    crate::catlog!("batch: {}", note.as_str());
    menu::message(ui.panel, HEAD, "batch complete", &note);
    menu::wait_for_any_key(ui);
}

/// Review a PSBT already sitting in `buf`, and sign it if the owner approves.
///
/// Split from [`sign_psbt`] because how the bytes arrived stops mattering here: a
/// transaction read off a card and one caught as a few hundred QR codes get the same
/// review, the same refusals and the same signatures. `spare` is the second working
/// buffer -- every signature rewrites the whole container, so the two alternate.
#[allow(clippy::too_many_arguments)]
pub(crate) fn review_and_sign(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    buf: &mut [u8],
    spare: &mut [u8],
    len: usize,
    dest: &SignDest<'_>,
    storage: Storage,
) {
    const HEAD: &str = "Sign";

    // A version-2 file (BIP-370) is worked on through its v0 view: the transaction its
    // fields describe, built once here, is what the review and the signer read, so a v2
    // gets exactly the refusals and the signatures its v0 twin would. The original stays
    // at the head of `buf`, word-aligned, and the view goes after it; once signed, the
    // view is merged back into the original and the owner's host gets v2 back. Nothing
    // here touches a key, so it runs before the master is unlocked.
    let mut original_v2: Option<&[u8]> = None;
    let (buf, len): (&mut [u8], usize) = if psbtv2::is_v2(&buf[..len]) {
        let at = (len + 3) & !3;
        if at >= buf.len() {
            menu::message(
                ui.panel,
                HEAD,
                "too big for this board",
                "any key to go back",
            );
            menu::wait_for_any_key(ui);
            return;
        }
        let (head, tail) = buf.split_at_mut(at);
        let head: &[u8] = &head[..len];
        let view = V2::parse(head)
            .and_then(|v2| v2.check_for_signing().map(|()| v2))
            .and_then(|v2| v2.to_v0(tail));
        match view {
            Ok(n) => {
                crate::catlog!("sign: PSBT v2, {} bytes as its v0 view", n);
                original_v2 = Some(head);
                (tail, n)
            }
            Err(e) => {
                crate::catlog!("sign: psbt v2 refused: {:?}", e);
                menu::message(ui.panel, HEAD, v2_error_text(e), "any key to go back");
                menu::wait_for_any_key(ui);
                return;
            }
        }
    } else {
        (buf, len)
    };

    let Some(master) = menu::unlock_master(gate, login, ui, HEAD) else {
        return;
    };
    let fingerprint = crate::keywork::run(|kw| master.fingerprint(kw));

    // Parsed before the multisig wallets are worked out: the trust policy below may
    // reconstruct a wallet the PSBT itself carries, which needs the parsed container.
    let psbt = match Psbt::parse(&buf[..len]) {
        Ok(p) => p,
        Err(e) => {
            crate::catlog!("sign: psbt refused: {:?}", e);
            menu::message(ui.panel, HEAD, parse_error_text(e), "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        }
    };

    // The multisig wallets a script-hash input may be checked against. The registered ones
    // come first: the chain says which script the coin is locked to, but only a
    // registration says whose wallet that script belongs to. On top of those, the trust
    // policy may add wallets the PSBT itself proves -- [`MultisigTrust::VerifyOnly`], the
    // default, adds nothing, so an unregistered multisig stays refused; the other two add a
    // wallet whose keys rebuild this coin's script and that this device provably co-signs.
    #[cfg(not(feature = "board-mk3"))]
    let wallets: &[catcard_wallet::multisig::Multisig] = {
        let registered = crate::msimport::registered(gate, login, ui.panel);
        let trust = crate::prefs::current().multisig_trust;
        if trust == catcard_settings::prefs::MultisigTrust::VerifyOnly {
            registered
        } else {
            // `registered` has just filled the store the trust step appends to.
            crate::msimport::trust_from_psbt(gate, login, ui, &psbt, &master, fingerprint, trust)
        }
    };
    // The mk3 has no settings store yet, so nothing can be registered on it and every
    // multisig input is refused. That is the safe direction, and the honest one: the
    // alternative is signing for a wallet this device was never shown.
    #[cfg(feature = "board-mk3")]
    let wallets: &[catcard_wallet::multisig::Multisig] = &[];

    // The WIF store, read once like the multisig registrations: standalone keys, not
    // derived from the seed, each able to sign an input that pays its own address. Their
    // public keys go into the review so a spend of a stored key is recognised as ours
    // rather than refused as "nothing of ours"; the keys themselves sign in the pass
    // below. Empty on the mk3, which has no settings store.
    #[cfg(not(feature = "board-mk3"))]
    let mut wif_keys: heapless::Vec<
        catcard_wallet::wif::WifKey,
        { catcard_settings::wifs::MAX_KEYS },
    > = heapless::Vec::new();
    #[cfg(not(feature = "board-mk3"))]
    crate::wifstore::load_keys(gate, login, ui.panel, &mut wif_keys);
    #[cfg(not(feature = "board-mk3"))]
    let mut bare_keys: heapless::Vec<[u8; 33], { catcard_settings::wifs::MAX_KEYS }> =
        heapless::Vec::new();
    #[cfg(not(feature = "board-mk3"))]
    crate::keywork::run(|kw| {
        for k in &wif_keys {
            if let Some(pk) = k.public_key(kw) {
                let _ = bare_keys.push(pk);
            }
        }
    });

    let owner = psbtview::Owner {
        master: &master,
        fingerprint,
        wallets,
        #[cfg(not(feature = "board-mk3"))]
        bare_keys: &bare_keys,
        #[cfg(feature = "board-mk3")]
        bare_keys: &[],
    };

    // The review. Every judgement here derives a key per input and per claimed change
    // output, so it runs masked, with the screen saying what it is doing.
    let mut busy = menu::Working::new(ui.panel, HEAD, "checking the transaction");
    // The fee cap the owner set, or the ten-percent default. `Policy` still does the
    // comparing: "no cap" is a limit no percentage can exceed rather than a check that
    // gets skipped, so there is no path through this that forgets to look at the fee.
    // The sighash policy is the owner's Danger Zone choice. Its firmware form
    // (`SighashChecks`) and its wallet-crate form (`SighashPolicy`) are the same two
    // words; the wallet crate does not depend on the settings crate, so they are mapped
    // here rather than shared.
    let sighash = match crate::prefs::current().sighash {
        catcard_settings::prefs::SighashChecks::Block => SighashPolicy::Block,
        catcard_settings::prefs::SighashChecks::Warn => SighashPolicy::Warn,
    };
    let policy = Policy {
        max_fee_percent: crate::prefs::current().fee_cap.percent_limit(),
        sighash,
        ..Policy::default()
    };
    let summary = crate::keywork::run(|kw| psbtview::summarise(&psbt, &owner, &policy, kw));
    busy.tick(ui.panel);
    let summary = match summary {
        Ok(s) => s,
        Err(r) => {
            crate::catlog!("sign: refused: {:?}", r);
            menu::message(ui.panel, HEAD, refusal_text(r), "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        }
    };
    // The only bound on the output count is the memory the PSBT sits in (see
    // `MIN_OUTPUT_BYTES`); the review pages through however many there are. A parsed
    // PSBT cannot be over this, so the check states the bound rather than enforcing a
    // screen limit -- there is no screen limit any more.
    if summary.outputs > buf.len() / MIN_OUTPUT_BYTES {
        crate::catlog!("sign: refused: {} outputs", summary.outputs);
        menu::message(
            ui.panel,
            HEAD,
            "too many outputs for memory",
            "any key to go back",
        );
        menu::wait_for_any_key(ui);
        return;
    }
    let mut ours = [0usize; MAX_INPUTS];
    // `mut` because the WIF pass below extends the set; on the mk3 that pass is compiled
    // out, so nothing there mutates it.
    #[cfg_attr(feature = "board-mk3", allow(unused_mut))]
    let mut signable =
        crate::keywork::run(|kw| psbtview::our_inputs(&psbt, &master, fingerprint, &mut ours, kw));

    // Inputs a stored WIF key can sign, added to the set the review reports and the loop
    // signs. Only those a seed key does not already cover: an input both can sign is signed
    // once, by the seed. Matching a key to a script is public work, so no masking here.
    #[cfg(not(feature = "board-mk3"))]
    for k in &bare_keys {
        let mut hits = [0usize; MAX_INPUTS];
        let m = psbtview::wif_inputs(&psbt, k, &mut hits);
        for &i in &hits[..m] {
            if signable < ours.len() && !ours[..signable].contains(&i) {
                ours[signable] = i;
                signable += 1;
            }
        }
    }

    // Under the warn policy, an input asking for an unusual sighash type is named -- the
    // input and the type -- on its own screen before the review, and the owner has to say
    // yes to it. `SIGHASH_NONE` gets stock's "Danger": the signature it asks for covers no
    // output, so whoever holds it can attach it to a transaction paying anyone. The other
    // types get "Caution". Source: hw-reference/help-and-warning-screens.md "sighash NONE
    // on our input", "Other non-ALL sighash" [C]
    if summary.odd_count > 0 {
        drop(busy);
        if !warn_odd_sighash(ui, &summary) {
            menu::message(ui.panel, HEAD, "not signed", "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        }
    }

    // The review, a page of outputs at a time. Each page derives the keys of the outputs
    // it shows -- an output is change only if our own key rebuilds its script -- so it
    // runs masked, with the accounts and wallets the summary already worked out from the
    // inputs: deriving those twice would be twice the elliptic-curve work for the same
    // answer.
    let mut fill = |start: usize, page: &mut [psbtview::Destination]| {
        crate::keywork::run(|kw| {
            psbtview::destinations_with(
                &psbt,
                &owner,
                crate::prefs::network(),
                &summary.spent(),
                start,
                page,
                kw,
            )
        })
    };
    if !review(ui, &psbt, &summary, signable, &mut fill) {
        menu::message(ui.panel, HEAD, "not signed", "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    }

    // Sign, one input at a time, alternating buffers: each signature rewrites the whole
    // container. `at` says which buffer currently holds the PSBT.
    let mut busy = menu::Working::new(ui.panel, HEAD, "signing");
    let (mut from, mut into) = (buf, spare);
    let mut at = len;
    let mut signed = 0usize;
    for &index in &ours[..signable] {
        let psbt = match Psbt::parse(&from[..at]) {
            Ok(p) => p,
            Err(_) => break,
        };
        let mut done = false;
        match crate::keywork::run(|kw| {
            signer::sign_input_under(&psbt, index, &master, fingerprint, sighash, into, kw)
        }) {
            Ok(n) => {
                core::mem::swap(&mut from, &mut into);
                at = n;
                signed += 1;
                done = true;
            }
            Err(e) => {
                crate::catlog!("sign: input {} not a seed key: {:?}", index, e);
            }
        }
        // A stored WIF key next, if the seed did not sign this input. Each key signs only
        // the input paying its own address -- `sign_input_with_secret` returns
        // `KeyNotInvolved` otherwise -- so this tries them in turn and stops at the first
        // that takes. The scalar is masked like every other signature.
        #[cfg(not(feature = "board-mk3"))]
        if !done {
            for k in &wif_keys {
                let psbt = match Psbt::parse(&from[..at]) {
                    Ok(p) => p,
                    Err(_) => break,
                };
                match crate::keywork::run(|kw| {
                    signer::sign_input_with_secret(&psbt, index, k.secret(), sighash, into, kw)
                }) {
                    Ok(n) => {
                        core::mem::swap(&mut from, &mut into);
                        at = n;
                        signed += 1;
                        done = true;
                        break;
                    }
                    Err(_) => continue,
                }
            }
        }
        if !done {
            crate::catlog!("sign: input {} refused by every key", index);
        }
        busy.tick(ui.panel);
    }
    drop(master);
    #[cfg(not(feature = "board-mk3"))]
    drop(wif_keys);

    if signed == 0 {
        menu::message(
            ui.panel,
            HEAD,
            "nothing could be signed",
            "any key to go back",
        );
        menu::wait_for_any_key(ui);
        return;
    }

    let mut wait: heapless::String<24> = heapless::String::new();
    let _ = core::fmt::Write::write_fmt(&mut wait, format_args!("writing to {}", storage.medium()));
    menu::card_wait(ui.panel, HEAD, &wait);
    // A v2 source gets v2 back: the signed view merged into the original container, built
    // in `into`, which is free until `finalise` below wants it. `from` keeps the signed
    // v0 view, which is what finalises and extracts.
    let v2_len = match original_v2 {
        Some(original) => match write_back_v2(original, &from[..at], into) {
            Ok(n) => Some(n),
            Err(why) => {
                crate::catlog!("sign: v2 write-back failed: {}", why);
                menu::message(ui.panel, "Write failed", why, "any key to go back");
                menu::wait_for_any_key(ui);
                return;
            }
        },
        None => None,
    };
    let written = match v2_len {
        Some(n) => write_output(storage, dest.signed_name, &into[..n]),
        None => write_output(storage, dest.signed_name, &from[..at]),
    };
    match &written {
        Ok(()) => crate::catlog!(
            "sign: {} of {} inputs, {} bytes",
            signed,
            signable,
            v2_len.unwrap_or(at)
        ),
        Err(why) => {
            crate::catlog!("sign: write failed: {}", why);
            menu::message(ui.panel, "Write failed", why, "any key to go back");
            menu::wait_for_any_key(ui);
        }
    }
    // The signature exists whether or not the card took it, and a Q1 has a camera's
    // worth of screen to hand it back through. Offered on both paths on purpose: no
    // card is exactly the case where a QR is the only way out, and a signed
    // transaction that cannot leave the device is a signature nobody can use. A batch
    // skips this -- a queue of QR prompts, one per file, is not what it asks for.
    //
    // `into` is the second buffer, free until `finalise` below wants it.
    //
    // The mk3 has neither a camera nor an NFC tag, so there is no transport to offer and the
    // flag is unused there; naming it keeps the field honest rather than dead.
    #[cfg(feature = "board-mk3")]
    let _ = dest.offer_transports;
    #[cfg(feature = "board-q1")]
    if dest.offer_transports {
        match v2_len {
            // The v2 result sits in `into`; the tail of `from` past the view is the scratch.
            Some(n) => offer_signed_qr(ui, &into[..n], &mut from[at..]),
            None => offer_signed_qr(ui, &from[..at], &mut into[..]),
        }
    }
    if written.is_err() {
        return;
    }

    // If every input is now signed, the transaction can be finished here and the result is
    // ready to broadcast -- no other software needed. A transaction still waiting on a
    // cosigner simply does not finalise, which is not a failure -- and is said as such:
    // how many more signatures it needs, read from the multisig script the chain pins to
    // each coin against the partial signatures now on it, and where to take the file.
    // Source: hw-reference/firmware-features.md §5 "re-export of a partially-signed PSBT
    // (with an offer to hand off to a cosigner)" [C]
    let mut note: heapless::String<32> = heapless::String::new();
    use core::fmt::Write as _;
    let needs = Psbt::parse(&from[..at])
        .map(|p| psbtview::more_signatures_needed(&p))
        .unwrap_or(0);
    if needs > 0 {
        let _ = write!(
            note,
            "needs {needs} more signature{}",
            if needs == 1 { "" } else { "s" }
        );
    } else {
        let _ = write!(note, "{signed} of {signable} inputs");
    }
    match finalise(&from[..at], into) {
        Some(len) => {
            let hex_len = match write_hex_file(storage, dest.final_name, &into[..len], from) {
                Ok(n) => n,
                Err(why) => {
                    crate::catlog!("sign: final tx not written: {}", why);
                    menu::message(
                        ui.panel,
                        "Signed",
                        strip_slash(dest.signed_name),
                        note.as_str(),
                    );
                    menu::wait_for_any_key(ui);
                    return;
                }
            };
            crate::catlog!("sign: finalised, {} bytes of hex", hex_len);
            menu::message(
                ui.panel,
                "Signed",
                strip_slash(dest.final_name),
                "ready to broadcast",
            );
            menu::wait_for_any_key(ui);
            // Nothing here has a network. What this offers is to put the transaction on
            // the NFC tag as a link, so a phone that taps the device can send it.
            #[cfg(not(feature = "board-mk3"))]
            if dest.offer_transports {
                crate::nfc::offer_broadcast(ui, crate::nfc::CHAIN, &into[..len]);
            }
            return;
        }
        None => {
            menu::message(
                ui.panel,
                "Signed",
                strip_slash(dest.signed_name),
                note.as_str(),
            );
            if needs > 0 {
                crate::catlog!("sign: {} more signature(s) needed", needs);
                menu::wait_for_any_key(ui);
                menu::message(
                    ui.panel,
                    "Cosigners",
                    strip_slash(dest.signed_name),
                    "pass it to the next cosigner",
                );
            }
        }
    }
    menu::wait_for_any_key(ui);
}

/// The red message screen where the build has one (`menu::alarm` exists on the
/// multichain colour builds), and the plain one elsewhere: the mono boards have no red,
/// and the words carry the warning on their own.
fn alarm(panel: &mut crate::display::Panel, head: &str, a: &str, b: &str) {
    #[cfg(all(feature = "multichain", not(feature = "board-mk3")))]
    menu::alarm(panel, head, a, b);
    #[cfg(not(all(feature = "multichain", not(feature = "board-mk3"))))]
    menu::message(panel, head, a, b);
}

/// Name each of our inputs that asks for an unusual sighash type, and ask whether to go
/// on. True if the owner said yes to all of it.
///
/// Only reached under the warn policy; under block the review has already refused.
/// `SIGHASH_NONE` is red and called danger, because a signature under it covers no
/// output: the coins go wherever whoever holds the signature says. The rest are caution.
/// Source: hw-reference/help-and-warning-screens.md "sighash NONE on our input" (Danger),
/// "Other non-ALL sighash" (Caution) [C]
fn warn_odd_sighash(ui: &mut Ui<'_>, summary: &psbtview::Summary) -> bool {
    use core::fmt::Write as _;
    for odd in &summary.odd_sighash[..summary.odd_count] {
        let mut line: heapless::String<40> = heapless::String::new();
        let _ = write!(line, "input {}: SIGHASH_{}", odd.input, odd.name());
        if odd.signs_no_output() {
            alarm(ui.panel, "DANGER", &line, "signs no output at all");
        } else {
            alarm(ui.panel, "Caution", &line, "signs only part of the tx");
        }
        menu::wait_for_any_key(ui);
    }
    if summary.odd_total > summary.odd_count {
        let mut line: heapless::String<40> = heapless::String::new();
        let _ = write!(
            line,
            "and {} more input(s)",
            summary.odd_total - summary.odd_count
        );
        alarm(ui.panel, "Caution", &line, "with unusual sighash");
        menu::wait_for_any_key(ui);
    }
    menu::ask(
        ui.panel,
        "Sighash",
        "review it anyway?",
        "the coins may be redirected",
    );
    menu::confirmed(ui)
}

/// Offer to hand the signed transaction back as animated QR.
///
/// # Which of the two, and why it is asked rather than decided
///
/// **BBQr is first, because it is denser.** Base32 is five bits a character against
/// bytewords' four, so the same transaction is about a quarter fewer codes and a
/// quarter less waiting -- and `FileType::PSBT` tells the reader exactly what it has.
/// That is the right default for anything Bitcoin, and it is what this device uses
/// everywhere else.
///
/// **BC-UR is second, because more software reads it.** A wallet that is not
/// Coldcard-aware very likely speaks URs and not BBQr, and `crypto-psbt` is the type
/// BCR-2020-006 registers for a transaction. [C] So it is offered rather than chosen
/// for: which one works is a fact about the phone being held up, which this device
/// cannot see and its owner can.
///
/// Cancel is a third answer, and the common one: the card already has the file.
#[cfg(feature = "board-q1")]
fn offer_signed_qr(ui: &mut Ui<'_>, psbt: &[u8], scratch: &mut [u8]) {
    const HEAD: &str = "Signed";
    // Both where this build speaks both. BBQr alone is not a lesser screen -- it is the
    // denser of the two and the right default for a PSBT -- so a Bitcoin-only build
    // shows it without asking a question that has one answer.
    #[cfg(feature = "multichain")]
    const WAYS: &[&str] = &["BBQr", "BC-UR"];
    #[cfg(not(feature = "multichain"))]
    const WAYS: &[&str] = &["BBQr"];

    let Some(pick) = menu::choose(ui, HEAD, "show it as QR", WAYS) else {
        return;
    };
    let _ = scratch;
    match pick {
        0 => crate::qrshow::animate_bbqr(ui, HEAD, psbt, catcard_bbqr::FileType::PSBT),
        #[cfg(feature = "multichain")]
        _ => crate::qrshow::animate_psbt_ur(ui, HEAD, psbt, scratch),
        #[cfg(not(feature = "multichain"))]
        _ => {}
    }
}

/// Finish a fully-signed PSBT and write the network transaction into `out`.
///
/// `None` when it is not complete -- a multisig input still short of signatures, or a
/// script this cannot finish -- which is a normal outcome, not an error.
fn finalise(psbt: &[u8], out: &mut [u8]) -> Option<usize> {
    let parsed = Psbt::parse(psbt).ok()?;
    // Finalising rewrites the container again, in the same buffer this then extracts from.
    let (len, count) = parsed.finalize_to_slice(out).ok()?;
    if count == 0 {
        return None;
    }
    let done = Psbt::parse(&out[..len]).ok()?;
    if !done.is_finalized() {
        return None;
    }
    // Extract into the tail of the same buffer, then move it to the front: the caller only
    // needs the transaction, and this avoids a third buffer.
    let tx_len = done.extracted_tx_len().ok()?;
    if len + tx_len > out.len() {
        return None;
    }
    let (head, tail) = out.split_at_mut(len);
    let n = Psbt::parse(head).ok()?.extract_tx_to_slice(tail).ok()?;
    out.copy_within(len..len + n, 0);
    Some(n)
}

/// Write `bytes` as lower-case hex to `path` on the chosen storage, using `scratch` for the
/// text.
fn write_hex_file(
    storage: Storage,
    path: &str,
    bytes: &[u8],
    scratch: &mut [u8],
) -> Result<usize, &'static str> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let need = bytes.len() * 2;
    if need > scratch.len() {
        return Err("no room for the hex");
    }
    for (i, b) in bytes.iter().enumerate() {
        scratch[i * 2] = HEX[(b >> 4) as usize];
        scratch[i * 2 + 1] = HEX[(b & 0xF) as usize];
    }
    write_output(storage, path, &scratch[..need])?;
    Ok(need)
}

/// Write `bytes` to `path` on the chosen storage, replacing whatever it held.
///
/// The one plain replace-contents writer, shared with the rest of the firmware:
/// [`menu::write_storage_file`] is the card's `write_card_file` or, on a PSRAM board, the
/// Virtual Disk over the same generic [`menu::write_into`].
fn write_output(storage: Storage, path: &str, bytes: &[u8]) -> Result<(), &'static str> {
    menu::write_storage_file(storage, path, bytes)
}

/// Show what signing would authorise, a page of outputs at a time, and ask. True if the
/// owner confirmed on the last page.
///
/// The fee and the destinations are the point of the screen, so they are what it leads
/// with: how much leaves, to where, and what the miner takes. `fill` writes the outputs
/// from a given index into a page and says how many it wrote; it is called once per page,
/// so a transaction with a thousand outputs costs a thousand rows of screen and nothing
/// else. The Sign key is offered on the last page only: the confirm key on any earlier
/// page turns it, and cancel on any page refuses the whole transaction. Every output is
/// therefore on a screen -- read to its end, since `scroll_choice` takes confirm only at
/// the end of a page -- before the key that signs them all exists.
fn review(
    ui: &mut Ui<'_>,
    psbt: &Psbt<'_>,
    summary: &psbtview::Summary,
    signable: usize,
    fill: &mut dyn FnMut(usize, &mut [psbtview::Destination]) -> usize,
) -> bool {
    let mut page = [psbtview::Destination::BLANK; PAGE];
    let mut start = 0usize;
    loop {
        let got = fill(start, &mut page);
        let last = start + got >= summary.outputs;
        // A page that filled nothing and is not the last would be an output nobody sees.
        // Refuse rather than sign past it; `destinations_from` does not do this, but the
        // rule is stated here so no caller can.
        if got == 0 && !last {
            return false;
        }
        if !review_page(ui, psbt, summary, signable, &page[..got], start, last) {
            return false;
        }
        if last {
            return true;
        }
        start += got;
    }
}

/// One page of the review: the totals and warnings on the first, the outputs from
/// `start`, and on the last page the Sign key.
#[allow(clippy::too_many_arguments)]
fn review_page(
    ui: &mut Ui<'_>,
    psbt: &Psbt<'_>,
    summary: &psbtview::Summary,
    signable: usize,
    shown: &[psbtview::Destination],
    start: usize,
    last: bool,
) -> bool {
    use catcard_ui::scroll::{Line, ScrollView};
    use core::fmt::Write as _;

    /// Lines a page can hold: the totals and their warnings, the timelocks, up to three
    /// per output (the amount, the address or key, and a change warning), the page note
    /// and the key hint.
    const LINES: usize = 12 + MAX_RELATIVE_SHOWN + 3 * PAGE;
    /// Relative locks named on the first page before the rest are only counted.
    const MAX_RELATIVE_SHOWN: usize = 4;
    type Text = heapless::String<72>;

    let mut texts: heapless::Vec<Text, LINES> = heapless::Vec::new();
    let mut small: heapless::Vec<bool, LINES> = heapless::Vec::new();
    let mut wrapped: heapless::Vec<bool, LINES> = heapless::Vec::new();
    let say = |texts: &mut heapless::Vec<Text, LINES>,
               small_v: &mut heapless::Vec<bool, LINES>,
               wrap_v: &mut heapless::Vec<bool, LINES>,
               text: Text,
               is_small: bool,
               wrap: bool| {
        if texts.push(text).is_ok() {
            let _ = small_v.push(is_small);
            let _ = wrap_v.push(wrap);
        }
    };

    if start == 0 {
        let mut amount = heapless::String::<AMOUNT_LEN>::new();
        btc(summary.sending, &mut amount);
        let mut line = Text::new();
        let _ = write!(line, "Sending {amount}");
        say(&mut texts, &mut small, &mut wrapped, line, false, false);

        // The fee, or that there is none to state. A foreign input priced on the host's
        // word alone -- a coinjoin's -- leaves the fee unknown, and "unknown" is what
        // the screen says: not zero, and not the host's figure. Stock words it the same
        // way. Source: hw-reference/firmware-features.md §5 "Coinjoin / foreign inputs
        // supported (fee shown as unknown, with warnings)" [C]
        let mut line = Text::new();
        if summary.fee_known {
            let mut amount = heapless::String::<AMOUNT_LEN>::new();
            btc(summary.fee, &mut amount);
            let _ = write!(
                line,
                "Fee {amount} ({}%){}",
                summary.fee_percent,
                if summary.fee_warn { " HIGH" } else { "" }
            );
            say(&mut texts, &mut small, &mut wrapped, line, false, false);
        } else {
            let _ = write!(line, "Fee UNKNOWN");
            say(&mut texts, &mut small, &mut wrapped, line, false, false);
            let mut line = Text::new();
            let _ = write!(
                line,
                "{} input(s) unverified: fee cap not checked",
                summary.unpriced
            );
            say(&mut texts, &mut small, &mut wrapped, line, true, true);
        }

        let mut line = Text::new();
        let _ = write!(line, "{} of {} inputs ours", signable, summary.inputs);
        say(&mut texts, &mut small, &mut wrapped, line, true, false);

        // A bare P2PK input has no address to show, so the review says what it is.
        // Source: hw-reference/firmware-features.md §3 (P2PK signable) [C]
        if summary.p2pk_inputs > 0 {
            let mut line = Text::new();
            let _ = write!(line, "{} P2PK input(s)", summary.p2pk_inputs);
            say(&mut texts, &mut small, &mut wrapped, line, true, false);
        }

        // An opted-in transaction is signed under the unified message, which only the
        // chain that implements that rule verifies. Said here because it is the one
        // thing about this transaction the owner cannot see from the amounts: everything
        // else on this screen reads the same either way.
        #[cfg(feature = "multichain")]
        if summary.opted_in {
            let mut line = Text::new();
            let _ = write!(line, "OPT-IN sighash: fork only");
            say(&mut texts, &mut small, &mut wrapped, line, true, false);
        }

        // An unusual sighash type was already warned about on its own screen; the row
        // here is so the review still says it once the warning is gone.
        if summary.odd_total > 0 {
            let mut line = Text::new();
            let _ = write!(line, "{} input(s) NOT SIGHASH_ALL", summary.odd_total);
            say(&mut texts, &mut small, &mut wrapped, line, true, false);
        }

        // Timelocks, only when set. An absolute lock the network will not enforce --
        // every input final -- is said to be ineffective rather than left looking like
        // a promise. Source: hw-reference/firmware-features.md §5 "Relative and absolute
        // timelocks are surfaced"; help-and-warning-screens.md "odd-locktime" [C]
        if let Some(lock) = timelock::absolute(psbt) {
            let mut line = Text::new();
            let _ = match lock.lock {
                timelock::Absolute::Height(h) => write!(line, "Locktime: block {h}"),
                timelock::Absolute::Time(t) => write!(line, "Locktime: unix time {t}"),
            };
            if !lock.effective {
                let _ = write!(line, " (INEFFECTIVE)");
            }
            say(&mut texts, &mut small, &mut wrapped, line, true, true);
        }
        let tx = psbt.unsigned_tx();
        let mut relatives = 0usize;
        for (input, lock) in timelock::relatives(&tx) {
            relatives += 1;
            if relatives > MAX_RELATIVE_SHOWN {
                continue;
            }
            let mut line = Text::new();
            let _ = match lock {
                timelock::Relative::Blocks(b) => {
                    write!(line, "input {input}: wait {b} blocks")
                }
                timelock::Relative::Seconds(s) => write!(line, "input {input}: wait {s} s"),
            };
            say(&mut texts, &mut small, &mut wrapped, line, true, false);
        }
        if relatives > MAX_RELATIVE_SHOWN {
            let mut line = Text::new();
            let _ = write!(
                line,
                "and {} more timelocked input(s)",
                relatives - MAX_RELATIVE_SHOWN
            );
            say(&mut texts, &mut small, &mut wrapped, line, true, false);
        }
    }

    // Where this page sits, when there is more than one.
    if summary.outputs > PAGE {
        let mut line = Text::new();
        let _ = write!(
            line,
            "outputs {}-{} of {}",
            start + 1,
            start + shown.len(),
            summary.outputs
        );
        say(&mut texts, &mut small, &mut wrapped, line, true, false);
    }

    for d in shown {
        let mut amount = heapless::String::<AMOUNT_LEN>::new();
        btc(d.amount, &mut amount);
        let mut line = Text::new();
        let _ = write!(
            line,
            "{}{}{}",
            if d.change { "change " } else { "to " },
            amount,
            // A P2PK output has no address; the line names the form and the next line
            // carries the key.
            if d.p2pk {
                " P2PK"
            } else if d.address_len == 0 {
                " (no address)"
            } else {
                ""
            }
        );
        say(&mut texts, &mut small, &mut wrapped, line, true, false);
        if d.address_len > 0 {
            let mut line = Text::new();
            let _ = write!(line, "{}", d.address());
            say(&mut texts, &mut small, &mut wrapped, line, true, true);
        }
        // Stock's suspicious-change warning: proven change, on a path no wallet would
        // choose. Said with the path, so the owner can see for themselves; not a
        // refusal. Source: hw-reference/firmware-features.md §5 "suspicious change" [C]
        if let Some(why) = d.unusual {
            let mut line = Text::new();
            let _ = write!(line, "unusual change path ");
            let _ = d.write_path(&mut line);
            let _ = write!(line, ": {}", why.text());
            say(&mut texts, &mut small, &mut wrapped, line, true, true);
        }
    }

    let mut line = Text::new();
    if last {
        let _ = write!(
            line,
            "{} sign   {} cancel",
            display::CONFIRM_KEY,
            display::CANCEL_KEY
        );
    } else {
        let _ = write!(
            line,
            "{} next page   {} cancel",
            display::CONFIRM_KEY,
            display::CANCEL_KEY
        );
    }
    say(&mut texts, &mut small, &mut wrapped, line, true, false);

    let mut doc: heapless::Vec<Line, { LINES + 1 }> = heapless::Vec::new();
    let _ = doc.push(Line::title("Sign transaction"));
    for (i, text) in texts.iter().enumerate() {
        let mut l = Line::body(text.as_str());
        if small[i] {
            l = l.small();
        }
        if wrapped[i] {
            l = l.wrapped();
        }
        let _ = doc.push(l);
    }

    let mut view = ScrollView::build(&doc, display::SCREEN_W, display::SCREEN_H, display::FONTS);
    menu::scroll_choice(ui, &mut view)
}
