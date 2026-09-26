//! Checking a signed-message file, or an export's `.sig` sidecar, from the card.
//!
//! The other half of [`crate::signmsg`], and the half that needs no key at all: a
//! signature is public, so nothing here unlocks the secure element or asks for a PIN.
//! It is the screen someone uses to check what a counterparty sent them, and the thing it
//! must never do is say yes on the file's say-so.
//!
//! So the file's own claims are checked, never used:
//!
//! - the signature is recovered or verified against the message *in that file*, so a
//!   signature moved onto other text fails;
//! - the key that comes out is measured against the address *in that file*, so a signature
//!   made by another key fails;
//! - when the message is a sidecar's file list, each named file is read from the same
//!   directory and hashed, so an export edited after it was signed is reported as changed
//!   -- per file, before the signature's own verdict.
//!
//! Every scheme [`catcard_wallet::signfile`] reads is checked here -- legacy, and BIP-322
//! in its simple, full and proof-of-reserves variants -- and the screen says which one the
//! file turned out to carry, because "verified" means something slightly different in each
//! and the owner is entitled to know which they got. A proof of reserves says what it
//! proves: how many outputs, and their total. A multisig cosigner's share -- every
//! signature in it good, and short of the script's threshold -- is reported as exactly
//! that, neither verified nor forged.
//!
//! "Cannot check this" is its own answer. A P2PKH address behind a BIP-322 prefix, or a
//! script this has no interpreter for, is refused as unreadable rather than reported as a
//! bad signature: a screen that renders "I have no script interpreter" as "forged" teaches
//! people to ignore it.
//!
//! A message this screen cannot show faithfully gets no verdict either. "Signature good"
//! above a message the panel truncated is an answer about a different string from the one
//! being read.

use catcard_wallet::signfile::{self, ListedFile, Scheme};
use core::fmt::Write as _;

use crate::display;
use crate::menu;
use crate::ui::Ui;

/// Longest signed-message file this reads. A legacy or simple signature is a few hundred
/// bytes; a proof of reserves carries a whole PSBT, base64'd, and a multisig cosigner's
/// full signature runs to a kilobyte. The rest is room for a note above the block.
const MAX_FILE: usize = 6144;

/// Scratch the verifier gets beside the file: the compacted signature text and what it
/// decodes to. A proof of reserves decodes to its PSBT, so this is sized like the file.
const SCRATCH: usize = 6144;

/// Largest file this hashes for a sidecar check.
///
/// An export is a few kilobytes. The bound is against a sidecar that names something
/// enormous: hashing a card's worth of video through a 512-byte window would turn a check
/// into an afternoon with nothing on the glass, and "too big to check" is an answer.
const MAX_HASHED: u64 = 1 << 20;

/// Bytes read at a time while hashing: one sector, so the buffer is small and the
/// hash never needs the file in memory.
const CHUNK: usize = 512;

/// Room for a listed file's full path: the sidecar's directory and the longest name.
const FILE_PATH: usize = menu::BROWSE_PATH_MAX + signfile::MAX_NAME + 1;

/// What became of one file a sidecar named.
#[derive(Copy, Clone, PartialEq, Eq)]
enum Check {
    /// Its digest is the one the sidecar carries.
    Ok,
    /// It is there, and it is not the file that was signed.
    Mismatch,
    /// Not in the sidecar's directory.
    Missing,
    /// Larger than [`MAX_HASHED`].
    TooBig,
    /// The card stopped answering part-way.
    ReadFailed,
}

impl Check {
    const fn word(self) -> &'static str {
        match self {
            Check::Ok => "OK",
            Check::Mismatch => "CHANGED",
            Check::Missing => "missing",
            Check::TooBig => "too big to check",
            Check::ReadFailed => "read failed",
        }
    }
}

/// Pick a signed-message file or a sidecar and say whether its signature is its
/// address's -- and, for a sidecar, whether the files it names are still the files it
/// signed.
pub(crate) fn screen(ui: &mut Ui<'_>) {
    const HEAD: &str = "Verify sig";

    let Some(storage) = menu::pick_storage(ui, HEAD) else {
        return;
    };
    // The browser filters on one extension, and the two kinds of file have different
    // ones, so the kind is asked first.
    let (title, ext) = match menu::choose(
        ui,
        HEAD,
        "which kind of file?",
        &["Signed message .txt", "Export sidecar .sig"],
    ) {
        Some(0) => ("Pick a signed .txt", "txt"),
        Some(_) => ("Pick a .sig", "sig"),
        None => return,
    };
    let Some(path) = menu::browse_storage(ui, storage, title, Some(ext), menu::Browse::File) else {
        return;
    };
    // The file and the verifier's scratch, leased from the heap rather than put on the
    // stack: twelve kilobytes is more than a foreground frame should carry.
    let Some(mut block) = crate::heap::take(MAX_FILE + SCRATCH) else {
        return say(ui, HEAD, "no memory free");
    };
    let (raw, scratch) = block.bytes().split_at_mut(MAX_FILE);
    let mut note: heapless::String<32> = heapless::String::new();
    let _ = write!(note, "reading {}", storage.medium());
    menu::card_wait(ui.panel, HEAD, note.as_str());
    let len = match crate::signtx::read_source_file(storage, &path, raw) {
        Ok(n) => n,
        Err(why) => return say(ui, HEAD, why),
    };
    let Ok(text) = core::str::from_utf8(&raw[..len]) else {
        return say(ui, HEAD, "not text");
    };
    check(
        ui,
        HEAD,
        Some((storage, path.as_str())),
        path.as_str(),
        text,
        scratch,
    );
}

/// Say whether the signed-message text carries its address's signature: the half of
/// [`screen`] after the read, for a caller that has the text from somewhere other than a
/// file -- the NFC tag today. `source` names where it came from, for the log.
///
/// A sidecar that names files cannot be checked this way: the files live beside the
/// sidecar on a medium, and this has no medium. It says so rather than verifying the
/// signature alone and calling that good.
#[cfg_attr(feature = "board-mk3", allow(dead_code))]
pub(crate) fn verify_text(ui: &mut Ui<'_>, head: &str, source: &str, text: &str) {
    let Some(mut block) = crate::heap::take(SCRATCH) else {
        return say(ui, head, "no memory free");
    };
    check(ui, head, None, source, text, block.bytes());
}

/// Parse, hash the listed files if there is a medium to find them on, then verify.
///
/// `scratch` is the verifier's: see [`signfile::verify_with`].
fn check(
    ui: &mut Ui<'_>,
    head: &str,
    files_at: Option<(menu::Storage, &str)>,
    source: &str,
    text: &str,
    scratch: &mut [u8],
) {
    let file = match signfile::parse(text) {
        Ok(f) => f,
        Err(why) => return say(ui, head, describe(why)),
    };

    // The files a sidecar names, each hashed and compared -- before the signature, so
    // the report reads in the order the question is asked: are these the files, and did
    // this key sign for them.
    let mut checks: heapless::Vec<(ListedFile<'_>, Check), { signfile::MAX_FILES }> =
        heapless::Vec::new();
    if let Some(files) = signfile::listed_files(file.message) {
        let Some((storage, path)) = files_at else {
            return say(ui, head, "names files: verify it from the card");
        };
        menu::card_wait(ui.panel, head, "hashing the files");
        let dir = &path[..path.rfind('/').map(|i| i + 1).unwrap_or(0)];
        if let Err(why) = check_files(storage, dir, files, &mut checks) {
            return say(ui, head, why);
        }
        for (f, c) in &checks {
            crate::catlog!("verify: {}: {}", f.name, c.word());
        }
    }

    match signfile::verify_with(&file, scratch) {
        Ok(scheme) => {
            crate::catlog!("verify: {} good ({})", file.address, scheme.name());
            good(ui, &file, scheme, &checks);
        }
        // A cosigner's share: not a verdict on the message, and not a forgery either. The
        // numbers are the news, so they go on the screen.
        Err(signfile::Error::NeedsCosigners { have, need }) => {
            let mut why: heapless::String<48> = heapless::String::new();
            let _ = write!(why, "cosigner {have} of {need}: needs {} more", need - have);
            crate::catlog!("verify: {}: {}", source, why);
            bad(ui, &file, &why, &checks);
        }
        Err(why) => {
            crate::catlog!("verify: {}: {}", source, describe(why));
            bad(ui, &file, describe(why), &checks);
        }
    }
}

/// Hash every listed file on `storage` under `dir`, recording what became of each.
///
/// The medium is mounted once for all of them: a name checked under one mount and
/// hashed under another could be a different file.
fn check_files<'a>(
    storage: menu::Storage,
    dir: &str,
    files: signfile::Files<'a>,
    out: &mut heapless::Vec<(ListedFile<'a>, Check), { signfile::MAX_FILES }>,
) -> Result<(), &'static str> {
    match storage {
        menu::Storage::Sd => {
            let mut vol = menu::mount_card()?;
            for f in files {
                let check = check_one(&mut vol, dir, &f);
                let _ = out.push((f, check));
            }
            Ok(())
        }
        #[cfg(not(feature = "board-mk3"))]
        menu::Storage::Vdisk => menu::with_vdisk(|vol| {
            for f in files {
                let check = check_one(vol, dir, &f);
                let _ = out.push((f, check));
            }
            Ok(())
        }),
    }
}

/// Stream one file through SHA-256 and compare.
///
/// Generic over the backing driver so the card and the Virtual Disk share the one loop.
/// The read is bounded twice: by the file's own length, and by [`MAX_HASHED`] before the
/// first byte is read.
fn check_one<D: catcard_sd::fat::SectorDriver>(
    vol: &mut catcard_sd::AnyVolume<D, 512>,
    dir: &str,
    listed: &ListedFile<'_>,
) -> Check {
    use purecrypto::hash::{Digest as _, Sha256};

    let mut path: heapless::String<FILE_PATH> = heapless::String::new();
    if path.push_str(dir).is_err() || path.push_str(listed.name).is_err() {
        return Check::Missing;
    }
    let Ok(mut file) = vol.open_file(&path) else {
        return Check::Missing;
    };
    let len = file.len();
    if len > MAX_HASHED {
        return Check::TooBig;
    }
    let mut hash = Sha256::new();
    let mut chunk = [0u8; CHUNK];
    let mut got = 0u64;
    while got < len {
        match file.read(vol, &mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                hash.update(&chunk[..n]);
                got += n as u64;
            }
            Err(_) => return Check::ReadFailed,
        }
    }
    if got != len {
        return Check::ReadFailed;
    }
    let digest = hash.finalize();
    if digest[..] == listed.digest[..] {
        Check::Ok
    } else {
        Check::Mismatch
    }
}

/// Why a file could not be checked, in the words a screen has.
///
/// `Invalid` is the only one of these that means the signature is wrong. The rest say
/// this device could not answer the question, which is not the same news.
fn describe(e: signfile::Error) -> &'static str {
    match e {
        signfile::Error::NotArmoured => "not a signed message file",
        signfile::Error::Malformed => "file is damaged",
        signfile::Error::Unsupported => "cannot check this kind",
        signfile::Error::BadAddress => "address not readable",
        signfile::Error::Unshowable => "message not plain ASCII",
        signfile::Error::Invalid => "signature does NOT match",
        // Worded on the spot, with its numbers; never reached through here.
        signfile::Error::NeedsCosigners { .. } => "needs more cosigners",
    }
}

/// One `OK  name` row per listed file.
type CheckRows =
    heapless::Vec<heapless::String<{ signfile::MAX_NAME + 24 }>, { signfile::MAX_FILES }>;

fn check_rows(checks: &[(ListedFile<'_>, Check)]) -> CheckRows {
    let mut rows = CheckRows::new();
    for (f, c) in checks {
        let mut row = heapless::String::new();
        let _ = write!(row, "{}  {}", c.word(), f.name);
        let _ = rows.push(row);
    }
    rows
}

/// The verdict for a signature that checked out.
///
/// With a file list, the title says whether the files did too: a good signature over a
/// list whose files have changed is the sidecar telling on the export, and the title is
/// where that has to be said.
fn good(
    ui: &mut Ui<'_>,
    file: &signfile::Armoured<'_>,
    scheme: Scheme,
    checks: &[(ListedFile<'_>, Check)],
) {
    use catcard_ui::scroll::Line;
    let mut note: heapless::String<32> = heapless::String::new();
    let _ = write!(note, "{} signature", scheme.name());
    // What a proof of reserves proved: the outputs and their total, in the owner's
    // display units. Whether those outputs are still unspent is a question for a node.
    let mut proved: heapless::String<48> = heapless::String::new();
    if let Scheme::Bip322Proof { utxos, total } = scheme {
        let _ = write!(proved, "proves {utxos} UTXO(s), total ");
        let _ = crate::prefs::current().units.write(total, &mut proved);
    }
    let rows = check_rows(checks);
    let all_ok = checks.iter().all(|(_, c)| *c == Check::Ok);
    let mut doc: heapless::Vec<Line, { 8 + signfile::MAX_FILES }> = heapless::Vec::new();
    let _ = doc.push(Line::title(match (checks.is_empty(), all_ok) {
        (true, _) => "Signature good",
        (false, true) => "All good",
        (false, false) => "Files NOT ok",
    }));
    if !checks.is_empty() {
        let _ = doc.push(Line::body("signature good; files:").small());
        for row in &rows {
            let _ = doc.push(Line::body(row.as_str()).small().wrapped());
        }
    }
    let _ = doc.push(Line::body("signed by").small());
    let _ = doc.push(Line::body(file.address).small().wrapped());
    if checks.is_empty() {
        let _ = doc.push(Line::body(file.message).wrapped());
    }
    let _ = doc.push(Line::body(note.as_str()).small());
    if !proved.is_empty() {
        let _ = doc.push(Line::body(proved.as_str()).small().wrapped());
        let _ = doc.push(Line::body("(unspent status not checked)").small());
    }
    page(ui, &doc);
}

/// The verdict for one that did not, or could not be checked.
fn bad(
    ui: &mut Ui<'_>,
    file: &signfile::Armoured<'_>,
    why: &str,
    checks: &[(ListedFile<'_>, Check)],
) {
    use catcard_ui::scroll::Line;
    let rows = check_rows(checks);
    let mut doc: heapless::Vec<Line, { 8 + signfile::MAX_FILES }> = heapless::Vec::new();
    let _ = doc.push(Line::title("Not verified"));
    let _ = doc.push(Line::body(why).wrapped());
    if !checks.is_empty() {
        let _ = doc.push(Line::body("files:").small());
        for row in &rows {
            let _ = doc.push(Line::body(row.as_str()).small().wrapped());
        }
    }
    let _ = doc.push(Line::body("claimed address").small());
    let _ = doc.push(Line::body(file.address).small().wrapped());
    if checks.is_empty() {
        let _ = doc.push(Line::body(file.message).wrapped());
    }
    page(ui, &doc);
}

fn page(ui: &mut Ui<'_>, doc: &[catcard_ui::scroll::Line]) {
    let mut view = catcard_ui::scroll::ScrollView::build(
        doc,
        display::SCREEN_W,
        display::SCREEN_H,
        display::FONTS,
    );
    let _ = menu::scroll_choice(ui, &mut view);
}

fn say(ui: &mut Ui<'_>, head: &str, what: &str) {
    menu::message(ui.panel, head, what, "any key to go back");
    menu::wait_for_any_key(ui);
}
