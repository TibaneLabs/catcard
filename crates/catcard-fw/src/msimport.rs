//! Registering a multisig wallet from a descriptor on the card.
//!
//! This screen is where the owner's check happens, and it is the only one there will be: a
//! wallet registered here decides, from then on, which addresses this device calls its own
//! and which spends it will sign. So it shows what a person needs in order to compare this
//! device's reading against the other cosigners' -- the threshold, the script form, the
//! sortedness, and every cosigner's fingerprint -- before anything is stored.
//!
//! Two things are deliberately *not* asked of the owner:
//!
//! - **Whether the checksum matters.** A descriptor with a bad one is refused before this
//!   screen draws. It is eight characters that turn a mistyped wallet into a stopped
//!   import rather than an address nobody can spend from.
//! - **Whether our key is in it.** That is checked and shown, not asked. A wallet this
//!   device is not part of can still be registered -- watching one is legitimate -- but a
//!   person who thought they were registering *their* wallet should see that it is not.

use catcard_settings::prefs::MultisigTrust;
use catcard_settings::store::SCRATCH;
use catcard_settings::wallets::{self, Wallet};
use catcard_wallet::bip32::ExtendedPrivKey;
use catcard_wallet::multisig::{self, Kind, Multisig};
use catcard_wallet::psbtview;
use outscript::psbt::Psbt;

use crate::menu;
use crate::ui::Ui;

/// Longest descriptor file this will read.
///
/// Fifteen cosigners with origins and 111-character keys is about 1.9 KB; this leaves
/// room around that. A larger file is refused with its size rather than truncated into
/// something that might still parse.
const MAX_FILE: usize = 4096;

// The scratch these screens need -- the settings as they are, the rendered list, and the
// seal -- comes from `crate::heap`, a full slot (`SCRATCH`) at a time.
//
// It used to be three resident statics, twelve kilobytes reserved for the device's whole
// life to serve a screen that is open for a few seconds during an import. They are leased
// now: taken when the import or the management screen starts, dropped (and wiped) when it
// ends, so the RAM is the modal screen's for the moment it runs and nobody else's after. A
// slot is four kilobytes and the stacks are eight, so these never went on the stack; the
// heap is where a buffer this size that is only sometimes needed belongs.
//
// `crate::heap::take` can say no, and then the screen says so and returns rather than
// reserving the space against the chance. The parsed wallets below are the one thing that
// stays resident: a slice of them outlives the call that made it.

/// The parsed wallets, kept between calls so a slice of them can outlive [`registered`].
///
/// A `Multisig` is around two kilobytes -- fifteen extended keys and their origins -- so
/// eight of them do not go on a stack either.
static mut PARSED: heapless::Vec<Multisig, { wallets::MAX_WALLETS }> = heapless::Vec::new();

/// The multisig wallets this device has registered.
///
/// Read once per transaction rather than once per input: it costs a settings mount and a
/// callgate fetch of the login secret. **An empty slice is a meaningful answer** -- it is
/// what a device with nothing registered returns, and it makes every multisig input refuse
/// rather than be signed on the host's word about who the other cosigners are. So a
/// settings store that will not mount reads as "none registered", never as "allow".
///
/// A descriptor that no longer parses is skipped rather than failing the list: one entry
/// written by a version that stores more must not hide the wallets beside it.
///
/// # The slice is borrowed from a static this clears
///
/// The `'static` lifetime is a convenience, not a promise: the wallets live in
/// [`PARSED`], and the next call empties it and parses afresh. So a slice from one call
/// is stale -- and, since it aliases memory being rewritten, unsound to read -- the
/// moment another call is made. The rule for a caller is:
///
/// - **foreground only**, one screen at a time, like everything else in this module;
/// - **never hold the slice across another `registered()`**. Take it, use it, and let
///   it go before anything that might read the registered wallets again runs.
///
/// Both callers do: the signing screen reads it once per transaction and drops it with
/// the review, and the address explorer reads it once on entry and holds it for a loop
/// that calls nothing in this module.
pub(crate) fn registered(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    panel: &mut crate::display::Panel,
) -> &'static [Multisig] {
    // SAFETY: foreground only; one settings screen at a time.
    let parsed: &'static mut heapless::Vec<Multisig, { wallets::MAX_WALLETS }> =
        unsafe { &mut *core::ptr::addr_of_mut!(PARSED) };
    parsed.clear();

    // A leased slot to read the stored records into. If the heap cannot spare one, an
    // empty list is the safe answer -- the same one a store that will not mount gives --
    // so every multisig input refuses rather than being signed on the host's word.
    let Some(mut doc) = crate::heap::take(SCRATCH) else {
        crate::catlog!("multisig: no scratch, so no registered wallets");
        return parsed;
    };
    let doc_buf = doc.bytes();

    let mut list = [Wallet {
        name: "",
        descriptor: "",
    }; wallets::MAX_WALLETS];
    let have = match load(gate, login, panel, doc_buf, &mut list) {
        Ok(n) => n,
        Err(why) => {
            crate::catlog!("multisig: {}, so no registered wallets", why);
            return parsed;
        }
    };
    for w in &list[..have] {
        match multisig::parse(w.descriptor) {
            Ok(m) => {
                let _ = parsed.push(m);
            }
            Err(why) => crate::catlog!("multisig: skipping {}: {:?}", w.name, why),
        }
    }
    crate::catlog!("multisig: {} wallet(s) registered", parsed.len());
    parsed
}

/// Augment the registered wallets with any this PSBT itself describes, as far as the trust
/// `policy` allows, and return the combined set.
///
/// Called straight after [`registered`], which has just filled [`PARSED`]; this appends to
/// the same store, so the slice it returns is the registered wallets plus whichever ones the
/// PSBT vouched for. The multisig PSBT trust policy in one place:
///
/// - [`MultisigTrust::VerifyOnly`]: nothing is added -- an unregistered multisig stays
///   refused. (The caller does not call here in that case, but it is honoured anyway.)
/// - [`MultisigTrust::TrustPsbt`]: a wallet the PSBT proves (its keys rebuild the input's
///   script) and that this device provably co-signs is added for this signing, silently and
///   without storing it.
/// - [`MultisigTrust::OfferImport`]: the same, but the wallet is shown and the owner asked
///   first; on yes it is also stored permanently, on no it is left unregistered and its
///   input refused.
///
/// The proof is [`psbtview::reconstruct_for_input`] -- the rebuilt address has to equal the
/// coin's -- and [`multisig::our_cosigner`], which derives our key down the claimed origin
/// so a mere fingerprint claim does not qualify. Nothing here is signed on the host's word
/// alone.
///
/// # The slice is borrowed from [`PARSED`], which the next call rewrites
///
/// Exactly as [`registered`]: foreground only, and the caller must not hold the returned
/// slice across another call into this module.
#[cfg(not(feature = "board-mk3"))]
pub(crate) fn trust_from_psbt(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    psbt: &Psbt<'_>,
    master: &ExtendedPrivKey,
    fingerprint: [u8; 4],
    policy: MultisigTrust,
) -> &'static [Multisig] {
    // SAFETY: foreground only; one signing screen at a time. `registered` filled this on
    // the call just before ours.
    let parsed: &'static mut heapless::Vec<Multisig, { wallets::MAX_WALLETS }> =
        unsafe { &mut *core::ptr::addr_of_mut!(PARSED) };
    if policy == MultisigTrust::VerifyOnly {
        return parsed;
    }

    let inputs = psbt.unsigned_tx().input_count();
    for index in 0..inputs {
        if parsed.is_full() {
            break;
        }
        // Reconstruct against everything held so far -- registered wallets and ones already
        // trusted from this PSBT -- so an input matched by those is left alone.
        let Some(candidate) = psbtview::reconstruct_for_input(psbt, index, fingerprint, parsed)
        else {
            continue;
        };
        if parsed.contains(&candidate) {
            continue;
        }
        // The address proof says the keys build this coin; this says one of those keys is
        // genuinely ours, derived down the claimed origin. Only then is the wallet worth
        // trusting or storing.
        let ours = crate::keywork::run(|kw| multisig::our_cosigner(&candidate, master, kw));
        let Ok(Some(mine)) = ours else {
            crate::catlog!("multisig: PSBT wallet at input {} is not ours; not trusting", index);
            continue;
        };

        let take = match policy {
            MultisigTrust::TrustPsbt => {
                crate::catlog!(
                    "multisig: trusting a {}-of-{} wallet from the PSBT",
                    candidate.m,
                    candidate.n()
                );
                true
            }
            // Show it and ask; on yes, also store it permanently.
            MultisigTrust::OfferImport => offer_from_psbt(gate, login, ui, &candidate, mine),
            MultisigTrust::VerifyOnly => false,
        };
        if take {
            let _ = parsed.push(candidate);
        }
    }
    parsed
}

/// Show a wallet reconstructed from the PSBT and ask whether to import it. On yes it is
/// stored (so it needs no re-approval next time) and this returns `true` to trust it for the
/// signing in hand; on no, `false`, and the input it came from stays refused.
///
/// Storing needs the wallet as descriptor text, which [`Multisig::write_descriptor`]
/// produces. A store that cannot find memory still trusts the wallet for this one signing --
/// the owner has just approved it on screen -- and says so in the log, rather than throwing
/// away an approval over a transient shortage.
#[cfg(not(feature = "board-mk3"))]
fn offer_from_psbt(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    wallet: &Multisig,
    ours: usize,
) -> bool {
    let Some(mut held) = crate::heap::take(SCRATCH) else {
        crate::catlog!("multisig: no memory to render the PSBT wallet; not offering");
        return false;
    };
    let buf = held.bytes();
    let len = match wallet.write_descriptor(buf) {
        Ok(n) => n,
        Err(why) => {
            crate::catlog!("multisig: cannot render PSBT wallet: {:?}", why);
            return false;
        }
    };
    let Ok(descriptor) = core::str::from_utf8(&buf[..len]) else {
        return false;
    };

    menu::ask(
        ui.panel,
        "Multisig in PSBT",
        "an unregistered wallet",
        "review and import it?",
    );
    if !menu::confirmed(ui) {
        return false;
    }
    // The full review, with our own cosigner marked -- the index proven by the caller.
    if !confirm(ui, wallet, descriptor, Some(ours)) {
        return false;
    }
    match save(gate, login, ui, "", descriptor) {
        Ok(()) => crate::catlog!("multisig: PSBT wallet imported and trusted"),
        // Approved, but could not be stored: honour the approval for this signing anyway.
        Err(why) => crate::catlog!("multisig: PSBT wallet trusted but not stored: {}", why),
    }
    true
}

/// The stored wallet records, read into `doc_buf`. Returns how many `out` received.
///
/// The records borrow `doc_buf`, which is also the scratch a later write needs, so a
/// caller that goes on to store something must let that borrow end first -- which is why
/// the buffer is passed in (leased from [`crate::heap`] by the caller) rather than taken
/// here.
fn load<'a>(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    panel: &mut crate::display::Panel,
    doc_buf: &'a mut [u8],
    out: &mut [Wallet<'a>],
) -> Result<usize, &'static str> {
    use catcard_settings::json::Doc;
    use catcard_settings::store;

    // The wallet in force has its own settings file, so a registration made under a
    // BIP-85 child or a temporary seed belongs to that wallet and not to the root's.
    let key = crate::settings::wallet_key(gate, login, panel, "Multisig")?;
    // Read-only, as every read should be: see `vault::read_doc`.
    // SAFETY: the region is mapped and readable; nothing is written.
    let mut files =
        unsafe { crate::settings::Files::mount_read_only() }.map_err(|_| "no settings store")?;

    let n = store::read(&mut files, &key, doc_buf).unwrap_or(0);
    let doc = Doc::parse(&doc_buf[..n]).unwrap_or_default();
    Ok(wallets::list(&doc, out))
}

/// The Multisig screen: what is registered, and what can be done about it.
///
/// A registration decides which spends this device will sign, so it cannot be write-only.
/// A wallet imported from the wrong file has to be findable and removable, and the only
/// way to notice one is to be able to look.
pub(crate) fn manage(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) {
    use catcard_ui::scroll::Line as Row;

    /// The "Import from SD" row, numbered past any wallet.
    const IMPORT: u32 = 1000;
    /// The "Trust policy" row, numbered past the import row.
    #[cfg(not(feature = "board-mk3"))]
    const TRUST: u32 = 1001;

    /// What the list screen came back with. Nothing here borrows the settings buffer, so
    /// acting on it can read and write the settings again.
    enum Then {
        Leave,
        Import,
        #[cfg(not(feature = "board-mk3"))]
        Trust,
        Delete(heapless::String<8>),
    }

    loop {
        menu::blocking_screen(ui.panel, "Multisig", "reading");
        // Scoped: the wallet records borrow the settings buffer, and deleting one reads
        // the settings afresh.
        let next = {
            // A leased slot for the read; dropped (and wiped) when this scope ends, before
            // any import or delete acts on the choice.
            let Some(mut doc) = crate::heap::take(SCRATCH) else {
                return say(ui, "Multisig", "not enough memory");
            };
            let doc_buf = doc.bytes();
            let mut list = [Wallet {
                name: "",
                descriptor: "",
            }; wallets::MAX_WALLETS];
            let have = match load(gate, login, ui.panel, doc_buf, &mut list) {
                Ok(n) => n,
                Err(why) => return say(ui, "Multisig", why),
            };

            // A label per wallet: its name if it has one, otherwise its shape, and its
            // checksum -- which is what a person compares against the other cosigners.
            let mut labels: heapless::Vec<heapless::String<40>, { wallets::MAX_WALLETS }> =
                heapless::Vec::new();
            for w in &list[..have] {
                let _ = labels.push(label(w));
            }

            // The policy line, so a person can see at a glance whether this device will
            // sign a multisig it was never shown. Only where there is a settings store to
            // keep the answer in.
            #[cfg(not(feature = "board-mk3"))]
            let mut trust_row: heapless::String<40> = heapless::String::new();
            #[cfg(not(feature = "board-mk3"))]
            {
                use core::fmt::Write as _;
                let _ = write!(
                    trust_row,
                    "Trust policy: {}",
                    crate::prefs::current().multisig_trust.label()
                );
            }

            let exit = {
                let mut rows: heapless::Vec<Row, { wallets::MAX_WALLETS + 4 }> =
                    heapless::Vec::new();
                let _ = rows.push(Row::title("Multisig"));
                if have == 0 {
                    let _ = rows.push(Row::body("(none registered)").centered());
                }
                for (i, l) in labels.iter().enumerate() {
                    let _ = rows.push(Row::item(l.as_str(), i as u32));
                }
                let _ = rows.push(Row::item("Import from SD", IMPORT));
                #[cfg(not(feature = "board-mk3"))]
                let _ = rows.push(Row::item(trust_row.as_str(), TRUST));
                menu::show_doc(ui, &rows, false, false)
            };

            match exit {
                menu::DocExit::Selected(IMPORT) => Then::Import,
                #[cfg(not(feature = "board-mk3"))]
                menu::DocExit::Selected(TRUST) => Then::Trust,
                menu::DocExit::Selected(i) if (i as usize) < have => {
                    let w = &list[i as usize];
                    let mut sum: heapless::String<8> = heapless::String::new();
                    let _ = sum.push_str(w.checksum().unwrap_or(""));
                    if detail(ui, w) && !sum.is_empty() {
                        Then::Delete(sum)
                    } else {
                        continue;
                    }
                }
                _ => Then::Leave,
            }
        };

        match next {
            Then::Leave => return,
            Then::Import => import(gate, login, ui),
            #[cfg(not(feature = "board-mk3"))]
            Then::Trust => trust_policy_screen(gate, login, ui),
            Then::Delete(sum) => match remove(gate, login, ui, &sum) {
                Ok(()) => say(ui, "Multisig", "the wallet is gone"),
                Err(why) => say(ui, "Multisig", why),
            },
        }
    }
}

/// Settings → Multisig → Trust policy: how far to trust a multisig wallet a PSBT describes
/// but this device has not registered.
///
/// The safe policy is the default and the first choice; the other two relax it, and
/// "Trust PSBT" -- which signs against keys the PSBT alone vouches for -- is asked twice,
/// because it is the one that will sign for a wallet nobody imported.
#[cfg(not(feature = "board-mk3"))]
fn trust_policy_screen(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) {
    use catcard_settings::prefs::{MULTISIG_TRUST, MultisigTrust};
    use core::fmt::Write as _;
    const HEAD: &str = "Trust policy";

    let now = crate::prefs::current();
    let labels = MultisigTrust::ALL.map(|p| p.label());
    let mut note: heapless::String<48> = heapless::String::new();
    let _ = write!(note, "now {}", now.multisig_trust.label());

    let Some(row) = menu::choose(ui, HEAD, &note, &labels) else {
        return;
    };
    let chosen = MultisigTrust::ALL[row];
    if chosen == now.multisig_trust {
        menu::message(ui.panel, HEAD, "unchanged", labels[row]);
        menu::wait_for_any_key(ui);
        return;
    }
    // Trusting the PSBT means signing against a wallet definition the host supplied and the
    // owner never registered. Real, and useful for airgapped setups, but never a default and
    // never one press away.
    if chosen == MultisigTrust::TrustPsbt {
        menu::ask(
            ui.panel,
            HEAD,
            "trust wallet keys",
            "found inside a PSBT?",
        );
        if !menu::confirmed(ui) {
            return;
        }
        menu::ask(
            ui.panel,
            "Trust PSBT",
            "this device will sign a",
            "multisig it never imported",
        );
        if !menu::confirmed(ui) {
            return;
        }
    }
    let value = crate::prefs::quoted(chosen.code());
    let next = crate::prefs::Prefs {
        multisig_trust: chosen,
        ..now
    };
    if crate::prefs::save(gate, login, ui, HEAD, (MULTISIG_TRUST, &value), next) {
        menu::message(ui.panel, HEAD, "saved", chosen.label());
    } else {
        menu::message(ui.panel, HEAD, "could not save", "nothing changed");
    }
    menu::wait_for_any_key(ui);
}

/// One line for the list: the owner's name for the wallet, or its shape, plus the checksum.
fn label(w: &Wallet<'_>) -> heapless::String<40> {
    use core::fmt::Write as _;
    let mut text = heapless::String::new();
    let shape = match multisig::parse(w.descriptor) {
        Ok(m) => {
            let mut s: heapless::String<16> = heapless::String::new();
            let _ = write!(s, "{}-of-{}", m.m, m.n());
            s
        }
        // A descriptor this build cannot read is still shown, so it can be deleted.
        Err(_) => heapless::String::try_from("unreadable").unwrap_or_default(),
    };
    let name = if w.name.is_empty() {
        shape.as_str()
    } else {
        w.name
    };
    let _ = write!(text, "{name}  {}", w.checksum().unwrap_or("?"));
    text
}

/// Show one registered wallet. Returns whether the owner asked to delete it.
fn detail(ui: &mut Ui<'_>, w: &Wallet<'_>) -> bool {
    use catcard_ui::scroll::Line as Row;
    use core::fmt::Write as _;

    type Text = heapless::String<48>;
    let mut lines: heapless::Vec<Text, { multisig::MAX_COSIGNERS + 4 }> = heapless::Vec::new();
    match multisig::parse(w.descriptor) {
        Ok(m) => {
            let mut head = Text::new();
            let _ = write!(
                head,
                "{}-of-{} {}{}",
                m.m,
                m.n(),
                kind_name(m.kind),
                if m.sorted { "" } else { ", unsorted" }
            );
            let _ = lines.push(head);
            for (i, c) in m.cosigners().iter().enumerate() {
                let mut line = Text::new();
                let _ = write!(
                    line,
                    "{}: {:02x}{:02x}{:02x}{:02x}",
                    i + 1,
                    c.fingerprint[0],
                    c.fingerprint[1],
                    c.fingerprint[2],
                    c.fingerprint[3]
                );
                let _ = lines.push(line);
            }
        }
        Err(why) => {
            let mut line = Text::new();
            let _ = write!(line, "cannot read: {}", describe(why));
            let _ = lines.push(line);
        }
    }
    let mut sum = Text::new();
    let _ = write!(sum, "checksum {}", w.checksum().unwrap_or("none"));
    let _ = lines.push(sum);

    let mut hint = Text::new();
    let _ = write!(
        hint,
        "{} delete   {} back",
        crate::display::CONFIRM_KEY,
        crate::display::CANCEL_KEY
    );

    let title = if w.name.is_empty() { "Wallet" } else { w.name };
    let mut rows: heapless::Vec<Row, { multisig::MAX_COSIGNERS + 6 }> = heapless::Vec::new();
    let _ = rows.push(Row::title(title));
    for l in lines.iter() {
        let _ = rows.push(Row::body(l.as_str()).small());
    }
    let _ = rows.push(Row::body(hint.as_str()).small());
    if !matches!(
        menu::show_doc(ui, &rows, false, false),
        menu::DocExit::Confirmed
    ) {
        return false;
    }
    // Deleting is not destroying coins -- the wallet can be imported again -- but it does
    // stop this device signing for it until that happens, so it is asked once.
    menu::ask(
        ui.panel,
        "Delete wallet?",
        "this device will refuse",
        "its spends until re-imported",
    );
    menu::confirmed(ui)
}

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::P2sh => "P2SH",
        Kind::P2wsh => "P2WSH",
        Kind::P2shP2wsh => "P2SH-P2WSH",
    }
}

/// Store the wallet list without the one whose checksum is `sum`.
fn remove(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    sum: &str,
) -> Result<(), &'static str> {
    menu::blocking_screen(ui.panel, "Multisig", "saving");
    // Three leased slots: the settings scratch, the rendered list, and the seal the write
    // needs. All wiped on drop at the end of this call.
    let (Some(mut doc), Some(mut list_blk), Some(mut seal)) = (
        crate::heap::take(SCRATCH),
        crate::heap::take(SCRATCH),
        crate::heap::take(SCRATCH),
    ) else {
        return Err("not enough memory");
    };
    let doc_buf = doc.bytes();
    let list_buf = list_blk.bytes();
    // Scoped: the records borrow `doc_buf`, which the write below reuses as scratch.
    let len = {
        let mut list = [Wallet {
            name: "",
            descriptor: "",
        }; wallets::MAX_WALLETS];
        let have = load(gate, login, ui.panel, doc_buf, &mut list)?;
        let mut left = [Wallet {
            name: "",
            descriptor: "",
        }; wallets::MAX_WALLETS];
        let n = wallets::without(&list[..have], sum, &mut left);
        if n == have {
            return Err("no such wallet");
        }
        wallets::render(&left[..n], list_buf).map_err(|_| "too long")?
    };
    store_list(gate, login, ui, doc_buf, &list_buf[..len], seal.bytes())
}

/// Write the rendered wallet list `list_text` into the settings.
///
/// `doc_buf` and `seal_buf` are the leased scratch the edit needs; `doc_buf` must no
/// longer be lent to any wallet record by the time this is called -- which is what the
/// scopes above are for.
fn store_list(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    doc_buf: &mut [u8],
    list_text: &[u8],
    seal_buf: &mut [u8],
) -> Result<(), &'static str> {
    let text = core::str::from_utf8(list_text).map_err(|_| "not text")?;

    // Into the wallet in force's own file, as the read was.
    crate::settings::save_wallet(
        gate,
        login,
        ui,
        "Multisig",
        (wallets::KEY, text),
        doc_buf,
        seal_buf,
    )
}

/// Import a wallet: pick the file, read it, show it, and store it if the owner agrees.
pub(crate) fn import(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) {
    let Some(path) = menu::browse_sd(ui, "Pick a descriptor", None, menu::Browse::File) else {
        return;
    };

    let mut file = [0u8; MAX_FILE];
    menu::card_wait(ui.panel, "Import", "reading the card");
    let len = match crate::signtx::read_card_file(&path, &mut file) {
        Ok(n) => n,
        Err(why) => return say(ui, "Import", why),
    };
    let Ok(text) = core::str::from_utf8(&file[..len]) else {
        return say(ui, "Import", "not text");
    };
    // A descriptor file may carry comment lines and a name, as an exported one does. The
    // descriptor is the line that parses; nothing here guesses at the rest.
    let Some((line, name)) = pick_descriptor(text) else {
        return say(ui, "Import", "no descriptor in that file");
    };
    let wallet = match multisig::parse(line) {
        Ok(w) => w,
        Err(why) => return say(ui, "Import", describe(why)),
    };

    // The fingerprint of this device, to say which cosigner is us. Public, and this
    // session may already have paid for it -- registering several wallets in a row should
    // not mean stretching the seed once per wallet.
    let Some(ours_fp) = crate::pubkeys::fingerprint(gate, login, ui, "Import") else {
        return;
    };

    // A fingerprint is a claim by whoever wrote the file, not a proof. Where one names this
    // device, derive our master along the claimed origin and require the key it reaches to
    // be the one the descriptor names. Only a claim costs the unlock.
    let ours = if wallet.cosigners().iter().any(|c| c.fingerprint == ours_fp) {
        let Some(found) = crate::menu::unlock_master(gate, login, ui, "Import").map(|master| {
            let found = crate::keywork::run(|kw| multisig::our_cosigner(&wallet, &master, kw));
            drop(master);
            found
        }) else {
            return;
        };
        match found {
            Ok(found) => found,
            Err(why) => return say(ui, "Import", describe(why)),
        }
    } else {
        None
    };

    if !confirm(ui, &wallet, line, ours) {
        return;
    }
    match save(gate, login, ui, name, line) {
        Ok(()) => say(ui, "Registered", "the wallet is stored"),
        Err(why) => say(ui, "Import", why),
    }
}

/// The descriptor line in a file, and a name if one was given.
///
/// An exported multisig file carries comments (`#`), a `Name:` line and the descriptor.
/// The descriptor is recognised by parsing, not by position, so a file with the lines in
/// another order still imports.
fn pick_descriptor(text: &str) -> Option<(&str, &str)> {
    let mut name = "";
    let mut found = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line
            .strip_prefix("Name:")
            .or_else(|| line.strip_prefix("# Name:"))
        {
            name = rest.trim();
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        if found.is_none() && multisig::parse(line).is_ok() {
            found = Some(line);
        }
    }
    found.map(|line| (line, name))
}

/// Show the wallet and ask. Returns whether the owner accepted it.
fn confirm(ui: &mut Ui<'_>, wallet: &Multisig, descriptor: &str, ours: Option<usize>) -> bool {
    use catcard_ui::scroll::Line as Row;
    use core::fmt::Write as _;

    type Text = heapless::String<48>;
    let mut lines: heapless::Vec<Text, { multisig::MAX_COSIGNERS + 6 }> = heapless::Vec::new();

    let mut head = Text::new();
    let _ = write!(
        head,
        "{}-of-{} {}{}",
        wallet.m,
        wallet.n(),
        match wallet.kind {
            Kind::P2sh => "P2SH",
            Kind::P2wsh => "P2WSH",
            Kind::P2shP2wsh => "P2SH-P2WSH",
        },
        if wallet.sorted { "" } else { ", unsorted" }
    );
    let _ = lines.push(head);

    // Unsorted is not wrong, and it is rare enough that a person who did not choose it
    // should be told rather than left to notice.
    if !wallet.sorted {
        let mut warn = Text::new();
        let _ = write!(warn, "keys are NOT sorted (multi)");
        let _ = lines.push(warn);
    }

    let mut mine = false;
    for (i, c) in wallet.cosigners().iter().enumerate() {
        let is_ours = ours == Some(i);
        mine |= is_ours;
        let mut line = Text::new();
        let _ = write!(
            line,
            "{}: {:02x}{:02x}{:02x}{:02x}{}",
            i + 1,
            c.fingerprint[0],
            c.fingerprint[1],
            c.fingerprint[2],
            c.fingerprint[3],
            if is_ours { "  (this device)" } else { "" }
        );
        let _ = lines.push(line);
    }
    if !mine {
        let mut warn = Text::new();
        // Legitimate -- watching someone else's wallet is a real thing to do -- and worth
        // saying plainly, because it is also what a wallet imported from the wrong file
        // looks like.
        let _ = write!(warn, "this device is NOT a cosigner");
        let _ = lines.push(warn);
    }

    let mut sum = Text::new();
    let checksum = descriptor.rsplit_once('#').map(|(_, s)| s).unwrap_or("");
    let _ = write!(sum, "checksum {checksum}");
    let _ = lines.push(sum);

    // Declared before the rows that borrow it.
    let mut hint = Text::new();
    let _ = write!(
        hint,
        "{} register   {} cancel",
        crate::display::CONFIRM_KEY,
        crate::display::CANCEL_KEY
    );
    let mut rows: heapless::Vec<Row, { multisig::MAX_COSIGNERS + 8 }> = heapless::Vec::new();
    let _ = rows.push(Row::title("Register wallet"));
    for l in lines.iter() {
        let _ = rows.push(Row::body(l.as_str()).small());
    }
    let _ = rows.push(Row::body(hint.as_str()).small());
    matches!(
        menu::show_doc(ui, &rows, false, false),
        menu::DocExit::Confirmed
    )
}

/// Store the wallet in the settings, under the wallet key.
fn save(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    name: &str,
    descriptor: &str,
) -> Result<(), &'static str> {
    menu::blocking_screen(ui.panel, "Register wallet", "saving");
    // Three leased slots: the settings scratch, the rendered list, and the seal the write
    // needs. All wiped on drop at the end of this call.
    let (Some(mut doc), Some(mut list_blk), Some(mut seal)) = (
        crate::heap::take(SCRATCH),
        crate::heap::take(SCRATCH),
        crate::heap::take(SCRATCH),
    ) else {
        return Err("not enough memory");
    };
    let doc_buf = doc.bytes();
    let list_buf = list_blk.bytes();

    // Scoped: the records read here borrow `doc_buf`, and the write below reuses it as
    // scratch, so the borrow has to end first.
    let len = {
        let mut current = [Wallet {
            name: "",
            descriptor: "",
        }; wallets::MAX_WALLETS];
        let have = load(gate, login, ui.panel, doc_buf, &mut current)?;

        let mut next = [Wallet {
            name: "",
            descriptor: "",
        }; wallets::MAX_WALLETS];
        let added = wallets::with_added(&current[..have], Wallet { name, descriptor }, &mut next)
            .map_err(|e| match e {
            wallets::Error::TooMany => "no room for another wallet",
            wallets::Error::NotStorable => "that descriptor cannot be stored",
            wallets::Error::NoChecksum => "no checksum",
            wallets::Error::Overflow => "too long",
        })?;
        crate::catlog!("multisig: registering, {} wallet(s) after this", added);
        wallets::render(&next[..added], list_buf).map_err(|_| "too long")?
    };
    store_list(gate, login, ui, doc_buf, &list_buf[..len], seal.bytes())
}

/// Why a descriptor was refused, in words rather than a variant name.
fn describe(why: multisig::Error) -> &'static str {
    match why {
        multisig::Error::BadChecksum => "checksum does not match",
        multisig::Error::NotMultisig => "not a multisig descriptor",
        multisig::Error::BadThreshold => "threshold is impossible",
        multisig::Error::BadKey { .. } => "a key is malformed",
        multisig::Error::CosignerCount { .. } => "too many cosigners",
        multisig::Error::DuplicateKey => "the same key appears twice",
        multisig::Error::ForgedOrigin { .. } => "a key claims this device but is not ours",
        multisig::Error::Overflow => "too long",
    }
}

fn say(ui: &mut Ui<'_>, head: &str, what: &str) {
    menu::message(ui.panel, head, what, "any key to go back");
    menu::wait_for_any_key(ui);
}
