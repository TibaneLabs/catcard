//! Multisig wallets: registering one, and everything that can be done with one after.
//!
//! The import screen is where the owner's check happens, and it is the only one there
//! will be: a wallet registered here decides, from then on, which addresses this device
//! calls its own and which spends it will sign. So it shows what a person needs in order
//! to compare this device's reading against the other cosigners' -- the threshold, the
//! script form, the sortedness, and every cosigner's fingerprint -- before anything is
//! stored.
//!
//! Two things are deliberately *not* asked of the owner:
//!
//! - **Whether the checksum matters.** A descriptor with a bad one is refused before this
//!   screen draws. It is eight characters that turn a mistyped wallet into a stopped
//!   import rather than an address nobody can spend from.
//! - **Whether our key is in it.** That is checked and shown, not asked. A wallet this
//!   device is not part of can still be registered -- watching one is legitimate -- but a
//!   person who thought they were registering *their* wallet should see that it is not.
//!
//! # Where a wallet comes from
//!
//! A file on the card or the Virtual Disk, a code on the Q1's scanner, or a tag over NFC
//! -- all through [`from_text`], which reads either an output descriptor or stock's own
//! setup file (hw-reference/wallet-export-formats.md §J1). A wallet can also be built
//! here, airgapped, from the other cosigners' `ccxp` key bundles and this device's own key
//! ([`create_airgapped`]), and every registered wallet can be written back out in each of
//! stock's formats so the other cosigners can register the same agreement.
//!
//! # What an import refuses, and what it only warns about
//!
//! An exact duplicate of a registered wallet is refused: there is nothing to add. A
//! *near* duplicate -- the same keys in another order, `multi` where the other is
//! `sortedmulti`, another threshold or script form, or simply the same name -- is warned
//! about and asked, because that is the shape a wrong registration takes: signing against
//! the wrong one of two look-alikes is how funds end up in an address nobody else can
//! rebuild. And an unsorted wallet is refused outright unless "Unsorted Multisig?" is on,
//! as stock does: with BIP-67 off, the order of the keys is part of the wallet, and a
//! backup that loses it loses the addresses.

use catcard_settings::prefs::MultisigTrust;
use catcard_settings::store::SCRATCH;
use catcard_settings::wallets::{self, Wallet};
use catcard_wallet::bip32::{ChildNumber, ExtendedPrivKey, HARDENED_OFFSET};
use catcard_wallet::multisig::{self, Cosigner, Kind, Likeness, Multisig};
use catcard_wallet::psbtview;
use outscript::psbt::Psbt;

use crate::menu;
use crate::ui::Ui;

/// Longest wallet file this will read.
///
/// Fifteen cosigners with origins and 111-character keys is about 1.9 KB; this leaves
/// room around that. A larger file is refused with its size rather than truncated into
/// something that might still parse.
const MAX_FILE: usize = 4096;

/// The largest export built here: Bitcoin Core's line carries two fifteen-cosigner
/// descriptors, which is close to four kilobytes on its own.
const EXPORT_MAX: usize = 8192;

/// Columns of a registered wallet's address the Address Explorer shows while "Full
/// Address View?" is off: eight characters at each end around the elision. Enough to
/// compare against a cosigner's screen, and visibly not the whole address.
/// Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §MS "Full Address View?" [C]
pub(crate) const CENSORED_COLS: usize = 19;

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
            crate::catlog!(
                "multisig: PSBT wallet at input {} is not ours; not trusting",
                index
            );
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
fn offer_from_psbt(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    wallet: &Multisig,
    ours: usize,
) -> bool {
    // An import is an import: the unsorted rule applies here as it does to a file.
    if !unsorted_allowed(ui, wallet) {
        return false;
    }
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

/// What the owner asked to do with one registered wallet.
#[derive(Copy, Clone, PartialEq, Eq)]
enum WalletAct {
    Rename,
    Delete,
    /// Format J1, `export-{name}.txt`.
    ExportColdcard,
    /// Format K, `el-{name}.json`.
    ExportElectrum,
    DescriptorView,
    /// Format J2, `desc-{name}.txt`.
    DescriptorExport,
    /// Format J3, `bitcoin-core-{name}.txt`.
    DescriptorCore,
}

/// The Multisig screen: what is registered, and what can be done about it.
///
/// A registration decides which spends this device will sign, so it cannot be write-only.
/// A wallet imported from the wrong file has to be findable and removable, and the only
/// way to notice one is to be able to look.
///
/// The rows follow stock's Multisig Wallets menu: the wallets, then Import, Export XPUB,
/// Create Airgapped, the trust policy and the two switches.
/// Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §MS [C]
pub(crate) fn manage(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) {
    use catcard_ui::scroll::Line as Row;

    /// The action rows, numbered past any wallet.
    const IMPORT: u32 = 1000;
    const TRUST: u32 = 1001;
    const XPUB: u32 = 1002;
    const CREATE: u32 = 1003;
    const UNSORTED: u32 = 1004;
    const FULL_ADDR: u32 = 1005;

    /// What the list screen came back with. Nothing here borrows the settings buffer, so
    /// acting on it can read and write the settings again.
    enum Then {
        Leave,
        Import,
        Trust,
        ExportXpub,
        Create,
        Unsorted,
        FullAddr,
        Act(WalletAct, heapless::String<8>),
    }

    loop {
        menu::blocking_screen(ui.panel, "Multisig", "reading");
        // Scoped: the wallet records borrow the settings buffer, and acting on one reads
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

            // The policy line and the two switches, so a person can see at a glance
            // whether this device will sign a multisig it was never shown, and what it
            // will let through an import.
            let prefs = crate::prefs::current();
            let mut trust_row: heapless::String<40> = heapless::String::new();
            let mut unsorted_row: heapless::String<40> = heapless::String::new();
            let mut full_row: heapless::String<40> = heapless::String::new();
            {
                use core::fmt::Write as _;
                let _ = write!(trust_row, "Trust policy: {}", prefs.multisig_trust.label());
                let _ = write!(
                    unsorted_row,
                    "Unsorted Multisig? {}",
                    on_off(prefs.ms_unsorted)
                );
                let _ = write!(
                    full_row,
                    "Full Address View? {}",
                    on_off(prefs.ms_full_addr)
                );
            }

            let exit = {
                let mut rows: heapless::Vec<Row, { wallets::MAX_WALLETS + 8 }> =
                    heapless::Vec::new();
                let _ = rows.push(Row::title("Multisig"));
                if have == 0 {
                    let _ = rows.push(Row::body("(none registered)").centered());
                }
                for (i, l) in labels.iter().enumerate() {
                    let _ = rows.push(Row::item(l.as_str(), i as u32));
                }
                let _ = rows.push(Row::item("Import", IMPORT));
                let _ = rows.push(Row::item("Export XPUB", XPUB));
                let _ = rows.push(Row::item("Create Airgapped", CREATE));
                let _ = rows.push(Row::item(trust_row.as_str(), TRUST));
                let _ = rows.push(Row::item(unsorted_row.as_str(), UNSORTED));
                let _ = rows.push(Row::item(full_row.as_str(), FULL_ADDR));
                menu::show_doc(ui, &rows, false, false)
            };

            match exit {
                menu::DocExit::Selected(IMPORT) => Then::Import,
                menu::DocExit::Selected(TRUST) => Then::Trust,
                menu::DocExit::Selected(XPUB) => Then::ExportXpub,
                menu::DocExit::Selected(CREATE) => Then::Create,
                menu::DocExit::Selected(UNSORTED) => Then::Unsorted,
                menu::DocExit::Selected(FULL_ADDR) => Then::FullAddr,
                menu::DocExit::Selected(i) if (i as usize) < have => {
                    let w = &list[i as usize];
                    let mut sum: heapless::String<8> = heapless::String::new();
                    let _ = sum.push_str(w.checksum().unwrap_or(""));
                    match wallet_menu(ui, w) {
                        Some(act) if !sum.is_empty() => Then::Act(act, sum),
                        _ => continue,
                    }
                }
                _ => Then::Leave,
            }
        };

        match next {
            Then::Leave => return,
            Then::Import => import(gate, login, ui),
            Then::Trust => trust_policy_screen(gate, login, ui),
            Then::ExportXpub => export_xpubs(gate, login, ui),
            Then::Create => create_airgapped(gate, login, ui),
            Then::Unsorted => toggle(gate, login, ui, Switch::Unsorted),
            Then::FullAddr => toggle(gate, login, ui, Switch::FullAddr),
            Then::Act(WalletAct::Delete, sum) => match remove(gate, login, ui, &sum) {
                Ok(()) => say(ui, "Multisig", "the wallet is gone"),
                Err(why) => say(ui, "Multisig", why),
            },
            Then::Act(WalletAct::Rename, sum) => rename(gate, login, ui, &sum),
            Then::Act(act, sum) => export_registered(gate, login, ui, act, &sum),
        }
    }
}

fn on_off(on: bool) -> &'static str {
    if on { "on" } else { "off" }
}

/// The menu for one registered wallet: look at it, rename or delete it, or write it out.
///
/// Returns what to do once the settings buffer `w` borrows has been let go; viewing
/// happens here, since it needs nothing but the record. The Coldcard and Electrum exports
/// are offered for BIP-67 wallets only, as stock does: neither format can say "unsorted",
/// so writing one for such a wallet would hand the other cosigners a different wallet.
/// Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §MS "make_ms_wallet_menu" [C]
fn wallet_menu(ui: &mut Ui<'_>, w: &Wallet<'_>) -> Option<WalletAct> {
    let title = if w.name.is_empty() { "Wallet" } else { w.name };
    let sorted = multisig::parse(w.descriptor)
        .map(|m| m.sorted)
        .unwrap_or(false);
    let mut rows: heapless::Vec<&str, 6> = heapless::Vec::new();
    let mut acts: heapless::Vec<Option<WalletAct>, 6> = heapless::Vec::new();
    let _ = rows.push("View Details");
    let _ = acts.push(None);
    let _ = rows.push("Rename");
    let _ = acts.push(Some(WalletAct::Rename));
    let _ = rows.push("Delete");
    let _ = acts.push(Some(WalletAct::Delete));
    if sorted {
        let _ = rows.push("Coldcard Export");
        let _ = acts.push(Some(WalletAct::ExportColdcard));
        let _ = rows.push("Electrum Wallet");
        let _ = acts.push(Some(WalletAct::ExportElectrum));
    }
    let _ = rows.push("Descriptors");
    let _ = acts.push(None);

    loop {
        let chosen = menu::choose(ui, title, "", &rows)?;
        match (rows[chosen], acts[chosen]) {
            ("View Details", _) => detail(ui, w),
            ("Descriptors", _) => {
                const SUB: [&str; 3] = ["View Descriptor", "Export", "Bitcoin Core"];
                match menu::choose(ui, "Descriptors", title, &SUB) {
                    Some(0) => return Some(WalletAct::DescriptorView),
                    Some(1) => return Some(WalletAct::DescriptorExport),
                    Some(2) => return Some(WalletAct::DescriptorCore),
                    _ => {}
                }
            }
            (_, Some(WalletAct::Delete)) => {
                // Deleting is not destroying coins -- the wallet can be imported again --
                // but it does stop this device signing for it until that happens, so it
                // is asked once.
                menu::ask(
                    ui.panel,
                    "Delete wallet?",
                    "this device will refuse",
                    "its spends until re-imported",
                );
                if menu::confirmed(ui) {
                    return Some(WalletAct::Delete);
                }
            }
            (_, Some(act)) => return Some(act),
            (_, None) => {}
        }
    }
}

/// The trust policy screen: how far to trust a multisig wallet a PSBT describes but this
/// device has not registered.
///
/// The safe policy is the default and the first choice; the other two relax it, and
/// "Trust PSBT" -- which signs against keys the PSBT alone vouches for -- is asked twice,
/// because it is the one that will sign for a wallet nobody imported.
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
        menu::ask(ui.panel, HEAD, "trust wallet keys", "found inside a PSBT?");
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

/// The two on/off rows of the Multisig menu.
#[derive(Copy, Clone, PartialEq, Eq)]
enum Switch {
    /// "Unsorted Multisig?": whether a `multi` (non-BIP-67) wallet may be registered.
    Unsorted,
    /// "Full Address View?": whether the explorer shows a wallet's addresses whole.
    FullAddr,
}

/// Flip one of the switches, and say what it now is.
///
/// Turning unsorted wallets on gets a warning first, stock's: with BIP-67 off, the key
/// order in every backup and descriptor is part of the wallet, and one that loses it has
/// lost the addresses.
/// Source: hw-reference/help-and-warning-screens.md §10 "Non-BIP-67 unsorted multisig" [C]
fn toggle(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    which: Switch,
) {
    use catcard_settings::prefs::{MS_FULL_ADDR, MS_UNSORTED};

    let now = crate::prefs::current();
    let (head, key, on) = match which {
        Switch::Unsorted => ("Unsorted Multisig?", MS_UNSORTED, now.ms_unsorted),
        Switch::FullAddr => ("Full Address View?", MS_FULL_ADDR, now.ms_full_addr),
    };
    let Some(row) = menu::choose(
        ui,
        head,
        if on { "now on" } else { "now off" },
        &["Off", "On"],
    ) else {
        return;
    };
    let want = row == 1;
    if want == on {
        return;
    }
    if which == Switch::Unsorted && want {
        menu::ask(
            ui.panel,
            head,
            "key order is then part of",
            "the wallet: keep every backup",
        );
        if !menu::confirmed(ui) {
            return;
        }
    }
    let value = crate::prefs::quoted(if want { "1" } else { "0" });
    let next = match which {
        Switch::Unsorted => crate::prefs::Prefs {
            ms_unsorted: want,
            ..now
        },
        Switch::FullAddr => crate::prefs::Prefs {
            ms_full_addr: want,
            ..now
        },
    };
    if crate::prefs::save(gate, login, ui, head, (key, &value), next) {
        menu::message(ui.panel, head, "saved", on_off(want));
    } else {
        menu::message(ui.panel, head, "could not save", "nothing changed");
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

/// Show one registered wallet: its shape, and every cosigner's fingerprint, path and key.
///
/// The keys are what a person verifies out of band, so they are on the screen rather than
/// behind another row. Fifteen of them are about 1.7 KB of text, which comes from a leased
/// slot and not the stack.
fn detail(ui: &mut Ui<'_>, w: &Wallet<'_>) {
    use catcard_ui::scroll::Line as Row;
    use core::fmt::Write as _;

    type Text = heapless::String<48>;
    let title = if w.name.is_empty() { "Wallet" } else { w.name };
    let mut head = Text::new();
    let mut lines: heapless::Vec<Text, { multisig::MAX_COSIGNERS + 2 }> = heapless::Vec::new();
    let mut keys = crate::heap::take(SCRATCH);
    let mut key_at: heapless::Vec<(usize, usize), { multisig::MAX_COSIGNERS }> =
        heapless::Vec::new();

    let parsed = multisig::parse(w.descriptor);
    match &parsed {
        Ok(m) => {
            let _ = write!(
                head,
                "{}-of-{} {}{}",
                m.m,
                m.n(),
                kind_name(m.kind),
                if m.sorted { "" } else { ", unsorted" }
            );
            if !m.sorted {
                let mut warn = Text::new();
                let _ = write!(warn, "NOT BIP-67: key order matters");
                let _ = lines.push(warn);
            }
            let mut used = 0usize;
            for c in m.cosigners() {
                let mut line = Text::new();
                let [a, b, cc, d] = c.fingerprint;
                let _ = write!(line, "{a:02X}{b:02X}{cc:02X}{d:02X} ");
                let _ = multisig::coldcard::write_path(&mut line, c.origin());
                let _ = lines.push(line);
                // The key's text, into the leased slot, remembered as a range.
                if let Some(blk) = keys.as_mut()
                    && let Ok(n) = c.xpub.write_base58(&mut blk.bytes()[used..])
                {
                    let _ = key_at.push((used, used + n));
                    used += n;
                }
            }
        }
        Err(why) => {
            let _ = write!(head, "cannot read: {}", describe(*why));
        }
    }
    let mut sum = Text::new();
    let _ = write!(sum, "checksum {}", w.checksum().unwrap_or("none"));

    // The key text is borrowed from the slot, so the rows are built after everything that
    // writes into it.
    let key_text: &[u8] = keys.as_mut().map(|b| &*b.bytes()).unwrap_or(&[]);
    let mut rows: heapless::Vec<Row, { 2 * multisig::MAX_COSIGNERS + 6 }> = heapless::Vec::new();
    let _ = rows.push(Row::title(title));
    let _ = rows.push(Row::body(head.as_str()).small());
    let cosigner_lines = lines.len() - usize::from(parsed.as_ref().is_ok_and(|m| !m.sorted));
    for (i, l) in lines.iter().enumerate() {
        let _ = rows.push(Row::body(l.as_str()).small());
        // The warning line, if any, comes first and has no key.
        let key_index = i.checked_sub(lines.len() - cosigner_lines);
        if let Some((from, to)) = key_index.and_then(|k| key_at.get(k).copied())
            && let Ok(text) = core::str::from_utf8(&key_text[from..to])
        {
            let _ = rows.push(Row::body(text).small().wrapped());
        }
    }
    let _ = rows.push(Row::body(sum.as_str()).small());
    let _ = menu::show_doc(ui, &rows, false, false);
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

/// Rename the wallet whose checksum is `sum`: type the name, then store the list with it.
fn rename(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    sum: &str,
) {
    const HEAD: &str = "Rename";
    let Some(entry) = crate::passphrase::read(ui, "Wallet name") else {
        return;
    };
    let name = entry.as_str().trim();
    if name.is_empty() {
        return say(ui, HEAD, "a name cannot be empty");
    }
    menu::blocking_screen(ui.panel, HEAD, "saving");
    let (Some(mut doc), Some(mut list_blk), Some(mut seal)) = (
        crate::heap::take(SCRATCH),
        crate::heap::take(SCRATCH),
        crate::heap::take(SCRATCH),
    ) else {
        return say(ui, HEAD, "not enough memory");
    };
    let doc_buf = doc.bytes();
    let list_buf = list_blk.bytes();
    let stored = (|| -> Result<usize, &'static str> {
        let mut list = [Wallet {
            name: "",
            descriptor: "",
        }; wallets::MAX_WALLETS];
        let have = load(gate, login, ui.panel, doc_buf, &mut list)?;
        let mut next = [Wallet {
            name: "",
            descriptor: "",
        }; wallets::MAX_WALLETS];
        let n = wallets::renamed(&list[..have], sum, name, &mut next)
            .map_err(|_| "that name cannot be stored")?;
        wallets::render(&next[..n], list_buf).map_err(|_| "too long")
    })();
    let outcome = match stored {
        Ok(len) => store_list(gate, login, ui, doc_buf, &list_buf[..len], seal.bytes()),
        Err(why) => Err(why),
    };
    match outcome {
        Ok(()) => say(ui, HEAD, "renamed"),
        Err(why) => say(ui, HEAD, why),
    }
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

/// Import a wallet from a file: pick the storage and the file, read it, and hand the text
/// to [`from_text`].
pub(crate) fn import(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) {
    const HEAD: &str = "Import";
    let Some(storage) = menu::pick_storage(ui, HEAD) else {
        return;
    };
    let Some(path) =
        menu::browse_storage(ui, storage, "Pick a wallet file", None, menu::Browse::File)
    else {
        return;
    };

    // Leased rather than on the stack: four kilobytes for a file read once.
    let Some(mut file) = crate::heap::take(MAX_FILE) else {
        return say(ui, HEAD, "not enough memory");
    };
    menu::card_wait(ui.panel, HEAD, "reading");
    let len = match crate::signtx::read_source_file(storage, &path, file.bytes()) {
        Ok(n) => n,
        Err(why) => return say(ui, HEAD, why),
    };
    let Ok(text) = core::str::from_utf8(&file.bytes()[..len]) else {
        return say(ui, HEAD, "not text");
    };
    from_text(gate, login, ui, text);
}

/// Whether `text` holds a wallet this can register: a descriptor line, or a setup file.
///
/// For [`crate::sniff`], deciding what a scan or a tag brought. A descriptor is claimed
/// only if it parses whole, checksum included; a setup file on its shape alone, and the
/// import says what is wrong with it.
pub(crate) fn looks_like_config(text: &str) -> bool {
    text.lines()
        .any(|line| line.contains("multi(") && multisig::parse(line.trim()).is_ok())
        || multisig::coldcard::looks_like(text)
}

/// Register a wallet from text that arrived by any route: a file, a code, or a tag.
///
/// Two formats. An output descriptor -- one line, with a checksum, possibly among comment
/// and `Name:` lines as an exported one is -- or stock's setup file, which is turned into
/// the descriptor that is stored. Either way the review that follows is the same.
pub(crate) fn from_text(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    text: &str,
) {
    const HEAD: &str = "Import";
    match pick_descriptor(text) {
        Some(Ok((line, name))) => {
            let wallet = match multisig::parse(line) {
                Ok(w) => w,
                Err(why) => return say(ui, HEAD, describe(why)),
            };
            review_and_register(gate, login, ui, name, &wallet, line);
        }
        Some(Err(why)) => say(ui, HEAD, describe(why)),
        None => {
            if !multisig::coldcard::looks_like(text) {
                return say(ui, HEAD, "no wallet in that file");
            }
            let parsed = match multisig::coldcard::parse(text) {
                Ok(p) => p,
                Err(why) => return say(ui, HEAD, describe_text(why)),
            };
            // The setup file is not what is stored: the descriptor is, because it is
            // self-describing and carries a checksum the other formats lack.
            let Some(mut blk) = crate::heap::take(SCRATCH) else {
                return say(ui, HEAD, "not enough memory");
            };
            let n = match parsed.wallet.write_descriptor(blk.bytes()) {
                Ok(n) => n,
                Err(why) => return say(ui, HEAD, describe(why)),
            };
            let Ok(descriptor) = core::str::from_utf8(&blk.bytes()[..n]) else {
                return say(ui, HEAD, "not text");
            };
            review_and_register(gate, login, ui, parsed.name, &parsed.wallet, descriptor);
        }
    }
}

/// The descriptor line in a file, and a name if one was given.
///
/// An exported multisig file carries comments (`#`), a `Name:` line and the descriptor.
/// The descriptor is the first line that has a script function in it, wherever it sits;
/// `Some(Err)` is that line refusing to parse -- said as such, rather than falling through
/// to a reader for another format -- and `None` is a file with no descriptor at all.
fn pick_descriptor(text: &str) -> Option<Result<(&str, &str), multisig::Error>> {
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
        if found.is_none() && line.contains("multi(") {
            found = Some(multisig::parse(line).map(|_| line));
        }
    }
    found.map(|r| r.map(|line| (line, name)))
}

/// The review every import goes through, then the store.
///
/// In order: the unsorted rule, whose key is ours (proven, not claimed), the duplicate
/// check against what is registered, the screen the owner confirms, a name if the source
/// gave none, and the write.
fn review_and_register(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    name: &str,
    wallet: &Multisig,
    descriptor: &str,
) {
    const HEAD: &str = "Import";
    if !unsorted_allowed(ui, wallet) {
        return;
    }

    // The fingerprint of this device, to say which cosigner is us. Public, and this
    // session may already have paid for it -- registering several wallets in a row should
    // not mean stretching the seed once per wallet.
    let Some(ours_fp) = crate::pubkeys::fingerprint(gate, login, ui, HEAD) else {
        return;
    };

    // A fingerprint is a claim by whoever wrote the file, not a proof. Where one names this
    // device, derive our master along the claimed origin and require the key it reaches to
    // be the one the descriptor names. Only a claim costs the unlock.
    let ours = if wallet.cosigners().iter().any(|c| c.fingerprint == ours_fp) {
        let Some(found) = menu::unlock_master(gate, login, ui, HEAD).map(|master| {
            let found = crate::keywork::run(|kw| multisig::our_cosigner(wallet, &master, kw));
            drop(master);
            found
        }) else {
            return;
        };
        match found {
            Ok(found) => found,
            Err(why) => return say(ui, HEAD, describe(why)),
        }
    } else {
        None
    };

    // What is already registered, and whether this is one of them -- or nearly.
    match similar(gate, login, ui, name, wallet) {
        Verdict::Fresh => {}
        Verdict::Same(other) => {
            menu::message(ui.panel, HEAD, "already registered as", other.as_str());
            menu::wait_for_any_key(ui);
            return;
        }
        Verdict::Similar(other) => {
            // Stock: "resembles a stored wallet; will be added alongside, not replace it".
            // Source: hw-reference/help-and-warning-screens.md §10 "has_similar" [C]
            menu::ask(ui.panel, "Similar wallet", "resembles", other.as_str());
            if !menu::confirmed(ui) {
                return;
            }
            menu::ask(
                ui.panel,
                "Similar wallet",
                "it will be added beside it",
                "not replace it: add anyway?",
            );
            if !menu::confirmed(ui) {
                return;
            }
        }
    }

    if !confirm(ui, wallet, descriptor, ours) {
        return;
    }
    // A name, so the list and the export filenames can say which wallet this is. A file
    // that carried one keeps it; a bare descriptor gets asked, and an empty answer is the
    // wallet's shape.
    let mut typed: heapless::String<40> = heapless::String::new();
    let name = if name.is_empty() {
        let Some(entry) = crate::passphrase::read(ui, "Wallet name") else {
            return;
        };
        let _ = typed.push_str(entry.as_str().trim());
        if typed.is_empty() {
            use core::fmt::Write as _;
            let _ = write!(typed, "{}-of-{}", wallet.m, wallet.n());
        }
        typed.as_str()
    } else {
        name
    };
    match save(gate, login, ui, name, descriptor) {
        Ok(()) => say(ui, "Registered", "the wallet is stored"),
        Err(why) => say(ui, HEAD, why),
    }
}

/// Whether `wallet` may be registered under the unsorted rule, saying so if not.
///
/// `multi` -- keys in the descriptor's order rather than BIP-67's -- is refused unless
/// "Unsorted Multisig?" is on. Stock's rule, for stock's reason: a wallet whose key order
/// is part of its definition is one a backup can silently lose.
fn unsorted_allowed(ui: &mut Ui<'_>, wallet: &Multisig) -> bool {
    if wallet.sorted || crate::prefs::current().ms_unsorted {
        return true;
    }
    menu::message(
        ui.panel,
        "Unsorted wallet",
        "not BIP-67: refused while",
        "Unsorted Multisig? is off",
    );
    menu::wait_for_any_key(ui);
    false
}

/// How a wallet about to be imported stands to the registered ones.
enum Verdict {
    Fresh,
    /// Registered already, under this name.
    Same(heapless::String<40>),
    /// A near-duplicate of the wallet with this name: the same keys in another shape, or
    /// the same name over other keys.
    Similar(heapless::String<40>),
}

/// The duplicate check: every registered wallet, parsed and compared.
///
/// A store that cannot be read answers "fresh": the import goes on to the screen and the
/// store, which will say for itself if it cannot write. The check is a courtesy against
/// look-alikes, not a gate the safety of signing rests on.
fn similar(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    name: &str,
    wallet: &Multisig,
) -> Verdict {
    let Some(mut doc) = crate::heap::take(SCRATCH) else {
        return Verdict::Fresh;
    };
    let doc_buf = doc.bytes();
    let mut list = [Wallet {
        name: "",
        descriptor: "",
    }; wallets::MAX_WALLETS];
    let Ok(have) = load(gate, login, ui.panel, doc_buf, &mut list) else {
        return Verdict::Fresh;
    };
    let mut similar: Option<heapless::String<40>> = None;
    for w in &list[..have] {
        let other = || {
            let mut s: heapless::String<40> = heapless::String::new();
            let _ = s.push_str(if w.name.is_empty() {
                w.checksum().unwrap_or("?")
            } else {
                w.name
            });
            s
        };
        if let Ok(stored) = multisig::parse(w.descriptor) {
            match multisig::compare(&stored, wallet) {
                Likeness::Same => return Verdict::Same(other()),
                Likeness::Similar => similar.get_or_insert_with(other),
                Likeness::Different => continue,
            };
        }
        if !name.is_empty() && w.name == name {
            similar.get_or_insert_with(other);
        }
    }
    similar.map_or(Verdict::Fresh, Verdict::Similar)
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
        kind_name(wallet.kind),
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

// ---------------------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------------------

/// The registered wallet whose checksum is `sum`: parsed, with its name, and its stored
/// descriptor text copied into `text_out` (the length returned).
///
/// The settings are read into a leased slot that is given back before this returns; what
/// comes out is the wallet itself, which is a couple of kilobytes and lives on the caller's
/// stack for the length of one export. The text is kept as well because it is what the
/// owner imported and compared, and its checksum is the one the list shows.
fn fetch(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    sum: &str,
    text_out: &mut [u8],
) -> Result<(Multisig, heapless::String<40>, usize), &'static str> {
    let Some(mut doc) = crate::heap::take(SCRATCH) else {
        return Err("not enough memory");
    };
    let doc_buf = doc.bytes();
    let mut list = [Wallet {
        name: "",
        descriptor: "",
    }; wallets::MAX_WALLETS];
    let have = load(gate, login, ui.panel, doc_buf, &mut list)?;
    let w = list[..have]
        .iter()
        .find(|w| w.checksum() == Some(sum))
        .ok_or("no such wallet")?;
    let wallet = multisig::parse(w.descriptor).map_err(describe)?;
    let mut name: heapless::String<40> = heapless::String::new();
    let _ = name.push_str(w.name);
    let text = w.descriptor.as_bytes();
    text_out
        .get_mut(..text.len())
        .ok_or("too long")?
        .copy_from_slice(text);
    Ok((wallet, name, text.len()))
}

/// `{prefix}{name}.{ext}`, with the name made safe for a card: spaces to `_`, slashes to
/// `-`, anything a FAT name will not take dropped, and the checksum standing in for a
/// wallet that has no name. Cut so a collision number still fits.
/// Source: hw-reference/wallet-export-formats.md §"Multisig exports" (`make_fname`) [C]
fn export_name(
    prefix: &str,
    name: &str,
    sum: &str,
    ext: &str,
) -> heapless::String<{ menu::EXPORT_NAME_MAX }> {
    let mut out: heapless::String<{ menu::EXPORT_NAME_MAX }> = heapless::String::new();
    let _ = out.push_str(prefix);
    // Room for the extension's dot, the extension, and a `-NN` collision suffix.
    let room = menu::EXPORT_NAME_MAX.saturating_sub(out.len() + 1 + ext.len() + 3);
    let mut used = 0usize;
    for c in name.chars() {
        if used == room {
            break;
        }
        let c = match c {
            ' ' => '_',
            '/' => '-',
            c if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') => c,
            _ => continue,
        };
        let _ = out.push(c);
        used += 1;
    }
    if used == 0 {
        for c in sum.chars().take(room) {
            let _ = out.push(c);
        }
    }
    let _ = out.push('.');
    let _ = out.push_str(ext);
    out
}

/// Where an export's signature comes from: the cosigner path with `/0/0` below it, in the
/// classic address form. `None` if the path is too deep to describe, which leaves the
/// export unsigned rather than unwritten.
/// Source: hw-reference/wallet-export-formats.md §"Format J1" ("sign at der + /0/0") [C]
fn signing_below(origin: &[u32]) -> Option<crate::export::Signing> {
    let mut steps = heapless::Vec::new();
    for &step in origin {
        let child = if step & HARDENED_OFFSET != 0 {
            ChildNumber::hardened(step & !HARDENED_OFFSET).ok()?
        } else {
            ChildNumber::normal(step).ok()?
        };
        steps.push(child).ok()?;
    }
    steps.push(ChildNumber::normal(0).ok()?).ok()?;
    steps.push(ChildNumber::normal(0).ok()?).ok()?;
    Some(crate::export::Signing {
        steps,
        kind: catcard_wallet::address::AddressKind::P2pkh,
    })
}

/// Write a registered wallet out in one of stock's formats, or show its descriptor.
///
/// The file is signed when this device is a cosigner -- by fingerprint, which is what the
/// file names -- with the key at that cosigner's path, and left unsigned otherwise, as
/// stock does for an airgapped wallet it merely watches.
fn export_registered(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    act: WalletAct,
    sum: &str,
) {
    use catcard_bbqr::FileType;

    let (head, prefix, ext, filetype) = match act {
        WalletAct::ExportColdcard => ("Coldcard Export", "export-", "txt", FileType::UNICODE),
        WalletAct::ExportElectrum => ("Electrum Wallet", "el-", "json", FileType::JSON),
        WalletAct::DescriptorView => ("Descriptor", "", "", FileType::UNICODE),
        WalletAct::DescriptorExport => ("Descriptor", "desc-", "txt", FileType::UNICODE),
        WalletAct::DescriptorCore => ("Bitcoin Core", "bitcoin-core-", "txt", FileType::UNICODE),
        WalletAct::Rename | WalletAct::Delete => return,
    };
    let Some(mut out) = crate::heap::take(EXPORT_MAX) else {
        return say(ui, head, "not enough memory");
    };
    // The stored descriptor lands at the front of the export slot: it is the export
    // itself for the descriptor rows, and scratch the others write over.
    let (wallet, name, stored_len) = match fetch(gate, login, ui, sum, out.bytes()) {
        Ok(x) => x,
        Err(why) => return say(ui, head, why),
    };

    if act == WalletAct::DescriptorView {
        let text = core::str::from_utf8(&out.bytes()[..stored_len]).unwrap_or("");
        let mut rows: heapless::Vec<catcard_ui::scroll::Line, 3> = heapless::Vec::new();
        let _ = rows.push(catcard_ui::scroll::Line::title(if name.is_empty() {
            "Descriptor"
        } else {
            name.as_str()
        }));
        let _ = rows.push(catcard_ui::scroll::Line::body(text).small().wrapped());
        let _ = menu::show_doc(ui, &rows, false, false);
        return;
    }

    // Our fingerprint says whether to sign, and the Coldcard file names its writer.
    let Some(ours) = crate::pubkeys::fingerprint(gate, login, ui, head) else {
        return;
    };
    let member = wallet.cosigners().iter().find(|c| c.fingerprint == ours);

    let n = match act {
        WalletAct::ExportColdcard => {
            multisig::coldcard::write(name.as_str(), &wallet, ours, out.bytes())
        }
        WalletAct::ExportElectrum => multisig::export::electrum(&wallet, out.bytes()),
        // The text as imported, checksum and all; already in place.
        WalletAct::DescriptorExport => Ok(stored_len),
        WalletAct::DescriptorCore => multisig::export::bitcoin_core(&wallet, out.bytes()),
        _ => return,
    };
    let n = match n {
        Ok(n) => n,
        Err(why) => return say(ui, head, describe(why)),
    };

    // The key, only if there is a cosigner path to sign from -- taken last, so backing
    // out of anything above cost no unlock.
    let signer = match member {
        Some(c) => match menu::unlock_master(gate, login, ui, head) {
            Some(master) => menu::signer_for(master, signing_below(c.origin())),
            None => return,
        },
        None => None,
    };
    let file = export_name(prefix, name.as_str(), sum, ext);
    menu::offer_export(ui, head, &file, &out.bytes()[..n], filetype, signer);
}

/// The steps to this device's key for one script form: `m/45h` for BIP-45, or the BIP-48
/// leg `m/48h/{coin}h/{account}h/{1|2}h`.
fn leg_steps(kind: Kind, account: u32) -> Option<heapless::Vec<ChildNumber, 4>> {
    let coin = crate::prefs::network().coin_type();
    let mut steps = heapless::Vec::new();
    match kind {
        Kind::P2sh => steps.push(ChildNumber::hardened(45).ok()?).ok()?,
        Kind::P2wsh | Kind::P2shP2wsh => {
            let script = if kind == Kind::P2wsh { 2 } else { 1 };
            for s in [
                ChildNumber::hardened(48).ok()?,
                ChildNumber::hardened(coin).ok()?,
                ChildNumber::hardened(account).ok()?,
                ChildNumber::hardened(script).ok()?,
            ] {
                steps.push(s).ok()?;
            }
        }
    }
    Some(steps)
}

/// The same steps as raw origin indices, for a cosigner record.
fn origin_of(steps: &[ChildNumber]) -> ([u32; multisig::MAX_ORIGIN], usize) {
    let mut origin = [0u32; multisig::MAX_ORIGIN];
    let mut n = 0usize;
    for s in steps.iter().take(multisig::MAX_ORIGIN) {
        origin[n] = if s.is_hardened() {
            s.index() | HARDENED_OFFSET
        } else {
            s.index()
        };
        n += 1;
    }
    (origin, n)
}

/// Export XPUB: this device's keys for the three multisig legs, as `ccxp-{xfp}.json`, for
/// another Coldcard to build a wallet from.
///
/// Signed at the P2WSH leg's `/0/0`, as stock does. The BIP-45 key is included for account
/// zero only, since its path has no account level.
/// Source: hw-reference/wallet-export-formats.md §"Format L" [C]
fn export_xpubs(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) {
    const HEAD: &str = "Export XPUB";
    let Some(account) = menu::ask_number(ui, HEAD, None, "account", "empty is account 0") else {
        return;
    };
    let Some(master) = menu::unlock_master(gate, login, ui, HEAD) else {
        return;
    };
    let fingerprint = crate::keywork::run(|kw| master.fingerprint(kw));
    let mut busy = menu::Working::new(ui.panel, HEAD, "deriving keys");
    let derive = |kind: Kind, busy: &mut menu::Working<'_>, panel: &mut crate::display::Panel| {
        let steps = leg_steps(kind, account)?;
        menu::public_at(&master, &steps, busy, panel)
    };
    let p2sh = if account == 0 {
        match derive(Kind::P2sh, &mut busy, ui.panel) {
            Some(k) => Some(k),
            None => return say(ui, HEAD, "derivation failed"),
        }
    } else {
        None
    };
    let (Some(p2sh_p2wsh), Some(p2wsh)) = (
        derive(Kind::P2shP2wsh, &mut busy, ui.panel),
        derive(Kind::P2wsh, &mut busy, ui.panel),
    ) else {
        return say(ui, HEAD, "derivation failed");
    };

    let Some(mut out) = crate::heap::take(EXPORT_MAX) else {
        return say(ui, HEAD, "not enough memory");
    };
    let keys = multisig::export::OurKeys {
        fingerprint,
        account,
        coin: crate::prefs::network().coin_type(),
        p2sh: p2sh.as_ref(),
        p2sh_p2wsh: &p2sh_p2wsh,
        p2wsh: &p2wsh,
    };
    let n = match multisig::export::ccxp(&keys, out.bytes()) {
        Ok(n) => n,
        Err(why) => return say(ui, HEAD, describe(why)),
    };
    let signer = menu::signer_for(master, crate::export::Signing::cosigner(account));
    let [a, b, c, d] = fingerprint;
    let mut file: heapless::String<{ menu::EXPORT_NAME_MAX }> = heapless::String::new();
    {
        use core::fmt::Write as _;
        let _ = write!(file, "ccxp-{a:02X}{b:02X}{c:02X}{d:02X}.json");
    }
    menu::offer_export(
        ui,
        HEAD,
        &file,
        &out.bytes()[..n],
        catcard_bbqr::FileType::JSON,
        signer,
    );
}

/// Cosigner keys collected for [`create_airgapped`], as the key expressions of the
/// descriptor being built: `,[fp/path]xpub/0/*` each, in a leased slot.
///
/// Text rather than records because that is what the wallet is made from -- the finished
/// descriptor is parsed, checked and stored exactly as an imported one would be -- and
/// because fifteen cosigner records are two kilobytes better kept off the stack.
struct Keys<'a> {
    buf: &'a mut [u8],
    len: usize,
    count: usize,
}

impl Keys<'_> {
    /// Add one cosigner. Refuses a key already in the list, and a sixteenth.
    fn push(&mut self, c: &Cosigner) -> Result<(), &'static str> {
        use core::fmt::Write as _;
        if self.count + 1 >= multisig::MAX_COSIGNERS {
            return Err("no room for another cosigner");
        }
        let mut key = [0u8; catcard_wallet::bip32::serialize::MAX_BASE58_LEN];
        let n = c.xpub.write_base58(&mut key).map_err(|_| "bad key")?;
        let key = core::str::from_utf8(&key[..n]).map_err(|_| "bad key")?;
        let have = core::str::from_utf8(&self.buf[..self.len]).unwrap_or("");
        if have.contains(key) {
            return Err("that key is already in the list");
        }
        let mut w = Buf {
            out: &mut *self.buf,
            len: self.len,
        };
        let [a, b, cc, d] = c.fingerprint;
        write!(w, ",[{a:02x}{b:02x}{cc:02x}{d:02x}").map_err(|_| "too long")?;
        for &step in c.origin() {
            if step & HARDENED_OFFSET != 0 {
                write!(w, "/{}h", step & !HARDENED_OFFSET).map_err(|_| "too long")?;
            } else {
                write!(w, "/{step}").map_err(|_| "too long")?;
            }
        }
        write!(w, "]{key}/0/*").map_err(|_| "too long")?;
        self.len = w.len;
        self.count += 1;
        Ok(())
    }

    fn text(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

/// A `core::fmt::Write` over a byte slice, for building the descriptor.
struct Buf<'a> {
    out: &'a mut [u8],
    len: usize,
}

impl core::fmt::Write for Buf<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let end = self.len + s.len();
        self.out
            .get_mut(self.len..end)
            .ok_or(core::fmt::Error)?
            .copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// Create Airgapped: build a sorted multisig wallet from the other cosigners' `ccxp`
/// bundles and this device's own key, register it, and write the setup file the others
/// import.
///
/// The others' keys come from files on the card or the Virtual Disk and, on the Q1, from
/// their `ccxp` shown as a BBQr. This device's key is always in the wallet -- a wallet made
/// here without it would be a wallet made for someone else -- and is added last, so the
/// review marks it. More than fifteen cosigners is refused as the wallet is built up, and
/// a set that lacks our key cannot arise.
/// Source: hw-reference/help-and-warning-screens.md §10 "create_ms_step1" [C]
fn create_airgapped(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) {
    use core::fmt::Write as _;
    const HEAD: &str = "Create Airgapped";

    // Stock's step 1: the address format, P2WSH by default.
    const KINDS: [&str; 3] = ["P2WSH", "P2SH-P2WSH", "P2SH (BIP-45)"];
    let Some(k) = menu::choose(ui, HEAD, "address format", &KINDS) else {
        return;
    };
    let kind = [Kind::P2wsh, Kind::P2shP2wsh, Kind::P2sh][k];
    let account = if kind == Kind::P2sh {
        0
    } else {
        match menu::ask_number(ui, HEAD, None, "account", "empty is account 0") {
            Some(a) => a,
            None => return,
        }
    };

    let Some(mut keys_blk) = crate::heap::take(SCRATCH) else {
        return say(ui, HEAD, "not enough memory");
    };
    let mut keys = Keys {
        buf: keys_blk.bytes(),
        len: 0,
        count: 0,
    };
    loop {
        let mut note: heapless::String<32> = heapless::String::new();
        let _ = write!(note, "{} cosigner(s) added", keys.count);
        #[cfg(feature = "board-q1")]
        const WAYS: [&str; 3] = ["Add from a file", "Scan a BBQr", "Done adding"];
        #[cfg(not(feature = "board-q1"))]
        const WAYS: [&str; 2] = ["Add from a file", "Done adding"];
        let added = match menu::choose(ui, HEAD, &note, &WAYS) {
            Some(0) => add_from_file(ui, kind, &mut keys),
            #[cfg(feature = "board-q1")]
            Some(1) => add_from_scan(ui, kind, &mut keys),
            Some(_) => break,
            None => return,
        };
        match added {
            Ok(Some(fp)) => {
                let [a, b, c, d] = fp;
                let mut who: heapless::String<16> = heapless::String::new();
                let _ = write!(who, "{a:02X}{b:02X}{c:02X}{d:02X}");
                menu::message(ui.panel, HEAD, "added cosigner", &who);
                menu::wait_for_any_key(ui);
            }
            Ok(None) => {}
            Err(why) => say(ui, HEAD, why),
        }
    }
    if keys.count == 0 {
        return say(ui, HEAD, "no cosigner keys added");
    }

    // Our own key, last.
    let Some(master) = menu::unlock_master(gate, login, ui, HEAD) else {
        return;
    };
    let fingerprint = crate::keywork::run(|kw| master.fingerprint(kw));
    let Some(steps) = leg_steps(kind, account) else {
        return say(ui, HEAD, "bad account");
    };
    let mut busy = menu::Working::new(ui.panel, HEAD, "deriving our key");
    let Some(our_key) = menu::public_at(&master, &steps, &mut busy, ui.panel) else {
        return say(ui, HEAD, "derivation failed");
    };
    let (origin, origin_len) = origin_of(&steps);
    let ours = Cosigner {
        fingerprint,
        origin,
        origin_len,
        xpub: our_key,
    };
    if let Err(why) = keys.push(&ours) {
        // Our key already among the "others" is a file this device exported being fed
        // back to it.
        return say(ui, HEAD, why);
    }
    let total = keys.count;
    let our_index = total - 1;

    let mut of: heapless::String<16> = heapless::String::new();
    let _ = write!(of, "of {total}");
    let m = loop {
        let Some(m) = menu::ask_number(ui, HEAD, None, "M, signatures needed", &of) else {
            return;
        };
        if m >= 1 && m as usize <= total {
            break m as u8;
        }
        menu::message(
            ui.panel,
            HEAD,
            "M must be between",
            "1 and the cosigner count",
        );
        menu::wait_for_any_key(ui);
    };

    // The descriptor, checksummed, then read back through the same parser every import
    // uses: the wallet stored here is exactly what a later import of its own export gives.
    let Some(mut desc_blk) = crate::heap::take(SCRATCH) else {
        return say(ui, HEAD, "not enough memory");
    };
    let (open, close) = match kind {
        Kind::P2sh => ("sh(", ")"),
        Kind::P2wsh => ("wsh(", ")"),
        Kind::P2shP2wsh => ("sh(wsh(", "))"),
    };
    let mut w = Buf {
        out: desc_blk.bytes(),
        len: 0,
    };
    if write!(w, "{open}sortedmulti({m}{}){close}", keys.text()).is_err() {
        return say(ui, HEAD, "too long");
    }
    let body_len = w.len;
    let sum = core::str::from_utf8(&w.out[..body_len])
        .ok()
        .and_then(catcard_wallet::descriptor::checksum);
    let Some(sum) = sum else {
        return say(ui, HEAD, "could not checksum");
    };
    if w.write_char('#').is_err()
        || w.write_str(core::str::from_utf8(&sum).unwrap_or(""))
            .is_err()
    {
        return say(ui, HEAD, "too long");
    }
    let desc_len = w.len;
    // The collected key text is in the descriptor now; the slot it sat in goes back
    // (wiped) before the review, so the review's own scratch is not competing with it.
    let _ = keys;
    drop(keys_blk);
    let Ok(descriptor) = core::str::from_utf8(&desc_blk.bytes()[..desc_len]) else {
        return say(ui, HEAD, "not text");
    };
    let wallet = match multisig::parse(descriptor) {
        Ok(w) => w,
        Err(why) => return say(ui, HEAD, describe(why)),
    };

    if !confirm(ui, &wallet, descriptor, Some(our_index)) {
        return;
    }
    let mut name: heapless::String<40> = heapless::String::new();
    let Some(entry) = crate::passphrase::read(ui, "Wallet name") else {
        return;
    };
    let _ = name.push_str(entry.as_str().trim());
    if name.is_empty() {
        let _ = write!(name, "{m}-of-{total}");
    }
    if let Err(why) = save(gate, login, ui, name.as_str(), descriptor) {
        return say(ui, HEAD, why);
    }
    menu::message(
        ui.panel,
        "Registered",
        "now export the setup",
        "file for the others",
    );
    menu::wait_for_any_key(ui);

    // The setup file for the other cosigners, signed at our leg as stock does.
    let Some(mut out) = crate::heap::take(EXPORT_MAX) else {
        return say(ui, HEAD, "registered, but no memory to export");
    };
    let n = match multisig::coldcard::write(name.as_str(), &wallet, fingerprint, out.bytes()) {
        Ok(n) => n,
        Err(why) => return say(ui, HEAD, describe(why)),
    };
    let signer = menu::signer_for(master, signing_below(ours.origin()));
    let file = export_name(
        "export-",
        name.as_str(),
        descriptor.rsplit('#').next().unwrap_or(""),
        "txt",
    );
    menu::offer_export(
        ui,
        HEAD,
        &file,
        &out.bytes()[..n],
        catcard_bbqr::FileType::UNICODE,
        signer,
    );
}

/// One cosigner's `ccxp` file from the card or the Virtual Disk, into `keys`.
///
/// `Ok(Some(fingerprint))` for a key added, `Ok(None)` for a chooser backed out of.
fn add_from_file(
    ui: &mut Ui<'_>,
    kind: Kind,
    keys: &mut Keys<'_>,
) -> Result<Option<[u8; 4]>, &'static str> {
    const HEAD: &str = "Cosigner file";
    let Some(storage) = menu::pick_storage(ui, HEAD) else {
        return Ok(None);
    };
    let Some(path) = menu::browse_storage(
        ui,
        storage,
        "Pick ccxp-*.json",
        Some("json"),
        menu::Browse::File,
    ) else {
        return Ok(None);
    };
    let Some(mut file) = crate::heap::take(MAX_FILE) else {
        return Err("not enough memory");
    };
    menu::card_wait(ui.panel, HEAD, "reading");
    let len = crate::signtx::read_source_file(storage, &path, file.bytes())?;
    let text = core::str::from_utf8(&file.bytes()[..len]).map_err(|_| "not text")?;
    let cosigner = multisig::export::read_ccxp(text, kind).map_err(describe_ccxp)?;
    keys.push(&cosigner)?;
    Ok(Some(cosigner.fingerprint))
}

/// One cosigner's `ccxp` file shown as a BBQr (or a single code), scanned into `keys`.
#[cfg(feature = "board-q1")]
fn add_from_scan(
    ui: &mut Ui<'_>,
    kind: Kind,
    keys: &mut Keys<'_>,
) -> Result<Option<[u8; 4]>, &'static str> {
    const HEAD: &str = "Scan ccxp";
    let Some(mut file) = crate::heap::take(MAX_FILE) else {
        return Err("not enough memory");
    };
    let mut sink = HeapSink {
        buf: file.bytes(),
        len: 0,
    };
    let got = match crate::qrload::collect_any(ui, HEAD, &mut sink) {
        Ok(got) => got,
        Err(Some(why)) => return Err(why),
        Err(None) => return Ok(None),
    };
    if got.compressed {
        return Err("compressed codes are not read here");
    }
    let len = got.len.min(sink.len);
    let text = core::str::from_utf8(&file.bytes()[..len]).map_err(|_| "not text")?;
    let cosigner = multisig::export::read_ccxp(text, kind).map_err(describe_ccxp)?;
    keys.push(&cosigner)?;
    Ok(Some(cosigner.fingerprint))
}

/// A scan destination that is a leased heap block: for the small files this screen reads.
#[cfg(feature = "board-q1")]
struct HeapSink<'a> {
    buf: &'a mut [u8],
    len: usize,
}

#[cfg(feature = "board-q1")]
impl crate::qrload::Sink for HeapSink<'_> {
    fn expect(&mut self, about: usize) -> Result<(), &'static str> {
        if about > self.buf.len() {
            return Err("too large for a key file");
        }
        Ok(())
    }

    fn place(&mut self, offset: usize, bytes: &[u8]) -> Result<(), &'static str> {
        let end = offset.checked_add(bytes.len()).ok_or("bad offset")?;
        self.buf
            .get_mut(offset..end)
            .ok_or("too large for a key file")?
            .copy_from_slice(bytes);
        self.len = self.len.max(end);
        Ok(())
    }

    fn compressed(&mut self) -> Result<(), &'static str> {
        Err("compressed codes are not read here")
    }
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
        multisig::Error::FormMismatch { .. } => "a key's prefix names another script type",
        multisig::Error::Overflow => "too long",
    }
}

/// Why a setup file was refused.
fn describe_text(why: multisig::coldcard::TextError) -> &'static str {
    use multisig::coldcard::TextError as E;
    match why {
        E::BadPolicy => "no usable Policy: M of N line",
        E::BadFormat => "Format: is not P2SH, P2WSH or P2SH-P2WSH",
        E::BadDerivation => "a Derivation: line is not a path",
        E::NoDerivation => "a key has no Derivation: before it",
        E::BadKey { .. } => "a key line does not read",
        E::KeyCount { .. } => "the key count is not the policy's N",
        E::Wallet(e) => describe(e),
    }
}

/// Why a `ccxp` file gave no cosigner.
fn describe_ccxp(why: multisig::export::CcxpError) -> &'static str {
    use multisig::export::CcxpError as E;
    match why {
        E::NoFingerprint => "no xfp in that file",
        E::NoLeg => "no key for this format in it",
        E::BadDerivation => "its derivation is not a path",
        E::BadKey => "its key does not read",
    }
}

fn say(ui: &mut Ui<'_>, head: &str, what: &str) {
    menu::message(ui.panel, head, what, "any key to go back");
    menu::wait_for_any_key(ui);
}
