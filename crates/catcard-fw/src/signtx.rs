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
use catcard_wallet::psbtview::{self, Policy, Refusal};
use catcard_wallet::signer;
use outscript::psbt::Psbt;

use crate::display;
use crate::menu;
use crate::ui::Ui;

/// Where the signed PSBT is written back, and what the screen says it is called.
const SIGNED_NAME: &str = "/SIGNED.PSB";

/// Where a transaction that needs nothing further is written, as hex.
///
/// Hex rather than raw bytes because that is what a node or a block explorer takes to
/// broadcast: `bitcoin-cli sendrawtransaction <the file's contents>`.
const FINAL_NAME: &str = "/FINAL.TXN";

/// Most destinations shown. Beyond this the screen says how many more there are; the
/// summary's totals still cover every one of them.
const MAX_SHOWN: usize = 8;

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
        let card = match catcard_sd::init(&mut dev) {
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
fn lone_psbt() -> Option<heapless::String<{ PATH_MAX }>> {
    with_card(|vol| {
        let mut found: Option<heapless::String<PATH_MAX>> = None;
        let mut several = false;
        let _ = vol.enumerate("", |name, is_dir, _| {
            if is_dir || several {
                return;
            }
            let lower = name.trim();
            let is_psbt = lower.len() > 5
                && lower[lower.len() - 5..].eq_ignore_ascii_case(".psbt")
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
        Ok(found)
    })
    .ok()
    .flatten()
}

/// Longest path this screen carries.
const PATH_MAX: usize = 160;

/// Read the picked file into `buf`. Returns its length, or why not.
pub(crate) fn read_card_file(path: &str, buf: &mut [u8]) -> Result<usize, &'static str> {
    with_card(|vol| {
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
    })
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

/// Why the review stopped, in the few words a screen has.
fn refusal_text(r: Refusal) -> &'static str {
    match r {
        Refusal::NothingOfOurs => "no input is ours",
        Refusal::Sighash { .. } => "unsupported sighash",
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

    // Picked before the workspace is taken: browsing the card with the staging area held
    // would refuse a USB upload for as long as someone spent choosing a file.
    //
    // The card is the only source here. A transaction that arrives by camera comes in
    // through `Scan QR`, which reads first and offers afterwards -- it cannot know it is
    // being handed a PSBT until it has one, so asking in advance would be a second way
    // to do the same thing with a worse answer when the guess is wrong.
    let path = match lone_psbt() {
        // A card with one transaction on it needs no picker; two or more, and the owner
        // says which.
        Some(p) => p,
        None => {
            let Some(p) = menu::browse_sd(ui, "Pick a .psbt", Some("psbt"), menu::Browse::File)
            else {
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

    menu::card_wait(ui.panel, HEAD, "reading the card");
    let len = match read_card_file(&path, buf).and_then(|len| as_psbt_bytes(buf, len, spare)) {
        Ok(len) => len,
        Err(why) => {
            crate::catlog!("sign: {}: {}", path.as_str(), why);
            menu::message(ui.panel, HEAD, why, "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        }
    };
    crate::catlog!("sign: {} bytes from {}", len, path.as_str());

    review_and_sign(gate, login, ui, buf, spare, len);
}

/// Review a PSBT already sitting in `buf`, and sign it if the owner approves.
///
/// Split from [`sign_psbt`] because how the bytes arrived stops mattering here: a
/// transaction read off a card and one caught as a few hundred QR codes get the same
/// review, the same refusals and the same signatures. `spare` is the second working
/// buffer -- every signature rewrites the whole container, so the two alternate.
pub(crate) fn review_and_sign(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    buf: &mut [u8],
    spare: &mut [u8],
    len: usize,
) {
    const HEAD: &str = "Sign";

    let Some(master) = menu::unlock_master(gate, login, ui, HEAD) else {
        return;
    };
    let fingerprint = crate::keywork::run(|kw| master.fingerprint(kw));

    // The registered multisig wallets, read once. Without them a script-hash input is
    // refused: the chain says which script the coin is locked to, but only a registration
    // says whose wallet that script belongs to.
    #[cfg(not(feature = "board-mk3"))]
    let wallets = crate::msimport::registered(gate, login, ui.panel);
    // The mk3 has no settings store yet, so nothing can be registered on it and every
    // multisig input is refused. That is the safe direction, and the honest one: the
    // alternative is signing for a wallet this device was never shown.
    #[cfg(feature = "board-mk3")]
    let wallets: &[catcard_wallet::multisig::Multisig] = &[];
    let owner = psbtview::Owner {
        master: &master,
        fingerprint,
        wallets,
    };

    // The review. Every judgement here derives a key per input and per claimed change
    // output, so it runs masked, with the screen saying what it is doing.
    let mut busy = menu::Working::new(ui.panel, HEAD, "checking the transaction");
    let psbt = match Psbt::parse(&buf[..len]) {
        Ok(p) => p,
        Err(e) => {
            crate::catlog!("sign: psbt refused: {:?}", e);
            menu::message(ui.panel, HEAD, "not a valid PSBT", "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        }
    };
    // The fee cap the owner set, or the ten-percent default. `Policy` still does the
    // comparing: "no cap" is a limit no percentage can exceed rather than a check that
    // gets skipped, so there is no path through this that forgets to look at the fee.
    let policy = Policy {
        max_fee_percent: crate::prefs::current().fee_cap.percent_limit(),
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
    let mut shown = [psbtview::Destination {
        index: 0,
        amount: 0,
        change: false,
        address: [0; catcard_wallet::address::MAX_ADDRESS_LEN],
        address_len: 0,
    }; MAX_SHOWN];
    let count = crate::keywork::run(|kw| {
        psbtview::destinations(
            &psbt,
            &owner,
            catcard_wallet::bip32::Network::Mainnet,
            // The accounts the review already worked out from the inputs: an output is
            // change only if it belongs to one of them, and deriving them twice would be
            // twice the elliptic-curve work for the same answer.
            &summary.accounts[..summary.account_count],
            &mut shown,
            kw,
        )
    });
    let mut ours = [0usize; MAX_INPUTS];
    let signable =
        crate::keywork::run(|kw| psbtview::our_inputs(&psbt, &master, fingerprint, &mut ours, kw));

    if !review(ui, &summary, &shown[..count], signable) {
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
        match crate::keywork::run(|kw| {
            signer::sign_input(&psbt, index, &master, fingerprint, into, kw)
        }) {
            Ok(n) => {
                core::mem::swap(&mut from, &mut into);
                at = n;
                signed += 1;
            }
            Err(e) => {
                crate::catlog!("sign: input {} refused: {:?}", index, e);
            }
        }
        busy.tick(ui.panel);
    }
    drop(master);

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

    menu::card_wait(ui.panel, HEAD, "writing to the card");
    if let Err(why) = menu::write_card_file(SIGNED_NAME, &from[..at]) {
        crate::catlog!("sign: write failed: {}", why);
        menu::message(ui.panel, "Write failed", why, "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    }
    crate::catlog!("sign: {} of {} inputs, {} bytes", signed, signable, at);

    // If every input is now signed, the transaction can be finished here and the result is
    // ready to broadcast -- no other software needed. A transaction still waiting on a
    // cosigner simply does not finalise, which is not a failure.
    let mut note: heapless::String<24> = heapless::String::new();
    use core::fmt::Write as _;
    let _ = write!(note, "{signed} of {signable} inputs");
    match finalise(&from[..at], into) {
        Some(len) => {
            let hex_len = match write_hex_file(FINAL_NAME, &into[..len], from) {
                Ok(n) => n,
                Err(why) => {
                    crate::catlog!("sign: final tx not written: {}", why);
                    menu::message(ui.panel, "Signed", &SIGNED_NAME[1..], note.as_str());
                    menu::wait_for_any_key(ui);
                    return;
                }
            };
            crate::catlog!("sign: finalised, {} bytes of hex", hex_len);
            menu::message(ui.panel, "Signed", &FINAL_NAME[1..], "ready to broadcast");
            menu::wait_for_any_key(ui);
            // Nothing here has a network. What this offers is to put the transaction on
            // the NFC tag as a link, so a phone that taps the device can send it.
            #[cfg(not(feature = "board-mk3"))]
            crate::nfc::offer_broadcast(ui, &into[..len]);
            return;
        }
        None => {
            menu::message(ui.panel, "Signed", &SIGNED_NAME[1..], note.as_str());
        }
    }
    menu::wait_for_any_key(ui);
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

/// Write `bytes` as lower-case hex to `path`, using `scratch` for the text.
fn write_hex_file(path: &str, bytes: &[u8], scratch: &mut [u8]) -> Result<usize, &'static str> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let need = bytes.len() * 2;
    if need > scratch.len() {
        return Err("no room for the hex");
    }
    for (i, b) in bytes.iter().enumerate() {
        scratch[i * 2] = HEX[(b >> 4) as usize];
        scratch[i * 2 + 1] = HEX[(b & 0xF) as usize];
    }
    menu::write_card_file(path, &scratch[..need])?;
    Ok(need)
}

/// Show what signing would authorise, and ask. True if the owner confirmed.
///
/// The fee and the destinations are the point of the screen, so they are what it leads
/// with: how much leaves, to where, and what the miner takes.
fn review(
    ui: &mut Ui<'_>,
    summary: &psbtview::Summary,
    shown: &[psbtview::Destination],
    signable: usize,
) -> bool {
    use catcard_ui::scroll::{Line, ScrollView};
    use core::fmt::Write as _;

    /// Lines the review can hold: the totals, two per destination, the overflow note and
    /// the key hint.
    const LINES: usize = 4 + 2 * MAX_SHOWN;
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

    let mut amount = heapless::String::<AMOUNT_LEN>::new();
    btc(summary.sending, &mut amount);
    let mut line = Text::new();
    let _ = write!(line, "Sending {amount}");
    say(&mut texts, &mut small, &mut wrapped, line, false, false);

    let mut amount = heapless::String::<AMOUNT_LEN>::new();
    btc(summary.fee, &mut amount);
    let mut line = Text::new();
    let _ = write!(
        line,
        "Fee {amount} ({}%){}",
        summary.fee_percent,
        if summary.fee_warn { " HIGH" } else { "" }
    );
    say(&mut texts, &mut small, &mut wrapped, line, false, false);

    let mut line = Text::new();
    let _ = write!(line, "{} of {} inputs ours", signable, summary.inputs);
    say(&mut texts, &mut small, &mut wrapped, line, true, false);

    // An opted-in transaction is signed under the unified message, which only the chain
    // that implements that rule verifies. Said here because it is the one thing about this
    // transaction the owner cannot see from the amounts: everything else on this screen
    // reads the same either way.
    #[cfg(feature = "multichain")]
    if summary.opted_in {
        let mut line = Text::new();
        let _ = write!(line, "OPT-IN sighash: fork only");
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
            if d.address_len == 0 {
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
    }
    if summary.outputs > shown.len() {
        let mut line = Text::new();
        let _ = write!(line, "+{} more outputs", summary.outputs - shown.len());
        say(&mut texts, &mut small, &mut wrapped, line, true, false);
    }
    let mut line = Text::new();
    let _ = write!(
        line,
        "{} sign   {} cancel",
        display::CONFIRM_KEY,
        display::CANCEL_KEY
    );
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
