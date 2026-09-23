//! What a Solana transaction says, in the words a screen uses.
//!
//! The reading is [`catcard_solana`]; this is the firmware's side of it. For now that is
//! one line -- what the transaction mostly does, and how far through signing it is --
//! the same honest placeholder the EVM path carries in [`crate::evmtx`], until the
//! screen that lays the whole of it out and the signing behind it are built.

use catcard_callgate::Callgate;
use catcard_solana::{Action, Tx};
use core::fmt::Write as _;

/// One line for what a transaction does.
///
/// A Solana transaction is a list of instructions rather than one call, so there is no
/// single thing it "is". What gets named here is the first instruction that is about
/// value: a compute-budget setting is a price, not an act, and a transaction that led
/// with "sets a compute limit" would tell a person nothing about what they are signing.
/// The count that follows says how much else is in there.
fn what_it_does(tx: &Tx<'_>) -> &'static str {
    let mut fallback = "does nothing this build can name";
    for i in 0..tx.instruction_count() {
        let Some(action) = tx.action(i) else {
            continue;
        };
        match action {
            Action::TransferSol { .. } => return "sends SOL",
            Action::TransferToken { .. } => return "sends a token",
            Action::ApproveToken { .. } => return "approves spending",
            Action::CreateTokenAccount { .. } => return "opens a token account",
            // Neither of these is the point of a transaction, but an unnamed program is
            // worth saying if it turns out to be all there is.
            Action::ComputeBudget(_) => {}
            Action::Unknown { .. } => fallback = "calls a program this build cannot name",
        }
    }
    fallback
}

/// The line a review screen shows before anything else.
///
/// Three things, in the order they change a decision: what it does, how many
/// instructions that was one of, and whether somebody has already signed. The last
/// matters most -- a partly signed transaction is one this device is being asked to
/// join, not one it is starting.
///
pub(crate) fn headline(tx: &Tx<'_>, out: &mut heapless::String<80>) {
    let signing = tx.signing();
    let n = tx.instruction_count();
    let _ = write!(out, "{}", what_it_does(tx));
    if n > 1 {
        let _ = write!(out, ", 1 of {n} instructions");
    }
    if signing.present > 0 {
        let _ = write!(out, "; {} of {} signed", signing.present, signing.required);
    }
    // What a lookup table lends is named here rather than left out: those accounts are
    // fetched from the chain at execution and this device never sees them, so an
    // instruction touching one is an instruction it cannot fully read.
    let (w, r) = tx.lookups();
    if w + r > 0 {
        let _ = write!(out, "; {} accounts not shown", w + r);
    }
}

// ---------------------------------------------------------------------------
// Reading one out, line by line
// ---------------------------------------------------------------------------

/// How long a described line can be, and how many there can be.
///
/// A line holds `fee payer ` and a 44-character address with room to spare. The count is
/// a ceiling rather than a budget: a transaction that needs more than this is one this
/// device cannot show in full, and [`Lines::dropped`] is how that becomes a refusal
/// rather than a silence.
const LINE: usize = 64;
/// The most lines a description can run to. Heap, not stack -- 256 of these is sixteen
/// kilobytes, which is a heap block and would be most of a task's stack.
const MAX_LINES: usize = 256;

/// The description as it is built: the lines, and how many did not fit.
///
/// `dropped` is the point of the type. A screen that quietly stopped after twenty lines
/// would be asking somebody to sign a transaction whose tail it decided not to mention,
/// and that is the one failure a signing device must not have.
struct Lines {
    rows: alloc::vec::Vec<heapless::String<LINE>>,
    dropped: usize,
}

impl Lines {
    /// Room for a description, or `None` if the heap has nothing to spare.
    fn new() -> Option<Self> {
        let mut rows = alloc::vec::Vec::new();
        rows.try_reserve_exact(MAX_LINES).ok()?;
        Some(Lines { rows, dropped: 0 })
    }

    /// Add a line, or count it as one that did not fit.
    fn say(&mut self, args: core::fmt::Arguments<'_>) {
        if self.rows.len() == self.rows.capacity() {
            self.dropped += 1;
            return;
        }
        let mut s: heapless::String<LINE> = heapless::String::new();
        // A line too long for the buffer is truncated by `write_fmt`, which would hide
        // the tail of an address. Counted as dropped so the screen refuses rather than
        // showing half a key.
        if s.write_fmt(args).is_err() {
            self.dropped += 1;
            return;
        }
        self.rows.push(s);
    }
}

/// A lamport or token amount as people write it.
///
/// The formatter is [`catcard_evm::summary::decimal`], which takes a 256-bit number: a
/// Solana amount is 64 bits, so it goes in the bottom of one. Shared rather than written
/// twice because the awkward parts -- trimming trailing zeros, a value below one -- are
/// the same awkward parts, and they are already tested there.
fn amount(raw: u64, decimals: u8, out: &mut [u8; catcard_evm::summary::DECIMAL_MAX]) -> &str {
    let mut wide = [0u8; 32];
    wide[24..].copy_from_slice(&raw.to_be_bytes());
    catcard_evm::summary::decimal(&wide, decimals, out)
}

/// Lamports, written in SOL.
fn sol(lamports: u64, out: &mut [u8; catcard_evm::summary::DECIMAL_MAX]) -> &str {
    amount(
        lamports,
        catcard_solana::LAMPORTS_PER_SOL.ilog10() as u8,
        out,
    )
}

/// Describe the whole transaction into `lines`: who pays, what it costs, who must sign,
/// and every instruction in order.
///
/// **An address is never replaced by a name.** A mint this build knows is written as its
/// ticker *and* its address, because the table is a claim about which address that
/// ticker belongs to, and the address is the part the chain agrees with.
fn describe(tx: &catcard_solana::Tx<'_>, lines: &mut Lines) {
    use catcard_solana::{ADDRESS_MAX, Action, Budget, address};

    let mut addr = [0u8; ADDRESS_MAX];
    let mut num = [0u8; catcard_evm::summary::DECIMAL_MAX];

    // Who pays, and how much. The fee payer is account zero and pays whatever the
    // budget below says, so both belong above the instructions rather than after them.
    if let Some(payer) = tx.fee_payer() {
        lines.say(format_args!("fee payer {}", address(&payer, &mut addr)));
    }
    let fee = tx.fee();
    match (fee.priority, fee.priority_unknown) {
        (_, true) => {
            lines.say(format_args!(
                "fee {} SOL plus a priority",
                sol(fee.base, &mut num)
            ));
            lines.say(format_args!("this device cannot work out"));
        }
        (Some(0), _) => lines.say(format_args!("fee {} SOL", sol(fee.base, &mut num))),
        (Some(p), _) => {
            lines.say(format_args!(
                "fee up to {} SOL",
                sol(fee.base.saturating_add(p), &mut num)
            ));
        }
        (None, _) => {}
    }

    // Who must sign. One signer is the ordinary case and is the fee payer already named;
    // more than one means this transaction is not finished by this device alone.
    let signing = tx.signing();
    if signing.required > 1 {
        lines.say(format_args!("{} signatures needed", signing.required));
        for i in 0..signing.required {
            if let Some(k) = tx.key(i) {
                let mark = if tx.signed(i) { "signed" } else { "waiting" };
                lines.say(format_args!("{mark} {}", address(&k, &mut addr)));
            }
        }
    }

    for i in 0..tx.instruction_count() {
        let Some(action) = tx.action(i) else { continue };
        match action {
            Action::TransferSol { to, lamports, .. } => {
                lines.say(format_args!("send {} SOL", sol(lamports, &mut num)));
                if let Some(to) = to {
                    lines.say(format_args!("to {}", address(&to, &mut addr)));
                }
            }
            Action::TransferToken {
                to,
                amount: raw,
                decimals,
                mint,
                named,
                ..
            } => {
                // Scaled only where the instruction itself carried the decimals, or the
                // mint is one this build knows. An unchecked transfer of an unknown mint
                // gives a raw number, and saying so beats scaling it by a guess.
                match (decimals.or(named.map(|m| m.decimals)), named) {
                    (Some(d), Some(m)) => {
                        let n = amount(raw, d, &mut num);
                        lines.say(format_args!("send {n} {}", m.symbol));
                    }
                    (Some(d), None) => {
                        let n = amount(raw, d, &mut num);
                        lines.say(format_args!("send {n} of a token"));
                    }
                    _ => lines.say(format_args!("send {raw} raw units")),
                }
                if let Some(mint) = mint {
                    lines.say(format_args!("mint {}", address(&mint, &mut addr)));
                }
                if let Some(to) = to {
                    lines.say(format_args!("to {}", address(&to, &mut addr)));
                }
                if action.decimals_disagree() {
                    lines.say(format_args!("!! decimals disagree with this build"));
                }
            }
            Action::ApproveToken {
                delegate,
                amount: raw,
                ..
            } => {
                lines.say(format_args!("approve {raw} raw units"));
                if let Some(d) = delegate {
                    lines.say(format_args!("to {}", address(&d, &mut addr)));
                }
            }
            Action::CreateTokenAccount { mint, .. } => {
                lines.say(format_args!("open a token account"));
                if let Some(mint) = mint {
                    lines.say(format_args!("for {}", address(&mint, &mut addr)));
                }
            }
            // The numbers, not the word. These two decide the priority fee, and a
            // transaction can ask its payer for an arbitrary amount through them.
            Action::ComputeBudget(Budget::Limit { units }) => {
                lines.say(format_args!("compute limit {units} units"));
            }
            Action::ComputeBudget(Budget::Price { micro_lamports }) => {
                lines.say(format_args!("price {micro_lamports} micro-lamports a unit"));
            }
            Action::ComputeBudget(Budget::Heap { bytes }) => {
                lines.say(format_args!("heap {bytes} bytes"));
            }
            Action::ComputeBudget(Budget::DataSize { bytes }) => {
                lines.say(format_args!("account data limit {bytes} bytes"));
            }
            Action::ComputeBudget(Budget::Other) => {
                lines.say(format_args!("a compute budget setting, not decoded"));
            }
            Action::Unknown {
                program,
                accounts,
                data_len,
            } => {
                lines.say(format_args!("call {}", address(&program, &mut addr)));
                lines.say(format_args!(
                    "{accounts} accounts, {data_len} bytes -- not decoded"
                ));
            }
        }
    }

    let (w, r) = tx.lookups();
    if w + r > 0 {
        lines.say(format_args!("{} accounts come from tables", w + r));
        lines.say(format_args!("and are not shown here"));
    }
}

// ---------------------------------------------------------------------------
// Signing one
// ---------------------------------------------------------------------------

/// What is tried without being asked: **account zero, and nothing else.**
///
/// A transaction arriving bare names no path. It names the *public key* that must sign,
/// so finding which of this device's keys that is means deriving them and comparing --
/// and any number of accounts past the first is a guess about how somebody organises
/// their wallet.
///
/// Zero is the one worth guessing. It is what every wallet opens with and what almost
/// every transaction will want. Past it, a sweep would be this device inventing a range
/// nobody gave it, spending a seed stretch on each miss and still stopping short of the
/// account somebody actually keeps -- so past it, the owner says which, which they know
/// and this device cannot.
/// The two shapes a Solana path is written in.
///
/// `m/44'/501'/i'/0'` is Phantom's and Solflare's; `m/44'/501'/i'` is what Ledger and
/// older Solflare produce, and they give different keys for the same account number.
/// Both are tried, in that order, because a device that only knew one would tell half
/// its users it does not hold their key. [C] SLIP-0044 coin 501; the two conventions are
/// the ones those wallets ship.
const SHAPES: usize = 2;

/// Solana's coin type, from SLIP-0044. [C]
const COIN: u32 = 501;

/// Which of this device's keys to try.
#[derive(Copy, Clone)]
enum Which {
    /// Account zero, in both shapes. What a bare transaction gets, because a bare
    /// transaction names a public key and nothing else.
    Zero,
    /// One account number, in both shapes: the one the owner picked or typed after zero
    /// turned out not to be theirs.
    Account(u32),
    /// Exactly this path. What a `sol-sign-request` names, where there is nothing to
    /// search for and guessing would answer a question nobody asked.
    Path([u32; 4]),
}

/// The slot this device can fill, and the signature for it.
///
/// `Ok(None)` is the ordinary answer to "not ours": a transaction can perfectly well ask
/// for signatures this device does not have, and that is a sentence rather than an
/// error.
fn sign_it(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut crate::ui::Ui<'_>,
    tx: &catcard_solana::Tx<'_>,
    which: Which,
) -> Result<Option<(usize, [u8; 64])>, &'static str> {
    if let Which::Path(path) = which {
        // A request that named a key. Nothing to search: that path, or nothing.
        let message = tx.message();
        return crate::menu::with_seed(gate, login, ui.panel, HEAD, |seed, kw| {
            let node = catcard_wallet::slip10::derive(seed, &path, kw)?;
            let public = node.public_key(kw);
            let found = tx.signer_index(&public).map(|slot| {
                (
                    slot,
                    outscript::crypto::ed25519::sign(node.secret(), message),
                )
            });
            Some(found)
        });
    }
    let message = tx.message();
    // One account, two shapes, one seed stretch. Every account tried after the first is
    // another stretch -- a second of hashing -- which is the price of asking rather than
    // sweeping, and the reason the question is a list and a field rather than a walk.
    let account = match which {
        Which::Account(n) => n,
        _ => 0,
    };
    crate::menu::with_seed(gate, login, ui.panel, HEAD, |seed, kw| {
        // Both path shapes for the one account, and it stops at the first that fits.
        //
        // An earlier version derived every candidate whatever happened, on the grounds
        // that how long the masked region lasts is something a host can measure. That
        // reasoning does not survive contact with what is actually secret here: the key
        // being asked for is written in the transaction the asker sent, so a duration
        // that varies with which shape holds it tells them something they could have
        // worked out anyway. What the masking is really for -- the seed, and everything
        // derived from it -- is unchanged.
        let mut found = None;
        for shape in 0..SHAPES {
            let path: &[u32] = match shape {
                0 => &[44, COIN, account, 0],
                _ => &[44, COIN, account],
            };
            let Some(node) = catcard_wallet::slip10::derive(seed, path, kw) else {
                continue;
            };
            let public = node.public_key(kw);
            // A slot already filled is not signed again: the same signature would go
            // back in, and a second pass over a transaction is there to add somebody
            // else's key, not to redo this one's.
            if let Some(slot) = tx.signer_index(&public).filter(|&slot| !tx.signed(slot)) {
                found = Some((
                    slot,
                    outscript::crypto::ed25519::sign(node.secret(), message),
                ));
                break;
            }
        }
        Some(found)
    })
}

// ---------------------------------------------------------------------------
// Handing the result back
// ---------------------------------------------------------------------------

/// What to do with a signature, until the owner is done with it.
///
/// Two ways out, because two kinds of asker. A wallet that sent a `sol-sign-request`
/// wants the signature alone -- it still has the transaction, and sixty-four bytes fit
/// one QR code, which a kilobyte of transaction never would. A phone that is going to
/// *send* the transaction wants the whole thing, which is the tap.
#[cfg_attr(not(feature = "board-q1"), allow(unused_variables))]
fn hand_back(
    ui: &mut crate::ui::Ui<'_>,
    transaction: &[u8],
    signature: &[u8; 64],
    request_id: Option<&[u8]>,
) -> bool {
    let missing = catcard_solana::parse(transaction)
        .map(|t| t.signing().missing())
        .unwrap_or(0);
    let note: &str = if missing == 0 {
        "signed and complete"
    } else {
        "signed, others still to go"
    };
    loop {
        // The QR is a Q1 row. Not because the other boards cannot draw one, but because
        // the only asker who wants a bare signature is one that sent a sign request, and
        // a sign request arrives by camera -- which is the board that has one.
        let mut rows: heapless::Vec<&str, 4> = heapless::Vec::new();
        #[cfg(feature = "board-q1")]
        let _ = rows.push("Signature as QR");
        let _ = rows.push("Tap a phone");
        // Only where somebody else still has to sign, and only because that somebody
        // might be this device under another account.
        if missing > 0 {
            let _ = rows.push("Sign with another account");
        }
        let _ = rows.push("Done");
        let Some(chosen) = crate::menu::choose(ui, HEAD, note, &rows) else {
            return false;
        };
        match rows[chosen] {
            #[cfg(feature = "board-q1")]
            "Signature as QR" => signature_qr(ui, signature, request_id),
            "Tap a phone" => crate::nfc::offer_solana_link(ui, transaction, missing),
            "Sign with another account" => return true,
            _ => return false,
        }
    }
}

/// Show the signature as `ur:sol-signature`.
///
/// One static code: the answer is a signature and the handle it answers, which is under
/// a hundred bytes however long the transaction was.
#[cfg(feature = "board-q1")]
fn signature_qr(ui: &mut crate::ui::Ui<'_>, signature: &[u8; 64], request_id: Option<&[u8]>) {
    use catcard_bcur::registry::{Kind, solsign};

    // Sized for the largest answer: a signature and a sixteen-byte UUID.
    let mut out = [0u8; solsign::signature_len(16)];
    let Ok(n) = solsign::encode_signature(signature, request_id, &mut out) else {
        crate::menu::message(ui.panel, HEAD, "could not encode", "any key to go back");
        crate::menu::wait_for_any_key(ui);
        return;
    };
    crate::qrshow::animate_bcur(ui, HEAD, Kind::SolSignature.written_as(), &out[..n]);
}

// ---------------------------------------------------------------------------
// The screens
// ---------------------------------------------------------------------------

/// The head every screen in this file uses.
const HEAD: &str = "Solana";

/// Read a transaction out, offer to sign it, and hand the result back.
///
/// `bytes` is a transaction or the message inside one -- both arrive in the wild, and
/// which it is is decided by parsing rather than by who sent it. `path` is the key the
/// asker named, when one did; `request_id` is its handle for the question, echoed into
/// the answer.
fn review_and_sign(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut crate::ui::Ui<'_>,
    bytes: &[u8],
    request_id: Option<&[u8]>,
    path: Option<[u32; 4]>,
) {
    use catcard_ui::scroll::Line;

    // A transaction first, then a message: the transaction reading is the stricter one,
    // and a message that happened to parse as a transaction would be reported with
    // signatures it does not have.
    let tx = match catcard_solana::parse(bytes).or_else(|_| catcard_solana::parse_message(bytes)) {
        Ok(tx) => tx,
        Err(why) => {
            crate::menu::message(ui.panel, HEAD, why.why(), "any key to go back");
            crate::menu::wait_for_any_key(ui);
            return;
        }
    };

    let Some(mut lines) = Lines::new() else {
        crate::menu::message(ui.panel, HEAD, "not enough memory", "any key to go back");
        crate::menu::wait_for_any_key(ui);
        return;
    };
    describe(&tx, &mut lines);
    let mut said: heapless::String<80> = heapless::String::new();
    headline(&tx, &mut said);

    // **Nothing is signed that was not shown.** A description that did not fit is a
    // transaction this device cannot put in front of somebody, and the honest answer is
    // to say so rather than to offer a signature over a tail nobody read.
    let shown_in_full = lines.dropped == 0;
    let mut rows: alloc::vec::Vec<Line<'_>> = alloc::vec::Vec::new();
    if rows.try_reserve_exact(lines.rows.len() + 4).is_err() {
        crate::menu::message(ui.panel, HEAD, "not enough memory", "any key to go back");
        crate::menu::wait_for_any_key(ui);
        return;
    }
    rows.push(Line::title("Solana transaction"));
    rows.push(Line::body(&said).small());
    for line in &lines.rows {
        rows.push(Line::body(line).small());
    }
    let mut complaint: heapless::String<64> = heapless::String::new();
    if shown_in_full {
        rows.push(Line::item("Sign it", 1));
    } else {
        let _ = write!(
            complaint,
            "{} more lines than this screen holds",
            lines.dropped
        );
        rows.push(Line::body(&complaint).small());
        rows.push(Line::body("not signed: it cannot all be shown").small());
    }

    if !matches!(
        crate::menu::show_doc(ui, &rows, false, false),
        crate::menu::DocExit::Selected(1)
    ) {
        return;
    }

    // The buffer everything from here works on: what arrived, if a transaction arrived,
    // and the message with its empty slots in front if one did not. Signatures are
    // placed into it, so it is also what a second one is added to.
    let Some(mut block) = crate::heap::take(catcard_solana::link::PACKET_MAX) else {
        crate::menu::message(ui.panel, HEAD, "not enough memory", "any key to go back");
        crate::menu::wait_for_any_key(ui);
        return;
    };
    let Some(n) = tx.to_transaction(block.bytes()) else {
        crate::menu::message(ui.panel, HEAD, "too big to send", "any key to go back");
        crate::menu::wait_for_any_key(ui);
        return;
    };

    // Account zero first, then the owner says. A wallet kept at another account number
    // is an ordinary thing to have, and the only place that number exists is in the head
    // of the person holding the device.
    //
    // A request that named a path is not asked about. It said which key it wants, and
    // the answer to "that key is not here" is not "try another one" -- it is that the
    // asker and this device disagree about whose signature this is.
    let mut which = path.map_or(Which::Zero, Which::Path);
    loop {
        // Parsed afresh each time round, so a second signature is looked for against the
        // slots as they now stand: whichever key filled one is not offered it again.
        let outcome = {
            let Ok(current) = catcard_solana::parse(&block.bytes()[..n]) else {
                crate::menu::message(ui.panel, HEAD, "it stopped parsing", "any key to go back");
                crate::menu::wait_for_any_key(ui);
                return;
            };
            sign_it(gate, login, ui, &current, which)
        };
        let (slot, signature) = match outcome {
            Ok(Some(found)) => found,
            Ok(None) => {
                // Name a key it is still waiting on. "Not ours" on its own leaves a
                // person guessing between a wrong device, a wrong account and a wrong
                // passphrase; the address says which, because they can compare it to one
                // this device shows.
                let mut wanted: heapless::String<64> = heapless::String::new();
                let mut addr = [0u8; catcard_solana::ADDRESS_MAX];
                match catcard_solana::parse(&block.bytes()[..n])
                    .ok()
                    .and_then(|t| {
                        (0..t.signing().required)
                            .find(|&i| !t.signed(i))
                            .map(|i| (t, i))
                    })
                    .and_then(|(t, i)| t.key(i))
                {
                    Some(k) => {
                        let _ = write!(
                            wanted,
                            "it wants {}",
                            catcard_solana::address(&k, &mut addr)
                        );
                    }
                    None => {
                        let _ = wanted.push_str("any key to go back");
                    }
                }
                crate::menu::message(ui.panel, HEAD, "no key of this device signs it", &wanted);
                crate::menu::wait_for_any_key(ui);
                if path.is_some() {
                    return;
                }
                // The next few by name, and any of them by number. Most people who
                // have a second account have exactly that -- a second one -- and typing
                // is there because the number somebody knows may be 37, and nudging an
                // arrow thirty-seven times is not a design.
                const PICK: [&str; 8] = [
                    "Account 1",
                    "Account 2",
                    "Account 3",
                    "Account 4",
                    "Account 5",
                    "Account 6",
                    "Account 7",
                    "Type a number",
                ];
                let Some(chosen) = crate::menu::choose(ui, HEAD, "try another account", &PICK)
                else {
                    return;
                };
                which = if chosen + 1 < PICK.len() {
                    Which::Account(chosen as u32 + 1)
                } else {
                    let Some(typed) =
                        crate::menu::ask_number(ui, HEAD, None, "account", "digits, then accept")
                    else {
                        return;
                    };
                    Which::Account(typed)
                };
                continue;
            }
            Err(why) => {
                crate::menu::message(ui.panel, HEAD, why, "any key to go back");
                crate::menu::wait_for_any_key(ui);
                return;
            }
        };

        if !catcard_solana::place_signature(&mut block.bytes()[..n], slot, &signature) {
            crate::menu::message(ui.panel, HEAD, "no slot for it", "any key to go back");
            crate::menu::wait_for_any_key(ui);
            return;
        }
        crate::catlog!("solana: signed slot {} of {} bytes", slot, n);

        let (transaction, _) = block.bytes().split_at(n);
        if !hand_back(ui, transaction, &signature, request_id) {
            return;
        }
        // Another key of this device's, for a transaction that needs more than one. The
        // search starts at zero again and skips whatever is already filled.
        which = Which::Zero;
    }
}

/// A transaction that arrived on its own: scanned, or read off the tag.
///
/// `base64` says where it is inside `payload` when it arrived written down -- a broadcast
/// link, or the base64 a wallet's "copy transaction" gives -- and `None` when the payload
/// is the transaction itself.
pub(crate) fn screen(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut crate::ui::Ui<'_>,
    payload: &[u8],
    base64: Option<(usize, usize)>,
) {
    use catcard_solana::link;

    // Decoded into a block of its own when it arrived as text, borrowed from the payload
    // when it did not, so `raw` means the same thing to everything below.
    let mut block;
    let raw: &[u8] = match base64 {
        None => payload,
        Some((at, len)) => {
            let Some(text) = payload
                .get(at..at + len)
                .and_then(|b| core::str::from_utf8(b).ok())
            else {
                return;
            };
            let Some(got) = crate::heap::take(link::PACKET_MAX) else {
                crate::menu::message(ui.panel, HEAD, "not enough memory", "any key to go back");
                crate::menu::wait_for_any_key(ui);
                return;
            };
            block = got;
            let Ok(n) = outscript::base64::decode_to_slice(text, block.bytes()) else {
                return;
            };
            &block.bytes()[..n]
        }
    };
    review_and_sign(gate, login, ui, raw, None, None);
}

/// A `sol-sign-request`: a wallet asking this device for one signature.
///
/// Unlike a bare transaction, this says which key it wants. That is honoured rather than
/// searched for, and checked against the address the request claims for it -- if the key
/// at that path is not the key the asker expects, one of the two sides is wrong about
/// whose signature this is, and signing anyway would produce something neither of them
/// can use.
///
/// Q1 only: a sign request arrives by camera, and that is the board with one.
#[cfg(feature = "board-q1")]
pub(crate) fn sign_request(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut crate::ui::Ui<'_>,
    message: &[u8],
) {
    use catcard_bcur::registry::hdkey::Component;
    use catcard_bcur::registry::solsign::{self, SignType};

    let Ok(req) = solsign::decode(message) else {
        crate::menu::message(ui.panel, HEAD, "not a sign request", "any key to go back");
        crate::menu::wait_for_any_key(ui);
        return;
    };
    if req.sign_type != SignType::Transaction {
        crate::menu::message(
            ui.panel,
            HEAD,
            "this build signs transactions only",
            "any key to go back",
        );
        crate::menu::wait_for_any_key(ui);
        return;
    }

    // Four hardened steps, which is what every Solana wallet asks for. A path of another
    // shape is refused rather than bent into one: signing under a path nobody meant is
    // how a signature ends up on the wrong account.
    let mut path = [0u32; 4];
    let mut steps = 0;
    for c in &req.path.components {
        match *c {
            Component::Index {
                index,
                hardened: true,
            } if steps < 4 => {
                path[steps] = index;
                steps += 1;
            }
            _ => {
                steps = 0;
                break;
            }
        }
    }
    if steps != 4 || path[0] != 44 || path[1] != COIN {
        crate::menu::message(
            ui.panel,
            HEAD,
            "a derivation path this build will not use",
            "any key to go back",
        );
        crate::menu::wait_for_any_key(ui);
        return;
    }

    review_and_sign(gate, login, ui, req.sign_data, req.request_id, Some(path));
}
