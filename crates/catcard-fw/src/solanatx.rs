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
            Action::ComputeBudget => {}
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

/// How many lines of description a transaction gets, and how long each is.
///
/// Stack, on the board where stack is the scarce thing, so both are counted rather than
/// generous: eight instructions described is more than a person will read, and a line
/// wider than this does not fit the panel anyway.
const LINES: usize = 20;
const LINE: usize = 56;
type Arena = heapless::Vec<heapless::String<LINE>, LINES>;

/// Add one line to the arena, or silently stop at the last.
///
/// Silently, because a transaction with more instructions than there are lines is
/// reported by the count at the end rather than by half a sentence.
fn say(arena: &mut Arena, args: core::fmt::Arguments<'_>) {
    let mut s: heapless::String<LINE> = heapless::String::new();
    let _ = s.write_fmt(args);
    let _ = arena.push(s);
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

/// Describe every instruction, in order, into `arena`.
///
/// **An address is never replaced by a name.** A mint this build knows is written as its
/// ticker *and* its address, because the table is a claim about which address that
/// ticker belongs to, and the address is the part the chain agrees with.
fn describe(tx: &catcard_solana::Tx<'_>, arena: &mut Arena) {
    use catcard_solana::{ADDRESS_MAX, Action, LAMPORTS_PER_SOL, address};

    let mut addr = [0u8; ADDRESS_MAX];
    let mut num = [0u8; catcard_evm::summary::DECIMAL_MAX];

    for i in 0..tx.instruction_count() {
        let Some(action) = tx.action(i) else { continue };
        match action {
            Action::TransferSol { to, lamports, .. } => {
                let n = amount(lamports, LAMPORTS_PER_SOL.ilog10() as u8, &mut num);
                say(arena, format_args!("send {n} SOL"));
                if let Some(to) = to {
                    say(arena, format_args!("to {}", address(&to, &mut addr)));
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
                        say(arena, format_args!("send {n} {}", m.symbol));
                    }
                    (Some(d), None) => {
                        let n = amount(raw, d, &mut num);
                        say(arena, format_args!("send {n} of a token"));
                    }
                    _ => say(arena, format_args!("send {raw} raw units")),
                }
                if let Some(mint) = mint {
                    say(arena, format_args!("mint {}", address(&mint, &mut addr)));
                }
                if let Some(to) = to {
                    say(arena, format_args!("to {}", address(&to, &mut addr)));
                }
                if action.decimals_disagree() {
                    say(arena, format_args!("!! decimals disagree with this build"));
                }
            }
            Action::ApproveToken {
                delegate,
                amount: raw,
                ..
            } => {
                say(arena, format_args!("approve {raw} raw units"));
                if let Some(d) = delegate {
                    say(arena, format_args!("to {}", address(&d, &mut addr)));
                }
            }
            Action::CreateTokenAccount { mint, .. } => {
                say(arena, format_args!("open a token account"));
                if let Some(mint) = mint {
                    say(arena, format_args!("for {}", address(&mint, &mut addr)));
                }
            }
            Action::ComputeBudget => say(arena, format_args!("set the compute budget")),
            Action::Unknown {
                program,
                accounts,
                data_len,
            } => {
                say(arena, format_args!("call {}", address(&program, &mut addr)));
                say(
                    arena,
                    format_args!("{accounts} accounts, {data_len} bytes -- not decoded"),
                );
            }
        }
    }

    let (w, r) = tx.lookups();
    if w + r > 0 {
        say(arena, format_args!("{} accounts come from tables", w + r));
        say(arena, format_args!("and are not shown here"));
    }
    let signing = tx.signing();
    if signing.present > 0 {
        say(
            arena,
            format_args!("{} of {} already signed", signing.present, signing.required),
        );
    }
}

// ---------------------------------------------------------------------------
// Signing one
// ---------------------------------------------------------------------------

/// How many accounts are tried when nothing says which key is wanted.
///
/// A transaction arriving bare names no path. It names the *public key* that must sign,
/// so finding which of this device's keys that is means deriving them and comparing --
/// and the only question is how far to look.
///
/// Eight, which is what the address browser already derives for one page. That is the
/// honest bound: the same work this device visibly does when somebody pages through
/// their Solana addresses, so it is known to be tolerable rather than guessed to be.
///
/// It is still a window, and an account past it gets "no key of this device signs it".
/// That screen names the address the transaction wanted, so the answer to a key kept
/// further out is legible rather than mysterious -- and a wallet that says which path it
/// wants, which is what `sol-sign-request` is for, never comes through here at all.
const ACCOUNTS: u32 = 8;

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
    path: Option<[u32; 4]>,
) -> Result<Option<(usize, [u8; 64])>, &'static str> {
    if let Some(path) = path {
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
    crate::menu::with_seed(gate, login, ui.panel, HEAD, |seed, kw| {
        // Account 0 in both shapes, then account 1 in both, and so on: the first account
        // is the overwhelmingly common one, and this ends on it.
        //
        // **It stops at the first match.** An earlier version derived every candidate
        // whatever happened, on the grounds that how long the masked region lasts is
        // something a host can measure. That reasoning does not survive contact with
        // what is actually secret here: the key being asked for is written in the
        // transaction the asker sent, so a duration that varies with which of our
        // accounts holds it tells them an index they could have worked out anyway.
        // Paying for every account on every signature bought almost nothing. What the
        // masking is really for -- the seed, and everything derived from it -- is
        // unchanged.
        let mut found = None;
        'search: for account in 0..ACCOUNTS {
            for shape in 0..SHAPES {
                let path: &[u32] = match shape {
                    0 => &[44, COIN, account, 0],
                    _ => &[44, COIN, account],
                };
                let Some(node) = catcard_wallet::slip10::derive(seed, path, kw) else {
                    continue;
                };
                let public = node.public_key(kw);
                if let Some(slot) = tx.signer_index(&public) {
                    found = Some((
                        slot,
                        outscript::crypto::ed25519::sign(node.secret(), message),
                    ));
                    break 'search;
                }
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
) {
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
        #[cfg(feature = "board-q1")]
        let rows = ["Signature as QR", "Tap a phone", "Done"];
        #[cfg(not(feature = "board-q1"))]
        let rows = ["Tap a phone", "Done"];
        #[cfg(feature = "board-q1")]
        let tap = 1;
        #[cfg(not(feature = "board-q1"))]
        let tap = 0;
        match crate::menu::choose(ui, HEAD, note, &rows) {
            #[cfg(feature = "board-q1")]
            Some(0) => signature_qr(ui, signature, request_id),
            Some(n) if n == tap => crate::nfc::offer_solana_link(ui, transaction, missing),
            _ => return,
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

    let mut arena: Arena = heapless::Vec::new();
    describe(&tx, &mut arena);
    let mut said: heapless::String<80> = heapless::String::new();
    headline(&tx, &mut said);

    let mut rows: heapless::Vec<Line<'_>, { LINES + 4 }> = heapless::Vec::new();
    let _ = rows.push(Line::title("Solana transaction"));
    let _ = rows.push(Line::body(&said).small());
    for line in &arena {
        let _ = rows.push(Line::body(line).small());
    }
    let _ = rows.push(Line::item("Sign it", 1));

    if !matches!(
        crate::menu::show_doc(ui, &rows, false, false),
        crate::menu::DocExit::Selected(1)
    ) {
        return;
    }

    let signed = match sign_it(gate, login, ui, &tx, path) {
        Ok(Some(found)) => found,
        Ok(None) => {
            // Name the key it wanted. "Not ours" on its own leaves a person guessing
            // between a wrong device, a wrong account and a wrong passphrase; the
            // address says which, because they can compare it to one this device shows.
            let mut wanted: heapless::String<64> = heapless::String::new();
            let mut addr = [0u8; catcard_solana::ADDRESS_MAX];
            match tx.key(0) {
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
            return;
        }
        Err(why) => {
            crate::menu::message(ui.panel, HEAD, why, "any key to go back");
            crate::menu::wait_for_any_key(ui);
            return;
        }
    };
    let (slot, signature) = signed;

    // The transaction to hand back: what arrived, if a transaction arrived, and the
    // message with its empty slots in front if one did not.
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
    if !catcard_solana::place_signature(&mut block.bytes()[..n], slot, &signature) {
        crate::menu::message(ui.panel, HEAD, "no slot for it", "any key to go back");
        crate::menu::wait_for_any_key(ui);
        return;
    }
    crate::catlog!("solana: signed slot {} of {} bytes", slot, n);
    let (transaction, _) = block.bytes().split_at(n);
    hand_back(ui, transaction, &signature, request_id);
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
