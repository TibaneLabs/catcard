//! What a Solana transaction says, in the words and shapes a screen uses.
//!
//! The reading is [`catcard_solana`] and the screen is [`crate::txreview`]; this is what
//! joins them -- one card per instruction, in order, with the addresses and amounts
//! under it -- and the signing that follows if the owner says so.
//!
//! The same three steps as [`crate::evmtx`], which shares the screen: read, lay out,
//! sign. What differs between the two chains is only what the cards say.

use crate::txreview::{Review, short};

/// SOL's decimal places, which is what a lamport is a billionth of.
const SOL_DECIMALS: u8 = 9;
use catcard_callgate::Callgate;
use core::fmt::Write as _;

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

/// What a transaction comes to, per asset, for the accounts this device holds.
///
/// The question a person actually has -- "what does signing this cost me?" -- which no
/// single instruction answers: a transaction can take SOL in one and give some back in
/// another, and the fee is not an instruction at all. So the amounts are added up here,
/// in the one place that knows which accounts are ours.
///
/// **Only what can be attributed is counted.** A token account this device cannot tie to
/// a key of its own is somebody else's as far as this is concerned, and an amount
/// arriving there is not added to a total that says "yours". Under-counting is visible
/// on the rows below; over-counting would be a number that is simply wrong.
#[derive(Default)]
struct Ledger {
    entries: heapless::Vec<Entry, 6>,
    /// More assets than there is room for. Said out loud rather than dropped, because a
    /// total that is not the whole total must not read as one.
    lost: bool,
}

struct Entry {
    /// `None` is SOL itself.
    mint: Option<[u8; 32]>,
    symbol: Option<&'static str>,
    decimals: Option<u8>,
    /// Signed, because a transaction can move the same asset both ways.
    delta: i128,
}

impl Ledger {
    fn add(
        &mut self,
        mint: Option<[u8; 32]>,
        symbol: Option<&'static str>,
        decimals: Option<u8>,
        delta: i128,
    ) {
        if let Some(e) = self.entries.iter_mut().find(|e| e.mint == mint) {
            e.delta += delta;
            // A later instruction may name the mint where an earlier one could not.
            e.symbol = e.symbol.or(symbol);
            e.decimals = e.decimals.or(decimals);
            return;
        }
        if self
            .entries
            .push(Entry {
                mint,
                symbol,
                decimals,
                delta,
            })
            .is_err()
        {
            self.lost = true;
        }
    }

    /// Write the totals out, largest first is not worth the sort: they are read as a
    /// list of assets, and there are at most six.
    fn say(&self, out: &mut Review) {
        let mut num = [0u8; catcard_evm::summary::DECIMAL_MAX];
        let mut addr = [0u8; catcard_solana::ADDRESS_MAX];
        let mut brief: heapless::String<64> = heapless::String::new();
        for e in &self.entries {
            if e.delta == 0 {
                continue;
            }
            let sign = if e.delta < 0 { "-" } else { "+" };
            let magnitude = e.delta.unsigned_abs().min(u64::MAX as u128) as u64;
            match (e.symbol, e.decimals, e.mint) {
                (Some(symbol), Some(d), _) => {
                    let n = amount(magnitude, d, &mut num);
                    out.effect(format_args!("{sign}{n} {symbol}"));
                }
                (None, Some(d), _) => {
                    let n = amount(magnitude, d, &mut num);
                    out.effect(format_args!("{sign}{n} SOL"));
                }
                // A mint this build cannot name: the raw number and the address, since
                // scaling by a guessed decimal count would be inventing the amount.
                (_, None, Some(mint)) => {
                    let key = catcard_solana::SolanaKey(mint);
                    let text = catcard_solana::address(&key, &mut addr);
                    out.effect(format_args!(
                        "{sign}{magnitude} of {}",
                        short(text, &mut brief)
                    ));
                }
                (_, None, None) => out.effect(format_args!("{sign}{magnitude} lamports")),
            }
        }
        if self.lost {
            out.effect(format_args!("and more assets than fit here"));
        }
    }
}

/// Whether `account` is the associated token account of one of our keys for `mint`.
///
/// The addresses inside an SPL transfer are token accounts, not wallets, so "is this
/// mine?" cannot be answered by comparing against our own keys. It is answered by
/// deriving what our token account for that mint *would* be -- which is public key
/// arithmetic and needs no seed.
fn ours_token_account(
    account: Option<catcard_solana::SolanaKey>,
    mint: Option<catcard_solana::SolanaKey>,
    mine: &[[u8; 32]],
) -> bool {
    let (Some(account), Some(mint)) = (account, mint) else {
        return false;
    };
    mine.iter().any(|k| {
        outscript::solana::associated_token_address(catcard_solana::SolanaKey(*k), mint)
            .is_ok_and(|ata| ata == account)
    })
}

/// Whether `key` is one of this device's.
fn is_mine(key: Option<catcard_solana::SolanaKey>, mine: &[[u8; 32]]) -> bool {
    key.is_some_and(|k| mine.contains(&k.0))
}

/// Lay the transaction out: one row per part, with the detail behind each row.
///
/// `mine` is the public keys this device holds, which is what lets a row say "yours" --
/// the question underneath every other question, and one a person cannot answer by
/// eye against 44 characters of base58.
///
/// **An address is never replaced by a name.** A mint this build knows is written as its
/// ticker on the row *and* as its address in the detail, because the table is a claim
/// about which address that ticker belongs to and the address is the part the chain
/// agrees with.
fn describe(tx: &catcard_solana::Tx<'_>, mine: &[[u8; 32]], out: &mut Review) {
    use catcard_solana::{ADDRESS_MAX, Action, Budget, address};

    let mut addr = [0u8; ADDRESS_MAX];
    let mut num = [0u8; catcard_evm::summary::DECIMAL_MAX];
    let mut brief: heapless::String<64> = heapless::String::new();
    let mut ledger = Ledger::default();

    // What it costs, and who pays. The fee payer is account zero and pays whatever the
    // budget instructions say, so the two belong on one row.
    let fee = tx.fee();
    let payer = tx.fee_payer();
    match (fee.priority, fee.priority_unknown) {
        (Some(0), _) => out.element(
            is_mine(payer, mine),
            format_args!("Fee {} SOL", sol(fee.base, &mut num)),
        ),
        (Some(p), _) => out.element(
            is_mine(payer, mine),
            format_args!(
                "Fee up to {} SOL",
                sol(fee.base.saturating_add(p), &mut num)
            ),
        ),
        (None, _) => {
            out.element(
                is_mine(payer, mine),
                format_args!("Fee {} SOL plus a priority", sol(fee.base, &mut num)),
            );
            out.note(format_args!("the priority is not set out here,"));
            out.note(format_args!("so it cannot be totalled"));
        }
    }
    if let Some(payer) = payer {
        out.address("paid by", address(&payer, &mut addr));
    }
    if is_mine(payer, mine) {
        let paid = fee.base.saturating_add(fee.priority.unwrap_or(0));
        ledger.add(None, None, Some(SOL_DECIMALS), -(paid as i128));
    }

    for i in 0..tx.instruction_count() {
        let Some(action) = tx.action(i) else { continue };
        match action {
            Action::TransferSol { from, to, lamports } => {
                let amount = sol(lamports, &mut num);
                match to {
                    Some(to) => {
                        let text = address(&to, &mut addr);
                        out.element(
                            is_mine(from, mine) || is_mine(Some(to), mine),
                            format_args!("Send {amount} SOL to {}", short(text, &mut brief)),
                        );
                    }
                    None => out.element(is_mine(from, mine), format_args!("Send {amount} SOL")),
                }
                if let Some(from) = from {
                    out.address("from", address(&from, &mut addr));
                }
                if let Some(to) = to {
                    out.address("to", address(&to, &mut addr));
                }
                if is_mine(from, mine) {
                    ledger.add(None, None, Some(SOL_DECIMALS), -(lamports as i128));
                }
                if is_mine(to, mine) {
                    ledger.add(None, None, Some(SOL_DECIMALS), lamports as i128);
                }
            }
            Action::TransferToken {
                from,
                to,
                owner,
                amount: raw,
                decimals,
                mint,
                named,
            } => {
                // Scaled only where the instruction carried the decimals, or the mint is
                // one this build knows. An unchecked transfer of an unknown mint gives a
                // raw number, and saying so beats scaling it by a guess.
                let ours = is_mine(owner, mine) || is_mine(from, mine) || is_mine(to, mine);
                match (decimals.or(named.map(|m| m.decimals)), named) {
                    (Some(d), Some(m)) => {
                        let n = amount(raw, d, &mut num);
                        out.element(ours, format_args!("Send {n} {}", m.symbol));
                    }
                    (Some(d), None) => {
                        let n = amount(raw, d, &mut num);
                        out.element(ours, format_args!("Send {n} of a token"));
                    }
                    _ => out.element(ours, format_args!("Send {raw} raw units")),
                }
                if let Some(owner) = owner {
                    out.address("owner", address(&owner, &mut addr));
                }
                if let Some(from) = from {
                    out.address("from account", address(&from, &mut addr));
                }
                if let Some(to) = to {
                    out.address("to account", address(&to, &mut addr));
                }
                if let Some(mint) = mint {
                    out.address("mint", address(&mint, &mut addr));
                }
                // Out when the authority is ours, or the account it leaves is; in when
                // the account it arrives at is the one our key owns for that mint.
                let d = decimals.or(named.map(|m| m.decimals));
                let symbol = named.map(|m| m.symbol);
                let mint_bytes = mint.map(|m| m.0);
                if is_mine(owner, mine) || ours_token_account(from, mint, mine) {
                    ledger.add(mint_bytes, symbol, d, -(raw as i128));
                }
                if ours_token_account(to, mint, mine) {
                    ledger.add(mint_bytes, symbol, d, raw as i128);
                }
                // The one place a number here could be wrong by a power of ten.
                if action.decimals_disagree() {
                    out.cannot_read(format_args!("This amount may be wrong"));
                    out.note(format_args!("the instruction and this build disagree"));
                    out.note(format_args!("about the mint's decimal places"));
                }
            }
            Action::ApproveToken {
                account,
                delegate,
                owner,
                amount: raw,
                mint,
                named,
            } => {
                let ours = is_mine(owner, mine) || is_mine(account, mine);
                match named {
                    Some(m) => {
                        let n = amount(raw, m.decimals, &mut num);
                        out.element(ours, format_args!("Approve {n} {}", m.symbol));
                    }
                    None => out.element(ours, format_args!("Approve {raw} raw units")),
                }
                out.note(format_args!("an approval outlives this transaction"));
                if ours {
                    match named {
                        Some(m) => {
                            let n = amount(raw, m.decimals, &mut num);
                            out.effect(format_args!("{n} {} may be taken later", m.symbol));
                        }
                        None => out.effect(format_args!("{raw} raw units may be taken later")),
                    }
                }
                if let Some(d) = delegate {
                    out.address("to", address(&d, &mut addr));
                }
                if let Some(a) = account {
                    out.address("from account", address(&a, &mut addr));
                }
                if let Some(o) = owner {
                    out.address("owner", address(&o, &mut addr));
                }
                if let Some(mint) = mint {
                    out.address("mint", address(&mint, &mut addr));
                }
            }
            Action::CreateTokenAccount { owner, mint } => {
                out.element(is_mine(owner, mine), format_args!("Open a token account"));
                if let Some(o) = owner {
                    out.address("owner", address(&o, &mut addr));
                }
                if let Some(mint) = mint {
                    out.address("mint", address(&mint, &mut addr));
                }
            }
            Action::AdvanceNonce { account, authority } => {
                out.element(
                    is_mine(authority, mine),
                    format_args!("Spend a durable nonce"),
                );
                out.note(format_args!("what lets this be signed later"));
                if let Some(a) = account {
                    out.address("nonce account", address(&a, &mut addr));
                }
                if let Some(a) = authority {
                    out.address("authority", address(&a, &mut addr));
                }
            }
            // The numbers, not the word. These decide the priority fee, and a
            // transaction can ask its payer for an arbitrary amount through them.
            Action::ComputeBudget(Budget::Limit { units }) => {
                out.element(false, format_args!("Compute limit {units}"));
                out.note(format_args!("units this transaction may use"));
            }
            Action::ComputeBudget(Budget::Price { micro_lamports }) => {
                out.element(false, format_args!("Priority {micro_lamports} per unit"));
                out.note(format_args!("in millionths of a lamport"));
            }
            Action::ComputeBudget(Budget::Heap { bytes }) => {
                out.element(false, format_args!("Heap {bytes} bytes"));
            }
            Action::ComputeBudget(Budget::DataSize { bytes }) => {
                out.element(false, format_args!("Account data limit {bytes}"));
            }
            Action::ComputeBudget(Budget::Other) => {
                out.cannot_read(format_args!("A compute budget setting"));
                out.note(format_args!("not one of the four this build reads"));
            }
            Action::Unknown {
                program,
                named,
                tag,
                accounts,
                data_len,
            } => {
                match (named, tag) {
                    (Some(name), Some(tag)) => {
                        out.cannot_read(format_args!("Cannot read {name} {tag}"));
                    }
                    (Some(name), None) => {
                        out.cannot_read(format_args!("Cannot read a {name} call"))
                    }
                    _ => {
                        let text = address(&program, &mut addr);
                        out.cannot_read(format_args!("Cannot read {}", short(text, &mut brief)));
                    }
                }
                out.field("touches", format_args!("{accounts} accounts"));
                out.field("carries", format_args!("{data_len} bytes of data"));
                out.address("program", address(&program, &mut addr));
            }
        }
    }

    // Accounts lent by an on-chain table: precisely what this device cannot see, since
    // the instructions above touch accounts whose addresses are not in these bytes.
    let (w, r) = tx.lookups();
    if w + r > 0 {
        out.cannot_read(format_args!("{} accounts are not here", w + r));
        out.note(format_args!("they come from on-chain tables,"));
        out.note(format_args!("so this device cannot show them"));
    }

    ledger.say(out);

    // Who must sign, when it is more than just us.
    let signing = tx.signing();
    if signing.required > 1 {
        out.element(
            false,
            format_args!("{} of {} signed", signing.present, signing.required),
        );
        for i in 0..signing.required {
            if let Some(k) = tx.key(i) {
                let mark = if tx.signed(i) { "signed" } else { "waiting" };
                out.address(mark, address(&k, &mut addr));
            }
        }
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

/// The public keys at `paths`, for marking the rows that are this device's own.
///
/// Public keys only: nothing here is secret, and nothing secret outlives the closure
/// that derives them. A failure is not an error -- it means no row gets marked, and a
/// review with nothing marked is still a true review.
fn our_keys(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut crate::ui::Ui<'_>,
    paths: &[[u32; 4]],
) -> heapless::Vec<[u8; 32], 4> {
    let got = crate::menu::with_seed(gate, login, ui.panel, HEAD, |seed, kw| {
        let mut out: heapless::Vec<[u8; 32], 4> = heapless::Vec::new();
        for (i, path) in paths.iter().enumerate() {
            // The two shapes wallets write a Solana path in, for the sweep's own two
            // candidates; a request that named a path gets exactly that one.
            let node = if paths.len() > 1 && i == 1 {
                catcard_wallet::slip10::derive(seed, &path[..3], kw)
            } else {
                catcard_wallet::slip10::derive(seed, path, kw)
            };
            if let Some(node) = node {
                let _ = out.push(node.public_key(kw));
            }
        }
        Some(out)
    });
    got.unwrap_or_default()
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
/// **The same component as the review**, with different rows at the bottom. What
/// somebody wants here -- look at it again, hand it to a phone, sign with another
/// account -- is a list of actions over a transaction, which is what that screen already
/// is. A second hand-rolled menu would have been a second set of rows to keep in step
/// with the first, and a different shape to learn for no reason.
///
/// Returns whether another signature was asked for.
#[cfg_attr(not(feature = "board-q1"), allow(unused_variables))]
fn hand_back(
    ui: &mut crate::ui::Ui<'_>,
    transaction: &[u8],
    mine: &[[u8; 32]],
    signature: &[u8; 64],
    request_id: Option<&[u8]>,
) -> bool {
    let Ok(tx) = catcard_solana::parse(transaction) else {
        return false;
    };
    let missing = tx.signing().missing();
    let Some(mut review) = Review::new() else {
        return false;
    };
    describe(&tx, mine, &mut review);

    // The rows are built here so that the board and the transaction decide them: the QR
    // is a Q1 row because the only asker who wants a bare signature sent one by camera,
    // and another signature is only worth offering while one is still missing.
    let mut rows: heapless::Vec<&str, 4> = heapless::Vec::new();
    #[cfg(feature = "board-q1")]
    let _ = rows.push("Signature as QR");
    let _ = rows.push("Tap a phone");
    if missing > 0 {
        let _ = rows.push("Sign with another account");
    }
    let _ = rows.push("Done");

    loop {
        let Some(chosen) = review.show(ui, "Signed", &rows) else {
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
    // A transaction first, then a message: the transaction reading is the stricter one,
    // and a message that happened to parse as a transaction would be reported with
    // signatures it does not have.
    let tx = match catcard_solana::parse(bytes) {
        Ok(tx) => {
            crate::catlog!(
                "solana: {} bytes, a transaction, {} of {} signed",
                bytes.len(),
                tx.signing().present,
                tx.signing().required
            );
            tx
        }
        Err(first) => match catcard_solana::parse_message(bytes) {
            Ok(tx) => {
                crate::catlog!(
                    "solana: {} bytes, a message ({:?} as a transaction), {} signers",
                    bytes.len(),
                    first,
                    tx.signing().required
                );
                tx
            }
            Err(why) => {
                crate::catlog!("solana: {} bytes, neither: {:?}", bytes.len(), why);
                crate::menu::message(ui.panel, HEAD, why.why(), "any key to go back");
                crate::menu::wait_for_any_key(ui);
                return;
            }
        },
    };

    // Our own addresses, before anything is shown. **This is a seed stretch spent on a
    // question nobody asked**, and it is worth it: "is this my account?" is what a
    // person is really asking of every address on the screen, and it is the one question
    // they cannot answer themselves -- 44 characters of base58 do not get compared by
    // eye. The keys are public, so nothing secret outlives the closure.
    let mine = match path {
        Some(p) => our_keys(gate, login, ui, &[p]),
        None => our_keys(gate, login, ui, &[[44, COIN, 0, 0], [44, COIN, 0, 0]]),
    };

    let Some(mut review) = Review::new() else {
        crate::menu::message(ui.panel, HEAD, "not enough memory", "any key to go back");
        crate::menu::wait_for_any_key(ui);
        return;
    };
    describe(&tx, &mine, &mut review);
    if review
        .show(ui, "Solana transaction", &["Sign it"])
        .is_none()
    {
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
            let current = match catcard_solana::parse(&block.bytes()[..n]) {
                Ok(current) => current,
                Err(why) => {
                    let head = &block.bytes()[..n.min(8)];
                    crate::catlog!(
                        "solana: rebuilt {} bytes and {:?}; starts {:02x?}",
                        n,
                        why,
                        head
                    );
                    crate::menu::message(ui.panel, HEAD, why.why(), "any key to go back");
                    crate::menu::wait_for_any_key(ui);
                    return;
                }
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
        if !hand_back(ui, transaction, &mine, &signature, request_id) {
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
