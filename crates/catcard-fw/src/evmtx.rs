//! What an EVM transaction says, in the words and shapes a screen uses.
//!
//! The reading is [`catcard_evm`] and the screen is [`crate::txreview`]; this is what
//! joins them. The same three steps as [`crate::solanatx`], which shares the screen:
//! read, lay out, sign -- and what differs between the two chains is only what the cards
//! say.
//!
//! # What an EVM transaction hides that a Solana one does not
//!
//! One call, not a list, so there is less to lay out -- and more to be wrong about. The
//! whole of what a call does is in four bytes of selector and some arguments, and this
//! build can name a few thousand selectors out of millions. So the cards are careful
//! about the difference between *knowing what a call is* and *having seen its name
//! somewhere*: a named selector is shown as a name, and everything else is a red card.

use catcard_evm::summary::{Action, Amount};

use crate::txreview::Review;

/// Room for an address as EIP-55 writes it: `0x` and forty hex digits.
const ADDRESS: usize = 42;

/// An address, checksummed the way every explorer shows one.
///
/// EIP-55 rather than plain hex: the capitalisation is a checksum, so an address a
/// person compares against a screen somewhere else matches character for character or
/// does not match at all.
fn address<'o>(a: &[u8; 20], out: &'o mut [u8; ADDRESS]) -> &'o str {
    match outscript::address::eip55_to_slice(a, out) {
        Some(n) => core::str::from_utf8(&out[..n]).unwrap_or("(bad address)"),
        None => "(bad address)",
    }
}

/// A 256-bit amount at `decimals`, as people write it.
fn scaled<'o>(
    raw: &[u8; 32],
    decimals: u8,
    out: &'o mut [u8; catcard_evm::summary::DECIMAL_MAX],
) -> &'o str {
    catcard_evm::summary::decimal(raw, decimals, out)
}

/// A token amount as one row, with its ticker when the table has one.
fn token_row(out: &mut Review, lead: &str, amount: &Amount) {
    let mut num = [0u8; catcard_evm::summary::DECIMAL_MAX];
    match amount.token {
        Some(t) if amount.unlimited() => {
            out.element(false, format_args!("{lead} unlimited {}", t.symbol));
        }
        Some(t) => {
            let n = scaled(&amount.raw, t.decimals, &mut num);
            out.element(false, format_args!("{lead} {n} {}", t.symbol));
        }
        // Unnamed: the raw number and the contract, which is everything actually known.
        // Scaling it by a guessed decimal count would be inventing the amount.
        None if amount.unlimited() => out.element(false, format_args!("{lead} unlimited")),
        None => {
            let n = scaled(&amount.raw, 0, &mut num);
            out.element(false, format_args!("{lead} {n} raw units"));
            out.note(format_args!("of a token this build cannot name"));
        }
    }
    let mut addr = [0u8; ADDRESS];
    out.address("token", address(&amount.contract, &mut addr));
}

/// One line of what signing changes, for an amount of a token.
fn effect_of(out: &mut Review, lead: &str, amount: &Amount) {
    let mut num = [0u8; catcard_evm::summary::DECIMAL_MAX];
    match amount.token {
        Some(t) if amount.unlimited() => out.effect(format_args!("{lead}every {}", t.symbol)),
        Some(t) => {
            let n = scaled(&amount.raw, t.decimals, &mut num);
            out.effect(format_args!("{lead}{n} {}", t.symbol));
        }
        None if amount.unlimited() => {
            out.effect(format_args!("{lead}every unit of a token"));
        }
        None => {
            let n = scaled(&amount.raw, 0, &mut num);
            out.effect(format_args!("{lead}{n} raw units of a token"));
        }
    }
}

/// Lay a transaction out: which chain, what it costs, and what it does.
pub(crate) fn describe(tx: &catcard_evm::Tx<'_>, out: &mut Review) {
    let mut addr = [0u8; ADDRESS];
    let mut num = [0u8; catcard_evm::summary::DECIMAL_MAX];

    // Which chain, first. The same calldata on the wrong chain is a different
    // transaction, and one naming no chain is valid on every chain at once -- which is a
    // red row rather than a blank.
    match tx.chain_id {
        Some(id) => match catcard_evm::tokens::chain_name(id) {
            Some(name) => out.element(false, format_args!("On {name}")),
            None => out.element(false, format_args!("On chain {id}")),
        },
        None => {
            out.cannot_read(format_args!("This names no chain"));
            out.note(format_args!("so it is valid on every chain at once"));
        }
    }
    out.field("nonce", format_args!("{}", tx.nonce));

    // What the gas can cost at most: the limit times the price, which is what the sender
    // is committing to rather than what they will probably pay.
    let mut fee = [0u8; 32];
    let mut carry = 0u128;
    for i in (0..32).rev() {
        let v = u128::from(tx.max_fee[i]) * u128::from(tx.gas_limit) + carry;
        fee[i] = v as u8;
        carry = v >> 8;
    }
    if carry == 0 {
        out.field("gas up to", format_args!("{}", scaled(&fee, 18, &mut num)));
        // Gas is spent whatever the call does, so it belongs in the total. Everything
        // that leaves here leaves the account that signs, which is this device -- there
        // is one sender on an EVM transaction and it is whoever signs it, so unlike
        // Solana there is nothing to attribute.
        out.effect(format_args!(
            "-{} in gas at most",
            scaled(&fee, 18, &mut num)
        ));
    }

    match catcard_evm::summary::summarise(tx) {
        Action::Send { to, wei } => {
            out.effect(format_args!("-{}", scaled(&wei, 18, &mut num)));
            out.element(false, format_args!("Send {}", scaled(&wei, 18, &mut num)));
            out.note(format_args!("of the chain's own coin"));
            out.address("to", address(&to, &mut addr));
        }
        Action::TokenSend { to, amount } => {
            effect_of(out, "-", &amount);
            token_row(out, "Send", &amount);
            out.address("to", address(&to, &mut addr));
        }
        Action::TokenSendFrom { from, to, amount } => {
            // Out of `from`, which is only this device's account if it gave the
            // allowance being used. Said as a movement rather than as a loss.
            effect_of(out, "moves ", &amount);
            token_row(out, "Move", &amount);
            out.address("from", address(&from, &mut addr));
            out.address("to", address(&to, &mut addr));
            out.note(format_args!("under an allowance already given"));
        }
        Action::Approve { spender, amount } => {
            effect_of(out, "lets somebody take ", &amount);
            token_row(out, "Approve", &amount);
            out.address("to", address(&spender, &mut addr));
            out.note(format_args!("an approval outlives this transaction"));
        }
        // A selector this build can name. Named is not decoded: what the arguments say
        // is not read, so the amount inside a swap is not on this screen.
        Action::Call {
            to,
            method,
            data_len,
            wei,
        } => {
            out.cannot_read(format_args!("Calls {method}"));
            out.note(format_args!("the name is known, the arguments are not"));
            out.field("calldata", format_args!("{data_len} bytes"));
            out.address("contract", address(&to, &mut addr));
            if wei.iter().any(|&b| b != 0) {
                out.field("sending", format_args!("{}", scaled(&wei, 18, &mut num)));
            }
        }
        Action::UnknownCall {
            to,
            selector,
            data_len,
            wei,
        } => {
            out.cannot_read(format_args!("Calls a contract"));
            out.field(
                "selector",
                format_args!(
                    "{:02x}{:02x}{:02x}{:02x}",
                    selector[0], selector[1], selector[2], selector[3]
                ),
            );
            out.field("calldata", format_args!("{data_len} bytes"));
            out.address("contract", address(&to, &mut addr));
            if wei.iter().any(|&b| b != 0) {
                out.field("sending", format_args!("{}", scaled(&wei, 18, &mut num)));
            }
        }
        Action::CreateContract { data_len, wei } => {
            out.cannot_read(format_args!("Deploys a contract"));
            out.field("code", format_args!("{data_len} bytes"));
            if wei.iter().any(|&b| b != 0) {
                out.field("with", format_args!("{}", scaled(&wei, 18, &mut num)));
            }
        }
    }

    if tx.access_list_len > 0 {
        out.field(
            "access list",
            format_args!("{} entries", tx.access_list_len),
        );
    }
    if tx.signature.is_some() {
        out.note(format_args!("this already carries a signature"));
    }
}

/// Read a transaction out and offer to do the one thing that can be done with it.
///
/// Signing is not built for EVM yet, so the row is not offered: what this gives is the
/// whole transaction on a screen, which is the half that has to be right before a
/// signature over it means anything.
#[cfg(not(feature = "board-mk3"))]
pub(crate) fn screen(ui: &mut crate::ui::Ui<'_>, bytes: &[u8]) {
    const HEAD: &str = "EVM transaction";

    let Ok(tx) = catcard_evm::parse(bytes) else {
        crate::menu::message(
            ui.panel,
            HEAD,
            "this is not a transaction",
            "any key to go back",
        );
        crate::menu::wait_for_any_key(ui);
        return;
    };
    let Some(mut review) = Review::new() else {
        crate::menu::message(ui.panel, HEAD, "not enough memory", "any key to go back");
        crate::menu::wait_for_any_key(ui);
        return;
    };
    describe(&tx, &mut review);
    review.show(ui, HEAD, &["Signing is not built yet"]);
}

/// A computer's EVM sign request, uploaded over USB, signed with the one key it listed.
///
/// The screen is [`describe`]'s, the same one a scanned transaction gets, with one row
/// more at the top: the address that signs, derived from the listed key before anything
/// is shown, because an EVM transaction names no sender and the signer is whoever signs.
/// The signature is RFC 6979 over Keccak-256 of the bytes exactly as they arrived
/// ([`catcard_evm::Tx::signing_hash`]), and the signed form appends it without rebuilding
/// anything ([`catcard_evm::sign::encode_signed`]).
///
/// The upload sits at `tx_at` in the PSRAM lease `held`; the signed transaction and the
/// result are written into the lease past it, and the host pages the result out of there.
#[allow(clippy::too_many_arguments)]
// Its own frame: inlined into `hostwallet::sign` beside the other chains', the three made
// one 13 KB frame held under a TSS session, which ran past the UI task's stack.
#[inline(never)]
pub(crate) fn host_sign(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut crate::ui::Ui<'_>,
    mut held: crate::hostwallet::HostBuf,
    tx_at: usize,
    tx_len: usize,
    key: &catcard_wallet::hostkeys::KeyPath,
    ticket: u32,
) -> crate::hostwallet::Outcome {
    use crate::hostwallet::Outcome;
    use catcard_wallet::bip32::ChildNumber;
    use catcard_wallet::chain::{self, Encoding, address as caddr};
    const HEAD: &str = "EVM transaction";

    let refuse = |ui: &mut crate::ui::Ui<'_>, why: &'static str| {
        crate::menu::message(ui.panel, HEAD, why, "any key to go back");
        crate::menu::wait_for_any_key(ui);
        Outcome::Refused(why)
    };

    let base = (tx_at + tx_len + 3) & !3;
    let done: Result<(usize, usize), Outcome> = 'work: {
        let bytes = held.bytes();
        if base >= bytes.len() {
            break 'work Err(refuse(ui, "too big for this board"));
        }
        let (head, rest) = bytes.split_at_mut(base);
        let raw: &[u8] = &head[tx_at..tx_at + tx_len];
        let Ok(tx) = catcard_evm::parse(raw) else {
            break 'work Err(refuse(ui, "this is not a transaction"));
        };
        if tx.signed() {
            break 'work Err(refuse(ui, "it is already signed"));
        }

        let Some(master) = crate::menu::unlock_master(gate, login, ui, HEAD) else {
            break 'work Err(Outcome::Refused("the wallet could not be opened"));
        };
        let steps = key.steps();
        let public = crate::keywork::run(|kw| {
            let mut here = master.clone();
            for &s in steps {
                here = here.derive_child(ChildNumber(s), kw).ok()?;
            }
            Some(here.public_key(kw))
        });
        let Some(public) = public else {
            break 'work Err(refuse(ui, "the key could not be derived"));
        };
        let mut addr = [0u8; caddr::MAX_LEN];
        let who = caddr::from_secp256k1(
            &chain::ETHEREUM,
            Encoding::Evm,
            crate::prefs::network(),
            &public,
            &mut addr,
        )
        .ok()
        .and_then(|n| core::str::from_utf8(&addr[..n]).ok())
        .unwrap_or("(no address)");

        let Some(mut review) = Review::new() else {
            break 'work Err(refuse(ui, "not enough memory"));
        };
        review.address("signed by", who);
        describe(&tx, &mut review);
        if review.show(ui, HEAD, &["Sign it"]).is_none() {
            break 'work Err(Outcome::Declined);
        }
        drop(review);
        if !crate::usbtask::host_alive(ticket) {
            break 'work Err(Outcome::Declined);
        }

        // Scratch for the signing bytes, room for the signed transaction, then the result.
        let scratch_len = (tx_len + 1 + 3) & !3;
        let signed_len = (tx_len + 1 + catcard_evm::sign::OVERHEAD + 8 + 3) & !3;
        if scratch_len + signed_len >= rest.len() {
            break 'work Err(refuse(ui, "too big for this board"));
        }
        let (scratch, rest) = rest.split_at_mut(scratch_len);
        let (signed, result) = rest.split_at_mut(signed_len);
        let Ok(hash) = tx.signing_hash(scratch) else {
            break 'work Err(refuse(ui, "could not hash it"));
        };
        let sig = crate::keywork::run(|kw| {
            let mut here = master.clone();
            for &s in steps {
                here = here.derive_child(ChildNumber(s), kw).ok()?;
            }
            let k = outscript::crypto::secp256k1::SecpPrivateKey::from_bytes(here.secret_bytes())
                .ok()?;
            Some(k.sign_recoverable(&hash))
        });
        drop(master);
        let Some((r, s, recid)) = sig else {
            break 'work Err(refuse(ui, "could not sign"));
        };
        let n = match catcard_evm::sign::encode_signed(&tx, &r, &s, recid, signed) {
            Ok(n) => n,
            Err(_) => break 'work Err(refuse(ui, "could not sign")),
        };
        let m = match catcard_usb::hostwallet::write_evm(result, &signed[..n]) {
            Ok(m) => m,
            Err(_) => break 'work Err(refuse(ui, "result too large")),
        };
        Ok((base + scratch_len + signed_len, m))
    };
    match done {
        Ok((off, len)) => Outcome::Ready {
            buf: held,
            off,
            len,
        },
        Err(o) => o,
    }
}

/// Room for an address of either chain that signs here.
type Who = heapless::String<{ catcard_wallet::chain::address::MAX_LEN }>;

/// The one key a message is signed with, and what the screen says of it.
struct Signer {
    /// Only the leaf: the master is the whole wallet, and a review can stand on the
    /// screen for as long as nobody is in the room.
    leaf: catcard_wallet::bip32::ExtendedPrivKey,
    public: [u8; 33],
    who: Who,
    path: heapless::String<{ 1 + catcard_wallet::hostkeys::MAX_DEPTH * 12 }>,
}

/// What a refusal looks like on the screen, and what the host is told.
fn refuse(ui: &mut crate::ui::Ui<'_>, head: &str, why: &'static str) -> crate::hostwallet::Outcome {
    crate::menu::message(ui.panel, head, why, "any key to go back");
    crate::menu::wait_for_any_key(ui);
    crate::hostwallet::Outcome::Refused(why)
}

/// Derive the key at `key` and write its address as `chain` does (`tron` for Tron's,
/// Ethereum's otherwise).
#[inline(never)]
fn signer(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut crate::ui::Ui<'_>,
    head: &str,
    tron: bool,
    key: &catcard_wallet::hostkeys::KeyPath,
) -> Result<Signer, crate::hostwallet::Outcome> {
    use crate::hostwallet::Outcome;
    use catcard_wallet::bip32::ChildNumber;
    use catcard_wallet::chain::{self, Encoding, address as caddr};
    use core::fmt::Write as _;

    let Some(master) = crate::menu::unlock_master(gate, login, ui, head) else {
        return Err(Outcome::Refused("the wallet could not be opened"));
    };
    let leaf = {
        let mut busy = crate::menu::Working::new(ui.panel, head, "deriving");
        let leaf = crate::keywork::run(|kw| {
            let mut here = master.clone();
            for &s in key.steps() {
                here = here.derive_child(ChildNumber(s), kw).ok()?;
            }
            Some(here)
        });
        busy.tick(ui.panel);
        leaf
    };
    drop(master);
    let Some(leaf) = leaf else {
        return Err(refuse(ui, head, "the key could not be derived"));
    };
    let public = crate::keywork::run(|kw| leaf.public_key(kw));

    let (c, encoding) = if tron {
        (&chain::TRON, Encoding::Tron)
    } else {
        (&chain::ETHEREUM, Encoding::Evm)
    };
    let mut addr = [0u8; caddr::MAX_LEN];
    let Ok(n) = caddr::from_secp256k1(c, encoding, crate::prefs::network(), &public, &mut addr)
    else {
        drop(leaf);
        return Err(refuse(ui, head, "address failed"));
    };
    let mut who = Who::new();
    let _ = who.push_str(core::str::from_utf8(&addr[..n]).unwrap_or(""));

    let mut path = heapless::String::new();
    let _ = path.push('m');
    for step in key.steps() {
        const H: u32 = catcard_wallet::bip32::HARDENED_OFFSET;
        let _ = write!(
            path,
            "/{}{}",
            step & !H,
            if step & H != 0 { "h" } else { "" }
        );
    }
    Ok(Signer {
        leaf,
        public,
        who,
        path,
    })
}

/// Sign `hash` with the signer's key, check the signature as a verifier would, and give
/// the 65 bytes `r || s || v`.
///
/// The check recovers the key from the signature and compares it with the one that
/// signed -- as every signature made here is checked. One that does not recover is worse
/// than none.
#[inline(never)]
fn sign_digest(
    ui: &mut crate::ui::Ui<'_>,
    head: &str,
    signer: Signer,
    hash: &[u8; 32],
) -> Result<(Who, [u8; catcard_evm::personal::SIG_LEN]), crate::hostwallet::Outcome> {
    use outscript::crypto::secp256k1::{SecpPrivateKey, recover_public_key};
    let Signer {
        leaf, public, who, ..
    } = signer;
    let mut busy = crate::menu::Working::new(ui.panel, head, "signing");
    let sig = crate::keywork::run(|_kw| {
        let k = SecpPrivateKey::from_bytes(leaf.secret_bytes()).ok()?;
        Some(k.sign_recoverable(hash))
    });
    drop(leaf);
    busy.tick(ui.panel);
    let Some((r, s, recid)) = sig else {
        return Err(refuse(ui, head, "could not sign"));
    };
    match recover_public_key(&r, &s, recid, hash) {
        Ok(k) if k.serialize_compressed() == public => {}
        _ => return Err(refuse(ui, head, "signature did not verify")),
    }
    let Some(out) = catcard_evm::personal::signature(&r, &s, recid) else {
        return Err(refuse(ui, head, "could not sign"));
    };
    Ok((who, out))
}

/// Sign `text` for a computer asking over the encrypted channel (`crate::hostwallet`), as
/// EIP-191 `personal_sign` -- or, with `tron`, as TIP-191 for a Tron address -- by the
/// key at `key`: the text, the address that signs and the path on the screen, and yes or
/// no. The address and the 65 bytes `r || s || v`.
///
/// The text is put through [`catcard_evm::personal::text`], so every byte of it is one
/// the screen shows. It is laid out a line to a line, and a message this panel cannot
/// hold whole is refused rather than shown cut: what is signed is what was read.
// Its own frame, as `host_sign` is: the review's lines and view are the deepest part.
#[inline(never)]
pub(crate) fn host_sign_message(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut crate::ui::Ui<'_>,
    tron: bool,
    message: &[u8],
    key: &catcard_wallet::hostkeys::KeyPath,
    ticket: u32,
) -> Result<(Who, [u8; catcard_evm::personal::SIG_LEN]), crate::hostwallet::Outcome> {
    use crate::hostwallet::Outcome;
    use catcard_evm::personal;
    const HEAD: &str = "Sign message";

    let text = match personal::text(message) {
        Ok(text) => text,
        Err(why) => return Err(Outcome::Refused(why.why())),
    };
    // The key is read under another heading: nothing has been shown yet, and "Sign
    // message" over a progress bar reads as signing it.
    let signer = signer(gate, login, ui, "Message request", tron, key)?;
    let (how, prefix) = if tron {
        ("Tron, signMessageV2", personal::TRON_PREFIX)
    } else {
        ("Ethereum, personal_sign", personal::PREFIX)
    };
    match confirm_message(ui, HEAD, text, &signer.who, &signer.path, &[how]) {
        Ok(true) => {}
        Ok(false) => return Err(Outcome::Declined),
        Err(why) => return Err(refuse(ui, HEAD, why)),
    }
    if !crate::usbtask::host_alive(ticket) {
        return Err(Outcome::Declined);
    }

    let hash = crate::heap::take(personal::scratch_len(text.len()))
        .and_then(|mut scratch| personal::digest_under(prefix, text.as_bytes(), scratch.bytes()));
    let Some(hash) = hash else {
        return Err(refuse(ui, HEAD, "not enough memory"));
    };
    let done = sign_digest(ui, HEAD, signer, &hash)?;
    Ok(done)
}

/// The message a line to a line, the address that will sign it, the path and how. `Ok`
/// with the person's answer, or why the message cannot be put to them at all.
///
/// `how` is the last rows: the scheme, and whatever else the envelope carries that the
/// person should see.
#[inline(never)]
pub(crate) fn confirm_message(
    ui: &mut crate::ui::Ui<'_>,
    head: &str,
    text: &str,
    address: &str,
    path: &str,
    how: &[&str],
) -> Result<bool, &'static str> {
    use catcard_evm::personal;
    use catcard_ui::scroll::{Line, ScrollView};
    let mut doc: heapless::Vec<Line, { personal::MAX_LINES + 8 }> = heapless::Vec::new();
    let _ = doc.push(Line::title(head));
    for line in text.split('\n') {
        doc.push(Line::body(line).wrapped())
            .map_err(|_| "message has too many lines")?;
    }
    let _ = doc.push(Line::body("will be signed by").small());
    let _ = doc.push(Line::body(address).small().wrapped());
    let _ = doc.push(Line::body(path).small().wrapped());
    for row in how {
        doc.push(Line::body(row).small().wrapped())
            .map_err(|_| "message has too many lines")?;
    }
    if !fits(&doc) {
        return Err("too long to show here");
    }
    let mut view = ScrollView::build(
        &doc,
        crate::display::SCREEN_W,
        crate::display::SCREEN_H,
        crate::display::FONTS,
    );
    Ok(crate::menu::scroll_choice(ui, &mut view))
}

/// Whether every line of `doc` is in the view once wrapped. A view holds so many rows
/// and stops; one that came out full may have stopped short, and the rows it dropped
/// would be the end of the message and the address that signs it.
#[inline(never)]
fn fits(doc: &[catcard_ui::scroll::Line<'_>]) -> bool {
    !catcard_ui::scroll::wrap(doc, crate::display::SCREEN_W, &crate::display::FONTS).is_full()
}

// ---- typed data (EIP-712) --------------------------------------------------------------

/// Characters of text a typed-data review can run to, labels and values together.
const SHEET_TEXT: usize = 4096;
/// Rows a typed-data review can run to.
const SHEET_ROWS: usize = 192;
/// Rows on one page of it, before wrapping.
const PAGE_ROWS: usize = 40;

/// One row of a review: where its text is, and whether it names a value or is one.
#[derive(Copy, Clone)]
struct Span {
    start: u16,
    end: u16,
    label: bool,
}

/// A typed-data review as text: a label, then the rows of its value, for every value in
/// the order it is hashed.
///
/// On the heap, at a size fixed here. What does not fit is not shown short: `lost` is
/// set, and nothing is signed.
struct Sheet {
    text: alloc::string::String,
    spans: alloc::vec::Vec<Span>,
    lost: bool,
}

/// A `String` that is never grown: writing past what was reserved fails.
struct Bounded<'s>(&'s mut alloc::string::String);

impl core::fmt::Write for Bounded<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        if self.0.len() + s.len() > self.0.capacity() {
            return Err(core::fmt::Error);
        }
        self.0.push_str(s);
        Ok(())
    }
}

impl Sheet {
    fn new() -> Option<Self> {
        let mut text = alloc::string::String::new();
        text.try_reserve_exact(SHEET_TEXT).ok()?;
        let mut spans = alloc::vec::Vec::new();
        spans.try_reserve_exact(SHEET_ROWS).ok()?;
        Some(Sheet {
            text,
            spans,
            lost: false,
        })
    }

    fn put(&mut self, label: bool, args: core::fmt::Arguments<'_>) {
        use core::fmt::Write as _;
        let start = self.text.len();
        if self.spans.len() == self.spans.capacity()
            || Bounded(&mut self.text).write_fmt(args).is_err()
        {
            self.text.truncate(start);
            self.lost = true;
            return;
        }
        self.spans.push(Span {
            start: start as u16,
            end: self.text.len() as u16,
            label,
        });
    }

    /// The name of what follows.
    fn label(&mut self, args: core::fmt::Arguments<'_>) {
        self.put(true, args);
    }

    /// One row of a value.
    fn value(&mut self, args: core::fmt::Arguments<'_>) {
        self.put(false, args);
    }

    fn row(&self, span: Span) -> &str {
        &self.text[usize::from(span.start)..usize::from(span.end)]
    }
}

const _: () = assert!(SHEET_TEXT <= u16::MAX as usize);

/// Bytes as hex digits.
struct Hex<'a>(&'a [u8]);

impl core::fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// One value, in the words a person reads it in.
///
/// `chain` is set for the domain's `chainId`, which is worth a name beside the number.
fn typed_value(sheet: &mut Sheet, chain: bool, leaf: catcard_evm::typed::Leaf<'_>) {
    use catcard_evm::typed::Leaf;
    let mut num = [0u8; catcard_evm::summary::DECIMAL_MAX];
    match leaf {
        // An allowance of every token there will ever be is written as this number, and
        // seventy-eight digits is not how a person recognises it.
        Leaf::Uint { raw, bits: 256 } if raw == [0xff; 32] => {
            sheet.value(format_args!("unlimited (the largest number)"));
        }
        Leaf::Uint { raw, .. } => {
            let n = scaled(&raw, 0, &mut num);
            let name = (chain && raw[..24].iter().all(|b| *b == 0))
                .then(|| {
                    let mut id = [0u8; 8];
                    id.copy_from_slice(&raw[24..]);
                    catcard_evm::tokens::chain_name(u64::from_be_bytes(id))
                })
                .flatten();
            match name {
                Some(name) => sheet.value(format_args!("{n} ({name})")),
                None => sheet.value(format_args!("{n}")),
            }
        }
        Leaf::Int { raw } if raw[0] & 0x80 != 0 => {
            // Two's complement: the magnitude is every bit turned over, plus one.
            let mut mag = raw;
            let mut carry = true;
            for b in mag.iter_mut().rev() {
                let (v, c) = (!*b).overflowing_add(u8::from(carry));
                *b = v;
                carry = c;
            }
            sheet.value(format_args!("-{}", scaled(&mag, 0, &mut num)));
        }
        Leaf::Int { raw } => sheet.value(format_args!("{}", scaled(&raw, 0, &mut num))),
        Leaf::Bool(b) => sheet.value(format_args!("{}", if b { "true" } else { "false" })),
        Leaf::Address(a) => {
            let mut addr = [0u8; ADDRESS];
            sheet.value(format_args!("{}", address(&a, &mut addr)));
        }
        Leaf::Fixed(b) => sheet.value(format_args!("0x{}", Hex(b))),
        Leaf::Bytes([]) => sheet.value(format_args!("(no bytes)")),
        Leaf::Bytes(b) if b.len() <= 32 => sheet.value(format_args!("0x{}", Hex(b))),
        // What is signed for a `bytes` is its hash, so for one too long to read the hash
        // is the honest thing to show.
        Leaf::Bytes(b) => {
            let hash = outscript::hash::keccak256_once(b);
            sheet.value(format_args!("{} bytes, keccak256", b.len()));
            sheet.value(format_args!("0x{}", Hex(&hash)));
        }
        Leaf::Str("") => sheet.value(format_args!("(empty text)")),
        Leaf::Str(s) => {
            for line in s.split('\n') {
                sheet.value(format_args!("{line}"));
            }
        }
        Leaf::Empty => sheet.value(format_args!("(empty list)")),
    }
}

/// Hash the typed data and write every value of it onto `sheet`, in one pass.
#[inline(never)]
fn typed_sheet(
    typed: &catcard_evm::typed::Typed<'_>,
    sheet: &mut Sheet,
) -> Result<catcard_evm::typed::Hashes, catcard_evm::typed::Error> {
    use catcard_evm::typed::{Label, Part, Seg};
    sheet.label(format_args!("message type"));
    sheet.value(format_args!("{}", typed.primary()));
    typed.walk(&mut |part, path, leaf| {
        match part {
            Part::Domain => sheet.label(format_args!("domain {}", Label(path))),
            Part::Message => sheet.label(format_args!("{}", Label(path))),
        }
        let chain = part == Part::Domain && path == [Seg::Field("chainId")];
        typed_value(sheet, chain, leaf);
    })
}

/// Go through `sheet` a page at a time, a value never split across two, handing each page
/// to `show`. `Ok(Some(pages))` when every page was shown and accepted, `Ok(None)` when
/// one was not, and `Err` when a single value is more than a page holds.
///
/// `total` is the page count for the titles, zero while it is not yet known.
fn pages(
    sheet: &Sheet,
    head: &str,
    total: usize,
    show: &mut dyn FnMut(&[catcard_ui::scroll::Line<'_>]) -> bool,
) -> Result<Option<usize>, &'static str> {
    use catcard_ui::scroll::Line;
    use core::fmt::Write as _;
    let spans = &sheet.spans[..];
    let (mut at, mut page) = (0, 0);
    while at < spans.len() {
        page += 1;
        let mut title: heapless::String<40> = heapless::String::new();
        let _ = if total > 1 {
            write!(title, "{head} {page}/{total}")
        } else {
            write!(title, "{head}")
        };
        let mut doc: heapless::Vec<Line, PAGE_ROWS> = heapless::Vec::new();
        let _ = doc.push(Line::title(&title));
        let mut end = at;
        while end < spans.len() {
            // One value: its label, and every row up to the next label.
            let mut next = end + 1;
            while next < spans.len() && !spans[next].label {
                next += 1;
            }
            let before = doc.len();
            let room = spans[end..next].iter().all(|span| {
                let text = sheet.row(*span);
                let line = if span.label {
                    Line::body(text).small()
                } else {
                    Line::body(text).wrapped()
                };
                doc.push(line).is_ok()
            });
            if !room || !fits(&doc) {
                doc.truncate(before);
                break;
            }
            end = next;
        }
        if end == at {
            return Err("too long to show here");
        }
        at = end;
        if !show(&doc) {
            return Ok(None);
        }
    }
    Ok(Some(page))
}

/// Sign EIP-712 typed data for a computer asking over the encrypted channel
/// (`crate::hostwallet`), by the key at `key`. The address and the 65 bytes `r || s || v`.
///
/// Every value is on the screen before anything is signed: the domain, then the message,
/// each under the name the types give it, a page at a time, and the last page says who
/// signs. The digest comes out of the same pass that wrote those pages
/// ([`catcard_evm::typed::Typed::walk`]), so what is signed is what was shown. Typed data
/// that does not fit -- a value longer than a page, or more rows than there is room for --
/// is refused.
///
/// What the values *mean* is not known here. A `Permit` for every token an account will
/// ever hold reads as a spender, a number and a deadline, and the person has to know that
/// is what a permit is.
#[inline(never)]
pub(crate) fn host_sign_typed(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut crate::ui::Ui<'_>,
    blob: &[u8],
    key: &catcard_wallet::hostkeys::KeyPath,
    ticket: u32,
) -> Result<(Who, [u8; catcard_evm::personal::SIG_LEN]), crate::hostwallet::Outcome> {
    use crate::hostwallet::Outcome;
    use catcard_ui::scroll::ScrollView;
    const HEAD: &str = "Typed data";

    let typed = match catcard_evm::typed::Typed::parse(blob) {
        Ok(typed) => typed,
        Err(why) => return Err(Outcome::Refused(why.why())),
    };
    let signer = signer(gate, login, ui, "Typed data request", false, key)?;
    let Some(mut sheet) = Sheet::new() else {
        return Err(refuse(ui, HEAD, "not enough memory"));
    };
    let hashes = match typed_sheet(&typed, &mut sheet) {
        Ok(hashes) => hashes,
        Err(why) => return Err(refuse(ui, HEAD, why.why())),
    };
    sheet.label(format_args!("will be signed by"));
    sheet.value(format_args!("{}", signer.who));
    sheet.value(format_args!("{}", signer.path));
    sheet.label(format_args!("Ethereum, typed data (EIP-712)"));
    if sheet.lost {
        return Err(refuse(ui, HEAD, "too long to show here"));
    }

    // Once to count the pages and find out whether it can be shown at all, so nobody
    // reads three pages of something the fourth cannot hold; then for the person.
    let total = match pages(&sheet, HEAD, 0, &mut |_| true) {
        Ok(Some(total)) => total,
        Ok(None) => return Err(Outcome::Declined),
        Err(why) => return Err(refuse(ui, HEAD, why)),
    };
    let shown = pages(&sheet, HEAD, total, &mut |doc| {
        let mut view = ScrollView::build(
            doc,
            crate::display::SCREEN_W,
            crate::display::SCREEN_H,
            crate::display::FONTS,
        );
        crate::menu::scroll_choice(ui, &mut view)
    });
    match shown {
        Ok(Some(_)) => {}
        Ok(None) => return Err(Outcome::Declined),
        Err(why) => return Err(refuse(ui, HEAD, why)),
    }
    drop(sheet);
    if !crate::usbtask::host_alive(ticket) {
        return Err(Outcome::Declined);
    }
    let done = sign_digest(ui, HEAD, signer, &hashes.digest)?;
    Ok(done)
}
