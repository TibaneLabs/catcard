//! Key Teleport, on the Q1: the screens around [`catcard_wallet::teleport`].
//!
//! Utils → Backup → Key Teleport offers three things: **Receive** (show this device's `R`
//! code and receiver password, then scan the sender's `S`), **Send** (scan a receiver's
//! `R`, type its password, pick what to send, show `S` and the teleport password), and
//! **Multisig PSBT** (send a PSBT to a co-signer of a registered multisig wallet as an
//! `E` code). A teleport code caught by Scan QR anywhere, or tapped in over NFC as a
//! `keyteleport.com` link, lands here too ([`scanned`], [`received_text`]).
//!
//! The protocol is stock's, byte for byte, so this interoperates with a stock Q1; what it
//! does and does not protect is in `docs/KEY-TELEPORT.md` and at the top of the protocol
//! module. The warnings are stock's, from hw-reference/help-and-warning-screens.md §18.
//!
//! # Where the receiver key is kept
//!
//! In the wallet settings under [`KTRX_KEY`] (`cat_ktrx`, not stock's `ktrx`: ours is
//! our own name, like every other key this firmware writes), as lowercase hex -- the
//! value shape stock uses. Kept until a receive opens, so a sender's payload built for it
//! stays valid across failed attempts, and cleared the moment one does, **before** what
//! arrived is put anywhere: landing a seed changes the wallet in force, and with it which
//! settings file a later clear would write into. Source: key-teleport-protocol.md §6 [C]
//!
//! # Where the bytes are
//!
//! A scanned code lands in PSRAM through the scanner's lease, and it is opened there in
//! place -- a PSBT or a backup can be larger than the heap wants to give. Everything that
//! is not a PSBT is then copied into a heap block that wipes itself, and the PSRAM range
//! is zeroed through the staging driver before the lease goes back.

use catcard_callgate::Callgate;
use catcard_callgate::pin::{SECRET_LEN, bip39_entropy, encode_bip39, encode_xprv, xprv_parts};
use catcard_settings::store::{self, SCRATCH};
use catcard_ui::scroll::Line as Row;
use catcard_wallet::bip32::{ChildNumber, ExtendedPrivKey, HARDENED_OFFSET};
use catcard_wallet::teleport::{self as kt, Dtype, Key32, Wire};
use core::fmt::Write as _;
use zeroize::{Zeroize as _, Zeroizing};

use crate::menu::{self, Working};
use crate::ui::Ui;

const HEAD: &str = "Key Teleport";

/// Where the receiver's private key waits between attempts. **Not** stock's `ktrx`.
/// Source for the value shape (lowercase hex of the key): key-teleport-protocol.md §6 [C]
pub(crate) const KTRX_KEY: &str = "cat_ktrx";

/// PBKDF2 rounds between redraws: a fixed count, never anything derived from a key.
const STRETCH_SLICE: u32 = 250;

/// The largest body this device builds to send: a full backup (4 KiB) or the notes list
/// as the notes export writes it, whichever is more, with room for the framing.
const SEND_MAX: usize = 8 * 1024;

/// Where the body starts in a send buffer: after the sender key, then the dtype byte.
const TX_BODY_AT: usize = kt::PUBKEY_LEN;

// ---------------------------------------------------------------------------
// The menu
// ---------------------------------------------------------------------------

/// Utils → Backup → Key Teleport.
pub(crate) fn screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    const ROWS: &[&str] = &["Receive", "Send", "Multisig PSBT"];
    loop {
        match menu::pick_row(ui, HEAD, "between two Q1s", ROWS) {
            Some(0) => receive_start(gate, login, ui),
            Some(1) => send_start(gate, login, ui),
            Some(2) => psbt_send(gate, login, ui),
            _ => return,
        }
    }
}

// ---------------------------------------------------------------------------
// Receive
// ---------------------------------------------------------------------------

/// Start (or resume) a receive: the `R` code and the receiver password.
#[inline(never)]
fn receive_start(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    if crate::policy::hobbled() {
        // Source: help-and-warning-screens.md §18 "hobbled mode restriction" [C]
        return say(ui, "spending policy: only", "a multisig PSBT may come in");
    }
    let key = match load_ktrx(gate, login, ui) {
        Some(k) => {
            // Source: help-and-warning-screens.md §18 "Resume an incomplete teleport" [C]
            const ROWS: &[&str] = &["Keep it: same code", "Scan the sender now", "Start over"];
            match menu::pick_row(ui, HEAD, "a receive did not finish", ROWS) {
                Some(0) => k,
                Some(1) => return scan_now(gate, login, ui),
                Some(2) => match new_rx_key(gate, login, ui) {
                    Some(k) => k,
                    None => return,
                },
                _ => return,
            }
        }
        None => match new_rx_key(gate, login, ui) {
            Some(k) => k,
            None => return,
        },
    };
    let code = match crate::keywork::run(|kw| kt::rx_code(&key, kw)) {
        Ok(c) => c,
        Err(_) => return say(ui, "the receiver key", "is not usable"),
    };
    drop(key);

    let mut spaced: heapless::String<12> = heapless::String::new();
    let d = code.digits_str();
    let _ = write!(spaced, "{} {}", &d[..4], &d[4..]);
    loop {
        let rows = [
            Row::title(HEAD),
            Row::body("Receiver password:").small(),
            Row::body(&spaced).large().centered(),
            Row::body("Read it to the sender, then let them scan the code.").wrapped(),
            Row::item("Show the code", 0),
            Row::item("Scan the sender's code", 1),
            Row::item("Done for now", 2),
        ];
        match menu::show_doc(ui, &rows, false, false) {
            menu::DocExit::Selected(0) => crate::qrshow::animate_bbqr_padded(
                ui,
                "Receiver code",
                &code.payload,
                file_type(Wire::Rx),
            ),
            menu::DocExit::Selected(1) => return scan_now(gate, login, ui),
            _ => return,
        }
    }
}

/// A fresh receiver key, kept in the settings for a resume. `None` after saying why not.
fn new_rx_key(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) -> Option<Zeroizing<[u8; 32]>> {
    let key = random_key(ui)?;
    let mut hex = Zeroizing::new([0u8; 66]);
    hex[0] = b'"';
    for (i, b) in key.iter().enumerate() {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        hex[1 + 2 * i] = HEX[(b >> 4) as usize];
        hex[2 + 2 * i] = HEX[(b & 15) as usize];
    }
    hex[65] = b'"';
    let text = core::str::from_utf8(&hex[..]).unwrap_or("\"\"");
    if let Err(why) = save_setting(gate, login, ui, text) {
        // A receive that cannot be resumed still works, as long as it finishes now.
        crate::catlog!("teleport: receiver key not kept: {}", why);
        menu::message(
            ui.panel,
            HEAD,
            "cannot keep this key:",
            "finish before leaving",
        );
        menu::wait_for_any_key(ui);
    }
    Some(key)
}

/// Scan the sender's code from the Receive screen.
fn scan_now(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    let Some((lease, range, wire)) = scan_to_psram(ui, "Scan sender") else {
        return;
    };
    match wire {
        Some(w @ (Wire::Tx | Wire::Psbt)) => scanned(gate, login, ui, lease, range, w),
        _ => {
            wipe(lease, range.end);
            say(ui, "that is not a sender's", "teleport code")
        }
    }
}

/// A teleport code caught by the scanner: `lease` holds it at `range`.
pub(crate) fn scanned(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    mut lease: crate::psram::Lease,
    range: core::ops::Range<usize>,
    wire: Wire,
) {
    crate::catlog!("teleport: {} bytes of {}", range.len(), wire.label());
    match wire {
        Wire::Rx => {
            let got: Option<[u8; kt::PUBKEY_LEN]> = lease.bytes()[range.clone()].try_into().ok();
            wipe(lease, range.end);
            match got {
                Some(r) => send_to(gate, login, ui, &r),
                None => say(ui, "that receiver code", "is damaged"),
            }
        }
        Wire::Tx => open_tx(gate, login, ui, lease, range),
        Wire::Psbt => open_psbt(gate, login, ui, lease, range),
    }
}

/// A teleport link read off the NFC tag: a single part, decoded into PSRAM and opened as
/// a scanned one is.
pub(crate) fn received_text(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    text: &str,
) {
    use catcard_upgrade::StagingArea as _;

    // Decoded in the heap -- a tag holds at most eight kilobytes -- and written into PSRAM
    // through the paced driver, where it is opened as a scanned code is.
    let Some(mut held) = crate::heap::take(text.len()) else {
        return say(ui, "not enough memory", "");
    };
    let (wire, n) = match kt::parse_short(text, held.bytes()) {
        Ok(got) => got,
        Err(_) => return say(ui, "that teleport link", "is damaged"),
    };
    let lease = match crate::psram::take(crate::psram::Use::AnimatedQr) {
        Ok(l) => l,
        Err(why) => return say(ui, why.message(), ""),
    };
    let Ok(mut area) = crate::staging::area_from(lease) else {
        held.bytes().zeroize();
        return say(ui, "no staging area", "");
    };
    let written = area.write(0, &held.bytes()[..n]);
    held.bytes().zeroize();
    let at = area.image_at();
    let lease = area.into_lease();
    if written.is_err() {
        wipe(lease, at + n);
        return say(ui, "could not stage it", "");
    }
    scanned(gate, login, ui, lease, at..at + n, wire);
}

/// Open an `S` payload with the kept receiver key, then land what it holds.
#[inline(never)]
fn open_tx(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    mut lease: crate::psram::Lease,
    range: core::ops::Range<usize>,
) {
    if crate::policy::hobbled() {
        wipe(lease, range.end);
        return say(ui, "spending policy: only", "a multisig PSBT may come in");
    }
    let Some(key) = load_ktrx(gate, login, ui) else {
        wipe(lease, range.end);
        // Source: help-and-warning-screens.md §18 "not expecting a teleport" [C]
        return say(ui, "not expecting a teleport:", "start Receive first");
    };
    let sender = match kt::split_tx(&lease.bytes()[range.clone()]) {
        Ok((s, _)) => s,
        Err(_) => {
            wipe(lease, range.end);
            return say(ui, "the code is damaged:", "the sender must start over");
        }
    };
    let sealed = range.start + kt::PUBKEY_LEN..range.end;
    let _busy = menu::blocking_screen(ui.panel, HEAD, "opening");
    let opened = crate::keywork::run(|kw| {
        let session = kt::ecdh(&key, &sender, kw)?;
        let b1 = kt::open_outer(&session, &mut lease.bytes()[sealed.clone()])?;
        Ok::<_, kt::Error>((session, b1))
    });
    drop(key);
    let (session, b1) = match opened {
        Ok(o) => o,
        Err(_) => {
            wipe(lease, range.end);
            // Source: help-and-warning-screens.md §18 "damaged QR" [C]
            return say(ui, "not for this receiver,", "or damaged: resend");
        }
    };
    let inner = sealed.start..sealed.start + b1;
    finish_receive(gate, login, ui, lease, range.end, inner, &session, true);
}

/// Open an `E` payload by trying every co-signer of every registered multisig wallet
/// this device is in, then hand the PSBT to the signer.
/// Source: key-teleport-protocol.md §1b `kt_search_rxkey` [C]
#[inline(never)]
fn open_psbt(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    mut lease: crate::psram::Lease,
    range: core::ops::Range<usize>,
) {
    let ri = match kt::split_psbt(&lease.bytes()[range.clone()]) {
        Ok((ri, _)) => ri,
        Err(_) => {
            wipe(lease, range.end);
            return say(ui, "the code is damaged:", "the sender must start over");
        }
    };
    let sealed = range.start + kt::RI_LEN..range.end;
    let master = match menu::master_quietly(gate, login, ui.panel, HEAD) {
        Ok(m) => m,
        Err(why) => {
            wipe(lease, range.end);
            return say(ui, why, "");
        }
    };
    let wallets = crate::msimport::registered(gate, login, ui.panel);
    if wallets.is_empty() {
        wipe(lease, range.end);
        // Source: help-and-warning-screens.md §18 "no multisig wallet" [C]
        return say(ui, "a PSBT needs a multisig", "wallet: import it first");
    }
    let mut busy = Working::seed(ui.panel, HEAD, "finding the co-signer");
    let mut found: Option<(Key32, usize)> = None;
    for w in wallets.iter() {
        let try_one = crate::keywork::run(|kw| {
            let ours = catcard_wallet::multisig::our_cosigner(w, &master, kw).ok()??;
            let leg = derive_origin(&master, w.cosigners()[ours].origin(), kw)?;
            let mine = kt::psbt_leg_key(&leg, ri, kw).ok()?;
            for (j, c) in w.cosigners().iter().enumerate() {
                if j == ours {
                    continue;
                }
                let Ok(his) = kt::psbt_rx_pubkey(&c.xpub, ri) else {
                    continue;
                };
                let Ok(session) = kt::ecdh(&mine, &his, kw) else {
                    continue;
                };
                if let Ok(b1) = kt::open_outer(&session, &mut lease.bytes()[sealed.clone()]) {
                    return Some((session, b1));
                }
            }
            None
        });
        busy.tick(ui.panel);
        if try_one.is_some() {
            found = try_one;
            break;
        }
    }
    drop(master);
    let Some((session, b1)) = found else {
        wipe(lease, range.end);
        return say(ui, "no co-signer here sent", "this, or it is damaged");
    };
    let inner = sealed.start..sealed.start + b1;
    finish_receive(gate, login, ui, lease, range.end, inner, &session, false);
}

/// The inner layer and what comes out of it, for both kinds of receive.
///
/// `b1` is where the outer layer's plaintext sits in the lease; `kept_key` says whether a
/// kept receiver key is to be cleared (an `S` receive) or there is none (`E`).
#[allow(clippy::too_many_arguments)]
fn finish_receive(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    mut lease: crate::psram::Lease,
    end: usize,
    b1: core::ops::Range<usize>,
    session: &Key32,
    kept_key: bool,
) {
    // The teleport password, as often as it takes: a wrong one leaves the bytes as they
    // were, and the owner may simply have mistyped.
    let body_len = loop {
        let Some(noid) = ask_noid(ui) else {
            wipe(lease, end);
            return;
        };
        let inner = stretch(ui, session, &noid);
        let got = crate::keywork::run(|_| kt::open_inner(&inner, &mut lease.bytes()[b1.clone()]));
        match got {
            Ok(n) => break n,
            Err(_) => {
                menu::ask(
                    ui.panel,
                    "Wrong password",
                    "the teleport password",
                    "is not that: again?",
                );
                if !menu::confirmed(ui) {
                    wipe(lease, end);
                    return;
                }
            }
        }
    };
    if body_len == 0 {
        wipe(lease, end);
        return say(ui, "nothing came through", "");
    }
    crate::catlog!("teleport: opened, {} bytes", body_len);
    // Opened: the kept key has done its job. Cleared now, while the wallet whose settings
    // hold it is still the one in force -- see the module documentation.
    if kept_key {
        clear_ktrx(gate, login, ui);
    }

    let at = b1.start;
    let dtype = Dtype::from_byte(lease.bytes()[at]);
    let data = at + 1..at + body_len;
    // Source: help-and-warning-screens.md §18 "hobbled mode restriction" [C]
    if crate::policy::hobbled() && dtype != Some(Dtype::Psbt) {
        wipe(lease, end);
        return say(ui, "spending policy: only", "a multisig PSBT may come in");
    }
    match dtype {
        Some(Dtype::Psbt) => return sign_received(gate, login, ui, lease, end, data),
        None => {
            wipe(lease, end);
            return say(ui, "this teleport holds", "something unknown here");
        }
        _ => {}
    }
    // Everything else is small: out of PSRAM into a block that wipes itself, and the
    // PSRAM range zeroed before any question is asked.
    let Some(mut held) = crate::heap::take(data.len().max(1)) else {
        wipe(lease, end);
        return say(ui, "not enough memory", "");
    };
    let n = data.len();
    held.bytes()[..n].copy_from_slice(&lease.bytes()[data]);
    wipe(lease, end);
    land(
        gate,
        login,
        ui,
        dtype.unwrap_or(Dtype::Secret),
        &held.bytes()[..n],
    );
    held.bytes().zeroize();
}

/// Put a received body where the matching import puts it.
fn land(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    dtype: Dtype,
    data: &[u8],
) {
    match dtype {
        Dtype::Secret => {
            let Some(stash) = kt::stash_from_wire(data) else {
                return say(ui, "the secret in it", "is damaged");
            };
            land_stash(gate, login, ui, &stash);
        }
        Dtype::Xprv => {
            let stash = crate::keywork::run(|kw| {
                kt::xprv_from_wire(data, kw)
                    .ok()
                    .map(|k| Zeroizing::new(encode_xprv(&k.chain_code, k.secret_bytes())))
            });
            match stash {
                Some(s) => land_stash(gate, login, ui, &s),
                None => say(ui, "the XPRV in it", "does not parse"),
            }
        }
        Dtype::Notes => match core::str::from_utf8(data) {
            Ok(text) if text.trim_start().starts_with('[') => {
                crate::notes::merge_received(gate, login, ui, text)
            }
            _ => say(ui, "the notes in it", "are not a list"),
        },
        Dtype::Vault => match core::str::from_utf8(data) {
            Ok(text) => crate::vault::keep_received(gate, login, ui, text),
            Err(_) => say(ui, "the vault entry", "is not text"),
        },
        Dtype::Backup => crate::backup::teleport_received(gate, login, ui, data),
        Dtype::Psbt => {}
    }
}

/// A received secret: this device's seed if it has none, otherwise a temporary seed.
fn land_stash(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    stash: &[u8; SECRET_LEN],
) {
    let what = match kt::stash_kind(stash[0]) {
        Some(kt::StashKind::Words(12)) => "12 words",
        Some(kt::StashKind::Words(18)) => "18 words",
        Some(kt::StashKind::Words(_)) => "24 words",
        Some(kt::StashKind::Xprv) => "an XPRV",
        Some(kt::StashKind::Raw(_)) => "a raw master secret",
        None => return say(ui, "the secret in it", "is not a kind known here"),
    };
    let mut xfp: heapless::String<16> = heapless::String::new();
    if let Some([a, b, c, d]) = crate::backup::fingerprint_of(stash) {
        let _ = write!(xfp, "XFP {a:02X}{b:02X}{c:02X}{d:02X}");
    }
    if !crate::key::stored_wallet(login) {
        menu::ask(ui.panel, "Use as this seed?", what, &xfp);
        if !menu::confirmed(ui) {
            return;
        }
        let res = crate::backup::store_secret(gate, login, ui, stash);
        match res {
            Ok(()) => menu::message(ui.panel, "Seed stored", what, &xfp),
            Err(why) => menu::message(ui.panel, "Not stored", why, "any key to go back"),
        }
        return menu::wait_for_any_key(ui);
    }
    menu::ask(ui.panel, "Work in this?", what, "the stored seed stays");
    if !menu::confirmed(ui) {
        return;
    }
    let loaded = if let Some(entropy) = bip39_entropy(stash) {
        crate::key::set_temporary(entropy, "Teleport")
    } else if let Some((chain_code, key)) = xprv_parts(stash) {
        crate::key::set_temporary_xprv(chain_code, key, "Teleport")
    } else {
        false
    };
    if loaded {
        menu::message(ui.panel, "Temporary seed", &xfp, "now in force");
    } else {
        menu::message(ui.panel, HEAD, "that secret cannot be", "a temporary seed");
    }
    menu::wait_for_any_key(ui);
}

/// A received PSBT, in the lease at `data`: moved to the front and signed as a scanned
/// one is.
fn sign_received(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    mut lease: crate::psram::Lease,
    end: usize,
    data: core::ops::Range<usize>,
) {
    // A word-aligned start: `data` begins one byte past the dtype and is not.
    let base = (data.start - data.start % 4).saturating_sub(4);
    let len = data.len();
    let all = &mut lease.bytes()[base..];
    all.copy_within(data.start - base..data.start - base + len, 0);
    let half = (all.len() / 2) & !3;
    if len > half {
        wipe(lease, end);
        return say(ui, "too large to sign", "");
    }
    let (buf, spare) = all.split_at_mut(half);
    crate::signtx::review_and_sign(
        gate,
        login,
        ui,
        buf,
        spare,
        len,
        &mut crate::signtx::Sink::Files {
            dest: &crate::signtx::SignDest::SINGLE,
            storage: crate::menu::Storage::Sd,
        },
    );
}

// ---------------------------------------------------------------------------
// Send
// ---------------------------------------------------------------------------

/// Key Teleport → Send: scan the receiver's code first.
fn send_start(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    let Some((lease, range, wire)) = scan_to_psram(ui, "Scan receiver") else {
        return;
    };
    match wire {
        Some(w) => scanned(gate, login, ui, lease, range, w),
        None => {
            wipe(lease, range.end);
            say(ui, "that is not a", "teleport code")
        }
    }
}

/// The owner has scanned a receiver's `R`: its password, the warning, and the choice.
#[inline(never)]
fn send_to(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    r: &[u8; kt::PUBKEY_LEN],
) {
    let rx_pub = loop {
        let Some(num) = menu::ask_number(ui, HEAD, None, "receiver password", "8 digits") else {
            return;
        };
        if num < 100_000_000
            && let Some(pk) = kt::decrypt_rx_pubkey(&kt::format_code(num), r)
        {
            break pk;
        }
        // Only about half of wrong ones are caught here; the rest the receiver refuses.
        // Source: help-and-warning-screens.md §18 "incorrect teleport password" [C]
        menu::ask(
            ui.panel,
            "Incorrect password",
            "check the 8 digits",
            "try again?",
        );
        if !menu::confirmed(ui) {
            return;
        }
    };
    // Source: help-and-warning-screens.md §18 "Sender: after decoding" [C]
    menu::ask(
        ui.panel,
        "Ready to teleport",
        "the receiver gets FULL",
        "control of those funds",
    );
    if !menu::confirmed(ui) {
        return;
    }

    let Some(mut held) = crate::heap::take(SEND_MAX) else {
        return say(ui, "not enough memory", "");
    };
    let buf = held.bytes();
    let room = buf.len() - kt::SEAL_OVERHEAD;
    let Some((dtype, n)) = pick_payload(gate, login, ui, &mut buf[TX_BODY_AT + 1..room]) else {
        buf.zeroize();
        return;
    };
    buf[TX_BODY_AT] = dtype.byte();
    let body_len = 1 + n;

    let Some(my_priv) = random_key(ui) else {
        buf.zeroize();
        return;
    };
    let Some(noid) = random_noid(ui) else {
        buf.zeroize();
        return;
    };
    let _busy = menu::blocking_screen(ui.panel, HEAD, "sealing");
    let agreed = crate::keywork::run(|kw| {
        let me = kt::public_key(&my_priv, kw)?;
        let session = kt::ecdh(&my_priv, &rx_pub, kw)?;
        Ok::<_, kt::Error>((me, session))
    });
    drop(my_priv);
    let Ok((me, session)) = agreed else {
        buf.zeroize();
        return say(ui, "the receiver's key", "is not usable");
    };
    let inner = stretch(ui, &session, &noid);
    let sealed =
        crate::keywork::run(|_| kt::seal(&session, &inner, &mut buf[TX_BODY_AT..], body_len));
    drop(inner);
    drop(session);
    let Ok(sealed) = sealed else {
        buf.zeroize();
        return say(ui, "could not seal it", "");
    };
    buf[..kt::PUBKEY_LEN].copy_from_slice(&me);
    let total = kt::PUBKEY_LEN + sealed;
    present(ui, Wire::Tx, &buf[..total], &noid);
    buf.zeroize();
}

/// What to send, built into `out`. `None` when the owner backed out or it could not be
/// built (said on screen).
fn pick_payload(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    out: &mut [u8],
) -> Option<(Dtype, usize)> {
    let temp = !crate::key::is_root() || crate::passphrase::is_set();
    let mut rows: heapless::Vec<&str, 5> = heapless::Vec::new();
    let _ = rows.push("Master seed");
    if temp {
        let _ = rows.push("Temporary seed");
    }
    let _ = rows.push("Seed Vault entry");
    let _ = rows.push("Notes & passwords");
    let _ = rows.push("Full backup");
    let row = menu::pick_row(ui, HEAD, "what to send?", &rows)?;
    match rows[row] {
        "Master seed" => {
            // Sending the seed reveals it: in delta mode this erases it instead.
            crate::trickpin::seed_reveal(gate);
            let _busy = menu::reading_seed(ui.panel, HEAD);
            let pin_gate = crate::pinentry::BootloaderGate::new(gate);
            let stash = match login.fetch_secret(&pin_gate) {
                Ok(s) if s.iter().any(|b| *b != 0) => Zeroizing::new(s),
                Ok(mut s) => {
                    s.zeroize();
                    say(ui, "no seed is stored", "");
                    return None;
                }
                Err(_) => {
                    say(ui, "the seed would not", "come back");
                    return None;
                }
            };
            confirm_secret(ui, "Send master seed?", &stash)?;
            put_stash(ui, &stash, out)
        }
        "Temporary seed" => {
            let stash = in_force_stash(gate, login, ui)?;
            confirm_secret(ui, "Send this seed?", &stash)?;
            put_stash(ui, &stash, out)
        }
        "Seed Vault entry" => match crate::vault::pick_for_teleport(gate, login, ui, HEAD, out) {
            Ok(Some(n)) => {
                menu::ask(
                    ui.panel,
                    "Send this entry?",
                    "the receiver gets FULL",
                    "control of its funds",
                );
                menu::confirmed(ui).then_some((Dtype::Vault, n))
            }
            Ok(None) => None,
            Err(why) => {
                say(ui, why, "");
                None
            }
        },
        "Notes & passwords" => match crate::notes::pick_for_teleport(gate, login, ui, HEAD, out) {
            Ok(Some(n)) => Some((Dtype::Notes, n)),
            Ok(None) => None,
            Err(why) => {
                say(ui, why, "");
                None
            }
        },
        _ => {
            // Source: help-and-warning-screens.md §18 "Share complete backup" [C]
            let rows = [
                Row::title("Full backup"),
                Row::body(
                    "Sends the seed, multisig wallets, notes and passwords and every setting. \
                     The receiver gets full control of all the funds.",
                )
                .wrapped(),
                Row::body(
                    "The receiving Coldcard must be seed-wiped to install all of it; \
                     otherwise only the wallet loads, as a temporary seed.",
                )
                .wrapped()
                .small(),
                Row::item("Send it", 0),
            ];
            if !matches!(
                menu::show_doc(ui, &rows, false, false),
                menu::DocExit::Selected(0)
            ) {
                return None;
            }
            // A full backup carries the seed: in delta mode this erases it instead.
            crate::trickpin::seed_reveal(gate);
            let n = crate::backup::teleport_body(gate, login, ui, HEAD, out)?;
            Some((Dtype::Backup, n))
        }
    }
}

/// The key in force as a stash: its words, or its master as an XPRV.
fn in_force_stash(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) -> Option<Zeroizing<[u8; SECRET_LEN]>> {
    if crate::key::loaded() == Some(crate::key::Loaded::Wif) {
        say(ui, "a WIF key cannot", "be teleported");
        return None;
    }
    // A passphrase wallet has no words that make it, so it goes as its master.
    if !crate::passphrase::is_set()
        && let Ok((mut ent, len)) = menu::seed_entropy(gate, login, ui.panel, HEAD)
    {
        let s = encode_bip39(&ent[..len]).ok().map(Zeroizing::new);
        ent.zeroize();
        return s;
    }
    let master = match menu::master_quietly(gate, login, ui.panel, HEAD) {
        Ok(m) => m,
        Err(why) => {
            say(ui, why, "");
            return None;
        }
    };
    Some(Zeroizing::new(encode_xprv(
        &master.chain_code,
        master.secret_bytes(),
    )))
}

/// Stock's "share master secret" warning, with the fingerprint and what kind it is.
/// Source: help-and-warning-screens.md §18 "Share master secret over teleport" [C]
fn confirm_secret(ui: &mut Ui<'_>, head: &str, stash: &[u8; SECRET_LEN]) -> Option<()> {
    let mut xfp: heapless::String<24> = heapless::String::new();
    let kind = match kt::stash_kind(stash[0]) {
        Some(kt::StashKind::Words(n)) => {
            let _ = write!(xfp, "{n} words");
            ""
        }
        Some(kt::StashKind::Xprv) => "XPRV",
        Some(kt::StashKind::Raw(_)) => "raw secret",
        None => "",
    };
    let _ = xfp.push_str(kind);
    if let Some([a, b, c, d]) = crate::backup::fingerprint_of(stash) {
        let _ = write!(xfp, " {a:02X}{b:02X}{c:02X}{d:02X}");
    }
    menu::ask(ui.panel, head, &xfp, "gives FULL control");
    menu::confirmed(ui).then_some(())
}

/// A stash as an `s` body: trailing zeros off. Source: key-teleport-protocol.md §4b [C]
fn put_stash(ui: &mut Ui<'_>, stash: &[u8; SECRET_LEN], out: &mut [u8]) -> Option<(Dtype, usize)> {
    let n = kt::stash_wire_len(stash);
    let Some(dest) = out.get_mut(..n) else {
        say(ui, "no room", "");
        return None;
    };
    dest.copy_from_slice(&stash[..n]);
    Some((Dtype::Secret, n))
}

// ---------------------------------------------------------------------------
// Multisig PSBT
// ---------------------------------------------------------------------------

/// Key Teleport → Multisig PSBT: a PSBT off the card or the disk, to one co-signer.
///
/// Stock's `Teleport Multisig PSBT`. The keys are the wallets' own, derived at
/// `…/20250317/ri`, so no receiver code is scanned; the teleport password still is read
/// out. Source: key-teleport-protocol.md §1b, §4c `E` [C]
#[inline(never)]
fn psbt_send(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    const H: &str = "Teleport PSBT";
    /// Where the PSBT is read to: `ri` at 3..7, the dtype at 7, the PSBT from 8, which is
    /// word-aligned for the reader and the converter.
    const PSBT_AT: usize = 8;
    let Some(storage) = menu::pick_storage(ui, H) else {
        return;
    };
    let Some(path) = menu::browse_storage(
        ui,
        storage,
        "Pick a .psbt",
        Some("psbt"),
        menu::Browse::File,
    ) else {
        return;
    };
    let mut lease = match crate::psram::take(crate::psram::Use::Signing) {
        Ok(l) => l,
        Err(why) => return say(ui, why.message(), ""),
    };
    let all = lease.bytes();
    let half = (all.len() / 2) & !3;
    let (buf, spare) = all.split_at_mut(half);
    menu::card_wait(ui.panel, H, "reading");
    let len = match crate::signtx::read_source_file(storage, &path, &mut buf[PSBT_AT..])
        .and_then(|n| crate::signtx::as_psbt_bytes(&mut buf[PSBT_AT..], n, spare))
    {
        Ok(n) => n,
        Err(why) => return say(ui, why, ""),
    };
    if PSBT_AT + len + kt::SEAL_OVERHEAD > buf.len() {
        return say(ui, "too large to send", "");
    }

    // Every co-signer of every wallet this device is in, but itself.
    let master = match menu::master_quietly(gate, login, ui.panel, H) {
        Ok(m) => m,
        Err(why) => return say(ui, why, ""),
    };
    let wallets = crate::msimport::registered(gate, login, ui.panel);
    let mut targets: heapless::Vec<(usize, usize, usize), 32> = heapless::Vec::new();
    let mut labels: heapless::Vec<heapless::String<32>, 32> = heapless::Vec::new();
    for (wi, w) in wallets.iter().enumerate() {
        let ours = crate::keywork::run(|kw| catcard_wallet::multisig::our_cosigner(w, &master, kw));
        let Ok(Some(ours)) = ours else {
            continue;
        };
        for (j, c) in w.cosigners().iter().enumerate() {
            if j == ours {
                continue;
            }
            let [a, b, cc, d] = c.fingerprint;
            let mut l: heapless::String<32> = heapless::String::new();
            let _ = write!(l, "{a:02X}{b:02X}{cc:02X}{d:02X}");
            if wallets.len() > 1 {
                let _ = write!(l, " (wallet {})", wi + 1);
            }
            if targets.push((wi, ours, j)).is_err() || labels.push(l).is_err() {
                break;
            }
        }
    }
    if targets.is_empty() {
        // Source: help-and-warning-screens.md §18 "no multisig wallet" [C]
        return say(ui, "no multisig wallet here", "has this device in it");
    }
    let refs: heapless::Vec<&str, 32> = labels.iter().map(|l| l.as_str()).collect();
    let Some(pick) = menu::pick_row(ui, H, "send to which co-signer?", &refs) else {
        return;
    };
    let (wi, ours, theirs) = targets[pick];
    let w = &wallets[wi];

    let mut r = [0u8; 4];
    if ui.protocol.generate(&mut r).is_err() {
        return say(ui, "no random value", "");
    }
    let ri = kt::ri_from(r);
    let Some(noid) = random_noid(ui) else {
        return;
    };
    let _busy = menu::blocking_screen(ui.panel, H, "sealing");
    let session = crate::keywork::run(|kw| {
        let leg =
            derive_origin(&master, w.cosigners()[ours].origin(), kw).ok_or(kt::Error::BadKey)?;
        let mine = kt::psbt_leg_key(&leg, ri, kw)?;
        let his = kt::psbt_rx_pubkey(&w.cosigners()[theirs].xpub, ri)?;
        kt::ecdh(&mine, &his, kw)
    });
    drop(master);
    let Ok(session) = session else {
        return say(ui, "the keys would not", "derive");
    };
    let inner = stretch(ui, &session, &noid);
    buf[PSBT_AT - 1] = Dtype::Psbt.byte();
    let sealed =
        crate::keywork::run(|_| kt::seal(&session, &inner, &mut buf[PSBT_AT - 1..], 1 + len));
    let Ok(sealed) = sealed else {
        return say(ui, "could not seal it", "");
    };
    buf[PSBT_AT - 1 - kt::RI_LEN..PSBT_AT - 1].copy_from_slice(&ri.to_be_bytes());
    let start = PSBT_AT - 1 - kt::RI_LEN;
    present(
        ui,
        Wire::Psbt,
        &buf[start..start + kt::RI_LEN + sealed],
        &noid,
    );
}

/// `master` down a multisig origin path, as `multisig::our_cosigner` walks it.
fn derive_origin(
    master: &ExtendedPrivKey,
    origin: &[u32],
    kw: &catcard_wallet::KeyWork,
) -> Option<ExtendedPrivKey> {
    let mut key = master.clone();
    for &step in origin {
        let child = if step & HARDENED_OFFSET != 0 {
            ChildNumber::hardened(step & !HARDENED_OFFSET)
        } else {
            ChildNumber::normal(step)
        };
        key = key.derive_child(child.ok()?, kw).ok()?;
    }
    Some(key)
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

/// Show what was sealed: the teleport password, then the code, as often as asked, and the
/// NFC link where it fits.
fn present(ui: &mut Ui<'_>, wire: Wire, payload: &[u8], noid: &[u8; kt::NOID_LEN]) {
    let text = kt::noid_text(noid);
    let pw = core::str::from_utf8(&text).unwrap_or("");
    let mut spaced: heapless::String<12> = heapless::String::new();
    let _ = write!(spaced, "{} {}", &pw[..4], &pw[4..]);
    let nfc = payload.len() < kt::NFC_SIZE_LIMIT && catcard_board::BOARD.nfc.is_some();
    loop {
        let mut rows: heapless::Vec<Row, 8> = heapless::Vec::new();
        let _ = rows.push(Row::title(HEAD));
        let _ = rows.push(Row::body("Teleport password:").small());
        let _ = rows.push(Row::body(&spaced).large().centered().secret());
        let _ = rows.push(
            Row::body("Tell the receiver this password, then let them scan the code.").wrapped(),
        );
        let _ = rows.push(Row::item("Show the code", 0));
        if nfc {
            let _ = rows.push(Row::item("Share by NFC", 1));
        }
        let _ = rows.push(Row::item("Done", 2));
        match menu::show_doc(ui, &rows, false, false) {
            menu::DocExit::Selected(0) => {
                crate::qrshow::animate_bbqr_padded(ui, wire.label(), payload, file_type(wire))
            }
            menu::DocExit::Selected(1) => share_nfc(ui, wire, payload),
            menu::DocExit::Selected(2) => return,
            _ => {
                menu::ask(ui.panel, HEAD, "leave? the code is", "not shown again");
                if menu::confirmed(ui) {
                    return;
                }
            }
        }
    }
}

/// The NFC form: a `keyteleport.com` link to the page that shows it as a QR.
fn share_nfc(ui: &mut Ui<'_>, wire: Wire, payload: &[u8]) {
    let need = kt::nfc_url_len(payload.len());
    let Some(mut held) = crate::heap::take(need) else {
        return say(ui, "not enough memory", "");
    };
    let Ok(n) = kt::nfc_url(wire, payload, held.bytes()) else {
        return say(ui, "too big for NFC", "");
    };
    let text = core::str::from_utf8(&held.bytes()[..n]).unwrap_or("");
    crate::nfc::share_link(ui, HEAD, text, "to get the code");
}

/// The teleport password, typed. `None` when the owner leaves.
fn ask_noid(ui: &mut Ui<'_>) -> Option<[u8; kt::NOID_LEN]> {
    loop {
        let mut entry = crate::passphrase::read(ui, "Teleport password")?;
        let got = kt::noid_parse(entry.as_str());
        entry.clear();
        if let Some(k) = got {
            return Some(k);
        }
        menu::ask(
            ui.panel,
            "Not a password",
            "8 letters and digits",
            "try again?",
        );
        if !menu::confirmed(ui) {
            return None;
        }
    }
}

/// The inner key, with the bar moving between slices of a fixed size.
fn stretch(ui: &mut Ui<'_>, session: &Key32, noid: &[u8; kt::NOID_LEN]) -> Key32 {
    let mut busy = Working::seed(ui.panel, HEAD, "stretching the password");
    let mut s = crate::keywork::run(|kw| kt::Stretch::begin(session, noid, kw));
    while !crate::keywork::run(|kw| s.step(STRETCH_SLICE, kw)) {
        busy.tick(ui.panel);
    }
    crate::keywork::run(|kw| s.finish(kw))
}

/// A private key from the protocol DRBG, in range. `None` after saying why not.
fn random_key(ui: &mut Ui<'_>) -> Option<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    // The chance of a value out of range is about 2^-128; the bound is only so a broken
    // generator cannot hold the screen forever.
    for _ in 0..8 {
        if ui.protocol.generate(&mut key[..]).is_err() {
            break;
        }
        if catcard_wallet::bip32::is_valid_secret(&key) {
            return Some(key);
        }
    }
    say(ui, "no random key", "");
    None
}

/// Five random bytes for the teleport password.
fn random_noid(ui: &mut Ui<'_>) -> Option<[u8; kt::NOID_LEN]> {
    let mut k = [0u8; kt::NOID_LEN];
    if ui.protocol.generate(&mut k).is_err() {
        say(ui, "no random value", "");
        return None;
    }
    Some(k)
}

/// A BBQr file type for a teleport code.
fn file_type(wire: Wire) -> catcard_bbqr::FileType {
    catcard_bbqr::FileType::from_char(wire.code()).unwrap_or(catcard_bbqr::FileType::BINARY)
}

/// Scan a code into PSRAM, as the Scan QR screen does. The lease, where the bytes are,
/// and the teleport kind its BBQr file type names, if any.
fn scan_to_psram(
    ui: &mut Ui<'_>,
    head: &str,
) -> Option<(crate::psram::Lease, core::ops::Range<usize>, Option<Wire>)> {
    let lease = match crate::psram::take(crate::psram::Use::AnimatedQr) {
        Ok(l) => l,
        Err(why) => {
            say(ui, why.message(), "");
            return None;
        }
    };
    let area = match crate::staging::area_from(lease) {
        Ok(a) => a,
        Err(_) => {
            say(ui, "no staging area", "");
            return None;
        }
    };
    let mut sink = crate::qrload::Staging::new(area);
    let got = crate::qrload::collect_any(ui, head, &mut sink);
    let area = sink.into_area();
    let got = match got {
        Ok(g) => g,
        Err(why) => {
            drop(area);
            if let Some(why) = why {
                say(ui, why, "");
            }
            return None;
        }
    };
    let base = area.image_at();
    let lease = area.into_lease();
    if got.compressed {
        wipe(lease, base + got.len);
        say(ui, "a compressed code is", "not a teleport");
        return None;
    }
    let wire = got.file_type.and_then(Wire::from_code);
    Some((lease, base..base + got.len, wire))
}

/// Zero the lease up to `end` through the staging driver, then let it go.
///
/// Through the driver rather than the slice, because a byte store into this part is not
/// reliable (see `crate::psram`); a wipe that may not have happened is the worst kind.
fn wipe(lease: crate::psram::Lease, end: usize) {
    use catcard_upgrade::StagingArea as _;
    let Ok(mut area) = crate::staging::area_from(lease) else {
        return;
    };
    // The area's offset zero is the lease's `image_at`; anything the teleport touched
    // below that (an NFC payload, a PSBT moved to the front) is covered by starting the
    // lease-side wipe at zero. Both halves: one pass over the area, and one below it.
    let at = area.image_at();
    let zeros = [0u8; 256];
    let mut off = 0usize;
    let above = end.saturating_sub(at);
    while off < above {
        let n = (above - off).min(zeros.len());
        if area.write(off as u32, &zeros[..n]).is_err() {
            break;
        }
        off += n;
    }
    let below = end.min(at);
    if below > 0 {
        let mut lease = area.into_lease();
        // Below the staging area there is no paced driver; word stores, which this part
        // takes reliably, through the slice's aligned words.
        let bytes = lease.bytes();
        let upto = below.next_multiple_of(4).min(bytes.len());
        for w in bytes[..upto].as_chunks_mut::<4>().0 {
            // SAFETY: an aligned word inside the lease's own region (the slice starts at
            // the PSRAM base, which is word-aligned), written as a whole word.
            unsafe { core::ptr::write_volatile(w.as_mut_ptr() as *mut u32, 0) };
        }
    }
}

// ---------------------------------------------------------------------------
// The kept receiver key
// ---------------------------------------------------------------------------

/// The receiver key a previous Receive left, if any.
fn load_ktrx(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) -> Option<Zeroizing<[u8; 32]>> {
    let key = crate::settings::wallet_key(gate, login, ui.panel, HEAD).ok()?;
    let mut held = crate::heap::take(SCRATCH)?;
    // SAFETY: the region is mapped and readable; nothing is written through this.
    let mut files = unsafe { crate::settings::Files::mount_read_only() }.ok()?;
    let n = store::read(&mut files, &key, held.bytes()).unwrap_or(0);
    let got = {
        let doc = catcard_settings::json::Doc::parse(&held.bytes()[..n]).ok();
        doc.and_then(|d| d.get_str(KTRX_KEY)).and_then(|hex| {
            let b = hex.as_bytes();
            if b.len() != 64 {
                return None;
            }
            let mut out = Zeroizing::new([0u8; 32]);
            for (i, pair) in b.as_chunks::<2>().0.iter().enumerate() {
                let hi = (pair[0] as char).to_digit(16)?;
                let lo = (pair[1] as char).to_digit(16)?;
                out[i] = (hi * 16 + lo) as u8;
            }
            catcard_wallet::bip32::is_valid_secret(&out).then_some(out)
        })
    };
    held.bytes().zeroize();
    got
}

/// Forget the kept receiver key: an empty string where it was.
fn clear_ktrx(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    if let Err(why) = save_setting(gate, login, ui, "\"\"") {
        crate::catlog!("teleport: receiver key not cleared: {}", why);
    }
}

fn save_setting(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    raw: &str,
) -> Result<(), &'static str> {
    let (Some(mut doc), Some(mut seal)) = (crate::heap::take(SCRATCH), crate::heap::take(SCRATCH))
    else {
        return Err("not enough memory");
    };
    let res = crate::settings::save_wallet(
        gate,
        login,
        ui,
        HEAD,
        (KTRX_KEY, raw),
        doc.bytes(),
        seal.bytes(),
    );
    doc.bytes().zeroize();
    seal.bytes().zeroize();
    res
}

fn say(ui: &mut Ui<'_>, a: &str, b: &str) {
    menu::message(
        ui.panel,
        HEAD,
        a,
        if b.is_empty() {
            "any key to go back"
        } else {
            b
        },
    );
    menu::wait_for_any_key(ui);
}
