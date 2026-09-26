//! Proof of reserves: reviewing and signing a BIP-322 `pof` PSBT as a proof, not a spend.
//!
//! A proof of reserves arrives as an ordinary PSBT ([`catcard_wallet::bip322::por`]):
//! BIP-322's `to_sign`, with the wallet's real outputs added as inputs, ready for a
//! signer. Put through the spend review it would look like the worst transaction there is
//! -- everything in, an `OP_RETURN` out, the balance to fees -- and be refused. It is not
//! one: input 0 spends `to_spend`, which spends an output no chain can hold, and every
//! signature is `SIGHASH_ALL` over it. So [`crate::signtx`] hands a PSBT of that shape
//! here before its review, and this screen says what the thing actually is: *a message,
//! N outputs, their total, nothing spent*.
//!
//! # The message is the owner's to supply
//!
//! `to_spend` commits to a hash of the message, not the message, and a PSBT has no field
//! for the text. So the owner types it -- it is the sentence they are attesting to, which
//! a person should have to look at before a device signs under it -- and the device
//! recomputes `to_spend` from that text and the challenge script, and requires its txid
//! to be input 0's outpoint. A wrong message, or a host that wrote a real outpoint where
//! `to_spend` should be, fails there and nothing is signed.
//!
//! # What is signed, and how
//!
//! Every input this wallet can sign -- the seed's keys, and the WIF store's on a board
//! that has one -- through the ordinary signer, under `SIGHASH_ALL` and nothing else
//! whatever the sighash policy says: a proof under `ANYONECANPAY` would not commit to
//! input 0, and would be a real transaction burning the coins. The signed PSBT is written
//! back as any signing writes one. When every input was ours the PSBT is finalised, checked
//! by the crate's own proof-of-funds verifier, and written beside it as an armoured signed
//! message whose signature is `pof` and the base64 of the finalised PSBT -- the form
//! BIP-322 gives a proof of funds, and the form `Sign → Verify` reads back.
//!
//! Source: BIP-322 §Full (Proof of Funds), §Types of Signatures [C];
//! hw-reference/firmware-features.md §6 "Proof of Reserves" [C].

use catcard_callgate::Callgate;
use catcard_wallet::bip32::ExtendedPrivKey;
use catcard_wallet::bip322::{self, full, por};
use catcard_wallet::psbtview::{self, SighashPolicy};
use catcard_wallet::{address, signer, signfile};
use core::fmt::Write as _;
use outscript::psbt::Psbt;

use crate::display;
use crate::menu::{self, Storage};
use crate::signtx::SignDest;
use crate::ui::Ui;

const HEAD: &str = "Proof of reserves";

/// Where the finished proof goes for a single PSBT off the card: beside `SIGNED.PSB`.
const PROOF_NAME: &str = "/PROOF.TXT";

/// Most inputs signed in one pass: the verifier's bound, so a proof this signs is one it
/// can also check.
const MAX_INPUTS: usize = full::MAX_POF_INPUTS;

/// Longest path this builds for the proof file: the signing screen's own bound.
const PATH_MAX: usize = 160;

/// Is this PSBT shaped like a proof of reserves? The cheap test [`crate::signtx`] asks
/// before deciding which review a PSBT gets; [`review`] then settles whether it is one.
pub(crate) fn is_proof_of_reserves(psbt: &Psbt<'_>) -> bool {
    por::is_proof(psbt)
}

/// Why the proof will not be signed, in the words a screen has.
fn refusal(r: por::Refusal, line: &mut heapless::String<40>) -> &str {
    let _ = match r {
        por::Refusal::NotAProof => write!(line, "not a proof of reserves"),
        por::Refusal::BadToSpend => write!(line, "input 0 is not a to_spend"),
        por::Refusal::TooManyInputs { inputs } => write!(line, "{inputs} inputs: too many"),
        por::Refusal::MissingUtxo { input } => write!(line, "input {input} has no amount"),
        por::Refusal::Sighash { input, .. } => write!(line, "input {input}: not SIGHASH_ALL"),
        por::Refusal::WrongMessage => write!(line, "message does not match this proof"),
        por::Refusal::AlreadyFinal => write!(line, "already finalised"),
    };
    line.as_str()
}

/// Review the proof of reserves in `buf`, sign every input that is ours, and write back.
///
/// Takes the master key by value from the signing screen that unlocked it, and drops it
/// the moment the signatures are made. `spare` is the second working buffer, as for a
/// spend; the two alternate through the signatures and the finalisation.
#[allow(clippy::too_many_arguments)]
#[cfg_attr(feature = "board-mk3", allow(unused_variables))]
pub(crate) fn review(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    master: ExtendedPrivKey,
    fingerprint: [u8; 4],
    buf: &mut [u8],
    spare: &mut [u8],
    len: usize,
    dest: &SignDest<'_>,
    storage: Storage,
) {
    let psbt = match Psbt::parse(&buf[..len]) {
        Ok(p) => p,
        Err(_) => return say(ui, "PSBT is corrupt"),
    };
    let proof = match por::inspect(&psbt) {
        Ok(p) => p,
        Err(r) => {
            let mut line = heapless::String::new();
            let why = refusal(r, &mut line);
            crate::catlog!("proof: refused: {}", why);
            return say(ui, why);
        }
    };
    let network = crate::prefs::network();
    let mut addr_buf = [0u8; address::MAX_ADDRESS_LEN];
    let address = address::from_script(proof.challenge(), network, &mut addr_buf)
        .and_then(|n| core::str::from_utf8(&addr_buf[..n]).ok());

    // The message, typed. It is what the proof attests to, and the only check on the
    // PSBT's `to_spend` that does not take the host's word for anything.
    menu::message(
        ui.panel,
        HEAD,
        "this PSBT is a proof",
        "type the message it is of",
    );
    menu::wait_for_any_key(ui);
    let Some(typed) = crate::signmsg::read_message(ui, HEAD) else {
        return;
    };
    let text = typed.as_str();
    if text.is_empty() {
        return;
    }
    if let Err(r) = por::confirm_message(&proof, text.as_bytes()) {
        let mut line = heapless::String::new();
        let why = refusal(r, &mut line);
        crate::catlog!("proof: refused: {}", why);
        return say(ui, why);
    }

    // Which inputs are ours: the seed's keys, then the WIF store's.
    let mut ours = [0usize; MAX_INPUTS];
    #[cfg_attr(feature = "board-mk3", allow(unused_mut))]
    let mut signable =
        crate::keywork::run(|kw| psbtview::our_inputs(&psbt, &master, fingerprint, &mut ours, kw));
    #[cfg(not(feature = "board-mk3"))]
    let mut wif_keys: heapless::Vec<
        catcard_wallet::wif::WifKey,
        { catcard_settings::wifs::MAX_KEYS },
    > = heapless::Vec::new();
    #[cfg(not(feature = "board-mk3"))]
    {
        crate::wifstore::load_keys(gate, login, ui.panel, &mut wif_keys);
        let mut bare: heapless::Vec<[u8; 33], { catcard_settings::wifs::MAX_KEYS }> =
            heapless::Vec::new();
        crate::keywork::run(|kw| {
            for k in &wif_keys {
                if let Some(pk) = k.public_key(kw) {
                    let _ = bare.push(pk);
                }
            }
        });
        for k in &bare {
            let mut hits = [0usize; MAX_INPUTS];
            let m = psbtview::wif_inputs(&psbt, k, &mut hits);
            for &i in &hits[..m] {
                if signable < ours.len() && !ours[..signable].contains(&i) {
                    ours[signable] = i;
                    signable += 1;
                }
            }
        }
    }
    if signable == 0 {
        drop(master);
        return say(ui, "no input is ours");
    }

    if !confirm(ui, text, address, &proof, signable) {
        drop(master);
        return say(ui, "not signed");
    }

    // Sign, one input at a time, alternating buffers. `SIGHASH_ALL` only: `inspect`
    // refused anything else, and the signer is told to block it again here.
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
            signer::sign_input_under(
                &psbt,
                index,
                &master,
                fingerprint,
                SighashPolicy::Block,
                into,
                kw,
            )
        }) {
            Ok(n) => {
                core::mem::swap(&mut from, &mut into);
                at = n;
                signed += 1;
                done = true;
            }
            Err(e) => crate::catlog!("proof: input {} not a seed key: {:?}", index, e),
        }
        #[cfg(not(feature = "board-mk3"))]
        if !done {
            for k in &wif_keys {
                let psbt = match Psbt::parse(&from[..at]) {
                    Ok(p) => p,
                    Err(_) => break,
                };
                if let Ok(n) = crate::keywork::run(|kw| {
                    signer::sign_input_with_secret(
                        &psbt,
                        index,
                        k.secret(),
                        SighashPolicy::Block,
                        into,
                        kw,
                    )
                }) {
                    core::mem::swap(&mut from, &mut into);
                    at = n;
                    signed += 1;
                    done = true;
                    break;
                }
            }
        }
        if !done {
            crate::catlog!("proof: input {} refused by every key", index);
        }
        busy.tick(ui.panel);
    }
    drop(master);
    #[cfg(not(feature = "board-mk3"))]
    drop(wif_keys);

    if signed == 0 {
        return say(ui, "nothing could be signed");
    }

    let mut wait: heapless::String<24> = heapless::String::new();
    let _ = write!(wait, "writing to {}", storage.medium());
    menu::card_wait(ui.panel, HEAD, &wait);
    if let Err(why) = menu::write_storage_file(storage, dest.signed_name, &from[..at]) {
        crate::catlog!("proof: write failed: {}", why);
        menu::message(ui.panel, "Write failed", why, "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    }
    crate::catlog!(
        "proof: {} of {} inputs signed, {} bytes",
        signed,
        proof.inputs,
        at
    );

    // Every input ours and signed: finish it, check it as a counterparty would, and write
    // the proof. Otherwise the signed PSBT is what goes on to whoever signs next.
    let mut note: heapless::String<40> = heapless::String::new();
    if signed < proof.inputs {
        let _ = write!(note, "{signed} of {} inputs signed", proof.inputs);
        menu::message(ui.panel, "Signed", strip_slash(dest.signed_name), &note);
        menu::wait_for_any_key(ui);
        return;
    }
    let Some(flen) = finalise(&from[..at], into) else {
        menu::message(
            ui.panel,
            "Signed",
            strip_slash(dest.signed_name),
            "could not finalise",
        );
        menu::wait_for_any_key(ui);
        return;
    };
    match full::verify_pof(text.as_bytes(), proof.challenge(), &into[..flen]) {
        Ok(bip322::Variant::Proof { utxos, total })
            if utxos == proof.utxos && total == proof.total => {}
        other => {
            crate::catlog!("proof: self-check failed: {:?}", other);
            menu::message(
                ui.panel,
                "Signed",
                strip_slash(dest.signed_name),
                "proof did NOT verify",
            );
            menu::wait_for_any_key(ui);
            return;
        }
    }
    let Some(address) = address else {
        // No address, no armoured file: a verifier finds the challenge through it.
        menu::message(
            ui.panel,
            "Signed",
            strip_slash(dest.signed_name),
            "script has no address",
        );
        menu::wait_for_any_key(ui);
        return;
    };
    // The armoured file, built in the buffer the signed PSBT no longer needs.
    let Some(file_len) = armour(text, address, &into[..flen], from) else {
        menu::message(
            ui.panel,
            "Signed",
            strip_slash(dest.signed_name),
            "proof too large to write",
        );
        menu::wait_for_any_key(ui);
        return;
    };
    let name = proof_name(dest.final_name);
    match menu::write_storage_file(storage, &name, &from[..file_len]) {
        Ok(()) => {
            crate::catlog!("proof: {} written, {} UTXO(s)", name.as_str(), proof.utxos);
            let _ = write!(note, "{} UTXO(s), nothing spent", proof.utxos);
            menu::message(ui.panel, "Proof written", strip_slash(&name), &note);
        }
        Err(why) => {
            crate::catlog!("proof: write failed: {}", why);
            menu::message(ui.panel, "Write failed", why, "any key to go back");
        }
    }
    menu::wait_for_any_key(ui);
}

/// What signing would attest to, on one page, and the Sign key. True if the owner said so.
fn confirm(
    ui: &mut Ui<'_>,
    text: &str,
    address: Option<&str>,
    proof: &por::Proof,
    signable: usize,
) -> bool {
    use catcard_ui::scroll::{Line, ScrollView};
    let mut total: heapless::String<48> = heapless::String::new();
    let _ = write!(total, "{} UTXO(s), total ", proof.utxos);
    let _ = crate::prefs::current().units.write(proof.total, &mut total);
    let mut ours: heapless::String<32> = heapless::String::new();
    let _ = write!(ours, "{signable} of {} inputs ours", proof.inputs);
    let mut hint: heapless::String<32> = heapless::String::new();
    let _ = write!(
        hint,
        "{} sign   {} cancel",
        display::CONFIRM_KEY,
        display::CANCEL_KEY
    );
    let mut doc: heapless::Vec<Line, 10> = heapless::Vec::new();
    let _ = doc.push(Line::title(HEAD));
    let _ = doc.push(Line::body("message").small());
    let _ = doc.push(Line::body(text).wrapped());
    let _ = doc.push(Line::body("for address").small());
    let _ = doc.push(
        Line::body(address.unwrap_or("(no address)"))
            .small()
            .wrapped(),
    );
    let _ = doc.push(Line::body(total.as_str()).wrapped());
    let _ = doc.push(Line::body(ours.as_str()).small());
    let _ = doc.push(Line::body("NOTHING IS SPENT").small());
    let _ = doc.push(Line::body(hint.as_str()).small());
    let mut view = ScrollView::build(&doc, display::SCREEN_W, display::SCREEN_H, display::FONTS);
    menu::scroll_choice(ui, &mut view)
}

/// Finish a fully-signed PSBT into `out`; `None` when an input is still short.
fn finalise(psbt: &[u8], out: &mut [u8]) -> Option<usize> {
    let parsed = Psbt::parse(psbt).ok()?;
    let (len, count) = parsed.finalize_to_slice(out).ok()?;
    if count == 0 {
        return None;
    }
    Psbt::parse(&out[..len]).ok()?.is_finalized().then_some(len)
}

/// A `fmt::Write` over a byte slice, for the armoured file.
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

/// The armoured signed-message file around a proof: the message, the address, and
/// `pof` with the finalised PSBT in base64. Written into `out`; `None` if it does not fit.
fn armour(message: &str, address: &str, psbt: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut b = Buf { out, len: 0 };
    write!(
        b,
        "{}\n{message}\n{}\n{address}\n{}",
        signfile::BEGIN,
        signfile::SEPARATOR,
        bip322::PREFIX_POF
    )
    .ok()?;
    let at = b.len;
    let n = outscript::base64::encode_to_slice(psbt, &mut b.out[at..]).ok()?;
    b.len += n;
    write!(b, "\n{}\n", signfile::END).ok()?;
    Some(b.len)
}

/// Where the proof is written: `PROOF.TXT` beside a single PSBT's `FINAL.TXN`, or
/// `<name>-proof.txt` beside a batch's `<name>-final.txn`.
fn proof_name(final_name: &str) -> heapless::String<PATH_MAX> {
    let mut out = heapless::String::new();
    let stem = final_name
        .rfind('.')
        .filter(|dot| !final_name[*dot..].contains('/'))
        .map_or(final_name, |dot| &final_name[..dot]);
    let stem = stem.strip_suffix("-final").unwrap_or(stem);
    if stem.eq_ignore_ascii_case("/FINAL") {
        let _ = out.push_str(PROOF_NAME);
    } else if out.push_str(stem).is_err() || out.push_str("-proof.txt").is_err() {
        out.clear();
        let _ = out.push_str(PROOF_NAME);
    }
    out
}

fn strip_slash(name: &str) -> &str {
    name.strip_prefix('/').unwrap_or(name)
}

fn say(ui: &mut Ui<'_>, why: &str) {
    crate::catlog!("proof: {}", why);
    menu::message(ui.panel, HEAD, why, "any key to go back");
    menu::wait_for_any_key(ui);
}
