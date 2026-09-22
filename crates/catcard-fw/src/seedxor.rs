//! Seed XOR on the device: cutting the seed into parts, and putting parts back together.
//!
//! The arithmetic is [`catcard_wallet::seedxor`], which is where it is tested against the
//! published examples. This is the part that needs a person: what to split, how many ways,
//! which words to show, and what to do with a seed that has just been reassembled.
//!
//! # Splitting changes nothing
//!
//! It reads the wallet in force and shows words. Nothing is stored, nothing is written to
//! a card, and the device is in the same wallet afterwards as before. The risk is not to
//! the device, it is that **every part is as sensitive as the seed** -- the parts are only
//! safe while they are apart, and two of three in one drawer is two thirds of nothing
//! while three of three in one drawer is the wallet.
//!
//! # Joining is a temporary seed
//!
//! The reassembled seed becomes [`crate::key::Source::Temporary`]: in force for this
//! session, gone on reboot, and named in the status bar the whole time. It is not written
//! to the secure element -- except on a device that has no seed at all, where storing it is
//! the only thing that would make the device useful and is offered explicitly.
//!
//! That ordering is deliberate. A join is also how someone *checks* a set of parts, and a
//! check that overwrote the wallet would be a check nobody could afford to run.

use catcard_callgate::Callgate;
use catcard_wallet::bip39::{MAX_ENTROPY_LEN, Mnemonic};
use catcard_wallet::seedxor::{MAX_PARTS, MIN_PARTS, Parts};
use core::fmt::Write as _;
use zeroize::Zeroize as _;

use crate::menu::{self, DocExit};
use crate::ui::Ui;

const SPLIT: &str = "XOR split";
const JOIN: &str = "XOR join";

/// How many parts, as rows. Two to four, which is [`MIN_PARTS`] to [`MAX_PARTS`].
const COUNTS: &[&str] = &["2 parts", "3 parts", "4 parts"];
const _: () = assert!(COUNTS.len() == MAX_PARTS - MIN_PARTS + 1);

/// Where the parts come from.
const SOURCES: &[&str] = &["Deterministic", "From the TRNGs"];

/// A one-question list, returning the row chosen.
fn pick(ui: &mut Ui<'_>, head: &str, note: &str, items: &[&str]) -> Option<usize> {
    use catcard_ui::scroll::Line as DLine;
    let mut lines: heapless::Vec<DLine, 8> = heapless::Vec::new();
    let _ = lines.push(DLine::title(head));
    let _ = lines.push(DLine::body(note).small());
    for (i, s) in items.iter().enumerate() {
        let _ = lines.push(DLine::item(s, i as u32));
    }
    match menu::show_doc(ui, &lines, false, false) {
        DocExit::Selected(i) => Some(i as usize),
        _ => None,
    }
}

/// Split the wallet in force into parts, and show each one's words.
pub(crate) fn split(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    pool: Option<&mut catcard_entropy::EntropyPool>,
) {
    // The one thing about Seed XOR that people get wrong, said before anything is
    // derived: a part is not a share of the wallet, it *is* the wallet once the others
    // are beside it.
    menu::ask(
        ui.panel,
        SPLIT,
        "every part is the seed",
        "keep them far apart",
    );
    if !menu::confirmed(ui) {
        return;
    }

    // A passphrase is not in the words, so it is not in the parts. Someone who splits a
    // passphrase wallet and keeps only the parts has kept a different wallet.
    if crate::passphrase::is_set() {
        menu::ask(
            ui.panel,
            SPLIT,
            "splits the WORDS only",
            "your passphrase is not in them",
        );
        if !menu::confirmed(ui) {
            return;
        }
    }

    let Some(count) = pick(ui, SPLIT, "how many parts", COUNTS).map(|i| i + MIN_PARTS) else {
        return;
    };
    let Some(source) = pick(ui, SPLIT, "where the parts come from", SOURCES) else {
        return;
    };

    let (mut ent, len) = match menu::seed_entropy(gate, login, ui.panel, SPLIT) {
        Ok(got) => got,
        Err(why) => {
            menu::message(ui.panel, SPLIT, why, "nothing was split");
            menu::wait_for_any_key(ui);
            return;
        }
    };

    let parts = if source == 0 {
        crate::keywork::run(|kw| Parts::deterministic(&ent[..len], count, kw)).ok()
    } else {
        from_trngs(ui, pool, &ent[..len], count)
    };
    let Some(parts) = parts else {
        ent.zeroize();
        // `from_trngs` has already said why, and the deterministic path only fails on a
        // seed length BIP-39 has no words for -- which `seed_entropy` cannot return.
        return;
    };

    // Check the split before showing it, not after. The parts are a backup only if they
    // recombine, and the moment to find out that they do not is while the seed is still
    // in hand -- not next year, with three pieces of paper and no device.
    let mut back = [0u8; MAX_ENTROPY_LEN];
    let n = crate::keywork::run(|kw| parts.recombine(&mut back, kw));
    let good = n == len && back[..n] == ent[..len];
    back.zeroize();
    ent.zeroize();
    if !good {
        crate::catlog!("xor: split did not recombine; refused");
        menu::message(ui.panel, SPLIT, "the parts do not", "add back up");
        menu::wait_for_any_key(ui);
        return;
    }

    // Each part in turn, as words to write down, with the ragged marker every secret
    // gets. The owner cannot leave a part until every word of it has been on screen.
    for i in 0..count {
        let Some(m) = crate::keywork::run(|kw| parts.mnemonic(i, kw)) else {
            continue;
        };
        let mut head: heapless::String<24> = heapless::String::new();
        let _ = write!(head, "Part {} of {}", i + 1, count);
        menu::message(ui.panel, &head, "write down the words", "then any key");
        menu::wait_for_any_key(ui);
        menu::show_words(ui, &m);
    }
    drop(parts);

    crate::catlog!("xor: showed {} parts, {} bytes each", count, len);
    menu::message(ui.panel, SPLIT, "all parts shown", "nothing was stored");
    menu::wait_for_any_key(ui);
}

/// The noise for a random split: one draw per part but the last.
///
/// From the boot entropy pool, which is the only thing on this device allowed to hand
/// out seed material -- and which refuses when it did not meet its policy. A refusal is
/// the answer, not a reason to reach for something weaker: these bytes become a phrase
/// somebody stamps into metal.
fn from_trngs(
    ui: &mut Ui<'_>,
    pool: Option<&mut catcard_entropy::EntropyPool>,
    secret: &[u8],
    count: usize,
) -> Option<Parts> {
    let Some(pool) = pool else {
        menu::message(ui.panel, SPLIT, "the pool missed its", "policy at boot");
        menu::wait_for_any_key(ui);
        return None;
    };
    let mut noise = [[0u8; MAX_ENTROPY_LEN]; MAX_PARTS - 1];
    for slot in noise.iter_mut().take(count - 1) {
        if pool.draw(&mut slot[..secret.len()]).is_err() {
            noise.zeroize();
            menu::message(ui.panel, SPLIT, "not enough entropy", "for a random split");
            menu::wait_for_any_key(ui);
            return None;
        }
    }
    let mut refs: heapless::Vec<&[u8], { MAX_PARTS - 1 }> = heapless::Vec::new();
    for slot in noise.iter().take(count - 1) {
        let _ = refs.push(&slot[..secret.len()]);
    }
    let parts = crate::keywork::run(|kw| Parts::from_noise(secret, &refs, kw)).ok();
    drop(refs);
    noise.zeroize();
    parts
}

/// Type in the parts, XOR them, and work in what comes out.
pub(crate) fn join(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    let Some(count) = pick(ui, JOIN, "how many parts", COUNTS).map(|i| i + MIN_PARTS) else {
        return;
    };

    // Every part, each verified against its own checksum as it is typed. They are held
    // as entropy rather than as phrases because that is what combines, and because the
    // words are of no further use once the bits are out of them.
    let mut ents = [[0u8; MAX_ENTROPY_LEN]; MAX_PARTS];
    let mut len = 0usize;
    for i in 0..count {
        let mut head: heapless::String<24> = heapless::String::new();
        let _ = write!(head, "Part {} of {}", i + 1, count);
        menu::message(ui.panel, &head, "enter each word,", "then y y to finish");
        menu::wait_for_any_key(ui);

        let Some(m) = menu::read_phrase(ui) else {
            ents.zeroize();
            menu::message(ui.panel, JOIN, "cancelled", "nothing changed");
            menu::wait_for_any_key(ui);
            return;
        };
        let e = m.entropy();
        // Seed XOR is only defined between phrases of one length, and a part of the
        // wrong length is a part from a different split -- not something to combine
        // anyway and quietly get a wallet nobody can find again.
        if i == 0 {
            len = e.len();
        } else if e.len() != len {
            ents.zeroize();
            menu::message(
                ui.panel,
                JOIN,
                "parts are different",
                "lengths; cannot join",
            );
            menu::wait_for_any_key(ui);
            return;
        }
        ents[i][..len].copy_from_slice(e);
        drop(m);
    }

    let mut refs: heapless::Vec<&[u8], MAX_PARTS> = heapless::Vec::new();
    for slot in ents.iter().take(count) {
        let _ = refs.push(&slot[..len]);
    }
    let mut joined = [0u8; MAX_ENTROPY_LEN];
    let combined = crate::keywork::run(|kw| catcard_wallet::seedxor::join(&refs, &mut joined, kw));
    drop(refs);
    ents.zeroize();
    let Ok(n) = combined else {
        joined.zeroize();
        menu::message(ui.panel, JOIN, "those parts do not", "combine");
        menu::wait_for_any_key(ui);
        return;
    };

    // Show what came out before it is used for anything: any set of parts of the right
    // length combines into *some* valid wallet, so there is nothing for the device to
    // reject. The fingerprint is the only thing that says whether it is the right one.
    let words = crate::keywork::run(|kw| Mnemonic::from_entropy(&joined[..n], kw).ok());
    let Some(words) = words else {
        joined.zeroize();
        menu::message(ui.panel, JOIN, "the result is not", "a valid seed");
        menu::wait_for_any_key(ui);
        return;
    };
    let count_of_words = words.word_count();
    drop(words);

    let was = crate::key::in_force();
    if !crate::key::set_temporary(&joined[..n]) {
        joined.zeroize();
        menu::message(ui.panel, JOIN, "that seed length", "is not usable");
        menu::wait_for_any_key(ui);
        return;
    }

    match menu::master_quietly(gate, login, ui.panel, JOIN) {
        Ok(master) => {
            let [a, b, c, d] = crate::keywork::run(|kw| master.fingerprint(kw));
            drop(master);
            let mut said: heapless::String<24> = heapless::String::new();
            let _ = write!(said, "{a:02X}{b:02X}{c:02X}{d:02X}");
            crate::catlog!("xor: joined {} words -> {}", count_of_words, said.as_str());
            menu::message(ui.panel, "Joined", &said, "in force until reboot");
            menu::wait_for_any_key(ui);
        }
        Err(why) => {
            crate::key::set(was);
            joined.zeroize();
            menu::message(ui.panel, JOIN, why, "unchanged");
            menu::wait_for_any_key(ui);
            return;
        }
    }

    // On a device with no seed of its own this is a restore, not a session: offer to
    // keep it. Anywhere else the stored seed is somebody's wallet and this screen is
    // not where it gets replaced -- that is what Import is for, with its own warning.
    if matches!(login.step(), catcard_pin::Step::In { zero_secret: true }) {
        menu::ask(
            ui.panel,
            "Keep this seed?",
            "no wallet is stored yet",
            "y to store it for good",
        );
        if menu::confirmed(ui) {
            store(gate, login, ui, &joined[..n]);
        }
    }
    joined.zeroize();
}

/// Write a joined seed into the secure element, and go back to the root wallet.
///
/// Once it is stored it *is* the root, so keeping the temporary selection in force would
/// mean the device claimed a temporary seed while working from the stored one -- the same
/// wallet under two names, which is exactly the confusion the status bar exists to stop.
fn store(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>, entropy: &[u8]) {
    let Ok(mut secret) = catcard_callgate::pin::encode_bip39(entropy) else {
        menu::message(ui.panel, JOIN, "could not encode", "that seed");
        menu::wait_for_any_key(ui);
        return;
    };
    menu::message(ui.panel, "Storing", "do not disconnect", "");
    let pin_gate = crate::pinentry::BootloaderGate::new(gate);
    let stored = login.set_secret(&pin_gate, &secret);
    secret.zeroize();
    match stored {
        Ok(_) => {
            crate::key::to_root();
            crate::catlog!("xor: joined seed stored");
            menu::message(ui.panel, "Stored", "this is the wallet", "now");
        }
        Err(_) => menu::message(ui.panel, JOIN, "the secure element", "refused it"),
    }
    menu::wait_for_any_key(ui);
}
