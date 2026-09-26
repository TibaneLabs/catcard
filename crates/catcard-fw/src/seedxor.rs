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
//!
//! # Where the parts come from
//!
//! Each part is asked for separately: typed in, read from the wallet in force ("this
//! device's seed"), or taken from the Seed Vault by fingerprint. Stock offers the same
//! three, and the use is the same -- a split can be made so that one part *is* the seed
//! already in the secure element, and the others are the papers. Whatever the source, a
//! part is BIP-39 entropy and nothing else: a key with no words is refused by name, the
//! bytes are XOR-ed in inside [`crate::keywork::run`] and wiped at once, and only the
//! running XOR ([`Join`]) is held between parts. Order does not matter.

use catcard_callgate::Callgate;
use catcard_wallet::bip39::{MAX_ENTROPY_LEN, Mnemonic};
use catcard_wallet::seedxor::{Join, MAX_PARTS, MIN_PARTS, Parts};
use core::fmt::Write as _;
use zeroize::Zeroize as _;

use crate::menu::{self, pick_row};
use crate::ui::Ui;

const SPLIT: &str = "XOR split";
const JOIN: &str = "XOR join";

/// How many parts, as rows. Two to four, which is [`MIN_PARTS`] to [`MAX_PARTS`].
const COUNTS: &[&str] = &["2 parts", "3 parts", "4 parts"];
const _: () = assert!(COUNTS.len() == MAX_PARTS - MIN_PARTS + 1);

/// Where the parts come from.
const SOURCES: &[&str] = &["Deterministic", "From the TRNGs"];

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

    let Some(count) = pick_row(ui, SPLIT, "how many parts", COUNTS).map(|i| i + MIN_PARTS) else {
        return;
    };
    let Some(source) = pick_row(ui, SPLIT, "where the parts come from", SOURCES) else {
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

/// Where one part of a join comes from.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum PartFrom {
    /// Typed in, word by word, checksum and all.
    Typed,
    /// The words of the wallet in force: the stored seed, a BIP-85 child of it, or a
    /// seed loaded for the session. Stock's "fold in this device's current seed".
    OwnSeed,
    /// One of the keys kept in the Seed Vault, chosen by fingerprint and label.
    #[cfg(not(feature = "board-mk3"))]
    Vault,
}

/// One line of a refusal. Long enough for `seed_entropy`'s longest reason.
type Line = heapless::String<40>;

/// The source rows, in the order they are offered.
const TYPE_WORDS: &str = "Type words";
const OWN_SEED: &str = "This device's seed";
#[cfg(not(feature = "board-mk3"))]
const VAULT_ENTRY: &str = "A Seed Vault entry";

/// Ask where part `head` comes from. `None` if the owner backed out.
///
/// The rows are only the sources that exist: no "this device's seed" on a blank device,
/// and no vault row when the vault holds nothing -- or on a board without a settings
/// store to hold one.
fn pick_source(ui: &mut Ui<'_>, head: &str, has_own: bool, has_vault: bool) -> Option<PartFrom> {
    let mut rows: heapless::Vec<&str, 3> = heapless::Vec::new();
    let mut kinds: heapless::Vec<PartFrom, 3> = heapless::Vec::new();
    let _ = rows.push(TYPE_WORDS);
    let _ = kinds.push(PartFrom::Typed);
    if has_own {
        let _ = rows.push(OWN_SEED);
        let _ = kinds.push(PartFrom::OwnSeed);
    }
    #[cfg(not(feature = "board-mk3"))]
    if has_vault {
        let _ = rows.push(VAULT_ENTRY);
        let _ = kinds.push(PartFrom::Vault);
    }
    #[cfg(feature = "board-mk3")]
    let _ = has_vault;
    let row = pick_row(ui, head, "where is this part?", &rows)?;
    kinds.get(row).copied()
}

/// Why a part could not go in, in words that name the part.
///
/// A length mismatch is the one worth naming precisely: "part 3 is 12 words, the others
/// are 24" tells the owner which piece of paper is from a different split, where
/// "different lengths" only says that one is.
fn refusal(
    head: &str,
    part_len: usize,
    join: &Join,
    err: catcard_wallet::seedxor::Error,
) -> (Line, Line) {
    use catcard_wallet::bip39::words_for_entropy;
    use catcard_wallet::seedxor::Error;
    let mut a: Line = heapless::String::new();
    let mut b: Line = heapless::String::new();
    match err {
        Error::Mixed => {
            let mine = words_for_entropy(part_len).unwrap_or(0);
            let theirs = join.len().and_then(words_for_entropy).unwrap_or(0);
            let _ = write!(a, "{head} is {mine} words");
            let _ = write!(b, "the others are {theirs}");
        }
        Error::Length => {
            let _ = a.push_str("not a seed length");
            let _ = b.push_str("BIP-39 has words for");
        }
        Error::PartCount => {
            let _ = a.push_str("too many parts");
            let _ = b.push_str("for one join");
        }
    }
    (a, b)
}

/// Put the parts together, from wherever each one is, and work in what comes out.
///
/// Each part is typed, read from this device's own seed, or taken from the Seed Vault --
/// asked per part, so a set can be two pieces of paper plus the seed in the secure
/// element, which is how stock's "fold in this device's seed" is used. Every source
/// hands over sixteen to thirty-two bytes of BIP-39 entropy and nothing else: a key with
/// no words (an XPRV, a raw master, a WIF key) is refused by name, and so is a part of
/// another length than the first.
///
/// Parts go into a [`Join`] as they arrive, inside [`crate::keywork::run`], and each is
/// wiped as soon as it is in; only the running XOR is held. A part that is refused is
/// not mixed in, so the owner is asked for that part again rather than starting over.
pub(crate) fn join(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    // Said first, as the help screen does: with a seed stored, what comes out is a
    // session's wallet and not a replacement -- which is the point, and also the thing
    // someone restoring onto a used device most needs to hear before typing 72 words.
    // Source: hw-reference/help-and-warning-screens.md §4 "XOR restore while a seed
    // already exists" [C]
    let stored = crate::key::stored_wallet(login);
    if stored {
        menu::ask(
            ui.panel,
            JOIN,
            "a seed is stored, so",
            "the result is temporary",
        );
        if !menu::confirmed(ui) {
            return;
        }
    }

    let Some(count) = pick_row(ui, JOIN, "how many parts", COUNTS).map(|i| i + MIN_PARTS) else {
        return;
    };

    // Whether there is a wallet in force with words to lend: a stored seed, or something
    // loaded on top of nothing. A blank device with nothing loaded has neither, and its
    // vault -- which lives under the wallet in force -- is not worth a read either.
    let has_own = stored || crate::key::in_force() != crate::key::Source::Root;
    #[cfg(not(feature = "board-mk3"))]
    let has_vault = has_own && crate::vault::count(gate, login, ui) > 0;
    #[cfg(feature = "board-mk3")]
    let has_vault = false;

    let mut join = Join::new();
    // The same source twice XORs itself out, so each of the fixed ones goes in once.
    // Typed parts are not policed the same way; the all-zero check below catches the
    // pair that cancels.
    let mut own_used = false;
    #[cfg(not(feature = "board-mk3"))]
    let mut vault_used: heapless::Vec<heapless::String<8>, MAX_PARTS> = heapless::Vec::new();

    for i in 0..count {
        let mut head: heapless::String<24> = heapless::String::new();
        let _ = write!(head, "Part {} of {}", i + 1, count);

        // Until this part is in, or the owner backs out of the source list.
        loop {
            let Some(from) = pick_source(ui, &head, has_own, has_vault) else {
                menu::message(ui.panel, JOIN, "cancelled", "nothing changed");
                menu::wait_for_any_key(ui);
                return;
            };
            let added: Result<(), (Line, Line)> = match from {
                PartFrom::Typed => {
                    menu::message(ui.panel, &head, "enter each word,", "then y y to finish");
                    menu::wait_for_any_key(ui);
                    let Some(m) = menu::read_phrase(ui) else {
                        // Backing out of the words is backing out of the part; the
                        // source list comes back, and backing out of that is the end.
                        continue;
                    };
                    let part_len = m.entropy().len();
                    let r = crate::keywork::run(|kw| join.add(m.entropy(), kw));
                    drop(m);
                    r.map_err(|e| refusal(&head, part_len, &join, e))
                }
                PartFrom::OwnSeed if own_used => Err(said("this device's seed", "is already in")),
                PartFrom::OwnSeed => {
                    // `seed_entropy` names a wallet with no words -- an XPRV, a raw
                    // master, a WIF key -- and hands back nothing for it.
                    match menu::seed_entropy(gate, login, ui.panel, &head) {
                        Ok((mut ent, len)) => {
                            let r = crate::keywork::run(|kw| join.add(&ent[..len], kw));
                            ent.zeroize();
                            own_used = r.is_ok();
                            r.map_err(|e| refusal(&head, len, &join, e))
                        }
                        Err(why) => Err(said(why, "cannot be a part")),
                    }
                }
                #[cfg(not(feature = "board-mk3"))]
                PartFrom::Vault => {
                    let Some(picked) = crate::vault::pick_part(gate, login, ui, &head) else {
                        continue;
                    };
                    if vault_used.contains(&picked.xfp) {
                        Err(said("that entry", "is already in"))
                    } else {
                        // The entry is decoded, classified and mixed in inside one
                        // masked region; `picked` is wiped on the way out either way.
                        let r = crate::keywork::run(|kw| {
                            let e = picked
                                .entropy(kw)
                                .map_err(|why| said(why, "cannot be a part"))?;
                            let part_len = e.len();
                            join.add(e, kw)
                                .map_err(|err| refusal(&head, part_len, &join, err))
                        });
                        if r.is_ok() {
                            let _ = vault_used.push(picked.xfp.clone());
                        }
                        drop(picked);
                        r
                    }
                }
            };
            match added {
                Ok(()) => {
                    crate::catlog!("xor: part {} of {} from {:?}", i + 1, count, from);
                    break;
                }
                Err((a, b)) => {
                    menu::message(ui.panel, &head, &a, &b);
                    menu::wait_for_any_key(ui);
                }
            }
        }
    }

    // Two equal parts cancel, and a set that XORs to nothing is almost always the same
    // paper entered twice. The all-zero seed is a valid phrase, which is exactly why it
    // has to be refused here: nothing downstream would.
    // Source: hw-reference/help-and-warning-screens.md §4 "Per-part progress" [C]
    if join.is_all_zero() {
        drop(join);
        menu::message(
            ui.panel,
            JOIN,
            "result is all zeros:",
            "a part went in twice?",
        );
        menu::wait_for_any_key(ui);
        return;
    }

    let mut joined = [0u8; MAX_ENTROPY_LEN];
    let combined = crate::keywork::run(|kw| join.finish(&mut joined, kw));
    drop(join);
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
    if !crate::key::set_temporary(&joined[..n], "XOR") {
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
            crate::catlog!("xor: joined {} words", count_of_words);
            #[cfg(not(feature = "board-mk3"))]
            crate::settings::open_wallet(gate, login, ui.panel, JOIN, [a, b, c, d]);
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
    if !stored {
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

/// Two lines of refusal, as the screen shows them.
fn said(a: &str, b: &str) -> (Line, Line) {
    let mut x: Line = heapless::String::new();
    let mut y: Line = heapless::String::new();
    let _ = x.push_str(&a[..a.len().min(x.capacity())]);
    let _ = y.push_str(&b[..b.len().min(y.capacity())]);
    (x, y)
}

/// Write a joined seed into the secure element, and go back to the root wallet.
///
/// Once it is stored it *is* the root, so keeping the temporary selection in force would
/// mean the device claimed a temporary seed while working from the stored one -- the same
/// wallet under two names, which is exactly the confusion the status bar exists to stop.
///
/// The write goes through [`menu::store_seed`], as the scanned SeedQR's does: write, read
/// back, then claim. "Stored" is the last thing the owner hears before the shares go
/// back in their envelopes, so it is said only once the slot has been seen to hold it.
fn store(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>, entropy: &[u8]) {
    if !menu::store_seed(gate, login, ui, entropy) {
        // It has already said why.
        return;
    }
    crate::key::to_root();
    crate::catlog!("xor: joined seed stored");
    menu::message(ui.panel, "Stored", "this is the wallet", "now");
    menu::wait_for_any_key(ui);
}
