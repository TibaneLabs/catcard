//! New wallet: from fresh TRNG bytes to a seed stored in the secure element and read back.
//!
//! The most audited path in the firmware, kept in one file so it can be read in one
//! sitting. `docs/ENTROPY.md`, "Following the bytes: TRNG to seed", walks it step by step:
//! [`new_seed`] tops the boot pool up with fresh bytes from every hardware source
//! (steps 5-6), offers the owner's own dice, coins or mash ([`add_user_entropy`], step 7),
//! draws with interrupts masked (step 8), encodes the words and the slot image from the
//! same bytes (step 9), and shows, quizzes, stores and reads back (step 10).
//!
//! The same generator also makes a temporary seed ([`new_temp_seed`]) and CCC's key C
//! ([`new_key_c`]), and Debug -> View TRNG Words ([`view_trng_words`]) runs the same
//! collection and draw on a throwaway pool and only shows the words.
//!
//! The screens it borrows -- `message`, `ask`, `show_words` and the rest -- are the menu's
//! shared ones, used by imports and backups as well.

use core::fmt::Write as _;

use catcard_callgate::Callgate;
use catcard_ui::keypad::{Event, KEYS, Key};

use crate::menu::{
    Line, NEW_SEED_ITEMS, announce_key, ask, confirmed, info, message, pick_row, show_doc,
    show_words, wait_for_any_key, wait_for_release, why_failed, word_texts,
};
use crate::ui::Ui;
use crate::{display, usbtask};

/// What the entropy screens report.
///
/// A struct because seven numbers passed positionally is one transposed pair away from
/// telling someone their wallet has more entropy behind it than it does.
struct Gathered {
    /// Bytes each of this board's sources has answered with during *this* generation.
    read: heapless::Vec<(crate::trng::Kind, usize), 4>,
    /// Credited bits and distinct hardware TRNGs the pool counts right now (this includes
    /// what boot already collected -- the chip, the elements and startup timing).
    bits: u32,
    chips: u32,
    /// What this board's policy demands before a seed may be drawn at all.
    need_bits: u32,
    need_chips: u32,
}

impl Gathered {
    fn lines(&self, out: &mut heapless::Vec<Line, 6>) {
        for &(kind, n) in &self.read {
            let mut l = Line::new();
            // A source mixed in but not trusted to count says so, rather than letting its
            // bytes read as if they carried the seed.
            let _ = write!(
                l,
                "{:<3}  read {n:5} bytes{}",
                kind.label(),
                if kind.credited() { "" } else { " mixed" }
            );
            let _ = out.push(l);
        }
        let mut l = Line::new();
        let _ = write!(l, "chips  {} of {} needed", self.chips, self.need_chips);
        let _ = out.push(l);
        let mut l = Line::new();
        let _ = write!(l, "total {:5} / {} bits", self.bits, self.need_bits);
        let _ = out.push(l);
    }
}

fn gathering(panel: &mut display::Panel, g: &Gathered, pct: u8) {
    let mut lines: heapless::Vec<Line, 6> = heapless::Vec::new();
    g.lines(&mut lines);
    display::draw(panel, |c| {
        catcard_ui::widgets::info(c, &display::LAYOUT, "Collecting entropy", &lines);
        catcard_ui::splash::draw_progress(c, pct);
        crate::idle::note_progress();
    });
}

/// What was collected, and whether the policy is actually satisfied.
///
/// Shown before the seed is drawn and acknowledged with a key, so the numbers behind a
/// wallet are seen once by the person who will own it. `passed` is the pool's own
/// verdict from `check()`, not an assumption that the loop above did its job.
fn entropy_report(panel: &mut display::Panel, g: &Gathered, passed: bool) {
    let mut lines: heapless::Vec<Line, 6> = heapless::Vec::new();
    g.lines(&mut lines);
    info(
        panel,
        if passed {
            // Just the verdict, like the failure title: "Entropy OK, any key" is 19
            // characters and the 7px title font clips the last one on a 128px panel
            // ("...any ke"). The screen waits for a key regardless.
            "Entropy OK"
        } else {
            "NOT ENOUGH ENTROPY"
        },
        &lines,
    );
}

/// Fold a finished run into the pool and show what it was worth.
///
/// The digest prefix on this screen is the point of matching the published convention:
/// the owner wrote their rolls down, and `printf '%s' 4316... | sha256sum` on any machine
/// produces the same 32 bytes, so they can check the device used *their* rolls and not
/// something of its own. Unlike stock, where that digest **is** the seed, here it is one
/// contribution among the TRNGs' -- so showing a prefix of it, or recomputing it on a
/// computer that turns out to be compromised, does not hand anyone the wallet.
/// Source: <https://coldcard.com/docs/verifying-dice-roll-math/> [C]
fn mix_user_run(
    ui: &mut Ui<'_>,
    pool: &mut catcard_entropy::EntropyPool,
    run: &catcard_entropy::UserSymbols,
) {
    let noun = run.alphabet().noun();
    let n = run.count();
    let bits = pool.add_user(run);
    crate::catlog!("seed: user {} {} = {} bits", n, noun, bits);

    let d = run.digest();
    let mut lines: heapless::Vec<Line, 6> = heapless::Vec::new();
    let mut l = Line::new();
    let _ = write!(l, "{n} {noun}, +{bits} bits");
    let _ = lines.push(l);
    let mut l = Line::new();
    let _ = write!(l, "sha256 of your {noun}:");
    let _ = lines.push(l);
    let mut l = Line::new();
    let _ = write!(
        l,
        "{:02x}{:02x}{:02x}{:02x} {:02x}{:02x}{:02x}{:02x}",
        d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
    );
    let _ = lines.push(l);
    info(ui.panel, "Mixed in", &lines);
    wait_for_any_key(ui);
}

/// Collect a run of symbols the owner types -- dice faces, coin sides, a keypad mash --
/// and fold it into the pool.
///
/// Two things are credited on different footings, and the distinction is the point. The
/// press *timing* goes in the instant a key lands and is always kept: a human's intervals
/// are unpredictable even when their choices are not. The *values* are credited only when
/// the run clears its gate -- long enough and not dominated by one symbol -- because a
/// short or lopsided run is a pattern the pool must not count. The screen shows both
/// numbers as they are entered: how many symbols, and what they are worth by keyspace
/// (`log2(6)` a roll, so 50 rolls is 129 bits).
///
/// Neither is ever a precondition for a seed. The pool has already met its policy from
/// the hardware TRNGs or it refused outright, and [`EntropyPool::add_user`] cannot
/// replace what is in it -- so this only ever tops up.
///
/// [`EntropyPool::add_user`]: catcard_entropy::EntropyPool::add_user
fn collect_symbols(
    ui: &mut Ui<'_>,
    pool: &mut catcard_entropy::EntropyPool,
    alphabet: catcard_entropy::Alphabet,
) {
    use catcard_entropy::Alphabet;
    use catcard_entropy::user::Rejected;

    let (title, prompt) = match alphabet {
        Alphabet::Dice => ("Roll dice", "keys 1-6 = one roll"),
        Alphabet::Coin => ("Flip a coin", "0=tails 1=heads"),
        Alphabet::Keypad => ("Mash digits", "any digits"),
    };
    let mut run = catcard_entropy::UserSymbols::new(alphabet);
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    // Why the last press was not taken, or why a `y` was not accepted. Cleared on the
    // next press, so it reads as an answer to what was just done.
    let mut warn: Option<Line> = None;
    loop {
        let mut a = Line::new();
        let _ = write!(
            a,
            "{} {}, {} bits",
            run.count(),
            alphabet.noun(),
            run.worth_bits()
        );
        let mut hint = Line::new();
        if let Some(w) = &warn {
            hint = w.clone();
        } else if run.count() == 0 {
            let _ = write!(hint, "{prompt}");
        } else if run.weakness().is_none() {
            let _ = write!(hint, "y=use these");
        } else {
            let _ = write!(hint, "more, then y");
        }
        message(ui.panel, title, &a, &hint);

        wait_for_release(ui);
        loop {
            let _ = usbtask::pump();
            crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
            if !keys.is_empty() {
                break;
            }
            display::idle(ui.panel);
        }
        warn = None;
        for k in keys.iter() {
            // Every press, whatever key it was and whether or not its value is kept: the
            // cycle counter at a human's press is real if small entropy, and it is the
            // one contribution here that a stuck die cannot spoil.
            pool.add_timing(catcard_hal::dwt::cycles());
            match k {
                Key::Confirm => match run.weakness() {
                    // Too short or too lopsided to count: say which, and keep collecting
                    // rather than credit it. Refusing is the safety property here too.
                    Some(w) => {
                        let mut l = Line::new();
                        let _ = write!(l, "{w}");
                        warn = Some(l);
                    }
                    None => {
                        mix_user_run(ui, pool, &run);
                        return;
                    }
                },
                // Cancel abandons this mode. The timing already mixed stays -- it cannot
                // be unmixed and does no harm -- the values do not; they were never
                // credited, and `run` zeroizes on the way out.
                Key::Cancel => return,
                Key::Digit(d) => {
                    // ASCII, because ASCII is what the digest convention hashes.
                    match run.push(b'0' + d) {
                        Ok(()) => {}
                        Err(Rejected::Full) => {
                            let mut l = Line::new();
                            let _ = write!(l, "that is plenty, y");
                            warn = Some(l);
                        }
                        // A key outside the alphabet (a 7 while rolling a d6) is not a
                        // roll and must not be hashed as one.
                        Err(Rejected::NotInAlphabet) => {
                            let mut l = Line::new();
                            let _ = write!(l, "{prompt}");
                            warn = Some(l);
                        }
                    }
                }
                Key::Char(_) | Key::Qr => {}
            }
        }
    }
}

/// Offer the owner the choice, once the hardware has been collected: this device's own
/// entropy, or that combined with entropy they supplied themselves.
///
/// It is a genuine choice rather than a step, and "device only" is a complete answer --
/// the pool has already met its policy or it refused outright, so none of these can
/// rescue a bad device and none of them is needed by a good one. What they do offer is
/// the one thing a distrustful owner cannot get any other way: material the firmware
/// could not have predicted, in a form they can check afterwards.
fn add_user_entropy(ui: &mut Ui<'_>, pool: &mut catcard_entropy::EntropyPool) {
    use catcard_entropy::Alphabet;

    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        message(
            ui.panel,
            "Add your own?",
            "1=dice 2=coin 3=mash",
            "y=device only",
        );
        wait_for_release(ui);
        loop {
            let _ = usbtask::pump();
            crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
            if !keys.is_empty() {
                break;
            }
            display::idle(ui.panel);
        }
        // Take the first meaningful key of the batch, then redraw the menu.
        let mut done = false;
        for k in keys.iter() {
            match k {
                Key::Confirm | Key::Cancel => {
                    done = true;
                    break;
                }
                Key::Digit(1) => {
                    collect_symbols(ui, pool, Alphabet::Dice);
                    break;
                }
                Key::Digit(2) => {
                    collect_symbols(ui, pool, Alphabet::Coin);
                    break;
                }
                Key::Digit(3) => {
                    collect_symbols(ui, pool, Alphabet::Keypad);
                    break;
                }
                Key::Digit(_) => {}
                Key::Char(_) | Key::Qr => {}
            }
        }
        if done {
            return;
        }
    }
}

/// Create a wallet: draw entropy, store it, verify it, and show the words once.
///
/// The order is the point. The secret is written **and read back before any word reaches
/// the screen**, because words shown for a seed the secure element did not keep are
/// worse than no words at all — someone copies them down and believes they have a
/// backup of a wallet that does not exist.
///
/// User-supplied entropy -- dice, coin flips, a keypad mash -- is *offered* after the
/// hardware collection, as a choice rather than a step; see [`add_user_entropy`]. It is
/// never *required*, and it never replaces anything: the pool has already met its policy
/// or it refuses outright, and a handful of rolls cannot rescue a device whose TRNGs are
/// unhealthy. A seed made with 50 rolls is the seed that would have been made without
/// them, stirred further. See `docs/SECRETS-AND-SETTINGS.md` and `docs/ENTROPY.md`.
// Eight arguments, and clippy is right to say so. Four of them -- panel, pad, matrix,
// drbg -- are the same cluster every action screen drags around, and the remedy is the
// one this file already uses for `Session` and `View`: give them a struct. That is a
// refactor across every screen here rather than a change to this function, so it is
// deferred deliberately and not because the lint is wrong.
#[allow(clippy::too_many_arguments)]
pub(crate) fn new_seed(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    pool: Option<&mut catcard_entropy::EntropyPool>,
    words: u8,
    target: SeedTarget,
    handoff: Option<&mut [u8; catcard_callgate::pin::SECRET_LEN]>,
) {
    use catcard_wallet::bip39::Mnemonic;
    use zeroize::Zeroize;

    // How much entropy those words carry: 32 bytes for 24, 16 for 12. Anything else is
    // a caller bug rather than a user one, and 24 is the safe way to be wrong.
    let entropy_len = match words {
        12 => 16,
        _ => 32,
    };

    // No pool means it never met its policy at boot. That is a refusal.
    let Some(pool) = pool else {
        message(
            ui.panel,
            "No entropy",
            "the pool missed its",
            "policy at boot",
        );
        wait_for_any_key(ui);
        return;
    };

    // Overwriting a wallet that already exists is the destructive case, and this is the
    // only warning anyone gets. Asked of `key::stored_wallet`, which is the bootloader's
    // flag *and* what the slot turned out to hold: the flag alone says "in use" about a
    // slot whose seed was destroyed, and warning about a wallet that is not there
    // teaches an owner to press through the one warning that matters.
    //
    // A temporary seed touches the slot not at all, so there is nothing to warn about.
    if target == SeedTarget::Store && crate::key::stored_wallet(login) {
        ask(
            ui.panel,
            "Wallet exists",
            "a new seed DESTROYS",
            "the one stored now",
        );
        if !confirmed(ui) {
            return;
        }
    }
    let mut what = Line::new();
    let _ = write!(what, "{words} words, from this");
    match target {
        SeedTarget::Store => ask(ui.panel, "Create wallet?", &what, "device's own TRNGs"),
        // Said plainly: it is gone at reboot unless its words are kept or it is locked
        // down. Source: hw-reference/help-and-warning-screens.md §6 [C]
        SeedTarget::Temporary => ask(ui.panel, "Temporary seed?", &what, "device; RAM only"),
        SeedTarget::Handoff => ask(ui.panel, "New key C?", &what, "device's own TRNGs"),
    }
    if !confirmed(ui) {
        return;
    }

    // Fresh noise from both secure elements, on top of what the boot pool already
    // holds. The boot pool has met its policy or we would not be here; this is added
    // material, not a substitute for it.
    //
    // It goes through `EntropyPool` rather than into a hash of its own, because the
    // pool is what runs the health tests, keeps the sources domain-separated and
    // credits them. A side digest would mix the same bytes twice while skipping all
    // three. An element that fails its health test is mixed in but credited nothing and
    // not counted -- so if too few healthy sources remain, `draw` below refuses, which is
    // the intended outcome; a single bad element cannot by itself block a healthy pool.
    // How long to hold each step on screen. Legibility only: thirty-two counts that
    // flash past in a blink show nothing, and nobody can check a number they cannot
    // read. It contributes no entropy and must never be mistaken for doing so.
    const STEP_PAUSE_CYCLES: u32 = 4_000_000;

    let policy = crate::entropy_policy();
    let kinds = crate::trng::kinds();
    // SP 800-90B §4.3: from here a hardware source counts only once its start-up test --
    // its first 1,024 bytes this session through the health tests, boot's 64 included --
    // has passed; one that fails it counts for nothing for the rest of the session. Boot
    // does not enforce this yet (docs/ENTROPY.md, "Start-up test"); a wallet does, so the
    // reads below take at least that many bytes from every source.
    pool.enforce_startup();
    let mut g = Gathered {
        read: kinds.iter().map(|&k| (k, 0usize)).collect(),
        bits: pool.credited_bits(),
        chips: pool.hardware_sources(),
        need_bits: policy.min_bits,
        need_chips: policy.min_hw_sources,
    };

    // Every source this board can read, the same number of *bytes* from each -- not the
    // same number of turns. SE2 produces about a quarter as fast as SE1, so taking turns in
    // lockstep once collected `SE1 512 B, SE2 128 B`, which reads like a broken element and
    // is really a slower one. The chip TRNG is part of this on every board: it once sat
    // inside a check for the mk4+ callgate, and on mk3 a wallet was generated without a
    // single fresh byte from it. At least the start-up test's window, so every source's
    // test has completed on fresh bytes alone by the time the pool is asked.
    const TARGET: usize = catcard_entropy::STARTUP_SAMPLES;
    // Bounded, because a source that never answers must not hang a wallet. At SE2's
    // observed rate 512 bytes wanted roughly 64 turns, so 1,024 wants about 130; this
    // leaves room and still ends.
    const MAX_PASSES: usize = 320;

    let mut trngs = crate::trng::Trngs::new(Some(gate));
    // A source can decline two ways: `Some(0)` is "nothing ready", `None` a refusal.
    // Counted apart so a generation is a measurement rather than an inference.
    let mut tries = [0usize; 4];
    let mut empty = [0usize; 4];
    let mut failed = [0usize; 4];

    gathering(ui.panel, &g, 0);
    for _ in 0..MAX_PASSES {
        if g.read.iter().all(|&(_, n)| n >= TARGET) {
            break;
        }
        for (i, entry) in g.read.iter_mut().enumerate() {
            let (kind, n) = (entry.0, &mut entry.1);
            if *n >= TARGET {
                continue;
            }
            let _ = usbtask::pump();
            let mut buf = [0u8; 64];
            tries[i] += 1;
            match trngs.read(kind, &mut buf) {
                Some(got) if got > 0 => {
                    pool.add(kind.source(), &buf[..got]);
                    *n += got;
                }
                Some(_) => empty[i] += 1,
                None => failed[i] += 1,
            }
            buf.zeroize();
        }
        g.bits = pool.credited_bits();
        g.chips = pool.hardware_sources();
        let got: usize = g.read.iter().map(|&(_, n)| n.min(TARGET)).sum();
        let pct = got * 100 / (TARGET * g.read.len().max(1));
        gathering(ui.panel, &g, pct.min(100) as u8);
        catcard_hal::dwt::delay_cycles(STEP_PAUSE_CYCLES);
    }
    for (i, &(kind, n)) in g.read.iter().enumerate() {
        crate::catlog!(
            "seed: {} {}B/{}t {}e {}f",
            kind.label(),
            n,
            tries[i],
            empty[i],
            failed[i]
        );
        if let Some(st) = pool.startup(kind.source()) {
            crate::catlog!("seed: {} startup {:?}", kind.label(), st);
        }
    }

    // With the hardware collected, offer the owner the choice: this device's entropy, or
    // this device's combined with dice, coin flips or a keypad mash of their own. It is
    // optional -- the pool has already met its policy from the TRNGs -- and only ever
    // tops up, but it costs nothing and lets a distrustful owner add material the
    // firmware could not have predicted.
    add_user_entropy(ui, pool);

    // The pool's own verdict, not ours: enough credited bits from enough healthy hardware
    // TRNGs. A failed source counted for neither, so this is where too few healthy sources
    // becomes visible, before any word is shown.
    let passed = pool.check().is_ok();
    // The user's turn may have added bits; the report shows what the draw will rest on.
    g.bits = pool.credited_bits();
    g.chips = pool.hardware_sources();
    crate::catlog!(
        "seed: {} bits from {} chips, policy {}",
        g.bits,
        g.chips,
        if passed { "ok" } else { "FAILED" }
    );
    entropy_report(ui.panel, &g, passed);
    wait_for_any_key(ui);

    // Exactly as much as those words carry, rather than 256 bits with half thrown away.
    // Stock draws a full seed and truncates for twelve words; the pool can be asked for
    // the length actually wanted, and a draw that is all used is easier to reason about
    // than one that is half discarded.
    let mut entropy = [0u8; 32];
    // The draw is the moment the wallet's key comes into existence, so it runs masked
    // together with everything computed from it: nothing a host can time happens between
    // the entropy appearing and its being encoded. A refusal is reported only once the
    // region has closed.
    let made = crate::keywork::run(|kw| {
        let out = pool.draw(&mut entropy[..entropy_len]).map(|()| {
            (
                catcard_callgate::pin::encode_bip39(&entropy[..entropy_len]),
                Mnemonic::from_entropy(&entropy[..entropy_len], kw),
            )
        });
        entropy.zeroize();
        out
    });
    let (encoded, mnemonic) = match made {
        Ok(pair) => pair,
        Err(e) => {
            // The pool refusing is the entropy design working as intended, so report
            // which way it refused rather than a generic failure.
            crate::catlog!("seed: pool refused");
            let mut l = Line::new();
            let _ = write!(l, "{e}");
            info(ui.panel, "Refused", &[l]);
            wait_for_any_key(ui);
            return;
        }
    };

    let (Ok(mut secret), Ok(mnemonic)) = (encoded, mnemonic) else {
        // Both accept 16 and 32 bytes, which is all `entropy_len` can be, so this is
        // unreachable today. It is written out rather than unwrapped because this is
        // the one function that holds a wallet, and a panic here would carry the seed
        // to the panic screen with it.
        message(ui.panel, "Failed", "could not encode", "that seed length");
        wait_for_any_key(ui);
        return;
    };

    // Words first, the quiz second, the secure element last.
    //
    // That order is the safe one, and it is worth being explicit about why, because the
    // obvious ordering is the wrong way round. Commit first and a power loss between
    // the write and the words leaves a wallet in the element that nobody has a backup
    // of. Commit last and the same power loss leaves nothing at all: the user starts
    // again and draws fresh words, having lost only their time.
    //
    // A failed quiz is therefore free. No wallet exists yet, so it costs nothing to
    // send them back to the list rather than discarding twenty-four hand-written words
    // over one mistaken key.
    loop {
        show_words(ui, &mnemonic);
        if quiz(ui, &mnemonic) {
            break;
        }
        ask(ui.panel, "Not confirmed", "read them again", "and retry?");
        if !confirmed(ui) {
            secret.zeroize();
            crate::catlog!("seed: words not confirmed, nothing stored");
            message(ui.panel, "Nothing stored", "no wallet was", "created");
            wait_for_any_key(ui);
            return;
        }
    }

    // A key handed to another feature (CCC's key C) stops here too: the words are written
    // down and confirmed, and the encoding goes to the caller, which stores it.
    if target == SeedTarget::Handoff {
        if let Some(out) = handoff {
            out.copy_from_slice(&secret);
        }
        secret.zeroize();
        drop(mnemonic);
        return;
    }

    // A temporary seed stops here: the words are written down, and the entropy goes in
    // force for the session instead of into the slot. Locking it down later is the way
    // to keep it, and that screen has its own warnings.
    if target == SeedTarget::Temporary {
        secret.zeroize();
        let was = crate::key::in_force();
        let loaded = crate::key::set_temporary(mnemonic.entropy(), "TRNG Words");
        drop(mnemonic);
        if !loaded {
            message(ui.panel, "Not loaded", "that seed length", "is not usable");
            wait_for_any_key(ui);
            return;
        }
        crate::catlog!("seed: temporary, {} words", words);
        announce_key(gate, login, ui, "Temporary seed", was);
        return;
    }

    message(ui.panel, "Applying", "do not disconnect", "");
    // `Login` is driven through the `PinGate` seam, so that the same sequencing runs
    // against a model on the host and the callgate here.
    let pin_gate = crate::pinentry::BootloaderGate::new(gate);
    let outcome = login.set_secret(&pin_gate, &secret);
    if let Err(f) = outcome {
        secret.zeroize();
        crate::catlog!("seed: store failed");
        message(ui.panel, "Not stored", why_failed(f), "any key to go back");
        wait_for_any_key(ui);
        return;
    }

    // Read it back. The words are already written down by this point, so a slot that
    // did not keep them has to be reported rather than assumed good.
    let kept = login.verify_secret(&pin_gate, &secret).unwrap_or(false);
    secret.zeroize();
    if !kept {
        crate::catlog!("seed: read-back mismatch");
        message(
            ui.panel,
            "Not stored",
            "the slot did not keep",
            "what was written",
        );
        wait_for_any_key(ui);
        return;
    }

    crate::catlog!("seed: stored, {} words", mnemonic.word_count());
    message(
        ui.panel,
        "Wallet created",
        "keep those words",
        "somewhere safe",
    );
    wait_for_any_key(ui);
}

/// Where a freshly generated seed goes.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum SeedTarget {
    /// Into the secure element, as the device's wallet: New on a blank device.
    Store,
    /// In force for this session only, like a key typed in under Derive -> Import key:
    /// stock's Temporary Seed -> Generate Words. Nothing is written; the stored seed,
    /// if there is one, is untouched, and Lock down seed is the way to keep it.
    /// Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §S1 "Generate Words" [C]
    Temporary,
    /// To the caller, as its secret-stash encoding: CCC's key C, which is a second seed
    /// kept in the settings and never the wallet in force. The mk3 has no settings to
    /// keep one in.
    #[cfg_attr(feature = "board-mk3", allow(dead_code))]
    Handoff,
}

/// A fresh phrase for CCC's key C: the same generator, words and quiz as a new wallet,
/// handed back as its stash encoding for the caller to store. `None` if the owner backed
/// out or the pool refused -- each said on screen.
#[cfg(not(feature = "board-mk3"))]
pub(crate) fn new_key_c(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    pool: Option<&mut catcard_entropy::EntropyPool>,
    words: u8,
) -> Option<zeroize::Zeroizing<[u8; catcard_callgate::pin::SECRET_LEN]>> {
    let mut out = zeroize::Zeroizing::new([0u8; catcard_callgate::pin::SECRET_LEN]);
    new_seed(
        gate,
        login,
        ui,
        pool,
        words,
        SeedTarget::Handoff,
        Some(&mut out),
    );
    // A stash's marker is never zero: nothing was handed back.
    (out[0] != 0).then_some(out)
}

/// Derive -> New words: choose a length, then [`new_seed`] into the session.
pub(crate) fn new_temp_seed(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    pool: Option<&mut catcard_entropy::EntropyPool>,
) {
    let Some(row) = pick_row(ui, "New words", "for this session", NEW_SEED_ITEMS) else {
        return;
    };
    let words = match NEW_SEED_ITEMS[row] {
        "12 words" => 12,
        _ => 24,
    };
    new_seed(gate, login, ui, pool, words, SeedTarget::Temporary, None);
}

/// Ask for some of the words back, before anything is committed.
///
/// The only evidence the device ever gets that the words were written down rather than
/// paged past. It runs before the secret reaches the element, so failing it costs
/// nothing: no wallet exists yet and the caller offers the list again.
///
/// Decoys come from the same wordlist as the answer, so nothing about the shape or
/// rarity of an option narrows it down, and the three are shuffled by the DRBG rather
/// than placed — the correct one must not sit in a predictable slot.
///
/// Returns false on a wrong answer or a cancel; the caller stores nothing either way.
fn quiz(ui: &mut Ui<'_>, m: &catcard_wallet::bip39::Mnemonic) -> bool {
    use catcard_wallet::bip39::wordlist::{WORD_COUNT, word};
    const ASKS: usize = 3;
    const CHOICES: usize = 3;

    let total = m.word_count();
    for _ in 0..ASKS {
        // A DRBG failure means it wants reseeding. Refusing is the only safe answer: a
        // quiz whose questions are predictable proves nothing.
        let Ok(pos) = ui.drbg.below(total as u32) else {
            return false;
        };
        let pos = pos as usize;
        let Some(correct) = m.words().nth(pos) else {
            return false;
        };

        let mut choices = [correct; CHOICES];
        for i in 1..CHOICES {
            loop {
                let Ok(pick) = ui.drbg.below(WORD_COUNT as u32) else {
                    return false;
                };
                let w = word(pick as usize);
                // Distinct from the answer and from the other decoys, or the question
                // has two right answers or fewer than three options.
                if w != correct && !choices[..i].contains(&w) {
                    choices[i] = w;
                    break;
                }
            }
        }
        let _ = ui.drbg.shuffle(&mut choices);

        let mut lines: heapless::Vec<Line, { CHOICES + 1 }> = heapless::Vec::new();
        for (i, w) in choices.iter().enumerate() {
            let mut l = Line::new();
            let _ = write!(l, "{}  {w}", i + 1);
            let _ = lines.push(l);
        }
        let mut hint = Line::new();
        let _ = hint.push_str("y = skip");
        let _ = lines.push(hint);
        let mut title = Line::new();
        let _ = write!(title, "Which is word {}?", pos + 1);

        // Loop this one question so a declined skip re-asks it rather than failing.
        loop {
            info(ui.panel, &title, &lines);
            match read_choice(ui, CHOICES) {
                Choice::Pick(i) if choices[i] == correct => break,
                // A wrong pick or a cancel fails the quiz -- the caller offers the list
                // again, and nothing is stored yet, so it costs only time.
                Choice::Pick(_) | Choice::Cancel => return false,
                Choice::Skip => {
                    ask(
                        ui.panel,
                        "Skip the check?",
                        "store without",
                        "confirming words?",
                    );
                    if confirmed(ui) {
                        return true;
                    }
                    // Declined: ask this question again.
                }
            }
        }
    }
    true
}

/// What a person did at a quiz question.
enum Choice {
    /// Picked numbered option `0..n`.
    Pick(usize),
    /// Pressed `y` -- asking to skip the check.
    Skip,
    /// Backed out.
    Cancel,
}

/// Wait for one of `n` numbered choices, a skip (`y`), or a cancel (`x`).
fn read_choice(ui: &mut Ui<'_>, n: usize) -> Choice {
    wait_for_release(ui);
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        let _ = usbtask::pump();
        crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
        for k in keys.iter() {
            match k {
                Key::Cancel => return Choice::Cancel,
                Key::Confirm => return Choice::Skip,
                Key::Digit(d) if *d >= 1 && (*d as usize) <= n => {
                    return Choice::Pick(*d as usize - 1);
                }
                _ => {}
            }
        }
        display::idle(ui.panel);
    }
}

/// Draw a seed from the hardware TRNGs and show its words -- a verification tool, not a
/// wallet. Nothing is stored; it lets the owner see the elements and the chip TRNG
/// produce fresh, varied words, which is the whole point of this project. Shown through
/// the same large-font, emissions-scrambled pager the real backup uses.
pub(crate) fn view_trng_words(gate: &Callgate, ui: &mut Ui<'_>) {
    use catcard_entropy::EntropyPool;
    use catcard_wallet::bip39::Mnemonic;
    use zeroize::Zeroize;

    // A fresh pool, filled only from the hardware sources -- no boot material, no user
    // entropy -- so the words are exactly what the TRNGs produce right now.
    let mut pool = EntropyPool::new(crate::entropy_policy());
    // Held to the start-up test, as New wallet is.
    pool.enforce_startup();

    // The same collection effort as generating a real seed, from the same sources: a full
    // byte target from each, and a pause so the counts are legible. A "watch the generator
    // work" screen that finished in a blink would be reading a handful of bytes and calling
    // it done -- which is exactly the shortcut this project exists to replace, so it is not
    // one this screen is allowed to take either.
    const TARGET: usize = catcard_entropy::STARTUP_SAMPLES;
    const MAX_PASSES: usize = 320;
    const STEP_PAUSE_CYCLES: u32 = 4_000_000;

    let mut trngs = crate::trng::Trngs::new(Some(gate));
    let mut read: heapless::Vec<(crate::trng::Kind, usize), 4> =
        crate::trng::kinds().iter().map(|&k| (k, 0usize)).collect();
    for _ in 0..MAX_PASSES {
        if read.iter().all(|&(_, n)| n >= TARGET) {
            break;
        }
        for entry in read.iter_mut() {
            if entry.1 >= TARGET {
                continue;
            }
            let _ = usbtask::pump();
            let mut buf = [0u8; 64];
            if let Some(n) = trngs.read(entry.0, &mut buf)
                && n > 0
            {
                pool.add(entry.0.source(), &buf[..n]);
                entry.1 += n;
            }
            buf.zeroize();
        }

        let mut counts = Line::new();
        for (i, &(kind, n)) in read.iter().enumerate() {
            let _ = write!(
                counts,
                "{}{} {n}",
                if i > 0 { " " } else { "" },
                kind.label()
            );
        }
        let mut bits = Line::new();
        let _ = write!(bits, "{} bits", pool.credited_bits());
        message(ui.panel, "Reading TRNGs", &counts, &bits);
        catcard_hal::dwt::delay_cycles(STEP_PAUSE_CYCLES);
    }

    if pool.check().is_err() {
        message(
            ui.panel,
            "TRNG words",
            "TRNG check failed",
            "any key to go back",
        );
        wait_for_any_key(ui);
        return;
    }

    let mut entropy = [0u8; 32];
    // Masked: these words are only displayed, never a device key, but it is the same draw
    // and the same encoding a wallet goes through, and one rule is easier to keep than two.
    let mnemonic = crate::keywork::run(|kw| {
        let drawn = pool.draw(&mut entropy);
        let m = drawn
            .ok()
            .and_then(|()| Mnemonic::from_entropy(&entropy, kw).ok());
        entropy.zeroize();
        m
    });
    let Some(mnemonic) = mnemonic else {
        message(
            ui.panel,
            "TRNG words",
            "could not draw",
            "any key to go back",
        );
        wait_for_any_key(ui);
        return;
    };

    // Verification only -- never stored -- but scramble the emissions all the same, since
    // these are valid seed words on screen.
    let texts = word_texts(&mnemonic);
    let mut lines: heapless::Vec<catcard_ui::scroll::Line, 27> = heapless::Vec::new();
    let _ = lines.push(catcard_ui::scroll::Line::title("TRNG words"));
    let _ = lines.push(
        catcard_ui::scroll::Line::body("not saved")
            .small()
            .centered(),
    );
    for s in &texts {
        let _ = lines.push(catcard_ui::scroll::Line::body(s).secret());
    }
    show_doc(ui, &lines, true, false);
}
