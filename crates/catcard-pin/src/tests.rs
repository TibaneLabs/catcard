//! The sequencing tests, against a model of the bootloader.
//!
//! The model exists because the paths that matter most here — spending attempts,
//! reaching zero, bricking — cannot be exercised on a device without destroying it.
//! It is deliberately *not* a reimplementation of the bootloader: it enforces only the
//! rules this crate has to respect (an HMAC that must round-trip, an attempt counter
//! that only goes down, a brick that is final), so a test failing means our sequencing
//! is wrong rather than our copy of their logic having drifted.

use super::*;
use catcard_callgate::abi::state;
use core::cell::RefCell;

/// A stand-in bootloader.
struct Model {
    correct: &'static [u8],
    inner: RefCell<Inner>,
}

struct Inner {
    attempts_left: u32,
    num_fails: u32,
    blank: bool,
    bricked: bool,
    /// Whether the last struct we handed out is still the one being presented. Models
    /// `_validate_attempt`/`_sign_attempt` without any actual cryptography.
    signed: u32,
    next_signature: u32,
    secret: [u8; SECRET_LEN],
    zero_secret: bool,
    /// The PIN a `Change` installed, so a later login can be checked against it.
    set_pin: Vec<u8>,
    /// Region passed to method 7, if it was called.
    authorized: Option<(u32, u32)>,
    /// Whether the bootloader should reject the staged image.
    refuse_image: bool,
    /// The PIN field as it stood when the struct was last signed.
    signed_pin: Vec<u8>,
}

impl Model {
    fn new(correct: &'static [u8]) -> Self {
        Self {
            correct,
            inner: RefCell::new(Inner {
                attempts_left: MAX_ATTEMPTS,
                num_fails: 0,
                blank: false,
                bricked: false,
                signed: 0,
                next_signature: 1,
                secret: [7; SECRET_LEN],
                zero_secret: false,
                set_pin: Vec::new(),
                authorized: None,
                refuse_image: false,
                signed_pin: Vec::new(),
            }),
        }
    }

    fn blank() -> Self {
        let m = Self::new(b"");
        m.inner.borrow_mut().blank = true;
        m
    }

    /// Put the device one failure away from bricking.
    fn nearly_bricked(correct: &'static [u8]) -> Self {
        let m = Self::new(correct);
        m.inner.borrow_mut().attempts_left = 1;
        m
    }

    fn sign(&self, inner: &mut Inner, a: &mut PinAttempt) {
        inner.signed = inner.next_signature;
        inner.next_signature += 1;
        a.hmac = [0; 32];
        a.hmac[..4].copy_from_slice(&inner.signed.to_le_bytes());
        // The real HMAC covers `struct[..hmac]`, and `pin`/`pin_len` sit inside it. The
        // model records them so a struct edited after signing stops validating, exactly
        // as it does on a device. Without this the model accepted a sequence the
        // bootloader rejects, and the tests passed while every login on hardware failed
        // with HMAC_FAIL.
        inner.signed_pin.clear();
        inner
            .signed_pin
            .extend_from_slice(&a.pin[..a.pin_len as usize]);
    }

    fn validate(&self, inner: &Inner, a: &PinAttempt) -> bool {
        u32::from_le_bytes([a.hmac[0], a.hmac[1], a.hmac[2], a.hmac[3]]) == inner.signed
            && a.pin[..a.pin_len as usize] == *inner.signed_pin.as_slice()
    }
}

impl PinGate for Model {
    fn pin_attempt(&self, op: PinOp, a: &mut PinAttempt) -> Result<i32, GateError> {
        let mut inner = self.inner.borrow_mut();
        if inner.bricked {
            return Err(GateError::Pin(err::I_AM_BRICK));
        }

        // Everything the bootloader checks before it looks at the request, checked here
        // too. A double that waves these through lets a malformed struct pass in tests
        // and fail on a device, which is the failure this whole file exists to prevent.
        if a.magic != catcard_callgate::pin::PA_MAGIC_V2 {
            return Err(GateError::Pin(err::BAD_MAGIC));
        }
        if a.is_secondary != 0 {
            return Err(GateError::Pin(err::BAD_REQUEST));
        }
        // The reference flags this one specifically: the audit found `pin_len`
        // unchecked on the caller's side.
        if a.pin_len < 0 || a.pin_len as usize > catcard_callgate::pin::MAX_PIN_LEN {
            return Err(GateError::Pin(err::RANGE_ERR));
        }
        // The mk4+ mask, which is the mk3 one plus CHANGE_FIRMWARE. Modelling mk3's
        // would reject method 7 outright -- and did, until this test was written: the
        // flag that authorises an upgrade is exactly the bit the older mask omits.
        if a.change_flags & !catcard_callgate::abi::change::VALID_MASK_MK4 != 0 {
            return Err(GateError::Pin(err::BAD_REQUEST));
        }
        if op != PinOp::Setup && !self.validate(&inner, a) {
            return Err(GateError::Pin(err::HMAC_FAIL));
        }
        match op {
            PinOp::Setup => {
                a.state_flags = if inner.blank { state::IS_BLANK } else { 0 };
                a.attempts_left = inner.attempts_left;
                a.num_fails = inner.num_fails;
                self.sign(&mut inner, a);
                Ok(0)
            }
            PinOp::Login => {
                let n = a.pin_len as usize;
                let expected: &[u8] = if inner.set_pin.is_empty() {
                    self.correct
                } else {
                    &inner.set_pin
                };
                let ok = !inner.blank && a.pin[..n] == *expected;
                if ok {
                    inner.num_fails = 0;
                    inner.attempts_left = MAX_ATTEMPTS;
                    a.state_flags = state::SUCCESSFUL
                        | if inner.zero_secret {
                            state::ZERO_SECRET
                        } else {
                            0
                        };
                    a.attempts_left = inner.attempts_left;
                    a.num_fails = inner.num_fails;
                    self.sign(&mut inner, a);
                    Ok(0)
                } else {
                    inner.num_fails += 1;
                    inner.attempts_left = inner.attempts_left.saturating_sub(1);
                    a.state_flags = 0;
                    a.attempts_left = inner.attempts_left;
                    a.num_fails = inner.num_fails;
                    self.sign(&mut inner, a);
                    if inner.attempts_left == 0 {
                        inner.bricked = true;
                    }
                    Err(GateError::Pin(err::AUTH_FAIL))
                }
            }
            PinOp::Change => {
                let flags = a.change_flags;
                // Writing the secret slot. The bootloader takes this only from a caller
                // that has logged in, so a firmware which forgets that must fail here
                // rather than on a device holding someone's wallet.
                if flags == catcard_callgate::abi::change::SECRET {
                    if a.state_flags & state::SUCCESSFUL == 0 {
                        return Err(GateError::Pin(err::PIN_REQUIRED));
                    }
                    // §6 lists old_pin among what a change carries. If one is supplied it
                    // has to be the right one; the model will not accept nonsense there.
                    let old = &a.old_pin[..a.old_pin_len.max(0) as usize];
                    let old_ok = {
                        let expected: &[u8] = if inner.set_pin.is_empty() {
                            self.correct
                        } else {
                            &inner.set_pin
                        };
                        old.is_empty() || old == expected
                    };
                    if !old_ok {
                        return Err(GateError::Pin(err::AUTH_FAIL));
                    }
                    inner.secret = a.secret;
                    inner.zero_secret = a.secret.iter().all(|&b| b == 0);
                    a.state_flags = state::SUCCESSFUL
                        | if inner.zero_secret {
                            state::ZERO_SECRET
                        } else {
                            0
                        };
                    self.sign(&mut inner, a);
                    return Ok(0);
                }
                // Setting the wallet PIN. A blank device takes it with an empty old_pin;
                // a device that already has one takes it from a logged-in caller who
                // supplies the current PIN as old_pin (that is a PIN change).
                if flags != catcard_callgate::abi::change::WALLET_PIN {
                    return Err(GateError::Pin(err::BAD_REQUEST));
                }
                let old = &a.old_pin[..a.old_pin_len.max(0) as usize];
                if inner.blank {
                    if !old.is_empty() {
                        return Err(GateError::Pin(err::AUTH_FAIL));
                    }
                } else {
                    if a.state_flags & state::SUCCESSFUL == 0 {
                        return Err(GateError::Pin(err::PIN_REQUIRED));
                    }
                    let expected: &[u8] = if inner.set_pin.is_empty() {
                        self.correct
                    } else {
                        &inner.set_pin
                    };
                    if old != expected {
                        return Err(GateError::Pin(err::AUTH_FAIL));
                    }
                }
                inner.set_pin.clear();
                inner
                    .set_pin
                    .extend_from_slice(&a.new_pin[..a.new_pin_len as usize]);
                // An empty new PIN clears the PIN: the device returns to blank, and a blank
                // device holds no wallet (PA_IS_BLANK = "no wallet yet"). A non-empty new
                // PIN is an ordinary set/change and leaves the device provisioned.
                if a.new_pin_len == 0 {
                    inner.blank = true;
                    inner.secret = [0; SECRET_LEN];
                    inner.zero_secret = true;
                } else {
                    inner.blank = false;
                }
                // A change logs the session out, as on hardware: the caller re-logs in.
                a.state_flags = 0;
                self.sign(&mut inner, a);
                Ok(0)
            }
            // What the bootloader does for method 7, including what it refuses. The
            // point of modelling the refusals is that a caller which forgets the flag,
            // or asks before logging in, must fail here rather than on silicon.
            PinOp::FirmwareUpgrade => {
                if a.state_flags & state::SUCCESSFUL == 0 {
                    return Err(GateError::Pin(err::PIN_REQUIRED));
                }
                if a.change_flags != catcard_callgate::abi::change::FIRMWARE {
                    return Err(GateError::Pin(err::BAD_REQUEST));
                }
                let start = u32::from_le_bytes(a.secret[..4].try_into().unwrap());
                let len = u32::from_le_bytes(a.secret[4..8].try_into().unwrap());
                inner.authorized = Some((start, len));
                // The real one verifies the staged image and refuses it with AUTH_FAIL.
                if inner.refuse_image {
                    return Err(GateError::Pin(err::AUTH_FAIL));
                }
                // And on success it does not return: it reboots. Nothing the test can
                // model does that, so it reports the fact instead.
                Err(GateError::Pin(err::WRONG_SUCCESS))
            }
            PinOp::FetchSecret => {
                if a.state_flags & state::SUCCESSFUL == 0 {
                    return Err(GateError::Pin(err::PIN_REQUIRED));
                }
                a.secret = inner.secret;
                self.sign(&mut inner, a);
                Ok(0)
            }
            _ => Err(GateError::Pin(err::BAD_REQUEST)),
        }
    }

    fn anti_phishing(&self, prefix: &[u8]) -> Result<u32, GateError> {
        // Any deterministic function of the prefix will do; the point of the real one is
        // that it needs the pairing secret, which is not a property a model can have.
        let mut h = 0x811c_9dc5u32;
        for &b in prefix {
            h = (h ^ b as u32).wrapping_mul(0x0100_0193);
        }
        Ok(h)
    }
}

/// Walk a login all the way through, the way a UI would.
fn login_with(model: &Model, prefix: &[u8], suffix: &[u8]) -> (Login, Step) {
    let mut l = Login::new(model);
    l.prefix_entered(model, prefix).unwrap();
    l.words_confirmed();
    let step = l.attempt(model, suffix).unwrap();
    (l, step)
}

#[test]
fn the_happy_path_reaches_the_secret() {
    let m = Model::new(b"12-3456");
    let (mut l, step) = login_with(&m, b"12", b"3456");
    assert_eq!(step, Step::In { zero_secret: false });
    assert_eq!(l.fetch_secret(&m).unwrap(), [7; SECRET_LEN]);
}

#[test]
fn the_secret_does_not_stay_in_the_struct_after_it_is_read() {
    // The struct goes back to the gate on every later call, and each one copies all of it
    // through the bootloader's staging buffer. A wallet only has to be read once.
    let m = Model::new(b"12-3456");
    let (mut l, _) = login_with(&m, b"12", b"3456");
    assert_eq!(l.fetch_secret(&m).unwrap(), [7; SECRET_LEN]);
    assert_eq!(
        l.attempt.secret, [0; SECRET_LEN],
        "the secret is still resident"
    );
    // And it is still readable: the gate, not this struct, is where it lives.
    assert_eq!(l.fetch_secret(&m).unwrap(), [7; SECRET_LEN]);
}

#[test]
fn the_prefix_and_suffix_are_joined_with_a_separator() {
    // The bootloader hashes the whole string, so where the dash goes is part of the
    // PIN. Getting it wrong would make every correct PIN read as wrong -- and cost the
    // user thirteen attempts finding out.
    let m = Model::new(b"12-3456");
    assert_eq!(
        login_with(&m, b"12", b"3456").1,
        Step::In { zero_secret: false }
    );

    // The same digits without the separator are a different PIN.
    let m2 = Model::new(b"123456");
    assert!(matches!(
        login_with(&m2, b"12", b"3456").1,
        Step::Wrong { .. }
    ));
}

#[test]
fn a_wrong_pin_reports_the_bootloaders_count_not_ours() {
    let m = Model::new(b"12-3456");
    let mut l = Login::new(&m);
    l.prefix_entered(&m, b"12").unwrap();
    l.words_confirmed();

    let step = l.attempt(&m, b"9999").unwrap();
    assert_eq!(
        step,
        Step::Wrong {
            attempts_left: MAX_ATTEMPTS - 1,
            num_fails: 1
        }
    );
    assert_eq!(l.attempts_left(), MAX_ATTEMPTS - 1);
}

#[test]
fn a_good_login_after_failures_clears_the_count() {
    let m = Model::new(b"12-3456");
    let mut l = Login::new(&m);
    l.prefix_entered(&m, b"12").unwrap();
    l.words_confirmed();
    assert!(matches!(
        l.attempt(&m, b"0000").unwrap(),
        Step::Wrong { .. }
    ));
    assert_eq!(
        l.attempt(&m, b"3456").unwrap(),
        Step::In { zero_secret: false }
    );
    assert_eq!(l.attempts_left(), MAX_ATTEMPTS);
    assert_eq!(l.num_fails(), 0);
}

#[test]
fn the_last_attempt_bricks_and_bricking_is_terminal() {
    // The path that cannot be tested on hardware. Once bricked, every later call must
    // keep saying so -- a UI that offers "try again" here is lying to the user.
    let m = Model::nearly_bricked(b"12-3456");
    let mut l = Login::new(&m);
    l.prefix_entered(&m, b"12").unwrap();
    l.words_confirmed();

    assert!(matches!(
        l.attempt(&m, b"0000").unwrap(),
        Step::Wrong {
            attempts_left: 0,
            ..
        }
    ));
    assert_eq!(l.attempt(&m, b"3456").unwrap(), Step::Bricked);
    assert_eq!(Login::new(&m).step(), Step::Bricked);
}

#[test]
fn a_suffix_without_the_words_is_refused() {
    // The anti-phishing words are the only defence against a substituted device, and
    // they only work if the user sees them *before* typing the rest of the PIN. Skipping
    // the confirmation sends the caller back to the prefix rather than spending an
    // attempt.
    let m = Model::new(b"12-3456");
    let mut l = Login::new(&m);
    assert_eq!(l.attempt(&m, b"3456").unwrap(), Step::Prefix);
    assert_eq!(l.attempts_left(), MAX_ATTEMPTS, "an attempt was spent");
}

#[test]
fn the_words_come_from_the_prefix_and_change_with_it() {
    let m = Model::new(b"12-3456");
    let mut l = Login::new(&m);

    l.prefix_entered(&m, b"12").unwrap();
    let Step::ConfirmWords(a) = l.step() else {
        panic!("expected words, got {:?}", l.step())
    };
    l.prefix_entered(&m, b"34").unwrap();
    let Step::ConfirmWords(b) = l.step() else {
        panic!("expected words")
    };
    assert_ne!(a, b, "two prefixes produced the same words");

    // Re-entering the first prefix gives the first words back: they are a function of
    // the prefix, not of how many times the screen has been visited.
    l.prefix_entered(&m, b"12").unwrap();
    assert_eq!(l.step(), Step::ConfirmWords(a));
}

#[test]
fn a_blank_device_is_reported_rather_than_offered_a_login() {
    let m = Model::blank();
    assert_eq!(Login::new(&m).step(), Step::Blank);
}

#[test]
fn an_over_long_part_is_refused_without_spending_an_attempt() {
    let m = Model::new(b"12-3456");
    let mut l = Login::new(&m);
    let long = [b'1'; MAX_PART_LEN + 1];
    assert_eq!(l.prefix_entered(&m, &long), Err(BadPartLength));

    l.prefix_entered(&m, b"12").unwrap();
    l.words_confirmed();
    assert_eq!(l.attempt(&m, &long), Err(BadPartLength));
    assert_eq!(l.attempts_left(), MAX_ATTEMPTS);
}

#[test]
fn a_one_character_part_is_refused_without_spending_an_attempt() {
    // Stock firmware never lets a part be shorter than two, so a one-digit part cannot be
    // anyone's PIN -- sending it to the gate would only burn one of thirteen attempts.
    let m = Model::new(b"12-3456");
    let mut l = Login::new(&m);
    assert_eq!(l.prefix_entered(&m, b"1"), Err(BadPartLength));
    l.prefix_entered(&m, b"12").unwrap();
    l.words_confirmed();
    assert_eq!(l.attempt(&m, b"3"), Err(BadPartLength));
    assert_eq!(l.attempts_left(), MAX_ATTEMPTS);
}

#[test]
fn no_pin_is_set_that_stock_firmware_could_not_type() {
    // The PIN lives in the secure element, not in the firmware. A part outside 2..=6 set
    // here survives a reflash to stock, and stock will not accept it at its prompt: a
    // device nobody can unlock. So setting one is refused before the gate is touched --
    // for a first PIN, and for both sides of a change.
    let m = Model::blank();
    let mut l = Login::new(&m);
    for (prefix, suffix) in [
        (&b"1"[..], &b"3456"[..]),
        (&b"12"[..], &b"3"[..]),
        (&b"1234567"[..], &b"3456"[..]),
        (&b"12"[..], &b"3456789"[..]),
    ] {
        assert_eq!(l.set_first_pin(&m, prefix, suffix), Err(BadPartLength));
        assert_eq!(
            l.step(),
            Step::Blank,
            "a refused first PIN changed the device"
        );
    }
    // The boundaries themselves are allowed.
    assert!(part_len_ok(b"12") && part_len_ok(b"123456"));
    assert!(!part_len_ok(b"1") && !part_len_ok(b"1234567"));

    let m = Model::new(b"12-3456");
    let mut l = Login::new(&m);
    l.prefix_entered(&m, b"12").unwrap();
    l.words_confirmed();
    l.attempt(&m, b"3456").unwrap();
    assert!(matches!(l.step(), Step::In { .. }));
    assert_eq!(
        l.change_pin(&m, b"12", b"3456", b"1234567", b"12"),
        Err(BadPartLength)
    );
    assert!(
        matches!(l.step(), Step::In { .. }),
        "a refused change left the session"
    );
}

#[test]
fn the_longest_pin_the_ui_allows_fits_the_gates_field() {
    // MAX_PART_LEN is a UI split of the gate's 32-byte field. If the arithmetic is
    // wrong, the overflow shows up as a corrupted PIN on a real device rather than here.
    let m = Model::new(b"");
    let mut l = Login::new(&m);
    let part = [b'9'; MAX_PART_LEN];
    l.prefix_entered(&m, &part).unwrap();
    l.words_confirmed();
    // Refused as wrong, not as too long, and nothing panicked on the way.
    assert!(matches!(l.attempt(&m, &part).unwrap(), Step::Wrong { .. }));
    const { assert!(MAX_PART_LEN * 2 < MAX_PIN_LEN) };
}

#[test]
fn a_stale_struct_recovers_instead_of_looking_like_a_wrong_pin() {
    // `attempt` re-runs setup before logging in -- it has to, because the HMAC covers
    // the PIN field -- and setup re-signs. So a struct that stopped round-tripping is
    // repaired rather than reported.
    //
    // That is the outcome worth having. The failure this replaces was showing "wrong
    // PIN, 12 attempts left" to someone who had typed it correctly, and nothing about
    // the counters is invented here: setup re-reads them from the device.
    let m = Model::new(b"12-3456");
    let mut l = Login::new(&m);
    l.prefix_entered(&m, b"12").unwrap();
    l.words_confirmed();

    // Something else talks to the gate in between, so our signature is no longer current.
    let _ = Login::new(&m);

    assert_eq!(
        l.attempt(&m, b"3456").unwrap(),
        Step::In { zero_secret: false }
    );
    assert_eq!(l.attempts_left(), MAX_ATTEMPTS);
}

#[test]
fn the_secret_cannot_be_fetched_before_logging_in() {
    let m = Model::new(b"12-3456");
    let mut l = Login::new(&m);
    assert!(l.fetch_secret(&m).is_err());

    l.prefix_entered(&m, b"12").unwrap();
    l.words_confirmed();
    assert!(matches!(
        l.attempt(&m, b"0000").unwrap(),
        Step::Wrong { .. }
    ));
    assert!(l.fetch_secret(&m).is_err(), "fetched after a failed login");
}

#[test]
fn a_logged_in_device_with_no_seed_says_so() {
    // Logged in but nothing stored: the device needs seed generation, not a wallet
    // screen. Distinct from Blank, which is "no PIN either".
    let m = Model::new(b"12-3456");
    m.inner.borrow_mut().zero_secret = true;
    assert_eq!(
        login_with(&m, b"12", b"3456").1,
        Step::In { zero_secret: true }
    );
}

#[test]
fn a_blank_device_can_be_given_its_first_pin_and_then_asks_for_it() {
    // The whole first-run sequence: blank, set a PIN, and from then on the device is
    // PIN-gated. Untested until now because the emulator's secure element is blank, so
    // every run took the `Blank` path and stopped there.
    let m = Model::blank();
    let mut l = Login::new(&m);
    assert_eq!(l.step(), Step::Blank);

    assert_eq!(l.set_first_pin(&m, b"12", b"3456").unwrap(), Step::Prefix);

    // It is no longer blank, and the PIN just set is the one that works.
    let mut l = Login::new(&m);
    assert_eq!(l.step(), Step::Prefix, "still reporting itself blank");
    l.prefix_entered(&m, b"12").unwrap();
    l.words_confirmed();
    assert_eq!(
        l.attempt(&m, b"3456").unwrap(),
        Step::In { zero_secret: false }
    );
}

#[test]
fn the_wrong_pin_after_setup_is_wrong_and_costs_an_attempt() {
    let m = Model::blank();
    let mut l = Login::new(&m);
    l.set_first_pin(&m, b"12", b"3456").unwrap();

    let mut l = Login::new(&m);
    l.prefix_entered(&m, b"12").unwrap();
    l.words_confirmed();
    assert_eq!(
        l.attempt(&m, b"9999").unwrap(),
        Step::Wrong {
            attempts_left: MAX_ATTEMPTS - 1,
            num_fails: 1
        }
    );
}

#[test]
fn setting_a_first_pin_is_refused_once_one_exists() {
    // On a device that already has a PIN this is a *change*, which needs the old one --
    // a different operation with a different failure mode, and not one to reach by
    // walking into it.
    let m = Model::new(b"12-3456");
    let mut l = Login::new(&m);
    assert_eq!(l.step(), Step::Prefix, "model should not be blank");
    assert_eq!(l.set_first_pin(&m, b"99", b"9999").unwrap(), Step::Prefix);

    // The original PIN still works, so nothing was changed.
    let mut l = Login::new(&m);
    l.prefix_entered(&m, b"12").unwrap();
    l.words_confirmed();
    assert_eq!(
        l.attempt(&m, b"3456").unwrap(),
        Step::In { zero_secret: false }
    );
}

#[test]
fn showing_the_words_does_not_stop_a_first_pin_being_set() {
    // Setup shows the anti-phishing words before taking the suffix. Doing that through
    // the login path moved the state machine off `Blank`, and `set_first_pin` then
    // refused without saying so -- the device walked the whole setup flow and came back
    // with no PIN set. `words_for` is a query, so the guard keeps its meaning.
    let m = Model::blank();
    let mut l = Login::new(&m);
    assert_eq!(l.step(), Step::Blank);

    let w = l.words_for(&m, b"12").expect("words");
    assert_eq!(l.step(), Step::Blank, "asking for words changed the state");
    assert_eq!(
        l.words_for(&m, b"12"),
        Some(w),
        "not a pure function of the prefix"
    );

    assert_eq!(l.set_first_pin(&m, b"12", b"3456").unwrap(), Step::Prefix);

    let mut l = Login::new(&m);
    l.prefix_entered(&m, b"12").unwrap();
    l.words_confirmed();
    assert_eq!(
        l.attempt(&m, b"3456").unwrap(),
        Step::In { zero_secret: false }
    );
}

#[test]
fn the_same_login_can_be_used_to_sign_in_after_setting_the_first_pin() {
    // The firmware carries one `Login` through setup and straight into the sign-in that
    // follows. Every earlier test built a fresh one at that point, so the struct left
    // behind by a `Change` was never exercised -- and on the device every login after
    // setup failed with a gate error rather than a wrong PIN.
    let m = Model::blank();
    let mut l = Login::new(&m);
    let w = l.words_for(&m, b"12").expect("words");
    assert_eq!(l.set_first_pin(&m, b"12", b"3456").unwrap(), Step::Prefix);

    // No new Login: continue with this one, as the screens do.
    l.prefix_entered(&m, b"12").unwrap();
    assert_eq!(l.step(), Step::ConfirmWords(w), "words changed after setup");
    l.words_confirmed();
    assert_eq!(
        l.attempt(&m, b"3456").unwrap(),
        Step::In { zero_secret: false }
    );
}

/// The double must reject what the bootloader rejects, or a malformed struct passes
/// here and fails on a device. Each of these is a documented refusal, and each is
/// checked by corrupting exactly one field of an otherwise valid request.
mod the_model_enforces_what_the_bootloader_does {
    use super::*;

    fn ready() -> (Model, PinAttempt) {
        let m = Model::new(b"12-3456");
        let mut a = PinAttempt::new();
        m.pin_attempt(PinOp::Setup, &mut a).expect("setup");
        (m, a)
    }

    #[test]
    fn a_wrong_magic_is_bad_magic() {
        let (m, mut a) = ready();
        a.magic = 0xDEAD_BEEF;
        assert_eq!(
            m.pin_attempt(PinOp::Login, &mut a),
            Err(GateError::Pin(err::BAD_MAGIC))
        );
    }

    #[test]
    fn a_secondary_request_is_refused() {
        // Secondary wallets were an ATECC508-era feature and the field must be zero.
        let (m, mut a) = ready();
        a.is_secondary = 1;
        assert_eq!(
            m.pin_attempt(PinOp::Login, &mut a),
            Err(GateError::Pin(err::BAD_REQUEST))
        );
    }

    #[test]
    fn an_out_of_range_pin_len_is_a_range_error() {
        // The reference names this one: the audit found `pin_len` unchecked on the
        // caller's side, so a double that ignores it is reproducing the original bug.
        let (m, mut a) = ready();
        a.pin_len = catcard_callgate::pin::MAX_PIN_LEN as i32 + 1;
        assert_eq!(
            m.pin_attempt(PinOp::Login, &mut a),
            Err(GateError::Pin(err::RANGE_ERR))
        );

        a.pin_len = -1;
        assert_eq!(
            m.pin_attempt(PinOp::Login, &mut a),
            Err(GateError::Pin(err::RANGE_ERR))
        );
    }

    #[test]
    fn undefined_change_flags_are_a_bad_request() {
        let (m, mut a) = ready();
        a.change_flags = !catcard_callgate::abi::change::VALID_MASK_MK4;
        assert_eq!(
            m.pin_attempt(PinOp::Change, &mut a),
            Err(GateError::Pin(err::BAD_REQUEST))
        );
    }

    #[test]
    fn a_valid_request_still_passes_all_of_them() {
        // The guards have to admit the real thing, or every other test in this file is
        // passing for the wrong reason.
        let (m, mut a) = ready();
        a.set_pin(b"12-3456").unwrap();
        m.pin_attempt(PinOp::Setup, &mut a).expect("re-sign");
        assert_eq!(m.pin_attempt(PinOp::Login, &mut a), Ok(0));
        assert!(a.logged_in());
    }
}

// ---------------------------------------------------------------------------
// gate 18 / 7 — authorising a staged firmware
// ---------------------------------------------------------------------------

/// The call must carry the region and the flag, or the bootloader rejects the request.
///
/// On mk4 and later this call *is* the upgrade: staging and rebooting, which is all mk3
/// needs, leaves an L4S5 board booting what it booted before and reporting nothing.
#[test]
fn authorising_firmware_passes_the_region_and_the_change_flag() {
    let g = Model::new(b"12-3456");
    let (mut l, _) = login_with(&g, b"12", b"3456");
    assert!(matches!(l.step(), Step::In { .. }), "not logged in");

    // The model cannot reboot, so a success arrives as WRONG_SUCCESS.
    let r = l.authorize_firmware(&g, 0x9040_0000, 262_144);
    assert!(r.is_err());
    assert_eq!(
        g.inner.borrow().authorized,
        Some((0x9040_0000, 262_144)),
        "the staged region did not reach the gate"
    );
}

/// A refused image is not a refused PIN. The PIN was accepted to get this far, and
/// reporting "wrong PIN" here would send someone to re-enter one that was right.
#[test]
fn an_image_the_bootloader_rejects_is_reported_as_such() {
    let g = Model::new(b"12-3456");
    g.inner.borrow_mut().refuse_image = true;
    let (mut l, _) = login_with(&g, b"12", b"3456");
    assert_eq!(
        l.authorize_firmware(&g, 0x9040_0000, 262_144),
        Err(Failure::ImageRefused)
    );
}

/// Asking before logging in must fail here rather than at the gate.
#[test]
fn authorising_without_a_login_is_refused_before_the_call() {
    let g = Model::new(b"12-3456");
    let mut l = Login::new(&g);
    assert!(l.authorize_firmware(&g, 0x9040_0000, 262_144).is_err());
    assert_eq!(
        g.inner.borrow().authorized,
        None,
        "the gate was called without a login"
    );
}

// ---------------------------------------------------------------------------
// gate 18 / 3 — writing the wallet secret
// ---------------------------------------------------------------------------

#[test]
fn a_generated_secret_can_be_stored_and_read_back() {
    // The whole point of the milestone: a device that had no seed has one afterwards,
    // and the bytes that come back are the bytes that went in.
    let m = Model::new(b"12-3456");
    m.inner.borrow_mut().zero_secret = true;
    let (mut l, step) = login_with(&m, b"12", b"3456");
    assert_eq!(
        step,
        Step::In { zero_secret: true },
        "model should start with no seed"
    );

    let secret = catcard_callgate::pin::encode_bip39(&[0x5A; 32]).unwrap();
    assert_eq!(
        l.set_secret(&m, &secret).unwrap(),
        Step::In { zero_secret: false },
        "the device should no longer report an empty secret slot"
    );
    assert!(
        l.verify_secret(&m, &secret).unwrap(),
        "what came back is not what was written"
    );
    assert_eq!(l.fetch_secret(&m).unwrap(), secret);
}

#[test]
fn storing_a_secret_without_a_login_is_refused_before_the_gate() {
    let m = Model::new(b"12-3456");
    let mut l = Login::new(&m);
    let secret = catcard_callgate::pin::encode_bip39(&[1; 16]).unwrap();
    assert!(l.set_secret(&m, &secret).is_err());
    assert_eq!(
        m.inner.borrow().secret,
        [7; SECRET_LEN],
        "the slot was written without a login"
    );
}

#[test]
fn a_stored_secret_is_not_left_behind_in_the_attempt_struct() {
    // The struct is handed back to the gate on every later call. A plaintext seed parked
    // in it only has to be read once.
    let m = Model::new(b"12-3456");
    let (mut l, _) = login_with(&m, b"12", b"3456");
    let secret = catcard_callgate::pin::encode_bip39(&[0x42; 24]).unwrap();
    l.set_secret(&m, &secret).unwrap();
    assert!(
        l.attempt.secret.iter().all(|&b| b == 0),
        "the seed is still sitting in the attempt struct"
    );
}

#[test]
fn a_slot_that_did_not_keep_what_we_wrote_is_reported() {
    // The failure `verify_secret` exists for: the gate accepted the write, the element
    // did not keep it. Discovering that now beats discovering it at the next unlock,
    // after the words have been shown and written down.
    let m = Model::new(b"12-3456");
    let (mut l, _) = login_with(&m, b"12", b"3456");
    let secret = catcard_callgate::pin::encode_bip39(&[9; 32]).unwrap();
    l.set_secret(&m, &secret).unwrap();

    m.inner.borrow_mut().secret = [3; SECRET_LEN];
    assert!(
        !l.verify_secret(&m, &secret).unwrap(),
        "a slot holding something else was reported as matching"
    );
}

#[test]
fn changing_the_pin_takes_the_new_one_and_retires_the_old() {
    let m = Model::new(b"12-3456");
    let (mut l, step) = login_with(&m, b"12", b"3456");
    assert_eq!(step, Step::In { zero_secret: false });

    // Change to a new PIN: the struct is re-run through Setup, landing at Prefix.
    assert_eq!(
        l.change_pin(&m, b"12", b"3456", b"99", b"8888").unwrap(),
        Step::Prefix
    );

    // The new PIN logs in; the old one is now wrong.
    let (_l2, s2) = login_with(&m, b"99", b"8888");
    assert_eq!(s2, Step::In { zero_secret: false });
    let (_l3, s3) = login_with(&m, b"12", b"3456");
    assert!(matches!(s3, Step::Wrong { .. }), "the old PIN still worked");
}

#[test]
fn changing_the_pin_with_the_wrong_current_pin_is_refused_and_changes_nothing() {
    let m = Model::new(b"12-3456");
    let (mut l, _) = login_with(&m, b"12", b"3456");

    // A wrong current PIN is refused, as a wrong login would be.
    let step = l.change_pin(&m, b"00", b"0000", b"99", b"8888").unwrap();
    assert!(
        matches!(step, Step::Wrong { .. } | Step::Failed(_)),
        "a wrong current PIN was accepted"
    );

    // And the PIN is untouched: the original still logs in, the attempted new one does not.
    let (_l2, s2) = login_with(&m, b"12", b"3456");
    assert_eq!(s2, Step::In { zero_secret: false });
    let (_l3, s3) = login_with(&m, b"99", b"8888");
    assert!(matches!(s3, Step::Wrong { .. }));
}

#[test]
fn a_change_pin_before_login_does_nothing() {
    // Only a logged-in session may change the PIN; a fresh struct is at Prefix.
    let m = Model::new(b"12-3456");
    let mut l = Login::new(&m);
    let step = l.change_pin(&m, b"12", b"3456", b"99", b"8888").unwrap();
    assert_eq!(step, Step::Prefix, "change_pin acted outside a login");
}

#[test]
fn clearing_the_pin_returns_the_device_to_blank() {
    // Factory reset: CHANGE_WALLET_PIN with the current PIN as old and an empty new. The
    // device ends blank -- no PIN, no wallet -- and the struct reports it.
    let m = Model::new(b"12-3456");
    let (mut l, _) = login_with(&m, b"12", b"3456");
    let secret = catcard_callgate::pin::encode_bip39(&[9; 32]).unwrap();
    l.set_secret(&m, &secret).unwrap();

    assert_eq!(l.clear_pin(&m, b"12", b"3456").unwrap(), Step::Blank);

    // A fresh login now finds a blank device that needs setup, not a PIN prompt, and the
    // wallet is gone with the PIN.
    let l2 = Login::new(&m);
    assert_eq!(l2.step(), Step::Blank, "the device still asked for a PIN");
    assert!(
        m.inner.borrow().zero_secret,
        "the wallet survived the reset"
    );
}

#[test]
fn clearing_the_pin_with_the_wrong_current_pin_is_refused() {
    // The current PIN is still required, so a factory reset cannot wipe a device the
    // operator has not actually unlocked with the right PIN.
    let m = Model::new(b"12-3456");
    let (mut l, _) = login_with(&m, b"12", b"3456");

    let step = l.clear_pin(&m, b"00", b"0000").unwrap();
    assert!(
        matches!(step, Step::Wrong { .. } | Step::Failed(_)),
        "a wrong current PIN cleared the PIN anyway"
    );
    // Untouched: the real PIN still logs in, and the device is not blank.
    let (_l2, s2) = login_with(&m, b"12", b"3456");
    assert_eq!(s2, Step::In { zero_secret: false });
    assert!(
        !m.inner.borrow().blank,
        "the device was wiped on a wrong PIN"
    );
}

#[test]
fn a_clear_pin_before_login_does_nothing() {
    let m = Model::new(b"12-3456");
    let mut l = Login::new(&m);
    let step = l.clear_pin(&m, b"12", b"3456").unwrap();
    assert_eq!(step, Step::Prefix, "clear_pin acted outside a login");
    assert!(!m.inner.borrow().blank, "clear_pin wiped without a login");
}
