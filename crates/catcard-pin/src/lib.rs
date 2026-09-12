//! PIN login: the state machine that turns keypresses into an unlocked wallet secret.
//!
//! The bootloader owns everything that matters here — the pairing secret, the
//! key-stretching, the attempt counter, the brick. This crate does not implement PIN
//! checking; it sequences [`callgate 18`](catcard_callgate::abi::PinOp) correctly and
//! makes the outcomes something a UI can render without getting them subtly wrong.
//!
//! Source: `hw-reference/gate18-pin-state-machine.md` [C].
//!
//! # The shape of a Coldcard PIN
//!
//! A PIN is `prefix-suffix`, and the split exists for one reason: after the prefix the
//! device shows two **anti-phishing words** derived from the prefix under a key only the
//! bootloader holds. A substituted device cannot compute them. So the user learns
//! whether they are talking to their own device *before* typing the rest of the PIN,
//! which is why [`Login`] refuses to accept a suffix until the words have been shown.
//!
//! # What this crate deliberately does not do
//!
//! - **It does not decide how many attempts are left.** `attempts_left` is read back
//!   from the bootloader after every call; it is never inferred locally.
//! - **It cannot tell a duress login from a real one.** That is by design in the
//!   bootloader (§7), so no API here pretends to distinguish them.
//! - **It does not retry.** Every failed login costs one of thirteen attempts against a
//!   monotonic counter in the secure element. Automatic retry would spend a user's
//!   device.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use catcard_callgate::abi::{err, PinOp};
use catcard_callgate::pin::{PinAttempt, PinTooLong, MAX_PIN_LEN, SECRET_LEN};
use catcard_callgate::Error as GateError;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod words;

/// The separator between the prefix and the suffix, as the bootloader hashes it.
pub const SEPARATOR: u8 = b'-';

/// Longest prefix or suffix we accept.
///
/// The two, plus the separator, have to fit the gate's 32-byte `pin` field. Splitting
/// the budget evenly is a UI choice, not an ABI constraint.
pub const MAX_PART_LEN: usize = (MAX_PIN_LEN - 1) / 2;

/// The most failed attempts a device tolerates before it bricks itself.
///
/// Reported by the bootloader as `attempts_left`; repeated here only so a UI can render
/// "3 of 13" without inventing the denominator. Source: gate18-pin-state-machine.md §8.
pub const MAX_ATTEMPTS: u32 = 13;

/// What the caller should do next.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Step {
    /// Collect the prefix, then call [`Login::prefix_entered`].
    Prefix,
    /// Show these two words, then collect the suffix.
    ///
    /// The user confirming they recognise the words is the whole point of the step; a
    /// UI that displays them without pausing has removed the protection.
    ConfirmWords(words::Words),
    /// Collect the suffix, then call [`Login::attempt`].
    Suffix,
    /// Logged in. The secret can be fetched.
    In { zero_secret: bool },
    /// Wrong PIN. `attempts_left` comes from the bootloader, not from counting here.
    Wrong { attempts_left: u32, num_fails: u32 },
    /// No PIN has ever been set: a blank device, which needs setup rather than login.
    Blank,
    /// The device is bricked — the pairing secret is gone and no PIN will ever work
    /// again. Terminal. The only thing left is to say so and enter DFU.
    Bricked,
    /// The bootloader refused for a reason that is not about this PIN.
    Failed(Failure),
}

/// A refusal that is not "wrong PIN".
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Failure {
    /// The struct's HMAC did not validate. It cannot be repaired — start over from
    /// [`Login::new`], which re-runs setup.
    NeedsSetup,
    /// Rate-limited; the bootloader wants more time before the next attempt.
    MustWait,
    /// The gate itself is unreachable or misbehaving.
    Gate(GateError),
    /// A documented PIN error we have no specific handling for. Carried so the screen
    /// can show the number rather than a shrug.
    Code(i32),
    /// The bootloader refused the staged firmware image. Only from
    /// [`Login::authorize_firmware`], where an auth failure is about the image rather
    /// than the PIN — the PIN was already accepted to get that far.
    ImageRefused,
}

/// A return that cannot happen.
///
/// [`Login::authorize_firmware`] reboots inside the call on success, so its `Ok` arm has
/// no value to carry and no caller to run.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Never {}

/// Entering a PIN part that does not fit.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct TooLong;

impl From<PinTooLong> for TooLong {
    fn from(_: PinTooLong) -> Self {
        TooLong
    }
}

/// The bootloader operations this crate needs.
///
/// A trait rather than a direct [`Callgate`](catcard_callgate::Callgate) call so the
/// sequencing can be tested against a model of the bootloader on the host. The one in
/// this crate's tests counts attempts and bricks at zero, because those are the paths
/// that must not be got wrong and cannot be exercised on a device without destroying
/// it.
pub trait PinGate {
    /// Callgate 18 with the given method.
    fn pin_attempt(&self, op: PinOp, attempt: &mut PinAttempt) -> Result<i32, GateError>;
    /// Callgate 16: 32 bits derived from the PIN prefix.
    fn anti_phishing(&self, prefix: &[u8]) -> Result<u32, GateError>;
}

/// A login in progress.
///
/// Holds a plaintext PIN and, after [`Login::fetch_secret`], the wallet secret; both are
/// zeroed on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Login {
    #[zeroize(skip)]
    attempt: PinAttempt,
    prefix: [u8; MAX_PART_LEN],
    prefix_len: u8,
    /// Set once the words have been computed, so a suffix cannot skip the check.
    #[zeroize(skip)]
    words_shown: bool,
    #[zeroize(skip)]
    step: Step,
}

impl Login {
    /// Run `setup` and report where that leaves us.
    ///
    /// This is the only call that does not need a bootloader-signed struct, so it is
    /// also the recovery path from [`Failure::NeedsSetup`].
    pub fn new<G: PinGate>(gate: &G) -> Self {
        let mut attempt = PinAttempt::new();
        let step = match gate.pin_attempt(PinOp::Setup, &mut attempt) {
            Ok(_) if attempt.is_blank() => Step::Blank,
            Ok(_) => Step::Prefix,
            Err(e) => classify(e),
        };
        Self {
            attempt,
            prefix: [0; MAX_PART_LEN],
            prefix_len: 0,
            words_shown: false,
            step,
        }
    }

    /// What the caller should do next.
    pub fn step(&self) -> Step {
        self.step
    }

    /// Attempts remaining before the device bricks itself, as the bootloader last
    /// reported it.
    pub fn attempts_left(&self) -> u32 {
        self.attempt.attempts_left
    }

    /// Failed attempts since the last good login.
    pub fn num_fails(&self) -> u32 {
        self.attempt.num_fails
    }

    /// Length of the PIN as the gate last saw it, for diagnostics.
    ///
    /// Not the PIN, and never the PIN: a length distinguishes "we sent the wrong
    /// digits" from "we sent nothing", which are different bugs, without putting a
    /// secret on a screen.
    pub fn last_pin_len(&self) -> usize {
        self.attempt.pin_len.max(0) as usize
    }

    /// Submit the prefix and compute its anti-phishing words.
    ///
    /// Moves to [`Step::ConfirmWords`]. Calling it again re-derives the words for a new
    /// prefix, which is what a user backing out of the confirmation screen needs.
    pub fn prefix_entered<G: PinGate>(&mut self, gate: &G, prefix: &[u8]) -> Result<(), TooLong> {
        if prefix.len() > MAX_PART_LEN {
            return Err(TooLong);
        }
        self.prefix.zeroize();
        self.prefix[..prefix.len()].copy_from_slice(prefix);
        self.prefix_len = prefix.len() as u8;

        self.step = match gate.anti_phishing(prefix) {
            Ok(bits) => {
                self.words_shown = true;
                Step::ConfirmWords(words::from_bits(bits))
            }
            Err(e) => classify(e),
        };
        Ok(())
    }

    /// Authorise the firmware staged in PSRAM, and reboot to install it.
    ///
    /// **On mk4 and later this is what makes an upgrade happen.** That bootrom does not
    /// install from staging on its own: it installs what a logged-in `gate 18/7` told it
    /// to, and records the image's `world_check` in a secure-element slot on the way
    /// past. Staging an image and rebooting — which is all mk3 needs — leaves an L4S5
    /// board booting exactly what it booted before, with no error anywhere.
    ///
    /// Requires a successful login: the struct carries the bootloader's HMAC and the
    /// call is refused without it. `Err` on return is the only outcome worth reporting,
    /// because success does not return — the device reboots inside the call.
    ///
    /// `-112` means the bootloader's own verification rejected the staged image, which
    /// is a different and more trustworthy answer than our `inspect`: it is the check
    /// that actually gates the install.
    ///
    /// Source: gate18-pin-state-machine.md §2 method 7 [C],
    /// install-and-usb-transport.md §2b [C]
    pub fn authorize_firmware<G: PinGate>(
        &mut self,
        gate: &G,
        start: u32,
        len: u32,
    ) -> Result<Never, Failure> {
        if !matches!(self.step, Step::In { .. }) {
            return Err(Failure::Code(err::PIN_REQUIRED));
        }
        self.attempt.set_firmware_region(start, len);
        match gate.pin_attempt(PinOp::FirmwareUpgrade, &mut self.attempt) {
            // The call returned, so the install did not happen. The bootloader reports
            // a rejected image as an auth failure, which would otherwise read as a wrong
            // PIN -- it is not; the PIN was accepted and the image was not.
            Ok(_) => Err(Failure::Code(0)),
            Err(GateError::Pin(err::AUTH_FAIL)) => Err(Failure::ImageRefused),
            Err(e) => {
                let s = classify(e);
                self.step = s;
                Err(match s {
                    Step::Failed(f) => f,
                    Step::Bricked => Failure::Code(err::I_AM_BRICK),
                    _ => Failure::Code(0),
                })
            }
        }
    }

    /// The anti-phishing words for a prefix, without touching the login state.
    ///
    /// [`prefix_entered`](Self::prefix_entered) is the login path and advances the state
    /// machine. Setting a *first* PIN needs the same words for a prefix that is not being
    /// logged in with, and using the login path for it moved the machine off
    /// [`Step::Blank`] — which is the exact condition [`set_first_pin`](Self::set_first_pin)
    /// requires, so the PIN was silently never set.
    pub fn words_for<G: PinGate>(&self, gate: &G, prefix: &[u8]) -> Option<words::Words> {
        gate.anti_phishing(prefix).ok().map(words::from_bits)
    }

    /// Acknowledge the words and move on to the suffix.
    ///
    /// Separate from [`Self::prefix_entered`] so that "the user has seen the words" is a
    /// state the caller has to pass through rather than an assumption.
    pub fn words_confirmed(&mut self) {
        if matches!(self.step, Step::ConfirmWords(_)) {
            self.step = Step::Suffix;
        }
    }

    /// Try `prefix-suffix` against the secure element.
    ///
    /// **Costs one of [`MAX_ATTEMPTS`] attempts on failure**, against a monotonic
    /// counter in the secure element. There is no way to give one back.
    ///
    /// Refuses unless the words have been shown for the current prefix, so a UI cannot
    /// accidentally skip the anti-phishing step.
    pub fn attempt<G: PinGate>(&mut self, gate: &G, suffix: &[u8]) -> Result<Step, TooLong> {
        if suffix.len() > MAX_PART_LEN {
            return Err(TooLong);
        }
        if !self.words_shown {
            self.step = Step::Prefix;
            return Ok(self.step);
        }

        let mut joined = [0u8; MAX_PIN_LEN];
        let n = self.join(suffix, &mut joined);
        let set = self.attempt.set_pin(&joined[..n]);
        joined.zeroize();
        set?;

        // Re-run `setup` now the PIN is in the struct, before logging in.
        //
        // The bootloader's HMAC covers `struct[..hmac]`, and `pin`/`pin_len` are inside
        // it — so a struct signed while the PIN field was empty stops validating the
        // moment the PIN is written. §6 of the reference sets the PIN first and *then*
        // calls setup, which is the same thing said from the other end. Getting this
        // backwards fails as `HMAC_FAIL`, which reads like a stale struct rather than
        // like "you filled this in in the wrong order".
        if let Err(e) = gate.pin_attempt(PinOp::Setup, &mut self.attempt) {
            self.step = classify(e);
            return Ok(self.step);
        }

        self.step = match gate.pin_attempt(PinOp::Login, &mut self.attempt) {
            Ok(_) if self.attempt.logged_in() => Step::In {
                zero_secret: self.attempt.has_zero_secret(),
            },
            // A zero return without PA_SUCCESSFUL is the bootloader saying the PIN did
            // not match without raising an error code. Treated as a wrong PIN, because
            // the one thing it definitely is not is a successful login.
            Ok(_) => Step::Wrong {
                attempts_left: self.attempt.attempts_left,
                num_fails: self.attempt.num_fails,
            },
            Err(GateError::Pin(err::AUTH_FAIL)) => Step::Wrong {
                attempts_left: self.attempt.attempts_left,
                num_fails: self.attempt.num_fails,
            },
            Err(e) => classify(e),
        };
        Ok(self.step)
    }

    /// Set the first PIN on a blank device.
    ///
    /// The one change a device with no PIN accepts: `CHANGE_WALLET_PIN` with an empty
    /// `old_pin`. Only offered from [`Step::Blank`], because on a device that already
    /// has a PIN this same call is a *change* and needs the old one — a different
    /// operation with a different failure mode, and not one to reach by accident.
    ///
    /// **Not reversible.** After this the device is PIN-gated: there is no path back to
    /// blank that does not go through knowing the PIN.
    pub fn set_first_pin<G: PinGate>(
        &mut self,
        gate: &G,
        prefix: &[u8],
        suffix: &[u8],
    ) -> Result<Step, TooLong> {
        if !matches!(self.step, Step::Blank) {
            return Ok(self.step);
        }
        if prefix.len() > MAX_PART_LEN || suffix.len() > MAX_PART_LEN {
            return Err(TooLong);
        }

        let mut joined = [0u8; MAX_PIN_LEN];
        let p = prefix.len();
        joined[..p].copy_from_slice(prefix);
        joined[p] = SEPARATOR;
        joined[p + 1..p + 1 + suffix.len()].copy_from_slice(suffix);
        let n = p + 1 + suffix.len();

        self.attempt.change_flags = catcard_callgate::abi::change::WALLET_PIN;
        let set = self
            .attempt
            .set_old_pin(&[])
            .and_then(|()| self.attempt.set_new_pin(&joined[..n]));
        joined.zeroize();
        set?;

        self.step = match gate.pin_attempt(PinOp::Change, &mut self.attempt) {
            Ok(_) => {
                // The device is no longer blank, and the struct that just performed a
                // change is not a struct that can log in: re-run setup so what follows
                // is a login against the PIN that now exists.
                //
                // Leaving this to the caller looked reasonable and was not. The tests
                // built a fresh `Login` afterwards and passed; the firmware carried the
                // same one forward and every login failed with a gate error rather than
                // a wrong PIN — which is a confusing thing to show someone who has just
                // chosen their PIN.
                self.attempt.change_flags = 0;
                match gate.pin_attempt(PinOp::Setup, &mut self.attempt) {
                    Ok(_) if self.attempt.is_blank() => Step::Blank,
                    Ok(_) => Step::Prefix,
                    Err(e) => classify(e),
                }
            }
            Err(e) => classify(e),
        };
        self.attempt.change_flags = 0;
        self.words_shown = false;
        Ok(self.step)
    }

    /// Fetch the wallet secret. Only valid after [`Step::In`].
    pub fn fetch_secret<G: PinGate>(&mut self, gate: &G) -> Result<[u8; SECRET_LEN], Failure> {
        if !matches!(self.step, Step::In { .. }) {
            return Err(Failure::Code(err::PIN_REQUIRED));
        }
        match gate.pin_attempt(PinOp::FetchSecret, &mut self.attempt) {
            Ok(_) => Ok(self.attempt.secret),
            Err(e) => {
                let s = classify(e);
                self.step = s;
                Err(match s {
                    Step::Failed(f) => f,
                    Step::Bricked => Failure::Code(err::I_AM_BRICK),
                    _ => Failure::Code(0),
                })
            }
        }
    }

    /// `prefix` `-` `suffix` into `out`, returning the length written.
    fn join(&self, suffix: &[u8], out: &mut [u8; MAX_PIN_LEN]) -> usize {
        let p = self.prefix_len as usize;
        out[..p].copy_from_slice(&self.prefix[..p]);
        out[p] = SEPARATOR;
        out[p + 1..p + 1 + suffix.len()].copy_from_slice(suffix);
        p + 1 + suffix.len()
    }
}

/// Map a gate error onto the step it leaves the caller in.
///
/// `I_AM_BRICK` is separated from every other code because it is the one that is
/// terminal: no later call will succeed, and a UI that offers "try again" after it is
/// lying to the user.
fn classify(e: GateError) -> Step {
    match e {
        GateError::Pin(err::I_AM_BRICK) => Step::Bricked,
        GateError::Pin(err::HMAC_FAIL | err::HMAC_REQUIRED | err::OLD_ATTEMPT) => {
            Step::Failed(Failure::NeedsSetup)
        }
        GateError::Pin(err::MUST_WAIT) => Step::Failed(Failure::MustWait),
        GateError::Pin(code) => Step::Failed(Failure::Code(code)),
        other => Step::Failed(Failure::Gate(other)),
    }
}

#[cfg(test)]
mod tests;
