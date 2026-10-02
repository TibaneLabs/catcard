//! Where the randomness comes from.
//!
//! Two consumers, one rule: nothing here reads an OS generator, and nothing invents a
//! fallback when the caller's source refuses.
//!
//! - **This crate** asks the caller for bytes through [`Entropy`]: the session id, the
//!   per-session identity key, a Codex32 split's noise, and the seed of the protocol DRBG
//!   below. Each call is a fallible draw of whole bytes, never a narrow integer.
//! - **tsslib** draws from one process-wide generator it is given with
//!   `tsslib::rng::set_entropy_source`, for every nonce, OT seed and -- in a DKG -- the
//!   member's secret contribution. That registration is first-wins and has no way to
//!   fail later: a draw with nothing registered panics.
//!
//! # How tsslib's generator is fed
//!
//! [`install`] registers a forwarder, once, that reads from a DRBG held in this module
//! (HMAC-DRBG SHA-256, NIST SP 800-90A). The DRBG exists only while a session or an
//! export is running: each one *arms* it with 48 bytes drawn from its caller's [`Entropy`]
//! (the first arming instantiates, a concurrent one reseeds), and the last to finish
//! wipes it. So the firmware's job is:
//!
//! 1. Nothing else in the image calls `tsslib::rng::set_entropy_source`. If something
//!    did first, [`install`] returns `false` and every session refuses to start
//!    ([`crate::Error::Randomness`]) rather than run on a generator nobody here chose.
//! 2. The [`Entropy`] handed to a keygen session or an export is seed-grade (the entropy
//!    pool): what the armed DRBG produces there becomes key material.
//! 3. No tsslib call is made outside a session or an export. Between them the forwarder
//!    has nothing to read and panics, by design: a draw nobody armed for is a bug, and
//!    there is no safe default to hand it.
//!
//! Sessions arm on construction and disarm when dropped, so (3) holds for everything this
//! crate drives.

use alloc::boxed::Box;
use purecrypto::hash::Sha256;
use purecrypto::rng::{CryptoRng, HmacDrbg, RngCore};
use spin::mutex::SpinMutex;
use zeroize::Zeroize;

use crate::Error;

/// A source of random bytes the caller trusts: the entropy pool, or a DRBG seeded from
/// it. A draw may refuse; nothing here retries or substitutes.
pub trait Entropy {
    /// Fill `out` completely, or refuse.
    fn fill(&mut self, out: &mut [u8]) -> Result<(), NoEntropy>;
}

/// The source refused a draw (a health test failed, a DRBG needs reseeding...).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NoEntropy;

/// Bytes drawn to seed the protocol DRBG: 256 bits of entropy input plus a 128-bit
/// nonce, the SP 800-90A instantiation for a 256-bit security strength.
const SEED_LEN: usize = 48;

/// Personalisation strings, so this DRBG's output cannot coincide with another HMAC-DRBG
/// in the image fed the same seed.
const PERSONAL: &[u8] = b"catcard-tss protocol drbg v1";
const RESEED: &[u8] = b"catcard-tss protocol drbg rearm";

struct Slot {
    drbg: Option<HmacDrbg<Sha256>>,
    users: usize,
}

static SLOT: SpinMutex<Slot> = SpinMutex::new(Slot {
    drbg: None,
    users: 0,
});

/// Whether our forwarder is the source tsslib draws from.
static INSTALLED: spin::Once<bool> = spin::Once::new();

/// What tsslib holds: a handle onto [`SLOT`].
struct Forwarder;

impl RngCore for Forwarder {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut slot = SLOT.lock();
        match slot.drbg.as_mut() {
            Some(drbg) => drbg.fill_bytes(dest),
            // tsslib's contract has no error path. Every session and export arms before
            // it calls in, so reaching this is a bug in this crate, not a runtime state.
            None => panic!("catcard-tss: tsslib drew randomness with no session armed"),
        }
    }
}

impl CryptoRng for Forwarder {}

/// Register the forwarder as tsslib's generator. Idempotent; `true` when tsslib draws
/// from this module, `false` if another source was registered first.
pub fn install() -> bool {
    *INSTALLED.call_once(|| tsslib::rng::set_entropy_source(Box::new(Forwarder)))
}

/// The protocol DRBG is armed while this lives. Dropping the last one wipes it.
pub(crate) struct Armed(());

impl Armed {
    /// Arm the protocol DRBG with 48 bytes from `source`.
    pub(crate) fn new(source: &mut dyn Entropy) -> Result<Self, Error> {
        if !install() {
            return Err(Error::Randomness);
        }
        let mut seed = [0u8; SEED_LEN];
        if source.fill(&mut seed).is_err() {
            seed.zeroize();
            return Err(Error::Randomness);
        }
        {
            let mut slot = SLOT.lock();
            match slot.drbg.as_mut() {
                Some(drbg) => drbg.reseed(&seed, RESEED),
                None => slot.drbg = Some(HmacDrbg::new(&seed[..32], &seed[32..], PERSONAL)),
            }
            slot.users += 1;
        }
        seed.zeroize();
        Ok(Armed(()))
    }
}

impl Drop for Armed {
    fn drop(&mut self) {
        let mut slot = SLOT.lock();
        slot.users -= 1;
        if slot.users == 0 {
            // HmacDrbg wipes its key and value on drop.
            slot.drbg = None;
        }
    }
}

/// A generator for tsslib's synchronous calls (the export's reshare), which take their
/// RNG as an argument: HMAC-DRBG seeded with 48 bytes from the caller's [`Entropy`].
pub(crate) struct LocalDrbg(HmacDrbg<Sha256>);

impl LocalDrbg {
    pub(crate) fn new(source: &mut dyn Entropy) -> Result<Self, Error> {
        let mut seed = [0u8; SEED_LEN];
        if source.fill(&mut seed).is_err() {
            seed.zeroize();
            return Err(Error::Randomness);
        }
        let drbg = HmacDrbg::new(&seed[..32], &seed[32..], b"catcard-tss export drbg v1");
        seed.zeroize();
        Ok(LocalDrbg(drbg))
    }
}

impl RngCore for LocalDrbg {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }
}

impl CryptoRng for LocalDrbg {}

/// Draw exactly `out.len()` bytes or report [`Error::Randomness`].
pub(crate) fn draw(source: &mut dyn Entropy, out: &mut [u8]) -> Result<(), Error> {
    source.fill(out).map_err(|_| {
        out.zeroize();
        Error::Randomness
    })
}
