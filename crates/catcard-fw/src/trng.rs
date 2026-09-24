//! Every hardware randomness source this board can read, behind one interface.
//!
//! Boot, New wallet, Utils -> Analyze RNG and View TRNG Words each used to decide for
//! themselves which generators a board had, and they drifted: on mk3 the wallet screen
//! gated its whole collection -- the STM32's own TRNG included -- on a callgate only mk4+
//! has, and generated a seed without reading a single fresh byte. This module is the one
//! answer to "what can be read here", so a source added for one board reaches every place
//! that draws.
//!
//! What each source is *worth* is not decided here. [`Kind::source`] names the pool
//! [`Source`], and `catcard-entropy` owns the crediting: a source that cannot be trusted
//! (the bootloader's second read of the MCU TRNG) is still read and mixed, but counts for
//! nothing.

use catcard_callgate::Callgate;
use catcard_callgate::abi::RngSource;
use catcard_entropy::Source;
use zeroize::Zeroize;

/// One readable generator.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Kind {
    /// SE1 through callgate 26 (mk4+): authenticated against the pairing secret.
    Se1,
    /// SE2 through callgate 26 (mk4+).
    Se2,
    /// SE1's `Random` over its raw single-wire bus (mk3, which has no callgate for it).
    /// Unauthenticated, so mixed and credited zero.
    Se1Wire,
    /// The bootloader's read of the MCU TRNG, callgate 17. Every board.
    Bootloader,
    /// The STM32's own TRNG, read directly. Every board.
    Chip,
}

impl Kind {
    /// The pool source these bytes go in under, which decides their credit.
    pub const fn source(self) -> Source {
        match self {
            Kind::Se1 => Source::Se1Trng,
            Kind::Se2 => Source::Se2Trng,
            Kind::Se1Wire => Source::Se1TrngUnauthenticated,
            Kind::Bootloader => Source::BootloaderTrng,
            Kind::Chip => Source::Stm32Trng,
        }
    }

    /// Three characters for a screen.
    pub const fn label(self) -> &'static str {
        match self {
            Kind::Se1 | Kind::Se1Wire => "SE1",
            Kind::Se2 => "SE2",
            Kind::Bootloader => "BL",
            Kind::Chip => "S32",
        }
    }

    /// Whether the board's policy can count on this source. Screens use it to show which
    /// lines are mixed for good measure and which carry the seed.
    pub const fn credited(self) -> bool {
        self.source().is_hardware_trng()
    }
}

/// The sources this board has, in the order screens list them: the secure elements, the
/// bootloader's read, then the chip.
pub fn kinds() -> heapless::Vec<Kind, 4> {
    let mut v = heapless::Vec::new();
    if catcard_board::BOARD.has_callgate_se_rng {
        let _ = v.push(Kind::Se1);
        let _ = v.push(Kind::Se2);
    } else if catcard_board::BOARD.se1_swi.is_some() {
        let _ = v.push(Kind::Se1Wire);
    }
    let _ = v.push(Kind::Bootloader);
    let _ = v.push(Kind::Chip);
    v
}

/// The board's generators, ready to read.
pub struct Trngs<'a> {
    gate: Option<&'a Callgate>,
    chip: Option<catcard_hal::rng::Rng>,
}

impl<'a> Trngs<'a> {
    /// Bring up what needs bringing up. `gate` is `None` when the callgate could not be
    /// bound; the sources behind it then simply produce nothing.
    pub fn new(gate: Option<&'a Callgate>) -> Self {
        Self {
            gate,
            // SAFETY: `Rng::init` is idempotent -- after boot's call it only attaches to
            // the running generator -- and this is the one reader: it is made on the UI
            // task, for one screen, after boot's own handle has been dropped.
            chip: unsafe { catcard_hal::rng::Rng::init() }.ok(),
        }
    }

    /// Read up to `out.len()` bytes from `kind`, returning how many are valid.
    ///
    /// `None` is a refusal or a fault; `Some(0)` is a source with nothing ready yet. The
    /// secure elements answer at most 32 bytes a call, so a caller wanting more calls again.
    pub fn read(&mut self, kind: Kind, out: &mut [u8]) -> Option<usize> {
        match kind {
            Kind::Se1 | Kind::Se2 => {
                let gate = self.gate?;
                let src = if kind == Kind::Se1 {
                    RngSource::Se1
                } else {
                    RngSource::Se2
                };
                let mut buf = [0u8; 33];
                // SAFETY: exactly the documented 33-byte output buffer for callgate 26.
                let got = unsafe { gate.se_rng(src, &mut buf) }.ok();
                let n = got.map(|n| n.min(out.len()));
                if let Some(n) = n {
                    out[..n].copy_from_slice(&buf[1..1 + n]);
                }
                buf.zeroize();
                n
            }
            Kind::Bootloader => {
                let gate = self.gate?;
                let mut buf = [0u8; 32];
                // SAFETY: exactly the documented 32-byte output buffer for callgate 17.
                let ok = unsafe { gate.bootloader_rng(&mut buf) }.is_ok();
                let n = ok.then(|| buf.len().min(out.len()));
                if let Some(n) = n {
                    out[..n].copy_from_slice(&buf[..n]);
                }
                buf.zeroize();
                n
            }
            Kind::Se1Wire => {
                // A bus that has failed several reads in a row is left alone for the rest of
                // the session: each failure costs retries during which the screen cannot
                // move and USB is not served, and it is an extra source, not a needed one.
                use core::sync::atomic::{AtomicU32, Ordering};
                static FAILED_IN_A_ROW: AtomicU32 = AtomicU32::new(0);
                const GIVE_UP_AFTER: u32 = 3;
                if FAILED_IN_A_ROW.load(Ordering::Relaxed) >= GIVE_UP_AFTER {
                    return None;
                }
                let pin = catcard_board::BOARD.se1_swi?;
                // Opened and closed around every read, so the bootloader's bus is only ever
                // borrowed for one exchange and is back as it left it before anything else
                // -- a callgate call above all -- can run.
                // SAFETY: `pin` is this board's SE1 bus, and nothing else runs until the
                // driver is dropped at the end of this arm.
                let got = match unsafe { catcard_hal::se1swi::Se1Swi::open(pin) } {
                    Ok(mut bus) => bus.random(),
                    Err(e) => Err(e),
                };
                // The first few failures go to the log with their reason: this is a bus
                // the firmware drives by hand, and "no bytes" alone says nothing about why.
                match got {
                    Ok(_) => FAILED_IN_A_ROW.store(0, Ordering::Relaxed),
                    Err(e) => {
                        let n = FAILED_IN_A_ROW.fetch_add(1, Ordering::Relaxed) + 1;
                        crate::catlog!("trng: SE1 wire read failed: {:?}", e);
                        if n == GIVE_UP_AFTER {
                            crate::catlog!("trng: SE1 wire not answering; skipped from now on");
                        }
                    }
                }
                let mut bytes = got.ok()?;
                let n = bytes.len().min(out.len());
                out[..n].copy_from_slice(&bytes[..n]);
                bytes.zeroize();
                Some(n)
            }
            Kind::Chip => {
                let rng = self.chip.as_ref()?;
                let n = out.len().min(64);
                rng.fill(&mut out[..n]).ok().map(|()| n)
            }
        }
    }
}
