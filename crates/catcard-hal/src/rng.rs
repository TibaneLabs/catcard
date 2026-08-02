//! STM32 hardware TRNG.
//!
//! This is the peripheral the stock firmware never used for the wallet seed. Getting
//! it right is the point of the whole project, so this driver is deliberately strict:
//! it refuses to hand back bytes it cannot vouch for, rather than returning zeroes or
//! stale samples.
//!
//! Register map: `RNG_CR` +0x00, `RNG_SR` +0x04, `RNG_DR` +0x08 at 0x5006_0800.
//! Source: `hw-reference/platform.md §2-3` [C] for the base address, ST RM0351 §24
//! (RM0432 §26 on L4+) for the bit definitions.

use catcard_board::memory::fixed;

use crate::reg;

// Offsets written out in full, `+ 0x00` included, to match RM0351 Table 24.
#[allow(clippy::identity_op)]
const CR: u32 = fixed::RNG + 0x00;
const SR: u32 = fixed::RNG + 0x04;
const DR: u32 = fixed::RNG + 0x08;

// RNG_CR
const CR_RNGEN: u32 = 1 << 2;
/// Clock Error Detection *disable*. Left clear so the peripheral reports a bad clock.
const CR_CED: u32 = 1 << 5;

// RNG_SR
const SR_DRDY: u32 = 1 << 0;
/// Clock error current status.
const SR_CECS: u32 = 1 << 1;
/// Seed error current status.
const SR_SECS: u32 = 1 << 2;
/// Clock error interrupt status (write 0 to clear).
const SR_CEIS: u32 = 1 << 5;
/// Seed error interrupt status (write 0 to clear).
const SR_SEIS: u32 = 1 << 6;

// RCC_AHB2ENR bit 18 enables the RNG clock gate. Source: RM0351 §6.4.17.
const RCC_AHB2ENR: u32 = fixed::RCC + 0x4C;
const AHB2ENR_RNGEN: u32 = 1 << 18;

/// How many polls to wait for `DRDY` before declaring the peripheral dead. The RNG
/// produces a 32-bit word roughly every 40 clock cycles of the 48 MHz RNG clock, so
/// this is several orders of magnitude of headroom.
const DRDY_TRIES: u32 = 100_000;

/// How many times to reset the conditioning chain after a seed error before giving up.
const SEED_ERROR_RETRIES: u32 = 4;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// `DRDY` never came up. Usually the 48 MHz RNG clock is not running — see
    /// [`Rng::init`].
    Timeout,
    /// `CECS`: the RNG clock is out of spec. Output must not be used.
    ClockError,
    /// `SECS`: the entropy source failed its built-in checks repeatedly.
    SeedError,
}

/// Exclusive handle to the RNG peripheral.
pub struct Rng {
    _private: (),
}

impl Rng {
    /// Enable and start the RNG.
    ///
    /// # The 48 MHz clock
    ///
    /// On STM32L4 the RNG needs a dedicated 48 MHz clock selected by
    /// `RCC_CCIPR.CLK48SEL` (HSI48, PLLSAI1 "Q", PLL "Q" or MSI). Without it `DRDY`
    /// never asserts and this returns [`Error::Timeout`]. Clock setup belongs to
    /// [`crate::clock`], not here, so that the RNG driver has exactly one job.
    ///
    /// # Safety
    ///
    /// Must be called at most once; there is no hardware interlock preventing two
    /// handles from racing on `RNG_DR`, and two readers would each get half the
    /// words.
    pub unsafe fn init() -> Result<Self, Error> {
        unsafe {
            reg::set_bits(RCC_AHB2ENR, AHB2ENR_RNGEN);
            // Read back: the RCC needs a cycle for the clock to actually gate on, and
            // reading the register is the documented way to insert that delay.
            let _ = reg::read(RCC_AHB2ENR);

            // Clear any latched error from a previous boot, leave CED clear so clock
            // errors are reported, then enable.
            reg::write(SR, 0);
            reg::modify(CR, CR_CED, CR_RNGEN);
        }

        let this = Self { _private: () };
        // Draw and discard one word: the first sample after enabling is the one the
        // reference manual says to throw away, and it also proves the peripheral is
        // alive before anything depends on it.
        this.word()?;
        Ok(this)
    }

    /// Read one 32-bit random word.
    pub fn word(&self) -> Result<u32, Error> {
        for _ in 0..SEED_ERROR_RETRIES {
            // SAFETY: we hold the exclusive handle to this peripheral.
            let sr = unsafe { reg::read(SR) };

            if sr & (SR_CECS | SR_CEIS) != 0 {
                // A clock error invalidates the output entirely; there is nothing to
                // retry until the clock tree is fixed.
                return Err(Error::ClockError);
            }

            if sr & (SR_SECS | SR_SEIS) != 0 {
                // Seed error: per the reference manual, clear the flag and restart the
                // conditioning by toggling RNGEN, then try again.
                // SAFETY: exclusive handle.
                unsafe {
                    reg::clear_bits(SR, SR_SEIS);
                    reg::clear_bits(CR, CR_RNGEN);
                    reg::set_bits(CR, CR_RNGEN);
                }
                continue;
            }

            // SAFETY: exclusive handle.
            if !unsafe { reg::wait_for(SR, SR_DRDY, SR_DRDY, DRDY_TRIES) } {
                return Err(Error::Timeout);
            }

            // SAFETY: exclusive handle; DRDY is set so DR holds a fresh word.
            let v = unsafe { reg::read(DR) };

            // The reference manual requires re-checking the error flags after the
            // read: a word latched alongside a seed error must be discarded.
            // SAFETY: exclusive handle.
            let sr2 = unsafe { reg::read(SR) };
            if sr2 & (SR_CECS | SR_CEIS) != 0 {
                return Err(Error::ClockError);
            }
            if sr2 & (SR_SECS | SR_SEIS) != 0 {
                continue;
            }
            return Ok(v);
        }
        Err(Error::SeedError)
    }

    /// Fill a buffer with random bytes.
    pub fn fill(&self, out: &mut [u8]) -> Result<(), Error> {
        for chunk in out.chunks_mut(4) {
            let w = self.word()?.to_le_bytes();
            chunk.copy_from_slice(&w[..chunk.len()]);
        }
        Ok(())
    }

    /// Draw `N` bytes straight into the entropy pool, health-tested on the way in.
    ///
    /// This is the only path seed entropy should take: never truncated, never
    /// summarised to a word.
    pub fn feed_pool(
        &self,
        pool: &mut catcard_entropy::EntropyPool,
        bytes: usize,
    ) -> Result<(), Error> {
        let mut buf = [0u8; 64];
        let mut left = bytes;
        while left > 0 {
            let n = left.min(buf.len());
            self.fill(&mut buf[..n])?;
            pool.add(catcard_entropy::Source::Stm32Trng, &buf[..n]);
            left -= n;
        }
        Ok(())
    }
}
