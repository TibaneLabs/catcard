//! Where threshold signing's randomness comes from (docs/TSS.md, "Randomness").
//!
//! - **Seed-grade**: a DKG member's contribution to the new key, an export's Codex32 noise
//!   and reshare polynomials, the per-session identity key, and the seed of the protocol
//!   DRBG (tsslib's nonces and OT seeds). All of it comes from the session's own
//!   generator, [`Fresh`], made the way a new wallet's words are: every hardware TRNG read
//!   afresh into the pool, the owner's own dice offered, the report shown, then one draw
//!   (`newseed::gather_and_draw`). Nothing here draws from the boot pool as it stands.
//! - **A session's id** is public (it names the card's folder) and comes from the UI
//!   DRBG through [`Drbg`].

use catcard_tss::{Entropy, NoEntropy};

/// A session's own generator: HMAC-DRBG instantiated from one draw of a freshly gathered
/// pool, under its own personalisation. Wiped on drop.
pub(super) struct Fresh(catcard_entropy::HmacDrbg);

impl Fresh {
    /// Gather from every chip, as for a new wallet, and seed the session's generator from
    /// it: 48 bytes of entropy input and a 16-byte nonce, drawn and used with interrupts
    /// masked. `None` once the pool's refusal has been shown.
    pub(super) fn gather(
        gate: &catcard_callgate::Callgate,
        ui: &mut crate::ui::Ui<'_>,
        pool: &mut catcard_entropy::EntropyPool,
    ) -> Option<Fresh> {
        crate::newseed::gather_and_draw(gate, ui, pool, 64, |seed, _kw| {
            Fresh(catcard_entropy::HmacDrbg::new(
                &seed[..48],
                &seed[48..],
                catcard_entropy::domain::TSS,
            ))
        })
    }
}

impl Fresh {
    /// [`gather`](Self::gather) into a pool of the session's own, filled only from the
    /// chips now -- for a flow that holds no pool (signing together is reached from
    /// every way a PSBT arrives), and so that a signing session's nonces rest on nothing
    /// read before it started.
    pub(super) fn gather_own(
        gate: &catcard_callgate::Callgate,
        ui: &mut crate::ui::Ui<'_>,
    ) -> Option<Fresh> {
        let mut pool = catcard_entropy::EntropyPool::new(crate::entropy_policy());
        Self::gather(gate, ui, &mut pool)
    }
}

impl Entropy for Fresh {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), NoEntropy> {
        // One generate call returns at most 8 KiB; ask in pieces.
        for chunk in out.chunks_mut(catcard_entropy::drbg::MAX_BYTES_PER_REQUEST) {
            self.0.generate(chunk).map_err(|_| NoEntropy)?;
        }
        Ok(())
    }
}

/// The UI DRBG, for values that are shown or written in the clear anyway.
pub(super) struct Drbg<'a>(pub(super) &'a mut catcard_entropy::HmacDrbg);

impl Entropy for Drbg<'_> {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), NoEntropy> {
        self.0.generate(out).map_err(|_| NoEntropy)
    }
}
