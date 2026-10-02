//! Where threshold signing's randomness comes from (docs/TSS.md, "Randomness").
//!
//! - **Seed-grade**: a DKG member's contribution to the new key, an export's Codex32 noise
//!   and reshare polynomials, and the per-session identity key. These come from the
//!   entropy pool through [`Pool`], which refuses whenever the pool does: the pool is the
//!   one thing on this device that hands out seed material, and this file is on its
//!   allowlist (`tools/pooldraw-lint.sh`, docs/ENTROPY.md).
//! - **The protocol DRBG** -- tsslib's nonces and OT seeds -- is `catcard_tss::rng`'s,
//!   armed for the session with 48 bytes from the same [`Pool`] and wiped after it.
//! - **A session's id** is public (it names the card's folder) and comes from the UI
//!   DRBG through [`Drbg`].

use catcard_tss::{Entropy, NoEntropy};

/// The entropy pool, as `catcard_tss` draws from it.
pub(super) struct Pool<'a> {
    pub(super) pool: &'a mut catcard_entropy::EntropyPool,
}

impl Entropy for Pool<'_> {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), NoEntropy> {
        // The pool hands out at most 64 bytes a draw, each from a fresh counter.
        for chunk in out.chunks_mut(64) {
            self.pool.draw(chunk).map_err(|_| NoEntropy)?;
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
