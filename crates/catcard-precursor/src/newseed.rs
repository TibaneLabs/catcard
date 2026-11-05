//! Fresh seed entropy: both noise sources through a new pool, one draw.
//!
//! The same discipline as `rngcheck.rs` and catcard-fw's `newseed.rs`: each source is read
//! apart and health-tested by the pool under its own `Source`, the start-up test is
//! enforced, `Policy::precursor()` demands both sources and 256 credited bits, and a pool
//! that has not earned it refuses -- this returns that refusal rather than a weaker seed.
//! The draw is wiped once the mnemonic holds it. One of the files tools/pooldraw-lint.sh
//! allows a draw in.

use alloc::format;
use alloc::string::String;

use catcard_entropy::{EntropyPool, Policy, Source};
use catcard_wallet::bip39::{self, Mnemonic};
use zeroize::Zeroize;

use crate::trng::{self, Which};

/// Bytes read per source: the 1024-byte start-up window and a margin.
const PER_SOURCE: usize = 2048;

/// A new mnemonic of `words` words, or why not.
pub fn mnemonic(words: usize) -> Result<Mnemonic, String> {
    let len = bip39::entropy_for_words(words).ok_or_else(|| String::from("bad word count"))?;
    let mut pool = EntropyPool::new(Policy::precursor());
    pool.enforce_startup();
    for which in [Which::Avalanche, Which::RingOsc] {
        let mut buf = [0u8; PER_SOURCE];
        let read = trng::read(which, &mut buf);
        if read.is_ok() {
            for chunk in buf.chunks(256) {
                pool.add(which.source(), chunk);
            }
        }
        buf.zeroize();
        if let Err(e) = read {
            return Err(format!("{}: {e}", which.label()));
        }
    }
    // When it happened: unpredictable to the last millisecond only, credited nothing.
    pool.add(Source::Auxiliary, &crate::timer::now_ms().to_le_bytes());

    let mut entropy = [0u8; 32];
    pool.draw(&mut entropy[..len]).map_err(|e| format!("{e}"))?;
    let made = crate::keywork::run(|kw| Mnemonic::from_entropy(&entropy[..len], kw));
    entropy.zeroize();
    made.map_err(|_| String::from("could not make the words"))
}
