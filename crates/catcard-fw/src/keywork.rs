//! Private-key work, done where a host cannot time it.
//!
//! Anything computed from a private key or a seed -- BIP-39 entropy and seed stretching,
//! BIP-32 derivation, a private key's public key -- runs with interrupts masked for its
//! whole duration. Nothing else runs inside it: no USB reply, no scheduled task, no
//! interrupt handler. A host can then see only when the work began and when it ended, and
//! nothing about what happened in between.
//!
//! That boundary matters more under the kernel, not less. Before it, USB simply went quiet
//! while a screen computed. With USB in its own task, a host could keep sending requests
//! during a derivation and read the response latency as the work progressed.
//!
//! Masking hides the *inside* of the operation. It cannot hide how long the whole thing
//! took -- the gap in USB service is visible -- which is why the operations themselves are
//! written to be constant-time. The two are separate defences against one measurement.
//!
//! The rule is enforced by the type system, not by review: every such function in
//! `catcard-wallet` takes a [`KeyWork`], and the only way firmware gets one is [`run`].
//!
//! Only computation goes inside. A masked region that waited on a keypress or drew a
//! screen would freeze the device; screens and key waits stay outside, and a closure
//! returns results -- public keys, addresses, success or failure -- for them to use.

use catcard_wallet::KeyWork;

/// Run `f` with interrupts masked, lending it the token that private-key functions require.
///
/// The token is created inside the critical section and only lent, so it cannot outlive
/// the masked region: the closure is higher-ranked over the borrow, and nothing it returns
/// can hold onto it. Nests correctly inside a callgate call, which preserves an already
/// masked state rather than unmasking.
pub fn run<R>(f: impl FnOnce(&KeyWork) -> R) -> R {
    cortex_m::interrupt::free(|_| {
        // SAFETY: interrupts are masked for the whole of this closure, and the token is a
        // local that dies at its end -- `f` receives a borrow it cannot return.
        let kw = unsafe { KeyWork::assume_masked() };
        f(&kw)
    })
}
