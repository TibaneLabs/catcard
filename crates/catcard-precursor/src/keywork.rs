//! Private-key work, with interrupts masked -- the Precursor's `keywork::run`.
//!
//! catcard-wallet's rule (see `catcard_wallet::KeyWork`): anything computed from a seed or
//! a private key runs where nothing else can interrupt it, and the type system enforces
//! that through the token this lends. This firmware never enables interrupts today, so
//! masking changes nothing yet -- but the guarantee is made here, by construction, rather
//! than assumed from the rest of the code staying that way.

use catcard_wallet::KeyWork;

/// Run `f` with machine-mode interrupts masked (`mstatus.MIE` clear), lending it the token.
pub fn run<R>(f: impl FnOnce(&KeyWork) -> R) -> R {
    let mstatus: usize;
    // SAFETY: reads and clears MIE in one instruction; touches no memory.
    unsafe { core::arch::asm!("csrrci {0}, mstatus, 8", out(reg) mstatus) };
    let r = {
        // SAFETY: interrupts are masked from here until the restore below, and the token
        // is a local of this block that only `f` borrows, so no borrow outlives the masked
        // region.
        let kw = unsafe { KeyWork::assume_masked() };
        f(&kw)
    };
    if mstatus & 8 != 0 {
        // SAFETY: re-enables interrupts only if they were enabled on entry.
        unsafe { core::arch::asm!("csrsi mstatus, 8") };
    }
    r
}
