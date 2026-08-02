//! Volatile register access.
//!
//! Deliberately not a PAC. The peripheral surface CatCard needs is small, and a
//! hand-written register layer keeps every address next to the manual section it came
//! from — which is what makes the clean-room provenance auditable.

/// Read a 32-bit peripheral register.
///
/// # Safety
/// `addr` must be a valid, 4-byte-aligned MMIO address for a readable register.
#[inline(always)]
pub unsafe fn read(addr: u32) -> u32 {
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// Write a 32-bit peripheral register.
///
/// # Safety
/// `addr` must be a valid, 4-byte-aligned MMIO address for a writable register, and
/// the caller must have exclusive access to the peripheral.
#[inline(always)]
pub unsafe fn write(addr: u32, val: u32) {
    unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
}

/// Read-modify-write: `*addr = (*addr & !clear) | set`.
///
/// # Safety
/// As [`read`] and [`write`]. Not atomic — callers must hold a critical section if
/// another context can touch the same register.
#[inline(always)]
pub unsafe fn modify(addr: u32, clear: u32, set: u32) {
    unsafe {
        let v = read(addr);
        write(addr, (v & !clear) | set);
    }
}

/// Set bits.
///
/// # Safety
/// As [`modify`].
#[inline(always)]
pub unsafe fn set_bits(addr: u32, bits: u32) {
    unsafe { modify(addr, 0, bits) }
}

/// Clear bits.
///
/// # Safety
/// As [`modify`].
#[inline(always)]
pub unsafe fn clear_bits(addr: u32, bits: u32) {
    unsafe { modify(addr, bits, 0) }
}

/// Spin until `read(addr) & mask == want`, giving up after `tries` polls.
///
/// Every wait in this crate is bounded. An unbounded `while !ready {}` in a wallet's
/// boot path turns a dead peripheral into a silent hang with no diagnosis.
///
/// # Safety
/// As [`read`].
#[inline]
pub unsafe fn wait_for(addr: u32, mask: u32, want: u32, tries: u32) -> bool {
    for _ in 0..tries {
        if unsafe { read(addr) } & mask == want {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}
