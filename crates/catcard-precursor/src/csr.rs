//! Control-register access. Addresses come from the generated table; see `build.rs`.

include!(concat!(env!("OUT_DIR"), "/csr.rs"));

/// Reads a 32-bit control register.
#[inline(always)]
pub fn read(addr: usize) -> u32 {
    // SAFETY: `addr` is a register address from the generated gateware table, an
    // aligned word in the uncached CSR region. Reads have no side effects on the
    // registers this firmware reads (status and data registers documented as such
    // where they are used).
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// Writes a 32-bit control register.
#[inline(always)]
pub fn write(addr: usize, value: u32) {
    // SAFETY: as for `read`; every call site names the register and documents what the
    // written bits do.
    unsafe { core::ptr::write_volatile(addr as *mut u32, value) }
}
