//! The Memory Protection Unit, used for exactly one thing: a fence under the main stack.
//!
//! The main (MSP) stack starts at the top of linked RAM and grows down into `.bss` with
//! nothing between them. It has already overflowed once, into the kernel's task table
//! (`catcard-fw/src/heap.rs`), and on this device what sits in `.bss` can be a seed. So
//! this module programs **one** PMSAv7 region -- 32 bytes at the floor, no access for
//! anyone, execute-never -- and turns the MPU on with the default map left in force for
//! every other address. A push that reaches the floor then faults instead of writing.
//!
//! Nothing here runs on the boot path. The guard is armed from *Debug -> Stack guard* and
//! stays off until it has been proven on every board (docs/KERNEL.md §5): a misprogrammed
//! region on an RDP=2 unit is a device that faults on its first stack push, with no way
//! back in.
//!
//! The encoding is kept in pure functions so the arithmetic is tested on the host; the
//! register writes are the thin unsafe layer under them.
//!
//! Registers are the ARMv7-M core's, not ST's, so RM0432 does not describe them:
//!
//! - `MPU_TYPE` 0xE000_ED90, `MPU_CTRL` 0xE000_ED94, `MPU_RNR` 0xE000_ED98,
//!   `MPU_RBAR` 0xE000_ED9C, `MPU_RASR` 0xE000_EDA0.
//!   Source: ARMv7-M ARM (DDI 0403E) §B3.5.4 Table B3-10 "MPU register summary" [C]
//! - `SHCSR` 0xE000_ED24, `MEMFAULTENA` bit 16.
//!   Source: ARMv7-M ARM §B3.2.2 Table B3-4 (SCB summary), §B3.2.13 (SHCSR) [C]
//! - After any change to the MPU registers a `DSB` then an `ISB` are required before the
//!   new map is guaranteed to apply. Source: ARMv7-M ARM §B3.5.2 ("MPU pseudocode" /
//!   barrier note) and §A3.7.3 [C]
//! - The STM32L4 and L4+ cores carry the optional MPU with eight regions. Source: ST
//!   PM0214 §4.2 (Cortex-M4 programming manual) [I] -- not relied on: `MPU_TYPE.DREGION`
//!   is read at run time and zero refuses to arm.

use crate::reg;

/// `MPU_TYPE`: `DREGION` in bits 15:8 is the number of data regions supported; zero means
/// no MPU. Source: ARMv7-M ARM §B3.5.5 [C]
const MPU_TYPE: u32 = 0xE000_ED90;
/// `MPU_CTRL`: `ENABLE` bit 0, `HFNMIENA` bit 1, `PRIVDEFENA` bit 2.
/// Source: ARMv7-M ARM §B3.5.6 [C]
const MPU_CTRL: u32 = 0xE000_ED94;
/// `MPU_RNR`: which region `RBAR`/`RASR` address, in bits 7:0. Source: §B3.5.7 [C]
const MPU_RNR: u32 = 0xE000_ED98;
/// `MPU_RBAR`: `ADDR` in the top bits, `VALID` bit 4, `REGION` bits 3:0. Source: §B3.5.8 [C]
const MPU_RBAR: u32 = 0xE000_ED9C;
/// `MPU_RASR`: `XN` bit 28, `AP` bits 26:24, `TEX`/`S`/`C`/`B` bits 21:16, `SRD` bits
/// 15:8, `SIZE` bits 5:1, `ENABLE` bit 0. Source: §B3.5.9 [C]
const MPU_RASR: u32 = 0xE000_EDA0;
/// `SHCSR`: `MEMFAULTENA` bit 16 routes a MemManage fault to its own handler rather
/// than escalating it to HardFault. Source: ARMv7-M ARM §B3.2.13 [C]
const SHCSR: u32 = 0xE000_ED24;
const SHCSR_MEMFAULTENA: u32 = 1 << 16;

/// `MPU_CTRL.ENABLE`. Source: §B3.5.6 [C]
pub const CTRL_ENABLE: u32 = 1 << 0;
/// `MPU_CTRL.PRIVDEFENA`: with the MPU on, privileged code keeps the default memory map
/// for every address no region covers. Without it, every address outside our one region
/// would fault -- code, data, peripherals, the lot. Source: §B3.5.6 [C]
pub const CTRL_PRIVDEFENA: u32 = 1 << 2;

/// `MPU_RBAR.VALID`: the write also selects the region named in bits 3:0, so `RNR` need
/// not be written first. Both are done anyway; it costs one store. Source: §B3.5.8 [C]
const RBAR_VALID: u32 = 1 << 4;

/// `MPU_RASR.ENABLE`. Source: §B3.5.9 [C]
const RASR_ENABLE: u32 = 1 << 0;
/// `MPU_RASR.XN`: execute-never. Source: §B3.5.9 [C]
const RASR_XN: u32 = 1 << 28;
/// `MPU_RASR.AP = 0b000`: no access, privileged or unprivileged. Source: ARMv7-M ARM
/// §B3.5.9 Table B3-15 "AP encoding" [C]
const RASR_AP_NONE: u32 = 0 << 24;
/// `SIZE` field bit position and width. Source: §B3.5.9 [C]
const RASR_SIZE_SHIFT: u32 = 1;
const RASR_SIZE_MAX: u8 = 31;
/// The smallest region PMSAv7 can express is 32 bytes, `SIZE = 4`: region bytes are
/// `2^(SIZE + 1)`, and `SIZE` values below 4 are reserved. Source: §B3.5.9 [C]
const RASR_SIZE_MIN: u8 = 4;

/// The fence under the main stack: one minimum-size region.
pub const GUARD_BYTES: u32 = 32;

/// The region number the guard uses. Zero: it is the only region this firmware ever
/// programs.
const GUARD_REGION: u8 = 0;

/// Why the guard could not be armed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// `MPU_TYPE.DREGION` is zero: this core has no MPU, or it is not there to be seen.
    NoRegions,
    /// The base is not aligned to the region size, which PMSAv7 requires.
    Misaligned,
}

/// Where the guard goes: the higher of the two section ends, rounded **up** to the region
/// size.
///
/// cortex-m-rt lays `.bss` out and then `.uninit` above it, and provides `_stack_end` at
/// whichever is higher; the main stack grows down towards that point. Rounding up means
/// the 32 guard bytes never overlap the last word of either section -- a region that
/// covered a live static would fault the first read of it. The cost is up to 31 bytes of
/// stack that the fence sits on rather than the program.
pub const fn guard_floor(ebss: u32, euninit: u32) -> u32 {
    let end = if euninit > ebss { euninit } else { ebss };
    // Saturating: an end within 31 bytes of the top of the address space cannot happen
    // on this part, but a wrap to zero would put the fence over the vector table.
    let mask = GUARD_BYTES - 1;
    match end.checked_add(mask) {
        Some(v) => v & !mask,
        // The highest aligned address there is.
        None => !mask,
    }
}

/// The `SIZE` field for a region of `bytes`, or `None` if PMSAv7 cannot express it: the
/// size must be a power of two, at least 32 bytes.
pub const fn size_field(bytes: u32) -> Option<u8> {
    if bytes < GUARD_BYTES || !bytes.is_power_of_two() {
        return None;
    }
    // bytes = 2^(SIZE + 1)  =>  SIZE = log2(bytes) - 1
    let field = bytes.trailing_zeros() as u8 - 1;
    if field < RASR_SIZE_MIN || field > RASR_SIZE_MAX {
        return None;
    }
    Some(field)
}

/// The bytes a `SIZE` field covers. The inverse of [`size_field`].
pub const fn region_bytes(size: u8) -> u32 {
    1u32 << (size as u32 + 1)
}

/// `MPU_RASR` for a region nobody may touch: no access at either privilege level,
/// execute-never, no sub-region disabled, enabled.
///
/// `TEX`/`S`/`C`/`B` are left zero: they describe memory type and cacheability for an
/// access that is *permitted*, and none is.
pub const fn rasr_no_access(size: u8) -> u32 {
    RASR_XN | RASR_AP_NONE | ((size as u32) << RASR_SIZE_SHIFT) | RASR_ENABLE
}

/// `MPU_RBAR` selecting `region` at `base`, which must already be aligned to the region
/// size ([`arm_guard`] checks; this only encodes).
pub const fn rbar(base: u32, region: u8) -> u32 {
    base | RBAR_VALID | (region as u32 & 0xF)
}

/// How many regions the MPU has. Zero means there is no MPU to arm.
pub fn region_count() -> u8 {
    // SAFETY: MPU_TYPE is a read-only ID register.
    let t = unsafe { reg::read(MPU_TYPE) };
    ((t >> 8) & 0xFF) as u8
}

/// Whether the MPU is enabled at all -- which, in this firmware, means the guard is armed:
/// nothing else ever turns it on.
pub fn is_enabled() -> bool {
    // SAFETY: reading MPU_CTRL has no side effects.
    let ctrl = unsafe { reg::read(MPU_CTRL) };
    ctrl & CTRL_ENABLE != 0
}

/// Fence `GUARD_BYTES` at `base` and turn the MPU on, default map kept for everything
/// else.
///
/// After this any access to `base..base + 32` -- a push, a load, a probe -- raises a
/// MemManage fault, or a HardFault if `MEMFAULTENA` is clear (see [`enable_memfault`]).
/// `HFNMIENA` is deliberately left clear, so the HardFault handler itself runs with the
/// MPU bypassed and cannot fault on the fence while it wipes.
///
/// # Safety
/// `base` must be memory nothing live uses: the caller has to know the stack is above it
/// and every static below it. Interrupts should be masked by the caller if anything could
/// touch the region between the `RASR` write and the barrier.
pub unsafe fn arm_guard(base: u32) -> Result<(), Error> {
    if region_count() == 0 {
        return Err(Error::NoRegions);
    }
    if !base.is_multiple_of(GUARD_BYTES) {
        return Err(Error::Misaligned);
    }
    // `size_field(GUARD_BYTES)` is `Some(4)` by construction; a `None` here would be a
    // change to `GUARD_BYTES` that this code was not updated for.
    let Some(size) = size_field(GUARD_BYTES) else {
        return Err(Error::Misaligned);
    };
    // SAFETY: the MPU registers are always present at these addresses on ARMv7-M with
    // an MPU (DREGION checked non-zero above), and the caller owns the memory fenced.
    unsafe {
        // Off while the region is rewritten, so a half-programmed region is never live.
        reg::write(MPU_CTRL, 0);
        barrier();
        reg::write(MPU_RNR, GUARD_REGION as u32);
        reg::write(MPU_RBAR, rbar(base, GUARD_REGION));
        reg::write(MPU_RASR, rasr_no_access(size));
        reg::write(MPU_CTRL, CTRL_ENABLE | CTRL_PRIVDEFENA);
        barrier();
    }
    Ok(())
}

/// Turn the MPU off. The region stays programmed but does nothing.
///
/// # Safety
/// Only in that the memory this unfences becomes writable again; nothing about the call
/// itself can fault.
pub unsafe fn disarm() {
    // SAFETY: a single store to a core register that is always present.
    unsafe {
        reg::write(MPU_CTRL, 0);
        barrier();
    }
}

/// Route MemManage faults to the `MemoryManagement` handler.
///
/// With this clear the fault escalates to HardFault instead, which in this firmware ends
/// in the same wipe-and-reset; this exists so the two are distinguishable, and so the
/// dedicated handler's priority (configurable, below HardFault's fixed -1) applies.
///
/// # Safety
/// The image must define a `MemoryManagement` handler that never returns into the
/// faulting context, or a fault would resume the access that failed.
pub unsafe fn enable_memfault() {
    // SAFETY: read-modify-write of SHCSR, a core register; the caller has interrupts in
    // a state where nothing else writes it.
    unsafe {
        reg::set_bits(SHCSR, SHCSR_MEMFAULTENA);
        barrier();
    }
}

/// `DSB; ISB`: the MPU change is complete and no instruction fetched under the old map
/// is still in flight. Source: ARMv7-M ARM §B3.5.2 [C]
#[inline(always)]
fn barrier() {
    #[cfg(target_arch = "arm")]
    // SAFETY: barriers have no memory or register effects beyond ordering.
    unsafe {
        core::arch::asm!("dsb", "isb", options(nostack, preserves_flags));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_is_the_higher_section_end_rounded_up_to_the_region() {
        // The Q1 map at the time of writing: `.uninit` empty, both ends equal.
        assert_eq!(guard_floor(0x2002_9524, 0x2002_9524), 0x2002_9540);
        // `.uninit` above `.bss` wins.
        assert_eq!(guard_floor(0x2002_9524, 0x2002_9600), 0x2002_9600);
        // `.bss` above (a layout cortex-m-rt does not produce, but the order of the
        // arguments must not matter).
        assert_eq!(guard_floor(0x2002_9600, 0x2002_9524), 0x2002_9600);
        // Already aligned: untouched.
        assert_eq!(guard_floor(0x2000_0020, 0), 0x2000_0020);
        // One byte over an alignment boundary rounds to the next, never down onto a
        // static.
        assert_eq!(guard_floor(0x2000_0021, 0), 0x2000_0040);
        assert_eq!(guard_floor(0x2000_003F, 0), 0x2000_0040);
    }

    #[test]
    fn floor_never_wraps_past_the_top_of_memory() {
        let f = guard_floor(u32::MAX - 3, 0);
        assert_eq!(f % GUARD_BYTES, 0);
        assert!(f >= u32::MAX - 3 - GUARD_BYTES);
    }

    #[test]
    fn size_field_encodes_powers_of_two_from_32_bytes() {
        assert_eq!(size_field(32), Some(4));
        assert_eq!(size_field(64), Some(5));
        assert_eq!(size_field(1024), Some(9));
        assert_eq!(size_field(1 << 31), Some(30));
        // Below the minimum, or not a power of two.
        assert_eq!(size_field(16), None);
        assert_eq!(size_field(0), None);
        assert_eq!(size_field(48), None);
        assert_eq!(size_field(33), None);
    }

    #[test]
    fn size_field_and_region_bytes_are_inverses() {
        for size in RASR_SIZE_MIN..=30 {
            assert_eq!(size_field(region_bytes(size)), Some(size));
        }
    }

    #[test]
    fn the_guard_is_the_minimum_region() {
        assert_eq!(size_field(GUARD_BYTES), Some(RASR_SIZE_MIN));
        assert_eq!(region_bytes(RASR_SIZE_MIN), GUARD_BYTES);
    }

    #[test]
    fn rasr_denies_everything_and_enables() {
        let v = rasr_no_access(4);
        assert_eq!(v & 1, 1, "ENABLE");
        assert_eq!((v >> 1) & 0x1F, 4, "SIZE");
        assert_eq!((v >> 8) & 0xFF, 0, "no sub-region disabled");
        assert_eq!((v >> 24) & 0x7, 0, "AP = no access");
        assert_eq!((v >> 28) & 1, 1, "XN");
        // Nothing else set.
        assert_eq!(v, (1 << 28) | (4 << 1) | 1);
    }

    #[test]
    fn rbar_carries_base_valid_and_region() {
        assert_eq!(rbar(0x2002_9540, 0), 0x2002_9540 | (1 << 4));
        assert_eq!(rbar(0x2002_9540, 3), 0x2002_9540 | (1 << 4) | 3);
        // A region number wider than the field is truncated, not smeared into VALID.
        assert_eq!(rbar(0x2002_9540, 0x13) & 0xF, 3);
    }

    #[test]
    fn a_rounded_floor_is_always_a_legal_base() {
        for end in [0x2000_0001u32, 0x2002_9524, 0x2002_953F, 0x2003_0000] {
            assert_eq!(guard_floor(end, 0) % GUARD_BYTES, 0);
        }
    }
}
