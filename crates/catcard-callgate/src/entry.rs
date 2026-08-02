//! Finding the callgate, and calling it.
//!
//! # The entry point is published, not fixed
//!
//! The callgate lives behind the STM32 Firewall peripheral: the only legal way into the
//! bootloader's protected code segment is to branch to its call-gate address, and
//! branching anywhere *else* inside that segment resets the CPU. The address moves
//! between bootloader versions and boards, so the bootloader publishes it in a table at
//! a fixed location:
//!
//! ```text
//! 0x0800_0040  callgate_entry   the address to BLX (Thumb, so bit 0 set)
//! 0x0800_0044  version_number   callgate protocol version, BCD (e.g. 0x0100)
//! 0x0800_0048  reserved[4]
//! ```
//!
//! **Read it; never hardcode it.** mk3 happens to give `0x0800_0305`, but mk4 and Q
//! differ.
//!
//! # The calling convention is not AAPCS
//!
//! It looks like a function call and is not one. The buffer *length* occupies `r2`,
//! which an ordinary three-argument `extern "C"` signature would use for the scalar
//! argument — so calling it through a normal function pointer silently passes the wrong
//! values in the wrong registers.
//!
//! | reg | in | out |
//! |---|---|---|
//! | r0 | `method_num` | return value |
//! | r1 | `buf_io` pointer, or NULL | — |
//! | r2 | `buf_io` length, or 0 | — |
//! | r3 | `arg2` | — |
//!
//! The gate runs on its own stack and clobbers `r0`–`r4`, `r9`, `r10`.
//!
//! Source: `hw-reference/bootloader-callgate-abi.md §0` [C],
//! `hw-reference/platform.md §2` [C].

use catcard_board::memory::fixed;
use catcard_board::BoardSpec;

/// Address of the `bootloaderInfoTable_t`. Source: platform.md §2 [C]
pub const INFO_TABLE_ADDR: u32 = 0x0800_0040;

/// Offset of `callgate_entry` within the table.
pub const OFF_CALLGATE_ENTRY: u32 = 0;
/// Offset of `version_number` within the table.
pub const OFF_VERSION: u32 = 4;

/// The call gate sits at `firewall_base + 4`, with bit 0 set for Thumb. The firewall
/// code segment base is 0x100-aligned, so a valid entry address always ends in `0x05`.
///
/// This is a cheap, total check that catches an erased or garbage table before we
/// branch into protected flash — where a wrong target resets the CPU rather than
/// returning an error.
const CALLGATE_ADDR_LOW_BYTE: u32 = 0x05;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum EntryError {
    /// The table reads as erased flash or zero: no bootloader published an entry here.
    NotPopulated { raw: u32 },
    /// Bit 0 is clear, so branching to it would fault out of Thumb state.
    NotThumb { raw: u32 },
    /// Not `firewall_base + 4 + 1` for a 0x100-aligned base.
    NotACallGate { raw: u32 },
    /// Outside the bootloader's flash region — below `FLASH_BASE` or at/above where our
    /// own firmware starts.
    OutsideBootloader { raw: u32, firmware_base: u32 },
}

/// What the bootloader published about itself.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct BootloaderInfo {
    /// Validated address to `BLX`.
    pub callgate_entry: u32,
    /// Callgate protocol version, BCD. Check this before relying on a method that was
    /// added in a later bootloader (callgate 26 is the current example).
    pub version: u32,
}

impl BootloaderInfo {
    /// Major version, from the BCD encoding (`0x0100` → 1).
    pub const fn major(&self) -> u32 {
        (self.version >> 8) & 0xff
    }
    /// Minor version, from the BCD encoding (`0x0102` → 2).
    pub const fn minor(&self) -> u32 {
        self.version & 0xff
    }
}

/// Check a published entry address before branching to it.
///
/// Pure, so the reasoning is testable without hardware — which matters, because the
/// failure mode of getting this wrong is a CPU reset with no diagnostic.
pub fn validate_entry(raw: u32, firmware_base: u32) -> Result<u32, EntryError> {
    if raw == 0 || raw == u32::MAX {
        return Err(EntryError::NotPopulated { raw });
    }
    if raw & 1 == 0 {
        return Err(EntryError::NotThumb { raw });
    }
    if raw & 0xff != CALLGATE_ADDR_LOW_BYTE {
        return Err(EntryError::NotACallGate { raw });
    }
    // The gate must be in bootloader flash: at or above the start of flash, and below
    // where our own image begins.
    if raw < fixed::FLASH_BASE || (raw & !1) >= firmware_base {
        return Err(EntryError::OutsideBootloader { raw, firmware_base });
    }
    Ok(raw)
}

/// Read and validate the bootloader info table.
///
/// # Safety
///
/// Reads main flash at [`INFO_TABLE_ADDR`], which is always mapped and readable. Safe in
/// practice; `unsafe` because a caller on the wrong hardware would misinterpret it.
pub unsafe fn read_info_table(board: &BoardSpec) -> Result<BootloaderInfo, EntryError> {
    // SAFETY: reading two words from mapped main flash.
    let (raw_entry, version) = unsafe {
        (
            core::ptr::read_volatile((INFO_TABLE_ADDR + OFF_CALLGATE_ENTRY) as *const u32),
            core::ptr::read_volatile((INFO_TABLE_ADDR + OFF_VERSION) as *const u32),
        )
    };
    let callgate_entry = validate_entry(raw_entry, board.memory.firmware_base)?;
    Ok(BootloaderInfo {
        callgate_entry,
        version,
    })
}

/// Branch into the callgate.
///
/// Interrupts must already be masked — an interrupt taken inside firewall code closes
/// the firewall and resets the CPU. [`crate::Callgate::call`] handles that.
///
/// # Safety
///
/// `dest` must be a validated callgate entry address for the running bootloader.
/// `buf`/`len` must satisfy the selected method's contract, and `buf` must be in SRAM1.
#[cfg(target_arch = "arm")]
#[inline(never)]
pub unsafe fn invoke(dest: u32, method: i32, buf: *mut u8, len: u32, arg2: u32) -> i32 {
    let rv: i32;
    // SAFETY: the caller guarantees `dest` is the real gate. Register assignment
    // follows the documented convention exactly; see the module docs.
    unsafe {
        core::arch::asm!(
            // The gate clobbers r9 and r10. They are not declared as asm clobbers
            // because LLVM reserves r9 on some ARM configurations and would refuse;
            // saving them here is correct regardless of how the allocator behaves.
            "push {{r9, r10}}",
            "blx {dest}",
            "pop {{r9, r10}}",
            dest = in(reg) dest,
            inout("r0") method => rv,
            inout("r1") buf => _,
            inout("r2") len => _,
            inout("r3") arg2 => _,
            lateout("r4") _,
            lateout("r12") _,
            lateout("lr") _,
            // No `nostack`: the push/pop above uses our stack (the gate itself does
            // not). No `nomem`/`readonly`: the gate reads and writes `buf`.
        );
    }
    rv
}

/// Non-ARM stub so the crate's logic stays host-testable. Never reachable: nothing can
/// produce a validated entry address on a host.
///
/// # Safety
/// Same contract as the ARM implementation; this one always panics.
#[cfg(not(target_arch = "arm"))]
pub unsafe fn invoke(_dest: u32, _method: i32, _buf: *mut u8, _len: u32, _arg2: u32) -> i32 {
    unimplemented!("the callgate can only be invoked on the target")
}

/// Mask interrupts, run `f`, then restore the previous mask state.
///
/// An interrupt taken while executing inside the firewall-protected segment closes the
/// firewall, which the hardware treats as a violation and resets the CPU. This is not a
/// re-entrancy guard — it is a hardware requirement.
///
/// Restores rather than unconditionally enabling, so calling this from a context that
/// already had interrupts masked does not silently enable them.
///
/// # Safety
/// `f` must not depend on interrupts being enabled.
#[cfg(target_arch = "arm")]
pub unsafe fn with_interrupts_masked<R>(f: impl FnOnce() -> R) -> R {
    let primask: u32;
    // SAFETY: reading PRIMASK and masking interrupts.
    unsafe {
        core::arch::asm!("mrs {}, PRIMASK", out(reg) primask, options(nomem, nostack, preserves_flags));
        core::arch::asm!("cpsid i", options(nomem, nostack, preserves_flags));
    }

    let r = f();

    // PRIMASK bit 0 set means interrupts were already masked on entry; leave them so.
    if primask & 1 == 0 {
        // SAFETY: restoring the caller's interrupt state.
        unsafe {
            core::arch::asm!("cpsie i", options(nomem, nostack, preserves_flags));
        }
    }
    r
}

/// Non-ARM stub: there are no interrupts to mask on the host.
///
/// # Safety
/// Same contract as the ARM implementation.
#[cfg(not(target_arch = "arm"))]
pub unsafe fn with_interrupts_masked<R>(f: impl FnOnce() -> R) -> R {
    f()
}

#[cfg(test)]
mod tests {
    use super::*;
    use catcard_board::spec::{MK3, MK4};

    /// The documented mk3 value: firewall segment at 0x0800_0300, +4 for the call gate,
    /// +1 for Thumb.
    const MK3_ENTRY: u32 = 0x0800_0305;

    #[test]
    fn the_documented_mk3_entry_validates() {
        assert_eq!(
            validate_entry(MK3_ENTRY, MK3.memory.firmware_base),
            Ok(MK3_ENTRY)
        );
        // 0x0800_0300 + 4 + 1 — spelled out, as the doc derives it.
        assert_eq!(MK3_ENTRY, 0x0800_0300 + 4 + 1);
    }

    #[test]
    fn an_erased_table_is_rejected() {
        for raw in [0u32, u32::MAX] {
            assert_eq!(
                validate_entry(raw, MK3.memory.firmware_base),
                Err(EntryError::NotPopulated { raw })
            );
        }
    }

    #[test]
    fn a_non_thumb_address_is_rejected() {
        // Same address without the Thumb bit: branching there faults.
        assert_eq!(
            validate_entry(0x0800_0304, MK3.memory.firmware_base),
            Err(EntryError::NotThumb { raw: 0x0800_0304 })
        );
    }

    #[test]
    fn an_address_that_is_not_a_call_gate_is_rejected() {
        // Thumb, in range, but not `0x100-aligned + 4`: entering the protected segment
        // anywhere but the gate resets the CPU, so this must never be branched to.
        for raw in [0x0800_0301u32, 0x0800_0311, 0x0800_03FDu32] {
            assert_eq!(
                validate_entry(raw, MK3.memory.firmware_base),
                Err(EntryError::NotACallGate { raw })
            );
        }
    }

    #[test]
    fn an_address_outside_bootloader_flash_is_rejected() {
        // At or past our own firmware base: that is not the bootloader.
        let raw = MK3.memory.firmware_base + 0x105;
        assert!(matches!(
            validate_entry(raw, MK3.memory.firmware_base),
            Err(EntryError::OutsideBootloader { .. })
        ));
        // Below main flash entirely (e.g. a RAM address).
        assert!(matches!(
            validate_entry(0x2000_0105, MK3.memory.firmware_base),
            Err(EntryError::OutsideBootloader { .. })
        ));
    }

    #[test]
    fn the_bound_is_per_board() {
        // mk4's bootloader is much larger, so an address that is inside it would be
        // outside mk3's. The check has to use the running board's firmware base.
        let raw = 0x0801_0005;
        assert!(validate_entry(raw, MK4.memory.firmware_base).is_ok());
        assert!(matches!(
            validate_entry(raw, MK3.memory.firmware_base),
            Err(EntryError::OutsideBootloader { .. })
        ));
    }

    #[test]
    fn version_bcd_decoding() {
        let info = BootloaderInfo {
            callgate_entry: MK3_ENTRY,
            version: 0x0100,
        };
        assert_eq!(info.major(), 1);
        assert_eq!(info.minor(), 0);

        let info = BootloaderInfo {
            callgate_entry: MK3_ENTRY,
            version: 0x0203,
        };
        assert_eq!(info.major(), 2);
        assert_eq!(info.minor(), 3);
    }

    #[test]
    fn info_table_address_matches_the_reference() {
        assert_eq!(INFO_TABLE_ADDR, 0x0800_0040);
        assert_eq!(INFO_TABLE_ADDR + OFF_VERSION, 0x0800_0044);
        // The table lives inside the bootloader on every board.
        for b in catcard_board::spec::ALL {
            assert!(INFO_TABLE_ADDR < b.memory.firmware_base, "{}", b.name);
        }
    }
}
