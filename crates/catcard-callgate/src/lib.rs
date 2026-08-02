//! The bootloader callgate — CatCard's only route to PIN, secrets and SE entropy.
//!
//! The Coldcard bootloader sits in protected flash below our firmware and cannot be
//! replaced (at RDP=2 it cannot even be read). It owns the pairing secret, PIN
//! rate-limiting, secure-element authentication, the genuine light, and DFU. App
//! firmware reaches all of it through one entry point:
//!
//! ```c
//! int gate(int method_num, void *buf_io, uint32_t arg2);
//! ```
//!
//! `buf_io` is used in place for both input and output. The bootloader range-checks
//! it: it must lie in SRAM1 and be at most 1024 bytes.
//!
//! Source: `hw-reference/bootloader-callgate-abi.md` [C].
//!
//! # Status
//!
//! The *ABI* is fully specified. The *entry address* is not — see
//! [`Callgate::new`]. Until it is recovered from a device, [`Callgate::from_board`]
//! returns `None` and no secret operation can run. Everything in this crate below
//! that point is written and tested against the documented layouts, so bring-up is a
//! matter of supplying one address.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod abi;
pub mod pin;

use abi::{err, Method, PinOp, RngSource, MAX_BUF_LEN};
use catcard_board::BoardSpec;
use pin::{PinAttempt, PIN_ATTEMPT_SIZE};

/// The bootloader's calling convention, as an ordinary AAPCS function.
pub type EntryFn = unsafe extern "C" fn(i32, *mut u8, u32) -> i32;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// The callgate entry address is not known for this board yet.
    EntryUnknown,
    /// `buf_io` is not in SRAM1. The bootloader would reject it.
    BufferNotInSram1 { addr: u32, len: usize },
    /// `buf_io` is larger than the bootloader accepts.
    BufferTooLong { len: usize },
    /// The buffer is too small for the method's documented output.
    BufferTooShort { len: usize, need: usize },
    /// A PIN-subsystem error (`-112 ..= -100`).
    Pin(i32),
    /// Any other non-zero return.
    Failed(i32),
}

/// Verify a `buf_io` against the bootloader's own range check, before we make the
/// call rather than after it rejects us.
///
/// Source: bootloader-callgate-abi.md [C] — "must be in SRAM1, `len <= 1024`".
pub fn check_buffer(sram1_base: u32, sram1_len: u32, addr: u32, len: usize) -> Result<(), Error> {
    if len > MAX_BUF_LEN {
        return Err(Error::BufferTooLong { len });
    }
    let end = addr as u64 + len as u64;
    let sram_end = sram1_base as u64 + sram1_len as u64;
    if (addr as u64) < sram1_base as u64 || end > sram_end {
        return Err(Error::BufferNotInSram1 { addr, len });
    }
    Ok(())
}

/// A bound callgate: an entry address plus the SRAM1 window to validate against.
#[derive(Copy, Clone)]
pub struct Callgate {
    entry: u32,
    sram1_base: u32,
    sram1_len: u32,
}

impl Callgate {
    /// Bind the callgate at a known address.
    ///
    /// # The missing address
    ///
    /// `hw-reference` specifies the ABI completely but not where to branch to. The
    /// bootloader is protected by the STM32 Firewall peripheral, which permits entry
    /// into a protected code segment only through its call gate at a fixed offset from
    /// the segment start. So the address is derivable, but both the firewall code
    /// segment base and the offset convention must be read off a device (or from the
    /// `FW_CSSA`/`FW_CSL` option registers) before this can be filled in.
    ///
    /// See `docs/HARDWARE-OPEN-ITEMS.md#callgate-entry-address`.
    ///
    /// # Safety
    ///
    /// `entry` must be the real callgate entry point for the running bootloader.
    /// Branching anywhere else executes arbitrary flash contents with the firewall
    /// pre-armed. `board` must describe the running hardware.
    pub const unsafe fn new(entry: u32, board: &BoardSpec) -> Self {
        Self {
            entry,
            sram1_base: board.memory.sram1_base,
            sram1_len: board.memory.sram1_len,
        }
    }

    /// Bind using the address recorded in the board spec, if there is one.
    ///
    /// Returns `None` on every board today.
    ///
    /// # Safety
    ///
    /// Safe to call, but the caller must be running on `board`'s hardware for the
    /// returned handle to be sound to use.
    pub unsafe fn from_board(board: &BoardSpec) -> Option<Self> {
        // SAFETY: forwarding an address the board spec asserts is correct.
        board.callgate_entry.map(|e| unsafe { Self::new(e, board) })
    }

    /// Invoke the callgate.
    ///
    /// Validates `buf` against the bootloader's range check first, so a mistake shows
    /// up as an `Err` here rather than as an opaque failure from the bootloader.
    ///
    /// # Safety
    ///
    /// The method must be one whose documented `buf_io` contract `buf` satisfies —
    /// the bootloader writes into it in place, using the length the *method* implies,
    /// not the length of the slice.
    pub unsafe fn call(&self, method: Method, buf: &mut [u8], arg2: u32) -> Result<i32, Error> {
        check_buffer(
            self.sram1_base,
            self.sram1_len,
            buf.as_ptr() as u32,
            buf.len(),
        )?;

        // SAFETY: `entry` was asserted correct at construction; `buf` has just been
        // range-checked against the window the bootloader itself enforces.
        let rv = unsafe {
            let f: EntryFn = core::mem::transmute(self.entry as usize);
            f(method as i32, buf.as_mut_ptr(), arg2)
        };

        match rv {
            rv if rv >= 0 => Ok(rv),
            rv if err::is_pin_error(rv) => Err(Error::Pin(rv)),
            rv => Err(Error::Failed(rv)),
        }
    }

    // -- convenience wrappers -------------------------------------------------

    /// Callgate 0: bootloader version string. Returns the length written.
    ///
    /// # Safety
    /// See [`Self::call`].
    pub unsafe fn bootloader_version(&self, buf: &mut [u8]) -> Result<usize, Error> {
        if buf.len() < 64 {
            return Err(Error::BufferTooShort {
                len: buf.len(),
                need: 64,
            });
        }
        // SAFETY: buffer meets the documented >=64-byte output contract.
        let n = unsafe { self.call(Method::GetBootloaderVersion, buf, 0)? };
        Ok(n as usize)
    }

    /// Callgate 5: has the pairing secret stopped working?
    ///
    /// # Safety
    /// See [`Self::call`].
    pub unsafe fn is_bricked(&self) -> Result<bool, Error> {
        let mut empty: [u8; 0] = [];
        // SAFETY: this method takes no buffer.
        match unsafe { self.call(Method::IsBricked, &mut empty, 0) } {
            Ok(rv) => Ok(rv != 0),
            Err(e) => Err(e),
        }
    }

    /// Callgate 17: 32 bytes from the bootloader's STM32 TRNG.
    ///
    /// # Safety
    /// See [`Self::call`].
    pub unsafe fn bootloader_rng(&self, out: &mut [u8; 32]) -> Result<(), Error> {
        // SAFETY: exactly the documented 32-byte output buffer.
        unsafe { self.call(Method::GetBootloaderRng, out.as_mut_slice(), 0)? };
        Ok(())
    }

    /// Callgate 26: TRNG bytes from a secure element (mk4+).
    ///
    /// The buffer is `[len][bytes...]`; returns the populated slice length.
    ///
    /// # Safety
    /// See [`Self::call`].
    pub unsafe fn se_rng(&self, source: RngSource, out: &mut [u8; 33]) -> Result<usize, Error> {
        // SAFETY: exactly the documented 33-byte output buffer.
        unsafe { self.call(Method::ReadSeRng, out.as_mut_slice(), source as u32)? };
        let n = out[0] as usize;
        if n > 32 {
            return Err(Error::Failed(-1));
        }
        Ok(n)
    }

    /// Callgate 18 with a [`PinAttempt`] buffer.
    ///
    /// # Safety
    ///
    /// `attempt` must live in SRAM1 (checked) and must be a struct the bootloader
    /// previously initialised via [`PinOp::Setup`], except for the setup call itself.
    pub unsafe fn pin_attempt(&self, op: PinOp, attempt: &mut PinAttempt) -> Result<i32, Error> {
        // SAFETY: `PinAttempt` is `#[repr(C)]` and exactly `PIN_ATTEMPT_SIZE` bytes
        // (statically asserted), so viewing it as a byte buffer is well defined.
        let buf = unsafe {
            core::slice::from_raw_parts_mut(attempt as *mut PinAttempt as *mut u8, PIN_ATTEMPT_SIZE)
        };
        // SAFETY: buffer matches the documented `pinAttempt_t` contract.
        unsafe { self.call(Method::PinAttempt, buf, op as u32) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use catcard_board::spec::MK4;

    const BASE: u32 = 0x2000_0000;
    const LEN: u32 = 192 * 1024;

    #[test]
    fn buffer_must_be_inside_sram1() {
        assert!(check_buffer(BASE, LEN, BASE, 280).is_ok());
        assert!(check_buffer(BASE, LEN, BASE + LEN - 280, 280).is_ok());

        // Just below SRAM1.
        assert!(matches!(
            check_buffer(BASE, LEN, BASE - 4, 8),
            Err(Error::BufferNotInSram1 { .. })
        ));
        // Runs off the end.
        assert!(matches!(
            check_buffer(BASE, LEN, BASE + LEN - 4, 8),
            Err(Error::BufferNotInSram1 { .. })
        ));
        // The SRAM2 alias window the bootloader reserves is not SRAM1.
        assert!(matches!(
            check_buffer(BASE, LEN, 0x1000_6000, 32),
            Err(Error::BufferNotInSram1 { .. })
        ));
    }

    #[test]
    fn buffer_length_is_capped_at_1024() {
        assert!(check_buffer(BASE, LEN, BASE, MAX_BUF_LEN).is_ok());
        assert!(matches!(
            check_buffer(BASE, LEN, BASE, MAX_BUF_LEN + 1),
            Err(Error::BufferTooLong { .. })
        ));
    }

    #[test]
    fn address_arithmetic_does_not_overflow() {
        // A bogus pointer near the top of the address space must be rejected, not wrap.
        assert!(matches!(
            check_buffer(BASE, LEN, u32::MAX - 4, 64),
            Err(Error::BufferNotInSram1 { .. })
        ));
    }

    #[test]
    fn no_board_has_a_callgate_address_yet() {
        // This test is the tripwire: when the address is recovered and filled in,
        // it fails, which is the prompt to write real integration tests for gate 18.
        for b in catcard_board::spec::ALL {
            assert!(
                b.callgate_entry.is_none(),
                "{}: callgate entry is now known — see HARDWARE-OPEN-ITEMS",
                b.name
            );
        }
        // SAFETY: no address is set, so nothing is called.
        assert!(unsafe { Callgate::from_board(&MK4) }.is_none());
    }
}
