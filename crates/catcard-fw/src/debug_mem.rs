//! The raw memory monitor behind `DebugPeek` / `DebugPoke` / `DebugJsr`.
//!
//! peek, poke, jsr: read an address, write an address, call an address. A ZX-Spectrum
//! monitor for a Cortex-M, and about as safe -- which is to say not at all. It reads and
//! writes anything the bus will answer, and runs whatever a host hands it.
//!
//! **This is the most dangerous code in the firmware, and it must never ship.** It is
//! behind `usb-debug-mem`, which the `fw-*-bringup` aliases leave off; only `fw-*-debug`
//! turns it on. On a device holding a secret it reads the seed and PIN straight out of
//! RAM, because there is nothing here that could stop it -- that is the point of a
//! monitor and the reason it is a bring-up tool and nothing else.
//!
//! Every access is logged by the caller. A peek is bounded to what one reply frame
//! carries; a poke and a jsr are bounded only by what the hardware does.

/// Read `count` elements of `width` (1/2/4) bytes from `addr` into `out`.
///
/// Returns the number of bytes written, or `None` on a bad width or an over-long read.
/// Access is at the requested width so a register that must be read as a word is read as
/// one, rather than as four bytes that fault or read zero.
pub fn peek(addr: u32, width: u8, count: u8, out: &mut [u8]) -> Option<usize> {
    let stride = match width {
        1 | 2 | 4 => width as usize,
        _ => return None,
    };
    let total = stride.checked_mul(count as usize)?;
    // Bounded by the caller's buffer. A silent clamp on a memory read is a wrong answer,
    // so an over-long request is refused rather than truncated.
    if total > out.len() {
        return None;
    }
    let mut at = addr;
    for chunk in out[..total].chunks_mut(stride) {
        // SAFETY: a debug read of an arbitrary address. It can fault on an unmapped
        // region -- which is information, not a bug -- and this feature only exists on a
        // build with no secret to protect.
        unsafe {
            match stride {
                1 => chunk[0] = core::ptr::read_volatile(at as *const u8),
                2 => {
                    chunk.copy_from_slice(&core::ptr::read_volatile(at as *const u16).to_le_bytes())
                }
                _ => {
                    chunk.copy_from_slice(&core::ptr::read_volatile(at as *const u32).to_le_bytes())
                }
            }
        }
        at = at.wrapping_add(stride as u32);
    }
    Some(total)
}

/// Write `data` to `addr` in `width`-byte units. Returns false on a bad width or a
/// length that is not a whole number of elements.
pub fn poke(addr: u32, width: u8, data: &[u8]) -> bool {
    let stride = match width {
        1 | 2 | 4 => width as usize,
        _ => return false,
    };
    if data.is_empty() || data.len() % stride != 0 {
        return false;
    }
    let mut at = addr;
    for chunk in data.chunks(stride) {
        // SAFETY: a debug write to an arbitrary address, on a build that exists only for
        // bench bring-up. It can brick the running image; that is what it is for.
        unsafe {
            match stride {
                1 => core::ptr::write_volatile(at as *mut u8, chunk[0]),
                2 => core::ptr::write_volatile(
                    at as *mut u16,
                    u16::from_le_bytes([chunk[0], chunk[1]]),
                ),
                _ => core::ptr::write_volatile(
                    at as *mut u32,
                    u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]),
                ),
            }
        }
        at = at.wrapping_add(stride as u32);
    }
    true
}

/// Call `addr` as `fn(u32) -> u32`, with interrupts masked, and return its result.
///
/// The address is used as a Thumb entry, so bit 0 is forced set -- a caller that passes
/// an even address means the instruction there, not an ARM-mode switch. Interrupts are
/// masked across the call because the routine may touch state a handler also touches, or
/// may be mid-relocation.
///
/// If the routine does not return, neither does this; the log line written before the
/// call is then the record of what ran.
pub fn jsr(addr: u32, arg: u32) -> u32 {
    let entry = addr | 1;
    // SAFETY: the host asked to run code at `entry`. There is no way to make this safe
    // and no attempt to; it is the monitor's `USR` and exists only on a bench build.
    let f: extern "C" fn(u32) -> u32 = unsafe { core::mem::transmute(entry as usize) };
    cortex_m::interrupt::free(|_| f(arg))
}
