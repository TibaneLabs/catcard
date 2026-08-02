//! Where boot ends until there is a display to report on.

use crate::BootReport;

/// Observable state, laid out so a debugger (or, later, the selftest screen) can read
/// the outcome of bring-up without a protocol.
///
/// `#[used]` and `#[no_mangle]` keep it in the image and findable by name in the map
/// file even at `opt-level = "s"` with LTO.
#[no_mangle]
#[used]
pub static mut CATCARD_BOOT_STATUS: BootStatus = BootStatus {
    magic: BOOT_STATUS_MAGIC,
    hal_ok: 0,
    entropy_ok: 0,
    credited_bits: 0,
    dwt_running: 0,
};

pub const BOOT_STATUS_MAGIC: u32 = 0xCA7C_A2D0;

#[repr(C)]
pub struct BootStatus {
    pub magic: u32,
    pub hal_ok: u32,
    pub entropy_ok: u32,
    pub credited_bits: u32,
    pub dwt_running: u32,
}

/// Publish the boot result and stop.
pub fn park(report: &BootReport) -> ! {
    let status = BootStatus {
        magic: BOOT_STATUS_MAGIC,
        hal_ok: report.hal.is_ok() as u32,
        entropy_ok: report.entropy.is_ok() as u32,
        credited_bits: *report.entropy.as_ref().unwrap_or(&0),
        dwt_running: report.dwt_running as u32,
    };

    // SAFETY: single-threaded, interrupts are not enabled yet, and this is the only
    // writer of this static.
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(CATCARD_BOOT_STATUS), status);
    }

    loop {
        cortex_m::asm::wfi();
    }
}
