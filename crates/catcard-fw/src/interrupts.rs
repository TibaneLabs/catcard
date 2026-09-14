//! Interrupt wiring.
//!
//! The wallet runs **polled** -- the main loop and each screen call [`usbtask::pump`],
//! and nothing depends on an interrupt firing. The one exception is the USB Drive screen,
//! which drives mass storage from the OTG_FS interrupt so the transport keeps moving
//! while the foreground is busy with the SD card. That interrupt is enabled only while
//! that screen is open (see [`usbtask::msc_enter`]/[`msc_exit`](usbtask::msc_exit)) and
//! disabled on the way out, so the rest of the firmware is unaffected by it.
//!
//! There is no device PAC in this tree, so the vector is not claimed by name. cortex-m-rt
//! routes every device interrupt through `DefaultHandler`, handing it the active IRQ
//! number; we service ours and trap anything else, since nothing else is ever unmasked in
//! the NVIC.

use cortex_m::interrupt::InterruptNumber;
use cortex_m::peripheral::NVIC;

/// OTG_FS global interrupt, position 67 in the vector table.
///
/// Source: RM0432 §NVIC interrupt table [C]. Cross-checked on hardware: the handler only
/// ever runs while the OTG line is the sole enabled interrupt, so a wrong number would
/// show up immediately as an unserviced (never-firing) mass-storage transport.
const OTG_FS_IRQN: u16 = 67;

/// A hand-rolled [`InterruptNumber`] standing in for the entry a PAC would provide.
#[derive(Clone, Copy)]
struct OtgFs;

// SAFETY: 67 is OTG_FS's position in the L4S5 vector table, and this is the only code
// that claims that line.
unsafe impl InterruptNumber for OtgFs {
    fn number(self) -> u16 {
        OTG_FS_IRQN
    }
}

/// Enable the OTG_FS line in the NVIC. The core's own `GAHBCFG` gate is opened alongside
/// this by [`usbtask::msc_enter`]; both must be on for the handler to run.
pub fn enable_otg() {
    NVIC::unpend(OtgFs);
    // SAFETY: enabling one well-known line whose handler is installed in this module.
    unsafe { NVIC::unmask(OtgFs) };
}

/// Mask the OTG_FS line and drop any pending latch. Paired with the `GAHBCFG` gate being
/// shut, this returns the core to fully polled operation.
pub fn disable_otg() {
    NVIC::mask(OtgFs);
    NVIC::unpend(OtgFs);
}

/// Every device interrupt lands here (no PAC to name them). Service OTG_FS; trap anything
/// else, which can only be a bug since nothing else is ever unmasked.
// cortex-m-rt requires `DefaultHandler` be `unsafe`; the body itself does nothing unsafe.
#[cortex_m_rt::exception]
unsafe fn DefaultHandler(irqn: i16) {
    if irqn == OTG_FS_IRQN as i16 {
        crate::usbtask::on_otg_interrupt();
        return;
    }
    // An interrupt we never enabled fired: park rather than return to a corrupt state.
    loop {
        cortex_m::asm::nop();
    }
}
