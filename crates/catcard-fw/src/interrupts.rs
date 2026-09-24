//! Interrupt wiring.
//!
//! The wallet runs **polled** -- the main loop and each screen call [`usbtask::pump`],
//! and nothing depends on an interrupt firing. Two things are the exception:
//!
//! - the USB Drive screen drives mass storage from the OTG_FS interrupt so the transport
//!   keeps moving while the foreground is busy with the SD card. That one is enabled only
//!   while that screen is open (see [`usbtask::msc_enter`]/[`msc_exit`](usbtask::msc_exit)).
//! - the keypad columns carry falling-edge EXTI interrupts the whole time, so a keypress
//!   is timestamped at the electrical edge for entropy rather than at the next 60 Hz scan
//!   (see [`keypad::on_key_edge`](crate::keypad::on_key_edge)). Their handler only samples
//!   two timers and masks itself, so the firmware stays polled in every other respect.
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

/// A dynamically-numbered NVIC line, for the several EXTI IRQs whose numbers are computed
/// from which pins the board's keypad columns sit on.
#[derive(Clone, Copy)]
struct DynIrq(u16);

// SAFETY: every number passed here comes from `exti::irq_of_line`, which only yields valid
// EXTI positions in the L4 vector table, and those handlers are installed in this module.
unsafe impl InterruptNumber for DynIrq {
    fn number(self) -> u16 {
        self.0
    }
}

/// Unmask, in the NVIC, every distinct EXTI IRQ the given column lines can raise. Called
/// once from keypad bring-up; the lines' own arming is done in the EXTI controller.
pub fn enable_exti(line_mask: u16) {
    for line in 0..16u8 {
        if line_mask & (1 << line) == 0 {
            continue;
        }
        let irqn = catcard_hal::exti::irq_of_line(line);
        let irq = DynIrq(irqn);
        NVIC::unpend(irq);
        // SAFETY: `irqn` is a real EXTI position and `DefaultHandler` services it.
        unsafe { NVIC::unmask(irq) };
    }
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
    if irqn >= 0 && catcard_hal::exti::is_exti_irq(irqn as u16) {
        // A keypad column fell: latch the timing sample. The handler clears and masks its
        // own EXTI lines, so this returns cleanly to the foreground.
        crate::keypad::on_key_edge();
        return;
    }
    // An interrupt we never enabled fired. Returning would resume a state nothing
    // understands, and parking -- the old answer -- left the seed in SRAM on a device
    // sitting on a desk. Same path as a fault: wipe what can be reached, then reset.
    crate::panic::wipe_and_reset()
}

/// A hard fault: a bus fault, an escalated MemManage or UsageFault, or the `bkpt` a task
/// that returned lands on when no debugger is attached.
///
/// Without this, cortex-m-rt's default is `loop {}`: the device halts with whatever was in
/// RAM at the time -- a seed, a signing scalar -- still there, while a *panic* wipes. A
/// fault must not be the softer failure. The frame is deliberately not read, formatted or
/// stored: it is a snapshot of the registers at the fault, which can be key material.
///
/// The callgate is not used from here; see [`panic::wipe_and_reset`](crate::panic::wipe_and_reset).
///
/// `#[exception]` with the trampoline (the default) requires exactly this signature,
/// `unsafe fn(&ExceptionFrame) -> !`, on cortex-m-rt 0.7.6 (its `exception` docs, "HardFault
/// handler"). The release profile's `panic = "abort"` means no unwinding ever meets a
/// diverging handler.
// cortex-m-rt requires the handler be `unsafe`; the body itself does nothing unsafe.
#[cortex_m_rt::exception]
unsafe fn HardFault(_frame: &cortex_m_rt::ExceptionFrame) -> ! {
    crate::panic::wipe_and_reset()
}
