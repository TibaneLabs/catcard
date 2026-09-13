//! USB OTG full-speed device driver.
//!
//! The Synopsys DWC2 core, as ST integrates it. Enough of it to be a HID device: bring
//! the core up in device mode, answer control transfers on endpoint zero, and move
//! 64-byte reports over one interrupt endpoint each way.
//!
//! **Polled, not interrupt-driven.** [`Otg::poll`] is called from the main loop and does
//! everything; nothing here runs in interrupt context. A wallet's foreground work is a
//! human pressing keys, so there is nothing to preempt, and a polled driver cannot race
//! with the code that owns the display or the callgate. The cost is that a poll must
//! happen often enough — the host retries a NAK, so a late poll is slow rather than
//! broken.
//!
//! The parts that can be got wrong at a desk are not here: framing, descriptors and what
//! to answer a `SETUP` packet with live in `catcard-usb` and are host-tested. This file
//! is the part that genuinely needs silicon.
//!
//! Source: RM0432 §USB OTG_FS (STM32L4+), RM0351 §USB OTG_FS (STM32L4). The register
//! map is the DWC2 core's and identical on both. [C]

use catcard_board::Pin;
use catcard_usb::REPORT_LEN;
use catcard_usb::control::{self, Action, Device, Setup};
use catcard_usb::descriptor::{EP_IN, EP_OUT};

use crate::gpio::{self, OutputType, Pull, Speed};
use crate::reg;

/// OTG_FS peripheral base. Source: RM0432 §2.2.2 memory map [C]
const OTG: u32 = 0x5000_0000;

/// Alternate function 10 puts PA11/PA12 on OTG_FS DM/DP.
/// Source: STM32L4S5 datasheet, alternate function table [C]
const AF_OTG_FS: u8 = 10;

// --- global registers. Source: RM0432 §USB_OTG global register map [C] ---
const GOTGCTL: u32 = OTG;
const GAHBCFG: u32 = OTG + 0x008;
const GUSBCFG: u32 = OTG + 0x00C;
const GRSTCTL: u32 = OTG + 0x010;
const GINTSTS: u32 = OTG + 0x014;
const GINTMSK: u32 = OTG + 0x018;
const GRXSTSP: u32 = OTG + 0x020;
const GRXFSIZ: u32 = OTG + 0x024;
/// Doubles as `HNPTXFSIZ` in host mode; in device mode it sizes endpoint 0's TX FIFO.
const DIEPTXF0: u32 = OTG + 0x028;
const GCCFG: u32 = OTG + 0x038;
/// `DIEPTXF1..5`, one per non-zero IN endpoint.
const DIEPTXF: u32 = OTG + 0x104;

// --- device registers ---
const DCFG: u32 = OTG + 0x800;
const DCTL: u32 = OTG + 0x804;
const DIEPMSK: u32 = OTG + 0x810;
const DOEPMSK: u32 = OTG + 0x814;
const DAINTMSK: u32 = OTG + 0x81C;
const PCGCCTL: u32 = OTG + 0xE00;

const DIEPCTL: u32 = OTG + 0x900;
const DIEPINT: u32 = OTG + 0x908;
const DIEPTSIZ: u32 = OTG + 0x910;
const DTXFSTS: u32 = OTG + 0x918;
const DOEPCTL: u32 = OTG + 0xB00;
const DOEPINT: u32 = OTG + 0xB08;
const DOEPTSIZ: u32 = OTG + 0xB10;
/// Endpoint register blocks are 0x20 apart.
const EP_STRIDE: u32 = 0x20;
/// Each endpoint's FIFO is a 4 KB window; only the first word of each is used.
const FIFO: u32 = OTG + 0x1000;
const FIFO_STRIDE: u32 = 0x1000;

// --- bits we use ---
const GRSTCTL_CSRST: u32 = 1 << 0;
const GRSTCTL_RXFFLSH: u32 = 1 << 4;
const GRSTCTL_TXFFLSH: u32 = 1 << 5;
const GRSTCTL_TXFNUM_ALL: u32 = 0x10 << 6;
const GRSTCTL_AHBIDL: u32 = 1 << 31;

const GUSBCFG_PHYSEL: u32 = 1 << 6;
const GUSBCFG_FDMOD: u32 = 1 << 30;
/// Turnaround time. 6 is the value for a 48 MHz AHB with the internal FS PHY.
const GUSBCFG_TRDT_6: u32 = 6 << 10;
const GUSBCFG_TRDT_MASK: u32 = 0xF << 10;

const GCCFG_PWRDWN: u32 = 1 << 16;
/// VBUS sensing. Left **off**: whether VBUS is routed is board-dependent and
/// unconfirmed, and with sensing enabled a core that never sees VBUS simply never
/// attaches — a silent failure with no diagnostic anywhere.
const GCCFG_VBDEN: u32 = 1 << 21;

/// Start of frame. Not acted on, but it **must** be acknowledged: `GINTSTS` bits are
/// write-1-to-clear, so an unhandled one latches and the register stops reflecting what
/// is actually happening. Leaving it set makes every later read return the same value.
const GINTSTS_SOF: u32 = 1 << 3;
const GINTSTS_RXFLVL: u32 = 1 << 4;
const GINTSTS_USBSUSP: u32 = 1 << 11;
const GINTSTS_USBRST: u32 = 1 << 12;
const GINTSTS_ENUMDNE: u32 = 1 << 13;
const GINTSTS_IEPINT: u32 = 1 << 18;
const GINTSTS_OEPINT: u32 = 1 << 19;

const DCFG_DSPD_FS: u32 = 0b11;
/// Answer a non-zero-length status stage with a STALL, as the spec requires.
const DCFG_NZLSOHSK: u32 = 1 << 2;
const DCFG_DAD_SHIFT: u32 = 4;
const DCFG_DAD_MASK: u32 = 0x7F << 4;

const DCTL_SDIS: u32 = 1 << 1;
const DCTL_CGINAK: u32 = 1 << 8;
/// Clear the global **OUT** NAK. Its counterpart `CGINAK` was here and this was not:
/// while a global OUT NAK stands, no OUT endpoint receives anything and the core will
/// not keep `EPENA` set, however often software writes it.
const DCTL_CGONAK: u32 = 1 << 10;

const EPCTL_USBAEP: u32 = 1 << 15;
const EPCTL_STALL: u32 = 1 << 21;
const EPCTL_CNAK: u32 = 1 << 26;
const EPCTL_SNAK: u32 = 1 << 27;
const EPCTL_SD0PID: u32 = 1 << 28;
const EPCTL_EPENA: u32 = 1 << 31;
const EPCTL_EPTYP_INTR: u32 = 0b11 << 18;
const EPCTL_TXFNUM_SHIFT: u32 = 22;

/// The self-clearing command bits in an endpoint control register.
///
/// These are *write* commands, not state. A read-modify-write on `DxEPCTL` reads them
/// back and writes them again, which asks the core to set and clear NAK in the same
/// word — and an endpoint enable submitted alongside that contradiction does not take.
/// Every enable here clears them first.
const EPCTL_COMMANDS: u32 = EPCTL_SNAK | EPCTL_CNAK | EPCTL_SD0PID | (1 << 29);

const EPINT_XFRC: u32 = 1 << 0;
const DOEPINT_STUP: u32 = 1 << 3;

/// `PKTSTS` values in `GRXSTSP`. Source: RM0432 §OTG_GRXSTSP (device mode) [C]
mod pktsts {
    pub const OUT_DATA: u32 = 2;
    pub const OUT_DONE: u32 = 3;
    pub const SETUP_DONE: u32 = 4;
    pub const SETUP_DATA: u32 = 6;
}

/// FIFO allocation, in 32-bit words. The FS core has 1.25 KB — 320 words — of FIFO RAM.
///
/// Deliberately under-committed: 224 of 320 words. The RX minimum for one 64-byte
/// control endpoint plus one data endpoint is around 50 words, so this is generous, and
/// spending the remainder would buy throughput this device does not need.
const RX_WORDS: u32 = 128;
const EP0_TX_WORDS: u32 = 32;
const EP1_TX_WORDS: u32 = 64;

/// Endpoint numbers, from the addresses the descriptors advertise.
const EP_IN_NUM: u32 = (EP_IN & 0x0F) as u32;
const EP_OUT_NUM: u32 = (EP_OUT & 0x0F) as u32;

/// How long to wait for a core reset or an AHB idle, in poll iterations.
///
/// Bounded, like every other wait in this tree: a core that never idles must produce an
/// error, not a device that hangs before it has drawn anything on screen.
const RESET_TRIES: u32 = 200_000;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// The AHB never went idle, or the soft reset never completed.
    CoreStuck,
    /// `PWR_CR2.USV` would not stay set, so VDDUSB is not validated and the transceiver
    /// has no supply. The device cannot appear on the bus at all in that state.
    UsbSupplyNotValid,
}

/// What a poll produced.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Event {
    /// Nothing happened.
    Idle,
    /// The bus was reset; any transfer in progress is void.
    Reset,
    /// A 64-byte report arrived on the OUT endpoint.
    Report,
}

/// The device side of the OTG FS core.
pub struct Otg {
    dev: Device,
    /// The most recent report from the host, valid when `poll` returned [`Event::Report`].
    pub rx: [u8; REPORT_LEN],
    rx_len: usize,
    setup: [u8; Setup::LEN],
    scratch: [u8; 64],
    /// How many times the OUT endpoint has been armed. Distinguishes "the arm never
    /// runs" from "it runs and the core rejects it", which look the same in a register
    /// dump taken after the fact.
    pub rearms: u32,
}

impl Otg {
    /// Bring the core up in device mode and attach to the bus.
    ///
    /// The data pins are passed in rather than read from the board table, so this crate
    /// stays buildable without a board selected and the pin choice remains the caller's.
    ///
    /// # Safety
    /// Call once. Takes exclusive ownership of OTG_FS and of `dm`/`dp`, and assumes the
    /// 48 MHz clock is already running — [`crate::clock::enable_hsi48`] does that, and
    /// USB will enumerate erratically or not at all without it.
    pub unsafe fn init(dm: Pin, dp: Pin, serial: &'static str) -> Result<Self, Error> {
        // SAFETY: the caller promises exclusive ownership of the peripheral and pins.
        unsafe {
            enable_clock()?;
            gpio::enable_port(dm.port);
            gpio::enable_port(dp.port);
            for p in [dm, dp] {
                gpio::set_alternate(
                    p,
                    AF_OTG_FS,
                    OutputType::PushPull,
                    Pull::None,
                    Speed::VeryHigh,
                );
            }

            core_reset()?;

            // Power the internal transceiver. VBUS sensing stays off -- see GCCFG_VBDEN.
            reg::modify(GCCFG, GCCFG_VBDEN, GCCFG_PWRDWN);
            // B-session valid, so the core believes a cable is present without sensing.
            reg::set_bits(GOTGCTL, (1 << 6) | (1 << 7));

            // Internal full-speed PHY, forced device mode.
            reg::modify(
                GUSBCFG,
                GUSBCFG_TRDT_MASK,
                GUSBCFG_PHYSEL | GUSBCFG_FDMOD | GUSBCFG_TRDT_6,
            );

            // No clock gating; full speed; STALL a non-zero-length status stage.
            reg::write(PCGCCTL, 0);
            reg::write(DCFG, DCFG_DSPD_FS | DCFG_NZLSOHSK);

            configure_fifos();

            // Poll GINTSTS rather than taking interrupts: leave the AHB interrupt gate
            // shut and clear anything latched from before the reset.
            reg::write(GAHBCFG, 0);
            reg::write(GINTSTS, u32::MAX);
            reg::write(
                GINTMSK,
                GINTSTS_USBRST | GINTSTS_ENUMDNE | GINTSTS_RXFLVL | GINTSTS_IEPINT | GINTSTS_OEPINT,
            );
            reg::write(DIEPMSK, EPINT_XFRC);
            reg::write(DOEPMSK, EPINT_XFRC | DOEPINT_STUP);
            reg::write(DAINTMSK, u32::MAX);

            // Attach.
            reg::clear_bits(DCTL, DCTL_SDIS);
        }

        Ok(Self {
            dev: Device::new(serial),
            rx: [0; REPORT_LEN],
            rx_len: 0,
            setup: [0; Setup::LEN],
            scratch: [0; 64],
            rearms: 0,
        })
    }

    /// The endpoint registers, for a RAM-dump diagnostic.
    ///
    /// `[GINTSTS, DAINT, DOEPCTL(out), DOEPTSIZ(out), DIEPCTL(in), DCTL]`. Reading these back
    /// is the only way to tell "we never armed the endpoint" from "we armed it and the
    /// core closed it again", which are different bugs that present identically.
    ///
    /// # Safety
    /// Exclusive access to OTG_FS.
    pub unsafe fn debug_regs(&self) -> [u32; 6] {
        // SAFETY: plain reads of registers this driver owns.
        unsafe {
            [
                reg::read(GINTSTS),
                reg::read(OTG + 0x818),
                reg::read(DOEPCTL + EP_OUT_NUM * EP_STRIDE),
                reg::read(DOEPTSIZ + EP_OUT_NUM * EP_STRIDE),
                reg::read(DIEPCTL + EP_IN_NUM * EP_STRIDE),
                reg::read(DCTL),
            ]
        }
    }

    /// Whether the host has configured us, so reports may be exchanged.
    pub fn is_configured(&self) -> bool {
        self.dev.is_configured()
    }

    /// Bytes of the most recent report.
    pub fn report(&self) -> &[u8] {
        &self.rx[..self.rx_len]
    }

    /// Service the core once.
    ///
    /// # Safety
    /// Exclusive access to OTG_FS, as established by [`Self::init`].
    pub unsafe fn poll(&mut self) -> Event {
        // SAFETY: as documented on this function.
        unsafe {
            let sts = reg::read(GINTSTS);

            // Acknowledge what we do not act on. Every bit here is write-1-to-clear and
            // a latched one never comes back, so leaving them set turns GINTSTS into a
            // constant and the next event is invisible.
            let ignored = sts & GINTSTS_SOF;
            if ignored != 0 {
                reg::write(GINTSTS, ignored);
            }

            if sts & GINTSTS_USBRST != 0 {
                reg::write(GINTSTS, GINTSTS_USBRST);
                self.on_reset();
                return Event::Reset;
            }
            if sts & GINTSTS_ENUMDNE != 0 {
                reg::write(GINTSTS, GINTSTS_ENUMDNE);
                self.on_enum_done();
            }
            if sts & GINTSTS_USBSUSP != 0 {
                reg::write(GINTSTS, GINTSTS_USBSUSP);
            }
            if sts & GINTSTS_RXFLVL != 0
                && let Some(e) = self.drain_rx()
            {
                return e;
            }
            if sts & GINTSTS_OEPINT != 0 {
                self.service_out_endpoints();
            }
            if sts & GINTSTS_IEPINT != 0 {
                self.service_in_endpoints();
            }

            // The OUT endpoint is armed once at configuration and again after each
            // delivered report -- not on every poll. Rewriting DOEPTSIZ and DOEPCTL
            // while a reception is in progress aborts it, so an unconditional re-arm
            // here does not make the endpoint more available, it makes it permanently
            // unavailable.
            Event::Idle
        }
    }

    /// Send one 64-byte report to the host.
    ///
    /// Returns false when the IN FIFO has no room, in which case nothing was sent and
    /// the caller should retry after another poll. Never blocks: a host that has stopped
    /// polling must not be able to wedge the firmware.
    ///
    /// # Safety
    /// Exclusive access to OTG_FS.
    pub unsafe fn send(&mut self, report: &[u8; REPORT_LEN]) -> bool {
        // SAFETY: as documented.
        unsafe {
            if !self.dev.is_configured() {
                return false;
            }
            let ctl = DIEPCTL + EP_IN_NUM * EP_STRIDE;
            // Still sending the previous one.
            if reg::read(ctl) & EPCTL_EPENA != 0 {
                return false;
            }
            let words = (REPORT_LEN as u32).div_ceil(4);
            if reg::read(DTXFSTS + EP_IN_NUM * EP_STRIDE) & 0xFFFF < words {
                return false;
            }
            reg::write(
                DIEPTSIZ + EP_IN_NUM * EP_STRIDE,
                (1 << 19) | REPORT_LEN as u32,
            );
            reg::modify(ctl, EPCTL_COMMANDS, EPCTL_EPENA | EPCTL_CNAK);
            write_fifo(EP_IN_NUM, report);
            true
        }
    }

    /// Re-arm the OUT endpoint for the next report.
    ///
    /// # Safety
    /// Exclusive access to OTG_FS.
    pub unsafe fn receive_next(&mut self) {
        // SAFETY: as documented.
        unsafe {
            self.rx_len = 0;
            self.rearms = self.rearms.saturating_add(1);
            reg::write(
                DOEPTSIZ + EP_OUT_NUM * EP_STRIDE,
                (1 << 19) | REPORT_LEN as u32,
            );
            reg::modify(
                DOEPCTL + EP_OUT_NUM * EP_STRIDE,
                EPCTL_COMMANDS,
                EPCTL_EPENA | EPCTL_CNAK,
            );
        }
    }

    /// # Safety
    /// Exclusive access to OTG_FS.
    unsafe fn on_reset(&mut self) {
        self.dev.reset();
        // SAFETY: as documented.
        unsafe {
            // `CGINAK`/`CGONAK` are write-1 commands: clearing them did nothing at all.
            reg::set_bits(DCTL, DCTL_CGINAK | DCTL_CGONAK);
            flush_fifos();
            reg::modify(DCFG, DCFG_DAD_MASK, 0);
            // Endpoint zero, ready for the first SETUP. Three back-to-back SETUP
            // packets is what the core expects to be armed for; fewer and a host that
            // retries during enumeration is answered with a NAK it does not expect.
            reg::write(DOEPTSIZ, (3 << 29) | (1 << 19) | 24);
            reg::modify(DOEPCTL, EPCTL_COMMANDS, EPCTL_EPENA | EPCTL_CNAK);
        }
    }

    /// # Safety
    /// Exclusive access to OTG_FS.
    unsafe fn on_enum_done(&mut self) {
        // SAFETY: as documented. MPSIZ 0 on endpoint zero means 64 bytes.
        unsafe {
            reg::modify(DIEPCTL, 0b11, 0);
            // Both global NAKs, not just the IN one.
            reg::set_bits(DCTL, DCTL_CGINAK | DCTL_CGONAK);
        }
    }

    /// Read whatever the receive FIFO is holding.
    ///
    /// # Safety
    /// Exclusive access to OTG_FS.
    unsafe fn drain_rx(&mut self) -> Option<Event> {
        // SAFETY: as documented.
        unsafe {
            let sts = reg::read(GRXSTSP);
            let ep = sts & 0x0F;
            let bytes = ((sts >> 4) & 0x7FF) as usize;
            let kind = (sts >> 17) & 0x0F;

            match kind {
                pktsts::SETUP_DATA => {
                    read_fifo(&mut self.setup[..bytes.min(Setup::LEN)]);
                    None
                }
                pktsts::OUT_DATA if ep == EP_OUT_NUM => {
                    let n = bytes.min(REPORT_LEN);
                    read_fifo(&mut self.rx[..n]);
                    self.rx_len = n;
                    None
                }
                pktsts::OUT_DATA => {
                    // A data stage on endpoint zero. Nothing here has an OUT data
                    // stage, but the bytes still have to leave the FIFO or the core
                    // stops delivering anything at all.
                    discard_fifo(bytes);
                    None
                }
                pktsts::SETUP_DONE => {
                    let setup = Setup::from_bytes(&self.setup);
                    self.answer(&setup);
                    None
                }
                pktsts::OUT_DONE if ep == EP_OUT_NUM && self.rx_len > 0 => Some(Event::Report),
                _ => {
                    discard_fifo(bytes);
                    None
                }
            }
        }
    }

    /// Act on a decoded `SETUP` packet.
    ///
    /// # Safety
    /// Exclusive access to OTG_FS.
    unsafe fn answer(&mut self, setup: &Setup) {
        let was_configured = self.dev.is_configured();
        let action = control::handle(&mut self.dev, setup, &mut self.scratch);
        // SAFETY: as documented.
        unsafe {
            // Start from an empty transmit FIFO. Whatever the host did with the previous
            // control transfer -- a short read, an abandoned one -- anything left behind
            // would be sent as the front of this reply. That failure looks like a
            // descriptor with another descriptor stuck to the front of it, and the host
            // rejects the device with no indication why.
            flush_tx(0);
            match action {
                Action::Data(data) => {
                    let len = data.len();
                    reg::write(DIEPTSIZ, (1 << 19) | len as u32);
                    reg::modify(DIEPCTL, EPCTL_COMMANDS, EPCTL_EPENA | EPCTL_CNAK);
                    write_fifo_bytes(0, data);
                    // The host's status stage is an OUT; arm for it.
                    arm_ep0_out();
                }
                Action::Ack => {
                    reg::write(DIEPTSIZ, 1 << 19);
                    reg::modify(DIEPCTL, EPCTL_COMMANDS, EPCTL_EPENA | EPCTL_CNAK);
                    arm_ep0_out();
                }
                Action::AckThenAddress(addr) => {
                    // The address is programmed *before* the status stage on this core:
                    // unlike most peripherals, DWC2 wants DCFG.DAD set as soon as the
                    // request is decoded, and handles the ordering itself.
                    reg::modify(DCFG, DCFG_DAD_MASK, (addr as u32) << DCFG_DAD_SHIFT);
                    reg::write(DIEPTSIZ, 1 << 19);
                    reg::modify(DIEPCTL, EPCTL_COMMANDS, EPCTL_EPENA | EPCTL_CNAK);
                    arm_ep0_out();
                }
                Action::Stall => {
                    reg::modify(DIEPCTL, EPCTL_COMMANDS, EPCTL_STALL);
                    reg::modify(DOEPCTL, EPCTL_COMMANDS, EPCTL_STALL);
                    arm_ep0_out();
                }
            }

            if self.dev.is_configured() && !was_configured {
                open_data_endpoints();
                self.receive_next();
            }
        }
    }

    /// # Safety
    /// Exclusive access to OTG_FS.
    unsafe fn service_out_endpoints(&mut self) {
        // SAFETY: as documented. Interrupt flags are write-1-to-clear.
        unsafe {
            for ep in [0, EP_OUT_NUM] {
                let at = DOEPINT + ep * EP_STRIDE;
                let v = reg::read(at);
                if v != 0 {
                    reg::write(at, v);
                }
                if ep == 0 && v & DOEPINT_STUP != 0 {
                    arm_ep0_out();
                }
            }
        }
    }

    /// # Safety
    /// Exclusive access to OTG_FS.
    unsafe fn service_in_endpoints(&mut self) {
        // SAFETY: as documented.
        unsafe {
            for ep in [0, EP_IN_NUM] {
                let at = DIEPINT + ep * EP_STRIDE;
                let v = reg::read(at);
                if v != 0 {
                    reg::write(at, v);
                }
            }
        }
    }
}

/// # Safety
/// Exclusive access to RCC and PWR.
unsafe fn enable_clock() -> Result<(), Error> {
    const RCC_AHB2ENR: u32 = catcard_board::memory::fixed::RCC + 0x4C;
    const RCC_AHB2ENR_OTGFSEN: u32 = 1 << 12;
    /// `PWREN` — the PWR peripheral's own clock gate. Source: RM0432 §RCC_APB1ENR1 [C]
    const RCC_APB1ENR1: u32 = catcard_board::memory::fixed::RCC + 0x58;
    const APB1ENR1_PWREN: u32 = 1 << 28;
    const PWR_CR2: u32 = catcard_board::memory::fixed::PWR + 0x04;
    /// `USV` — validate the VDDUSB supply. Without it the transceiver has no power and
    /// the device never appears on the bus. Source: RM0432 §PWR_CR2 [C]
    const PWR_CR2_USV: u32 = 1 << 10;
    // SAFETY: as documented.
    unsafe {
        // PWR's clock first. It is off after reset, and a write to an unclocked
        // peripheral is discarded without any indication -- so setting USV before this
        // did nothing at all, and the only symptom was a device that never appeared on
        // the bus. An emulator does not model APB gating, so this passed there.
        reg::set_bits(RCC_APB1ENR1, APB1ENR1_PWREN);
        // The gate takes effect a cycle or two later; reading back stalls until it has.
        let _ = reg::read(RCC_APB1ENR1);

        reg::set_bits(PWR_CR2, PWR_CR2_USV);
        // Read it back. This is the write whose silent failure cost a hardware round
        // trip, and a supply that did not come up is worth an error rather than a
        // peripheral that is initialised perfectly and connected to nothing.
        if reg::read(PWR_CR2) & PWR_CR2_USV == 0 {
            return Err(Error::UsbSupplyNotValid);
        }

        reg::set_bits(RCC_AHB2ENR, RCC_AHB2ENR_OTGFSEN);
        let _ = reg::read(RCC_AHB2ENR);
    }
    Ok(())
}

/// Wait for the AHB to idle, then soft-reset the core.
///
/// # Safety
/// Exclusive access to OTG_FS.
unsafe fn core_reset() -> Result<(), Error> {
    // SAFETY: as documented.
    unsafe {
        if !reg::wait_for(GRSTCTL, GRSTCTL_AHBIDL, GRSTCTL_AHBIDL, RESET_TRIES) {
            return Err(Error::CoreStuck);
        }
        reg::set_bits(GRSTCTL, GRSTCTL_CSRST);
        if !reg::wait_for(GRSTCTL, GRSTCTL_CSRST, 0, RESET_TRIES) {
            return Err(Error::CoreStuck);
        }
        if !reg::wait_for(GRSTCTL, GRSTCTL_AHBIDL, GRSTCTL_AHBIDL, RESET_TRIES) {
            return Err(Error::CoreStuck);
        }
    }
    Ok(())
}

/// # Safety
/// Exclusive access to OTG_FS.
unsafe fn configure_fifos() {
    // SAFETY: as documented. Each TX FIFO's start address is the sum of everything
    // allocated before it, which is why these are written in order.
    unsafe {
        reg::write(GRXFSIZ, RX_WORDS);
        reg::write(DIEPTXF0, (EP0_TX_WORDS << 16) | RX_WORDS);
        reg::write(
            DIEPTXF + (EP_IN_NUM - 1) * 4,
            (EP1_TX_WORDS << 16) | (RX_WORDS + EP0_TX_WORDS),
        );
        flush_fifos();
    }
}

/// # Safety
/// Exclusive access to OTG_FS.
unsafe fn flush_fifos() {
    // SAFETY: as documented.
    unsafe {
        reg::write(GRSTCTL, GRSTCTL_TXFNUM_ALL | GRSTCTL_TXFFLSH);
        let _ = reg::wait_for(GRSTCTL, GRSTCTL_TXFFLSH, 0, RESET_TRIES);
        reg::write(GRSTCTL, GRSTCTL_RXFFLSH);
        let _ = reg::wait_for(GRSTCTL, GRSTCTL_RXFFLSH, 0, RESET_TRIES);
    }
}

/// Empty one transmit FIFO.
///
/// # Safety
/// Exclusive access to OTG_FS.
unsafe fn flush_tx(ep: u32) {
    // SAFETY: as documented.
    unsafe {
        reg::write(GRSTCTL, (ep << 6) | GRSTCTL_TXFFLSH);
        let _ = reg::wait_for(GRSTCTL, GRSTCTL_TXFFLSH, 0, RESET_TRIES);
    }
}

/// Arm endpoint zero to receive the next SETUP or status packet.
///
/// # Safety
/// Exclusive access to OTG_FS.
unsafe fn arm_ep0_out() {
    // SAFETY: as documented.
    unsafe {
        reg::write(DOEPTSIZ, (3 << 29) | (1 << 19) | 24);
        reg::modify(DOEPCTL, EPCTL_COMMANDS, EPCTL_EPENA | EPCTL_CNAK);
    }
}

/// Enable the two data endpoints, which only exist once configured.
///
/// # Safety
/// Exclusive access to OTG_FS.
unsafe fn open_data_endpoints() {
    // SAFETY: as documented.
    unsafe {
        reg::write(
            DIEPCTL + EP_IN_NUM * EP_STRIDE,
            EPCTL_USBAEP
                | EPCTL_EPTYP_INTR
                | EPCTL_SD0PID
                | EPCTL_SNAK
                | (EP_IN_NUM << EPCTL_TXFNUM_SHIFT)
                | REPORT_LEN as u32,
        );
        reg::write(
            DOEPCTL + EP_OUT_NUM * EP_STRIDE,
            EPCTL_USBAEP | EPCTL_EPTYP_INTR | EPCTL_SD0PID | EPCTL_SNAK | REPORT_LEN as u32,
        );
    }
}

/// Push `data` into endpoint `ep`'s transmit FIFO.
///
/// # Safety
/// The endpoint must be enabled with room for `data`.
unsafe fn write_fifo(ep: u32, data: &[u8; REPORT_LEN]) {
    // SAFETY: as documented.
    unsafe { write_fifo_bytes(ep, data) }
}

/// # Safety
/// As [`write_fifo`].
unsafe fn write_fifo_bytes(ep: u32, data: &[u8]) {
    let at = FIFO + ep * FIFO_STRIDE;
    // The FIFO is word-wide, so a trailing partial word is padded. The endpoint's
    // transfer size is what tells the core how many of those bytes are real.
    for chunk in data.chunks(4) {
        let mut w = [0u8; 4];
        w[..chunk.len()].copy_from_slice(chunk);
        // SAFETY: as documented on this function.
        unsafe { reg::write(at, u32::from_le_bytes(w)) };
    }
}

/// Pop `out.len()` bytes from the receive FIFO.
///
/// # Safety
/// The FIFO must hold at least this many bytes, as `GRXSTSP` reported.
unsafe fn read_fifo(out: &mut [u8]) {
    for chunk in out.chunks_mut(4) {
        // SAFETY: as documented on this function.
        let w = unsafe { reg::read(FIFO) }.to_le_bytes();
        chunk.copy_from_slice(&w[..chunk.len()]);
    }
}

/// Drop `bytes` from the receive FIFO.
///
/// Not optional: the core stops delivering anything at all if a packet is left in the
/// FIFO, so an unhandled packet still has to be read out and thrown away.
///
/// # Safety
/// As [`read_fifo`].
unsafe fn discard_fifo(bytes: usize) {
    for _ in 0..bytes.div_ceil(4) {
        // SAFETY: as documented.
        let _ = unsafe { reg::read(FIFO) };
    }
}
