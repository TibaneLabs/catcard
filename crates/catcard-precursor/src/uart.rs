//! The debug UART, which the Raspberry Pi debug hat carries to the Pi's own UART.
//!
//! The gateware has one physical UART (115200 8N1, pins V6/V7 on the hat connector) and
//! a mux in front of it choosing which of its UART cores drives the pins: 0 = `uart`
//! (the kernel debug port), 1 = `console`. Xous leaves it on 1; this firmware selects 0
//! and talks to `uart`.
//! Source: betrusted_soc.py `_io_uart_debug_swapped` (V6/V7, "wired to the RPi"),
//! `uart.UARTPHY(baudrate=115200)`, `uartsel` CSR description [C]; the bench unit's boot
//! ROM and kernel output read on the Pi at 115200, 2026-11-05 [C].
//!
//! Register semantics are LiteX's stock UART: `rxtx` takes a byte to send, `txfull`
//! bit 0 says the transmit FIFO (16 deep) has no room.
//! Source: csr.csv register names [C]; LiteX soc/cores/uart.py [C].

use crate::csr::{self, reg};

/// How long a byte may wait for FIFO space before it is dropped. At 115200 baud a byte
/// leaves every ~87 us, so a FIFO that has not moved in 10 ms is not draining at all
/// (the mux was switched away, or the core is held in reset). Dropping the byte keeps a
/// dead UART from hanging the firmware: diagnostics are not worth a stall.
const TX_TIMEOUT_MS: u64 = 10;

pub struct Uart(());

impl Uart {
    /// Routes the physical UART to the `uart` core and returns a writer for it.
    pub fn take() -> Self {
        csr::write(reg::GPIO_UARTSEL, 0);
        Uart(())
    }

    fn put(&mut self, b: u8) {
        let deadline = crate::timer::now_ms() + TX_TIMEOUT_MS;
        while csr::read(reg::UART_TXFULL) & 1 != 0 {
            if crate::timer::now_ms() >= deadline {
                return;
            }
        }
        csr::write(reg::UART_RXTX, u32::from(b));
    }
}

/// One received byte, if any. LiteX: `rxempty` bit 0 clear means a byte waits in `rxtx`;
/// writing bit 1 of `ev_pending` acknowledges it and advances the FIFO.
/// Source: LiteX soc/cores/uart.py and libbase uart.c `uart_read` [C].
pub fn read_byte() -> Option<u8> {
    if csr::read(reg::UART_RXEMPTY) & 1 != 0 {
        return None;
    }
    let b = csr::read(reg::UART_RXTX) as u8;
    csr::write(reg::UART_EV_PENDING, 1 << 1);
    Some(b)
}

impl core::fmt::Write for Uart {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for b in s.bytes() {
            if b == b'\n' {
                self.put(b'\r');
            }
            self.put(b);
        }
        Ok(())
    }
}
