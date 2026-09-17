//! SE1's `Random`, read directly over its single-wire bus.
//!
//! mk4 and later reach the secure element's TRNG through callgate 26, which authenticates
//! the element against the pairing secret. The mk3 bootloader has no callgate for SE
//! randomness at all, so on mk3 the firmware drives the bus itself and issues the one
//! command it needs: `Random` (`0x1B`), which is unprivileged. Nothing authenticates this
//! wire, which is why its bytes enter the pool credited zero -- mixed, never trusted.
//!
//! The bus is Microchip's single-wire interface carried over UART4 in half-duplex mode on
//! one pin: each ATECC bit is one UART byte, `0x7F` for 1 and `0x7D` for 0, least
//! significant bit first.
//!
//! **The bus belongs to the bootloader.** Every PIN attempt and secret read goes through
//! it. So this driver snapshots UART4, its clock gate and source, and the pin before it
//! touches anything, and puts all of it back afterwards: the bootloader's next call finds
//! exactly what it left. The element is sent to sleep at the end, which is the state it
//! wakes from anyway.
//!
//! Protocol source: hw-reference/se1-driver-spec.md §1-5 [C], platform.md §3 "Reading the
//! SE1 RNG on mk3" [C]. Register layout: ST RM0351 §38.8 (USART), §6.4 (RCC).

use crate::gpio::{self, OutputType, Pull, Speed};
use crate::{dwt, reg};
use catcard_board::Pin;
use catcard_board::memory::fixed;

// --- the protocol: pure, and tested on the host -----------------------------------------

/// "A command frame follows". Source: se1-driver-spec.md §3 [C]
pub const IOFLAG_CMD: u8 = 0x77;
/// "Send your response". Source: se1-driver-spec.md §3 [C]
pub const IOFLAG_TX: u8 = 0x88;
/// "Sleep" -- also clears the element's volatile state. Source: se1-driver-spec.md §3 [C]
pub const IOFLAG_SLEEP: u8 = 0xCC;
/// The `Random` opcode. Source: se1-driver-spec.md §7 [C]
pub const OP_RANDOM: u8 = 0x1B;

/// UART byte for an ATECC `1` bit. Source: se1-driver-spec.md §2 [C]
const BIT1: u8 = 0x7F;
/// UART byte for an ATECC `0` bit. Source: se1-driver-spec.md §2 [C]
const BIT0: u8 = 0x7D;

/// Bytes in a `Random` response: count, 32 random, CRC.
pub const RANDOM_RESPONSE_LEN: usize = 35;

/// Microchip's CRC-16 (poly `0x8005`, bits taken least significant first), little-endian.
///
/// Source: se1-driver-spec.md §4 "CRC-16 (Microchip)" [C]
pub fn crc16(data: &[u8]) -> [u8; 2] {
    let mut reg: u16 = 0;
    for &byte in data {
        for bit in 0..8 {
            let data_bit = (byte >> bit) & 1;
            let msb = (reg >> 15) as u8;
            reg <<= 1;
            if data_bit ^ msb != 0 {
                reg ^= 0x8005;
            }
        }
    }
    reg.to_le_bytes()
}

/// One ATECC byte as the eight UART bytes that carry it.
pub fn encode(byte: u8) -> [u8; 8] {
    core::array::from_fn(|bit| if (byte >> bit) & 1 == 1 { BIT1 } else { BIT0 })
}

/// The `Random` command frame: `[len][op][p1][p2 lsb][p2 msb][crc lo][crc hi]`.
///
/// `p1 = 0` asks for fresh random rather than a fixed test value, and there is no data.
/// Source: se1-driver-spec.md §4 [C]; platform.md §3 [C]
pub fn random_command() -> [u8; 7] {
    let head = [7, OP_RANDOM, 0, 0, 0];
    let crc = crc16(&head);
    [head[0], head[1], head[2], head[3], head[4], crc[0], crc[1]]
}

/// Received UART bytes, as ATECC bytes. Returns how many were written.
///
/// A received byte that reads `0x7F` (after the 7-bit mask the stock driver applies) is a
/// `1`, anything else a `0`. Bits that do not make up a whole byte are dropped from the
/// *front*: that is where a spurious edge from the line turning around lands. Source:
/// se1-driver-spec.md §1, §2 [C]
pub fn decode(uart: &[u8], out: &mut [u8]) -> usize {
    let skip = uart.len() % 8;
    let mut n = 0;
    for chunk in uart[skip..].as_chunks::<8>().0 {
        if n == out.len() {
            break;
        }
        out[n] = chunk
            .iter()
            .enumerate()
            .fold(0u8, |b, (i, &u)| b | (u8::from(u & 0x7F == BIT1) << i));
        n += 1;
    }
    n
}

/// Why a read did not produce random bytes.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// The element answered with a status code instead of data: `0x11` is "just woke,
    /// resend", `0xFF` a CRC error on its side, `0x0F` an execution error.
    Status(u8),
    /// Nothing that parses as a frame came back: no reply, or a corrupted one. Carries
    /// what did come back -- how many UART bytes, and the first decoded bytes -- because
    /// "garbled" alone cannot tell a silent element from a misaligned one.
    Garbled { uart: u16, head: [u8; 4] },
    /// The peripheral did not become ready in time.
    Timeout,
    /// UART4's clock source is one this driver cannot compute a baud rate for.
    UnsupportedClock,
}

/// Pick the 32 random bytes out of a decoded response.
///
/// The line echoes what was just sent, so a reply can start with the `IOFLAG_TX` token
/// itself; a frame is looked for at the start and one byte in. It is accepted only whole:
/// the right count and a CRC over it that matches. Source: se1-driver-spec.md §5 [C]
pub fn parse_random(resp: &[u8]) -> Result<[u8; 32], Error> {
    let mut status = None;
    for start in 0..resp.len().min(2) {
        let frame = &resp[start..];
        match frame.first().copied() {
            Some(n) if n as usize == RANDOM_RESPONSE_LEN && frame.len() >= RANDOM_RESPONSE_LEN => {
                if crc16(&frame[..33]) == [frame[33], frame[34]] {
                    let mut out = [0u8; 32];
                    out.copy_from_slice(&frame[1..33]);
                    return Ok(out);
                }
            }
            Some(4) if frame.len() >= 4 && crc16(&frame[..2]) == [frame[2], frame[3]] => {
                status = Some(frame[1]);
            }
            _ => {}
        }
    }
    let mut head = [0u8; 4];
    let n = resp.len().min(4);
    head[..n].copy_from_slice(&resp[..n]);
    Err(status.map_or(Error::Garbled { uart: 0, head }, Error::Status))
}

// --- the hardware: target only ----------------------------------------------------------

/// UART4. Source: RM0351 Table 1 (memory map) [C]
const UART4: u32 = 0x4000_4C00;
#[allow(clippy::identity_op)]
const CR1: u32 = UART4 + 0x00;
const CR2: u32 = UART4 + 0x04;
const CR3: u32 = UART4 + 0x08;
const BRR: u32 = UART4 + 0x0C;
const RTOR: u32 = UART4 + 0x14;
const RQR: u32 = UART4 + 0x18;
const ISR: u32 = UART4 + 0x1C;
const ICR: u32 = UART4 + 0x20;
const RDR: u32 = UART4 + 0x24;
const TDR: u32 = UART4 + 0x28;

// Bit positions. Source: RM0351 §38.8.1-38.8.11 [C]
const CR1_UE: u32 = 1 << 0;
const CR1_RE: u32 = 1 << 2;
const CR1_TE: u32 = 1 << 3;
/// `M1`: with `M0` clear, **7 data bits**. The single-wire symbols are 7-bit patterns --
/// `0x7F` is a start bit and seven ones, a single short low -- and an eighth data bit adds
/// a low the element reads as garbage. The bootloader's own UART4 has this bit set
/// (`CR1 = 0x1000_000D`, read from a live mk3), which is also why reads mask with `0x7F`.
/// Source: hw-reference/se1-driver-spec.md §1.1 [C] (measured on hardware)
const CR1_M1: u32 = 1 << 28;
const CR2_RTOEN: u32 = 1 << 23;
const CR3_HDSEL: u32 = 1 << 3;
/// `ONEBIT` is bit 11. The bootloader's UART4 reads `CR3 = 0x0000_0808`: `HDSEL` and this.
const CR3_ONEBIT: u32 = 1 << 11;
const RQR_RXFRQ: u32 = 1 << 3;
const ISR_RXNE: u32 = 1 << 5;
const ISR_TC: u32 = 1 << 6;
const ISR_TXE: u32 = 1 << 7;
const ISR_RTOF: u32 = 1 << 11;
const ICR_FECF: u32 = 1 << 1;
const ICR_ORECF: u32 = 1 << 3;
const ICR_RTOCF: u32 = 1 << 11;

/// `RCC_APB1ENR1.UART4EN`. Source: RM0351 §6.4.19 [C]
const RCC_APB1ENR1: u32 = fixed::RCC + 0x58;
const APB1ENR1_UART4EN: u32 = 1 << 19;
/// `RCC_CCIPR.UART4SEL`, bits 7:6; `00` is PCLK1. Source: RM0351 §6.4.28 [C]
const RCC_CCIPR: u32 = fixed::RCC + 0x88;
const CCIPR_UART4SEL: u32 = 0b11 << 6;

/// UART4_TX on PA0. Source: STM32L496 datasheet, alternate function table (PA0 AF8) [C]
const AF_UART4: u8 = 8;

/// 230400 bps. Source: se1-driver-spec.md §1 [C]
const BAUD: u32 = 230_400;
/// Data rate for the wake byte only: slow enough that a `0x00` holds the line low past
/// the element's minimum wake time. See [`Se1Swi::wake`]. With 7-bit framing a `0x00` is
/// eight bit periods low: ~139 µs.
const WAKE_BAUD: u32 = 57_600;
/// Receive timeout, in bit periods. Source: se1-driver-spec.md §1 [C]
const RTOR_BITS: u32 = 24;

/// Polls for a UART flag before calling the peripheral dead.
const FLAG_TRIES: u32 = 200_000;
/// Attempts at a whole wake-command-read exchange. The stock driver allows up to ~7
/// (se1-driver-spec.md §5 [C]); this reads an *extra* source for mixing, and a caller's
/// screen is frozen while it retries, so a bus that is not answering gives up sooner.
const TRIES: usize = 3;
/// Times to ask for the response while `Random` executes (~23 ms nominally), a few ms
/// apart. Polled rather than timed: se1-driver-spec.md §6 [C]
const POLLS: usize = 6;
/// How long one ask listens for a reply. A whole `Random` response is 280 UART bytes, about
/// 12 ms at 230400 bps.
const LISTEN_MS: u32 = 20;

/// UART4 and SE1's pin, borrowed from the bootloader and handed back on drop.
pub struct Se1Swi {
    pin: Pin,
    pin_state: gpio::PinState,
    clock_was_on: bool,
    uart4sel: u32,
    cr1: u32,
    cr2: u32,
    cr3: u32,
    brr: u32,
    rtor: u32,
}

impl Se1Swi {
    /// Snapshot everything this driver will touch, then set the bus up.
    ///
    /// # Safety
    ///
    /// `pin` must be the board's SE1 single-wire pin, and nothing else may use UART4 or the
    /// pin while this value lives -- in particular no callgate call, since the bootloader
    /// talks to SE1 over the same bus.
    pub unsafe fn open(pin: Pin) -> Result<Self, Error> {
        // SAFETY: the caller owns UART4 and the pin; everything read here is put back by
        // `Drop`, and the clock gate is enabled before any UART4 register is read.
        unsafe {
            gpio::enable_port(pin.port);
            let clock_was_on = reg::read(RCC_APB1ENR1) & APB1ENR1_UART4EN != 0;
            reg::set_bits(RCC_APB1ENR1, APB1ENR1_UART4EN);
            let _ = reg::read(RCC_APB1ENR1);

            let saved = Self {
                pin,
                pin_state: gpio::snapshot(pin),
                clock_was_on,
                uart4sel: reg::read(RCC_CCIPR) & CCIPR_UART4SEL,
                cr1: reg::read(CR1),
                cr2: reg::read(CR2),
                cr3: reg::read(CR3),
                brr: reg::read(BRR),
                rtor: reg::read(RTOR),
            };

            // BRR is computed from PCLK1, so UART4 is put on PCLK1 while this runs; the
            // original selection comes back on drop.
            reg::clear_bits(RCC_CCIPR, CCIPR_UART4SEL);
            let fck = crate::clock::pclk1_hz();
            if fck == 0 {
                drop(saved);
                return Err(Error::UnsupportedClock);
            }

            // CR2, CR3 and BRR are only writable with the UART disabled.
            reg::write(CR1, CR1_M1);
            reg::write(BRR, (fck + BAUD / 2) / BAUD);
            reg::write(RTOR, RTOR_BITS);
            reg::write(CR2, CR2_RTOEN);
            // Half duplex: TX and RX on one line. ONEBIT sampling, as the stock driver uses.
            reg::write(CR3, CR3_HDSEL | CR3_ONEBIT);
            // In half duplex the TX pin is released when idle, so it is open drain against
            // the bus pull-up. Source: RM0351 §38.5.13 [C]
            gpio::set_alternate(pin, AF_UART4, OutputType::OpenDrain, Pull::Up, Speed::High);
            reg::write(CR1, CR1_M1 | CR1_UE | CR1_TE | CR1_RE);
            Ok(saved)
        }
    }

    /// 32 bytes from SE1's TRNG.
    pub fn random(&mut self) -> Result<[u8; 32], Error> {
        let mut last = Error::Garbled {
            uart: 0,
            head: [0; 4],
        };
        for _ in 0..TRIES {
            match self.exchange() {
                Ok(bytes) => {
                    // Back to sleep, the state the bootloader wakes it from.
                    let _ = self.send_token(IOFLAG_SLEEP);
                    return Ok(bytes);
                }
                Err(e) => last = e,
            }
        }
        let _ = self.send_token(IOFLAG_SLEEP);
        Err(last)
    }

    fn exchange(&mut self) -> Result<[u8; 32], Error> {
        self.wake()?;
        self.send_token(IOFLAG_CMD)?;
        for b in random_command() {
            self.send_token(b)?;
        }
        let mut last = Error::Garbled {
            uart: 0,
            head: [0; 4],
        };
        for poll in 0..POLLS {
            // The first ask waits most of `Random`'s nominal execution time; later asks are
            // a few milliseconds apart.
            // SAFETY: reads RCC only.
            unsafe { dwt::delay_ms(if poll == 0 { 20 } else { 4 }) };
            self.flush_rx();
            self.send_token(IOFLAG_TX)?;
            let mut uart = [0u8; 8 * (RANDOM_RESPONSE_LEN + 2)];
            let got = self.receive(&mut uart);
            let mut bytes = [0u8; RANDOM_RESPONSE_LEN + 2];
            let n = decode(&uart[..got], &mut bytes);
            match parse_random(&bytes[..n]) {
                Ok(r) => return Ok(r),
                // Still executing, or just woken: ask again.
                Err(Error::Garbled { head, .. }) => {
                    last = Error::Garbled {
                        uart: got as u16,
                        head,
                    }
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Hold the line low long enough to wake the element, then let it settle.
    ///
    /// The wake is a raw `0x00` byte (se1-driver-spec.md §3 [C]), but at 230400 bps that
    /// is nine bit periods, about 39 µs low -- under the ATECC608's 60 µs minimum wake low
    /// time (tWLO, ATECC608 datasheet). So the byte goes out at 57600 bps instead, about
    /// 139 µs low (7-bit framing). A low that long can only mean "wake" to the element, so the margin costs
    /// nothing. The data rate is restored before anything else is sent.
    fn wake(&mut self) -> Result<(), Error> {
        // SAFETY: UART4 is ours for the life of `self`; BRR is written with UE clear.
        let fck = unsafe { crate::clock::pclk1_hz() };
        unsafe {
            reg::write(CR1, CR1_M1);
            reg::write(BRR, (fck + WAKE_BAUD / 2) / WAKE_BAUD);
            reg::write(CR1, CR1_M1 | CR1_UE | CR1_TE);
        }
        let sent = self.send_raw(0x00);
        // SAFETY: as above.
        unsafe {
            reg::write(CR1, CR1_M1);
            reg::write(BRR, (fck + BAUD / 2) / BAUD);
            reg::write(CR1, CR1_M1 | CR1_UE | CR1_TE | CR1_RE);
        }
        sent?;
        // SAFETY: reads RCC only.
        unsafe { dwt::delay_ms(3) };
        self.flush_rx();
        Ok(())
    }

    /// Send one encoded byte with the receiver switched off.
    ///
    /// In half duplex the receiver hears its own transmitter. An echo byte left unread in
    /// `RDR` blocks every byte after it until it is read -- so the element's reply, which
    /// starts right after our token, would lose its leading bits and come back misaligned.
    /// With `RE` clear during transmission there is no echo, and the receiver is re-enabled
    /// the moment the last bit has left. Source: RM0351 §38.5.13, §38.8.1 (`RE`) [C]
    fn send_token(&mut self, byte: u8) -> Result<(), Error> {
        // SAFETY: UART4 is ours for the life of `self`; RE may change while UE is set.
        unsafe { reg::clear_bits(CR1, CR1_RE) };
        let sent = encode(byte).into_iter().try_for_each(|u| self.send_raw(u));
        // SAFETY: as above.
        unsafe {
            reg::write(ICR, ICR_ORECF | ICR_FECF | ICR_RTOCF);
            reg::set_bits(CR1, CR1_RE);
        }
        sent
    }

    fn send_raw(&mut self, byte: u8) -> Result<(), Error> {
        // SAFETY: UART4 is ours for the life of `self`.
        unsafe {
            if !reg::wait_for(ISR, ISR_TXE, ISR_TXE, FLAG_TRIES) {
                return Err(Error::Timeout);
            }
            reg::write(TDR, byte as u32);
            if !reg::wait_for(ISR, ISR_TC, ISR_TC, FLAG_TRIES) {
                return Err(Error::Timeout);
            }
        }
        Ok(())
    }

    /// Drop anything received so far -- the echo of our own bytes -- and clear the error
    /// flags that would otherwise stop reception.
    fn flush_rx(&mut self) {
        // SAFETY: UART4 is ours for the life of `self`.
        unsafe {
            reg::write(ICR, ICR_ORECF | ICR_FECF | ICR_RTOCF);
            reg::write(RQR, RQR_RXFRQ);
        }
    }

    /// Collect UART bytes until the line has gone quiet after a reply, or a deadline.
    fn receive(&mut self, out: &mut [u8]) -> usize {
        // SAFETY: reads RCC only.
        let per_ms = (unsafe { crate::clock::hclk_hz() } / 1000).max(1);
        let start = dwt::cycles();
        let mut n = 0;
        loop {
            // SAFETY: UART4 is ours for the life of `self`.
            let isr = unsafe { reg::read(ISR) };
            if isr & ISR_RXNE != 0 {
                // SAFETY: as above. The stock driver masks to 7 bits. se1-driver-spec.md §1
                let b = unsafe { reg::read(RDR) } as u8 & 0x7F;
                if n < out.len() {
                    out[n] = b;
                    n += 1;
                }
                continue;
            }
            // A receive timeout after data is the end of the reply. Before any data it is
            // just the gap after our own token, so keep listening until the deadline.
            if isr & ISR_RTOF != 0 {
                // SAFETY: as above.
                unsafe { reg::write(ICR, ICR_RTOCF | ICR_ORECF | ICR_FECF) };
                if n >= 8 {
                    break;
                }
            }
            if n == out.len() || dwt::cycles().wrapping_sub(start) > LISTEN_MS * per_ms {
                break;
            }
        }
        n
    }
}

impl Drop for Se1Swi {
    fn drop(&mut self) {
        // SAFETY: restoring exactly what `open` recorded, with the UART disabled while its
        // configuration registers are written back.
        unsafe {
            reg::write(CR1, 0);
            reg::write(BRR, self.brr);
            reg::write(RTOR, self.rtor);
            reg::write(CR2, self.cr2);
            reg::write(CR3, self.cr3);
            gpio::restore(self.pin, self.pin_state);
            reg::modify(RCC_CCIPR, CCIPR_UART4SEL, self.uart4sel);
            reg::write(CR1, self.cr1);
            if !self.clock_was_on {
                reg::clear_bits(RCC_APB1ENR1, APB1ENR1_UART4EN);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_crc_matches_what_the_element_sends_and_expects() {
        // Two frames with CRCs fixed by the element itself: the status it answers right
        // after waking, and the `Random` command as it appears on the wire.
        assert_eq!(crc16(&[0x04, 0x11]), [0x33, 0x43]);
        assert_eq!(random_command(), [0x07, 0x1B, 0x00, 0x00, 0x00, 0x24, 0xCD]);
    }

    #[test]
    fn bits_go_out_least_significant_first() {
        // 0x01: only the first UART byte carries a one.
        assert_eq!(
            encode(0x01),
            [BIT1, BIT0, BIT0, BIT0, BIT0, BIT0, BIT0, BIT0]
        );
        assert_eq!(
            encode(0x80),
            [BIT0, BIT0, BIT0, BIT0, BIT0, BIT0, BIT0, BIT1]
        );
    }

    #[test]
    fn encode_and_decode_round_trip_every_byte() {
        for b in 0..=255u8 {
            let mut out = [0u8; 1];
            assert_eq!(decode(&encode(b), &mut out), 1);
            assert_eq!(out[0], b);
        }
    }

    #[test]
    fn a_stray_leading_bit_does_not_shift_the_frame() {
        // The line turning around can add an edge before the reply; it lands at the front,
        // and dropping the odd bits there keeps every byte aligned.
        let mut uart = vec![BIT1, BIT0, BIT1];
        uart.extend(encode(0xA5));
        uart.extend(encode(0x3C));
        let mut out = [0u8; 4];
        assert_eq!(decode(&uart, &mut out), 2);
        assert_eq!(&out[..2], &[0xA5, 0x3C]);
    }

    fn response(data: [u8; 32]) -> Vec<u8> {
        let mut f = vec![RANDOM_RESPONSE_LEN as u8];
        f.extend(data);
        let crc = crc16(&f);
        f.extend(crc);
        f
    }

    #[test]
    fn a_whole_random_response_is_accepted_with_or_without_the_echo() {
        let data: [u8; 32] = core::array::from_fn(|i| i as u8 * 7 + 1);
        assert_eq!(parse_random(&response(data)), Ok(data));
        let mut echoed = vec![IOFLAG_TX];
        echoed.extend(response(data));
        assert_eq!(parse_random(&echoed), Ok(data));
    }

    #[test]
    fn a_corrupted_response_is_refused_not_passed_on() {
        // A byte flipped anywhere fails the CRC. Returning those bytes anyway would put a
        // bus error into the pool as if it were the element's output.
        let data = [0x55u8; 32];
        for i in 0..RANDOM_RESPONSE_LEN {
            let mut r = response(data);
            r[i] ^= 0x10;
            assert!(parse_random(&r).is_err(), "flip at {i} was accepted");
        }
        assert!(matches!(parse_random(&[]), Err(Error::Garbled { .. })));
    }

    #[test]
    fn a_status_reply_is_reported_as_one() {
        // "Just woke up": the element's answer to anything before a real command.
        assert_eq!(
            parse_random(&[0x04, 0x11, 0x33, 0x43]),
            Err(Error::Status(0x11))
        );
    }
}
