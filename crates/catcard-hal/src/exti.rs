//! EXTI + SYSCFG: falling-edge external interrupts on GPIO input lines.
//!
//! Used for exactly one thing: catching the instant a keypad column falls, so the jitter
//! of *when* a person pressed a key -- not when a 60 Hz scan happened to notice -- can be
//! mixed into the UI DRBG at CPU-cycle resolution. This is the "hard falling-edge IRQ per
//! press" the stock firmware arms for its seed-mash entropy.
//! Source: hw-reference/gpio-peripherals.md §Interrupt model [C].
//!
//! EXTI line `n` is driven by pin `n` of whichever port `SYSCFG_EXTICR` selects, so a
//! column on GPIO pin `num` uses EXTI line `num`. Only lines 0..=15 (the GPIO lines) are
//! ever used here, so the `*1` half of each register covers everything.
//!
//! Register map: EXTI base `0x4001_0400`, SYSCFG base `0x4001_0000` -- RM0432 §EXTI /
//! §SYSCFG memory map [C]. Offsets: `IMR1`=+0x00, `RTSR1`=+0x08, `FTSR1`=+0x0C,
//! `PR1`=+0x14; `SYSCFG_EXTICR1..4`=+0x08..+0x14, four bits per line selecting the port
//! (PA=0, PB=1, ...), which matches [`Port`](catcard_board::pin::Port)'s discriminants.

use catcard_board::memory::fixed;
use catcard_board::pin::Pin;

use crate::reg;

/// SYSCFG controller.
const SYSCFG: u32 = 0x4001_0000;
/// `SYSCFG_EXTICR1`; `EXTICR2..4` follow at +4 each.
const SYSCFG_EXTICR1: u32 = SYSCFG + 0x08;

/// EXTI controller.
const EXTI: u32 = 0x4001_0400;
const EXTI_IMR1: u32 = EXTI; // +0x00
const EXTI_RTSR1: u32 = EXTI + 0x08;
const EXTI_FTSR1: u32 = EXTI + 0x0C;
/// Pending register: a set bit flags a captured edge; writing 1 clears it.
const EXTI_PR1: u32 = EXTI + 0x14;

/// `RCC_APB2ENR` bit 0 = `SYSCFGEN`, the SYSCFG register clock. Source: RM0432 §RCC [C].
const RCC_APB2ENR: u32 = fixed::RCC + 0x60;
const SYSCFGEN: u32 = 1 << 0;

/// The EXTI line a pin drives: line `n` is pin `n` of the selected port.
#[inline]
pub const fn line_of(pin: Pin) -> u8 {
    pin.num
}

/// Turn on the SYSCFG register clock. `SYSCFG_EXTICR` reads back zero until this is done.
///
/// # Safety
/// Writes RCC.
pub unsafe fn enable_clock() {
    unsafe {
        reg::set_bits(RCC_APB2ENR, SYSCFGEN);
        let _ = reg::read(RCC_APB2ENR); // let the gate settle before first access
    }
}

/// Point EXTI line `pin.num` at `pin`'s port via the matching `SYSCFG_EXTICR` nibble.
///
/// # Safety
/// Writes SYSCFG with a read-modify-write; the SYSCFG clock must be enabled and no other
/// context may configure the same `EXTICR` register concurrently.
pub unsafe fn select_source(pin: Pin) {
    let line = line_of(pin) as u32;
    // Four lines per EXTICR register, four bits per line.
    let reg_addr = SYSCFG_EXTICR1 + (line / 4) * 4;
    let shift = (line % 4) * 4;
    unsafe {
        reg::modify(reg_addr, 0b1111 << shift, (pin.port as u32) << shift);
    }
}

/// Select falling-edge triggering (and clear rising) for every line in `mask`.
///
/// # Safety
/// Writes EXTI registers; single-threaded configuration only.
pub unsafe fn set_falling(mask: u16) {
    let mask = mask as u32;
    unsafe {
        reg::clear_bits(EXTI_RTSR1, mask);
        reg::set_bits(EXTI_FTSR1, mask);
    }
}

/// Clear any latched edges on `mask` (write-1-to-clear).
///
/// # Safety
/// Writes `EXTI_PR1`.
#[inline]
pub unsafe fn clear_pending(mask: u16) {
    unsafe { reg::write(EXTI_PR1, mask as u32) }
}

/// Unmask (arm) the lines in `mask` after clearing any stale pending edge, so the next
/// falling edge on one of them raises its interrupt.
///
/// # Safety
/// Writes EXTI registers.
#[inline]
pub unsafe fn arm(mask: u16) {
    unsafe {
        clear_pending(mask);
        reg::set_bits(EXTI_IMR1, mask as u32);
    }
}

/// Mask (disarm) the lines in `mask`. With the line masked, an edge no longer latches a
/// pending bit, so the row toggling of an active scan raises nothing.
///
/// # Safety
/// Writes `EXTI_IMR1`.
#[inline]
pub unsafe fn disarm(mask: u16) {
    unsafe { reg::clear_bits(EXTI_IMR1, mask as u32) }
}

/// Clear the pending edges on `mask` and mask the lines, in that order -- the interrupt
/// handler's own cleanup, so a held or bouncing key does not re-enter before the
/// foreground re-arms.
///
/// # Safety
/// Writes EXTI registers.
#[inline]
pub unsafe fn clear_and_mask(mask: u16) {
    unsafe {
        clear_pending(mask);
        reg::clear_bits(EXTI_IMR1, mask as u32);
    }
}

/// The NVIC IRQ number servicing a given EXTI line. Lines 5..=9 share `EXTI9_5`, lines
/// 10..=15 share `EXTI15_10`; the rest have their own. Source: RM0432 §NVIC vector table [C].
pub const fn irq_of_line(line: u8) -> u16 {
    match line {
        0 => 6,
        1 => 7,
        2 => 8,
        3 => 9,
        4 => 10,
        5..=9 => 23,
        _ => 40, // 10..=15
    }
}

/// Whether an IRQ number is one of the EXTI GPIO IRQs this module can raise.
pub const fn is_exti_irq(irqn: u16) -> bool {
    matches!(irqn, 6 | 7 | 8 | 9 | 10 | 23 | 40)
}

#[cfg(test)]
mod tests {
    use super::*;
    use catcard_board::pin::{pa, pb, pd};

    #[test]
    fn a_pin_uses_the_exti_line_of_its_number() {
        assert_eq!(line_of(pa(1)), 1);
        assert_eq!(line_of(pb(0)), 0);
        assert_eq!(line_of(pd(15)), 15);
    }

    #[test]
    fn exticr_register_and_nibble_selection() {
        // Mirror the arithmetic in `select_source` without touching hardware.
        fn target(pin: Pin) -> (u32, u32) {
            let line = line_of(pin) as u32;
            (SYSCFG_EXTICR1 + (line / 4) * 4, (line % 4) * 4)
        }
        assert_eq!(target(pb(0)), (SYSCFG_EXTICR1, 0)); // EXTICR1, line 0
        assert_eq!(target(pa(3)), (SYSCFG_EXTICR1, 12)); // EXTICR1, line 3
        assert_eq!(target(pb(5)), (SYSCFG_EXTICR1 + 4, 4)); // EXTICR2, line 5
        assert_eq!(target(pd(15)), (SYSCFG_EXTICR1 + 12, 12)); // EXTICR4, line 15
    }

    #[test]
    fn each_line_maps_to_its_nvic_irq() {
        // The three numpad column groups and the Q1 spread must all resolve.
        assert_eq!(irq_of_line(0), 6); // mk4 COL0
        assert_eq!(irq_of_line(1), 7); // mk5 COL0 / mk4 COL1
        assert_eq!(irq_of_line(2), 8);
        assert_eq!(irq_of_line(3), 9); // mk5 COL1
        assert_eq!(irq_of_line(5), 23); // Q1, EXTI9_5
        assert_eq!(irq_of_line(9), 23);
        assert_eq!(irq_of_line(10), 40); // Q1, EXTI15_10
        assert_eq!(irq_of_line(15), 40);
    }

    #[test]
    fn only_the_gpio_exti_irqs_are_recognised() {
        for irqn in [6, 7, 8, 9, 10, 23, 40] {
            assert!(is_exti_irq(irqn));
        }
        for irqn in [0, 5, 11, 22, 24, 39, 41, 67] {
            assert!(!is_exti_irq(irqn));
        }
    }
}
