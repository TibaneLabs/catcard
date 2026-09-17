//! Binding the keypad scanner to this board's GPIO.
//!
//! One scanner per input type: the 4x3 numpad ([`catcard_ui::keypad`]) on mk3/mk4/mk5 and
//! the 10x6 QWERTY matrix ([`catcard_ui::qwerty`]) on Q1. Both hand the rest of the
//! firmware the same `Key` events through a type named [`Keypad`], so no screen needs to
//! know which one it is reading.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use catcard_board::spec::Input;
use catcard_board::{BOARD, Pin};
use catcard_hal::gpio::{self, Mode, OutputType, Pull, Speed};
use catcard_hal::{dwt, exti, rtc};

#[cfg(not(feature = "board-q1"))]
pub use catcard_ui::keypad::Keypad;
#[cfg(not(feature = "board-q1"))]
use catcard_ui::keypad::{COLS, Matrix, ROWS};
#[cfg(feature = "board-q1")]
pub use catcard_ui::qwerty::Keypad;
#[cfg(feature = "board-q1")]
use catcard_ui::qwerty::{COLS, Matrix, ROWS};

/// Column bits as the scanner's `Matrix` returns them: 3 lanes fit a `u8`, 10 need a `u16`.
#[cfg(not(feature = "board-q1"))]
type Bits = u8;
#[cfg(feature = "board-q1")]
type Bits = u16;

/// Settling time between driving a row and sampling the columns.
///
/// The columns are pulled up by weak internal resistors against the membrane's cable
/// capacitance, so the line takes real time to rise. Sampling too early reads the
/// previous row's state, which presents as keys registering from the wrong row.
const SETTLE_CYCLES: u32 = 200;

/// The keypad as wired on this board.
pub struct GpioMatrix {
    rows: [Pin; ROWS],
    cols: [Pin; COLS],
    /// Bitmask of the column EXTI lines (`1 << pin.num` per column), cached so `arm`/
    /// `disarm` need not recompute it.
    edge_mask: u16,
}

// --- Exact-edge keypress timing -------------------------------------------------------
//
// A scan only sees a key when the poll happens; the falling edge on a column line happens
// the moment the key makes contact. The gap between the two is up to a scan period (~16
// ms), and its *width* is exactly the human timing jitter we want as entropy. So while the
// matrix idles between scans it sits with every row driven low and a falling-edge EXTI
// armed on each column: a press raises an interrupt at once, [`on_key_edge`] latches the
// cycle counter and the RTC at that instant, and the next [`pressed_keys`] mixes that
// precise sample into the UI DRBG. Source: hw-reference/gpio-peripherals.md §Interrupt
// model [C] -- the stock firmware arms the same hard falling-edge IRQ for its mash entropy.

/// Column EXTI lines, published so the interrupt handler can clear the right pending bits
/// without a reference to the [`GpioMatrix`] (which the foreground owns).
static EDGE_MASK: AtomicU32 = AtomicU32::new(0);
/// The latched sample: DWT cycle counter, then the three RTC registers.
static EDGE_CYCLES: AtomicU32 = AtomicU32::new(0);
static EDGE_RTC0: AtomicU32 = AtomicU32::new(0);
static EDGE_RTC1: AtomicU32 = AtomicU32::new(0);
static EDGE_RTC2: AtomicU32 = AtomicU32::new(0);
/// Set by the handler when a sample is waiting; cleared when the foreground drains it.
static EDGE_READY: AtomicBool = AtomicBool::new(false);
/// Edges seen since boot, for the Keypad debug screen.
static EDGE_COUNT: AtomicU32 = AtomicU32::new(0);
/// Set when the edge path has been shut off and must not be re-armed: either it was never
/// armed on this board, or the storm guard below tripped.
static EDGE_OFF: AtomicBool = AtomicBool::new(true);
/// Set by the storm guard so the foreground can say why the path went quiet.
static EDGE_STORM: AtomicBool = AtomicBool::new(false);
/// Edges inside the current window, and when the window started (DWT cycles).
static EDGE_WINDOW: AtomicU32 = AtomicU32::new(0);
static EDGE_WINDOW_AT: AtomicU32 = AtomicU32::new(0);

/// Edges in one window that mean something other than a finger is driving the line.
///
/// The foreground re-arms once per scan, so a real key -- even one held down, even one
/// bouncing -- cannot produce more than one edge per scan period, about sixty a second. Ten
/// times that is not a person.
const EDGE_STORM_LIMIT: u32 = 600;
/// The window the limit is counted over: a second at the slowest core clock we run (mk3's
/// 80 MHz), which is short enough to trip before a user notices and long enough that a fast
/// mash cannot reach the limit.
const EDGE_STORM_WINDOW_CYCLES: u32 = 80_000_000;

/// Interrupt handler for a keypad column's falling edge.
///
/// Kept to the essentials of an ISR: sample the two free-running timers, publish them, and
/// clear + mask the column lines so a held or bouncing key does not re-enter before the
/// foreground re-arms. Runs to completion before any foreground code, so plain `Relaxed`
/// stores under the `Release` on `EDGE_READY` are enough to hand the sample over.
pub fn on_key_edge() {
    let mask = EDGE_MASK.load(Ordering::Relaxed) as u16;
    let cycles = dwt::cycles();
    // SAFETY: `snapshot` only opens an APB read gate and reads three registers; no shared
    // state it could corrupt, and it is re-entrancy-safe.
    let r = unsafe { rtc::snapshot() };
    EDGE_CYCLES.store(cycles, Ordering::Relaxed);
    EDGE_RTC0.store(r[0], Ordering::Relaxed);
    EDGE_RTC1.store(r[1], Ordering::Relaxed);
    EDGE_RTC2.store(r[2], Ordering::Relaxed);
    EDGE_READY.store(true, Ordering::Release);
    EDGE_COUNT.fetch_add(1, Ordering::Relaxed);

    // Storm guard. A column that is being driven by something other than the keypad -- a
    // pin that is not the column we think it is, a line another peripheral owns -- raises
    // an edge every time the foreground re-arms, and the device then spends its life in
    // this handler: the keypad goes half-dead and USB, which is polled from the foreground,
    // turns erratic. That is a device nobody can re-flash, and on a locked unit that is the
    // end of it. So count the rate here, and shut the path off for good if it is not human.
    let window_at = EDGE_WINDOW_AT.load(Ordering::Relaxed);
    let elapsed = cycles.wrapping_sub(window_at);
    if window_at == 0 || elapsed > EDGE_STORM_WINDOW_CYCLES {
        EDGE_WINDOW_AT.store(cycles, Ordering::Relaxed);
        EDGE_WINDOW.store(1, Ordering::Relaxed);
    } else if EDGE_WINDOW.fetch_add(1, Ordering::Relaxed) + 1 >= EDGE_STORM_LIMIT {
        EDGE_STORM.store(true, Ordering::Relaxed);
        EDGE_OFF.store(true, Ordering::Release);
    }

    // SAFETY: writes EXTI PR1/IMR1 for our own lines only; the foreground re-arms them,
    // and stops re-arming once `EDGE_OFF` is set.
    unsafe { exti::clear_and_mask(mask) };
}

/// Edges seen since boot, whether the path is still armed, and whether the guard tripped.
pub fn edge_stats() -> (u32, bool, bool) {
    (
        EDGE_COUNT.load(Ordering::Relaxed),
        !EDGE_OFF.load(Ordering::Relaxed),
        EDGE_STORM.load(Ordering::Relaxed),
    )
}

/// The DWT cycle count latched by the most recent keypad edge, or 0 if none ever fired.
///
/// Read-only and non-consuming, for diagnostics: the kernel test logs it so a keypress
/// during the test shows the edge interrupt preempting whatever task was running.
pub fn edge_latch() -> u32 {
    EDGE_CYCLES.load(Ordering::Relaxed)
}

/// Take the most recent latched edge sample, if a press was caught since the last call.
///
/// Sixteen bytes: the cycle counter and the three RTC registers, little-endian. `None`
/// when no edge fired -- e.g. a key that went down exactly at scan time, or input injected
/// over USB, both of which carry no such timing.
pub fn take_edge_sample() -> Option<[u8; 16]> {
    if !EDGE_READY.swap(false, Ordering::Acquire) {
        return None;
    }
    let mut s = [0u8; 16];
    s[0..4].copy_from_slice(&EDGE_CYCLES.load(Ordering::Relaxed).to_le_bytes());
    s[4..8].copy_from_slice(&EDGE_RTC0.load(Ordering::Relaxed).to_le_bytes());
    s[8..12].copy_from_slice(&EDGE_RTC1.load(Ordering::Relaxed).to_le_bytes());
    s[12..16].copy_from_slice(&EDGE_RTC2.load(Ordering::Relaxed).to_le_bytes());
    Some(s)
}

impl GpioMatrix {
    /// Configure the matrix pins.
    ///
    /// Rows are open-drain: a push-pull row driven high would fight a different row
    /// driven low through any pressed key, which at best reads wrong and at worst
    /// sources current through the membrane.
    ///
    /// Returns `None` when this build's scanner does not match the board's input, or when
    /// a column reads low with every row released -- see below.
    ///
    /// # Safety
    /// Call once; takes exclusive ownership of the keypad pins.
    pub unsafe fn init() -> Option<Self> {
        let (rows, cols) = match BOARD.input {
            #[cfg(not(feature = "board-q1"))]
            Input::Numpad4x3 { rows, cols } => (rows, cols),
            #[cfg(feature = "board-q1")]
            Input::Qwerty { rows, cols } => (rows, cols),
            #[allow(unreachable_patterns)]
            _ => return None,
        };

        // SAFETY: these pins belong to the keypad alone, which the board table's
        // pin-conflict test enforces.
        unsafe {
            for r in rows {
                gpio::enable_port(r.port);
                gpio::configure(
                    r,
                    Mode::Output,
                    OutputType::OpenDrain,
                    Pull::None,
                    Speed::Low,
                );
                gpio::write(r, true); // released
            }
            for c in cols {
                gpio::enable_port(c.port);
                gpio::configure(c, Mode::Input, OutputType::PushPull, Pull::Up, Speed::Low);
            }
        }

        // With every row released no key can pull a column low, so a column that reads
        // low now is a short, a missing pull-up, or the wrong pins -- and a matrix like
        // that presses something on every scan, which on a confirmation screen is an
        // answer nobody gave. Refuse it: the session then runs headless, which keeps the
        // device reprogrammable over USB. Nothing is driven, so no scan order can leak.
        catcard_hal::dwt::delay_cycles(SETTLE_CYCLES * 10);
        // SAFETY: configured as inputs just above.
        if cols.iter().any(|&c| !unsafe { gpio::read(c) }) {
            crate::catlog!("keypad: a column reads low with no row driven; matrix refused");
            return None;
        }

        let edge_mask = cols.iter().fold(0u16, |m, &c| m | (1 << exti::line_of(c)));
        let mut this = Self {
            rows,
            cols,
            edge_mask,
        };
        // SAFETY: the column pins are configured as inputs and belong to the keypad; this
        // wires their EXTI lines and enables the NVIC entries, done once from the boot path.
        unsafe { this.init_edge_detect() };
        Some(this)
    }

    /// One-time EXTI/NVIC setup for exact-edge keypress timing, then arm the lines for the
    /// first idle gap. Idempotent enough to call once from [`init`](Self::init).
    ///
    /// # Safety
    /// Writes SYSCFG/EXTI and the NVIC. Call once, from bring-up.
    unsafe fn init_edge_detect(&mut self) {
        EDGE_MASK.store(self.edge_mask as u32, Ordering::Relaxed);
        // SAFETY: single-threaded bring-up; the column pins are ours.
        unsafe {
            // Open the RTC read gate here, from the foreground, so the per-press interrupt
            // handler only ever *reads* the RTC and never races the shared RCC register.
            rtc::enable();
            exti::enable_clock();
            for &c in &self.cols {
                exti::select_source(c);
            }
            exti::set_falling(self.edge_mask);
            exti::disarm(self.edge_mask); // masked until the first `arm`
            exti::clear_pending(self.edge_mask);
        }
        // Unmask each distinct EXTI IRQ these columns can raise. The `DefaultHandler`
        // routes them to `on_key_edge`; nothing else is ever unmasked on those lines.
        crate::interrupts::enable_exti(self.edge_mask);

        // Arm at boot only where this path has been watched running on real hardware. It
        // is the one thing in the firmware that hands control to an interrupt before
        // anybody can look at the device, and a board where it misbehaves comes up with a
        // half-dead keypad and unreliable USB -- which is to say, a board that cannot be
        // re-flashed. Where it is not proven the lines stay masked and the keypad is purely
        // polled, exactly as every board ran before interrupts were enabled at boot; Debug
        // -> Keypad arms it on demand, and a power cycle undoes that.
        if BOARD.keypad_edge_at_boot {
            EDGE_OFF.store(false, Ordering::Release);
            self.arm_edge_detect();
        } else {
            crate::catlog!("keypad: edge entropy not armed at boot on this board");
        }
    }

    /// Arm the edge path now, from the foreground. Returns false if the storm guard has
    /// shut it off, which is permanent until the next boot.
    pub fn arm_edge_now(&mut self) -> bool {
        if EDGE_STORM.load(Ordering::Relaxed) {
            return false;
        }
        EDGE_OFF.store(false, Ordering::Release);
        self.arm_edge_detect();
        true
    }

    /// Mask the edge path and leave it masked.
    pub fn disarm_edge_now(&mut self) {
        EDGE_OFF.store(true, Ordering::Release);
        self.disarm_edge_detect();
    }

    /// Idle the matrix for edge detection: drive every row low so any key pulls its column
    /// low, then unmask the column EXTI lines. Called after each scan, before the wait.
    ///
    /// # Safety
    /// Rows must be configured as outputs (they are, from [`init`](Self::init)).
    pub fn arm_edge_detect(&mut self) {
        // SAFETY: rows are open-drain outputs. All-low is one shared ground with no
        // potential across rows, so nothing shorts -- the state the pad idles in per
        // hw-reference/gpio-peripherals.md §Interrupt model [C].
        unsafe {
            for r in self.rows {
                gpio::write(r, false);
            }
            // Not armed on a board where the path is not proven, and never again once the
            // storm guard has tripped: the rows still idle low, so the scan is unaffected.
            if !EDGE_OFF.load(Ordering::Acquire) {
                exti::arm(self.edge_mask);
            }
        }
    }

    /// Mask the column EXTI lines so an active scan's row toggling raises no interrupt.
    /// Called at the start of each scan.
    pub fn disarm_edge_detect(&mut self) {
        // SAFETY: writes EXTI IMR1 for our own lines only.
        unsafe { exti::disarm(self.edge_mask) };
    }
}

impl Matrix for GpioMatrix {
    fn select_row(&mut self, row: usize) {
        // Release every row, then drive the one wanted. Doing it in this order means
        // two rows are never low simultaneously, even briefly.
        // SAFETY: configured as outputs in `init`.
        unsafe {
            for r in self.rows {
                gpio::write(r, true);
            }
            gpio::write(self.rows[row], false);
        }
    }

    fn read_columns(&mut self, order: &[u8; COLS]) -> Bits {
        let mut bits: Bits = 0;
        for &c in order {
            let ci = c as usize;
            // Read in the caller's randomised order, and accumulate branchlessly: a
            // pressed key (column low) sets its bit, a released one sets nothing, via
            // identical code with no data-dependent branch. So neither which lane is
            // pressed nor which row leaks through the read timing or the EM ordering.
            // Pulled up, so a pressed key pulls the column to the driven row's low.
            // SAFETY: configured as inputs in `init`.
            bits |= Bits::from(!unsafe { gpio::read(self.cols[ci]) }) << ci;
        }
        bits
    }

    fn release_rows(&mut self) {
        // SAFETY: configured as outputs in `init`.
        unsafe {
            for r in self.rows {
                gpio::write(r, true);
            }
        }
    }

    fn settle(&mut self) {
        catcard_hal::dwt::delay_cycles(SETTLE_CYCLES);
    }
}
