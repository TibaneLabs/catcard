//! Whether the Q1 is running on its batteries or on external power.
//!
//! There is no VBUS-present GPIO on this board -- USB power just feeds the regulator and
//! is not sensed anywhere. `NOT_BATTERY` is the only signal there is, and it is
//! **active-low**: high means external/USB, low means battery.
//!
//! Which pin carries it depends on the board revision, and the revision is itself a strap
//! (`REV_D`, read with a pull-up): rev D and later use `NOT_BATTERY=PE7`, earlier boards
//! `NOT_BATTERY_OLD=PC1`. Both are read once at init and the choice is remembered, since
//! a board does not change revision while it runs.
//!
//! # The level
//!
//! On battery, [`charge`] reads `VIN_SENSE` (PA1, ADC1 channel 6, behind a divide-by-two)
//! the way stock does -- five conversions, the first thrown away, the other four
//! averaged, times 3.3 V and times two -- and buckets it into stock's four steps
//! ([`Charge`]). VDDA is the 3.3 V rail itself on this board, so 3.3 V is the real
//! reference. The ADC is brought up the first time a level is wanted, not on the boot
//! path.
//!
//! Source: hw-reference/power.md §"Battery & power pins", §"Power source: battery vs USB",
//! §"Battery sense", §"Battery level & monitoring (Q1)" [C], except the strap's polarity,
//! which that document does not give and which was measured on hardware -- see [`init`].
//! ADC programming: RM0432 §21 [C], in `catcard_hal::adc`.

use core::ptr::addr_of_mut;

use catcard_board::{BOARD, Pin};
use catcard_hal::gpio::{self, Mode, OutputType, Pull, Speed};
pub use catcard_ui::statusbar::Charge;

/// The `NOT_BATTERY` pin this board revision actually uses, once known.
static mut SENSE: Option<Pin> = None;

/// Where the device's power is coming from.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Source {
    /// External or USB power.
    External,
    /// The batteries.
    Battery,
}

/// Configure the sense pins and work out which one this board uses.
///
/// # Safety
/// Claims the board's battery-sense pins and reads RCC. Call once, from the boot path.
pub unsafe fn init() {
    let Some(sense) = BOARD.battery else { return };
    // SAFETY: the caller is the boot path and these pins belong to nothing else.
    let strap = unsafe {
        gpio::enable_port(sense.rev_d.port);
        gpio::configure(
            sense.rev_d,
            Mode::Input,
            OutputType::PushPull,
            Pull::Up,
            Speed::Low,
        );
        gpio::read(sense.rev_d)
    };
    // **Fitted reads low.** `power.md` says the strap selects the pin but not which way
    // round, and guessing it the other way is why a Q1 on USB power showed a battery:
    // it read `NOT_BATTERY_OLD`, which is not connected on this board, floating low.
    //
    // Measured on a **rev E** Q1 on 2026-09-18, through the debug-memory peek: `PC3`
    // reads 0 against our own pull-up, so the strap is pulling it to ground; `PE7` reads
    // 1 while on USB power, which is the documented "external" level; `PC1` reads 0 with
    // no pull, which is a floating input and not a reading. The board revision is known
    // independently, so this is the polarity itself and not an inference from which pin
    // looked plausible. An unfitted strap reads 1 through the pull-up: the older boards.
    let rev_d = !strap;
    let pin = if rev_d {
        sense.not_battery
    } else {
        sense.not_battery_old
    };
    // SAFETY: as above.
    unsafe {
        gpio::enable_port(pin.port);
        // No pull: the signal is driven. Asking for one could hold a floating input at
        // the wrong level and report external power on a device running from batteries.
        gpio::configure(
            pin,
            Mode::Input,
            OutputType::PushPull,
            Pull::None,
            Speed::Low,
        );
        *addr_of_mut!(SENSE) = Some(pin);
    }
    crate::catlog!(
        "power: rev {}, battery sense on P{}{}",
        if rev_d { "D+" } else { "pre-D" },
        pin.port.letter(),
        pin.num
    );
}

/// Where power is coming from, or `None` on a board with no battery to be on.
///
/// `None` is not "external": the mk3/mk4/mk5 have no battery at all, and a status bar
/// should say nothing rather than draw a plug it did not check.
pub fn source() -> Option<Source> {
    // SAFETY: foreground only; the read finishes within this statement.
    let pin = unsafe { *addr_of_mut!(SENSE) }?;
    // Active-low: high is external power, low is battery.
    // SAFETY: reads one GPIO input register.
    Some(if unsafe { gpio::read(pin) } {
        Source::External
    } else {
        Source::Battery
    })
}

/// `VIN_SENSE` is ADC1 input 6. Source: hw-reference/power.md §"Battery sense" --
/// "`VIN_SENSE=PA1` (= ADC1 `IN6`)" [C]
const VIN_CHANNEL: u32 = 6;
/// The ADC's reference: VDDA / VREF+ tie to the 3.3 V system rail, with no separate
/// reference on the board. Source: power.md §"Battery sense" (schematic-confirmed) [C]
const VREF_MV: u32 = 3300;
/// The divide-by-two in front of the pin. Source: power.md §"Battery sense" [C]
const DIVIDER: u32 = 2;

/// Where the ADC stands: not yet tried, up, or failed (and not to be retried every
/// frame).
#[derive(Copy, Clone, PartialEq, Eq)]
enum Adc {
    Untried,
    Up,
    Failed,
}
static mut ADC: Adc = Adc::Untried;

/// How full the batteries read, or `None` when not on battery or no reading could be
/// taken.
///
/// Five conversions, the first discarded (stock cites the part's errata for it), the
/// other four averaged; the first call brings the ADC up. A failure is logged once and
/// leaves every later call answering `None`, which draws an unfilled battery -- an
/// honest "unknown" rather than a guessed level.
///
/// Foreground only: the ADC belongs to this function.
/// Source: hw-reference/power.md §"Battery sense" [C]
pub fn charge() -> Option<Charge> {
    if source()? != Source::Battery {
        return None;
    }
    let sense = BOARD.battery?;
    // SAFETY: foreground only, single core; nothing else touches the ADC or this state.
    let state = unsafe { &mut *addr_of_mut!(ADC) };
    if *state == Adc::Untried {
        // SAFETY: the pin is the board's battery-sense input and belongs to nothing
        // else; analog mode disconnects its digital input. The ADC is ours alone.
        let up = unsafe {
            gpio::enable_port(sense.vin_sense.port);
            gpio::configure(
                sense.vin_sense,
                Mode::Analog,
                OutputType::PushPull,
                Pull::None,
                Speed::Low,
            );
            catcard_hal::adc::init()
        };
        *state = match up {
            Ok(()) => Adc::Up,
            Err(e) => {
                crate::catlog!("battery: ADC would not start: {:?}", e);
                Adc::Failed
            }
        };
    }
    if *state != Adc::Up {
        return None;
    }
    let mut samples = [0u16; 5];
    for s in samples.iter_mut() {
        // SAFETY: the ADC came up above and is ours alone.
        match unsafe { catcard_hal::adc::read(VIN_CHANNEL) } {
            Ok(v) => *s = v,
            Err(e) => {
                crate::catlog!("battery: ADC read failed: {:?}", e);
                return None;
            }
        }
    }
    let mv = catcard_hal::adc::millivolts(&samples[1..], VREF_MV, DIVIDER)?;
    Some(Charge::from_millivolts(mv))
}
