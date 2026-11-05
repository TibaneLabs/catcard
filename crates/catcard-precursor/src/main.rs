//! CatCard on the Precursor: bare metal on the stock betrusted-soc gateware.
//!
//! The Precursor is a VexRiscv RV32IMAC SoC in a Spartan-7, with 16 MiB of external
//! SRAM, a 336x536 memory LCD, a QWERTY keyboard and a TRNG, all as memory-mapped
//! peripherals described by the gateware's own `csr.csv` (see `build.rs`). There is no
//! secure element and no Coldcard bootloader, so nothing here uses `catcard-callgate`.
//!
//! Milestone 1 (this file): prove the toolchain and the board layer end to end. The image
//! runs from SRAM, entered over the USB debug bridge by `tools/precursor/run.py`; it
//! feeds the watchdog Xous left armed, says hello on the UART the debug hat carries to a
//! Raspberry Pi, draws a test card on the LCD, and keeps time. See docs/PRECURSOR.md.
//!
//! On a host this crate builds as an empty stub so `cargo clippy --workspace` and the
//! workspace tests stay green; everything real is behind `target_arch = "riscv32"`.
#![cfg_attr(target_arch = "riscv32", no_std, no_main)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "riscv32")]
mod csr;
#[cfg(target_arch = "riscv32")]
mod kbd;
#[cfg(target_arch = "riscv32")]
mod lcd;
#[cfg(target_arch = "riscv32")]
mod rngcheck;
#[cfg(target_arch = "riscv32")]
mod screens;
#[cfg(target_arch = "riscv32")]
mod start;
#[cfg(target_arch = "riscv32")]
mod timer;
#[cfg(target_arch = "riscv32")]
mod trng;
#[cfg(target_arch = "riscv32")]
mod uart;
#[cfg(target_arch = "riscv32")]
mod wdt;

#[cfg(not(target_arch = "riscv32"))]
fn main() {}

#[cfg(target_arch = "riscv32")]
#[unsafe(no_mangle)]
extern "C" fn rust_main() -> ! {
    use core::fmt::Write as _;

    // First thing: Xous arms the watchdog and it cannot be disarmed, so a slow start
    // means a reset back into stock firmware.
    wdt::feed();

    let mut out = uart::Uart::take();
    let _ = writeln!(
        out,
        "\n\nCatCard for Precursor -- milestone 2 (in progress)"
    );
    let _ = writeln!(out, "built against gateware {}", csr::GATEWARE_REV);
    let _ = writeln!(
        out,
        "watchdog: {}",
        if wdt::enabled() {
            "armed by previous firmware, feeding"
        } else {
            "off"
        }
    );
    let _ = writeln!(out, "uptime at entry: {} ms", timer::now_ms());

    // The screens are catcard-ui's, laid out for this panel by `Layout::large()`. The frame
    // lives on the stack: 23.6 KB against a stack of most of 16 MiB.
    let layout = catcard_ui::widgets::Layout::large();
    let mut frame = catcard_ui::memlcd::MemLcd::new();

    catcard_ui::widgets::message(
        &mut frame,
        &layout,
        "CatCard",
        "for Precursor",
        "checking entropy",
    );
    show(&mut out, &frame, "splash");

    let summary = rngcheck::run(&mut out);
    let lines = screens::entropy_lines(&summary);
    catcard_ui::widgets::info(&mut frame, &layout, "Entropy", &lines);
    show(&mut out, &frame, "entropy");
    timer::delay_ms(3000);

    // A blank device's main menu, as CatCard has it (catcard-fw MAIN_ITEMS_BLANK, the
    // boards with a Help row). Not wired to anything yet: no keyboard driver.
    let items = ["New", "Import", "Utils", "Settings", "Help"];
    catcard_ui::widgets::menu(
        &mut frame,
        &layout,
        "CatCard",
        "no seed",
        &items,
        catcard_ui::menu::Scroll::default(),
    );
    show(&mut out, &frame, "main menu");

    main_menu(&mut out, &layout, &mut frame, &items);
}

#[cfg(target_arch = "riscv32")]
fn show(out: &mut uart::Uart, frame: &catcard_ui::memlcd::MemLcd, what: &str) {
    use core::fmt::Write as _;
    match lcd::show(frame) {
        Ok(ms) => {
            let _ = writeln!(out, "lcd: {what} shown ({ms} ms)");
        }
        Err(e) => {
            let _ = writeln!(out, "lcd: {what}: {e}");
        }
    }
}

/// The blank device's main menu, driven by the keyboard. Items open a placeholder until
/// their flows exist on this board. Runs forever, feeding the watchdog.
#[cfg(target_arch = "riscv32")]
fn main_menu(
    out: &mut uart::Uart,
    layout: &catcard_ui::widgets::Layout<'_>,
    frame: &mut catcard_ui::memlcd::MemLcd,
    items: &[&str],
) -> ! {
    use catcard_ui::keypad::{Event, Key};
    use core::fmt::Write as _;

    let rows = layout.rows(catcard_ui::memlcd::HEIGHT);
    let mut sc = catcard_ui::menu::Scroll::default();
    let mut open: Option<usize> = None;
    let mut prev = kbd::scan();
    loop {
        wdt::feed();
        let now = kbd::scan();
        let mut events = [Event::Released(Key::Cancel); 8];
        let n = catcard_ui::precursorkeys::events(&prev, &now, &mut events);
        prev = now;

        let mut redraw = false;
        for ev in &events[..n] {
            let _ = writeln!(out, "key {ev:?}");
            let Event::Pressed(key) = *ev else { continue };
            match (open, key) {
                (None, Key::Digit(5)) => sc = sc.step(items.len(), rows, false),
                (None, Key::Digit(8)) => sc = sc.step(items.len(), rows, true),
                (None, Key::Confirm) => open = Some(sc.cursor),
                (Some(_), Key::Cancel) => open = None,
                _ => continue,
            }
            redraw = true;
        }
        if redraw {
            match open {
                None => catcard_ui::widgets::menu(frame, layout, "CatCard", "no seed", items, sc),
                Some(i) => catcard_ui::widgets::message(
                    frame,
                    layout,
                    items[i],
                    "not on Precursor yet",
                    "backspace: back",
                ),
            }
            show(out, frame, "menu");
        }
        timer::delay_ms(10);
    }
}
