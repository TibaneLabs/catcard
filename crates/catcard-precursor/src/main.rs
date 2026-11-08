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
extern crate alloc;

#[cfg(target_arch = "riscv32")]
mod app;
#[cfg(target_arch = "riscv32")]
mod csr;
#[cfg(target_arch = "riscv32")]
mod heap;
#[cfg(target_arch = "riscv32")]
mod input;
#[cfg(target_arch = "riscv32")]
mod kbd;
#[cfg(target_arch = "riscv32")]
mod keyrom;
#[cfg(target_arch = "riscv32")]
mod keywork;
#[cfg(target_arch = "riscv32")]
mod lcd;
#[cfg(target_arch = "riscv32")]
mod newseed;
#[cfg(target_arch = "riscv32")]
mod rngcheck;
#[cfg(target_arch = "riscv32")]
mod screens;
#[cfg(target_arch = "riscv32")]
mod session;
#[cfg(target_arch = "riscv32")]
mod sign;
#[cfg(target_arch = "riscv32")]
mod start;
#[cfg(target_arch = "riscv32")]
mod timer;
#[cfg(target_arch = "riscv32")]
mod trng;
#[cfg(target_arch = "riscv32")]
mod uart;
#[cfg(target_arch = "riscv32")]
mod ui;
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
    let _ = writeln!(out, "\n\nCatCard for Precursor");
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
    keyrom::report(&mut out);

    heap::init();
    let mut ui = ui::Ui::new(out);
    ui.notice("CatCard", "for Precursor", "checking entropy");
    let summary = rngcheck::run(&mut ui.out);
    let lines = screens::entropy_lines(&summary);
    catcard_ui::widgets::info(&mut ui.frame, &ui.layout, "Entropy", &lines);
    ui.show("entropy");
    timer::delay_ms(2000);
    app::run(&mut ui)
}
