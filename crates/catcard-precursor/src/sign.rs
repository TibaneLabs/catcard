//! Sign PSBT, with the PSBT carried over the debug UART.
//!
//! A bench transport until this board has USB (docs/PRECURSOR.md): the host sends the PSBT
//! as one line of hex, and gets back `signed <hex>`. Nothing about the review or the
//! signing depends on it -- swapping the transport for USB HID leaves this flow as it is.
//! What the person approves is on the device's screen, from catcard-wallet's `summarise`:
//! every output with change marked, and the fee.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use catcard_ui::keypad::Key;

use crate::session::Session;
use crate::ui::Ui;

/// The longest PSBT accepted over the UART, in bytes.
const MAX_PSBT: usize = 64 * 1024;
const SATS: u64 = 100_000_000;

pub fn run(ui: &mut Ui, s: &Session) {
    ui.notice("Sign PSBT", "send hex on the", "debug UART; bksp: no");
    let _ = writeln!(ui.out, "psbt: send one line of hex");
    let Some(psbt) = receive(ui) else { return };
    let _ = writeln!(ui.out, "psbt: {} bytes received", psbt.len());

    ui.notice("Sign PSBT", "checking", "");
    let review = match s.review(&psbt) {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(ui.out, "psbt: {e}");
            ui.ask("Refused", &e, "");
            return;
        }
    };

    let mut lines: Vec<String> = Vec::new();
    for (addr, amount, change) in &review.outputs {
        lines.push(format!(
            "{}{}",
            btc(*amount),
            if *change { "  change" } else { "" }
        ));
        for chunk in addr.as_bytes().chunks(21) {
            lines.push(format!(" {}", core::str::from_utf8(chunk).unwrap_or("?")));
        }
    }
    lines.push(String::new());
    lines.push(format!("fee {} ({}%)", btc(review.fee), review.fee_percent));
    if review.fee_warn {
        lines.push(String::from("FEE IS HIGH"));
    }
    lines.push(format!("signing {} of {} in", review.ours, review.inputs));
    lines.push(String::from("enter: sign  bksp: no"));
    if !ui.pages("Send", &lines) {
        let _ = writeln!(ui.out, "psbt: declined on the device");
        return;
    }

    ui.notice("Sign PSBT", "signing", "");
    match s.sign(&psbt) {
        Ok((signed, count)) => {
            let mut hex = String::with_capacity(signed.len() * 2);
            for b in &signed {
                let _ = write!(hex, "{b:02x}");
            }
            let _ = writeln!(ui.out, "signed {hex}");
            ui.ask(
                "Signed",
                &format!("{count} input(s) signed"),
                "sent on the UART",
            );
        }
        Err(e) => {
            let _ = writeln!(ui.out, "psbt: {e}");
            ui.ask("Failed", &e, "");
        }
    }
}

/// Satoshis as BTC with 8 decimals.
fn btc(sats: u64) -> String {
    format!("{}.{:08} BTC", sats / SATS, sats % SATS)
}

/// One line of hex from the UART, decoded. `None` if cancelled on the keyboard or bad.
/// Reads in a tight loop: the UART's receive FIFO is 16 bytes deep, about 1.4 ms at
/// 115200 baud, so the wait never sleeps.
fn receive(ui: &mut Ui) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut high: Option<u8> = None;
    let mut started = false;
    loop {
        crate::wdt::feed();
        if let Some(b) = crate::uart::read_byte() {
            match b {
                b'\n' | b'\r' if started => return Some(out),
                b'\n' | b'\r' => {}
                _ => {
                    started = true;
                    let v = (b as char).to_digit(16)? as u8;
                    match high.take() {
                        None => high = Some(v),
                        Some(h) => out.push(h << 4 | v),
                    }
                    if out.len() > MAX_PSBT {
                        ui.ask("Refused", "PSBT too large", "");
                        return None;
                    }
                }
            }
            continue;
        }
        // The keyboard only (the UART carries the PSBT): backspace cancels.
        if let Some(catcard_ui::keypad::Event::Pressed(Key::Cancel)) = ui.input.poll_keyboard() {
            return None;
        }
    }
}
