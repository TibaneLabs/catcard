//! Reading a QR code with the Q1's scanner.
//!
//! The module is a decoded-barcode engine on USART2, not a camera: it images and decodes
//! on its own and hands back plain text. [`catcard_qr`] holds the wire format -- the
//! framing, the commands and the rules for reading a reply -- and is tested against the
//! reference's own worked example.
//!
//! What is missing is everything below that: this firmware has no USART driver. `se1swi`
//! drives UART4 half-duplex for the mk3's secure element and puts every register back
//! afterwards, which is a different job from owning a port and running a link at 57600
//! baud. So the screen says so rather than presenting a scanner that cannot scan.
//!
//! Source: hw-reference/input.md §"QR scanner (Q1)" [C]

use crate::menu;
use crate::ui::Ui;

pub(crate) fn screen(ui: &mut Ui<'_>) {
    menu::message(
        ui.panel,
        "Scan QR",
        "the scanner is not driven yet",
        "any key to go back",
    );
    menu::wait_for_any_key(ui);
}
