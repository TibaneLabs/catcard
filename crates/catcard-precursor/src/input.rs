//! Key events: the keyboard, and on bench builds the debug UART.
//!
//! The keyboard comes through `catcard_ui::precursorkeys`. With the `uart-keys` feature,
//! bytes received on the UART are key presses too, so a flow can be driven from the
//! Raspberry Pi: digits and lower-case letters (and `!`, `?`, space) type themselves,
//! CR/LF confirms, backspace/DEL cancels, and `U` `D` `L` `R` are the navigation pad's
//! arrows. Each byte is a press immediately followed by its release.

use catcard_ui::keypad::{Event, Key};

use crate::kbd;

pub struct Input {
    prev: [u16; kbd::ROWS],
    queue: [Option<Event>; 16],
}

impl Input {
    pub fn new() -> Self {
        Self {
            prev: kbd::scan(),
            queue: [None; 16],
        }
    }

    /// The next event, if any, without waiting.
    pub fn poll(&mut self) -> Option<Event> {
        if let Some(ev) = self.pop() {
            return Some(ev);
        }
        let now = kbd::scan();
        let mut evs = [Event::Released(Key::Cancel); 8];
        let n = catcard_ui::precursorkeys::events(&self.prev, &now, &mut evs);
        self.prev = now;
        for ev in &evs[..n] {
            self.push(*ev);
        }
        #[cfg(feature = "uart-keys")]
        if let Some(key) = uart_key() {
            self.push(Event::Pressed(key));
            self.push(Event::Released(key));
        }
        self.pop()
    }

    /// The keyboard alone, leaving the UART to whoever is reading it.
    pub fn poll_keyboard(&mut self) -> Option<Event> {
        let now = kbd::scan();
        let mut evs = [Event::Released(Key::Cancel); 8];
        let n = catcard_ui::precursorkeys::events(&self.prev, &now, &mut evs);
        self.prev = now;
        evs[..n]
            .iter()
            .copied()
            .find(|e| matches!(e, Event::Pressed(_)))
    }

    /// Waits for the next key press, feeding the watchdog.
    pub fn press(&mut self) -> Key {
        loop {
            crate::wdt::feed();
            if let Some(Event::Pressed(k)) = self.poll() {
                return k;
            }
            crate::timer::delay_ms(5);
        }
    }

    fn push(&mut self, ev: Event) {
        if let Some(slot) = self.queue.iter_mut().find(|s| s.is_none()) {
            *slot = Some(ev);
        }
    }

    fn pop(&mut self) -> Option<Event> {
        let ev = self.queue[0].take()?;
        self.queue.rotate_left(1);
        Some(ev)
    }
}

#[cfg(feature = "uart-keys")]
fn uart_key() -> Option<Key> {
    let b = crate::uart::read_byte()?;
    Some(match b {
        b'0'..=b'9' => Key::Digit(b - b'0'),
        b'a'..=b'z' | b'!' | b'?' | b' ' => Key::Char(b),
        b'\r' | b'\n' => Key::Confirm,
        0x08 | 0x7f => Key::Cancel,
        b'U' => Key::Digit(5),
        b'D' => Key::Digit(8),
        b'L' => Key::Digit(7),
        b'R' => Key::Digit(9),
        _ => return None,
    })
}
