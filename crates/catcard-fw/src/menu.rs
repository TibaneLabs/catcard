//! The main menu, and the debug screens under it.
//!
//! This exists because of how the first hardware bring-up went. The device booted,
//! drew its screen, took a PIN — and then sat on a status line that said `usb down`
//! and nothing else. Every fact that would have identified the fault in a minute was
//! in a register the firmware could read and had no way to show: whether the USB
//! supply came up, what the OTG core thought its state was, what the system clock
//! actually is. The diagnosis took a round trip through a reference manual and a
//! rebuild, and the rebuild could not be installed, because the only channel for
//! installing it was the thing that was broken.
//!
//! So the rule here is: **show the register, not a verdict about it.** A screen that
//! says "USB: failed" is worth very little; one that says `PWR_CR2 0000_0000` says
//! which write did not land. Every debug screen below prints raw values next to the
//! names they have in the reference manual, so what is on the glass can be compared
//! against RM0432 directly.
//!
//! Navigation follows the arrows **printed on the keypad**: `5` up, `7` left, `8` down,
//! `9` right. So `5`/`8` move the cursor, `9` and `y` both select, and `7` and `x` both
//! go back.
//!
//! That is a fact about the hardware rather than a convention worth arguing over — the
//! legend is on the keys, in front of whoever is holding the device, and a menu that
//! moves some other way is simply wrong about the thing it is running on.
//!
//! The list scrolls rather than being capped at what fits. An earlier version drew a
//! fixed number of rows and silently dropped the rest, which hid `Enter DFU` — the one
//! item that exists to rescue a device nothing else can reach. A menu that cannot
//! outgrow the panel is the property worth having here, not a shorter menu.

use core::fmt::Write as _;

use catcard_callgate::Callgate;
use catcard_callgate::abi::{DfuMode, LogoutMode};
use catcard_entropy::HmacDrbg;
use catcard_ui::Mono128x64;
use catcard_ui::font::{misc4x6, peep7x14};
use catcard_ui::keypad::{Event, KEYS, Key, Keypad};
use catcard_ui::menu::Scroll;
use catcard_ui::text::{centred, draw_text};

use crate::{BootReport, display, keypad::GpioMatrix, usbtask};

/// A line of debug text. Wide enough for `NAME 0000_0000` and a little more.
type Line = heapless::String<32>;

/// First text row, below the title.
const LINE0: usize = 21;
/// Row pitch: the 4x6 font plus a pixel of air.
const LINE_H: usize = 7;
/// Rows that fit between [`LINE0`] and the bottom of the panel.
const MAX_LINES: usize = (64 - LINE0) / LINE_H;
/// Characters that fit on a log line: the 4x6 font at `x = 2`, same as [`info`] draws.
const LOG_COLS: usize = (128 - 2) / 4;

// Scrolling is what keeps a long menu honest, so the old "must fit on the panel"
// assertions are gone. This one stays: every scroll calculation below assumes there is
// a window to scroll, and a zero- or one-row window makes `top` meaningless.
const _: () = assert!(MAX_LINES >= 2, "the panel must fit at least two menu rows");

/// Where we are. Flat rather than a stack: the tree is two deep, and a stack would be
/// state to get wrong for no gain.
#[derive(Copy, Clone, PartialEq, Eq)]
enum Screen {
    Main,
    About,
    SdInstall,
    Debug,
    Usb,
    Clocks,
    Psram,
    PsramProbe,
    Sd,
    Boot,
    Keypad,
    Logs,
    SaveLog,
    ConfirmDfu,
}

const MAIN_ITEMS: &[&str] = &["Status", "Install from SD", "Debug", "About", "Reboot"];
const DEBUG_ITEMS: &[&str] = &[
    "USB",
    "Clocks",
    "PSRAM",
    "Boot report",
    "Keypad",
    "microSD",
    "Logs",
    "Save log to SD",
    "Enter DFU",
];

/// Run the menu. Never returns.
///
/// Also the idle loop: USB is polled here, and a staged upgrade takes over the screen
/// wherever the user happens to be. Keeping one loop means there is no menu screen that
/// quietly stops serving the host.
pub fn run(session: Session<'_>) -> ! {
    let Session {
        gate,
        login,
        panel,
        matrix,
        drbg,
        report,
        head,
        note,
    } = session;
    let mut screen = Screen::Main;
    let mut showing_offer = false;
    let mut redraw = true;
    // `sc` is tested in `catcard_ui::menu` -- the arithmetic deciding which rows are on
    // screen is the part of a menu that can be wrong without looking wrong.
    let mut v = View {
        report,
        head,
        note,
        last_key: None,
        keys_seen: 0,
        sc: Scroll::new(),
        log_scroll: 0,
    };

    let mut pad = Keypad::new();
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();

    loop {
        if redraw && !showing_offer {
            draw(panel, screen, &v);
            redraw = false;
        }

        let _ = usbtask::pump();
        catcard_hal::dwt::delay_cycles(usbtask::IDLE_PAUSE_CYCLES);

        // An upgrade that passed inspection is waiting on a person, wherever they are.
        if let Some(a) = usbtask::pending() {
            if !showing_offer {
                crate::session::show_offer(panel, &a);
                showing_offer = true;
            }
        } else if showing_offer {
            showing_offer = false;
            redraw = true;
        }

        crate::pinentry::pressed_keys(&mut pad, matrix, drbg, &mut events, &mut keys);
        for key in keys.iter() {
            if showing_offer {
                match key {
                    Key::Confirm => match usbtask::approve() {
                        Ok(region) => {
                            message(panel, "Installing", "do not disconnect", "");
                            install(gate, login, panel, region);
                            showing_offer = false;
                            redraw = true;
                        }
                        Err(_) => {
                            crate::catlog!("install: staging failed");
                            message(panel, "Failed", "could not stage", "the image");
                            showing_offer = false;
                        }
                    },
                    Key::Cancel => {
                        usbtask::decline();
                        showing_offer = false;
                        redraw = true;
                    }
                    Key::Digit(_) => {}
                }
                continue;
            }

            v.last_key = Some(*key);
            v.keys_seen = v.keys_seen.saturating_add(1);
            redraw = true;

            // Cursor movement first: it stays on this screen, so it never reaches the
            // transition table below.
            if let Some(items) = items_of(screen) {
                match key {
                    // The up and down arrows on the keys.
                    Key::Digit(5) => {
                        v.sc = v.sc.step(items.len(), MAX_LINES, false);
                        continue;
                    }
                    Key::Digit(8) => {
                        v.sc = v.sc.step(items.len(), MAX_LINES, true);
                        continue;
                    }
                    _ => {}
                }
            }

            // The log viewer scrolls its text window rather than a cursor, so it is
            // paged here instead of through `items_of`. Any other key leaves, falling
            // through to `step`, whose default sends an info screen back to Debug.
            if screen == Screen::Logs {
                match key {
                    Key::Digit(5) => {
                        v.log_scroll = v.log_scroll.saturating_sub(1);
                        continue;
                    }
                    Key::Digit(8) => {
                        let max = log_total().saturating_sub(MAX_LINES);
                        if v.log_scroll < max {
                            v.log_scroll = v.log_scroll.saturating_add(1);
                        }
                        continue;
                    }
                    _ => v.log_scroll = 0,
                }
            }

            let next = step(gate, panel, screen, *key, v.sc.cursor);
            if next == Screen::SdInstall {
                install_from_card(gate, login, panel, matrix, drbg);
                v.sc = Scroll::new();
                screen = Screen::Main;
                break;
            }
            if next == Screen::SaveLog {
                save_log_to_card(panel, matrix, drbg);
                v.sc = Scroll::new();
                screen = Screen::Debug;
                break;
            }
            if next != screen {
                // A new list starts at the top. Carrying a cursor between menus of
                // different lengths is how you land on an item nobody chose.
                v.sc = Scroll::new();
            }
            screen = next;
        }
    }
}

/// Where a key takes us. Returns the next screen.
fn step(
    gate: &Callgate,
    panel: &mut display::Panel,
    screen: Screen,
    key: Key,
    cursor: usize,
) -> Screen {
    // The right arrow goes in and the left arrow comes out, the same as `y` and `x`.
    // Normalising here keeps every screen below written in terms of two actions rather
    // than four keys, so a screen cannot accidentally honour one and forget the other.
    let key = match key {
        Key::Digit(9) => Key::Confirm,
        Key::Digit(7) => Key::Cancel,
        k => k,
    };
    match screen {
        Screen::Main => match (key, cursor) {
            // "Status" is the screen behind the menu, so choosing it just redraws --
            // there is no separate page.
            (Key::Confirm, 0) => Screen::Main,
            (Key::Confirm, 1) => Screen::SdInstall,
            (Key::Confirm, 2) => Screen::Debug,
            (Key::Confirm, 3) => Screen::About,
            (Key::Confirm, _) => {
                message(panel, "Rebooting", "", "");
                // SAFETY: nothing after this runs.
                unsafe { gate.logout(LogoutMode::LogoutAndReboot) }
            }
            _ => Screen::Main,
        },
        // The splash, dismissed by any key.
        Screen::About => Screen::Main,
        Screen::Debug => match (key, cursor) {
            (Key::Confirm, 0) => Screen::Usb,
            (Key::Confirm, 1) => Screen::Clocks,
            (Key::Confirm, 2) => Screen::Psram,
            (Key::Confirm, 3) => Screen::Boot,
            (Key::Confirm, 4) => Screen::Keypad,
            (Key::Confirm, 5) => Screen::Sd,
            (Key::Confirm, 6) => Screen::Logs,
            (Key::Confirm, 7) => Screen::SaveLog,
            (Key::Confirm, _) => Screen::ConfirmDfu,
            (Key::Cancel, _) => Screen::Main,
            _ => Screen::Debug,
        },
        // The probe is reached by pressing the tick on the PSRAM screen, never by
        // arriving there. An unmapped read faults and a fault needs a power cycle, so
        // the risk is worth taking deliberately and not by navigation.
        Screen::Psram => match key {
            Key::Confirm => Screen::PsramProbe,
            _ => Screen::Debug,
        },
        Screen::ConfirmDfu => match key {
            Key::Confirm => {
                message(panel, "Entering DFU", "hangs if locked", "");
                // SAFETY: nothing after this runs. On an RDP=2 unit the bootloader
                // calls LOCKUP_FOREVER instead, so the device hangs until it is
                // power-cycled -- which the screen says before the key is pressed.
                unsafe { gate.enter_dfu(DfuMode::Normal) }
            }
            _ => Screen::Debug,
        },
        // Every info screen leaves on any key.
        _ => Screen::Debug,
    }
}

/// What the menu runs on: the peripherals it drives and the state it reports.
///
/// A struct rather than eight positional arguments, which is one transposed pair away
/// from driving the wrong thing.
pub struct Session<'a> {
    pub gate: &'a Callgate,
    /// The logged-in PIN struct. `gate 18/7` authorises an upgrade through it, and only
    /// a logged-in one carries the signature that call requires.
    pub login: &'a mut catcard_pin::Login,
    pub panel: &'a mut display::Panel,
    pub matrix: &'a mut GpioMatrix,
    pub drbg: &'a mut HmacDrbg,
    pub report: &'a BootReport,
    pub head: &'a str,
    pub note: &'a str,
}

/// Everything a screen needs to draw itself.
///
/// Grouped rather than passed one by one: these travel together through the loop, and a
/// call taking eight positional arguments is one transposed pair away from drawing the
/// wrong thing without the compiler noticing.
struct View<'a> {
    report: &'a BootReport,
    /// Title of the top-level screen: what the unlock resolved to.
    head: &'a str,
    /// Its second line, until USB has something to say.
    note: &'a str,
    last_key: Option<Key>,
    keys_seen: u32,
    sc: Scroll,
    /// First line shown by the log viewer.
    log_scroll: usize,
}

/// The list on this screen, if it is a menu.
fn items_of(screen: Screen) -> Option<&'static [&'static str]> {
    match screen {
        Screen::Main => Some(MAIN_ITEMS),
        Screen::Debug => Some(DEBUG_ITEMS),
        _ => None,
    }
}

/// Draw whichever screen we are on.
fn draw(panel: &mut display::Panel, screen: Screen, v: &View<'_>) {
    match screen {
        // The note line is the USB state rather than a fixed string: it was the one
        // number worth seeing without navigating anywhere, and losing it to a submenu
        // would undo the thing this menu exists to fix.
        Screen::Main => menu(panel, v.head, &usb_line(v.note), MAIN_ITEMS, v.sc),
        Screen::About => about_screen(panel),
        Screen::Debug => menu(panel, "Debug", "", DEBUG_ITEMS, v.sc),
        Screen::Usb => usb_screen(panel),
        Screen::Clocks => clock_screen(panel),
        Screen::Psram => psram_screen(panel),
        Screen::PsramProbe => psram_probe(panel),
        Screen::Boot => boot_screen(panel, v.report),
        Screen::Keypad => keypad_screen(panel, v.last_key, v.keys_seen),
        Screen::Sd => sd_screen(panel),
        Screen::Logs => log_screen(panel, v.log_scroll),
        // Handled in `run`; never drawn.
        Screen::SaveLog => {}
        // Handled in `run`: it needs the keypad, which the drawing half does not have.
        Screen::SdInstall => {}
        Screen::ConfirmDfu => confirm_dfu(panel),
    }
}

/// `usb up in 3 out 3`, or the reason it is not, falling back to `note` before init.
fn usb_line(note: &str) -> Line {
    let (configured, rx, tx, _) = usbtask::stats();
    let fault = usbtask::init_fault();
    let mut l = Line::new();
    if !configured && rx == 0 && tx == 0 && fault.is_empty() {
        // Nothing has happened yet and nothing has failed: say what the device is
        // rather than reporting a zero that looks like a fault.
        let _ = l.push_str(note);
        return l;
    }
    let _ = write!(
        l,
        "usb {}{} in {rx} out {tx}",
        if configured { "up" } else { "down" },
        fault
    );
    l
}

/// A numbered menu. `note` is the second line, for a hint or a status.
fn menu(panel: &mut display::Panel, title: &str, note: &str, items: &[&str], sc: Scroll) {
    let mut fb = Mono128x64::new();
    let t = &peep7x14::FONT;
    let f = &misc4x6::FONT;
    draw_text(&mut fb, t, centred(t, title, 128), 0, title);
    draw_text(&mut fb, f, centred(f, note, 128), 15, note);

    let (top, end) = sc.window(items.len(), MAX_LINES);
    for (row, item) in items[top..end].iter().enumerate() {
        let y = LINE0 + row * LINE_H;
        // A marker rather than inverted pixels: the 4x6 font has no room for a
        // highlight that stays legible, and this reads at arm's length.
        if top + row == sc.cursor {
            draw_text(&mut fb, f, 2, y, ">");
        }
        draw_text(&mut fb, f, 10, y, item);
    }

    // Say that there is more, in the only place there is room for it. Without this a
    // list that scrolls looks exactly like one that has ended.
    if top > 0 {
        draw_text(&mut fb, f, 122, LINE0, "^");
    }
    if end < items.len() {
        draw_text(&mut fb, f, 122, LINE0 + (MAX_LINES - 1) * LINE_H, "v");
    }
    let _ = panel.flush(&fb);
}

/// A titled screen of raw values, left-aligned, leaving on any key.
fn info(panel: &mut display::Panel, title: &str, lines: &[Line]) {
    let mut fb = Mono128x64::new();
    let t = &peep7x14::FONT;
    let f = &misc4x6::FONT;
    draw_text(&mut fb, t, centred(t, title, 128), 0, title);
    for (i, line) in lines.iter().take(MAX_LINES).enumerate() {
        draw_text(&mut fb, f, 2, LINE0 + i * LINE_H, line);
    }
    let _ = panel.flush(&fb);
}

/// `NAME 0000_0000`, grouped like the reference manual prints registers.
fn reg_line(name: &str, v: u32) -> Line {
    let mut s = Line::new();
    let _ = write!(s, "{name} {:04x}_{:04x}", v >> 16, v & 0xFFFF);
    s
}

/// USB: did the peripheral come up, is the host talking, and what does the core think.
fn usb_screen(panel: &mut display::Panel) {
    let (configured, rx, tx, pending) = usbtask::stats();
    let fault = usbtask::init_fault();

    let mut lines: heapless::Vec<Line, MAX_LINES> = heapless::Vec::new();

    let mut l = Line::new();
    let _ = write!(
        l,
        "state {}{}",
        if configured { "configured" } else { "down" },
        if fault.is_empty() { "" } else { " " }
    );
    let _ = l.push_str(fault);
    let _ = lines.push(l);

    let mut l = Line::new();
    let _ = write!(
        l,
        "in {rx}  out {tx}{}",
        if pending { "  staged" } else { "" }
    );
    let _ = lines.push(l);

    // The supply and its clock gate, which is where the first hardware failure lived.
    // SAFETY: reads only.
    unsafe {
        let cr2 = catcard_hal::clock::pwr_cr2();
        let mut l = Line::new();
        let _ = write!(
            l,
            "USV {}  PWREN {}",
            (cr2 >> 10) & 1,
            (catcard_hal::clock::apb1enr1() >> 28) & 1
        );
        let _ = lines.push(l);
    }

    match usbtask::otg_regs() {
        Some(r) => {
            let _ = lines.push(reg_line("GINTSTS", r[0]));
            let _ = lines.push(reg_line("DCTL   ", r[5]));
        }
        None => {
            let mut l = Line::new();
            let _ = write!(l, "core not initialised");
            let _ = lines.push(l);
        }
    }
    info(panel, "USB", &lines);
}

/// Clocks: the MSI range every cycle-count delay in this firmware is calibrated against.
fn clock_screen(panel: &mut display::Panel) {
    let mut lines: heapless::Vec<Line, MAX_LINES> = heapless::Vec::new();
    // SAFETY: reads only.
    unsafe {
        let cr = catcard_hal::clock::rcc_cr();
        let khz = catcard_hal::clock::msi_range_khz(cr);

        let mut l = Line::new();
        let _ = write!(l, "MSI {}.{:03} MHz", khz / 1000, khz % 1000);
        let _ = lines.push(l);

        let mut l = Line::new();
        let _ = write!(
            l,
            "HSI48 {}  PLL {}",
            u8::from(catcard_hal::clock::hsi48_ready()),
            (cr >> 25) & 1
        );
        let _ = lines.push(l);

        let _ = lines.push(reg_line("RCC_CR ", cr));
        let _ = lines.push(reg_line("AHB3EN ", catcard_hal::clock::ahb3enr()));
    }
    info(panel, "Clocks", &lines);
}

/// PSRAM: says the thing our own code knows and the hardware cannot be asked.
fn psram_screen(panel: &mut display::Panel) {
    let mut lines: heapless::Vec<Line, MAX_LINES> = heapless::Vec::new();
    match catcard_board::BOARD.psram {
        None => {
            let mut l = Line::new();
            let _ = write!(l, "none on this board");
            let _ = lines.push(l);
        }
        Some(p) => {
            let mut l = Line::new();
            let _ = write!(l, "base {:04x}_0000", p.base >> 16);
            let _ = lines.push(l);

            let mut l = Line::new();
            let _ = write!(l, "we never configure OCTOSPI");
            let _ = lines.push(l);

            // Whether that matters is the open question: the bootloader maps PSRAM to
            // read a staged image, and may leave it mapped.
            let mut l = Line::new();
            let _ = write!(l, "press ok to write+read back");
            let _ = lines.push(l);

            let mut l = Line::new();
            let _ = write!(l, "(hangs if not mapped)");
            let _ = lines.push(l);

            // SAFETY: reads only.
            let _ = lines.push(reg_line("AHB3EN ", unsafe {
                catcard_hal::clock::ahb3enr()
            }));
        }
    }
    info(panel, "PSRAM", &lines);
}

/// Write a word to PSRAM and read it back.
///
/// **The question this answers is whether an upgrade can work at all.** The bootloader
/// installs from PSRAM, so it configures OCTOSPI to read one at boot; if it leaves that
/// mapping in place for the firmware, staging works with no driver of ours. If it does
/// not, every upgrade this device accepts writes into nothing.
///
/// A read of an unmapped region faults rather than returning a value, and the fault
/// needs a power cycle — so **the device hanging on this screen is itself the answer**,
/// and says the mapping is not inherited.
///
/// Writes into the staging area, which holds nothing unless an upgrade is in flight.
fn psram_probe(panel: &mut display::Panel) {
    let Some(p) = catcard_board::BOARD.psram else {
        message(panel, "PSRAM", "none on this board", "");
        return;
    };
    // Scratch at the base of the staging half, clear of the recovery header.
    let at = (p.base + p.len / 2) as *mut u32;
    const PATTERN: u32 = 0xCA7C_A2D0;

    message(panel, "Probing PSRAM", "hangs if unmapped", "");
    // SAFETY: `at` is inside the region `BoardSpec` describes as memory-mapped PSRAM,
    // aligned, and in the staging half, which nothing else is using while the menu is
    // up. If the region is not actually mapped this faults -- which is the result being
    // measured, and is why the screen above is drawn first.
    let (wrote, read) = unsafe {
        core::ptr::write_volatile(at, PATTERN);
        let back = core::ptr::read_volatile(at);
        (PATTERN, back)
    };

    let mut lines: heapless::Vec<Line, MAX_LINES> = heapless::Vec::new();
    let _ = lines.push(reg_line("wrote  ", wrote));
    let _ = lines.push(reg_line("read   ", read));
    let mut l = Line::new();
    let _ = write!(
        l,
        "{}",
        if read == wrote {
            "MAPPED: staging works"
        } else {
            "NOT MAPPED: upgrades fail"
        }
    );
    let _ = lines.push(l);
    info(panel, "PSRAM probe", &lines);
}

/// What bring-up found, in the same words the selftest screen used.
fn boot_screen(panel: &mut display::Panel, report: &BootReport) {
    let mut lines: heapless::Vec<Line, MAX_LINES> = heapless::Vec::new();

    let mut l = Line::new();
    let _ = write!(l, "HAL {}", if report.hal.is_ok() { "ok" } else { "FAIL" });
    let _ = lines.push(l);

    let mut l = Line::new();
    let _ = write!(l, "DWT {}", if report.dwt_running { "ok" } else { "FAIL" });
    let _ = lines.push(l);

    let mut l = Line::new();
    match report.entropy {
        Ok(bits) => {
            let _ = write!(l, "entropy ok {bits} bit");
        }
        Err(_) => {
            let _ = write!(l, "entropy BELOW POLICY");
        }
    }
    let _ = lines.push(l);

    let mut l = Line::new();
    // What it is running on, and what it was built for, when those differ.
    let running = crate::running_board();
    let _ = if running == crate::BOARD_NAME {
        write!(l, "board {running}")
    } else {
        write!(l, "board {running} (built {})", crate::BOARD_NAME)
    };
    let _ = lines.push(l);
    info(panel, "Boot", &lines);
}

/// Which key the firmware decoded, which is the question a mirrored pad raises.
fn keypad_screen(panel: &mut display::Panel, last: Option<Key>, seen: u32) {
    let mut lines: heapless::Vec<Line, MAX_LINES> = heapless::Vec::new();

    let mut l = Line::new();
    match last {
        Some(Key::Digit(d)) => {
            let _ = write!(l, "last  {d}");
        }
        Some(Key::Confirm) => {
            let _ = write!(l, "last  y");
        }
        Some(Key::Cancel) => {
            let _ = write!(l, "last  x");
        }
        None => {
            let _ = write!(l, "press any key");
        }
    }
    let _ = lines.push(l);

    let mut l = Line::new();
    let _ = write!(l, "count {seen}");
    let _ = lines.push(l);

    let mut l = Line::new();
    let _ = write!(l, "press what the cap says");
    let _ = lines.push(l);

    let mut l = Line::new();
    let _ = write!(l, "x twice  back");
    let _ = lines.push(l);
    info(panel, "Keypad", &lines);
}

/// Ask before DFU, with the two keys drawn as they are printed on the caps.
fn confirm_dfu(panel: &mut display::Panel) {
    use catcard_ui::icons;
    let mut fb = Mono128x64::new();
    let t = &peep7x14::FONT;
    let f = &misc4x6::FONT;
    draw_text(&mut fb, t, centred(t, "Enter DFU?", 128), 6, "Enter DFU?");

    let gap = 4 * f.width as usize;
    let total = icons::hint_width(f, "yes") + gap + icons::hint_width(f, "no");
    let mut x = (128usize).saturating_sub(total) / 2;
    x = icons::draw_hint(&mut fb, &icons::CHECK, f, x, 30, "yes") + gap;
    icons::draw_hint(&mut fb, &icons::CROSS, f, x, 30, "no");

    // Not "refused": at RDP=2 the bootloader calls LOCKUP_FOREVER, so the device hangs
    // until it is power-cycled. Flash is untouched and it boots normally afterwards, but
    // saying "refused" would suggest it simply returns here.
    let warn = "locked unit: hangs, repower";
    draw_text(&mut fb, f, centred(f, warn, 128), 44, warn);
    let _ = panel.flush(&fb);
}

/// Read a firmware off the card, ask, and install it.
///
/// Blocking on purpose. It draws what it is doing at each step because the steps are
/// slow — bringing a card up, then moving a quarter of a megabyte through a 512-byte
/// buffer — and a screen that does not change is how a working device looks broken.
///
/// The approval is the same question the USB path asks, in the same words, and the
/// install is the same two calls: `commit` publishes the recovery header, then the
/// bootloader does the rest on the next boot.
fn install_from_card(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    panel: &mut display::Panel,
    matrix: &mut GpioMatrix,
    drbg: &mut HmacDrbg,
) {
    use crate::sdupgrade::{Outcome, stage_from_card};

    crate::catlog!("sd: looking for a firmware");
    message(panel, "Reading card", "please wait", "");
    let (staged, approval) = match stage_from_card() {
        Outcome::Offered(s, a) => (s, a),
        Outcome::Failed(why) => {
            crate::catlog!("sd: {}", why);
            message(panel, "No upgrade", why, "any key to go back");
            wait_for_any_key(matrix, drbg);
            return;
        }
    };

    crate::session::show_offer(panel, &approval);

    let mut pad = Keypad::new();
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        crate::pinentry::pressed_keys(&mut pad, matrix, drbg, &mut events, &mut keys);
        for k in keys.iter() {
            match k {
                Key::Confirm => {
                    match staged.commit(approval) {
                        Ok(region) => {
                            message(panel, "Installing", "do not disconnect", "");
                            install(gate, login, panel, region);
                        }
                        Err(_) => {
                            message(panel, "Failed", "could not stage", "any key to go back");
                        }
                    }
                    wait_for_any_key(matrix, drbg);
                    return;
                }
                Key::Cancel => return,
                Key::Digit(_) => {}
            }
        }
        catcard_hal::dwt::delay_cycles(usbtask::IDLE_PAUSE_CYCLES);
    }
}

/// Write the current log to the card as `/CATCARD.LOG`.
///
/// The other half of the log story: `Debug -> Logs` shows it on the glass and USB pages
/// it out, and this drops it somewhere it can be read on another machine -- which is the
/// channel that survives a device that will not enumerate and a panel that will not draw.
///
/// Blocking, and it says which step it stopped at rather than "failed": the SD write path
/// has never run on hardware, so a failure here is as likely to be the first exercise of
/// `write_sectors` as a bad card, and the step is the difference. Nothing here is
/// irreversible -- at worst it leaves a short file behind.
fn save_log_to_card(panel: &mut display::Panel, matrix: &mut GpioMatrix, drbg: &mut HmacDrbg) {
    crate::catlog!("sd: saving log");
    message(panel, "Saving log", "please wait", "");

    // Snapshot the log before touching anything else, so what lands on the card is the
    // state at the moment it was asked for, not a log with this function's own steps in
    // it.
    let mut buf = [0u8; crate::logbuf::LOG_LEN];
    let n = crate::logbuf::read(0, &mut buf);

    match write_log_file(&buf[..n]) {
        Ok(()) => {
            crate::catlog!("sd: wrote {} bytes to /CATCARD.LOG", n);
            message(panel, "Log saved", "/CATCARD.LOG", "any key to go back");
        }
        Err(why) => {
            crate::catlog!("sd: log save failed: {}", why);
            message(panel, "Save failed", why, "any key to go back");
        }
    }
    wait_for_any_key(matrix, drbg);
}

/// Bring the card up, mount it, and write `bytes` to `/CATCARD.LOG`.
///
/// Split from the screen so each step is one `?`, and the reason it stopped rides out on
/// the `Err` for the caller to show and log. The step matters here specifically because
/// the SD *write* path has never run on hardware -- a failure is as likely to be the
/// first exercise of `write_sectors` as a bad card, and only the step tells them apart.
fn write_log_file(bytes: &[u8]) -> Result<(), &'static str> {
    use catcard_sd::fat;

    // SAFETY: nothing else has claimed SDMMC1 or its pins, and the menu waits for this
    // to return before it can be chosen again.
    let mut dev = unsafe { catcard_hal::sdmmc::Sdmmc::init(&catcard_board::BOARD) }
        .map_err(|_| "controller failed")?;
    let card = catcard_sd::init(&mut dev).map_err(|e| match e {
        catcard_sd::Error::NoCard => "no card in slot",
        _ => "card would not start",
    })?;
    let mut vol = fat::Volume::<_, 512>::mount_auto(catcard_sd::Sectors::new(dev, card))
        .map_err(|_| "not a FAT card")?;
    let mut file = vol
        .open_or_create_file("/CATCARD.LOG")
        .map_err(|_| "could not open file")?;
    file.write_all(&mut vol, bytes)
        .map_err(|_| "write failed")?;
    // Trim any tail from a longer earlier save, so the file is exactly this log.
    file.set_len(&mut vol, bytes.len() as u32)
        .map_err(|_| "truncate failed")?;
    file.flush(&mut vol).map_err(|_| "flush failed")?;
    vol.flush().map_err(|_| "flush failed")?;
    Ok(())
}

/// Authorise a staged image, which is what actually installs it.
///
/// **Staging and rebooting is not an upgrade on mk4 or later.** That bootrom installs
/// what a logged-in `gate 18/7` pointed it at and nothing else, so a device that stages
/// an image and resets comes back running exactly what it was running, reporting nothing
/// wrong — which is what this firmware did until the mechanism was documented.
///
/// Does not return when it works: the bootloader reboots inside the call. Everything
/// below the call is the failure path.
fn install(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    panel: &mut display::Panel,
    region: catcard_upgrade::Region,
) {
    let g = crate::pinentry::BootloaderGate::new(gate);
    crate::catlog!(
        "install: authorizing {:#010x} len {}",
        region.start,
        region.len
    );
    let why = match login.authorize_firmware(&g, region.start, region.len) {
        Ok(never) => match never {},
        // The bootloader ran its own verification and refused. That is a better answer
        // than ours: it is the check that actually gates the install.
        Err(catcard_pin::Failure::ImageRefused) => "bootloader refused it (gate 18/7 -112)",
        Err(catcard_pin::Failure::NeedsSetup) => "login went stale",
        Err(catcard_pin::Failure::MustWait) => "rate limited",
        Err(catcard_pin::Failure::Gate(_)) => "callgate unreachable",
        Err(catcard_pin::Failure::Code(c)) => {
            crate::catlog!("install: refused, gate code {}", c);
            "refused"
        }
    };
    // The panel may be the broken thing, so this goes in the log too -- which is the
    // only place a dark device can put it.
    crate::catlog!("install: NOT INSTALLED: {}", why);
    message(panel, "Not installed", why, "any key to go back");
}

/// Block until something is pressed. Used only by screens that have already said so.
fn wait_for_any_key(matrix: &mut GpioMatrix, drbg: &mut HmacDrbg) {
    let mut pad = Keypad::new();
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        crate::pinentry::pressed_keys(&mut pad, matrix, drbg, &mut events, &mut keys);
        if !keys.is_empty() {
            return;
        }
        catcard_hal::dwt::delay_cycles(usbtask::IDLE_PAUSE_CYCLES);
    }
}

/// The splash as an "about" page: cat logo, wordmark, and version, held until a key.
fn about_screen(panel: &mut display::Panel) {
    let mut fb = Mono128x64::new();
    catcard_ui::splash::draw(&mut fb, crate::VERSION, 100);
    let _ = panel.flush(&fb);
}

/// Break the log into display lines and hand the window at `scroll` to `out`.
///
/// Returns the total number of lines, which is what bounds the scroll. The log is walked
/// once into a fixed stack buffer -- no allocation, and no per-line copy of the whole
/// buffer -- pushing only the lines the window shows, so the cost does not grow with how
/// far down the log the reader is.
fn collect_log(scroll: usize, out: &mut heapless::Vec<Line, MAX_LINES>) -> usize {
    let mut buf = [0u8; crate::logbuf::LOG_LEN];
    let n = crate::logbuf::read(0, &mut buf);
    let mut total = 0usize;
    let mut line = Line::new();
    let mut push = |line: &mut Line, total: &mut usize| {
        if *total >= scroll && out.len() < MAX_LINES {
            let _ = out.push(line.clone());
        }
        line.clear();
        *total += 1;
    };
    for &b in &buf[..n] {
        if b == b'\n' {
            push(&mut line, &mut total);
        } else {
            // The buffer is our own text, but a stray byte would derail `push_str`, so
            // anything outside printable ASCII shows as a dot rather than a gap.
            let c = if (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '.'
            };
            let _ = line.push(c);
            if line.len() == LOG_COLS {
                push(&mut line, &mut total);
            }
        }
    }
    if !line.is_empty() {
        push(&mut line, &mut total);
    }
    total
}

/// How many display lines the log currently makes -- used to clamp the scroll.
fn log_total() -> usize {
    let mut sink: heapless::Vec<Line, MAX_LINES> = heapless::Vec::new();
    collect_log(usize::MAX, &mut sink)
}

/// The log, on the glass. `5`/`8` scroll; any other key returns to Debug.
///
/// This is the on-device twin of the USB `ReadLog`: the same ring, shown to whoever is
/// holding the device rather than paged to a host. It draws through [`info`] so it reads
/// exactly like the other debug screens.
fn log_screen(panel: &mut display::Panel, scroll: usize) {
    let mut lines: heapless::Vec<Line, MAX_LINES> = heapless::Vec::new();
    let total = collect_log(scroll, &mut lines);
    if lines.is_empty() {
        let mut l = Line::new();
        let _ = l.push_str(if total == 0 { "(log empty)" } else { "(end)" });
        let _ = lines.push(l);
    }
    info(panel, "Logs", &lines);
}

/// microSD: does a card come up, and what does the controller say if not.
///
/// Brings the controller up and runs the card's bring-up conversation on the spot. This
/// screen is where the SD driver is first exercised at all — the emulator models the
/// SDMMC command registers and no data path, so nothing below `catcard_sd` has ever run
/// against anything. `STA` is on screen for that reason: a failure here should say which
/// step failed and what the controller thought, not just "no".
fn sd_screen(panel: &mut display::Panel) {
    use catcard_hal::sdmmc::Sdmmc;
    let mut lines: heapless::Vec<Line, MAX_LINES> = heapless::Vec::new();

    // SAFETY: nothing else has claimed SDMMC1 or its pins; this screen is the only user.
    let dev = unsafe { Sdmmc::init(&catcard_board::BOARD) };
    let mut dev = match dev {
        Ok(d) => d,
        Err(e) => {
            let mut l = Line::new();
            let _ = write!(l, "controller: {}", describe_sd(&e));
            let _ = lines.push(l);
            let mut l = Line::new();
            let _ = write!(l, "clock gate or base wrong");
            let _ = lines.push(l);
            info(panel, "microSD", &lines);
            return;
        }
    };

    let mut l = Line::new();
    let _ = write!(
        l,
        "slot: {}",
        if catcard_sd::Transport::card_present(&dev) {
            "card detected"
        } else {
            "empty"
        }
    );
    let _ = lines.push(l);

    match catcard_sd::init(&mut dev) {
        Ok(card) => {
            let mut l = Line::new();
            let _ = write!(l, "{} MiB  rca {:04x}", card.mib(), card.rca);
            let _ = lines.push(l);

            let mut l = Line::new();
            let _ = write!(
                l,
                "{}  {} bit",
                match card.addressing {
                    catcard_sd::Addressing::BlockAddressed => "SDHC",
                    catcard_sd::Addressing::ByteAddressed => "SDSC",
                },
                if card.wide { 4 } else { 1 }
            );
            let _ = lines.push(l);

            // One block, to prove the data path and not only the command path.
            let mut block = [0u8; catcard_sd::BLOCK_LEN];
            let mut l = Line::new();
            match catcard_sd::read_block(&mut dev, &card, 0, &mut block) {
                // The MBR/boot signature, which every formatted card carries.
                Ok(()) if block[510] == 0x55 && block[511] == 0xAA => {
                    let _ = write!(l, "block 0 ok (55 aa)");
                }
                Ok(()) => {
                    let _ = write!(l, "block 0 read, no 55aa");
                }
                Err(e) => {
                    let _ = write!(l, "read: {}", describe_sd(&e));
                }
            }
            let _ = lines.push(l);
        }
        Err(e) => {
            let mut l = Line::new();
            let _ = write!(l, "init: {}", describe_sd(&e));
            let _ = lines.push(l);
        }
    }

    let _ = lines.push(reg_line("STA    ", dev.status()));
    info(panel, "microSD", &lines);
}

/// An SD error in the few characters a line has.
fn describe_sd(e: &catcard_sd::Error) -> &'static str {
    use catcard_sd::Error as E;
    match e {
        E::NoCard => "no card",
        E::Timeout { .. } => "timeout",
        E::BadResponse { .. } => "bad response",
        E::Unusable => "unusable card",
        E::InitTimeout => "never ready",
        E::BadCsd => "bad CSD",
        E::DataError { .. } => "data error",
        E::Peripheral => "peripheral",
        E::ReadOnly => "read only",
    }
}

/// Draw up to three lines and return.
fn message(panel: &mut display::Panel, head: &str, a: &str, b: &str) {
    let mut fb = Mono128x64::new();
    let t = &peep7x14::FONT;
    let s = &misc4x6::FONT;
    draw_text(&mut fb, t, centred(t, head, 128), 8, head);
    draw_text(&mut fb, s, centred(s, a, 128), 30, a);
    draw_text(&mut fb, s, centred(s, b, 128), 40, b);
    let _ = panel.flush(&fb);
}
