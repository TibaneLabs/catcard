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
//! fixed number of rows and silently dropped the rest, which hid the last item entirely.
//! A menu that cannot outgrow the panel is the property worth having here, not a shorter
//! menu.

use core::fmt::Write as _;

use catcard_callgate::Callgate;
use catcard_callgate::abi::LogoutMode;
use catcard_entropy::HmacDrbg;
use catcard_ui::Mono128x64;
use catcard_ui::font::misc4x6;
use catcard_ui::keypad::{Event, KEYS, Key};

use crate::keypad::Keypad;
use catcard_ui::menu::Scroll;
use catcard_ui::text::draw_text;

use crate::{BootReport, display, keypad::GpioMatrix, usbtask};

/// A line of debug text: a full body line on the widest panel (44 columns of 7x14 across
/// the Q1), which also covers `NAME 0000_0000`.
type Line = heapless::String<48>;

/// Body rows a list or info screen shows on this board's panel and layout.
const MAX_LINES: usize = display::ROWS;
/// Characters of body text that fit on a log line, as [`info`] draws them.
const LOG_COLS: usize = display::LOG_COLS;

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
    Selftest,
    Keypad,
    Colours,
    Logs,
    SaveLog,
    Utils,
    AnalyzeRng,
    UsbDrive,
    NewSeed,
}

const MAIN_ITEMS: &[&str] = &[
    "Status",
    "Install from SD",
    "Debug",
    "Utils",
    "About",
    "New wallet",
    "Reboot",
];
/// The same list with the only useful action first, for a device holding no wallet.
///
/// A device with no seed has exactly one thing worth doing. Making someone scroll past
/// Debug and Utils to find it is backwards.
const MAIN_ITEMS_BLANK: &[&str] = &[
    "New wallet",
    "Status",
    "Install from SD",
    "Debug",
    "Utils",
    "About",
    "Reboot",
];

/// The main menu, ordered for the device in front of you.
fn main_items(no_seed: bool) -> &'static [&'static str] {
    if no_seed {
        MAIN_ITEMS_BLANK
    } else {
        MAIN_ITEMS
    }
}
const UTILS_ITEMS: &[&str] = &["Analyze RNG", "USB Drive"];
const DEBUG_ITEMS: &[&str] = &[
    "USB",
    "Clocks",
    "PSRAM",
    "Boot report",
    "Selftest",
    "Keypad",
    "microSD",
    "Logs",
    "Save log to SD",
    "Colours",
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
        no_seed,
        mut pool,
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
        no_seed,
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
                if screen == Screen::Colours {
                    display::wipe(panel);
                }
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
            if let Some(items) = items_of(screen, v.no_seed) {
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

            let next = step(gate, panel, screen, *key, v.sc.cursor, v.no_seed);
            if next == Screen::SdInstall {
                install_from_card(gate, login, panel, &mut pad, matrix, drbg);
                v.sc = Scroll::new();
                screen = Screen::Main;
                break;
            }
            if next == Screen::SaveLog {
                save_log_to_card(panel, &mut pad, matrix, drbg);
                v.sc = Scroll::new();
                screen = Screen::Debug;
                break;
            }
            if next == Screen::Logs {
                page_through(panel, &mut pad, matrix, drbg, "Logs", &LogLines, false);
                v.sc = Scroll::new();
                screen = Screen::Debug;
                break;
            }
            if next == Screen::AnalyzeRng {
                analyze_rng(gate, panel, &mut pad, matrix, drbg);
                v.sc = Scroll::new();
                screen = Screen::Utils;
                break;
            }
            if next == Screen::UsbDrive {
                usb_drive(panel, &mut pad, matrix, drbg);
                v.sc = Scroll::new();
                screen = Screen::Utils;
                break;
            }
            if next == Screen::NewSeed {
                new_seed(
                    gate,
                    login,
                    panel,
                    &mut pad,
                    matrix,
                    drbg,
                    pool.as_deref_mut(),
                );
                // A wallet that now exists reorders the menu, so re-read the slot state
                // from the login rather than assuming the flow got as far as storing
                // one -- it can be declined or refused at several points.
                v.no_seed = matches!(login.step(), catcard_pin::Step::In { zero_secret: true });
                v.sc = Scroll::new();
                screen = Screen::Main;
                break;
            }
            if next != screen {
                // A new list starts at the top. Carrying a cursor between menus of
                // different lengths is how you land on an item nobody chose.
                v.sc = Scroll::new();
            }
            // The colour chart painted the panel directly, behind the canvas and its row
            // cache, so the next frame has to go out whole or the chart stays under it.
            if screen == Screen::Colours && next != Screen::Colours {
                display::wipe(panel);
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
    no_seed: bool,
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
        // Dispatched by name rather than by cursor index, because this list reorders:
        // a device with no seed puts "New wallet" first. An index table silently points
        // at the wrong entry the moment the order changes, and the entry it used to
        // reach by falling through was Reboot.
        Screen::Main => match (key, main_items(no_seed).get(cursor).copied()) {
            // "Status" is the screen behind the menu, so choosing it just redraws --
            // there is no separate page.
            (Key::Confirm, Some("Status")) => Screen::Main,
            (Key::Confirm, Some("Install from SD")) => Screen::SdInstall,
            (Key::Confirm, Some("Debug")) => Screen::Debug,
            (Key::Confirm, Some("Utils")) => Screen::Utils,
            (Key::Confirm, Some("About")) => Screen::About,
            (Key::Confirm, Some("New wallet")) => Screen::NewSeed,
            (Key::Confirm, Some("Reboot")) => {
                message(panel, "Rebooting", "", "");
                // SAFETY: nothing after this runs.
                unsafe { gate.logout(LogoutMode::LogoutAndReboot) }
            }
            _ => Screen::Main,
        },
        // The splash, dismissed by any key.
        Screen::About => Screen::Main,
        Screen::Utils => match (key, cursor) {
            (Key::Confirm, 0) => Screen::AnalyzeRng,
            (Key::Confirm, 1) => Screen::UsbDrive,
            (Key::Cancel, _) => Screen::Main,
            _ => Screen::Utils,
        },
        Screen::Debug => match (key, cursor) {
            (Key::Confirm, 0) => Screen::Usb,
            (Key::Confirm, 1) => Screen::Clocks,
            (Key::Confirm, 2) => Screen::Psram,
            (Key::Confirm, 3) => Screen::Boot,
            (Key::Confirm, 4) => Screen::Selftest,
            (Key::Confirm, 5) => Screen::Keypad,
            (Key::Confirm, 6) => Screen::Sd,
            (Key::Confirm, 7) => Screen::Logs,
            (Key::Confirm, 8) => Screen::SaveLog,
            (Key::Confirm, _) => Screen::Colours,
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
    /// Whether the secret slot is still empty, as the bootloader reported it at login.
    pub no_seed: bool,
    /// The boot entropy pool, moved out of the report so it can be drawn from.
    ///
    /// `None` on a device whose pool never met its policy — which is a refusal to
    /// generate a seed, not a reason to look for entropy somewhere weaker.
    pub pool: Option<&'a mut catcard_entropy::EntropyPool>,
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
    /// No wallet stored yet, so the main menu leads with creating one.
    no_seed: bool,
}

/// The list on this screen, if it is a menu.
fn items_of(screen: Screen, no_seed: bool) -> Option<&'static [&'static str]> {
    match screen {
        Screen::Main => Some(main_items(no_seed)),
        Screen::Debug => Some(DEBUG_ITEMS),
        Screen::Utils => Some(UTILS_ITEMS),
        _ => None,
    }
}

/// Draw whichever screen we are on.
fn draw(panel: &mut display::Panel, screen: Screen, v: &View<'_>) {
    match screen {
        // The note line is the USB state rather than a fixed string: it was the one
        // number worth seeing without navigating anywhere, and losing it to a submenu
        // would undo the thing this menu exists to fix.
        Screen::Main => menu(
            panel,
            v.head,
            &usb_line(v.note),
            main_items(v.no_seed),
            v.sc,
        ),
        Screen::About => about_screen(panel),
        Screen::Utils => menu(panel, "Utils", "", UTILS_ITEMS, v.sc),
        Screen::Debug => menu(panel, "Debug", "", DEBUG_ITEMS, v.sc),
        Screen::Usb => usb_screen(panel),
        Screen::Clocks => clock_screen(panel),
        Screen::Psram => psram_screen(panel),
        Screen::PsramProbe => psram_probe(panel),
        Screen::Boot => boot_screen(panel, v.report),
        Screen::Selftest => crate::selftest::screen(v.report, panel),
        Screen::Keypad => keypad_screen(panel, v.last_key, v.keys_seen),
        Screen::Colours => colours_screen(panel),
        Screen::Sd => sd_screen(panel),
        // Handled in `run`: it pages itself, and owns the keypad while it does.
        Screen::Logs => {}
        // Handled in `run`; never drawn.
        Screen::SaveLog => {}
        // Handled in `run`: it drives the panel itself in a tight loop.
        Screen::AnalyzeRng => {}
        // Handled in `run`: it takes over USB and needs the keypad to leave.
        Screen::UsbDrive => {}
        // Handled in `run`: it needs the keypad, which the drawing half does not have.
        Screen::SdInstall => {}
        // Handled in `run`: it asks questions and shows words, so it drives the panel
        // and the keypad itself.
        Screen::NewSeed => {}
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
    display::draw(panel, |c| {
        catcard_ui::widgets::menu(c, &display::LAYOUT, title, note, items, sc);
    });
}

/// A titled screen of raw values, left-aligned, leaving on any key.
fn info(panel: &mut display::Panel, title: &str, lines: &[Line]) {
    display::draw(panel, |c| {
        catcard_ui::widgets::info(c, &display::LAYOUT, title, lines);
    });
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

    // Resets seen / self-heal re-inits / OUT-endpoint arms. `rst` climbing with `state
    // down` means the host keeps resetting and we keep dropping it; `re` climbing means
    // the self-heal is firing.
    let (resets, reinits, rearms) = usbtask::recovery_counts();
    let mut l = Line::new();
    let _ = write!(l, "rst {resets} re {reinits} arm {rearms}");
    let _ = lines.push(l);

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

/// Colours: a chart of what the panel can show -- bars, the full ramp of each channel,
/// and a hue sweep. It fills the whole LCD, not the UI's window; any key leaves, and the
/// menu wipes the panel on the way out.
#[cfg(feature = "board-q1")]
fn colours_screen(panel: &mut display::Panel) {
    if panel.draw_colour_chart().is_err() {
        crate::catlog!("colours: chart write failed");
    }
}

/// Colours, on a panel that has two of them.
#[cfg(not(feature = "board-q1"))]
fn colours_screen(panel: &mut display::Panel) {
    let mut lines: heapless::Vec<Line, MAX_LINES> = heapless::Vec::new();
    for text in [
        "mono OLED: black and white",
        "only -- nothing to chart",
        "any key  back",
    ] {
        let mut l = Line::new();
        let _ = l.push_str(text);
        let _ = lines.push(l);
    }
    info(panel, "Colours", &lines);
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
    pad: &mut Keypad,
    matrix: &mut GpioMatrix,
    drbg: &mut HmacDrbg,
) {
    use crate::sdupgrade::{Outcome, stage_from_card};

    crate::catlog!("sd: looking for a firmware");
    message(panel, "Reading card", "please wait", "");
    let (staged, approval) = match stage_from_card(catcard_hal::sdmmc::Slot::A) {
        Outcome::Offered(s, a) => (s, a),
        Outcome::Failed(why) => {
            crate::catlog!("sd: {}", why);
            message(panel, "No upgrade", why, "any key to go back");
            wait_for_any_key(pad, matrix, drbg);
            return;
        }
    };

    crate::session::show_offer(panel, &approval);

    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        crate::pinentry::pressed_keys(pad, matrix, drbg, &mut events, &mut keys);
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
                    wait_for_any_key(pad, matrix, drbg);
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
fn save_log_to_card(
    panel: &mut display::Panel,
    pad: &mut Keypad,
    matrix: &mut GpioMatrix,
    drbg: &mut HmacDrbg,
) {
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
    wait_for_any_key(pad, matrix, drbg);
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

// --- Analyze RNG ------------------------------------------------------------------
//
// A live look at the secure-element TRNGs -- the RNGs this whole project exists to
// distrust. SE1 and SE2 are sampled separately through callgate 26 and each gets its
// own half of the screen: a header with its Shannon entropy (bits per byte -- 8.00 is
// ideal, a number well below it is the failure this screen is for) and running byte
// count, over a framed field that renders that element's own recent bytes as raw bits.
// It should look like static; a source that is stuck or biased stops looking random,
// and keeping the two streams apart is the point -- a fault in one element must not be
// hidden by the other's good bytes.
//
// The bit fields refresh every frame (as fast as the elements deliver); the entropy
// figures are recomputed on a ~5 Hz timer so the digits are readable rather than a blur.

/// Split-view geometry: one framed bit field per secure element, stacked, SE1 over SE2.
/// The field is `RNG_FW` x `RNG_FH` pixels with its inner top-left at (`RNG_FX`, y); a
/// header line sits just above each. SE1's field starts at [`RNG_SE1_Y`], SE2's at
/// [`RNG_SE2_Y`], splitting the 64-pixel height into two halves.
const RNG_FX: usize = 2;
const RNG_FW: usize = 122;
const RNG_FH: usize = 20;
const RNG_SE1_Y: usize = 9;
const RNG_SE2_Y: usize = 41;
/// Bytes backing one field: one bit per pixel, rounded up. Each source has its own.
const RNG_RING: usize = (RNG_FW * RNG_FH).div_ceil(8);

/// `log2` for `f32`, no libm: split `x = m * 2^e` from the IEEE bits, then `log2(m)`
/// via the `atanh` series for `ln`. Good to a few thousandths over `m in [1, 2)`, which
/// is far finer than a 2-decimal entropy readout needs. `x` must be > 0.
fn flog2(x: f32) -> f32 {
    let bits = x.to_bits();
    let e = ((bits >> 23) & 0xff) as i32 - 127;
    // Force the exponent to 0 so the mantissa reads back as m in [1, 2).
    let m = f32::from_bits((bits & 0x007f_ffff) | 0x3f80_0000);
    let t = (m - 1.0) / (m + 1.0);
    let t2 = t * t;
    // ln(m) = 2*(t + t^3/3 + t^5/5 + t^7/7 + ...)
    let ln_m = 2.0 * t * (1.0 + t2 / 3.0 + (t2 * t2) / 5.0 + (t2 * t2 * t2) / 7.0);
    e as f32 + ln_m * core::f32::consts::LOG2_E
}

/// Shannon entropy of a byte histogram, in bits per byte (0..=8).
///
/// `H = log2(n) - (1/n) * sum(c_i * log2(c_i))` over the non-empty bins -- the same as
/// `-sum(p_i log2 p_i)`, rearranged so it divides once instead of per bin.
fn shannon_bits(hist: &[u32; 256], total: u64) -> f32 {
    if total == 0 {
        return 0.0;
    }
    let n = total as f32;
    let mut acc = 0.0f32;
    for &c in hist.iter() {
        if c > 0 {
            let cf = c as f32;
            acc += cf * flog2(cf);
        }
    }
    (flog2(n) - acc / n).clamp(0.0, 8.0)
}

/// Degrees of freedom for a 256-bin byte histogram, and the standard deviation of the
/// chi-squared distribution at that df (`sqrt(2*df)`), for reading a statistic as a
/// rough number of sigmas.
const CHI2_DF: f32 = 255.0;
const CHI2_SD: f32 = 22.5832; // sqrt(510)

/// Pearson chi-squared goodness-of-fit statistic for a byte histogram against a uniform
/// distribution, over 255 degrees of freedom.
///
/// `X^2 = sum((c_i - e)^2 / e)` with `e = n/256`, rearranged to `256 * sum(c_i^2)/n - n`
/// so it needs one pass and one divide. Its expected value for a uniform source is the
/// degrees of freedom (255) and does not depend on `n`, so it stays comparable as the
/// histogram is rescaled. A value far above 255 means the bytes are not uniform -- the
/// failure this screen exists to catch; one far below is its own kind of wrong (too even
/// to be random). `flog2`/`shannon_bits` measure disorder; this measures the shape.
fn chi2_uniform(hist: &[u32; 256], total: u64) -> f32 {
    if total == 0 {
        return 0.0;
    }
    let mut sum_sq = 0u64;
    for &c in hist.iter() {
        sum_sq += (c as u64) * (c as u64);
    }
    let n = total as f32;
    256.0 * (sum_sq as f32) / n - n
}

/// A short verdict for a chi-squared value: how many standard deviations it sits from the
/// mean a uniform source would give. Deliberately generous -- a healthy source wanders a
/// little frame to frame, a broken one misses by hundreds of sigma, so a wide "ok" band
/// avoids crying wolf without hiding a real failure.
fn chi2_verdict(chi2: f32) -> &'static str {
    let z = ((chi2 - CHI2_DF) / CHI2_SD).abs();
    if z < 4.0 {
        "ok"
    } else if z < 8.0 {
        "chk"
    } else {
        "BAD"
    }
}

/// A large count in a couple of characters, for the narrow left column.
fn compact(n: u64) -> Line {
    let mut s = Line::new();
    let _ = if n < 1000 {
        write!(s, "{n}")
    } else if n < 1_000_000 {
        write!(s, "{}k", n / 1000)
    } else {
        write!(s, "{}M", n / 1_000_000)
    };
    s
}

/// Draw one secure element's own view: a header (label, entropy, running count) above a
/// framed field of that element's recent bytes as raw bits. `field_y` is the field's
/// inner top; the header sits two rows above it. `exit_hint` adds the "x=exit" note to
/// the right of this header (shown once, on the top view).
#[allow(clippy::too_many_arguments)]
fn draw_se_view(
    fb: &mut Mono128x64,
    field_y: usize,
    label: &str,
    h_text: &str,
    chi2: f32,
    count: u64,
    ring: &[u8; RNG_RING],
    exit_hint: bool,
) {
    let f = &misc4x6::FONT;
    let hy = field_y - 8;
    draw_text(fb, f, 1, hy, label);
    // Shannon entropy (bits/byte), chi-squared value with its verdict, and byte count.
    let mut stat = Line::new();
    let _ = write!(
        stat,
        "H{h_text} X{} {} n{}",
        compact(chi2 as u64),
        chi2_verdict(chi2),
        compact(count)
    );
    draw_text(fb, f, 16, hy, &stat);
    if exit_hint {
        draw_text(fb, f, 104, hy, "x=exit");
    }
    // A thin frame, then this source's bytes one bit per pixel. Laid out column by
    // column with the newest bits entering at the right, so the write head sweeps
    // right-to-left down the field rather than top-to-bottom across it.
    fb.rect(
        RNG_FX - 1,
        field_y - 1,
        RNG_FX + RNG_FW + 1,
        field_y + RNG_FH + 1,
        true,
    );
    for col in 0..RNG_FW {
        for row in 0..RNG_FH {
            let bit = (RNG_FW - 1 - col) * RNG_FH + row;
            let on = (ring[bit / 8] >> (bit % 8)) & 1 == 1;
            fb.set(RNG_FX + col, field_y + row, on);
        }
    }
}

/// Live RNG analyzer. Blocks, driving the panel itself; `x` (or the left arrow) exits.
fn analyze_rng(
    gate: &Callgate,
    panel: &mut display::Panel,
    pad: &mut Keypad,
    matrix: &mut GpioMatrix,
    drbg: &mut HmacDrbg,
) {
    use catcard_callgate::abi::RngSource;

    if !catcard_board::BOARD.has_callgate_se_rng {
        crate::catlog!("rng: no SE RNG on this board");
        message(panel, "Analyze RNG", "no SE RNG here", "any key to go back");
        wait_for_any_key(pad, matrix, drbg);
        return;
    }

    let sources = [RngSource::Se1, RngSource::Se2];
    // Everything below is kept per source, so a fault in one element is never masked by
    // the other: its own histogram (for entropy), its own bounded total, its own
    // lifetime count (for the readout), and its own ring of recent bytes (for the bits).
    let mut hist = [[0u32; 256]; 2];
    let mut total = [0u64; 2];
    let mut seen = [0u64; 2];
    let mut ring = [[0u8; RNG_RING]; 2];
    let mut ring_at = [0usize; 2];

    // Recompute the entropy figures at ~5 Hz so the digits are readable.
    // SAFETY: reads the RCC config only.
    let hz = unsafe { catcard_hal::clock::hclk_hz() };
    let period = (hz / 5).max(1);
    let mut last_h = catcard_hal::dwt::cycles();
    let mut h_text: [Line; 2] = [Line::new(), Line::new()];
    for h in h_text.iter_mut() {
        let _ = h.push_str("--");
    }
    let mut chi2 = [0.0f32; 2];

    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();

    loop {
        // One call per source per frame: at most 32 bytes each, and each field is sized
        // so a few frames turn it over completely. USB is polled here, not interrupt-
        // driven, and the frame is dominated by waiting on the elements, so it is pumped
        // before every blocking read (the read runs in the bootloader and cannot itself
        // be interrupted) and once more after the flush below. Pumping only once a frame
        // would leave the bus deaf through the slow parts -- which is most of the frame.
        for (i, src) in sources.iter().enumerate() {
            let _ = usbtask::pump();
            let mut buf = [0u8; 33];
            // SAFETY: exactly the documented 33-byte output buffer for callgate 26.
            if let Ok(n) = unsafe { gate.se_rng(*src, &mut buf) } {
                for &b in &buf[1..1 + n] {
                    seen[i] += 1;
                    hist[i][b as usize] += 1;
                    total[i] += 1;
                    ring[i][ring_at[i]] = b;
                    ring_at[i] = (ring_at[i] + 1) % RNG_RING;
                }
            }
        }

        // Keep each source's counts (and so its f32 sums) bounded, and let the measure
        // stay adaptive: halving every bin preserves the ratios that entropy depends on.
        for i in 0..2 {
            if total[i] >= (1 << 20) {
                total[i] = 0;
                for c in hist[i].iter_mut() {
                    *c >>= 1;
                    total[i] += *c as u64;
                }
            }
        }

        let now = catcard_hal::dwt::cycles();
        if now.wrapping_sub(last_h) >= period {
            last_h = now;
            for i in 0..2 {
                h_text[i].clear();
                let _ = write!(h_text[i], "{:.2}", shannon_bits(&hist[i], total[i]));
                chi2[i] = chi2_uniform(&hist[i], total[i]);
            }
        }

        let mut fb = Mono128x64::new();
        draw_se_view(
            &mut fb, RNG_SE1_Y, "SE1", &h_text[0], chi2[0], seen[0], &ring[0], true,
        );
        draw_se_view(
            &mut fb, RNG_SE2_Y, "SE2", &h_text[1], chi2[1], seen[1], &ring[1], false,
        );
        display::show_mono(panel, &fb);
        let _ = usbtask::pump();

        crate::pinentry::pressed_keys(pad, matrix, drbg, &mut events, &mut keys);
        if keys
            .iter()
            .any(|k| matches!(k, Key::Cancel | Key::Digit(7)))
        {
            return;
        }
    }
}

/// Block until no key is held.
///
/// Every screen that waits for a press calls this first, and it is not a nicety. A key
/// still down from the *previous* screen is reported the moment the next screen starts
/// waiting, so one long press walks through several screens in a row -- which is how a
/// page of seed words went past before it could be read, and why the fix belongs here
/// rather than in the screens.
///
/// `held_count` is the debounced state of the pad, so this asks what is physically down
/// instead of inferring it from events. Scanning still has to run while its events are
/// thrown away: the scan is what updates that state.
fn wait_for_release(pad: &mut Keypad, matrix: &mut GpioMatrix, drbg: &mut HmacDrbg) {
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        let _ = usbtask::pump();
        crate::pinentry::pressed_keys(pad, matrix, drbg, &mut events, &mut keys);
        if pad.held_count() == 0 {
            return;
        }
        catcard_hal::dwt::delay_cycles(usbtask::IDLE_PAUSE_CYCLES);
    }
}

/// Block until something is pressed. Used only by screens that have already said so.
fn wait_for_any_key(pad: &mut Keypad, matrix: &mut GpioMatrix, drbg: &mut HmacDrbg) {
    wait_for_release(pad, matrix, drbg);
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        // Service USB while this message is up, for the same reason as the main loop:
        // a polled bus that no one pumps is a device the host cannot reach.
        let _ = usbtask::pump();
        crate::pinentry::pressed_keys(pad, matrix, drbg, &mut events, &mut keys);
        if !keys.is_empty() {
            return;
        }
        catcard_hal::dwt::delay_cycles(usbtask::IDLE_PAUSE_CYCLES);
    }
}

/// Wait for a yes or a no.
///
/// Any other key keeps waiting. This is asked before something irreversible, and "a key
/// was pressed" is not consent — [`wait_for_any_key`] is the one that takes anything.
fn confirmed(pad: &mut Keypad, matrix: &mut GpioMatrix, drbg: &mut HmacDrbg) -> bool {
    // The key that brought us to this question must not also answer it. That matters
    // most here: one of the questions this asks destroys a stored wallet.
    wait_for_release(pad, matrix, drbg);
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        let _ = usbtask::pump();
        crate::pinentry::pressed_keys(pad, matrix, drbg, &mut events, &mut keys);
        for k in keys.iter() {
            match k {
                Key::Confirm => return true,
                Key::Cancel => return false,
                Key::Digit(_) => {}
            }
        }
        catcard_hal::dwt::delay_cycles(usbtask::IDLE_PAUSE_CYCLES);
    }
}

/// A yes/no question, with the keys named the way this board labels them.
fn ask(panel: &mut display::Panel, head: &str, a: &str, b: &str) {
    use catcard_ui::canvas::Canvas;
    use catcard_ui::icons;
    display::draw(panel, |c| {
        catcard_ui::widgets::message(c, &display::LAYOUT, head, a, b);
        let f = display::LAYOUT.body;
        let gap = 3 * f.advance(b' ');
        let total = icons::key_hint_width(f, display::CONFIRM, "yes")
            + gap
            + icons::key_hint_width(f, display::CANCEL, "no");
        let mut x = c.width().saturating_sub(total) / 2;
        let y = c.height().saturating_sub(f.line_height() + 2);
        x = icons::draw_key_hint(c, f, x, y, display::CONFIRM, "yes") + gap;
        icons::draw_key_hint(c, f, x, y, display::CANCEL, "no");
    });
}

/// What the entropy screens report.
///
/// A struct because seven numbers passed positionally is one transposed pair away from
/// telling someone their wallet has more entropy behind it than it does.
struct Gathered {
    /// Credited bits the pool already held from boot: the chip TRNG, both elements and
    /// startup timing, collected before this screen existed.
    boot_bits: u32,
    /// Bytes each secure element has answered with during *this* generation.
    se1: usize,
    se2: usize,
    /// Credited bits and distinct hardware TRNGs the pool counts right now.
    bits: u32,
    chips: u32,
    /// What this board's policy demands before a seed may be drawn at all.
    need_bits: u32,
    need_chips: u32,
}

impl Gathered {
    fn lines(&self, out: &mut heapless::Vec<Line, 5>) {
        let mut l = Line::new();
        let _ = write!(l, "boot pool {:5} bits", self.boot_bits);
        let _ = out.push(l);
        for (name, n) in [("SE1", self.se1), ("SE2", self.se2)] {
            let mut l = Line::new();
            let _ = write!(l, "{name}  read {n:5} bytes");
            let _ = out.push(l);
        }
        let mut l = Line::new();
        let _ = write!(l, "chips  {} of {} needed", self.chips, self.need_chips);
        let _ = out.push(l);
        let mut l = Line::new();
        let _ = write!(l, "total {:5} / {} bits", self.bits, self.need_bits);
        let _ = out.push(l);
    }
}

/// The count, climbing, with a bar along the bottom row.
///
/// Reading a kilobyte out of two secure elements takes long enough to look like a hang,
/// and a wallet being created is the worst moment for a device to look stuck. Counting
/// each element separately also shows *which* one is answering: a column that stops
/// moving is a dead element, which a single bar would hide.
///
/// The bits shown are what the pool *credits*, not what was read — hardware noise is
/// credited at half its nominal rate, so the two differ by design and showing the
/// larger number would overstate what the device actually has.
fn gathering(panel: &mut display::Panel, g: &Gathered, pct: u8) {
    let mut lines: heapless::Vec<Line, 5> = heapless::Vec::new();
    g.lines(&mut lines);
    display::draw(panel, |c| {
        catcard_ui::widgets::info(c, &display::LAYOUT, "Collecting entropy", &lines);
        catcard_ui::splash::draw_progress(c, pct);
    });
}

/// What was collected, and whether the policy is actually satisfied.
///
/// Shown before the seed is drawn and acknowledged with a key, so the numbers behind a
/// wallet are seen once by the person who will own it. `passed` is the pool's own
/// verdict from `check()`, not an assumption that the loop above did its job.
fn entropy_report(panel: &mut display::Panel, g: &Gathered, passed: bool) {
    let mut lines: heapless::Vec<Line, 5> = heapless::Vec::new();
    g.lines(&mut lines);
    info(
        panel,
        if passed {
            "Entropy OK, any key"
        } else {
            "NOT ENOUGH ENTROPY"
        },
        &lines,
    );
}

/// Create a wallet: draw entropy, store it, verify it, and show the words once.
///
/// The order is the point. The secret is written **and read back before any word reaches
/// the screen**, because words shown for a seed the secure element did not keep are
/// worse than no words at all — someone copies them down and believes they have a
/// backup of a wallet that does not exist.
///
/// User-supplied entropy (dice, coins, key-mash) is deliberately *not* required. The
/// pool has already met its policy or it refuses outright, and a handful of dice rolls
/// cannot rescue a device whose TRNGs are unhealthy. See `docs/SECRETS-AND-SETTINGS.md`.
fn new_seed(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    panel: &mut display::Panel,
    pad: &mut Keypad,
    matrix: &mut GpioMatrix,
    drbg: &mut HmacDrbg,
    pool: Option<&mut catcard_entropy::EntropyPool>,
) {
    use catcard_wallet::bip39::Mnemonic;
    use zeroize::Zeroize;

    // No pool means it never met its policy at boot. That is a refusal.
    let Some(pool) = pool else {
        message(panel, "No entropy", "the pool missed its", "policy at boot");
        wait_for_any_key(pad, matrix, drbg);
        return;
    };

    // Overwriting a wallet that already exists is the destructive case, and this is the
    // only warning anyone gets. `zero_secret` is the bootloader's own answer about the
    // slot, not a guess of ours.
    if matches!(login.step(), catcard_pin::Step::In { zero_secret: false }) {
        ask(
            panel,
            "Wallet exists",
            "a new seed DESTROYS",
            "the one stored now",
        );
        if !confirmed(pad, matrix, drbg) {
            return;
        }
    }
    ask(
        panel,
        "Create wallet?",
        "24 words, from this",
        "device's own TRNGs",
    );
    if !confirmed(pad, matrix, drbg) {
        return;
    }

    // Fresh noise from both secure elements, on top of what the boot pool already
    // holds. The boot pool has met its policy or we would not be here; this is added
    // material, not a substitute for it.
    //
    // It goes through `EntropyPool` rather than into a hash of its own, because the
    // pool is what runs the health tests, keeps the sources domain-separated and
    // credits them. A side digest would mix the same bytes twice while skipping all
    // three. If an element answers with something that fails its health test the pool
    // is poisoned and `draw_seed` below refuses -- which is the intended outcome, not a
    // reason to fall back to the boot material alone.
    // How long to hold each step on screen. Legibility only: thirty-two counts that
    // flash past in a blink show nothing, and nobody can check a number they cannot
    // read. It contributes no entropy and must never be mistaken for doing so.
    const STEP_PAUSE_CYCLES: u32 = 4_000_000;

    let policy = crate::entropy_policy();
    let boot_bits = pool.credited_bits();
    let mut g = Gathered {
        boot_bits,
        se1: 0,
        se2: 0,
        bits: boot_bits,
        chips: pool.hardware_sources(),
        need_bits: policy.min_bits,
        need_chips: policy.min_hw_sources,
    };

    if catcard_board::BOARD.has_callgate_se_rng {
        // 16 rounds of 32 bytes from each element: a kilobyte of fresh noise, and
        // thirty-two visible steps rather than a bar that jumps.
        const ROUNDS: usize = 16;
        const READS: usize = ROUNDS * 2;
        let mut done = 0usize;
        gathering(panel, &g, 0);

        for _ in 0..ROUNDS {
            for (src, tag) in [
                (
                    catcard_callgate::abi::RngSource::Se1,
                    catcard_entropy::Source::Se1Trng,
                ),
                (
                    catcard_callgate::abi::RngSource::Se2,
                    catcard_entropy::Source::Se2Trng,
                ),
            ] {
                let mut buf = [0u8; 33];
                // SAFETY: exactly the documented 33-byte output buffer for callgate 26.
                // `buf` is on our stack, which the linker places in SRAM1, and `call`
                // range-checks it regardless.
                if let Ok(n) = unsafe { gate.se_rng(src, &mut buf) }
                    && n > 0
                {
                    pool.add(tag, &buf[1..1 + n]);
                    // Counted only when bytes actually arrived, so a column that stops
                    // moving is an element that stopped answering.
                    if matches!(tag, catcard_entropy::Source::Se1Trng) {
                        g.se1 += n;
                    } else {
                        g.se2 += n;
                    }
                }
                buf.zeroize();
                done += 1;
                g.bits = pool.credited_bits();
                g.chips = pool.hardware_sources();
                gathering(panel, &g, (done * 100 / READS) as u8);
                catcard_hal::dwt::delay_cycles(STEP_PAUSE_CYCLES);
            }
        }
    }

    // The pool's own verdict, not ours. If a source failed its health test the pool is
    // poisoned and this is where that becomes visible, before any word is shown.
    let passed = pool.check().is_ok();
    crate::catlog!(
        "seed: SE1 {} B, SE2 {} B, {} bits from {} chips, policy {}",
        g.se1,
        g.se2,
        g.bits,
        g.chips,
        if passed { "ok" } else { "FAILED" }
    );
    entropy_report(panel, &g, passed);
    wait_for_any_key(pad, matrix, drbg);

    let mut entropy = match pool.draw_seed() {
        Ok(e) => e,
        // The pool refusing is the entropy design working as intended, so report which
        // way it refused rather than a generic failure.
        Err(e) => {
            crate::catlog!("seed: pool refused");
            let mut l = Line::new();
            let _ = write!(l, "{e}");
            info(panel, "Refused", &[l]);
            wait_for_any_key(pad, matrix, drbg);
            return;
        }
    };

    let encoded = catcard_callgate::pin::encode_bip39(&entropy);
    let mnemonic = Mnemonic::from_entropy(&entropy);
    entropy.zeroize();

    let (Ok(mut secret), Ok(mnemonic)) = (encoded, mnemonic) else {
        // 32 bytes is a length both of them accept, so this is unreachable today. It is
        // written out rather than unwrapped because this is the one function that holds
        // a wallet, and a panic here would take the seed to the panic screen with it.
        message(panel, "Failed", "could not encode", "that seed length");
        wait_for_any_key(pad, matrix, drbg);
        return;
    };

    // Words first, the quiz second, the secure element last.
    //
    // That order is the safe one, and it is worth being explicit about why, because the
    // obvious ordering is the wrong way round. Commit first and a power loss between
    // the write and the words leaves a wallet in the element that nobody has a backup
    // of. Commit last and the same power loss leaves nothing at all: the user starts
    // again and draws fresh words, having lost only their time.
    //
    // A failed quiz is therefore free. No wallet exists yet, so it costs nothing to
    // send them back to the list rather than discarding twenty-four hand-written words
    // over one mistaken key.
    loop {
        show_words(panel, pad, matrix, drbg, &mnemonic);
        if quiz(panel, pad, matrix, drbg, &mnemonic) {
            break;
        }
        ask(panel, "Not confirmed", "read them again", "and retry?");
        if !confirmed(pad, matrix, drbg) {
            secret.zeroize();
            crate::catlog!("seed: words not confirmed, nothing stored");
            message(panel, "Nothing stored", "no wallet was", "created");
            wait_for_any_key(pad, matrix, drbg);
            return;
        }
    }

    message(panel, "Applying", "do not disconnect", "");
    // `Login` is driven through the `PinGate` seam, so that the same sequencing runs
    // against a model on the host and the callgate here.
    let pin_gate = crate::pinentry::BootloaderGate::new(gate);
    let outcome = login.set_secret(&pin_gate, &secret);
    if let Err(f) = outcome {
        secret.zeroize();
        crate::catlog!("seed: store failed");
        message(panel, "Not stored", why_failed(f), "any key to go back");
        wait_for_any_key(pad, matrix, drbg);
        return;
    }

    // Read it back. The words are already written down by this point, so a slot that
    // did not keep them has to be reported rather than assumed good.
    let kept = login.verify_secret(&pin_gate, &secret).unwrap_or(false);
    secret.zeroize();
    if !kept {
        crate::catlog!("seed: read-back mismatch");
        message(
            panel,
            "Not stored",
            "the slot did not keep",
            "what was written",
        );
        wait_for_any_key(pad, matrix, drbg);
        return;
    }

    crate::catlog!("seed: stored, {} words", mnemonic.word_count());
    message(
        panel,
        "Wallet created",
        "keep those words",
        "somewhere safe",
    );
    wait_for_any_key(pad, matrix, drbg);
}

/// Ask for some of the words back, before anything is committed.
///
/// The only evidence the device ever gets that the words were written down rather than
/// paged past. It runs before the secret reaches the element, so failing it costs
/// nothing: no wallet exists yet and the caller offers the list again.
///
/// Decoys come from the same wordlist as the answer, so nothing about the shape or
/// rarity of an option narrows it down, and the three are shuffled by the DRBG rather
/// than placed — the correct one must not sit in a predictable slot.
///
/// Returns false on a wrong answer or a cancel; the caller stores nothing either way.
fn quiz(
    panel: &mut display::Panel,
    pad: &mut Keypad,
    matrix: &mut GpioMatrix,
    drbg: &mut HmacDrbg,
    m: &catcard_wallet::bip39::Mnemonic,
) -> bool {
    use catcard_wallet::bip39::wordlist::{ENGLISH, WORD_COUNT};
    const ASKS: usize = 3;
    const CHOICES: usize = 3;

    let total = m.word_count();
    for _ in 0..ASKS {
        // A DRBG failure means it wants reseeding. Refusing is the only safe answer: a
        // quiz whose questions are predictable proves nothing.
        let Ok(pos) = drbg.below(total as u32) else {
            return false;
        };
        let pos = pos as usize;
        let Some(correct) = m.words().nth(pos) else {
            return false;
        };

        let mut choices = [correct; CHOICES];
        for i in 1..CHOICES {
            loop {
                let Ok(pick) = drbg.below(WORD_COUNT as u32) else {
                    return false;
                };
                let w = ENGLISH[pick as usize];
                // Distinct from the answer and from the other decoys, or the question
                // has two right answers or fewer than three options.
                if w != correct && !choices[..i].contains(&w) {
                    choices[i] = w;
                    break;
                }
            }
        }
        let _ = drbg.shuffle(&mut choices);

        let mut lines: heapless::Vec<Line, CHOICES> = heapless::Vec::new();
        for (i, w) in choices.iter().enumerate() {
            let mut l = Line::new();
            let _ = write!(l, "{}  {w}", i + 1);
            let _ = lines.push(l);
        }
        let mut title = Line::new();
        let _ = write!(title, "Which is word {}?", pos + 1);
        info(panel, &title, &lines);

        match read_choice(pad, matrix, drbg, CHOICES) {
            Some(i) if choices[i] == correct => {}
            _ => return false,
        }
    }
    true
}

/// Wait for one of `n` numbered choices, or a cancel.
fn read_choice(
    pad: &mut Keypad,
    matrix: &mut GpioMatrix,
    drbg: &mut HmacDrbg,
    n: usize,
) -> Option<usize> {
    wait_for_release(pad, matrix, drbg);
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        let _ = usbtask::pump();
        crate::pinentry::pressed_keys(pad, matrix, drbg, &mut events, &mut keys);
        for k in keys.iter() {
            match k {
                Key::Cancel => return None,
                Key::Digit(d) if *d >= 1 && (*d as usize) <= n => {
                    return Some(*d as usize - 1);
                }
                _ => {}
            }
        }
        catcard_hal::dwt::delay_cycles(usbtask::IDLE_PAUSE_CYCLES);
    }
}

/// Why a gate operation refused, in words that fit a line.
fn why_failed(f: catcard_pin::Failure) -> &'static str {
    match f {
        catcard_pin::Failure::NeedsSetup => "login went stale",
        catcard_pin::Failure::MustWait => "the gate wants a wait",
        catcard_pin::Failure::ImageRefused => "the gate refused it",
        catcard_pin::Failure::Gate(_) => "the callgate failed",
        catcard_pin::Failure::Code(_) => "the bootloader refused",
    }
}

/// Show the words. The only time they are ever displayed.
///
/// Paged rather than flashed past: ENTER moves forward and only means "done" once the
/// last word has been on screen. The previous version advanced on *any* key, which is
/// how a held key walked through a page of someone's backup before they could read it.
fn show_words(
    panel: &mut display::Panel,
    pad: &mut Keypad,
    matrix: &mut GpioMatrix,
    drbg: &mut HmacDrbg,
    m: &catcard_wallet::bip39::Mnemonic,
) {
    page_through(
        panel,
        pad,
        matrix,
        drbg,
        "Write these down",
        &WordLines(m),
        true,
    );
}

/// The splash as an "about" page: cat logo, wordmark, and version, held until a key.
fn about_screen(panel: &mut display::Panel) {
    #[cfg(feature = "board-q1")]
    {
        use catcard_ui::art::tibane::LOGO;
        display::draw_with_palette(panel, &LOGO.palette, |c| {
            catcard_ui::splash::draw_colour(c, &LOGO, crate::VERSION, 100, &display::LAYOUT)
        });
    }
    #[cfg(not(feature = "board-q1"))]
    display::draw(panel, |c| catcard_ui::splash::draw(c, crate::VERSION, 100));
}

/// The log, as lines for the pager.
///
/// The on-device twin of the USB `ReadLog`: the same ring, shown to whoever is holding
/// the device rather than paged to a host.
///
/// Long entries are **wrapped** at the panel's column count rather than clipped, which
/// does make the line count depend on the board -- a Q1 fits 44 columns, a mono panel
/// 31. That is fine for a log, where the reader wants the whole line and there is no
/// scroll position to carry between panels; the sink clips instead, for the reasons in
/// `catcard_ui::pager`.
///
/// The buffer is walked once per window and only the visible lines are rendered, so the
/// cost does not grow with how far down the reader has scrolled. Counting continues
/// after the sink is full, because the pager needs the total to know there is more.
struct LogLines;

impl catcard_ui::pager::LineSource for LogLines {
    fn fill(&self, from: usize, sink: &mut catcard_ui::pager::LineSink) -> usize {
        let mut buf = [0u8; crate::logbuf::LOG_LEN];
        let n = crate::logbuf::read(0, &mut buf);
        let mut total = 0usize;
        let mut line = Line::new();
        let mut push = |line: &mut Line, total: &mut usize| {
            if *total >= from {
                let _ = sink.push(line.as_str());
            }
            line.clear();
            *total += 1;
        };
        for &b in &buf[..n] {
            if b == b'\n' {
                push(&mut line, &mut total);
            } else {
                // Our own text, but a stray byte would derail `push`, so anything
                // outside printable ASCII shows as a dot rather than a gap.
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
}

/// The seed words, numbered, as lines for the pager.
struct WordLines<'a>(&'a catcard_wallet::bip39::Mnemonic);

impl catcard_ui::pager::LineSource for WordLines<'_> {
    fn fill(&self, from: usize, sink: &mut catcard_ui::pager::LineSink) -> usize {
        for (i, w) in self.0.words().enumerate().skip(from) {
            let mut l = Line::new();
            let _ = write!(l, "{:2}  {w}", i + 1);
            if !sink.push(l.as_str()) {
                break;
            }
        }
        self.0.word_count()
    }
}

/// Show something longer than the screen, and let it be read.
///
/// `5` and `8` are the arrow keys; CANCEL leaves and returns false.
///
/// `require_end` is for the seed backup. Until the last line has been on screen, ENTER
/// pages forward instead of finishing — so the familiar "press to continue" still works
/// and still cannot skip a word. Once the end is showing, ENTER means done.
fn page_through<S: catcard_ui::pager::LineSource + ?Sized>(
    panel: &mut display::Panel,
    pad: &mut Keypad,
    matrix: &mut GpioMatrix,
    drbg: &mut HmacDrbg,
    title: &str,
    src: &S,
    require_end: bool,
) -> bool {
    use catcard_ui::pager::{LineSink, Pager, paged};

    let rows = MAX_LINES;
    let mut p = Pager::new();
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();

    loop {
        let mut sink = LineSink::new(rows);
        let total = src.fill(p.top, &mut sink);
        // The log grows while it is being read, so the window can end up past the end.
        // Re-fill rather than draw a window that does not match where we think we are.
        let clamped = p.clamped(total, rows);
        if clamped != p {
            p = clamped;
            continue;
        }
        display::draw(panel, |c| {
            paged(c, &display::LAYOUT, title, &sink, p, total)
        });

        wait_for_release(pad, matrix, drbg);
        loop {
            let _ = usbtask::pump();
            crate::pinentry::pressed_keys(pad, matrix, drbg, &mut events, &mut keys);
            let mut moved = false;
            for k in keys.iter() {
                match k {
                    Key::Cancel | Key::Digit(7) => return false,
                    Key::Confirm | Key::Digit(9) => {
                        if !require_end || p.at_end(total, rows) {
                            return true;
                        }
                        p = p.page(total, rows, true);
                        moved = true;
                    }
                    Key::Digit(5) => {
                        p = p.step(total, rows, false);
                        moved = true;
                    }
                    Key::Digit(8) => {
                        p = p.step(total, rows, true);
                        moved = true;
                    }
                    Key::Digit(_) => {}
                }
            }
            if moved {
                break;
            }
            catcard_hal::dwt::delay_cycles(usbtask::IDLE_PAUSE_CYCLES);
        }
    }
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
/// Block until any key is pressed. For the error notices below, which would otherwise be
/// overwritten by the menu redraw the instant this returns.
fn wait_any_key(pad: &mut Keypad, matrix: &mut GpioMatrix, drbg: &mut HmacDrbg) {
    wait_for_release(pad, matrix, drbg);
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        crate::pinentry::pressed_keys(pad, matrix, drbg, &mut events, &mut keys);
        if !keys.is_empty() {
            return;
        }
        catcard_hal::dwt::delay_cycles(66_000);
    }
}

/// Expose the SD card to the host as a USB mass-storage drive, until `x` is pressed.
///
/// While this screen is up the device re-enumerates as a disk -- its HID wallet protocol
/// is gone until it leaves -- and serves Bulk-Only Transport against the card. On `x` it
/// switches its identity back and returns. Reached only from `Utils`, which is behind the
/// PIN, so the card is never exposed on a locked device.
fn usb_drive(
    panel: &mut display::Panel,
    pad: &mut Keypad,
    matrix: &mut GpioMatrix,
    drbg: &mut HmacDrbg,
) {
    use catcard_hal::sdmmc::Sdmmc;

    // SAFETY: nothing else has claimed SDMMC1 or its pins; this screen is its only user
    // and the menu waits for it to return before it can be chosen again.
    let mut dev = match unsafe { Sdmmc::init(&catcard_board::BOARD) } {
        Ok(d) => d,
        Err(_) => {
            message(panel, "USB Drive", "no SD controller", "press a key");
            wait_any_key(pad, matrix, drbg);
            return;
        }
    };
    let card = match catcard_sd::init(&mut dev) {
        Ok(c) => c,
        Err(catcard_sd::Error::NoCard) => {
            message(panel, "USB Drive", "no card in slot", "press a key");
            wait_any_key(pad, matrix, drbg);
            return;
        }
        Err(_) => {
            message(panel, "USB Drive", "card would not start", "press a key");
            wait_any_key(pad, matrix, drbg);
            return;
        }
    };

    message(panel, "USB Drive", "SD is on USB", "press x to eject");

    // Re-enumerate as a disk, serve it, and switch the identity back on the way out.
    crate::usbtask::msc_enter();

    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    let mut spins: u32 = 0;
    crate::msc_drive::run(&mut dev, &card, || {
        // Scanning the pad every spin would swamp the transport; once every 16384 spins
        // is a few milliseconds and plenty responsive to a key.
        spins = spins.wrapping_add(1);
        if !spins.is_multiple_of(16384) {
            return false;
        }
        crate::pinentry::pressed_keys(pad, matrix, drbg, &mut events, &mut keys);
        keys.contains(&Key::Cancel)
    });

    crate::usbtask::msc_exit();
}

fn message(panel: &mut display::Panel, head: &str, a: &str, b: &str) {
    display::draw(panel, |c| {
        catcard_ui::widgets::message(c, &display::LAYOUT, head, a, b);
    });
}
