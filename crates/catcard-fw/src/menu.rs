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
use crate::ui::Ui;
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
    /// About's second page: the STM32 itself.
    AboutChip,
    SdInstall,
    Debug,
    Usb,
    Clocks,
    Psram,
    PsramProbe,
    /// SPI-NOR flash probe (mk3): show the JEDEC id and size.
    Sflash,
    Sd,
    Boot,
    Selftest,
    Keypad,
    /// The UI DRBG's diagnostic counters: how many times it has been (re)seeded, and how
    /// much it has generated.
    PrngStatus,
    /// The RTC registers, resampled about thirty times a second.
    Rtc,
    /// Start the preemptive kernel with test tasks. Takes the CPU and never gives it
    /// back; a power cycle is how you leave.
    KernelTest,
    /// The scheduler's live state, once the menu itself runs as a kernel task.
    Kernel,
    /// Restart this menu as a kernel task, beside a heartbeat.
    KernelUi,
    ScrollTest,
    Colours,
    Logs,
    SaveLog,
    Utils,
    AnalyzeRng,
    UsbDrive,
    ViewTrngWords,
    AddressExplorer,
    BrowseSd,
    /// Format the SD card to the SD standard (MBR + FAT16/FAT32/exFAT by capacity).
    FormatSd,
    /// Sign a partially-signed transaction (PSBT) picked from the SD card.
    SignPsbt,
    /// Wipe the cached PIN/secret and reboot to the PIN prompt.
    SecureLogout,
    /// The Games submenu.
    #[cfg(feature = "games")]
    Games,
    /// The Block Mine game.
    #[cfg(feature = "games")]
    BlockMine,
    /// The Block Cutter game.
    #[cfg(feature = "games")]
    BlockCutter,
    /// Choosing how long a new seed should be.
    NewSeedMenu,
    /// Generating one, of this many words.
    NewSeed(u8),
    /// Restoring a seed: word count is not asked, the owner types until done.
    ImportSeed,
    /// Device settings: the login submenu and, when a seed exists, destroying it.
    Settings,
    /// Login settings, currently just changing the main PIN.
    Login,
    /// Changing the main PIN.
    ChangePin,
    WipeSeed,
    /// Factory reset: clear the PIN to a zero-length value and reboot to blank.
    FactoryReset,
}

/// The main menu of a device that holds a wallet.
///
/// A device with a seed has no "New wallet" or "Import seed": both would destroy the
/// wallet it already holds, so they live only in the blank ordering. "Destroy seed" is not
/// here either -- it moved into Settings, behind its warnings. The first item is "Ready to
/// Sign": a wallet exists, so the thing worth doing is signing a transaction the host has
/// staged to the SD card.
const MAIN_ITEMS: &[&str] = &[
    "Ready to Sign",
    "Utils",
    "About",
    "Settings",
    "Debug",
    "Secure Logout",
];
/// The blank device's ordering: the two ways to get a wallet come first, since that is the
/// only thing worth doing here. New/Import appear only in this list.
const MAIN_ITEMS_BLANK: &[&str] = &[
    "New wallet",
    "Import seed",
    "Utils",
    "About",
    "Settings",
    "Debug",
    "Secure Logout",
];

/// The main menu, ordered for the device in front of you.
fn main_items(no_seed: bool) -> &'static [&'static str] {
    if no_seed {
        MAIN_ITEMS_BLANK
    } else {
        MAIN_ITEMS
    }
}

/// Settings, with "Destroy seed" only where there is a seed to destroy.
const SETTINGS_ITEMS: &[&str] = &["Login", "Destroy seed"];
const SETTINGS_ITEMS_BLANK: &[&str] = &["Login"];

/// The settings menu for the device in front of you.
fn settings_items(no_seed: bool) -> &'static [&'static str] {
    if no_seed {
        SETTINGS_ITEMS_BLANK
    } else {
        SETTINGS_ITEMS
    }
}

/// Login settings. Just the PIN today; a place for login-related settings to grow.
const LOGIN_ITEMS: &[&str] = &["Change PIN"];
/// How long a new seed should be.
///
/// Twenty-four first, and under the cursor when the menu opens. Twelve is a sound
/// 128-bit seed and stock offers both, but on a device whose whole argument is the
/// quality of its entropy, the stronger option should be the default one.
///
/// The word count travels in [`Screen::NewSeed`], so adding another length here needs
/// only a matching arm in [`step`].
const NEW_SEED_ITEMS: &[&str] = &["24 words", "12 words"];

#[cfg(feature = "games")]
const UTILS_ITEMS: &[&str] = &[
    "Analyze RNG",
    "USB Drive",
    "View TRNG Words",
    "Address Explorer",
    "Browse SD card",
    "Format SD card",
    "Games",
];
#[cfg(not(feature = "games"))]
const UTILS_ITEMS: &[&str] = &[
    "Analyze RNG",
    "USB Drive",
    "View TRNG Words",
    "Address Explorer",
    "Browse SD card",
    "Format SD card",
];

/// The games in the Games submenu.
#[cfg(feature = "games")]
const GAMES_ITEMS: &[&str] = &["Block Mine", "Block Cutter"];
const DEBUG_ITEMS: &[&str] = &[
    "Install from SD",
    "USB",
    "Clocks",
    "RTC",
    "Kernel",
    "Kernel test",
    "Kernel UI",
    "Scroll test",
    "PSRAM",
    "SPI-NOR",
    "Boot report",
    "Selftest",
    "Keypad",
    "PRNG status",
    "microSD",
    "Logs",
    "Save log to SD",
    "Colours",
    "Factory Reset",
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
    } = session;
    let mut screen = Screen::Main;
    let mut showing_offer = false;
    let mut redraw = true;
    let mut v = View {
        report,
        last_key: None,
        keys_seen: 0,
        drbg_stats: drbg.stats(),
        drbg_sample: None,
        menu: MenuScreen::new(),
        raw_kn: None,
        raw_held: 0,
        rtc: RtcWatch::default(),
        kernel_pace: Pace::default(),
        no_seed,
    };

    // About thirty frames a second. Taken from the running clock rather than assumed, so
    // a board on a different HCLK still redraws at the same rate.
    // SAFETY: reads RCC.
    let frame_cycles = unsafe { catcard_hal::clock::hclk_hz() } / 30;

    let mut pad = Keypad::new();
    // One bundle for the session. Every screen takes this instead of four
    // separate borrows, and the keypad inside it is the single scanner whose
    // retained state is what makes a still-held key read as held.
    let mut ui = Ui {
        panel,
        pad: &mut pad,
        matrix,
        drbg,
    };
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();

    loop {
        if redraw && !showing_offer {
            // On the PRNG-status screen, draw a fresh 32-bit sample first so the counters
            // snapshotted just below include that generate call. Done only here, so no
            // other screen advances the DRBG just by being shown.
            if screen == Screen::PrngStatus {
                let mut b = [0u8; 4];
                v.drbg_sample = ui
                    .drbg
                    .generate(&mut b)
                    .ok()
                    .map(|()| u32::from_be_bytes(b));
            }
            // Snapshot the DRBG's counters so the PRNG-status screen shows the current
            // numbers; cheap and side-effect-free on any other screen.
            v.drbg_stats = ui.drbg.stats();
            draw(ui.panel, screen, &v);
            redraw = false;
        }

        let _ = usbtask::pump();
        catcard_hal::dwt::delay_cycles(usbtask::IDLE_PAUSE_CYCLES);

        // The RTC screen redraws on a clock rather than on input: it is showing something
        // that changes on its own, and the whole question it answers is whether it does.
        if screen == Screen::Rtc && v.rtc.sample(frame_cycles) {
            redraw = true;
        }
        if screen == Screen::Kernel && v.kernel_pace.due(frame_cycles) {
            redraw = true;
        }

        // The tester repaints on raw matrix state, not on events: the keys that produce
        // no event are exactly the ones it is needed for.
        if screen == Screen::Keypad {
            let (kn, held) = (ui.pad.last_pressed(), ui.pad.held_mask());
            if kn != v.raw_kn || held != v.raw_held {
                v.raw_kn = kn;
                v.raw_held = held;
                redraw = true;
            }
        }

        crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);

        // An upgrade that passed inspection is waiting on a person, wherever they are.
        //
        // **Checked after the keys are read, not before.** With USB serviced by its own
        // task, the offer can become pending between a check made earlier in this loop
        // and the key read -- and a host approving over USB injects its Confirm the moment
        // the offer's reply arrives. That Confirm was then read with no offer showing and
        // dispatched to whichever menu item was selected, while the install waited forever.
        //
        // Ordering closes it without a lock: the offer is marked pending before its reply
        // goes out, and the host injects only after the reply. So by the time an injected
        // key has been read, the offer is already pending, and this check routes the key
        // to it. Single-threaded it is equally correct, since pump, read and check still
        // happen in order.
        if let Some(a) = usbtask::pending() {
            if !showing_offer {
                if screen == Screen::Colours {
                    display::wipe(ui.panel);
                }
                crate::session::show_offer(ui.panel, &a);
                showing_offer = true;
            }
        } else if showing_offer {
            showing_offer = false;
            redraw = true;
        }

        for key in keys.iter() {
            if showing_offer {
                match key {
                    Key::Confirm => match usbtask::approve() {
                        Ok(region) => {
                            message(ui.panel, "Installing", "do not disconnect", "");
                            crate::staging::install(gate, login, ui.panel, region);
                            showing_offer = false;
                            redraw = true;
                        }
                        Err(_) => {
                            crate::catlog!("install: staging failed");
                            message(ui.panel, "Failed", "could not stage", "the image");
                            showing_offer = false;
                        }
                    },
                    Key::Cancel => {
                        usbtask::decline();
                        showing_offer = false;
                        redraw = true;
                    }
                    Key::Digit(_) => {}
                    Key::Char(_) => {}
                }
                continue;
            }

            let prev_key = v.last_key;
            v.last_key = Some(*key);
            v.keys_seen = v.keys_seen.saturating_add(1);
            redraw = true;

            // The live debug screens (keypad tester, PRNG status) stay open and repaint on
            // each key instead of leaving on the first. `x` returns to Debug -- and on the
            // keypad tester it takes two `x` in a row, so a single `x` still registers as a
            // key to test. Every other key just refreshes the numbers above.
            if matches!(
                screen,
                Screen::Keypad | Screen::PrngStatus | Screen::Rtc | Screen::Kernel
            ) {
                // `0` arms the keypad edge path by hand, on a board where the boot path
                // leaves it masked. If it misbehaves the cure is a power cycle: nothing
                // here is persisted, which is the whole reason it is offered from a screen
                // rather than done at boot.
                if screen == Screen::Keypad && *key == Key::Digit(0) {
                    let (_, armed, _) = crate::keypad::edge_stats();
                    if armed {
                        ui.matrix.disarm_edge_now();
                        crate::catlog!("keypad: edge entropy masked by hand");
                    } else {
                        let ok = ui.matrix.arm_edge_now();
                        crate::catlog!(
                            "keypad: edge entropy {}",
                            if ok {
                                "armed by hand"
                            } else {
                                "refused (storm guard)"
                            }
                        );
                    }
                    redraw = true;
                }
                let leave = match screen {
                    Screen::Keypad => *key == Key::Cancel && prev_key == Some(Key::Cancel),
                    _ => *key == Key::Cancel,
                };
                if leave {
                    v.reset_menu();
                    screen = Screen::Debug;
                }
                continue;
            }

            // Cursor movement first: it stays on this screen, so it never reaches the
            // transition table below. The menu owns what moving means.
            if let Some(items) = items_of(screen, v.no_seed)
                && matches!(key, Key::Digit(5) | Key::Digit(8) | Key::Digit(0))
            {
                v.menu.key(&mut ui, screen, items, *key);
                continue;
            }

            let next = step(screen, *key, v.menu.cursor, v.no_seed);
            // Anything that takes over the panel is a row in the action table rather than
            // a branch here: which routine runs, where the menu lands afterwards, and
            // whether the secret slot has to be re-read. This was seventeen
            // `if next == Screen::X` blocks, each spelling out `reset_menu` / `screen =` /
            // `break` again -- three chances per action to name the wrong screen, and no
            // way to see the whole set at once.
            let words = if let Screen::NewSeed(w) = next { w } else { 0 };
            if let Some(action) = action_for(next) {
                {
                    let mut act = Act {
                        gate,
                        login,
                        ui: &mut ui,
                        pool: pool.as_deref_mut(),
                        words,
                        report: v.report,
                    };
                    (action.run)(&mut act);
                }
                // A wallet that now exists -- or no longer does -- reorders the main menu.
                // Re-read the slot from the login rather than assuming the flow ran to
                // completion: it can be declined or refused at several points.
                if action.seed_may_change {
                    v.no_seed = matches!(login.step(), catcard_pin::Step::In { zero_secret: true });
                }
                v.reset_menu();
                screen = action.back;
                break;
            }
            if next != screen {
                // A new list starts at the top. Carrying a cursor between menus of
                // different lengths is how you land on an item nobody chose.
                v.reset_menu();
                // Entering a live debug screen: clear the key trail so the keypad tester
                // opens on "press any key" rather than the `y` that selected it, and its
                // count starts at zero.
                if matches!(next, Screen::Keypad | Screen::PrngStatus) {
                    v.last_key = None;
                    v.keys_seen = 0;
                }
                // A fresh watch, so "seconds seen" counts from opening the screen
                // rather than from boot.
                if next == Screen::Rtc {
                    v.rtc = RtcWatch::default();
                }
            }
            // The colour chart painted the panel directly, behind the canvas and its row
            // cache, so the next frame has to go out whole or the chart stays under it.
            if screen == Screen::Colours && next != Screen::Colours {
                display::wipe(ui.panel);
            }
            screen = next;
        }
    }
}

/// What a full-screen action is handed.
///
/// The actions have four different argument lists between them -- some want the gate,
/// some the login too, one the entropy pool, one a word count -- and a table can hold
/// only one signature. Bundling them lets each row be the call itself instead of an
/// adapter function, and a fifth thing added later does not touch every row.
struct Act<'a, 'u> {
    gate: &'a Callgate,
    login: &'a mut catcard_pin::Login,
    ui: &'a mut Ui<'u>,
    /// The boot entropy pool. `None` on a device whose pool never met its policy, which
    /// is a refusal to generate a seed rather than a reason to use something weaker.
    pool: Option<&'a mut catcard_entropy::EntropyPool>,
    /// The word count carried by `Screen::NewSeed(n)`; zero for every other action.
    words: u8,
    /// The boot report, for an action that has to restart the session around it.
    report: &'a BootReport,
}

/// A screen that takes over the panel, runs to completion, and hands back to a menu.
#[derive(Copy, Clone)]
struct Action {
    /// Runs it.
    run: fn(&mut Act<'_, '_>),
    /// Where the menu lands when it returns.
    back: Screen,
    /// Re-read the secret slot afterwards: this action can create or destroy a wallet,
    /// and that reorders the main menu.
    seed_may_change: bool,
}

/// The action table: every screen that is a routine rather than a list.
///
/// `None` means the screen is a menu or an info page, which the run loop draws and
/// leaves on a key -- no routine to call.
fn action_for(screen: Screen) -> Option<Action> {
    fn to(run: fn(&mut Act<'_, '_>), back: Screen) -> Action {
        Action {
            run,
            back,
            seed_may_change: false,
        }
    }
    /// For the three that can leave the device holding a different wallet than before.
    fn reseeds(run: fn(&mut Act<'_, '_>), back: Screen) -> Action {
        Action {
            run,
            back,
            seed_may_change: true,
        }
    }

    Some(match screen {
        Screen::SdInstall => to(|a| install_from_card(a.gate, a.login, a.ui), Screen::Main),
        Screen::SaveLog => to(|a| save_log_to_card(a.ui), Screen::Debug),
        Screen::Logs => to(
            |a| {
                page_through(a.ui, "Logs", &LogLines, false, &display::LAYOUT, false);
            },
            Screen::Debug,
        ),
        Screen::AnalyzeRng => to(|a| analyze_rng(a.gate, a.ui), Screen::Utils),
        Screen::UsbDrive => to(|a| usb_drive(a.ui), Screen::Utils),
        Screen::ViewTrngWords => to(|a| view_trng_words(a.gate, a.ui), Screen::Utils),
        Screen::AddressExplorer => to(|a| address_explorer(a.gate, a.login, a.ui), Screen::Utils),
        Screen::BrowseSd => to(
            |a| {
                browse_sd(a.ui, "SD card", None, false);
            },
            Screen::Utils,
        ),
        Screen::FormatSd => to(|a| format_sd(a.ui), Screen::Utils),
        Screen::SignPsbt => to(|a| sign_psbt(a.ui), Screen::Main),
        // Never returns, so `back` is unreachable; the bootloader reboots the device.
        Screen::SecureLogout => to(|a| secure_logout(a.gate, a.login, a.ui), Screen::Main),
        // Both take the CPU for good once they start; they return only to refuse a
        // second start when the kernel is already running.
        Screen::KernelTest => to(|a| crate::ktest::run(a.gate, a.ui), Screen::Debug),
        Screen::KernelUi => to(
            |a| crate::ktest::run_ui(a.gate, a.login, a.ui, a.report, a.pool.take()),
            Screen::Debug,
        ),
        Screen::ScrollTest => to(|a| scroll_test(a.ui), Screen::Debug),
        #[cfg(feature = "games")]
        Screen::BlockMine => to(|a| crate::game::block_mine(a.ui), Screen::Games),
        #[cfg(feature = "games")]
        Screen::BlockCutter => to(|a| crate::game::block_cutter(a.ui), Screen::Games),
        Screen::NewSeed(_) => reseeds(
            |a| new_seed(a.gate, a.login, a.ui, a.pool.as_deref_mut(), a.words),
            Screen::Main,
        ),
        Screen::ImportSeed => reseeds(|a| import_seed(a.gate, a.login, a.ui), Screen::Main),
        Screen::WipeSeed => reseeds(
            |a| {
                wipe_seed(a.gate, a.login, a.ui);
            },
            Screen::Main,
        ),
        Screen::ChangePin => to(|a| change_pin_screen(a.gate, a.login, a.ui), Screen::Login),
        Screen::FactoryReset => to(
            |a| factory_reset_screen(a.gate, a.login, a.ui),
            Screen::Debug,
        ),
        _ => return None,
    })
}

/// Secure logout: drop the MCU's copy of the secret, then hand over to the bootloader.
///
/// On this hardware the secret lives only in MCU SRAM -- the secure element re-runs the
/// full PIN key-stretch on every secret read, so there is no persistent SE session to
/// end, and clearing the MCU's copy is what de-authorises. Zeroize the login struct (its
/// cached PIN and any secret material) first, then callgate 3 wipes *all* SRAM and
/// reboots to the PIN prompt, so nothing survives to the next boot.
fn secure_logout(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) -> ! {
    use zeroize::Zeroize;

    login.zeroize();
    message(ui.panel, "Secure Logout", "wiping memory", "");
    // SAFETY: nothing after this runs; the bootloader clears SRAM.
    unsafe { gate.logout(LogoutMode::LogoutAndReboot) }
}

/// Change the main PIN, and say what happened.
fn change_pin_screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    use crate::pinentry::ChangePin;

    match crate::pinentry::change_pin(gate, ui.panel, ui.matrix, ui.drbg, login) {
        ChangePin::Changed => {
            crate::catlog!("pin: changed");
            message(ui.panel, "PIN changed", "logged in with", "the new PIN");
            wait_for_any_key(ui);
        }
        // Nothing was written; the session is untouched.
        ChangePin::Cancelled => {}
        ChangePin::Mismatch => {
            message(ui.panel, "Not changed", "the two entries", "did not match");
            wait_for_any_key(ui);
        }
        // The change was refused (usually a wrong current PIN); the session is no longer
        // valid, so reboot to a fresh login with the unchanged PIN.
        ChangePin::Refused => {
            crate::catlog!("pin: change refused, rebooting");
            message(ui.panel, "Not changed", "rebooting", "");
            // SAFETY: nothing after this runs.
            unsafe { gate.logout(LogoutMode::LogoutAndReboot) }
        }
    }
}

/// Factory reset: clear the PIN back to blank, behind two confirmations.
fn factory_reset_screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    use crate::pinentry::FactoryReset;

    // Destructive and irreversible: it clears the PIN back to blank. Ask twice, the same
    // as destroying a wallet, before even collecting the PIN.
    let go = {
        ask(
            ui.panel,
            "Factory reset?",
            "the PIN is CLEARED",
            "device back to blank",
        );
        confirmed(ui) && {
            ask(ui.panel, "Really reset?", "this cannot be", "undone");
            confirmed(ui)
        }
    };
    if !go {
        return;
    }
    match crate::pinentry::factory_reset(gate, ui.panel, ui.matrix, ui.drbg, login) {
        // The device is blank now; reboot straight into the first-run flow.
        FactoryReset::Wiped => {
            crate::catlog!("pin: factory reset, rebooting blank");
            message(ui.panel, "Reset done", "rebooting", "");
            // SAFETY: nothing after this runs.
            unsafe { gate.logout(LogoutMode::LogoutAndReboot) }
        }
        // A wrong current PIN (or another failure) leaves the session invalid, so reboot
        // to a fresh login with the unchanged PIN.
        FactoryReset::Refused => {
            crate::catlog!("pin: factory reset refused, rebooting");
            message(ui.panel, "Not reset", "rebooting", "");
            // SAFETY: nothing after this runs.
            unsafe { gate.logout(LogoutMode::LogoutAndReboot) }
        }
        // Backed out during PIN entry; nothing changed.
        FactoryReset::Cancelled => {}
    }
}

/// Where a key takes us. Returns the next screen.
fn step(screen: Screen, key: Key, cursor: usize, no_seed: bool) -> Screen {
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
            // A wallet is present: the first item signs a transaction from the SD card.
            (Key::Confirm, Some("Ready to Sign")) => Screen::SignPsbt,
            (Key::Confirm, Some("Debug")) => Screen::Debug,
            (Key::Confirm, Some("Utils")) => Screen::Utils,
            (Key::Confirm, Some("About")) => Screen::About,
            // New/Import appear only on a blank device, but the arms are harmless anywhere.
            (Key::Confirm, Some("New wallet")) => Screen::NewSeedMenu,
            (Key::Confirm, Some("Import seed")) => Screen::ImportSeed,
            (Key::Confirm, Some("Settings")) => Screen::Settings,
            // Handled in `run`, where the login struct is in scope to be zeroized first.
            (Key::Confirm, Some("Secure Logout")) => Screen::SecureLogout,
            _ => Screen::Main,
        },
        // By name again, for the same reason as Main: the list is short today and the
        // count is what the next screen acts on, so an index table would be one
        // reordering away from generating the wrong length of seed.
        Screen::NewSeedMenu => match (key, NEW_SEED_ITEMS.get(cursor).copied()) {
            (Key::Confirm, Some("24 words")) => Screen::NewSeed(24),
            (Key::Confirm, Some("12 words")) => Screen::NewSeed(12),
            (Key::Cancel, _) => Screen::Main,
            _ => Screen::NewSeedMenu,
        },
        Screen::Settings => match (key, settings_items(no_seed).get(cursor).copied()) {
            (Key::Confirm, Some("Login")) => Screen::Login,
            (Key::Confirm, Some("Destroy seed")) => Screen::WipeSeed,
            (Key::Cancel, _) => Screen::Main,
            _ => Screen::Settings,
        },
        Screen::Login => match (key, LOGIN_ITEMS.get(cursor).copied()) {
            (Key::Confirm, Some("Change PIN")) => Screen::ChangePin,
            (Key::Cancel, _) => Screen::Settings,
            _ => Screen::Login,
        },
        // The splash: any key but cancel turns to the chip page, which any key but cancel
        // leaves. Cancel steps back a page.
        Screen::About => match key {
            Key::Cancel => Screen::Main,
            _ => Screen::AboutChip,
        },
        Screen::AboutChip => match key {
            Key::Cancel => Screen::About,
            _ => Screen::Main,
        },
        Screen::Utils => match (key, UTILS_ITEMS.get(cursor).copied()) {
            (Key::Confirm, Some("Analyze RNG")) => Screen::AnalyzeRng,
            (Key::Confirm, Some("USB Drive")) => Screen::UsbDrive,
            (Key::Confirm, Some("View TRNG Words")) => Screen::ViewTrngWords,
            (Key::Confirm, Some("Address Explorer")) => Screen::AddressExplorer,
            (Key::Confirm, Some("Browse SD card")) => Screen::BrowseSd,
            (Key::Confirm, Some("Format SD card")) => Screen::FormatSd,
            #[cfg(feature = "games")]
            (Key::Confirm, Some("Games")) => Screen::Games,
            (Key::Cancel, _) => Screen::Main,
            _ => Screen::Utils,
        },
        #[cfg(feature = "games")]
        Screen::Games => match (key, GAMES_ITEMS.get(cursor).copied()) {
            (Key::Confirm, Some("Block Mine")) => Screen::BlockMine,
            (Key::Confirm, Some("Block Cutter")) => Screen::BlockCutter,
            (Key::Cancel, _) => Screen::Utils,
            _ => Screen::Games,
        },
        // By name, like Main: the list reorders (Install from SD was just added at the
        // top), and an index table would silently point at the wrong entry.
        Screen::Debug => match (key, DEBUG_ITEMS.get(cursor).copied()) {
            (Key::Confirm, Some("Install from SD")) => Screen::SdInstall,
            (Key::Confirm, Some("USB")) => Screen::Usb,
            (Key::Confirm, Some("Clocks")) => Screen::Clocks,
            (Key::Confirm, Some("RTC")) => Screen::Rtc,
            (Key::Confirm, Some("Kernel")) => Screen::Kernel,
            (Key::Confirm, Some("Kernel test")) => Screen::KernelTest,
            (Key::Confirm, Some("Kernel UI")) => Screen::KernelUi,
            (Key::Confirm, Some("Scroll test")) => Screen::ScrollTest,
            (Key::Confirm, Some("PSRAM")) => Screen::Psram,
            (Key::Confirm, Some("SPI-NOR")) => Screen::Sflash,
            (Key::Confirm, Some("Boot report")) => Screen::Boot,
            (Key::Confirm, Some("Selftest")) => Screen::Selftest,
            (Key::Confirm, Some("Keypad")) => Screen::Keypad,
            (Key::Confirm, Some("PRNG status")) => Screen::PrngStatus,
            (Key::Confirm, Some("microSD")) => Screen::Sd,
            (Key::Confirm, Some("Logs")) => Screen::Logs,
            (Key::Confirm, Some("Save log to SD")) => Screen::SaveLog,
            (Key::Confirm, Some("Colours")) => Screen::Colours,
            (Key::Confirm, Some("Factory Reset")) => Screen::FactoryReset,
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
}

/// Everything a screen needs to draw itself.
///
/// Grouped rather than passed one by one: these travel together through the loop, and a
/// call taking eight positional arguments is one transposed pair away from drawing the
/// wrong thing without the compiler noticing.
struct View<'a> {
    report: &'a BootReport,
    last_key: Option<Key>,
    keys_seen: u32,
    /// A snapshot of the UI DRBG's diagnostic counters, refreshed before each draw so the
    /// PRNG-status screen shows current numbers.
    drbg_stats: catcard_entropy::DrbgStats,
    /// A fresh 32-bit draw from the UI DRBG, taken only when the PRNG-status screen is
    /// about to be drawn. `None` if the draw errored (only possible past the reseed
    /// interval). Advancing the DRBG to show a sample is exactly what it is for.
    drbg_sample: Option<u32>,
    /// The list screen's own state: where the cursor is and how far the view is scrolled.
    menu: MenuScreen,
    /// The last raw matrix position pressed, and which positions are held, for the
    /// keypad tester. Raw rather than decoded: the modifiers, the lamp and the two
    /// hardware keys decode to nothing, and a tester that showed only decoded keys made
    /// them look dead on the one screen meant to tell dead from unmapped.
    raw_kn: Option<usize>,
    raw_held: u64,
    /// The RTC debug screen's sampler.
    rtc: RtcWatch,
    /// The kernel status screen's repaint pacer.
    kernel_pace: Pace,
    /// No wallet stored yet, so the main menu leads with creating one.
    no_seed: bool,
}

impl View<'_> {
    /// A fresh scroll position for a new list: cursor at the top, view unscrolled.
    fn reset_menu(&mut self) {
        self.menu.reset();
    }
}

/// A list screen: the cursor and scroll offset that survive a keypress.
///
/// These lived on [`View`] as two loose fields that one block of the run loop moved
/// inline, so the only thing able to drive a menu was that block. Owned by the screen,
/// a menu answers a key the way [`DocScreen`] does -- the shape a run loop can hand
/// events to rather than reach into.
///
/// The `ScrollView` is rebuilt per draw and per key rather than stored. It borrows both
/// the item slice and the note, and the note is a [`Line`] built on the caller's stack by
/// [`menu_head`] -- so a stored view would borrow a local. Rebuilding is what `draw_menu`
/// always did.
#[derive(Copy, Clone)]
struct MenuScreen {
    /// Index of the item under the cursor, in the id space `build_menu_view` gives its
    /// rows -- the item's position, with title and note rows carrying no id.
    cursor: usize,
    /// Pixel scroll offset, kept across redraws so the highlight pushes the view at the
    /// edges rather than the view snapping to the cursor each frame.
    off: usize,
}

impl MenuScreen {
    const fn new() -> Self {
        Self { cursor: 0, off: 0 }
    }

    /// Start a new list at the top. Carrying a cursor between menus of different lengths
    /// is how you land on an item nobody chose.
    fn reset(&mut self) {
        *self = Self::new();
    }

    fn draw(&self, panel: &mut display::Panel, screen: Screen, no_seed: bool) {
        let (title, note) = menu_head(screen);
        let items = items_of(screen, no_seed).unwrap_or(&[]);
        let view = build_menu_view(title, note.as_str(), items, self.off, self.cursor);
        display::draw(panel, |c| catcard_ui::scroll::render(c, &view));
    }

    /// Take a movement key (`0`, `5` or `8`) and animate where it lands.
    ///
    /// The move runs through the scroll view so the highlight travels within the panel
    /// and only pushes the view at an edge, and so pressing past the first or last item
    /// keeps scrolling to reveal the title.
    fn key(&mut self, ui: &mut Ui<'_>, screen: Screen, items: &[&str], k: Key) {
        let (title, note) = menu_head(screen);
        let mut view = build_menu_view(title, note.as_str(), items, self.off, self.cursor);
        let old = view.off();
        match k {
            // `0` jumps back to the top, the arrows move one row.
            Key::Digit(0) => view.to_top(),
            Key::Digit(8) => view.move_cursor(true),
            _ => view.move_cursor(false),
        }
        if let Some(id) = view.selected() {
            self.cursor = id as usize;
        }
        let new_off = view.off();
        // Animate the move, then let the loop's redraw paint the settled frame.
        glide_view(ui.panel, &mut view, old, new_off);
        self.off = new_off;
    }
}

/// The list on this screen, if it is a menu.
fn items_of(screen: Screen, no_seed: bool) -> Option<&'static [&'static str]> {
    match screen {
        Screen::Main => Some(main_items(no_seed)),
        Screen::Debug => Some(DEBUG_ITEMS),
        Screen::Utils => Some(UTILS_ITEMS),
        Screen::NewSeedMenu => Some(NEW_SEED_ITEMS),
        Screen::Settings => Some(settings_items(no_seed)),
        Screen::Login => Some(LOGIN_ITEMS),
        #[cfg(feature = "games")]
        Screen::Games => Some(GAMES_ITEMS),
        _ => None,
    }
}

/// Draw whichever screen we are on.
fn draw(panel: &mut display::Panel, screen: Screen, v: &View<'_>) {
    match screen {
        // Every list screen renders the same way; the title and note come from
        // `menu_head`, the single place they are defined.
        Screen::Main
        | Screen::Utils
        | Screen::NewSeedMenu
        | Screen::Debug
        | Screen::Settings
        | Screen::Login => draw_menu(panel, screen, v),
        #[cfg(feature = "games")]
        Screen::Games => draw_menu(panel, screen, v),
        Screen::About => about_screen(panel),
        Screen::AboutChip => chip_screen(panel),
        Screen::Usb => usb_screen(panel),
        Screen::Clocks => clock_screen(panel),
        Screen::Psram => psram_screen(panel),
        Screen::Sflash => sflash_screen(panel),
        Screen::PsramProbe => psram_probe(panel),
        Screen::Boot => boot_screen(panel, v.report),
        Screen::Selftest => crate::selftest::screen(v.report, panel),
        Screen::Keypad => keypad_screen(panel, v.last_key, v.keys_seen, v.raw_kn, v.raw_held),
        Screen::PrngStatus => prng_screen(panel, v.drbg_stats, v.drbg_sample),
        Screen::Rtc => rtc_screen(panel, &v.rtc),
        // Handled in `run`: it takes the CPU and never returns.
        Screen::KernelTest | Screen::KernelUi | Screen::ScrollTest => {}
        Screen::Kernel => kernel_screen(panel),
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
        Screen::ViewTrngWords => {}
        // Handled in `run`: it fetches the secret and drives its own paging loop.
        Screen::AddressExplorer => {}
        // Handled in `run`: it lists the SD card and drives its own loop.
        Screen::BrowseSd => {}
        // Handled in `run`: it confirms, brings up the card, and drives the panel itself.
        Screen::FormatSd => {}
        // Handled in `run`: it runs the file picker and drives the panel itself.
        Screen::SignPsbt => {}
        // Handled in `run`: it zeroizes the login and calls the bootloader; never drawn.
        Screen::SecureLogout => {}
        // Handled in `run`: it needs the keypad, which the drawing half does not have.
        Screen::SdInstall => {}
        // Handled in `run`: it asks questions and shows words, so it drives the panel
        // and the keypad itself.
        Screen::NewSeed(_) => {}
        // Handled in `run`: it reads words from the keypad and drives the panel itself.
        Screen::ImportSeed => {}
        // Handled in `run`: it drives the PIN-entry screens itself.
        Screen::ChangePin => {}
        // Handled in `run`: the game drives the panel in its own loop.
        #[cfg(feature = "games")]
        Screen::BlockMine => {}
        #[cfg(feature = "games")]
        Screen::BlockCutter => {}
        // Handled in `run`: it asks twice and drives the panel itself.
        Screen::WipeSeed => {}
        // Handled in `run`: it confirms, collects the PIN, and drives the panel itself.
        Screen::FactoryReset => {}
    }
}

/// The title and note line for a menu screen -- the single place each is defined, used by
/// both the draw path and the arrow handler so the two never diverge. The note is owned so
/// a screen that wants a dynamic one can build it here.
fn menu_head(screen: Screen) -> (&'static str, Line) {
    let mut note = Line::new();
    let title = match screen {
        Screen::Main => "CatCard",
        Screen::Utils => "Utils",
        Screen::NewSeedMenu => {
            let _ = note.push_str("how many words?");
            "New wallet"
        }
        Screen::Debug => "Debug",
        Screen::Settings => "Settings",
        Screen::Login => "Login",
        #[cfg(feature = "games")]
        Screen::Games => "Games",
        _ => "",
    };
    (title, note)
}

/// Build the scroll view for a menu: a title, an optional small note, then the items --
/// each carrying its index as its `menu_item` id, wrapped, so a long label stays one
/// selectable row. Positioned on `cursor` at the persisted scroll `off`.
fn build_menu_view<'a>(
    title: &'a str,
    note: &'a str,
    items: &'a [&'a str],
    off: usize,
    cursor: usize,
) -> catcard_ui::scroll::ScrollView<'a> {
    use catcard_ui::scroll::{Line as DLine, ScrollView};

    let mut lines: heapless::Vec<DLine, 40> = heapless::Vec::new();
    let _ = lines.push(DLine::title(title));
    if !note.is_empty() {
        let _ = lines.push(DLine::body(note).small().centered());
    }
    for (i, item) in items.iter().enumerate() {
        let _ = lines.push(DLine::item(item, i as u32).wrapped());
    }
    let mut view = ScrollView::build(&lines, display::SCREEN_W, display::SCREEN_H, display::FONTS);
    view.set_off(off);
    view.select(cursor as u32);
    view
}

/// Draw a menu screen: the larger font, the selected row an inverted bar, scrolled to the
/// view's persisted offset.
fn draw_menu(panel: &mut display::Panel, screen: Screen, v: &View<'_>) {
    v.menu.draw(panel, screen, v.no_seed);
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
    // The fourth field is an outbox that has not drained -- a reply we owe the host --
    // not a staged image. It used to be labelled "staged" here, which said the device
    // was holding firmware when it was holding a reply. The staged image is a separate
    // question, asked below.
    let (configured, rx, tx, queued) = usbtask::stats();
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
    let _ = write!(l, "in {rx}  out {tx}{}", if queued { "  txq" } else { "" });
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
    //
    // "staged" rides on this line rather than its own: the mono panel fits exactly six
    // rows and this screen already uses all six, so a seventh would be dropped by the
    // ignored `push` and the board with the least room would lose it silently.
    let (resets, reinits, rearms) = usbtask::recovery_counts();
    let mut l = Line::new();
    let _ = write!(
        l,
        "rst {resets} re {reinits} arm {rearms}{}",
        if usbtask::has_pending() {
            "  staged"
        } else {
            ""
        }
    );
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

/// SPI-NOR probe: bring up the flash and show its JEDEC id and size.
///
/// This is the first thing to check on an mk3 -- a plausible id (Macronix `C2 20 14`, a
/// 1 MB MX25L8006E) proves the SPI2 pins, the PB9 chip-select and the clock are all right.
/// Boards with no SPI-NOR (mk4/mk5/Q1) say so.
fn sflash_screen(panel: &mut display::Panel) {
    let mut lines: heapless::Vec<Line, MAX_LINES> = heapless::Vec::new();
    if catcard_board::BOARD.sflash.is_none() {
        let mut l = Line::new();
        let _ = write!(l, "none on this board");
        let _ = lines.push(l);
        info(panel, "SPI-NOR", &lines);
        return;
    }

    // SAFETY: this screen is the only SPI-NOR user; SPI2 and its pins belong to the
    // sflash alone, and the menu waits for this to return before it can be chosen again.
    match unsafe { crate::nor::init() } {
        Some(mut nor) => match nor.jedec_id() {
            Ok(id) => {
                let mut l = Line::new();
                let _ = write!(
                    l,
                    "id {:02x} {:02x} {:02x}",
                    id.manufacturer, id.memory_type, id.capacity
                );
                let _ = lines.push(l);
                let mut l = Line::new();
                let _ = write!(l, "size {} KB", nor.size() / 1024);
                let _ = lines.push(l);
            }
            Err(_) => {
                let mut l = Line::new();
                let _ = write!(l, "no response");
                let _ = lines.push(l);
            }
        },
        None => {
            let mut l = Line::new();
            let _ = write!(l, "probe failed");
            let _ = lines.push(l);
        }
    }
    info(panel, "SPI-NOR", &lines);
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
fn keypad_screen(
    panel: &mut display::Panel,
    last: Option<Key>,
    seen: u32,
    raw_kn: Option<usize>,
    held: u64,
) {
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
        Some(Key::Char(c)) => {
            let _ = write!(l, "last  {}", c as char);
        }
    }
    let _ = lines.push(l);

    // The raw matrix position, which every physical key produces -- including the ones
    // that decode to nothing (SYM, LAMP, NFC, QR). This is what makes the tester able to
    // tell a key that is wired but unmapped from a key that is not wired at all.
    let mut l = Line::new();
    match raw_kn {
        Some(kn) => {
            let _ = write!(l, "kn {kn}  held {}", held.count_ones());
        }
        None => {
            let _ = write!(l, "kn -");
        }
    }
    let _ = lines.push(l);

    let mut l = Line::new();
    let _ = write!(l, "count {seen}");
    let _ = lines.push(l);

    // The edge path: whether the hard falling-edge interrupt is armed, how many edges it
    // has taken, and whether the storm guard shut it off. On a board where it is not armed
    // at boot this is the screen that arms it -- with a power cycle as the undo.
    let (edges, armed, storm) = crate::keypad::edge_stats();
    let mut l = Line::new();
    let _ = write!(
        l,
        "edges {edges} {}",
        if storm {
            "STORM, off"
        } else if armed {
            "armed"
        } else {
            "off"
        }
    );
    let _ = lines.push(l);

    let mut l = Line::new();
    let _ = l.push_str(if armed {
        "0 masks edges"
    } else {
        "0 arms edges"
    });
    let _ = lines.push(l);

    let mut l = Line::new();
    let _ = write!(l, "x twice  back");
    let _ = lines.push(l);
    info(panel, "Keypad", &lines);
}

/// The UI DRBG's diagnostic counters. This is the generator behind the keypad scan
/// shuffle and every UI random draw; it is topped up (reseeded) on each physical keypress
/// with the edge-timed cycle counter and RTC, so `seeded`/`reseeds` climb as keys are
/// pressed. It is never the wallet-seed generator -- that is `EntropyPool`, which has no
/// draw API at all. Counters only; no generator state is shown.
/// A repaint pacer: says yes once per `period` cycles, and immediately the first time.
///
/// One of these instead of each self-refreshing screen carrying its own copy of the same
/// three lines. The first frame is never delayed, so a screen is painted the moment it
/// opens rather than a frame later.
#[derive(Copy, Clone, Default)]
struct Pace {
    last: u32,
    started: bool,
}

impl Pace {
    fn due(&mut self, period: u32) -> bool {
        let now = catcard_hal::dwt::cycles();
        // `wrapping_sub` because DWT_CYCCNT wraps every 2^32 cycles, far longer than a frame.
        if self.started && now.wrapping_sub(self.last) < period {
            return false;
        }
        self.last = now;
        self.started = true;
        true
    }
}

/// What the RTC debug screen shows: the three registers, resampled on a clock.
///
/// **Nothing here initialises or writes the RTC.** The point of the screen is to show how
/// the *bootloader* left it, so every value is read exactly as found -- `snapshot` is pure
/// reads, and the only RCC write anywhere near the RTC is the APB read gate that bring-up
/// already opened, which lets the CPU see the registers without configuring the peripheral.
#[derive(Copy, Clone, Default)]
struct RtcWatch {
    /// `[SSR, TR, DR]`, in the order the shadow registers require.
    snap: [u32; 3],
    pace: Pace,
}

impl RtcWatch {
    /// Resample if `period` cycles have passed. Returns whether it did.
    fn sample(&mut self, period: u32) -> bool {
        if !self.pace.due(period) {
            return false;
        }
        // SAFETY: three register reads, in the order the shadow registers require (SSR,
        // TR, DR -- reading DR unlocks the shadow). The APB read gate was opened during
        // bring-up; nothing here writes.
        self.snap = unsafe { catcard_hal::rtc::snapshot() };
        true
    }
}

/// The scheduler, live: ticks, switches, recovered time, and each task's stack depth.
///
/// Only meaningful with the menu itself running as a kernel task (Debug -> Kernel UI):
/// starting the kernel any other way replaces the menu, so nothing would be left to draw
/// this. Without the kernel it says so rather than showing a column of zeros.
fn kernel_screen(panel: &mut display::Panel) {
    let mut lines: heapless::Vec<Line, MAX_LINES> = heapless::Vec::new();
    if !catcard_kernel::running() {
        let mut l = Line::new();
        let _ = l.push_str("not running");
        let _ = lines.push(l);
        let mut l = Line::new();
        let _ = l.push_str("start: Kernel UI");
        let _ = lines.push(l);
        info(panel, "Kernel", &lines);
        return;
    }

    let mut l = Line::new();
    let _ = write!(
        l,
        "t {} sw {}",
        catcard_kernel::ticks(),
        catcard_kernel::switches()
    );
    let _ = lines.push(l);

    let mut l = Line::new();
    let _ = write!(
        l,
        "rec {} fp {}",
        catcard_kernel::recovered(),
        catcard_kernel::fp_saves()
    );
    let _ = lines.push(l);

    for i in 0..catcard_kernel::count().min(MAX_LINES - 2) {
        let id = catcard_kernel::TaskId(i);
        let mut l = Line::new();
        let _ = write!(
            l,
            "{} {}/{} {}",
            catcard_kernel::name(id),
            catcard_kernel::high_water(id),
            catcard_kernel::stack_len(id),
            if catcard_kernel::stack_ok(id) {
                "ok"
            } else {
                "OVERFLOW"
            }
        );
        let _ = lines.push(l);
    }

    info(panel, "Kernel", &lines);
}

/// Two BCD digits as a number. The RTC stores its time and date this way.
/// Source: RM0432 §RTC, `RTC_TR`/`RTC_DR` field layout [C]
fn bcd2(v: u32) -> u32 {
    ((v >> 4) & 0xf) * 10 + (v & 0xf)
}

/// The RTC as the bootloader left it: the raw registers, and what they decode to.
///
/// Read-only, and deliberately so -- see [`RtcWatch`]. A device that has never had its
/// clock set still shows something here, because the RTC counts from whenever it started,
/// not from a wall-clock epoch.
fn rtc_screen(panel: &mut display::Panel, w: &RtcWatch) {
    let [ssr, tr, dr] = w.snap;
    let mut lines: heapless::Vec<Line, MAX_LINES> = heapless::Vec::new();

    // The sub-second down-counter, reloaded from the synchronous prescaler each second.
    // The one that moves fastest, so it is the one that shows the RTC is running at all.
    let mut l = Line::new();
    let _ = write!(l, "SSR  {ssr:#010x}  {ssr}");
    let _ = lines.push(l);

    // Source: RM0432 §RTC -- TR is seconds[6:0], minutes[14:8], hours[21:16], all BCD.
    let mut l = Line::new();
    let _ = write!(
        l,
        "TR   {tr:#010x}  {:02}:{:02}:{:02}",
        bcd2((tr >> 16) & 0x3f),
        bcd2((tr >> 8) & 0x7f),
        bcd2(tr & 0x7f)
    );
    let _ = lines.push(l);

    // Source: RM0432 §RTC -- DR is day[5:0], month[12:8], year[23:16], all BCD.
    let mut l = Line::new();
    let _ = write!(
        l,
        "DR   {dr:#010x}  {:02}-{:02}-{:02}",
        bcd2((dr >> 16) & 0xff),
        bcd2((dr >> 8) & 0x1f),
        bcd2(dr & 0x3f)
    );
    let _ = lines.push(l);

    info(panel, "RTC", &lines);
}

fn prng_screen(panel: &mut display::Panel, s: catcard_entropy::DrbgStats, sample: Option<u32>) {
    let mut lines: heapless::Vec<Line, MAX_LINES> = heapless::Vec::new();

    let mut l = Line::new();
    let _ = write!(l, "UI HMAC-SHA256");
    let _ = lines.push(l);

    // A fresh 32-bit draw, redrawn on every key. Shown at the top so it is the first thing
    // that changes when you press a key -- alongside the reseed count climbing.
    let mut l = Line::new();
    match sample {
        Some(x) => {
            let _ = write!(l, "out  {x:08x}");
        }
        None => {
            let _ = write!(l, "out  --------");
        }
    }
    let _ = lines.push(l);

    // Total seedings counts the boot instantiation plus every reseed.
    let mut l = Line::new();
    let _ = write!(l, "seeded  {}", s.seedings);
    let _ = lines.push(l);

    let mut l = Line::new();
    let _ = write!(l, "reseeds {}", s.reseeds);
    let _ = lines.push(l);

    let mut l = Line::new();
    let _ = write!(l, "gen     {}", s.generates);
    let _ = lines.push(l);

    let mut l = Line::new();
    let _ = write!(l, "since rs {}", s.since_reseed);
    let _ = lines.push(l);

    info(panel, "PRNG status", &lines);
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
fn install_from_card(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    use crate::sdupgrade::{Outcome, stage_from_card};

    // Pick the firmware from the card by browsing for a .dfu, rather than guessing at a
    // fixed name. Cancelling the browser cancels the install.
    let chosen = browse_sd(ui, "Pick a .dfu", Some("dfu"), true);
    let Some(chosen) = chosen else {
        return;
    };

    crate::catlog!("sd: staging the chosen firmware");
    message(ui.panel, "Reading card", "please wait", "");
    let (staged, approval) = match stage_from_card(catcard_hal::sdmmc::Slot::A, Some(&chosen)) {
        Outcome::Offered(s, a) => (s, a),
        Outcome::Failed(why) => {
            crate::catlog!("sd: {}", why);
            message(ui.panel, "No upgrade", why, "any key to go back");
            wait_for_any_key(ui);
            return;
        }
    };

    crate::session::show_offer(ui.panel, &approval);

    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
        for k in keys.iter() {
            match k {
                Key::Confirm => {
                    match staged.commit(approval) {
                        Ok(region) => {
                            message(ui.panel, "Installing", "do not disconnect", "");
                            crate::staging::install(gate, login, ui.panel, region);
                        }
                        Err(_) => {
                            message(ui.panel, "Failed", "could not stage", "any key to go back");
                        }
                    }
                    wait_for_any_key(ui);
                    return;
                }
                Key::Cancel => return,
                Key::Digit(_) => {}
                Key::Char(_) => {}
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
/// Blocking, and it says which step it stopped at rather than "failed", so a bad card, a
/// full card and a filesystem it cannot mount tell themselves apart. Nothing here is
/// irreversible -- at worst it leaves a short file behind.
fn save_log_to_card(ui: &mut Ui<'_>) {
    crate::catlog!("sd: saving log");
    message(ui.panel, "Saving log", "please wait", "");

    // Snapshot the log before touching anything else, so what lands on the card is the
    // state at the moment it was asked for, not a log with this function's own steps in
    // it.
    let mut buf = [0u8; crate::logbuf::LOG_LEN];
    let n = crate::logbuf::read(0, &mut buf);

    match write_log_file(&buf[..n]) {
        Ok(()) => {
            crate::catlog!("sd: wrote {} bytes to /CATCARD.LOG", n);
            message(ui.panel, "Log saved", "/CATCARD.LOG", "any key to go back");
        }
        Err(why) => {
            crate::catlog!("sd: log save failed: {}", why);
            message(ui.panel, "Save failed", why, "any key to go back");
        }
    }
    wait_for_any_key(ui);
}

/// Bring the card up, mount it, and write `bytes` to `/CATCARD.LOG`.
///
/// Split from the screen so each step is one `?`, and the reason it stopped rides out on
/// the `Err` for the caller to show and log -- the step is what tells a bad card apart
/// from a full one or a filesystem it cannot mount.
fn write_log_file(bytes: &[u8]) -> Result<(), &'static str> {
    // Mount FAT or exFAT; `why` carries the specific bring-up failure out of the closure.
    let mut why: &'static str = "card error";
    let mut vol: catcard_sd::AnyVolume<_, 512> = catcard_sd::AnyVolume::mount_with(|| {
        // SAFETY: nothing else has claimed SDMMC1 or its pins, and the menu waits for this
        // to return before it can be chosen again.
        let mut dev = match unsafe { catcard_hal::sdmmc::Sdmmc::init(&catcard_board::BOARD) } {
            Ok(d) => d,
            Err(_) => {
                why = "controller failed";
                return Err(());
            }
        };
        let card = match catcard_sd::init(&mut dev) {
            Ok(c) => c,
            Err(catcard_sd::Error::NoCard) => {
                why = "no card in slot";
                return Err(());
            }
            Err(e) => {
                crate::catlog!("sd: card would not start: {:?}", e);
                why = "card would not start";
                return Err(());
            }
        };
        Ok(catcard_sd::Sectors::new(dev, card))
    })
    .map_err(|e| match e {
        catcard_sd::MountError::Device => why,
        catcard_sd::MountError::NoFilesystem => "not FAT or exFAT",
    })?;
    let mut file = vol
        .open_or_create_file("/CATCARD.LOG")
        .map_err(|_| "could not open file")?;
    file.write_all(&mut vol, bytes)
        .map_err(|_| "write failed")?;
    // Trim any tail from a longer earlier save, so the file is exactly this log.
    file.set_len(&mut vol, bytes.len() as u64)
        .map_err(|_| "truncate failed")?;
    file.flush(&mut vol).map_err(|_| "flush failed")?;
    vol.flush().map_err(|_| "flush failed")?;
    Ok(())
}

/// Longest file name a browser row keeps; longer names are truncated for display (the
/// marquee still scrolls what is kept).
const BROWSE_NAME_MAX: usize = 64;
/// Most entries one directory shows; beyond this the listing stops (rare on a wallet card).
const BROWSE_ENTRIES: usize = 48;
/// Longest path the browser tracks as it descends.
const BROWSE_PATH_MAX: usize = 160;
/// The id the "Parent" row carries; real entries carry their (small) index.
const BROWSE_PARENT: u32 = u32::MAX;

/// One directory entry as the browser holds it, copied out of the lending `DirEntry`.
struct BrowseEntry {
    name: heapless::String<BROWSE_NAME_MAX>,
    is_dir: bool,
    len: u64,
}

/// Whether `name`'s extension equals `ext`, case-insensitively.
fn ext_matches(name: &str, ext: &str) -> bool {
    match name.rsplit_once('.') {
        Some((_, e)) => e.eq_ignore_ascii_case(ext),
        None => false,
    }
}

/// Drop the last `/segment` of a path, leaving the parent (or root, the empty string).
fn pop_segment(path: &mut heapless::String<BROWSE_PATH_MAX>) {
    match path.rfind('/') {
        Some(i) => path.truncate(i),
        None => path.clear(),
    }
}

/// Show a file's details, and -- when picking -- offer to choose it. Returns whether the
/// owner confirmed (chose it).
fn file_info(ui: &mut Ui<'_>, name: &str, len: u64, pick: bool) -> bool {
    use catcard_ui::scroll::Line as DLine;
    let mut sz = Line::new();
    let _ = write!(sz, "{len} bytes");
    let mut lines: heapless::Vec<DLine, 6> = heapless::Vec::new();
    let _ = lines.push(DLine::title("File"));
    let _ = lines.push(DLine::body(name).wrapped());
    let _ = lines.push(DLine::body(&sz).small());
    if pick {
        let _ = lines.push(DLine::body("y = select this").centered());
    }
    matches!(show_doc(ui, &lines, false, false), DocExit::Confirmed)
}

/// A generic microSD file browser.
///
/// Lists a directory as icon + name rows (folders, files, and a "Parent" row when not at
/// the root), each selectable; a name too wide for the panel marquees while selected.
/// Descending into a folder re-lists it; Cancel or "Parent" goes up, and Cancel at the
/// root leaves. Selecting a file shows its details. When `pick` is set, that detail screen
/// offers to choose the file and the chosen full path is returned; otherwise the browser
/// is a viewer and returns `None`. `filter`, when set, hides files without that extension
/// (folders always show), which is how the caller narrows to `.dfu`, `.psbt`, and so on.
///
/// A mount or read failure is reported with the step it stopped at, so a missing card, a
/// filesystem it cannot mount (exFAT, today) and a read error tell themselves apart.
fn browse_sd(
    ui: &mut Ui<'_>,
    title: &str,
    filter: Option<&str>,
    pick: bool,
) -> Option<heapless::String<BROWSE_PATH_MAX>> {
    fn fail(ui: &mut Ui<'_>, why: &str) {
        message(ui.panel, "SD card", why, "any key to go back");
        wait_for_any_key(ui);
    }

    // Mount the card, FAT or exFAT, re-initialising it for the exFAT attempt. `why` carries
    // the specific bring-up failure out of the closure for the message.
    let mut why = "card error";
    let mount: Result<catcard_sd::AnyVolume<_, 512>, _> = catcard_sd::AnyVolume::mount_with(|| {
        // SAFETY: nothing else has claimed SDMMC1 or its pins, and the menu waits for this
        // to return before it can be chosen again.
        let mut dev = match unsafe { catcard_hal::sdmmc::Sdmmc::init(&catcard_board::BOARD) } {
            Ok(d) => d,
            Err(_) => {
                why = "controller failed";
                return Err(());
            }
        };
        let card = match catcard_sd::init(&mut dev) {
            Ok(c) => c,
            Err(catcard_sd::Error::NoCard) => {
                why = "no card in slot";
                return Err(());
            }
            Err(e) => {
                crate::catlog!("sd: card would not start: {:?}", e);
                why = "card would not start";
                return Err(());
            }
        };
        Ok(catcard_sd::Sectors::new(dev, card))
    });
    let mut vol = match mount {
        Ok(v) => v,
        Err(catcard_sd::MountError::Device) => {
            fail(ui, why);
            return None;
        }
        Err(catcard_sd::MountError::NoFilesystem) => {
            fail(ui, "not FAT or exFAT");
            return None;
        }
    };

    let mut path: heapless::String<BROWSE_PATH_MAX> = heapless::String::new();
    let mut entries: heapless::Vec<BrowseEntry, BROWSE_ENTRIES> = heapless::Vec::new();

    loop {
        // List the current directory, copying each entry the callback is handed (its name
        // is borrowed from the lending iterator, so it must be copied out here).
        entries.clear();
        let listing_ok = vol
            .enumerate(&path, |name, is_dir, len| {
                if let Some(ext) = filter
                    && !is_dir
                    && !ext_matches(name, ext)
                {
                    return;
                }
                if entries.is_full() {
                    return;
                }
                let mut nm = heapless::String::new();
                for c in name.chars() {
                    if nm.push(c).is_err() {
                        break;
                    }
                }
                let _ = entries.push(BrowseEntry {
                    name: nm,
                    is_dir,
                    len,
                });
            })
            .is_ok();

        // Build the listing as a menu document and run it. Scoped so `lines` -- which
        // borrows `path` (the title) and `entries` (the names) -- is dropped before the
        // navigation below mutates `path`.
        let exit = {
            use catcard_ui::scroll::Line as DLine;
            let header: &str = if path.is_empty() { title } else { &path };
            let mut lines: heapless::Vec<DLine, { BROWSE_ENTRIES + 3 }> = heapless::Vec::new();
            let _ = lines.push(DLine::title(header));
            if !path.is_empty() {
                let _ = lines
                    .push(DLine::item("Parent", BROWSE_PARENT).with_icon(&catcard_ui::icons::BACK));
            }
            if !listing_ok {
                let _ = lines.push(DLine::body("(could not read)").centered());
            } else if entries.is_empty() {
                let _ = lines.push(DLine::body("(empty)").centered());
            }
            for (i, e) in entries.iter().enumerate() {
                let icon = if e.is_dir {
                    &catcard_ui::icons::FOLDER
                } else {
                    &catcard_ui::icons::FILE
                };
                let _ = lines.push(DLine::item(&e.name, i as u32).with_icon(icon));
            }
            show_doc(ui, &lines, false, false)
        };

        match exit {
            // Back out one level, or leave the browser at the root.
            DocExit::Cancelled | DocExit::Confirmed => {
                if path.is_empty() {
                    return None;
                }
                pop_segment(&mut path);
            }
            DocExit::Selected(BROWSE_PARENT) => pop_segment(&mut path),
            DocExit::Selected(idx) => {
                let e = &entries[idx as usize];
                if e.is_dir {
                    let _ = path.push('/');
                    let _ = path.push_str(&e.name);
                } else {
                    let mut full: heapless::String<BROWSE_PATH_MAX> = heapless::String::new();
                    let _ = full.push_str(&path);
                    let _ = full.push('/');
                    let _ = full.push_str(&e.name);
                    if file_info(ui, &e.name, e.len, pick) && pick {
                        return Some(full);
                    }
                }
            }
        }
    }
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

/// Split-view geometry: one framed bit field per source, stacked -- SE1, SE2, then the
/// STM32's own TRNG. Each field is `RNG_FW` x `RNG_FH` pixels with its inner top-left at
/// (`RNG_FX`, `RNG_FIELD_Y[i]`), a header line eight pixels above it, and the three share
/// the 64-pixel height in equal bands.
const RNG_FX: usize = 2;
const RNG_FW: usize = 122;
const RNG_FH: usize = 11;
/// Inner top of each source's field. Bands of 20 px: header at `y-8`, frame `y-1`, field
/// `y..y+RNG_FH`, bottom border `y+RNG_FH`. The last ends at 59, inside 64.
const RNG_FIELD_Y: [usize; 3] = [8, 28, 48];
/// Sources shown, in band order.
const RNG_SOURCES: usize = 3;
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
fn analyze_rng(gate: &Callgate, ui: &mut Ui<'_>) {
    use crate::trng::Kind;

    // Three bands: up to two of the board's other generators, then the chip's own TRNG,
    // which every board has and which is the one the mk3's pool actually runs on. The
    // bands come from the same source list boot and New wallet draw from, so this screen
    // shows what a seed is made of rather than its own idea of the board.
    let others: heapless::Vec<Kind, 4> = crate::trng::kinds()
        .into_iter()
        .filter(|&k| k != Kind::Chip)
        .collect();
    let bands: [Option<Kind>; RNG_SOURCES] = [
        others.first().copied(),
        others.get(1).copied(),
        Some(Kind::Chip),
    ];
    let mut trngs = crate::trng::Trngs::new(Some(gate));

    // Everything below is kept per source, so a fault in one is never masked by another:
    // its own histogram (for entropy), its own bounded total, its own lifetime count (for
    // the readout), and its own ring of recent bytes (for the bits).
    let mut hist = [[0u32; 256]; RNG_SOURCES];
    let mut total = [0u64; RNG_SOURCES];
    let mut seen = [0u64; RNG_SOURCES];
    let mut ring = [[0u8; RNG_RING]; RNG_SOURCES];
    let mut ring_at = [0usize; RNG_SOURCES];

    // Recompute the entropy figures at ~5 Hz so the digits are readable.
    // SAFETY: reads the RCC config only.
    let hz = unsafe { catcard_hal::clock::hclk_hz() };
    let period = (hz / 5).max(1);
    let mut last_h = catcard_hal::dwt::cycles();
    let mut h_text: [Line; RNG_SOURCES] = core::array::from_fn(|_| Line::new());
    for h in h_text.iter_mut() {
        let _ = h.push_str("--");
    }
    let mut chi2 = [0.0f32; RNG_SOURCES];

    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();

    loop {
        // One call per source per frame: at most 32 bytes each, and each field is sized
        // so a few frames turn it over completely. USB is polled here, not interrupt-
        // driven, and the frame is dominated by waiting on the elements, so it is pumped
        // before every blocking read (the read runs in the bootloader and cannot itself
        // be interrupted) and once more after the flush below. Pumping only once a frame
        // would leave the bus deaf through the slow parts -- which is most of the frame.
        // 32 bytes a band a frame: what a secure element answers per call, and a small
        // enough read that the far faster chip does not swamp the frame.
        for (i, kind) in bands.iter().enumerate() {
            let Some(kind) = kind else { continue };
            let _ = usbtask::pump();
            let mut buf = [0u8; 32];
            if let Some(n) = trngs.read(*kind, &mut buf) {
                for &b in &buf[..n] {
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
        for i in 0..RNG_SOURCES {
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
            for i in 0..RNG_SOURCES {
                h_text[i].clear();
                let _ = write!(h_text[i], "{:.2}", shannon_bits(&hist[i], total[i]));
                chi2[i] = chi2_uniform(&hist[i], total[i]);
            }
        }

        let mut fb = Mono128x64::new();
        for (i, kind) in bands.iter().enumerate() {
            let Some(kind) = kind else {
                // A band this board has nothing for says so, instead of an empty field that
                // looks like a dead generator.
                let f = &misc4x6::FONT;
                let y = RNG_FIELD_Y[i] - 8;
                draw_text(&mut fb, f, 1, y, "--");
                draw_text(&mut fb, f, 16, y, "no other generator here");
                if i == 0 {
                    draw_text(&mut fb, f, 104, y, "x=exit");
                }
                continue;
            };
            draw_se_view(
                &mut fb,
                RNG_FIELD_Y[i],
                kind.label(),
                &h_text[i],
                chi2[i],
                seen[i],
                &ring[i],
                i == 0, // the exit hint sits on the first band only
            );
        }
        display::show_mono(ui.panel, &fb);
        let _ = usbtask::pump();

        crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
        if keys
            .iter()
            .any(|k| matches!(k, Key::Cancel | Key::Digit(7)))
        {
            return;
        }
    }
}

/// Draw a seed from the hardware TRNGs and show its words -- a verification tool, not a
/// wallet. Nothing is stored; it lets the owner see the elements and the chip TRNG
/// produce fresh, varied words, which is the whole point of this project. Shown through
/// the same large-font, emissions-scrambled pager the real backup uses.
fn view_trng_words(gate: &Callgate, ui: &mut Ui<'_>) {
    use catcard_entropy::EntropyPool;
    use catcard_wallet::bip39::Mnemonic;
    use zeroize::Zeroize;

    // A fresh pool, filled only from the hardware sources -- no boot material, no user
    // entropy -- so the words are exactly what the TRNGs produce right now.
    let mut pool = EntropyPool::new(crate::entropy_policy());

    // The same collection effort as generating a real seed, from the same sources: a full
    // byte target from each, and a pause so the counts are legible. A "watch the generator
    // work" screen that finished in a blink would be reading a handful of bytes and calling
    // it done -- which is exactly the shortcut this project exists to replace, so it is not
    // one this screen is allowed to take either.
    const TARGET: usize = 512;
    const MAX_PASSES: usize = 160;
    const STEP_PAUSE_CYCLES: u32 = 4_000_000;

    let mut trngs = crate::trng::Trngs::new(Some(gate));
    let mut read: heapless::Vec<(crate::trng::Kind, usize), 4> =
        crate::trng::kinds().iter().map(|&k| (k, 0usize)).collect();
    for _ in 0..MAX_PASSES {
        if read.iter().all(|&(_, n)| n >= TARGET) {
            break;
        }
        for entry in read.iter_mut() {
            if entry.1 >= TARGET {
                continue;
            }
            let _ = usbtask::pump();
            let mut buf = [0u8; 64];
            if let Some(n) = trngs.read(entry.0, &mut buf)
                && n > 0
            {
                pool.add(entry.0.source(), &buf[..n]);
                entry.1 += n;
            }
            buf.zeroize();
        }

        let mut counts = Line::new();
        for (i, &(kind, n)) in read.iter().enumerate() {
            let _ = write!(
                counts,
                "{}{} {n}",
                if i > 0 { " " } else { "" },
                kind.label()
            );
        }
        let mut bits = Line::new();
        let _ = write!(bits, "{} bits", pool.credited_bits());
        message(ui.panel, "Reading TRNGs", &counts, &bits);
        catcard_hal::dwt::delay_cycles(STEP_PAUSE_CYCLES);
    }

    if pool.check().is_err() {
        message(
            ui.panel,
            "TRNG words",
            "TRNG check failed",
            "any key to go back",
        );
        wait_for_any_key(ui);
        return;
    }

    let mut entropy = [0u8; 32];
    // Masked: these words are only displayed, never a device key, but it is the same draw
    // and the same encoding a wallet goes through, and one rule is easier to keep than two.
    let mnemonic = crate::keywork::run(|kw| {
        let drawn = pool.draw(&mut entropy);
        let m = drawn
            .ok()
            .and_then(|()| Mnemonic::from_entropy(&entropy, kw).ok());
        entropy.zeroize();
        m
    });
    let Some(mnemonic) = mnemonic else {
        message(
            ui.panel,
            "TRNG words",
            "could not draw",
            "any key to go back",
        );
        wait_for_any_key(ui);
        return;
    };

    // Verification only -- never stored -- but scramble the emissions all the same, since
    // these are valid seed words on screen.
    let texts = word_texts(&mnemonic);
    let mut lines: heapless::Vec<catcard_ui::scroll::Line, 27> = heapless::Vec::new();
    let _ = lines.push(catcard_ui::scroll::Line::title("TRNG words"));
    let _ = lines.push(
        catcard_ui::scroll::Line::body("not saved")
            .small()
            .centered(),
    );
    for s in &texts {
        let _ = lines.push(catcard_ui::scroll::Line::body(s).secret());
    }
    show_doc(ui, &lines, true, false);
}

/// Write `s` into `out`, eliding the middle to `...` when it is wider than `cols`.
///
/// The start and end survive because those are the parts an eye actually checks against a
/// watch-only wallet; the dropped middle is the part nobody reads character by character.
/// The strings this is used on -- bech32 and base58 addresses -- are ASCII, so byte
/// offsets are character offsets and the slicing is on boundaries.
fn ellipsize_middle(s: &str, cols: usize, out: &mut Line) {
    // Fits as-is, or too narrow for an elision to leave anything useful: show the head.
    if s.len() <= cols || cols < 7 {
        let _ = out.push_str(&s[..s.len().min(cols.max(1))]);
        return;
    }
    let keep = cols - 3; // three columns go to the "..."
    let head = keep.div_ceil(2); // the front gets the odd character
    let tail = keep - head;
    let _ = out.push_str(&s[..head]);
    let _ = out.push_str("...");
    let _ = out.push_str(&s[s.len() - tail..]);
}

/// Walk the receive addresses of the stored wallet.
///
/// BIP-84 native segwit (`m/84'/0'/0'/0/i`) on mainnet -- the modern default -- one
/// address at a time, the down arrow forward and the up arrow back, as the pager does. The
/// point of showing them here is verification: an owner can check that an address the
/// device displays matches what a watch-only wallet derives from the same account, before
/// trusting it with funds.
///
/// The secret is fetched, turned into a master key, and reduced to the external-chain key
/// once; only the final `/i` step runs per address. The seed and the secret are wiped as
/// soon as that key exists -- nothing secret outlives the setup, and the chain key kept
/// here is a public-derivation parent, not the seed.
/// PBKDF2 rounds run between two redraws of the busy bar.
///
/// The whole stretch is 2048 rounds and takes about 1.7 s on an mk4, so 64 rounds is
/// roughly 50 ms of masked work per frame -- fast enough that the bar reads as moving,
/// long enough that the redraws stay a small fraction of the job. It is a fixed number by
/// design: a slice length that varied with the seed is exactly what the masking is for.
const STRETCH_SLICE: u32 = 64;

/// The address types the explorer walks, in the order the left/right arrows move through
/// them. Native segwit leads because it is what this wallet derives by default.
const PROTOCOLS: [catcard_wallet::address::AddressKind; 4] = [
    catcard_wallet::address::AddressKind::P2wpkh,
    catcard_wallet::address::AddressKind::P2tr,
    catcard_wallet::address::AddressKind::P2shP2wpkh,
    catcard_wallet::address::AddressKind::P2pkh,
];

/// What to call each on screen.
fn kind_name(kind: catcard_wallet::address::AddressKind) -> &'static str {
    use catcard_wallet::address::AddressKind;
    match kind {
        AddressKind::P2wpkh => "Native segwit",
        AddressKind::P2tr => "Taproot",
        AddressKind::P2shP2wpkh => "Nested segwit",
        AddressKind::P2pkh => "Legacy",
    }
}

/// `m/purpose'/0'/0'/0` as an extended **public** key: the receive chain every address of
/// that type hangs off.
///
/// Public on purpose. Receive addresses are non-hardened children of this level, so they
/// derive from the public key alone -- which means the private keys can all be dropped
/// before the masked region closes, and the browsing loop afterwards holds no key material
/// and needs no masking at all.
/// One level at a time, with `busy` ticked between them: each hardened step is an
/// HMAC-SHA512 and a point multiplication, about a tenth of a second of masked work, so the
/// four of them are a visible pause and the bar should keep moving across it.
fn receive_chain(
    master: &catcard_wallet::bip32::ExtendedPrivKey,
    kind: catcard_wallet::address::AddressKind,
    busy: &mut Working<'_>,
    panel: &mut display::Panel,
) -> Option<catcard_wallet::bip32::ExtendedPubKey> {
    use catcard_wallet::bip32::ChildNumber;
    let steps = [
        ChildNumber::hardened(kind.bip44_purpose()).ok()?,
        ChildNumber::hardened(0).ok()?,
        ChildNumber::hardened(0).ok()?,
        ChildNumber::normal(0).ok()?,
    ];
    // The intermediate private keys never leave this function; each masked region derives
    // the next level and drops the previous one, and the last hop keeps only the public
    // half. Splitting the path this way exposes which level is running -- a fixed,
    // published shape -- and nothing about the key.
    let mut here = crate::keywork::run(|kw| master.derive_child(steps[0], kw).ok())?;
    for step in &steps[1..] {
        busy.tick(panel);
        here = crate::keywork::run(|kw| here.derive_child(*step, kw).ok())?;
    }
    busy.tick(panel);
    Some(crate::keywork::run(|kw| here.to_extended_pub(kw)))
}

/// Which way of asking the panel to scroll by itself actually moves the bar.
///
/// The busy bar crosses a secure-element call only if the panel controller scrolls it
/// unaided, and that has not been seen working on every board. Three labelled phases, two
/// seconds each, with the CPU doing nothing that could draw:
///
/// 1. the SSD1306 scroll setup this firmware sends today (six parameters);
/// 2. the longer form some SSD1306-family controllers take, with start and end columns;
/// 3. the CPU-ticked bar, as a control that must always move.
///
/// Whichever moves decides what `scroll_busy_bar` sends. A full redraw between phases puts
/// the panel back in a known state whatever the previous command did.
fn scroll_test(ui: &mut Ui<'_>) {
    #[cfg(not(feature = "board-q1"))]
    {
        use catcard_ui::DisplayBus;
        // SAFETY: reads RCC only.
        let per_ms = (unsafe { catcard_hal::clock::hclk_hz() } / 1000).max(1);
        let hold = |ms: u32| catcard_hal::dwt::delay_cycles(ms * per_ms);

        let phases: [(&str, &[u8]); 2] = [
            (
                "1 of 3: short form",
                &[0x2E, 0x26, 0x00, 7, 0x07, 7, 0x00, 0xFF, 0x2F],
            ),
            (
                "2 of 3: long form",
                &[0x2E, 0x26, 0x00, 7, 0x07, 7, 0x00, 0x00, 0x7F, 0x2F],
            ),
        ];
        for (label, bytes) in phases {
            display::draw(ui.panel, |c| {
                catcard_ui::widgets::working(c, &display::LAYOUT, "Scroll test", label, 0);
            });
            let _ = ui.panel.bus_mut().command(bytes);
            crate::catlog!("scroll test: {}", label);
            hold(2000);
        }
        let mut busy = Working::new(ui.panel, "Scroll test", "3 of 3: CPU ticks");
        for _ in 0..40 {
            hold(50);
            busy.tick(ui.panel);
        }
        message(
            ui.panel,
            "Scroll test",
            "which moved?",
            "any key to go back",
        );
        wait_for_any_key(ui);
    }
    #[cfg(feature = "board-q1")]
    {
        // The GPU co-processor's bar: the screen is drawn, the bus handed over, and the CPU
        // then does nothing that could draw for three seconds, as in a callgate call.
        // SAFETY: reads RCC only.
        let per_ms = (unsafe { catcard_hal::clock::hclk_hz() } / 1000).max(1);
        message(ui.panel, "Scroll test", "GPU bar, 3 seconds", "");
        display::scroll_busy_bar(ui.panel);
        crate::catlog!("scroll test: gpu bar");
        catcard_hal::dwt::delay_cycles(3000 * per_ms);
        message(
            ui.panel,
            "Scroll test",
            "did a bar move at the bottom?",
            "any key to go back",
        );
        wait_for_any_key(ui);
    }
}

/// The screen for a wait the CPU cannot draw through: a callgate call, where interrupts are
/// masked and the firewall resets the CPU if one lands inside.
///
/// On an OLED the bar goes up and the controller keeps it moving (see
/// [`display::scroll_busy_bar`]). On the Q1 the text goes up without a bar of ours, and the
/// GPU co-processor draws its own moving one along the bottom -- or, where it is not in use,
/// nothing does: a bar that sits still for two seconds claims progress that is not being
/// shown, which is worse than a plain line saying what the device is waiting for.
pub(crate) fn blocking_screen(panel: &mut display::Panel, head: &str, note: &str) {
    #[cfg(not(feature = "board-q1"))]
    {
        display::draw(panel, |c| {
            catcard_ui::widgets::working(c, &display::LAYOUT, head, note, 0);
        });
        display::scroll_busy_bar(panel);
    }
    #[cfg(feature = "board-q1")]
    {
        message(panel, head, note, "");
        if display::GPU_BAR_ON_BLOCKING {
            display::scroll_busy_bar(panel);
        }
    }
}

/// The screen shown while something slow runs: a heading, a note, and a bar that moves.
///
/// The bar is the whole point. Every computation behind one of these screens runs with
/// interrupts masked, so the panel cannot repaint while a slice of it is in flight -- and a
/// device that holds one frame for two seconds is a device the owner reads as crashed.
/// Nothing here knows how far along the work is; it only knows that it was asked to tick,
/// which is exactly what it shows.
pub(crate) struct Working<'a> {
    head: &'a str,
    note: Line,
    phase: u32,
}

impl<'a> Working<'a> {
    /// Draw the first frame. `note` is formatted by the caller, so a screen can say which
    /// address type it is deriving without this owning that vocabulary.
    pub(crate) fn new(panel: &mut display::Panel, head: &'a str, note: &str) -> Self {
        let mut w = Self {
            head,
            note: Line::new(),
            phase: 0,
        };
        let _ = w.note.push_str(note);
        w.draw(panel);
        w
    }

    /// Advance the bar one step and redraw.
    pub(crate) fn tick(&mut self, panel: &mut display::Panel) {
        self.phase = self.phase.wrapping_add(1);
        self.draw(panel);
    }

    fn draw(&self, panel: &mut display::Panel) {
        let (head, note, phase) = (self.head, self.note.as_str(), self.phase);
        display::draw(panel, |c| {
            catcard_ui::widgets::working(c, &display::LAYOUT, head, note, phase);
        });
    }
}

/// The two faces the QR screen offers its text, largest first.
fn qr_faces() -> (
    &'static dyn catcard_ui::face::Face,
    &'static dyn catcard_ui::face::Face,
) {
    (display::FONTS.body, display::FONTS.small)
}

/// Show an address as a QR code beside the address itself, until a key is pressed.
///
/// The QR is for a wallet to scan; the text beside it, in blocks of four, is for a person to
/// compare against what their wallet shows. Both carry the same characters: the text is the
/// payload minus the BIP-21 scheme, upper-cased bech32 included, so what is read out loud is
/// what was encoded. [`address::qr_payload`] decides the payload's shape -- upper-case and
/// bare for bech32, `bitcoin:` and untouched for base58.
///
/// Encoding is `anyd`'s heap-free path, so nothing here allocates. The one choice left is
/// error correction: M, dropping to L only where M would leave one pixel a module on this
/// panel and L would not. On a 64-row OLED that is the difference between a symbol a phone
/// reads and a grey square.
///
/// Version 8 is the largest symbol the buffers hold: 49 modules, already more than a 64-row
/// panel can draw at one pixel each and far more than any address needs.
fn address_qr(ui: &mut Ui<'_>, address: &str, kind: catcard_wallet::address::AddressKind) {
    use anyd::codes::qr::{EcLevel, QrEncoder, Version};
    use catcard_wallet::address;

    const MAX_VERSION: Version = match Version::new(8) {
        Some(v) => v,
        None => unreachable!(),
    };
    const BUF: usize = QrEncoder::buffer_len(MAX_VERSION);

    let mut payload = [0u8; address::MAX_QR_PAYLOAD];
    let Some(payload) = address::qr_payload(address, kind, &mut payload) else {
        message(ui.panel, "QR", "address not encodable", "");
        wait_for_any_key(ui);
        return;
    };
    let shown = address::qr_address(payload);

    let mut scratch = [0u8; BUF];
    let mut storage = [0u8; BUF];
    let encoder = QrEncoder::new();
    // Pixels per module this level would get, or 0 if it does not encode or does not fit.
    // Scoped so the two buffers are reused rather than held twice over.
    let pixels = |level, scratch: &mut [u8; BUF], storage: &mut [u8; BUF]| {
        encoder
            .encode_text_into(payload.as_bytes(), level, scratch, storage)
            .ok()
            .and_then(|(grid, _)| {
                catcard_ui::widgets::qr_text_fit(
                    qr_faces(),
                    display::FONTS.gap,
                    grid.width(),
                    shown.len(),
                    display::SCREEN_W,
                    display::SCREEN_H,
                )
            })
            .map_or(0, |fit| fit.scale)
    };

    let medium = pixels(EcLevel::M, &mut scratch, &mut storage);
    let level = if medium > 1 || pixels(EcLevel::L, &mut scratch, &mut storage) <= medium {
        EcLevel::M
    } else {
        EcLevel::L
    };

    let Ok((grid, _meta)) =
        encoder.encode_text_into(payload.as_bytes(), level, &mut scratch, &mut storage)
    else {
        message(ui.panel, "QR", "address too long", "");
        wait_for_any_key(ui);
        return;
    };

    let mut drawn = false;
    display::draw(ui.panel, |c| {
        drawn = catcard_ui::widgets::qr_with_text(
            c,
            qr_faces(),
            display::FONTS.gap,
            grid.width(),
            |x, y| grid.get(x, y),
            shown,
        )
        .is_some()
            // No arrangement fits the text: the symbol alone still beats nothing, since it
            // is the half a wallet reads.
            || catcard_ui::widgets::qr(c, grid.width(), |x, y| grid.get(x, y));
    });
    if !drawn {
        message(ui.panel, "QR", "too big for this panel", "");
    }
    wait_for_any_key(ui);
}

fn address_explorer(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    use catcard_callgate::pin::bip39_entropy;
    use catcard_wallet::address;
    use catcard_wallet::bip32::{ChildNumber, ExtendedPrivKey, Network};
    use catcard_wallet::bip39::{Mnemonic, SEED_LEN, Stretch};
    use zeroize::Zeroize;

    fn fail(ui: &mut Ui<'_>, why: &str) {
        message(ui.panel, "Addresses", why, "any key to go back");
    }

    // Say so before asking for the secret, not after. The fetch is one callgate call: the
    // bootloader runs the PIN key-stretch inside the secure element -- about 1.6 s on an
    // mk4 -- and the firewall resets the CPU if an interrupt lands in it, so the firmware
    // cannot repaint across it. The panel can, where its controller scrolls on its own.
    blocking_screen(ui.panel, "Addresses", "reading seed");
    let pin_gate = crate::pinentry::BootloaderGate::new(gate);
    let mut secret = match login.fetch_secret(&pin_gate) {
        Ok(s) => s,
        Err(_) => {
            fail(ui, "could not read seed");
            wait_for_any_key(ui);
            return;
        }
    };

    // Copy the entropy out into an owned buffer so the secret can be wiped immediately;
    // only a BIP-39 wallet has one, and an empty slot or an imported xprv is not
    // something this screen can enumerate.
    let mut ent = [0u8; 32];
    let ent_len = match bip39_entropy(&secret) {
        Some(e) if e.len() <= ent.len() => {
            ent[..e.len()].copy_from_slice(e);
            e.len()
        }
        _ => {
            secret.zeroize();
            fail(ui, "no BIP39 seed here");
            wait_for_any_key(ui);
            return;
        }
    };
    secret.zeroize();

    // Seed -> master -> the external receive chain m/84'/0'/0'/0. Empty passphrase: the
    // plain wallet; passphrase wallets are a separate feature. Done once, then the seed
    // material is gone and only the chain key (a derivation parent) remains.
    //
    // Turning the words into a seed is PBKDF2-HMAC-SHA512 run 2048 times -- about a second
    // of hashing by design -- and the key derivation adds elliptic-curve work on top. That
    // is far too long to hold one frame, so it runs in slices with the busy bar stepped
    // between them: masked while a slice is in flight, repainting in the gaps.
    let mut busy = Working::new(ui.panel, "Addresses", "stretching seed");
    let stretch = crate::keywork::run(|kw| {
        let mnemonic = Mnemonic::from_entropy(&ent[..ent_len], kw);
        ent.zeroize();
        let Ok(mnemonic) = mnemonic else {
            return Err("seed did not decode");
        };
        Stretch::begin(&mnemonic, "", kw).map_err(|_| "key derivation failed")
    });
    let master = stretch.and_then(|mut stretch| {
        // The 2048 PBKDF2 rounds run a slice at a time so the bar can move between them.
        // The slices end at round counts fixed here, never at anything derived from the
        // seed, so what a watching host can see is the iteration count BIP-39 publishes.
        while !crate::keywork::run(|kw| stretch.step(STRETCH_SLICE, kw)) {
            busy.tick(ui.panel);
        }
        crate::keywork::run(|kw| {
            let mut seed = [0u8; SEED_LEN];
            stretch.finish(&mut seed, kw);
            let master = ExtendedPrivKey::from_seed(&seed, Network::Mainnet, kw).ok();
            seed.zeroize();
            master.ok_or("key derivation failed")
        })
    });
    // The master key is kept for as long as this screen is open, so a type can be derived
    // when it is first asked for instead of paying for all four up front. That is a
    // deliberate trade: a private key is resident while the screen waits for keypresses.
    // It is the master alone -- each chain key is derived inside a masked region and
    // dropped there, leaving only its public half -- and it is zeroized on the way out,
    // which `ExtendedPrivKey`'s `ZeroizeOnDrop` does at every return below.
    let master = match master {
        Ok(master) => master,
        Err(why) => {
            fail(ui, why);
            wait_for_any_key(ui);
            return;
        }
    };
    let mut chains: [Option<catcard_wallet::bip32::ExtendedPubKey>; PROTOCOLS.len()] =
        [None; PROTOCOLS.len()];

    // How many characters of the address fit on one line **in the large face**, asked of the
    // renderer rather than worked out from the panel width: it keeps a gutter for the scroll
    // arrows and clips text at it, so one column too many leaves the last glyph sliced down
    // the middle -- and half a character at the end of an address is indistinguishable from
    // a different one. The address is longer than the line either way, so it is shown
    // start...end (see `ellipsize_middle`): the two ends are what an eye compares against a
    // watch-only wallet, and one clean line beats a wrap.
    let cols = catcard_ui::scroll::text_cols(
        &display::FONTS,
        catcard_ui::scroll::Size::Body,
        display::SCREEN_W,
    );
    let mut index: u32 = 0;
    let mut proto = 0usize;
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        let kind = PROTOCOLS[proto];
        // First time this type is asked for: derive its receive chain, masked, and keep
        // only the public half. Announced first -- it is about half a second during which
        // nothing can repaint, and an unexplained pause is what made the old entry feel
        // broken.
        if chains[proto].is_none() {
            let mut busy = Working::new(ui.panel, "Deriving", kind_name(kind));
            chains[proto] = receive_chain(&master, kind, &mut busy, ui.panel);
        }

        let mut path = Line::new();
        let _ = write!(
            path,
            "#{index}  m/{}h/0h/0h/0/{index}",
            kind.bip44_purpose()
        );

        let mut buf = [0u8; address::MAX_ADDRESS_LEN];
        // Public derivation from the chain's extended public key: no private key is
        // involved, so this needs no masked region and costs the host nothing to watch.
        // The index moves with the type, so the same position can be compared across them.
        let addr = chains[proto].and_then(|chain| {
            ChildNumber::normal(index)
                .ok()
                .and_then(|c| chain.derive_child(c).ok())
                .and_then(|k| address::encode(kind, Network::Mainnet, &k.public_key, &mut buf).ok())
        });
        let mut shown = Line::new();
        match addr {
            Some(n) => {
                let s = core::str::from_utf8(&buf[..n]).unwrap_or("");
                ellipsize_middle(s, cols, &mut shown);
            }
            // A child index that lands on an invalid scalar is vanishingly rare, but the
            // screen must not lie about it: show a gap rather than a wrong address.
            None => {
                let _ = shown.push_str("(no address)");
            }
        }
        // Name the keys the way the owner sees them. `5`/`8`/`7`/`9` is what the firmware
        // reads, but the keypad prints arrows on those keys and the Q1 has real arrow keys,
        // so digits here would send someone hunting for a number that is not the point.
        let mut key_hint = Line::new();
        let _ = write!(
            key_hint,
            "{} QR   {} back",
            display::CONFIRM_KEY,
            display::CANCEL_KEY
        );

        // The address in the large face, everything else in the small one. It is the only
        // thing on the screen worth reading carefully, and the elision costs less than the
        // squint did -- the whole of it, in blocks of four, is one keypress away.
        let mut doc: heapless::Vec<catcard_ui::scroll::Line, 8> = heapless::Vec::new();
        let _ = doc.push(catcard_ui::scroll::Line::title(kind_name(kind)));
        let _ = doc.push(catcard_ui::scroll::Line::body(path.as_str()).small());
        let _ = doc.push(catcard_ui::scroll::Line::body(shown.as_str()));
        let _ = doc.push(catcard_ui::scroll::Line::body("up/down address").small());
        let _ = doc.push(catcard_ui::scroll::Line::body("left/right type").small());
        let _ = doc.push(catcard_ui::scroll::Line::body(key_hint.as_str()).small());
        let view = catcard_ui::scroll::ScrollView::build(
            &doc,
            display::SCREEN_W,
            display::SCREEN_H,
            display::FONTS,
        );
        display::draw(ui.panel, |c| catcard_ui::scroll::render(c, &view));

        wait_for_release(ui);
        'wait: loop {
            let _ = usbtask::pump();
            crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
            for k in keys.iter() {
                match k {
                    Key::Cancel => return,
                    // The address as a QR: what the owner came here to compare against a
                    // watch-only wallet, without reading out 42 characters.
                    Key::Confirm => {
                        if let Some(n) = addr {
                            address_qr(ui, core::str::from_utf8(&buf[..n]).unwrap_or(""), kind);
                        }
                        break 'wait;
                    }
                    Key::Digit(8) => {
                        index = index.saturating_add(1);
                        break 'wait;
                    }
                    Key::Digit(5) => {
                        index = index.saturating_sub(1);
                        break 'wait;
                    }
                    // Left and right walk the address types, wrapping both ways.
                    Key::Digit(9) => {
                        proto = (proto + 1) % PROTOCOLS.len();
                        break 'wait;
                    }
                    Key::Digit(7) => {
                        proto = (proto + PROTOCOLS.len() - 1) % PROTOCOLS.len();
                        break 'wait;
                    }
                    _ => {}
                }
            }
            catcard_hal::dwt::delay_cycles(usbtask::IDLE_PAUSE_CYCLES);
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
pub(crate) fn wait_for_release(ui: &mut Ui<'_>) {
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        let _ = usbtask::pump();
        crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
        if ui.pad.held_count() == 0 {
            return;
        }
        catcard_hal::dwt::delay_cycles(usbtask::IDLE_PAUSE_CYCLES);
    }
}

/// Block until something is pressed. Used only by screens that have already said so.
pub(crate) fn wait_for_any_key(ui: &mut Ui<'_>) {
    wait_for_release(ui);
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        // Service USB while this message is up, for the same reason as the main loop:
        // a polled bus that no one pumps is a device the host cannot reach.
        let _ = usbtask::pump();
        crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
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
fn confirmed(ui: &mut Ui<'_>) -> bool {
    // The key that brought us to this question must not also answer it. That matters
    // most here: one of the questions this asks destroys a stored wallet.
    wait_for_release(ui);
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        let _ = usbtask::pump();
        crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
        for k in keys.iter() {
            match k {
                Key::Confirm => return true,
                Key::Cancel => return false,
                Key::Digit(_) => {}
                Key::Char(_) => {}
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
    /// Bytes each of this board's sources has answered with during *this* generation.
    read: heapless::Vec<(crate::trng::Kind, usize), 4>,
    /// Credited bits and distinct hardware TRNGs the pool counts right now (this includes
    /// what boot already collected -- the chip, the elements and startup timing).
    bits: u32,
    chips: u32,
    /// What this board's policy demands before a seed may be drawn at all.
    need_bits: u32,
    need_chips: u32,
}

impl Gathered {
    fn lines(&self, out: &mut heapless::Vec<Line, 6>) {
        for &(kind, n) in &self.read {
            let mut l = Line::new();
            // A source mixed in but not trusted to count says so, rather than letting its
            // bytes read as if they carried the seed.
            let _ = write!(
                l,
                "{:<3}  read {n:5} bytes{}",
                kind.label(),
                if kind.credited() { "" } else { " mixed" }
            );
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

fn gathering(panel: &mut display::Panel, g: &Gathered, pct: u8) {
    let mut lines: heapless::Vec<Line, 6> = heapless::Vec::new();
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
    let mut lines: heapless::Vec<Line, 6> = heapless::Vec::new();
    g.lines(&mut lines);
    info(
        panel,
        if passed {
            // Just the verdict, like the failure title: "Entropy OK, any key" is 19
            // characters and the 7px title font clips the last one on a 128px panel
            // ("...any ke"). The screen waits for a key regardless.
            "Entropy OK"
        } else {
            "NOT ENOUGH ENTROPY"
        },
        &lines,
    );
}

/// Optional keypad top-up: the user mashes digits and both the value and its timing feed
/// the pool.
///
/// Each press contributes two independent things. The **digit** is credited like a die's
/// face -- one of about ten symbols, [`Source::UserKeypad`] at 3 bits a byte -- so a
/// hundred taps is a few hundred credited bits, enough to clear the 256-bit bar on its
/// own (the ≥2-hardware-TRNG bar is separate and this does not touch it). The **cycle
/// counter** at the instant of the press goes in through [`Source::UserTiming`]: a human
/// press makes its low bits unpredictable, which is real if smaller entropy and also the
/// point at which a fast counter becomes a usable source.
///
/// There is no cap -- it all folds into the one SHA-512 sponge -- and the screen shows
/// the running total of credited bits from these presses. It is skippable: confirm or
/// cancel finishes, and the pool has already met its policy from the TRNGs. Waiting for
/// release between presses keeps a held key to one sample per press.
///
/// [`Source::UserKeypad`]: catcard_entropy::Source::UserKeypad
/// [`Source::UserTiming`]: catcard_entropy::Source::UserTiming
fn key_mash(ui: &mut Ui<'_>, pool: &mut catcard_entropy::EntropyPool) {
    let start_bits = pool.credited_bits();
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        let mut n = Line::new();
        let _ = write!(
            n,
            "{} bits added",
            pool.credited_bits().saturating_sub(start_bits)
        );
        message(ui.panel, "Add entropy", &n, "digits add, y=done");

        wait_for_release(ui);
        loop {
            let _ = usbtask::pump();
            crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
            if !keys.is_empty() {
                break;
            }
        }
        for k in keys.iter() {
            match k {
                // A deliberate key ends it; every digit adds the moment it landed.
                Key::Confirm | Key::Cancel => return,
                Key::Digit(d) => {
                    pool.add(catcard_entropy::Source::UserKeypad, &[*d]);
                    pool.add_timing(catcard_hal::dwt::cycles());
                }
                Key::Char(_) => {}
            }
        }
    }
}

/// True while no single symbol dominates the run: the catalogue's frequency gate.
///
/// A die stuck on one face or a coin that always reads heads is a pattern, not entropy,
/// and crediting it would be exactly the mistake the pool exists to prevent. `counts` is
/// indexed by digit value; `total` is the run length; `max_freq_pct` is the ceiling any
/// one symbol may occupy (30 for dice, 65 for coin, per `firmware-features.md §2`).
fn unbiased(counts: &[u32; 10], total: usize, max_freq_pct: u32) -> bool {
    if total == 0 {
        return false;
    }
    // Round the cap up: with 50 rolls at 30% a face is allowed 15, and 16 is the reject.
    let cap = (total as u32 * max_freq_pct).div_ceil(100);
    counts.iter().all(|&c| c <= cap)
}

/// Collect a run of user symbols from a fixed alphabet -- dice faces or coin sides -- and
/// credit their *values* to the pool, alongside the cycle counter at each press.
///
/// Two things are credited on different footings, and the distinction is the point. The
/// press *timing* (`add_timing`) goes in the instant a key lands and is always kept: a
/// human's intervals are unpredictable even when the values are not. The symbol *values*
/// (`source`) are credited only when the run clears the catalogue's gate -- long enough
/// (`min`) and unbiased ([`unbiased`]) -- because a short or lopsided run of values is a
/// pattern the pool must not count. Neither is ever a precondition for a seed; like the
/// keypad mash this only tops up a pool that has already met its policy from hardware.
#[allow(clippy::too_many_arguments)]
fn collect_rolls(
    ui: &mut Ui<'_>,
    pool: &mut catcard_entropy::EntropyPool,
    title: &str,
    prompt: &str,
    alphabet: &[u8],
    source: catcard_entropy::Source,
    min: usize,
    max_freq_pct: u32,
) {
    use zeroize::Zeroize;

    // 512 symbols is well past either minimum (50 dice, 128 coin) and there is no reason
    // to cap the volume lower -- the pool absorbs it all into one hash. A run that fills
    // the buffer stops taking values but keeps mixing timing.
    let mut buf: heapless::Vec<u8, 512> = heapless::Vec::new();
    let mut counts = [0u32; 10];
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    let mut warn: Option<&str> = None;
    loop {
        let ready = buf.len() >= min && unbiased(&counts, buf.len(), max_freq_pct);
        let mut a = Line::new();
        let _ = write!(a, "{} of {}", buf.len(), min);
        let hint = if let Some(w) = warn {
            w
        } else if buf.is_empty() {
            prompt
        } else if ready {
            "y=use these"
        } else {
            "more, then y"
        };
        message(ui.panel, title, &a, hint);

        wait_for_release(ui);
        loop {
            let _ = usbtask::pump();
            crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
            if !keys.is_empty() {
                break;
            }
            catcard_hal::dwt::delay_cycles(usbtask::IDLE_PAUSE_CYCLES);
        }
        warn = None;
        for k in keys.iter() {
            match k {
                Key::Confirm => {
                    if buf.len() < min {
                        // Too short to trust: keep collecting rather than credit it.
                        warn = Some("too few, keep going");
                    } else if !unbiased(&counts, buf.len(), max_freq_pct) {
                        // One symbol dominates: a pattern, not entropy. Credit nothing.
                        warn = Some("too lopsided");
                    } else {
                        pool.add(source, &buf);
                        buf.zeroize();
                        return;
                    }
                }
                // Cancel abandons this mode; the timing already mixed stays, the values
                // do not (they were never credited).
                Key::Cancel => {
                    buf.zeroize();
                    return;
                }
                Key::Digit(d) => {
                    if alphabet.contains(d) {
                        // Values only while there is room; timing every single press.
                        if buf.push(*d).is_ok() {
                            counts[*d as usize] += 1;
                        }
                        pool.add_timing(catcard_hal::dwt::cycles());
                    }
                }
                Key::Char(_) => {}
            }
        }
    }
}

/// Offer the owner a turn adding entropy of their own, in whatever form they trust: a
/// free keypad mash, dice rolls, or coin flips. Each is optional and additive -- the pool
/// has already met its policy from the hardware TRNGs (or refused outright), so none of
/// these can rescue a bad device. They only ever top up, and let a distrustful owner mix
/// in material the firmware could not have predicted.
fn add_user_entropy(ui: &mut Ui<'_>, pool: &mut catcard_entropy::EntropyPool) {
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        message(ui.panel, "Add entropy?", "1=mash 2=dice 3=coin", "y=done");
        wait_for_release(ui);
        loop {
            let _ = usbtask::pump();
            crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
            if !keys.is_empty() {
                break;
            }
            catcard_hal::dwt::delay_cycles(usbtask::IDLE_PAUSE_CYCLES);
        }
        // Take the first meaningful key of the batch, then redraw the menu.
        let mut done = false;
        for k in keys.iter() {
            match k {
                Key::Confirm | Key::Cancel => {
                    done = true;
                    break;
                }
                Key::Digit(1) => {
                    key_mash(ui, pool);
                    break;
                }
                Key::Digit(2) => {
                    // Dice: faces 1-6, at least 50 rolls, no face over 30%.
                    collect_rolls(
                        ui,
                        pool,
                        "Roll dice",
                        "keys 1-6 = roll",
                        &[1, 2, 3, 4, 5, 6],
                        catcard_entropy::Source::UserDice,
                        50,
                        30,
                    );
                    break;
                }
                Key::Digit(3) => {
                    // Coin: sides 0/1, at least 128 flips, neither side over 65%.
                    collect_rolls(
                        ui,
                        pool,
                        "Flip a coin",
                        "0=tails 1=heads",
                        &[0, 1],
                        catcard_entropy::Source::UserCoin,
                        128,
                        65,
                    );
                    break;
                }
                Key::Digit(_) => {}
                Key::Char(_) => {}
            }
        }
        if done {
            return;
        }
    }
}

/// Create a wallet: draw entropy, store it, verify it, and show the words once.
///
/// The order is the point. The secret is written **and read back before any word reaches
/// the screen**, because words shown for a seed the secure element did not keep are
/// worse than no words at all — someone copies them down and believes they have a
/// backup of a wallet that does not exist.
///
/// User-supplied entropy is *offered* -- a keypad mash after the hardware collection, see
/// [`key_mash`] -- but never *required*. The pool has already met its policy or it refuses
/// outright, and a handful of key taps cannot rescue a device whose TRNGs are unhealthy;
/// the mash only ever tops up. See `docs/SECRETS-AND-SETTINGS.md`.
// Eight arguments, and clippy is right to say so. Four of them -- panel, pad, matrix,
// drbg -- are the same cluster every action screen drags around, and the remedy is the
// one this file already uses for `Session` and `View`: give them a struct. That is a
// refactor across every screen here rather than a change to this function, so it is
// deferred deliberately and not because the lint is wrong.
#[allow(clippy::too_many_arguments)]
fn new_seed(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    pool: Option<&mut catcard_entropy::EntropyPool>,
    words: u8,
) {
    use catcard_wallet::bip39::Mnemonic;
    use zeroize::Zeroize;

    // How much entropy those words carry: 32 bytes for 24, 16 for 12. Anything else is
    // a caller bug rather than a user one, and 24 is the safe way to be wrong.
    let entropy_len = match words {
        12 => 16,
        _ => 32,
    };

    // No pool means it never met its policy at boot. That is a refusal.
    let Some(pool) = pool else {
        message(
            ui.panel,
            "No entropy",
            "the pool missed its",
            "policy at boot",
        );
        wait_for_any_key(ui);
        return;
    };

    // Overwriting a wallet that already exists is the destructive case, and this is the
    // only warning anyone gets. `zero_secret` is the bootloader's own answer about the
    // slot, not a guess of ours.
    if matches!(login.step(), catcard_pin::Step::In { zero_secret: false }) {
        ask(
            ui.panel,
            "Wallet exists",
            "a new seed DESTROYS",
            "the one stored now",
        );
        if !confirmed(ui) {
            return;
        }
    }
    let mut what = Line::new();
    let _ = write!(what, "{words} words, from this");
    ask(ui.panel, "Create wallet?", &what, "device's own TRNGs");
    if !confirmed(ui) {
        return;
    }

    // Fresh noise from both secure elements, on top of what the boot pool already
    // holds. The boot pool has met its policy or we would not be here; this is added
    // material, not a substitute for it.
    //
    // It goes through `EntropyPool` rather than into a hash of its own, because the
    // pool is what runs the health tests, keeps the sources domain-separated and
    // credits them. A side digest would mix the same bytes twice while skipping all
    // three. An element that fails its health test is mixed in but credited nothing and
    // not counted -- so if too few healthy sources remain, `draw` below refuses, which is
    // the intended outcome; a single bad element cannot by itself block a healthy pool.
    // How long to hold each step on screen. Legibility only: thirty-two counts that
    // flash past in a blink show nothing, and nobody can check a number they cannot
    // read. It contributes no entropy and must never be mistaken for doing so.
    const STEP_PAUSE_CYCLES: u32 = 4_000_000;

    let policy = crate::entropy_policy();
    let kinds = crate::trng::kinds();
    let mut g = Gathered {
        read: kinds.iter().map(|&k| (k, 0usize)).collect(),
        bits: pool.credited_bits(),
        chips: pool.hardware_sources(),
        need_bits: policy.min_bits,
        need_chips: policy.min_hw_sources,
    };

    // Every source this board can read, the same number of *bytes* from each -- not the
    // same number of turns. SE2 produces about a quarter as fast as SE1, so taking turns in
    // lockstep once collected `SE1 512 B, SE2 128 B`, which reads like a broken element and
    // is really a slower one. The chip TRNG is part of this on every board: it once sat
    // inside a check for the mk4+ callgate, and on mk3 a wallet was generated without a
    // single fresh byte from it.
    const TARGET: usize = 512;
    // Bounded, because a source that never answers must not hang a wallet. At SE2's
    // observed rate 512 bytes wants roughly 64 turns; this leaves room and still ends.
    const MAX_PASSES: usize = 160;

    let mut trngs = crate::trng::Trngs::new(Some(gate));
    // A source can decline two ways: `Some(0)` is "nothing ready", `None` a refusal.
    // Counted apart so a generation is a measurement rather than an inference.
    let mut tries = [0usize; 4];
    let mut empty = [0usize; 4];
    let mut failed = [0usize; 4];

    gathering(ui.panel, &g, 0);
    for _ in 0..MAX_PASSES {
        if g.read.iter().all(|&(_, n)| n >= TARGET) {
            break;
        }
        for (i, entry) in g.read.iter_mut().enumerate() {
            let (kind, n) = (entry.0, &mut entry.1);
            if *n >= TARGET {
                continue;
            }
            let _ = usbtask::pump();
            let mut buf = [0u8; 64];
            tries[i] += 1;
            match trngs.read(kind, &mut buf) {
                Some(got) if got > 0 => {
                    pool.add(kind.source(), &buf[..got]);
                    *n += got;
                }
                Some(_) => empty[i] += 1,
                None => failed[i] += 1,
            }
            buf.zeroize();
        }
        g.bits = pool.credited_bits();
        g.chips = pool.hardware_sources();
        let got: usize = g.read.iter().map(|&(_, n)| n.min(TARGET)).sum();
        let pct = got * 100 / (TARGET * g.read.len().max(1));
        gathering(ui.panel, &g, pct.min(100) as u8);
        catcard_hal::dwt::delay_cycles(STEP_PAUSE_CYCLES);
    }
    for (i, &(kind, n)) in g.read.iter().enumerate() {
        crate::catlog!(
            "seed: {} {}B/{}t {}e {}f",
            kind.label(),
            n,
            tries[i],
            empty[i],
            failed[i]
        );
    }

    // With the hardware collected, offer the user a turn of their own: a keypad mash,
    // dice, or coin flips. It is optional -- the pool has already met its policy from the
    // TRNGs -- and only ever tops up, but it costs nothing and lets a distrustful owner
    // add material the firmware could not have predicted.
    add_user_entropy(ui, pool);

    // The pool's own verdict, not ours: enough credited bits from enough healthy hardware
    // TRNGs. A failed source counted for neither, so this is where too few healthy sources
    // becomes visible, before any word is shown.
    let passed = pool.check().is_ok();
    // The user's turn may have added bits; the report shows what the draw will rest on.
    g.bits = pool.credited_bits();
    g.chips = pool.hardware_sources();
    crate::catlog!(
        "seed: {} bits from {} chips, policy {}",
        g.bits,
        g.chips,
        if passed { "ok" } else { "FAILED" }
    );
    entropy_report(ui.panel, &g, passed);
    wait_for_any_key(ui);

    // Exactly as much as those words carry, rather than 256 bits with half thrown away.
    // Stock draws a full seed and truncates for twelve words; the pool can be asked for
    // the length actually wanted, and a draw that is all used is easier to reason about
    // than one that is half discarded.
    let mut entropy = [0u8; 32];
    // The draw is the moment the wallet's key comes into existence, so it runs masked
    // together with everything computed from it: nothing a host can time happens between
    // the entropy appearing and its being encoded. A refusal is reported only once the
    // region has closed.
    let made = crate::keywork::run(|kw| {
        let out = pool.draw(&mut entropy[..entropy_len]).map(|()| {
            (
                catcard_callgate::pin::encode_bip39(&entropy[..entropy_len]),
                Mnemonic::from_entropy(&entropy[..entropy_len], kw),
            )
        });
        entropy.zeroize();
        out
    });
    let (encoded, mnemonic) = match made {
        Ok(pair) => pair,
        Err(e) => {
            // The pool refusing is the entropy design working as intended, so report
            // which way it refused rather than a generic failure.
            crate::catlog!("seed: pool refused");
            let mut l = Line::new();
            let _ = write!(l, "{e}");
            info(ui.panel, "Refused", &[l]);
            wait_for_any_key(ui);
            return;
        }
    };

    let (Ok(mut secret), Ok(mnemonic)) = (encoded, mnemonic) else {
        // Both accept 16 and 32 bytes, which is all `entropy_len` can be, so this is
        // unreachable today. It is written out rather than unwrapped because this is
        // the one function that holds a wallet, and a panic here would carry the seed
        // to the panic screen with it.
        message(ui.panel, "Failed", "could not encode", "that seed length");
        wait_for_any_key(ui);
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
        show_words(ui, &mnemonic);
        if quiz(ui, &mnemonic) {
            break;
        }
        ask(ui.panel, "Not confirmed", "read them again", "and retry?");
        if !confirmed(ui) {
            secret.zeroize();
            crate::catlog!("seed: words not confirmed, nothing stored");
            message(ui.panel, "Nothing stored", "no wallet was", "created");
            wait_for_any_key(ui);
            return;
        }
    }

    message(ui.panel, "Applying", "do not disconnect", "");
    // `Login` is driven through the `PinGate` seam, so that the same sequencing runs
    // against a model on the host and the callgate here.
    let pin_gate = crate::pinentry::BootloaderGate::new(gate);
    let outcome = login.set_secret(&pin_gate, &secret);
    if let Err(f) = outcome {
        secret.zeroize();
        crate::catlog!("seed: store failed");
        message(ui.panel, "Not stored", why_failed(f), "any key to go back");
        wait_for_any_key(ui);
        return;
    }

    // Read it back. The words are already written down by this point, so a slot that
    // did not keep them has to be reported rather than assumed good.
    let kept = login.verify_secret(&pin_gate, &secret).unwrap_or(false);
    secret.zeroize();
    if !kept {
        crate::catlog!("seed: read-back mismatch");
        message(
            ui.panel,
            "Not stored",
            "the slot did not keep",
            "what was written",
        );
        wait_for_any_key(ui);
        return;
    }

    crate::catlog!("seed: stored, {} words", mnemonic.word_count());
    message(
        ui.panel,
        "Wallet created",
        "keep those words",
        "somewhere safe",
    );
    wait_for_any_key(ui);
}

/// The outcome of entering one word during a restore.
enum WordPick {
    /// The chosen word, as its BIP-39 wordlist index.
    Word(u16),
    /// Back up to the previous word (or, at the first word, abandon the restore).
    Back,
    /// Finished entering words (OK pressed twice on an empty word).
    Finish,
}

/// The phone-keypad digit a BIP-39 letter sits on, or 0 for a non-letter.
///
/// Standard T9: 2 abc, 3 def, 4 ghi, 5 jkl, 6 mno, 7 pqrs, 8 tuv, 9 wxyz. The wordlist is
/// built so a four-letter prefix identifies a word, which is what makes typing letters on
/// a numeric pad workable -- a few digits narrow 2048 words to a short list.
fn letter_key(b: u8) -> u8 {
    match b {
        b'a'..=b'c' => b'2',
        b'd'..=b'f' => b'3',
        b'g'..=b'i' => b'4',
        b'j'..=b'l' => b'5',
        b'm'..=b'o' => b'6',
        b'p'..=b's' => b'7',
        b't'..=b'v' => b'8',
        b'w'..=b'z' => b'9',
        _ => 0,
    }
}

/// True if `word`'s leading letters map, under T9, onto the typed digit prefix.
fn word_matches(word: &str, typed: &str) -> bool {
    let wb = word.as_bytes();
    let tb = typed.as_bytes();
    wb.len() >= tb.len()
        && wb.iter().zip(tb).all(|(&w, &t)| {
            // A letter typed on a keyboard stands for itself. A digit is the numpad's
            // way of naming the group of letters that share a key, which is still how
            // the mono boards reach them -- and both may appear in one prefix, since
            // nothing stops a Q1 owner typing a digit.
            if t.is_ascii_lowercase() {
                w == t
            } else {
                letter_key(w) == t
            }
        })
}

/// Read one BIP-39 word on the numeric keypad, T9 style.
///
/// Two modes, kept separate because the digit keys mean different things in each and a
/// screen that used them for both at once could not tell a letter from a cursor move:
///
/// - **Type**: keys 2-9 spell the word's letters; `x` deletes the last, or backs out of
///   the word when nothing is typed; `y` opens the candidate list once there is one.
/// - **Pick**: the arrow keys (5/8) move a cursor over the matching words; `y` chooses,
///   `x` returns to typing to add or remove a letter.
///
/// The word is never guessed for the user: even a single match is confirmed from the list
/// so what lands in the seed is what they saw and chose.
///
/// On an empty word, pressing `y` twice returns [`WordPick::Finish`] -- the "I have entered
/// all my words" signal, since the count is not asked up front.
fn read_word(ui: &mut Ui<'_>, num: usize) -> WordPick {
    use catcard_wallet::bip39::wordlist::ENGLISH;
    // Enough to hold the candidates once a couple of letters have narrowed the list; the
    // pick screen is only offered when the true count is within this.
    const CAND_MAX: usize = 64;

    let mut typed: heapless::String<8> = heapless::String::new();
    // One `y` on an empty word arms the finish; a second confirms it. Any other key clears
    // it, so a stray press cannot end the seed early.
    let mut armed = false;
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();

    loop {
        // Candidates for the current digit prefix. `count` is the true total; `cands`
        // stops filling at its capacity, so the pick screen is gated on `count`.
        let mut cands: heapless::Vec<u16, CAND_MAX> = heapless::Vec::new();
        let mut count = 0usize;
        if !typed.is_empty() {
            for (i, w) in ENGLISH.iter().enumerate() {
                if word_matches(w, &typed) {
                    count += 1;
                    let _ = cands.push(i as u16);
                }
            }
        }

        // --- Type screen ---
        let mut title = Line::new();
        let _ = write!(title, "Word {num}");
        let mut lines: heapless::Vec<Line, 8> = heapless::Vec::new();
        // Two lines either way, so the screen below is laid out the same on both.
        #[cfg(feature = "board-q1")]
        {
            let mut l = Line::new();
            let _ = l.push_str("type the word");
            let _ = lines.push(l);
            let _ = lines.push(Line::new());
        }
        #[cfg(not(feature = "board-q1"))]
        {
            let mut l = Line::new();
            let _ = l.push_str("2abc 3def 4ghi 5jkl");
            let _ = lines.push(l);
            let mut l = Line::new();
            let _ = l.push_str("6mno 7pqrs 8tuv 9wxyz");
            let _ = lines.push(l);
        }
        let _ = lines.push(Line::new());
        let mut l = Line::new();
        let _ = write!(l, "keys: {typed}");
        let _ = lines.push(l);
        let mut l = Line::new();
        if armed {
            let _ = l.push_str("y again: finish");
        } else if typed.is_empty() {
            let _ = l.push_str("type, or y y = done");
        } else if count == 0 {
            let _ = l.push_str("no match, x=del");
        } else {
            let _ = write!(l, "{count} match, y=list");
        }
        let _ = lines.push(l);
        info(ui.panel, &title, &lines);

        wait_for_release(ui);
        let mut open_list = false;
        'type_wait: loop {
            let _ = usbtask::pump();
            crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
            for k in keys.iter() {
                match k {
                    // A letter key.
                    Key::Digit(d @ 2..=9) => {
                        armed = false;
                        let _ = typed.push((b'0' + d) as char);
                        break 'type_wait;
                    }
                    // 0 and 1 carry no letters; ignore them rather than mis-spell.
                    Key::Digit(_) => {}
                    Key::Cancel => {
                        armed = false;
                        if typed.pop().is_none() {
                            return WordPick::Back;
                        }
                        break 'type_wait;
                    }
                    Key::Confirm => {
                        if !typed.is_empty() {
                            if count > 0 && count <= CAND_MAX {
                                open_list = true;
                                break 'type_wait;
                            }
                        } else if armed {
                            // Second `y` on an empty word: that is the end of the seed.
                            return WordPick::Finish;
                        } else {
                            armed = true;
                            break 'type_wait;
                        }
                    }
                    // A letter, on a board with a keyboard. Typed straight in: the digit
                    // legend below is the numpad's way of reaching the same letters.
                    Key::Char(c @ b'a'..=b'z') => {
                        armed = false;
                        let _ = typed.push(*c as char);
                        break 'type_wait;
                    }
                    // Upper case, punctuation and space are not in any BIP-39 word.
                    Key::Char(_) => {}
                }
            }
            catcard_hal::dwt::delay_cycles(usbtask::IDLE_PAUSE_CYCLES);
        }
        if !open_list {
            continue;
        }

        // --- Pick screen --- a scrollable menu of the candidate words, each carrying its
        // index into `cands` as the id.
        let mut lines: heapless::Vec<catcard_ui::scroll::Line, CAND_MAX> = heapless::Vec::new();
        let _ = lines.push(catcard_ui::scroll::Line::title("Pick the word"));
        for (pos, &ci) in cands.iter().enumerate() {
            let _ = lines.push(catcard_ui::scroll::Line::item(
                ENGLISH[ci as usize],
                pos as u32,
            ));
        }
        match show_doc(ui, &lines, false, false) {
            DocExit::Selected(pos) => return WordPick::Word(cands[pos as usize]),
            // Back to typing, keeping what was entered so a letter can be added or removed.
            DocExit::Cancelled | DocExit::Confirmed => continue,
        }
    }
}

/// A short reason for a phrase that would not parse, for the error screen.
fn parse_error(e: catcard_wallet::bip39::Error) -> &'static str {
    use catcard_wallet::bip39::Error;
    match e {
        Error::BadChecksum => "checksum is wrong",
        Error::BadWordCount { .. } => "wrong number of words",
        Error::UnknownWord { .. } => "a word is not valid",
        _ => "could not read the seed",
    }
}

/// What the owner chose in the fix-the-seed editor.
enum EditChoice {
    /// Re-enter the word at this position.
    Edit(usize),
    /// Append another word.
    Add,
    /// Discard the whole entry.
    Cancel,
}

/// The ids the editor's non-word rows carry; word rows carry their position, always small.
const EDIT_ADD: u32 = u32::MAX;
const EDIT_CANCEL: u32 = u32::MAX - 1;

/// Show the entered words as a menu so the owner can fix one, add another, or discard.
fn edit_menu(ui: &mut Ui<'_>, idx: &[u16]) -> EditChoice {
    use catcard_ui::scroll::Line as DLine;
    use catcard_wallet::bip39::wordlist::ENGLISH;

    let mut texts: heapless::Vec<Line, 24> = heapless::Vec::new();
    for (pos, &i) in idx.iter().enumerate() {
        let mut s = Line::new();
        let _ = write!(s, "{:2}  {}", pos + 1, ENGLISH[i as usize]);
        let _ = texts.push(s);
    }
    let mut lines: heapless::Vec<DLine, 28> = heapless::Vec::new();
    let _ = lines.push(DLine::title("Fix the seed"));
    for (pos, s) in texts.iter().enumerate() {
        let _ = lines.push(DLine::item(s, pos as u32));
    }
    let _ = lines.push(DLine::item("+ add a word", EDIT_ADD));
    let _ = lines.push(DLine::item("x discard all", EDIT_CANCEL));

    match show_doc(ui, &lines, false, false) {
        DocExit::Selected(EDIT_ADD) => EditChoice::Add,
        DocExit::Selected(EDIT_CANCEL) => EditChoice::Cancel,
        DocExit::Selected(pos) => EditChoice::Edit(pos as usize),
        // Backing out of the editor discards, same as the explicit row.
        DocExit::Cancelled | DocExit::Confirmed => EditChoice::Cancel,
    }
}

/// Restore a wallet from a written-down BIP-39 phrase, typed on the keypad.
///
/// The count is not asked: the owner types each word and presses `y` twice to end. The
/// checksum is the whole safety story -- a restore stores whatever it is given, so nothing
/// is committed until [`Mnemonic::parse`] rebuilds the entropy and verifies the checksum.
/// A phrase that does not check out drops the owner into [`edit_menu`]: the words shown as
/// a list to fix in place, add to, or discard, and the checksum is re-tested after each
/// change. Only once it checks out is the import offered and stored.
///
/// The same write-then-read-back-then-claim order as [`new_seed`], and for the same
/// reason: a slot that did not keep the words must be reported, not assumed.
fn import_seed(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    use catcard_wallet::bip39::{Mnemonic, wordlist::ENGLISH};
    use zeroize::Zeroize;

    fn cancelled(ui: &mut Ui<'_>) {
        message(ui.panel, "Import cancelled", "nothing was", "stored");
        wait_for_any_key(ui);
    }

    // Overwriting an in-use wallet is the destructive case; this is the only warning.
    if matches!(login.step(), catcard_pin::Step::In { zero_secret: false }) {
        ask(
            ui.panel,
            "Wallet exists",
            "a restore DESTROYS",
            "the one stored now",
        );
        if !confirmed(ui) {
            return;
        }
    }
    message(
        ui.panel,
        "Import seed",
        "enter each word,",
        "then y y to finish",
    );
    wait_for_any_key(ui);

    let mut idx: heapless::Vec<u16, 24> = heapless::Vec::new();

    // Enter words until the owner signals the end. `Back` steps to the previous word;
    // backing off the first word abandons the restore.
    loop {
        match read_word(ui, idx.len() + 1) {
            WordPick::Word(i) => {
                if idx.push(i).is_err() {
                    // 24 words is the most a phrase can be; stop taking more and verify.
                    break;
                }
            }
            WordPick::Back => {
                if idx.pop().is_none() {
                    cancelled(ui);
                    return;
                }
            }
            WordPick::Finish => break,
        }
    }

    // Verify, and until it checks out let the owner fix it. Each pass reparses the phrase.
    let mnemonic = loop {
        let mut phrase: heapless::String<256> = heapless::String::new();
        for (n, &i) in idx.iter().enumerate() {
            if n > 0 {
                let _ = phrase.push(' ');
            }
            let _ = phrase.push_str(ENGLISH[i as usize]);
        }
        // Parsing rebuilds the entropy and checks its checksum: private-key work, masked.
        let parsed = crate::keywork::run(|kw| Mnemonic::parse(&phrase, kw));
        // SAFETY: zeroing then clearing the phrase's own bytes; the empty buffer that
        // remains is trivially valid UTF-8.
        let raw = unsafe { phrase.as_mut_vec() };
        raw.iter_mut().for_each(|b| *b = 0);
        raw.clear();

        match parsed {
            Ok(m) => break m,
            Err(e) => {
                message(ui.panel, "Bad seed", parse_error(e), "any key to fix");
                wait_for_any_key(ui);
                match edit_menu(ui, &idx) {
                    EditChoice::Edit(pos) => {
                        if let WordPick::Word(i) = read_word(ui, pos + 1) {
                            idx[pos] = i;
                        }
                    }
                    EditChoice::Add => {
                        if idx.len() < 24
                            && let WordPick::Word(i) = read_word(ui, idx.len() + 1)
                        {
                            let _ = idx.push(i);
                        }
                    }
                    EditChoice::Cancel => {
                        cancelled(ui);
                        return;
                    }
                }
            }
        }
    };

    // It checks out: offer to complete, then store.
    let mut what = Line::new();
    let _ = write!(what, "{} words, checksum ok", mnemonic.word_count());
    ask(ui.panel, "Restore this?", &what, "y to store it");
    if !confirmed(ui) {
        cancelled(ui);
        return;
    }

    let Ok(mut secret) = catcard_callgate::pin::encode_bip39(mnemonic.entropy()) else {
        message(ui.panel, "Failed", "could not encode", "that seed");
        wait_for_any_key(ui);
        return;
    };

    message(ui.panel, "Applying", "do not disconnect", "");
    let pin_gate = crate::pinentry::BootloaderGate::new(gate);
    if let Err(f) = login.set_secret(&pin_gate, &secret) {
        secret.zeroize();
        crate::catlog!("seed: restore store failed");
        message(ui.panel, "Not stored", why_failed(f), "any key to go back");
        wait_for_any_key(ui);
        return;
    }
    let kept = login.verify_secret(&pin_gate, &secret).unwrap_or(false);
    secret.zeroize();
    if !kept {
        crate::catlog!("seed: restore read-back mismatch");
        message(
            ui.panel,
            "Not stored",
            "the slot did not keep",
            "what was written",
        );
        wait_for_any_key(ui);
        return;
    }

    crate::catlog!("seed: restored, {} words", mnemonic.word_count());
    message(ui.panel, "Wallet restored", "your seed is", "now stored");
    wait_for_any_key(ui);
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
fn quiz(ui: &mut Ui<'_>, m: &catcard_wallet::bip39::Mnemonic) -> bool {
    use catcard_wallet::bip39::wordlist::{ENGLISH, WORD_COUNT};
    const ASKS: usize = 3;
    const CHOICES: usize = 3;

    let total = m.word_count();
    for _ in 0..ASKS {
        // A DRBG failure means it wants reseeding. Refusing is the only safe answer: a
        // quiz whose questions are predictable proves nothing.
        let Ok(pos) = ui.drbg.below(total as u32) else {
            return false;
        };
        let pos = pos as usize;
        let Some(correct) = m.words().nth(pos) else {
            return false;
        };

        let mut choices = [correct; CHOICES];
        for i in 1..CHOICES {
            loop {
                let Ok(pick) = ui.drbg.below(WORD_COUNT as u32) else {
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
        let _ = ui.drbg.shuffle(&mut choices);

        let mut lines: heapless::Vec<Line, { CHOICES + 1 }> = heapless::Vec::new();
        for (i, w) in choices.iter().enumerate() {
            let mut l = Line::new();
            let _ = write!(l, "{}  {w}", i + 1);
            let _ = lines.push(l);
        }
        let mut hint = Line::new();
        let _ = hint.push_str("y = skip");
        let _ = lines.push(hint);
        let mut title = Line::new();
        let _ = write!(title, "Which is word {}?", pos + 1);

        // Loop this one question so a declined skip re-asks it rather than failing.
        loop {
            info(ui.panel, &title, &lines);
            match read_choice(ui, CHOICES) {
                Choice::Pick(i) if choices[i] == correct => break,
                // A wrong pick or a cancel fails the quiz -- the caller offers the list
                // again, and nothing is stored yet, so it costs only time.
                Choice::Pick(_) | Choice::Cancel => return false,
                Choice::Skip => {
                    ask(
                        ui.panel,
                        "Skip the check?",
                        "store without",
                        "confirming words?",
                    );
                    if confirmed(ui) {
                        return true;
                    }
                    // Declined: ask this question again.
                }
            }
        }
    }
    true
}

/// What a person did at a quiz question.
enum Choice {
    /// Picked numbered option `0..n`.
    Pick(usize),
    /// Pressed `y` -- asking to skip the check.
    Skip,
    /// Backed out.
    Cancel,
}

/// Wait for one of `n` numbered choices, a skip (`y`), or a cancel (`x`).
fn read_choice(ui: &mut Ui<'_>, n: usize) -> Choice {
    wait_for_release(ui);
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        let _ = usbtask::pump();
        crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
        for k in keys.iter() {
            match k {
                Key::Cancel => return Choice::Cancel,
                Key::Confirm => return Choice::Skip,
                Key::Digit(d) if *d >= 1 && (*d as usize) <= n => {
                    return Choice::Pick(*d as usize - 1);
                }
                _ => {}
            }
        }
        catcard_hal::dwt::delay_cycles(usbtask::IDLE_PAUSE_CYCLES);
    }
}

/// Sign a partially-signed transaction (PSBT) staged on the SD card.
///
/// Chosen from the main menu's "Ready to Sign" when a wallet exists. For now this runs the
/// `.psbt` file picker and acknowledges the choice; loading, parsing, verifying, showing
/// the transaction, confirming and signing land as the PSBT support is wired in.
fn sign_psbt(ui: &mut Ui<'_>) {
    let Some(path) = browse_sd(ui, "Pick a .psbt", Some("psbt"), true) else {
        return;
    };
    // TODO: load the file into scratch, parse the PSBT, check it is ours and not already
    // signed, show the transaction, confirm, sign each input, and write it back.
    message(
        ui.panel,
        "PSBT selected",
        path.as_str(),
        "signing coming soon",
    );
    wait_any_key(ui);
}

/// Format the SD card to the SD standard: one MBR partition filling the card, holding the
/// filesystem its capacity tier calls for -- FAT16 up to 2 GB, FAT32 up to 32 GB, exFAT
/// above. This erases everything on the card, so it asks twice, and shows what it is about
/// to write first.
fn format_sd(ui: &mut Ui<'_>) {
    use catcard_hal::sdmmc::Sdmmc;

    // SAFETY: nothing else has claimed SDMMC1 or its pins; this screen is its only user and
    // the menu waits for it to return before it can be chosen again.
    let mut dev = match unsafe { Sdmmc::init(&catcard_board::BOARD) } {
        Ok(d) => d,
        Err(_) => {
            message(ui.panel, "Format SD", "no SD controller", "press a key");
            wait_any_key(ui);
            return;
        }
    };
    let card = match catcard_sd::init(&mut dev) {
        Ok(c) => c,
        Err(catcard_sd::Error::NoCard) => {
            message(ui.panel, "Format SD", "no card in slot", "press a key");
            wait_any_key(ui);
            return;
        }
        Err(e) => {
            crate::catlog!("sd: card would not start: {:?}", e);
            message(ui.panel, "Format SD", "card would not start", "press a key");
            wait_any_key(ui);
            return;
        }
    };

    // Which filesystem the card's size calls for, shown before anyone commits.
    let fs = catcard_sd::format::standard_fs(card.blocks as u64);
    let mut summary = Line::new();
    let _ = write!(summary, "{} MiB  {}", card.mib(), fs.name());
    ask(
        ui.panel,
        "Format SD card?",
        summary.as_str(),
        "ERASES everything",
    );
    if !confirmed(ui) {
        return;
    }
    ask(
        ui.panel,
        "Really format?",
        "all data is lost",
        "cannot be undone",
    );
    if !confirmed(ui) {
        return;
    }

    // A volume serial from the UI DRBG, so two cards do not come out sharing one.
    let mut id = [0u8; 4];
    let _ = ui.drbg.generate(&mut id);
    let volume_id = u32::from_le_bytes(id);

    message(ui.panel, "Formatting", "do not remove card", "");
    let sectors = catcard_sd::Sectors::new(dev, card);
    match catcard_sd::format::format(sectors, volume_id, "CATCARD") {
        Ok(fs) => {
            let mut done = Line::new();
            let _ = write!(done, "{} ready", fs.name());
            message(ui.panel, "Formatted", done.as_str(), "press a key");
        }
        Err(catcard_sd::format::FormatError::TooSmall) => {
            message(ui.panel, "Not formatted", "card too small", "press a key")
        }
        Err(catcard_sd::format::FormatError::Io(_)) => message(
            ui.panel,
            "Not formatted",
            "card write failed",
            "press a key",
        ),
        Err(catcard_sd::format::FormatError::Layout(_)) => message(
            ui.panel,
            "Not formatted",
            "size not supported",
            "press a key",
        ),
    }
    wait_any_key(ui);
}

/// Destroy the stored seed.
///
/// `gate 18/3` with `change::SECRET` and seventy-two zero bytes: the same call that
/// stores a wallet, pointed at nothing. Stock uses the bootloader's `fast_wipe`
/// (gate 23), which is not in our ABI and which also resets the device — so nothing
/// could confirm the result. This path can be *checked*, and is: the slot is read back
/// before anyone is told their seed is gone, because that is the one claim this screen
/// must never make wrongly.
///
/// The PIN survives. This erases the wallet, not the device.
///
/// Returns whether the slot is empty afterwards.
fn wipe_seed(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) -> bool {
    use zeroize::Zeroize;

    // Nothing to destroy is worth saying, rather than going through the motions and
    // reporting success for a wallet that never existed.
    if matches!(login.step(), catcard_pin::Step::In { zero_secret: true }) {
        message(ui.panel, "No wallet", "there is no seed", "to destroy");
        wait_for_any_key(ui);
        return true;
    }

    // Twice, because one question is what people press through. The first says what is
    // lost; the second says it does not come back.
    ask(
        ui.panel,
        "Destroy wallet?",
        "the seed is ERASED",
        "from this device",
    );
    if !confirmed(ui) {
        return false;
    }
    ask(
        ui.panel,
        "Really destroy?",
        "only your words can",
        "ever bring it back",
    );
    if !confirmed(ui) {
        return false;
    }

    message(ui.panel, "Erasing", "do not disconnect", "");
    let mut empty = [0u8; catcard_callgate::pin::SECRET_LEN];
    let pin_gate = crate::pinentry::BootloaderGate::new(gate);
    if let Err(f) = login.set_secret(&pin_gate, &empty) {
        crate::catlog!("wipe: store failed");
        message(ui.panel, "Not erased", why_failed(f), "any key to go back");
        wait_for_any_key(ui);
        return false;
    }

    let bytes_zeroed = login.verify_secret(&pin_gate, &empty).unwrap_or(false);
    empty.zeroize();

    // Two different questions, and only the second is the device's own opinion.
    //
    // `verify_secret` compares what `gate 18/4` hands back, and the bootloader
    // XOR-masks the slot with `otp_key` going in and coming out
    // (`hw-reference/secure-elements.md` §"PIN → secret flow"). Writing zeros and
    // reading zeros therefore round-trips through the same mask: it proves the write
    // landed, and says nothing about whether the element now counts as empty. What the
    // menu and the next boot actually consult is ZERO_SECRET, so that is what decides
    // the wording here.
    //
    // This distinction is not theoretical. An earlier version checked only the bytes,
    // reported "Wallet erased", and the entry was back after a reboot -- the one wrong
    // answer this screen must never give.
    let flag_empty = matches!(login.step(), catcard_pin::Step::In { zero_secret: true });
    crate::catlog!(
        "wipe: bytes {} flag {}",
        if bytes_zeroed { "zeroed" } else { "MISMATCH" },
        if flag_empty { "EMPTY" } else { "IN USE" }
    );

    match (bytes_zeroed, flag_empty) {
        (true, true) => message(ui.panel, "Wallet erased", "no seed is stored", ""),
        // The write was taken and the device still counts the slot as holding a
        // secret. Whatever that means, it is not "erased".
        (true, false) => message(
            ui.panel,
            "Not confirmed",
            "zeros were written",
            "slot still reads used",
        ),
        _ => message(ui.panel, "Not erased", "the slot did not", "take the write"),
    }
    wait_for_any_key(ui);
    flag_empty
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
fn show_words(ui: &mut Ui<'_>, m: &catcard_wallet::bip39::Mnemonic) {
    let texts = word_texts(m);
    let mut lines: heapless::Vec<catcard_ui::scroll::Line, 26> = heapless::Vec::new();
    let _ = lines.push(catcard_ui::scroll::Line::title("Write these down"));
    for s in &texts {
        // Secret, so each word carries the ragged sensitive-line marker.
        let _ = lines.push(catcard_ui::scroll::Line::body(s).secret());
    }
    // `require_end`: Confirm will not finish until every word has been on screen.
    show_doc(ui, &lines, true, true);
}

/// The numbered words of a mnemonic as `"NN  word"` strings, for a document.
fn word_texts(m: &catcard_wallet::bip39::Mnemonic) -> heapless::Vec<Line, 24> {
    let mut out = heapless::Vec::new();
    for (i, w) in m.words().enumerate() {
        let mut s = Line::new();
        let _ = write!(s, "{:2}  {w}", i + 1);
        let _ = out.push(s);
    }
    out
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

/// The STM32 in this device: part, silicon revision, flash, and where on which wafer the
/// die was cut, from the factory unique ID.
fn chip_screen(panel: &mut display::Panel) {
    let mut lines: heapless::Vec<Line, 6> = heapless::Vec::new();
    // SAFETY: reads of always-mapped ID registers, each checked on a locked unit first.
    let (uid, (dev, rev), kb) = unsafe {
        (
            catcard_hal::uid::read(),
            catcard_hal::uid::idcode(),
            catcard_hal::uid::flash_size_kb(),
        )
    };
    let die = catcard_hal::uid::Die::from_uid(&uid);
    // Part numbers from the boards' BOMs. Source: platform.md §1 [C]
    let part = match catcard_board::BOARD.mcu {
        catcard_board::spec::Mcu::Stm32L496 => "STM32L496RGT6",
        catcard_board::spec::Mcu::Stm32L4S5 => "STM32L4S5VIT6",
    };
    let _ = lines.push(Line::try_from(part).unwrap_or_default());
    let mut l = Line::new();
    let _ = write!(l, "ID {:03X} rev {:04X}, {} KB", dev, rev, kb);
    let _ = lines.push(l);
    let mut l = Line::new();
    let _ = l.push_str("Lot ");
    for c in die.lot() {
        let _ = l.push(c);
    }
    let _ = write!(l, ", wafer {}", die.wafer);
    let _ = lines.push(l);
    let mut l = Line::new();
    let _ = write!(l, "Die X {}, Y {}", die.x, die.y);
    let _ = lines.push(l);
    let mut l = Line::new();
    let _ = l.push_str("UID ");
    for b in uid {
        let _ = write!(l, "{:02X}", b);
    }
    let _ = lines.push(l);
    info(panel, "STM32", &lines);
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

/// How a scrollable document screen ([`show_doc`]) ended.
enum DocExit {
    /// A menu row was chosen; carries its `menu_item` id.
    Selected(u32),
    /// A reading screen was confirmed (Confirm on a document with no selectable lines).
    Confirmed,
    /// The user backed out.
    Cancelled,
}

/// Idle beats between marquee steps for an over-long selected name -- how fast it scrolls
/// sideways. One `IDLE_PAUSE_CYCLES` beat is the loop's natural tick.
const MARQUEE_BEATS: u32 = 8;

/// Animate a scroll view's offset from `from` to `to` on boards that animate, rendering the
/// intermediate frames. The final frame at exactly `to` is left to the caller's next draw,
/// so this only ever paints the in-between steps. On boards that don't animate it just
/// leaves the view at `to`.
fn glide_view(
    panel: &mut display::Panel,
    view: &mut catcard_ui::scroll::ScrollView<'_>,
    from: usize,
    to: usize,
) {
    if display::SMOOTH_SCROLL && from != to {
        let frames = display::GLIDE_FRAMES as isize;
        let (a, b) = (from as isize, to as isize);
        for f in 1..frames {
            let off = (a + (b - a) * f / frames).max(0) as usize;
            view.set_off(off);
            display::draw(panel, |c| catcard_ui::scroll::render(c, view));
            let _ = usbtask::pump();
            catcard_hal::dwt::delay_cycles(display::GLIDE_PAUSE_CYCLES);
        }
    }
    view.set_off(to);
}

/// Show a scrollable document ([`catcard_ui::scroll`]) and drive it from the keypad.
///
/// A reading screen (no selectable lines) scrolls with `5`/`8` and leaves on Confirm or
/// Cancel. A menu (some line carries a `menu_item`) moves a cursor with `5`/`8` and returns
/// the chosen id on Confirm. `require_end`, for the seed backup, refuses Confirm on a
/// reading screen until the bottom has been on screen -- the "read every word" gate the old
/// pager enforced. `scramble` turns on the ragged sensitive-line marker.
fn show_doc(
    ui: &mut Ui<'_>,
    lines: &[catcard_ui::scroll::Line<'_>],
    scramble: bool,
    require_end: bool,
) -> DocExit {
    let mut screen = DocScreen::new(ui, lines, scramble, require_end);
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        screen.draw(ui);
        wait_for_release(ui);
        // A tick counter so a selected, over-long name marquees while nothing is pressed.
        let mut beat = 0u32;
        'wait: loop {
            let _ = usbtask::pump();
            crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
            if keys.is_empty() {
                // Advance the marquee every few idle beats when the selection overflows,
                // redrawing only then so a static screen still never re-flushes.
                if screen.needs_marquee() {
                    beat = beat.wrapping_add(1);
                    if beat.is_multiple_of(MARQUEE_BEATS) && screen.tick_marquee() {
                        screen.draw(ui);
                    }
                }
                catcard_hal::dwt::delay_cycles(usbtask::IDLE_PAUSE_CYCLES);
                continue;
            }
            for k in keys.iter() {
                match screen.key(ui, *k) {
                    DocFlow::Done(exit) => return exit,
                    // The view moved: leave the wait so the outer loop repaints the
                    // settled frame.
                    DocFlow::Redraw => break 'wait,
                    // Nothing happened -- an unused digit, or Confirm on a menu row that
                    // is not selectable. Keep waiting rather than repainting, which would
                    // also re-run `wait_for_release` and swallow the next press.
                    DocFlow::Ignored => {}
                }
            }
        }
    }
}

/// A scrollable document as a screen: it owns its view and takes one key at a time.
///
/// Split out of [`show_doc`] so the same screen can be driven two ways. Today every
/// caller drives it blocking, through `show_doc`. What this makes possible is the other
/// way: a run loop that hands it one key at a time and keeps pumping USB -- and noticing
/// staged upgrade offers -- in between. That matters most for the seed backup, which
/// blocks on a person copying down 24 words while `usbtask::pending()` goes unread.
///
/// Everything that has to survive a keypress is here; `show_doc` keeps only the keypad
/// plumbing.
struct DocScreen<'a> {
    view: catcard_ui::scroll::ScrollView<'a>,
    /// Some line is selectable, so `5`/`8` move a cursor instead of scrolling.
    is_menu: bool,
    /// Refuse Confirm until the last line has been on screen: the seed backup's gate.
    require_end: bool,
}

/// What one key did to a [`DocScreen`].
///
/// Three outcomes, not two: an ignored key must not repaint, because a repaint also
/// re-runs `wait_for_release` and would eat the press that follows.
enum DocFlow {
    /// Nothing changed; keep waiting.
    Ignored,
    /// The view moved; repaint the settled frame.
    Redraw,
    /// The screen is finished.
    Done(DocExit),
}

impl<'a> DocScreen<'a> {
    fn new(
        ui: &mut Ui<'_>,
        lines: &'a [catcard_ui::scroll::Line<'a>],
        scramble: bool,
        require_end: bool,
    ) -> Self {
        let mut view = catcard_ui::scroll::ScrollView::build(
            lines,
            display::SCREEN_W,
            display::SCREEN_H,
            display::FONTS,
        );
        if scramble {
            let mut b = [0u8; 4];
            let _ = ui.drbg.generate(&mut b);
            view = view.with_scramble(catcard_ui::pager::Scramble::new(u32::from_le_bytes(b)));
        }
        let is_menu = view.is_menu();
        Self {
            view,
            is_menu,
            require_end,
        }
    }

    fn draw(&self, ui: &mut Ui<'_>) {
        display::draw(ui.panel, |c| catcard_ui::scroll::render(c, &self.view));
    }

    fn needs_marquee(&self) -> bool {
        self.view.needs_marquee()
    }

    fn tick_marquee(&mut self) -> bool {
        self.view.tick_marquee()
    }

    /// Move the view and animate from where it was to where it lands.
    fn glide(&mut self, ui: &mut Ui<'_>, f: impl FnOnce(&mut catcard_ui::scroll::ScrollView<'a>)) {
        let old = self.view.off();
        f(&mut self.view);
        let new = self.view.off();
        glide_view(ui.panel, &mut self.view, old, new);
    }

    /// Take one key.
    fn key(&mut self, ui: &mut Ui<'_>, k: Key) -> DocFlow {
        match k {
            // The up/down arrows: move a menu cursor, or scroll a reading screen.
            Key::Digit(0) => {
                self.glide(ui, |v| v.to_top());
                DocFlow::Redraw
            }
            Key::Digit(5) => {
                let menu = self.is_menu;
                self.glide(ui, move |v| {
                    if menu {
                        v.move_cursor(false);
                    } else {
                        v.scroll(false, v.line_step());
                    }
                });
                DocFlow::Redraw
            }
            Key::Digit(8) => {
                let menu = self.is_menu;
                self.glide(ui, move |v| {
                    if menu {
                        v.move_cursor(true);
                    } else {
                        v.scroll(true, v.line_step());
                    }
                });
                DocFlow::Redraw
            }
            Key::Confirm => {
                if self.is_menu {
                    match self.view.selected() {
                        Some(id) => DocFlow::Done(DocExit::Selected(id)),
                        // A menu with nothing selectable under the cursor: not an exit.
                        None => DocFlow::Ignored,
                    }
                } else if self.require_end && !self.view.at_end() {
                    // Not read to the end yet: page down instead of finishing.
                    self.glide(ui, |v| v.scroll(true, v.line_step()));
                    DocFlow::Redraw
                } else {
                    DocFlow::Done(DocExit::Confirmed)
                }
            }
            Key::Cancel => DocFlow::Done(DocExit::Cancelled),
            Key::Digit(_) => DocFlow::Ignored,
            Key::Char(_) => DocFlow::Ignored,
        }
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
    ui: &mut Ui<'_>,
    title: &str,
    src: &S,
    require_end: bool,
    layout: &catcard_ui::widgets::Layout<'_>,
    scramble: bool,
) -> bool {
    use catcard_ui::pager::{LineSink, Pager, paged};

    // Rows depend on the body face, which the words layout enlarges, so compute them
    // from the layout rather than the fixed default.
    let rows = layout.pager_rows(display::SCREEN_H);
    // One random seed for the whole viewing, so the emissions scramble is stable per
    // line (it scrolls with the text) yet different each time the page is opened.
    let scr = scramble.then(|| {
        let mut b = [0u8; 4];
        let _ = ui.drbg.generate(&mut b);
        catcard_ui::pager::Scramble::new(u32::from_le_bytes(b))
    });
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
        display::draw(ui.panel, |c| paged(c, layout, title, &sink, p, total, scr));

        wait_for_release(ui);
        loop {
            let _ = usbtask::pump();
            crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
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
                    Key::Char(_) => {}
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
fn wait_any_key(ui: &mut Ui<'_>) {
    wait_for_release(ui);
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
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
fn usb_drive(ui: &mut Ui<'_>) {
    use catcard_hal::sdmmc::Sdmmc;

    // SAFETY: nothing else has claimed SDMMC1 or its pins; this screen is its only user
    // and the menu waits for it to return before it can be chosen again.
    let mut dev = match unsafe { Sdmmc::init(&catcard_board::BOARD) } {
        Ok(d) => d,
        Err(_) => {
            message(ui.panel, "USB Drive", "no SD controller", "press a key");
            wait_any_key(ui);
            return;
        }
    };
    let card = match catcard_sd::init(&mut dev) {
        Ok(c) => c,
        Err(catcard_sd::Error::NoCard) => {
            message(ui.panel, "USB Drive", "no card in slot", "press a key");
            wait_any_key(ui);
            return;
        }
        Err(e) => {
            crate::catlog!("sd: card would not start: {:?}", e);
            message(ui.panel, "USB Drive", "card would not start", "press a key");
            wait_any_key(ui);
            return;
        }
    };

    message(ui.panel, "USB Drive", "SD is on USB", "press x to eject");

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
        crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
        keys.contains(&Key::Cancel)
    });

    crate::usbtask::msc_exit();
}

pub(crate) fn message(panel: &mut display::Panel, head: &str, a: &str, b: &str) {
    display::draw(panel, |c| {
        catcard_ui::widgets::message(c, &display::LAYOUT, head, a, b);
    });
}
