//! What happens after bring-up: acknowledge the selftest, then unlock.
//!
//! Everything here is conditional on the device being able to do it at all. A wallet
//! that cannot show a prompt must not pretend to take a PIN, and one whose entropy pool
//! never met its policy has no UI DRBG — so rather than degrade to a weaker source or a
//! fixed scan order, those devices stop at the selftest screen where the fault is
//! legible. That is the whole reason this function is a pile of `Option`s.

use catcard_board::BOARD;
use catcard_callgate::Callgate;
use catcard_entropy::{domain, spawn_drbg};

use crate::{BootReport, display, keypad, menu, pinentry, power, selftest, usbtask};

/// Run the post-boot sequence. Never returns.
pub fn run(mut report: BootReport, panel: Option<display::Panel>) -> ! {
    // First, unconditionally: the only report a device with a dead panel can make.
    selftest::publish(&report);

    crate::catlog!(
        "boot: {} {} built {}",
        crate::running_board(),
        crate::VERSION,
        crate::BOARD_NAME
    );
    crate::catlog!(
        "boot: hal {} dwt {} entropy {}",
        if report.hal.is_ok() { "ok" } else { "FAIL" },
        if report.dwt_running { "ok" } else { "FAIL" },
        report.entropy.unwrap_or_default()
    );
    crate::catlog!(
        "boot: panel {}",
        if panel.is_some() { "up" } else { "ABSENT" }
    );
    // SAFETY: reads RCC. Logged so a wrong prescaler assumption is visible, not guessed.
    crate::catlog!(
        "clk: hclk {} MHz pclk2 {} MHz",
        unsafe { catcard_hal::clock::hclk_hz() } / 1_000_000,
        unsafe { catcard_hal::clock::pclk2_hz() } / 1_000_000
    );
    #[cfg(feature = "usb-debug-mem")]
    crate::catlog!("boot: WARNING debug memory monitor is enabled (peek/poke/jsr)");

    // SAFETY: bring-up is complete and nothing else has claimed the keypad pins.
    let matrix = unsafe { keypad::GpioMatrix::init() };

    // Put the QR module into a known state before anything can ask it for anything --
    // the lamp key works from any screen, including the PIN prompt. Two seconds, once.
    #[cfg(feature = "board-q1")]
    crate::qrscan::boot_bringup();
    // The scan-order shuffle draws from the UI domain, never from the seed pool.
    let drbg = report
        .pool
        .as_mut()
        .and_then(|pool| spawn_drbg(pool, domain::UI, &[]).ok());
    // A second generator for values that leave the device and have to stay secret -- the
    // microSD 2FA token, a backup's password words and IV. The UI one's outputs are on
    // the screen (the keypad's scramble order), and a generator whose outputs are shown
    // must not be the one whose outputs are kept: one instance per purpose, each from
    // its own pool draw. A local, like the UI one, so it costs the Q1's .bss nothing.
    let protocol = report
        .pool
        .as_mut()
        .and_then(|pool| spawn_drbg(pool, domain::PROTOCOL, &[]).ok());

    // SAFETY: we are running on BOARD; `discover` validates the published entry address
    // before anything can branch to it.
    let gate = unsafe { Callgate::discover(&BOARD) }.ok();

    // USB before anything a person has to do, and before the checks below that can park
    // the device. A host presents the cable and enumerates within milliseconds; a device
    // that only appears after a PIN looks broken. What the PIN gates is the upgrade, not
    // the enumeration -- see `usbtask`.
    //
    // Before the park branches specifically, because those fire on a dead panel, a
    // keypad that would not initialise, an entropy pool that missed its policy, or an
    // unreachable callgate -- the exact failures where a host is the only way to reach
    // the device, and where it used to park with USB never started at all.
    //
    // SAFETY: nothing else has claimed OTG_FS or the USB pins, and HSI48 was started
    // during bring-up.
    unsafe { usbtask::init(serial()) };
    crate::catlog!(
        "usb: {}",
        if usbtask::init_fault().is_empty() {
            "started"
        } else {
            usbtask::init_fault()
        }
    );

    // Without the callgate nothing can log in or install, so there is nothing to offer
    // beyond answering USB.
    let Some(gate) = gate else {
        selftest::park(report, panel)
    };
    // Needs the gate: powering off is `show_logout(3)`, which only the bootloader can do.
    // Armed before the PIN prompt, because that is exactly where someone reaches for the
    // button on a device they did not mean to wake.
    //
    // SAFETY: nothing else claims the power-button pin, and this runs once, in the boot
    // path, before any screen.
    unsafe { power::init(&gate) };
    // The idle timeout uses the same gate, and needs the clock read while it is still
    // being read here. Armed with nothing: only a wallet's own settings can turn it on,
    // and those are not readable until the PIN is in.
    //
    // SAFETY: reads RCC; once, on the boot path, before any tick.
    unsafe { crate::idle::init(&gate) };
    // Which pin reports the power source, and therefore what the status bar's icon says.
    // SAFETY: bring-up; nothing else drives the battery-sense pins.
    #[cfg(feature = "board-q1")]
    unsafe {
        crate::battery::init()
    };
    // A device that cannot run the front panel -- no panel, no keypad, or no UI DRBG to
    // shuffle the scan with -- must still be reprogrammable, or a board whose drivers are
    // missing (Q1 today) runs a validly-signed image that nothing can replace. On a bench
    // build `recovery` runs the unlock and the install over USB; on any other build it is
    // the park this used to be. Taken one at a time so a device with a working panel but
    // no keypad keeps what is on its screen.
    let Some(mut panel) = panel else {
        crate::recovery::run(report, None, gate)
    };
    let (Some(mut matrix), Some(mut drbg), Some(mut protocol)) = (matrix, drbg, protocol) else {
        crate::recovery::run(report, Some(panel), gate)
    };

    // No boot selftest screen: boot goes straight to the PIN prompt, so a host can drive
    // an unlock with nothing touching the keypad. The self-test view lives under
    // Debug -> Selftest instead.
    // The nickname and the login preferences, if the owner set any. Reading them needs no
    // secret -- the pre-login blob is under a key of zero bytes -- and every failure is
    // silent and means the defaults, because a device whose settings cannot be read must
    // still ask for its PIN. `unlock` shows the nickname once the device has attached to USB.
    #[cfg(not(feature = "board-mk3"))]
    // SAFETY: once, here, before anything else touches the settings volume.
    let prefs = unsafe { crate::settings::load_prelogin() };
    #[cfg(feature = "board-mk3")]
    let prefs = pinentry::LoginPrefs::default();

    crate::catlog!("pin: prompting");
    let (unlocked, mut login) = pinentry::unlock(&gate, &mut panel, &mut matrix, &mut drbg, prefs);
    crate::catlog!("pin: unlocked");

    // microSD 2FA, where it is enrolled: the card before the menu, or the seed goes.
    // Release builds only; see `crate::guard`.
    #[cfg(all(not(feature = "dev"), not(feature = "board-mk3")))]
    if matches!(unlocked, pinentry::Unlocked::In { zero_secret: false }) {
        crate::guard::check_card(&gate, &mut login);
    }

    // The PIN is in. Upgrades are allowed from here; a blank device reaches this too,
    // which is what keeps a unit with no PIN set recoverable.
    usbtask::unlocked();

    // `unlock` only returns once the PIN is in -- a blank device is offered setup
    // rather than being turned away, so there is no longer a state where the front
    // panel has nothing to offer.
    let no_seed = matches!(unlocked, pinentry::Unlocked::In { zero_secret: true });
    // The bootloader's own verdict on the secret slot, written down.
    //
    // It is not exposed over USB -- Identify's BLANK bit means "no PIN", a different
    // thing -- so until this line the only way to know whether a wallet existed was to
    // look at the menu and see whether "Destroy seed" was on it. That is no way to
    // diagnose a wipe that did not take.
    crate::catlog!(
        "pin: secret slot {}",
        if no_seed { "EMPTY" } else { "IN USE" }
    );
    // Name the wallet on the status bar from the first frame. One seed stretch, here,
    // where the owner has just entered a PIN and is waiting for the menu -- rather than
    // on the bar's own account, which is painted every frame and must never be the
    // reason a seed is read. Skipped on a device with no wallet to name.
    #[cfg(feature = "board-q1")]
    if !no_seed {
        crate::pubkeys::warm_fingerprint(&gate, &mut login, &mut panel);
    }

    // Move the pool out of the report rather than borrowing it from inside: the menu
    // holds `&report` for as long as it runs, so a `&mut` into the same struct could
    // never coexist with it. Nothing reads `report.pool` after this point -- the UI DRBG
    // was spawned above, and the selftest screen reports `entropy`, not the pool.
    let mut pool = report.pool.take();

    // The menu runs as a kernel task from here on, with USB and a heartbeat beside it --
    // proven on mk3, mk4, mk5 and Q1 under Debug -> Kernel UI before being made the
    // default. It starts only after the PIN is in, so the prompt a locked unit depends on
    // is exactly the polled one it always was.
    //
    // Holding cancel while the PIN is checked skips it for this session and runs the menu
    // polled, as before. The check happens before the kernel exists, so it still works if
    // the kernel is what went wrong -- on a locked board that is the difference between a
    // power cycle and a brick.
    if cancel_held(&mut matrix, &mut drbg) {
        crate::catlog!("boot: cancel held, menu polled without the kernel");
        menu::run(menu::Session {
            gate: &gate,
            login: &mut login,
            panel: &mut panel,
            matrix: &mut matrix,
            drbg: &mut drbg,
            protocol: &mut protocol,
            report: &report,
            no_seed,
            pool: pool.as_mut(),
        })
    }
    crate::catlog!("boot: menu as a kernel task");
    crate::ktest::start_menu(
        &gate,
        &mut login,
        &mut panel,
        &mut matrix,
        &mut drbg,
        &mut protocol,
        &report,
        pool.as_mut(),
    )
}

/// Whether cancel is down right now, sampled for long enough for the keypad's debounce to
/// settle on a key that was already held when sampling began.
///
/// **A hold, not a press.** This used to return true the moment a `Pressed` event for
/// cancel appeared anywhere in the sampling window, which is a different question: a
/// press is an edge, and one glitchy scan manufactures one. Getting it wrong is not a
/// small thing -- a false positive runs the whole session's menu polled on the main
/// stack, which is what SRAM1 has left after `.bss`, with none of the kernel's stack
/// guard or heartbeat behind it.
///
/// So the window is scanned to let the debounce settle, and then the question is asked
/// of the settled state: is the key *still* down. A glitch has to last the whole window
/// to pass that, and a finger holding the key passes it every time.
fn cancel_held(matrix: &mut keypad::GpioMatrix, drbg: &mut catcard_entropy::HmacDrbg) -> bool {
    use catcard_ui::keypad::{Event, KEYS, Key};
    // A fresh scanner reads a key that is already down as a new press, which is exactly the
    // question here.
    let mut pad = keypad::Keypad::new();
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    // SAFETY: reads RCC only.
    let per_ms = (unsafe { catcard_hal::clock::hclk_hz() } / 1000).max(1);
    // Twenty samples at 10 ms is 200 ms: several times the debounce, and short enough
    // that nobody holding the key notices the wait.
    let mut held_for = 0u32;
    for _ in 0..20 {
        pinentry::pressed_keys(&mut pad, matrix, drbg, &mut events, &mut keys);
        // Held through the last stretch of the window, not merely seen once in it.
        held_for = if pad.holds(Key::Cancel) {
            held_for + 1
        } else {
            0
        };
        catcard_hal::dwt::delay_cycles(10 * per_ms);
    }
    held_for >= 3
}

/// Ask about a staged firmware image.
///
/// Everything the approval knows that a person would want before saying yes: which
/// build, which key signed it, whether it is older than what is running, and -- the one
/// line that must never be missing -- whether installing it sets the bootloader's OTP
/// anti-downgrade mark. That mark is the only irreversible thing an install can do:
/// after it, stock firmware and every earlier CatCard are refused forever. It gets its
/// own two lines here and a second question in the menu, the way destroying a seed does.
pub(crate) fn show_offer(panel: &mut display::Panel, a: &catcard_upgrade::Approval) {
    use core::fmt::Write as _;

    // The version *and* the build time. Two builds of the same firmware carry the same
    // version string and differ only in the timestamp, so on a bench -- or against a
    // release someone published a date for -- the version alone does not say which image
    // this is.
    let stamp = catcard_fwhdr::format_timestamp(&a.header.timestamp);
    let mut line: heapless::String<40> = heapless::String::new();
    let _ = write!(
        line,
        "{}  {}",
        a.header.version_str().unwrap_or("unknown version"),
        core::str::from_utf8(&stamp).unwrap_or("")
    );

    // Whose key signed the image. Every image that reaches this screen has a signature
    // that *verified* -- a bad one is refused before here -- so the question is which
    // key, and what that key means.
    //
    // A downgrade is reported, not refused: going back to older or stock firmware is a
    // legitimate thing to want, and the bootloader holds the final say through its OTP
    // high-water mark. But "reported" has to mean on this screen, not only in the USB
    // reply, or the person at the keys is the one party not told.
    let mut lines: heapless::Vec<&str, 5> = heapless::Vec::new();
    let _ = lines.push(line.as_str());
    let _ = lines.push(signature_status(a));
    if a.older_than_running {
        let _ = lines.push("older than running");
    }
    if sets_high_water(a) {
        let _ = lines.push("SETS ANTI-DOWNGRADE MARK");
        let _ = lines.push("irreversible: no way back");
    }
    display::draw(panel, |c| {
        catcard_ui::widgets::info(c, &display::LAYOUT, "Install firmware?", &lines);
    });
}

/// Whether installing this image records a new anti-downgrade high-water mark.
///
/// `install_flags & HIGH_WATER` (firmware-signing.md §1 [C]): the bootloader writes the
/// image's timestamp to OTP, and from then on refuses anything older -- stock firmware
/// included. Irreversible, so every layer that can see it names it: this screen, the
/// second question in the menu, and the log.
pub(crate) fn sets_high_water(a: &catcard_upgrade::Approval) -> bool {
    a.header.install_flags & catcard_fwhdr::install_flags::HIGH_WATER != 0
}

/// A short line naming which key signed an image, for the offer screen and the log.
///
/// The firmware now holds all six approved public keys, so a Coinkite-signed image (e.g.
/// stock firmware) can be named as such rather than dismissed as "not checked". A dev-key
/// signature is intact but attests nothing -- its private half is public, so anyone can
/// produce it. `UntrustedSlot` is a valid production signature this board's bootloader
/// will not boot (slot 5 on mk3).
pub(crate) fn signature_status(a: &catcard_upgrade::Approval) -> &'static str {
    use catcard_upgrade::Signature;
    match a.signature {
        Signature::FactoryKey { slot: 1 } => "Coinkite signed",
        Signature::FactoryKey { .. } => "Coinkite signed (key 2+)",
        Signature::DeveloperKey => "dev key (not genuine)",
        Signature::UntrustedSlot { .. } => "signed, not valid here",
    }
}

/// The device's USB serial number: its unique ID, in hex.
fn serial() -> &'static str {
    static mut SERIAL: [u8; catcard_board::memory::fixed::UNIQUE_ID_LEN * 2] = [b'0'; 24];
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    // SAFETY: written once, before USB is initialised, from the only caller; the boot
    // path is single-threaded and no interrupt reads it.
    unsafe {
        let uid = catcard_hal::uid::read();
        let out = &mut *core::ptr::addr_of_mut!(SERIAL);
        for (i, b) in uid.iter().enumerate() {
            out[i * 2] = HEX[(b >> 4) as usize];
            out[i * 2 + 1] = HEX[(b & 0xF) as usize];
        }
        core::str::from_utf8(out).unwrap_or("CATCARD")
    }
}
