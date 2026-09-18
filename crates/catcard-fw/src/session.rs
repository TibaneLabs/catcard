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

    // The scan-order shuffle draws from the UI domain, never from the seed pool.
    let drbg = report
        .pool
        .as_mut()
        .and_then(|pool| spawn_drbg(pool, domain::UI, &[]).ok());

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
    // A device that cannot run the front panel -- no panel, no keypad, or no UI DRBG to
    // shuffle the scan with -- must still be reprogrammable, or a board whose drivers are
    // missing (Q1 today) runs a validly-signed image that nothing can replace. On a bench
    // build `recovery` runs the unlock and the install over USB; on any other build it is
    // the park this used to be. Taken one at a time so a device with a working panel but
    // no keypad keeps what is on its screen.
    let Some(mut panel) = panel else {
        crate::recovery::run(report, None, gate)
    };
    let (Some(mut matrix), Some(mut drbg)) = (matrix, drbg) else {
        crate::recovery::run(report, Some(panel), gate)
    };

    // No boot selftest screen: boot goes straight to the PIN prompt, so a host can drive
    // an unlock with nothing touching the keypad. The self-test view lives under
    // Debug -> Selftest instead.
    // The nickname, if the owner set one. Reading it needs no secret -- the pre-login blob
    // is under a key of zero bytes -- and every failure is silent, because a device whose
    // nickname cannot be read must still ask for its PIN. `unlock` shows it, once the
    // device has attached to USB.
    #[cfg(not(feature = "board-mk3"))]
    // SAFETY: once, here, before anything else touches the settings volume.
    let nick = unsafe { crate::settings::load_nickname() };
    #[cfg(feature = "board-mk3")]
    let nick = None;

    crate::catlog!("pin: prompting");
    let (unlocked, mut login) = pinentry::unlock(&gate, &mut panel, &mut matrix, &mut drbg, nick);
    crate::catlog!("pin: unlocked");

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
        &report,
        pool.as_mut(),
    )
}

/// Whether cancel is down right now, sampled for long enough for the keypad's debounce to
/// settle on a key that was already held when sampling began.
fn cancel_held(matrix: &mut keypad::GpioMatrix, drbg: &mut catcard_entropy::HmacDrbg) -> bool {
    use catcard_ui::keypad::{Event, KEYS, Key};
    // A fresh scanner reads a key that is already down as a new press, which is exactly the
    // question here.
    let mut pad = keypad::Keypad::new();
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    // SAFETY: reads RCC only.
    let per_ms = (unsafe { catcard_hal::clock::hclk_hz() } / 1000).max(1);
    for _ in 0..20 {
        pinentry::pressed_keys(&mut pad, matrix, drbg, &mut events, &mut keys);
        if keys.contains(&Key::Cancel) {
            return true;
        }
        catcard_hal::dwt::delay_cycles(10 * per_ms);
    }
    false
}

/// Ask about a staged firmware image.
///
/// Says whether the signature was checked, in those words. "Unverified" here does not
/// mean "bad" -- the five factory keys are not published, so an official image cannot be
/// checked on-device at all -- but it is the difference between a claim we can stand
/// behind and one we cannot, and the person about to overwrite their firmware is the one
/// who should weigh it.
pub(crate) fn show_offer(panel: &mut display::Panel, a: &catcard_upgrade::Approval) {
    // State whose key signed the image. Every image that reaches this screen has a
    // signature that *verified* -- a bad one is refused outright before here -- so the
    // question is which key, and what that key means. We deliberately do not warn about a
    // downgrade: going back to older or stock firmware is a legitimate thing to want, and
    // the bootloader holds the final say through its OTP high-water mark.
    message(
        panel,
        "Install firmware?",
        a.header.version_str().unwrap_or("unknown version"),
        signature_status(a),
    );
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

/// Draw up to three lines and return.
fn message(panel: &mut display::Panel, head: &str, a: &str, b: &str) {
    display::draw(panel, |c| {
        catcard_ui::widgets::message(c, &display::LAYOUT, head, a, b);
    });
}
