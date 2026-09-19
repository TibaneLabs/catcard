//! Reading a QR code with the Q1's scanner.
//!
//! The module is a decoded-barcode engine on USART2, not a camera: it images and decodes
//! on its own and hands back plain text. [`catcard_qr`] holds the wire format, tested
//! against the reference's own worked example; [`catcard_hal::usart`] holds the port.
//! This is the sequence between them, and the screen.
//!
//! # Why it probes
//!
//! The module's baud rate is whatever it was left at, and nothing on the board says
//! which. So a version query goes out at each rate in turn until one answers, and then
//! the link is locked to 57600. Stock does the same, and bounds its attempts; an
//! unbounded probe on a module that is unplugged or asleep is a device that stops.
//!
//! # Where this differs from stock
//!
//! Stock configures the module **once**, early after boot, and then sleeps it; a scan
//! wakes it, reads, and sleeps it again. This resets and reconfigures on every scan,
//! which costs the two-second recovery each time. The idle state is the same -- asleep,
//! reset released -- and that is the part that matters for a battery, but the wait is
//! ours and stock does not pay it.
//!
//! Source: hw-reference/qr.md [C]

use catcard_hal::usart::Usart;
use catcard_qr::{cmd, wrap};

use crate::menu;
use crate::ui::Ui;

/// Loop iterations a single byte may take. At 9600 baud a byte is about a millisecond,
/// and this is generous against that rather than tuned to it: the cost of being wrong
/// high is a slower failure, and of being wrong low is a working scanner called broken.
const BYTE_BUDGET: u32 = 400_000;

/// How long the reset line is held low: 10 ms, per the reference.
const RESET_MS: u32 = 10;
/// And how long the module needs afterwards before it will answer: two seconds.
const RECOVERY_MS: u32 = 2_000;

/// Attempts at finding the baud rate. Stock uses five; past that the module is not
/// there, and trying forever would be a screen that never comes back.
const PROBE_TRIES: usize = 5;
/// Attempts at the configuration sequence, as stock bounds it.
const SETUP_TRIES: usize = 3;
/// How long to give the module to answer before reading its reply.
const REPLY_MS: u32 = 10;
/// Attempts at waking: the first is always lost, so one try is no try at all.
const WAKE_TRIES: usize = 5;
/// Between the two sleep commands, for the module's second sleep layer.
const SLEEP_GAP_MS: u32 = 150;
/// Attempts at stopping. Stock uses three, because a fresh read can land in the gap
/// between deciding to stop and saying so.
const STOP_TRIES: usize = 3;
/// Bytes the drain will throw away before it gives up on the line going quiet. A
/// version-40 code is 4350, so this is a code and a bit.
const DRAIN_LIMIT: usize = 5_000;

/// The longest decoded QR this will hand back.
///
/// The module can produce a version-40 code, which is more than any screen can show and
/// more than the 8 KB stack a screen gets. What arrives past this is dropped, and the
/// screen says the code was too long rather than showing a truncated prefix of it --
/// half an address is not an address.
pub const MAX_TEXT: usize = 512;

/// Why a scan did not produce anything.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Fault {
    /// This board has no scanner in its table.
    NoScanner,
    /// No rate answered the version query, so nothing is listening.
    NotFound,
    /// It answered, but would not take the setup.
    SetupRefused,
    /// Nothing was read before the owner gave up.
    Cancelled,
    /// A code was read that is longer than [`MAX_TEXT`].
    TooLong,
}

/// Send one framed command and return whatever frame comes back.
///
/// **Silence is the negative.** There is no NACK on this wire, so not hearing back is
/// the failure, and the budget is what turns that into an answer.
fn ask(port: &mut Usart, body: &[u8], reply: &mut [u8; 64]) -> Option<usize> {
    let mut out = [0u8; 64];
    let frame = wrap(catcard_qr::FID_COMMAND, body, &mut out).ok()?;
    port.flush_input();
    port.write(frame, BYTE_BUDGET).ok()?;
    // Let it answer before deciding it did not. A framed acknowledgement is eight bytes
    // -- about 1.4 ms at 57600 -- and the module thinks first. Reading immediately is
    // what made the lamp report "silence" for commands that plainly worked, and here it
    // would mean a scan-start that succeeded looking like one that failed.
    catcard_hal::dwt::delay_cycles(ms_cycles(REPLY_MS));
    let n = port.read(reply, BYTE_BUDGET);
    (n > 0).then_some(n)
}

/// Stop scanning and put the module away.
///
/// Retried, because the module may be part-way through a read when the stop arrives and
/// answers with the code rather than with an acknowledgement. Each attempt clears the
/// stream first, so the reply being read is a reply and not the tail of a barcode.
///
/// If it will not answer at all, fall back to saying it blindly at both rates: a scanner
/// left running is a lamp that stays on and a module that never sleeps, and by then the
/// screen has gone and nobody is coming back to fix it.
///
/// Source: hw-reference/qr.md §6 [C]
fn stop(port: &mut Usart) {
    for _ in 0..STOP_TRIES {
        port.drain(DRAIN_LIMIT, BYTE_BUDGET / 64);
        if command(port, cmd::SCAN_STOP) {
            let _ = command(port, cmd::TORCH_OFF);
            sleep(port);
            return;
        }
    }
    crate::catlog!("qr: stop was not acknowledged; shutting the module down blind");
    // Which now sleeps it too, at both rates. It used to stop it and then sleep at
    // whichever rate the port happened to be set to, so the module we had just failed
    // to talk to was left awake with its aimer on.
    blind_shutdown(port);
}

/// Tell it to stop at every rate it might be listening at, without waiting to be
/// answered.
///
/// The prelude to probing: a module left running from a previous session cannot be
/// probed until it stops talking, and it cannot be asked politely because its rate is
/// the very thing that is unknown. It stops there and stays awake, because the next
/// thing that happens is a question.
fn blind_stop(port: &mut Usart) {
    for rate in catcard_qr::BAUDS {
        port.set_baud(rate);
        let mut out = [0u8; 64];
        for body in [cmd::SCAN_STOP, cmd::TORCH_OFF] {
            if let Ok(frame) = wrap(catcard_qr::FID_COMMAND, body, &mut out) {
                let _ = port.write(frame, BYTE_BUDGET);
            }
        }
        // Whatever it was mid-way through saying is not an answer to anything.
        port.drain(DRAIN_LIMIT, BYTE_BUDGET / 64);
    }
}

/// Stop it **and put it to sleep**, at every rate it might be listening at.
///
/// For walking away from a module we could not get an answer out of. Stopping is not
/// enough: an awake module drives the aimer, so one that is merely stopped sits there
/// with its red light on and its current drawn until something else resets it. That is
/// what "the scanner does not switch off at boot" was -- the stop landed and the sleep
/// went out at one rate, chosen by whichever rate the probe happened to end on, which on
/// a failed probe is not the rate the module is listening at.
///
/// Source: hw-reference/qr.md §7, which spells the recovery out as both bauds getting
/// `S_CMD_020D`, `S_CMD_03L0`, then `SRDF0050` twice. [C]
fn blind_shutdown(port: &mut Usart) {
    blind_stop(port);
    // Twice, 150 ms apart, for the module's two sleep layers -- and at both rates,
    // since not knowing the rate is the reason to be here.
    for _ in 0..2 {
        for rate in catcard_qr::BAUDS {
            port.set_baud(rate);
            bare(port, cmd::SLEEP);
        }
        catcard_hal::dwt::delay_cycles(ms_cycles(SLEEP_GAP_MS));
    }
}

/// Send one framed command and require its acknowledgement.
fn command(port: &mut Usart, body: &[u8]) -> bool {
    let mut reply = [0u8; 64];
    let Some(n) = ask(port, body, &mut reply) else {
        return false;
    };
    matches!(catcard_qr::unwrap(&reply[..n]), Ok(f) if catcard_qr::is_ack(&f))
}

/// Send a command the module expects **unframed**: sleep and wake.
fn bare(port: &mut Usart, body: &[u8]) {
    let _ = port.write(body, BYTE_BUDGET);
}

/// Wake the module, retrying: the first send lands while it is still down and is lost.
fn wake(port: &mut Usart) {
    for _ in 0..WAKE_TRIES {
        bare(port, cmd::WAKE);
        let mut reply = [0u8; 16];
        if port.read(&mut reply, BYTE_BUDGET / 16) > 0 {
            return;
        }
    }
}

/// Put it back to sleep. Twice, because the module has two sleep layers and one command
/// only reaches the first.
fn sleep(port: &mut Usart) {
    bare(port, cmd::SLEEP);
    catcard_hal::dwt::delay_cycles(ms_cycles(SLEEP_GAP_MS));
    bare(port, cmd::SLEEP);
}

/// Find the rate the module is listening at, and lock the link to 57600.
///
/// A module still scanning from a previous session answers a version query with barcode
/// data, or with nothing, so the probe reads as "no scanner" on hardware that is sitting
/// right there working. Quieten it first: the stop goes out blind at both rates, because
/// the whole point is that we do not yet know which one it is listening at.
fn find(port: &mut Usart) -> Result<(), Fault> {
    blind_stop(port);
    for _ in 0..PROBE_TRIES {
        for rate in catcard_qr::BAUDS {
            port.set_baud(rate);
            // The version query answers with a *version*, not an acknowledgement, so
            // this is the one command whose reply is read for what it is. Requiring an
            // ack here declares a module that is answering to be absent.
            let mut reply = [0u8; 64];
            let answered = ask(port, cmd::VERSION, &mut reply).is_some_and(|n| {
                matches!(catcard_qr::unwrap(&reply[..n]), Ok(f) if catcard_qr::is_version(f.body))
            });
            if answered {
                // Found it. Ask for the fast rate and follow it there; if the module
                // does not take the change, carry on at the rate that answered rather
                // than moving to one nothing is listening at.
                let mut settled = rate;
                if rate != 57_600 && command(port, cmd::BAUD_57600) {
                    port.set_baud(57_600);
                    settled = 57_600;
                }
                // The rate the module ends on, **not** the one that answered. A reset
                // leaves it at its 9600 default -- which is why stock opens there -- so
                // the probe almost always answers at 9600 and is then moved. Recording
                // the answering rate left the lamp talking at 9600 to a module listening
                // at 57600, which reads exactly like a module that is not there.
                crate::torch::note_rate(settled);
                return Ok(());
            }
        }
    }
    // Nothing answered. Leave it stopped rather than however it was found: the commonest
    // reason to be here is a module that was left scanning, and walking away from it
    // still scanning is what made this screen fail the *next* time too.
    blind_shutdown(port);
    Err(Fault::NotFound)
}

/// Put the module into a known state.
///
/// The whole sequence, in order: the trigger mode, the sleep behaviour and the
/// continuous-read timings all have to be set or the module scans on rules nobody chose,
/// and the last command locks the setting codes so a configuration barcode cannot
/// reprogram it. Retried as a whole, as stock retries it -- a step that times out leaves
/// the module half-configured, and the cure is to start again rather than to carry on.
fn setup(port: &mut Usart) -> Result<(), Fault> {
    for _ in 0..SETUP_TRIES {
        if cmd::CONFIG.iter().all(|body| command(port, body)) {
            return Ok(());
        }
    }
    Err(Fault::SetupRefused)
}

/// Read one decoded code, or stop when the owner cancels.
///
/// A decoded QR does not arrive framed: setup asked for plain text ending in CRLF, so
/// this reads bytes until that terminator. Anything the module cannot express as text
/// arrives as its own message, which is a *decoded answer* and not the code's contents.
fn read_code(port: &mut Usart, ui: &mut Ui<'_>, out: &mut [u8]) -> Result<usize, Fault> {
    let mut n = 0;
    let mut overflowed = false;
    loop {
        let mut byte = [0u8; 1];
        if port.read(&mut byte, BYTE_BUDGET / 8) == 1 {
            match byte[0] {
                b'\r' => {}
                b'\n' if n > 0 || overflowed => {
                    return if overflowed {
                        Err(Fault::TooLong)
                    } else {
                        Ok(n)
                    };
                }
                b'\n' => {}
                b => {
                    if n < out.len() {
                        out[n] = b;
                        n += 1;
                    } else {
                        overflowed = true;
                    }
                }
            }
            continue;
        }
        // Nothing arrived this time round: give the owner a chance to leave. The scan is
        // continuous, so without this the only way out would be the power button.
        if menu::cancel_pressed(ui) {
            return Err(Fault::Cancelled);
        }
    }
}

/// Put the module into a known state once, early in the boot.
///
/// Until this ran, the module was in whatever state the bootloader or the last session
/// left it: never configured, still scanning, or asleep -- and a lamp command to a
/// module in an unknown state does nothing you can predict. Stock does the same thing at
/// the same point, and for the same reason.
///
/// Ends **asleep with reset released**, which is the idle state the reference describes:
/// the module keeps its configuration and draws almost nothing, and a scan or the lamp
/// wakes it. Leaving it awake would run the illumination on a battery device.
///
/// Costs the reset recovery -- two seconds -- once per boot rather than once per scan.
/// Failure is silent: a board with no module, or one that will not answer, must not stop
/// a boot over a scanner nobody has asked to use yet.
///
/// Source: hw-reference/qr.md §2 [C]
pub(crate) fn boot_bringup() {
    let Some(scanner) = catcard_board::BOARD.qr else {
        return;
    };
    // SAFETY: bring-up, before any screen exists; nothing else has these pins or USART2.
    let mut port = unsafe {
        catcard_hal::usart::pulse_reset(scanner.reset, ms_cycles(RESET_MS));
        catcard_hal::dwt::delay_cycles(ms_cycles(RECOVERY_MS));
        Usart::init(scanner.tx, scanner.rx, catcard_qr::BAUDS[0])
    };
    // Asleep either way: a module that answered but would not configure is still a
    // module that should not sit there drawing current. This is the idle state the
    // reference describes -- asleep, reset released, configuration retained -- and on a
    // battery device it is the difference between a scanner and a flat battery.
    //
    // *How* it is put to sleep depends on whether we know what it is listening to. A
    // configured module is at 57600 and can be told; one that never answered has to be
    // told at every rate, which is the case that was getting a sleep sent at the rate
    // the probe gave up on and leaving the aimer lit for the whole session.
    match find(&mut port).and_then(|()| setup(&mut port)) {
        Ok(()) => {
            crate::catlog!("qr: configured, sleeping");
            sleep(&mut port);
        }
        Err(why) => {
            crate::catlog!("qr: not configured at boot: {:?}; blind shutdown", why);
            blind_shutdown(&mut port);
        }
    }
}

/// Bring the scanner up, read one code, and put it back to sleep.
fn scan(ui: &mut Ui<'_>, out: &mut [u8]) -> Result<usize, Fault> {
    let scanner = catcard_board::BOARD.qr.ok_or(Fault::NoScanner)?;

    // The lamp holds the same port between presses; it stands down while a scan owns it.
    crate::torch::release();
    menu::blocking_screen(ui.panel, "Scan QR", "waking the scanner");
    // SAFETY: the board table's scanner pins, and USART2, belong to this screen: nothing
    // else in the firmware touches either, and the menu waits for this to return.
    let mut port = unsafe {
        catcard_hal::usart::pulse_reset(scanner.reset, ms_cycles(RESET_MS));
        catcard_hal::dwt::delay_cycles(ms_cycles(RECOVERY_MS));
        Usart::init(scanner.tx, scanner.rx, catcard_qr::BAUDS[0])
    };

    let outcome = run(&mut port, ui, out);

    // **Every path out of here stops the module.** It used to be stopped only after a
    // read returned, so the early exits above it -- a probe that found nothing, a setup
    // that was refused, and worst of all a scan-start whose acknowledgement was missed
    // -- all left it running. That last one is the real one: the command lands, the
    // reply is not seen, and the screen goes away leaving the aimer lit and the module
    // awake until something resets it.
    stop(&mut port);
    outcome
}

/// The scan itself, so that whichever way it ends the caller can stop the module.
fn run(port: &mut Usart, ui: &mut Ui<'_>, out: &mut [u8]) -> Result<usize, Fault> {
    wake(port);
    find(port)?;
    setup(port)?;

    menu::blocking_screen(ui.panel, "Scan QR", "point it at a code");
    if !command(port, cmd::SCAN_START) {
        return Err(Fault::SetupRefused);
    }
    read_code(port, ui, out)
}

/// Milliseconds as CPU cycles.
fn ms_cycles(ms: u32) -> u32 {
    // SAFETY: reads RCC only.
    let hz = unsafe { catcard_hal::clock::hclk_hz() };
    (hz / 1_000).saturating_mul(ms)
}

/// The Scan QR screen: read a code and show what it said.
pub(crate) fn screen(ui: &mut Ui<'_>) {
    let mut text = [0u8; MAX_TEXT];
    match scan(ui, &mut text) {
        Ok(n) => show(ui, &text[..n]),
        Err(Fault::Cancelled) => {}
        Err(why) => {
            menu::message(ui.panel, "Scan QR", describe(why), "any key to go back");
            menu::wait_for_any_key(ui);
        }
    }
}

/// Show what was read.
///
/// Only shown, for now: nothing here decides that a string is an address or a PSBT and
/// acts on it. Reading a code and acting on one are different features, and the second
/// is where a wrong guess sends money somewhere.
fn show(ui: &mut Ui<'_>, raw: &[u8]) {
    use catcard_ui::scroll::Line as Row;

    let text = core::str::from_utf8(raw).unwrap_or("(not text)");
    let text = if raw == catcard_qr::UNSUPPORTED {
        // The module's way of saying it read a code that held bytes rather than
        // characters. Passing it on as the contents would be a lie about what is there.
        "the code was not text"
    } else {
        text
    };
    let mut rows: heapless::Vec<Row, 4> = heapless::Vec::new();
    let _ = rows.push(Row::title("Scanned"));
    let _ = rows.push(Row::body(text).small());
    let _ = menu::show_doc(ui, &rows, false, false);
}

fn describe(why: Fault) -> &'static str {
    match why {
        Fault::NoScanner => "this board has no scanner",
        Fault::NotFound => "the scanner did not answer",
        Fault::SetupRefused => "the scanner refused setup",
        Fault::Cancelled => "cancelled",
        Fault::TooLong => "that code is too long to show",
    }
}
