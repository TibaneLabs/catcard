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
use zeroize::Zeroize as _;

use catcard_callgate::Callgate;

use crate::menu;
use crate::sniff::Content;
use crate::ui::Ui;

/// Loop iterations a single byte may take. At 9600 baud a byte is about a millisecond,
/// and this is generous against that rather than tuned to it: the cost of being wrong
/// high is a slower failure, and of being wrong low is a working scanner called broken.
const WIRE_MS: u32 = 20;

/// How long the reset line is held low: 10 ms, per the reference.
const RESET_MS: u32 = 10;
/// And how long the module needs afterwards before it will answer: two seconds.
///
/// Only the Debug probe waits this out blindly, because its question is "what does this
/// module say when asked cold" and an answer that arrived because we kept asking would
/// be a different measurement. Everything else polls to [`CONTACT_MS`] instead and
/// carries on the moment the module speaks.
const RECOVERY_MS: u32 = 2_000;

/// Attempts at the configuration sequence, as stock bounds it.
const SETUP_TRIES: usize = 3;
/// How long to wait for the *first* byte of a reply.
///
/// The module thinks before it answers, and at the slowest rate the reply is several
/// milliseconds of wire time on top. Generous, because the cost of being wrong here is
/// declaring a working module absent.
const FIRST_MS: u32 = 60;
/// And between the bytes of one reply, which arrive back to back.
const GAP_MS: u32 = 5;
/// Attempts at waking: the first is always lost, so one try is no try at all.
const WAKE_TRIES: usize = 5;
/// How long the line must stay silent before a stop is believed.
///
/// Long enough to outlast the gap between two decoded codes, short enough that three
/// tries do not hold the screen. A module that is still scanning talks inside this.
const QUIET_MS: u32 = 120;
/// Between the two sleep commands, for the module's second sleep layer.
const SLEEP_GAP_MS: u32 = 150;
/// Attempts at stopping. Stock uses three, because a fresh read can land in the gap
/// between deciding to stop and saying so.
const STOP_TRIES: usize = 3;
/// Bytes the drain will throw away before it gives up on the line going quiet. A
/// version-40 code is 4350, so this is a code and a bit.
const DRAIN_LIMIT: usize = 5_000;

/// How long to keep asking after a reset before calling the module absent.
///
/// The reference says it needs "a full ~2 seconds after a reset pulse before it will
/// talk", and that is a schedule rather than a measurement: waiting it out blindly cost
/// two seconds of every boot and of every scan. So it is a **bound** now. The probe asks
/// from the moment the line is released and stops the instant it gets an answer, which
/// on real hardware is long before this.
///
/// Source: hw-reference/qr.md §2 [C]
const CONTACT_MS: u32 = 2_500;

/// A point in the future, in cycles, for a wait that ends when something happens.
#[derive(Copy, Clone)]
struct Deadline {
    at: u32,
}

impl Deadline {
    fn after(ms: u32) -> Self {
        Deadline {
            at: catcard_hal::dwt::cycles().wrapping_add(ms_cycles(ms)),
        }
    }

    /// Whether it has arrived. Wrapping arithmetic, so the DWT counter rolling over
    /// mid-wait is not a two-minute stall: the comparison is on the *difference*, which
    /// stays small, and spans here are milliseconds against a counter that wraps every
    /// 35 seconds at 120 MHz.
    fn passed(&self) -> bool {
        catcard_hal::dwt::cycles().wrapping_sub(self.at) < u32::MAX / 2
    }
}

/// Whether the module has been configured since this boot.
///
/// Cleared whenever the recovery path runs, which is the reference's own rule: a blind
/// shutdown is followed by a re-initialisation on the next use rather than by carrying
/// on as though the module were still set up. Source: hw-reference/qr.md §2, §6 [C]
static mut CONFIGURED: bool = false;

fn configured() -> bool {
    // SAFETY: foreground only; the borrow ends within this statement.
    unsafe { *core::ptr::addr_of!(CONFIGURED) }
}

fn note_configured(yes: bool) {
    // SAFETY: as above.
    unsafe { *core::ptr::addr_of_mut!(CONFIGURED) = yes };
}

/// The longest decoded QR this will hand back.
///
/// The module can produce a version-40 code, which is more than any screen can show and
/// more than the 8 KB stack a screen gets. What arrives past this is dropped, and the
/// screen says the code was too long rather than showing a truncated prefix of it --
/// half an address is not an address.
pub const MAX_TEXT: usize = 2048;

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
    port.write(frame, ms_cycles(GAP_MS)).ok()?;
    // **Straight into the read.** There used to be a sleep here, to "let it answer
    // before deciding it did not", and it was the bug: the receiver is one byte deep,
    // so while nothing is draining it the reply overruns and all that survives is the
    // first byte. `Debug -> QR probe` showed it exactly -- `57600 framed: 1B 5a`, the
    // STX of a perfectly good frame and nothing else -- and `find` then read a
    // one-byte frame, failed to parse it, and called a module that was answering
    // absent. The wait belongs in the deadline for the first byte, not in a sleep.
    let n = port.read_reply(reply, ms_cycles(FIRST_MS), ms_cycles(GAP_MS));
    (n > 0).then_some(n)
}

/// Stop scanning and put the module away.
///
/// **Silence is the proof, not an acknowledgement.** A stop is sent while the module is
/// mid-sentence -- it is streaming decoded codes, which is the state we are trying to
/// leave -- so its reply lands somewhere after however much barcode was already in
/// flight, past the end of any reply buffer worth having. Waiting for an ack therefore
/// reported failure for stops that had plainly worked, every time, and the fallback
/// path took over: the screen went away and the aimer stayed lit.
///
/// What a stop that landed actually does is make the module stop talking. So that is
/// what is checked.
///
/// The light and the sleep go out **whether or not** the stop was confirmed. They were
/// conditional on it, which meant the one case that needed them most -- a module still
/// running that would not answer -- was the case that skipped them.
///
/// Source: hw-reference/qr.md §6, §7 [C]
fn stop(port: &mut Usart) {
    for _ in 0..STOP_TRIES {
        // Talk over whatever it is saying, then say it -- and **listen for the answer**.
        //
        // This used to drain, send, drain again and then require silence. The second
        // drain gives up after `GAP_MS` of quiet, which is five milliseconds, and the
        // module takes tens to answer: so the drain ended before the acknowledgement
        // arrived, and then the acknowledgement -- the proof that the stop had worked --
        // was the byte that made `quiet` report it had not. Every scan ended in the
        // blind shutdown, on hardware doing exactly as it was told.
        //
        // So the ack is read for what it is, the way every other command here is read,
        // and silence is kept only as the second way to believe it: a module that never
        // acked but has gone quiet has also stopped.
        port.drain(DRAIN_LIMIT, ms_cycles(GAP_MS));
        if command(port, cmd::SCAN_STOP) || quiet(port) {
            let _ = command(port, cmd::TORCH_OFF);
            sleep(port);
            return;
        }
    }
    crate::catlog!("qr: it would not stop talking; shutting the module down blind");
    blind_shutdown(port);
}

/// Whether the module says nothing for [`QUIET_MS`].
///
/// A running scan is never quiet for that long: it is reporting codes, or the aimer is
/// on and it is about to. Silence is what stopping looks like from here.
fn quiet(port: &mut Usart) -> bool {
    let mut byte = [0u8; 1];
    port.read(&mut byte, ms_cycles(QUIET_MS)) == 0
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
                let _ = port.write(frame, ms_cycles(WIRE_MS));
            }
        }
        // Whatever it was mid-way through saying is not an answer to anything.
        port.drain(DRAIN_LIMIT, ms_cycles(GAP_MS));
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
    // Whatever state it is in after this, it is not the configured one. The next use
    // pulses reset and starts again, which is the reference's own recovery.
    note_configured(false);
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
///
/// The ack is looked for *within* the reply rather than as the whole of it. A command
/// sent while the module is scanning is answered in the middle of whatever it was
/// already saying, so an exact match on the buffer fails for a command that worked --
/// which is how every attempt to stop a running scan ended in the blind shutdown.
fn command(port: &mut Usart, body: &[u8]) -> bool {
    let mut reply = [0u8; 64];
    let Some(n) = ask(port, body, &mut reply) else {
        return false;
    };
    catcard_qr::ack_within(&reply[..n])
}

/// Send a command the module expects **unframed**: sleep and wake.
fn bare(port: &mut Usart, body: &[u8]) {
    let _ = port.write(body, ms_cycles(WIRE_MS));
}

/// Wake the module, retrying: the first send lands while it is still down and is lost.
fn wake(port: &mut Usart) {
    for _ in 0..WAKE_TRIES {
        bare(port, cmd::WAKE);
        let mut reply = [0u8; 16];
        if port.read_reply(&mut reply, ms_cycles(FIRST_MS), ms_cycles(GAP_MS)) > 0 {
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
    find_until(port, Deadline::after(CONTACT_MS))
}

/// As [`find`], but keeping at it until `deadline`.
///
/// The rounds are not counted, they are timed: what matters is how long the module has
/// had since its reset, not how many times it has been asked. A module that is ready in
/// a quarter of a second answers the first round and the rest of the budget is never
/// spent.
fn find_until(port: &mut Usart, deadline: Deadline) -> Result<(), Fault> {
    blind_stop(port);
    loop {
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
        if deadline.passed() {
            break;
        }
    }
    // Nothing answered. Leave it stopped rather than however it was found: the commonest
    // reason to be here is a module that was left scanning, and walking away from it
    // still scanning is what made this screen fail the *next* time too.
    blind_shutdown(port);
    Err(Fault::NotFound)
}

/// Have a configured module, resetting it first only if this boot has not done so.
///
/// **The reset is not per scan.** It was: every scan pulsed the line and then waited the
/// full recovery before saying a word, which is two seconds a person stands there for on
/// a screen that has already told them to point the camera. The reference's idle state is
/// *asleep, reset released, configuration retained* -- so a scan on a configured module
/// is a wake and nothing more, and the reset belongs to the paths that have lost track of
/// it: the first use after boot, and anything that has been through a blind shutdown.
///
/// Source: hw-reference/qr.md §2 "configure-once -> sleep -> wake-per-scan -> sleep" [C]
fn ensure(port: &mut Usart, scanner: catcard_board::spec::QrScanner) -> Result<(), Fault> {
    if configured() {
        wake(port);
        return Ok(());
    }
    // SAFETY: the board table's scanner reset pin, which only this module drives.
    unsafe { catcard_hal::usart::pulse_reset(scanner.reset, ms_cycles(RESET_MS)) };
    let deadline = Deadline::after(CONTACT_MS);
    port.set_baud(catcard_qr::BAUDS[0]);
    // Woken at both rates first: a module left asleep by the previous session answers
    // nothing until it is told to wake, and a reset pulse does not change that.
    for rate in catcard_qr::BAUDS {
        port.set_baud(rate);
        wake(port);
    }
    find_until(port, deadline)?;
    setup(port)?;
    note_configured(true);
    Ok(())
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
        if port.read(&mut byte, ms_cycles(GAP_MS)) == 1 {
            match byte[0] {
                b'\r' => {}
                b'\n' if n > 0 || overflowed => {
                    return if overflowed {
                        Err(Fault::TooLong)
                    } else {
                        // **Strip the inline acknowledgements before anyone reads this.**
                        // A bare command sent while the scan is running -- the torch,
                        // above all -- is answered with `0x90 0x00` that lands in the RX
                        // stream amongst the decoded data. A line with those two bytes in
                        // it does not begin `B$` any more, so a BBQr part reads as an
                        // unrecognised payload, and it is no longer text either. The
                        // reference calls this out as the reimplementation gotcha and it
                        // was the one thing here not doing it.
                        //
                        // Safe: a real text QR cannot contain that sequence.
                        //
                        // Source: hw-reference/qr.md §6 [C]
                        Ok(catcard_qr::strip_inline_ack(&mut out[..n]))
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
    let mut port = unsafe { Usart::init(scanner.tx, scanner.rx, catcard_qr::BAUDS[0]) };
    // Asleep either way: a module that answered but would not configure is still a
    // module that should not sit there drawing current. This is the idle state the
    // reference describes -- asleep, reset released, configuration retained -- and on a
    // battery device it is the difference between a scanner and a flat battery.
    //
    // *How* it is put to sleep depends on whether we know what it is listening to. A
    // configured module is at 57600 and can be told; one that never answered has to be
    // told at every rate, which is the case that was getting a sleep sent at the rate
    // the probe gave up on and leaving the aimer lit for the whole session.
    match ensure(&mut port, scanner) {
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

/// Whether a collecting scan wants another code.
#[derive(Copy, Clone, PartialEq, Eq)]
pub(crate) enum Next {
    /// Keep reading. The module stays configured and running.
    More,
    /// Everything has arrived.
    Done,
}

/// Read codes until `on_code` has what it wants, or the owner cancels.
///
/// The animated-QR loop. A payload too large for one symbol arrives as a few hundred of
/// them, shown in a cycle, and the reader takes whichever it catches in whatever order
/// it catches them -- so the module has to stay awake and configured across the whole
/// transfer. Bringing it up per code would cost the two-second reset recovery each time
/// and turn a two-minute transfer into an afternoon.
///
/// `on_code` gets each decoded line and says whether it needs more. Its own screen
/// drawing is up to it: this only draws the first "point it at a code".
///
/// **A single unreadable code is not a failed transfer.** One line longer than
/// [`MAX_TEXT`] is skipped rather than fatal -- the animation comes round again, and
/// giving up on the whole thing because one frame was caught badly is the behaviour that
/// makes people stop trusting the feature.
pub(crate) fn scan_many(
    ui: &mut Ui<'_>,
    head: &str,
    on_code: &mut dyn FnMut(&mut Ui<'_>, &[u8]) -> Next,
) -> Result<(), Fault> {
    let scanner = catcard_board::BOARD.qr.ok_or(Fault::NoScanner)?;

    crate::torch::release();
    // The scanner's own icon while it comes up: the reset and its recovery take a couple
    // of seconds before the first code can be read, and a line of text alone made that
    // look like a device thinking about nothing in particular.
    menu::icon_page(
        ui.panel,
        &catcard_ui::art::menuicons::SCAN_QR_CODE,
        head,
        "waking the scanner",
    );
    // SAFETY: the board table's scanner pins, and USART2, belong to this screen: nothing
    // else in the firmware touches either, and the menu waits for this to return.
    // SAFETY: the board table's scanner pins, and USART2, belong to this screen:
    // nothing else in the firmware touches either, and the menu waits for this to
    // return.
    let mut port = unsafe { Usart::init(scanner.tx, scanner.rx, catcard_qr::BAUDS[0]) };
    // Configured already? Then this is a wake and nothing else. Only a module this boot
    // has never set up -- or one a fault has been through -- pays for a reset here.
    if let Err(why) = ensure(&mut port, scanner) {
        blind_shutdown(&mut port);
        return Err(why);
    }

    let outcome = collect(&mut port, ui, head, on_code);
    // Every path out stops the module, for the reason `scan` gives at length.
    stop(&mut port);
    outcome
}

/// The collecting loop, so that whichever way it ends the caller can stop the module.
fn collect(
    port: &mut Usart,
    ui: &mut Ui<'_>,
    head: &str,
    on_code: &mut dyn FnMut(&mut Ui<'_>, &[u8]) -> Next,
) -> Result<(), Fault> {
    wake(port);
    find(port)?;
    setup(port)?;

    menu::blocking_screen(ui.panel, head, "point it at the codes");
    if !command(port, cmd::SCAN_START) {
        return Err(Fault::SetupRefused);
    }

    // One buffer for the whole transfer rather than one per code: a couple of kilobytes
    // is worth keeping off the stack of every iteration.
    let Some(mut line_mem) = crate::heap::take(MAX_TEXT) else {
        return Err(Fault::TooLong);
    };
    let outcome = loop {
        let line = line_mem.bytes();
        match read_code(port, ui, line) {
            Ok(n) => {
                if on_code(ui, &line_mem.bytes()[..n]) == Next::Done {
                    break Ok(());
                }
            }
            // One badly caught frame. The animation loops, so it comes round again.
            Err(Fault::TooLong) => {}
            Err(why) => break Err(why),
        }
    };
    // **Wiped before the block goes back.** A scanned code can be a whole wallet -- a
    // SeedQR is one -- and the heap's own rule is that nothing keeps key material in a
    // freed block, where it sits in memory nobody is tracking until some later screen
    // happens to be handed the same bytes. Every scan pays a two-kilobyte memset for it,
    // which is nothing against the two seconds this screen already spends on the module.
    line_mem.bytes().zeroize();
    outcome
}

/// Debug: ask the module for its version at each rate and report exactly what came back.
///
/// The scan screen can only say "the scanner did not answer", which is true of a module
/// that is absent, one at a rate nothing is asking at, and one whose replies are not
/// reaching the pin. Those want different fixes, and the log had no way to tell them
/// apart: the torch reports "silence" for commands that visibly work, so the module
/// hears us and we do not hear it, and the next question is whether anything at all
/// arrives on PA3.
///
/// So this reports the raw truth per rate -- bytes in, the first of them, and whether
/// the line showed a framing or overrun error, which is what "wrong rate" looks like as
/// against "nothing connected".
pub(crate) fn probe(ui: &mut Ui<'_>) {
    use core::fmt::Write as _;

    const HEAD: &str = "QR probe";
    let Some(scanner) = catcard_board::BOARD.qr else {
        menu::message(
            ui.panel,
            HEAD,
            "this board has no scanner",
            "any key to go back",
        );
        menu::wait_for_any_key(ui);
        return;
    };

    crate::torch::release();
    menu::blocking_screen(ui.panel, HEAD, "resetting the module");
    // SAFETY: as `scan_many` -- the board table's scanner pins and USART2 belong to this
    // screen, and the menu waits for it to return.
    // The one screen that always resets: its whole job is to answer "does this module
    // say anything at all", from whatever state it is in. Which also means whatever
    // this boot had configured is gone.
    note_configured(false);
    let mut port = unsafe {
        catcard_hal::usart::pulse_reset(scanner.reset, ms_cycles(RESET_MS));
        catcard_hal::dwt::delay_cycles(ms_cycles(RECOVERY_MS));
        Usart::init(scanner.tx, scanner.rx, catcard_qr::BAUDS[0])
    };

    // The text is owned here and the rows borrow it afterwards: a `Line` holds a
    // reference, and the obvious loop would hand it one that dies at the next iteration.
    let mut said: heapless::Vec<heapless::String<64>, 8> = heapless::Vec::new();

    // Both the framed query and a bare one. A module that answers neither is not
    // talking; one that answers the bare command only is in a state the framing is
    // wrong for, which is a different thing entirely.
    for rate in catcard_qr::BAUDS {
        port.set_baud(rate);
        for (what, framed) in [("framed", true), ("bare", false)] {
            port.flush_input();
            let mut out = [0u8; 64];
            if framed {
                if let Ok(frame) = wrap(catcard_qr::FID_COMMAND, cmd::VERSION, &mut out) {
                    let _ = port.write(frame, ms_cycles(WIRE_MS));
                }
            } else {
                let _ = port.write(cmd::VERSION, ms_cycles(WIRE_MS));
            }
            // Generously: at 9600 a framed query is 17 ms on the wire before the module
            // has even heard it, and the reply is another 8. The scan path's budget is
            // tighter than that, which is itself worth knowing.
            catcard_hal::dwt::delay_cycles(ms_cycles(120));
            let mut reply = [0u8; 64];
            let n = port.read_reply(&mut reply, ms_cycles(FIRST_MS), ms_cycles(GAP_MS));

            let mut line: heapless::String<64> = heapless::String::new();
            let _ = write!(line, "{rate} {what}: {n}B");
            for b in reply.iter().take(6.min(n)) {
                let _ = write!(line, " {b:02x}");
            }
            crate::catlog!("qr probe: {}", line.as_str());
            let _ = said.push(line);
        }
    }

    // Leave it as the scan screen would: stopped and asleep, not however it was found.
    blind_shutdown(&mut port);

    let mut rows: heapless::Vec<catcard_ui::scroll::Line, 10> = heapless::Vec::new();
    let _ = rows.push(catcard_ui::scroll::Line::title("QR probe"));
    for line in &said {
        let _ = rows.push(catcard_ui::scroll::Line::body(line).small());
    }
    let _ = menu::show_doc(ui, &rows, false, false);
}

/// Milliseconds as CPU cycles.
fn ms_cycles(ms: u32) -> u32 {
    // SAFETY: reads RCC only.
    let hz = unsafe { catcard_hal::clock::hclk_hz() };
    (hz / 1_000).saturating_mul(ms)
}

/// The Scan QR screen: read whatever is shown, then offer what can be done with it.
///
/// One way in for everything that arrives by camera. A single code holds an address or a
/// key; a few hundred of them hold a PSBT or a whole firmware image, and which of those
/// is being shown is not something a person should have to say in advance -- the codes
/// themselves say it. So this reads first and asks afterwards.
///
/// # Everything lands in PSRAM
///
/// Including a single short code, which does not need it. The point is not the size but
/// the ownership: the moment this screen might be receiving an image, it has to be the
/// only thing using that memory, and deciding that partway through -- after some parts
/// are already somewhere else -- means moving them. So the claim is taken at the door,
/// and a USB upload offered while someone is scanning is refused with "reading a QR"
/// rather than landing on top of it.
pub(crate) fn screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    const HEAD: &str = "Scan QR";

    let lease = match crate::psram::take(crate::psram::Use::AnimatedQr) {
        Ok(l) => l,
        Err(why) => {
            menu::message(ui.panel, HEAD, why.message(), "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        }
    };

    // Written through the staging driver rather than as a plain slice: a quarter of a
    // megabyte stored with whatever the compiler picked, and none of the CE# timing this
    // part needs, is how it loses data.
    let area = match crate::staging::area_from(lease) {
        Ok(a) => a,
        Err(_) => {
            menu::message(ui.panel, HEAD, "no staging area", "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        }
    };
    let mut sink = crate::qrload::Staging::new(area);
    let got = crate::qrload::collect_any(ui, HEAD, &mut sink);
    let mut area = sink.into_area();
    let got = match got {
        Ok(got) => got,
        Err(why) => {
            // **The memory goes back before the message goes up.** A screen waiting for
            // a keypress waits as long as nobody is standing there, and every USB
            // upgrade offered in the meantime is refused with "the PSRAM has reading a
            // QR" -- which is how a scanner that would not answer became a device that
            // would not take firmware.
            drop(area);
            if let Some(why) = why {
                menu::message(ui.panel, HEAD, why, "any key to go back");
                menu::wait_for_any_key(ui);
            }
            return;
        }
    };
    crate::catlog!(
        "qr: received {} bytes{}",
        got.len,
        if got.compressed { ", compressed" } else { "" }
    );

    // A `Z` transfer reassembles the deflate stream, not the file. Expanding it is a
    // pass over the whole thing, so it says so -- on a payload this size it is not
    // instant, and a screen that has stopped changing reads as a device that has hung.
    let len = if got.compressed {
        menu::blocking_screen(ui.panel, HEAD, "expanding");
        let max = catcard_board::BOARD.image_ceiling();
        match crate::inflate::staged(&mut area, got.len as u32, max) {
            Ok(n) => {
                crate::catlog!("qr: expanded to {} bytes", n);
                n as usize
            }
            Err(why) => {
                drop(area);
                menu::message(ui.panel, HEAD, why, "any key to go back");
                menu::wait_for_any_key(ui);
                return;
            }
        }
    } else {
        got.len
    };
    #[cfg(feature = "multichain")]
    let kind = got.kind;
    #[cfg(not(feature = "multichain"))]
    let kind = ();

    // A plain view of the same memory, for looking at what arrived. Reading it back is
    // fine now: every write is done, and it is only a run of writes that a read must not
    // be placed among.
    //
    // **At the area's base, not the lease's.** They are four megabytes apart: the scan
    // wrote through the staging area, which lives in the upper half of the part.
    let base = area.image_at();
    // Mutable for the checksum below, which reads the slice; a build with no BC-UR has
    // nothing to check and hands it on as it is.
    #[cfg_attr(not(feature = "multichain"), allow(unused_mut))]
    let mut lease = area.into_lease();

    // Every part of a UR carried the CRC-32 of the whole message. Counting fragments
    // says every slot was filled; only this says they were filled with the message the
    // headers named, and a message that fails it is not the one that was sent, however
    // many parts it took. BC-UR has no compressed form, so `len` is still the message's
    // own length here and the bytes are the ones the parts carried.
    #[cfg(feature = "multichain")]
    if let Some(expected) = got.checksum
        && catcard_bcur::crc32(&lease.bytes()[base..base + len]) != expected
    {
        crate::catlog!("qr: the UR checksum does not match the assembled message");
        // As above: the memory goes back before the message goes up.
        drop(lease);
        menu::message(
            ui.panel,
            HEAD,
            "the parts did not add up",
            "any key to go back",
        );
        menu::wait_for_any_key(ui);
        return;
    }
    offer(gate, login, ui, HEAD, lease, base..base + len, kind);
}

/// Say what arrived and offer what can be done with it.
///
/// `kind` is what the UR said it was, where this build reads URs at all. On a build with
/// no BC-UR there is nothing a scan could have been wrapped in, so it carries nothing --
/// which keeps one function rather than two that have to be kept in step.
///
/// `lease` is the staging memory as a plain slice, and `payload` is where the bytes sit
/// in it -- starting at the area's offset zero, which is not the lease's. The caller has
/// already checked what it can about those bytes; this only says what they are.
fn offer(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    head: &str,
    mut lease: crate::psram::Lease,
    payload: core::ops::Range<usize>,
    #[cfg(feature = "multichain")] kind: Option<catcard_bcur::registry::Kind>,
    #[cfg(not(feature = "multichain"))] _kind: (),
) {
    let (base, len) = (payload.start, payload.len());

    // A request for a Solana signature is answered where it lands, rather than being
    // turned into a `Content` first. It is not only a payload: it carries the key that
    // is wanted and the handle the answer has to quote, and flattening it into "some
    // bytes that look like a transaction" would throw both away.
    #[cfg(feature = "multichain")]
    if kind == Some(catcard_bcur::registry::Kind::SolSignRequest) {
        crate::solanatx::sign_request(gate, login, ui, &lease.bytes()[base..base + len]);
        return;
    }

    // What the UR said, if it said anything, and otherwise what the bytes look like. A
    // registry item is CBOR, so the payload starts a few bytes into the message --
    // `skip` is that header, and `base` stays where the scan wrote, because the
    // staging area is addressed from there.
    #[cfg(feature = "multichain")]
    let arrival = crate::sniff::from_ur(&lease.bytes()[base..base + len], kind);
    // Nothing arrives wrapped on a build with no BC-UR: what a scan holds is what was
    // scanned, so there is no header to step over.
    #[cfg(not(feature = "multichain"))]
    let arrival: Option<(Content, usize, usize)> = None;
    #[cfg(feature = "multichain")]
    let arrival = arrival.map(|a| (a.what, a.skip, a.len));
    let (what, skip, len) = match arrival {
        Some(a) => a,
        None => (
            crate::sniff::sniff(&lease.bytes()[base..base + len]),
            0,
            len,
        ),
    };
    let at = base + skip;

    // A whole wallet arrived. It is taken out and the memory it came through is wiped
    // before anybody is asked anything: the screens that follow can stand there for as
    // long as nobody is in the room, and the lease is handed back when this returns --
    // to a firmware upload, a soak test, or the next scan, none of which should find a
    // seed lying in it. A SeedQR payload is at most 96 bytes, so the copy is a stack
    // buffer that wipes itself.
    if let Content::Seed(kind) = what {
        use catcard_wallet::seedqr::MAX_DIGITS;
        use core::fmt::Write as _;

        let mut payload = zeroize::Zeroizing::new([0u8; MAX_DIGITS]);
        let len = len.min(MAX_DIGITS);
        payload[..len].copy_from_slice(&lease.bytes()[at..at + len]);
        wipe(lease, len);
        // Which shape it was, because the two differ in what a misread costs: a Standard
        // code that was read wrong is refused by its checksum, and a Compact one cannot
        // be.
        let mut note: heapless::String<32> = heapless::String::new();
        let _ = write!(note, "a seed backup, {}", kind.name());
        if menu::choose(ui, head, &note, &["Load it"]).is_some() {
            crate::seedqr::received(gate, login, ui, &payload[..len], kind);
        }
        return;
    }
    // What arrived, when it was nothing this device can use. The screen has room for a
    // length and a word, and the length alone has never been enough to say what went
    // wrong: a line with two stray bytes in it and a line that is genuinely not ours
    // look identical from there.
    if matches!(what, Content::Unknown) {
        let head = &lease.bytes()[at..at + len.min(16)];
        crate::catlog!("qr: {} bytes, not recognised; starts {:02x?}", len, head);
    } else {
        // What it turned out to be, and whether a UR wrapper came off on the way. The
        // log had the failures and not the successes, which is the wrong way round when
        // the question is "it read something, but not the something I sent".
        crate::catlog!("qr: {} bytes at +{}, {}", len, skip, what.note());
    }
    // Everything worth doing with it, as a list: what this firmware makes of the bytes,
    // and keeping them whatever they are. `choices` is shared with the tag, so a code and
    // a tap offer the same things.
    let choices = what.choices();
    let mut rows: heapless::Vec<&str, 3> = heapless::Vec::new();
    for (label, _) in &choices {
        let _ = rows.push(label);
    }
    let mut said: heapless::String<40> = heapless::String::new();
    use core::fmt::Write as _;
    let _ = write!(said, "{len} bytes, {}", what.note());
    let Some(chosen) = menu::choose(ui, head, &said, &rows) else {
        return;
    };
    if choices[chosen].1 == crate::sniff::Act::Save {
        crate::sniff::save_to_card(ui, &lease.bytes()[at..at + len], what);
        return;
    }
    // A signing request: text in the three-line form, or just a message. The parser
    // behind it says what it makes of the bytes, so nothing is decided here.
    if choices[chosen].1 == crate::sniff::Act::Sign {
        match core::str::from_utf8(&lease.bytes()[at..at + len]) {
            Ok(text) => crate::signmsg::sign_request_text(gate, login, ui, text),
            Err(_) => {
                menu::message(
                    ui.panel,
                    head,
                    "the code was not text",
                    "any key to go back",
                );
                menu::wait_for_any_key(ui);
            }
        }
        return;
    }

    match what {
        Content::Firmware => install(gate, login, ui, lease, len),
        Content::Psbt => sign(gate, login, ui, lease, base, skip, len),
        // Read, named and offered -- but the screen that shows what it does and the
        // signing behind it are not built yet. Saying so is the honest state; silently
        // returning to the menu would read as a device that did not understand.
        #[cfg(feature = "multichain")]
        Content::EvmTx { .. } => {
            crate::evmtx::screen(ui, &lease.bytes()[at..at + len]);
        }
        #[cfg(feature = "multichain")]
        Content::SolanaTx { base64 } => {
            crate::solanatx::screen(gate, login, ui, &lease.bytes()[at..at + len], base64);
        }
        Content::Seed(_) => {}
        // A wallet to register, from a descriptor or a setup file shown as a code.
        Content::MultisigConfig => {
            let text = core::str::from_utf8(&lease.bytes()[at..at + len]).unwrap_or("");
            crate::msimport::from_text(gate, login, ui, text);
        }
        // A payment request: read out, and its address checked against this wallet.
        Content::PaymentUri => {
            let text = core::str::from_utf8(&lease.bytes()[at..at + len]).unwrap_or("");
            crate::payuri::received(gate, login, ui, text);
        }
        Content::Text => {
            // Borrowed for the length of the screen; the lease is dropped after it.
            let text = core::str::from_utf8(&lease.bytes()[at..at + len]).unwrap_or("(not text)");
            show(ui, text);
        }
        Content::Unknown => {}
    }
}

/// Give the staging memory back with the first `len` bytes of it zeroed.
///
/// For the one payload that must not outlive the screen that read it. The zeros go in
/// through the staging driver rather than through the lease's slice, because a byte
/// store into this part is not reliable -- a wipe written the easy way is a wipe that
/// may not have happened, which is the worst of both.
///
/// A failure to claim the area is a wipe that did not happen and there is nothing to be
/// done about it here; the lease is dropped either way, which is what stops a refused
/// scan from holding the memory against the next USB upgrade.
fn wipe(lease: crate::psram::Lease, len: usize) {
    use catcard_upgrade::StagingArea as _;

    let Ok(mut area) = crate::staging::area_from(lease) else {
        return;
    };
    let zeros = [0u8; catcard_wallet::seedqr::MAX_DIGITS];
    let _ = area.write(0, &zeros[..len.min(zeros.len())]);
}

/// Hand a staged image to the installer.
fn install(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    lease: crate::psram::Lease,
    len: usize,
) {
    // The lease this screen already holds becomes the staging area's. Taking it again
    // would refuse against itself.
    let area = match crate::staging::area_from(lease) {
        Ok(a) => a,
        Err(_) => {
            menu::message(ui.panel, "Install", "no staging area", "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        }
    };
    menu::install_staged_image(gate, login, ui, area, len as u32);
}

/// Hand a received transaction to the signer.
fn sign(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    mut lease: crate::psram::Lease,
    at: usize,
    skip: usize,
    len: usize,
) {
    // The same two alternating buffers the card path uses: each signature rewrites the
    // whole container. A word-aligned split, because everything writing this region
    // writes whole words -- and from `at`, which is where the scan actually put the
    // transaction.
    let all = &mut lease.bytes()[at..];
    let half = (all.len() / 2) & !3;
    let (buf, spare) = all.split_at_mut(half);
    // A `crypto-psbt` arrived wrapped in a CBOR byte string, and the few header bytes
    // in front of it are not part of the transaction. They come off by moving the
    // transaction to the front rather than by signing from an offset: the split above
    // is word-aligned because every write into this region is, and a base a byte or
    // two off would be one rule for this one path.
    if skip > 0 {
        if skip + len > buf.len() {
            menu::message(ui.panel, "Sign", "too large to sign", "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        }
        buf.copy_within(skip..skip + len, 0);
    }
    let len = match crate::signtx::as_psbt_bytes(buf, len, spare) {
        Ok(n) => n,
        Err(why) => {
            menu::message(ui.panel, "Sign", why, "any key to go back");
            menu::wait_for_any_key(ui);
            return;
        }
    };
    crate::signtx::review_and_sign(
        gate,
        login,
        ui,
        buf,
        spare,
        len,
        // Caught over the air, not from a file; the signed result is written to the card
        // as before.
        &mut crate::signtx::Sink::Files {
            dest: &crate::signtx::SignDest::SINGLE,
            storage: crate::menu::Storage::Sd,
        },
    );
}

/// Show what was read.
fn show(ui: &mut Ui<'_>, text: &str) {
    use catcard_ui::scroll::Line as Row;

    let text = if text.as_bytes() == catcard_qr::UNSUPPORTED {
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

pub(crate) fn describe(why: Fault) -> &'static str {
    match why {
        Fault::NoScanner => "this board has no scanner",
        Fault::NotFound => "the scanner did not answer",
        Fault::SetupRefused => "the scanner refused setup",
        Fault::Cancelled => "cancelled",
        Fault::TooLong => "that code is too long to show",
    }
}
