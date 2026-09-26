//! What this device is, and the bootloader rows in the Danger zone.
//!
//! Everything here talks to the bootloader through the callgate wrappers in
//! `catcard-callgate`, each of which masks interrupts across its call exactly as the
//! login does; nothing is called from anywhere but a menu row the owner chose.
//!
//! - **View Identity** (About, third page): firmware and build time, hardware, the
//!   bootloader's version string, which secure elements answer, the factory bag number,
//!   the wallet's master fingerprint, the genuine light as the secure element reports it
//!   (gate 4/0), whether the chip is locked (gate 19/2, mk4 on) and the anti-downgrade
//!   mark as a date (gate 21/0). All reads.
//! - **Bless Firmware**: gate 18/5 on the logged-in struct -- commits this image's
//!   checksum to the SE and turns the genuine light green -- then reads the light back.
//! - **Set High-Water**: gate 21/2 -- **irreversible**; asked twice.
//! - **DFU Upgrade**: refused unless gate 19/2 answers, positively, *not locked*
//!   (`0xFF`); then asked twice before `enter_dfu`. A locked unit -- every bench unit is
//!   RDP=2 -- locks up rather than enter DFU, so a failed read, an unknown byte, or a
//!   board without the read all refuse.
//! - **Settings Space**: how much of the settings volume the slots use.
//!
//! Source: hw-reference/bootloader-callgate-abi.md methods 0, 4, 6, 19, 21 and
//! §"Decoding three status gates" [C];
//! gate18-pin-state-machine.md §2 method 5 [C]; menu-map-mk4-mk5-q1-v5.6.2.md §DZ,
//! §ADV "View Identity" [C]; help-and-warning-screens.md §14 [C].

use core::fmt::Write as _;

use catcard_callgate::Callgate;
use catcard_callgate::abi::{DfuMode, Light, LockState};
use catcard_ui::scroll::Line as DLine;

use crate::menu::{self, DocExit};
use crate::ui::Ui;

/// One rendered line of the identity page.
type Text = heapless::String<64>;

/// The genuine light in words, as the secure element reports it.
///
/// "green" / "red" and nothing stronger: the bootloader passes on the SE's own GPIO
/// reading, which its source calls forgeable by a man in the middle.
/// Source: hw-reference/bootloader-callgate-abi.md §"Decoding three status gates" [C]
fn light_text(read: Result<Option<Light>, catcard_callgate::Error>) -> &'static str {
    match read {
        Ok(Some(Light::Green)) => "green",
        Ok(Some(Light::Red)) => "red",
        Ok(None) => "no clear answer",
        Err(_) => "unreadable",
    }
}

/// Whether every nibble of `ts` is a decimal digit -- the header's BCD shape.
fn is_bcd(ts: &[u8; 8]) -> bool {
    ts.iter().all(|b| (b >> 4) <= 9 && (b & 0xF) <= 9)
}

/// The mark as `YYYY-MM-DD HH:MM`, "none recorded" for all zero, or hex if it is not BCD.
fn stamp_text(ts: &[u8; 8]) -> Text {
    let mut t = Text::new();
    if ts.iter().all(|&b| b == 0) {
        let _ = t.push_str("none recorded");
    } else if is_bcd(ts) {
        let s = catcard_fwhdr::format_timestamp(ts);
        let _ = t.push_str(core::str::from_utf8(&s).unwrap_or("?"));
    } else {
        for b in ts {
            let _ = write!(t, "{b:02x}");
        }
    }
    t
}

/// The bag number as the factory wrote it: printable text up to the first byte that
/// is not, "unbagged" for the all-ones a blank field reads as, hex otherwise.
///
/// That the field holds text is inferred from stock showing it in a title
/// (help-and-warning-screens.md §1) rather than stated [I].
fn bag_text(bag: &[u8; 32]) -> Text {
    let mut t = Text::new();
    if bag.iter().all(|&b| b == 0xFF) {
        let _ = t.push_str("unbagged");
        return t;
    }
    let end = bag
        .iter()
        .position(|&b| !(0x20..0x7F).contains(&b))
        .unwrap_or(bag.len());
    if end == 0 {
        for b in &bag[..8] {
            let _ = write!(t, "{b:02x}");
        }
        let _ = t.push_str("...");
    } else {
        let _ = t.push_str(core::str::from_utf8(&bag[..end]).unwrap_or("?"));
    }
    t
}

/// About → (page 3) View Identity.
///
/// A document rather than an info screen: the mono panels show six rows and there are
/// more lines than that, and a page that clips is a page that hides.
pub(crate) fn view_identity(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    const HEAD: &str = "Identity";
    let mut rows: heapless::Vec<Text, 14> = heapless::Vec::new();
    let mut push = |t: Text| {
        let _ = rows.push(t);
    };

    // This firmware, and the build that produced it.
    let mut t = Text::new();
    let _ = write!(t, "CatCard {}", crate::VERSION);
    if let Some(h) = crate::own_header() {
        let s = catcard_fwhdr::format_timestamp(&h.timestamp);
        let _ = write!(t, " ({})", core::str::from_utf8(&s).unwrap_or("?"));
    }
    push(t);

    let mut t = Text::new();
    let part = match catcard_board::BOARD.mcu {
        catcard_board::spec::Mcu::Stm32L496 => "STM32L496",
        catcard_board::spec::Mcu::Stm32L4S5 => "STM32L4S5",
    };
    let _ = write!(t, "hardware: {} ({})", catcard_board::BOARD.name, part);
    push(t);

    // The bootloader's own version string (gate 0). Shown whole: it carries a build
    // time and a commit, which is what tells one bootloader from another.
    let mut ver = [0u8; 64];
    let mut t = Text::new();
    // SAFETY: a 64-byte buffer, the documented minimum; the call masks interrupts.
    match unsafe { gate.bootloader_version(&mut ver) } {
        Ok(n) => {
            let n = n.min(ver.len());
            let s = core::str::from_utf8(&ver[..n]).unwrap_or("?");
            let _ = write!(t, "bootloader: {}", s.trim_end_matches('\0'));
        }
        Err(e) => {
            let _ = write!(t, "bootloader: unreadable {:?}", e);
        }
    }
    push(t);

    let mut t = Text::new();
    // SAFETY: no buffer; masks interrupts across the call.
    let se1 = if unsafe { gate.has_608() } {
        "ATECC608"
    } else {
        "not 608"
    };
    let _ = write!(
        t,
        "SE1 {}, SE2 {}",
        se1,
        if catcard_board::BOARD.has_se2 {
            "DS28C36"
        } else {
            "none"
        }
    );
    push(t);

    let mut bag = [0u8; 32];
    let mut t = Text::new();
    // SAFETY: the documented 32-byte buffer; read only; interrupts masked in the call.
    match unsafe { gate.bag_number(&mut bag) } {
        Ok(()) => {
            let _ = write!(t, "bag: {}", bag_text(&bag));
        }
        Err(e) => {
            let _ = write!(t, "bag: unreadable {:?}", e);
        }
    }
    push(t);

    // The wallet's master fingerprint, derived now if no screen has yet.
    let mut t = Text::new();
    let fp = if crate::key::in_force() == crate::key::Source::Root {
        crate::pubkeys::fingerprint(gate, login, ui, HEAD)
    } else {
        crate::pubkeys::known_fingerprint()
    };
    match fp {
        Some([a, b, c, d]) => {
            let _ = write!(t, "fingerprint: {a:02X}{b:02X}{c:02X}{d:02X}");
        }
        None => {
            let _ = t.push_str("fingerprint: not derived");
        }
    }
    push(t);

    // The genuine light, in the secure element's own words: advisory, as the
    // bootloader's source says of this read.
    // SAFETY: no buffer, a read; interrupts masked in the call.
    let light = unsafe { gate.genuine_light_read() };
    crate::catlog!("identity: genuine light {:?}", light);
    let mut t = Text::new();
    let _ = write!(
        t,
        "genuine light: {} (secure element's reading)",
        light_text(light)
    );
    push(t);

    // Whether the chip is locked against being read out or reflashed over DFU. The
    // read exists from mk4 on: the boards with a second secure element.
    if catcard_board::BOARD.has_se2 {
        // SAFETY: method 19's documented buffer, a read sub-method; masked.
        let lock = unsafe { gate.lock_state() };
        crate::catlog!("identity: lock {:?}", lock);
        let mut t = Text::new();
        let _ = write!(
            t,
            "chip lock: {}",
            match lock {
                Ok(Some(LockState::Locked)) => "locked",
                Ok(Some(LockState::NotLocked)) => "not locked",
                Ok(None) => "no clear answer",
                Err(_) => "unreadable",
            }
        );
        push(t);
    }

    // The anti-downgrade mark: firmware built before this date is refused.
    let mut mark = [0u8; 8];
    let mut t = Text::new();
    // SAFETY: the documented 8-byte buffer; read only; interrupts masked in the call.
    match unsafe { gate.high_water_read(&mut mark) } {
        Ok(()) => {
            let _ = write!(t, "oldest firmware allowed: {}", stamp_text(&mark));
        }
        Err(e) => {
            crate::catlog!("identity: high-water read {:?}", e);
            let _ = t.push_str("oldest firmware allowed: unreadable");
        }
    }
    push(t);

    let mut lines: heapless::Vec<DLine<'_>, 16> = heapless::Vec::new();
    let _ = lines.push(DLine::title(HEAD));
    for r in rows.iter() {
        let _ = lines.push(DLine::body(r).small().wrapped());
    }
    let _ = lines.push(DLine::body("STM32 UID: previous page").small());
    let _ = menu::show_doc(ui, &lines, false, false);
}

/// Danger zone → Bless Firmware: commit this image as genuine, so the light goes green.
///
/// Changes the front LED and what the secure element holds in its firmware slot;
/// nothing about the wallet. Needs the session's logged-in struct, which is why it is
/// behind the PIN. A dev-key image blessed this way is still a dev-key image: the light
/// says "this device trusts this image", not "Coinkite signed it".
pub(crate) fn bless_firmware(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    const HEAD: &str = "Bless Firmware";
    menu::ask(
        ui.panel,
        "Bless this firmware?",
        "marks it genuine: the",
        "front light turns green",
    );
    if !menu::confirmed(ui) {
        return;
    }
    menu::blocking_screen(ui.panel, HEAD, "asking the bootloader");
    let g = crate::pinentry::BootloaderGate::new(gate);
    match login.greenlight(&g) {
        Ok(()) => {
            // Read the light back: the bless is only as good as what the secure element
            // now reports, and that is what the owner is shown.
            // SAFETY: no buffer, a read; interrupts masked in the call.
            let after = unsafe { gate.genuine_light_read() };
            crate::catlog!("bless: gate 18/5 ok; light reads {:?}", after);
            if matches!(after, Ok(Some(Light::Green))) {
                menu::message(ui.panel, HEAD, "done", "the light is now green");
            } else {
                let mut b = Text::new();
                let _ = write!(b, "light reads {}", light_text(after));
                menu::message(ui.panel, "Not green", "blessed, but the", &b);
            }
        }
        Err(why) => {
            let what = match why {
                catcard_pin::Failure::NeedsSetup => "login went stale",
                catcard_pin::Failure::MustWait => "rate limited",
                catcard_pin::Failure::Gate(_) => "callgate unreachable",
                catcard_pin::Failure::ImageRefused => "refused",
                catcard_pin::Failure::Code(c) => {
                    crate::catlog!("bless: refused, gate code {}", c);
                    "bootloader refused"
                }
            };
            crate::catlog!("bless: NOT blessed: {}", what);
            menu::message(ui.panel, "Not blessed", what, "any key to go back");
        }
    }
    menu::wait_for_any_key(ui);
}

/// Danger zone → Set High-Water: **irreversible**. Records this image's build time as
/// the bootloader's anti-downgrade floor.
///
/// After it, every image older than this one -- stock firmware included, and every
/// earlier CatCard -- is refused by this device for good. The bootloader does the same
/// on its own when it installs an image flagged `HIGH_WATER`; this is the owner asking
/// for it now. Asked twice, with the mark that is there and the one that would replace
/// it both on screen, and refused outright when the current mark is already at or
/// above this build.
///
/// Source: help-and-warning-screens.md §14 "Set high-water mark" [C].
pub(crate) fn set_high_water(gate: &Callgate, ui: &mut Ui<'_>) {
    const HEAD: &str = "Set High-Water";
    let Some(own) = crate::own_header() else {
        menu::message(
            ui.panel,
            HEAD,
            "own header unreadable",
            "any key to go back",
        );
        menu::wait_for_any_key(ui);
        return;
    };
    let mut now = [0u8; 8];
    // SAFETY: the documented 8-byte buffer; read only; interrupts masked in the call.
    if let Err(e) = unsafe { gate.high_water_read(&mut now) } {
        crate::catlog!("high-water: read refused: {:?}", e);
        menu::message(ui.panel, HEAD, "cannot read the mark", "nothing changed");
        menu::wait_for_any_key(ui);
        return;
    }
    // BCD timestamps order as their bytes do (big-endian digits).
    if now >= own.timestamp {
        let mut a = Text::new();
        let _ = write!(a, "now {}", stamp_text(&now));
        menu::message(ui.panel, HEAD, &a, "already at or above this");
        menu::wait_for_any_key(ui);
        return;
    }

    {
        let mut a = Text::new();
        let mut b = Text::new();
        let _ = write!(a, "now {}", stamp_text(&now));
        let _ = write!(b, "-> {}", stamp_text(&own.timestamp));
        let lines = [
            DLine::title(HEAD),
            DLine::body("IRREVERSIBLE: every older").small(),
            DLine::body("firmware, stock included, is").small(),
            DLine::body("refused by this device forever.").small(),
            DLine::body(&a).small(),
            DLine::body(&b).small(),
        ];
        if !matches!(menu::show_doc(ui, &lines, false, true), DocExit::Confirmed) {
            return;
        }
    }
    menu::ask(ui.panel, "Really set it?", "no way back, ever", "");
    if !menu::confirmed(ui) {
        return;
    }
    menu::ask(ui.panel, "Last chance", "raise the floor now?", "");
    if !menu::confirmed(ui) {
        return;
    }

    // What the bootloader's own check says of this timestamp, for the log: this image
    // is running, so it cleared the floor when it was installed.
    // SAFETY: the documented 8-byte buffer; a check, not a write; interrupts masked.
    let check = unsafe { gate.is_downgrade(&own.timestamp) };
    crate::catlog!("high-water: check of own timestamp -> {:?}", check);

    menu::blocking_screen(ui.panel, HEAD, "recording");
    // SAFETY: the irreversible write, taken after three answers on screen; the buffer is
    // the documented 8 bytes and the call masks interrupts.
    match unsafe { gate.high_water_record(&own.timestamp) } {
        Ok(()) => {
            crate::catlog!("high-water: RECORDED {}", stamp_text(&own.timestamp));
            let mut a = Text::new();
            let _ = write!(a, "{}", stamp_text(&own.timestamp));
            menu::message(ui.panel, "High-water set", &a, "older firmware refused");
        }
        Err(e) => {
            crate::catlog!("high-water: record refused: {:?}", e);
            menu::message(ui.panel, HEAD, "bootloader refused", "nothing changed");
        }
    }
    menu::wait_for_any_key(ui);
}

/// Danger zone → DFU Upgrade: restart into the chip's own ROM loader, as stock does --
/// but only on a device that says, positively, that it is not locked.
///
/// A security-locked unit (RDP=2, which every bench unit is) cannot enter DFU: the
/// bootloader locks up instead, and that reads as a brick until the power is cycled.
/// Gate 19/2 answers the question in `buf_io[0]`: `2` locked, `0xFF` not. **Only
/// `0xFF` opens the way** -- a failed read, any other byte, and the mk3, whose
/// bootloader has no such read, all get the refusal. Then it is asked twice, and
/// `enter_dfu` does not return.
///
/// Source: firmware-features.md §9 [C]; bootloader-callgate-abi.md method 2, "gate 19
/// gained sub-method 2", §"Decoding three status gates" [C].
pub(crate) fn dfu_upgrade(gate: &Callgate, ui: &mut Ui<'_>) {
    const HEAD: &str = "DFU Upgrade";
    // The flag exists from mk4 on: the boards with a second secure element.
    let state = if catcard_board::BOARD.has_se2 {
        // SAFETY: method 19's documented 32-byte buffer, a read sub-method; masked.
        let read = unsafe { gate.lock_state() };
        crate::catlog!("dfu: lock flag {:?}", read);
        read.ok().flatten()
    } else {
        crate::catlog!("dfu: this bootloader has no lock-flag read");
        None
    };
    match state {
        Some(LockState::NotLocked) => {}
        Some(LockState::Locked) => {
            menu::message(
                ui.panel,
                HEAD,
                "unavailable on a locked",
                "device; use Upgrade Firmware",
            );
            menu::wait_for_any_key(ui);
            return;
        }
        None => {
            menu::message(
                ui.panel,
                HEAD,
                "cannot tell if it is locked,",
                "so not entering it",
            );
            menu::wait_for_any_key(ui);
            return;
        }
    }

    {
        let lines = [
            DLine::title(HEAD),
            DLine::body("Restarts into the chip's own").small(),
            DLine::body("firmware loader, for a DFU").small(),
            DLine::body("tool on a computer to write").small(),
            DLine::body("firmware over USB.").small(),
            DLine::body("Power off to leave it.").small(),
        ];
        if !matches!(menu::show_doc(ui, &lines, false, true), DocExit::Confirmed) {
            return;
        }
    }
    menu::ask(ui.panel, "Enter DFU now?", "the device restarts", "");
    if !menu::confirmed(ui) {
        return;
    }
    crate::catlog!("dfu: entering the ROM loader");
    // SAFETY: the lock flag read `0xFF` (not locked) just now, and the owner confirmed
    // twice; the call wipes SRAM and does not return.
    unsafe { gate.enter_dfu(DfuMode::Normal) }
}

/// Danger zone → Settings Space: how much of the settings volume is in use.
///
/// Files under `/settings` and their bytes, against the region the board table gives
/// the volume. The filesystem's own metadata is not counted, so "used" is a floor. On
/// the mk3 it is sectors of the SPI-NOR region, each wholly used or wholly free.
pub(crate) fn settings_space(ui: &mut Ui<'_>) {
    const HEAD: &str = "Settings Space";
    let region = match catcard_board::BOARD.settings {
        catcard_board::spec::SettingsArea::InternalFlash { len, .. }
        | catcard_board::spec::SettingsArea::SpiNor { len, .. } => Some(len),
    };
    // SAFETY: read-only mount; nothing is written.
    let usage = match unsafe { crate::settings::Files::mount_read_only() } {
        Ok(mut files) => files.usage(),
        Err(e) => {
            crate::catlog!("settings: space: mount failed {:?}", e);
            None
        }
    };
    // The info screen's own line width.
    type Row = heapless::String<48>;
    let mut lines: heapless::Vec<Row, 5> = heapless::Vec::new();
    match usage {
        Some((n, bytes)) => {
            let mut t = Row::new();
            let _ = write!(t, "{} of {} slots in use", n, crate::settings::SLOT_COUNT);
            let _ = lines.push(t);
            let mut t = Row::new();
            let _ = write!(t, "{} KB in files", bytes.div_ceil(1024));
            let _ = lines.push(t);
            if let Some(len) = region {
                let mut t = Row::new();
                let _ = write!(
                    t,
                    "of a {} KB region, ~{} KB free",
                    len / 1024,
                    (u64::from(len).saturating_sub(bytes)) / 1024
                );
                let _ = lines.push(t);
            }
        }
        None => {
            let _ = lines.push(Row::try_from("settings volume unreadable").unwrap_or_default());
        }
    }
    menu::info(ui.panel, HEAD, &lines);
    menu::wait_for_any_key(ui);
}
