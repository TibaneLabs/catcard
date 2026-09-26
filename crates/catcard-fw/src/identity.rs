//! What this device is, and the bootloader rows in the Danger zone.
//!
//! Everything here talks to the bootloader through the callgate wrappers in
//! `catcard-callgate`, each of which masks interrupts across its call exactly as the
//! login does; nothing is called from anywhere but a menu row the owner chose.
//!
//! - **View Identity** (About, third page): firmware and build time, hardware, the
//!   bootloader's version string, which secure elements answer, the factory bag number,
//!   the wallet's master fingerprint, the genuine light's raw reading and the
//!   anti-downgrade mark. All reads.
//! - **Bless Firmware**: gate 18/5 on the logged-in struct -- commits this image's
//!   checksum to the SE and turns the genuine light green.
//! - **Set High-Water**: gate 21/2 -- **irreversible**; asked twice.
//! - **DFU Upgrade**: always refused. Every bench unit is RDP=2, the bootloader locks up
//!   rather than enter DFU there, and the gate's lock flag has no documented encoding --
//!   so the lock state is never *positively* known to be open, and `enter_dfu` is never
//!   called from here.
//! - **Settings Space**: how much of the settings volume the slots use.
//!
//! Source: hw-reference/bootloader-callgate-abi.md methods 0, 4, 6, 19, 21 [C];
//! gate18-pin-state-machine.md §2 method 5 [C]; menu-map-mk4-mk5-q1-v5.6.2.md §DZ,
//! §ADV "View Identity" [C]; help-and-warning-screens.md §14 [C].

use core::fmt::Write as _;

use catcard_callgate::Callgate;
use catcard_callgate::abi::GenuineOp;
use catcard_ui::scroll::Line as DLine;

use crate::menu::{self, DocExit};
use crate::ui::Ui;

/// One rendered line of the identity page.
type Text = heapless::String<64>;

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
#[cfg_attr(feature = "board-mk3", allow(unused_variables))]
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

    // The wallet's master fingerprint. Derived now if no screen has yet, on the boards
    // with a settings store (the derivation lives beside it); the mk3 shows what it has.
    let mut t = Text::new();
    #[cfg(not(feature = "board-mk3"))]
    let fp = if crate::key::in_force() == crate::key::Source::Root {
        crate::pubkeys::fingerprint(gate, login, ui, HEAD)
    } else {
        crate::pubkeys::known_fingerprint()
    };
    #[cfg(feature = "board-mk3")]
    let fp = crate::pubkeys::known_fingerprint();
    match fp {
        Some([a, b, c, d]) => {
            let _ = write!(t, "fingerprint: {a:02X}{b:02X}{c:02X}{d:02X}");
        }
        None => {
            let _ = t.push_str("fingerprint: not derived");
        }
    }
    push(t);

    // The genuine light, as the gate answers a read. The number is shown as it is: the
    // reference does not say what it means (docs/HARDWARE-OPEN-ITEMS.md).
    let mut t = Text::new();
    // SAFETY: no buffer, a read; interrupts masked in the call.
    match unsafe { gate.genuine_light(GenuineOp::Read) } {
        Ok(rv) => {
            let _ = write!(t, "genuine light: gate says {rv}");
        }
        Err(e) => {
            let _ = write!(t, "genuine light: {:?}", e);
        }
    }
    push(t);

    let mut mark = [0u8; 8];
    let mut t = Text::new();
    // SAFETY: the documented 8-byte buffer; read only; interrupts masked in the call.
    match unsafe { gate.high_water_read(&mut mark) } {
        Ok(()) => {
            let _ = write!(t, "high-water: {}", stamp_text(&mark));
        }
        Err(e) => {
            let _ = write!(t, "high-water: unreadable {:?}", e);
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
            // What the light reads now, for the log: the number's meaning is open.
            // SAFETY: no buffer, a read; interrupts masked in the call.
            let after = unsafe { gate.genuine_light(GenuineOp::Read) };
            crate::catlog!("bless: gate 18/5 ok; light reads {:?}", after);
            menu::message(ui.panel, HEAD, "done", "genuine light set");
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

    // What the bootloader's own check says of this timestamp, for the log only: its
    // answer's encoding is not documented, so it decides nothing here.
    // SAFETY: the documented 8-byte buffer; a check, not a write; interrupts masked.
    let check = unsafe { gate.high_water_check(&own.timestamp) };
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

/// Danger zone → DFU Upgrade: stock enters the ROM bootloader here. This never does.
///
/// A security-locked unit (RDP=2, which every bench unit is) cannot enter DFU: the
/// bootloader locks up instead, and that reads as a brick until the power is cycled.
/// The one way to know the lock state is gate 19/2, whose answer's encoding the
/// reference does not give -- so it is read and logged, raw, on the boards that have
/// it, and the row says what it can honestly say. `enter_dfu` is not called from here
/// in any mode. Source: firmware-features.md §9 [C]; bootloader-callgate-abi.md
/// method 2, "gate 19 gained sub-method 2" [C]; docs/HARDWARE-OPEN-ITEMS.md.
pub(crate) fn dfu_upgrade(gate: &Callgate, ui: &mut Ui<'_>) {
    const HEAD: &str = "DFU Upgrade";
    // The flag exists from mk4 on: the boards with a second secure element.
    if catcard_board::BOARD.has_se2 {
        let mut raw = [0u8; 32];
        // SAFETY: method 19's documented 32-byte buffer, a read sub-method; masked.
        let rv = unsafe { gate.lock_flag_raw(&mut raw) };
        crate::catlog!(
            "dfu: lock flag raw rv {:?}, buf {:02x}{:02x}{:02x}{:02x}",
            rv,
            raw[0],
            raw[1],
            raw[2],
            raw[3]
        );
    } else {
        crate::catlog!("dfu: this bootloader has no lock-flag read");
    }
    menu::message(
        ui.panel,
        HEAD,
        "unavailable on a locked",
        "device; use Upgrade Firmware",
    );
    menu::wait_for_any_key(ui);
}

/// Danger zone → Settings Space: how much of the settings volume is in use.
///
/// Files under `/settings` and their bytes, against the region the board table gives
/// the volume. The filesystem's own metadata is not counted, so "used" is a floor.
#[cfg(not(feature = "board-mk3"))]
pub(crate) fn settings_space(ui: &mut Ui<'_>) {
    const HEAD: &str = "Settings Space";
    let region = match catcard_board::BOARD.settings {
        catcard_board::spec::SettingsArea::InternalFlash { len, .. } => Some(len),
        catcard_board::spec::SettingsArea::SpiNor { .. } => None,
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
