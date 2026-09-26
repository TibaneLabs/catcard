//! The device preferences of the wallet in force, read once and kept for the session.
//!
//! The values themselves, and every rule about what an unreadable one means, live in
//! [`catcard_settings::prefs`]; this is the firmware's copy of them and the plumbing that
//! makes each one actually do something. A preference that is stored and never honoured
//! is worse than no preference at all, so each field below names where it is obeyed:
//!
//! | preference | honoured by |
//! |---|---|
//! | idle timeout | [`crate::idle`], ticked from [`crate::usbtask::pump`] |
//! | display units | `crate::signtx::btc`, the one amount formatter |
//! | max network fee | the [`catcard_wallet::psbtview::Policy`] the PSBT review is built with |
//! | USB port | [`crate::usbtask::set_port`] |
//! | Virtual Disk | the USB Drive screen, which refuses to start when it is off |
//! | Keyboard EMU | [`crate::usbtask::set_keyboard`], which re-enumerates with or without the keyboard |
//! | menu wrapping | the [`catcard_ui::scroll::ScrollView`] every menu is drawn through |
//! | backlight (Q1) | [`crate::display::set_backlight`], from [`apply`] |
//! | BIP-85 index cap | [`crate::derive`], which refuses an index past 9999 unless lifted |
//!
//! # Why a cache
//!
//! Opening a wallet's settings file costs a key derivation -- a callgate fetch or a seed
//! stretch -- so reading a preference at the moment it is needed would put a second and a
//! half in front of every amount drawn on a signing screen. [`load`] pays that once, just
//! after login, and every read afterwards is a struct copy. Writes go through [`save`],
//! which updates the cache in the same call, so what the screen says and what the next
//! boot will do can never disagree.
//!
//! # The mk3 has no settings store
//!
//! It keeps its slots in raw SPI-NOR, which is not wired up, so there is nothing to read
//! or write. [`current`] still exists there and still answers -- with the defaults -- so
//! nothing downstream needs a `cfg` of its own. The menu rows are what disappear.

use catcard_settings::prefs::{Chain, FeeCap, MultisigTrust, Units};
use catcard_wallet::bip32::Network;

/// Everything the preference screens set, as the firmware reads it.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) struct Prefs {
    /// Minutes of no keypress before the device logs itself out; `None` is off.
    pub idle_minutes: Option<u32>,
    /// The same while running on the battery, where there is one. `None` means
    /// `idle_minutes` applies on battery too.
    pub battery_idle_minutes: Option<u32>,
    /// How an amount is written on screen.
    pub units: Units,
    /// The largest share of a transaction that may go to fees.
    pub fee_cap: FeeCap,
    /// Whether the USB port is presented to a host at all.
    pub usb_port: bool,
    /// Whether the device may re-enumerate as a USB disk.
    pub virtual_disk: bool,
    /// Whether the device also enumerates a USB keyboard, for typing passwords into the
    /// host. Honoured by [`crate::usbtask::set_keyboard`]; [`crate::usbkbd`] types.
    pub keyboard_emu: bool,
    /// Whether the menu cursor comes round at the ends of a list.
    pub menu_wrap: bool,
    /// Which Bitcoin network every address, xpub and default path is built for.
    pub net: Chain,
    /// The Q1 LCD backlight level, `1..=100` percent. Honoured by
    /// [`crate::display::set_backlight`] on the Q1; the mono boards keep the default and
    /// have no backlight to drive.
    pub backlight_percent: u8,
    /// What to do with a multisig wallet a PSBT describes but this device has not registered.
    /// Honoured by [`crate::signtx`], through [`crate::msimport::trust_from_psbt`].
    pub multisig_trust: MultisigTrust,
    /// Whether Secure Notes & Passwords is on (Q1). `None` means never asked. Honoured by
    /// the main menu, which shows the `Notes` tile only when it is `Some(true)`, and by
    /// `crate::notes`, which tells its opt-in story otherwise.
    pub notes: Option<bool>,
    /// Whether BIP-85 takes an index past 9999. Off keeps the cap; on is the Danger
    /// zone's `B85 Idx Values`, and reads as off from anything but a literal `"1"`.
    pub b85_unlimited: bool,
}

impl Prefs {
    /// The BIP-32 network the wallet in force derives and encodes under.
    ///
    /// Baked into every master key so its version bytes and every derived address follow
    /// from it, and passed to every address encoder alongside.
    pub(crate) fn network(&self) -> Network {
        match self.net {
            Chain::Mainnet => Network::Mainnet,
            Chain::Testnet => Network::Testnet,
            Chain::Regtest => Network::Regtest,
        }
    }
}

impl Default for Prefs {
    /// What a device with no settings file behaves like: no timeout, BTC, the ten-percent
    /// fee cap, both hardware switches on, the keyboard off, no wrapping, and
    /// unregistered multisig refused.
    fn default() -> Self {
        Self {
            idle_minutes: None,
            battery_idle_minutes: None,
            units: Units::Btc,
            fee_cap: FeeCap::DEFAULT,
            usb_port: true,
            virtual_disk: true,
            keyboard_emu: false,
            menu_wrap: false,
            net: Chain::Mainnet,
            backlight_percent: catcard_settings::prefs::BACKLIGHT_DEFAULT,
            multisig_trust: MultisigTrust::VerifyOnly,
            notes: None,
            b85_unlimited: false,
        }
    }
}

/// The preferences of the wallet in force. Defaults until [`load`] has run.
static mut CURRENT: Prefs = Prefs {
    idle_minutes: None,
    battery_idle_minutes: None,
    units: Units::Btc,
    fee_cap: FeeCap::DEFAULT,
    usb_port: true,
    virtual_disk: true,
    keyboard_emu: false,
    menu_wrap: false,
    net: Chain::Mainnet,
    backlight_percent: catcard_settings::prefs::BACKLIGHT_DEFAULT,
    multisig_trust: MultisigTrust::VerifyOnly,
    notes: None,
    b85_unlimited: false,
};

/// What the wallet in force is set to.
pub(crate) fn current() -> Prefs {
    // SAFETY: foreground only, single core; `Prefs` is `Copy` and the read finishes
    // within this statement. Written only by `load` and `save`, both foreground.
    unsafe { *core::ptr::addr_of!(CURRENT) }
}

/// The BIP-32 network the wallet in force derives and shows addresses for.
///
/// The one accessor every key-derivation and address-encoding site reads, so the choice
/// lives in one place rather than as a `Network::Mainnet` scattered through the firmware.
/// A plain static read, safe to call inside a [`crate::keywork::run`] closure: it depends
/// on no secret and so leaks nothing about one.
pub(crate) fn network() -> Network {
    current().network()
}

/// Put `next` in force: remember it, then tell the parts of the firmware that act on it.
///
/// Every field that has a home outside this module is pushed there here rather than
/// polled from there, so there is one place to look for "what happens when this changes".
fn apply(next: Prefs) {
    // SAFETY: foreground only, single core; the write finishes within this statement.
    unsafe { *core::ptr::addr_of_mut!(CURRENT) = next };
    crate::idle::arm(next.idle_minutes, next.battery_idle_minutes);
    crate::usbtask::set_port(next.usb_port);
    crate::usbtask::set_keyboard(next.keyboard_emu);
    // Only the Q1 has a backlight to drive; the mono boards carry the field at its default
    // and there is nothing to apply.
    #[cfg(feature = "board-q1")]
    crate::display::set_backlight(next.backlight_percent);
}

/// Forget this wallet's preferences and go back to the defaults.
///
/// Called where [`crate::settings::forget_key`] is: a different wallet is in force, and
/// its file has not been read yet. Going back to the defaults rather than keeping the
/// previous wallet's values means the gap between the switch and the next [`load`] is
/// spent with the safe settings -- the fee cap in place and USB reachable -- rather than
/// with a stranger's.
///
/// mk3 has no settings store, so nothing there ever loads a wallet's preferences and
/// there is nothing to forget.
#[cfg(not(feature = "board-mk3"))]
pub(crate) fn forget() {
    apply(Prefs::default());
}

/// Read the wallet in force's preferences out of its settings file.
///
/// Costs one key derivation, which is then cached for the session by
/// [`crate::settings::wallet_key`], so every per-wallet screen after this is free. Run
/// once, from the menu's start-up, while the owner is already waiting for the first frame.
///
/// **Every failure is silent and gives the defaults.** No settings region, no file, an
/// unreadable slot, a blank device, a WIF key that has no file at all: all of them mean a
/// device that works with the safe settings, not a device that will not start.
#[cfg(not(feature = "board-mk3"))]
pub(crate) fn load(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    panel: &mut crate::display::Panel,
    head: &str,
) {
    use catcard_settings::json::Doc;
    use catcard_settings::prefs;
    use catcard_settings::store::{self, SCRATCH};

    let key = match crate::settings::wallet_key(gate, login, panel, head) {
        Ok(k) => k,
        Err(why) => {
            crate::catlog!("prefs: no key ({}), using the defaults", why);
            apply(Prefs::default());
            return;
        }
    };
    let Some(mut held) = crate::heap::take(SCRATCH) else {
        crate::catlog!("prefs: no memory to read them, using the defaults");
        apply(Prefs::default());
        return;
    };
    let buf = held.bytes();
    // Read-only: nothing here writes, and a writable mount is a risk this has no use for.
    // SAFETY: the region is mapped and readable; nothing is written.
    let mut files = match unsafe { crate::settings::Files::mount_read_only() } {
        Ok(f) => f,
        Err(e) => {
            crate::catlog!("prefs: mount failed ({:?}), using the defaults", e);
            apply(Prefs::default());
            return;
        }
    };
    let n = store::read(&mut files, &key, buf).unwrap_or(0);
    let doc = Doc::parse(&buf[..n]).unwrap_or_default();
    let next = Prefs {
        idle_minutes: prefs::idle_minutes(&doc),
        battery_idle_minutes: prefs::battery_idle_minutes(&doc),
        units: prefs::units(&doc),
        fee_cap: prefs::fee_cap(&doc),
        usb_port: prefs::usb_port(&doc),
        virtual_disk: prefs::virtual_disk(&doc),
        keyboard_emu: prefs::keyboard_emu(&doc),
        menu_wrap: prefs::menu_wrap(&doc),
        net: prefs::network(&doc),
        backlight_percent: prefs::backlight_percent(&doc),
        multisig_trust: prefs::multisig_trust(&doc),
        notes: prefs::notes_enabled(&doc),
        b85_unlimited: prefs::b85_unlimited(&doc),
    };
    crate::catlog!(
        "prefs: idle {:?}/{:?} min, {}, fee {:?}, usb {}, vdisk {}, kbd {}, wrap {}, net {}, mstrust {}, b85 {}",
        next.idle_minutes,
        next.battery_idle_minutes,
        next.units.code(),
        next.fee_cap,
        next.usb_port,
        next.virtual_disk,
        next.keyboard_emu,
        next.menu_wrap,
        next.net.ticker(),
        next.multisig_trust.code(),
        if next.b85_unlimited { "open" } else { "capped" }
    );
    apply(next);
}

/// The mk3's settings medium is not wired up, so there is nothing to read.
#[cfg(feature = "board-mk3")]
pub(crate) fn load(
    _gate: &catcard_callgate::Callgate,
    _login: &mut catcard_pin::Login,
    _panel: &mut crate::display::Panel,
    _head: &str,
) {
    apply(Prefs::default());
}

/// Save one preference into the wallet in force's file, then put `next` in force.
///
/// `next` is the whole set as it will be once the write lands, so the caller states the
/// new value once rather than this module re-reading the file to find out what it just
/// wrote. Nothing is applied unless the write succeeded: a setting that could not be
/// stored must not be in force for this session either, or the next boot silently
/// disagrees with the screen.
#[cfg(not(feature = "board-mk3"))]
pub(crate) fn save(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut crate::ui::Ui<'_>,
    head: &str,
    (name, raw): (&str, &str),
    next: Prefs,
) -> bool {
    use catcard_settings::store::SCRATCH;

    crate::menu::blocking_screen(ui.panel, head, "saving");
    // Two full-slot buffers, as every other writer here takes: one holds the settings
    // while the key is changed, the other seals them.
    let (Some(mut doc_held), Some(mut seal_held)) =
        (crate::heap::take(SCRATCH), crate::heap::take(SCRATCH))
    else {
        crate::catlog!("prefs: no memory to save {}", name);
        return false;
    };
    match crate::settings::save_wallet(
        gate,
        login,
        ui,
        head,
        (name, raw),
        doc_held.bytes(),
        seal_held.bytes(),
    ) {
        Ok(()) => {
            apply(next);
            true
        }
        Err(why) => {
            crate::catlog!("prefs: saving {} failed: {}", name, why);
            false
        }
    }
}

/// The value a preference is stored as, quoted, ready for [`save`].
///
/// Every preference here is written as a JSON *string*, never as a bare number or
/// boolean, so that one reader ([`catcard_settings::prefs`]) covers all of them and a
/// value's type can never be the thing that makes it unreadable.
#[cfg(not(feature = "board-mk3"))]
pub(crate) fn quoted(value: &str) -> heapless::String<16> {
    let mut s: heapless::String<16> = heapless::String::new();
    let _ = s.push('"');
    let _ = s.push_str(value);
    let _ = s.push('"');
    s
}
