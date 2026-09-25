//! The device preferences kept in a wallet's own settings file.
//!
//! Idle timeout, display units, the network-fee cap, the hardware switches and menu
//! wrapping. Stock keeps the same set of preferences:
//!
//! | stock key | meaning | ours |
//! |---|---|---|
//! | `idle_to`, `batt_to` | idle timeout, in **seconds**; the battery-only one | [`IDLE`], [`BATT_IDLE`] |
//! | `rz` | display units | [`UNITS`] |
//! | `fee_limit` | max fee as a percentage of the value sent | [`FEE_CAP`] |
//! | `du` | disable-USB | [`USB_PORT`] |
//! | `vidsk` | Virtual Disk | [`VIRTUAL_DISK`] |
//! | `wa` | menu wrap | [`MENU_WRAP`] |
//!
//! Source: hw-reference/settings-nvstore-format.md §5 [C]
//!
//! The reference names those keys but, apart from `rz` (`8`=BTC, `5`=mBTC, `2`=bits,
//! `0`=sats), does not say what their values look like `[?]`. Writing a value in a shape
//! stock misreads could log a stock device out every minute, or leave it with no fee cap
//! at all, so these are **our own keys**, prefixed `cat_`, which stock ignores exactly as
//! it ignores every key it does not know. This is the same rule [`crate::prelogin`]
//! follows, for the same reason. When stock's shapes are known -- `rz` already is --
//! reading its keys as well is an addition, not a migration.
//!
//! Note in particular that `idle_to` counts **seconds** while [`IDLE`] counts minutes:
//! two units under one name is exactly the confusion a separate key avoids.
//!
//! # What doubt reads as
//!
//! Every value that is absent, unparseable or out of range reads as a default -- but
//! "the default" is not one direction for all of them, and picking the direction is the
//! whole of the safety argument here:
//!
//! - **The fee cap** reads as [`FeeCap::DEFAULT`], never as [`FeeCap::None`]. A cap that
//!   evaporated because two bytes of a settings slot were unreadable is a transaction
//!   that pays its whole value to miners. Having no cap is a thing the owner says out
//!   loud, once, on a screen that warns; it is never something a parser concludes.
//! - **The idle timeout** reads as off. A device that logs itself out on a schedule
//!   nobody chose is a device whose owner cannot finish signing, and the timeout protects
//!   against someone walking up to an unattended device -- which is a risk worth taking
//!   over an unreadable byte turning the wallet off mid-review.
//! - **The hardware switches** read as *on*. They are the two preferences that can take a
//!   capability away, and USB is the only channel that reaches a device whose panel has
//!   failed: a garbled slot that switched USB off would strand exactly the unit that
//!   needs reaching. So only a literal `"0"` disables either; nothing is ever inferred
//!   into a disable.
//! - **Menu wrapping** reads as off, which is how the menus behaved before there was a
//!   preference at all.

use crate::json::Doc;

/// Minutes with no key pressed before the device logs itself out. Decimal digits, as a
/// string; `"0"` or absent is off.
pub const IDLE: &str = "cat_idle";
/// The same while the device runs on its battery (Q1). Absent means [`IDLE`] applies on
/// battery too.
pub const BATT_IDLE: &str = "cat_bidle";
/// How amounts are shown: one of `btc`, `mbtc`, `bits`, `sats`.
///
/// Not `cat_du`: stock's `du` is *disable-USB*, and a name that echoed it while meaning
/// something else is a trap for whoever reads both files next.
pub const UNITS: &str = "cat_units";
/// The network-fee cap: decimal percent, or `"none"` for no cap at all.
pub const FEE_CAP: &str = "cat_fee";
/// The USB port: `"0"` off, anything else on. Stock's `du` is the same switch written the
/// other way round, as *disable*-USB.
pub const USB_PORT: &str = "cat_usb";
/// The Virtual Disk (USB mass storage): `"0"` off, anything else on.
pub const VIRTUAL_DISK: &str = "cat_vdsk";
/// Whether the menu cursor wraps past the ends of a list: `"1"` on.
pub const MENU_WRAP: &str = "cat_wrap";
/// Which Bitcoin network the wallet shows: the ticker `"BTC"`, `"XTN"` or `"XRT"`.
///
/// This is **stock's own key**, not a `cat_`-prefixed one, and it is read the way stock
/// writes it -- a bare ticker string whose shape is fully known
/// (hw-reference/wallet-export-formats.md §"Chain parameters" [C]), exactly as `rz` is.
/// A device that ran stock in testnet mode keeps that choice, and one this firmware writes
/// is understood by stock.
pub const CHAIN: &str = "chain";
/// The Q1 LCD backlight level, as a decimal percent string `"1"`..`"100"`. Absent, zero,
/// or out of range reads as [`BACKLIGHT_DEFAULT`]. Q1-only; the mono boards have no
/// backlight to dim. Our own key: stock keeps an on-battery brightness under a different
/// name and shape, which we do not read. Source: hw-reference/firmware-features.md §9
/// "LCD brightness on battery" [C]
pub const BACKLIGHT: &str = "cat_bl";

/// Full brightness — the level a device with no setting runs at.
///
/// Doubt reads as full, never dim and never off: a dark panel is an unusable device, and
/// on the Q1 the panel is the only way to drive the menu that would turn it back up. So an
/// absent, zero or unparseable value lights the screen fully rather than leaving someone
/// unable to see how to fix it.
pub const BACKLIGHT_DEFAULT: u8 = 100;
/// The multisig PSBT trust policy: `verify`, `offer` or `trust`. Anything else, or absent,
/// is [`MultisigTrust::VerifyOnly`]. Our own key, prefixed `cat_`, as the rest are: stock's
/// own multisig-policy key has a shape this firmware has not confirmed, and writing a value
/// stock misreads could relax a device's policy without its owner asking.
pub const MULTISIG_TRUST: &str = "cat_mstrust";

/// The longest idle timeout accepted: twenty-four hours.
///
/// Stock offers at most an hour; this reads further so a value written by a later
/// version of this firmware is not silently thrown away, while still refusing a number
/// that can only be nonsense.
pub const MAX_IDLE_MINUTES: u32 = 24 * 60;

/// The value's text without its quotes, if it is a string.
fn text<'a>(doc: &Doc<'a>, key: &str) -> Option<&'a str> {
    doc.get(key)?.strip_prefix('"')?.strip_suffix('"')
}

/// Decimal digits as a number, if that is all the text is.
fn digits(t: &str, max_len: usize) -> Option<u32> {
    if t.is_empty() || t.len() > max_len || !t.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    t.parse().ok()
}

/// Minutes of no key before logging out, if a sane one is set. `None` is off.
pub fn idle_minutes(doc: &Doc<'_>) -> Option<u32> {
    let m = digits(text(doc, IDLE)?, 5)?;
    (1..=MAX_IDLE_MINUTES).contains(&m).then_some(m)
}

/// The same while running on the battery, if the owner set a separate one.
///
/// `None` means there is no battery-only value, so [`idle_minutes`] applies on battery as
/// well -- **not** that the timeout is off there. A device on its battery is the one most
/// likely to be away from its owner, so falling back to the shorter-lived setting is the
/// direction that cannot be gamed by pulling the cable.
pub fn battery_idle_minutes(doc: &Doc<'_>) -> Option<u32> {
    let m = digits(text(doc, BATT_IDLE)?, 5)?;
    (1..=MAX_IDLE_MINUTES).contains(&m).then_some(m)
}

/// Whether the menu cursor wraps past the ends of a list.
pub fn menu_wrap(doc: &Doc<'_>) -> bool {
    text(doc, MENU_WRAP) == Some("1")
}

/// The Q1 LCD backlight level, as a percent in `1..=100`.
///
/// Doubt reads as [`BACKLIGHT_DEFAULT`] (full): absent, a bare number rather than a
/// string, zero, or anything over 100 all light the panel fully rather than risk a dark
/// or blank screen the owner cannot see to correct.
pub fn backlight_percent(doc: &Doc<'_>) -> u8 {
    match text(doc, BACKLIGHT).and_then(|t| digits(t, 3)) {
        Some(p) if (1..=100).contains(&p) => p as u8,
        _ => BACKLIGHT_DEFAULT,
    }
}

/// The text a backlight percent is stored as.
pub fn backlight_value(percent: u8) -> heapless::String<4> {
    use core::fmt::Write as _;
    let mut s: heapless::String<4> = heapless::String::new();
    let _ = write!(s, "{percent}");
    s
}

/// Whether the USB port is switched on. Only a literal `"0"` switches it off.
pub fn usb_port(doc: &Doc<'_>) -> bool {
    text(doc, USB_PORT) != Some("0")
}

/// Whether the Virtual Disk may be presented. Only a literal `"0"` switches it off.
pub fn virtual_disk(doc: &Doc<'_>) -> bool {
    text(doc, VIRTUAL_DISK) != Some("0")
}

/// How an amount is written on screen.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum Units {
    /// `0.00012345 BTC`.
    #[default]
    Btc,
    /// `0.12345 mBTC`, a thousandth of a bitcoin.
    MBtc,
    /// `123.45 bits`, a millionth of a bitcoin.
    Bits,
    /// `12345 sats`, the indivisible unit the protocol actually counts.
    Sats,
}

impl Units {
    /// The name shown after the number.
    pub const fn label(self) -> &'static str {
        match self {
            Units::Btc => "BTC",
            Units::MBtc => "mBTC",
            Units::Bits => "bits",
            Units::Sats => "sats",
        }
    }

    /// How the value is stored in a settings file.
    pub const fn code(self) -> &'static str {
        match self {
            Units::Btc => "btc",
            Units::MBtc => "mbtc",
            Units::Bits => "bits",
            Units::Sats => "sats",
        }
    }

    /// Digits after the point.
    const fn decimals(self) -> usize {
        match self {
            Units::Btc => 8,
            Units::MBtc => 5,
            Units::Bits => 2,
            Units::Sats => 0,
        }
    }

    /// Satoshis per whole unit.
    const fn divisor(self) -> u64 {
        match self {
            Units::Btc => 100_000_000,
            Units::MBtc => 100_000,
            Units::Bits => 100,
            Units::Sats => 1,
        }
    }

    /// Every unit this firmware offers, in the order the chooser lists them.
    pub const ALL: [Units; 4] = [Units::Btc, Units::MBtc, Units::Bits, Units::Sats];

    /// Write `sats` in this unit, followed by the unit's name.
    ///
    /// **No rounding and no truncation.** Every unit here divides a satoshi count exactly
    /// -- each divisor is a power of ten no larger than 10^8 -- so the fractional part is
    /// printed in full and the text says precisely how many satoshis are being moved. An
    /// amount display that dropped a digit would be a display an attacker could hide
    /// value behind.
    pub fn write(self, sats: u64, out: &mut impl core::fmt::Write) -> core::fmt::Result {
        let d = self.divisor();
        match self.decimals() {
            0 => write!(out, "{} {}", sats, self.label()),
            n => write!(
                out,
                "{}.{:0width$} {}",
                sats / d,
                sats % d,
                self.label(),
                width = n
            ),
        }
    }
}

/// How amounts are shown. Anything unrecognised is [`Units::Btc`].
pub fn units(doc: &Doc<'_>) -> Units {
    match text(doc, UNITS) {
        Some("mbtc") => Units::MBtc,
        Some("bits") => Units::Bits,
        Some("sats") => Units::Sats,
        _ => Units::Btc,
    }
}

/// Which Bitcoin network the device derives keys and shows addresses for.
///
/// Three, matching stock: mainnet (`BTC`), testnet4 (`XTN`) and regtest (`XRT`). No
/// signet. The value stored under [`CHAIN`] is the ticker; anything else, absent or
/// unreadable reads as [`Chain::Mainnet`] -- the default stock uses and the network whose
/// addresses are real, so a wallet whose settings slot went bad shows mainnet rather than
/// quietly deriving somewhere else.
///
/// Source: hw-reference/firmware-features.md §10 [C]; wallet-export-formats.md
/// §"Chain parameters" [C].
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum Chain {
    /// Bitcoin mainnet. Real coins.
    #[default]
    Mainnet,
    /// Bitcoin testnet4.
    Testnet,
    /// Bitcoin regtest.
    Regtest,
}

impl Chain {
    /// Every network the chooser offers, in the order it lists them.
    pub const ALL: [Chain; 3] = [Chain::Mainnet, Chain::Testnet, Chain::Regtest];

    /// The ticker this network is stored and exported as.
    pub const fn ticker(self) -> &'static str {
        match self {
            Chain::Mainnet => "BTC",
            Chain::Testnet => "XTN",
            Chain::Regtest => "XRT",
        }
    }

    /// The long name exports and backups write, e.g. `Bitcoin Mainnet`.
    /// Source: hw-reference/wallet-export-formats.md §"Chain parameters" [C].
    pub const fn long_name(self) -> &'static str {
        match self {
            Chain::Mainnet => "Bitcoin Mainnet",
            Chain::Testnet => "Bitcoin Testnet 4",
            Chain::Regtest => "Bitcoin Regtest",
        }
    }

    /// The SLIP-44 coin type for default paths: 0 on mainnet, 1 on testnet and regtest.
    pub const fn coin_type(self) -> u32 {
        match self {
            Chain::Mainnet => 0,
            Chain::Testnet | Chain::Regtest => 1,
        }
    }

    /// Whether this is anything other than mainnet -- i.e. "testnet mode" is on.
    pub const fn is_testnet_mode(self) -> bool {
        !matches!(self, Chain::Mainnet)
    }
}

/// Which network the wallet is set to. Anything unrecognised is [`Chain::Mainnet`].
pub fn network(doc: &Doc<'_>) -> Chain {
    match text(doc, CHAIN) {
        Some("XTN") => Chain::Testnet,
        Some("XRT") => Chain::Regtest,
        _ => Chain::Mainnet,
    }
}

/// The largest network fee a transaction may pay before it is refused.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum FeeCap {
    /// Refuse above this percentage of the amount sent.
    Percent(u32),
    /// Sign whatever the transaction says, however much of it is fee.
    None,
}

impl FeeCap {
    /// Stock's cap, and ours: refuse above ten percent.
    /// Source: hw-reference/firmware-features.md §5 [C]
    pub const DEFAULT: FeeCap = FeeCap::Percent(10);

    /// The caps the chooser offers.
    pub const CHOICES: [FeeCap; 4] = [
        FeeCap::Percent(10),
        FeeCap::Percent(25),
        FeeCap::Percent(50),
        FeeCap::None,
    ];

    /// The percentage to compare a transaction's fee against.
    ///
    /// [`FeeCap::None`] gives `u32::MAX`, which no fee percentage can exceed: the check
    /// stays in place and simply never fires, rather than being skipped somewhere that
    /// would then have to remember to skip it.
    pub const fn percent_limit(self) -> u32 {
        match self {
            FeeCap::Percent(p) => p,
            FeeCap::None => u32::MAX,
        }
    }
}

impl Default for FeeCap {
    fn default() -> Self {
        FeeCap::DEFAULT
    }
}

/// The fee cap this wallet is set to.
///
/// Doubt reads as [`FeeCap::DEFAULT`] and **never** as [`FeeCap::None`]: see the module
/// note. Only the exact word `none` removes the cap.
pub fn fee_cap(doc: &Doc<'_>) -> FeeCap {
    let Some(t) = text(doc, FEE_CAP) else {
        return FeeCap::DEFAULT;
    };
    if t == "none" {
        return FeeCap::None;
    }
    match digits(t, 3) {
        Some(p) if (1..=100).contains(&p) => FeeCap::Percent(p),
        _ => FeeCap::DEFAULT,
    }
}

/// The text a [`FeeCap`] is stored as.
pub fn fee_cap_value(cap: FeeCap) -> heapless::String<8> {
    use core::fmt::Write as _;
    let mut s: heapless::String<8> = heapless::String::new();
    match cap {
        FeeCap::None => {
            let _ = s.push_str("none");
        }
        FeeCap::Percent(p) => {
            let _ = write!(s, "{p}");
        }
    }
    s
}

/// What to do with the cosigner keys a PSBT carries for a multisig wallet this device has
/// not registered.
///
/// A multisig spend is only signable against a wallet definition -- who the cosigners are,
/// in which script form, sorted or not. Normally that comes from a registration the owner
/// made deliberately ([`crate::wallets`]). A PSBT can also carry the definition inside it
/// (its global xpubs and per-input scripts), and this setting says how far to trust that:
///
/// Source: hw-reference/firmware-features.md §4 "A trust policy governs xpubs seen in
/// PSBTs (verify-only / offer-to-import / trust)." [C]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum MultisigTrust {
    /// **The default, and the safe one.** A multisig input is signed only against a wallet
    /// already registered on this device; a definition that lives only in the PSBT is not
    /// enough, and such an input is refused. Doubt reads as this.
    #[default]
    VerifyOnly,
    /// Reconstruct the wallet from the PSBT and, once it is shown and its address proven to
    /// rebuild from those keys, offer to register it. The owner is asked, per wallet, before
    /// anything is signed or stored.
    OfferImport,
    /// Trust the definition in the PSBT: reconstruct the wallet, prove its address, and sign
    /// against it without asking and without storing it. The least cautious of the three.
    TrustPsbt,
}

impl MultisigTrust {
    /// How the value is stored in a settings file.
    pub const fn code(self) -> &'static str {
        match self {
            MultisigTrust::VerifyOnly => "verify",
            MultisigTrust::OfferImport => "offer",
            MultisigTrust::TrustPsbt => "trust",
        }
    }

    /// The name shown on the chooser, as stock spells them.
    /// Source: hw-reference/firmware-features.md §4 [C]
    pub const fn label(self) -> &'static str {
        match self {
            MultisigTrust::VerifyOnly => "Verify Only",
            MultisigTrust::OfferImport => "Offer Import",
            MultisigTrust::TrustPsbt => "Trust PSBT",
        }
    }

    /// Every policy this firmware offers, in the order the chooser lists them -- the safest
    /// first, matching the default.
    pub const ALL: [MultisigTrust; 3] = [
        MultisigTrust::VerifyOnly,
        MultisigTrust::OfferImport,
        MultisigTrust::TrustPsbt,
    ];
}

/// The multisig PSBT trust policy this wallet is set to.
///
/// **Doubt reads as [`MultisigTrust::VerifyOnly`]**, never as a form that would sign for a
/// wallet the owner never registered: only the exact words `offer` and `trust` relax the
/// policy. An unreadable slot leaves the device refusing an unregistered multisig, which
/// is the direction that cannot sign a stranger's script on the host's say-so -- the same
/// safety argument the fee cap follows.
pub fn multisig_trust(doc: &Doc<'_>) -> MultisigTrust {
    match text(doc, MULTISIG_TRUST) {
        Some("offer") => MultisigTrust::OfferImport,
        Some("trust") => MultisigTrust::TrustPsbt,
        _ => MultisigTrust::VerifyOnly,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(json: &str) -> Doc<'_> {
        Doc::parse(json.as_bytes()).unwrap()
    }

    #[test]
    fn set_values_read_back() {
        let d = doc(
            r#"{"cat_idle":"15","cat_bidle":"2","cat_units":"sats","cat_fee":"25",
                "cat_usb":"0","cat_vdsk":"0","cat_wrap":"1"}"#,
        );
        assert_eq!(idle_minutes(&d), Some(15));
        assert_eq!(battery_idle_minutes(&d), Some(2));
        assert_eq!(units(&d), Units::Sats);
        assert_eq!(fee_cap(&d), FeeCap::Percent(25));
        assert!(!usb_port(&d));
        assert!(!virtual_disk(&d));
        assert!(menu_wrap(&d));
    }

    /// An empty file is every default: no timeout, BTC, the 10% cap, both switches on,
    /// no wrapping.
    #[test]
    fn an_empty_file_is_the_defaults() {
        let d = doc(r#"{}"#);
        assert_eq!(idle_minutes(&d), None);
        assert_eq!(battery_idle_minutes(&d), None);
        assert_eq!(units(&d), Units::Btc);
        assert_eq!(fee_cap(&d), FeeCap::DEFAULT);
        assert!(usb_port(&d));
        assert!(virtual_disk(&d));
        assert!(!menu_wrap(&d));
    }

    /// Absent, zero, garbage, a bare number rather than a string, negative, too big: the
    /// timeout is off. Off is the direction that cannot interrupt a signing session.
    #[test]
    fn a_doubtful_timeout_is_off() {
        for json in [
            r#"{}"#,
            r#"{"cat_idle":"0"}"#,
            r#"{"cat_idle":15}"#,
            r#"{"cat_idle":"fifteen"}"#,
            r#"{"cat_idle":"-5"}"#,
            r#"{"cat_idle":""}"#,
            r#"{"cat_idle":"1441"}"#,
            r#"{"cat_idle":"1 5"}"#,
            r#"{"cat_idle":"999999999999"}"#,
            // Stock's own key, which we do not read.
            r#"{"idle_to":"900"}"#,
        ] {
            assert_eq!(idle_minutes(&doc(json)), None, "{json}");
            assert_eq!(battery_idle_minutes(&doc(json)), None, "{json}");
        }
        assert_eq!(idle_minutes(&doc(r#"{"cat_idle":"1440"}"#)), Some(1440));
    }

    /// The trust policy reads back what was written.
    #[test]
    fn multisig_trust_reads_back() {
        assert_eq!(
            multisig_trust(&doc(r#"{"cat_mstrust":"verify"}"#)),
            MultisigTrust::VerifyOnly
        );
        assert_eq!(
            multisig_trust(&doc(r#"{"cat_mstrust":"offer"}"#)),
            MultisigTrust::OfferImport
        );
        assert_eq!(
            multisig_trust(&doc(r#"{"cat_mstrust":"trust"}"#)),
            MultisigTrust::TrustPsbt
        );
    }

    /// **The one that matters here.** Nothing unreadable may relax the policy: absent,
    /// garbage, the wrong case, a bare value, or stock's own key all read as
    /// "verify only", which refuses an unregistered multisig rather than signing it on the
    /// host's word about who the cosigners are.
    #[test]
    fn a_doubtful_trust_policy_is_verify_only() {
        for json in [
            r#"{}"#,
            r#"{"cat_mstrust":""}"#,
            r#"{"cat_mstrust":"Trust"}"#,
            r#"{"cat_mstrust":"TRUST"}"#,
            r#"{"cat_mstrust":"offer "}"#,
            r#"{"cat_mstrust":"2"}"#,
            r#"{"cat_mstrust":2}"#,
            r#"{"cat_mstrust":"yes"}"#,
            // Stock's own key, whatever it holds, is not one we read.
            r#"{"multisig_policy":"2"}"#,
        ] {
            assert_eq!(
                multisig_trust(&doc(json)),
                MultisigTrust::VerifyOnly,
                "{json}"
            );
        }
        assert_eq!(MultisigTrust::default(), MultisigTrust::VerifyOnly);
    }

    /// **The one that matters.** Nothing unreadable may ever become "no cap": a slot that
    /// will not parse leaves the ten-percent refusal in place.
    #[test]
    fn a_doubtful_fee_cap_is_never_uncapped() {
        for json in [
            r#"{}"#,
            r#"{"cat_fee":""}"#,
            r#"{"cat_fee":"0"}"#,
            r#"{"cat_fee":"101"}"#,
            r#"{"cat_fee":"NONE"}"#,
            r#"{"cat_fee":"none "}"#,
            r#"{"cat_fee":"nope"}"#,
            r#"{"cat_fee":"-1"}"#,
            r#"{"cat_fee":25}"#,
            r#"{"cat_fee":"1e9"}"#,
            r#"{"cat_fee":"99999"}"#,
            // Stock's own key again.
            r#"{"fee_limit":"none"}"#,
        ] {
            let cap = fee_cap(&doc(json));
            assert_ne!(cap, FeeCap::None, "{json}");
            assert_eq!(cap, FeeCap::DEFAULT, "{json}");
        }
        assert_eq!(fee_cap(&doc(r#"{"cat_fee":"none"}"#)), FeeCap::None);
        assert_eq!(fee_cap(&doc(r#"{"cat_fee":"100"}"#)), FeeCap::Percent(100));
        assert_eq!(fee_cap(&doc(r#"{"cat_fee":"1"}"#)), FeeCap::Percent(1));
    }

    /// A cap that is present but unreadable still refuses a fee that the default would
    /// refuse -- the property the test above exists to protect, stated as a comparison.
    #[test]
    fn an_unreadable_cap_still_refuses_a_ruinous_fee() {
        let cap = fee_cap(&doc(r#"{"cat_fee":"\u0000garbage"}"#));
        assert!(60 > cap.percent_limit(), "a 60% fee must still be refused");
        assert_eq!(FeeCap::None.percent_limit(), u32::MAX);
    }

    /// The two switches can only be turned off by saying so. Anything else -- absent, a
    /// number, the wrong word -- leaves the hardware on, because off is the state that
    /// can strand a device whose screen has died.
    #[test]
    fn doubt_never_switches_hardware_off() {
        for json in [
            r#"{}"#,
            r#"{"cat_usb":"","cat_vdsk":""}"#,
            r#"{"cat_usb":0,"cat_vdsk":0}"#,
            r#"{"cat_usb":"off","cat_vdsk":"off"}"#,
            r#"{"cat_usb":"false","cat_vdsk":"false"}"#,
            r#"{"cat_usb":"00","cat_vdsk":"00"}"#,
            // Stock's keys are not ours to read.
            r#"{"du":"1","vidsk":"0"}"#,
        ] {
            assert!(usb_port(&doc(json)), "{json}");
            assert!(virtual_disk(&doc(json)), "{json}");
        }
        let off = doc(r#"{"cat_usb":"0","cat_vdsk":"0"}"#);
        assert!(!usb_port(&off));
        assert!(!virtual_disk(&off));
    }

    #[test]
    fn unrecognised_units_are_btc() {
        for json in [
            r#"{}"#,
            r#"{"cat_units":""}"#,
            r#"{"cat_units":"BTC"}"#,
            r#"{"cat_units":"SATS"}"#,
            r#"{"cat_units":"satoshi"}"#,
            r#"{"cat_units":3}"#,
            // Stock's own key for the units, whose values are decimal counts rather than
            // these words at all.
            r#"{"rz":"0"}"#,
            r#"{"rz":0}"#,
        ] {
            assert_eq!(units(&doc(json)), Units::Btc, "{json}");
        }
    }

    /// Every unit round-trips through its stored code.
    #[test]
    fn units_round_trip() {
        for u in Units::ALL {
            let json = format!(r#"{{"cat_units":"{}"}}"#, u.code());
            assert_eq!(units(&doc(&json)), u);
        }
    }

    /// The same satoshi count, four ways, losing nothing.
    #[test]
    fn the_same_amount_in_every_unit() {
        let show = |u: Units, sats: u64| {
            let mut s = heapless::String::<32>::new();
            u.write(sats, &mut s).unwrap();
            s.as_str().to_owned()
        };
        assert_eq!(show(Units::Btc, 12_345), "0.00012345 BTC");
        assert_eq!(show(Units::MBtc, 12_345), "0.12345 mBTC");
        assert_eq!(show(Units::Bits, 12_345), "123.45 bits");
        assert_eq!(show(Units::Sats, 12_345), "12345 sats");

        assert_eq!(show(Units::Btc, 0), "0.00000000 BTC");
        assert_eq!(show(Units::Sats, 0), "0 sats");
        // One whole coin, and one satoshi short of it.
        assert_eq!(show(Units::Btc, 100_000_000), "1.00000000 BTC");
        assert_eq!(show(Units::Btc, 99_999_999), "0.99999999 BTC");
        assert_eq!(show(Units::Bits, 99_999_999), "999999.99 bits");
        // The whole supply, which must not overflow or round.
        assert_eq!(
            show(Units::Btc, 21_000_000 * 100_000_000),
            "21000000.00000000 BTC"
        );
    }

    /// **The widest thing this can ever print.** A PSBT may claim any `u64`, and the
    /// firmware writes amounts into a fixed buffer -- so a unit that could overrun it
    /// would leave a *truncated number* on a signing screen. Stated here, next to the
    /// code that decides the width, rather than left to whoever sizes the buffer.
    #[test]
    fn no_unit_can_write_more_than_thirty_two_characters() {
        for u in Units::ALL {
            let mut s = heapless::String::<32>::new();
            u.write(u64::MAX, &mut s).expect("u64::MAX must fit in 32");
            assert!(s.len() <= 32, "{} took {}", u.code(), s.len());
        }
    }

    /// The network reads back from its ticker, and doubt is always mainnet.
    #[test]
    fn network_reads_its_ticker_and_doubt_is_mainnet() {
        assert_eq!(network(&doc(r#"{"chain":"BTC"}"#)), Chain::Mainnet);
        assert_eq!(network(&doc(r#"{"chain":"XTN"}"#)), Chain::Testnet);
        assert_eq!(network(&doc(r#"{"chain":"XRT"}"#)), Chain::Regtest);
        // Absent, wrong case, a number, an unknown ticker, signet: all mainnet.
        for json in [
            r#"{}"#,
            r#"{"chain":"xtn"}"#,
            r#"{"chain":1}"#,
            r#"{"chain":""}"#,
            r#"{"chain":"SIG"}"#,
            r#"{"chain":"BTC "}"#,
        ] {
            assert_eq!(network(&doc(json)), Chain::Mainnet, "{json}");
        }
    }

    /// Every network round-trips through the ticker it is stored as, and carries the
    /// coin type its default paths use.
    #[test]
    fn network_round_trips_and_carries_its_coin_type() {
        for c in Chain::ALL {
            let json = format!(r#"{{"chain":"{}"}}"#, c.ticker());
            assert_eq!(network(&doc(&json)), c, "{}", c.ticker());
        }
        assert_eq!(Chain::Mainnet.coin_type(), 0);
        assert_eq!(Chain::Testnet.coin_type(), 1);
        assert_eq!(Chain::Regtest.coin_type(), 1);
        assert!(!Chain::Mainnet.is_testnet_mode());
        assert!(Chain::Testnet.is_testnet_mode());
        assert!(Chain::Regtest.is_testnet_mode());
    }

    /// A fee cap round-trips through the text it is stored as.
    #[test]
    fn fee_caps_round_trip() {
        for cap in FeeCap::CHOICES {
            let v = fee_cap_value(cap);
            let json = format!(r#"{{"cat_fee":"{v}"}}"#);
            assert_eq!(fee_cap(&doc(&json)), cap, "{v}");
        }
    }

    /// A stored backlight level round-trips, and an in-range value reads back exactly.
    #[test]
    fn backlight_round_trips() {
        for p in [1u8, 25, 50, 75, 100] {
            let v = backlight_value(p);
            let json = format!(r#"{{"cat_bl":"{v}"}}"#);
            assert_eq!(backlight_percent(&doc(&json)), p, "{v}");
        }
    }

    /// Doubt is full brightness, never dim or off: a dark panel is a device the owner
    /// cannot see to fix. Absent, zero, over-range, a bare number, or garbage all read
    /// as [`BACKLIGHT_DEFAULT`].
    #[test]
    fn a_doubtful_backlight_is_full() {
        for json in [
            r#"{}"#,
            r#"{"cat_bl":""}"#,
            r#"{"cat_bl":"0"}"#,
            r#"{"cat_bl":"101"}"#,
            r#"{"cat_bl":"999"}"#,
            r#"{"cat_bl":50}"#,
            r#"{"cat_bl":"-5"}"#,
            r#"{"cat_bl":"half"}"#,
        ] {
            assert_eq!(backlight_percent(&doc(json)), BACKLIGHT_DEFAULT, "{json}");
        }
        assert_eq!(backlight_percent(&doc(r#"{"cat_bl":"1"}"#)), 1);
        assert_eq!(backlight_percent(&doc(r#"{"cat_bl":"100"}"#)), 100);
    }
}
