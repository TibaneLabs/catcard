//! Trick PINs: what a trick login means, and what each trick the menu offers is made of.
//!
//! The bytes and the flag bits are `catcard_callgate::trick`. This is the meaning: which
//! flag word each behaviour on the Add New Trick screen is stored as, what a login that
//! reports a trick asks the firmware to do, and the short list the firmware keeps so the
//! menu can name the tricks it made -- without their PINs.
//!
//! # What the firmware can and cannot learn at login
//!
//! A trick login reports success exactly as the real PIN does. The flags that destroy or
//! fake -- wipe, brick, pretend-wrong, the duress wallets -- have already fired inside the
//! bootloader and are removed from what the login reports; only delta mode, reboot, the
//! firmware-defined bit (the spending policy's unlock) and the two firmware-only effects
//! (look blank, countdown) arrive, in `delay_required`, with `tc_arg` in
//! `delay_achieved`. A duress login is therefore invisible here by design, and nothing in
//! this module tries to see it.
//!
//! Source: hw-reference/trick-pin-slot-format.md §1.4, §2 [C]

use catcard_callgate::trick::{TCA_SP_UNLOCK, censor, tc};

/// What a successful login asks of the firmware, from the flags and argument it reported.
///
/// Source: trick-pin-slot-format.md §2.2 [C]; menu-map-mk4-mk5-q1-v5.6.2.md §(A) login
/// sequence [C] for the policy-unlock re-prompt and the countdown-then-re-prompt.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Effect {
    /// Nothing visible: the real PIN, or a trick the firmware is not told about (a duress
    /// wallet, a wipe that logs in). Carry on exactly as for the real PIN.
    None,
    /// Delta mode: this is the real wallet, and it must not sign validly or show its seed.
    Delta,
    /// Reboot. The bootloader normally does this itself before answering.
    Reboot,
    /// The spending policy's unlock PIN: note it, then ask for the main PIN.
    PolicyUnlock,
    /// Show a login countdown of this many minutes, then ask for the PIN again.
    Countdown { minutes: u16 },
    /// Behave as a device with no wallet.
    LookBlank,
}

/// Interpret the flags and argument a login reported.
///
/// `flags` is censored again here, so a hidden bit that somehow arrived changes nothing.
/// Reboot first (it is the bootloader's own action and outranks everything), then delta
/// (the one that concerns the real wallet), then the firmware-defined ones. A
/// firmware-defined argument this firmware does not know is [`Effect::None`]: logging in
/// is the one thing every trick that reports nothing else does.
pub const fn effect(flags: u16, arg: u16) -> Effect {
    let f = censor(flags);
    if f & tc::REBOOT != 0 {
        Effect::Reboot
    } else if f & tc::DELTA_MODE != 0 {
        Effect::Delta
    } else if f & tc::FW_DEFINED != 0 && arg == TCA_SP_UNLOCK {
        Effect::PolicyUnlock
    } else if f & tc::COUNTDOWN != 0 {
        Effect::Countdown { minutes: arg }
    } else if f & tc::BLANK_WALLET != 0 {
        Effect::LookBlank
    } else {
        Effect::None
    }
}

/// A duress wallet's `tc_arg`: the BIP-85 index. `1001..=1003` are 24-word children,
/// `2001..=2003` 12-word ones; `n` is 1 to 3.
/// Source: trick-pin-slot-format.md §1.4 (`tc_arg` encodings) [C]
pub const fn duress_index(words: u32, n: u16) -> Option<u16> {
    if n < 1 || n > 3 {
        return None;
    }
    match words {
        24 => Some(1000 + n),
        12 => Some(2000 + n),
        _ => None,
    }
}

/// The word count and BIP-85 index a word-wallet `tc_arg` names.
pub const fn duress_words(arg: u16) -> Option<(u32, u32)> {
    match arg {
        1001..=1003 => Some((24, arg as u32)),
        2001..=2003 => Some((12, arg as u32)),
        _ => None,
    }
}

/// The BIP-85 XPRV index an xprv duress wallet is derived at.
///
/// **A CatCard choice, not stock's.** Stock's xprv duress wallet is its "legacy Mk2/Mk3"
/// fixed derivation, which the reference does not give; this derives a BIP-85 XPRV child
/// (`m/83696968'/32'/1001'`) instead. The slot bytes are the bootloader's format either
/// way, so the decoy it opens is the same under any firmware -- only re-deriving it from
/// the seed ("Activate Wallet") is ours.
/// Source: trick-pin-slot-format.md §3.5 (64-byte xdata, chain code then key) [C];
/// BIP-85 §XPRV [C]; the index [CatCard]
pub const XPRV_DURESS_INDEX: u16 = 1001;

/// Longest countdown the trick takes, in minutes: 28 days, stock's longest login
/// countdown. Source: firmware-features.md "login countdown (5 min–28 days)" [C]
pub const MAX_COUNTDOWN_MINUTES: u16 = 28 * 24 * 60;

/// A behaviour the Add New Trick screen offers.
///
/// Every one maps to a flag word the bootloader or this firmware acts on. What is *not*
/// here, and why:
///
/// - **Delta mode**: `tc_arg` must hold the true PIN's last digits "as packed nibbles",
///   and the reference does not give the packing. A wrong guess logs in with a PIN that
///   is not the real one -- a failed attempt on the real counter, every time the trick is
///   used. A delta trick another firmware made is still honoured at login.
/// - **Countdown, then brick**: the reference does not say how that is stored, and a
///   brick flag on the slot would fire at the login, not after the countdown.
/// - **Add If Wrong**: the reference does not say how the bootloader identifies the
///   wrong-PIN slot.
///
/// docs/HARDWARE-OPEN-ITEMS.md §Trick PINs lists all three.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Behaviour {
    /// Destroy the pairing secret. The device never works again.
    BrickSelf,
    /// Erase the seed, then reboot.
    WipeReboot,
    /// Erase the seed, and answer as a wrong PIN.
    WipeSilent,
    /// Erase the seed, and log into a duress wallet.
    WipeToDuress { words: u32, n: u16 },
    /// Erase the seed, and log in to what is left: a device with no wallet.
    WipeStop,
    /// Log into a BIP-85 words duress wallet.
    Duress { words: u32, n: u16 },
    /// Log into a BIP-85 XPRV duress wallet.
    DuressXprv,
    /// A login countdown of `minutes`; with `wipe`, the seed is erased first.
    Countdown { minutes: u16, wipe: bool },
    /// Look like a device with no wallet. The real seed is untouched.
    LookBlank,
    /// Reboot.
    JustReboot,
    /// The spending policy's unlock PIN; with `wipe`, the seed is erased first.
    PolicyUnlock { wipe: bool },
}

impl Behaviour {
    /// `(tc_flags, tc_arg)` for the slot. `None` for an argument out of range.
    ///
    /// Wipe with a countdown and wipe with a policy unlock are the documented bits
    /// combined; the reference names the bits and says the bootloader acts on `WIPE`
    /// whatever else is set, so the combination does what its parts do `[I]`.
    pub const fn encode(self) -> Option<(u16, u16)> {
        Some(match self {
            Behaviour::BrickSelf => (tc::BRICK, 0),
            Behaviour::WipeReboot => (tc::WIPE | tc::REBOOT, 0),
            Behaviour::WipeSilent => (tc::WIPE | tc::FAKE_OUT, 0),
            Behaviour::WipeToDuress { words, n } => match duress_index(words, n) {
                Some(i) => (tc::WIPE | tc::WORD_WALLET, i),
                None => return None,
            },
            Behaviour::WipeStop => (tc::WIPE, 0),
            Behaviour::Duress { words, n } => match duress_index(words, n) {
                Some(i) => (tc::WORD_WALLET, i),
                None => return None,
            },
            Behaviour::DuressXprv => (tc::XPRV_WALLET, XPRV_DURESS_INDEX),
            Behaviour::Countdown { minutes, wipe } => {
                if minutes == 0 || minutes > MAX_COUNTDOWN_MINUTES {
                    return None;
                }
                (tc::COUNTDOWN | if wipe { tc::WIPE } else { 0 }, minutes)
            }
            Behaviour::LookBlank => (tc::BLANK_WALLET, 0),
            Behaviour::JustReboot => (tc::REBOOT, 0),
            Behaviour::PolicyUnlock { wipe } => (
                tc::FW_DEFINED | if wipe { tc::WIPE } else { 0 },
                TCA_SP_UNLOCK,
            ),
        })
    }
}

/// Whether a trick with `flags` destroys something when its PIN is typed: the seed, or
/// the device. Every screen that shows or arms one says so.
pub const fn irreversible(flags: u16) -> bool {
    flags & (tc::WIPE | tc::BRICK) != 0
}

/// Whether a trick with `flags` opens a duress wallet.
pub const fn is_duress(flags: u16) -> bool {
    flags & (tc::WORD_WALLET | tc::XPRV_WALLET) != 0
}

/// Whether `flags` is the spending policy's unlock (with or without a wipe).
pub const fn is_policy_unlock(flags: u16, arg: u16) -> bool {
    flags & tc::FW_DEFINED != 0 && arg == TCA_SP_UNLOCK
}

/// A short name for a trick, for the list and the per-trick screen.
pub const fn describe(flags: u16, arg: u16) -> &'static str {
    let wipe = flags & tc::WIPE != 0;
    if flags & tc::BRICK != 0 {
        "Brick Self"
    } else if flags & tc::DELTA_MODE != 0 {
        "Delta Mode"
    } else if is_policy_unlock(flags, arg) {
        if wipe {
            "Unlock Policy+Wipe"
        } else {
            "Unlock Policy"
        }
    } else if flags & tc::COUNTDOWN != 0 {
        if wipe { "Wipe, Countdown" } else { "Countdown" }
    } else if is_duress(flags) {
        if wipe {
            "Wipe -> Wallet"
        } else {
            "Duress Wallet"
        }
    } else if flags & tc::BLANK_WALLET != 0 {
        "Look Blank"
    } else if wipe && flags & tc::FAKE_OUT != 0 {
        "Silent Wipe"
    } else if wipe && flags & tc::REBOOT != 0 {
        "Wipe & Reboot"
    } else if wipe {
        "Wipe & Stop"
    } else if flags & tc::REBOOT != 0 {
        "Just Reboot"
    } else if flags & tc::FAKE_OUT != 0 {
        "Pretends Wrong"
    } else {
        "Trick"
    }
}

/// Whether `pin` has the shape of a PIN: `prefix-suffix`, digits, each part 2 to 6.
///
/// Held to the same rule as the main PIN (gate18-pin-state-machine.md §6.1): a trick PIN
/// is typed at the same prompt, and one that the prompt cannot take -- here or on stock --
/// would be a trick nobody can ever use.
pub fn pin_shape_ok(pin: &[u8]) -> bool {
    let Some(sep) = pin.iter().position(|&b| b == crate::SEPARATOR) else {
        return false;
    };
    let (prefix, rest) = pin.split_at(sep);
    let suffix = &rest[1..];
    let ok = |p: &[u8]| crate::part_len_ok(p) && p.iter().all(u8::is_ascii_digit);
    ok(prefix) && ok(suffix)
}

/// One trick this firmware made, as it is remembered to list it: its slot, flags and
/// argument. **Never the PIN**, and never a delta trick's digits.
///
/// Kept in the stored wallet's own (encrypted) settings file, so a duress session -- a
/// different wallet, a different file -- sees an empty list.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Record {
    pub slot: u8,
    pub flags: u16,
    pub arg: u16,
}

/// The most records a list holds: one per slot.
pub const MAX_RECORDS: usize = catcard_callgate::trick::NUM_TRICKS;

/// Longest rendered list: `ss:ffff:aaaa` and a comma per record.
pub const RECORDS_TEXT_LEN: usize = MAX_RECORDS * 13;

/// The list as the settings value holds it: `slot:flags:arg`, hex, comma-separated.
/// A delta trick's argument is written as `ffff`, whatever it was.
pub fn render(records: &[Record], out: &mut heapless::String<RECORDS_TEXT_LEN>) -> bool {
    use core::fmt::Write as _;
    out.clear();
    for (i, r) in records.iter().take(MAX_RECORDS).enumerate() {
        let arg = if r.flags & tc::DELTA_MODE != 0 {
            0xffff
        } else {
            r.arg
        };
        let sep = if i == 0 { "" } else { "," };
        if write!(out, "{sep}{:x}:{:04x}:{:04x}", r.slot, r.flags, arg).is_err() {
            return false;
        }
    }
    true
}

/// Read a list back. Anything that does not parse is dropped, not guessed at: a record
/// is only a label, and the slot it names is still in the secure element either way.
pub fn parse(text: &str) -> heapless::Vec<Record, MAX_RECORDS> {
    let mut out = heapless::Vec::new();
    for item in text.split(',') {
        let mut f = item.split(':');
        let (Some(s), Some(fl), Some(a), None) = (f.next(), f.next(), f.next(), f.next()) else {
            continue;
        };
        let (Ok(slot), Ok(flags), Ok(arg)) = (
            u8::from_str_radix(s, 16),
            u16::from_str_radix(fl, 16),
            u16::from_str_radix(a, 16),
        ) else {
            continue;
        };
        if usize::from(slot) >= MAX_RECORDS || out.iter().any(|r: &Record| r.slot == slot) {
            continue;
        }
        let _ = out.push(Record { slot, flags, arg });
    }
    out
}

/// The pages a list of records occupies, as a `blank_slots`-style mask.
pub fn used_mask(records: &[Record]) -> u32 {
    records.iter().fold(0, |m, r| {
        m | catcard_callgate::trick::blank_mask(r.slot as usize, r.flags).unwrap_or(0)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use catcard_callgate::trick::{NUM_TRICKS, blank_mask};

    #[test]
    fn what_a_login_reports_decides_the_effect() {
        assert_eq!(effect(0, 0), Effect::None);
        assert_eq!(effect(tc::DELTA_MODE, 0), Effect::Delta);
        assert_eq!(effect(tc::REBOOT, 0), Effect::Reboot);
        assert_eq!(effect(tc::FW_DEFINED, TCA_SP_UNLOCK), Effect::PolicyUnlock);
        assert_eq!(effect(tc::COUNTDOWN, 60), Effect::Countdown { minutes: 60 });
        assert_eq!(effect(tc::BLANK_WALLET, 0), Effect::LookBlank);
        // An unknown firmware-defined argument logs in and does nothing else.
        assert_eq!(effect(tc::FW_DEFINED, 7), Effect::None);
    }

    #[test]
    fn the_hidden_flags_never_change_the_effect() {
        // What the bootloader removed stays removed, even if it arrived somehow.
        for hidden in [
            tc::WIPE,
            tc::BRICK,
            tc::FAKE_OUT,
            tc::WORD_WALLET,
            tc::XPRV_WALLET,
        ] {
            assert_eq!(effect(hidden, 1001), Effect::None);
            assert_eq!(effect(hidden | tc::DELTA_MODE, 0), Effect::Delta);
        }
    }

    #[test]
    fn every_offered_behaviour_is_stored_as_its_documented_bits() {
        use Behaviour::*;
        assert_eq!(BrickSelf.encode(), Some((0x4000, 0)));
        assert_eq!(WipeReboot.encode(), Some((0x8200, 0)));
        assert_eq!(WipeSilent.encode(), Some((0xa000, 0)));
        assert_eq!(WipeStop.encode(), Some((0x8000, 0)));
        assert_eq!(
            WipeToDuress { words: 24, n: 1 }.encode(),
            Some((0x9000, 1001))
        );
        assert_eq!(Duress { words: 12, n: 3 }.encode(), Some((0x1000, 2003)));
        assert_eq!(DuressXprv.encode(), Some((0x0800, 1001)));
        assert_eq!(
            Countdown {
                minutes: 60,
                wipe: false
            }
            .encode(),
            Some((0x0040, 60))
        );
        assert_eq!(
            Countdown {
                minutes: 5,
                wipe: true
            }
            .encode(),
            Some((0x8040, 5))
        );
        assert_eq!(LookBlank.encode(), Some((0x0080, 0)));
        assert_eq!(JustReboot.encode(), Some((0x0200, 0)));
        assert_eq!(PolicyUnlock { wipe: false }.encode(), Some((0x0100, 1)));
        assert_eq!(PolicyUnlock { wipe: true }.encode(), Some((0x8100, 1)));
    }

    #[test]
    fn an_argument_out_of_range_is_refused() {
        use Behaviour::*;
        assert_eq!(Duress { words: 18, n: 1 }.encode(), None);
        assert_eq!(Duress { words: 24, n: 0 }.encode(), None);
        assert_eq!(Duress { words: 24, n: 4 }.encode(), None);
        assert_eq!(
            Countdown {
                minutes: 0,
                wipe: false
            }
            .encode(),
            None
        );
        assert_eq!(
            Countdown {
                minutes: MAX_COUNTDOWN_MINUTES + 1,
                wipe: false
            }
            .encode(),
            None
        );
    }

    #[test]
    fn each_stored_trick_logs_in_the_way_it_says() {
        use Behaviour::*;
        let cases = [
            (Duress { words: 24, n: 1 }, Effect::None),
            (DuressXprv, Effect::None),
            (WipeStop, Effect::None),
            (
                Countdown {
                    minutes: 15,
                    wipe: true,
                },
                Effect::Countdown { minutes: 15 },
            ),
            (LookBlank, Effect::LookBlank),
            (JustReboot, Effect::Reboot),
            (PolicyUnlock { wipe: true }, Effect::PolicyUnlock),
        ];
        for (b, want) in cases {
            let (f, a) = b.encode().unwrap();
            // The bootloader reports the censored flags and, outside delta, the argument.
            assert_eq!(effect(censor(f), a), want, "{b:?}");
        }
    }

    #[test]
    fn the_destructive_ones_are_flagged_irreversible() {
        use Behaviour::*;
        for b in [
            BrickSelf,
            WipeReboot,
            WipeSilent,
            WipeStop,
            WipeToDuress { words: 12, n: 1 },
            Countdown {
                minutes: 5,
                wipe: true,
            },
            PolicyUnlock { wipe: true },
        ] {
            assert!(irreversible(b.encode().unwrap().0), "{b:?}");
        }
        for b in [
            Duress { words: 24, n: 2 },
            DuressXprv,
            LookBlank,
            JustReboot,
            PolicyUnlock { wipe: false },
            Countdown {
                minutes: 5,
                wipe: false,
            },
        ] {
            assert!(!irreversible(b.encode().unwrap().0), "{b:?}");
        }
    }

    #[test]
    fn duress_indices_round_trip() {
        for words in [12, 24] {
            for n in 1..=3 {
                let i = duress_index(words, n).unwrap();
                assert_eq!(duress_words(i), Some((words, u32::from(i))));
            }
        }
        assert_eq!(duress_words(1000), None);
        assert_eq!(duress_words(2004), None);
    }

    #[test]
    fn names_for_the_list() {
        assert_eq!(describe(0x4000, 0), "Brick Self");
        assert_eq!(describe(0x9000, 1001), "Wipe -> Wallet");
        assert_eq!(describe(0x1000, 1001), "Duress Wallet");
        assert_eq!(describe(0x8100, 1), "Unlock Policy+Wipe");
        assert_eq!(describe(0x0400, 0xffff), "Delta Mode");
        assert_eq!(describe(0xa000, 0), "Silent Wipe");
        assert_eq!(describe(0x8000, 0), "Wipe & Stop");
    }

    #[test]
    fn a_trick_pin_has_the_main_pins_shape() {
        assert!(pin_shape_ok(b"12-34"));
        assert!(pin_shape_ok(b"123456-654321"));
        assert!(!pin_shape_ok(b"1-234"));
        assert!(!pin_shape_ok(b"1234567-12"));
        assert!(!pin_shape_ok(b"1234"));
        assert!(!pin_shape_ok(b"12-3a"));
        assert!(!pin_shape_ok(b"12-34-56"));
    }

    #[test]
    fn records_round_trip_and_never_carry_delta_digits() {
        let rs = [
            Record {
                slot: 0,
                flags: 0x9000,
                arg: 1001,
            },
            Record {
                slot: 13,
                flags: 0x0100,
                arg: 1,
            },
            Record {
                slot: 4,
                flags: 0x0400,
                arg: 0x1234,
            },
        ];
        let mut t = heapless::String::new();
        assert!(render(&rs, &mut t));
        assert_eq!(t.as_str(), "0:9000:03e9,d:0100:0001,4:0400:ffff");
        let back = parse(&t);
        assert_eq!(back.len(), 3);
        assert_eq!(back[0], rs[0]);
        assert_eq!(back[1], rs[1]);
        assert_eq!(back[2].arg, 0xffff);
    }

    #[test]
    fn a_full_list_fits_its_text() {
        let rs: heapless::Vec<Record, MAX_RECORDS> = (0..NUM_TRICKS as u8)
            .map(|s| Record {
                slot: s,
                flags: 0xffff,
                arg: 0xffff,
            })
            .collect();
        let mut t = heapless::String::new();
        assert!(render(&rs, &mut t));
        assert_eq!(parse(&t).len(), NUM_TRICKS);
    }

    #[test]
    fn junk_in_the_list_is_dropped_not_guessed() {
        let got = parse("zz:1:1,5:1000:03e9,5:4000:0,e:1:1,1:2,,7:0200:0000:9");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].slot, 5);
        assert!(parse("").is_empty());
    }

    #[test]
    fn the_used_mask_covers_data_pages() {
        let rs = [
            Record {
                slot: 0,
                flags: tc::XPRV_WALLET,
                arg: 0,
            },
            Record {
                slot: 5,
                flags: tc::WORD_WALLET,
                arg: 1001,
            },
        ];
        assert_eq!(
            used_mask(&rs),
            blank_mask(0, tc::XPRV_WALLET).unwrap() | blank_mask(5, tc::WORD_WALLET).unwrap()
        );
        assert_eq!(used_mask(&rs), 0b110_0111);
    }
}
