//! The board table.
//!
//! Every fact here is tagged with its source and confidence, per `CLEANROOM.md`:
//! **[C]** confirmed, **[I]** inferred, **[?]** unconfirmed — the `[?]` items are
//! collected in `docs/HARDWARE-OPEN-ITEMS.md`.

use crate::memory::MemoryMap;
use crate::pin::{pa, pb, pc, pd, MaybePin, Pin};

/// Which silicon a board carries. Drives register-map differences in `catcard-hal`
/// (flash controller, RAM banks, and the extra peripherals on the L4+).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Mcu {
    /// STM32L496RG — Cortex-M4F, 1 MB flash, 320 KB RAM. Source: platform.md §1 [C]
    Stm32L496,
    /// STM32L4S5xx — Cortex-M4F (L4+), 2 MB flash, 640 KB RAM. Source: platform.md §1 [C]
    Stm32L4S5,
}

impl Mcu {
    /// The L4+ parts have OCTOSPI, a different flash controller and extra SRAM banks.
    pub const fn is_l4plus(self) -> bool {
        matches!(self, Mcu::Stm32L4S5)
    }
}

/// Display panel and its wiring.
#[derive(Copy, Clone, Debug)]
pub enum Display {
    /// SSD1306 128x64 monochrome OLED on SPI1.
    /// Source: gpio-peripherals.md §Mk3 [C] for RESET/DC/CS.
    Ssd1306 {
        width: u16,
        height: u16,
        spi: SpiBus,
        reset: Pin,
        /// Data/Command select.
        dc: Pin,
        cs: Pin,
    },
    /// ST77xx-class colour LCD on SPI1 (Q / Q1).
    /// Source: gpio-peripherals.md §Q [C] for the pins; controller part and
    /// resolution are `[?]`.
    St77xx {
        width: u16,
        height: u16,
        spi: SpiBus,
        reset: Pin,
        dc: Pin,
        cs: Pin,
        /// Tearing-effect input from the panel.
        tear: MaybePin,
    },
}

/// User input hardware.
#[derive(Copy, Clone, Debug)]
pub enum Input {
    /// 4x3 membrane matrix: rows are open-drain outputs driven low one at a time,
    /// columns are pulled-up inputs. 12 keys = `0-9`, cancel, OK.
    /// Source: gpio-peripherals.md §Mk3 [C]
    Numpad4x3 { rows: [Pin; 4], cols: [Pin; 3] },
    /// 10x6 QWERTY matrix (Q / Q1), up to 60 keys. Replaces the numpad.
    ///
    /// The anti-Tempest scan randomisation the numpad uses applies here too — and, as
    /// on the numpad, it must be driven from the UI DRBG and never from seed entropy.
    /// Source: generations-mk2-q-mk5.md §Q [C] for pins; scan detail `[?]`
    Qwerty { rows: [Pin; 6], cols: [Pin; 10] },
}

/// Second secure element, on I2C. Secrets go through the bootloader callgate, so this
/// is only needed for direct non-secret access.
/// Source: generations-mk2-q-mk5.md §Q [C]
#[derive(Copy, Clone, Debug)]
pub struct Se2Pins {
    pub scl: Pin,
    pub sda: Pin,
}

/// NFC interface, used for tap-to-transfer of PSBTs and addresses.
/// Source: generations-mk2-q-mk5.md §Q [C]
#[derive(Copy, Clone, Debug)]
pub struct NfcPins {
    /// Event/interrupt line from the tag.
    pub ed: Pin,
    pub scl: Pin,
    /// The matching SDA line is not stated in the reference. `[?]`
    pub sda: MaybePin,
}

/// Which SPI peripheral instance, and the data pins on it.
#[derive(Copy, Clone, Debug)]
pub struct SpiBus {
    /// 1-based, matching ST's naming (SPI1, SPI2, ...).
    pub instance: u8,
    pub sck: Pin,
    pub mosi: Pin,
    /// Display buses are write-only; MISO may be unrouted.
    pub miso: MaybePin,
    /// True when `sck`/`mosi`/`miso` are inferred rather than confirmed.
    pub pins_confirmed: bool,
}

/// SDMMC in 4-bit mode. Source: gpio-peripherals.md §Mk3 [C]
#[derive(Copy, Clone, Debug)]
pub struct SdmmcPins {
    pub d0: Pin,
    pub d1: Pin,
    pub d2: Pin,
    pub d3: Pin,
    pub cmd: Pin,
    pub ck: Pin,
    /// Card-detect switch. `[?]`
    pub card_detect: MaybePin,
    /// Activity LED / power-enable line.
    pub active: MaybePin,
}

/// SPI-NOR flash: PSBT scratch, settings, and the staging area a pending firmware
/// image is written to before reboot. Source: gpio-peripherals.md §Mk3 [C],
/// install-and-usb-transport.md §2 [C]
#[derive(Copy, Clone, Debug)]
pub struct SflashPins {
    pub spi: SpiBus,
    /// Chip select. `[?]` on every board — see HARDWARE-OPEN-ITEMS.
    pub cs: MaybePin,
    /// Bus clock the stock firmware ran at; a safe starting point.
    pub max_hz: u32,
    /// Erase granularity of the NOR part (4 KB sector erase, opcode 0x20).
    pub sector_len: u32,
}

/// USB OTG FS. Source: install-and-usb-transport.md §1 [C]
#[derive(Copy, Clone, Debug)]
pub struct UsbPins {
    pub dm: Pin,
    pub dp: Pin,
}

/// Everything the firmware needs to know about the hardware it was built for.
#[derive(Copy, Clone, Debug)]
pub struct BoardSpec {
    /// Short name used for build features, artifact filenames and CLI selection.
    pub name: &'static str,
    pub mcu: Mcu,
    pub memory: MemoryMap,

    /// Bit to set in the firmware header's `hw_compat` field so the bootloader will
    /// accept this image. Source: firmware-signing.md §1 [C]
    pub hw_compat_bit: u32,

    pub display: Display,
    pub input: Input,
    pub sdmmc: SdmmcPins,
    pub sflash: SflashPins,
    pub usb: UsbPins,

    /// Second secure element on I2C. Source: secure-elements.md §SE2 [C] for presence.
    pub has_se2: bool,
    /// SE2's bus pins, where they are confirmed. `None` means the chip is present but
    /// we do not know where — see `docs/HARDWARE-OPEN-ITEMS.md`.
    pub se2: Option<Se2Pins>,
    /// NFC bus pins, where confirmed.
    pub nfc: Option<NfcPins>,
    /// External PSRAM. Source: gpio-peripherals.md §Mk4 [I]
    pub has_psram: bool,
    /// `true` once we can read the SE TRNGs through callgate 26 on this board.
    /// Source: bootloader-callgate-abi.md #26 — documented for mk4+ only.
    pub has_callgate_se_rng: bool,
}

// The callgate entry address is deliberately NOT a field here. The bootloader
// publishes it at runtime in a table at 0x0800_0040, and it moves between bootloader
// versions and boards -- so it is read and validated by `catcard_callgate::entry`,
// never baked into a board table. Source: bootloader-callgate-abi.md §0 [C].

impl BoardSpec {
    /// Look a board up by the name used in build features and CLI flags.
    pub fn by_name(name: &str) -> Option<&'static BoardSpec> {
        ALL.iter().find(|b| b.name == name)
    }
}

// ---------------------------------------------------------------------------
// Mk3 — STM32L496RG
// ---------------------------------------------------------------------------

/// SPI1 carries the OLED. RESET/DC/CS are confirmed; SCK/MOSI are not stated in the
/// reference, but the Q1 board (same MCU family, same display-control pins PA4/PA6/PA8)
/// routes SCLK=PA5 and MOSI=PA7 — the SPI1 default AF5 pins. Taking those as [I].
/// Source: gpio-peripherals.md §Mk3 [C] (control pins), §Q [C] (SPI1 data pins)
const MK3_DISPLAY_SPI: SpiBus = SpiBus {
    instance: 1,
    sck: pa(5),
    mosi: pa(7),
    miso: None,
    pins_confirmed: false,
};

/// SPI2 carries the SPI-NOR flash. MISO=PC2 / MOSI=PC3 are confirmed (AF5). SCK and
/// CS are not stated. Note PB12/PB13 — the usual SPI2 NSS/SCK pins — are taken by the
/// numpad rows on this board, which leaves PB10 or PD1 for SCK and PB9 or PD0 for CS.
/// PD1 is recorded as the working candidate so the driver has something to compile
/// against; `pins_confirmed: false` and `cs: None` are what actually gate bring-up.
/// Source: gpio-peripherals.md §Mk3 [C] (MISO/MOSI), [?] (SCK/CS)
const MK3_SFLASH_SPI: SpiBus = SpiBus {
    instance: 2,
    sck: pd(1),
    mosi: pc(3),
    miso: Some(pc(2)),
    pins_confirmed: false,
};

pub const MK3: BoardSpec = BoardSpec {
    name: "mk3",
    mcu: Mcu::Stm32L496,
    memory: MemoryMap {
        // Source: platform.md §2 [C]
        firmware_base: 0x0800_8000,
        // 1 MB part, minus the 32 KB bootloader below us.
        firmware_flash_len: 0x0010_0000 - 0x8000,
        total_flash_len: 0x0010_0000,
        // STM32L4 (non-plus): 2 KB pages. Source: RM0351 §3.3.1
        flash_page_len: 2 * 1024,
        // SRAM1 is 256 KB on the L496. SRAM2 is contiguous above it but its size is
        // reported inconsistently in our reference (32 KB there vs 64 KB in the ST
        // datasheet), so it is excluded until measured. See HARDWARE-OPEN-ITEMS.
        sram1_base: 0x2000_0000,
        sram1_len: 256 * 1024,
        // Source: platform.md §2 [C] — `BL_SRAM_BASE` / `BL_SRAM_SIZE`, in the
        // SRAM2 alias window at 0x1000_0000. Outside our linked region either way.
        bl_sram_base: 0x1000_6000,
        bl_sram_len: 0x1c00,
    },
    hw_compat_bit: 0x04, // MK_3_OK
    display: Display::Ssd1306 {
        width: 128,
        height: 64,
        spi: MK3_DISPLAY_SPI,
        reset: pa(6),
        dc: pa(8),
        cs: pa(4),
    },
    input: Input::Numpad4x3 {
        rows: [pb(12), pb(13), pb(14), pc(6)],
        cols: [pa(1), pa(3), pa(2)],
    },
    sdmmc: SdmmcPins {
        d0: pc(8),
        d1: pc(9),
        d2: pc(10),
        d3: pc(11),
        cmd: pd(2),
        ck: pc(12),
        card_detect: Some(pa(9)), // [?]
        active: Some(pc(7)),
    },
    sflash: SflashPins {
        spi: MK3_SFLASH_SPI,
        cs: None, // [?]
        max_hz: 8_000_000,
        sector_len: 4096,
    },
    usb: UsbPins {
        dm: pa(11),
        dp: pa(12),
    },
    has_se2: false,
    se2: None,
    nfc: None,
    has_psram: false,
    // Callgate 26 is documented as mk4+. On mk3 the STM32 TRNG plus user-input
    // timing must carry the entropy pool on their own.
    has_callgate_se_rng: false,
};

// ---------------------------------------------------------------------------
// Mk4 — STM32L4S5
// ---------------------------------------------------------------------------

pub const MK4: BoardSpec = BoardSpec {
    name: "mk4",
    mcu: Mcu::Stm32L4S5,
    memory: MemoryMap {
        // Source: platform.md §2 [C]
        firmware_base: 0x0802_0000,
        // 2 MB part [I], minus the 128 KB below us.
        firmware_flash_len: 0x0020_0000 - 0x2_0000,
        total_flash_len: 0x0020_0000,
        // L4+ single-bank: 8 KB pages; dual-bank: 4 KB. Bank config is [?], so the
        // conservative (larger) erase unit is assumed. Source: RM0432 §3.3.1
        flash_page_len: 8 * 1024,
        // SRAM1 on the L4S5 is 192 KB; SRAM2/SRAM3 sit above it. Only SRAM1 is linked
        // for now — and the callgate requires its buffer in SRAM1 regardless.
        sram1_base: 0x2000_0000,
        sram1_len: 192 * 1024,
        bl_sram_base: 0x1000_6000,
        bl_sram_len: 0x1c00,
    },
    hw_compat_bit: 0x08, // MK_4_OK
    // Same OLED as mk3. Source: gpio-peripherals.md §Mk4 [I]
    display: Display::Ssd1306 {
        width: 128,
        height: 64,
        spi: MK3_DISPLAY_SPI,
        reset: pa(6),
        dc: pa(8),
        cs: pa(4),
    },
    // Same numpad as mk3. Source: gpio-peripherals.md §Mk4 [I]
    input: Input::Numpad4x3 {
        rows: [pb(12), pb(13), pb(14), pc(6)],
        cols: [pa(1), pa(3), pa(2)],
    },
    sdmmc: SdmmcPins {
        d0: pc(8),
        d1: pc(9),
        d2: pc(10),
        d3: pc(11),
        cmd: pd(2),
        ck: pc(12),
        card_detect: Some(pa(9)), // [?]
        active: Some(pc(7)),
    },
    sflash: SflashPins {
        spi: MK3_SFLASH_SPI, // [I] — shared with mk3 per gpio-peripherals.md §Q
        cs: None,            // [?]
        max_hz: 8_000_000,
        sector_len: 4096,
    },
    usb: UsbPins {
        dm: pa(11),
        dp: pa(12),
    },
    has_se2: true,
    // SE2 is confirmed present on mk4, but its pins are not. The Q1 board routes
    // SE2 to PB13/PB14 -- which on mk3 are numpad rows. mk4 is documented as having
    // both the mk3 numpad [I] and SE2 [C], and those two cannot both be true at
    // PB13/PB14. Rather than pick one, both stay unresolved here: `se2: None`, and
    // the numpad map below is inherited from mk3 but flagged in HARDWARE-OPEN-ITEMS.
    se2: None,
    // NFC is confirmed present on mk4 from image strings, pins unconfirmed.
    nfc: None,
    has_psram: true,
    has_callgate_se_rng: true,
};

// ---------------------------------------------------------------------------
// Q / Q1 — STM32L4S5 with LCD, QWERTY and a QR scanner
// ---------------------------------------------------------------------------

/// Source: gpio-peripherals.md §Q [C]
const Q1_DISPLAY_SPI: SpiBus = SpiBus {
    instance: 1,
    sck: pa(5),
    mosi: pa(7),
    miso: None,
    pins_confirmed: true,
};

pub const Q1: BoardSpec = BoardSpec {
    name: "q1",
    mcu: Mcu::Stm32L4S5,
    memory: MK4.memory,
    // The reference lists MK_5_OK=0x10 as the highest bit; which bit the bootloader
    // checks for a Q is [?]. Both mk4 and mk5 bits are set so the image is accepted
    // either way — `hw_compat` is a permit-list, not an identity.
    hw_compat_bit: 0x08 | 0x10,
    display: Display::St77xx {
        // ~320x240 [?] — confirm the controller and resolution on a board.
        width: 320,
        height: 240,
        spi: Q1_DISPLAY_SPI,
        reset: pa(6),
        dc: pa(8),
        cs: pa(4),
        tear: Some(pb(11)),
    },
    // Source: generations-mk2-q-mk5.md §Q [C]
    input: Input::Qwerty {
        rows: [pd(8), pd(9), pd(10), pd(11), pd(12), pd(7)],
        cols: [
            pb(0),
            pb(1),
            pb(2),
            pb(5),
            pb(8),
            pb(9),
            pb(10),
            pd(13),
            pd(14),
            pd(15),
        ],
    },
    sdmmc: MK4.sdmmc,
    sflash: MK4.sflash,
    usb: MK4.usb,
    has_se2: true,
    // Source: generations-mk2-q-mk5.md §Q [C]
    se2: Some(Se2Pins {
        scl: pb(13),
        sda: pb(14),
    }),
    // Source: generations-mk2-q-mk5.md §Q [C] for ED/SCL; SDA `[?]`
    nfc: Some(NfcPins {
        ed: pd(6),
        scl: pb(6),
        sda: None,
    }),
    has_psram: true,
    has_callgate_se_rng: true,
};

/// Every board, for host tools that must handle all of them.
pub const ALL: &[BoardSpec] = &[MK3, MK4, Q1];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{fixed, FW_HEADER_OFFSET};

    #[test]
    fn names_are_unique() {
        for (i, a) in ALL.iter().enumerate() {
            for b in &ALL[i + 1..] {
                assert_ne!(a.name, b.name);
            }
        }
    }

    #[test]
    fn lookup_by_name() {
        assert_eq!(BoardSpec::by_name("mk3").unwrap().mcu, Mcu::Stm32L496);
        assert!(BoardSpec::by_name("mk9").is_none());
    }

    #[test]
    fn firmware_region_fits_in_flash() {
        for b in ALL {
            let m = &b.memory;
            assert_eq!(m.bootloader_len(), m.firmware_base - fixed::FLASH_BASE);
            assert!(
                m.bootloader_len() + m.firmware_flash_len <= m.total_flash_len,
                "{}: firmware region overruns flash",
                b.name
            );
            // The header must land inside the region we hand to the linker.
            assert!(FW_HEADER_OFFSET + 128 < m.firmware_flash_len, "{}", b.name);
        }
    }

    #[test]
    fn erase_granularity_divides_the_region() {
        for b in ALL {
            assert_eq!(
                b.memory.firmware_flash_len % b.memory.flash_page_len,
                0,
                "{}: firmware region is not a whole number of flash pages",
                b.name
            );
        }
    }

    #[test]
    fn bootloader_sram_is_outside_our_linked_ram() {
        for b in ALL {
            let m = &b.memory;
            let bl_end = m.bl_sram_base + m.bl_sram_len;
            assert!(
                bl_end <= m.sram1_base || m.bl_sram_base >= m.sram1_end(),
                "{}: linked RAM overlaps the bootloader's SRAM reservation",
                b.name
            );
        }
    }

    #[test]
    fn hw_compat_bits_are_within_the_defined_mask() {
        // MK_1_OK..MK_5_OK. Source: firmware-signing.md §1 [C]
        for b in ALL {
            assert_eq!(b.hw_compat_bit & !0x1f, 0, "{}", b.name);
            assert_ne!(b.hw_compat_bit, 0, "{}", b.name);
        }
    }

    #[test]
    fn no_pin_is_assigned_twice_on_a_board() {
        for b in ALL {
            let mut used: Vec<(char, u8, &str)> = Vec::new();
            let mut claim = |p: Pin, what: &'static str, board: &str| {
                let key = (p.port.letter(), p.num);
                if let Some((_, _, prev)) = used.iter().find(|(l, n, _)| (*l, *n) == key) {
                    panic!(
                        "{board}: P{}{} claimed by both {prev} and {what}",
                        key.0, key.1
                    );
                }
                used.push((key.0, key.1, what));
            };

            match b.display {
                Display::Ssd1306 {
                    spi, reset, dc, cs, ..
                }
                | Display::St77xx {
                    spi, reset, dc, cs, ..
                } => {
                    claim(spi.sck, "display SCK", b.name);
                    claim(spi.mosi, "display MOSI", b.name);
                    claim(reset, "display RESET", b.name);
                    claim(dc, "display DC", b.name);
                    claim(cs, "display CS", b.name);
                }
            }
            match b.input {
                Input::Numpad4x3 { rows, cols } => {
                    for r in rows {
                        claim(r, "numpad row", b.name);
                    }
                    for c in cols {
                        claim(c, "numpad col", b.name);
                    }
                }
                Input::Qwerty { rows, cols } => {
                    for r in rows {
                        claim(r, "keyboard row", b.name);
                    }
                    for c in cols {
                        claim(c, "keyboard col", b.name);
                    }
                }
            }
            if let Some(se2) = b.se2 {
                claim(se2.scl, "SE2 SCL", b.name);
                claim(se2.sda, "SE2 SDA", b.name);
            }
            if let Some(nfc) = b.nfc {
                claim(nfc.ed, "NFC ED", b.name);
                claim(nfc.scl, "NFC SCL", b.name);
            }
            for (p, what) in [
                (b.sdmmc.d0, "SD D0"),
                (b.sdmmc.d1, "SD D1"),
                (b.sdmmc.d2, "SD D2"),
                (b.sdmmc.d3, "SD D3"),
                (b.sdmmc.cmd, "SD CMD"),
                (b.sdmmc.ck, "SD CK"),
                (b.sflash.spi.sck, "SPI-NOR SCK"),
                (b.sflash.spi.mosi, "SPI-NOR MOSI"),
                (b.usb.dm, "USB DM"),
                (b.usb.dp, "USB DP"),
            ] {
                claim(p, what, b.name);
            }
            if let Some(p) = b.sflash.spi.miso {
                claim(p, "SPI-NOR MISO", b.name);
            }
        }
    }
}
