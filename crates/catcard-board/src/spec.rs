//! The board table.
//!
//! Every fact here is tagged with its source and confidence, per `CLEANROOM.md`:
//! **[C]** confirmed, **[I]** inferred, **[?]** unconfirmed — the `[?]` items are
//! collected in `docs/HARDWARE-OPEN-ITEMS.md`.

use crate::memory::{MemoryMap, SpareRam};
use crate::pin::{MaybePin, Pin, pa, pb, pc, pd, pe};

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
    /// Sitronix ST7789 colour LCD on SPI1 (Q / Q1), 320x240 RGB565. The bootloader
    /// initialises it; the firmware must inherit that state and never reset the panel.
    /// Source: gpio-peripherals.md §Q/Q1 [C] for the pins; display.md §Q1 [C] for the
    /// controller, the resolution and the inherit rule
    St77xx {
        width: u16,
        height: u16,
        spi: SpiBus,
        reset: Pin,
        dc: Pin,
        cs: Pin,
        /// Tearing-effect input from the panel.
        tear: MaybePin,
        /// Backlight enable. The bootloader's picture is invisible until the firmware
        /// drives this high.
        backlight: MaybePin,
        /// Hand-off with a display co-processor sharing SPI1, as `(request, busy)`: drive
        /// `request` high to take the bus, then wait for `busy` to read low.
        bus_grant: Option<(Pin, Pin)>,
    },
}

/// Where a board keeps its settings blob.
///
/// Not a preference: it is where stock firmware put it, and reading an existing device's
/// settings after a firmware swap means looking in the same place.
/// Source: hw-reference/settings-nvstore-format.md §1 [C]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SettingsArea {
    /// A LittleFS2 volume on internal flash (mk4 / mk5 / Q1): the 512 KB region above the
    /// firmware, holding `settings/%03x.aes`.
    InternalFlash { start: u32, len: u32 },
    /// Raw slots in SPI-NOR (mk3): 4 KB each, in the last 128 KB of the part.
    SpiNor { start: u32, len: u32, slot: u32 },
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
/// External PSRAM, memory-mapped through OCTOSPI1.
///
/// Firmware upgrades are staged here on the boards that have it — there is no SPI-NOR
/// on mk4 or later. The bootloader looks for a recovery header at [`Self::staging_header`]
/// on boot and installs whatever it points at, so this is the address that decides
/// whether an upgrade happens.
///
/// Source: gpio-peripherals.md §Mk4 [C], install-and-usb-transport.md §2 [C]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Psram {
    /// Where the chip appears in the address space.
    pub base: u32,
    pub len: u32,
    /// The OCTOSPI clock, in hertz.
    ///
    /// How long the part is held selected for a given number of bytes is a function of
    /// this, and the limit it has to stay under is a time (`tCEM`). So the burst length
    /// is arithmetic, not a constant, and it is arithmetic **per board**: a figure worked
    /// out on one board's bus is silently wrong on another's.
    ///
    /// Source: hw-reference/storage.md §PSRAM — prescaler 2 off the 120 MHz kernel
    /// clock, for all three boards that have PSRAM [C].
    pub ospi_hz: u32,
    /// The controller's memory-mapped timeout, in OCTOSPI clocks.
    ///
    /// What actually drives CE# high once the bus goes idle, and therefore how long a
    /// gap between bursts has to be before it is a gap at all.
    ///
    /// **The bootloader's, not ours.** `psram_setup()` runs once at boot and hands over
    /// a controller that is clocked, initialised and memory-mapped with
    /// `TimeOutPeriod = 16`; this firmware inherits it the way it inherits the clock
    /// tree and the LCD, and never re-inits, re-clocks, or leaves memory-mapped mode.
    /// So this is a number to read and compute against, never one to write.
    ///
    /// Source: hw-reference/storage.md §PSRAM, `mk4-bootloader/psram.c` [C].
    pub mmap_timeout_clocks: u32,
    /// Where the bootloader reads the firmware-staging recovery header.
    ///
    /// `base + len - 2048`, but written out rather than computed: it is confirmed as an
    /// absolute address, and a wrong `len` would silently move it.
    pub staging_header: u32,
}

impl Psram {
    /// One past the last byte.
    pub const fn end(&self) -> u32 {
        self.base + self.len
    }

    /// Where a staged firmware image begins.
    ///
    /// Half way in, which is not a partition -- PSRAM is claimed whole, one holder at a
    /// time -- but simply where the bootloader has been handed images that it accepted.
    /// The staging header carries this offset, so the bootloader is told rather than
    /// assuming; moving it is nonetheless a change to the one path that can leave a
    /// device unable to boot, and there is nothing to gain by it.
    pub const fn image_base(&self) -> u32 {
        self.base + self.len / 2
    }

    /// Everything below the recovery header: the part a holder may use.
    ///
    /// The last two kilobytes are the bootloader's -- they say where a staged image is,
    /// and they are read before any of this firmware runs -- so they are not scratch and
    /// are not handed out.
    pub const fn usable(&self) -> u32 {
        self.staging_header - self.base
    }
}

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
    /// I2C1 SDA. Source: gpio-peripherals.md §Bus instance summary [C]
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
    /// Card-detect switch for the first (or only) slot, read with a pull-up.
    pub card_detect: MaybePin,
    /// The level `card_detect` reads when a card **is** present.
    ///
    /// Not the same on every board -- high on mk3 and mk4, low on Q1 -- so it is a fact
    /// recorded per board rather than a convention the driver assumes. Getting it
    /// backwards reports an empty slot as full and a full one as empty.
    /// Source: gpio-peripherals.md §SDMMC1 "Card-detect -- polarity differs" [C]
    pub card_present_high: bool,
    /// Activity LED / power-enable line.
    pub active: MaybePin,
    /// Analog multiplexer steering the one controller between two slots, on boards that
    /// have two: low selects slot A, high slot B. `None` on single-slot boards.
    pub mux: MaybePin,
    /// The second slot's own detect and activity lines, where there is one.
    pub slot_b: Option<SdSlot>,
}

/// A second microSD slot sharing the controller through [`SdmmcPins::mux`].
#[derive(Copy, Clone, Debug)]
pub struct SdSlot {
    /// Read with a pull-up, at the same polarity as [`SdmmcPins::card_present_high`].
    pub card_detect: Pin,
    pub active: Pin,
}

/// SPI-NOR flash: PSBT scratch, settings, and the staging area a pending firmware
/// image is written to before reboot. Source: gpio-peripherals.md §Mk3 [C],
/// install-and-usb-transport.md §2 [C]
#[derive(Copy, Clone, Debug)]
pub struct SflashPins {
    pub spi: SpiBus,
    /// Chip select, a software-driven GPIO output (not the SPI hardware NSS). Confirmed
    /// PB9 on mk3; the only board with SPI-NOR at all.
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

/// The Q1's QR scanner: a decoded-barcode engine on its own serial port.
///
/// Not a camera. The module images and decodes by itself and hands back plain text over
/// USART2, so the firmware's side of it is a UART and two GPIOs.
///
/// Source: hw-reference/gpio.md §Q1, hw-reference/input.md §"QR scanner (Q1)" [C]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct QrScanner {
    /// `QR_TX`: this board's transmit, the module's receive.
    pub tx: Pin,
    /// `QR_RX`.
    pub rx: Pin,
    /// `QR_RESET`, **open-drain and active-low**: a 10 ms pulse, then the module needs
    /// two seconds before it will answer.
    pub reset: Pin,
    /// `QR_TRIG`, open-drain. Stock leaves it alone and drives scanning over the UART.
    pub trigger: Pin,
}

/// How a board reports whether it is on battery or external power.
///
/// There is no VBUS-present GPIO: USB power just feeds the regulator. `NOT_BATTERY` is
/// the only signal, and it is **active-low** -- high means external/USB, low means
/// battery. Which pin carries it depends on the board revision, which is itself a strap
/// read at runtime, so both are here and the firmware picks.
///
/// Source: power.md §"Battery & power pins", §"Power source: battery vs USB" [C]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct BatterySense {
    /// `NOT_BATTERY`, on rev D and later.
    pub not_battery: Pin,
    /// `NOT_BATTERY_OLD`, on earlier revisions.
    pub not_battery_old: Pin,
    /// `REV_D`: read with a pull-up, high on rev D and later, which picks between the two
    /// pins above.
    pub rev_d: Pin,
    /// `VIN_SENSE`, the divided battery voltage (ADC1 IN6, with a divide-by-two).
    ///
    /// Only meaningful while on battery. Not read yet -- the status bar shows the source,
    /// not the level -- but it belongs with the rest of the description rather than being
    /// rediscovered later.
    pub vin_sense: Pin,
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
    /// SPI-NOR flash, on the boards that have one.
    ///
    /// `None` from mk4 onward: SPI2 was "removed in Mk4 rev B", settings moved to
    /// internal flash and upgrade staging moved to [`Psram`].
    /// Source: gpio-peripherals.md §Mk4 [C]
    pub sflash: Option<SflashPins>,
    pub usb: UsbPins,
    /// USB activity LED, on the boards that have one.
    ///
    /// A plain firmware-driven output: there is no hardware activity-detect circuit, so
    /// nothing blinks unless the firmware blinks it. `None` on mk3, which has no such
    /// line at all. Source: usb.md §"USB activity LED" [C]
    pub usb_active: MaybePin,

    /// The power button, on a board that can actually power itself off.
    ///
    /// Active-low with a pull-up, so a press reads 0. `None` on the USB-powered boards:
    /// they have no button and nothing to switch off. Source: power.md §"Battery & power
    /// pins" [C]
    pub pwr_btn: MaybePin,

    /// The QR scanner, on the one board that has one.
    pub qr: Option<QrScanner>,

    /// Whether this board runs on a battery, and how to tell.
    ///
    /// `None` on the USB-powered boards, which are never on battery and have no pin for
    /// it. Source: power.md §"Battery & power pins" [C]
    pub battery: Option<BatterySense>,

    /// How much of SRAM1, from its base, the bootloader will accept a callgate buffer in.
    ///
    /// Not the same as [`MemoryMap::sram1_len`], and finding that out cost a day: the mk3
    /// bootloader takes a `buf_io` only in the **first 96 KB** of SRAM1 and answers `1` --
    /// a generic error, not a range error -- for anything above it, writing nothing into
    /// the buffer. Gate 18 setup then "succeeded" with an all-zero struct, so the firmware
    /// read `state_flags = 0`, concluded the device had a PIN, and offered a login that
    /// could never work: every later call failed its HMAC check against a signature that
    /// was never written.
    ///
    /// Measured on hardware (mk3 bootloader 2.0.0, `git=mark3@d841cc5`) by calling gate 0
    /// `get_bl_version` at descending addresses: it fills a buffer ending at exactly
    /// `0x2001_8000` and refuses one that starts there.
    ///
    /// Source: hw-reference/bootloader-callgate-abi.md §0.1 [C] (measured on hardware)
    pub gate_buf_len: u32,

    /// Whether the keypad's falling-edge EXTI path is armed from the boot path.
    ///
    /// The columns carry a hard interrupt so a keypress can be timestamped at the
    /// electrical edge rather than at the next scan -- that sample is entropy, and it is
    /// the only interrupt this firmware arms before anyone can look at the device. Where it
    /// misbehaves the result is a board whose keypad half works and whose USB, polled from
    /// the same foreground, turns unreliable: a unit that cannot be re-flashed, which on a
    /// locked board is permanent.
    ///
    /// So this is false until the path has been watched working on that board, and Debug ->
    /// Keypad arms it by hand meanwhile. Not an `Option`: "we have not checked" and "it
    /// does not work here" want the same safe behaviour.
    pub keypad_edge_at_boot: bool,

    /// Where the settings blob lives on this board.
    pub settings: SettingsArea,

    /// The Q1's GPU co-processor reset line, `G_RESET`: open-drain, low holds it in reset.
    ///
    /// The co-processor draws the activity bar by itself while the main MCU is blocked --
    /// the only way the Q1's screen can move during a secure-element call. The bootloader
    /// leaves it held in reset; the firmware releases it. Its bus-grant lines are
    /// `Display::St77xx::bus_grant`.
    ///
    /// Source: hw-reference/gpu.md [C]; gpio.md "GPU co-MCU (STM32C011F4, I²C1,
    /// `G_RESET=PE6`/`G_CTRL=PE5`/`G_BUSY=PE2`)" [C]
    pub gpu_reset: MaybePin,

    /// SE1's single-wire bus pin, on a board where the firmware reads SE1 directly.
    ///
    /// SE1 sits on UART4 in half-duplex mode, one pin for both directions, on every
    /// generation. mk4+ reach its TRNG through callgate 26, which authenticates the element,
    /// so they leave this `None` and never touch the bus. The mk3 bootloader has no such
    /// callgate, so there the firmware issues SE1's unprivileged `Random` itself -- mixed
    /// into the pool and credited zero, because nothing authenticates this wire.
    ///
    /// Source: hw-reference/gpio.md "UART4 `TX=RX=PA0`, half-duplex, SE1, all generations"
    /// [C]; platform.md §3 "Reading the SE1 RNG on mk3" [C]
    pub se1_swi: MaybePin,

    /// Second secure element on I2C. Source: secure-elements.md §SE2 [C] for presence.
    pub has_se2: bool,
    /// SE2's bus pins, where they are confirmed. `None` means the chip is present but
    /// we do not know where — see `docs/HARDWARE-OPEN-ITEMS.md`.
    pub se2: Option<Se2Pins>,
    /// NFC bus pins, where confirmed.
    pub nfc: Option<NfcPins>,
    /// External PSRAM, where present. Source: gpio-peripherals.md §Mk4 [C]
    pub psram: Option<Psram>,
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

/// SPI1 carries the OLED, write-only: SCK=PA5, MOSI=PA7, no MISO; control pins RESET=PA6,
/// DC=PA8, CS=PA4. Mode 0. PA6 doubles as SPI1_MISO's AF pin but is driven as the reset
/// GPIO (the panel is write-only), which is why MISO is unrouted rather than a conflict.
/// Source: hw-reference/display.md §OLED [C].
const MK3_DISPLAY_SPI: SpiBus = SpiBus {
    instance: 1,
    sck: pa(5),
    mosi: pa(7),
    miso: None,
    pins_confirmed: true,
};

/// SPI2 carries the SPI-NOR flash (Macronix MX25L8006E, 1 MB): SCK=PB10, MOSI=PC3,
/// MISO=PC2, at 8 MHz in mode 0. The chip-select is PB9 driven as a plain GPIO output
/// (low around each opcode) -- it is *not* the SPI2 hardware NSS, even though PB9 is that
/// pin's AF. A firmware that leaves CS unset cannot write SPI-NOR, and on mk3 that is the
/// only staging area, so it cannot self-upgrade. Source: hw-reference/storage.md §SPI-NOR
/// and gpio.md [C].
const MK3_SFLASH_SPI: SpiBus = SpiBus {
    instance: 2,
    sck: pb(10),
    mosi: pc(3),
    miso: Some(pc(2)),
    pins_confirmed: true,
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
        // SRAM2 here is a 32 KB alias window at 0x1000_0000 rather than a continuation
        // of SRAM1, its size is reported inconsistently (see HARDWARE-OPEN-ITEMS), and
        // the bootloader lives in it. SRAM1's own 256 KB has room to spare regardless.
        spare_ram: None,
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
    // 4x3 membrane numpad. Rows are open-drain outputs, columns pulled-up inputs.
    // mk3 pins: rows M2_ROW0..3 = PB12, PB13, PB14, PC6; cols M2_COL0..2 = PA1, PA3, PA2 --
    // in that order, so the scanner's `row * 3 + col` index matches the DECODER
    // 'y0x987654321'. NOTE: these are the *mk3* pins. Mk4/Mk5 use different numpad pins
    // (cols PB0/1/2, rows PD8-11) -- do not cross them. Confirmed working on hardware.
    // Source: hw-reference/input.md §Membrane numpad, "Mk3 pins" table [C].
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
        // `SD_SW`, pulled up: **card present = pin high**.
        // Source: gpio-peripherals.md §Mk3 [C]
        card_detect: Some(pa(9)),
        card_present_high: true,
        active: Some(pc(7)),
        mux: None,
        slot_b: None,
    },
    // The only board with one. Source: hw-reference/storage.md §SPI-NOR [C].
    sflash: Some(SflashPins {
        spi: MK3_SFLASH_SPI,
        cs: Some(pb(9)), // software-driven GPIO CS, not SPI2 NSS -- storage.md [C]
        max_hz: 8_000_000,
        sector_len: 4096,
    }),
    usb: UsbPins {
        dm: pa(11),
        dp: pa(12),
    },
    // mk3 has no USB activity line. Source: usb.md §"USB activity LED" [C]
    usb_active: None,
    pwr_btn: None,
    qr: None,
    battery: None,
    // **Not** armed at boot. With interrupts enabled at boot this path came up on an mk3
    // with a keypad that answered a few presses and then mostly stopped, and USB that did
    // not work right -- a unit that could no longer be re-flashed. Whatever the mk3 columns
    // do here has never been watched, so the keypad stays polled until it is: Debug ->
    // Keypad arms it, and a power cycle undoes that.
    // 96 KB, measured -- see the field's documentation. The rest of SRAM1 is ours to
    // use, but nothing the callgate is handed may live up there.
    gate_buf_len: 96 * 1024,
    keypad_edge_at_boot: false,
    // 32 slots of 4 KB in the last 128 KB of the 1 MB SPI-NOR.
    // Source: settings-nvstore-format.md §1 [C]
    settings: SettingsArea::SpiNor {
        start: 0x000E_0000,
        len: 0x0002_0000,
        slot: 0x1000,
    },
    gpu_reset: None,
    // No SE-randomness callgate on mk3, so the firmware reads SE1 over this pin itself.
    se1_swi: Some(pa(0)),
    has_se2: false,
    se2: None,
    nfc: None,
    psram: None,
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
        // **Not the mk3's alias window.** On these parts SRAM1/2/3 are one contiguous
        // 640 KB from 0x2000_0000 and there is no 0x1000_0000 alias at all; what the
        // bootloader reserves is the top 8 KB of SRAM3.
        // Source: platform.md §"Mk4/Mk5/Q flash & SRAM map" [C]
        bl_sram_base: 0x2009_e000,
        bl_sram_len: 8 * 1024,
        // Everything above the linked 192 KB, stopping where the bootloader's 8 KB
        // begins: 0x2003_0000..0x2009_e000, which is 440 KiB of SRAM2+SRAM3 that no
        // section is placed in. Source: platform.md §"Mk4/Mk5/Q flash & SRAM map" [C]
        spare_ram: Some(SpareRam {
            base: 0x2003_0000,
            len: 0x2009_e000 - 0x2003_0000,
        }),
    },
    hw_compat_bit: 0x08, // MK_4_OK
    // "Same OLED 128x64" as mk3, in a section whose header reads `[C unless noted]`
    // and which notes only the numpad as differing; the bus summary lists the SSD1306
    // on SPI1 for mk3/4/5 outright. Control pins are the mk3 ones, unchanged.
    // Source: gpio-peripherals.md §Mk4 and §Bus instance summary [C]
    display: Display::Ssd1306 {
        width: 128,
        height: 64,
        spi: MK3_DISPLAY_SPI,
        reset: pa(6),
        dc: pa(8),
        cs: pa(4),
    },
    // Same 4x3 layout as mk3 but **different pins** — the reference calls out the
    // "same as mk3" inference as wrong, and these are the corrected ones. They also
    // free PB13/PB14 for SE2, which is what the old map collided with.
    // Source: gpio-peripherals.md §Mk4 [C]
    input: Input::Numpad4x3 {
        rows: [pd(8), pd(9), pd(10), pd(11)],
        cols: [pb(0), pb(1), pb(2)],
    },
    sdmmc: SdmmcPins {
        d0: pc(8),
        d1: pc(9),
        d2: pc(10),
        d3: pc(11),
        cmd: pd(2),
        ck: pc(12),
        // Moved off the mk3 pin: PA9 is USART1 TX (the REPL) on this board, so the
        // inherited value named a line that does something else entirely.
        // Source: gpio-peripherals.md §Mk4 [C]
        card_detect: Some(pc(13)),
        // `SD_DETECT` pulled up, **card present = reads 1** -- the same sense as mk3.
        // Source: gpio-peripherals.md §SDMMC1 "Card-detect" [C]
        card_present_high: true,
        active: Some(pc(7)),
        mux: None,
        slot_b: None,
    },
    // No SPI-NOR: SPI2 is commented out of the board file as "removed in Mk4 rev B".
    // Settings live in internal flash and upgrade staging is in PSRAM.
    // Source: gpio-peripherals.md §Mk4 [C]
    sflash: None,
    usb: UsbPins {
        dm: pa(11),
        dp: pa(12),
    },
    // `USB_ACTIVE=PC6`, mk4 rev B and later. Source: usb.md §"USB activity LED" [C]
    usb_active: Some(pc(6)),
    pwr_btn: None,
    qr: None,
    battery: None,
    // Armed at boot: watched working on this board (and on the mk5, which inherits this).
    // Proven by use, as on the Q1: stack buffers at the top of SRAM1 are accepted.
    gate_buf_len: 192 * 1024,
    keypad_edge_at_boot: true,
    // The LittleFS region above the firmware. Source: platform.md §2 [C]
    settings: SettingsArea::InternalFlash {
        start: 0x0818_0000,
        len: 512 * 1024,
    },
    gpu_reset: None,
    // Callgate 26 reaches SE1 authenticated; the bus is left to the bootloader.
    se1_swi: None,
    has_se2: true,
    // I2C2. The contradiction this used to record -- SE2 on PB13/PB14 versus an
    // inherited mk3 numpad claiming the same pins -- resolved in SE2's favour: the
    // numpad map above was the wrong half.
    // Source: gpio-peripherals.md §Mk4 [C]
    se2: Some(Se2Pins {
        scl: pb(13),
        sda: pb(14),
    }),
    // ST25DV on I2C1, with its event line on PC4 (Q1 puts that on PD6 instead).
    // Source: gpio-peripherals.md §Mk4 [C]
    nfc: Some(NfcPins {
        ed: pc(4),
        scl: pb(6),
        sda: Some(pb(7)),
    }),
    // 8 MB on OCTOSPI1, memory-mapped. Source: gpio-peripherals.md §Mk4 [C]
    psram: Some(Psram {
        base: 0x9000_0000,
        len: 8 * 1024 * 1024,
        ospi_hz: 60_000_000,
        mmap_timeout_clocks: 16,
        staging_header: 0x907F_F800,
    }),
    has_callgate_se_rng: true,
};

// ---------------------------------------------------------------------------
// mk5 — an mk4 board revision, with its own compatibility bit
// ---------------------------------------------------------------------------

/// mk5: electrically an mk4, and deliberately **not** an alias for it.
///
/// The reference calls mk5 "a board rev" sharing mk4's board definition, differing only
/// by `STRAP_MK5` (`PE0`, pulled low). Every pin, the MCU, PSRAM, both secure elements
/// and the firmware base are mk4's, so this borrows them rather than restating them --
/// a second copy would be two places to fix a pin.
///
/// What it must not borrow is `hw_compat`. `MK_5_OK` is `0x20`, its own bit, and an
/// image built with mk4's `0x08` is refused by an mk5 bootloader and vice versa. That
/// separation is the whole reason this is a board and not a feature flag on mk4.
///
/// `V12EN=PC1` exists on this board and not on mk4 (relayed from the maintainer). Its
/// purpose is not documented and nothing here drives it — see
/// `docs/HARDWARE-OPEN-ITEMS.md`.
///
/// Source: generations-mk2-q-mk5.md §Mk4/Mk5 [C], firmware-signing.md §1 [C]
pub const MK5: BoardSpec = BoardSpec {
    name: "mk5",
    hw_compat_bit: 0x20, // MK_5_OK
    ..MK4
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
    // MK_Q1_OK. An earlier revision of the reference gave 0x10 as MK_5_OK, and this
    // board previously set 0x08|0x10 reasoning "mk4 or mk5" — which claimed Q1
    // compatibility by accident and mk4 compatibility wrongly.
    // Source: firmware-signing.md §1 [C]
    hw_compat_bit: 0x10,
    display: Display::St77xx {
        // ST7789, 320x240. Source: display.md §Q1 [C]
        width: 320,
        height: 240,
        spi: Q1_DISPLAY_SPI,
        reset: pa(6),
        dc: pa(8),
        cs: pa(4),
        tear: Some(pb(11)),
        // `BL_ENABLE`. Source: gpio-peripherals.md §Q/Q1 LCD [C]
        backlight: Some(pe(3)),
        // `G_CTRL` (open-drain, pull-up) and `G_BUSY` (input, pull-down): the GPU
        // co-processor shares SPI1, and the bootloader leaves it in reset with `G_CTRL`
        // high, so taking the bus should find it already free.
        // Source: gpio-peripherals.md §GPU co-processor [C]
        bus_grant: Some((pe(5), pe(2))),
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
    // Not `MK4.sdmmc` wholesale: Q1 has two slots on one controller, and PC13 -- mk4's
    // card-detect -- is `SD_MUX` here, the line that selects between them. The bus pins
    // and the first activity LED are mk4's.
    // Source: gpio-peripherals.md §SDMMC1 [C] (bus pins identical to mk4; Q1 detect,
    // polarity and mux), §Q/Q1 Power/battery [C] (pin names)
    sdmmc: SdmmcPins {
        // `SD_DETECT`, slot A (top), pulled up.
        card_detect: Some(pd(3)),
        // **Card present = reads 0** on Q1 -- the opposite of mk3 and mk4.
        card_present_high: false,
        // `SD_MUX`: 0 = slot A (top), 1 = slot B (bottom).
        mux: Some(pc(13)),
        // `SD_DETECT2` / `SD_ACTIVE2`.
        slot_b: Some(SdSlot {
            card_detect: pd(4),
            active: pd(0),
        }),
        ..MK4.sdmmc
    },
    sflash: MK4.sflash, // none, as mk4
    usb: MK4.usb,
    // The same `PC6` as mk4. Source: usb.md §"USB activity LED" [C]
    usb_active: MK4.usb_active,
    // `PWR_BTN`: the only board that truly powers off. Source: power.md [C]
    pwr_btn: Some(pb(12)),
    // The only board with a scanner. Source: hw-reference/gpio.md §Q1 [C]
    qr: Some(QrScanner {
        tx: pa(2),
        rx: pa(3),
        reset: pe(0),
        trigger: pe(1),
    }),
    // The only board with a battery. `NOT_BATTERY` is active-low (high = external/USB),
    // and `REV_D` picks which pin carries it.
    // Source: power.md §"Battery & power pins" [C]
    battery: Some(BatterySense {
        not_battery: pe(7),
        not_battery_old: pc(1),
        rev_d: pc(3),
        vin_sense: pa(1),
    }),
    // Armed at boot: watched working on this board -- the latch fills on every press
    // and the boot survives with every line otherwise closed.
    // Proven by use: every gate call this firmware makes on a Q1 passes a buffer on the
    // stack, at the top of SRAM1, and is answered.
    gate_buf_len: 192 * 1024,
    keypad_edge_at_boot: true,
    settings: SettingsArea::InternalFlash {
        start: 0x0818_0000,
        len: 512 * 1024,
    },
    gpu_reset: Some(pe(6)),
    // Callgate 26 reaches SE1 authenticated; the bus is left to the bootloader.
    se1_swi: None,
    has_se2: true,
    // Source: generations-mk2-q-mk5.md §Q [C]
    se2: Some(Se2Pins {
        scl: pb(13),
        sda: pb(14),
    }),
    // Source: generations-mk2-q-mk5.md §Q [C] for ED/SCL; SDA from the I2C1 bus
    // summary in gpio-peripherals.md [C]
    nfc: Some(NfcPins {
        ed: pd(6),
        scl: pb(6),
        sda: Some(pb(7)),
    }),
    // 8 MB on OCTOSPI1, memory-mapped. Source: gpio-peripherals.md §Mk4 [C]
    psram: Some(Psram {
        base: 0x9000_0000,
        len: 8 * 1024 * 1024,
        ospi_hz: 60_000_000,
        mmap_timeout_clocks: 16,
        staging_header: 0x907F_F800,
    }),
    has_callgate_se_rng: true,
};

/// Every board, for host tools that must handle all of them.
pub const ALL: &[BoardSpec] = &[MK3, MK4, MK5, Q1];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{FW_HEADER_OFFSET, fixed};

    /// What a holder is handed stops short of the bootloader's recovery header.
    ///
    /// PSRAM is claimed whole, so nothing inside it is protected from its holder by
    /// address -- except those last two kilobytes, which are read by the bootloader
    /// before this firmware runs and are the one part no holder may have.
    #[test]
    fn the_usable_region_stops_short_of_the_recovery_header() {
        for board in ALL {
            let Some(psram) = board.psram else { continue };
            assert!(
                psram.staging_header < psram.end(),
                "{}: the header is off the end of the chip",
                board.name
            );
            assert_eq!(
                psram.base + psram.usable(),
                psram.staging_header,
                "{}: usable region does not end at the header",
                board.name
            );
            assert!(
                psram.image_base() < psram.staging_header,
                "{}: no room between a staged image and the header describing it",
                board.name
            );
        }
    }

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
            // MK_1..MK_4, MK_Q1 (0x10), MK_5 (0x20).
            assert_eq!(b.hw_compat_bit & !0x3f, 0, "{}", b.name);
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
            if let Display::St77xx {
                backlight,
                bus_grant,
                ..
            } = b.display
            {
                if let Some(p) = backlight {
                    claim(p, "display backlight", b.name);
                }
                if let Some((request, busy)) = bus_grant {
                    claim(request, "display bus request", b.name);
                    claim(busy, "display bus busy", b.name);
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
                (b.usb.dm, "USB DM"),
                (b.usb.dp, "USB DP"),
            ] {
                claim(p, what, b.name);
            }
            // The detect, activity and mux lines too: PC13 is mk4's card-detect and Q1's
            // slot mux, which is exactly the kind of reuse this test exists to catch.
            if let Some(p) = b.sdmmc.card_detect {
                claim(p, "SD detect", b.name);
            }
            if let Some(p) = b.sdmmc.active {
                claim(p, "SD active", b.name);
            }
            if let Some(p) = b.sdmmc.mux {
                claim(p, "SD mux", b.name);
            }
            // PC6 sits next to the SD activity LED on PC7, so a transposed digit here
            // would drive the card light on every USB packet -- which is exactly the
            // kind of quiet wrong-pin mistake this test exists to catch.
            if let Some(p) = b.usb_active {
                claim(p, "USB active LED", b.name);
            }
            // PB12 sits beside SE2's PB13/PB14, and this board already recorded one
            // wrong-half contradiction between the numpad map and the SE2 bus -- both of
            // which are claimed above, so this line is what checks the button against
            // them.
            if let Some(p) = b.pwr_btn {
                claim(p, "power button", b.name);
            }
            if let Some(p) = b.se1_swi {
                claim(p, "SE1 single-wire bus", b.name);
            }
            if let Some(p) = b.gpu_reset {
                claim(p, "GPU reset", b.name);
            }
            if let Some(s) = b.sdmmc.slot_b {
                claim(s.card_detect, "SD slot B detect", b.name);
                claim(s.active, "SD slot B active", b.name);
            }
            if let Some(sf) = b.sflash {
                claim(sf.spi.sck, "SPI-NOR SCK", b.name);
                claim(sf.spi.mosi, "SPI-NOR MOSI", b.name);
                if let Some(p) = sf.spi.miso {
                    claim(p, "SPI-NOR MISO", b.name);
                }
                // The software CS too: PB9 is SPI2's NSS pin driven as a plain GPIO, so a
                // future reuse of it would be exactly the collision this test catches.
                if let Some(p) = sf.cs {
                    claim(p, "SPI-NOR CS", b.name);
                }
            }
        }
    }

    fn at(p: Pin) -> (char, u8) {
        (p.port.letter(), p.num)
    }

    /// Q1's detect lines read **low** for a card, and PC13 selects a slot rather than
    /// detecting one. Assuming mk3's sense reports a Q1 card missing and an empty slot full.
    /// Source: gpio-peripherals.md §SDMMC1 "Card-detect -- polarity differs" [C]
    #[test]
    fn q1_card_detect_is_active_low_behind_a_two_slot_mux() {
        let s = Q1.sdmmc;
        assert!(!s.card_present_high);
        assert_eq!(s.card_detect.map(at), Some(('D', 3)));
        assert_eq!(s.mux.map(at), Some(('C', 13)));
        let b = s.slot_b.expect("Q1 has a second slot");
        assert_eq!(at(b.card_detect), ('D', 4));
        assert_eq!(at(b.active), ('D', 0));
        assert_eq!(s.active.map(at), Some(('C', 7)));
    }

    /// Source: gpio-peripherals.md §Mk3 (`SD_SW`) and §SDMMC1 (mk4 `SD_DETECT`) [C]
    #[test]
    fn single_slot_boards_read_high_for_a_card_and_have_no_mux() {
        for b in [MK3, MK4, MK5] {
            assert!(b.sdmmc.card_present_high, "{}", b.name);
            assert!(b.sdmmc.mux.is_none(), "{}", b.name);
            assert!(b.sdmmc.slot_b.is_none(), "{}", b.name);
        }
    }
}
