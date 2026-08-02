//! Flash / RAM layout per board, and the fixed addresses shared by the whole family.
//!
//! Sources: `hw-reference/platform.md §2`, `hw-reference/firmware-signing.md §1`,
//! plus ST RM0351 (STM32L4) and RM0432 (STM32L4+) for the register-block addresses.

/// Addresses identical across every Coldcard generation (they are STM32L4-family
/// constants, not board choices).
pub mod fixed {
    /// Start of main flash. The bootloader lives here and is unreplaceable at RDP=2.
    /// Source: platform.md §2 [C]
    pub const FLASH_BASE: u32 = 0x0800_0000;

    /// 96-bit factory unique ID. **Public** — it is exposed as the USB serial number,
    /// and on STM32L4 word 0 encodes wafer X/Y die coordinates. Never treat as entropy.
    /// Source: platform.md §2, §3 [C]
    pub const UNIQUE_ID: u32 = 0x1FFF_7590;
    pub const UNIQUE_ID_LEN: usize = 12;

    /// One-time-programmable area (1 KB). The bootloader keeps the anti-downgrade
    /// high-water mark here. Source: platform.md §2 [C]
    pub const OTP_BASE: u32 = 0x1FFF_7000;
    pub const OTP_LEN: u32 = 0x400;

    /// ST factory DFU bootloader in system ROM. Reachable only on RDP<2 units.
    /// Source: platform.md §2 [C]
    pub const SYSTEM_MEMORY: u32 = 0x1FFF_0000;

    /// Hardware TRNG peripheral. Source: platform.md §2, §3 [C]
    pub const RNG: u32 = 0x5006_0800;
    /// RCC. `AHB2ENR` at +0x4C gates `RNGEN`; `BDCR` +0x90, `CSR` +0x94.
    /// Source: platform.md §2 [C] + RM0351 §6.4
    pub const RCC: u32 = 0x4002_1000;
    /// PWR. `CR1.DBP` unlocks the backup domain. Source: platform.md §2 [C]
    pub const PWR: u32 = 0x4000_7000;
    /// RTC. `TR` +0x00, `SSR` +0x28. Source: platform.md §2 [C]
    pub const RTC: u32 = 0x4000_2800;
    /// GPIO port A; ports are 0x400 apart. Source: RM0351 §2.2.2
    pub const GPIOA: u32 = 0x4800_0000;

    /// Data Watchpoint & Trace cycle counter, used as a jitter source.
    /// Source: platform.md §2 + ARMv7-M ARM C1.8
    pub const DWT_CYCCNT: u32 = 0xE000_1004;
    pub const DWT_CTRL: u32 = 0xE000_1000;
    pub const DEMCR: u32 = 0xE000_EDFC;
}

/// Where the 128-byte signed firmware header sits inside the image, relative to the
/// start of the image (= relative to [`MemoryMap::firmware_base`]).
///
/// `0x4000 - 128`. Source: firmware-signing.md §1 [C]
pub const FW_HEADER_OFFSET: u32 = 0x3F80;
pub const FW_HEADER_SIZE: u32 = 128;

/// Flash and RAM layout for one board.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MemoryMap {
    /// `TEXT0_ADDR` — where our signed image is installed and starts executing.
    /// Everything below this belongs to the bootloader.
    pub firmware_base: u32,
    /// Flash available to the firmware image, from `firmware_base`.
    ///
    /// The tail of this region is also where the flash filesystem lives on stock
    /// firmware (it starts at `firmware_length`). We do not reserve for it here —
    /// the header's `firmware_length` field marks the real end of the image.
    pub firmware_flash_len: u32,

    /// Total main flash on the part, for bounds checks.
    pub total_flash_len: u32,
    /// Flash page size, the erase granularity used when staging an upgrade.
    ///
    /// STM32L4 (L496): 2 KB pages. STM32L4+ (L4S5) in single-bank mode: 8 KB pages,
    /// 4 KB in dual-bank. Source: RM0351 §3.3.1 / RM0432 §3.3.1. `[?]` — the actual
    /// bank configuration set by the option bytes must be confirmed on a board.
    pub flash_page_len: u32,

    /// Start of SRAM1. The bootloader callgate requires its `buf_io` argument to live
    /// in SRAM1, so this is the only region we place the callgate buffer in.
    /// Source: bootloader-callgate-abi.md [C]
    pub sram1_base: u32,
    /// Size of SRAM1 only. Deliberately conservative: SRAM2/SRAM3 are contiguous on
    /// these parts but their sizes are `[?]` (see docs/HARDWARE-OPEN-ITEMS.md), so the
    /// linker script is given SRAM1 alone until confirmed on hardware.
    pub sram1_len: u32,

    /// SRAM region the bootloader reserves for itself; must never be linked into.
    /// `BL_SRAM_BASE`/`BL_SRAM_SIZE`. Source: platform.md §2 [C]
    pub bl_sram_base: u32,
    pub bl_sram_len: u32,
}

impl MemoryMap {
    /// Absolute address of the firmware header once installed.
    pub const fn header_addr(&self) -> u32 {
        self.firmware_base + FW_HEADER_OFFSET
    }

    /// Absolute address where `.text` may begin: immediately after the header block.
    pub const fn text_addr(&self) -> u32 {
        self.firmware_base + FW_HEADER_OFFSET + FW_HEADER_SIZE
    }

    /// Bytes of flash the bootloader occupies below us.
    pub const fn bootloader_len(&self) -> u32 {
        self.firmware_base - fixed::FLASH_BASE
    }

    /// End of the RAM region the linker may use (exclusive).
    pub const fn sram1_end(&self) -> u32 {
        self.sram1_base + self.sram1_len
    }
}
