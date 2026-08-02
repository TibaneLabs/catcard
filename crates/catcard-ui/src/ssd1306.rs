//! SSD1306 command set and init sequence.
//!
//! Standard controller commands from the Solomon Systech SSD1306 datasheet (rev 1.1),
//! §9 "Command Table". Nothing here is Coldcard-specific; the board only decides which
//! pins carry SPI, RESET, D/C and CS — see `catcard_board::Display`.

/// Command bytes. Names follow the datasheet.
pub mod cmd {
    pub const SET_CONTRAST: u8 = 0x81;
    pub const DISPLAY_ALL_ON_RESUME: u8 = 0xA4;
    pub const DISPLAY_ALL_ON: u8 = 0xA5;
    pub const NORMAL_DISPLAY: u8 = 0xA6;
    pub const INVERT_DISPLAY: u8 = 0xA7;
    pub const DISPLAY_OFF: u8 = 0xAE;
    pub const DISPLAY_ON: u8 = 0xAF;
    pub const SET_DISPLAY_OFFSET: u8 = 0xD3;
    pub const SET_COM_PINS: u8 = 0xDA;
    pub const SET_VCOM_DETECT: u8 = 0xDB;
    pub const SET_DISPLAY_CLOCK_DIV: u8 = 0xD5;
    pub const SET_PRECHARGE: u8 = 0xD9;
    pub const SET_MULTIPLEX: u8 = 0xA8;
    pub const SET_START_LINE: u8 = 0x40;
    pub const MEMORY_MODE: u8 = 0x20;
    pub const COLUMN_ADDR: u8 = 0x21;
    pub const PAGE_ADDR: u8 = 0x22;
    pub const COM_SCAN_INC: u8 = 0xC0;
    pub const COM_SCAN_DEC: u8 = 0xC8;
    pub const SEG_REMAP: u8 = 0xA0;
    pub const CHARGE_PUMP: u8 = 0x8D;
}

/// Horizontal addressing mode: the column pointer auto-advances and wraps to the next
/// page, which makes a whole-framebuffer flush a single contiguous data write.
pub const MEMORY_MODE_HORIZONTAL: u8 = 0x00;

/// Enable the internal charge pump. Required on boards with no external 7.5 V rail;
/// without it the panel stays dark even though every command is accepted.
pub const CHARGE_PUMP_ON: u8 = 0x14;

/// Init sequence for a 128x64 panel.
///
/// Written as data rather than a sequence of driver calls so it can be reviewed
/// against the datasheet line by line, and unit-tested without hardware.
// `| 0x00` operands are kept so each entry reads as "command | parameter", matching
// how the datasheet presents the packed-argument commands.
#[allow(clippy::identity_op)]
pub const INIT_128X64: &[u8] = &[
    cmd::DISPLAY_OFF,
    cmd::SET_DISPLAY_CLOCK_DIV,
    0x80, // ratio 1, oscillator frequency 8
    cmd::SET_MULTIPLEX,
    63, // 64 rows - 1
    cmd::SET_DISPLAY_OFFSET,
    0x00,
    cmd::SET_START_LINE | 0x00,
    cmd::CHARGE_PUMP,
    CHARGE_PUMP_ON,
    cmd::MEMORY_MODE,
    MEMORY_MODE_HORIZONTAL,
    // Both remaps set: the panel is mounted rotated 180 degrees relative to the
    // controller's default scan order.
    cmd::SEG_REMAP | 0x01,
    cmd::COM_SCAN_DEC,
    cmd::SET_COM_PINS,
    0x12, // alternative COM pin config, no left/right remap -- correct for 128x64
    cmd::SET_CONTRAST,
    0x7F,
    cmd::SET_PRECHARGE,
    0xF1,
    cmd::SET_VCOM_DETECT,
    0x40,
    cmd::DISPLAY_ALL_ON_RESUME,
    cmd::NORMAL_DISPLAY,
    cmd::DISPLAY_ON,
];

/// Commands that set the column/page window to the whole panel, ahead of a full flush.
pub fn full_window(width: u8, pages: u8) -> [u8; 6] {
    [cmd::COLUMN_ADDR, 0, width - 1, cmd::PAGE_ADDR, 0, pages - 1]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_sequence_turns_the_panel_on_last() {
        assert_eq!(INIT_128X64[0], cmd::DISPLAY_OFF);
        assert_eq!(*INIT_128X64.last().unwrap(), cmd::DISPLAY_ON);
    }

    #[test]
    fn init_sequence_enables_the_charge_pump() {
        // The single most common reason an SSD1306 stays dark.
        let at = INIT_128X64
            .iter()
            .position(|&b| b == cmd::CHARGE_PUMP)
            .expect("charge pump command missing");
        assert_eq!(INIT_128X64[at + 1], CHARGE_PUMP_ON);
    }

    #[test]
    fn multiplex_ratio_matches_a_64_row_panel() {
        let at = INIT_128X64
            .iter()
            .position(|&b| b == cmd::SET_MULTIPLEX)
            .unwrap();
        assert_eq!(INIT_128X64[at + 1], 63);
    }

    #[test]
    fn full_window_covers_the_whole_panel() {
        assert_eq!(
            full_window(128, 8),
            [cmd::COLUMN_ADDR, 0, 127, cmd::PAGE_ADDR, 0, 7]
        );
    }
}
