//! The bar says what it is given, and stays inside the rows it was given.

use super::*;
use crate::canvas::Gray320x240;
use crate::font::peep7x14::FONT;

fn bar(status: &Status) -> Gray320x240 {
    let mut canvas = Gray320x240::new();
    render(&mut canvas, &FONT, status);
    canvas
}

/// Total ink in a row band, as a stand-in for "something is drawn here".
fn ink_in(canvas: &Gray320x240, x0: usize, x1: usize, y0: usize, y1: usize) -> u32 {
    let mut sum = 0u32;
    for y in y0..y1 {
        for x in x0..x1 {
            sum += canvas.get(x, y) as u32;
        }
    }
    sum
}

/// The whole point: a held modifier is brighter than one that is not.
///
/// A passphrase typed with SHIFT held is a different passphrase, opening a different and
/// empty wallet with nothing to say so. This indicator is the only warning there is.
#[test]
fn a_held_modifier_is_brighter_than_one_that_is_not() {
    let h = height(&FONT);
    let up = bar(&Status::default());
    let down = bar(&Status {
        shift: true,
        ..Status::default()
    });

    // "SHIFT" is the first word, in the left margin.
    let quiet = ink_in(&up, 0, 40, 0, h);
    let loud = ink_in(&down, 0, 40, 0, h);
    assert!(quiet > 0, "an inactive modifier should still be legible");
    assert!(
        loud > quiet,
        "holding SHIFT did not brighten it: {quiet} -> {loud}"
    );
}

/// Each indicator responds to its own flag and not to another's.
#[test]
fn each_indicator_answers_only_to_its_own_state() {
    let h = height(&FONT);
    let base = bar(&Status::default());
    for (label, set) in [
        (
            "sym",
            Status {
                symbol: true,
                ..Status::default()
            },
        ),
        (
            "caps",
            Status {
                caps: true,
                ..Status::default()
            },
        ),
        (
            "passphrase",
            Status {
                passphrase: true,
                ..Status::default()
            },
        ),
    ] {
        let lit = bar(&set);
        let before = ink_in(&base, 0, 200, 0, h);
        let after = ink_in(&lit, 0, 200, 0, h);
        assert!(after > before, "{label} did not light up");
    }
}

/// The fingerprint is shown as the hex every other wallet names the wallet by.
#[test]
fn the_fingerprint_is_drawn_as_upper_case_hex() {
    let mut out = [0u8; 8];
    hex([0x59, 0xDA, 0x84, 0xB8], &mut out);
    assert_eq!(&out, b"59DA84B8");

    // And it reaches the panel, on the right-hand side.
    let h = height(&FONT);
    let with = bar(&Status {
        fingerprint: Some([0x59, 0xDA, 0x84, 0xB8]),
        ..Status::default()
    });
    let without = bar(&Status::default());
    assert!(
        ink_in(&with, 200, 320, 0, h) > ink_in(&without, 200, 320, 0, h),
        "the fingerprint did not appear on the right"
    );
}

/// A wallet this session has not unlocked shows no fingerprint, rather than a wrong one.
///
/// The bar is painted every frame, so it must never be what causes a seed to be
/// stretched. Empty is the honest answer until something else has paid for it.
#[test]
fn an_unknown_fingerprint_leaves_the_space_empty() {
    let h = height(&FONT);
    let none = bar(&Status::default());
    // Only the bottom rule should be lit out at the right, past the power icon's slot.
    let rule = ink_in(&none, 200, 320, h - 1, h);
    assert_eq!(
        ink_in(&none, 200, 320, 0, h - 1),
        0,
        "something was drawn where the fingerprint goes"
    );
    assert!(rule > 0, "the bottom rule is missing");
}

/// The two power states draw different icons, and neither draws when there is no battery.
#[test]
fn the_power_icon_follows_the_source() {
    let h = height(&FONT);
    let band = |c: &Gray320x240| ink_in(c, 290, 320, 0, h - 1);

    let none = bar(&Status::default());
    let plugged = bar(&Status {
        power: Some(Power::External),
        ..Status::default()
    });
    let battery = bar(&Status {
        power: Some(Power::Battery),
        ..Status::default()
    });

    assert_eq!(band(&none), 0, "a board with no battery drew an icon");
    assert!(band(&plugged) > 0, "no plug icon");
    assert!(band(&battery) > 0, "no battery icon");
    assert_ne!(
        band(&plugged),
        band(&battery),
        "the two power states look the same"
    );
}

/// Nothing the bar draws may land below its own height.
///
/// The rows underneath belong to whatever screen is up. A bar that overran would paint
/// over the first line of a transaction's destinations, which is the one place on this
/// device where a covered character matters most.
#[test]
fn the_bar_stays_within_its_own_rows() {
    let canvas = bar(&Status {
        shift: true,
        symbol: true,
        caps: true,
        passphrase: true,
        fingerprint: Some([0xFF; 4]),
        power: Some(Power::Battery),
    });
    let h = height(&FONT);
    assert_eq!(
        ink_in(&canvas, 0, 320, h, 240),
        0,
        "the bar drew below its own height"
    );
}

/// A full bar still fits: the left group must not run into the fingerprint.
#[test]
fn the_two_groups_do_not_collide() {
    let canvas = bar(&Status {
        shift: true,
        symbol: true,
        caps: true,
        passphrase: true,
        fingerprint: Some([0x59, 0xDA, 0x84, 0xB8]),
        power: Some(Power::External),
    });
    let h = height(&FONT);
    // The left group ends with PASSPHRASE; the fingerprint starts right of the gap. A
    // blank column between them proves they are not overlapping.
    let gap = (150..190).any(|x| ink_in(&canvas, x, x + 1, 0, h - 1) == 0);
    assert!(gap, "no clear column between the two groups");
}

/// The firmware's reserved-row count has to match what this actually draws.
///
/// `catcard_fw::display::BAR_H` must be a constant -- the panel's usable height is
/// derived from it and every screen lays itself out against that -- so it cannot call
/// [`height`]. This is the other end of that: change the face and this fails, naming the
/// constant to change with it. Without it the bar would quietly overlap the first line of
/// whatever screen is up, or leave a dead strip below itself.
#[test]
fn the_bar_is_the_height_the_firmware_reserves_for_it() {
    const FW_BAR_H: usize = 17;
    assert_eq!(
        height(&FONT),
        FW_BAR_H,
        "catcard-fw's display::BAR_H must change to match"
    );
}
