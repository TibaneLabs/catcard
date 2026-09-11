# Hardware open items

Everything the implementation needs that `hw-reference` marks `[?]`, could not answer,
or answers ambiguously. Each entry says what is blocked and how to resolve it.

Ordered by how much they block. **Nothing here currently blocks wallet functionality** —
the callgate entry address, which did, is resolved.

---

## mk4 SE2 bus pins vs. the inherited numpad map — RESOLVED

The numpad map was the wrong half, exactly as this entry predicted. `gpio-peripherals.md
§Mk4` now states it outright: mk4 keeps the 4x3 layout but **not the mk3 pins** — cols
`M2_COL0..2 = PB0, PB1, PB2`, rows `M2_ROW0..3 = PD8, PD9, PD10, PD11` `[C]`, and it
flags the "same as mk3" reading as an error in an earlier revision of the reference. That
frees PB13/PB14, so `SE2_SCL=PB13`, `SE2_SDA=PB14` on I2C2 is no longer in contention and
`MK4.se2` is filled in `[C]`.

Worth recording how it surfaced, because it is the argument for keeping a keypad echo on
the selftest screen: under the emulator no keypress reached the firmware at all. The
symptom was a device that looked hung on a screen that was in fact polling a set of pins
nothing was attached to.

## Which physical key sits at which matrix position — RESOLVED, on a relayed fact

**The pad is mounted rotated.** Matrix position 0 is `y`, position 11 is `1` — the
printed legend inverted on both axes, the same 180° turn the OLED gets:

```text
legend          matrix sees
1 2 3           y 0 x
4 5 6           9 8 7
7 8 9           6 5 4
x 0 y           3 2 1
```

`catcard_ui::keypad::LAYOUT` was row-major until this was settled, which would have
mirrored the whole pad: every digit of a PIN landing on a different key, and `x` and `y`
swapped, so a user could not confirm anything.

**How it was settled, and why the provenance is written down.** It was *measured* first
— driving single keys under the emulator and echoing the decoded key back showed an
exact reversal, position *i* there being *11 − i* here, consistently. That measurement
alone could not settle it: `VALIDATION.md` says an emulator run does not settle anything
the reference marks `[I]`, and `gpio-peripherals.md` gives the pins and the scan model
but never says which key sits where.

It was settled by asking. The emulator's maintainer confirmed the mounting, sourced from
**the stock firmware's own decoder table for the membrane numpad** — a twelve-character
string indexed `row * 3 + col`.

That source matters. `CLEANROOM.md` keeps stock firmware out of this project, and the
answer arrived as a relayed fact rather than through reading it. Two things make it
usable:

- **It is a fact about where the panel sits in the case**, not about anybody's code. A
  clean-room implementation may know that a connector is rotated; what it may not do is
  copy an expression of it.
- **Nothing was transcribed.** The table is not reproduced here or in the code; the
  mounting is stated and `LAYOUT` derives from it in our own terms.

**Still worth a bench.** The relayed fact is tagged `[C]` on the emulator's side because
shipped firmware decodes real pads with that table and real pads work — which is a
firmware fact, not a measurement of silicon, and neither project has checked it on a
device. The `KEY` echo on the selftest screen settles it in seconds, and a disagreement
there beats the table.

---

## Callgate entry address — RESOLVED

Kept as a note because it was the project's blocking unknown and the resolution is
worth stating: the address is **published by the bootloader**, not fixed, in a table at
`0x0800_0040` (`{callgate_entry, version_number, reserved[4]}`).

Read it and validate it; never hardcode. mk3 yields `0x0800_0305`
(firewall base `0x0800_0300` + 4 for the call gate + 1 for Thumb) but mk4 and Q differ,
which is exactly why the table exists.

Implemented in `catcard_callgate::entry`. Remaining `[?]` in this area:

- Exact byte layout and CRC of the `gate 26` return across mk4/Q/Mk5.
- Any callgate methods added after v5.0.3 beyond #26. The table's `version_number`
  (BCD) is the intended way to detect these — we read it but do not yet gate on it.

---

## SRAM2 / SRAM3 sizes

**Blocks: using more than SRAM1.** Currently the linker is given SRAM1 only — 256 KB on
mk3, 192 KB on mk4/Q. That is plenty for now.

`hw-reference/platform.md §2` gives SRAM2 as 32 KB on the L496; the ST datasheet for
that part gives 64 KB (256 KB SRAM1 + 64 KB SRAM2 = the documented 320 KB total). The
32 KB figure matches the STM32L475/L476, which is what the stock build targets for its
CMSIS headers even though the die is an L496 — so the reference has likely inherited the
wrong number.

The bootloader reserves `0x1000_6000 .. 0x1000_7C00` (7 KB) in the SRAM2 alias window
either way, and that region is excluded from our linker script already.

**How to resolve.** Read the datasheet for the exact part marking, then confirm by
writing and reading back the top of each bank on hardware.

---

## SPI-NOR chip select and SCK

**Blocks: settings storage and PSBT scratch — on mk3 only.**

Narrower than it was. `gpio-peripherals.md §Mk4` confirms there is **no SPI-NOR from mk4
onward**: SPI2 is commented out of the board file as "removed in Mk4 rev B", settings
moved to internal flash and upgrade staging moved to PSRAM. So this blocks nothing on
mk4 or Q1, and `MK4.sflash` / `Q1.sflash` are `None` rather than an inherited guess.

`hw-reference/gpio-peripherals.md` confirms SPI2 MISO=PC2 and MOSI=PC3 but not SCK or
CS. PB12/PB13, the usual SPI2 NSS/SCK pins, are taken by numpad rows on this board,
which leaves:

- SCK: PB10 or PD1 (PD1 is recorded as the working candidate)
- CS: PB9 or PD0

Also unconfirmed: the NOR part number and total size. The reference says ≥1 MB usable
with settings occupying 896 KB–1 MB, and guesses 2 MB+.

**How to resolve.** Probe the board, or read the JEDEC ID (`RDID`, opcode `0x9F`) once
any candidate SCK/CS pairing produces a response.

**Where it goes:** `SflashPins` in `crates/catcard-board/src/spec.rs`;
`SpiBus::pins_confirmed` flips to `true`.

---

## MSI range, and therefore the PLL configuration

**Blocks: running faster than the reset default.** The core currently runs on the
reset-default MSI clock. Everything works; it is just slow.

`hw-reference/platform.md §1` records the divisors `N=40, M=2, R=2, P=7, Q=4` sourced
from MSI, but not the MSI range. `SYSCLK = MSI / M * N / R` gives **40 MHz at MSI=4 MHz**
and **80 MHz at MSI=8 MHz**. Programming the PLL on the wrong assumption either
underclocks the device or overclocks it past its voltage-scaling limit.

Note the RNG does **not** depend on this: `catcard-hal::clock::enable_hsi48` routes the
independent HSI48 oscillator to the 48 MHz peripheral clock, which is correct on every
generation.

**How to resolve.** Read `RCC_CR.MSIRANGE` on a running device, or measure SYSCLK on the
MCO pin.

**Where it goes:** `crates/catcard-hal/src/clock.rs`, `PLL_DIVISORS` and a new
`init_pll`.

---

## Flash page size and bank configuration

**Blocks: writing to main flash from the firmware** (not needed for the bootloader-driven
upgrade path, which erases on our behalf).

- STM32L4 (L496): 2 KB pages.
- STM32L4+ (L4S5): 8 KB pages single-bank, 4 KB dual-bank — set by the `DBANK` option
  bit, which we cannot know without reading it.

`MemoryMap::flash_page_len` currently assumes the larger (safer) 8 KB on L4S5.

**How to resolve.** Read the option bytes at `0x1FFF_7800`.

---

## Firmware staging base — RESOLVED on mk4 and Q1, still open on mk3

**mk4 / Q1 `[C]`.** PSRAM is an 8 MB part on OCTOSPI1, memory-mapped at `0x9000_0000`,
and the bootloader reads a firmware-staging recovery header at `0x907F_F800` — magics
`0xDBCC_8350` and `0xBAFC_FBA3`, both of which must match or it ignores the region
entirely. That "both magics or nothing" rule is what makes the mechanism safe to use:
an unwritten or half-written header stages nothing rather than staging garbage. Recorded
as [`Psram`](../crates/catcard-board/src/spec.rs) in the board table.

**mk3 `[?]`, and still blocking self-upgrade there.**
`install-and-usb-transport.md §2` says the pending image is staged at SPI-NOR **offset
0**, sourced from a comment that the entire flash "starting at zero may be used" — which
is weaker than a confirmation that the bootloader reads from exactly 0, and it says any
header or marker expected there is unconfirmed. mk3 also still lacks its SPI-NOR CS/SCK
pins, so nothing can be staged on it regardless.

Getting this wrong means a reboot into a bootloader that installs garbage.

**How to resolve.** Confirm on mk3 hardware before the first self-upgrade attempt, by
staging an image and observing what the bootloader installs. Test on a unit you are
willing to recover over DFU.

---

## `install_flags` bits

Only `HIGH_WATER` (`0x01`) is documented, and even that is inferred from behaviour
rather than a bit definition. All other bits must be left clear.

`catcard-image` sets only `HIGH_WATER`, and only when `--high-water` is passed. That
flag is irreversible on the device and is off by default.

---

## Q1 display controller and resolution

**Blocks: any Q1 UI.** `hw-reference` gives the pins (CS=PA4, SCLK=PA5, RESET=PA6,
MOSI=PA7, D/C=PA8, TEAR=PB11) and guesses an ST77xx-class controller at ~320×240. The
board spec records 320×240 as a placeholder.

**How to resolve.** Read the controller ID command response, or read the part marking.

---

## Q1 QR camera bus

**Blocks: QR scanning.** The camera interface (SPI / DCMI / UART) is not identified.

The keyboard is resolved: a 10x6 matrix, rows PD8–PD12 + PD7, cols PB0/PB1/PB2/PB5/
PB8/PB9/PB10/PD13/PD14/PD15 `[C]`. The scan *detail* — settling time, debounce, ghosting
handling for multi-key rollover — is still `[?]` and will come out of bring-up.

---

## microSD card-detect polarity

`SD_SW=PA9` is marked `[?]` in the reference, and its active polarity is not stated.
Recorded as `card_detect: Some(pa(9))` but not relied upon.

---

## Secret encoding within the `0x80+` BIP-39 marker range

`hw-reference` says the secret blob's marker is `0x01` for xprv and `0x80`+ for BIP-39
words, but not how word count is encoded in the low bits.

**Blocks: decoding a seed created by stock firmware.** Not needed to create our own,
since CatCard chooses its own encoding for secrets it writes — but needed for any
migration path.

`catcard_callgate::pin::classify_secret` returns the raw marker rather than guessing.

---

## SE1 single-wire UART pin; SE2 I²C addresses

Not needed while all secret operations go through the callgate, which is the design.
Would only matter for direct non-secret SE access (config zone reads, `Random`).

`se1-driver-spec.md` now gives the full SE1 transport — SWI-over-UART at 230400 bps,
`0x7d`/`0x7f` bit encoding, the Microchip CRC-16, frame layout and per-opcode delays —
so a direct driver is writable. The UART instance is UART4 on mk3 `[C]`, unconfirmed on
mk4/Q `[?]`. SE2's I2C pins are confirmed on Q1 only; see the mk4 item above.
