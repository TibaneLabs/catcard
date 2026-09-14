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

**Settled on silicon.** On the first mk4 hardware run the device was unlocked with a PIN
that had been **set by the stock firmware**, typed on CatCard. That is the test the map
cannot fake: stock chose the digits using its own decoder, so a mirrored map here would
have submitted different digits and the gate would have refused. It did not.

Note what would *not* have proved it, since an earlier draft of this file claimed it
would: setting a PIN through CatCard and then logging in with it. Both halves use the
same map, so a mirrored one succeeds at both and agrees with itself.

Confirmed for mk4. mk3 has the same membrane pad and the same decoder, so it is expected
to match, but it is a different board and the `Debug → Keypad` screen settles it in
seconds.

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

## MSI range, and therefore the PLL configuration — narrowed to 8 MHz `[I]`

**Blocks: running faster than the reset default.** The core currently runs on the
reset-default MSI clock. Everything works; it is just slow.

`hw-reference/platform.md §1` records the divisors `N=40, M=2, R=2, P=7, Q=4` sourced
from MSI, but not the MSI range. `SYSCLK = MSI / M * N / R` gives **40 MHz at MSI=4 MHz**
and **80 MHz at MSI=8 MHz**. Programming the PLL on the wrong assumption either
underclocks the device or overclocks it past its voltage-scaling limit.

Two data points now pick the second: `platform.md §1` describes the mk3 part as
"Cortex-M4F @ **~80 MHz**", and `gpio-peripherals.md` records `FLASH_LATENCY_4`, which
on these parts at VOS range 1 is the setting for the top frequency band rather than for
40 MHz. Both are consistent with **MSI = 8 MHz** (`RCC_CR.MSIRANGE = 0b0111`) and
inconsistent with 4 MHz.

That is an inference from two stated facts, not a stated fact, so it stays `[I]` and
nothing is programmed on it yet. It does mean the PLL work is no longer blocked on an
unknown — it is blocked on confirming one candidate.

**Note on the USB idle pause.** `usbtask::IDLE_PAUSE_CYCLES` is a cycle count, and the
device runs at the MSI reset default (4 MHz) rather than the PLL, so it is unaffected by
the above. It becomes wrong the moment the PLL is programmed, and that is the change
that has to revisit it.

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

## Q1 display controller and resolution — RESOLVED, driver not written

**`[C]`.** A Sitronix **ST7789**, **320×240 RGB565**, pixels written byte-swapped;
backlight `BL_ENABLE=PE3`; pins CS=PA4, SCLK=PA5, RESET=PA6, MOSI=PA7, D/C=PA8,
TEAR=PB11 (`hw-reference/display.md §Q1`, `gpio-peripherals.md §Q/Q1`).

The part that bites: **the firmware inherits the bootloader's LCD and must not reset or
re-initialise it.** CatCard used to treat the panel like the SSD1306 — hold `RESET` low,
pulse it, send an OLED init — which on a Q1 blanks a working LCD.

`catcard_ui::st7789` now draws on the inherited setup: it takes SPI1 from the GPU
co-processor (`G_CTRL=PE5` high, wait `G_BUSY=PE2` low, bounded), leaves `RESET` alone,
clears, turns on `BL_ENABLE=PE3`, and draws with only `CASET`/`RASET`/`RAMWR`: screens render
a 16-level 320×240 canvas, and only the rows that changed are sent. The 10×6 keyboard (`catcard_ui::qwerty`) maps the number row,
ENTER, CANCEL, DELETE and the arrows onto the numpad's keys. Any failure bringing either up
leaves the session on the headless recovery path (`recovery.rs`).

**Colour sense and orientation — confirmed by eye on a real Q1 `[C]`** (2026-09-14, the
display/keyboard build installed over USB). Both had been `[I]`, taken from the emulator's
model:

- **Colour sense.** `0x0000` shows black. The bootloader sends `INVON` and the glass is
  natively inverted, so inversion restores the normal sense — the UI comes up white on
  black. Colour is right too: the logo's orange-to-yellow gradient renders as drawn, so
  RGB565 byte order and the palette path are confirmed on the unit.
- **Orientation.** Address column 0 is the left edge as seen: `MADCTL = 0x60` sets `MX`
  and the glass is mirrored to match, so text reads left to right with no column reversal.

The keyboard mapping was exercised on the same unit: the number row, ENTER, DELETE and the
PIN flow behave as the decode table in `gpio-peripherals.md §Q/Q1` says.

The GPU co-MCU shares SPI1: the bootloader leaves it held in reset (`G_RESET=PE6` low)
with `G_CTRL=PE5` high, i.e. the main MCU owns the bus. Nothing in CatCard touches either
pin, which is what keeps that true.

---

## Q1 QR scanner bus — RESOLVED, driver not written

**`[C]`.** Not a camera: a decoded-barcode module on **USART2** (`QR_TX=PA2`,
`QR_RX=PA3`), with `QR_RESET=PE0` (open-drain, active low) and `QR_TRIG=PE1`. It speaks a
framed binary protocol (`5A | fid | len | body | BCC | A5`) at 9600, negotiated up to
57600 (`hw-reference/gpio-peripherals.md §QR scanner`). Blocks QR scanning only.

`PE0` is also the mk5 strap on mk4-class boards. CatCard samples it as a strap only on an
mk4/mk5 build (`running_board`), so a Q1 never reconfigures the scanner's reset line.

The keyboard is resolved: a 10x6 matrix, rows PD8–PD12 + PD7, cols PB0/PB1/PB2/PB5/
PB8/PB9/PB10/PD13/PD14/PD15 `[C]`. The scan *detail* — settling time, debounce, ghosting
handling for multi-key rollover — is still `[?]` and will come out of bring-up.

---

## microSD card-detect — RESOLVED on mk3, pin corrected on mk4

The reference now states both pin and polarity for mk3: `SD_SW=PA9` `[C]`, pulled up,
**card present = pin high**.

It also moves the line on mk4: `SD_DETECT=PC13`. Our mk4 entry had inherited the mk3
`PA9`, which on that board is USART1 TX — the REPL — so it named a pin that does
something else entirely. Corrected in `spec.rs`; Q1 inherits `MK4.sdmmc` and is fixed
with it.

Q1 is not mk4 here and must not inherit it: that board has **two** slots, and PC13 --
mk4's card-detect -- is `SD_MUX`, the line selecting between them. Q1's detect is
`SD_DETECT=PD3`, with `SD_DETECT2=PD4` and `SD_ACTIVE2=PD0` for the second slot. Q1 now
carries its own entry.

**Polarity and mux — RESOLVED `[C]`** (`hw-reference/gpio-peripherals.md §SDMMC1`). Card
present reads **high** on mk3 (`SD_SW=PA9`) and mk4 (`SD_DETECT=PC13`), and **low** on Q1
(`SD_DETECT=PD3` / `SD_DETECT2=PD4`, pulled up). Q1's two slots share SDMMC1 through the
analog mux `SD_MUX=PC13`: **0 selects slot A (top), 1 slot B (bottom)**; activity LEDs
`SD_ACTIVE=PC7` / `SD_ACTIVE2=PD0`. `SdmmcPins` now records `card_present_high`, `mux`
and `slot_b` per board, and `Sdmmc::init_slot` steers the mux before the bus comes up.

Assuming mk3's polarity everywhere, as the driver did, would have reported a Q1 card as
missing and an empty Q1 slot as full.

---

## Secret encoding within the `0x80+` BIP-39 marker range — RESOLVED `[C]`

`hw-reference/secret-stash-format.md §Layout` gives it: the marker is
`0x80 | ((L / 8) - 2)`, where `L` is the length of the stored **entropy** — so `0x80`,
`0x81` and `0x82` mean 16, 24 and 32 bytes, i.e. 12, 18 and 24 words. The entropy is
stored rather than the words or the checksum, and the mnemonic is re-derived from it.

Only those three lengths exist in this format. BIP-39's 20- and 28-byte entropy (15 and
21 words) has no marker, so `encode_bip39` refuses it: truncating a 20-byte seed to 16
would store a *different* wallet behind a marker that reads back as perfectly valid.

`catcard_callgate::pin` now encodes and decodes this — `bip39_marker`, `bip39_len`,
`encode_bip39`, `bip39_entropy` — and `classify_secret` still returns the raw marker, so
a value outside the three known lengths (`0x83` claims 40 bytes) is reported as
unreadable rather than guessed at. CatCard writes the stock layout deliberately; see
`docs/SECRETS-AND-SETTINGS.md`.

---

## `V12EN` (PC1) — now driven on mk5, on one piece of evidence

An mk5 came up with a **dark screen** on firmware that drew correctly on an mk4. The two
boards share every pin we know of except `STRAP_MK5` and `V12EN=PC1`, which is mk5-only.
So PC1 is driven high before the panel is initialised, when the strap says mk5, with a
40 ms settle.

This reverses an argument made earlier in this file and it is worth recording why, since
the reasoning was sound and the conclusion was wrong. The claim was that PC1 could not be
a display rail because an SSD1306 makes its own panel voltage from the charge pump
`ssd1306::init` enables. That holds only for a module that *has* one. A board that
supplies panel voltage itself, through a boost enabled by this pin, fits both the name
and the symptom — and "mk4 has no 12 V rail" was never evidence about mk5, which is
precisely the board that carries the pin.

**Still unconfirmed.** The reference names the pin and says nothing about what it
switches. If an mk5 lights up with this and stays dark without it, that is the
confirmation, and it belongs in `hw-reference`. If it stays dark either way, the fault is
elsewhere and this should come back out rather than linger as a write to an unknown
output.

`USB_ACTIVE=PC6` and the `STRAP_S1/S2/S3` straps are still unmodelled and undriven.

---

## Pins we do not model: `USB_ACTIVE`, `STRAP_S1/S2/S3`

`gpio-peripherals.md` lists three additions we carry no entry for: `V12EN=PC1`,
`USB_ACTIVE=PC6`, and the straps `STRAP_S1/S2/S3 = PE1/PE2/PE3` (the reference marks the
straps' purpose `[?]` and says the firmware does not use them). It gives names and pins
and nothing else.

**`V12EN` is mk5-only and is not on mk4** — relayed from the maintainer, the same class
of fact as the keypad mounting above. It reads as an mk4 pin only because that section
is headed *"Mk4 / Mk5 — deltas from mk3"* and treats the two as one board; the
capability table in `generations-mk2-q-mk5.md` likewise lists mk4 and mk5 as identical in
everything it covers. They are not identical here, so a pin in that section is not
automatically an mk4 pin.

**It is also not a 12 V rail enable, on any board.** The OLED runs from the SSD1306's own
internal charge pump, which `ssd1306::init` enables (`0x8D`) precisely because there is no
external panel supply — there is a test asserting that command is in the init sequence.
The only place this reference explains PC1 is the Q1 power section, where it is
`NOT_BATTERY_OLD`, a battery-presence input on earlier revs.

Nothing drives any of the three, and **a dark display on mk4 is unrelated to all of
them** — the charge pump, the SPI wiring and the reset sequence are the things upstream
of it.

**Where this bites later:** if mk5 support is ever added it cannot simply alias mk4, and
`MK_5_OK=0x20` is its own `hw_compat` bit (`MK_Q1_OK` is `0x10` — an earlier revision of
the reference had these swapped).

---

## `SYSCFG_CFGR3.ENREF_HSI48` — in the reference, not implemented

`install-and-usb-transport.md §OTG bring-up` step 3 says to set
`SYSCFG->CFGR3 |= SYSCFG_CFGR3_ENREF_HSI48` — "enable the VREFINT reference HSI48
requires on L4" — and warns that omitting step 2 or 3 gives a device that runs but never
enumerates.

**Step 2 was the bug and is fixed** (the PWR clock gate, below). Step 3 is not
implemented, deliberately, for two reasons:

- **The hardware says it is not needed to start HSI48.** On the first mk4 boot the
  selftest screen read `HAL ok` and `RNG ok 832 bit`. `enable_hsi48` spins on
  `RCC_CRRCR.HSI48RDY` with a bounded wait and propagates failure into `hal`, and the
  RNG cannot assert DRDY without CLK48. So HSI48 started and was driving the RNG with
  nothing written to SYSCFG.
- **We cannot place the register.** `SYSCFG_CFGR3` is not in the STM32L4/L4+ SYSCFG
  block as we have it — that layout is `MEMRMP, CFGR1, EXTICR[4], SCSR, CFGR2, SWPR,
  SKR, SWPR2`. A `CFGR3` carrying `ENREF_HSI48` is an STM32L0 register. Writing to a
  guessed offset in SYSCFG is not a harmless no-op; it lands on whatever *is* there.

So this may be an L0 detail that travelled into an L4 document, or it may be real and
merely not required for HSI48 to *start* — "accurate enough for the RNG" and "accurate
enough for USB" are not the same claim, and USB is the pickier of the two.

**How to resolve.** Confirm against RM0432 whether `SYSCFG_CFGR3` exists on STM32L4S5 and
what its offset is. If it does, implement it with a citation. If USB now enumerates with
step 2 alone, that is also an answer.

---

## OCTOSPI is never configured, so PSRAM is not mapped

**Blocks: the firmware upgrade path, on hardware.** `PsramArea::claim` documents a
safety contract that the PSRAM "must describe a memory-mapped PSRAM that is actually
present and mapped". Nothing in this firmware maps it: there is no OCTOSPI driver, and
`RCC_AHB3ENR.OSPI1EN` is never set.

Every emulator run passed because the emulator maps the region unconditionally. On
hardware, `0x9000_0000` is not backed until OCTOSPI1 is configured for memory-mapped
mode, so staging an image writes nowhere it can be read back from — and staging is the
last step before an irreversible install, and the only route back to stock firmware.

This is the same shape as the `PWREN` fault: a peripheral used without being turned on,
invisible to an emulator that does not model the gate.

**Debug → PSRAM says so on the device**, and deliberately does not probe the region: a
read of an unmapped address faults, and a fault needs a power cycle to clear, so naming
the gap is worth more than crashing to prove it.

**How to resolve.** Write the OCTOSPI1 driver: clock, pins on the GPIOE bank, the PSRAM
part's read/write commands, then memory-mapped mode. Until then the upgrade path cannot
work on real hardware, whatever USB does.

---

## One image for mk4 and mk5 needs runtime board detection

Coinkite ship a **single build for mk4 and mk5**, which is possible because `hw_compat`
is a bitmask: one image declares both bits and either bootloader accepts it.
`catcard-image build --hw-compat mk4,mk5` produces that, and it verifies as installable
on both.

What we cannot yet do is have that image *know which board it is on*. `BOARD` is a
compile-time constant, so a combined image reports whichever board it was built for —
an mk5 running it would call itself mk4 on the selftest screen, in `Identify`, and in
any log taken from it.

The hardware answers the question directly: `STRAP_MK5` is `PE0`, open on mk1-4 and
pulled **low** on mk5, which is how the stock firmware derives `mk_num`
(`generations-mk2-q-mk5.md` [C]). Reading that pin at boot and choosing between two
otherwise identical specs would give one image with a correct identity.

**Not done, and not urgent**: two builds are correct today, and a board that misreports
itself is worse than two files. It matters when images are published rather than built
per device.

---

## SDMMC constants that no emulator run can check

The driver in `catcard-hal::sdmmc` is written and **has never moved a byte**. The
emulator models the SDMMC command registers and nothing else: a probe reading every
offset from `0x00` to `0xFC` came back named only through `MASK` at `0x3C`, with no FIFO
and no data path traced at all. So this driver meets its first card on hardware.

What the probe did settle, by naming registers at both base addresses:

| | |
|---|---|
| SDMMC1 base | `0x5006_2400` (L4+) and `0x4001_2800` (L496) |
| `0x00..0x3C` | POWER, CLKCR, ARG, CMD, RESPCMD, RESP1-4, DTIMER, DLEN, DCTRL, DCOUNT, STA, ICR, MASK |

What rests on the reference manual alone, and is therefore `[?]`:

- **`FIFO` at `0x80`** — outside the range anything here names.
- **The RCC gate bit**: `AHB2ENR` bit 22 on L4+, `APB2ENR` bit 10 on L496. Both are read
  back after being set, so a wrong bit is `Error::Peripheral` on the screen rather than a
  peripheral that never answers — the `PWR_CR2.USV` lesson applied in advance.
- **`CMDTRANS`** (`CMD` bit 6), which the L4+ controller needs before a data command and
  the older one ignores.
- **AF12** for the six pins, and the clock dividers for 400 kHz then 12 MHz.
- **Card-detect polarity on mk4/mk5/Q1.** mk3's `SD_SW` is documented as high when a card
  is present; the others are assumed to match.

**How to resolve.** `Debug → microSD` reports each step and leaves `STA` on the screen. A
card that comes up prints its size, its addressing mode, and whether block 0 ends in
`55 aa`. Every wait is bounded, so a wrong constant reads as a timeout rather than a
device that has to be power-cycled.

---

## SD: the FAT reader is in, the peripheral driver is not

`catcard-sd` holds the card bring-up sequence and adapts an initialised card to
`fstool`'s heapless FAT driver (`fstool::fs::fat`, `alloc` off — one sector of scratch
RAM whatever the card's size, rather than the allocation table resident). Both halves are
tested on the host against a fake card and a real FAT32 volume.

The `Transport` over the peripheral now exists for both families — the command-register
half of the block is common to them, so one driver covers both with the base address and
clock gate chosen by MCU. It is unexercised; see above.

**And SD is not an escape route on its own.** The bootloader installs only from the
staging medium — SPI-NOR offset 0 on mk3, the PSRAM recovery header on mk4+ — so a card
is a transport into the same bottleneck USB already reaches. It becomes a second way in
only once staging works.

`tools/emu/mksd.sh` builds a FAT32 card image with a firmware file on it for the
emulator's `--sd`, and `fstool ls` reads it back afterwards — so a write from the device
can be checked without trusting the device's own report.

---

## SE1 single-wire UART pin; SE2 I²C addresses

Not needed while all secret operations go through the callgate, which is the design.
Would only matter for direct non-secret SE access (config zone reads, `Random`).

`se1-driver-spec.md` now gives the full SE1 transport — SWI-over-UART at 230400 bps,
`0x7d`/`0x7f` bit encoding, the Microchip CRC-16, frame layout and per-opcode delays —
so a direct driver is writable. The UART instance is UART4 on mk3 `[C]`, unconfirmed on
mk4/Q `[?]`. SE2's I2C pins are confirmed on Q1 only; see the mk4 item above.

---

## SE2 stops answering under sustained polling `[?]`

Seed generation reads callgate 26 sixteen times from each secure element, 32 bytes a
call. On a real Q1 the first run gave **SE1 512 bytes (16 of 16 calls) and SE2 128 bytes
(4 of 16)**: `seed: SE1 512 B, SE2 128 B, 3392 bits from 3 chips, policy ok`.

SE2 is not dead. At boot it delivers its full 64 bytes like SE1 — the boot line reads
`entropy 832`, which is exactly 256 (STM32) + 256 (SE1) + 256 (SE2) + 64 (DWT timing),
and 576 is what a missing element would produce. It answers, then stops answering when
polled repeatedly.

Candidate causes, none confirmed: the DS28C36B rate-limiting its RNG, a per-boot or
per-interval budget in the part, or the bootloader's SE2 path failing after a number of
calls for a reason of its own. `boot.rs` would not have noticed either way — it breaks
out of its read loop on the first error, so a short answer there looks the same as a
full one.

**Consequence.** Fresh-entropy collection cannot assume both elements contribute
equally. Today that is harmless: the pool credits what actually arrived, the policy is
checked against the real total, and the screen shows each element separately so a short
column is visible rather than hidden. It matters if anything later *requires* a fixed
number of bytes from SE2.

Worth measuring before designing around it: how many calls SE2 sustains, whether a pause
between calls restores it, and whether the limit resets across a reboot. Utils → Analyze
RNG already reads each element live and is the place to look.
