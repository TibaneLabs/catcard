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

## SPI-NOR chip select and SCK — RESOLVED

**Was blocking: settings storage and PSBT scratch — on mk3 only.**

`gpio-peripherals.md §Mk4` confirms there is **no SPI-NOR from mk4 onward**: SPI2 is
commented out of the board file as "removed in Mk4 rev B", settings moved to internal
flash and upgrade staging moved to PSRAM. So this blocks nothing on mk4 or Q1, and
`MK4.sflash` / `Q1.sflash` are `None` rather than an inherited guess.

On mk3 the full SPI2 pinout is now confirmed in `hw-reference/storage.md §SPI-NOR` and
`gpio.md`: **SCK=PB10, MOSI=PC3, MISO=PC2, CS=PB9** at 8 MHz in mode 0. The chip-select
is PB9 driven as a plain GPIO output — *not* the SPI2 hardware NSS, even though PB9 is
that pin's AF — pulled low around each opcode. The part is a Macronix **MX25L8006E,
1 MB, 4 KB sectors**. `MK3_SFLASH_SPI` now carries these with `pins_confirmed: true` and
`sflash.cs: Some(PB9)`. (The earlier `PD1` SCK candidate was wrong.)

The mk3 **firmware staging base/header** inside SPI-NOR is now confirmed too (tracked
below) — so what remains for self-upgrade is the firmware write/receive path, not a
hardware unknown.

---

## SYSCLK / PLL configuration — RESOLVED

The clock tree is now confirmed in `hw-reference/platform.md §1` [C], and the earlier
premise here (that the device idles at the 4 MHz MSI reset default and we would program
the PLL ourselves) was **wrong**:

- **The bootloader owns the clock tree and the firmware inherits it** — it must **not**
  reset RCC. At the firmware's first instruction SYSCLK is already running off the PLL,
  not the MSI reset default.
- **mk3 (L496): SYSCLK 80 MHz** off HSE 8 MHz (`M=2, N=40, R=2`).
- **mk4 / mk5 / Q1 (L4S5): SYSCLK 120 MHz** off HSE 8 MHz (`M=2, N=60, R=2`), AHB/APB ÷1,
  flash latency 5. (Not 80 MHz — that was an earlier assumption; 120 is L4S5-only.)

Nothing needs programming: `catcard-hal::clock` reads the live source, PLL divisors and
bus prescalers from RCC (`hclk_hz`, `pclk1_hz`, `pclk2_hz`), so every derived value —
the display and SPI-NOR SPI prescalers, logged clocks — is right whatever the bootloader
left, on every generation. The RNG's 48 MHz comes from the independent HSI48 via
`enable_hsi48`, unaffected either way.

**Stale assumption to sweep:** `usbtask::IDLE_PAUSE_CYCLES` and any comment saying the
device runs at "4 MHz MSI" or a flat "80 MHz" — the real inherited SYSCLK is 80 MHz on
mk3 and 120 MHz on the L4S5 boards. `IDLE_PAUSE_CYCLES = 66_000` was tuned empirically on
hardware and still works; it is just described against the wrong clock.

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

## Firmware staging base — RESOLVED on mk4, Q1 and mk3

**mk4 / Q1 `[C]`.** PSRAM is an 8 MB part on OCTOSPI1, memory-mapped at `0x9000_0000`,
and the bootloader reads a firmware-staging recovery header at `0x907F_F800` — magics
`0xDBCC_8350` and `0xBAFC_FBA3`, both of which must match or it ignores the region
entirely. That "both magics or nothing" rule is what makes the mechanism safe to use:
an unwritten or half-written header stages nothing rather than staging garbage. Recorded
as [`Psram`](../crates/catcard-board/src/spec.rs) in the board table.

**mk3 `[C]`** — now documented in `hw-reference/storage.md §"mk3 firmware staging & recovery"`:

- **Staging base = SPI-NOR address `0x00000000`.** The full image is written from offset 0,
  byte-identical to how it lands in main flash (`FIRMWARE_START = 0x0800_8000`). The
  bootloader reads the header at an *absolute* SPI-NOR offset, not `base+offset`.
- **Primary header @ `0x3F80`** (`0x4000 − 0x80`), 128 B, magic `0xCC00_1234`, signature the
  last 64 B (`0x3FC0:0x4000`) — the same `catcard-fwhdr` header this firmware already builds.
- **Trailing duplicate header @ offset = `firmware_length`**, written **last** by the
  uploader. Its valid presence is the "upload complete" marker: an interrupted upload leaves
  no trailing header, so a torn transfer stages nothing rather than garbage (the same safety
  the mk4 "both magics" rule gives). The bootloader zeroes it after a successful install.
- **Sizes:** `FW_MIN_LENGTH = 256 KB`, `FW_MAX_LENGTH = 0xF8000` (992 KB).
- **Settings coexistence — a real constraint.** nvstore is the last 128 KB, `0xE0000–0x100000`.
  The staged image *plus* its trailing header must end **below `0xE0000`** (image ≤ ~896 KB) or
  it overwrites settings, tighter than the nominal `FW_MAX_LENGTH`.

**Still needed to use it** (a from-scratch firmware, not a hardware fact): the SPI-NOR write
path wired to the mk3 bus (now that the pins are confirmed — see above), a firmware-receive
path over USB/SD, and writing the two headers in the crash-safe order (image + primary header
first, trailing header last). Until that exists, a broken image on a locked (RDP=2) mk3 is a
one-way brick recoverable only with an external SPI-NOR programmer, since mk3 has no PSRAM
fallback — get the write and receive paths working before installing any image on a locked unit.

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

## ~~OCTOSPI is never configured, so PSRAM is not mapped~~ — resolved: the bootloader owns it

**Not an open item, and the resolution is the opposite of what this entry used to
propose.** OCTOSPI1 belongs to the **bootloader**, which sets it up once in
`psram_setup()` at boot: clock enable, PE10–PE15 at AF10 (`OCTOSPIM_P1`),
`HAL_OSPI_Init` (prescaler 2 → 60 MHz, ClockMode 0, DHQC), the chip init sequence
(`0xF5` / `0x66` / `0x99` / `0x9F` / `0x35`), then `HAL_OSPI_MemoryMapped` with
**`TimeOutPeriod = 16`**. It stays memory-mapped for the firmware's whole lifetime.

The firmware inherits that and uses the address space, exactly as it inherits the clock
tree and the Q1's LCD. `RCC_AHB3ENR.OSPI1EN` is not set here because it is already set.

> **Do not write an OCTOSPI driver.** This entry previously said to, and that is now the
> thing most likely to break the upgrade path: re-initialising the controller, re-clocking
> it, or switching it back to indirect mode would take apart a working configuration that
> nothing in this firmware is in a position to rebuild. The firmware never re-inits,
> re-clocks, or leaves memory-mapped mode.

What this settles, beyond the mapping: **`TimeOutPeriod = 16` is armed**, so CE# does rise
once the bus goes idle — that is the mechanism the PSRAM driver's burst gaps rely on, and
it is present rather than assumed. It is recorded as `Psram::mmap_timeout_clocks` so the
gap length is computed from it rather than guessed, and the value is the bootloader's to
change, not ours.

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

## SE2 produces about four times slower than SE1 `[?]`

On Utils → Analyze RNG, which reads both elements once per frame, **SE1 completes four
rounds in the time SE2 takes for one** (observed on a real Q1).

That rate difference explains the first seed generation, which took sixteen turns each
and logged `SE1 512 B, SE2 128 B` — the same 4:1. An earlier revision of this entry
called it "SE2 stops answering under sustained polling", which was **wrong**: a chip
that stopped would give a sharp cutoff after four calls, not a steady quarter rate, and
nothing here ever stopped. That misreading came from taking our own lockstep loop's
output as a fact about the hardware.

SE2 is healthy. At boot it delivers its full 64 bytes like SE1 — `entropy 832` is
exactly 256 (STM32) + 256 (SE1) + 256 (SE2) + 64 (DWT timing), where a missing element
would give 576.

**Still unmeasured: how it declines.** `se_rng` can return `Ok(0)` (asked too soon,
nothing ready) or `Err` (refused), and every caller so far has treated them alike, so we
cannot yet say which one a too-early SE2 read produces. Seed generation now counts them
separately and logs `SE1 <bytes>B/<turns>t <empty>e <failed>f, SE2 …`, which settles it
on the next run. If they are `Ok(0)`, the element simply needs time and the fix is
pacing; if they are `Err`, something in the bootloader's SE2 path is refusing and that
is a different question.

**What already accounts for it.** Generation asks each element for a byte *target*
rather than a fixed number of turns, so a slower element takes longer instead of
contributing less, bounded so a dead one cannot hang a wallet. The pool credits what
actually arrived, the policy is checked against the real total, and the screen counts
each element separately — a column that lags is visible rather than hidden.

Worth knowing before designing around it: whether the rate is constant or a burst
followed by a slower refill, and whether it resets across a reboot.

## Fast wipe (callgate 23) through the ordinary gate entry `[I]`

`Callgate::fast_wipe` calls method 23 with `0xBEEF` (silent) or `0xDEAD` (noisy), which the
reference gives `[C]`. What is **inferred** is the entry: stock reaches 23 through
`ckcc.oneway`, a second entry beside the gate (bootloader-callgate-abi.md §"A second entry
point"). Methods 2 and 3 are on the same oneway list and answer through our ordinary gate
entry on real hardware, so 23 is called the same way.

Used only by the kill key, and as the fallback in microSD 2FA — both in release builds
alone (`crate::guard`), so no bench unit has run it and none can. If the gate returned
instead of wiping, `fast_wipe` stops rather than carrying on as though the seed were gone.

To confirm without losing a device: a unit whose seed is disposable (the mk5's test seed),
a release build, arm the kill key, type it.

## Trick PINs (callgate 22) — BLOCKED on the slot layout

The reference gives the outline only: 14 SE2 slots, each a PIN and a flag word with the
flag values (`0x8000` wipe, `0x4000` brick, `0x2000` fake-out, `0x1000` word duress,
`0x0800` xprv duress, `0x0400` delta, `0x0200` reboot), `0xF800` hidden from the firmware,
1–2 data pages of duress entropy per slot, and gate 22's sub-methods (0 clear all, 1 get by
PIN, 2 clear/update slot) — secure-elements.md §"Trick PINs", bootloader-callgate-abi.md
method 22 `[C]`.

Not given, and each one is a struct the secure element acts on — the brick flag among them —
so none of it is guessed:

1. The slot buffer gate 22 takes and returns: its size, field order and widths (slot number,
   flags, PIN bytes and length, tail/data fields), byte order, and what `arg2` carries
   besides the sub-method.
2. How a login that matched a trick PIN comes back through gate 18: which state flags or
   return codes, and what `fetch_secret` returns afterwards for a duress or delta slot.
3. How the duress wallet's data pages are written and read (which call, which offsets).
4. Whether "get by PIN" needs the main-PIN login gate 22 requires, or can run from the
   prompt.

## `PA_ZERO_SECRET` means "a secret was written", not "a secret is there" `[C]`

Seen on the Q1 (2026-09-23), after Destroy seed: the login reports the secret slot **in
use** while the slot's seventy-two bytes are all zero.

```
pin: attempt -> in, secret slot in use
wallet: secret is Empty, not BIP-39
```

Destroy seed had already said as much at the time -- it writes zeros through `gate 18/3`,
reads them back, and reports the bytes and the flag separately, which is why this was
visible rather than mysterious. The flag is what `gate 18` returns in `state_flags`
(`PA_ZERO_SECRET 0x10`); it is not cleared by writing zeros, and survives a reboot.

So the two answers mean different things, and the firmware asks the right one for the
question:

- **Is there a wallet to work in?** The bytes. `crate::key::no_stored_wallet()` answers
  from what the slot turned out to hold, and the menu leads with New and Import when it
  holds nothing -- before this, such a device offered Sign and Addresses for a wallet it
  did not have.
- **Has a secret ever been written?** The flag, which is all it can tell us.

### The flag is settled at login, and a write does not clear it `[C]`

Same Q1, same day, the other way round: after **creating** a seed the main menu went on
offering New and Import, and a restart put it right.

`set_secret` refreshes the step from the struct the gate hands back
(`attempt.has_zero_secret()`), so the firmware is reading the flag after the write, not
before it -- and it still says no secret. Restarting fixes it because login recomputes
the flag; the change call does not. The flag is therefore a statement about the state at
login, and the only thing that can contradict it during a session is the slot itself.

That is what the firmware does now: what it has read out of the slot, or written into it
and read back, outranks the flag, and the flag decides only where it has never looked. A
disagreement is logged (`seed: the login flag still says none; the slot says otherwise`),
so a bootloader that does clear it will show up in a device log rather than go unnoticed.

Unknown: whether any call clears the flag short of a factory path, and whether stock reads
it the same way. Neither blocks anything -- what a wallet needs is the bytes.

## The broadcast URL: host and chain segment `[?]`

`crate::nfc` writes `https://www.blockexplorer.com/<chain>/broadcast?tx=<hex>` to the tag,
with `<chain>` as `btc`. Neither half is confirmed:

- **The host** (`HOST_AND_PATH`) is the explorer named with the request. That it serves a
  `/<chain>/broadcast?tx=` page at all, and that this is the host the owner wants a phone
  sent to, has not been checked -- no tag has been tapped yet. It is the one string in
  the firmware that names a third party.
- **The chain segment** (`CHAIN`) is a guess at what that explorer uses for Bitcoin.

What depends on them: the NFC broadcast offer after a signed transaction, and nothing
else. Signing, the card and the USB paths do not touch either.

A wrong host or segment is a page that does not know the transaction, not a wrong
broadcast: the transaction is in the query either way, and the phone's owner sees the
address before anything is sent. Settled by tapping a phone on a written tag once.

**Privacy.** A tap is a web request from the phone: the host learns the signed
transaction and the phone's IP address, together, before the owner has decided to
broadcast. That is inherent to sending a phone to any explorer, and it is why the offer
is opt-in per transaction and never the only way out. A device that should not tell
anyone anything broadcasts from the card or over USB instead.

Both are one `const` each at the top of `crates/catcard-fw/src/nfc.rs`.

## Writing the NFC tag has not been tried on hardware

The driver follows the datasheet -- device select `0xA6`, two address bytes, one 16-byte
row per write, `tW` waited out afterwards -- but no tag has answered it yet. It is off the
boot path: Debug → NFC test writes a fixed URL and says whether the tag answered, the
broadcast offer only appears after a transaction is fully signed, Addresses → `2` writes
the address on screen, and Sign → By NFC is a menu action.

Unknown until then: whether the factory capability container differs from the one written
here, whether a phone reads the image back as a URL, and whether the co-processor sharing
this bus needs to be quiet during the write.

## Reading the NFC tag back has not been tried either `[I]`

Receiving works the other way round -- `crate::nfc::read_user_memory` loads the address
counter with a dummy write, turns the bus around with a **repeated** start
(`SoftI2c::write_read`), and reads 8192 bytes out in one transfer. Both halves are
datasheet-confirmed (§6.5.1 random address read, §6.5.3 sequential read access), and the
repeated start is tested on the host against the bit-bang mock. What is not confirmed is
the part answering it.

Unknown until a tag is in front of it:

- **Whether the poll sees a phone's write.** `Sign → By NFC` marks the tag with a text
  record and then watches the first 24 bytes of user memory until they change and settle.
  That a phone's NDEF write lands in those bytes, and that an I²C read taken during an RF
  field returns either the old value or the new one rather than something else, is `[I]` --
  read off the format and the bus, not measured.
- **How long a full read takes.** ~74 000 bit times at the bit-bang's quarter period, so
  under a second by arithmetic, with the screen held. Not timed.
- **Whether a phone's write arrives whole.** The settle window is two quiet polls, about
  0.4 s. If a phone writes its blocks with longer gaps than that, a partial message would
  be read -- which `catcard_nfc::read` refuses as `Truncated` rather than signing, so the
  failure is "nothing this can use" and another tap, not a wrong transaction.

The two mechanisms the part has for announcing an RF write are deliberately **not** used,
and why is in the module header: the fast transfer mode mailbox is 256 bytes and needs
ST's own RF commands (§4.5, Table 15), and the `RF_WRITE` bit of `IT_STS_Dyn` is only
reported once it is enabled in the `GPO1` *system* register, which needs the I²C security
session open (Table 31, Table 37, §5.4.5). Both would mean writing configuration registers
on a part nobody here has tried.

## The Q1 backlight PWM timer/channel behind `BL_ENABLE=PE3` `[?]`

`hw-reference/gpio.md` §"LCD backlight" and `display.md` §Q1 both give the pin — backlight
is **`BL_ENABLE=PE3`** on the Q1 `[C]` — and say its **brightness** is set the way stock
sets it: "backlight enable / brightness via `pyb.LED(1)`", i.e. PE3 is driven as a
MicroPython `pyb.LED`, whose `intensity()` is a **timer PWM duty**. So variable brightness
means a timer channel on PE3, not a plain GPIO.

**What is unknown:** *which* timer and channel are wired to PE3, and the polarity/period
the panel's backlight driver expects. `gpio.md` and `display.md` name the pin and the
`pyb.LED(1)` fact but not the timer behind it, and the sanctioned references stop there.
Guessing a `TIMx_CCRn` would be exactly the "plausible register" `CLAUDE.md` forbids.

**What ships in the meantime.** `crate::display::set_backlight` drives the one confirmed
control — the GPIO enable — so a non-zero level lights the panel and zero blanks it. The
"LCD brightness" setting (Q1 Settings menu) is persisted at full percent resolution and
applied on save and on the next login, so the chosen level is *stored* correctly; today
every non-zero level simply lights the panel. The menu offers no off/zero row, because a
dark panel is one the owner cannot see to turn back up.

**How to resolve it.** On real Q1 hardware, find PE3's alternate-function timer mapping
(STM32L4+ AF table, RM0432) and confirm the backlight driver's expected PWM frequency and
active level. Then `set_backlight` scales `percent` to a `TIMx_CCRn` duty; nothing else
changes — the setting, its storage, the menu row and the apply path are already in place.
Until then this is `[?]` and the feature is on/off, not dimming.
## Stock's WIF-store settings key and layout are unknown `[?]`

The WIF store (`crates/catcard-fw/src/wifstore.rs`, backed by
`catcard_settings::wifs`) keeps its keys under our own settings key `ccwif`, as a JSON
array of `{"n": <label>, "w": <wif>}` objects. Stock also keeps a WIF store, but the
settings-format document does not pin the key it lives under or the shape of an entry, so
this does not read or write stock's -- inventing its key would risk overwriting the store
of anyone whose device has been stock, exactly as the multisig registrations under `ccms`
avoid stock's `multisig`.

Consequence of being wrong: none to safety. A device that has been stock and then this
keeps two independent stores; neither firmware loses the other's keys. Only cross-firmware
interoperability of the WIF store is affected, and it is affected the same safe way the
multisig store already is.

The 30-key cap and the "can sign matching inputs" behaviour are confirmed from
`hw-reference/firmware-features.md` §7 and §11 `[C]`; only stock's on-disk key and JSON
shape are the open `[?]`.
