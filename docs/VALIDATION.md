# Hardware validation plan

Everything in this repository has been written without a device. The wallet crypto is
verified against official test vectors and needs no hardware; the drivers have never
executed a single instruction on silicon.

This is the running order for the first validation session, arranged so each step
depends only on steps above it. Where a step can fail, the likely cause is named —
several of these are guesses recorded in `HARDWARE-OPEN-ITEMS.md`, and this is the
session that turns them into facts.

> Use a device you are willing to recover over DFU. Nothing here is a wallet yet, and a
> unit running CatCard cannot be told to load anything else.

---

## 0. Before touching the device

```sh
just ci          # host tests, lints, all three boards built, images signed and verified
```

Confirm the board you have, and build for exactly it. `mk3` and `mk4` install at
different addresses; an image for the wrong one will not boot.

```sh
cargo run -p catcard-image -- boards
```

---

## 1. Does the image install and boot at all?

Install via microSD (`docs/FLASHING.md`). Expect the bootloader's 25-second dev-key
warning and a red "genuine" light — that is correct, not a fault.

**Success:** the device stops on a screen rather than rebooting or hanging.

**If nothing appears:** the image may be installing fine and only the *display* failing
— check step 3 before assuming a boot failure. Read `CATCARD_BOOT_STATUS` over SWD if a
probe is available; magic `0xCA7CA2D0` means the firmware ran.

**If it reboots repeatedly:** the vector table or `_stext` is misplaced. Compare the
first loadable section address against the board's `firmware_base`.

---

## 2. Is the entropy pool healthy?

The selftest screen reports it directly, and so does `CATCARD_BOOT_STATUS`.

| line | meaning if it says `FAIL` |
|---|---|
| `HAL` | HSI48 did not start, or the RNG never asserted `DRDY` |
| `DWT` | the cycle counter is not running; timing entropy contributes nothing |
| `RNG` | the pool did not reach its policy — see below |

**Expected:** `RNG ok` with **256 bits** on mk3 (the STM32 TRNG alone, 64 bytes credited
at 4 bits each) and **832** on mk4/Q — measured under the emulator, and it decomposes
exactly: STM32 256 + SE1 256 + SE2 256 + keypress timing 64. A count below 832 on mk4
means a secure-element source did not contribute; 256 exactly means neither did.

**If `RNG FAIL` on mk4/Q:** most likely the callgate. mk4's policy demands two distinct
hardware TRNGs, and the second comes from the secure elements via callgate 26. Check
step 5 first.

**If `RNG FAIL` on mk3:** the STM32 TRNG itself is not producing health-test-passing
output. That is the one result here that would block the whole project, so investigate
rather than working around it.

---

## 3. Does the display work?

This is the largest cluster of guesses in the tree.

**If the panel is blank:**

1. **SPI instance and pins.** `MK3_DISPLAY_SPI` assumes SPI1 with SCK=PA5, MOSI=PA7,
   inferred from the Q1 board sharing PA4/PA6/PA8 for control. `pins_confirmed` is
   `false`. Probe SCK for activity during boot.
2. **Alternate function.** `AF_SPI = 5` is taken from the datasheet's AF table; confirm
   for the specific pins.
3. **Charge pump.** Already enabled in the init sequence — the most common cause of a
   dark SSD1306 — so this is unlikely to be it.
4. **Reset polarity.** The driver holds reset low, then releases high.

**If the image is garbled or offset:** the panel is a different geometry, or `SEG_REMAP`
/ `COM_SCAN_DEC` are wrong for how it is mounted (the init sequence assumes a 180°
rotation). Both are one-line changes in `catcard-ui::ssd1306`.

---

## 4. Does the keypad work?

The selftest echoes the last key pressed as `KEY <n>`.

Press every key in turn and confirm the label matches the legend. Specifically:

- **All twelve keys register.** A dead row means the row pin is wrong; a dead column
  means the column's pull-up is not configured.
- **The map is not transposed.** If `1` shows as `3`, rows and columns are swapped.
- **No double registration.** Debounce is three samples at roughly 60 Hz; if keys repeat,
  the scan loop is running faster than assumed because the clock is not what
  `ASSUMED_PCLK_HZ` says.
- **Nothing registers while idle.** Phantom presses mean two rows are being driven at
  once, which should be structurally impossible — report it if seen.

---

## 5. Is the callgate reachable?

The single most important unknown, because every secret operation depends on it.

Read the bootloader info table at `0x0800_0040` over SWD, or infer it from behaviour:

- `[0x00]` is the entry address. It should be non-zero, odd (Thumb), end in `0x05`, and
  lie below the board's `firmware_base`. `catcard_callgate::entry::validate_entry`
  enforces all four.
- `[0x04]` is the BCD protocol version.

**mk3 is expected to read `0x0800_0305`** (firewall base `0x0800_0300` + 4 + 1). mk4 and
Q will differ — that is why the table exists and why the address must never be
hardcoded.

Once it validates, the SE-RNG path in `boot::feed_secure_elements` starts contributing
and step 2 should show more sources.

**If `validate_entry` rejects what is there:** do not relax the check. A wrong branch
target inside the firewall segment resets the CPU with no diagnostic, and a check that
passes garbage is worse than one that fails.

---

## 6. What the SPI-NOR flash actually is

Blocked on pin assignment, so this step is discovery rather than validation.

Probe or trace to determine SPI2's SCK and CS. The candidates, given PB12–PB14 are
numpad rows on mk3:

- SCK: PB10 or PD1 (PD1 is the recorded guess)
- CS: PB9 or PD0

With those, `NorFlash::probe` reads the JEDEC ID and derives the size. An all-zero or
all-ones ID means the pins are still wrong — it is reported rather than turned into a
plausible device size, so a bad guess fails loudly.

Record the manufacturer, memory type and capacity in `HARDWARE-OPEN-ITEMS.md`.

---

## 7. mk4 only: SE2 versus the numpad

`HARDWARE-OPEN-ITEMS.md` records a contradiction that only hardware can settle. mk4 is
documented as having the mk3 numpad (rows PB12/PB13/PB14) *and* SE2 — and Q1 routes SE2
to PB13/PB14. Both cannot be true on mk4.

Step 4 already answers half of it: if all twelve keys work with the mk3 row map, the
numpad is as inferred and mk4's SE2 must be elsewhere.

---

## 8. Clock

`ASSUMED_PCLK_HZ` is 4 MHz — the reset-default MSI — and the PLL is not programmed
because the reference gives the divisors but not the MSI range. `SYSCLK` would be 40 MHz
at MSI=4 and 80 MHz at MSI=8.

Read `RCC_CR.MSIRANGE`, or measure on MCO. Once known, `clock::PLL_DIVISORS` can be
applied and the SPI prescalers recomputed.

---

## Testing against the emulator

`../coldcard-emu` runs CatCard on an emulated STM32 with the **real Mk4 bootloader
binary** taken from a factory `.dfu`. That is the closest thing to hardware available
without hardware, and it already validates the things this document said needed a
device.

```sh
cargo fw-mk4
cargo run -p catcard-image -- build \
    target/thumbv7em-none-eabihf/release/catcard-fw \
    --board mk4 --version 0.0.1 --dfu out/catcard-mk4.dfu

ccemu -q run --dfu out/catcard-mk4.dfu \
    --bootloader <a factory .dfu> --board mk4 \
    --run-for 2500000000 --screen-log screens.txt --dump-ram ram.bin
```

CatCard's `.dfu` carries only the application, because on a device the bootloader is
already in flash — hence `--bootloader`. Budget at least 2.1e9 instructions: a dev-key
image gets the bootloader's 25-second "Danger! Custom Firmware" countdown first, which
is the documented behaviour for `pubkey_num = 0` and not a fault.

Read the result out of `CATCARD_BOOT_STATUS` (magic `0xCA7CA2D0`) in the RAM dump rather
than off the screen — the framebuffer render is legible but it is pixel art, and reading
a number out of it is guesswork.

### The limit, which matters more than the capability

**The emulator and CatCard are both ours, and both derived from `../hw-reference/`.**
Agreement between them is evidence of *consistency*, not of correctness. If the
reference is wrong, both will be wrong together and every test will pass — which is the
same failure that made 158 emulator tests unable to catch a slot-decode bug they had
encoded themselves.

So the rules are:

- **The emulator is consumed as a binary.** CatCard does not read its source or its
  docs — `coldcard-emu/docs/` quotes stock firmware inline, which `CLEANROOM.md`
  forbids reaching this project by any route.
- **Disagreements are resolved against `hw-reference` and the chip datasheets**, never
  by reading the emulator to find out what it expects. If neither settles it, it goes to
  `HARDWARE-OPEN-ITEMS.md` and waits for a device.
- **Anything the reference marks `[I]` or `[?]` is not settled by an emulator run.**
  Real hardware remains the arbiter for the display pins, the SPI-NOR pins, and the MSI
  range.

What it *does* settle: the image format against a real bootloader, the callgate ABI
against a real callgate, regressions, and every place CatCard diverges from the spec
both were built from.

### What the first run found

1. **`firmware_length` has a 256 KB floor.** `firmware-signing.md §1` documents it;
   CatCard did not implement it, so a 62 KB image was refused before any signature work,
   with no diagnosis about its contents. `catcard-image` now pads to the minimum and
   `validate` enforces it.
2. **The header spec had been revised** since CatCard implemented against it: `best_ts`
   splits out of `future`, `install_flags` has a second defined bit, and `0x10` in
   `hw_compat` is **Q1, not mk5** — the Q1 board was claiming mk4 compatibility and a
   test was asserting the wrong bit names.
3. **The SPI driver stalled waiting for `RXNE` on the display bus**, which has no MISO
   line at all. Fixed with a transmit-only path, which is the right shape for that bus
   independent of the emulator. Whether `RXNE` should assert on a real STM32 with MISO
   unrouted is a datasheet question, not one to settle by reading the emulator.

After those, CatCard boots: bootloader hands off, HAL comes up, the entropy pool reaches
832 credited bits from all three TRNGs (STM32 + SE1 + SE2 through callgate 26), the
SSD1306 driver initialises the panel, the selftest screen renders, and the keypad scan
loop runs.

## Recording the results

Every `[?]` this session resolves should move out of `HARDWARE-OPEN-ITEMS.md` and into
the board table with a `[C]` tag and a note saying it was confirmed on hardware rather
than read from a document. Confidence tags are how the next person knows what to trust.
