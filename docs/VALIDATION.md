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
    --board mk4 --version 7.0.0 --dfu out/catcard-mk4.dfu

ccemu -q run --dfu out/catcard-mk4.dfu \
    --bootloader <a factory .dfu> --board mk4 \
    --run-for 2500000000 --screen-log screens.txt --dump-ram ram.bin
```

CatCard's `.dfu` carries only the application, because on a device the bootloader is
already in flash — hence `--bootloader`. **Match the bootloader to the board.** They are
not interchangeable, and a Q1 loader given an mk4 image never reaches the firmware at
all: the screen log stops at the loader's own splash and `bootstatus.py` reports the
status block missing, which reads exactly like a firmware that failed to start.

Budget at least 2.1e9 instructions: a dev-key
image gets the bootloader's 25-second "Danger! Custom Firmware" countdown first, which
is the documented behaviour for `pubkey_num = 0` and not a fault.

Read the result out of `CATCARD_BOOT_STATUS` (magic `0xCA7CA2D0`) in the RAM dump rather
than eyeballing the screen — `tools/emu/bootstatus.py` does it and exits non-zero on any
failure.

### The screen decodes to text

The emulator reads its own framebuffer back as characters, using the same zevv-peep and
misc-fixed faces CatCard renders with. Since we adopted those faces, **CatCard's screens
decode too**:

```
CatCard
mk4 0.0.1
HAL ok
DWT ok
RNG ok 832 bit
```

That is the practically valuable half of using those fonts, and it is worth more than the
visual familiarity: a run can be asserted on strings rather than on a pixel hash, so a
screen test survives a font tweak or a one-pixel layout shift that a hash would break on.

**Lay text on the font's natural row pitch.** The status lines were first placed on an
8-pixel pitch with a 6-pixel face, and the 2-pixel slivers between them decoded as rows
of garbage. Moving to a 6-pixel pitch cleaned it up. A blank region can still produce one
spurious row; that is the decoder's segmentation, not stray ink, and it is worth
confirming against the raw render before chasing it.

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

### What the second run found

**mk4's numpad is not on the mk3 pins.** The board table had inherited them as an `[I]`,
and `gpio-peripherals.md §Mk4` has since been corrected to say so outright, calling that
exact inference wrong: mk4 keeps the 4x3 layout on cols `PB0..PB2` and rows `PD8..PD11`.
Nothing reached the firmware because it was polling pins with nothing attached.

That also resolved the SE2 contradiction this document's sibling had recorded — SE2 owns
PB13/PB14, the numpad never did — and confirmed there is **no SPI-NOR from mk4 onward**,
so upgrade staging is PSRAM at `0x9000_0000` with a recovery header at `0x907F_F800`.

The symptom is worth remembering: a device waiting on a keypad and a device that has
stopped looked pixel-identical, because `show()` and `park()` drew the same screen. The
selftest screen now says which, and that one line was what turned "it is hung" into "it
is polling the wrong pins".

After those, CatCard boots: bootloader hands off, HAL comes up, the entropy pool reaches
832 credited bits from all three TRNGs (STM32 + SE1 + SE2 through callgate 26), the
SSD1306 driver initialises the panel, the selftest screen renders, and the keypad scan
loop runs.

## The whole sequence, in one run — confirmed

A device from cold, given a PIN, unlocked with it, and then upgraded over USB:

```
init -> selftest -> blank -> choose a PIN -> anti-phishing words -> login -> Unlocked
ping              status=Ok
identify          protocol=1 board=mk4 version=0.0.1 unlocked=False
offer(locked)     status=NotNow
unlocked after wait: True
offer(unlocked)   status=Ok verified=True len=262144
device: reports in 4290, replies out 62, frame errors 0, staged 262144 bytes
```

**The two lines in the middle are the point.** An upgrade is refused while the device is
locked and accepted once a person has entered the PIN at the front panel — so someone
holding the device cannot replace its firmware without also being able to open it. Every
earlier upgrade run auto-unlocked as blank, so that gate had never actually been tested.

Five callgate paths are now exercised against the genuine bootloader rather than a
model: `gate 18` setup, `Change` and `login`, `gate 16` anti-phishing words, and
`gate 26` secure-element entropy.

### What running the whole thing found that the parts did not

Every one of these sat in a seam between units that were individually correct, and every
one passed its own tests:

| | |
|---|---|
| the downgrade check refused **all** stock firmware | going back to stock was impossible |
| the recovery header was written and never read back | the last unchecked write before an irreversible install |
| setup showed the words through the login path | the device walked the whole flow and set no PIN, silently |
| the struct left by a `Change` cannot log in | every login straight after setup failed |
| **the HMAC covers `pin`, so the PIN must be set before `setup` signs** | **login could never have worked on hardware** |

The last one is the one to remember. It was invisible because a blank secure element
never reaches a login attempt, and the model was too permissive to catch it — its
`validate` checked a counter and ignored the PIN field. The model now records the PIN as
signed, which is what gives those tests teeth.

## Firmware upgrade over USB — confirmed

The whole path, twice, against the real mk4 bootloader:

```
ping      status=Ok
identify  status=Ok protocol=1 board=mk4 version=0.0.1
offer     status=Ok verified=True  len=262144 version=0.0.1 key_slot=0 older=False
offer     status=Ok verified=False len=987136 version=5.4.5 key_slot=1 older=True
stopped: guest requested a system reset (AIRCR.SYSRESETREQ)
```

The second line is the one worth having: **Coldcard 5.4.5, 987 KB, signed with a
production key** — CatCard installing stock firmware back onto the device. It exercises
what the dev-signed case cannot:

- `verified=False`, `key_slot=1`. The five factory keys are not published, so the
  signature **cannot** be checked here. The device says so rather than implying an
  absence of evidence is evidence of absence.
- `older=True`. Every build of this firmware is newer than any released stock firmware,
  so an earlier version of `inspect` refused all of them — making a return to stock
  impossible. That is now a warning, with the bootloader's OTP high-water left as the
  real anti-rollback.

Both facts reach the approval screen, and a person decides:

```
signature checked            checked, but OLDER
SIGNATURE NOT CHECKED        NOT CHECKED, and OLDER
```

### The install itself is still unconfirmed, and now we know exactly why

With `--reboot` the emulator survives the reset, so the run no longer ends there — and
the device comes back up **still running the old version**. The staged image is not
installed. The cause is not in the firmware:

| | |
|---|---|
| PSRAM at the logout call (`--no-secure-die`) | both magics correct, header `start`/`size` point at a byte-identical copy of the offered image |
| the same region after the reboot | seeded noise; no header, no image |

The emulator refills PSRAM at reset — its own reset line says what carries over, and
PSRAM is not in the list: *"flash, secure elements and card carry over"*. So a correctly
staged image is gone before the bootloader ever looks for it, and this is a modelling
gap rather than a defect in the upgrade path.

What that leaves confirmed is everything up to the handover: transfer, validation,
approval, staging, publication of the recovery header, and the reset. What it leaves
open is the bootloader reading that header and installing — which needs either an
emulator that carries PSRAM across a reset, or hardware.

`tools/emu/psramcheck.py` is the check, so this does not have to be re-derived:

```sh
ccemu run ... --no-secure-die --dump-ram ram.bin
tools/emu/psramcheck.py ram.bin --image out/catcard-mk4-v2.bin
```

Offer an image built with a *different* `--version` than the running one. Installing a
byte-identical image over itself cannot be told apart from not installing at all, and an
earlier version of this test reported success for exactly that reason.

## First boot on real mk4 hardware — confirmed

It boots. The selftest screen reads:

```
                CatCard
MK4  7.0.0
HAL  ok
DWT  ok
RNG  ok   832 bit

y  continue            [USB KEYS]
```

That single screen settles a list of things this project could only infer before:

| | |
|---|---|
| SSD1306 on SPI1, `RESET=PA6 DC=PA8 CS=PA4` | the panel draws — mk4 display wiring is right |
| numpad `rows PD8..PD11`, `cols PB0..PB2`, mounted rotated | `y` advances the screen, so the map and the 180° flip are right |
| HSI48 | `HAL ok`, and the RNG cannot assert DRDY without it |
| STM32 TRNG + callgate 26 | `RNG ok 832 bit`: the pool met its policy from real silicon |
| callgate entry discovery at `0x0800_0040` | reached, or there would be no SE entropy and no PIN screen |
| the PIN path, **login branch** | unlocked with a PIN set by the *stock* firmware |
| the keypad map, including the 180° mounting | same — stock chose those digits with its own decoder, so a mirrored map would have submitted different ones |
| header version 7.0.0 | stock staged it, which it refuses below 3 |

**USB was the exception: the idle screen reported `usb down in 0 out 0`,** and the host
saw nothing at all — no `lsusb` entry, nothing in `dmesg` across replugs. That is a
device that never pulled up D+, not a protocol fault.

The cause was `PWR_CR2.USV`. It was being set, but the PWR peripheral's own clock gate
(`RCC_APB1ENR1.PWREN`) is off after reset and was never enabled — and a write to an
unclocked peripheral is discarded with no indication. So VDDUSB was never validated, the
transceiver had no supply, and everything downstream was initialised perfectly and
connected to nothing.

Three things made it invisible until hardware: the emulator does not model APB clock
gating, so the write appeared to work; the register was written but never read back; and
`Otg::init`'s error was discarded by `.ok()?`, so the device could only say "down". All
three are fixed — the gate is enabled and read back, `USV` is verified and returns
`UsbSupplyNotValid` if it will not stick, and the idle screen now prints the reason
beside "down".

**The original text, for the record:** The device never
enumerated, so key injection — the escape route the bring-up build exists for — is inert
on hardware. Not a clock fault (`HAL ok` means HSI48 started) and not VBUS sensing
(`GCCFG_VBDEN` is already cleared with `GOTGCTL` forcing B-session valid, for exactly the
boards that do not route it). Under investigation.

### Three things only a person holding the device could find

None of these are faults the emulator can have an opinion about, and all three came out
of one session with the hardware in hand.

- **The splash was invisible.** Below.
- **The device looked dead after the PIN was confirmed.** `prefix_entered` and `attempt`
  block for as long as the secure element takes, with no redraw and no USB polling in
  between, so the screen simply sat there. The natural response is to press the key
  again — and on the suffix that spends a second PIN attempt, of thirteen. There is now
  a "Checking" screen before each, drawn before the call rather than after it.
- **The keys are labelled ✓ and ✗, not `y` and `x`.** Those are names from our own wiring
  diagram. Every screen that named a key was asking the reader to translate, on a device
  where the key map is precisely what is in doubt. The symbols are drawn now
  (`catcard_ui::icons`), and the arrows printed on `5`, `7`, `8` and `9` are what the
  menu cursor follows.

### The splash was invisible

Bring-up takes a few milliseconds on silicon, so the splash was drawn and overwritten
faster than it could be read. It only ever looked right under the emulator, which is slow
enough to hide the problem — a reminder that emulator timing proves nothing about what a
person can actually see.

`bring_up` now holds the finished splash until at least `SPLASH_MIN_CYCLES` have passed
**since the first splash was drawn**, so the wait is only for the time bring-up did not
already use.

## One image for mk4 and mk5, and it knows which it is on

Coinkite ship a single build for both, which works because `hw_compat` is a bitmask:
`catcard-image build --hw-compat mk4,mk5` declares both bits and verifies as installable
on either while q1 still refuses it. `out/catcard-mk4-mk5.dfu` is that image.

The cost of one image is identity, and it is worth being concrete about: `BOARD` is a
compile-time constant, so a combined image would report whichever board it was compiled
for — an mk5 insisting it was an mk4 on its own screen, in `Identify`, and in every log
taken off it. `STRAP_MK5` (`PE0`, open on mk1-4, pulled low on mk5) settles it in
hardware, and `running_board()` reads it. `Debug → Boot` shows `board mk5 (built mk4)`
when they differ.

Read with our own pull-up, so an open strap reads high and only a board actively pulling
it down reads mk5 — a missing connection cannot be mistaken for a board revision.
Confirmed in the emulator: an mk4 build still reports `board=mk4` over USB.

## mk5 — added as its own board, and driven end to end

mk5 is electrically an mk4: same MCU, pins, PSRAM, secure elements and firmware base,
differing by `STRAP_MK5` (`PE0`, low). `spec::MK5` borrows mk4's definition with `..MK4`
rather than restating it, because a second copy is two places to fix a pin.

What it must not borrow is `hw_compat`. `MK_5_OK` is `0x20`, and the separation is the
entire reason this is a board rather than a flag — verified both ways:

```
$ catcard-image verify out/catcard-mk5.dfu --board mk5
installable   yes, on mk5
$ catcard-image verify out/catcard-mk5.dfu --board mk4
Error: image hw_compat is mk5 but board mk4 needs bit 0x8
```

The emulator runs it with the mk4 factory bootloader, which is right — the two share a
board definition — and the full drive test passes: enumerate, first PIN, unlock, offer a
256 KB image, approve, reset.

Adding it also turned up a shape problem. `build.rs` matched a tuple of board features,
which grew a dimension per board; adding mk5 to the spec table and the features gave
"no board selected" for a board that plainly existed. It reads `spec::ALL` now, so a new
board is one spec and one feature. The same applied to the "exactly one board" check in
`lib.rs`, which enumerated pairs.

## mk3 in the emulator — confirmed, except the PIN

The older mk3 releases carry a bootloader alongside the firmware, so mk3 emulates like
mk4 does; only the *factory* naming suggested otherwise. `tools/emu/drive.sh <boot.dfu>
mk3` runs the same test.

```
ping      status=Ok echo=b'cat'
identify  status=Ok protocol=1 board=mk3 version=7.0.0 unlocked=False blank=False
identify  key injection available
identify  device cannot stage an upgrade (no staging area wired up)
```

Confirmed by screenshot with `--tap`: the selftest screen draws `MK3 7.0.0 / HAL ok /
DWT ok / RNG ok 832 bit`, `✓` advances to **PIN prefix**, and entering a prefix reaches
the **anti-phishing words** — so callgate 16 works through the mk3 bootloader, whose
entry is at a different address (`0x0800_0305`, protocol `0x0100`).

Not confirmed: a successful login. The emulator's mk3 secure element reports a PIN is
set and we do not know it, so the drive test stops at a wrong-PIN. That is emulator
state rather than firmware behaviour — `is_blank()` reads the bootloader's own PIN
struct and is not board-specific.

### USB used to be off on mk3 entirely

`usbtask::init` returned early when the board had no PSRAM, on the reasoning that there
was nowhere to stage an upgrade so nothing to serve. The effect was that mk3 brought up
no USB at all: no enumeration, no diagnostics, no injected keys.

That is the condition that stranded the mk4, except guaranteed rather than accidental —
and it would have been the state of the *next* board to be flashed. A device that cannot
be upgraded is precisely the one worth being able to reach, so USB now comes up
regardless and the offer is what gets refused, with a reason (`NoStagingArea`) and a
capability bit so a host knows before sending 256 KB.

## The whole device driven over USB, with nothing touching the keypad — confirmed

Insurance for the first run on real hardware, where the keypad map is inferred from
photographs and the pad is mounted rotated 180°. A wrong map on a **locked production
unit** means no PIN can be typed, no menu reached, and no firmware installed to fix it.

```
ping      status=Ok echo=b'cat'
identify  status=Ok protocol=1 board=mk4 version=0.0.1 unlocked=False blank=False
identify  key injection available
setup     device is blank, setting a first PIN
unlocked  True running=0.0.1
offer     status=Ok verified=True len=262144
approved  device stopped answering: it reset to install
```

No `--tap`, no `--press`. Selftest screen, first-PIN setup, anti-phishing words, login,
a 256 KB upgrade and its approval — every keypress arriving over USB.

### A `.dfu` can be offered directly — confirmed

The device takes a raw signed image and knows nothing about DfuSe; the client unwraps
the container before sending. Verified both ways: the bytes extracted from a `.dfu` are
identical to the `.bin` built from the same ELF, a `.bin` passes through untouched, a
container with one flipped byte is refused on the suffix CRC rather than truncated, and
the full drive test passes offering a `.dfu` over the wire:

```
image     unwrapped DfuSe: 262144 bytes for 0x08020000
offer     status=Ok verified=True len=262144
approved  device stopped answering: it reset to install
```

So the file flashed through stock and the file offered to CatCard are the same file,
without the firmware growing a parser for a container format. That parser is reachable
by anything that can open the port, which is the reason to keep it small.

### What driving it found that offering an image did not

- **`Identify` said nothing about which screen you are on.** A host that cannot see the
  panel had to infer it from what its keys did. "Not unlocked" is two different devices —
  one wanting a PIN, one wanting to be *given* one — so the reply now carries a state
  byte. The emulator's secure element is blank, which is the case the host was silently
  getting wrong.
- **A reply waited for the next poll to go out.** `drain_outbox` ran only at the start of
  a poll, so the acknowledgement for a key that sent the firmware into a callgate call —
  choosing a PIN, fetching the words, logging in — sat in the outbox for the length of a
  secure element operation. From the host that is indistinguishable from a dead device.
  The poll that handles a report now drains the reply too.
- **The host waited out a boot-sized timeout for a stall.** One timeout covered both the
  first reply (which waits on the bootloader, a signature check and a 25-second warning
  screen) and every later one (which should be immediate). Now the client tightens it
  once the device has answered, so a stall is visible in seconds and points at the key
  that caused it.
- **The approval press expected a reply that by design never comes.** It is the key that
  reboots the device. Waiting for it hung the host against a device behaving correctly.
- **"Approved" was printed from having sent a byte.** The device going quiet is the first
  actual evidence the key landed; the client now waits for that.

### A parked device used to be unreachable — confirmed fixed

`usbtask::init` ran *after* the checks that park the device, and `park` was a `wfi`
loop. So a dead panel, a keypad that would not initialise, an entropy pool that missed
its policy, or an unreachable callgate all parked with USB never started: no
enumeration, no injection, no diagnostics. Those are the exact bring-up failures where a
host is the only way in, and they were the ones that got nothing.

USB now comes up before the park branches, and `park` pumps it. Verified by forcing the
panel to `None` in a throwaway build:

```
ping      status=Ok echo=b'cat'
identify  status=Ok board=mk4 version=0.0.1 unlocked=False blank=False
offer     status=NotNow  (expected NotNow)
```

The last line matters as much as the first two. A parked device is reachable and
identifiable, but **not flashable**: `unlocked` is never called on that path, so an
upgrade is still refused. Opening it would let anyone holding a locked device install a
dev-signed firmware of their own — signing with the published developer key is something
anyone can do — without ever knowing the PIN. That firmware would then be in a position
to capture the PIN when it is typed.

### The feature is opt-in, and `default` was a lie

`usb-key-injection` was in `[features] default`, which never applied: every firmware
build goes through the `fw-*` aliases and those pass `--no-default-features`. It read as
"on at this stage" while shipping nothing — the first image tested this way had no key
injection compiled in at all. It is now out of `default`, with `fw-*-bringup` aliases as
the only way to enable it, so turning it on is always a visible choice.

### What the USB work cost, and why the tools exist

Five defects, four in the driver. Every one was found by reading state back, and none
was visible from the code:

| | |
|---|---|
| `SNAK`/`CNAK` reissued by read-modify-write | endpoint enables carried a contradictory NAK command |
| global OUT NAK never cleared | `CGONAK` was simply absent beside `CGINAK` |
| `clear_bits` on a write-1 command bit | dead code posing as reset handling |
| poll loop with no pause | delivered no reports at all |
| downgrade refused rather than reported | made a return to stock firmware impossible |

`tools/emu/usbstatus.py` reads a status block out of a RAM dump: counters, the last
status code, and `DOEPCTL`/`DOEPTSIZ`/`DIEPCTL`/`DCTL`. It exists because **the emulator
emits no screens at all in `--usb-hid` mode**, which is the only mode our own protocol
can be driven in — so the screen, the natural place for a diagnostic, is unreadable
exactly where it is needed.

Building that first would have saved most of the effort. Several rounds were spent
reasoning about what the code should do, including one fix committed without validation
that regressed enumeration and had to be reverted. The register dump answered the
question in a single run.

## Test doubles must refuse what the hardware refuses

A double that is more permissive than the thing it stands in for does not merely fail to
catch a bug — it manufactures confidence. Every one of these was written to make a test
pass and quietly stopped testing anything:

| double | let through | what it cost |
|---|---|---|
| `Model` (callgate 18) | `validate` checked a counter and ignored the PIN field | **login could never have worked on hardware**; every test passed |
| `MockMatrix` | reading columns without settling | deleting `settle()` from the scanner broke nothing |
| `MockNor` | commands while the part is busy | deleting `wait_ready()` broke nothing |

The rule this leaves: **a double enforces every precondition the real part enforces**, and
where that is not practical, the gap is written down rather than left to be discovered.

The check that matters is whether an assertion ever fires. Both of the above were
verified by breaking the driver on purpose and confirming the tests fail — dropping
`settle()` produces 21 failures, dropping `wait_ready()` produces 11. An assertion that
has never been seen to fail is not yet evidence of anything.

Doubles that were already faithful, for the record: `MockStorage` models an erase
followed by a partial rewrite, which is what an interrupted flash write leaves;
`MockBus` records call order so an ordering bug is visible; the staging double in
`catcard-upgrade` can corrupt a read-back and can accept a marker without keeping it.
`catcard-entropy` has no double at all — its health tests reject all-zero, all-ones, long
runs, biased sources and short samples, which is the same property from the other side.

## Recording the results

Every `[?]` this session resolves should move out of `HARDWARE-OPEN-ITEMS.md` and into
the board table with a `[C]` tag and a note saying it was confirmed on hardware rather
than read from a document. Confidence tags are how the next person knows what to trust.
