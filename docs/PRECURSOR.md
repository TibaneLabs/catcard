# CatCard on the Precursor

The [Precursor](https://www.crowdsupply.com/sutajio-kosagi/precursor) (pvt2) is an open
hardware handheld: a Xilinx Spartan-7 FPGA running a VexRiscv RV32IMAC SoC at 100 MHz,
16 MiB of external SRAM, 128 MiB of SPI-NOR, a 336x536 Sharp memory LCD, a physical
QWERTY keyboard and a TRNG. Its gateware ([betrusted-soc]) and OS ([Xous]) are open.

This branch runs CatCard on it **bare metal, on the stock gateware**: no FPGA changes,
Xous replaced. It is not a Coldcard board and shares no hardware with one -- no secure
element, no Coldcard bootloader, no callgate -- so it is its own crate,
`crates/catcard-precursor`, built on the portable crates, rather than a `catcard-fw`
board feature.

**Status: milestone 1 done; milestone 2 under way (TRNG and UI done, keyboard next).** The image runs from SRAM on a bench unit: it takes over from
Xous, feeds the watchdog, prints on the UART and draws a test card, which comes out the
right way up. No wallet yet.

[betrusted-soc]: https://github.com/betrusted-io/betrusted-soc
[Xous]: https://github.com/betrusted-io/xous-core

## Milestones

1. **Board layer and toolchain** -- RV32IMAC image entered from SRAM, UART, LCD,
   watchdog, timer. Done.
2. The gateware TRNG as two entropy sources for `catcard-entropy` (done, see "TRNG");
   catcard-ui on the 336x536 panel (done, see "Screens"); keyboard; seed creation, not
   yet stored.
3. Menus and wallet flows that need no storage.
4. Storage on the SPI-NOR and a PIN / secret design. Precursor has no secure element, so
   this is a real design decision (FPGA key ROM, BBRAM key, PIN-stretched keys), taken
   then, not now.
5. Boot from flash in place of the Xous loader. The boot ROM verifies the loader slot
   with Ed25519; see "Booting from flash".
6. USB HID and FIDO. Needs gateware v0.9.14 or later; see "Gateware".

## Gateware

Every betrusted-soc build emits a `csr.csv` listing each control register, and stores it
inside the bitstream image at offset `0x277000` (length-prefixed, SHA-512 trailer), so a
device's own description can be read off its flash. `crates/catcard-precursor/gateware/`
carries two, and `build.rs` generates the register table from the one selected:

| feature | release | why |
|---|---|---|
| `gw-v0_9_5` (default) | v0.9.5-0-gb6dd1f7 | what the bench unit runs |
| `gw-v0_9_14` | v0.9.14-0-gd6be7b4 | current stable; first with the `usbdev` USB device core |

Addresses move between releases -- v0.9.14 put `usbdev` where v0.9.5 had `d11ctime` --
which is why nothing is hand-copied. The UART, timer, watchdog and LCD registers happen
to be identical in both.

v0.9.5 has no USB device core: its only USB function is the debug bridge. In v0.9.14 a mux
switches the pins between the bridge and `usbdev`, so while CatCard is a USB device the
bridge (and the development loop below) is gone; JTAG and the UART remain.

## Development loop (no flash writes)

```sh
cargo fw-precursor
llvm-objcopy -O binary target/riscv32imac-unknown-none-elf/release/catcard-precursor out/precursor.bin
# on the machine the Precursor is plugged into:
sudo python3 -I tools/precursor/run.py out/precursor.bin --seconds 10
```

`run.py` resets and holds the CPU through the VexRiscv debug port (machine mode, MMU
off), writes the image into SRAM at `0x4000_0000` over the USB debug bridge, verifies it,
injects a jump to the entry point and lets go, then prints the UART. The stock firmware
comes back on any SoC reset: a PROG_B pulse from the debug hat, or the watchdog.

It feeds the watchdog itself because Xous arms it and it cannot be disarmed: a CPU held
for a GDB load would be reset under the debugger 2.5-7.5 s later.

The debug hat carries the gateware's UART (115200 8N1) to the Raspberry Pi's
`/dev/ttyAMA0`, so output is readable without anyone at the bench.

## Screens

The screens are catcard-ui's own -- `widgets::menu`, `info`, `message` -- drawn into
`catcard_ui::memlcd::MemLcd`, a canvas in the panel's native framebuffer layout, and
copied out by `lcd::show` (one full update, ~100 ms). `Layout::large()` is `roomy()`'s
faces doubled through `face::Scaled` (20x40 titles over 14x28 body text): at 200 ppi
unscaled 7x14 is under a millimetre wide. It fits 23 columns and fifteen menu rows.

Boot currently shows a splash, the entropy self-test's verdicts, then a blank device's
main menu (New, Import, Utils, Settings, Help), not yet wired to keys.

`tools/precursor/screenshot.py` reads the framebuffer back over the USB bridge and writes
a PBM, so what is on the panel can be checked without being at the bench (it shows what
was sent, not what the gateware overlays -- the devboot line is not in it).

## TRNG

The gateware has two noise sources -- an avalanche diode sampled by the XADC and a bank of
ring oscillators -- each folded into 32-bit words and run through NIST SP 800-90B
repetition-count and adaptive-proportion tests in gateware, feeding a FIFO.

Its default output is the two XORed, refilled whenever **either** passes its tests: a dead
source would be carried silently by the other. So `src/trng.rs` reads them **apart**
(the `ro_dis` / `av_dis` control bits), and the pool absorbs them as two hardware sources,
`PrecursorAvalanche` and `PrecursorRingOsc`, each through `catcard-entropy`'s own start-up
and continuous tests. `Policy::precursor()` demands both and 256 credited bits.

One trap, found on the bench unit and documented in `trng.rs`: the gateware's `clr_err`
also resets its tests' readiness, and the avalanche tests only sample while a refill is
consuming words. Pulse `clr_err` (or let the source power down) with one source selected
alone and nothing can start a refill again -- a permanent stall. Errors are cleared, and
readiness rebuilt, with both sources on; then one is selected.

The boot self-test (`src/rngcheck.rs`) on the bench unit, three runs in a row:

| | warm-up | rate | start-up test | test sample (4 KiB, not absorbed) |
|---|---|---|---|---|
| avalanche | 51 ms from power-down (the 50 ms power-on delay) | ~58 KB/s | passed, 0 trips | ones 49.7-50.0 %, chi2 224-232 (df 255) |
| ring-osc | 1-2 ms | ~85 KB/s | passed, 0 trips | ones 49.4-50.1 %, chi2 236-261 (df 255) |

With the avalanche source stalled (before the fix above) the pool refused the draw --
"1 hardware TRNG(s) contributed, need 2" -- which is the behaviour the design is for.

## Booting from flash

The CPU resets into a 64 KiB boot ROM in the gateware (`0x8000_0000`), which checks an
Ed25519 signature over the loader slot (signature at `0x2050_0000`, image at
`0x2050_1000`) before jumping to it. It tries the device's self-signing key, then a
third-party key, then the developer key, and marks the screen with a strike-through when
it boots on anything but a self-signing key.

The bench unit boots with the **developer key** (`1c9beae3...58bb`, the public half of
betrusted-soc's `devkey/dev.key`, read off its boot log), i.e. root keys were never
initialised. A CatCard image signed with that published key will boot on it, with the
strike-through. Nothing is written to flash before milestone 5, and not before a verified
full backup of the unit exists.

## Hardware facts and their sources

Precursor sources are open (betrusted-soc and gateware: CERN-OHL / Apache-2.0), so they
are usable as hardware documentation; `CLEANROOM.md` constrains Coldcard sources only.
Facts are tagged as elsewhere in the repo.

| fact | value | source |
|---|---|---|
| CPU | VexRiscv RV32IMAC, 100 MHz, reset vector `0x8000_0000` | csr.csv constants [C] |
| SRAM | `0x4000_0000`, 16 MiB, cached | csr.csv `memory_region,sram_ext` [C] |
| UART to the hat | V6/V7, 115200 8N1; mux `gpio_uartsel` 0 = `uart`, 1 = `console` | betrusted_soc.py [C]; read on the Pi [C] |
| ticktimer | `+0x04` high word, `+0x08` low word, 1 ms per tick | csr.csv [C]; measured on the unit [C] |
| watchdog | armed by Xous (`wdt_state = 0x9`), cannot be disarmed, ~2.5-7.5 s; feed = write 1 | wdt.py [C]; read on the unit [C] |
| LCD | 336x536, 11 words per line, 1 = white, `UpdateAll` = command bit 1, `Busy` bit 0 | memlcd.py [C] |
| LCD pixel placement | (x, y) top-left origin = bit `x % 32` of word `y * 11 + x / 32` | memlcd.py + test card on the unit [C] |
| devboot marker | dashed line forced on framebuffer line 7 after a developer-key boot | memlcd.py [C]; seen on the unit [C] |
| boot key | developer key `1c9beae3...58bb` | boot ROM log on the unit [C] |
| TRNG output | `merged = av ^ ro`, single source when the other is disabled; refill gated on `av_pass \| ro_pass` | trng_managed.py [C] |
| TRNG `clr_err` | resets test readiness; with one source selected, stalls refills for good | trng_managed.py [C]; bench unit [C] |
| TRNG rates | avalanche ~58 KB/s after 51 ms power-up, rings ~85 KB/s | bench unit [C] |
