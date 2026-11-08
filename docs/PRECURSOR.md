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

**Status: a working wallet for one power cycle.** New (12/24 words from both TRNG
sources), Import, Addresses with QR codes (segwit, taproot, nested, legacy), Export xpub,
View seed words and Sign PSBT, all on the device's own screen and keyboard -- checked
against the BIP-44/49/84/86 test vectors, and a signed PSBT byte-identical to the host
library's. Not yet: storage (the wallet is forgotten at reset), a PIN, USB (PSBTs come
over the debug UART for now). **Not for funds.** The image runs from SRAM on a bench unit: it takes over from
Xous, feeds the watchdog, prints on the UART and draws a test card, which comes out the
right way up. No wallet yet.

[betrusted-soc]: https://github.com/betrusted-io/betrusted-soc
[Xous]: https://github.com/betrusted-io/xous-core

## Milestones

1. **Board layer and toolchain** -- RV32IMAC image entered from SRAM, UART, LCD,
   watchdog, timer. Done.
2. The gateware TRNG as two entropy sources for `catcard-entropy` (done, see "TRNG");
   catcard-ui on the 336x536 panel (done, see "Screens"); keyboard (done, see
   "Keyboard"); seed creation, not yet stored.
3. Menus and wallet flows that need no storage.
4. Storage on the SPI-NOR under a key-ROM device secret and a passphrase; see
   `docs/PRECURSOR-KEYS.md`. In progress: `catcard-bitstream` rewrites the gateware.
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

## Recovery

Two independent ways back, both tested on the bench unit (2026-11-06):

- **USB debug bridge** (as long as the stock gateware configures): `usb_update.py`
  halts the CPU through the debug port whatever firmware is running, and rewrites any
  flash region -- the loader slot back to Xous, for instance.
- **JTAG, with no working gateware at all**: OpenOCD on the debug hat loads
  betrusted-scripts' `bscan_spi_xc7s50.bit` (a JTAG-to-SPI bridge) into the FPGA and
  reaches the flash (Macronix MX66UM1G45G) through it: probed, and the first 4 KiB read
  back identical to the backup in 81 ms. Load the bridge with `pld load` and probe by
  hand -- `jtagspi_init` issues `reset halt`, which on a setup where reset is PROG_B
  wipes the bridge it has just loaded.

**Power trap.** While the FPGA is unconfigured nothing drives `fpga_sys_on`, and after
roughly half a minute the EC powers the board off; only the power key (top-left) brings
it back -- not an EC reset, not cycling USB power. Loading a full SoC bitstream over the
hat's GPIO JTAG takes ~30 s, so test a new gateware by writing it to flash and booting
it, not by a long JTAG load. Short loads (the bridge, test designs) are fine.

## Gateware v0.9.14 and USB (next)

Both the bench unit's v0.9.5 and the published v0.9.14 `soc_csr.bin` are **encrypted**
bitstreams (each carries the AES CBC IV write), and the unit boots its own, so its FPGA
holds the matching key -- presumably the dummy key betrusted's CI builds with. Plain
bitstreams load too. Whether v0.9.14's image configures on this unit is not known yet:
the JTAG test of it ended in the power trap above.

USB on this board needs, in order:

1. Gateware v0.9.14 (or later) in flash -- the first release with the SpinalHDL
   `usbdev` core. Plan: write it with `usb_update.py -i soc_csr.bin 0x0 --verify`, with
   the JTAG path above as the way back if it does not configure. Xous's kernel in flash
   would then mismatch it, which does not matter while CatCard is the loader.
2. A driver for SpinalHDL's `UsbDeviceCtrl` (`usbdev` region, 64 KiB at 0xE004_0000):
   16 endpoint status words at the base, setup packet at +0x40, transfer descriptors
   chained in the core's RAM, control registers at +0xFF00 (frame, address, interrupts,
   halt, config/pull-up, RAM size). Register model: SpinalHDL's UsbDeviceCtrl docs and
   xous-core `services/usb-device-xous/src/spinal_udc.rs`. In v0.9.14 a mux switches the
   pins between this core and the debug bridge -- while CatCard is a USB device the
   bridge, and `run.py`, are gone; JTAG and the UART remain.
3. CatCard's HID transport (`catcard-usb`) and its command handlers. catcard-fw's are
   written against its STM32 driver and its menus (`usbtask.rs`), so they need the same
   separation from the board the wallet flows here got. Sign PSBT would then take its
   PSBT over USB instead of the UART; nothing else about it changes.

## Storage and PIN

Chosen 2026-11-08: a device secret in the key ROM of gateware encrypted to a BBRAM key
this unit generates, mixed with the owner's passphrase by Argon2id. See
`docs/PRECURSOR-KEYS.md` for the facts it rests on, the threat table and the staged plan.
Until it lands the wallet is per power cycle.

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

## The wallet

`src/app.rs` holds the menus; flows are built on the portable crates rather than on
catcard-fw's menus, which are written against the Coldcard boards.

- **New**: `src/newseed.rs` reads 2 KiB from each noise source into a fresh pool with
  the start-up test enforced, and draws 16 or 32 bytes; a pool that has not earned it
  refuses and the screen says why. Words are shown a page at a time and never sent to
  the UART.
- **Import**: type a few letters per word, pick from the BIP-39 matches, checksum
  checked by `Mnemonic::parse`.
- **Session** (`src/session.rs`): the mnemonic and master key, zeroized on Logout. All
  private-key work goes through `src/keywork.rs`, which masks interrupts (`mstatus.MIE`)
  and lends catcard-wallet its `KeyWork` token.
- **Addresses / Export xpub**: account 0 of BIP-84/86/49/44, receive addresses 0-19,
  QR codes drawn for this panel (portrait, dark modules on a light quiet zone).
- **Sign PSBT** (`src/sign.rs`): catcard-wallet's `summarise` and `destinations` for the
  review -- amounts proven against the previous transaction (a bare `witness_utxo` is
  refused), change proven by re-deriving it, the fee policy -- then `sign_input_under`
  for every input that is ours. Transport for now: one line of hex on the debug UART,
  answered with `signed <hex>`. USB would replace only that part.

Checked on the bench unit (BIP-84 test mnemonic, imported by UART-driven keys):
fingerprint `73c5da0a`; `m/84'/0'/0'/0/0` `bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu`,
`m/86'/0'/0'/0/0` `bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr`,
`m/49'/...` `37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf`, `m/44'/...`
`1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA`, account xpub `xpub6CatWdiZ...PW6V` -- all as the
BIPs publish; the QR codes decode (zbar) to the same strings; a PSBT spending
`m/84'/0'/0'/0/0` with change to `/1/0` reviews correctly and its signed form is
byte-identical to catcard-wallet's on the host.

**Bench crutches** (default features, never in an image for anyone else): `uart-keys`,
UART bytes as key presses (`tools/precursor/drive.py` sends them). Build without:
`cargo fw-precursor --no-default-features --features gw-v0_9_5`.

## Screens

The screens are catcard-ui's own -- `widgets::menu`, `info`, `message` -- drawn into
`catcard_ui::memlcd::MemLcd`, a canvas in the panel's native framebuffer layout, and
copied out by `lcd::show` (one full update, ~100 ms). `Layout::large()` is `roomy()`'s
faces doubled through `face::Scaled` (20x40 titles over 14x28 body text): at 200 ppi
unscaled 7x14 is under a millimetre wide. It fits 23 columns and fifteen menu rows.

Boot currently shows a splash, the entropy self-test's verdicts, then a blank device's
main menu (New, Import, Utils, Settings, Help), driven by the keyboard; items open a
placeholder until their flows exist here.

`tools/precursor/screenshot.py` reads the framebuffer back over the USB bridge and writes
a PBM, so what is on the panel can be checked without being at the bench (it shows what
was sent, not what the gateware overlays -- the devboot line is not in it).

## Keyboard

The gateware scans and debounces the 9x10 matrix and publishes a column mask per row
(`keyboard_row0dat..8dat`); `src/kbd.rs` reads the nine words, and
`catcard_ui::precursorkeys` turns changes into the screens' `Event`s. Which key is where
was established twice, independently: on the bench unit, every key pressed once in reading
order with its position logged, and Xous's own QWERTY map -- all 54 agree.

Meaning follows the Q1's convention so every existing screen works unchanged: the number
row types digits, letters type characters, the navigation pad's arrows act as the
numpad's arrow digits (5 up, 8 down, 7 left, 9 right), its centre and ENTER confirm,
backspace cancels. F1-F4, the shifts, SYM and the emoji key are scanned but mean nothing
yet. Unlike the Q1 there is no scan order for firmware to shuffle: the gateware drives it.

```text
Tab/F1/pwr F2   [pad]   F3  F4/Ctrl/pwr     (8,0) (8,1)         (3,8) (3,9)
pad: up (6,4) down (8,2) left (8,3) right (3,6) centre (5,2)
1-5 (0,0..4)   6-0 (4,5..9)
q-t (1,0..4)   y-p (5,5..9)
a-g (2,0..4)   h-l, backspace (6,5..9)
!,z-v (3,0..4) b-m, ?, enter (7,5..9)
shift SYM space emoji shift (8,5..9)
```

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
Ed25519 signature over the loader slot and jumps to it. It tries the device's
self-signing key, then a third-party key, then the developer key, and marks the screen
with a strike-through when it boots on anything but a self-signing key.

`tools/precursor/mkloader.py IMAGE.bin KEY.pem OUT.bin` packages the same SRAM image
`run.py` loads for that slot:

```text
flash 0x500000  SignatureInFlash { version 1, signed_len, Ed25519 signature }   (4 KiB page)
flash 0x501000  64-byte stub | IMAGE.bin | version (1) | signed_len - 4
```

The stub copies the image into SRAM at `0x4000_0000`, runs `fence.i` and jumps there, so
what boots from flash is byte for byte what `run.py` runs. Written with stock tooling:

```sh
sudo python3 usb_update.py -i catcard-loader.bin 0x500000 --verify
```

(betrusted-scripts `usb_update.py`: halts the CPU over the debug bridge, erases and
programs only the blocks the image covers, reads them back, resets the SoC.)

The bench unit boots on the **developer key** (`1c9beae3...58bb`, the public half of
betrusted-soc's `devkey/dev.key`): its root keys were never initialised. Signed with that
key, CatCard boots on it -- done on 2026-11-06: boot ROM "Signature check passed", then
CatCard, from a SoC reset and from a full FPGA reload (PROG_B). Without Xous nothing arms
the watchdog, and CatCard does not arm it either. The strike-through stays, as it should:
the screen is telling the truth about which key the boot was signed with.

**Restoring Xous** is writing the original loader slot back: `0x500000`-`0x980000` of a
backup of the unit's flash, with the same command. Nothing else was changed -- gateware,
kernel and the PDDB are where Xous left them. Take the backup first (tools in
precursor_pvt2/tools: `flash_dump.py`, resumable in 8 MiB segments, each read twice).

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
| keyboard | 9x10 matrix, gateware-scanned, one column mask per row; map above | keyboard.py [C]; key test + xous qwerty.rs [C] |
