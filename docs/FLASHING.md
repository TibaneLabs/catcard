# Getting CatCard onto a device

Four routes, in order of how likely they are to apply to you.

> **The header version must be at least 3.0.0.** Stock firmware refuses to stage
> anything below that, and routes 1 and 2 both go through stock's uploader. The refusal
> happens on the device, after the transfer, and does not mention versions — so it is
> worth getting right rather than diagnosing. CatCard's version is **7.0.0**, which is
> the workspace version and therefore also what the running firmware reports about
> itself; `catcard-image build` warns if it is ever handed something lower.
>
> Every route below installs an image signed with the **published developer key**. The
> device will boot it with a 25-second warning screen and leave the "genuine" light red.
> That is not a bug — it is the bootloader correctly reporting that the image is not
> signed by a Coinkite production key. Anyone can sign with the dev key, so a dev-signed
> image is not attributable to any author, including this project.

---

## 1. USB, on a locked production unit

Works on any unit, including RDP=2. Needs the vendor's `ckcc-protocol` tool on the host
and a device running **stock** firmware, unlocked with its PIN — stock's own uploader is
doing the work, so this route stops being available the moment CatCard is installed (see
*Recovering* below for what replaces it).

```sh
cargo fw-mk4-bringup        # see "Flash the bring-up build first" below
cargo run -p catcard-image -- build \
    target/thumbv7em-none-eabihf/release/catcard-fw \
    --board mk4 --version 7.0.0 \
    --dfu out/catcard-mk4.dfu
```

Then push `out/catcard-mk4.dfu` with the vendor tool's firmware-upgrade command — consult
its own `--help` rather than anything here, since the invocation is theirs to define.
Stock uploads the image, stages it, asks for confirmation on the device's screen, and
reboots; the bootloader verifies the signature and installs.

**We use that tool as a black box.** The stock `ckcc` protocol is deliberately not
implemented and deliberately not studied — see [`../CLEANROOM.md`](../CLEANROOM.md).
Running the vendor's own binary to move a file is not studying it; reading it to learn
the wire format would be.

**The one thing we cannot tell you** is whether stock's uploader applies checks of its
own before handing the image to the bootloader. The *bootloader* accepts a dev-signed
image with a warning — that is confirmed against the real one. What stock does first is
not something we have verified, and not something we will read its source to find out.
If it refuses the image, use the microSD route below; the bootloader behaves identically
either way.

---

## 2. microSD, on a locked production unit

Works on any unit, including RDP=2, and needs no host tooling or debug hardware. Slow
loop: rebuild, copy, navigate the menu, reboot.

```sh
cargo fw-mk4
cargo run -p catcard-image -- build \
    target/thumbv7em-none-eabihf/release/catcard-fw \
    --board mk4 --version 7.0.0 \
    --dfu /media/sdcard/catcard-mk4.dfu
```

On the device running **stock** firmware: *Advanced → Upgrade Firmware → From SD Card*.
The stock firmware stages the image and reboots; the bootloader installs it into main
flash and verifies the signature. Where it stages differs by generation — SPI-NOR on
mk3, PSRAM on mk4 and later, which has no SPI-NOR at all.

**Recovering.** CatCard now has its own USB upgrade path: it accepts a complete signed
image over HID, stages it, and installs it after someone approves it at the device. That
includes the stock firmware, so the route back exists without the DFU button or an
unlocked bootloader — an older image is warned about, not refused, because returning to
stock is a legitimate thing to want. The bootloader's OTP high-water mark still has the
final say; see [`--high-water`](#--high-water) for the one way to lose that route
permanently.

**Still: do not install this on a device you rely on.** The upgrade path is verified in
the emulator, not yet on hardware.

---

## 3. SWD, on an unlocked unit

The fast loop, and the only one that gives you a debugger. Requires RDP < 2 and access to
the SWD pads.

```sh
cargo install probe-rs-tools
probe-rs run --chip STM32L4S5VI \
    target/thumbv7em-none-eabihf/release/catcard-fw
```

Chip names: `STM32L496RG` for mk3, `STM32L4S5VI` for mk4/Q1 — confirm the exact part
marking on your board.

Flashing the ELF directly writes to `0x0802_0000` and skips the bootloader's install
path entirely, so **the signature is not checked and the header is not required**. That
is convenient for iteration and misleading for validation: always test a real signed
image through route 1 or 3 before believing an image is loadable.

Reading the boot result without a display:

```sh
probe-rs attach --chip STM32L4S5VI target/thumbv7em-none-eabihf/release/catcard-fw
# then read the `CATCARD_BOOT_STATUS` symbol; magic should be 0xCA7CA2D0
```

Its fields are `magic, hal_ok, entropy_ok, credited_bits, dwt_running`
(`crates/catcard-fw/src/selftest.rs`).

---

## 4. ST USB-DFU, on an unlocked unit

The bootloader exposes ST's factory DFU (system ROM at `0x1FFF_0000`) on RDP < 2 units.
The device appears as `0483:df11`.

```sh
cargo run -p catcard-image -- build ... --bin out/catcard-mk4.bin
dfu-util -a 0 -s 0x08020000:leave -D out/catcard-mk4.bin
```

Write the **`.bin`**, not the `.dfu`, at the firmware base address — `dfu-util` takes the
address on the command line, so the DfuSe wrapper adds nothing here.

On locked (RDP=2) units USB-DFU is refused, and callgate 2 locks the device up rather
than entering it.

---

## mk5: the same trap as mk4, for the same reason

mk5 is an mk4 board revision and shares its upgrade path: staging into PSRAM, which
means **OCTOSPI, which this firmware never configures** (see
[`HARDWARE-OPEN-ITEMS.md`](HARDWARE-OPEN-ITEMS.md)). So the `UpgradeOffer` path answers
and reports success right up to the reboot, and whether the bootloader then finds
anything is unknown — the emulator maps PSRAM unconditionally and cannot answer it.

It may work: the bootloader reads a staged image from PSRAM itself, so it configures
OCTOSPI at boot, and if it leaves that mapping in place the firmware inherits it.
**`Debug → PSRAM` reports what is actually true on the device**, and is worth looking at
before trusting the upgrade path with the only route back.

Until that is confirmed, treat an mk5 exactly like an mk4: on a locked (RDP=2) unit,
assume flashing is one-way. `Debug → Enter DFU` is the only exit and the bootloader
refuses it on RDP=2.

---

## mk3: there is no way back yet

**Read this before flashing an mk3.** mk3 stages a firmware upgrade in SPI-NOR flash,
and this firmware cannot write it: `SflashPins.cs` is `None`, because the chip select is
not stated in the reference. So CatCard on an mk3 **cannot install any firmware, including
stock**. USB comes up and answers everything else; `UpgradeOffer` is refused outright
with `NoStagingArea`, which the host is told about in `Identify` before it sends anything.

That leaves exactly one route off an mk3 running CatCard: *Debug → Enter DFU*, which asks
the bootloader for `DfuMode::Normal`. **The bootloader refuses that on RDP=2**, so:

- **Unlocked mk3** — recoverable. DFU or SWD puts stock back.
- **Locked (RDP=2) mk3** — a one-way trip, exactly as an mk4 was.

This is the same trap that stranded the first mk4, and it is worth saying plainly rather
than discovering twice. Use a unit you can afford to leave on CatCard until the SPI-NOR
driver exists.

---

## Flash the bring-up build first, not the plain one

On a **locked production unit**, decide this before you install anything. The keypad map
is inferred from board photographs and the pad is mounted rotated 180°, so a mirrored map
is not a far-fetched failure — it is what you get if the inference is off.

If it is wrong you cannot type the PIN, cannot reach anything, and cannot install a
firmware that would fix it, because approving an install is itself a keypress. Checking
the map once the firmware is on the device tells you that you are stuck; it does not get
you out. The only thing that gets you out has to already be in the image:

```sh
cargo fw-mk4-bringup          # adds `usb-key-injection`
```

That build lets a host press keys over USB, so a mirrored map or a dead panel costs you
convenience instead of the device. USB comes up during bring-up — before the selftest
screen, before the PIN, and before the checks that park a device that cannot show or read
anything — so a host can drive it even when the front panel is useless. Verify it works
against the emulator before you rely on it:

```sh
tools/emu/drive.sh <factory-bootloader.dfu>
```

The same client drives the real device once it is running — same protocol code, only the
transport differs:

```sh
tools/usbclient.py hid                          # ping + identify, to see it at all
tools/usbclient.py hid out/x.bin --drive --expect-install
```

`/dev/hidraw*` is root-only until you add a udev rule; see
[`USB.md`](USB.md#talking-to-a-real-device).

It also means a host can approve its own firmware upgrade, which is why it must not
outlive bring-up — see [`USB.md`](USB.md#key-injection-a-bring-up-crutch-with-an-expiry-date).
The selftest screen shows `[USB KEYS]` whenever it is compiled in.

### Then check the map, to avoid bricking the secure element

Once it is running, the selftest screen draws each key as you press it, before any PIN is
involved. This is worth doing even though it is only a diagnosis: **thirteen wrong PIN
attempts brick the secure element**, so discovering a mirrored map by typing a PIN into
it is the expensive way to find out.

1. Press each digit `0`–`9` and confirm the screen shows the digit you pressed.
2. Confirm `x` and `y` are where the labels say, and not swapped.
3. If either is wrong, stop — drive the device over USB and do not type a PIN.

---

## Verifying before you flash

`catcard-image` re-runs every check the bootloader makes that can be reproduced off the
device:

```sh
cargo run -p catcard-image -- verify out/catcard-mk4.bin --board mk4
```

It checks the header magic, `pubkey_num` range, 512-alignment, that `firmware_length`
matches the file, that the timestamp is valid BCD, that the signature verifies against
the dev public key, and that `hw_compat` permits the board.

It cannot check two things:

- **Downgrade.** The bootloader compares the header timestamp against an OTP high-water
  mark that only the device knows. If a previous install set `HIGH_WATER`, older images
  are refused permanently.
- **Production signatures.** Slots 1–5 are Coinkite keys whose public halves are not
  published, so an image claiming one of those slots reports "not checkable" rather than
  "OK".

## `--high-water`

Off by default, and should stay off for anything but a release. Setting it makes the
install record a new anti-downgrade high-water mark on the device — **irreversibly**.
Every image with an older timestamp, including the stock firmware you might want to go
back to, stops being accepted.
