# Getting CatCard onto a device

Three routes, in order of how likely they are to apply to you.

> Every route below installs an image signed with the **published developer key**. The
> device will boot it with a 25-second warning screen and leave the "genuine" light red.
> That is not a bug — it is the bootloader correctly reporting that the image is not
> signed by a Coinkite production key. Anyone can sign with the dev key, so a dev-signed
> image is not attributable to any author, including this project.

---

## 1. microSD, on a locked production unit

Works on any unit, including RDP=2, and needs no host tooling or debug hardware. Slow
loop: rebuild, copy, navigate the menu, reboot.

```sh
cargo fw-mk4
cargo run -p catcard-image -- build \
    target/thumbv7em-none-eabihf/release/catcard-fw \
    --board mk4 --version 0.0.1 \
    --dfu /media/sdcard/catcard-mk4.dfu
```

On the device running **stock** firmware: *Advanced → Upgrade Firmware → From SD Card*.
The stock firmware stages the image to SPI-NOR flash and reboots; the bootloader
installs it into main flash and verifies the signature.

Once CatCard implements its own upgrade path (roadmap M6) it will accept images the same
way, and this route stops depending on stock firmware being present.

**Recovering.** There is no CatCard UI yet, so a device running CatCard cannot be told to
load anything. On a locked unit that means you cannot get back to stock firmware without
the DFU button / an unlocked bootloader. **Do not install this on a device you rely on.**

---

## 2. SWD, on an unlocked unit

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

## 3. ST USB-DFU, on an unlocked unit

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
