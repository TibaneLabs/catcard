# The Q1 rescue image

`make q1-rescue` builds `out/catcard-q1-rescue.{bin,dfu}`, version `7.0.0r`. This image
boots straight into the headless USB reflash: the loop behind the CANCEL-held failsafe
(`failsafe::run` → `recovery::headless`). It does nothing else, and has no panel UI past one
"Recovery" screen.

The flow is:

1. the host sends the PIN;
2. the host offers an image;
3. an injected confirm approves it;
4. `gate 18/7` installs it and the device reboots into it.

This is the same loop proven on a Q1 on 2026-09-25.

## Why it exists

A firmware can only be replaced by the firmware already running, because that firmware
stages the new image. When the running firmware's staging is broken, it cannot install its
own fix. 7.0.0a3 on a Q1 freezes partway through staging a full image, both over USB and
from the card.

The rescue image is a way past that, and only that. It has the current staging code, and
it carries the debug monitor (`usb-debug-mem`), so a staging fault on it can still be
repaired word by word.

## Size

- The code is about 125 KB.
- The bootloader refuses anything under `FW_MIN_LENGTH` = 256 KB (hw-reference
  `firmware-signing.md` [C]), so `catcard-image` pads it to 262,144 bytes.
- The padding is zeros, so a packed USB offer is about 91 KB on the wire. The device still
  stages all 256 KB.

## Using it

```sh
make q1-rescue
# offer it from the running firmware, and approve it on the device:
../work/ckcc-venv/bin/python tools/usbclient.py hid out/catcard-q1-rescue.dfu
# once it shows "Recovery", send the PIN and the real image; this also approves it:
../work/ckcc-venv/bin/python tools/usbclient.py hid --drive --pin=PREFIX-SUFFIX \
  out/catcard-q1.dfu
```

## Risk

- **A rescue image is a whole firmware.** It runs on a locked unit, and the bootrom's SD
  recovery only completes the pending install, which would be this image itself. So it must
  work.
- **It is built from proven code.** It is the ordinary boot up to `init_core`, then the
  failsafe loop exactly as the CANCEL-held path runs it.
- **The `rescue` feature only removes code.** It skips the CANCEL check, drops the loop's
  SD-card option, and leaves out the rest of `main`.
- **Ordinary builds are unchanged byte for byte.** For example, a Q1 image differs from the
  one before the feature only in its header's timestamp and signature.
