# USB identity and transport

Nothing about USB is fixed by the bootloader. The peripheral is STM32 USB OTG FS on
`PA11`/`PA12`; everything above that — device class, descriptors, VID/PID, framing,
encryption — is ours to choose, because CatCard owns both ends.

## VID/PID

**We will not reuse `0xd13e:0xcc10`.** Those are the numbers the stock firmware
advertises, and they are unregistered: the original source describes them as
"unofficial, unpermissioned" and `0xd13e` does not appear in the USB-IF vendor table.
Squatting someone else's squat is worse than either.

**Plan: pid.codes.** [pid.codes](https://pid.codes) allocates PIDs under VID `0x1209`
free of charge to open-source projects. That is the right home for this. Until a PID is
allocated, no CatCard build advertises a USB identity at all, because there is no USB
stack yet.

Separately, during ST factory DFU an unlocked device appears as `0483:df11` — ST's own
registered identity, nothing to do with us.

## DFU suffix VID/PID

The DfuSe container `catcard-image` produces carries a 16-byte DFU suffix with a VID/PID
pair. We write `0xFFFF:0xFFFF`, the DFU specification's wildcard, meaning "any device
may accept this file".

That is the honest value: the file is not claiming to be for a specific registered
product. `--vid`/`--pid` override it if a particular loader turns out to require a match.

## Transport (not yet built)

Design constraints, recorded now so the choice is deliberate later:

- **Class.** The stock firmware uses HID with 64-byte reports, plus a U2F-shaped
  descriptor that exists only to stop host HID drivers from complaining. HID avoids
  driver installation on every desktop OS, which is a real advantage for a hardware
  wallet. WebUSB would allow browser access without a native host application. Both are
  open.
- **The host is not trusted.** A hardware wallet's entire premise is that the machine it
  is plugged into may be compromised. The transport must therefore provide
  authenticated encryption with replay resistance, and — more importantly — **no
  transport-level authentication may substitute for on-device confirmation of what is
  being signed.** Anything with consequences gets confirmed on the device's own screen,
  by a human, every time.
- **Nonces come from `domain::PROTOCOL`**, never from the entropy pool directly. See
  [`ENTROPY.md`](ENTROPY.md).
- **Parsing is attacker-facing.** Every host-supplied length is bounded before
  allocation, and the parser is the first thing that should get fuzzed.

The stock `ckcc` protocol (`vers`, `ncry`, `stxn`, …) is deliberately not implemented and
deliberately not studied — see [`../CLEANROOM.md`](../CLEANROOM.md). Host compatibility
with existing Coldcard tooling is not a goal.
