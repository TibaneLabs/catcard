# USB identity and transport

Nothing about USB is fixed by the bootloader. The peripheral is STM32 USB OTG FS on
`PA11`/`PA12`; everything above that — device class, descriptors, VID/PID, framing,
encryption — is ours to choose, because CatCard owns both ends.

## VID/PID

**CatCard is `0x39F2:0x0401`.**

| | |
|---|---|
| Vendor ID | `0x39F2` (14834), allocated to Karpeles Lab Inc. by the USB-IF |
| Product ID | `0x0401`, the CatCard firmware |

The vendor ID is shared across Karpeles Lab products, so product IDs are allocated
outside this repository. If CatCard ever needs a second identity — a DFU or recovery
interface presenting differently — that PID has to be allocated, not picked. The
constants live in `catcard_board::usb`, which is the one dependency-free crate both the
firmware descriptor and the packaging tool read, so the two cannot drift.

**Why not `0xd13e:0xcc10`.** Those are the numbers the stock firmware advertises, and
they are unregistered: its own source describes them as "unofficial, unpermissioned",
and `0xd13e` does not appear in the USB-IF vendor table. Beyond squatting someone
else's squat, reusing them would make CatCard indistinguishable from a Coldcard to every
host on the bus — which is a bad property for a device whose whole job is to be
identifiable and trusted.

(An earlier plan used pid.codes VID `0x1209`, which allocates PIDs free to open-source
projects. That is no longer needed and is recorded only so the change is traceable.)

Separately, during ST factory DFU an unlocked device appears as `0483:df11` — ST's own
registered identity, nothing to do with us.

## DFU suffix VID/PID

The DfuSe container `catcard-image` produces carries a 16-byte suffix with its own
VID/PID pair, and that is **not** the same question as the device's identity. It says
which devices the *file* is for.

The default stays `0xFFFF:0xFFFF`, the DFU specification's wildcard, even now that a real
allocation exists. The reason is the bootstrap path: the first CatCard image reaches a
device through *stock* Coldcard firmware's SD-card upgrade menu, and whether that
firmware checks the suffix against its own VID/PID is not documented either way. A
wildcard cannot be rejected for naming the wrong device; naming ourselves might be.

Pass `--vid 0x39f2 --pid 0x0401` to stamp the real identity — appropriate once the
target is CatCard's own loader rather than the stock one. Revisit the default at M6,
when that loader exists and the bootstrap path stops being the only way in.

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
