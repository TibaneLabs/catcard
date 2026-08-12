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

**Goal: reachable from a web browser**, so that wallet extensions can talk to the device
without a native helper application.

### What that actually requires

Three constraints shape it, and two of them are not transport questions:

**1. "Browser" means Chromium.** WebUSB and WebHID are both Chromium-only — Chrome,
Edge, Opera, Brave. Firefox has declined to implement either on security grounds and
Safari does not support them. Both require a secure context and a user gesture per
origin. Designing for browser access is designing for roughly two thirds of desktop
users, not all of them, and that should be said out loud in any user-facing
documentation rather than discovered.

**2. A protocol is necessary but not sufficient for MetaMask.** MetaMask has no generic
"any hardware wallet over USB" interface. Its built-in support is per-vendor and lives
in MetaMask's own code — Ledger over WebHID, Trezor via the hosted Trezor Connect
iframe, Lattice via a relay. A new device gets in by one of:

  - **A Keyring Snap** (the Account Management API). This is the route that does not
    require upstream MetaMask changes. The catch: Snaps run sandboxed and **cannot reach
    WebUSB or WebHID directly**, so a Snap needs a companion page that holds the device
    permission and relays to it. That companion page becomes part of the product.
  - **Upstream support in MetaMask**, which is a much longer road.
  - **QR, no USB at all** — see below.

**3. Ethereum is a separate signing stack, not an extra command.** MetaMask is EVM.
Serving it means Keccak-256 (a different hash from anything CatCard has), EIP-155 and
EIP-1559 transaction encoding, EIP-712 typed-data hashing, EIP-55 address checksumming,
and recoverable `(r, s, v)` signatures rather than DER. None of that is shared with the
Bitcoin path beyond the secp256k1 curve itself. It belongs on the roadmap as its own
milestone and should be costed as one.

### The QR alternative, worth weighing first

MetaMask already supports QR-based hardware wallets (Keystone, AirGap) through the
UR/EIP-4527 encoding, **today, with no MetaMask changes and no USB**. The Q1 has an LCD
and a camera. For that board this route reaches the same destination while keeping the
device air-gapped, which is a stronger security position than any USB protocol can
offer — the attack surface is a camera and a screen rather than a parser exposed to any
page the user has granted permission to.

It does not help mk3 or mk4, which have neither a camera nor a display big enough. So
this is a per-board answer, not a replacement for the transport.

### Recommended shape

- **A vendor-class interface with MS OS 2.0 descriptors.** Vendor class keeps Chromium's
  WebUSB from refusing the interface — it blocks protected classes including HID — and
  the MS OS 2.0 platform capability descriptor makes Windows bind WinUSB automatically,
  which is what removes the driver-install step. The same interface is reachable from
  libusb for native tooling and CI, so there is one protocol rather than two.
- **Optionally a second HID interface** for reach: WebHID needs no special descriptors
  and is the transport Ledger uses with MetaMask today. A composite device can offer
  both; WebUSB claims only the vendor interface.
- **Framing and command set are ours**, versioned from the first byte, with every
  host-supplied length bounded before use.

### Constraints that do not change

- **The host is not trusted.** A hardware wallet's entire premise is that the machine it
  is plugged into may be compromised. Browser reachability sharpens this rather than
  softening it: after a user grants permission to one origin, **the device cannot tell
  which page is talking to it** — origin binding is enforced by the browser, not
  observable on the wire. So the transport must never be the security boundary.
  **Everything with consequences is confirmed on the device's own screen, by a human,
  every time**, and that confirmation shows what the device parsed, never what the host
  said it means.
- **Nonces come from `domain::PROTOCOL`**, never from the entropy pool directly. See
  [`ENTROPY.md`](ENTROPY.md).
- **Parsing is attacker-facing.** Any web page the user has been persuaded to grant
  access to can reach the parser. It is the first thing that should get fuzzed.
- Transport-level encryption is still worth having against a passive host, but it
  authenticates a channel, not an intent. It is not a substitute for the screen.

The stock `ckcc` protocol (`vers`, `ncry`, `stxn`, …) is deliberately not implemented and
deliberately not studied — see [`../CLEANROOM.md`](../CLEANROOM.md). Host compatibility
with existing Coldcard tooling is not a goal.
