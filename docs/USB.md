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

## Transport

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

### The decision: HID, and what it cost

**Built as a HID device with two 64-byte interrupt endpoints.** This reverses the
recommendation that stood in this file until the transport was written, which was a
vendor-class interface with MS OS 2.0 descriptors. Both are reachable from a browser, so
the deciding question is what a user has to do before either works:

| | WebUSB (vendor class) | WebHID (HID class) |
|---|---|---|
| Windows | needs WinUSB bound via MS OS 2.0 descriptors | binds to the OS driver |
| Linux | needs a `udev` rule | needs a `udev` rule for raw access, but `hidraw` is commonly permitted |
| macOS | works | works |
| Native tooling | libusb | hidapi |
| What extensions speak | Trezor, via a hosted iframe | **Ledger, via WebHID** |

A hardware wallet whose first instruction is "now edit a system file" has lost most of
its users, and the MS OS 2.0 route is a descriptor most hosts get right and some do not.
HID is the transport MetaMask's Ledger support already uses, which is the closest thing
to evidence available about what actually works in that environment.

The cost is throughput, and it is real: 64 bytes per 1 ms frame is **64 KB/s**, so a
256 KB firmware upgrade takes about four seconds. A bulk endpoint would be far quicker.
Four seconds, once, for something a user is already watching a confirmation screen for,
is a fine trade.

**Nothing forecloses WebUSB.** A composite device can carry both; the framing is
transport-independent and the vendor interface can be added beside the HID one if a case
appears that HID cannot serve. That case has not appeared yet.

### Status

Enumeration works: the device is configured, and `Ping` and `Identify` round-trip
against the emulator's register-level OTG model. **Reports stop being answered once the
firmware leaves the selftest screen**, which is an open bug — see `ROADMAP.md`. Until it
is fixed the upgrade path is not usable end to end, however well the staging half is
tested.

### The protocol

Only the transport is standard. The framing is `catcard-usb`:

```text
byte 0   kind    0x01 START, 0x02 CONT
byte 1   seq     increments per frame within a message, wrapping
START:
  2..4   u16     opcode (request) or status (response)
  4..8   u32     total payload length
  8..64  payload
CONT:
  2..64  payload
```

A message is one opcode and up to 4 GiB of payload, which is why a firmware image is a
single message rather than a chunking scheme layered on a chunking scheme. The device
never holds it: each frame's bytes go straight into PSRAM staging as they arrive.

The sequence byte earns its place. USB retries interrupt transfers in hardware, so a
dropped frame should not happen — but a host bug that drops one silently yields an image
62 bytes shorter than what was sent, and without the check the only thing left to catch
it is the signature.

| opcode | | |
|---|---|---|
| `0x0001` | `Ping` | payload echoed |
| `0x0002` | `Identify` | protocol version, board, firmware version |
| `0x0010` | `UpgradeOffer` | payload is a complete signed image, raw — **not** a DfuSe container; stages and validates, installs nothing |
| `0x0011` | `UpgradeCommit` | install what was offered, after approval **at the device** |

### The log, which is the only diagnostic that does not need a screen

`Opcode::ReadLog` (`0x0012`) pages out a ring in RAM: `tools/usbclient.py hid --log`.
The payload is a `u32` offset from the oldest byte held; the reply carries the total and
a flag saying whether the ring wrapped, so a truncated boot log cannot be mistaken for a
complete one.

It exists because every other diagnostic this firmware had ended on the panel, and the
first mk5 came up with a dark one — it enumerated, took a PIN typed blind, and refused an
upgrade for a reason drawn where nobody could read it. The same buffer is marked with a
magic so `--dump-ram` can find it, which is the other reader that cannot ask.

**Nothing secret goes in it.** Anything that can open the port can read it, including a
host that has not proved it knows the PIN, and it outlives a logout. The rule for a line
is that it must be safe to read aloud to a stranger holding the device: no PIN digits, no
seed, no anti-phishing words.

**Replies span frames, but only if the writer is resumed.** The reply writer is stateful,
yet `next_reply_frame` used to rebuild it at frame zero every call — so it re-sent the
first frame and, guarded by a `sent` flag, then stopped, capping every reply at one
frame. A longer body's tail vanished while the frame header still declared the full
length, and a host that believed the header waited for a continuation that never came,
which looks exactly like a device that died. The writer now carries `(sent, seq,
started)` between frames (`Writer::resume`), so a reply of any length goes out correctly —
which is what makes a 512-byte peek possible.

### The memory monitor: peek / poke / jsr (`usb-debug-mem`, bench only)

Three opcodes turn USB into a raw monitor: `DebugPeek` (`0x0030`) reads any address,
`DebugPoke` (`0x0031`) writes any address, `DebugJsr` (`0x0032`) calls any address as
`fn(u32) -> u32` with interrupts masked and returns its result. The names are the
ZX-Spectrum ones — peek, poke, and `RANDOMIZE USR`.

```sh
tools/usbclient.py hid --peek 0x08020000 64        # 64 words from the vector table
tools/usbclient.py hid --poke 0x20002000 deadbeef  # write bytes (hex)
tools/usbclient.py hid --jsr  0x20001000 0         # call it, print the return value
```

**This is the most dangerous thing in the firmware and it must never ship.** There is no
access control and there cannot be: a monitor that refused to read an address would not
be a monitor. On a provisioned device it reads the seed and the PIN out of RAM and runs
whatever a host sends. It exists for bring-up on a device with no secret.

It is in the **bring-up build** — the one with every diagnostic on, which is the build
you flash to a device under test. There is one such build per board (`fw-<board>-bringup`)
and one shipping build (`fw-<board>`, no features and none of this). The point of a
bring-up build is that everything you might need to see what went wrong is on the single
image you flash; splitting the monitor into its own image would just mean flashing the
one without it and then wishing you hadn't.

It is loud rather than hidden, which is the actual safety property here:

- `Identify` sets `caps::DEBUG_MEM`, the selftest screen lists `MEM` among the build's
  hazards (`[KEYS PIN MEM]`), and the boot log carries a warning line.
- Every access is logged (`peek`/`poke`/`jsr` lines), and a `jsr` is logged *before* the
  call, so if it never returns the log still records what ran.

None of that belongs in a shipping build, and `fw-<board>` compiles all of it out.

Peek reads span several frames — a request returns up to 512 bytes — so a range comes
back in one round trip rather than one byte at a time. Poke is paged one frame per
request by the client, because the device reassembles a multi-frame message only for a
firmware upgrade.

### Talking to a real device

`tools/usbclient.py` speaks to both the emulator and hardware, over the same protocol
code — the transport is the only thing that differs, duck-typed onto the three calls a
socket offers. That matters more than it sounds: if the hardware path were a separate
tool, an emulator run would prove nothing about the device.

```sh
tools/usbclient.py /tmp/x.sock ...      # the emulator's --usb-hid socket
tools/usbclient.py hid ...              # a real device, found by VID:PID
tools/usbclient.py /dev/hidraw3 ...     # a real device, named outright
```

`hid` searches `/sys/class/hidraw/*/device/uevent` for `39F2:0401` and waits for one to
appear, so it can be started before the cable goes in.

**`/dev/hidraw*` is root-only by default**, which is the first thing that will stop you.
A udev rule fixes it without `sudo` on every run:

```
# /etc/udev/rules.d/70-catcard.rules
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="39f2", ATTRS{idProduct}=="0401", TAG+="uaccess"
```

Then `sudo udevadm control --reload && sudo udevadm trigger`, and replug. `uaccess`
grants the logged-in user access rather than a group, so nothing needs to be added to
`plugdev`.

The device sets no report ID, so hidraw takes a leading zero byte on every write; the
client does that. Reads come back as whole 64-byte reports and are buffered, because a
short read on hidraw discards the rest of the report rather than leaving it queued.

### The device takes a raw image; the host unwraps the container

`UpgradeOffer` carries the signed image itself, with the header at `0x3F80`. The
firmware knows nothing about DfuSe and should not: this parser is reachable by anything
that can open the port, so it stays as small as it can be, and a container format is
work the host can do instead.

`tools/usbclient.py` therefore accepts either. Hand it a `.dfu` and it checks the
signature, the suffix CRC and the declared sizes, then offers the element inside; hand it
a `.bin` and it passes it through untouched. So the file you flash through stock and the
file you offer to CatCard can be the same file, without the device growing a parser for
it.

A container that does not check out is refused on the host, before anything is sent —
a corrupted one fails on the CRC rather than being quietly truncated into a short image
that the device would then reject for the wrong reason.

### A reply goes out in the poll that produced it

Replies are staged into an outbox and pushed by `drain_outbox`. That used to run only at
the *start* of the next poll, which is fine while the firmware is sitting in a key loop
and wrong the moment a key makes it leave one: choosing a PIN, fetching the anti-phishing
words and logging in are all callgate calls that mask interrupts and do not poll. The
acknowledgement for the key that *started* that work sat in the outbox until it finished,
and from the host that is indistinguishable from a device that died mid-operation.

So the poll that handles a report also drains the reply. The host's timeout can then be
short enough to be diagnostic — a late reply means stopped, not busy.

### Enumeration is not gated by the PIN; upgrades are

The peripheral comes up during bring-up, before the PIN prompt, because a host presents
the cable and begins enumerating within milliseconds and will not wait for someone to
type a PIN — a device that only appears after unlocking looks broken. Enumerating
discloses a name, an ID, and a serial number that is already the USB serial number.

`UpgradeOffer` and `UpgradeCommit` answer `NotNow` until the unlock resolves. Someone
holding the device therefore cannot replace its firmware without also being able to open
it. A blank device with no PIN set reaches the unlocked state too, which is what keeps
such a unit recoverable.

### Key injection: a bring-up crutch with an expiry date

`InjectKey` (`0x0020`) hands the firmware one keypress from the host. It is behind the
cargo feature `usb-key-injection`, on by default **at this stage only**, and it
contradicts the first constraint below on purpose. Be clear about what it is: with it
compiled in, a host can approve its own firmware upgrade. The screen is no longer the
boundary.

It exists because of the order in which unknowns get resolved. The first run on real
hardware is the run where the keypad map, the display init, and the panel wiring are all
still `[I]` or `[?]` — and it is also a run on a **locked production unit**, where being
unable to type the PIN means being unable to do anything at all, including install a
firmware that would fix the typing. A mirrored key map is a plausible mistake that costs
the device. `--drive` in `tools/usbclient.py` is the whole device driven over USB
with nothing touching the keypad, which is what turns that class of mistake back into an
inconvenience.

What it does not do: it does not bypass the PIN. An injected `4` is a `4` at the prompt
and nothing more — the bootloader still checks the PIN, still rate-limits, still bricks
on the thirteenth wrong answer. It buys a way to *reach* the prompt, not past it.

The capability is advertised in `Identify` (`caps::KEY_INJECTION`) and shown on the
selftest screen as `[USB KEYS]`, because a device that can be driven by its host should
say so where its owner can read it.

**It must not ship enabled.** The ordinary `fw-mk3` / `fw-mk4` / `fw-q1` aliases build
without it; the `fw-*-bringup` aliases are the only way to turn it on, so enabling it is
always a visible choice rather than an inherited default. The feature is the whole
removal: without it the opcode, the queue, and the merge in every key loop compile out,
and `Identify` stops advertising the capability. Once the key map is confirmed on
hardware, stop building the bring-up image.

### Identify reports which screen you are on

A host driving the device blind needs to know what it is answering. `Identify` carries a
state byte — `UNLOCKED` and `BLANK` — because "not unlocked" is two different devices:
one asking for a PIN, and one asking to be given a first PIN. They take different keys,
and inferring which from the outside is guesswork against a screen you may not be able
to see.

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
