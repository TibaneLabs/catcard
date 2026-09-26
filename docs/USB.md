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
| `0x0013` | `UpgradePacked` | the same image, deflated; `[u32 uncompressed length][u32 block size][deflate streams]` |
| `0x0040` | `NcryStart` | open an encrypted channel; payload is the host's ephemeral X25519 public key, reply is the device's |
| `0x0041` | `NcryMsg` | a command or reply sealed for that channel |

### The encrypted channel (`ncry`)

The framing above is in the clear, so a passive observer on the wire — a USB analyser, a
logging hub — can read every opcode and payload. Anything that should not be seen travels
instead inside `NcryMsg`, once a session has been negotiated.

The handshake is one round trip, ephemeral on both sides (the Noise `NN` pattern):

```text
host   → device   NcryStart, payload = host ephemeral X25519 public key (32 B)
device → host     Ok,        payload = device ephemeral X25519 public key (32 B)
```

Each side computes the X25519 shared secret and runs it through
`HKDF-SHA256(salt = host_pub‖device_pub, ikm = shared, info = "catcard-ncry-v1")` to two
directional keys. The device's ephemeral scalar comes from the HMAC-DRBG under its own
domain (`catcard/drbg/usb/v1`), never the raw entropy pool and never anything key-derived.

After the handshake, each direction is a ChaCha20-Poly1305 stream keyed separately, with a
per-direction message counter as the nonce — used once, never reused. The receiver derives
the nonce from the count it expects next, so a replayed or reordered record authenticates
against the wrong nonce and is refused; any authentication failure tears the session down.
A sealed record is `[ciphertext][16-byte tag]`, and the plaintext inside is an ordinary
message: `[u16 opcode][payload]` in, `[u16 status][payload]` out, dispatched as if it had
arrived in the clear.

**What it defends.** Both keys are ephemeral and neither party is authenticated, so this
stops a *passive* eavesdropper reading the protocol. It does **not** stop an *active*
man-in-the-middle that relays the handshake: with no static device identity to bind, the
two ends cannot tell a relay from the wire. Device authentication — a static device key and
an on-screen session fingerprint — is a later, version-bumped step; the `info` string
carries the version so an authenticated `v2` cannot be confused for this `v1`.

The bulk upgrade opcodes are deliberately left in the clear and are not accepted inside the
channel: the image is public and signed, its integrity already guaranteed, and it streams
to staging without being buffered whole, which a per-message seal would break.

`tools/usbclient.py hid <image> --ncry` negotiates a session and runs `Identify`, a log
page and a `Ping` through it, then checks that a tampered record is rejected.
`tools/ncry.py --selftest` checks the host crypto against a vector baked into the firmware
unit tests, so the two implementations cannot silently diverge.

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

It is in the **dev build** — the one with every diagnostic on, which is the build you
flash to a device under test. That is now the default: `fw-<board>` carries it, and the
shipping build is `fw-<board>-ship` (`--no-default-features`, none of this). The point of a
bring-up build is that everything you might need to see what went wrong is on the single
image you flash; splitting the monitor into its own image would just mean flashing the
one without it and then wishing you hadn't.

It is loud rather than hidden, which is the actual safety property here:

- `Identify` sets `caps::DEBUG_MEM`, the selftest screen lists `MEM` among the build's
  hazards (`[KEYS PIN MEM]`), and the boot log carries a warning line.
- Every access is logged (`peek`/`poke`/`jsr` lines), and a `jsr` is logged *before* the
  call, so if it never returns the log still records what ran.

None of that belongs in a shipping build, and `fw-<board>-ship` compiles all of it out.

Two Debug screens ride on the same feature, because they are the two ends of one
bench workflow: **Dump state** (`statedump.rs`) writes the settings region and the seed
**in the clear** to `XXXXXXXX-STATE.BIN` on the card, and **Restore settings**
(`restore.rs`) writes a dump's settings section, staged by `--stage-settings`, back over
the region. A shipping image has neither; a card that holds the wallet with no PIN on it
is a diagnostic for a device under test, not something a menu should offer an owner.

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

#### Deflated, when the device says it can take one

`UpgradePacked` is the same image through the same checks, with a smaller wire. Firmware
deflates to about two thirds, and at 62 bytes a report that third is a third of the wait.

The payload is a `u32` uncompressed length, a `u32` block size, then a run of raw deflate
streams, each inflating to that block size but the last.

The block size is declared rather than assumed by both ends. It used to be a constant
compiled separately into the firmware and the host tool; when the firmware's changed and
the tool's did not, an upload failed part way through and surfaced as a frame error with
the real reason — a block too large for the device's slab — reported nowhere. A device
whose slab is smaller now answers `RetryUncompressed` before any of it is sent. Nothing frames the streams: deflate marks its own final
block, so the device splits them on that and there is one account of where a block ends
rather than two — a second opinion about a length is how a decoder gets talked past the
end of its buffer.

The length prefix is the one the signature was computed over, and the device stops there.
A stream that would produce more is refused (`Unpackable`), not truncated, and so is a
transfer that stops short: the tail of the staging area is whatever the last upload left
in it, and that is what would otherwise be installed. The message's own `total` counts
the compressed bytes, because that is what crosses the wire.

Blocks rather than one stream because a decompressor owns its output and never gives it
back: a single stream's decoder would have to live across frames writing through a sink
into the staging area stored beside it, which is a self-reference, and the ways out of it
are a global or a raw pointer. A block's output is bounded, so it inflates into a fixed
slab the caller reads afterwards. Measured cost on a real image: 65.8% against 63.7%.

Advertised as `caps::UPGRADE_PACKED`, set exactly when `caps::UPGRADE` is. A host that
does not see the bit sends `UpgradeOffer`, which every build understands.

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

### One offer at a time, and the host cannot withdraw it

An offer that passed inspection is on the device's screen waiting for a person, and a
second `UpgradeOffer` / `UpgradePacked` while it waits is answered `NotNow` on its first
frame -- the same answer a premature `UpgradeCommit` gets, meaning the same thing: wait
for the device. Likewise once the person has approved and the recovery marker is
published, right up to the reboot. It used to be that a new offer silently replaced the
one on the screen, which let any host clear a question it is not entitled to answer, and
pull an approved image out from under the marker that names it.

What a host must do: offer once, then wait. The outcome arrives on its own -- a
`Declined` frame if the person refuses, or the device dropping off the bus as it reboots
to install. There is no opcode to withdraw an offer; unplugging (a bus reset) is the
only way a host can take one back, and that is deliberate. A transfer that is still
*arriving* is different: a new offer replaces it, because a host restarting a failed
upload is the same holder coming back.

`tools/usbclient.py` offers once per run and prints a hint on `NotNow`, so running it
twice while the first offer is on the screen fails cleanly rather than restarting the
upload.

Every other opcode fits one frame. A START frame for anything but an upgrade that
declares more payload than one frame carries is refused with `BadRequest` and its frames
reset, rather than being reassembled into something the device would then treat as an
image.

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

**It must not ship enabled.** Every dev build carries it by default (`fw-mk3` / `fw-mk4`
/ `fw-q1`); a release is built with the `fw-*-ship` aliases, which strip it, so leaving it
out is an explicit release step rather than something to remember. The feature is the whole
removal: without it the opcode, the queue, and the merge in every key loop compile out,
and `Identify` stops advertising the capability. Once the key map is confirmed on
hardware, stop building the bring-up image.

### Keyboard emulation: a second interface, off by default

With **Settings → Hardware On/Off → Keyboard EMU** on, the device enumerates as a
*composite*: the wallet's vendor HID interface exactly as above, plus a **boot-protocol
USB keyboard** as interface 1. It exists so a BIP-85 password or a stored note can be
typed straight into a login form on the host, with no clipboard for the host's other
software to read (stock: "USB-keyboard emulation (for BIP-85 passwords)").

**It is off by default, and doubt reads as off.** The setting is `cat_kbemu` in the
wallet's own settings file, and only a literal `"1"` switches it on -- the opposite
direction from the port and disk switches, which read as on. Those two can only take a
channel away; this one gives the host a keyboard, and no unreadable byte should ever do
that. Like the port switch it is read after the PIN, so a locked device never shows a
keyboard.

**Nothing changes for host tools.** The vendor interface keeps interface number 0 and
endpoints `0x81`/`0x01`, and the 32 bytes describing it after the configuration header
are the same bytes as in the single-interface table (`catcard-usb` tests that they are). `usbclient`
and `mk5install.py` open interface 0 by VID:PID and never see the difference. The
keyboard is:

| | |
|---|---|
| interface | 1, class HID, subclass 1 (boot), protocol 1 (keyboard) |
| endpoint | `0x82` interrupt IN, 8 bytes, 8 ms |
| report | the boot report: `[modifiers, 0, key×6]` (HID 1.11 Appendix B.1) |
| report descriptor | HID 1.11 Appendix E.6, byte for byte, LED output report included |
| keycodes | HID Usage Tables 1.12 §10, **US layout**; `catcard_usb::kbd::keycode` |

A host set to another keyboard layout will type the shifted symbols wrong (`z` for `y`
on a German host, and so on); letters, digits, space and Enter agree across the common
ones. The device has no way to know the host's layout, so this is said here rather than
worked around.

**The descriptor set is fixed per enumeration.** Switching the setting re-enumerates the
device -- a soft-disconnect, a pause, a re-attach -- the same dance the USB Drive screen
does, so a host always sees a device that either has the keyboard or does not, never one
that grew an interface mid-session. The mass-storage identity never carries it.

**Typing is `usbkbd::type_text`.** Each character is one press report and one release,
paced a few milliseconds apart; a string with a character the table cannot type is
refused whole, before the first report, rather than typed half-way into a password
field. No Enter is sent unless the caller asks (`Options::enter`). Every wait is
bounded: a host that stops taking reports -- screen locked, port suspended -- is
reported within a second, never waited for. Nothing about the text, not even its
length, goes in the log, because the log is readable by any host that can open the port.

**Proving it on hardware:** Debug → `Keyboard EMU test` types the constant line
`catcard keyboard ok` into whatever window the host has focused, after asking. Open a
text editor first.

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


## Rescue: staging and installing with the memory monitor

A device whose own staging path is broken cannot be fixed by either ordinary route: the
USB offer and the card both run through the code that is failing. That happened on
2026-09-19 — a barrier in `burst_gap` stopped the core part way through an image — and
there was no way back. These modes exist for that, on a `usb-debug-mem` build:

```sh
usbclient.py hid --selftest                 # no device needed
usbclient.py hid --stage out/catcard-q1.dfu # poke the image into PSRAM, publish the header
usbclient.py hid --find-attempt             # locate the live pinAttempt_t
usbclient.py hid --rescue out/catcard-q1.dfu --yes   # stage, then authorise and install
```

**Staging** pokes the image to `PSRAM_BASE + PSRAM_LEN/2` and writes the recovery header
at `0x907F_F800` with `magic1` last, so no intermediate state reads as a valid header.
It never calls the firmware's PSRAM driver. It is also gentle on the part by accident of
shape: one frame per request means each write is a short burst with the bus idle until
the next arrives, which is far more CE#-high time than `tCPH` asks for.

**Installing** is `gate 18 / 7`, and needs the login's own `pinAttempt_t` — so the device
must be unlocked. The struct is found by scanning SRAM for `PA_MAGIC_V2`; the two fields
the caller owns (`change_flags` and the region in `secret[0..8]`) are poked, which does
not disturb the bootloader's HMAC because that covers only the struct up to `hmac` plus
`cached_main_pin`.

`DebugJsr` calls `fn(u32) -> u32` and can set only `r0`, but the gate wants the method in
`r0`, the buffer in `r1` and **its length in `r2`** — not a second argument. So a
ten-instruction Thumb thunk loads them from a literal pool and branches, saving `r9` and
`r10` because the gate clobbers them. It is poked into the unused lower half of PSRAM,
read back before it is called, and its bytes are pinned by `--selftest` against what a
real assembler produces from the listing in the source.

On success the call does not return: the device reboots and the bootloader installs. A
return is a refusal — `-112` is the staged image failing verification, `-103` a bad
region.
