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
| `0x0041` | `NcryMsg` | a command or reply sealed for a **paired** channel; before pairing only a sealed `PairConfirm` is admitted |
| `0x0042` | `PairCommit` | start pairing; payload `SHA-256("catcard-pair-v2/commit" ‖ host_pub)` (32 B), reply the device's ephemeral X25519 public key (32 B). `NotNow` before the PIN, `Busy` while a code is up or cooling down |
| `0x0043` | `PairReveal` | payload `host_pub` (32 B), which must hash to the commitment (`BadRequest` if not); empty reply, and the device shows the code |
| `0x0044` | `PairConfirm` | **sealed only**, inside `NcryMsg`: the host's user accepted the code. Inner reply `Ok` once paired, `NotNow` while the device's user is still deciding |
| `0x0045` | `PairAbort` | the host's user refused or gave up: tears down any handshake or session, always `Ok` |
| `0x0050`..`0x0055` | `Host*` | host-wallet commands, **inside a paired `NcryMsg` only** -- see "Host-wallet commands" below |

`0x0040` was v1's `NcryStart`. It is retired, not reused: a v1 host gets `UnknownOpcode`.
`Identify` reports protocol version **2** and the capability `caps::PAIRING` (bit 7); bit 5,
v1's `NCRY`, is retired and never set.

### The encrypted channel (`ncry` v2): a code compared on every connection

The framing above is in the clear, so a passive observer on the wire — a USB analyser, a
logging hub — can read every opcode and payload. Anything that should not be seen travels
instead inside `NcryMsg`, once a session has been **paired**. Pairing is Bluetooth-style
numeric comparison, done afresh on every connection: nothing is stored on either side —
no pairing key, no list of paired computers.

The handshake commits, then reveals; the host is the initiator:

```text
host   → device   PairCommit   commit   = SHA-256("catcard-pair-v2/commit" ‖ host_pub)   32 B
device → host     Ok           device_pub                                                 32 B
host   → device   PairReveal   host_pub                                                   32 B
device → host     Ok           (empty)      -- BadRequest, handshake dropped, on a mismatch
```

Both sides compute the X25519 shared secret and, with the whole transcript
`T = commit ‖ device_pub ‖ host_pub` (96 B) as the salt:

- `HKDF-SHA256(salt = T, ikm = shared, info = "catcard-ncry-v2")`, 64 bytes: the
  host→device key, then the device→host key;
- `HKDF-SHA256(salt = T, ikm = shared, info = "catcard-pair-v2/code")`, 8 bytes, read as a
  big-endian `u64` mod 10^6: the **pairing code**, shown zero-padded as `123 456`.

The device's ephemeral scalar comes from the HMAC-DRBG under its own domain
(`catcard/drbg/usb/v1`), never the raw entropy pool and never anything key-derived.

Then a person on each side compares:

```text
device screen     "Pair with this computer?"  398 660   yes / no
host terminal     pairing code: 398 660 -- same code on the device? [y/N]
host   → device   NcryMsg( seal([u16 PairConfirm]) )
device → host     Ok, NcryMsg( seal([u16 Ok]) )       paired
                  Ok, NcryMsg( seal([u16 NotNow]) )   the device's user has not answered: send again
                  Declined                            the device's user said no; session gone
                  NotNow                              no session: timed out, or torn down
```

The session is paired only when the device's user accepted **and** the host's sealed
`PairConfirm` authenticated, in either order. Until then any sealed record other than
`PairConfirm` is refused and tears the session down. The host's user saying no sends
`PairAbort`, which takes the prompt off the device. The device drops an unpaired session
after two minutes (`ncry::PROMPT_MS`), and a failed tag at any point tears it down.

Rules on the device side: pairing needs the PIN (`NotNow` before it, as upgrades do); one
pairing prompt at a time (`Busy`); and after each code shown a five-second pause before the
next handshake (`Busy`), so the device's code cannot be re-rolled faster than a person
reads it. The prompt takes the screen from the menu loop exactly as the upgrade offer does,
checked after the keys are read, and an answer applies only to the prompt that was shown.

**Why the commitment.** A relay in the middle runs one handshake with each side. If the
host revealed its key up front, the relay could wait for it and then grind its own
device-facing key offline until the two codes matched — 10^6 tries is a moment's work. With
the commitment the host is bound before it sees anything the relay sends, and the device's
key is fresh for each handshake, so the relay gets one guess per code a person looks at:
one in a million, and with the pause above about two dozen guesses in the two minutes a
host's user waits.

**What v2 defends.** With the codes compared, an **active relay**: a relayed connection
shows a different code on each screen, and the person says no. And, as v1 did, a
**passive** observer reading the protocol.

**What it does not.** A **host that is itself compromised** — it is the genuine other end,
and pairing with it is exactly what the person agreed to; the channel protects the wire,
not the computer. And a **person who accepts without comparing** the codes — the code is
the whole defence, and a yes pressed without reading it defends nothing.

After pairing, each direction is a ChaCha20-Poly1305 stream keyed separately, with a
per-direction message counter as the nonce — used once, never reused. The receiver derives
the nonce from the count it expects next, so a replayed or reordered record authenticates
against the wrong nonce and is refused; any authentication failure tears the session down.
A sealed record is `[ciphertext][16-byte tag]`, and the plaintext inside is an ordinary
message: `[u16 opcode][payload]` in, `[u16 status][payload]` out, dispatched as if it had
arrived in the clear. `Identify`, `Ping` and `ReadLog` remain available in the clear too, as
they always were; the channel is what commands that need an authenticated host require.

The bulk upgrade opcodes are deliberately left in the clear and are not accepted inside the
channel: the image is public and signed, its integrity already guaranteed, and it streams
to staging without being buffered whole, which a per-message seal would break.

`tools/usbclient.py hid --pair` (or `--ncry`) pairs — printing the code and asking — then
runs `Identify`, a log page and a `Ping` through the channel and checks that a tampered
record is rejected. Other commands pair through the same `open_session()` helper.
`tools/ncry.py --selftest` checks the host crypto against the v2 vector baked into the
firmware unit tests (commitment, code `398 660`, and a sealed record), so the two
implementations cannot silently diverge.

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
firmware upgrade and a sealed `NcryMsg` record (see "Sealed requests may span frames").

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

Every other opcode fits one frame, with one bounded exception: a sealed `NcryMsg` record
of up to `ncry::RECORD_MAX` (1040) bytes, which is gathered into a heap block and opened
only once whole (see "Sealed requests may span frames" below). A START frame for anything
else that declares more payload than one frame carries -- or an `NcryMsg` past that bound
-- is refused with `BadRequest` and its frames reset, rather than being reassembled into
something the device would then treat as an image. An upgrade offer is also answered
`NotNow` while a host-wallet question is queued or on the screen, as a host question is
while an upgrade waits.

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

**What types.** Three screens, all through `usbkbd::send_screen`, which says in one line
why not (switch off, no host, a character with no key), offers Enter after the text,
and asks before a keystroke goes out: the main menu's `Type Passwords` (a BIP-85
password child, never shown; on the Q1 also a Secure Notes password), Notes → `Send
Password`, and Confirm on a BIP-85 password child's screen under Derive → `BIP-85`.

**Proving it on hardware:** Debug → `Keyboard EMU test` types the constant line
`catcard keyboard ok` into whatever window the host has focused, after asking. Open a
text editor first.

### Host-wallet commands: a computer asks, the person decides

Two things a computer may ask the wallet for, **only inside the encrypted channel**:
its addresses, and a signature. Both follow the upgrade offer's shape -- the host asks,
the device puts the question on its own screen, the person holding it answers there,
and the host polls for the outcome. The host cannot answer for the person and cannot
withdraw a question once the device has it; only the person, or a bus reset, ends one.

In the clear these opcodes are `UnknownOpcode`, exactly as the bench debug opcodes are
unknown *inside* the channel. Advertised by `caps::HOST_WALLET` (bit 6) in `Identify`.
Whether a session may carry them at all is decided in one place,
`ncry::Channel::host_wallet_allowed()`: any open session today, a paired one when the
channel gains pairing. The host tool gets its session from one helper,
`usbclient.open_session()`, for the same reason.

The layouts are `catcard_usb::hostwallet`, whose tests pin every one byte for byte;
`tools/hostwallet.py` is the host half, written from this section, with `--selftest`
checking the same bytes.

| opcode | | request | reply |
|---|---|---|---|
| `0x0050` | `HostAddresses` | empty | `Ok` = queued for the person; `NotNow` + `[u8 busy]` |
| `0x0051` | `HostSignBegin` | `[u8 chain][u32 blob length]` | `Ok` + `[u32 largest chunk]`; `NotNow` + `[u8 busy]`; `Refused` + reason |
| `0x0052` | `HostSignData` | `[u32 offset][1..=1018 bytes]` | `Ok` + `[u32 received so far]`; `BadRequest` for an offset out of order or past the end |
| `0x0053` | `HostSignCommit` | empty | `Ok` = queued for the person; `Refused` + reason |
| `0x0054` | `HostResult` | `[u32 offset]` | `NotNow` + `[u8 stage]`; `Declined`; `Refused` + reason; `Ok` + `[u32 total][page]` |
| `0x0055` | `HostAbort` | empty | `Ok`; `NotNow` + `[u8 stage]` for a question already queued or on the screen |

Conventions: integers little-endian. A **path** is `[u8 depth][depth × u32]` with the
hardened bit (`0x8000_0000`) set on hardened steps, depth 1 to 8. A **chain** is one byte:
Bitcoin 1, Ethereum 2, Solana 3, Litecoin 4, Dogecoin 5, Bitcoin Cash 6, Monacoin 7,
Electra Protocol 8, Tron 9, Namecoin 10 (`catcard_wallet::chain::ChainId`). A **reason**
is up to 64 bytes of UTF-8, for a person to read. A request with a payload it should not
have, or one byte too many, is `BadRequest` -- trailing bytes are refused, not ignored.

`busy` (the `NotNow` byte for a new question): `1` locked -- the PIN has not been entered,
the same gate as upgrades; `2` busy -- another host question, an upgrade offer, or an
unfetched result is in hand. `stage` (the `NotNow` byte for `HostResult`/`HostAbort`):
`0` nothing asked (or already fetched), `1` upload open, `2` waiting for the screen, `3`
the person is deciding, `4` the device is busy with **another session's** question.

#### Getting addresses

`HostAddresses` queues the question. On the device: "Computer asks for this wallet's
addresses. Share?", then the **account** (typed, as in the Address Explorer; empty is 0),
then -- on a multichain build -- a checklist of the chains this wallet offers
(Settings → Chains, in that order), all ticked, then "Share these? account N / M chains".
Cancel anywhere answers the host `Declined`. The person is never asked about address
types: every script type a chain supports is included.

The result:

```text
[u8 kind = 1][u8 version = 1][4 master fingerprint][u32 account][u8 count]
count × entry:
  [u8 shape][u8 chain][u8 format]
  [path: account]            m/purpose'/coin'/account'
  [path: address]            where `address` and `pubkey` are
  shape 1 (UTXO) only:       [u8 len][extended public key, base58]
  [u8 len][address, ASCII]
  [u8 len][public key]       33 bytes compressed secp256k1, or 32 ed25519
```

`shape` 1 is a **UTXO chain**: Bitcoin, and Litecoin, Dogecoin, Bitcoin Cash, Monacoin,
Namecoin and Electra Protocol on a multichain build -- one entry per script type **that
chain supports** in the registry (`chain::Chain::formats`): Bitcoin has all four
(P2PKH/BIP-44, P2SH-P2WPKH/BIP-49, P2WPKH/BIP-84, P2TR/BIP-86); Dogecoin and Bitcoin
Cash are BIP-44 only; the Litecoin family has no taproot. Each carries the account path
under that chain's SLIP-44 coin type -- Bitcoin's is 1 on testnet and regtest, every
other chain keeps its own -- the account's extended public key, and the first receive
address `.../0/0` in the chain's own format, as a check. The host derives the rest from
the key. **The extended key is written with the classic `xpub`/`tpub` version bytes on
every chain**: this firmware has no per-chain version bytes anywhere (its multichain
Keystone export carries raw key data, not base58), and inventing `Ltub`-style prefixes
here would be a guess. `shape` 2 is an **account chain** -- Ethereum/EVM, Tron, Solana --
with one address, its full path (`m/44'/60'/n'/0/0`, `m/44'/195'/n'/0/0`,
`m/44'/501'/n'/0'`) and its public key.

`format`: 1 P2PKH, 2 P2SH-P2WPKH, 3 P2WPKH, 4 P2TR, 5 EVM (EIP-55), 6 Tron, 7 Solana.

The device then **remembers, for this session only**, the account paths it showed --
each (chain, `m/purpose'/coin'/account'`). A later approval in the same session replaces
the list. It lives in the channel's per-session state and is dropped with the session: a
new pairing (`PairCommit`), a teardown after a bad record, `PairAbort`, a bus reset, logout or idle logout (both
reboot), and a change of the wallet in force (a passphrase).

#### Signing

The host uploads one **sign blob**:

```text
[u8 version = 1][u8 chain][u8 key count, 1..=32]
key count × [path]           the keys that must sign, from the address reply
[u32 tx length][tx bytes]    nothing may follow
```

`tx` is what the chain's own signer reads: a PSBT (binary, v0 or v2; base64 is accepted
too), an unsigned EVM transaction (RLP, typed or legacy), or a Solana transaction or
message.

1. `HostSignBegin [chain][length]`. Refused at once, before any byte is sent, for a chain
   this build does not sign ("Litecoin cannot be signed here" -- only Bitcoin PSBT, EVM
   and Solana sign; every address-only chain is refused by name), a chain not in this
   build, a chain nothing was shared on this session, or a length the board cannot take
   ("too big for this board": 16 KiB on the mk3, three eighths of the PSRAM elsewhere).
   It claims the memory: PSRAM through `psram::take`, so an upgrade offer or a card
   signing waits while it is held -- or, on the mk3, a heap block.
2. `HostSignData [offset][bytes]`, in order, up to 1018 bytes each (the reply to
   `HostSignBegin` says so). A chunk out of order is `BadRequest` and the upload is kept.
3. `HostSignCommit`. The blob is parsed and checked: the chain matches; **every listed
   key is strictly below an account path shown this session on that chain**; an EVM
   request lists exactly one key; a Solana key is hardened throughout. Any failure is
   `Refused` + reason and drops the upload. Otherwise the question is queued.

On the device: "Computer asks you to sign a <chain> transaction", then **the
ordinary review for that chain** -- the same code as signing from the card, a QR or the
tag: for Bitcoin `signtx` with PSBT v2 through its v0 view, proof-of-reserves detection,
the Spending Policy, hobbled mode, the fee cap and the sighash policy all unchanged; for
EVM the `evmtx` review with the signing address added at the top; for Solana the
`solanatx` review with the listed keys marked as this device's. On the USB sink the
review is followed by no "where should it go" choices at all -- "Sent back to the
computer".

Only the listed keys sign, and that is enforced where the key is chosen
(`signer::sign_input_listed`), not by removing signatures afterwards. A Bitcoin input this
wallet could sign with a key the request did not list is **left unsigned**, and the
review says how many ("N more of ours NOT signed: not asked for"). A listed key that
matches no input's derivation record (fingerprint, path, and the key the path really
leads to) is a refusal before the review. A Solana key that is not one of the
transaction's signers likewise. Stored WIF keys never sign for a host.

The result:

```text
Bitcoin  [u8 kind = 2][u8 psbt version, 0 or 2][u32 len][signed PSBT][u32 len][network tx]
EVM      [u8 kind = 3][u32 len][signed raw transaction]
Solana   [u8 kind = 4][u8 n][n × ([u8 signer slot][64-byte signature])][u32 len][transaction]
```

The PSBT goes back in the version it arrived in. The network transaction is present
(non-empty) only when every input is complete and it finalised; a proof of reserves
never carries one. The Solana transaction has the signatures already in their slots.

#### Polling and paging

`HostResult [offset]` answers `NotNow` + stage while the person decides, then once with
`Declined` or `Refused` + reason (after which the desk is free), or `Ok` +
`[u32 total][page]` with up to 448 bytes from `offset`. The host pages with rising
offsets until it has `total` bytes; the device releases the result -- and its memory --
when the page that reaches the end has been sent. An offset past `total` is
`BadRequest`.

A result is **bound to the session that asked**: another session polling gets `NotNow` +
stage 4. If the asking session ends while the person is deciding, their answer is
dropped when they give it; nobody else can fetch it. `HostAbort` drops an upload that
was not committed or a result that will not be fetched; it cannot withdraw a question
that is queued or on the screen.

Every blocking step -- derivation, signing, the person -- happens on the UI task. The
USB task only takes bytes, checks what can be checked without a key, and pages results
out, so a host polling never waits on anything but the poll itself.

#### Sealed requests may span frames

Every host-wallet reply fits one sealed reply, but a `HostSignData` chunk does not fit
one frame. So an `NcryMsg` record may span frames up to a bound: **1024 bytes of
plaintext** (`ncry::PLAIN_MAX`, opcode included), 1040 sealed. A record that fits one
frame is opened straight off the frame as before; a longer one is gathered into a heap
block of its own (never a new static: the Q1's boot stack is what `.bss` leaves over)
and **authenticated as a whole before anything in it is used**. A record over the bound
is refused on its first frame. Any record that does not authenticate, or has the wrong
size, tears the session down.

#### What this defends, and what it does not

These commands run only on a **paired** session (`Channel::host_wallet_allowed`): the
handshake committed before it revealed, both screens showed the same six-digit code, and
the person accepted it on the device while the host's user accepted it on the computer.
A **passive** observer on the wire learns nothing -- not the addresses, not the keys, not
the transaction. An **active relay** in the middle produces a different code on each
side, which the person sees and refuses; its one way through is a person who accepts
without comparing, or a one-in-a-million code collision per attempt (the device waits a
few seconds after each code shown, so attempts cannot be ground through).

What pairing does **not** defend against is a computer that is itself compromised: it
holds a genuine paired session. What protects the owner then is the same as for every
other signing path: the review shows what the device parsed -- the amounts, the
destinations, the fee, the signing address -- never what the host said it means, and only
keys under accounts the person chose to share in this session can sign at all.

`tools/usbclient.py hid --addresses` and
`tools/usbclient.py hid --sign FILE --chain btc|evm|sol --key m/84h/0h/0h/0/3 [--key ...]
[--out FILE]` drive both flows. A PSBT result is written to `FILE` (and the network
transaction, as hex, to `FILE.txn`); an EVM one as `0x`-hex; a Solana one as base64.

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
