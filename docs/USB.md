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

## USB modes: Off, ckcc, CatCard

**Settings → Hardware On/Off → `USB mode`** picks what the device is on the bus, for the
whole device:

| mode | the host sees | protocol |
|---|---|---|
| **CatCard** (default) | `39F2:0401`, "CatCard" | ours: everything above this section -- framing, pairing, host-wallet commands, upgrades, key injection and the monitor on bench builds |
| **ckcc** | `D13E:CC10`, "CatCard" | stock Coldcard's, so the `ckcc` command line, HWI and Sparrow work unchanged |
| **Off** | nothing: a real soft-disconnect | none |

It replaces the old per-wallet `USB port` on/off switch.

**Why ckcc mode presents stock's USB identity.** Compatibility, and the owner's
decision. Every existing Coldcard host tool finds its device by stock's VID/PID and speaks
stock's protocol; a device that answered only to ours would be invisible to them. The
section above on why *not* to use `0xD13E:0xCC10` still describes CatCard mode, and the
cost it names is real: in ckcc mode this device is indistinguishable from a Coldcard to a
host, which is exactly the point of the mode -- so it is never the default, and the screen
says so in one line when it is chosen ("computers will see it as a Coldcard").

**What stays ours in ckcc mode.** Only the VID/PID changes: the one HID interface, its two
64-byte interrupt endpoints, the report descriptor (vendor page `0xFF00`) and the strings
are the CatCard tables (`descriptor::DEVICE_CKCC` is `DEVICE` with two fields changed).
The host tools match the device on VID/PID and not on the report descriptor or the
product string (`hw-reference/usb-ckcc-protocol.md` §1.1), so the product string stays
"CatCard" rather than borrowing stock's name. Stock's mass-storage interface is not
presented; the Virtual Disk is still the USB Drive screen.

### Where the setting lives, and when it applies

The value is `cat_usbm` (`off` / `ckcc` / `catcard`) in the **pre-login** settings,
because what a host sees when the cable goes in cannot wait for someone to log in. A value
that is present but unreadable reads as CatCard. While no value is set, the wallet's old
`cat_usb` switch still counts after the PIN: `"0"` is Off, anything else CatCard
(`prelogin::effective_usb_mode`) -- so a wallet that had USB off keeps it off.

Boot-time bring-up is unchanged: the core comes up as CatCard and the PIN prompt attaches
it, exactly as before. The pre-login read (`settings::load_prelogin`) hands the mode to the
USB task, which applies it at its **first poll after the port is attached** -- Off by
soft-disconnect, ckcc or CatCard by a soft-disconnect and re-enumeration with the other
identity, the same dance as the keyboard switch. Never earlier: a core presented to a host
before anything services it wedges (`pinentry::unlock`).

**Recovery is always CatCard.** The failsafe (Cancel held at power-on), `recovery::headless`
and a boot that ends in `recovery::run` never read the setting, so they speak CatCard's
protocol with its key injection and monitor whatever the owner chose. A device left in
ckcc or Off mode with a dead panel is reached that way. Note what that means on a bench
build: in ckcc or Off mode the ordinary boot has no `InjectKey` before the PIN, so a device
that is driven blind needs the Cancel-held boot.

The **Keyboard EMU** switch is separate and only means something in CatCard mode: the
keyboard rides beside CatCard's interface, and stock's identity never carries it (its row
says so while the mode is not CatCard).

### The ckcc protocol

Written from `hw-reference/usb-ckcc-protocol.md`, in `catcard_usb::ckcc` (framing, session,
parsing, replies -- host-testable) and `crate::ckcc` (what each request does):

- **Framing**: 64-byte reports, a flag byte (`len | 0x40 encrypted | 0x80 last`) and 63
  payload bytes; an empty last report is a resync. Messages up to `MAX_MSG_LEN` (2060) --
  2076 once v3 is up, for its tag.
- **`ncry` v1, v2 and v3**: secp256k1 ECDH with an ephemeral key from the USB DRBG, session
  key `SHA-256(X‖Y)`. v1/v2: AES-256-CTR under that key, a stream each way from counter
  zero; v2 binds the link (everything encrypted, no second `ncry`). v3: four keys by
  HKDF-SHA256 over the transcript (`ccncry3`), AES-256-CTR per direction and a 16-byte
  HMAC-SHA256 tag over `dir ‖ seq ‖ len ‖ ciphertext`; any failure ends the link until the
  next bus session.
- **Tests**: known answers computed outside the crate (python-ecdsa, pyaes, `hashlib`/`hmac`)
  for the session key, v1 streams, v3's keys and tags; tampering, replay, short messages,
  framing limits and every parser. The module was also driven by the real host library as a
  black box over its simulator socket -- `cargo run -p catcard-usb --example ckcc_sim` and
  then `ckcc -x ...` -- for v1, v2 and v3 sessions, a 1500-byte ping, xpub, address, a PSBT
  upload/sign/download, a message signature and a firmware upload.

What the host tool does, observed that way: every `ckcc` run resyncs, then `ncry` v1 (the
library's default), then its command; `sign` checks `mitm` first. `upgrade` uploads the
image, reads `sha2`, uploads the image's 128-byte header again **after** the image (the
total grows by 128), reads `sha2` again, then sends `rebo`.

### Every opcode

"Held" means the reply waits until the UI task has derived what it needs (a second or so:
the seed is stretched each time); "polled" means `okay` at once and the host polls.
Everything that needs the seed or the person runs on the UI task from the menu loop -- the
same hand-off as upgrade offers and host-wallet requests -- so a request that arrives while
the person is inside another screen waits until they come back to the menu, and the host's
three-second read may time out first.

| opcode | here | how |
|---|---|---|
| `ncry` | implemented | v1/v2/v3; `mypb` carries the master fingerprint and xpub once learnt (zero and empty before the PIN, as stock with no secret) |
| `vers` | implemented | build date, version, bootloader version, `date T hhmm -v version`, board (`mk4`/`mk5`/`q1`/`mk3`) |
| `ping` | implemented | echo |
| `blkc` | implemented | `BTC`, or `XTN` on testnet/regtest |
| `mitm` | implemented, held | the session key signed with the master key (`message::sign_raw_digest`, recoverable, header 31+recid); must be encrypted |
| `xpub` | implemented, held | `menu::public_at` from the master; the master itself answered at once; must be encrypted |
| `show` | implemented, held | single-key address (`AF_CLASSIC`, `P2WPKH`, `P2WPKH_P2SH`, `P2TR`; old `0x17` read as P2TR); answered, then shown until a key |
| `p2sh` | implemented, held | a **registered** multisig wallet with the same M, N and form, whose cosigners' fingerprints and origins match the paths sent and whose own script at that branch/index equals the script sent; answered, then shown. Anything else: `err_Multisig wallet not registered` |
| `msck` | implemented, held | `int1` 1 if a registered wallet has that M, N and fingerprint XOR |
| `upld` / `sha2` | implemented | stock's rules (256-aligned, strictly in order, running SHA-256); PSRAM (`Use::Host`) on mk4/mk5/Q1, a heap block up to 16 KiB or the SPI-NOR staging area on the mk3; under the spending policy only a PSBT; in HSM mode only a binary PSBT of at most 2 MiB |
| firmware upgrade | implemented | an upload whose last block is 128 bytes repeating the header it carried at `0x3F80` (kept in RAM as it passed -- nothing is read back from PSRAM mid-upload) is an image: inspected (`Staged::stored_elsewhere`) and put on the **same approval screen** as a CatCard offer; a refused image is an `err_` on that block, so the host never sends the `rebo`; `rebo` does nothing while an image waits |
| `stxn` / `stok` | implemented, polled | the upload re-hashed on the UI task, then `signtx::host_sign` -- the ordinary review, spending policy and all, every derived key of ours allowed (stored WIF keys never sign for a computer); `strx` names the signed PSBT, or with `STXN_FINALIZE` the finished transaction when complete. In HSM mode the policy's rules replace the review screens (below); a refusal is `refu` |
| `dwld` | implemented | file 1 only: the last signed result; must be encrypted |
| `smsg` / `smok` | implemented, polled | `signmsg::sign_for_host`: the ordinary message confirmation, legacy signature; taproot refused (no legacy header for it). In HSM mode: `msg_paths` decides, nobody is asked |
| `pass` / `pwok` | implemented, polled | `passphrase::apply` with its own "use this wallet?"; `pwok` answers the new master xpub; must be encrypted |
| `enrl` | implemented | `msimport::from_text` on the uploaded file, its own review; answered `okay` at once |
| `logo` / `rebo` | implemented | `okay`, then half a second, then logout (or restart) |
| `bagi` | read only | the factory bag number; writing it is refused (`err_Not allowed`) |
| `hsms` | implemented, held | mk4/mk5/Q1. With a length and digest: the uploaded policy; without: the stored one. Checked on the UI task and answered -- `err_` with the reason when it fails, as stock raises -- then explained on the screen for the person to approve. See "HSM mode" |
| `hsts` | implemented, held | the status report, JSON (below) |
| `nwur` `rmur` `user` | implemented, held | HSM users (below); `nwur` answers the secret or password the host is to show, `user` outside HSM mode is a dry run answered with stock's words (`mismatch`, `replay`, ...) or nothing |
| `gslr` | refused | `err_Storage Locker not supported` in HSM mode, `err_HSM not active` otherwise: no policy this firmware accepts allows a read |
| `back` `bkok` `rest` | refused | `err_Unknown cmd`: backup and restore are on the card here, not over USB |
| `dfu_` | refused | `err_Unknown cmd`: never offered (bench units are RDP 2) |
| `msls` `msdl` `msgt` `msas` `mins` | refused | `err_Unknown cmd`, as stock 5.6.2 itself answers them |
| anything else, `XKEY…` | refused | `err_Unknown cmd`; on a bound (v2/v3) link the device also logs out, as stock does |

Gates, as the spec gives them: `xpub`, `mitm`, `pass` and `dwld` must arrive encrypted
(`err_must encrypt`); before the PIN only `vers`, `ping`, `ncry` and `blkc` are answered
(`err_Not ready: enter the PIN on the device`); under the spending policy `enrl`, `pass`,
`pwok`, a `bagi` write, `back`, `rest`, `dfu_` and firmware uploads are refused
(`err_Spending policy in effect`) -- stock lets `pass` through when its policy allows it,
and ours has no such allowance. A second request while a job is in hand is `busy`. The
HSM commands (`hsms` `hsts` `gslr` `nwur` `rmur` `user`) are answered only with Settings →
Spending Policy → **HSM Mode** enabled (`err_HSM commands disabled` otherwise, stock's
`hsmcmd`), never under the spending policy, and never on the mk3. In HSM mode only stock's
whitelist is answered (`err_Not allowed in HSM mode` for the rest).

**Not in ckcc mode**: key injection, the memory monitor, pairing and the host-wallet
opcodes. They exist only in CatCard mode.

### HSM mode

Unattended signing under a policy file, driven by stock's own host tool: `ckcc hsm-start`,
`ckcc hsm`, `ckcc user`, `ckcc auth`, `ckcc local-conf` work unchanged. mk4, mk5 and Q1 --
stock's `supports_hsm` is false on the Q1, but the Q1 speaks the same ckcc protocol and the
user asked for it there; not the mk3, which has no settings store. Written from
`hw-reference/hsm-policy-format.md`; the rules are `catcard_settings::hsm` and
`catcard_settings::hsmusers` (host-tested), the device side is `crate::hsm`.

**Setting it up.** Settings → Spending Policy → `HSM Mode` → Enable (our own key
`cat_hsmcmd`, off by default; stock's `hsmcmd` is named but not its value shape). Then,
from a computer with the device in ckcc USB mode:

```sh
ckcc user alice                 # a TOTP user; the device picks the secret, shows its QR
ckcc hsm-start policy.json      # uploaded, checked, then approved on the device
ckcc hsm                        # the status report
ckcc local-conf tx.psbt         # the 6-digit code the local operator types for tx.psbt
ckcc auth alice 123456          # alice's code, queued for the next PSBT
ckcc sign tx.psbt out.psbt      # judged by the policy, signed or refused
```

**Starting.** A policy comes from `hsms` (uploaded, up to 200 000 bytes, or the stored one)
or from the stored file `/hsm-policy.json` (stock's `/flash/hsm-policy.json`, the same
volume): main menu → `Start HSM Mode` on mk4/mk5, Settings → Spending Policy on the Q1, and
at every login while one is stored (stock offers it at boot). It is checked against this
device -- its users, its registered multisig wallets, its network's address syntax --
refused with the reason if anything is wrong, then **explained** on the screen (read to
the end before OK counts). A new policy also gets stock's **last chance**: its hash and a
digit picked at random from 1 2 3 4 6, which must be pressed. HSM mode needs the stored
wallet in force (no passphrase, no temporary seed) and no active spending policy.

**Running.** The menus are replaced by a status screen: approved, refused, what is left of
the velocity period, the local-code field, and a sweep that shows the device is alive --
never an amount. Only stock's whitelist of opcodes is answered, uploads must be binary
PSBTs, and every job is answered by the policy: `stxn` through `signtx`'s ordinary review
and signer with the rules in place of the screens (fee cap, sighash rules and delta-mode
spoiling all still apply; CCC's key C does not co-sign), `smsg` by `msg_paths`, `xpub` by
`share_xpubs` (the master always), `show` by `share_addrs`, `p2sh` by `p2sh` in
`share_addrs`. Nothing waits on a key: every "any key" returns at once and every question
is a no. The idle logout is off (`[I]`: the reference does not say; a mode meant to run
with nobody at the keypad cannot time out on it). A CatCard-mode request or upgrade offer
is turned down. A hundredth refusal logs the device out.

**The order a PSBT is judged in** (stock's §3.1): the local code is used up (right or
wrong, the key behind `next_local_code` changes); warnings refuse it unless `warnings_ok`;
every queued user's code is checked and its counter recorded (any bad one refuses); then
the rules, first match wins, and a velocity rule's spend is recorded. "Warnings" are what
this firmware's review would have flagged: a fee above the warning level, an unknown fee
(an unpriced foreign input), an unusual sighash type, change at an unusual index, and on
multichain builds the unified-hash opt-in (`[I]`: stock's own list of PSBT warnings is not
in the reference). The spender is `"1"` (single-signer) when every input of ours is
single-signature, a wallet's name when every one is from that one registered multisig
wallet, and anything else only matches a rule with no `wallet`.

**Stricter than stock, on purpose** (`[I]`): an unknown fee (an unpriced foreign input) is
refused even with `warnings_ok`, since it lets our coins leave as fee with no rule seeing
them; and `max_amount` / `per_period` are charged with what leaves this wallet -- the
outputs paid out, or what our inputs spend and does not come back when that is larger, so
our share of the fee counts. Stock charges the outputs alone.

**Known weakness, inherited from stock** (`[?]`): outside HSM mode `user` is an unlimited
dry-run oracle, and a TOTP slot is whatever the host names above the floor, so someone with
USB access and HSM Mode enabled could search for a far-future slot's code at leisure --
and using it moves that user's counter past every real code until then. The reference
gives no rate limit and no ceiling on the slot; none is invented here.

**Leaving.** Power off, or the host's `logo`. With `boot_to_hsm`, also its code typed on
the keypad within the first 60 seconds of uptime.

**Irreversible -- `boot_to_hsm`.** A policy with it goes straight into HSM mode at every
login, with no question. Its code, typed within a minute of power-on, is the only way back
to the menus (six digits send themselves, fewer are sent with OK) -- and a code that is not
all digits can never be typed, so such a device never leaves HSM mode again. A stored boot-to-HSM policy that no longer loads stops the
device at login (the reason on the screen, then logout) rather than run unprotected, as
stock does -- so a future change in what this firmware accepts could leave such a device
unable to reach its menus. Both are on the approval screens, asked about separately (press
4), and never a default: they come only from a policy file.

**Users** (`nwur`, `rmur`, `user`; Settings → Spending Policy → `User Management`, shown
while HSM Mode is enabled). Stock's own settings key `usr`, whose shape the reference pins:
`{name: [mode, base32 secret, last counter]}`, thirty at most, names of 2-16 characters not
starting with `_` (and, ours, no quote, backslash or control character). TOTP and HOTP take
a 10- or 20-byte secret or have the device pick 10 (an HOTP enrolment link starts the app at
counter 1); a password user stores
PBKDF2-HMAC-SHA512(password, SHA-256(`pepper` ‖ USB serial), 2500)[:32], and a password the
device picks is sixteen base32 characters. `nwur` answers the base32 secret, or the picked
password, for the host to show; with the QR bit (`0x80`) the device also shows an
`otpauth://` enrolment QR (issuer `CatCard <serial>`) or the password as a QR. TOTP accepts
the slot named and the two before it, never one at or before the last used; HOTP the nine
counters after the last (not counter zero: a fresh user's counter is zero too, and
accepting it would let the first code be sent twice -- `[I]`); a password token is
HMAC-SHA256 of the PSBT's hash.

**Status report** (`hsts`, `ckcc hsm`): `active` and `policy_available` (ours: the
reference lists only an active policy's fields), then stock's: `policy_hash`,
`next_local_code` (when a rule has `local_conf`), `last_refusal`, `approvals`, `refusals`,
and unless `priv_over_ux`: `summary`, `sl_reads`, `period`, `uptime` (seconds since boot),
`period_ends` (seconds left, or null), `has_spent` (per rule), `users` (every user on the
device), `pending_auth`. `summary` is cut short to keep the report in one reply.

**What this firmware refuses, where the reference stops** (each refused with a sentence,
never guessed; the policy is rejected before anything else happens):

| stock accepts | here | why |
|---|---|---|
| `set_sl`, `allow_sl` (Storage Locker), `gslr` | refused | the long secret's read/write selection on gate 18 method 6 and its stored encoding are not specified |
| `must_log` | refused | the microSD audit log's name and format are not specified; no log is written, so `never_log` holds by construction |
| `whitelist_opts.mode = "ATTEST"` | refused | where an output's attestation signature is carried and what it signs are not specified |
| BIP-322 proof-of-reserves PSBTs in HSM mode | refused | stock gates them by `msg_paths`, but which path of a proof is matched is not given `[?]` |
| a `*` path step that is hardened | refused | `*` matches exactly one unhardened step here: `cleanup_deriv_path`'s matching rule is not given, and this is never wider than stock's |
| more than 16 rules, 16 paths per list, 48 KB of canonical policy | refused | our bounds (the whitelist's 25 is stock's) |
| `min_pct_self_transfer` written with an exponent (`1e1`) | refused | kept as millionths of a percent, compared exactly (no floating point in the image); a seventh decimal rounds the threshold up |

**The policy hash is ours.** Stock hashes `ujson.dumps` of its own canonical dictionary,
whose key order and defaults are not in the reference; here it is SHA-256 of this
firmware's canonical form (keys in the reference's order, defaults left out, paths spelled
`m/84h/0h/0h`), which is also what is stored. It is shown on the last-chance screen and in
the report; it is not the number stock would print for the same file.

**Not done** (needs hardware, or the reference): none of this has run on a device yet --
the approval screens, the status screen and its keypad, boot-to-HSM at login, the policy
file on the internal flash, and a signing under a rule are all bench items. The simulator
stand-in runs the wire side against the real engine (`tools/ckcc_check.py --simulator
--hsm`).

### Checking it on hardware

```sh
tools/ckcc_check.py [--ckcc PATH] [--psbt FILE] [--hsm]
```

`--hsm` adds the HSM commands (HSM Mode must be enabled): the status report, a TOTP user
made, checked in a dry run and deleted, and a bad policy refused with its reason. Against
the simulator it also starts a policy (the stand-in approves at once) and checks that the
report says active, that `local-conf` answers and that user commands are refused. On a
device it stops short of starting one: that is the person's call.

With the device in ckcc mode, unlocked and holding a wallet: runs `ckcc version`,
`ckcc xpub`, `ckcc xpub m/84h/0h/0h`, `ckcc addr -s m/84h/0h/0h/0/0` (the device shows the
address; any key clears it) and, with `--psbt`, `ckcc sign` (approve it on the device).
`--ckcc` defaults to `$CKCC`, then `../work/ckcc-venv/bin/ckcc` beside the repository.
`--simulator` runs the same checks against `examples/ckcc_sim`. On Linux the device needs a
udev rule for `d13e:cc10`, like the CatCard one below with the other numbers.

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
| `0x0060` | `RngSample` | raw samples of the random sources, **inside a paired `NcryMsg` only**, every build, asked of the person once per session -- see "Raw RNG samples and health for a paired computer" below |
| `0x0061` | `RngHealth` | the random sources' health report, **inside a paired `NcryMsg` only**, every build |

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
pairing prompt at a time (`Busy`); and the attempt limits below. The prompt takes the screen
from the menu loop exactly as the upgrade offer does, checked after the keys are read, and
an answer applies only to the prompt that was shown.

**Why the commitment.** A relay in the middle runs one handshake with each side. If the
host revealed its key up front, the relay could wait for it and then grind its own
device-facing key offline until the two codes matched — 10^6 tries is a moment's work. With
the commitment the host is bound before it sees anything the relay sends, and the device's
key is fresh for each handshake, so within one handshake the relay cannot choose a
matching code: one chance in a million.

**Attempts are limited** (`ncry::PairGuard`). The commitment bounds one handshake, not how
many a relay may start. Facing the device, the relay learns the device's code the moment it
holds the device's key -- before it reveals anything, and before the device shows anything
-- so it could discard every non-matching key and ask for another, re-rolling the device's
code silently until it matched the one the host is already showing. So:

- **Every device key is charged** a five-second cooldown (`ATTEMPT_COOLDOWN_MS`), whether
  or not a code is ever shown; a `PairCommit` inside it gets `Busy`.
- **A handshake dropped before its reveal counts as abandoned**: replaced by a new
  `PairCommit`, ended by `PairAbort`, answered with a reveal that misses its commitment, or
  cut by a bus reset. An honest host reveals right after committing and never does this
  except by crashing mid-way.
- **After three abandoned handshakes** (`ABANDON_LIMIT`) the device blocks pairing: a
  `PairCommit` gets `Refused` + `pairing blocked: acknowledge it on the device`, and the
  screen says "Pairing blocked -- N pairing attempts abandoned" until the person dismisses
  it. Dismissing restores the full allowance; a completed pairing clears the count.

A relay therefore gets at most three silent re-rolls before the person has to act, three
chances in a million, instead of the thousands that fit in a host's two-minute wait
without the limits. `ncry::tests::a_relay_re_rolling_the_device_code_is_throttled_then_blocked`
runs exactly that loop.

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

### Raw TRNG capture: `DebugTrng` (`usb-trng-capture`, bench only)

`DebugTrng` (`0x0035`) hands out raw, **unmixed** bytes from one of the board's random
sources, so they can be assessed off the device with the NIST SP 800-90B estimators
(`docs/ENTROPY.md`, "Measuring the sources"). The bytes are exactly what
`trng::Trngs::read` returns -- what New wallet passes to `pool.add` -- before any mixing.

| source | | what |
|---|---|---|
| 1 | `chip` | the MCU's TRNG, `RNG_DR`, read directly (every board) |
| 2 | `se1` | SE1 through callgate 26 (mk4, mk5, Q1) |
| 3 | `se2` | SE2 through callgate 26 (mk4, mk5, Q1) |
| 4 | -- | retired: was the bootloader's read of the MCU TRNG (callgate 17), which is no longer read; the number is not reused |
| 5 | `se1wire` | SE1's `Random` over its raw single-wire bus (mk3) |

- **Empty payload** lists what this board has: `[u16 chunk_max][u8 count][u8 source]...`.
  `chunk_max` is 448 (fourteen 32-byte secure-element answers).
- **`[u8 source][u16 len]`**, `len` 1..=`chunk_max`, asks for a chunk. The first answer is
  `NotNow`: the USB side only records the request. The host asks again with the same
  payload until the reply is `Ok` + `[u8 source][u8 flags][u16 n][u32 chunk][n bytes]`.
  Collecting a chunk queues the next one of the same shape at once, so a host that keeps
  asking is not paying a round trip per chunk. A different request replaces a waiting
  one. `flags` bit 0 is *short* (`n < len`: the source went quiet within the read bound),
  bit 1 *refused* (a read failed; nothing more is queued). `chunk` counts every chunk read
  since boot, so a gap shows chunks that were read and discarded (a replaced request).
- `BadRequest` for a malformed payload, `Refused` for a source this board does not have,
  `UnknownOpcode` from a build without the feature.

**Where the reads happen is the safety property.** The USB task never reads a source. The
reads run in `rngread::serve`, which only the **main menu loop** calls, on the UI task.
Every seed flow -- New wallet, a temporary seed, key C -- runs on that task, synchronously,
from that loop, so while one is running the menu loop is not and no capture can happen;
the device answers `NotNow` until the person is back on a menu. For the same reason the MCU
TRNG's registers are never read by two tasks at once. It never touches the entropy pool,
reads nothing from it and feeds nothing into it. Each chunk is bounded (eight reads per 32
bytes asked), so a silent source ends a chunk short rather than holding the menu.

The samples are consecutive *within* a chunk. Between chunks the device keeps running --
the secure elements are asked for other things, the menu redraws -- which is also true of
the bytes the pool sees; 90B's non-IID estimators do not assume more.

It is a bench feature like the memory monitor: `usb-trng-capture` is a default feature,
`SHIP=1` (`--no-default-features`) strips it, and CI fails a published image whose strings
contain `trngcap:` -- the line the bench front end (`trngcap`) logs on its first request,
and its module's name. The reader itself is `rngread`, shared with the paired
`RngSample` below and present in every build; `DebugTrng` adds nothing to it but the
plaintext door, which is why only the door is stripped.

```sh
tools/trng_capture.py hid --list                   # this board's sources
tools/trng_capture.py hid                          # every source, 1,000,000 bytes each
tools/trng_capture.py hid --source se2 --bytes 2000000
tools/trng_assess.py captures/*.bin                # SP 800-90B, see docs/ENTROPY.md
```

A capture resumes: an existing `captures/<board>-<source>.bin` is appended to until it
holds `--bytes` (`--fresh` starts over).

### Raw RNG samples and health for a paired computer: `RngSample`, `RngHealth`

A release build has no `DebugTrng`, but its owner may still want to see their device's
random sources for themselves -- that is the point of this firmware (`docs/ENTROPY.md`).
Two commands give a paired computer that, in **every** build. Both are **sealed only**:
they exist only as the inner opcode of an `NcryMsg` on a **paired** session (the six-digit
code compared on both screens, `ncry` v2 above). In the clear, or on a session still in its
handshake, they are `UnknownOpcode`. `Identify` has no capability bit for them (every bit
is taken); a host finds out by asking: an older firmware answers `UnknownOpcode`.

They are in a range of their own, `0x0060`.., after the host-wallet commands: they are not
wallet commands and ask nothing of the wallet.

#### `RngSample` (`0x0060`)

The same request and chunk as `DebugTrng` (source numbers, list query, `[u8 source][u16
len]`, `NotNow` until ready, `[u8 source][u8 flags][u16 n][u32 chunk][n bytes]`), from the
same reader in the same place -- the main menu loop, never inside a seed flow, never the
pool. What differs:

- **The person at the device is asked, once per session.** The first chunk request of a
  paired session puts an approval page on the device -- "Share RNG samples?", main line
  "Raw bytes from this device's random generators, for the paired computer.", small print
  "Never your seed or keys; these bytes are not used for any wallet." / "Asked once while
  this computer stays paired." -- with the Utils grid's *Analyze RNG* picture on the Q1
  (none on the 64-row panels). It is asked from the main menu loop, like the security
  key's questions, so it waits for the person to be back on a menu. Until they answer,
  chunk requests are `NotNow` + `[2]` (`rng::wait::ASKING`); a chunk being read is
  `NotNow` + `[1]` (`READING`). **Yes** lets chunks leave for the rest of that session.
  **No**, or no answer within a minute, makes every chunk request in that session
  `Declined`. The session ending -- `PairAbort`, a torn-down channel, a bus reset, an
  unplug -- forgets the answer (and takes a question still on the screen down); the next
  session is asked afresh. The list query needs no answer. HSM mode answers no.
- **The secure elements are read only so often.** Each `Random` a secure element answers
  may write its EEPROM (below), so a paired session may make at most **128** reads of each
  secure element, and all sessions together **256** per power-up (`rng::SE_CALLS_PER_SESSION`,
  `SE_CALLS_PER_BOOT`; counted in calls, declined ones too). The chunk that spends the last
  carries flags bit 2, *limit*; a request after that is `Refused` + `[1]` (session) or `[2]`
  (power-up). SE1 through the callgate and SE1 over its own bus are one chip and share an
  allowance. The MCU TRNG, a register read, has no allowance. The bench's `DebugTrng` does
  not spend it and is not limited by it.
- **A secure element's chunk is read a few calls at a time** -- at most four per chunk, so
  the menu loop is back reading keys within about a tenth of a second -- and is never read
  ahead of a request: collecting one does not start the next. Expect short chunks (flags bit
  0) and a round trip each. The MCU TRNG's chunks are read whole and queued as `DebugTrng`'s
  are.

**Why the secure elements are limited.** The ATECC508A's datasheet (the 608A/B/C's full
datasheets are under NDA; the 608A's public summary calls it compatible with the 508A,
§3.1, with an "updated" RNG):
"Random numbers are generated from a combination of the output of a hardware RNG and an
internal seed value ... The internal seed is stored in the EEPROM and is normally updated
once after every power-up or sleep/wake cycle", and its `Random` mode 0 -- the one the mk3
driver sends -- "Automatically update[s] EEPROM seed only if necessary" (DS20005927A §3.3.2,
§9.15 Table 9-44) [C for the 508A, I for the 608]. The mk3's own bus driver
(`catcard_hal::se1swi`) wakes the chip for every read and sends it back to sleep, so on the
mk3 **every read is a seed write** against the 400,000-cycle rating (summary datasheets,
Table 2-1/3-1). Whether callgate 26 does the same on mk4/mk5/Q1 -- its mode, whether it
sleeps the chip between calls -- is not documented [?], nor is whether the DS28C36's RNG
writes its EEPROM (abridged datasheet; 100,000-cycle rating) [?]. Until they are known,
each read is counted as a write: 128 reads a session is at most 0.03% of the ATECC's rating
and 0.13% of the DS28C36's, 256 a power-up twice that. Both unknowns are in
`docs/HARDWARE-OPEN-ITEMS.md`; a confirmed "no EEPROM write" there is what would lift the
limit. A paired capture of a secure element is therefore a few kilobytes: enough to see a
stuck, biased or repeating generator, not the million samples a full SP 800-90B assessment
takes -- that stays the bench's job.

#### `RngHealth` (`0x0061`)

No payload, no question on the device: `Ok` + the report, which carries verdicts and counts
of verdicts, never a byte any source produced and nothing of the pool's state:

```text
[u8 version = 1][u8 pool flags][u8 hardware sources counted][u8 count]
count x [u8 source][u8 start-up][u8 failure][u8 last read][u16 tested][u16 trips]
```

| field | meaning |
|---|---|
| pool flags bit 0 | *published*: the menu has run since power-up. Without it every other field is zero and means nothing |
| bit 1 | *pool*: there is a boot entropy pool -- it met its policy at power-up (without one, no wallet can be made this session) |
| bit 2 | *policy met*: the pool meets its policy now (enough credited bits from enough distinct hardware sources) |
| bit 3 | *start-up enforced*: a New wallet has run, so a hardware source counts only once its start-up test passed |
| hardware sources counted | distinct hardware TRNGs the pool counts now |
| start-up | 0 pending, 1 passed, 2 failed (the source counts for nothing until power-off), 3 not tested (SE1's raw bus on mk3: mixed, credited zero) |
| failure | why the start-up test failed: 1 repetition count, 2 adaptive proportion, 3 constant output, 4 read too short |
| last read | the last read's continuous tests (SP 800-90B §4.4): 0 not read yet, 1 passed, 2 tripped |
| tested | bytes through the start-up window so far (1,024 once passed) |
| trips | reads that tripped a continuous test since power-up |

The pool lives in the UI task's frame and is never handed to the USB task: the menu loop
publishes this snapshot on every pass (`rngshare::publish`, a few comparisons per source),
and `RngHealth` returns the last one. The credited bit count, byte counts and the pool's
state are deliberately not in it. The value that tripped a test is not either.

```sh
tools/trng_capture.py hid --paired --list
tools/trng_capture.py hid --paired --source chip --bytes 1000000   # any build
tools/rng_report.py hid                                            # the health report
tools/rng_report.py hid --json
```

Both pair afresh (compare the code on both screens), and `trng_capture.py --paired` says
when the device is asking its owner. CatCard Manager (`TibaneLabs/catcard-mgr`, a separate
project) can offer the same to people who would rather not use a terminal: these two
commands need nothing but a paired session, the one its host-wallet features pair for.

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

With **Settings → Hardware On/Off → Keyboard EMU** on -- and `USB mode` CatCard, since
stock's identity never carries it -- the device enumerates as a *composite*: the wallet's vendor HID interface exactly as above, plus a **boot-protocol
USB keyboard** as interface 1. It exists so a BIP-85 password or a stored note can be
typed straight into a login form on the host, with no clipboard for the host's other
software to read (stock: "USB-keyboard emulation (for BIP-85 passwords)").

**It is off by default, and doubt reads as off.** The setting is `cat_kbemu` in the
wallet's own settings file, and only a literal `"1"` switches it on -- the opposite
direction from the disk switch (and the USB mode), which read as on. Those can only take
a channel away; this one gives the host a keyboard, and no unreadable byte should ever do
that. It is read after the PIN, so a locked device never shows a keyboard.

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

### The FIDO2 security key: another interface, off by default

With **Settings → Hardware On/Off → Security key** on (per wallet, `cat_fido`, only a
literal `"1"`; CatCard USB mode only), the composite gains a **CTAPHID interface** after
the others -- interface 1, or 2 beside the keyboard -- with its own interrupt endpoints
`0x83`/`0x03` and the FIDO usage page `0xF1D0`, so every browser finds it without a
driver. It answers CTAP2 and U2F (`catcard-fido`); the whole story is `docs/FIDO.md`.

The same rules as the keyboard: interface 0 is byte for byte unchanged (`catcard-usb`
tests both composites), the switch is read after the PIN and applied by
re-enumeration, and the disk and ckcc identities never carry it. One more, because it has
an OUT endpoint and a FIFO of its own: **with the switch off, no register of endpoint 3 is
ever written** -- `configure_fifos` sizes its TX FIFO only while it is on, and the
endpoint is opened, closed and serviced only once it has been presented this session --
so boot enumerates with exactly the register writes it always has.

On Linux the hidraw node needs the usual `uaccess` rule (below); browsers ship their own
FIDO rules for `0xF1D0` devices on most distributions.

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
five seconds after every device key it hands out, and blocks pairing after three
handshakes are dropped unrevealed -- see "Attempts are limited" in the channel section).

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

CatCard's own protocol is not the stock `ckcc` protocol and does not interoperate with it.
Compatibility with existing Coldcard tooling is the **ckcc USB mode**'s job -- a separate
identity and protocol the owner opts into, written from `hw-reference/usb-ckcc-protocol.md`
(see "USB modes" above) -- never this one's.


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
