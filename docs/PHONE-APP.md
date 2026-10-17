# Talking to a CatCard from a phone app

A guide for whoever writes the app: from a `TKSmartCard` in hand to a signed transaction,
with the bytes of every exchange. It gathers what `docs/USB.md` specifies for the
firmware into the order an app does things in, and nothing here is new protocol -- where
the two disagree, `USB.md` and the firmware's tests are right and this file has a bug.

The reference host is `tools/ccidclient.py` with `tools/ncry.py` and `tools/hostwallet.py`:
an independent implementation of everything below, in Python, that runs the same flows
against a device. When in doubt, run it and compare bytes.

## 1. The device as a phone sees it

In its CatCard USB mode the device is a composite: a vendor HID interface the phone cannot
open, and a **CCID smart-card reader** with one slot and one card that is always inserted.
The reader is class `0x0B`, answers every CCID command a host driver sends, and declares
*extended APDU level* exchange, so the app sends whole APDUs and never sees T=1 blocks.

On iOS use CryptoTokenKit:

1. `TKSmartCardSlotManager.default` lists the slots; the CatCard's is named after the
   USB product string, "CatCard". Watch `slotNames` -- the device enumerates the reader
   from power-on, before anyone has typed the PIN, so the slot can be there while the
   wallet is still locked.
2. `slot.makeSmartCard()` and `card.beginSession` power the card on; the ATR is
   `3B 87 81 31 FE 45 43 61 74 43 61 72 64 EE` (`CatCard` as the historical bytes, T=1).
   There is nothing to check in it; it is the same on every CatCard.
3. `card.transmit(_:)` sends one APDU and returns its response including the two status
   bytes. Send extended APDUs (below). Do not use the `send(ins:p1:p2:data:le:)`
   convenience with its automatic class byte; the class byte is part of the protocol.

The card has **no application to select**. `SELECT` and every instruction but the one
below is refused with an ISO status word, so skip the usual application discovery.

## 2. The one APDU

Everything is one proprietary APDU whose data is a CatCard **wire message**:

```text
CLA   80   a whole message, or the last chunk of one
      90   a chunk with more to follow (command chaining)
INS   CC
P1 P2 00 00
Lc    extended: 00 hh ll      (short Lc is accepted; chaining at 255 is then needed sooner)
data  first chunk:  [u16 opcode LE][u32 total LE][payload...]
      later chunks: [payload...]
Le    extended: 00 00  (65536) -- always send one
```

The response data is `[u16 status LE][u32 total LE][payload...]` with `SW 90 00`; `total`
equals the payload length. A chunk that is not the last is answered with no data and
`90 00`.

Keep every message in one APDU unless it is larger than 1024 bytes of data; nothing in
this guide is. (A firmware image is, and chains; `USB.md` has the rules.) With `Le` of
65536 every reply fits one response: the longest the firmware gives is 512 bytes of
payload. If you ever see `61 xx`, more waits for `00 C0 00 00 00 00 00` (`GET RESPONSE`),
and the pages concatenate.

Status words that mean the APDU itself was wrong, not the message:

| SW | |
|---|---|
| `6E 00` | class not `80`/`90` |
| `6D 00` | instruction not `CC` (or `C0`) |
| `6A 86` | P1 P2 not zero |
| `67 00` | the body is none of ISO 7816-4's four cases |
| `69 85` | `GET RESPONSE` with nothing waiting |

Worked example -- `Identify` (opcode `0x0002`, no payload), extended:

```text
→  80 CC 00 00  00 00 06  02 00 00 00 00 00  00 00
   CLA INS P1 P2  Lc=6     opcode 2, total 0    Le=65536
←  00 00  0D 00 00 00  02 00 01 C0 02 71 31 05 37 2E 30 2E 30   90 00
   status Ok  total 13   protocol 2, unlocked, caps C0, "q1", "7.0.0"   SW
```

(An unlocked Q1 running 7.0.0; the body's length follows the board and version strings,
see §3.)

The **message status** is the first two bytes of the response data, not the SW:

| status | | meaning |
|---|---|---|
| `0x0000` | `Ok` | |
| `0x0001` | `UnknownOpcode` | this build does not know the opcode, **or the opcode is only valid inside the channel** (§4) |
| `0x0002` | `NotNow` | well formed, wrong time: locked, busy, nothing to fetch; a byte of detail follows where §5 says |
| `0x0003` | `BadRequest` | the payload is not what the opcode takes; trailing bytes count |
| `0x0004` | `Declined` | the person at the device said no |
| `0x0005` | `Refused` | the payload is UTF-8 text saying why, to show the person |
| `0x0006` | `Busy` | a pairing prompt is up or cooling down; try again in a few seconds |

A `BadRequest` to a chunk carries one byte: `1` no six-byte header, `2` more payload than
`total`, `3` the last chunk left the message short, `4` more announced when it was whole.

## 3. First contact: `Identify` and `Ping`

`Identify` (`0x0002`, empty payload) answers:

```text
[u16 protocol version = 2][u8 state][u8 caps][u8 n][board, n bytes][u8 m][version, m bytes]
```

- `state` bit 0 **UNLOCKED**: the PIN has been entered. Bit 1 BLANK: no PIN set yet.
- `caps` bit 7 **PAIRING** and bit 6 **HOST_WALLET** are what the app needs; both are set
  together on every normal boot. Bits 0 and 3 (key injection) and bit 2 (memory monitor)
  mean a bench build that no owner should be using.
- `board` is `mk3`, `mk4`, `mk5` or `q1`; `version` is the firmware version string.

Refuse to go on without protocol version 2 and both capability bits, and tell the person
to unlock the device when UNLOCKED is clear: nothing below works before the PIN, and
the device says so with `NotNow`.

`Ping` (`0x0001`) echoes up to 64 bytes of payload, for a round-trip check.

## 4. Pairing: the encrypted channel and the code

Everything that matters -- addresses, signing -- travels inside a channel the app pairs
afresh **on every connection**. Nothing is stored on either side. The person compares a
six-digit code on the phone and on the device; that comparison is the whole defence
against a relay in the middle, so show the code large and make the person tap "same
code", never pre-accept.

Primitives: X25519, HKDF-SHA256, ChaCha20-Poly1305 (RFC 8439, 12-byte nonce), SHA-256.
CryptoKit has all four (`Curve25519.KeyAgreement`, `HKDF<SHA256>`,
`ChaChaPoly`).

### 4.1 The handshake, three messages

```text
host_priv  ← 32 random bytes       host_pub = X25519(host_priv, 9)
commit     = SHA-256("catcard-pair-v2/commit" ‖ host_pub)                 32 bytes

→ PairCommit (0x0042)   payload commit
←   Ok, payload device_pub (32)      NotNow before the PIN; Busy while a prompt is up or
                                     cooling down; Refused + text when pairing is blocked
→ PairReveal (0x0043)   payload host_pub
←   Ok, empty                        BadRequest if host_pub does not hash to commit
```

Commit before reveal, so a relay cannot grind a matching code; the device charges a
five-second cooldown per handshake and blocks after three abandoned ones, so never retry
in a loop -- one handshake per tap.

### 4.2 The key schedule

```text
shared     = X25519(host_priv, device_pub)          refuse if all zero
transcript = commit ‖ device_pub ‖ host_pub          96 bytes, wire order
okm        = HKDF-SHA256(salt = transcript, ikm = shared, info = "catcard-ncry-v2", 64)
send_key   = okm[0..32]      host → device
recv_key   = okm[32..64]     device → host
code       = BE_u64( HKDF-SHA256(salt = transcript, ikm = shared,
                                 info = "catcard-pair-v2/code", 8) ) mod 1_000_000
```

Show the code as `ddd ddd`, zero-padded. The device shows the same and asks its owner.

### 4.3 Sealed records

A record is `ciphertext ‖ 16-byte tag`: ChaCha20-Poly1305 with the direction's key, empty
AAD, and nonce = `LE_u64(counter) ‖ 00 00 00 00`. Each direction counts its own records
from 0; the first thing the host seals uses nonce 0, the first thing the device seals
uses nonce 0 with the other key. Never reuse a counter; a record that fails to open ends
the session on the device, and it will on the phone too.

The plaintext is an ordinary message: `[u16 opcode LE][payload]` going in,
`[u16 status LE][payload]` coming back. A sealed message is carried by `NcryMsg`
(`0x0041`):

```text
→ NcryMsg   payload = seal_host(  [u16 opcode][payload] )
← Ok        payload = seal_device([u16 status][payload] )      open it; that is the answer
← NotNow                                                      no session (timed out, torn down)
← Declined                                                    the device's owner said no
```

Both statuses are checked: the outer one tells you about the channel, the inner one
about the command.

### 4.4 Confirming

After `PairReveal`, once the person taps "same code":

```text
→ NcryMsg( seal( 44 00 ) )               PairConfirm (0x0044), empty payload
← Ok, seal( 02 00 )   inner NotNow:  the device's owner has not answered yet -- send
                                     again after half a second (a fresh record each time)
← Ok, seal( 00 00 )   inner Ok:      paired
← Declined                           refused on the device
← NotNow                             the prompt timed out (two minutes)
```

If the person taps "different" or cancels, send `PairAbort` (`0x0045`, empty, always
`Ok`) so the device's prompt goes away. Until the session is paired, the only sealed
opcode the device accepts is `PairConfirm`; anything else tears the session down.

### 4.5 A worked vector

Fixed scalars, so an implementation can be checked offline (these are the firmware's
own test vector, `ncry::tests::known_answer_pins_the_wire_format`, and
`tools/ncry.py --selftest`):

```text
host_priv  77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
host_pub   8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
commit     41b5c26ca1226fb39c62a654157393a96c0179a91af67a6f62f7bd9ad72f144a
device_pub de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f
code       398 660
send_key   b631096c19e44d3db26d6badc589fa733cc7834370b5a10294cc0dc172b572bb
recv_key   8d6609a5de2fc1db62a52b7097c9a96540e77fad90341b703bdb2aa2a97259a6

seal_host(counter 0, "catcard")  = 80a853252814c6dd77e16e59d98cf64481bf28f853b316
seal_host(counter 0, 44 00)      = a7c96031987b403d35728dfcb775d969c2a8
                                   (ciphertext, then the 16-byte tag)
```

(The device's private scalar for this vector is
`5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb`, for an app that
wants to simulate the other side in its tests.)

## 5. Asking for addresses

Inside the channel. `HostAddresses` (`0x0050`, empty):

- `Ok`: the question is on its way to the device's screen.
- `NotNow` + `[1]`: locked. `NotNow` + `[2]`: the device has another question, an
  upgrade offer or an unfetched result in hand.
- `UnknownOpcode`: you sent it in the clear, or before pairing completed.

Then poll `HostResult` (§7). The person chooses the account number and, on a
multichain build, which chains, then confirms. The result:

```text
[u8 kind = 1][u8 version = 1][4 master fingerprint][u32 account][u8 count]
count × entry:
  [u8 shape][u8 chain][u8 format]
  [path]                     the account path  m/purpose'/coin'/account'
  [path]                     the address path
  shape 1 only:  [u8 len][account xpub, base58 text]
  [u8 len][address, ASCII]
  [u8 len][public key]       33 bytes compressed secp256k1, or 32 ed25519
```

A **path** is `[u8 depth][depth × u32 LE]`, hardened steps with bit 31 set. `chain`:
Bitcoin 1, Ethereum/EVM 2, Solana 3, Litecoin 4, Dogecoin 5, Bitcoin Cash 6, Monacoin 7,
Electra Protocol 8, Tron 9, Namecoin 10. `format`: 1 P2PKH, 2 P2SH-P2WPKH, 3 P2WPKH,
4 P2TR, 5 EVM, 6 Tron, 7 Solana. `shape` 1 is a UTXO chain: one entry per script type
with the account's extended public key (always `xpub`/`tpub` version bytes, whatever the
chain) and the first receive address as a check; derive the rest yourself. `shape` 2 is
an account chain with its one address.

**The device remembers which account paths it showed this session.** A later signing
request may only name keys under those paths; a key under an account that was never
shared is refused. Ask for addresses first, every session.

## 6. Signing

Build the **sign blob**:

```text
[u8 version = 1][u8 chain][u8 key count 1..32]
key count × [path]        the signing keys, each strictly below a shared account path
[u32 tx length][tx bytes] nothing after it
```

`tx` is what the chain's signer reads: a binary PSBT (v0 or v2) for Bitcoin, an unsigned
RLP transaction (legacy or typed) for EVM, a transaction or message for Solana. Only
Bitcoin, EVM and Solana sign; the other chains are address-only and `HostSignBegin`
refuses them by name.

```text
→ HostSignBegin (0x0051)  [u8 chain][u32 blob length]
←   Ok + [u32 largest chunk]          NotNow + busy byte;   Refused + reason text
→ HostSignData  (0x0052)  [u32 offset][bytes]      in order, chunks of at most the
                                                    size announced (never more than 1018)
←   Ok + [u32 received so far]        BadRequest for an offset out of order
→ HostSignCommit (0x0053) empty
←   Ok: queued for the person         Refused + reason (the blob failed its checks)
```

On any failure after `HostSignBegin` succeeded, send `HostAbort` (`0x0055`) so the upload
is dropped and the memory freed. The person then sees the chain's ordinary transaction
review on the device and approves or cancels; poll `HostResult`.

The result:

```text
Bitcoin  [u8 kind = 2][u8 psbt version][u32 len][signed PSBT][u32 len][network tx]
EVM      [u8 kind = 3][u32 len][signed raw transaction]
Solana   [u8 kind = 4][u8 n][n × ([u8 signer slot][64 signature])][u32 len][transaction]
```

For Bitcoin the network transaction is non-empty only when every input is complete and
the device could finalise; otherwise take the PSBT and finalise or pass it on yourself.
Only the keys you listed sign; an input the wallet could have signed with an unlisted key
is left unsigned, and the review tells the person so.

## 7. Polling for the answer

`HostResult` (`0x0054`) with `[u32 offset]`, inside the channel:

- `NotNow` + stage: `1` upload open, `2` waiting for the screen (the person is in
  another menu), `3` the person is deciding, `0` nothing asked or already fetched, `4`
  another session's question is in hand. Poll every half second; the person may take
  minutes. Give up only on your own UI's cancel.
- `Declined`: the person said no. `Refused` + text: the device could not do it; show the
  text.
- `Ok` + `[u32 total][page]`: up to 448 bytes from `offset`. Keep asking with
  `offset = bytes so far` until you hold `total`. The device frees the result when the
  last page goes out, so fetch it in one go.

A result belongs to the session that asked. If the app reconnects, pairs again, and polls,
it gets stage `4` or `0`: the old answer is gone. Never leave a question on the device
you will not fetch; `HostAbort` cannot withdraw one once it is on the screen.

## 8. Putting it together

```text
slot appears → beginSession → Identify
  not UNLOCKED → "unlock your CatCard", retry Identify
PairCommit → PairReveal → show code → person taps same → PairConfirm until inner Ok
HostAddresses → poll HostResult → show accounts
...
build blob → HostSignBegin → HostSignData × n → HostSignCommit → poll HostResult
  Declined / Refused → tell the person
  Ok → broadcast
```

Ending: `PairAbort` is polite but optional; unplugging, a bus reset or the device's
logout ends the session, and the next connection pairs from scratch.

## 9. Things that bite

- **Counters.** A sealed record with a reused or skipped counter fails authentication and
  tears the session down; the symptom is `NotNow` on the next `NcryMsg`. Count per
  direction, from zero, including the `PairConfirm` records you resend while waiting.
- **The six-byte header is in the APDU data, not in P1 P2.** `total` is the payload
  length; a mismatch is `BadRequest` with a reason byte.
- **One APDU in flight.** CCID is strictly command-then-answer; CryptoTokenKit serialises
  for you, but do not open two sessions.
- **Locked device.** Everything but `Identify`, `Ping` and the log answers `NotNow`
  before the PIN.
- **Only the one session.** A second app, or the same app after a reconnect, is a new
  pairing with a new code; the device's per-session memory of shared accounts starts
  empty.
- **Bench builds.** `caps` bits 0, 2 or 3 set means the firmware is a development image
  whose host can press keys or read memory; warn the person.
