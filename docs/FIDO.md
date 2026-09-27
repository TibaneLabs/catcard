# The FIDO2 security key

CatCard can be a **FIDO2 / U2F security key** for websites: the second factor (or the
only one) a browser asks for with WebAuthn. It speaks CTAP2 and U2F (CTAP1) over USB HID,
and every credential key is **derived from the wallet in force** -- nothing is stored on
the device, and a restored seed restores every login.

Stock has no security key; this is a CatCard addition.

| | |
|---|---|
| switch | Settings → Hardware On/Off → `Security key` (`cat_fido`, per wallet, off by default) |
| USB | an extra HID interface, usage page `0xF1D0` (FIDO), endpoints `0x83`/`0x03` |
| protocols | CTAP 2.1 (`FIDO_2_0`, `FIDO_2_1`) and U2F (`U2F_V2`) |
| algorithm | ES256 only (ECDSA P-256, SHA-256), RFC 6979 deterministic nonces |
| attestation | `packed` self-attestation (CTAP2); a per-registration self-signed certificate (U2F) |
| sign counter | always 0 ("no counter", WebAuthn L2 §6.1.1) |
| code | `crates/catcard-fido` (protocol, host-tested), `crates/catcard-fw/src/fido.rs` (glue) |
| check | `tools/fido_check.py` (python-fido2) |

## Turning it on

Settings → Hardware On/Off → `Security key` → `On`, and confirm "computers see a FIDO
key". The device leaves the bus and comes back with the security-key interface added:
the wallet's own interface is unchanged (interface 0, same endpoints), the keyboard (if
Keyboard EMU is on) stays interface 1, and the security key comes last.

- **Per wallet**, like Keyboard EMU, and read after the PIN. A locked device never offers
  a security key, and **boot enumerates exactly as it always has**: the interface is
  added later, by a runtime re-enumeration when the wallet's settings are read. Before
  login there would be nothing to answer with anyway -- every key comes from the wallet --
  and a browser watches for a key to appear while it waits, so a key that appears after
  login is found.
- Only in the **CatCard** USB mode. Stock's identity (ckcc mode) and USB Drive never
  carry it; with the port Off there is nothing to enumerate.
- The failsafe and recovery paths never read wallet settings, so they never offer it.

Doubt reads as **off**: only a literal `"1"` under `cat_fido` turns it on.

## What a site sees, and what the person sees

Every request that needs a person takes the screen through the menu loop's host hand-off
(the same one host-wallet and ckcc requests use) and says, in plain words:

- **Security key** -- what is asking;
- the **site** (the RP ID, e.g. `github.com`), or "an older (U2F) request: the computer
  does not say which site" for U2F, which only sends a hash of it;
- for a registration, the **account** (`user.name`, else `displayName`), printable ASCII
  only, cut at 56 characters;
- **which wallet** is in force (`MASTER`, `PASSPHRASE`, `BIP85`, ... and the fingerprint
  when this session knows it) -- because each is a different security key;
- `ENTER to allow, CANCEL to refuse` (`y`/`x` on the mono boards). A question longer than
  the screen scrolls, and confirm pages down until the end has been seen.

The host hears `KEEPALIVE UPNEEDED` every 100 ms while the question is up. Nobody answers
in **30 s**: `CTAP2_ERR_USER_ACTION_TIMEOUT`. The browser cancels: the screen goes and it
hears `CTAP2_ERR_KEEPALIVE_CANCEL`. Cancel on the device: `CTAP2_ERR_OPERATION_DENIED`.

A request that arrives while the person is inside another flow waits for the menu (with
keepalives) for up to 30 s, then is answered as timed out.

`CTAPHID_WINK` shows "the computer is pointing at this one" for a second and a half.

## What is supported

| CTAP2 command | |
|---|---|
| `authenticatorGetInfo` | answered at once, without the screen |
| `authenticatorMakeCredential` | ES256, `excludeList` honoured, `packed` self-attestation |
| `authenticatorGetAssertion` | `allowList` required; the first id that is this wallet's for this site |
| `authenticatorReset` | see [Reset](#reset-irreversible) |
| `authenticatorSelection` | one press |

GetInfo says: versions `U2F_V2`, `FIDO_2_0`, `FIDO_2_1`; AAGUID
`54a5d3d6-f9d6-4b05-bdac-7cc541efc8f1` (a random version-4 UUID generated once for this
firmware, 2026-09-27 -- it identifies the model, never a unit or a wallet); options `rk: false`,
`up: true`, `plat: false`, and no `uv` or `clientPin` key (absent means unsupported);
`maxMsgSize` 1024; `maxCredentialCountInList` 8; `maxCredentialIdLength` 64 (ours are 33);
transports `usb`; algorithms `[{alg: -7, type: "public-key"}]`.

| U2F | |
|---|---|
| `U2F_VERSION` | `U2F_V2` |
| `U2F_REGISTER` | a key handle that is also a CTAP2 credential id |
| `U2F_AUTHENTICATE` | `0x07` check-only, `0x03` enforce presence, `0x08` don't enforce |

Short and extended APDU encodings are both accepted.

**U2F presence works the U2F way.** A command that needs a press answers
`SW_CONDITIONS_NOT_SATISFIED` (0x6985) at once -- U2F has no keepalive -- and the device
then asks on its screen. The host keeps re-sending; once the person allows, the next
retry for the same site within 10 s succeeds.

**One key space.** A U2F key handle and a CTAP2 credential id are the same thing, bound to
the same 32-byte site hash, so a site whose U2F AppID hashes like its RP ID (or that uses
the WebAuthn `appid` extension) finds either from the other.

### Silent requests

`GetAssertion` with `up: false`, and U2F `0x07`/`0x08`, are answered without the screen,
with the UP flag clear. That is spec behaviour and what browsers use to find which of a
list of keys holds a credential; a relying party that needs presence rejects an
assertion without UP. They still need the wallet's FIDO master, so the first request of
a session may show the seed-reading progress screen (see below).

### What is refused, and how

| request | answer |
|---|---|
| no ES256 in `pubKeyCredParams` | `CTAP2_ERR_UNSUPPORTED_ALGORITHM` |
| `rk: true` (resident key, passkey) | `CTAP2_ERR_UNSUPPORTED_OPTION` |
| `uv: true` | `CTAP2_ERR_INVALID_OPTION` (no built-in user verification) |
| `up: false` on MakeCredential | `CTAP2_ERR_INVALID_OPTION` |
| `pinUvAuthParam` without / with a protocol | `CTAP2_ERR_MISSING_PARAMETER` / `CTAP1_ERR_INVALID_PARAMETER` |
| `enterpriseAttestation` | `CTAP1_ERR_INVALID_PARAMETER` |
| `rk` in GetAssertion options | `CTAP2_ERR_UNSUPPORTED_OPTION` |
| GetAssertion with no (matching) `allowList` | `CTAP2_ERR_NO_CREDENTIALS` (after the person answers, unless `up: false`) |
| `authenticatorClientPIN`, anything unknown | `CTAP1_ERR_INVALID_COMMAND` |
| `authenticatorGetNextAssertion` | `CTAP2_ERR_NOT_ALLOWED` |
| no wallet (logged out, no seed, a WIF key) | `CTAP2_ERR_OPERATION_DENIED` / U2F `0x6985`, never a question |
| malformed CBOR, non-canonical CBOR | `CTAP2_ERR_INVALID_CBOR` / `CTAP2_ERR_CBOR_UNEXPECTED_TYPE` |
| a malformed CTAPHID frame | a `CTAPHID_ERROR` frame; never a hang |

The CBOR reader is strict, as CTAP 2.1 §8 says a decoder should be: shortest-form
integers and lengths, definite lengths, map keys in canonical order and never repeated,
no tags or floats, nesting at most 6 deep, UTF-8 text, nothing trailing.

### Not supported

- **Resident keys / passkeys** (`rk: true`, discoverable credentials, credential
  management). The device stores nothing per site; a passkey would need storage and a
  way to list and delete it.
- **clientPIN and user verification** (`uv`). The device PIN protects the whole wallet at
  login, but CTAP has no way to say so; a site demanding UV will not accept this key.
- **NFC.** The NFC chip on the mk4/Q1 is a passive tag the device writes; it cannot run
  the ISO 14443-4 card emulation CTAP-over-NFC needs.
- **BLE** (no radio), **enterprise attestation**, and every **extension**
  (`credProtect`, `hmac-secret`, `largeBlob`, `minPinLength`, ...): parsed, ignored, never
  answered.

## The keys

```text
master     = HMAC-SHA512(key = "CatCard FIDO v1",
                         msg = chain_code ‖ private_key ‖ generation (u32, big-endian))
             over the wallet in force's BIP-32 master node m
mac_key    = master[0..32]
key_key    = master[32..64]

credential id (33 bytes) = 0x01 ‖ nonce (16 bytes, the UI DRBG) ‖ tag (16 bytes)
tag        = HMAC-SHA256(mac_key, "id" ‖ 0x01 ‖ rpIdHash ‖ nonce)[0..16]
private key: the first d_i with 1 ≤ d_i < n, for i = 0, 1, ... (at most 16 tries):
  d_i      = HMAC-SHA256(key_key, "key" ‖ 0x01 ‖ rpIdHash ‖ nonce ‖ i), big-endian
```

`rpIdHash` is SHA-256 of the RP ID (U2F: the application parameter). A credential id is
checked by recomputing its tag, compared in constant time; an id made by another wallet,
another generation or for another site fails and is "not ours".

**What this means for you:**

- **Restore the seed, restore the logins.** The same seed words (and the same
  passphrase) on any CatCard answer for every site registered here -- the credential ids
  the sites hold carry everything else. Back up the seed and you have backed up the
  security key.
- **A passphrase wallet is a different security key.** So is each BIP-85 child and each
  loaded XPRV: different master node, different keys. A site registered while the
  passphrase was on only accepts the device with that passphrase on. The screen names the
  wallet in force on every question for exactly this reason.
- A **WIF key** has no master node: the security key refuses to work while one is in force.
- The FIDO master is **independent of every Bitcoin key**: no BIP-32 or BIP-85 derivation
  keys HMAC with this label, and the HMAC is one-way, so FIDO keys reveal nothing about the
  wallet and vice versa.

All of it runs inside `keywork::run` (interrupts masked; `catcard-fido`'s key functions take
`&KeyWork`), and every secret is `Zeroize` + `ZeroizeOnDrop`. The derived master -- 64 bytes
that say nothing about the wallet's own keys -- is cached for the session once made,
because making it means fetching the seed (≈1.6 s of secure-element key stretch on an mk4)
and stretching the words (PBKDF2, 2048 rounds): paying that for every silent probe a
browser sends would make the key unusable. The cache is wiped when the wallet in force
changes (`pubkeys::forget`) and after a reset.

ECDSA is purecrypto 0.9.3's P-256 with RFC 6979 nonces -- deterministic, so no randomness
is involved in signing and none can leak the key -- and a constant-time windowed ladder
for the fixed-base multiplication (the 60 KB `p256-table` stays off) and a Fermat
inversion for the nonce. The only randomness is the 16-byte credential nonce, from the UI
DRBG, never the entropy pool.

### Checking the derivation

The one vector pinned in `catcard_fido::keys` (`a_vector_cross_checked_with_python_cryptography`)
was reproduced outside this code:

```python
import hmac, hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
m = hmac.new(b"CatCard FIDO v1", bytes([7]*32) + bytes([9]*32) + (0).to_bytes(4, "big"), hashlib.sha512).digest()
rp = hashlib.sha256(b"example.com").digest(); n = bytes([0x11]*16)
print((b"\x01" + n + hmac.new(m[:32], b"id\x01" + rp + n, hashlib.sha256).digest()[:16]).hex())
k = ec.derive_private_key(int.from_bytes(hmac.new(m[32:], b"key\x01" + rp + n + b"\0", hashlib.sha256).digest(), "big"), ec.SECP256R1())
print(k.sign(b"catcard fido vector", ec.ECDSA(hashes.SHA256(), deterministic_signing=True)).hex())
```

The id, the public key and the RFC 6979 signature come out byte-identical (cryptography
50.0.1).

## The sign counter is always zero

WebAuthn defines a counter of 0 as "this authenticator keeps no counter" (L2 §6.1.1), and
a relying party then skips its clone check instead of failing it. A real counter would be a
settings-flash write -- a key derivation and a sealed-file rewrite -- at every sign-in, and
on seed-derived keys it would detect nothing: a restored seed on a second device *is* a
clone, made on purpose. Some old U2F-only servers insist the counter rise; they will
refuse this key, which is the honest outcome.

## Attestation

**CTAP2: `packed` self-attestation** -- the statement is signed by the new credential's
own key, `alg: -7`, no `x5c`. It is a real, verifiable statement (WebAuthn L2 §8.2), where
`none` would be none at all; and a device attestation key would either be shared by every
CatCard (proving nothing) or unique to one (linking every site it registers with).

**U2F: a self-signed certificate per registration.** U2F must carry an X.509 certificate;
each registration gets its own v1 certificate (`CN=CatCard FIDO`, valid 2000 to 9999, a
random serial) signed by that registration's key, so no two registrations can be linked
through it. A server that checks U2F attestation against a vendor list will not find it.

## Reset (IRREVERSIBLE)

`authenticatorReset` (Chrome: Settings → Privacy and security → Security keys → Reset)
**raises this wallet's FIDO generation** (`cat_fidogen` in the wallet's settings). Every
credential id made before then fails its tag from then on: **every site registered with
this wallet's security key stops accepting it, and nothing brings those logins back.**

- Only within **10 s** of the security key appearing on USB (CTAP 2.1 §6.6): the interface
  appears after login, so replug, log in, and let the browser send it. Otherwise
  `CTAP2_ERR_NOT_ALLOWED`, with no question.
- **Asked twice** on the device, both bounded to 30 s: first confirm, then **the 7 key**
  (not confirm, so a confirm pressed twice out of habit does not do it). Cancel at either
  is `CTAP2_ERR_OPERATION_DENIED`.
- Never a default and never automatic; `tools/fido_check.py --reset` makes you type RESET.
- It is **per wallet**: other wallets (a passphrase, a BIP-85 child) are untouched.
- It is **per device**: another CatCard holding the same seed has its own generation. If
  you reset here because a site's credential leaked, reset every device with this seed.
  Conversely, restoring the seed on a new device starts at generation 0: logins retired by
  a reset on the old device work again there until it is reset too.
- A generation value that cannot be read is **not** read as 0 (that would revive retired
  credentials): the security key refuses to work for that wallet until a reset writes a
  new, random, generation.

## Transport

| | |
|---|---|
| interface | 1 (or 2 when Keyboard EMU is on), HID class, no subclass/protocol |
| endpoints | `0x83` interrupt IN, `0x03` interrupt OUT, 64 bytes, 5 ms |
| report descriptor | CTAP 2.1 §11.2.8.1: usage page `0xF1D0`, usage `0x01`, 64-byte in and out |
| TX FIFO | endpoint 3, 64 words, programmed only while the switch is on |
| CTAPHID | INIT (broadcast channel allocation, nonce echo, caps `CBOR`+`WINK`, MSG supported), PING, MSG, CBOR, CANCEL, WINK, KEEPALIVE, ERROR; LOCK is not offered (`ERR_INVALID_CMD`) |
| limits | messages up to 1024 bytes; 3 s between packets of one message (`ERR_MSG_TIMEOUT`); one channel processing at a time, the others `ERR_CHANNEL_BUSY` |

With the switch off, **no register of endpoint 3 is touched** -- not its FIFO, not its
control registers, not its interrupt flags -- so a device that never turns it on runs
exactly the register sequence it always did (`Otg::fido_opened`).

Memory: the CTAPHID state is a few hundred bytes in the USB task (`.bss` grew 552 bytes on
the Q1). A request leases **1 KB** from the heap while it is in flight and the UI task
leases **another 1 KB** for the answer, so a request peaks at 2 KB of heap; a reset's
settings write takes the usual two settings buffers on top. Nothing is held between
requests.

## Timing

P-256 without the comb table does one fixed-base multiplication per public key and per
signature. Measured on the host it costs the same as purecrypto's secp256k1 public key,
which is ≈120 ms on an mk4/Q1 (120 MHz): so **≈120-150 ms** per public key and
**≈200-250 ms** per signature there, about 1.5× that on the mk3 (80 MHz). Per request:
GetAssertion ≈ one signature; MakeCredential ≈ a public key and a signature; U2F
REGISTER ≈ a public key and two signatures (certificate and registration). These are
estimates to confirm on hardware. The first request of a session also pays for the
master (seed fetch and stretch, a few seconds, with its progress screen). The masked
windows pause the USB task, so keepalives stop for the length of one signature.

## Checking on hardware

`tools/fido_check.py` drives the key with python-fido2 -- Yubico's library, whose CTAP2
client refuses non-canonical CBOR and whose attestation verifiers check every signature:

```sh
python3 -m venv /tmp/fido-venv && /tmp/fido-venv/bin/pip install fido2
/tmp/fido-venv/bin/python tools/fido_check.py          # a real device: press when asked
/tmp/fido-venv/bin/python tools/fido_check.py --sim    # the same checks, at a desk
```

`--sim` runs `cargo run -p catcard-fido --example fido_sim`, the protocol code on a pipe;
it passes every step with python-fido2 2.2.1. On a device, confirm on the screen when the
script says so. `--reset` is the irreversible reset above.

Then a real site: <https://webauthn.io> (register, then authenticate), and Chrome's
Settings → Security keys.

What only hardware can settle: that the composite enumerates with the security key
(Windows, macOS, Linux; with and without Keyboard EMU), that endpoint 3's FIFO and
interrupt handling work as the others do, keepalive pacing under a real browser, the
sign times above, and the U2F retry loop against Chrome's `appid` path.
