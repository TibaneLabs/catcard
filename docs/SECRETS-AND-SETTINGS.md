# Secrets and settings — the plan

How CatCard generates a wallet secret and how it stores the settings blob that hangs off
it. Tags as elsewhere: **[C]** confirmed, **[I]** inferred, **[?]** unconfirmed.

Two decisions frame everything here, and they were made deliberately:

- **The settings blob is stock-compatible.** Same medium (LittleFS2 on internal flash),
  same crypto, same slot rotation, so a device that has been reflashed either way keeps
  its settings. `hw-reference/settings-nvstore-format.md` is the contract.
- **A new seed is written in the stock SecretStash layout.** Costs nothing — the wallet
  crate already stores BIP-39 *entropy* rather than words — and means stock firmware can
  read a CatCard-generated wallet and vice versa.

And one rule about entropy: **user-supplied entropy is offered, never required.** Stock
refuses to generate a seed without dice, coins or key-mash since 5.6.0; we do not. The
pool's policy (≥256 credited bits from ≥2 hardware TRNGs on mk4/Q1) is the bar, and dice
or mash are an *additional* source that can only raise it. A device whose TRNGs are
healthy must not be made unusable by a UI requirement, and a device whose TRNGs are not
healthy must not be rescued by a handful of dice rolls — `EntropyPool` already refuses in
that case, which is the property that matters.

## The key is the seed — what that forces

The main blob is encrypted under `hash_key(raw 72-byte stash)`, and that stash comes only
from `gate 18/4` after a successful login. **The secret is a precondition for the settings
store, not a peer of it.** What follows is not a preference about ordering:

- **A device with no seed has no main blob at all.** Nothing to read and nothing to
  migrate; the store becomes meaningful only once E has run.
- **Generating a new seed orphans the old blob.** The key moves with the secret, so the
  previous settings become undecryptable — not corrupt, just unreadable. Changing the
  secret must therefore *either* decrypt-and-re-encrypt the settings under the new key as
  part of the same operation, *or* deliberately start from defaults. Doing neither loses
  the user's configuration silently, which is the failure this note exists to prevent.
- **Transposing settings needs both keys in one window.** Decrypt under the old secret,
  re-encrypt under the new one — possible only while the old stash is still fetchable.
- **Migration from stock needs the seed intact and the PIN known.** A firmware swap alone
  is safe (the seed lives in the SE and survives it); it is a *seed change*, not a
  reflash, that breaks settings.
- **The pre-login slots are the sole exception.** `nick`, `rngk`, `lgto`, `kbtn`,
  `terms_ok`, `_skip_pin` sit under a key of 32 zero bytes, readable with no wallet and no
  login. That is why validation targets them, and why that slice of D is the only part
  that can be built before E lands.

So E gates D. The re-key step above belongs to E's exit criteria, not to a later cleanup.

## What already exists

| piece | state |
|---|---|
| `catcard-entropy` | complete. `EntropyPool` (SHA-512 absorb, per-source credit, policy refusal, ratchet), `HmacDrbg`, SP 800-90B health tests |
| SE1/SE2 entropy via callgate 26 | live — `boot.rs` discovers the callgate and draws 64 B per element |
| `catcard-wallet` | complete and portable: BIP-39 (`Mnemonic` stores entropy), BIP-32, addresses, sighash, base58/bech32 |
| `catcard-pin` | login, `fetch_secret`, first-PIN set, firmware authorisation |
| `catcard-settings` | complete two-slot authenticated store — **orphaned**, and superseded for mk4+ by the stock-compatible format below |
| crypto primitives | `purecrypto` has everything needed: `Aes256` + `Ctr`, `Sha256`/`Sha512`, `HmacSha512`, generic `pbkdf2<D>`. All no-alloc (`cipher = []`, `kdf = ["hash","cipher"]`) |

## What is missing

- No STM32 internal-flash driver at all — no unlock, no page erase, no doubleword
  program. `catcard-flash` drives *external* SPI-NOR, which mk4+ does not have
  (`spec.rs:209-214`).
- No settings region in any board memory map (`catcard-board/src/memory.rs`).
- No LittleFS implementation.
- No secret-*write* path: `PinOp::Change` is used only for PINs, and
  `EntropyPool::draw_seed` has no caller.
- No `no_std`, no-alloc JSON codec.

## Geometry — measured, not assumed  [C]

Read off a real Q1's superblock over `DebugPeek` (`0x0818_0000`):

| field | value |
|---|---|
| version | `0x0002_0000` (littlefs v2.0) |
| block_size | **512** |
| block_count | **1024** |
| name_max / file_max / attr_max | 255 / `0x7fffffff` / 1022 |

512 × 1024 = 524 288 B, matching the documented 512 KB region. The image mounts under the
canonical implementation at that geometry, which is the proof.

**The block size is 512 while the flash erase page is 8 KB** [C]. littlefs normally wants
those equal, so stock must present 512-byte logical blocks over 8 KB pages with
read-modify-write underneath (MicroPython's flash block device does exactly this). Any
stock-compatible *writer* has to reproduce that mapping; a reader does not care. This is
not recorded in `hw-reference` and is the single most load-bearing discovery here.

## Milestones

Ordered by dependency. **E comes first** even though it is last alphabetically: the
settings key is derived from the secret, so nothing in the store can be keyed until a
secret exists. E needs no flash driver at all.

### E. Secret generation and storage

1. Wrap `gate 18/3` with `change::SECRET` in `catcard-pin` (the ABI constant exists;
   nothing calls it).
2. `EntropyPool::draw_seed()` → 32 B, already policy-gated and health-tested.
3. Optional user entropy through `UserSymbols` + `EntropyPool::add_user` — dice (`123456`),
   coin (`01`), key-mash, each absorbed as `sha256` of its ASCII symbols and credited by
   keyspace behind a length/frequency gate, with DWT timing mixed at every press.
   Additive; never a precondition.
4. Encode SecretStash: `marker = 0x80 | ((L/8) - 2)` then L bytes of entropy, L ∈ {16,24,32}
   (`secret-stash-format.md`).
5. Write it, then re-read via `gate 18/4` and compare before telling the user the wallet
   exists.
6. **Settle the settings key in the same operation.** Changing the secret changes
   `hash_key(stash)`, so any existing blob stops being readable the moment step 5 lands.
   Either carry the settings across — decrypt under the old key while it is still
   fetchable, re-encrypt under the new one — or write fresh defaults under the new key and
   say so on screen. What is not allowed is leaving a blob keyed to a secret that no
   longer exists, because that is indistinguishable to the user from having lost their
   configuration to a bug.

Note that steps 1-5 need no flash driver and no filesystem; step 6 is where E meets D, and
on a device with no prior blob it reduces to "write defaults".

**Exit:** the device generates a seed from its own TRNGs, stores it, shows the words, and
leaves the settings blob keyed to the secret that is actually installed; stock firmware
reflashed over the top finds the same wallet and can still read its settings.

### A. Internal flash driver

STM32L4/L4+ FLASH peripheral: unlock (`KEYR` ← `0x45670123`, `0xCDEF89AB`), page erase,
64-bit doubleword program, `BSY` polling with a **bounded** wait, and `PGSERR`/`PGAERR`/
`WRPERR` surfaced as errors rather than ignored. 8 KB pages on mk4/mk5/Q1, 2 KB on mk3
(`platform.md`). Host-tested against a mock register bank.

Add the region to `MemoryMap`: `settings_base`/`settings_len` — `0x0818_0000` + 512 KB on
mk4/mk5/Q1, absent on mk3. Currently nothing is reserved and `firmware_flash_len` does not
subtract it.

### B. A 512-byte block device over 8 KB pages

The RMW mapping described above: an 8 KB page cache, erase-on-demand, and honest failure
if a program does not stick. This is the seam littlefs sits on, and the piece most likely
to corrupt a filesystem if it is subtly wrong.

### C. LittleFS v2

Read first, write second. **Recommendation: implement it, do not depend.** Every candidate
crate is a 0.1.x single-author package (`littlefs2-pure` is an empty `0.0.0` placeholder);
`littlefs-rust` is explicitly "a port to *unsafe* rust" and defaults to `alloc`;
`littlefs2-rust` defaults to `std`. This workspace denies unsafe and runs no-alloc, and a
filesystem parser sitting under the wallet's settings is not where an unaudited dependency
belongs.

What makes this tractable is that we now have an **oracle**: `littlefs-python` binds the
canonical C implementation, so host tests can generate reference images and diff against
them. That is the same discipline used for the DRBG vectors.

Scope: metadata pairs and revision selection, CRC32, tag decoding, CTZ skip-lists for file
data, directory traversal. The writer additionally needs allocation, compaction and
wear-levelling — materially harder, and worth deferring until the reader is proven.

### D. The nvstore crypto

- **Key** `hash_key(raw_secret)`: five rounds of `SHA256(x ‖ b'pad')` then one plain
  `SHA256`, over the **raw 72-byte stash** from `gate 18/4` — not the decoded seed.
- **Pre-login key** is 32 zero bytes, for `nick`, `rngk`, `lgto`, `kbtn`, `terms_ok`,
  `_skip_pin`. Worth implementing first: it needs no secret, so it can be developed and
  validated before E lands.
- **Slot** = `AES-256-CTR(plaintext ‖ SHA256(plaintext))`, one continuous stream, counter
  seeded `pack('<4I', 4, 3, 2, pos)` where `pos` is the slot index 0..99, padded to 4064 + 32.
- **Load:** scan slots, cheap 2-byte prefilter against `{"`, full decrypt, verify digest,
  take the highest `_age`. **Save:** `_age += 1`, write a new random free slot, then erase
  the old one — new data durable before the old copy dies.
- **JSON:** needs a no-alloc codec over a 4064-byte buffer. Not yet chosen; the dict is
  free-form and unknown keys must survive a round-trip, which argues for a DOM over
  `heapless` rather than a fixed struct.

**CTR convention [?]** — `purecrypto`'s `Ctr` increments the counter block as a big-endian
128-bit integer. For `pos ≤ 99` the byte that moves is byte 15, clear of the `pos` field,
so a 256-block slot never disturbs it — but whether libngu agrees is unverified, and the
failure mode is nasty: block 0 decrypts correctly and everything after is garbage. The
digest check catches it; reasoning does not. **Validate against a stock-written slot.**

## Validation — and an unresolved anomaly

The intended proof is a stock-written slot decrypted by our code. The pre-login slots are
the ideal target because their key is 32 zero bytes, so the whole chain — geometry,
CTR convention, digest — can be checked with no secret and no login.

> **Settled, 2026-09-18 — the ground truth is now in hand [C].** A Q1 was run on stock
> long enough to set a nickname and write a couple of Secure Notes, and the settings then
> read back correctly on this firmware: the pre-login blob under thirty-two zero bytes and
> the wallet blob under `hash_key(raw stash)`, both decrypting, both parsing, with `nick`,
> `notes` and `secnap` where the format document says. The whole chain — geometry, slot
> naming, CTR convention, digest, `_age` selection — is checked against a volume another
> firmware wrote, which is what this section was waiting for.
>
> Debug → Settings to SD copies the region to a card; `/settings/001.aes` and
> `/settings/002.aes`, 4096 bytes each, mount out of that image with the same LittleFS code
> the firmware runs. The paragraphs below describe the volume **before stock had used it**
> and are kept because the reasoning was sound and the emptiness was real.

**That ground truth was not in hand, and the reason is odd enough to record.** On the Q1
here the volume mounts, holds a valid superblock pair (blocks 0 and 1, revisions
`…1df4`/`…1df5`), and reports an **empty `/settings` directory** — no `.aes` filename
appears anywhere in the raw 512 KB. Every block from 2 to 1023 reads back as one identical
512-byte pattern.

This was checked rather than assumed, because it first looked like a bad dump [C]:

- Erased flash at `0x0816_0000`–`0x0817_FE00` returns clean `0xFF`, and firmware addresses
  return distinct plausible content — so the read path works.
- Request size is irrelevant: 56 / 128 / 256 / 512-byte reads of one address agree, so
  multi-frame reassembly is not corrupting anything.
- Address bits are honoured: reads at `+4`, `+8`, `+16`, `+64` return the pattern shifted
  by exactly that much, and `0x081E_0004` returns the same shifted bytes as `0x0818_0404`.
- `width=1` agrees with `width=4`.

So the repetition is real flash content. It also explains why blocks 0, 1 and 2 are
byte-identical from offset 64 on: programming can only clear bits, so the superblock pair
is that same pattern with just its first ~64 bytes written into littlefs structures. The
region was filled with repeating content *before* the filesystem was put on it.

What it means for us is simply that **this unit carries no stock settings to validate
against** — not that our tooling is broken. How a Q1 comes to have a pre-filled settings
region is unexplained and worth understanding before we write to it `[?]`.

The fallback, which does not depend on the anomaly: run **stock firmware** in `ccemu`
(mizuki holds `v1.5.0Q-q1` and `v5.4.5-mk4` releases), let it write its own settings, and
capture the region. The emulator currently has `--dump-ram` but no flash equivalent;
adding one is small, and it is our own code. Running a vendor binary as a black box and
observing its output bytes is squarely within CLEANROOM.

## Risks

| risk | why it bites |
|---|---|
| LittleFS **writer** | wear-levelling and compaction bugs corrupt the whole volume, including data stock wrote |
| 512-over-8K RMW | a torn page erase loses 16 logical blocks at once, not one |
| CTR convention `[?]` | silently wrong past block 0 |
| no-alloc JSON | must preserve unknown keys or a round-trip through CatCard strips settings stock relies on |
| flash write protection `[?]` | the bootloader write-protects 14 pages on mk4; those are low pages, but that the settings region is writable from app firmware is **assumed, not tested** |
