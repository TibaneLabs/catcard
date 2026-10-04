# Threshold signing (TSS)

Status: **protocol layer built, 2026-10-02** (`crates/catcard-tss`, host-tested). **Stage 1
screens built, 2026-10-03** (`crates/catcard-fw/src/tss/`, mk4/mk5/Q1 bench builds, not yet
run on a device): create together, export, import, restore from shares, restore a
created-together key, and the kept shares -- all over the SD card. Signing a PSBT and QR as
a transport are stage 2. See "On the device" below.

A wallet whose key is held in **shares** by several CatCards: any `t` of the `n` can sign
together without the key ever being put back together, and `t` shares can also restore it.
Two ways to get there:

1. **Create together.** `n` CatCards run a distributed key generation. No device ever holds
   the whole key, before or after.
2. **Export.** One CatCard that holds a wallet splits it into `n` shares and writes each to an
   SD card. The shares can sign (any `t`, on CatCards) and restore the wallet (any `t`).

In both, the user chooses `n` (members) and `t` (threshold), `2 <= t <= n`, and the same `t`
governs signing and restoring.

## The scheme and its limits

- **DKLs23 threshold ECDSA on secp256k1** (tsslib `dklstss`, MIT, our own). The result is an
  ordinary ECDSA signature, so a TSS wallet is an ordinary single-signature wallet to the
  outside world: same address types, same fees, no visible multisig.
- **No Taproot, yet.** DKLs signs ECDSA. tsslib 0.2.12 adds FROST on secp256k1 (BIP-340,
  `frostsecp256k1tss`), which would give threshold Taproot; that is stage 2, not built.
  Address types are native SegWit (`wpkh`), nested SegWit (`sh(wpkh)`) and legacy (`pkh`).
- **No hardened derivation under a shared key.** BIP-32's hardened step needs the private key;
  a threshold key only supports non-hardened steps (tsslib `dklstss::derive_child`). So:
  - an **exported** wallet shares its *account* key (`m/84'/coin'/account'` and so on): the
    hardened steps are done by the exporting device before it splits, and the shares then
    sign for exactly the addresses the original wallet already uses;
  - a **created-together** wallet is its joint key plus the chain code tsslib derives from
    the joint public key; receive and change are the non-hardened `0/*` and `1/*` under it.
    A watch-only wallet imports it as a single-sig `wpkh(xpub/0/*)` descriptor.

## Members, sessions, messages

- A **session** is one run of a protocol (create, sign) among numbered **members** `1..n`.
  Its id is random, from the UI DRBG, and shown on every member's screen.
- **Messages travel by SD card or, on the Q1, by QR.** Each device writes what it has to say
  and reads what is addressed to it. The screen always says what to do next ("Member 2 of 3 —
  round 2: give this card to member 3", or a QR to show to member 3).
  - SD: one directory per session, `TSS/<session id>/`, one file per message, named
    `r<round>-<from>-<to>.msg` (`to` 0 for a broadcast). One card can circulate among the
    members, or each member can have its own.
  - QR (Q1 only): the same messages, as BBQr. A Q1 can scan what another Q1 shows; a mixed
    group uses SD.
- **Messages are authenticated.** tsslib leaves peer authentication to the transport, and an
  SD card or a QR is not one. So every session opens with two rounds of introductions, as
  **commit, then reveal**:
  - round 0: each member makes a per-session identity key and broadcasts only a
    **commitment** to it — a hash of the key, its member number, the session id and
    parameters, and 32 fresh random bytes;
  - round 1: once a member holds every other member's commitment, it broadcasts the key and
    the random bytes. A key that does not open its sender's commitment is refused, and so
    is a round-1 message that arrives before every commitment is in (it is not held; the
    device asks for it again once it can take it).

  Every member then shows a **session code** — a hash of the parameters, every commitment
  and every identity key, as 8 BIP-39 words — and the user checks the codes match on all
  devices before anything secret is sent. From then on each message is signed by its
  sender's session key, and anything unsigned or signed by someone else is refused.
  The commitments are what make 8 words enough: whoever carries the card between members
  has to choose any key it substitutes before it has seen the honest keys, so it cannot
  search for substitutes whose codes match.
- **Unicasts are encrypted.** tsslib also assumes point-to-point messages are private, and
  some are secret: a DKG's round-1 unicasts are Shamir shares, so whoever copied every
  round-1 file off a shared card could rebuild the key. Each unicast is AES-256-GCM under a
  one-message key from ECDH between the two members' session keys.
- **One session, many sighashes.** A signing session runs one DKLs signing per input, and
  every input's messages for a round travel in the same file: a PSBT of ten inputs takes
  the same eight passes of the cards (two of introductions, six of signing) as one.
- **Randomness.** The DKG's secret contribution and every share made on export are seed-grade
  and come from the entropy pool, like a new wallet (the pool-draw lint allowlist names the
  TSS module). Protocol randomness (nonces, OT seeds) comes from a DRBG seeded from the pool
  for the session and wiped after it.

## The flows

### Create together

1. On every member: choose *Create TSS wallet*, `n`, `t`, and its member number.
2. Rounds 0 and 1: identity commitments out, then identity keys; session code shown and
   compared.
3. DKLs keygen rounds 2-4, by SD or QR, until every member has its share.
4. Each member stores its share and shows the wallet's fingerprint and first address; the
   user checks they are the same on every device.

### Export

1. On the device holding the wallet: choose *Export as TSS shares*, `n`, `t`, the account and
   address type.
2. The device:
   - splits the BIP-39 entropy into `n` Codex32 `cw1` shares, threshold `t` (the restore
     half; Codex32 is already implemented — `catcard_wallet::codex32`);
   - derives the account key, wraps it as a 1-of-1 DKLs key (`dklstss::import_key`) and
     reshares it to a `t`-of-`n` committee by running every party itself (it holds the whole
     key already, so nothing is lost by its knowing the parties' setup), then wipes all of
     it but what goes into the shares;
   - bundles member `i`'s Codex32 share and DKLs share into share file `i`.
3. Share files are written to SD **one at a time**, with the option to change cards between
   them ("Insert the card for share 2 of 5").
4. A share is taken into a CatCard (*Import TSS share*) to sign with. To restore instead,
   *Restore from TSS shares* reads `t` share files, one card after another, combines the
   Codex32 halves and stores the wallet's words.

### Sign

1. Each signing member loads the same PSBT (SD, QR) and approves it on its own screen, after
   checking the outputs as for any signature.
2. Rounds 0 and 1 as above, then the DKLs signing rounds 2-7 for every input. Signing is
   **checked** unless the caller asks otherwise (`SignMode::default()` is `Checked`).
3. The first member writes the signed PSBT.

### Restore a created-together wallet

`t` members combine their shares into the joint private key and its chain code, stored as an
xprv-type wallet. **This ends the "nobody holds the key" property** and is said so, twice,
before it is done.

## Where things live

Decided 2026-10-04, pending tsslib support
([KarpelesLab/tsslib-rs#16](https://github.com/KarpelesLab/tsslib-rs/issues/16)):

- **Inside the device: only the core.** The 32-byte share, the joint public key and chain
  code, `n`, `t`, the member number and the members' public shares: well under 1 KB even at 9
  members. It goes in the current key's own settings (records take about 4 KB of JSON),
  under the settings encryption like everything else there.
- **On the card: the pairwise OT state**, about 12.8 KB per other member, as a cache:
  encrypted under a key derived from the device's root secret and the wallet's id, and
  checked against a hash kept in the core, so a swapped or stale cache is refused and a copied
  card is useless without the device. Signing already travels over the card, so the cache
  comes with it.
- **A lost cache is rebuilt, not fatal.** A member with a fresh card re-runs the pairwise
  setup with the members it is signing with: a short exchange at the start of a signing,
  changing no share, no address and no other pair. (tsslib's `refresh` would also do it, but it
  rotates every share and needs every member, so it is kept for periodic proactive refresh.)
- The share itself cannot be derived from the root secret: it depends on the other members'
  randomness (create together) or the exporting device's (export). An exporter could derive
  its polynomial from its own seed, so that it can re-issue a lost share while it still holds
  the seed.
- Boards: mk4, mk5, Q1. The mk3 has no flash left for it.

Until tsslib#16 lands, stage 1 stores the whole share record as its own encrypted file in the
settings volume.

## On the device (stage 1, 2026-10-03)

Settings → **TSS wallets** (beside `Multisig`, docs/MENU.md) lists the shares kept here
(`2-of-3 #2 1A2B3C4D`: t, n, member, fingerprint) and offers *Create together*, *Import a
share*, *Split this wallet* (the export), *Restore from shares* and *What is this?*. A kept
share opens to *Details* (n, t, member, origin, three receive addresses, the xpub, a
watch-only descriptor), *Descriptor to card*, *Copy share to card*, *Restore the whole key*
(created-together only) and *Delete this share*. On a blank device, Import → **TSS shares**
is *Restore from shares*.

- **Create together.** Member 1 picks n and t (up to 9 members, as the memory allows; the
  shapes `can_create_together` refuses
  are refused with "too many needed: a few could bias the key"; fewer than 3 members
  with "2-of-3 is the usual minimum") and starts a session: its id is from the UI DRBG, its
  folder `TSS/<id>/` gets the round-0 file and `invite.txt` (n and t as text). The others
  choose *Join*, pick the session from those on the card, and a member number not yet
  taken. Then every device runs the same loop over the card, driven only by the session's
  outbox and `awaiting()`: write what it has, read what it waits for, show the 8-word code
  when every identity is in (and go on only on "the same on all"), and otherwise say
  "Step k of 5. Pass the card to member m (waiting for members ...), then put it back
  here." At the end each member keeps its share and shows the wallet's fingerprint, first
  addresses, xpub and descriptor to compare across the devices. The session is in memory
  only: leaving the screen abandons it.
- **Split this wallet.** The words of the wallet in force (refused with a passphrase: the
  shares carry the words alone), n and t (any `2 <= t <= n` the memory allows), native
  SegWit / nested SegWit / legacy (and "Why not Taproot?"), the account number, then how
  to protect the files. The account key is derived from the master in `keywork::run`, the
  export runs in one masked region and is checked by recombining the first t Codex32 halves
  before anything is written; then "Share i of n: insert its card, or keep this one" for
  each file, `tss-<FP>-<i>of<n>.7z`.
- **Share files** are 7-Zip archives of one stored file, as a backup is: AES-256 under a
  password typed twice and stretched once per export (7-Zip's KDF, 2^19 rounds, a fresh
  IV per file from the protocol DRBG), or -- asked twice, never the default -- in the
  clear. A password per export rather than per file: the cards are kept apart, and one
  stretch rather than n keeps the export to one wait.
- **Import a share** takes a bundle (keeping its signing half) or a lone record (from
  *Copy share to card*), checks the DKLs share decodes before keeping it, and refuses a
  share already kept.
- **Restore from shares** reads t bundles one card after another, using only their Codex32
  halves (no DKLs decode, so no extra memory), recovers the words, shows the fingerprint
  and word count, warns before replacing a stored wallet, and stores the words as the
  seed-import path does.
- **Restore the whole key** says twice -- an approval page, then "3 = yes" -- that the
  device will hold the whole key, then gathers t records (the ones kept here, the rest from
  cards), recombines them (`combine`) and stores the key as an XPRV. Its addresses are
  then `m/0/*` and `m/1/*` of that XPRV, and the device says so.

### Storage

Each kept share is its own file in the settings volume, `/tss-<16 hex>.ts`
(`catcard_settings::tss`): `"CTSe" ‖ iv ‖ HMAC tag ‖ AES-256-CTR(record)`, encrypt-then-MAC
as the FIDO passkey file is, under keys made by HMAC from the **root wallet's settings key**
(whichever wallet is in force). The name is an HMAC of the wallet key and member number, so
it says nothing without the key, and a file of another wallet is skipped. A device with no
stored wallet keeps no shares (its settings key would be all zeros). Listing and showing a
share read only the record's fixed header; nothing decodes the DKLs half to show it.

### Memory

Since tsslib 0.2.12 (2026-10-04) keys and messages use its binary encoding
(`tsslib::wire`), streamed: a record is written straight into a buffer sized by a counting
pass and read straight from its bytes, with no JSON document built in between. Measured on
the host with 32-bit pointers (wasm32-wasip1 under node, an allocator that tags every block
with its member and charges it as the device heap does -- a two-word header, the payload
rounded to a word), 2026-10-04:

| members | record | encode one key | decode one key | create together, one member | export (all bundles held) |
|---|---|---|---|---|---|
| 2 | 13.1 KB | 45 KB | 45 KB | - | 71 KB |
| 3 | 25.9 KB | 77 KB | 65 KB | 126 KB | 152 KB |
| 4 | 38.7 KB | 109 KB | 85 KB | 165 KB | 259 KB |
| 5 | 51.5 KB | 141 KB | 105 KB | 207 KB | 389 KB |
| 6 | 64.2 KB | 173 KB | 125 KB | 249 KB | 544 KB |
| 7 | 77.0 KB | 205 KB | 145 KB | 291 KB | 724 KB |
| 8 | 89.8 KB | 237 KB | 165 KB | 331 KB | 928 KB |
| 9 | 102.6 KB | 269 KB | 185 KB | 374 KB | 1156 KB |

"Create together" is one member's whole session -- its DKG rounds, the messages it reads
and writes, and the record encoded and copied at the end while the session still lives --
with every member run in one process and only that member's blocks counted. "Export" is
tsslib's reshare to `n` members, then every bundle held while each in turn is encoded:
the larger of the two. Before (tsslib 0.2.11's JSON, raw allocation sizes), encoding one
key peaked at 116 / 231 / 445 / 462 KB for 2-5 members and decoding at 88 / 150 / 213 /
276 KB.

The heap is 216 KB in three pieces (32 KB linked, 64 and 120 KB of spare RAM either side
of the app area). Every flow that touches a DKLs key borrows the 256 KB app area for its
duration (`crate::heap::borrow_app_area`), which joins the two spare pieces into one 440 KB
run; apps refuse to start meanwhile, and on return every free heap byte is wiped -- which
also clears what tsslib freed without wiping (its encoding structs, the messages it
copied). Each flow then checks the peak above, plus 32 KB for the card and the screens,
against what is free, and offers only the `n` that fits. With the area lent:

- **create together: up to 9 members** (374 + 32 KB);
- **split this wallet: up to 5 shares** -- an export holds every member's key at once, and
  that grows with `n`²;
- **import a share, restore the whole key: any `n` to 9.** Restoring the key decodes one
  record at a time and keeps only its Shamir share (`catcard_tss::combine_parts`), so it
  needs one decode, not `t`.

Without the lease, 3 or 4 members would create together in 216 KB and an export to 3 would
fit too; the lease is still taken for them, for the wipe on return.

### Flash

The screens bring in all of catcard-tss and tsslib's DKLs parties (a session dispatches over
keygen and both signing kinds). The workspace builds `tsslib` and `catcard-tss` at
`opt-level = "z"` on every board (purecrypto, which does the heavy arithmetic, stays at
`"s"`; the bench times below were at `"s"` and want re-measuring).

tsslib 0.2.12 without its `json` feature took serde_json out of the image, and with it
catcard-tss's own JSON re-encoder: images (dev builds, 2026-10-04) mk4/mk5 1,419,264 →
1,393,664 bytes, Q1 1,440,256 → 1,401,856. That put the `DebugTssBench` bench back on the
Q1 (12 KB): **1,414,144 of 1,441,792 bytes, 27 KB left**. tsslib 0.2.12 needs purecrypto
0.9.9, whose secp256k1 and safegcd inversion grew the mk3 image (which has no TSS)
876,544 → 892,928 bytes of its 915,456-byte ceiling.

## Measured on an mk5 (2026-10-02, `usbclient.py --tss-bench`)

Both parties of a 2-member wallet in one process, mk4/mk5 image at `opt-level = "s"`:

| | |
|---|---|
| keygen | 28.7 s |
| one signature | 11.0 s (verified) |
| one party's share, tsslib JSON | 45.6 KB |
| peak heap | 145 KB |

With one party per device the work splits, so roughly 14 s per device to create a 2-member
wallet and 5-6 s per device per input to sign, before any card is carried. Keygen is mostly
the pairwise OT setup (EC multiplications in software); signing mostly OT extension (AES and
hashing in software). Ways down: the L4S5's AES peripheral for the OT PRG, and DKLs
presigning, which moves the work before the transaction is known.

The share grows with `n` (per-peer OT state), so it also sets the most members a device can
hold shares for. tsslib's binary key encoding is 2-of-2's 45.6 KB of JSON in 13.1 KB.

## Measured (host, `cargo test -p catcard-tss --test sizes -- --nocapture`)

Message envelope sizes in bytes, as one member sends them (SD file or BBQr payload), for
2-of-3 / 2-of-4 / 3-of-5 / 4-of-7 (2026-10-04, envelope format 3: tsslib's binary message
payloads). Signing messages are almost all OT-extension data.

| | round 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
|---|---|---|---|---|---|---|---|---|
| create together, broadcast | 117 | 150 | 227 / 227 / 293 / 359 | 165 / 200 / 235 / 305 | | | | |
| create together, to each peer | | | 308 | | 8,560 | | | |
| sign, broadcast, one input | 117 | 150 | 160 | 130 / 130 / 165 / 200 | | | 160 | 130 / 130 / 165 / 200 |
| sign (plain), to each peer, per input | | | | | 11,310 | 17,010 | | |
| sign (checked, the default), to each peer, per input | | | | | 22,510 | 33,975 | | |

Rounds 0 and 1 are the introductions (a 32-byte commitment, then the 33-byte key and the
32 bytes that open it); the protocol proper is rounds 2 and on. A unicast's size does not
depend on `n`; a broadcast's grows with `t` (round 2's commitments) and `n` (the echoes).
Each further input adds about 75 bytes to a signing broadcast (four inputs: 379 bytes in
round 2). Every envelope carries 85 bytes of header and signature. Against format 2
(tsslib's JSON re-encoded by catcard-tss) these are 3-10% smaller.

Share records (settings), record format 2:

| members | 2 | 3 | 4 | 5 | 7 | 9 |
|---|---|---|---|---|---|---|
| record | 13,120 | 25,894 | 38,672 | 51,450 | 77,006 | 102,562 |

-- 12,778 bytes per other member (the pairwise OT state), against about 13.4 KB in format 1.
An export's share bundle adds 61 bytes and the 48-character Codex32 string.

## Open

- ~~Heap per member with one party per device~~ — measured on the host (2026-10-04, "On
  the device / Memory"): with tsslib's binary encoding, 9 members create together and 5
  take an export. Wants checking on a device.
- Settings space for a 9-member record (103 KB a share), and QR part counts for the
  signing unicasts (11-34 KB per input per peer).
- An export past 5 shares: tsslib's reshare makes every member's key at once, so the
  export's memory grows with `n`² (1.16 MB at 9).
- ~~The Q1's flash: 1.5 KB left with the TSS screens in~~ — 27 KB left with tsslib 0.2.12
  and the bench back in (see "Flash").
- Stage 2: tsslib 0.2.12 has `frostsecp256k1tss`, FROST on secp256k1 with BIP-340
  signatures and the BIP-341 tweak -- threshold Taproot. Not enabled yet.
- An exported share's xpub carries a zero parent fingerprint: the record does not keep the
  account's parent. The key, chain code and addresses are the account's; the xpub text
  differs from the one the whole wallet exports.
- ~~Plain or checked signing by default (`SignMode`)~~ — settled (2026-10-02): checked is
  the default (`SignMode::default()`). It costs twice the signing unicasts and the work, and
  catches one form of a selective-failure attack (see the crate docs); `Plain` stays
  available to a caller that asks for it.
- ~~The session code is 8 words (88 bits); an attacker between the members during round 0
  could grind substitute identity keys for a birthday match, about 2^44 work~~ — settled
  (2026-10-02): round 0 is now commit-then-reveal (commitments in round 0, keys in round 1,
  a key that does not open its commitment refused as `Refused::CommitmentMismatch`).
  Each device's view contains its own key, revealed only after everything else in that
  view was committed, so the code each device shows is fixed before the attacker learns
  it: two views match with probability 2^-88 per session, however much it computes. It
  cost one more pass of the cards; the code stays 8 words.
- ~~tsslib's DKG lets colluding members bias the key when `n <= 2t - 2`~~ — settled
  (2026-10-02): *Create together* refuses those shapes (2-of-2, 3-of-3, 3-of-4...;
  `catcard_tss::can_create_together`). 2-of-3 is the expected minimum and is not affected.
  Export splits an existing key, so it keeps any `2 <= t <= n`.
- ~~Encryption of share files on SD~~ — settled (2026-10-03): a 7-Zip archive under a
  password per export, as a backup is, or in the clear when the owner insists twice.
