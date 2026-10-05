# Threshold signing (TSS)

Status: **protocol layer built, 2026-10-02** (`crates/catcard-tss`, host-tested). **Stage 1
screens built, 2026-10-03** (`crates/catcard-fw/src/tss/`, mk4/mk5/Q1 bench builds, not yet
run on a device): create together, export, import, restore from shares, restore a
created-together key, and the kept shares -- over the SD card or the Virtual Disk. **Key
core in settings, pairs in a sealed cache on the medium, and Rebuild setup, 2026-10-04**
(tsslib 0.2.14; "Where things live"). Signing a PSBT and QR as a transport are stage 2.
See "On the device" below.

A wallet whose key is held in **shares** by several CatCards: any `t` of the `n` can sign
together without the key ever being put back together, and `t` shares can also restore it.
Two ways to get there:

1. **Create together.** `n` CatCards run a distributed key generation. No device ever holds
   the whole key, before or after.
2. **Export.** One CatCard that holds a wallet splits it into `n` shares and writes each to an
   SD card (or the Virtual Disk). The shares can sign (any `t`, on CatCards) and restore the
   wallet (any `t`).

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

- A **session** is one run of a protocol (create, sign, pair setup) among numbered
  **members** `1..n`.
  Its id is random, from the UI DRBG, and shown on every member's screen.
- **Messages travel by SD card, the Virtual Disk or, on the Q1, by QR** (stage 2). Each
  device writes what it has to say
  and reads what is addressed to it. The screen always says what to do next ("Member 2 of 3 —
  round 2: give this card to member 3", or a QR to show to member 3).
  - SD or Virtual Disk: one directory per session, `TSS/<session id>/`, one file per
    message, named `r<round>-<from>-<to>.msg` (`to` 0 for a broadcast). One card can
    circulate among the members, or each member can have its own; with no card, the files
    go between the devices' Virtual Disks over USB.
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
  the same seven passes of the cards (two of introductions, five of signing) as one.
- **Randomness.** The DKG's secret contribution and every share made on export are seed-grade
  and come from the entropy pool, like a new wallet (the pool-draw lint allowlist names the
  TSS module). Protocol randomness (nonces, OT seeds) comes from a DRBG seeded from the pool
  for the session and wiped after it.

## The flows

### Create together

1. On every member: choose *Create TSS wallet*, the medium (SD card or Virtual Disk), `n`,
   `t`, and its member number.
2. Rounds 0 and 1: identity commitments out, then identity keys; session code shown and
   compared.
3. DKLs keygen rounds 2-3 (shares; then the echo with the base-OT replies), by SD or the
   Virtual Disks' files (QR in stage 2), until every member has its share. With one SD card
   passed member to member that is 5n - 4 insertions: 11 for 2-of-3, 21 for 3-of-5 (tsslib
   0.2.14 sends the base-OT replies with the echo, KarpelesLab/tsslib-rs#18; 0.2.13 took
   6n - 5).
4. Each member keeps its **key core** in its settings and writes its **pair cache** beside
   the session's files (`TSS/<wallet>-m<member>.pairs`), then shows the wallet's fingerprint
   and first address; the user checks they are the same on every device. On the Virtual
   Disk the cache is gone at power off: the pairs are then set up again before signing.

### Export

1. On the device holding the wallet: choose *Export as TSS shares*, `n`, `t`, the account and
   address type, the medium and how to protect the files.
2. The device:
   - splits the BIP-39 entropy into `n` Codex32 `cw1` shares, threshold `t` (the restore
     half; Codex32 is already implemented — `catcard_wallet::codex32`);
   - derives the account key, wraps it as a 1-of-1 DKLs key (`dklstss::import_key`) and
     reshares it to a `t`-of-`n` committee by running every party itself (it holds the whole
     key already, so nothing is lost by its knowing the parties' setup), then wipes all of
     it but each member's **key core** -- the pairwise state the reshare made is wiped too;
   - bundles member `i`'s Codex32 share and key core into share file `i`: about 0.6 KB at
     3 members, 1.1 KB at 9, small enough for a QR code or two.
3. Share files are written **one at a time**, with the option to change cards between them
   ("Insert the card for share 2 of 5"), or all to the Virtual Disk.
4. A share is taken into a CatCard (*Import a share*) to sign with: its core goes into the
   settings, and the member sets up its pairs with its co-signers (*Rebuild setup*) before
   it first signs. To restore instead, *Restore from TSS shares* reads `t` share files, one
   after another, combines the Codex32 halves and stores the wallet's words.

### Rebuild setup

Signing needs, between every two signers, the pairwise OT state their devices set up
together, and a member keeps its own in its pair cache -- which a lost card, a power-off
of the Virtual Disk or an import leaves it without. Two members make their pair again:

1. On each of the two: the kept wallet → *Rebuild setup*, the medium, then the other member
   (or *Every missing member*, which takes them one after another). The device first reads
   its cache from that medium, if there, and lists who it has no pair with.
2. The lower member number starts a pair-setup session and writes its invitation; the
   other finds it on the medium.
3. Rounds 0 and 1 as in every session (commitments, identities, the session code compared on
   both screens), then rounds 2 and 3: the base-OT exchange both ways (tsslib
   `PairSetupParty`), unicast, encrypted and signed.
4. Each installs its new pair, writes a new cache with every pair it holds, and saves the
   new digest in its settings. No share, no other pair and no address changes.

Signing (stage 2) does the same for the pairs it lacks before the signing rounds:
`catcard_tss` refuses a signing session whose member lacks a pair with another signer
(`Error::MissingPairs`) before anything is sent. Pairs with members not signing are never
needed.

### Sign without a card (Q1, by QR)

Users with no SD card can sign air-gapped (decided 2026-10-04):

- The **Virtual Disk** stands in for the card. Session files and the pair cache live there as
  they would on a card; the firmware already treats both as one media type.
- **QR carries the files**, round by round: each Q1 shows its outgoing messages as animated
  BBQr and scans the others'.
- The Virtual Disk is gone at power off, so the **pairwise setup is rebuilt from scratch at
  the start of each signing** (the missing-pairs path, `PairSetupParty`). That is a normal
  path, not an error.
- Q1 only: an mk4/mk5 can show codes but has no camera, so a group with one needs a card for
  that member.
- Cost per round, as QR: a pair setup is about 8.5 KB each way per pair; a checked signing
  22-34 KB per input per co-signer (plain about half). Expect a few animated codes per round.

### Sign

1. Each signing member loads the same PSBT (SD, QR) and approves it on its own screen, after
   checking the outputs as for any signature.
2. Each loads its pair cache; a pair it lacks with another signer is set up first (*Rebuild
   setup*).
3. Rounds 0 and 1 as above, then the DKLs signing rounds 2-6 for every input. Signing is
   **checked** unless the caller asks otherwise (`SignMode::default()` is `Checked`).
4. The first member writes the signed PSBT.

### Restore a created-together wallet

`t` members combine their shares into the joint private key and its chain code, stored as an
xprv-type wallet. **This ends the "nobody holds the key" property** and is said so, twice,
before it is done. Only the cores are read: no pair is needed.

## Where things live

Decided 2026-10-04 and built the same day with tsslib 0.2.13
([KarpelesLab/tsslib-rs#16](https://github.com/KarpelesLab/tsslib-rs/issues/16): the key
core and each pair encode on their own, `PairSetupParty` rebuilds one pair).

- **Inside the device: only the core.** Per TSS wallet and member, one **share record**
  (`catcard_tss` record format 3): the tsslib key core (`Key::write_core_to` -- the 32-byte
  share, the joint public key and chain code, every member's public share), and around it
  `n`, `t`, the member number, the origin (fingerprint and path), the joint key and chain
  code again (so the wallet can be listed and shown without decoding the share) and the
  digest of the member's current pair cache. 534 bytes at 3 members, 1,032 at 9 (283 + 83
  per member + 4 per path step). The records are a JSON array of base64 strings under
  `cctss` in the **settings of the wallet in force** (`catcard_settings::tss`), under the
  settings encryption like its multisig registrations and WIF store: 712 characters at 3
  members, 1,376 at 9, of the slot's 4,064 bytes for everything -- so a wallet keeps a
  handful, and a save that would not fit says "no room in the settings" rather than
  dropping one.
- **On the card or the Virtual Disk: the pairwise OT state**, 12.7 KB per other member, as a
  cache file per wallet and member, `TSS/<first 8 bytes of the wallet id>-m<member>.pairs`
  (`catcard_tss::cache`), so one card holds several members' and wallets' side by side:
  - sealed as the FIDO passkey file is -- `"CTSp" ‖ version ‖ member ‖ n ‖ IV ‖ tag ‖ ct`,
    AES-256-CTR under a fresh IV, then HMAC-SHA-256 over everything before it, the tag
    checked in constant time before anything is decrypted -- under two keys made by
    HMAC-SHA-256 from the **stored wallet's settings key** (made from the secret the secure
    element holds; inside `keywork::run`), the wallet's id and the member number;
  - taken only if its SHA-256 is the digest the record keeps, so a stale (from before a
    rebuild), changed, truncated or swapped cache is refused before its tag is even
    computed; a record copied to another device keeps its digest, and the cache still
    does not open there (the tag);
  - a cache that is missing or refused is the ordinary case, not an error: the screen says
    which and offers *Rebuild setup*.
  The wallet id is SHA-256 over `n`, `t`, the joint key, the chain code and every
  member's public share: public, and different for two splits of one account.
- **A lost cache is rebuilt, not fatal.** Two members re-run the pairwise setup between them
  (*Rebuild setup*, a `Session::pair_setup`), changing no share, no address and no other
  pair. (tsslib's `refresh` would also do it, but it rotates every share and needs every
  member, so it is kept for periodic proactive refresh.)
- **Export bundles carry the core alone**, with the Codex32 half: whoever takes one in sets
  up its pairs with its co-signers.
- The share itself cannot be derived from the root secret: it depends on the other members'
  randomness (create together) or the exporting device's (export). An exporter could derive
  its polynomial from its own seed, so that it can re-issue a lost share while it still holds
  the seed.
- A device keeps no TSS wallet without a stored wallet: the caches are sealed under its
  secret, and a blank device has none.
- Boards: mk4, mk5, Q1. The mk3 has no flash left for it.

Nothing of stage 1 (each whole record as a sealed file in the settings volume) was
deployed, so nothing migrates: record and bundle formats 1 and 2 are refused.

## On the device (stage 1, 2026-10-03; storage 2026-10-04)

Settings → **TSS wallets** (beside `Multisig`, docs/MENU.md) lists the TSS wallets this
wallet keeps (`2-of-3 #2 1A2B3C4D`: t, n, member, fingerprint) and offers *Create together*,
*Import a share*, *Split this wallet* (the export), *Restore from shares* and *What is
this?*. A kept wallet opens to *Details* (n, t, member, origin, three receive addresses, the
xpub, a watch-only descriptor), *Rebuild setup*, *Descriptor to file*, *Copy share to file*,
*Restore the whole key* (created-together only) and *Delete this share*. On a blank device,
Import → **TSS shares** is *Restore from shares*.

Every flow that reads or writes a file asks which medium first, wherever a card can be
picked: the **SD card** or the **Virtual Disk (temporary)**, through `menu::Storage` and the
one volume type both mount as (`crate::media`). A session only produces and takes envelope
bytes under their file names (`catcard_tss::Session`), and one loop drives every session
kind over the medium (`tss::drive`), so QR (stage 2) is another way of moving the same
bytes.

- **Create together.** The medium, then member 1 picks n and t (up to 9 members, as the
  memory allows; the shapes `can_create_together` refuses are refused with "too many
  needed: a few could bias the key"; fewer than 3 members with "2-of-3 is the usual
  minimum") and starts a session: its id is from the UI DRBG, its folder `TSS/<id>/` gets
  the round-0 file and `invite.txt` (n and t as text). The others choose *Join*, pick the
  session from those on the medium, and a member number not yet taken. Then every device
  runs the same loop, driven only by the session's outbox and `awaiting()`: write what it
  has, read what it waits for, show the 8-word code when every identity is in (and go on
  only on "the same on all"), and otherwise say "Step k of 4. Pass the card to member m
  (waiting for members ...), then put it back here." -- or, on the Virtual Disk, to copy
  the TSS folder between this disk and member m's. At the end each member keeps its core in
  its settings, writes its pair cache to the medium, and shows the wallet's fingerprint,
  first addresses, xpub and descriptor to compare across the devices. A cache that will
  not write is said ("set it up again to sign") and the core kept naming none. The session
  is in memory only: leaving the screen abandons it.
- **Rebuild setup.** See the flow above. The invitation of a pair setup names the wallet
  (the first 8 bytes of its id) and the two members, so the second device finds the right
  session among several; it is not trusted, the session code covers the whole wallet id.
  After each pair the cache and the record are written again, so a pair made is kept even
  if the next is not.
- **Split this wallet.** The words of the wallet in force (refused with a passphrase: the
  shares carry the words alone), n and t (any `2 <= t <= n` the memory allows), native
  SegWit / nested SegWit / legacy (and "Why not Taproot?"), the account number, the
  medium, then how to protect the files. The account key is derived from the master in
  `keywork::run`, the export runs in one masked region and is checked by recombining the
  first t Codex32 halves before anything is written; then "Share i of n: insert its card,
  or keep this one" for each file, `tss-<FP>-<i>of<n>.7z`.
- **Share files** are 7-Zip archives of one stored file, as a backup is: AES-256 under a
  password typed twice and stretched once per export (7-Zip's KDF, 2^19 rounds, a fresh
  IV per file from the protocol DRBG), or -- asked twice, never the default -- in the
  clear. A password per export rather than per file: the cards are kept apart, and one
  stretch rather than n keeps the export to one wait.
- **Import a share** takes a bundle (keeping its key core) or a lone record (from *Copy
  share to file*), checks the core decodes before keeping it, keeps it naming no pair cache
  (a copied record's cache is another device's), and refuses a share already kept. It says
  to set up the pairs before signing.
- **Restore from shares** reads t bundles one file after another, using only their Codex32
  halves (no DKLs decode), recovers the words, shows the fingerprint and word count, warns
  before replacing a stored wallet, and stores the words as the seed-import path does.
- **Restore the whole key** says twice -- an approval page, then "3 = yes" -- that the
  device will hold the whole key, then gathers t records (the ones kept here, the rest from
  files), recombines them (`combine`) and stores the key as an XPRV. Its addresses are
  then `m/0/*` and `m/1/*` of that XPRV, and the device says so.

### Memory

Since tsslib 0.2.12 (2026-10-04) keys and messages use its binary encoding
(`tsslib::wire`), streamed: a record is written straight into a buffer sized by a counting
pass and read straight from its bytes, with no JSON document built in between. Measured on
the host with 32-bit pointers (wasm32-wasip1 under node, an allocator that tags every block
with its member and charges it as the device heap does -- a two-word header, the payload
rounded to a word), 2026-10-04, with the whole key -- core and pairs -- as one record
(stage 1):

| members | whole key | encode one key | decode one key | create together, one member | export (all bundles held) |
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
and writes, and the whole key encoded and copied at the end while the session still lives
-- with every member run in one process and only that member's blocks counted. Since the
split it ends instead by moving the key out of the session, dropping the session, and
sealing the pairs into the cache (the key and the cache, about twice the whole key), which
the column bounds. "Export" is tsslib's reshare to `n` members, then every bundle held
while each in turn is encoded: the larger of the two; bundles are now cores, so the reshare
is the peak. Before (tsslib 0.2.11's JSON, raw allocation sizes), encoding one key peaked at
116 / 231 / 445 / 462 KB for 2-5 members and decoding at 88 / 150 / 213 / 276 KB.

Not re-measured since the split: a record is now its core, so *import* and *restore the
whole key* decode a kilobyte, and the "decode one key" column only bounds them. *Rebuild
setup* holds the record with every pair it has, one pair-setup party and the cache it
writes; it is bounded by the "create together" column of the same `n` (which holds a whole
key and runs a pair setup with every other member besides its DKG), 3 members' for 2. All
of these want measuring.

The heap is 216 KB in three pieces (32 KB linked, 64 and 120 KB of spare RAM either side
of the app area). Every flow that touches a DKLs key borrows the 256 KB app area for its
duration (`crate::heap::borrow_app_area`), which joins the two spare pieces into one 440 KB
run; apps refuse to start meanwhile, and on return every free heap byte is wiped -- which
also clears what tsslib freed without wiping (its encoding structs, the messages it
copied). Each flow then checks the peak above, plus 32 KB for the files and the screens,
against what is free, and offers only the `n` that fits. With the area lent:

- **create together, rebuild setup: up to 9 members** (374 + 32 KB);
- **split this wallet: up to 5 shares** -- an export holds every member's key at once, and
  that grows with `n`²;
- **import a share, restore the whole key: any `n` to 9.** Restoring the key decodes one
  record at a time and keeps only its Shamir share (`catcard_tss::combine_parts`).

Without the lease, 3 or 4 members would create together in 216 KB and an export to 3 would
fit too; the lease is still taken for them, for the wipe on return.

### Flash

The screens bring in all of catcard-tss and tsslib's DKLs parties (a session dispatches over
keygen, pair setup and both signing kinds; signing itself is not reachable from a screen
yet, so the linker drops it). The workspace builds `tsslib` and `catcard-tss` at
`opt-level = "z"` on every board (purecrypto, which does the heavy arithmetic, stays at
`"s"`; the bench times below were at `"s"` and want re-measuring).

tsslib 0.2.12 without its `json` feature took serde_json out of the image, and with it
catcard-tss's own JSON re-encoder: images (dev builds, 2026-10-04) mk4/mk5 1,419,264 →
1,393,664 bytes, Q1 1,440,256 → 1,401,856. That put the `DebugTssBench` bench back on the
Q1 (12 KB). tsslib 0.2.12 needs purecrypto 0.9.9, whose secp256k1 and safegcd inversion grew
the mk3 image (which has no TSS) 876,544 → 892,928 bytes of its 915,456-byte ceiling.

The split (tsslib 0.2.13, the pair cache, pair setup and *Rebuild setup*, the medium
choice; dev builds, rustc 1.99, 2026-10-04): mk4/mk5 1,392,128 → 1,422,848 bytes, Q1
1,412,608 → **1,438,208 of 1,441,792, 3.5 KB left**; mk3 889,344 → 888,832. Of the
~25 KB: catcard-tss ~7.7 KB (records, cache, pair setup), the screens ~8.8 KB, tsslib
~6.1 KB (its pair-setup party and the pair decoder), the bench ~1.1 KB (tsslib's
signing now checks pairs). The `DebugTssBench` bench (12 KB) is the obvious room if the
Q1 needs more.

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

The whole key grows with `n` (per-peer OT state); since 2026-10-04 only its core, 338
bytes at 2 members, is kept in the settings, and the pairs live in the pair cache. tsslib's
binary key encoding is 2-of-2's 45.6 KB of JSON in 13.1 KB.

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

Share records (settings), record format 3 -- the key core, created together (an
exported record adds 4 bytes per path step, 12 for an account), and the pair cache
(card or Virtual Disk) that goes with it:

| members | 2 | 3 | 4 | 5 | 7 | 9 |
|---|---|---|---|---|---|---|
| record (core) | 451 | 534 | 617 | 700 | 866 | 1,032 |
| in the settings, base64 | 604 | 712 | 824 | 936 | 1,156 | 1,376 |
| pair cache | 12,757 | 25,458 | 38,159 | 50,860 | 76,262 | 101,664 |

-- the core is 338 bytes at 2 members and 83 more per member (one public share); a pair is
12,701 bytes in the cache. In format 2 the record was the whole key, 13,120 to 102,562
bytes. An export's share bundle is the record, 11 bytes and the 48-character Codex32
string: 522 / 605 / 771 / 1,103 bytes for 2-of-2 / 2-of-3 / 3-of-5 / 5-of-9.

Pair setup, one pair, as one member sends it: rounds 0 and 1 as every session (117 and
150 bytes), round 2 a 275-byte unicast (base-OT sender), round 3 an 8,560-byte unicast
(base-OT receiver): 9,102 bytes each way.

## Open

- ~~Heap per member with one party per device~~ — measured on the host (2026-10-04, "On
  the device / Memory"): with tsslib's binary encoding, 9 members create together and 5
  take an export. Wants checking on a device.
- ~~Settings space for a 9-member record (103 KB a share)~~ -- the record is the core
  now, 1 KB at 9 members, in the wallet's settings (2026-10-04). Still open: a settings
  object is 4 KB for everything, so a wallet keeps a handful of TSS wallets, fewer the
  larger they are; and QR part counts for the signing unicasts (11-34 KB per input per
  peer) and a pair setup's (8.6 KB each way).
- The memory of *Rebuild setup*, and of import and restore with cores, is bounded by older
  measurements, not measured (see "Memory").
- Nothing of the split has run on a device: create together writing its cache, Rebuild
  setup between two devices, import of a core-only bundle, and the Virtual Disk as the
  session medium all want trying on hardware.
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
