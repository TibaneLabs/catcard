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
- **No Taproot.** tsslib's FROST is Ed25519; there is no threshold Schnorr on secp256k1 here.
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

- Shares are kept in the device's encrypted settings, beside its own wallet, one record per
  TSS wallet: member number, `n`, `t`, the joint public key and chain code, the DKLs share.
  The DKLs share includes per-peer setup state, so its size grows with `n`; it is measured
  before a maximum `n` is fixed.
- Boards: mk4, mk5, Q1. The mk3 has no flash left for it.

## On the device (stage 1, 2026-10-03)

Settings → **TSS wallets** (beside `Multisig`, docs/MENU.md) lists the shares kept here
(`2-of-3 #2 1A2B3C4D`: t, n, member, fingerprint) and offers *Create together*, *Import a
share*, *Split this wallet* (the export), *Restore from shares* and *What is this?*. A kept
share opens to *Details* (n, t, member, origin, three receive addresses, the xpub, a
watch-only descriptor), *Descriptor to card*, *Copy share to card*, *Restore the whole key*
(created-together only) and *Delete this share*. On a blank device, Import → **TSS shares**
is *Restore from shares*.

- **Create together.** Member 1 picks n and t (the shapes `can_create_together` refuses
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

tsslib's key save format costs far more heap than the key: measured on the host with
32-bit pointers (wasm32, counting allocator, 2026-10-02), encoding one member's key peaks
at 116 / 231 / 445 / 462 KB for 2 / 3 / 4 / 5 members, decoding at 88 / 150 / 213 /
276 KB; a DKG member's own rounds peak at 118 KB (2-of-3). The heap is 216 KB in three
pieces, so every flow that touches a DKLs key borrows the 256 KB app area for its duration
(`crate::heap::borrow_app_area`: apps refuse to start meanwhile, and on return every free
heap byte is wiped -- which also clears what tsslib freed without wiping), then checks the
measured need against what is free and offers only the `n` that fits. In practice **at most
3 members** on the device today: 2-of-3 create together, 2-of-2 / 2-of-3 / 3-of-3 export.
Larger shapes want tsslib's encode and decode to stop building the whole JSON document.

### Flash

The screens bring in all of catcard-tss and tsslib's DKLs parties (a session dispatches over
keygen and both signing kinds) and serde_json's parser: about 200 KB at `opt-level = "z"`.
To fit, the workspace builds `tsslib`, `catcard-tss` and `serde_json` at `"z"` on every
board (purecrypto, which does the heavy arithmetic, stays at `"s"`; the bench times above
were at `"s"` and want re-measuring), and the Q1 image leaves out the `DebugTssBench`
bench (mk4/mk5 keep it). Images (dev builds): mk4/mk5 1,208,320 → 1,419,264 bytes, Q1
1,250,816 → 1,440,256 bytes of a 1,441,792-byte ceiling -- **the Q1 has 1.5 KB left**.

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
hold shares for; binary instead of JSON roughly halves it.

## Measured (host, `cargo test -p catcard-tss --test sizes -- --nocapture`)

Message envelope sizes, as one member sends them (SD file or BBQr payload). tsslib's JSON
is re-encoded into a compact binary form first (base64 and byte arrays as raw bytes);
signing messages are almost all OT-extension data and do not compress further.

| | round 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
|---|---|---|---|---|---|---|---|---|
| create together, broadcast | 117 | 150 | 250-318 | 178-250 | | | | |
| create together, to each peer | | | 410 | | 8.8 KB | | | |
| sign, broadcast, one input | 117 | 150 | 176 | 142-178 | | | 173 | 142-178 |
| sign (plain), to each peer, per input | | | | | 11.8 KB | 17.5 KB | | |
| sign (checked, the default), to each peer, per input | | | | | 23.5 KB | 35.0 KB | | |

Rounds 0 and 1 are the introductions (a 32-byte commitment, then the 33-byte key and the
32 bytes that open it); the protocol proper is rounds 2 and on. Ranges are over 2, 3, 4 and
5 members; each further input adds about 90 bytes to a signing broadcast. Every envelope
carries 85 bytes of header and signature.

Share records (settings): **13.7 KB** for 2-of-2, **27.0 KB** for 2-of-3, **53.5 KB** for
3-of-5 -- about 13.4 KB per other member (the pairwise OT state). An export's share bundle
adds 61 bytes and the 48-character Codex32 string.

## Open

- ~~Heap per member with one party per device~~ — measured on the host (2026-10-02, "On
  the device / Memory"): tsslib's key encode, not the protocol, sets the limit, at 3
  members today. Wants checking on a device.
- Maximum `n` given the record sizes above (settings space), and QR part counts for the
  signing unicasts (12-35 KB per input per peer).
- The Q1's flash: 1.5 KB left with the TSS screens in (see "Flash").
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
