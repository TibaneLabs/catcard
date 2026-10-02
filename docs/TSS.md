# Threshold signing (TSS)

Status: **protocol layer built, 2026-10-02** (`crates/catcard-tss`, host-tested; not yet
wired into the firmware). Screens, SD/QR transport and settings storage are still to do.

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

- Heap per member with one party per device: the bench above holds every party at once.
- Maximum `n` given the record sizes above (settings space), and QR part counts for the
  signing unicasts (12-35 KB per input per peer).
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
- Encryption of share files on SD (a password per file, or none and the card is the secret).
