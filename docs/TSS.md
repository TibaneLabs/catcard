# Threshold signing (TSS)

Status: **design, 2026-10-02.** Nothing implemented yet.

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
  SD card or a QR is not one. So round 0 of every session: each member makes a per-session
  identity key and publishes its public key. Every member shows a **session code** — a hash
  of the parameters and every identity key, as words — and the user checks the codes match
  on all devices before anything secret is sent. From then on each message is signed by its
  sender's session key, and anything unsigned or signed by someone else is refused.
- **Randomness.** The DKG's secret contribution and every share made on export are seed-grade
  and come from the entropy pool, like a new wallet (the pool-draw lint allowlist names the
  TSS module). Protocol randomness (nonces, OT seeds) comes from a DRBG seeded from the pool
  for the session and wiped after it.

## The flows

### Create together

1. On every member: choose *Create TSS wallet*, `n`, `t`, and its member number.
2. Round 0: identity keys out, session code shown and compared.
3. DKLs keygen rounds, by SD or QR, until every member has its share.
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
2. Round 0 as above, then the DKLs signing rounds for every input.
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

## Open before implementation

- Share and message sizes for real `n` (settings space; QR part counts).
- Time and heap per DKLs round on the device.
- Encryption of share files on SD (a password per file, or none and the card is the secret).
