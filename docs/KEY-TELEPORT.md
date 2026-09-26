# Key Teleport

Q1 only. Moves a seed, a Seed Vault entry, notes and passwords, a whole backup, or a
multisig PSBT from one Q1 to another over QR codes (or an NFC link), authenticated by two
passwords read aloud. **The wire format is stock's, byte for byte**, so a CatCard Q1 and a
stock Q1 can teleport to each other. The spec is `hw-reference/key-teleport-protocol.md`;
the code is `crates/catcard-wallet/src/teleport.rs` (protocol, host-tested against the
spec's own vector) and `crates/catcard-fw/src/teleport.rs` (screens).

## How it runs

| Step | Receiver | Sender |
|---|---|---|
| 1 | Utils → Backup → Key Teleport → Receive. Shows the `R` QR and an **8-digit receiver password**. | |
| 2 | | Key Teleport → Send (or Scan QR on the `R` code). Scans `R`, types the 8 digits, reads the warning, picks what to send. |
| 3 | | Shows the `S` QR and an **8-character teleport password**. |
| 4 | Scans `S` (from the Receive screen, or Scan QR anywhere), types the teleport password. | |
| 5 | The payload lands where the matching import puts it. | |

The multisig PSBT variant (`E`) needs no receiver step: both co-signers already hold each
other's xpubs, so the keys come from those, and only the teleport password is spoken.

## What it protects, and what it does not

This is stock's construction. It is kept, weaknesses included, because interoperating
with stock is the point; the list below is so nobody mistakes it for more than it is.

- **Encryption**: two layers of AES-256-CTR from a zero counter. The outer key is the
  secp256k1 ECDH of the two devices' keys (`SHA256(X‖Y)` of the shared point); the inner
  key is PBKDF2-HMAC-SHA512 (5000 rounds) of that session key, salted with the 40-bit
  teleport password. Someone who photographs both QRs and heard neither password has to
  break the ECDH.
- **No MAC, no AEAD.** Each layer carries the last two bytes of an *unkeyed* SHA-256 of
  its plaintext. That detects a wrong password or a damaged scan (about 1 in 65,536 slips
  through); it does not detect a deliberate change by someone who can predict the
  plaintext. CTR is malleable.
- **Authentication is the spoken passwords.** The receiver password is about 26.6 bits
  and is what ties the sender to *this* receiver: someone who can replace the `R` QR and
  hear the digits can put their own key in the middle. Read the digits in person, or over
  a channel you trust, and never read them where the QR is also visible to the same
  observer.
- **Only about half of wrong receiver passwords are caught when typed** (the decrypted key
  must land on the curve). The rest produce a key nobody holds, and the receiver then
  refuses the payload as damaged. So a refused teleport after a correct-looking send
  usually means the digits were mistyped: start the send again.
- **The teleport password is 40 bits.** Against an attacker who does not hold the session
  key it is irrelevant; against one who does, 5000 PBKDF2 rounds is a modest stretch.
- **No nonce is transmitted.** Safe because every sender keypair is fresh and every PSBT
  teleport has a fresh `ri`; the receiver keeps its keypair only until one receive
  succeeds (below).

**Anyone who receives a master secret, a vault entry or a backup can spend everything
those keys control.** Every send path says so before anything is built.

## Resume

The receiver's private key is kept in the wallet settings under **`cat_ktrx`** (stock uses
`ktrx`; ours is under our own name, per `docs/SECRETS-AND-SETTINGS.md`). Starting a
receive again while it is set offers to keep it -- the digits and the `R` code are
recomputed from it and come out the same, so a sender's `S` code already built for it
still opens -- to scan now, or to start over with new values. A failed receive (wrong
sender, damaged scan, wrong teleport password) keeps it, as stock does.

It is cleared the moment a payload opens, **before** the owner is asked where to put it.
Stock clears it on each accept path instead; we clear earlier because landing a seed
changes the wallet in force, and with it which settings file a later clear would write
into. The cost: backing out at "use this seed?" means the sender has to send again.

## Where a received payload goes

| Body | Lands in |
|---|---|
| `s` secret | A device with no seed: offered as *the* seed (the restore confirmation). Otherwise: a temporary seed for this session (words or XPRV; a raw master is refused, as the backup temporary load refuses it). |
| `x` XPRV | As an `s` XPRV. |
| `v` vault entry | The Seed Vault of the wallet in force. |
| `n` notes | Merged into Secure Notes & Passwords: new titles added, identical ones skipped, a differing title asked about. |
| `b` backup | A device with no seed: the wallet is restored from it. Otherwise: its wallet as a temporary seed. |
| `p` PSBT (`E` only) | The signing review, as a PSBT scanned from a QR would be. |

## Known gaps against stock

- **Notes shape.** Stock's note/password JSON fields are not documented in
  `hw-reference/`. We send our own item objects and accept any object with a `title`;
  a stock receiver may not show every field of ours, and fields of stock's we do not know
  are not imported.
- **Multisig wallets and settings from a `b` backup** are not installed on receive: the
  existing backup restore installs the seed only, and this uses it unchanged.
- **The PSBT stays on the device** after it is signed through the ordinary review;
  stock's onward "teleport to the next co-signer" after signing is not offered -- send it
  on from Key Teleport → Multisig PSBT, picking the signed file.

With a spending policy active (hobbled), only a multisig PSBT may come in, as stock says.
