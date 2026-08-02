# Signing keys

## `dev-privkey.pem` — the published developer key (slot 0)

This is **not a secret**. Coinkite publishes it so that anyone can build firmware that
a Coldcard bootloader will load. It is committed here deliberately so a clean checkout
can produce a loadable image with no extra setup.

Source: `hw-reference/firmware-signing.md §4` [C].

Corresponding public key (`approved_pubkeys[0]`, raw `X || Y`):

```
b4cb4126f7e16cf38ff2b4711dfb23010d76d666a78aa36c9b53f9f67b581805
580b3be931c49fb844043c1196080f478125ed377a239e4aafb71838ba3804da
```

**What signing with it does:** the bootloader accepts the image and boots it, showing
a 25-second warning screen and leaving the "genuine" light red. There is no green
attestation.

**What it does not do:** it grants no authenticity whatsoever. Everyone has this
private key, so a dev-signed image is not attributable to anybody. Do not treat a
dev-signed CatCard build as evidence of provenance, and do not tell users otherwise.

Bootloader key slots 1–5 are Coinkite production keys; those private keys are not
public and CatCard cannot sign with them.

## Release keys

CatCard release builds should be signed with a **project key** in addition to the dev
key, so that users can verify a build actually came from this project even though the
device cannot. That key is not in this repository — see `docs/RELEASING.md`.

Never commit a private key here other than the published dev key above.
