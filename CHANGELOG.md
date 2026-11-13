# Changelog

What changed in each published release, newest first. Written for someone deciding
whether to install one; the commit history has the detail.

Every release so far is a pre-release signed with the published developer key.

## 7.0.0-beta1 — 2026-11-13

Changes since 7.0.0-alpha5 (2026-10-05).

**Run on hardware:** bench builds of this code on a Q1 (every message scheme below) and
an mk5 (address by path, typed data), with the signatures checked on the host. The
published images themselves, the mk3, and the CANCEL-at-power-on reflash were not run.

### For computers and phones talking to the device

- **An address by its path** (`HostAddressAt`): a paired computer asks for the address at
  a path it names. The owner approves each one, or ticks "Allow during session"; a flag
  puts the address on the device's screen to compare.
- **Message signing over USB** (`HostSignMessage`), reviewed on the device:
  - Bitcoin: BIP-137, BIP-322 simple and full;
  - Ethereum: `personal_sign` (EIP-191) and typed data (EIP-712);
  - Tron: `signMessageV2` (TIP-191);
  - Solana: off-chain messages, versions 1 and 0.

  The chains other than Bitcoin need a multichain image, and none of them is on the mk3.
- **`HostInfo`**: what a build supports, per chain, without a prompt.
- **A smart-card reader interface (CCID)** beside the HID one, so a phone can reach the
  device; `docs/PHONE-APP.md` is the guide for app authors.

### Threshold signing (TSS)

- **In every published mk4/mk5 and Q1 image.** Until now only local bench builds had it.
- Transactions and messages, BIP-322 included, signed together with a TSS wallet in
  force.
- Exports and addresses from a TSS wallet's public half, other chains included.
- "Rebuild setup" pairs every member present in one session.
- Session codes are shown as BBQr.

### On the device

- Review screens scroll half a screen a key. On the Q1 they keep `ENTER` and `CANCEL`
  labelled at the foot of the screen.
- Seed words can be shown, and entered, as BitCan glyphs.
- Q1: the owner chooses which SD slot to use.
- BBQr display speed is on the arrow keys.
- The Debug menu is eleven rows. The bring-up screens are gone: TRNG words, bootloader
  replies, the NFC, keyboard, QR and sweep tests, USB, clocks, RTC, kernel, scroll test,
  colours, keypad, PSRAM, SPI-NOR, the nickname preview, and dump / restore state.

### Removed

- **A computer can no longer press keys or enter the PIN in the ordinary session.** No
  published image ever could; bench builds now keep it only for the USB reflash (hold
  CANCEL at power-on, or a unit whose panel or keypad is dead).
- About 190 routine log lines. In published images a logged error says what failed and
  shows `?` for which error it was.
- `tools/statedump.py` and `usbclient.py --stage-settings`.

### Fixed

- The UI task's stack ran out on the TSS signing paths.
- Showing a PNG held a whole frame in memory.
- A new wallet, and Lock down, now record that the secret slot holds a wallet.

### Other

- A Q1 rescue image that boots straight into the USB reflash, for a unit that cannot
  stage a full image (`docs/RESCUE.md`).
- `compcol` 0.8.0, `tsslib` 0.2.15.

## Earlier

7.0.0-alpha1 to 7.0.0-alpha5 were published without notes; `git log` between their tags
is the record.
