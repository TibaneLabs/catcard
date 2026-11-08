# Precursor: keeping a seed at rest

Design for storage on the Precursor (`docs/PRECURSOR.md`, milestone 4), chosen
2026-11-08: **a device secret inside the encrypted gateware, mixed with the owner's
passphrase**. Status: the bitstream rewriting it rests on is built and verified
offline (`crates/catcard-bitstream`); nothing has been provisioned on a device yet.

## What the hardware offers

- A **key ROM** in the stock gateware: 256 x 32-bit words, read by the `keyrom` CSR,
  each word lockable until reset (`lockaddr`; a locked word reads 0). Its contents are
  LUT INIT values, i.e. **part of the bitstream**. Source: betrusted-io/gateware
  `keyrom.py` [C].
- **AES-256 bitstream encryption** with the key in eFuse or BBRAM, selected by CTL0
  bit 31 in the bitstream. BBRAM is battery-backed, rewritable, and erased by the
  self-destruct path; eFuse is permanent. Source: Xilinx UG470 ch. 5 [C].
- A boot ROM that verifies the loader against the **first non-zero** of three key ROM
  slots: self-signing key (0x10), third-party key (0x20), developer key (0x18), and
  marks the screen when it fell back past the first. Source: betrusted-soc
  `boot/betrusted-boot/src/main.rs` [C].

## What the bench unit has (read 2026-11-08 from its flash dump)

- Gateware v0.9.5, **encrypted to the all-zero key, eFuse source** (CTL0 0x80000040).
  Release gateware is built this way (`dummy.nky`); a public key protects nothing.
- Key ROM: only the developer public key `1c9beae3…58bb` at 0x18 and version 0x0001
  at 0xff. Unprovisioned.
- eFuses unburned (the zero key decrypts). **CatCard never burns eFuses.**

So today anyone holding the flash can decrypt the gateware and read the key ROM, and
anyone with USB can run code through the v0.9.5 debug bridge.

## The design

Provisioning, once, on the device:

1. Draw from the entropy pool: `K_fpga` (BBRAM key), `DS` (device secret), `SK`
   (Ed25519 firmware-signing key). All 256-bit.
2. Rewrite the gateware (`catcard-bitstream`): decrypt with the zero key, put `DS`,
   `K_fpga` and `pub(SK)` into the key ROM, switch the key source to BBRAM, fresh IV
   and HMAC key, encrypt to `K_fpga`. Write it to flash only after the pass verified
   the source HMAC, then read it back through a second pass.
3. Sign the CatCard loader with `SK`.
4. Hand `K_fpga` to the provisioning helper (the Raspberry Pi on the debug hat) over
   the UART. It writes BBRAM over JTAG, then reloads the FPGA. **BBRAM can't be written
   from the device itself**: programming it needs ISC mode, which unconfigures the
   FPGA, and with it the SoC that would be driving the JTAG. Xous uses the same
   helper arrangement (root-keys `BbramProvision`). The key crosses the UART once;
   the helper must be trusted, and must forget it.

Key ROM layout (CatCard's; Xous's slot numbers where they mean the same thing):

| addr | contents |
|---|---|
| 0x00..0x08 | `K_fpga`, so the device can re-encrypt gateware updates |
| 0x10..0x18 | `pub(SK)`: the boot ROM now only accepts loaders signed by `SK` |
| 0x18..0x20 | developer key, left in place (unused while 0x10 is set) |
| 0x28..0x30 | `DS` |
| 0xff | version word, unchanged |

`SK`'s private half is stored in flash, wrapped under the unlock key. Signing a
firmware update needs the passphrase, as Xous's update password does.

Unlock at power-on:

- Read `DS` and `K_fpga` from the key ROM, then **lock** those words until reset.
- Unlock key = Argon2id(passphrase, salt, **secret = DS**), memory-hard, a second or
  so on the device. Argon2's own `secret` input is where a pepper belongs.
- The seed is stored encrypted under the unlock key with `catcard-settings`.

## What it buys, and what it doesn't

| attacker | outcome |
|---|---|
| holds the flash (lost or stolen device, chip-off dump) | needs `DS`, which is inside a bitstream encrypted to a key only in this FPGA's BBRAM. A weak passphrase is safe here |
| USB access, v0.9.5 gateware | the debug bridge can halt the CPU and run code, reading the key ROM. Firmware sets `usbdisable` first thing, but the boot ROM runs before that. **Provision on v0.9.14 or later**, whose bridge carries no CPU debug and filters addresses (betrusted_soc.py, `filters=`) [C] |
| writes a loader to flash | the boot ROM refuses anything not signed by `SK` |
| replaces the gateware (zero-key, eFuse) | it loads, because the eFuses are unburned, but it can't contain `DS`. Phishing the passphrase this way, then putting our gateware back, is the classic evil-maid attack. Burning the eFuse "decrypt only" bit would close it, and CatCard won't burn eFuses |
| opened case, JTAG, a lab | BBRAM isn't readable, but 7-series bitstream encryption has published attacks (Starbleed, 2020). Assume a lab can get `DS`. What's left is Argon2id against the passphrase, so the passphrase still matters |
| BBRAM battery dies | the FPGA can't decrypt its gateware. Recover by JTAG; the stored seed is gone with `DS`. **The seed words are the backup** |

## Staged plan

- **A. Patch test, zero key, no BBRAM.** Rewrite the gateware keeping the zero key and
  eFuse source but with a fresh IV and HMAC key and a marker word in an unused key ROM
  slot. Flash it, boot, read the marker from firmware. This proves the frame mapping
  and HMAC on the real FPGA. Recovery is the USB bridge, or JTAG.
- **B. Recovery bitstream.** A JTAG-to-SPI bridge that also drives `fpga_sys_on`
  (pin A5) high, so the EC keeps power during a long JTAG flash write. The stock
  `bscan_spi` bitstream doesn't, and the board powers off about 30 s after the FPGA
  stops driving it.
- **C. Gateware v0.9.14** in flash, the boot ROM's key selection unchanged.
- **D. Firmware**: key ROM driver (read, lock), `usbdisable` at entry, Argon2id
  unlock, the encrypted seed store, and passphrase entry.
- **E. Provisioning** (steps 1-4 above) with the Pi helper. Test BBRAM with a
  throwaway `K_fpga` first: burning BBRAM while the flash still holds the zero-key
  eFuse gateware changes nothing, so the key can be written, then the BBRAM gateware
  flashed, and B undoes either step.

## Sources

- betrusted-io/gateware `keyrom.py`; betrusted-soc `betrusted_soc.py`,
  `gen_keyrom.py`, `dummy.nky`, `boot/betrusted-boot`.
- Xous `services/root-keys`: `implementation.rs` (`KeyRomLocs`, `do_key_init`,
  `gateware_copy_and_patch`), `implementation/oracle.rs` (bit order, CTL0 patching),
  `key2bits/patch.rs` (the frame/bit tables in `keyrom-map.bin`).
- Xilinx UG470, 7 Series FPGAs Configuration User Guide, ch. 5 and 6.
- M. Ender, A. Moradi, C. Paar, "The Unpatchable Silicon: A Full Break of the
  Bitstream Encryption of Xilinx 7-Series FPGAs", USENIX Security 2020.
