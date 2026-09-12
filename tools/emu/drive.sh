#!/bin/bash
# Drive the whole device over USB, with nothing touching the keypad.
#
# Selftest screen, PIN (set one first if the device is blank), a firmware upgrade and
# its approval -- every keypress arriving over USB. This is the escape route for a first
# run on hardware whose keypad map and display are both still unconfirmed, so it is worth
# knowing it works before that run rather than during it.
#
# Needs a bring-up build: `cargo fw-mk4-bringup` compiles in `usb-key-injection`.
#
# Under the emulator the final install cannot be verified -- it refills PSRAM at reset,
# so a correctly staged image is gone before the bootloader looks. The run says so and
# does not fail on it. On hardware, add --expect-install to make that step mandatory.
#
# Usage: tools/emu/drive.sh <bootloader.dfu> [--expect-install]
set -u
BOOTLOADER=${1:?usage: drive.sh <factory-bootloader.dfu>}
EMU=${CCEMU:-../coldcard-emu/target/release/ccemu}
cd "$(dirname "$0")/../.."

# The offered image carries a different --version than the running one on purpose:
# installing a byte-identical image over itself cannot be distinguished from not
# installing at all.
cargo fw-mk4-bringup || exit 1
FW=target/thumbv7em-none-eabihf/release/catcard-fw
cargo run -q -p catcard-image -- build "$FW" --board mk4 --version 7.0.0 \
    --dfu out/catcard-mk4.dfu || exit 1
cargo run -q -p catcard-image -- build "$FW" --board mk4 --version 7.0.1 \
    --bin out/catcard-mk4-v2.bin || exit 1

SOCK=$(mktemp -u /tmp/catcard-XXXX.sock)
"$EMU" -q run --dfu out/catcard-mk4.dfu --bootloader "$BOOTLOADER" --board mk4 \
    --reboot --usb-hid "$SOCK" --run-for 600000000000 >out/drive.log 2>&1 &
PID=$!
python3 -u tools/usbclient.py "$SOCK" out/catcard-mk4-v2.bin --drive "${@:2}"
RC=$?
kill $PID 2>/dev/null; wait $PID 2>/dev/null
rm -f "$SOCK"
exit $RC
