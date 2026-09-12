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
# Usage: tools/emu/drive.sh <bootloader.dfu> [board] [--expect-install]
#
# `board` defaults to mk4. Any Coldcard release image works as the bootloader source --
# the older mk3 releases carry one alongside the firmware, not just the "factory" ones.
set -u
BOOTLOADER=${1:?usage: drive.sh <bootloader.dfu> [board]}
BOARD=${2:-mk4}
case "$BOARD" in mk3|mk4|mk5|q1) ;; *) echo "unknown board: $BOARD" >&2; exit 2 ;; esac
EMU=${CCEMU:-../coldcard-emu/target/release/ccemu}
cd "$(dirname "$0")/../.."

cargo "fw-$BOARD-bringup" || exit 1
FW=target/thumbv7em-none-eabihf/release/catcard-fw

# mk4 and mk5 are the same board to within a strap, so they get one image carrying both
# `hw_compat` bits -- the same thing Coinkite ship. The firmware reads STRAP_MK5 at
# runtime, so the one image still names the board it is actually on.
case "$BOARD" in
mk4 | mk5) IMAGE="out/catcard-mk4-mk5.dfu"; COMPAT="--hw-compat mk4,mk5" ;;
*) IMAGE="out/catcard-$BOARD.dfu"; COMPAT="" ;;
esac
# shellcheck disable=SC2086
cargo run -q -p catcard-image -- build "$FW" --board "$BOARD" --version 7.0.0 \
    $COMPAT --dfu "$IMAGE" || exit 1
# The image offered over USB is the same file that was just built -- one version, one
# artefact, nothing sitting in `out/` that could be mistaken for the thing to flash.
#
# The cost is that the post-install check cannot prove anything by version, since the
# offered image and the running one are the same build. The client says so rather than
# claiming a pass; the emulator could not confirm an install anyway, because it refills
# PSRAM at reset.
#
# Only for boards that can stage: mk3 has nowhere to put an image.
OFFER=""
case "$BOARD" in
mk4 | mk5 | q1) OFFER="$IMAGE" ;;
esac

SOCK=$(mktemp -u /tmp/catcard-XXXX.sock)
"$EMU" -q run --dfu "$IMAGE" --bootloader "$BOOTLOADER" --board "$BOARD" \
    --reboot --usb-hid "$SOCK" --run-for 600000000000 >out/drive.log 2>&1 &
PID=$!
python3 -u tools/usbclient.py "$SOCK" $OFFER --drive "${@:3}"
RC=$?
kill $PID 2>/dev/null; wait $PID 2>/dev/null
rm -f "$SOCK"
exit $RC
