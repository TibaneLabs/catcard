#!/bin/bash
# Build a FAT32 microSD image with a firmware file on it, for testing the SD path.
#
# Needs `fstool` (cargo install fstool). The emulator mounts the result with
# `--sd out/sd-test.img`, and `fstool ls` / `fstool cat` read it back afterwards, which
# is how a write from the device gets checked without trusting the device's own report.
#
# Usage: tools/emu/mksd.sh [image-to-put-on-the-card] [output.img]
set -eu
cd "$(dirname "$0")/../.."
FW=${1:-out/catcard-mk4-mk5.dfu}
OUT=${2:-out/sd-test.img}
SRC=$(mktemp -d)
trap 'rm -rf "$SRC"' EXIT
cp "$FW" "$SRC/"
fstool create --type fat32 --output "$OUT" --size 64M "$SRC"
fstool ls "$OUT" /
