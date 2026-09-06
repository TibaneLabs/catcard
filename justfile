# CatCard task runner.  `just --list` to see everything.

board := "mk4"
version := "0.0.1"
elf := "target/thumbv7em-none-eabihf/release/catcard-fw"

default:
    @just --list

# Host tests for every portable crate.
test:
    cargo test --workspace --exclude catcard-fw

# Lint host crates and the firmware for its real target.
#
# RUSTFLAGS matches CI exactly, so a warning fails here rather than after a push.
lint:
    cargo fmt --all -- --check
    RUSTFLAGS="-D warnings" cargo clippy --workspace --exclude catcard-fw --all-targets
    @for b in mk3 mk4 q1; do \
        echo "clippy: $b"; \
        cargo clippy --release -p catcard-fw --target thumbv7em-none-eabihf \
            --no-default-features --features board-$b || exit 1; \
    done

# Build the firmware ELF for a board.
build board=board:
    cargo build --release -p catcard-fw --target thumbv7em-none-eabihf \
        --no-default-features --features board-{{board}}

# Build, header, sign and package. Outputs land in out/.
image board=board version=version: (build board)
    mkdir -p out
    cargo run --release -q -p catcard-image -- build {{elf}} \
        --board {{board}} --version {{version}} \
        --bin out/catcard-{{board}}.bin --dfu out/catcard-{{board}}.dfu

# Re-run every bootloader check we can reproduce off-device.
verify board=board:
    cargo run --release -q -p catcard-image -- verify \
        out/catcard-{{board}}.bin --board {{board}}

# What the bootloader would see.
info board=board:
    cargo run --release -q -p catcard-image -- info out/catcard-{{board}}.dfu

# Everything CI runs, locally.
ci: lint test
    @for b in mk3 mk4 q1; do just image $b && just verify $b; done

# Confirm the build is byte-identical given a fixed SOURCE_DATE_EPOCH.
repro board=board:
    #!/usr/bin/env bash
    set -euo pipefail
    export SOURCE_DATE_EPOCH=1785628800
    just image {{board}} && cp out/catcard-{{board}}.bin /tmp/repro-a.bin
    cargo clean -p catcard-fw
    just image {{board}} && cp out/catcard-{{board}}.bin /tmp/repro-b.bin
    cmp /tmp/repro-a.bin /tmp/repro-b.bin && echo "reproducible"

# Boot the firmware in ../coldcard-emu against a real bootloader.
#
# The emulator is consumed as a binary only — never its source or docs, which quote
# stock firmware inline. Agreement between it and CatCard is evidence of consistency,
# not correctness: both are ours and both derive from ../hw-reference. See
# docs/VALIDATION.md.
#
# `bootloader` must point at a factory .dfu, which carries the bootloader element that
# a firmware-only image does not. Budget past the 25-second dev-key warning.
emu board=board emulator="../coldcard-emu/target/release/ccemu" bootloader="" steps="2100000000": (image board)
    #!/usr/bin/env bash
    set -euo pipefail
    bl="{{bootloader}}"
    if [ -z "$bl" ]; then
        bl=$(ls -1 ../coldcard-emu/*factory*.dfu 2>/dev/null | tail -1 || true)
    fi
    if [ -z "$bl" ]; then
        echo "no bootloader image: pass bootloader=<a factory .dfu>" >&2; exit 1
    fi
    echo "bootloader: $bl"
    mkdir -p out
    {{emulator}} -q run --dfu out/catcard-{{board}}.dfu --bootloader "$bl" \
        --board {{board}} --run-for {{steps}} \
        --screen-log out/emu-{{board}}-screens.txt --dump-ram out/emu-{{board}}-ram.bin
    python3 tools/emu/bootstatus.py out/emu-{{board}}-ram.bin
    # The emulator decodes its own framebuffer back to characters using the same
    # zevv-peep and misc-fixed faces CatCard renders with, so a run can be asserted on
    # strings rather than on a pixel hash. Optional: it lives in the sibling repo.
    decoder="$(dirname {{emulator}})/../../tools/screentext.py"
    if [ -f "$decoder" ]; then
        echo "--- decoded screen ---"
        python3 "$decoder" out/emu-{{board}}-screens.txt | tail -12
    fi

# Board table, including which facts are still unknown.
boards:
    cargo run -q -p catcard-image -- boards

# Regenerate the HMAC-DRBG cross-check vectors from the independent reference.
drbg-vectors:
    python3 tools/reference/drbg_ref.py

clean:
    cargo clean
    rm -rf out
