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

# Board table, including which facts are still unknown.
boards:
    cargo run -q -p catcard-image -- boards

# Regenerate the HMAC-DRBG cross-check vectors from the independent reference.
drbg-vectors:
    python3 tools/reference/drbg_ref.py

clean:
    cargo clean
    rm -rf out
