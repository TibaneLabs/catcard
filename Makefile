# CatCard firmware images.
#
# A plain-make front end for the build, for machines without the `just` task runner
# (the justfile stays the fuller CI/emulator surface). Each board has exactly one image
# name in out/ -- no per-attempt or per-variant filenames.
#
#   make                 # dev images for every board
#   make mk4-mk5         # just the mk4/mk5 image  -> out/catcard-mk4-mk5.{bin,dfu}
#   make mk4-mk5 SHIP=1  # same file, stripped of the debug crutches for a real release
#   make test lint       # host tests / firmware clippy
#   make clean
#
# mk5 is electrically an mk4 (an added strap and its own hw_compat bit), so a single
# build serves both and its header claims both boards.
#
# The USB bench crutches (host key injection + the peek/poke/jsr memory monitor) are
# default features, so a dev build carries them -- that is how the device is driven and
# inspected during this development period. SHIP=1 passes --no-default-features to strip
# them for a real, signed release; never ship a build without it (usb-debug-mem exposes
# the seed/PIN and arbitrary code execution). See docs/USB.md.
#
# The image tool stamps the workspace version into the header by default; pass
# VERSION=x.y.z to override.

# A `cargo` earlier in PATH than rustup's (Homebrew's, a distro's) ships no
# thumbv7em-none-eabihf std, and the failure reads "the target may not be installed" --
# which sends you to `rustup target add`, where the target is already installed. Ask
# rustup which toolchain rust-toolchain.toml pins instead of trusting PATH.
#
# Prepending the directory is what fixes it, not just calling the absolute path:
# rustup's cargo invoked by absolute path still resolves *rustc* from PATH, so the
# wrong rustc would be picked up anyway.
CARGO_PATH := $(shell rustup which cargo 2>/dev/null)
ifneq ($(CARGO_PATH),)
  export PATH := $(dir $(CARGO_PATH)):$(PATH)
  CARGO := $(CARGO_PATH)
else
  CARGO := cargo
endif

ELF     := target/thumbv7em-none-eabihf/release/catcard-fw
OUT     := out
PACKAGE := $(CARGO) run --release -q -p catcard-image -- build $(ELF)
FW      := $(CARGO) build --release -p catcard-fw --target thumbv7em-none-eabihf

VERSION ?=
VER      = $(if $(VERSION),--version $(VERSION),)
SHIP    ?=
NODEF    = $(if $(SHIP),--no-default-features,)

# The firmware ELF has one path, so a build must be packaged before the next overwrites it.
.NOTPARALLEL:
.PHONY: all mk3 mk4-mk5 q1 test lint clean

all: mk3 mk4-mk5 q1

mk3:
	$(FW) $(NODEF) --features board-mk3
	@mkdir -p $(OUT)
	$(PACKAGE) --board mk3 $(VER) --bin $(OUT)/catcard-mk3.bin --dfu $(OUT)/catcard-mk3.dfu

mk4-mk5:
	$(FW) $(NODEF) --features board-mk5
	@mkdir -p $(OUT)
	$(PACKAGE) --board mk5 $(VER) --hw-compat mk4,mk5 \
	  --bin $(OUT)/catcard-mk4-mk5.bin --dfu $(OUT)/catcard-mk4-mk5.dfu

q1:
	$(FW) $(NODEF) --features board-q1
	@mkdir -p $(OUT)
	$(PACKAGE) --board q1 $(VER) --bin $(OUT)/catcard-q1.bin --dfu $(OUT)/catcard-q1.dfu

# `catcard-kernel` is excluded for the same reason as `catcard-fw`: it is ARM-only --
# the context switch is Cortex-M assembly and cortex-m's register access does not exist
# on the host.
test:
	$(CARGO) test --workspace --exclude catcard-fw --exclude catcard-kernel

# What CI runs, so a green tree here means a green tree there.
#
# `-D warnings` is the part that matters: without it clippy's findings are warnings
# locally and errors in CI, which is how this tree stayed red through a day of pushes
# that all looked clean from here. The workspace clippy and the format check are the
# other two gates CI applies and this did not.
export RUSTFLAGS := -D warnings

lint:
	$(CARGO) fmt --all -- --check
	$(CARGO) clippy --workspace --exclude catcard-fw --exclude catcard-kernel --all-targets
	$(CARGO) clippy -p catcard-wallet --all-targets --no-default-features --features std
	$(CARGO) clippy -p catcard-wallet --all-targets --no-default-features --features std,multichain
	$(CARGO) clippy -p catcard-fw --target thumbv7em-none-eabihf --features board-mk5
	$(CARGO) clippy -p catcard-fw --target thumbv7em-none-eabihf --no-default-features --features board-mk5
	$(CARGO) clippy -p catcard-fw --target thumbv7em-none-eabihf --no-default-features --features board-q1,multichain

clean:
	rm -f $(OUT)/catcard-*.bin $(OUT)/catcard-*.dfu
