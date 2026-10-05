# CatCard firmware images.
#
# A plain-make front end for the build, for machines without the `just` task runner
# (the justfile stays the fuller CI/emulator surface). Each board has exactly one image
# name in out/ -- no per-attempt or per-variant filenames.
#
#   make                 # dev images for every board
#   make mk4-mk5         # just the mk4/mk5 image  -> out/catcard-mk4-mk5.{bin,dfu}
#   make mk4-mk5 SHIP=1  # same file, stripped of the debug crutches for a real release
#   make q1              # every chain the registry knows (the default)
#   make q1 BITCOIN=1    # Bitcoin alone: no other chain's parser in the image
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
# The firmware reports the same string the header carries (`crate::VERSION`), so an
# override reaches the compiler too, not only the image tool.
ifneq ($(VERSION),)
  export CATCARD_VERSION := $(VERSION)
endif
SHIP    ?=
NODEF    = $(if $(SHIP),--no-default-features,)
# Every chain by default, because a bench build is for using the device and the device
# is meant to hold more than Bitcoin. The Bitcoin-only image is the one that has to be
# asked for -- `make q1 BITCOIN=1` -- and CI builds both shapes from its own matrix
# rather than from these defaults, so neither can quietly stop being built.
BITCOIN ?=
MULTICHAIN ?= $(if $(BITCOIN),,1)
comma   := ,
CHAINS   = $(if $(MULTICHAIN),$(comma)multichain,)

# The firmware ELF has one path, so a build must be packaged before the next overwrites it.
.NOTPARALLEL:
.PHONY: q1-rescue all mk3 mk4-mk5 q1 test lint clean apps

all: mk3 mk4-mk5 q1

mk3:
	$(FW) $(NODEF) --features board-mk3$(CHAINS)
	@mkdir -p $(OUT)
	$(PACKAGE) --board mk3 $(VER) --bin $(OUT)/catcard-mk3.bin --dfu $(OUT)/catcard-mk3.dfu

mk4-mk5: $(if $(SHIP),,apps)
	$(FW) $(NODEF) --features board-mk5$(CHAINS)
	@mkdir -p $(OUT)
	$(PACKAGE) --board mk5 $(VER) --hw-compat mk4,mk5 $(MONO_APPS) \
	  --bin $(OUT)/catcard-mk4-mk5.bin --dfu $(OUT)/catcard-mk4-mk5.dfu

# Apps (docs/APPS.md): thumb-only binaries in their own workspace under apps/, linked to
# run in the app area. Bench use for now: tools/usbclient.py hid --run-app <elf> [arg].
# The exported RUSTFLAGS below would make cargo ignore apps/.cargo/config.toml's rustflags,
# so the layout is passed here as well.
#
# Built twice: every app for the mono boards' 128x64 screen, then the games again for the
# Q1's (an app that draws through `catcard_app::screen` is built for one panel). Flappy
# drives the Q1 panel through its own services, so the one build serves.
APPS_RUSTFLAGS = $(RUSTFLAGS) -C link-arg=-Tlink.x
apps:
	cd apps && RUSTFLAGS="$(APPS_RUSTFLAGS)" $(CARGO) build --release
	cd apps && RUSTFLAGS="$(APPS_RUSTFLAGS)" $(CARGO) build --release -p app-games \
	  --features board-q1 --target-dir target/q1

# Apps the Q1 image carries (docs/APPS.md). Flappy Cat is a game, and games are a default
# feature that SHIP drops, so it goes in exactly when the firmware's games menu does.
APPS_DIR    := apps/target/thumbv7em-none-eabihf/release
APPS_DIR_Q1 := apps/target/q1/thumbv7em-none-eabihf/release
Q1_APPS      = $(if $(SHIP),,--app flappy=$(APPS_DIR)/app-flappy --app games=$(APPS_DIR_Q1)/app-games)
MONO_APPS    = $(if $(SHIP),,--app games=$(APPS_DIR)/app-games)

# The Q1 firmware is built for size (`opt-level = "z"`, about 200 KB smaller): its games are
# apps now, compiled on their own, so nothing slow is left in the firmware's hot paths --
# the per-pixel drawing is `#[inline(always)]`. Q1 only until the other boards have each
# booted a "z" build: it changes the code on their boot path too.
q1: $(if $(SHIP),,apps)
	CARGO_PROFILE_RELEASE_OPT_LEVEL=z $(FW) $(NODEF) --features board-q1$(CHAINS)
	@mkdir -p $(OUT)
	$(PACKAGE) --board q1 $(VER) $(Q1_APPS) --bin $(OUT)/catcard-q1.bin --dfu $(OUT)/catcard-q1.dfu

# The Q1 rescue image: boot straight into the headless USB reflash, nothing else (~110 KB),
# for a device whose own staging gives out before a full image is in. docs/RESCUE.md.
# Its own target dir, so it never leaves a rescue ELF where `q1` packages from.
RESCUE_ELF := target/rescue/thumbv7em-none-eabihf/release/catcard-fw
q1-rescue:
	CATCARD_VERSION=7.0.0r CARGO_PROFILE_RELEASE_OPT_LEVEL=z $(CARGO) build --release -p catcard-fw \
	  --target thumbv7em-none-eabihf --target-dir target/rescue --no-default-features \
	  --features board-q1,rescue
	@mkdir -p $(OUT)
	$(CARGO) run --release -q -p catcard-image -- build $(RESCUE_ELF) --board q1 --version 7.0.0r \
	  --bin $(OUT)/catcard-q1-rescue.bin --dfu $(OUT)/catcard-q1-rescue.dfu

# `catcard-kernel` is excluded for the same reason as `catcard-fw`: it is ARM-only --
# the context switch is Cortex-M assembly and cortex-m's register access does not exist
# on the host.
test:
	$(CARGO) test --workspace --exclude catcard-fw --exclude catcard-kernel
	python3 tools/test_trng_assess.py
	python3 tools/test_rng_report.py

# What CI runs, so a green tree here means a green tree there.
#
# `-D warnings` is the part that matters: without it clippy's findings are warnings
# locally and errors in CI, which is how this tree stayed red through a day of pushes
# that all looked clean from here. The workspace clippy and the format check are the
# other two gates CI applies and this did not.
export RUSTFLAGS := -D warnings

lint:
	$(CARGO) fmt --all -- --check
# Drawing callgates only through crate::gatecall, and no waiting-screen guard dropped at
# once: tools/gatecall-lint.sh says why.
	sh tools/gatecall-lint.sh
# Seed material leaves the entropy pool only where docs/ENTROPY.md says it does:
# tools/pooldraw-lint.sh lists the files.
	sh tools/pooldraw-lint.sh
	$(CARGO) clippy --workspace --exclude catcard-fw --exclude catcard-kernel --all-targets
	$(CARGO) clippy -p catcard-wallet --all-targets --no-default-features --features std
	$(CARGO) clippy -p catcard-wallet --all-targets --no-default-features --features std,multichain
	$(CARGO) clippy -p catcard-fw --target thumbv7em-none-eabihf --features board-mk5
	$(CARGO) clippy -p catcard-fw --target thumbv7em-none-eabihf --no-default-features --features board-mk5
	$(CARGO) clippy -p catcard-fw --target thumbv7em-none-eabihf --no-default-features --features board-q1,multichain
# The mk3 compiles out whole modules the others have -- no PSRAM, no settings store -- so
# it is the shape that breaks when something new is wired in unconditionally. CI builds it
# either way; linting it here is what stops that being found a push later.
	$(CARGO) clippy -p catcard-fw --target thumbv7em-none-eabihf --no-default-features --features board-mk3

clean:
	rm -f $(OUT)/catcard-*.bin $(OUT)/catcard-*.dfu
