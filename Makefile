# CatCard firmware images.
#
# A plain-make front end for the build, for machines without the `just` task runner
# (the justfile stays the fuller CI/emulator surface). Each board has exactly one image
# name in out/ -- no per-attempt or per-variant filenames.
#
#   make                 # release images for every board
#   make mk4-mk5         # just the mk4/mk5 image  -> out/catcard-mk4-mk5.{bin,dfu}
#   make mk4-mk5 BRINGUP=1   # same file, built with the on-bench debug crutches
#   make test lint       # host tests / firmware clippy
#   make clean
#
# mk5 is electrically an mk4 (an added strap and its own hw_compat bit), so a single
# build serves both and its header claims both boards -- the image Coinkite ship.
#
# BRINGUP=1 folds in usb-key-injection + usb-debug-mem (host can press keys and read/write
# any memory). Never ship it -- it writes the *same* filename, so a debug build does not
# linger under a different name; rebuild without BRINGUP to get a clean image back.
#
# The image tool stamps the workspace version into the header by default; pass
# VERSION=x.y.z to override (rather than hardcoding one here, which is how the justfile's
# has drifted).

ELF     := target/thumbv7em-none-eabihf/release/catcard-fw
OUT     := out
PACKAGE := cargo run --release -q -p catcard-image -- build $(ELF)
FW      := cargo build --release -p catcard-fw --target thumbv7em-none-eabihf --no-default-features

comma   := ,
VERSION ?=
VER      = $(if $(VERSION),--version $(VERSION),)
BRINGUP ?=
DBG      = $(if $(BRINGUP),$(comma)usb-key-injection$(comma)usb-debug-mem,)

# The firmware ELF has one path, so a build must be packaged before the next overwrites it.
.NOTPARALLEL:
.PHONY: all mk3 mk4-mk5 q1 test lint clean

all: mk3 mk4-mk5 q1

mk3:
	$(FW) --features board-mk3$(DBG)
	@mkdir -p $(OUT)
	$(PACKAGE) --board mk3 $(VER) --bin $(OUT)/catcard-mk3.bin --dfu $(OUT)/catcard-mk3.dfu

mk4-mk5:
	$(FW) --features board-mk5$(DBG)
	@mkdir -p $(OUT)
	$(PACKAGE) --board mk5 $(VER) --hw-compat mk4,mk5 \
	  --bin $(OUT)/catcard-mk4-mk5.bin --dfu $(OUT)/catcard-mk4-mk5.dfu

q1:
	$(FW) --features board-q1$(DBG)
	@mkdir -p $(OUT)
	$(PACKAGE) --board q1 $(VER) --bin $(OUT)/catcard-q1.bin --dfu $(OUT)/catcard-q1.dfu

test:
	cargo test --workspace --exclude catcard-fw

lint:
	cargo clippy -p catcard-fw --target thumbv7em-none-eabihf --no-default-features --features board-mk5
	cargo clippy -p catcard-fw --target thumbv7em-none-eabihf --no-default-features --features board-mk5,usb-key-injection,usb-debug-mem

clean:
	rm -f $(OUT)/catcard-*.bin $(OUT)/catcard-*.dfu
