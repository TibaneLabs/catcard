#!/usr/bin/env python3
"""Run a CatCard image from SRAM on a Precursor, over the stock USB debug bridge.

    sudo python3 -I run.py IMAGE.bin [--entry 0x40000000] [--seconds 10] [--uart /dev/ttyAMA0]

Runs on the machine the Precursor is plugged into (the Raspberry Pi with the debug
hat, so the UART can be read too). Nothing is written to flash: the CPU is reset
and held, the image is written into external SRAM, the CPU is pointed at it and let
go. Pulsing PROG_B, or the watchdog, puts the stock firmware back.

Why not GDB: Xous arms the gateware watchdog, which cannot be disarmed and resets
the SoC 2.5-7.5 s after its last feed. A halted CPU cannot feed it, so this tool
feeds it from the host between every USB transfer while the CPU is held.

Bridge: vendor control transfers on endpoint 0, bmRequestType 0x43 (write) / 0xC3
(read), wValue/wIndex = address low/high halves, up to 4096 bytes each.
Source: betrusted-scripts usb_update.py peek/poke/burst_read [C].

Debug port (VexRiscv DebugPlugin, `vexriscv_debug` region at 0xEFFF0000 in csr.csv):
  +0 write: bit16 reset set, bit24 reset clear, bit17 halt set, bit25 halt clear
  +0 read : bit0 in reset, bit1 halted, bit2 pipeline busy
  +4 write: instruction to execute while halted
Halt set/clear values are the ones usb_update.py uses [C]; the rest is from the
DebugPlugin source [I], and this tool checks the halted bit before relying on it.
"""
import argparse
import array
import os
import select
import subprocess
import sys
import time

import usb.core

VID, PID = 0x1209, 0x5BF0
DEBUG = 0xEFFF0000          # csr.csv memory_region vexriscv_debug [C]
WDT_WATCHDOG = 0xF0022000   # csr.csv wdt_watchdog; writing 1 = reset_wdt [C]
SRAM, SRAM_LEN = 0x40000000, 16 << 20

RESET_SET, RESET_CLEAR = 1 << 16, 1 << 24
HALT_SET, HALT_CLEAR = 1 << 17, 1 << 25
ST_RESET, ST_HALTED, ST_BUSY = 1 << 0, 1 << 1, 1 << 2


class Bridge:
    def __init__(self):
        self.dev = usb.core.find(idVendor=VID, idProduct=PID)
        if self.dev is None:
            sys.exit("Precursor not found on USB (is the stock gateware running?)")
        self.dev.set_configuration()

    def read(self, addr, n):
        buf = array.array("B", bytes(n))
        got = self.dev.ctrl_transfer(0xC3, 0, addr & 0xFFFF, addr >> 16, buf, timeout=1000)
        if got != n:
            raise IOError(f"short read at {addr:#010x}: {got}/{n}")
        return buf.tobytes()

    def write(self, addr, data):
        got = self.dev.ctrl_transfer(0x43, 0, addr & 0xFFFF, addr >> 16, array.array("B", data), timeout=1000)
        if got != len(data):
            raise IOError(f"short write at {addr:#010x}: {got}/{len(data)}")

    def peek(self, addr):
        return int.from_bytes(self.read(addr, 4), "little")

    def poke(self, addr, value):
        self.write(addr, value.to_bytes(4, "little"))

    def feed(self):
        self.poke(WDT_WATCHDOG, 1)


def lui(rd, imm):
    return ((imm >> 12) & 0xFFFFF) << 12 | rd << 7 | 0x37


def addi(rd, rs1, imm):
    return (imm & 0xFFF) << 20 | rs1 << 15 | rd << 7 | 0x13


def inject(br, insn):
    for _ in range(100):
        if not br.peek(DEBUG) & ST_BUSY:
            break
        br.feed()
    else:
        sys.exit("debug port: pipeline stayed busy, giving up")
    br.poke(DEBUG + 4, insn)


def uart_open(path):
    subprocess.run(["stty", "-F", path, "115200", "raw", "-echo", "cs8", "-cstopb", "-parenb"], check=True)
    return os.open(path, os.O_RDONLY | os.O_NONBLOCK)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image", help="flat binary (llvm-objcopy -O binary)")
    ap.add_argument("--entry", type=lambda s: int(s, 0), default=SRAM)
    ap.add_argument("--load", type=lambda s: int(s, 0), default=SRAM)
    ap.add_argument("--seconds", type=float, default=10.0, help="how long to print the UART afterwards")
    ap.add_argument("--uart", default="/dev/ttyAMA0")
    a = ap.parse_args()

    img = open(a.image, "rb").read()
    if not (SRAM <= a.load and a.load + len(img) <= SRAM + SRAM_LEN):
        sys.exit("image does not fit in SRAM at that address")
    if len(img) % 4:
        img += bytes(4 - len(img) % 4)

    br = Bridge()
    uart = uart_open(a.uart) if a.uart else None

    br.feed()
    br.poke(DEBUG, RESET_SET | HALT_SET)
    br.poke(DEBUG, RESET_CLEAR)
    st = br.peek(DEBUG)
    if not st & ST_HALTED or st & ST_RESET:
        br.poke(DEBUG, HALT_CLEAR)
        sys.exit(f"CPU did not end up halted out of reset (status {st:#x}); released it, nothing written")
    print(f"CPU reset and halted (status {st:#x})")

    t0 = time.time()
    for off in range(0, len(img), 4096):
        br.write(a.load + off, img[off:off + 4096])
        br.feed()
    for off in range(0, len(img), 4096):
        chunk = img[off:off + 4096]
        if br.read(a.load + off, len(chunk)) != chunk:
            br.poke(DEBUG, HALT_CLEAR)
            sys.exit(f"readback mismatch at {a.load + off:#010x}")
        br.feed()
    print(f"wrote and verified {len(img)} bytes at {a.load:#010x} in {time.time() - t0:.2f}s")

    if uart is not None:
        while os.read(uart, 4096) if select.select([uart], [], [], 0)[0] else b"":
            pass   # drop whatever Xous printed before the reset

    inject(br, 0x0000100F)                      # fence.i: the I-cache must not hold Xous code
    inject(br, lui(1, a.entry + 0x800))         # x1 = entry (lui/addi pair, addi sign-extends)
    inject(br, addi(1, 1, a.entry & 0xFFF))
    inject(br, 0x00008067 | 1 << 15)            # jalr x0, 0(x1)
    br.feed()
    br.poke(DEBUG, HALT_CLEAR)
    print(f"released at {a.entry:#010x}")

    if uart is None:
        return
    end = time.time() + a.seconds
    while time.time() < end:
        r, _, _ = select.select([uart], [], [], 0.2)
        if r:
            sys.stdout.write(os.read(uart, 4096).decode("utf-8", "replace"))
            sys.stdout.flush()


if __name__ == "__main__":
    main()
