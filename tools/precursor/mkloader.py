#!/usr/bin/env python3
"""Package a CatCard SRAM image as a Precursor loader-slot image, signed.

    python3 -I mkloader.py IMAGE.bin KEY.pem OUT.bin

IMAGE.bin is the flat SRAM image (`llvm-objcopy -O binary`), linked at 0x40000000 and
entered at its first byte -- the same file tools/precursor/run.py loads. OUT.bin goes at
flash offset 0x500000 (the Xous loader's slot); KEY.pem is an Ed25519 private key the
device's boot ROM accepts. A unit that boots on the published developer key
(betrusted-soc devkey/dev.key) takes an image signed with that.

Layout, as the gateware boot ROM reads it:
  flash 0x2050_0000  SignatureInFlash { version: u32 = 1, signed_len: u32, signature[64] }
  flash 0x2050_1000  signed region, `signed_len` bytes, which must end with
                     version (u32 LE, = 1) and signed_len - 4 (u32 LE)
The boot ROM verifies Ed25519(signature) over the whole signed region and jumps to
0x2050_1000 in machine mode.
Source: betrusted-soc boot/betrusted-boot/src/main.rs (LOADER_SIG_OFFSET,
LOADER_DATA_OFFSET, SignatureInFlash, the protected_version / protected_len checks,
start_loader) [C].

The signed region is a 64-byte stub followed by IMAGE.bin. The stub copies IMAGE.bin from
flash into SRAM at 0x40000000, executes `fence.i`, and jumps there -- so the image that
boots from flash is byte for byte the one run.py runs from RAM.
"""
import struct
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SIG_PAGE = 0x1000
DATA_ADDR = 0x2050_1000
STUB_LEN = 64
SRAM = 0x4000_0000

# RV32I encodings.
def lui(rd, imm):
    return ((imm >> 12) & 0xFFFFF) << 12 | rd << 7 | 0x37

def addi(rd, rs1, imm):
    return (imm & 0xFFF) << 20 | rs1 << 15 | rd << 7 | 0x13

def li(rd, value):  # lui + addi, compensating for addi's sign extension
    return [lui(rd, value + 0x800), addi(rd, rd, value & 0xFFF)]

def add(rd, rs1, rs2):
    return rs2 << 20 | rs1 << 15 | rd << 7 | 0x33

def lw(rd, rs1, imm):
    return (imm & 0xFFF) << 20 | rs1 << 15 | 0b010 << 12 | rd << 7 | 0x03

def sw(rs2, rs1, imm):
    return ((imm >> 5) & 0x7F) << 25 | rs2 << 20 | rs1 << 15 | 0b010 << 12 | (imm & 0x1F) << 7 | 0x23

def bltu(rs1, rs2, off):
    o = off & 0x1FFF
    return (((o >> 12) & 1) << 31 | ((o >> 5) & 0x3F) << 25 | rs2 << 20 | rs1 << 15
            | 0b110 << 12 | ((o >> 1) & 0xF) << 8 | ((o >> 11) & 1) << 7 | 0x63)

FENCE_I = 0x0000100F
T0, T1, T2, T3 = 5, 6, 7, 28


def stub(payload_len):
    words = []
    words += li(T0, DATA_ADDR + STUB_LEN)     # source: the image, in flash
    words += li(T1, SRAM)                     # destination
    words += li(T2, payload_len)
    words += [add(T2, T1, T2)]                # end of destination
    loop = len(words)
    words += [lw(T3, T0, 0), sw(T3, T1, 0), addi(T0, T0, 4), addi(T1, T1, 4)]
    words += [bltu(T1, T2, (loop - len(words)) * 4)]
    words += [FENCE_I]
    words += li(T0, SRAM)
    words += [0x00028067]                     # jalr x0, 0(t0)
    code = b"".join(struct.pack("<I", w) for w in words)
    assert len(code) <= STUB_LEN, len(code)
    return code + b"\x00" * (STUB_LEN - len(code))


def main():
    image_path, key_path, out_path = sys.argv[1:4]
    image = open(image_path, "rb").read()
    image += b"\x00" * (-len(image) % 4)
    key = serialization.load_pem_private_key(open(key_path, "rb").read(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        sys.exit("KEY.pem is not an Ed25519 private key")

    body = stub(len(image)) + image
    signed_len = len(body) + 8
    region = body + struct.pack("<II", 1, signed_len - 4)
    signature = key.sign(region)
    header = struct.pack("<II", 1, signed_len) + signature
    out = header + b"\xff" * (SIG_PAGE - len(header)) + region
    open(out_path, "wb").write(out)

    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    print(f"{out_path}: {len(out)} bytes, signed_len {signed_len}, payload {len(image)} bytes")
    print(f"signed with Ed25519 key {pub.hex()}")


if __name__ == "__main__":
    main()
