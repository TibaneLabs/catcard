"""Host side of the CatCard encrypted USB channel (`catcard_usb::ncry`), v2: a channel
paired by a six-digit code a person compares on the host and on the device.

Pure standard-library crypto, so the tool stays self-contained: X25519 (RFC 7748),
HKDF-SHA256 (RFC 5869) and ChaCha20-Poly1305 (RFC 8439). None of it is constant time,
which does not matter on the host — the secret is a throwaway session key, and the device
is the side whose timing an attacker cares about.

The wire format mirrors the firmware exactly; `--selftest` checks that against a vector
baked into the Rust unit tests, so a divergence is caught here rather than on hardware.
"""

import hashlib
import hmac
import os
import struct
import sys

P = 2**255 - 19

# Domain separation; each must match its namesake in the Rust `ncry` module.
INFO = b"catcard-ncry-v2"
COMMIT_LABEL = b"catcard-pair-v2/commit"
CODE_INFO = b"catcard-pair-v2/code"
CODE_MODULUS = 10**6
KEY_LEN = 32
TAG_LEN = 16


# --- X25519 (RFC 7748 §5) ------------------------------------------------------------

def _decode_scalar(k):
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(k, "little")


def x25519(scalar, u):
    """scalar * u on Curve25519; both 32-byte little-endian, result 32-byte."""
    k = _decode_scalar(scalar)
    x1 = int.from_bytes(bytes(u[:31]) + bytes([u[31] & 127]), "little") % P
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in reversed(range(255)):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % P
        aa = a * a % P
        b = (x2 - z2) % P
        bb = b * b % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = d * a % P
        cb = c * b % P
        x3 = (da + cb) % P
        x3 = x3 * x3 % P
        z3 = (da - cb) % P
        z3 = x1 * (z3 * z3 % P) % P
        x2 = aa * bb % P
        z2 = e * ((aa + 121665 * e) % P) % P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    res = x2 * pow(z2, P - 2, P) % P
    return res.to_bytes(32, "little")


BASE_POINT = bytes([9] + [0] * 31)


def public_key(scalar):
    return x25519(scalar, BASE_POINT)


# --- HKDF-SHA256 (RFC 5869) ----------------------------------------------------------

def hkdf(salt, ikm, info, length):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    t = b""
    i = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


# --- ChaCha20-Poly1305 (RFC 8439) ----------------------------------------------------

def _rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _quarter(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl(s[b] ^ s[c], 7)


def _chacha_block(key, counter, nonce):
    consts = struct.unpack("<4I", b"expand 32-byte k")
    state = list(consts) + list(struct.unpack("<8I", key)) + [counter] + list(struct.unpack("<3I", nonce))
    work = state[:]
    for _ in range(10):
        _quarter(work, 0, 4, 8, 12)
        _quarter(work, 1, 5, 9, 13)
        _quarter(work, 2, 6, 10, 14)
        _quarter(work, 3, 7, 11, 15)
        _quarter(work, 0, 5, 10, 15)
        _quarter(work, 1, 6, 11, 12)
        _quarter(work, 2, 7, 8, 13)
        _quarter(work, 3, 4, 9, 14)
    out = [(work[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
    return struct.pack("<16I", *out)


def _chacha20(key, counter, nonce, data):
    out = bytearray(len(data))
    for i in range(0, len(data), 64):
        block = _chacha_block(key, counter + i // 64, nonce)
        chunk = data[i:i + 64]
        for j in range(len(chunk)):
            out[i + j] = chunk[j] ^ block[j]
    return bytes(out)


def _poly1305(key, msg):
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:32], "little")
    acc = 0
    prime = (1 << 130) - 5
    for i in range(0, len(msg), 16):
        block = msg[i:i + 16]
        n = int.from_bytes(block + b"\x01", "little")
        acc = (acc + n) * r % prime
    acc = (acc + s) & ((1 << 128) - 1)
    return acc.to_bytes(16, "little")


def _pad16(n):
    return b"\x00" * ((16 - n % 16) % 16)


def chacha20poly1305_encrypt(key, nonce, aad, plaintext):
    otk = _chacha_block(key, 0, nonce)[:32]
    ct = _chacha20(key, 1, nonce, plaintext)
    mac_data = aad + _pad16(len(aad)) + ct + _pad16(len(ct))
    mac_data += struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ct))
    return ct, _poly1305(otk, mac_data)


def chacha20poly1305_decrypt(key, nonce, aad, ct, tag):
    otk = _chacha_block(key, 0, nonce)[:32]
    mac_data = aad + _pad16(len(aad)) + ct + _pad16(len(ct))
    mac_data += struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ct))
    if not hmac.compare_digest(_poly1305(otk, mac_data), tag):
        raise ValueError("ncry: bad tag")
    return _chacha20(key, 1, nonce, ct)


# --- session -------------------------------------------------------------------------

def _nonce(counter):
    return struct.pack("<Q", counter) + b"\x00\x00\x00\x00"


def commitment(host_pub):
    """`SHA-256(COMMIT_LABEL || host_pub)`: the `PairCommit` payload."""
    return hashlib.sha256(COMMIT_LABEL + host_pub).digest()


def code_text(code):
    """Six digits, zero padded, grouped the way both screens show them: `123 456`."""
    s = f"{code:06d}"
    return f"{s[:3]} {s[3:]}"


def _schedule(dh, commit, device_pub, host_pub):
    """Keys and code from the shared secret. The transcript is in wire order:
    `commit || device_pub || host_pub`."""
    transcript = commit + device_pub + host_pub
    okm = hkdf(transcript, dh, INFO, 64)
    code = int.from_bytes(hkdf(transcript, dh, CODE_INFO, 8), "big") % CODE_MODULUS
    return okm[:32], okm[32:], code


class Session:
    """One end of an established channel, with the pairing code its handshake produced."""

    def __init__(self, send_key, recv_key, code=None):
        self.send_key = send_key
        self.recv_key = recv_key
        self.send_ctr = 0
        self.recv_ctr = 0
        self.code = code

    def seal(self, plaintext):
        ct, tag = chacha20poly1305_encrypt(self.send_key, _nonce(self.send_ctr), b"", plaintext)
        self.send_ctr += 1
        return ct + tag

    def open(self, record):
        if len(record) < TAG_LEN:
            raise ValueError("ncry: short record")
        ct, tag = record[:-TAG_LEN], record[-TAG_LEN:]
        pt = chacha20poly1305_decrypt(self.recv_key, _nonce(self.recv_ctr), b"", ct, tag)
        self.recv_ctr += 1
        return pt


class Initiator:
    """The host's half of the handshake: commit first, reveal after the device answers."""

    def __init__(self, eph_priv=None):
        self.priv = eph_priv if eph_priv is not None else os.urandom(KEY_LEN)
        self.public = public_key(self.priv)
        self.commit = commitment(self.public)

    def finish(self, device_pub):
        """Derive the host `Session` (and its `.code`) from the device's public key."""
        dh = x25519(self.priv, device_pub)
        if dh == bytes(32):
            raise ValueError("ncry: small-order peer")
        i2r, r2i, code = _schedule(dh, self.commit, device_pub, self.public)
        # Host sends on initiator->responder, receives on responder->initiator.
        return Session(i2r, r2i, code)


def responder(eph_priv, commit, host_pub):
    """The device's half, for the selftest: check the reveal, derive the session."""
    if commitment(host_pub) != commit:
        raise ValueError("ncry: reveal does not match the commitment")
    device_pub = public_key(eph_priv)
    dh = x25519(eph_priv, host_pub)
    if dh == bytes(32):
        raise ValueError("ncry: small-order peer")
    i2r, r2i, code = _schedule(dh, commit, device_pub, host_pub)
    # Device sends on responder->initiator, receives on initiator->responder.
    return device_pub, Session(r2i, i2r, code)


# The v2 vector, shared with the Rust `ncry::tests` (`HOST_PRIV`/`DEV_PRIV`, `KAT_COMMIT`,
# `KAT_CODE`, `KAT_RECORD`): same scalars, same bytes, or the two sides have diverged.
KAT_HOST_PRIV = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
KAT_DEV_PRIV = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
KAT_COMMIT = bytes([
    65, 181, 194, 108, 161, 34, 111, 179, 156, 98, 166, 84, 21, 115, 147, 169, 108, 1,
    121, 169, 26, 246, 122, 111, 98, 247, 189, 154, 215, 47, 20, 74,
])
KAT_CODE = 398660
KAT_RECORD = bytes([
    128, 168, 83, 37, 40, 20, 198, 221, 119, 225, 110, 89, 217, 140, 246, 68, 129, 191,
    40, 248, 83, 179, 22,
])


def selftest(show=False):
    host = Initiator(KAT_HOST_PRIV)
    dev_pub, dev = responder(KAT_DEV_PRIV, host.commit, host.public)
    sess = host.finish(dev_pub)
    # Counter-0 seal of b"catcard" host->device.
    record = sess.seal(b"catcard")
    if show:
        print("commit", list(host.commit))
        print("code  ", sess.code)
        print("record", list(record))
        return
    assert host.commit == KAT_COMMIT, f"commit mismatch: {list(host.commit)}"
    assert sess.code == dev.code == KAT_CODE, f"code mismatch: {sess.code} / {dev.code}"
    assert record == KAT_RECORD, f"KAT mismatch:\n got {list(record)}\n want {list(KAT_RECORD)}"

    # The device opens it and can reply.
    assert dev.open(record) == b"catcard"
    assert sess.open(dev.seal(b"pong")) == b"pong"

    # A reveal that misses the commitment is refused.
    try:
        responder(KAT_DEV_PRIV, host.commit, public_key(bytes([0x42] * 32)))
        raise AssertionError("a reveal that misses the commitment was accepted")
    except ValueError:
        pass

    # A relay -- one handshake facing each side, with the Rust test's relay scalars --
    # shows the two people different codes.
    relay_to_host = bytes([0x24] * 32)
    relay_to_dev = Initiator(bytes([0x42] * 32))
    host_side = Initiator(KAT_HOST_PRIV).finish(public_key(relay_to_host))
    _, dev_side = responder(KAT_DEV_PRIV, relay_to_dev.commit, relay_to_dev.public)
    assert host_side.code != dev_side.code

    assert code_text(7) == "000 007" and code_text(123456) == "123 456"
    print(f"ncry selftest: OK (v2 KAT matches the firmware, code {code_text(KAT_CODE)})")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest(show="--show" in sys.argv)
    else:
        print("usage: ncry.py --selftest", file=sys.stderr)
        sys.exit(2)
