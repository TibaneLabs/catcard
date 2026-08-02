#!/usr/bin/env python3
"""Independent HMAC-DRBG (SHA-256) written straight from NIST SP 800-90A 10.1.2.

Used to cross-check the Rust implementation in catcard-entropy. Deliberately written
without looking at the Rust code's structure.
"""
import hmac as _hmac
import hashlib


def H(key, *parts):
    m = _hmac.new(key, digestmod=hashlib.sha256)
    for p in parts:
        m.update(p)
    return m.digest()


class Drbg:
    def __init__(self, entropy, nonce=b"", perso=b""):
        self.K = b"\x00" * 32
        self.V = b"\x01" * 32
        self.reseed_counter = 1
        self._update(entropy + nonce + perso)

    # 10.1.2.2
    def _update(self, provided=b""):
        self.K = H(self.K, self.V, b"\x00", provided)
        self.V = H(self.K, self.V)
        if provided:
            self.K = H(self.K, self.V, b"\x01", provided)
            self.V = H(self.K, self.V)

    # 10.1.2.4
    def reseed(self, entropy, additional=b""):
        self._update(entropy + additional)
        self.reseed_counter = 1

    # 10.1.2.5
    def generate(self, nbytes, additional=b""):
        if additional:
            self._update(additional)
        out = b""
        while len(out) < nbytes:
            self.V = H(self.K, self.V)
            out += self.V
        self._update(additional)
        self.reseed_counter += 1
        return out[:nbytes]


if __name__ == "__main__":
    # Vector 1: the one pinned in the Rust test.
    d = Drbg(b"\x00" * 32, b"", b"")
    print("v1_zero_seed        ", d.generate(32).hex())

    # Vector 2: the test-fixture DRBG used across the Rust unit tests.
    d = Drbg(b"\x42" * 32, b"\x01" * 16, b"catcard/test")
    print("v2_fixture_first32  ", d.generate(32).hex())
    d = Drbg(b"\x42" * 32, b"\x01" * 16, b"catcard/test")
    print("v2_fixture_first128 ", d.generate(128).hex())

    # Vector 3: unaligned length, exercising the partial-block path.
    d = Drbg(b"\x42" * 32, b"\x01" * 16, b"catcard/test")
    print("v3_len33            ", d.generate(33).hex())

    # Vector 4: after a reseed.
    d = Drbg(b"\x42" * 32, b"\x01" * 16, b"catcard/test")
    d.reseed(b"\x99" * 32)
    print("v4_after_reseed     ", d.generate(32).hex())
