"""Host-wallet commands: ask a CatCard for addresses, or for a signature.

The host half of `catcard_usb::hostwallet`, written from `docs/USB.md` §"Host-wallet
commands" rather than shared with the firmware. Every command travels inside the encrypted
channel (`NcryMsg`); in the clear the device answers `UnknownOpcode`.

The shape is the upgrade offer's: the host asks, the device shows the question to the
person holding it, the person decides on the device, and the host polls `HostResult`
until there is an answer. Nothing here can answer for the person.

    usbclient.py hid --addresses
    usbclient.py hid --sign tx.psbt --chain btc --key m/84h/0h/0h/0/3 [--key ...] [--out F]
    usbclient.py --selftest          (includes the layout checks below; no device needed)
"""
import struct
import time

HOST_ADDRESSES = 0x0050
HOST_SIGN_BEGIN = 0x0051
HOST_SIGN_DATA = 0x0052
HOST_SIGN_COMMIT = 0x0053
HOST_RESULT = 0x0054
HOST_ABORT = 0x0055

# Capability bit, matching `catcard_usb::caps::HOST_WALLET`.
CAP_HOST_WALLET = 1 << 6

VERSION = 1
MAX_DEPTH = 8
MAX_KEYS = 32
PAGE_MAX = 448
# Sealed plaintext bound (1024) less the opcode and the offset.
DATA_MAX = 1024 - 2 - 4
HARDENED = 0x8000_0000

OK, NOT_NOW, BAD_REQUEST, DECLINED, REFUSED = 0, 2, 3, 4, 5

STAGE = {0: "nothing asked", 1: "upload open", 2: "waiting for the screen",
         3: "the person is deciding", 4: "busy with another session's request"}
BUSY = {1: "the device is locked: enter the PIN first",
        2: "another request or an upgrade is pending"}

KIND_ADDRESSES, KIND_BITCOIN, KIND_EVM, KIND_SOLANA = 1, 2, 3, 4
SHAPE = {1: "utxo", 2: "account"}
FORMAT = {1: "p2pkh", 2: "p2sh-p2wpkh", 3: "p2wpkh", 4: "p2tr", 5: "evm", 6: "tron",
          7: "solana"}
CHAIN_IDS = {"btc": 1, "eth": 2, "evm": 2, "sol": 3, "ltc": 4, "doge": 5, "bch": 6,
             "mona": 7, "xep": 8, "trx": 9, "nmc": 10}
CHAIN_NAMES = {1: "Bitcoin", 2: "Ethereum", 3: "Solana", 4: "Litecoin", 5: "Dogecoin",
               6: "Bitcoin Cash", 7: "Monacoin", 8: "Electra Protocol", 9: "Tron",
               10: "Namecoin"}


class Refused(Exception):
    pass


# ---- paths -----------------------------------------------------------------------------

def parse_path(text):
    """`m/84h/0h/0h/0/3` (or with `'`) into a list of u32 steps, hardened bit set."""
    parts = text.strip().split("/")
    if parts[0] in ("m", "M"):
        parts = parts[1:]
    steps = []
    for p in parts:
        hard = p.endswith(("h", "H", "'"))
        n = int(p[:-1] if hard else p)
        if n >= HARDENED:
            raise ValueError(f"path step {p} out of range")
        steps.append(n | HARDENED if hard else n)
    if not 1 <= len(steps) <= MAX_DEPTH:
        raise ValueError(f"path depth must be 1..{MAX_DEPTH}")
    return steps


def path_text(steps):
    return "m/" + "/".join(f"{s & ~HARDENED}h" if s & HARDENED else str(s) for s in steps)


def enc_path(steps):
    return bytes([len(steps)]) + b"".join(struct.pack("<I", s) for s in steps)


class Reader:
    def __init__(self, b):
        self.b, self.at = bytes(b), 0

    def take(self, n):
        if self.at + n > len(self.b):
            raise ValueError("truncated")
        s = self.b[self.at:self.at + n]
        self.at += n
        return s

    def u8(self):
        return self.take(1)[0]

    def u32(self):
        return struct.unpack("<I", self.take(4))[0]

    def path(self):
        d = self.u8()
        if not 1 <= d <= MAX_DEPTH:
            raise ValueError("bad path depth")
        return [self.u32() for _ in range(d)]

    def short(self):
        return self.take(self.u8())

    def done(self):
        if self.at != len(self.b):
            raise ValueError("trailing bytes")


# ---- layouts ---------------------------------------------------------------------------

def sign_blob(chain, keys, tx):
    """[u8 version][u8 chain][u8 n][n x path][u32 len][tx]."""
    if not 1 <= len(keys) <= MAX_KEYS:
        raise ValueError(f"1..{MAX_KEYS} keys")
    if not tx:
        raise ValueError("empty transaction")
    return (bytes([VERSION, chain, len(keys)]) + b"".join(enc_path(k) for k in keys)
            + struct.pack("<I", len(tx)) + tx)


def decode_addresses(r):
    rd = Reader(r)
    if rd.u8() != KIND_ADDRESSES or rd.u8() != VERSION:
        raise ValueError("not an address reply")
    fp = rd.take(4)
    account = rd.u32()
    n = rd.u8()
    entries = []
    for _ in range(n):
        shape = rd.u8()
        if shape not in SHAPE:
            raise ValueError("bad entry shape")
        e = {"shape": SHAPE[shape], "chain": rd.u8(), "format": rd.u8(),
             "account_path": rd.path(), "address_path": rd.path()}
        e["xpub"] = rd.short().decode() if shape == 1 else ""
        e["address"] = rd.short().decode()
        e["pubkey"] = rd.short().hex()
        entries.append(e)
    rd.done()
    return {"fingerprint": fp.hex(), "account": account, "entries": entries}


def decode_bitcoin(r):
    rd = Reader(r)
    if rd.u8() != KIND_BITCOIN:
        raise ValueError("not a Bitcoin result")
    version = rd.u8()
    psbt = rd.take(rd.u32())
    tx = rd.take(rd.u32())
    rd.done()
    return version, psbt, tx


def decode_evm(r):
    rd = Reader(r)
    if rd.u8() != KIND_EVM:
        raise ValueError("not an EVM result")
    tx = rd.take(rd.u32())
    rd.done()
    return tx


def decode_solana(r):
    rd = Reader(r)
    if rd.u8() != KIND_SOLANA:
        raise ValueError("not a Solana result")
    sigs = [(rd.u8(), rd.take(64)) for _ in range(rd.u8())]
    tx = rd.take(rd.u32())
    rd.done()
    return sigs, tx


# ---- the flows -------------------------------------------------------------------------

def await_result(call, wait=900.0, poll=0.5):
    """Poll HostResult until the person has answered, then page the result in.

    `call(opcode, payload)` runs one command inside the channel and returns
    (status, body). Returns the whole result; raises `Refused` on a refusal and on a
    decline. Bounded: gives up after `wait` seconds of the person not answering.
    """
    deadline = time.time() + wait
    said = None
    while True:
        st, body = call(HOST_RESULT, struct.pack("<I", 0))
        if st == NOT_NOW:
            stage = body[0] if body else 0
            if stage != said:
                print(f"host      {STAGE.get(stage, stage)}")
                said = stage
            if stage in (0, 4):
                raise Refused(STAGE.get(stage, "nothing to fetch"))
            if time.time() > deadline:
                raise TimeoutError("nobody answered at the device")
            time.sleep(poll)
            continue
        if st == DECLINED:
            raise Refused("declined at the device")
        if st == REFUSED:
            raise Refused(body.decode(errors="replace"))
        if st != OK:
            raise ValueError(f"HostResult status {st}")
        total = struct.unpack("<I", body[:4])[0]
        got = bytearray(body[4:])
        while len(got) < total:
            st, body = call(HOST_RESULT, struct.pack("<I", len(got)))
            if st != OK:
                raise ValueError(f"HostResult page status {st}")
            page = body[4:]
            if not page:
                raise ValueError("empty page before the end")
            got += page
        return bytes(got)


def not_now(body):
    return BUSY.get(body[0], f"not now ({body[0]})") if body else "not now"


def addresses(call):
    st, body = call(HOST_ADDRESSES, b"")
    if st == NOT_NOW:
        raise Refused(not_now(body))
    if st != OK:
        raise ValueError(f"HostAddresses status {st}")
    print("host      asked; answer on the device")
    return decode_addresses(await_result(call))


def sign(call, chain, keys, tx):
    blob = sign_blob(chain, keys, tx)
    st, body = call(HOST_SIGN_BEGIN, struct.pack("<BI", chain, len(blob)))
    if st == NOT_NOW:
        raise Refused(not_now(body))
    if st == REFUSED:
        raise Refused(body.decode(errors="replace"))
    if st != OK:
        raise ValueError(f"HostSignBegin status {st}")
    chunk = struct.unpack("<I", body[:4])[0] if len(body) >= 4 else DATA_MAX
    chunk = min(chunk, DATA_MAX)
    at = 0
    try:
        while at < len(blob):
            part = blob[at:at + chunk]
            st, body = call(HOST_SIGN_DATA, struct.pack("<I", at) + part)
            if st != OK:
                raise ValueError(f"HostSignData status {st} at {at}")
            at += len(part)
        st, body = call(HOST_SIGN_COMMIT, b"")
    except Exception:
        call(HOST_ABORT, b"")
        raise
    if st == REFUSED:
        raise Refused(body.decode(errors="replace"))
    if st != OK:
        raise ValueError(f"HostSignCommit status {st}")
    print(f"host      {len(blob)} bytes uploaded; review it on the device")
    return await_result(call)


def print_addresses(r):
    print(f"wallet    fingerprint {r['fingerprint']}  account {r['account']}")
    for e in r["entries"]:
        name = CHAIN_NAMES.get(e["chain"], e["chain"])
        fmt = FORMAT.get(e["format"], e["format"])
        print(f"  {name:<16} {fmt:<12} {path_text(e['address_path'])}  {e['address']}")
        if e["xpub"]:
            print(f"  {'':<16} {'account':<12} {path_text(e['account_path'])}  {e['xpub']}")
        else:
            print(f"  {'':<16} {'pubkey':<12} {e['pubkey']}")


# ---- selftest: the same pinned bytes as the Rust tests ---------------------------------

def selftest():
    H = HARDENED
    blob = sign_blob(1, [[84 | H, H, H, 0, 3]], bytes([0x70, 0x73, 0x62, 0x74]))
    want = bytes([1, 1, 1, 5, 84, 0, 0, 0x80, 0, 0, 0, 0x80, 0, 0, 0, 0x80, 0, 0, 0, 0,
                  3, 0, 0, 0, 4, 0, 0, 0, 0x70, 0x73, 0x62, 0x74])
    assert blob == want, blob.hex()
    assert parse_path("m/84'/0h/0H/0/3") == [84 | H, H, H, 0, 3]
    assert path_text([44 | H, 501 | H, 7 | H, H]) == "m/44h/501h/7h/0h"

    reply = bytes([KIND_ADDRESSES, 1, 0xde, 0xad, 0xbe, 0xef, 7, 0, 0, 0, 2,
                   1, 1, 3,
                   3, 84, 0, 0, 0x80, 0, 0, 0, 0x80, 0, 0, 0, 0x80,
                   5, 84, 0, 0, 0x80, 0, 0, 0, 0x80, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0,
                   4]) + b"xpub" + bytes([4]) + b"bc1q" + bytes([2, 2, 3,
                   2, 3, 7,
                   3, 44, 0, 0, 0x80, 0xf5, 1, 0, 0x80, 7, 0, 0, 0x80,
                   4, 44, 0, 0, 0x80, 0xf5, 1, 0, 0x80, 7, 0, 0, 0x80, 0, 0, 0, 0x80,
                   3]) + b"So1" + bytes([1, 9])
    r = decode_addresses(reply)
    assert r["fingerprint"] == "deadbeef" and r["account"] == 7
    assert r["entries"][0]["xpub"] == "xpub" and r["entries"][1]["xpub"] == ""
    assert r["entries"][1]["address_path"] == [44 | H, 501 | H, 7 | H, H]
    for cut in range(len(reply)):
        try:
            decode_addresses(reply[:cut])
        except ValueError:
            continue
        raise AssertionError(f"truncated reply at {cut} accepted")

    btc = bytes([KIND_BITCOIN, 2, 2, 0, 0, 0, 0xAA, 0xBB, 1, 0, 0, 0, 0xCC])
    assert decode_bitcoin(btc) == (2, b"\xaa\xbb", b"\xcc")
    assert decode_evm(bytes([KIND_EVM, 2, 0, 0, 0, 2, 0xf8])) == b"\x02\xf8"
    sol = bytes([KIND_SOLANA, 1, 1]) + b"\x55" * 64 + bytes([1, 0, 0, 0, 0xEE])
    assert decode_solana(sol) == ([(1, b"\x55" * 64)], b"\xee")
    print("selftest  host-wallet layouts ok")
