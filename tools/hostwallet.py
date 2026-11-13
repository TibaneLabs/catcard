"""Host-wallet commands: ask a CatCard for addresses, one address by its path, or a
signature over a transaction or a message.

The host half of `catcard_usb::hostwallet`, written from `docs/USB.md` §"Host-wallet
commands" rather than shared with the firmware. Every command travels inside the encrypted
channel (`NcryMsg`); in the clear the device answers `UnknownOpcode`.

The shape is the upgrade offer's: the host asks, the device shows the question to the
person holding it, the person decides on the device, and the host polls `HostResult`
until there is an answer. Nothing here can answer for the person.

    usbclient.py hid --host-info
    usbclient.py hid --addresses
    usbclient.py hid --address m/84h/0h/0h/0/3 [--chain btc] [--format p2wpkh] [--show]
    usbclient.py hid --sign tx.psbt --chain btc --key m/84h/0h/0h/0/3 [--key ...] [--out F]
    usbclient.py hid --sign-message "text" --key m/84h/0h/0h/0/3 [--chain btc]
                     [--format p2wpkh] [--scheme bip137|bip322|bip322-full|eip191|tip191|
                     solana-offchain|solana-offchain-v0 [--app-domain HEX]]
    usbclient.py hid --sign-typed data.json --key m/44h/60h/0h/0/0      (EIP-712)
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
HOST_ADDRESS_AT = 0x0056
HOST_SIGN_MESSAGE = 0x0057
HOST_INFO = 0x0058

# Capability bit, matching `catcard_usb::caps::HOST_WALLET`.
CAP_HOST_WALLET = 1 << 6

VERSION = 1
MAX_DEPTH = 8
MAX_KEYS = 32
PAGE_MAX = 448
# Sealed plaintext bound (1024) less the opcode and the offset.
DATA_MAX = 1024 - 2 - 4
HARDENED = 0x8000_0000
# One sealed record holds a whole message request.
MESSAGE_MAX = 960

OK, UNKNOWN_OPCODE, NOT_NOW, BAD_REQUEST, DECLINED, REFUSED = 0, 1, 2, 3, 4, 5

STAGE = {0: "nothing asked", 1: "upload open", 2: "waiting for the screen",
         3: "the person is deciding", 4: "busy with another session's request"}
BUSY = {1: "the device is locked: enter the PIN first",
        2: "another request or an upgrade is pending"}

KIND_ADDRESSES, KIND_BITCOIN, KIND_EVM, KIND_SOLANA = 1, 2, 3, 4
KIND_ADDRESS, KIND_MESSAGE = 5, 6
# HostAddressAt flags.
ASK_SHOW = 1
SCHEME = {1: "bip137", 2: "bip322", 3: "bip322-full", 4: "eip191", 5: "tip191",
          6: "eip712", 7: "solana-offchain", 8: "solana-offchain-v0"}
SCHEME_IDS = {v: k for k, v in SCHEME.items()}
# HostInfo bits.
CAN = {1: "addresses", 2: "sign", 4: "messages"}
FEATURE = {1: "address-at", 2: "sign-message", 4: "typed-data"}
SESSION = {1: "paths-allowed", 2: "shared"}
SHAPE = {1: "utxo", 2: "account"}
FORMAT = {1: "p2pkh", 2: "p2sh-p2wpkh", 3: "p2wpkh", 4: "p2tr", 5: "evm", 6: "tron",
          7: "solana"}
FORMAT_IDS = {v: k for k, v in FORMAT.items()}
# The script type a BIP-44-family purpose means, for a Bitcoin path given without one.
PURPOSE_FORMAT = {44: 1, 49: 2, 84: 3, 86: 4}
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

    def u16(self):
        return struct.unpack("<H", self.take(2))[0]

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


def address_at_request(chain, fmt, steps, show=False):
    """[u8 chain][u8 format][u8 flags][path]."""
    return bytes([chain, fmt, ASK_SHOW if show else 0]) + enc_path(steps)


def message_request(chain, fmt, scheme, steps, message):
    """[u8 version][u8 chain][u8 format][u8 scheme][path][u16 len][message]."""
    if not 1 <= len(message) <= MESSAGE_MAX:
        raise ValueError(f"a message is 1..{MESSAGE_MAX} bytes")
    return (bytes([VERSION, chain, fmt, scheme]) + enc_path(steps)
            + struct.pack("<H", len(message)) + message)


def short(text):
    b = text.encode()
    if len(b) > 255:
        raise ValueError("a name is at most 255 bytes")
    return bytes([len(b)]) + b


def typed_value(types, ty, v):
    """One EIP-712 value in the device's layout (crates/catcard-evm/src/typed.rs)."""
    if ty.endswith("]"):
        elem, _, n = ty[:-1].rpartition("[")
        items = list(v)
        if n and len(items) != int(n):
            raise ValueError(f"{ty} takes {n} elements, not {len(items)}")
        head = b"" if n else struct.pack("<H", len(items))
        return head + b"".join(typed_value(types, elem, i) for i in items)
    if ty in types:
        return b"".join(typed_value(types, f["type"], v[f["name"]]) for f in types[ty])
    if ty == "bool":
        return bytes([1 if v else 0])
    if ty == "string":
        b = v.encode()
        return struct.pack("<H", len(b)) + b
    as_bytes = lambda x: bytes.fromhex(x[2:] if x.startswith("0x") else x) \
        if isinstance(x, str) else bytes(x)
    if ty == "bytes":
        b = as_bytes(v)
        return struct.pack("<H", len(b)) + b
    if ty == "address":
        b = as_bytes(v)
        if len(b) != 20:
            raise ValueError("an address is twenty bytes")
        return b
    as_int = lambda x: int(x, 0) if isinstance(x, str) else int(x)
    if ty.startswith("bytes"):
        b = as_bytes(v)
        if len(b) != int(ty[5:]):
            raise ValueError(f"{ty} takes {ty[5:]} bytes, not {len(b)}")
        return b
    if ty.startswith("uint"):
        n = as_int(v)
        if not 0 <= n < 1 << int(ty[4:]):
            raise ValueError(f"{n} does not fit {ty}")
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes([len(b)]) + b
    if ty.startswith("int"):
        return as_int(v).to_bytes(int(ty[3:]) // 8, "big", signed=True)
    raise ValueError(f"unknown type {ty!r}")


def typed_blob(doc):
    """What `eth_signTypedData_v4` is handed (the parsed JSON), as a HostSignMessage
    message for scheme eip712: the types, then the domain's and the message's values."""
    types = doc["types"]
    names = list(types)
    out = bytes([1, len(names)])
    for n in names:
        out += short(n) + bytes([len(types[n])])
        out += b"".join(short(f["type"]) + short(f["name"]) for f in types[n])
    out += bytes([names.index(doc["primaryType"])])
    out += typed_value(types, "EIP712Domain", doc["domain"])
    out += typed_value(types, doc["primaryType"], doc["message"])
    return out


def solana_v0_message(app_domain, text, fmt=0):
    """A scheme solana-offchain-v0 message: [32 application domain][u8 format][text]."""
    if len(app_domain) != 32:
        raise ValueError("an application domain is 32 bytes")
    return bytes(app_domain) + bytes([fmt]) + text


def decode_address(r):
    rd = Reader(r)
    if rd.u8() != KIND_ADDRESS or rd.u8() != VERSION:
        raise ValueError("not an address-by-path reply")
    e = {"fingerprint": rd.take(4).hex(), "chain": rd.u8(), "format": rd.u8(),
         "path": rd.path()}
    e["address"] = rd.short().decode()
    e["pubkey"] = rd.short().hex()
    rd.done()
    return e


def decode_message(r):
    rd = Reader(r)
    if rd.u8() != KIND_MESSAGE or rd.u8() != VERSION:
        raise ValueError("not a message result")
    e = {"chain": rd.u8(), "scheme": rd.u8(), "path": rd.path()}
    e["address"] = rd.short().decode()
    e["signature"] = rd.take(rd.u16())
    rd.done()
    return e


def decode_info(r):
    rd = Reader(r)
    if rd.u8() != VERSION:
        raise ValueError("not an info reply this tool reads")
    info = {"features": rd.u8(), "session": rd.u8(), "message_max": rd.u16(), "chains": []}
    for _ in range(rd.u8()):
        info["chains"].append({"chain": rd.u8(), "can": rd.u8(), "formats": list(rd.short())})
    rd.done()
    return info


def default_format(chain, steps):
    """The address format to ask for when none was named: the chain's one, or for
    Bitcoin the one its path's purpose means (native segwit when it means none)."""
    if chain == 2:
        return 5
    if chain == 9:
        return 6
    if chain == 3:
        return 7
    purpose = steps[0] & ~HARDENED if steps and steps[0] & HARDENED else None
    if chain == 1:
        return PURPOSE_FORMAT.get(purpose, 3)
    return 1


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


def info(call):
    """What this build answers and what the session has. `None` from a device that
    predates the command (it answers `UnknownOpcode`): it has the first six only."""
    st, body = call(HOST_INFO, b"")
    if st == UNKNOWN_OPCODE:
        return None
    if st != OK:
        raise ValueError(f"HostInfo status {st}")
    return decode_info(body)


def ask(call, opcode, payload, name):
    """Send a one-request question and wait for the person's answer."""
    st, body = call(opcode, payload)
    if st == UNKNOWN_OPCODE:
        raise Refused("this device's firmware does not have that command")
    if st == NOT_NOW:
        raise Refused(not_now(body))
    if st == REFUSED:
        raise Refused(body.decode(errors="replace"))
    if st != OK:
        raise ValueError(f"{name} status {st}")
    print("host      asked; answer on the device")
    return await_result(call)


def address_at(call, chain, fmt, steps, show=False):
    return decode_address(ask(call, HOST_ADDRESS_AT,
                              address_at_request(chain, fmt, steps, show), "HostAddressAt"))


def sign_message(call, chain, fmt, scheme, steps, message):
    return decode_message(ask(call, HOST_SIGN_MESSAGE,
                              message_request(chain, fmt, scheme, steps, message),
                              "HostSignMessage"))


def bits(value, names):
    return ", ".join(n for b, n in names.items() if value & b) or "none"


def print_info(i):
    print(f"host      commands: {bits(i['features'], FEATURE)}; "
          f"session: {bits(i['session'], SESSION)}; longest message {i['message_max']}")
    for c in i["chains"]:
        fmts = " ".join(FORMAT.get(f, str(f)) for f in c["formats"])
        print(f"  {CHAIN_NAMES.get(c['chain'], c['chain']):<16} {bits(c['can'], CAN):<28} {fmts}")


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

    def truncations_refused(decode, reply):
        for cut in range(len(reply)):
            try:
                decode(reply[:cut])
            except ValueError:
                continue
            raise AssertionError(f"truncated reply at {cut} accepted")
        try:
            decode(reply + b"\0")
        except ValueError:
            return
        raise AssertionError("trailing byte accepted")

    # One address by its path: the request, and the reply.
    want = bytes([1, 4, 1, 5, 86, 0, 0, 0x80, 0, 0, 0, 0x80, 0, 0, 0, 0x80, 0, 0, 0, 0,
                  5, 0, 0, 0])
    assert address_at_request(1, 4, [86 | H, H, H, 0, 5], show=True) == want
    assert address_at_request(2, 5, [44 | H])[2] == 0
    one = bytes([KIND_ADDRESS, 1, 0xde, 0xad, 0xbe, 0xef, 2, 5,
                 5, 44, 0, 0, 0x80, 60, 0, 0, 0x80, 0, 0, 0, 0x80, 0, 0, 0, 0, 9, 0, 0, 0,
                 4]) + b"0xAb" + bytes([2, 2, 7])
    a = decode_address(one)
    assert a == {"fingerprint": "deadbeef", "chain": 2, "format": 5,
                 "path": [44 | H, 60 | H, H, 0, 9], "address": "0xAb", "pubkey": "0207"}
    truncations_refused(decode_address, one)
    assert default_format(1, [86 | H, H, H, 0, 0]) == 4
    assert default_format(1, [0, 5]) == 3 and default_format(3, [44 | H]) == 7

    # A message: the request, and the result.
    want = bytes([1, 1, 3, 2, 5, 84, 0, 0, 0x80, 0, 0, 0, 0x80, 0, 0, 0, 0x80, 0, 0, 0, 0,
                  3, 0, 0, 0, 2, 0]) + b"hi"
    assert message_request(1, 3, 2, [84 | H, H, H, 0, 3], b"hi") == want
    for bad in (b"", b"x" * (MESSAGE_MAX + 1)):
        try:
            message_request(1, 3, 1, [84 | H], bad)
        except ValueError:
            continue
        raise AssertionError("a message out of bounds was encoded")
    msg = bytes([KIND_MESSAGE, 1, 2, 4,
                 5, 44, 0, 0, 0x80, 60, 0, 0, 0x80, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0,
                 4]) + b"0xAb" + bytes([3, 0, 0xAA, 0xBB, 27])
    m = decode_message(msg)
    assert m == {"chain": 2, "scheme": 4, "path": [44 | H, 60 | H, H, 0, 0],
                 "address": "0xAb", "signature": b"\xaa\xbb\x1b"}
    truncations_refused(decode_message, msg)

    # Typed data: the example in EIP-712 itself, from its JSON to the bytes the firmware's
    # tests pin (crates/catcard-evm/src/typed/tests.rs, MAIL) and hash to the standard's
    # own digest.
    person = [{"name": "name", "type": "string"}, {"name": "wallet", "type": "address"}]
    mail = {
        "types": {
            "EIP712Domain": [{"name": "name", "type": "string"},
                             {"name": "version", "type": "string"},
                             {"name": "chainId", "type": "uint256"},
                             {"name": "verifyingContract", "type": "address"}],
            "Person": person,
            "Mail": [{"name": "from", "type": "Person"}, {"name": "to", "type": "Person"},
                     {"name": "contents", "type": "string"}]},
        "primaryType": "Mail",
        "domain": {"name": "Ether Mail", "version": "1", "chainId": 1,
                   "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"},
        "message": {
            "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
            "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
            "contents": "Hello, Bob!"}}
    assert typed_blob(mail).hex() == (
        "01030c454950373132446f6d61696e0406737472696e67046e616d6506737472696e670776657273"
        "696f6e0775696e7432353607636861696e4964076164647265737311766572696679696e67436f6e"
        "747261637406506572736f6e0206737472696e67046e616d6507616464726573730677616c6c6574"
        "044d61696c0306506572736f6e0466726f6d06506572736f6e02746f06737472696e6708636f6e74"
        "656e7473020a004574686572204d61696c0100310101cccccccccccccccccccccccccccccccccccc"
        "cccc0300436f77cd2a3d9f938e13cd947ec05abc7fe734df8dd8260300426f62bbbbbbbbbbbbbbbb"
        "bbbbbbbbbbbbbbbbbbbbbbbb0b0048656c6c6f2c20426f6221")
    types = {"EIP712Domain": [], "T": []}
    assert typed_value(types, "uint8[]", [1, "0x02"]) == bytes([2, 0, 1, 1, 1, 2])
    assert typed_value(types, "uint256", 0) == b"\0"
    assert typed_value(types, "int16", -2) == b"\xff\xfe"
    assert typed_value(types, "bool[2]", [True, False]) == b"\x01\x00"
    assert typed_value(types, "bytes", "0x0102") == b"\x02\x00\x01\x02"
    for ty, bad in (("uint8", 256), ("bytes4", "0x00"), ("bool[2]", [True]),
                    ("address", "0x00"), ("float", 1)):
        try:
            typed_value(types, ty, bad)
        except ValueError:
            continue
        raise AssertionError(f"{ty} took {bad!r}")
    assert solana_v0_message(bytes(32), b"hi", 1) == bytes(32) + b"\x01hi"

    # What a build answers.
    inf = bytes([1, 0b11, 0b10, 0xC0, 0x03, 2, 1, 0b111, 2, 3, 4, 9, 0b001, 1, 6])
    i = decode_info(inf)
    assert i["features"] == 3 and i["session"] == 2 and i["message_max"] == MESSAGE_MAX
    assert i["chains"] == [{"chain": 1, "can": 7, "formats": [3, 4]},
                           {"chain": 9, "can": 1, "formats": [6]}]
    truncations_refused(decode_info, inf)
    print("selftest  host-wallet layouts ok")
