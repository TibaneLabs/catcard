#!/usr/bin/env python3
"""Speak CatCard's USB protocol through its CCID smart-card interface.

The device is a CCID reader with one card in it (docs/USB.md, "The CCID smart-card
interface"), which is the transport a phone can open. Every CatCard message is one
APDU to that card, and the answer comes back as the APDU's response. This is the host
half of `catcard_usb::ccid::apdu`, written from the doc comment rather than shared with
the firmware; the flows on top -- pairing, the log, host-wallet -- are `usbclient.py`'s
own, run over this transport unchanged.

    tools/ccidclient.py                     find the reader, Identify, Ping
    tools/ccidclient.py --log               the device's log
    tools/ccidclient.py --pair              pair the encrypted channel, then Identify
                                            and Ping inside it
    tools/ccidclient.py --short             short APDUs only: chunks of 255, replies
                                            paged by GET RESPONSE (as a host without
                                            extended APDUs would)
    tools/ccidclient.py --reader NAME       a reader by (part of) its PC/SC name
    tools/ccidclient.py --selftest          the APDU encoding against fixed bytes

Needs pyscard (`pip install pyscard`) and the platform's PC/SC service: pcscd on
Linux (with the CCID driver, `libccid`), built in on macOS and Windows. The reader
appears under the device's USB product string, "CatCard".
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import usbclient  # noqa: E402  -- the flows and the message constants

# --- the one APDU (catcard_usb::ccid::apdu) ---

CLA, CLA_CHAIN, INS_MESSAGE = 0x80, 0x10, 0xCC
INS_GET_RESPONSE = 0xC0
HEADER = 6  # [u16 opcode][u32 total] in, [u16 status][u32 total] out
SW_OK, SW_MORE = 0x9000, 0x6100

# The most APDU an XfrBlock carries: `catcard_usb::ccid::APDU_MAX` (1078), less the
# extended header (7), our six-byte message header and a two-byte Le, rounded down.
CHUNK_EXTENDED = 1024
# A short APDU's data field.
CHUNK_SHORT = 255 - HEADER


def message_apdus(opcode, payload, short=False):
    """The APDUs that carry one message: a header on the first, chaining on all but
    the last, an `Le` on every one."""
    data = struct.pack("<HI", opcode, len(payload)) + payload
    chunk = CHUNK_SHORT + HEADER if short else CHUNK_EXTENDED + HEADER
    pieces = [data[i:i + chunk] for i in range(0, len(data), chunk)] or [data]
    out = []
    for i, piece in enumerate(pieces):
        last = i == len(pieces) - 1
        cla = CLA if last else CLA | CLA_CHAIN
        out.append(encode(cla, INS_MESSAGE, 0, 0, piece, short))
    return out


def encode(cla, ins, p1, p2, data=b"", short=False):
    """Case 2/4 short, or case 2E/4E extended, with `Le` = the maximum."""
    head = bytes([cla, ins, p1, p2])
    if short:
        if len(data) > 255:
            raise ValueError("short APDU data over 255 bytes")
        return head + (bytes([len(data)]) + data if data else b"") + b"\x00"
    if data:
        return head + b"\x00" + struct.pack(">H", len(data)) + data + b"\x00\x00"
    return head + b"\x00\x00\x00"


def get_response(short=False):
    return encode(0x00, INS_GET_RESPONSE, 0, 0, b"", short)


class CcidPort:
    """A CatCard reached as a smart card. `request` is what `usbclient` calls."""

    def __init__(self, connection, short=False):
        self.conn = connection
        self.short = short

    def transmit(self, apdu):
        data, sw1, sw2 = self.conn.transmit(list(apdu))
        return bytes(data), (sw1 << 8) | sw2

    def request(self, opcode, payload=b""):
        body = b""
        for apdu in message_apdus(opcode, payload, self.short):
            data, sw = self.transmit(apdu)
            body += data
        while (sw & 0xFF00) == SW_MORE:
            data, sw = self.transmit(get_response(self.short))
            body += data
        if sw != SW_OK:
            raise RuntimeError(f"card refused the APDU: SW {sw:04X}")
        if len(body) < HEADER:
            raise RuntimeError(f"reply too short for a message header: {body!r}")
        status, total = struct.unpack("<HI", body[:HEADER])
        rest = body[HEADER:]
        if len(rest) != total:
            raise RuntimeError(f"reply says {total} bytes, carried {len(rest)}")
        return status, rest


def open_reader(name_part=None, short=False):
    try:
        from smartcard.System import readers
    except ImportError:
        sys.exit("pyscard is not installed: pip install pyscard")
    found = readers()
    wanted = [r for r in found if (name_part or "CatCard").lower() in str(r).lower()]
    if not wanted:
        names = ", ".join(str(r) for r in found) or "none"
        sys.exit(f"no CatCard reader; readers seen: {names}")
    reader = wanted[0]
    conn = reader.createConnection()
    conn.connect()
    print(f"reader    {reader}")
    print(f"atr       {bytes(conn.getATR()).hex()}")
    return CcidPort(conn, short)


def selftest():
    """The bytes on the wire, pinned."""
    # One short message, extended: 00 Lc(2) data Le(2).
    a = message_apdus(usbclient.IDENTIFY, b"")
    assert a == [bytes.fromhex("80cc0000000006" "0200" "00000000" "0000")], a
    # Short: Lc data Le.
    a = message_apdus(usbclient.PING, b"hi", short=True)
    assert a == [bytes.fromhex("80cc000008" "0100" "02000000" "6869" "00")], a
    # Chained, short: 249 payload bytes per chunk after the header on the first.
    payload = bytes(range(256)) * 2
    a = message_apdus(0x0041, payload, short=True)
    assert len(a) == 3, len(a)
    assert a[0][0] == 0x90 and a[1][0] == 0x90 and a[2][0] == 0x80
    assert a[0][4] == 255 and a[0][5:11] == struct.pack("<HI", 0x41, 512)
    joined = b"".join(x[5:-1] for x in a)
    assert joined == struct.pack("<HI", 0x41, 512) + payload
    # Chained, extended: 1030 bytes on the first, the rest on the second.
    payload = bytes(1500)
    a = message_apdus(0x0041, payload)
    assert len(a) == 2 and a[0][0] == 0x90 and a[1][0] == 0x80
    assert a[0][5:7] == struct.pack(">H", 1030) and a[1][5:7] == struct.pack(">H", 476)
    assert get_response() == bytes.fromhex("00c00000000000")
    assert get_response(short=True) == bytes.fromhex("00c0000000")

    class Fake:
        """A card that answers Identify-like bodies 100 bytes long, paged by 256."""
        def __init__(self):
            self.pending = b""
            self.seen = []

        def transmit(self, apdu):
            apdu = bytes(apdu)
            self.seen.append(apdu)
            if apdu[1] == INS_GET_RESPONSE:
                page, self.pending = self.pending[:255], self.pending[255:]
                sw = SW_OK if not self.pending else SW_MORE | min(len(self.pending), 255)
                return list(page), sw >> 8, sw & 0xFF
            if apdu[0] & CLA_CHAIN:
                return [], 0x90, 0x00
            body = struct.pack("<HI", 0, 300) + bytes(300)
            page, self.pending = body[:255], body[255:]
            sw = SW_MORE | min(len(self.pending), 255)
            return list(page), sw >> 8, sw & 0xFF

    port = CcidPort(Fake(), short=True)
    st, body = port.request(usbclient.IDENTIFY)
    assert (st, body) == (0, bytes(300)), (st, len(body))
    assert len(port.conn.seen) == 2
    print("ccid selftest ok")


def main():
    args = sys.argv[1:]
    if "--selftest" in args:
        return selftest()
    short = "--short" in args
    name = None
    if "--reader" in args:
        name = args[args.index("--reader") + 1]
    port = open_reader(name, short)

    st, body = usbclient.request(port, usbclient.IDENTIFY)
    info = usbclient.identify(body) if st == 0 else None
    print(f"identify  status={usbclient.STATUS.get(st, st)} {info}")
    st, body = usbclient.request(port, usbclient.PING, b"catcard over ccid")
    print(f"ping      status={usbclient.STATUS.get(st, st)} echo={body!r}")

    if "--log" in args:
        text, total, wrapped = usbclient.fetch_log(port)
        print(f"log       {total} bytes{' (wrapped)' if wrapped else ''}")
        sys.stdout.write(text.decode("utf-8", "replace"))

    if "--pair" in args:
        session = usbclient.pair_session(port)
        st, body = usbclient.ncry_request(port, session, usbclient.IDENTIFY)
        print(f"ncry identify   status={usbclient.STATUS.get(st, st)} "
              f"{usbclient.identify(body)}")
        st, body = usbclient.ncry_request(port, session, usbclient.PING, b"sealed")
        print(f"ncry ping       status={usbclient.STATUS.get(st, st)} echo={body!r}")


if __name__ == "__main__":
    main()
