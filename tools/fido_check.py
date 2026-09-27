#!/usr/bin/env python3
"""Check a CatCard's FIDO2 / U2F security key with python-fido2, an independent client.

The device must be unlocked, with a wallet, in the CatCard USB mode, and with
Settings -> Hardware On/Off -> Security key switched on. Every step that needs the person
says so; press the confirm key on the device when its screen asks. Nothing here speaks
CTAP itself: python-fido2 (Yubico's library, `pip install fido2`) does the transport,
the CBOR -- strictly, it refuses non-canonical answers -- and every signature check.

    INIT / PING                 a channel, capabilities CBOR+WINK, MSG supported; echo
    GetInfo                     versions, AAGUID, options, algorithms, maxMsgSize
    MakeCredential              ES256; `packed` self-attestation verified   [press]
    GetAssertion                signature verified with the new credential [press]
    GetAssertion up=false       silent: UP clear, signature verified
    exclude list                CREDENTIAL_EXCLUDED                        [press]
    refusals                    rk, an unsupported algorithm, a foreign id
    U2F                         VERSION; REGISTER (polling, as U2F does)   [press]
                                AUTHENTICATE check-only, then signed        [press]
                                and the U2F key handle used from CTAP2

With --reset, **IRREVERSIBLE**: authenticatorReset, which raises this wallet's FIDO
generation so every site registered with this wallet's security key -- by anyone, ever
-- stops accepting it. The device only allows it within 10 s of the security key
appearing on USB and asks twice; this script asks you to type RESET first.

Usage:

    tools/fido_check.py                   # the first CatCard security key found
    tools/fido_check.py --sim             # against `cargo run -p catcard-fido --example fido_sim`
    tools/fido_check.py --reset           # IRREVERSIBLE, see above

python-fido2 not installed?

    python3 -m venv /tmp/fido-venv && /tmp/fido-venv/bin/pip install fido2
    /tmp/fido-venv/bin/python tools/fido_check.py

On Linux the hidraw node needs a udev rule (docs/USB.md); on macOS and Windows nothing.
Exit status 0 when every step passed. See docs/FIDO.md.
"""
import argparse
import hashlib
import os
import subprocess
import sys
import time

try:
    from fido2.ctap import CtapError
    from fido2.ctap1 import ApduError, APDU, Ctap1
    from fido2.ctap2 import Ctap2
    from fido2.attestation import PackedAttestation
    from fido2.hid import CtapHidDevice, CTAPHID, CAPABILITY
    from fido2.hid.base import CtapHidConnection, HidDescriptor
    from fido2.webauthn import AttestedCredentialData
except ImportError:
    sys.exit("needs python-fido2: pip install fido2 (see the top of this file)")

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, ".."))

CATCARD_VID = 0x39F2
CATCARD_PID = 0x0401
AAGUID = bytes.fromhex("54a5d3d6f9d64b05bdac7cc541efc8f1")
RP = {"id": "catcard.example", "name": "CatCard check"}
USER = {"id": b"fido-check-user", "name": "check@catcard.example", "displayName": "Check"}
ES256 = {"type": "public-key", "alg": -7}


class PipeConnection(CtapHidConnection):
    """CTAPHID packets over a child process's stdin/stdout: the simulator."""

    def __init__(self, argv):
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, cwd=REPO)

    def write_packet(self, data):
        self.proc.stdin.write(bytes(data).ljust(64, b"\0"))
        self.proc.stdin.flush()

    def read_packet(self):
        data = self.proc.stdout.read(64)
        if len(data) != 64:
            raise OSError("the simulator went away")
        return data

    def close(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=5)


def open_device(args):
    if args.sim:
        conn = PipeConnection(["cargo", "run", "-q", "-p", "catcard-fido", "--example", "fido_sim"])
        desc = HidDescriptor("sim", CATCARD_VID, CATCARD_PID, 64, 64, "CatCard sim", None)
        return CtapHidDevice(desc, conn)
    found = list(CtapHidDevice.list_devices())
    ours = [d for d in found if (d.descriptor.vid, d.descriptor.pid) == (CATCARD_VID, CATCARD_PID)]
    if not ours:
        names = ", ".join(f"{d.descriptor.vid:04x}:{d.descriptor.pid:04x}" for d in found) or "none"
        sys.exit(f"no CatCard security key found (FIDO devices seen: {names}). Is the switch on?")
    return ours[0]


class Checks:
    def __init__(self, sim):
        self.sim = sim
        self.failed = 0

    def step(self, name, fn):
        try:
            detail = fn()
        except Exception as e:  # noqa: BLE001 - every failure is a report, not a crash
            self.failed += 1
            print(f"FAIL  {name}: {type(e).__name__}: {e}")
            return None
        print(f"ok    {name}{': ' + detail if isinstance(detail, str) and detail else ''}")
        return detail

    def press(self, what):
        if not self.sim:
            print(f"      >>> on the device: {what}")


def expect_ctap_error(code, fn):
    try:
        fn()
    except CtapError as e:
        if e.code != code:
            raise AssertionError(f"wanted {code.name}, got {e.code!r}") from e
        return f"{code.name}, as it should"
    raise AssertionError(f"wanted {code.name}, got success")


def u2f_poll(fn, checks, what, seconds=35):
    """U2F answers 'conditions not satisfied' until the person presses; retry like a host."""
    checks.press(what)
    deadline = time.time() + seconds
    while True:
        try:
            return fn()
        except ApduError as e:
            if e.code != APDU.USE_NOT_SATISFIED or time.time() > deadline:
                raise
            time.sleep(0.25)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--sim", action="store_true", help="run against the fido_sim example")
    ap.add_argument(
        "--reset",
        action="store_true",
        help="IRREVERSIBLE: reset this wallet's security key (every registered site stops accepting it)",
    )
    args = ap.parse_args()

    if args.reset and not args.sim:
        print("--reset raises this wallet's FIDO generation: EVERY site registered with this")
        print("wallet's security key stops accepting it, for good. Restoring the seed elsewhere")
        print("does not bring those logins back unless that device was never reset.")
        if input("Type RESET to go on: ").strip() != "RESET":
            sys.exit("not reset")

    dev = open_device(args)
    c = Checks(args.sim)
    ctap2 = Ctap2(dev)  # strict CBOR: a non-canonical answer is an error
    ctap1 = Ctap1(dev)

    def init():
        caps = CAPABILITY(dev.capabilities)
        assert CAPABILITY.CBOR in caps and CAPABILITY.WINK in caps, caps
        assert CAPABILITY.NMSG not in caps, "MSG (U2F) must be supported"
        assert dev.version == 2
        echo = os.urandom(1000)
        assert dev.call(CTAPHID.PING, echo) == echo
        return f"device {dev.device_version}, caps {caps!r}"

    c.step("INIT and PING", init)

    def info():
        i = ctap2.get_info()
        assert set(i.versions) >= {"U2F_V2", "FIDO_2_0", "FIDO_2_1"}, i.versions
        assert bytes(i.aaguid) == AAGUID, i.aaguid
        assert i.options.get("rk") is False and i.options.get("up") is True, i.options
        assert "clientPin" not in i.options and "uv" not in i.options, i.options
        assert i.max_msg_size == 1024, i.max_msg_size
        assert {"type": "public-key", "alg": -7} in [dict(a) for a in i.algorithms], i.algorithms
        assert "usb" in i.transports
        return f"{i.versions}, maxMsgSize {i.max_msg_size}"

    c.step("GetInfo", info)

    state = {}

    def make():
        cdh = os.urandom(32)
        c.press("allow the registration with catcard.example")
        att = ctap2.make_credential(cdh, RP, USER, [ES256])
        assert att.fmt == "packed", att.fmt
        ad = att.auth_data
        assert ad.rp_id_hash == hashlib.sha256(RP["id"].encode()).digest()
        assert ad.is_user_present() and ad.is_attested(), ad.flags
        assert bytes(ad.credential_data.aaguid) == AAGUID
        assert "x5c" not in att.att_stmt, "self-attestation carries no certificate"
        PackedAttestation().verify(att.att_stmt, ad, cdh)
        state["cred"] = ad.credential_data
        return f"credential id {len(ad.credential_data.credential_id)} bytes, packed self-attestation verified"

    c.step("MakeCredential", make)

    def assertion(up):
        cred = state["cred"]
        cdh = os.urandom(32)
        if up:
            c.press("allow signing in to catcard.example")
        allow = [{"type": "public-key", "id": os.urandom(40)}, {"type": "public-key", "id": cred.credential_id}]
        r = ctap2.get_assertion(RP["id"], cdh, allow, options=None if up else {"up": False})
        assert r.credential["id"] == cred.credential_id
        assert r.auth_data.is_user_present() == up, r.auth_data.flags
        assert r.auth_data.counter == 0, "this device keeps no counter"
        r.verify(cdh, cred.public_key)
        return "signature verified"

    if "cred" in state:
        c.step("GetAssertion", lambda: assertion(True))
        c.step("GetAssertion up=false (silent)", lambda: assertion(False))

        def excluded():
            c.press("acknowledge 'already registered'")
            return expect_ctap_error(
                CtapError.ERR.CREDENTIAL_EXCLUDED,
                lambda: ctap2.make_credential(
                    os.urandom(32), RP, USER, [ES256],
                    exclude_list=[{"type": "public-key", "id": state["cred"].credential_id}],
                ),
            )

        c.step("exclude list", excluded)

    c.step(
        "rk=true refused",
        lambda: expect_ctap_error(
            CtapError.ERR.UNSUPPORTED_OPTION,
            lambda: ctap2.make_credential(os.urandom(32), RP, USER, [ES256], options={"rk": True}),
        ),
    )
    c.step(
        "EdDSA only refused",
        lambda: expect_ctap_error(
            CtapError.ERR.UNSUPPORTED_ALGORITHM,
            lambda: ctap2.make_credential(os.urandom(32), RP, USER, [{"type": "public-key", "alg": -8}]),
        ),
    )
    c.step(
        "a foreign credential id is not ours",
        lambda: expect_ctap_error(
            CtapError.ERR.NO_CREDENTIALS,
            lambda: ctap2.get_assertion(
                RP["id"], os.urandom(32), [{"type": "public-key", "id": os.urandom(33)}], options={"up": False}
            ),
        ),
    )

    # ---- U2F (CTAP1) over CTAPHID_MSG ----
    c.step("U2F VERSION", lambda: ctap1.get_version() == "U2F_V2" and "U2F_V2")
    app = hashlib.sha256(RP["id"].encode()).digest()

    def u2f_register():
        chal = os.urandom(32)
        reg = u2f_poll(lambda: ctap1.register(chal, app), c, "allow the (U2F) registration")
        reg.verify(app, chal)  # the self-signed certificate's key signed the registration
        state["u2f"] = reg
        return f"key handle {len(reg.key_handle)} bytes, certificate {len(reg.certificate)} bytes, verified"

    c.step("U2F REGISTER", u2f_register)

    if "u2f" in state:
        reg = state["u2f"]

        def check_only():
            try:
                ctap1.authenticate(os.urandom(32), app, reg.key_handle, check_only=True)
            except ApduError as e:
                assert e.code == APDU.USE_NOT_SATISFIED, hex(e.code)
            try:
                ctap1.authenticate(os.urandom(32), app, os.urandom(33), check_only=True)
            except ApduError as e:
                assert e.code == APDU.WRONG_DATA, hex(e.code)
                return "ours: 6985, a stranger's: 6A80"
            raise AssertionError("a foreign key handle was accepted")

        c.step("U2F AUTHENTICATE check-only", check_only)

        def u2f_auth():
            chal = os.urandom(32)
            sig = u2f_poll(lambda: ctap1.authenticate(chal, app, reg.key_handle), c, "allow the (U2F) sign-in")
            sig.verify(app, chal, reg.public_key)
            assert sig.user_presence & 1
            return "signature verified"

        c.step("U2F AUTHENTICATE", u2f_auth)

        def cross():
            cdh = os.urandom(32)
            r = ctap2.get_assertion(RP["id"], cdh, [{"type": "public-key", "id": reg.key_handle}], options={"up": False})
            from fido2.cose import ES256 as CoseES256

            r.verify(cdh, CoseES256.from_ctap1(reg.public_key))
            return "the U2F key handle signs for CTAP2"

        c.step("U2F key handle via CTAP2", cross)

    if args.reset:

        def reset():
            c.press("confirm the reset twice (the second is the 7 key)")
            ctap2.reset()
            if "cred" in state:
                expect_ctap_error(
                    CtapError.ERR.NO_CREDENTIALS,
                    lambda: ctap2.get_assertion(
                        RP["id"], os.urandom(32),
                        [{"type": "public-key", "id": state["cred"].credential_id}], options={"up": False},
                    ),
                )
            return "the old credential no longer verifies"

        c.step("Reset (IRREVERSIBLE)", reset)

    dev.close()
    print("all passed" if not c.failed else f"{c.failed} failed")
    return 1 if c.failed else 0


if __name__ == "__main__":
    sys.exit(main())
