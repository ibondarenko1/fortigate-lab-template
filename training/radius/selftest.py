"""Local-only positive/negative RADIUS checks. Requires RADIUS_SELFTEST=true."""

import hashlib
import hmac
from pathlib import Path
import secrets
import socket
import struct
import os
import sys
import time


def attribute(kind, value):
    return bytes((kind, len(value) + 2)) + value


def request(username, password, shared):
    identifier = secrets.randbelow(256)
    authenticator = secrets.token_bytes(16)
    padded = password + b"\0" * (-len(password) % 16 or 0)
    ciphertext = b""
    previous = authenticator
    for offset in range(0, len(padded), 16):
        digest = hashlib.md5(shared + previous).digest()
        previous = bytes(a ^ b for a, b in zip(padded[offset:offset + 16], digest))
        ciphertext += previous
    attributes = attribute(1, username) + attribute(2, ciphertext)
    attributes += attribute(80, b"\0" * 16)
    header = struct.pack("!BBH", 1, identifier, 20 + len(attributes)) + authenticator
    packet = header + attributes
    packet = packet[:-16] + hmac.new(shared, packet, hashlib.md5).digest()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as transport:
        transport.settimeout(3)
        transport.sendto(packet, ("127.0.0.1", 1812))
        response, _ = transport.recvfrom(4096)
    code, reply_id, length = struct.unpack("!BBH", response[:4])
    assert reply_id == identifier and length == len(response), "Invalid RADIUS response"
    expected = hashlib.md5(response[:4] + authenticator + response[20:] + shared).digest()
    assert hmac.compare_digest(expected, response[4:20]), "Invalid response authenticator"
    # Response Message-Authenticator uses the original request authenticator
    # and a zeroed AVP value, before the Response Authenticator is calculated.
    signed = bytearray(response)
    signed[4:20] = authenticator
    message_authenticators = []
    offset = 20
    while offset < len(response):
        assert offset + 2 <= len(response), "Truncated response attribute"
        kind, size = response[offset:offset + 2]
        assert size >= 2 and offset + size <= len(response), "Invalid response attribute length"
        if kind == 80:
            assert size == 18, "Invalid Message-Authenticator length"
            message_authenticators.append(response[offset + 2:offset + size])
            signed[offset + 2:offset + size] = b"\0" * 16
        offset += size
    assert len(message_authenticators) == 1, "Response must contain exactly one Message-Authenticator"
    expected_message_authenticator = hmac.new(shared, signed, hashlib.md5).digest()
    assert hmac.compare_digest(expected_message_authenticator, message_authenticators[0]), "Invalid response Message-Authenticator"
    return code


def check_responses():
    shared = Path("/run/secrets/radius_shared").read_bytes().strip()
    password = Path("/run/secrets/radius_password").read_bytes().strip()
    assert request(b"labco.radius.student", password, shared) == 2, "Positive test failed"
    assert request(b"labco.radius.student", b"deliberately-wrong", shared) == 3, "Wrong password was accepted"
    assert request(b"unknown.student", password, shared) == 3, "Unknown user was accepted"
    print("PASS: PAP accepted the synthetic student; wrong password and unknown user rejected; all response Message-Authenticators verified")


def wait_for_fixture():
    # docker run -d returns before the bootstrap has created the credentials
    # and before FreeRADIUS has bound its socket. Retry only startup failures.
    deadline = time.monotonic() + 15
    while True:
        try:
            check_responses()
            return
        except (FileNotFoundError, TimeoutError, ConnectionRefusedError) as exc:
            if time.monotonic() >= deadline:
                raise SystemExit("FreeRADIUS did not become ready in 15 seconds") from exc
            time.sleep(0.2)


if __name__ == "__main__":
    if not __debug__:
        raise SystemExit("The RADIUS self-test requires Python assertions")
    if sys.argv[1:] == ["--bootstrap-disposable"]:
        if os.environ.get("RADIUS_SELFTEST") != "true":
            raise SystemExit("Enable RADIUS_SELFTEST only in a disposable isolated container")
        for name in ("radius_shared", "radius_password"):
            path = Path("/run/secrets", name)
            with path.open("x", encoding="ascii") as output:
                output.write(secrets.token_hex(32))
            path.chmod(0o600)
        os.execv(sys.executable, [sys.executable, "/opt/radius/entrypoint.py"])
    elif not sys.argv[1:]:
        wait_for_fixture()
    else:
        raise SystemExit("Usage: selftest.py [--bootstrap-disposable]")
