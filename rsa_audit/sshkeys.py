"""Identify SSH key types without ever printing key material.

Private keys are only inspected for their unencrypted public header; the
secret part is never decoded or stored.
"""

import base64
import re
import struct

SSH_TYPES = {
    "ssh-rsa": "RSA",
    "ssh-rsa-cert-v01@openssh.com": "RSA",
    "ssh-dss": "DSA",
    "ssh-dss-cert-v01@openssh.com": "DSA",
    "ecdsa-sha2-nistp256": "EC",
    "ecdsa-sha2-nistp384": "EC",
    "ecdsa-sha2-nistp521": "EC",
    "sk-ecdsa-sha2-nistp256@openssh.com": "EC",
    "ssh-ed25519": "Ed25519",
    "ssh-ed25519-cert-v01@openssh.com": "Ed25519",
    "sk-ssh-ed25519@openssh.com": "Ed25519",
}
EC_BITS = {"nistp256": 256, "nistp384": 384, "nistp521": 521}
PEM_TYPES = {
    "RSA PRIVATE KEY": "RSA",
    "DSA PRIVATE KEY": "DSA",
    "EC PRIVATE KEY": "EC",
}
PEM_RE = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END", re.S)


def _read_string(buf: bytes, pos: int) -> tuple[bytes, int]:
    (n,) = struct.unpack(">I", buf[pos : pos + 4])
    return buf[pos + 4 : pos + 4 + n], pos + 4 + n


def key_from_blob(blob: bytes) -> tuple[str, int | None]:
    """(family, bits) for an SSH wire-format public key blob."""
    name, pos = _read_string(blob, 0)
    name = name.decode("ascii", "replace")
    family = SSH_TYPES.get(name, "unknown")
    bits = None
    if family == "RSA":
        if name.endswith("-cert-v01@openssh.com"):
            _, pos = _read_string(blob, pos)  # nonce
        _, pos = _read_string(blob, pos)  # e
        n, _ = _read_string(blob, pos)
        bits = int.from_bytes(n, "big").bit_length()
    elif family == "EC":
        bits = next((b for c, b in EC_BITS.items() if c in name), None)
    elif family == "Ed25519":
        bits = 256
    return family, bits


def parse_pubkey_line(line: str) -> tuple[str, int | None, str] | None:
    """Find the key in an authorized_keys / known_hosts / .pub line.

    Returns (family, bits, text_before_key) or None for blank/comment lines.
    Options (authorized_keys) or host patterns (known_hosts) come before the
    key type, so we scan for the first token that is a known type.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    tokens = line.split()
    for i, tok in enumerate(tokens[:-1]):
        if tok in SSH_TYPES or tok.startswith(("ssh-", "ecdsa-", "sk-")):
            try:
                family, bits = key_from_blob(base64.b64decode(tokens[i + 1]))
            except (ValueError, struct.error):
                family, bits = SSH_TYPES.get(tok, "unknown"), None
            return family, bits, " ".join(tokens[:i])
    return None


def private_key_type(text: str) -> tuple[str, int | None] | None:
    """Key family of a private key file, or None if it isn't one."""
    m = PEM_RE.search(text)
    if not m:
        return None
    label, body = m.group(1), m.group(2)
    if label in PEM_TYPES:
        return PEM_TYPES[label], None
    if label == "OPENSSH PRIVATE KEY":
        raw = base64.b64decode("".join(body.split()))
        if not raw.startswith(b"openssh-key-v1\0"):
            return "unknown", None
        pos = len(b"openssh-key-v1\0")
        for _ in range(3):  # cipher, kdf, kdf options
            _, pos = _read_string(raw, pos)
        pos += 4  # number of keys
        pubblob, _ = _read_string(raw, pos)  # public half, stored in the clear
        return key_from_blob(pubblob)
    if label == "PRIVATE KEY":  # unencrypted PKCS#8
        raw = base64.b64decode("".join(body.split()))
        for oid, family in (
            (bytes.fromhex("2a864886f70d010101"), "RSA"),
            (bytes.fromhex("2a8648ce3d0201"), "EC"),
            (bytes.fromhex("2b6570"), "Ed25519"),
        ):
            if oid in raw[:40]:
                return family, None
        return "unknown", None
    if label == "ENCRYPTED PRIVATE KEY":
        return "unknown", None
    return None
