"""Just enough DER/X.509 parsing to answer: what kind of public key is in this cert?

Hand-rolled on purpose so the tool needs nothing beyond the standard library.
"""

import base64
import hashlib
import re
from dataclasses import dataclass

# Algorithm OIDs (DER-encoded content bytes) -> family name
KEY_OIDS = {
    bytes.fromhex("2a864886f70d010101"): "RSA",
    bytes.fromhex("2a864886f70d01010a"): "RSA",  # RSASSA-PSS
    bytes.fromhex("2a8648ce380401"): "DSA",
    bytes.fromhex("2a8648ce3d0201"): "EC",
    bytes.fromhex("2b6570"): "Ed25519",
    bytes.fromhex("2b6571"): "Ed448",
    bytes.fromhex("608648016503040311"): "ML-DSA",
    bytes.fromhex("608648016503040312"): "ML-DSA",
    bytes.fromhex("608648016503040313"): "ML-DSA",
}
OID_COMMON_NAME = bytes.fromhex("550403")
OID_ORG = bytes.fromhex("55040a")

PEM_CERT_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", re.S
)


@dataclass
class CertInfo:
    subject: str
    issuer: str
    key_type: str  # RSA, EC, Ed25519, ...
    key_bits: int | None
    not_after: str
    sha1: str  # hex, matches `security find-identity` output


def _tlv(data: bytes, pos: int) -> tuple[int, int, int]:
    """Return (tag, content_start, content_end) for the element at pos."""
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[pos : pos + n], "big")
        pos += n
    return tag, pos, pos + length


def _children(data: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    out = []
    pos = start
    while pos < end:
        tag, cs, ce = _tlv(data, pos)
        out.append((tag, cs, ce))
        pos = ce
    return out


def _name(data: bytes, start: int, end: int) -> str:
    """Pull CN (falling back to O) out of an X.509 Name."""
    found = {}
    for _, rs, re_ in _children(data, start, end):  # RDN SETs
        for _, as_, ae in _children(data, rs, re_):  # AttributeTypeAndValue
            (_, os_, oe), (_, vs, ve) = _children(data, as_, ae)[:2]
            found.setdefault(data[os_:oe], data[vs:ve].decode("utf-8", "replace"))
    return found.get(OID_COMMON_NAME) or found.get(OID_ORG) or "(unnamed)"


def _time(raw: bytes, tag: int) -> str:
    s = raw.decode()
    if tag == 0x17:  # UTCTime YYMMDD...
        year = int(s[:2])
        s = f"{1900 + year if year >= 50 else 2000 + year}{s[2:]}"
    return f"{s[0:4]}-{s[4:6]}-{s[6:8]}"


def parse_cert(der: bytes) -> CertInfo:
    _, cs, ce = _tlv(der, 0)
    _, ts, te = _children(der, cs, ce)[0]  # tbsCertificate
    fields = _children(der, ts, te)
    if fields[0][0] == 0xA0:  # explicit version tag
        fields = fields[1:]
    # serial, signature, issuer, validity, subject, spki
    issuer = _name(der, fields[2][1], fields[2][2])
    validity = _children(der, fields[3][1], fields[3][2])
    not_after = _time(der[validity[1][1] : validity[1][2]], validity[1][0])
    subject = _name(der, fields[4][1], fields[4][2])

    _, ss, se = fields[5]
    (_, als, ale), (_, bs, be) = _children(der, ss, se)
    _, os_, oe = _children(der, als, ale)[0]
    key_type = KEY_OIDS.get(der[os_:oe], "unknown")

    bits = None
    if key_type == "RSA":
        # BIT STRING: one unused-bits byte, then SEQUENCE { modulus, exponent }
        _, ks, ke = _tlv(der, bs + 1)
        _, ms, me = _children(der, ks, ke)[0]
        bits = int.from_bytes(der[ms:me], "big").bit_length()
    elif key_type == "EC":
        # params OID names the curve; key length is enough for a summary
        bits = {65: 256, 97: 384, 133: 521}.get(be - bs - 1)

    return CertInfo(
        subject=subject,
        issuer=issuer,
        key_type=key_type,
        key_bits=bits,
        not_after=not_after,
        sha1=hashlib.sha1(der).hexdigest().upper(),
    )


def certs_from_pem(blob: bytes) -> list[bytes]:
    return [base64.b64decode(m) for m in PEM_CERT_RE.findall(blob)]
