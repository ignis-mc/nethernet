"""Just enough X.509 for WebRTC's self-signed DTLS certificates.

WebRTC peers authenticate each other by the certificate fingerprint carried
in the SDP, so no chain building or name checking happens here. This module
creates a self-signed ECDSA P-256 certificate and extracts the public key
from a peer's certificate.
"""

from ..wire import Reader, bytes_equal, put_bytes
from .der import (
    DER_BIT_STRING,
    DER_CONTEXT_0,
    DER_GENERALIZED_TIME,
    DER_INTEGER,
    DER_OID,
    DER_SEQUENCE,
    DER_SET,
    DER_UTC_TIME,
    DER_UTF8_STRING,
    der_expect,
    der_next,
    der_put,
    der_put_unsigned,
)
from .ecdsa_der import ecdsa_signature_to_der
from .p256 import p256_public_key, p256_sign
from .sha256 import sha256

comptime KEY_ALGORITHM_UNKNOWN = 0
"""A public-key algorithm this library cannot verify with."""
comptime KEY_ALGORITHM_EC_P256 = 1
"""An elliptic-curve key on NIST P-256 (secp256r1)."""
comptime KEY_ALGORITHM_EC_P384 = 2
"""An elliptic-curve key on NIST P-384 (secp384r1)."""


def _oid_ecdsa_with_sha256() -> List[UInt8]:
    return [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]


def _oid_ec_public_key() -> List[UInt8]:
    return [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]


def _oid_prime256v1() -> List[UInt8]:
    return [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]


def _oid_secp384r1() -> List[UInt8]:
    return [0x2B, 0x81, 0x04, 0x00, 0x22]


def _oid_common_name() -> List[UInt8]:
    return [0x55, 0x04, 0x03]


@fieldwise_init
struct PublicKeyInfo(Copyable):
    """A public key extracted from a certificate or a PKIX structure."""

    var algorithm: Int
    """One of the `KEY_ALGORITHM_*` constants."""
    var key: List[UInt8]
    """The key bytes: an uncompressed SEC1 point for elliptic-curve keys."""


def _two_digits(mut out: List[UInt8], v: Int):
    out.append(UInt8(0x30 + (v // 10) % 10))
    out.append(UInt8(0x30 + v % 10))


def _put_time(mut out: List[UInt8], unix_s: Int):
    """Appends a UTCTime (or GeneralizedTime from 2050) for a Unix time."""
    var days = unix_s // 86400
    var rem = unix_s % 86400
    # Civil-from-days (Howard Hinnant's algorithm), valid for the Gregorian
    # calendar.
    var z = days + 719468
    var era = z // 146097
    var doe = z - era * 146097
    var yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    var year = yoe + era * 400
    var doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    var mp = (5 * doy + 2) // 153
    var day = doy - (153 * mp + 2) // 5 + 1
    var month = mp + 3 if mp < 10 else mp - 9
    if month <= 2:
        year += 1
    var text = List[UInt8]()
    var tag = UInt8(DER_UTC_TIME)
    if year >= 2050:
        tag = DER_GENERALIZED_TIME
        _two_digits(text, year // 100)
    _two_digits(text, year % 100)
    _two_digits(text, month)
    _two_digits(text, day)
    _two_digits(text, rem // 3600)
    _two_digits(text, (rem % 3600) // 60)
    _two_digits(text, rem % 60)
    text.append(0x5A)
    der_put(out, tag, Span(text))


def _put_name(mut out: List[UInt8], common_name: StringSpan):
    var oid = _oid_common_name()
    var atv = List[UInt8]()
    der_put(atv, DER_OID, Span(oid))
    der_put(atv, DER_UTF8_STRING, common_name.as_bytes())
    var rdn = List[UInt8]()
    der_put(rdn, DER_SEQUENCE, Span(atv))
    var name = List[UInt8]()
    der_put(name, DER_SET, Span(rdn))
    der_put(out, DER_SEQUENCE, Span(name))


def _put_ecdsa_sha256_algorithm(mut out: List[UInt8]):
    var oid = _oid_ecdsa_with_sha256()
    var alg = List[UInt8]()
    der_put(alg, DER_OID, Span(oid))
    der_put(out, DER_SEQUENCE, Span(alg))


def encode_ec_public_key_info(
    algorithm: Int, point: Span[UInt8, _]
) raises -> List[UInt8]:
    """Encodes an elliptic-curve key as a PKIX SubjectPublicKeyInfo."""
    var curve: List[UInt8]
    if algorithm == KEY_ALGORITHM_EC_P256:
        curve = _oid_prime256v1()
    elif algorithm == KEY_ALGORITHM_EC_P384:
        curve = _oid_secp384r1()
    else:
        raise Error("unsupported public-key algorithm")
    var ec = _oid_ec_public_key()
    var alg = List[UInt8]()
    der_put(alg, DER_OID, Span(ec))
    der_put(alg, DER_OID, Span(curve))
    var bits = List[UInt8]()
    bits.append(0)
    put_bytes(bits, point)
    var body = List[UInt8]()
    der_put(body, DER_SEQUENCE, Span(alg))
    der_put(body, DER_BIT_STRING, Span(bits))
    var out = List[UInt8]()
    der_put(out, DER_SEQUENCE, Span(body))
    return out^


def _parse_spki_body(body: Span[UInt8, _]) raises -> PublicKeyInfo:
    var r = Reader(body)
    var alg = Reader(der_expect(r, DER_SEQUENCE))
    var oid = der_expect(alg, DER_OID)
    var bits = der_expect(r, DER_BIT_STRING)
    if len(bits) < 1 or bits[0] != 0:
        raise Error("X.509: unsupported BIT STRING padding")
    var key = List[UInt8](bits[1 : len(bits)])
    var ec = _oid_ec_public_key()
    if not bytes_equal(oid, Span(ec)):
        return PublicKeyInfo(KEY_ALGORITHM_UNKNOWN, key^)
    var curve = der_expect(alg, DER_OID)
    var p256 = _oid_prime256v1()
    var p384 = _oid_secp384r1()
    if bytes_equal(curve, Span(p256)):
        return PublicKeyInfo(KEY_ALGORITHM_EC_P256, key^)
    if bytes_equal(curve, Span(p384)):
        return PublicKeyInfo(KEY_ALGORITHM_EC_P384, key^)
    return PublicKeyInfo(KEY_ALGORITHM_UNKNOWN, key^)


def parse_public_key_info(der: Span[UInt8, _]) raises -> PublicKeyInfo:
    """Decodes a PKIX SubjectPublicKeyInfo."""
    var r = Reader(der)
    return _parse_spki_body(der_expect(r, DER_SEQUENCE))


def certificate_public_key(cert_der: Span[UInt8, _]) raises -> PublicKeyInfo:
    """Extracts the subject public key from an X.509 certificate.

    Nothing else about the certificate is validated: WebRTC trusts the
    certificate by its fingerprint.
    """
    var r = Reader(cert_der)
    var cert = Reader(der_expect(r, DER_SEQUENCE))
    var tbs = Reader(der_expect(cert, DER_SEQUENCE))
    var first = der_next(tbs)
    if first.tag == DER_CONTEXT_0:
        _ = der_expect(tbs, DER_INTEGER)
    elif first.tag != DER_INTEGER:
        raise Error("X.509: unexpected field before serial number")
    _ = der_expect(tbs, DER_SEQUENCE)  # signature algorithm
    _ = der_expect(tbs, DER_SEQUENCE)  # issuer
    _ = der_expect(tbs, DER_SEQUENCE)  # validity
    _ = der_expect(tbs, DER_SEQUENCE)  # subject
    return _parse_spki_body(der_expect(tbs, DER_SEQUENCE))


def self_signed_certificate(
    private_key: Span[UInt8, _],
    serial: Span[UInt8, _],
    not_before_unix_s: Int,
    not_after_unix_s: Int,
    common_name: StringSpan,
) raises -> List[UInt8]:
    """Creates a self-signed ECDSA P-256 certificate with SHA-256."""
    var point = p256_public_key(private_key)
    var tbs = List[UInt8]()
    var version: List[UInt8] = [0x02, 0x01, 0x02]
    der_put(tbs, DER_CONTEXT_0, Span(version))
    var serial_bytes = List[UInt8](serial)
    if len(serial_bytes) == 0:
        serial_bytes.append(1)
    serial_bytes[0] &= 0x7F
    if serial_bytes[0] == 0:
        serial_bytes[0] = 1
    der_put_unsigned(tbs, Span(serial_bytes))
    _put_ecdsa_sha256_algorithm(tbs)
    _put_name(tbs, common_name)
    var validity = List[UInt8]()
    _put_time(validity, not_before_unix_s)
    _put_time(validity, not_after_unix_s)
    der_put(tbs, DER_SEQUENCE, Span(validity))
    _put_name(tbs, common_name)
    var spki = encode_ec_public_key_info(KEY_ALGORITHM_EC_P256, Span(point))
    put_bytes(tbs, Span(spki))

    var tbs_der = List[UInt8]()
    der_put(tbs_der, DER_SEQUENCE, Span(tbs))
    var digest = sha256(Span(tbs_der))
    var raw_sig = p256_sign(private_key, Span(digest))
    var sig_der = ecdsa_signature_to_der(Span(raw_sig))
    var sig_bits = List[UInt8]()
    sig_bits.append(0)
    put_bytes(sig_bits, Span(sig_der))

    var body = List[UInt8]()
    put_bytes(body, Span(tbs_der))
    _put_ecdsa_sha256_algorithm(body)
    der_put(body, DER_BIT_STRING, Span(sig_bits))
    var out = List[UInt8]()
    der_put(out, DER_SEQUENCE, Span(body))
    return out^


def certificate_fingerprint(cert_der: Span[UInt8, _]) -> String:
    """Formats the SHA-256 fingerprint of a certificate as SDP expects."""
    var digest = sha256(cert_der)
    var digits = "0123456789ABCDEF".as_bytes()
    var out = List[UInt8]()
    for i in range(32):
        if i > 0:
            out.append(0x3A)
        out.append(digits[Int(digest[i] >> 4)])
        out.append(digits[Int(digest[i] & 0xF)])
    return String(unsafe_from_utf8=Span(out))
