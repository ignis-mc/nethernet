from nethernet.crypto.base64 import (
    base64_decode,
    base64_encode,
    base64url_decode,
    base64url_encode,
)
from nethernet.crypto.p256 import p256_private_key_from_bytes, p256_public_key
from nethernet.crypto.p384 import p384_private_key_from_bytes, p384_public_key
from nethernet.crypto.x509 import (
    KEY_ALGORITHM_EC_P256,
    encode_ec_public_key_info,
)
from nethernet.json import json_parse_object, json_parse_string
from nethernet.signaling.identity import (
    IDENTITY_DOMAIN_CLIENT,
    IDENTITY_DOMAIN_SERVER,
    Identity,
    RemoteIdentity,
    fingerprint_payload,
)
from nethernet.wire import hex_encode, string_of
from std.testing import (
    TestSuite,
    assert_equal,
    assert_false,
    assert_raises,
    assert_true,
)

comptime NOW = 1_800_000_000
comptime DIGEST: StaticString = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89"


def _key(tag: UInt8) raises -> List[UInt8]:
    var seed = List[UInt8]()
    for i in range(56):
        seed.append(UInt8((i * 31 + Int(tag) * 17 + 5) & 0xFF))
    var key = p384_private_key_from_bytes(Span(seed))
    return List[UInt8](Span(key))


def test_fingerprint_payload() raises:
    assert_equal(
        fingerprint_payload("sha-256", "AA:BB"),
        '{"fingerprint":[{"algorithm":"sha-256","digest":"AA:BB"}]}',
    )


def test_server_identity_round_trip() raises:
    var key = _key(1)
    var id = Identity.self_signed(Span(key), IDENTITY_DOMAIN_SERVER, NOW, True)
    var value = id.sign("sha-256", DIGEST)
    var remote = RemoteIdentity.parse(value)
    assert_true(remote.is_valid())
    assert_equal(remote.domain, "self")
    assert_equal(remote.protocol, "default")
    var public_key = remote.public_key(True, NOW)
    var expected = p384_public_key(Span(key))
    assert_equal(hex_encode(Span(public_key)), hex_encode(Span(expected)))
    remote.verify("sha-256", DIGEST, Span(public_key))

    # The document has the shape go-nethernet writes.
    var document = json_parse_object(string_of(Span(base64_decode(value))))
    var assertion = json_parse_object(json_parse_string(document["assertion"]))
    var fingerprints = json_parse_string(assertion["fingerprints"])
    assert_true(".." in fingerprints)
    var header_b64 = String(fingerprints.split(".")[0])
    assert_equal(
        string_of(Span(base64url_decode(header_b64))), '{"alg":"ES384"}'
    )
    var token = json_parse_string(assertion["token"])
    var token_parts = token.split(".")
    var token_header = json_parse_object(
        string_of(Span(base64url_decode(String(token_parts[0]))))
    )
    assert_equal(json_parse_string(token_header["alg"]), "ES384")
    assert_true("x5u" in token_header)
    var claims = json_parse_object(
        string_of(Span(base64url_decode(String(token_parts[1]))))
    )
    assert_true(claims["cpk"].startswith("{"))
    assert_equal(claims["iat"], String(NOW))
    assert_equal(claims["exp"], String(NOW + 60))


def test_client_identity_uses_pkix_cpk() raises:
    var key = _key(2)
    var id = Identity.self_signed(Span(key), IDENTITY_DOMAIN_CLIENT, NOW, False)
    var remote = RemoteIdentity.parse(id.sign("sha-256", DIGEST))
    assert_equal(
        remote.domain, "https://authorization.franchise.minecraft-services.net/"
    )
    var parts = remote.token.split(".")
    var claims = json_parse_object(
        string_of(Span(base64url_decode(String(parts[1]))))
    )
    assert_true(claims["cpk"].startswith('"'))
    # Listener-style check: time claims only.
    var public_key = remote.public_key(False, NOW + 30)
    remote.verify("sha-256", DIGEST, Span(public_key))
    # Dialer-style check works on the same token.
    var again = remote.public_key(True, NOW + 100000)
    assert_equal(hex_encode(Span(again)), hex_encode(Span(public_key)))


def test_time_claims() raises:
    var key = _key(3)
    var id = Identity.self_signed(Span(key), IDENTITY_DOMAIN_CLIENT, NOW, False)
    var remote = RemoteIdentity.parse(id.sign("sha-256", DIGEST))
    _ = remote.public_key(False, NOW)
    _ = remote.public_key(False, NOW + 60 + 60)
    with assert_raises(contains="expired"):
        _ = remote.public_key(False, NOW + 60 + 61)
    _ = remote.public_key(False, NOW - 60)
    with assert_raises(contains="future"):
        _ = remote.public_key(False, NOW - 61)


def test_wrong_fingerprint_or_key_is_rejected() raises:
    var key = _key(4)
    var id = Identity.self_signed(Span(key), IDENTITY_DOMAIN_SERVER, NOW, True)
    var remote = RemoteIdentity.parse(id.sign("sha-256", DIGEST))
    var public_key = remote.public_key(True, NOW)
    var other_digest = String(DIGEST).replace("AB:CD", "AB:CE")
    with assert_raises(contains="mismatch"):
        remote.verify("sha-256", other_digest, Span(public_key))
    # The payload is case-sensitive: sign the exact text that is sent.
    with assert_raises(contains="mismatch"):
        remote.verify("sha-256", String(DIGEST).lower(), Span(public_key))
    with assert_raises(contains="mismatch"):
        remote.verify("SHA-256", DIGEST, Span(public_key))
    var other_key = _key(5)
    var other_public = p384_public_key(Span(other_key))
    with assert_raises(contains="mismatch"):
        remote.verify("sha-256", DIGEST, Span(other_public))


def test_token_must_be_signed_by_its_key() raises:
    var key = _key(6)
    var other = _key(7)
    var real = Identity.self_signed(
        Span(key), IDENTITY_DOMAIN_SERVER, NOW, True
    )
    var forged_token = Identity.self_signed(
        Span(other), IDENTITY_DOMAIN_SERVER, NOW, True
    )
    # Splice: claims of `key` with the signature of `other`.
    var a = real.token.split(".")
    var b = forged_token.token.split(".")
    var spliced = Identity(Span(key), String(t"{a[0]}.{a[1]}.{b[2]}"), "self")
    var remote = RemoteIdentity.parse(spliced.sign("sha-256", DIGEST))
    with assert_raises(contains="not signed by its own key"):
        _ = remote.public_key(True, NOW)
    # Without the self-signed check the key is still extracted.
    _ = remote.public_key(False, NOW)


def _with_claims(key: List[UInt8], claims: StringSpan) raises -> RemoteIdentity:
    """Builds an assertion whose token carries hand-written claims."""
    var header = base64url_encode('{"alg":"ES384"}'.as_bytes())
    var token = String(t"{header}.{base64url_encode(claims.as_bytes())}.AAAA")
    var id = Identity(Span(key), token, "self")
    return RemoteIdentity.parse(id.sign("sha-256", DIGEST))


def test_unsupported_keys_are_rejected() raises:
    # Mirrors go-nethernet's TestParsePublicKey: only P-384 keys are usable.
    var key = _key(8)
    var rsa = _with_claims(key, '{"cpk":{"kty":"RSA","n":"AQAB","e":"AQAB"}}')
    with assert_raises(contains="unsupported key"):
        _ = rsa.public_key(False, NOW)
    var symmetric = _with_claims(key, '{"cpk":{"kty":"oct","k":"AAAA"}}')
    with assert_raises(contains="unsupported key"):
        _ = symmetric.public_key(False, NOW)
    var p256 = _with_claims(
        key, '{"cpk":{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}}'
    )
    with assert_raises(contains="unsupported key"):
        _ = p256.public_key(False, NOW)
    var short_point = _with_claims(
        key, '{"cpk":{"kty":"EC","crv":"P-384","x":"AA","y":"AA"}}'
    )
    with assert_raises(contains="malformed key"):
        _ = short_point.public_key(False, NOW)
    var missing = _with_claims(key, '{"iat":1}')
    with assert_raises(contains="no cpk"):
        _ = missing.public_key(False, NOW)
    var not_pkix = _with_claims(key, '{"cpk":"AAAA"}')
    with assert_raises():
        _ = not_pkix.public_key(False, NOW)
    # A P-256 key in PKIX form is the wrong curve.
    var p256_seed = List[UInt8](length=40, fill=9)
    var p256_private = p256_private_key_from_bytes(Span(p256_seed))
    var p256_point = p256_public_key(Span(p256_private))
    var p256_pkix = encode_ec_public_key_info(
        KEY_ALGORITHM_EC_P256, Span(p256_point)
    )
    var wrong_curve = _with_claims(
        key, String(t"{{\"cpk\":\"{base64_encode(Span(p256_pkix))}\"}}")
    )
    with assert_raises(contains="unsupported key"):
        _ = wrong_curve.public_key(False, NOW)


def test_parse_rejects_malformed() raises:
    with assert_raises():
        _ = RemoteIdentity.parse("not base64!")
    with assert_raises():
        _ = RemoteIdentity.parse(base64_encode("{}".as_bytes()))
    with assert_raises(contains="malformed"):
        _ = RemoteIdentity.parse(
            base64_encode(
                '{"assertion":"{\\"fingerprints\\":\\"a.b\\",\\"token\\":\\"a.b.c\\"}","idp":{"domain":"self","protocol":"default"}}'
                .as_bytes()
            )
        )
    with assert_raises(contains="malformed"):
        _ = RemoteIdentity.parse(
            base64_encode(
                '{"assertion":"{\\"fingerprints\\":\\"a..c\\",\\"token\\":\\"a.b.c\\"}","idp":{"domain":"self","protocol":"other"}}'
                .as_bytes()
            )
        )
    var shaped = RemoteIdentity.parse(
        base64_encode(
            '{"assertion":"{\\"fingerprints\\":\\"a..c\\",\\"token\\":\\"a.b.c\\"}","idp":{"domain":"self","protocol":"default"}}'
            .as_bytes()
        )
    )
    assert_true(shaped.is_valid())
    with assert_raises():
        _ = shaped.public_key(True, NOW)
    var empty = RemoteIdentity()
    assert_false(empty.is_valid())


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
