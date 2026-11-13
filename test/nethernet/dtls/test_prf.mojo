from nethernet.dtls.prf import prf_sha256
from nethernet.wire import hex_decode, hex_encode
from std.testing import TestSuite, assert_equal


def test_prf_sha256_known_answer() raises:
    # Widely used TLS 1.2 PRF vector (IETF TLS list, "test label").
    var secret = hex_decode("9bbe436ba940f017b17652849a71db35")
    var seed = hex_decode("a0ba9f936cda311827a6f796ffd5198c")
    var out = prf_sha256(Span(secret), "test label", Span(seed), 100)
    assert_equal(
        hex_encode(Span(out)),
        "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66",
    )


def test_prf_lengths() raises:
    var secret = hex_decode("0102030405")
    var seed = hex_decode("aabbcc")
    for n in [0, 1, 12, 31, 32, 33, 48, 64, 65]:
        var out = prf_sha256(Span(secret), "key expansion", Span(seed), n)
        assert_equal(len(out), n)
    var short = prf_sha256(Span(secret), "x", Span(seed), 12)
    var long = prf_sha256(Span(secret), "x", Span(seed), 48)
    assert_equal(hex_encode(Span(short)), hex_encode(Span(long)[0:12]))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
