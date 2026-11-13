from nethernet.sctp.cookie import (
    COOKIE_SIZE,
    CookieData,
    decode_cookie,
    encode_cookie,
)
from nethernet.wire import bytes_of
from std.testing import (
    TestSuite,
    assert_equal,
    assert_false,
    assert_raises,
    assert_true,
)


def _sample() -> CookieData:
    var d = CookieData()
    d.peer_tag = 0xA1B2C3D4
    d.peer_initial_tsn = 0xFFFFFFFE
    d.peer_a_rwnd = 1048576
    d.peer_outbound_streams = 65535
    d.peer_inbound_streams = 1024
    d.peer_forward_tsn = True
    d.peer_reconfig = False
    d.local_tag = 0x01020304
    d.local_initial_tsn = 77
    d.created_ms = 123456789012
    return d


def test_round_trip() raises:
    var secret = bytes_of("a secret only this endpoint knows")
    var cookie = encode_cookie(_sample(), Span(secret))
    assert_equal(len(cookie), COOKIE_SIZE)
    var d = decode_cookie(Span(cookie), Span(secret))
    assert_equal(d.peer_tag, 0xA1B2C3D4)
    assert_equal(d.peer_initial_tsn, 0xFFFFFFFE)
    assert_equal(d.peer_a_rwnd, 1048576)
    assert_equal(d.peer_outbound_streams, 65535)
    assert_equal(d.peer_inbound_streams, 1024)
    assert_true(d.peer_forward_tsn)
    assert_false(d.peer_reconfig)
    assert_equal(d.local_tag, 0x01020304)
    assert_equal(d.local_initial_tsn, 77)
    assert_equal(d.created_ms, 123456789012)
    var other = _sample()
    other.peer_forward_tsn = False
    other.peer_reconfig = True
    var d2 = decode_cookie(
        Span(encode_cookie(other, Span(secret))), Span(secret)
    )
    assert_false(d2.peer_forward_tsn)
    assert_true(d2.peer_reconfig)


def test_tampering_is_detected() raises:
    var secret = bytes_of("k1")
    var cookie = encode_cookie(_sample(), Span(secret))
    # Every single-bit change, in the body or in the tag, is rejected.
    for i in range(len(cookie)):
        var bad = cookie.copy()
        bad[i] ^= 0x01
        with assert_raises():
            _ = decode_cookie(Span(bad), Span(secret))
    var wrong = bytes_of("k2")
    with assert_raises():
        _ = decode_cookie(Span(cookie), Span(wrong))


def test_wrong_size_is_rejected() raises:
    var secret = bytes_of("k1")
    var cookie = encode_cookie(_sample(), Span(secret))
    with assert_raises():
        _ = decode_cookie(Span(cookie)[0 : COOKIE_SIZE - 1], Span(secret))
    var longer = cookie.copy()
    longer.append(0)
    with assert_raises():
        _ = decode_cookie(Span(longer), Span(secret))
    var empty = List[UInt8]()
    with assert_raises():
        _ = decode_cookie(Span(empty), Span(secret))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
