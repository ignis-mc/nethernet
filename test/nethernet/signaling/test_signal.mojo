from nethernet.signaling.signal import (
    SIGNAL_ANSWER,
    SIGNAL_CANDIDATE,
    SIGNAL_ERROR,
    SIGNAL_OFFER,
    Signal,
    parse_signal,
)
from std.testing import TestSuite, assert_equal, assert_raises


def test_encode() raises:
    var s = Signal(SIGNAL_OFFER, 18446744073709551615, "v=0\r\n", "peer")
    assert_equal(s.encode(), "CONNECTREQUEST 18446744073709551615 v=0\r\n")
    assert_equal(String(s), "CONNECTREQUEST 18446744073709551615 v=0\r\n")
    var c = Signal(SIGNAL_CANDIDATE, 7, "candidate:1 1 udp 1 1.2.3.4 5 typ host", "peer")
    assert_equal(c.encode(), "CANDIDATEADD 7 candidate:1 1 udp 1 1.2.3.4 5 typ host")


def test_parse_valid() raises:
    var s = parse_signal("CONNECTRESPONSE 12345 v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\n", "9001")
    assert_equal(s.kind, SIGNAL_ANSWER)
    assert_equal(s.connection_id, 12345)
    assert_equal(s.data, "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\n")
    assert_equal(s.network_id, "9001")
    # Data may itself contain spaces; only the first two split.
    var c = parse_signal("CANDIDATEADD 5 candidate:1 1 udp 2130706431 10.0.0.1 1 typ host", "n")
    assert_equal(c.data, "candidate:1 1 udp 2130706431 10.0.0.1 1 typ host")
    # Empty data is allowed.
    var e = parse_signal("CONNECTERROR 5 ", "n")
    assert_equal(e.data, "")
    assert_equal(e.error_code(), 0)


def test_parse_go_nethernet_table() raises:
    # Cases from go-nethernet's signal_test.go.
    var a = parse_signal("CONNECTERROR 42junk -12suffix", "n")
    assert_equal(a.connection_id, 42)
    assert_equal(a.error_code(), -12)
    var b = parse_signal("CONNECTERROR 0x10 0x10", "n")
    assert_equal(b.connection_id, 0)
    assert_equal(b.error_code(), 0)
    var c = parse_signal("CONNECTERROR 1 37", "n")
    assert_equal(c.error_code(), 37)
    with assert_raises():
        _ = parse_signal("CONNECTERROR  1 2", "n")
    with assert_raises():
        _ = parse_signal("CONNECTERROR +1 2", "n")
    with assert_raises():
        _ = parse_signal("connecterror 1 2", "n")
    with assert_raises():
        _ = parse_signal("CONNECTERROR 18446744073709551616 2", "n")
    with assert_raises():
        _ = parse_signal("CONNECTERROR 1", "n")
    with assert_raises():
        _ = parse_signal("CONNECTERROR", "n")
    with assert_raises():
        _ = parse_signal("", "n")
    with assert_raises():
        _ = parse_signal("HELLO 1 2", "n")


def test_round_trip() raises:
    var s = Signal(SIGNAL_ERROR, 99, "15", "abc")
    var back = parse_signal(s.encode(), "abc")
    assert_equal(back.kind, SIGNAL_ERROR)
    assert_equal(back.connection_id, 99)
    assert_equal(back.error_code(), 15)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
