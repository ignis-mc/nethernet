from nethernet.ice.candidate import ICE_HOST_PRIORITY, IceCandidate, parse_candidate
from nethernet.os.addr import SocketAddr
from std.testing import TestSuite, assert_equal, assert_raises, assert_true


def test_parse_minimal() raises:
    var c = parse_candidate("1 1 udp 2130706431 192.168.1.10 40000 typ host")
    assert_equal(c.foundation, "1")
    assert_equal(c.component, 1)
    assert_equal(c.priority, 2130706431)
    assert_equal(String(c.addr), "192.168.1.10:40000")
    assert_equal(c.kind, "host")
    assert_true(c.related is None)


def test_parse_prefixed_and_extensions() raises:
    var line = "candidate:3288563104 1 udp 2130706431 10.0.0.5 51234 typ host generation 0 ufrag AbCd network-id 0 network-cost 0"
    var c = parse_candidate(line)
    assert_equal(c.foundation, "3288563104")
    assert_equal(String(c.addr), "10.0.0.5:51234")
    var d = parse_candidate("a=" + line)
    assert_equal(String(d.addr), "10.0.0.5:51234")
    var e = parse_candidate("  " + line + "  ")
    assert_equal(e.priority, 2130706431)


def test_parse_srflx_with_related() raises:
    var c = parse_candidate(
        "candidate:842163049 1 UDP 1694498815 203.0.113.7 3478 typ srflx raddr 192.168.1.2 rport 50000 generation 0"
    )
    assert_equal(c.kind, "srflx")
    assert_equal(String(c.related.value()), "192.168.1.2:50000")


def test_rejects_unusable() raises:
    with assert_raises(contains="transport"):
        _ = parse_candidate("1 1 tcp 1 192.168.1.10 9 typ host tcptype active")
    with assert_raises(contains="IPv4"):
        _ = parse_candidate("1 1 udp 1 fe80::1 40000 typ host")
    with assert_raises(contains="IPv4"):
        _ = parse_candidate("1 1 udp 1 abcd-ef.local 40000 typ host")
    with assert_raises(contains="few fields"):
        _ = parse_candidate("1 1 udp 1 192.168.1.10 40000")
    with assert_raises(contains="typ"):
        _ = parse_candidate("1 1 udp 1 192.168.1.10 40000 type host")
    with assert_raises(contains="type"):
        _ = parse_candidate("1 1 udp 1 192.168.1.10 40000 typ weird")
    with assert_raises():
        _ = parse_candidate("1 1 udp 99999999999 192.168.1.10 40000 typ host")
    with assert_raises():
        _ = parse_candidate("1 1 udp 1 192.168.1.10 70000 typ host")


def test_host_round_trip() raises:
    var c = IceCandidate.host(SocketAddr.v4(192, 168, 1, 20, 45000))
    assert_equal(c.priority, ICE_HOST_PRIORITY)
    var value = c.attribute_value("ufragXYZ", 0)
    assert_true(value.endswith(
        " 1 udp 2130706431 192.168.1.20 45000 typ host generation 0 ufrag ufragXYZ network-id 0 network-cost 0"
    ))
    var signal = c.signal_value("ufragXYZ", 2)
    assert_true(signal.startswith("candidate:"))
    assert_true(signal.endswith("network-id 2 network-cost 0"))
    var back = parse_candidate(signal)
    assert_equal(back.foundation, c.foundation)
    assert_true(back.addr == c.addr)
    assert_equal(back.kind, "host")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
