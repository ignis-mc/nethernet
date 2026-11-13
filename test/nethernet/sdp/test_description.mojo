from nethernet.sdp.description import Description, parse_description
from nethernet.wire import hex_encode
from std.testing import TestSuite, assert_equal, assert_raises, assert_true


def _sample() -> Description:
    var d = Description()
    d.session_id = 1234567890123
    d.ice_ufrag = "abcdEFGHijklMNOP"
    d.ice_pwd = "abcdefghijklmnopqrstuvwxyzABCDEF"
    d.fingerprint = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89"
    d.setup = "actpass"
    return d^


def test_encode_matches_go_nethernet_layout() raises:
    var d = _sample()
    var expected = String(
        "v=0\r\n"
        "o=- 1234567890123 2 IN IP4 127.0.0.1\r\n"
        "s=-\r\n"
        "t=0 0\r\n"
        "a=group:BUNDLE 0\r\n"
        "a=extmap-allow-mixed\r\n"
        "a=msid-semantic: WMS\r\n"
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
        "c=IN IP4 0.0.0.0\r\n"
        "a=ice-ufrag:abcdEFGHijklMNOP\r\n"
        "a=ice-pwd:abcdefghijklmnopqrstuvwxyzABCDEF\r\n"
        "a=ice-options:trickle\r\n"
        "a=fingerprint:sha-256 AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89\r\n"
        "a=setup:actpass\r\n"
        "a=mid:0\r\n"
        "a=sctp-port:5000\r\n"
        "a=max-message-size:262144\r\n"
    )
    assert_equal(d.encode(), expected)


def test_encode_with_candidates_and_identity() raises:
    var d = _sample()
    d.identity = "eyJhc3NlcnRpb24iOiJ4In0="
    d.candidates.append(
        "3288563104 1 udp 2130706431 192.168.1.20 45000 typ host generation 0 ufrag abcdEFGHijklMNOP network-id 0 network-cost 0"
    )
    var text = d.encode()
    assert_true("a=identity:eyJhc3NlcnRpb24iOiJ4In0=\r\nm=application 45000 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 192.168.1.20\r\na=candidate:3288563104 1 udp" in text)
    var back = parse_description(text)
    assert_equal(back.identity, "eyJhc3NlcnRpb24iOiJ4In0=")
    assert_equal(len(back.candidates), 1)
    assert_true(back.candidates[0].startswith("3288563104 1 udp 2130706431 192.168.1.20 45000 typ host"))


def test_round_trip() raises:
    var d = _sample()
    d.setup = "active"
    var back = parse_description(d.encode())
    assert_equal(back.session_id, 1234567890123)
    assert_equal(back.ice_ufrag, d.ice_ufrag)
    assert_equal(back.ice_pwd, d.ice_pwd)
    assert_equal(back.fingerprint_algorithm, "sha-256")
    assert_equal(back.fingerprint, d.fingerprint)
    assert_equal(back.setup, "active")
    assert_equal(back.max_message_size, 262144)
    assert_equal(len(back.candidates), 0)
    var digest = back.fingerprint_bytes()
    assert_equal(len(digest), 32)
    assert_equal(hex_encode(Span(digest)[0:4]), "abcdef01")


def test_parse_lf_endings_and_session_fingerprint() raises:
    var text = String(
        "v=0\n"
        "o=- 42 2 IN IP4 127.0.0.1\n"
        "s=-\n"
        "t=0 0\n"
        "a=fingerprint:SHA-256 01:02\n"
        "a=candidate:1 1 udp 2130706431 10.0.0.1 1000 typ host\n"
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\n"
        "c=IN IP4 0.0.0.0\n"
        "a=ice-ufrag:u\n"
        "a=ice-pwd:p\n"
        "a=setup:passive\n"
        "a=something-unknown:whatever\n"
        "a=max-message-size:1024\n"
    )
    var d = parse_description(text)
    assert_equal(d.fingerprint_algorithm, "sha-256")
    assert_equal(d.fingerprint, "01:02")
    assert_equal(d.setup, "passive")
    assert_equal(d.max_message_size, 1024)
    assert_equal(len(d.candidates), 1)
    assert_equal(d.session_id, 42)


def test_parse_rejects_bad_documents() raises:
    var good = _sample().encode()
    with assert_raises(contains="media section"):
        _ = parse_description("v=0\r\na=ice-ufrag:x\r\n")
    with assert_raises(contains="media section"):
        _ = parse_description(good + "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n")
    with assert_raises(contains="ICE credentials"):
        _ = parse_description(good.replace("a=ice-pwd:abcdefghijklmnopqrstuvwxyzABCDEF\r\n", ""))
    with assert_raises(contains="fingerprint"):
        _ = parse_description(good.replace("a=fingerprint:sha-256 ", "a=fingerprint:sha-256"))
    with assert_raises(contains="setup"):
        _ = parse_description(good.replace("a=setup:actpass", "a=setup:holdconn"))
    with assert_raises(contains="setup"):
        _ = parse_description(good.replace("a=setup:actpass\r\n", ""))
    with assert_raises(contains="max-message-size"):
        _ = parse_description(good.replace("a=max-message-size:262144", "a=max-message-size:1"))
    with assert_raises(contains="max-message-size"):
        _ = parse_description(good.replace("a=max-message-size:262144", "a=max-message-size:0"))
    with assert_raises():
        _ = parse_description(good.replace("a=max-message-size:262144", "a=max-message-size:abc"))
    var d = _sample()
    d.fingerprint = "ABCD"
    with assert_raises(contains="fingerprint"):
        _ = d.fingerprint_bytes()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
