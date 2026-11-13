from nethernet.os.addr import SocketAddr
from nethernet.stun.message import (
    STUN_ATTR_USE_CANDIDATE,
    STUN_BINDING_ERROR,
    STUN_BINDING_REQUEST,
    STUN_BINDING_SUCCESS,
    StunBuilder,
    is_stun,
    parse_stun,
    verify_fingerprint,
    verify_message_integrity,
)
from nethernet.wire import bytes_of, hex_decode, hex_encode
from std.testing import (
    TestSuite,
    assert_equal,
    assert_false,
    assert_raises,
    assert_true,
)


# RFC 5769 section 2.1: sample request, password "VOkJxbRl1RmTxUk/WvJxBt".
comptime RFC5769_REQUEST = "000100582112a442b7e7a701bc34d686fa87dfae802200105354554e207465737420636c69656e74002400046e0001ff80290008932ff9b151263b36000600096576746a3a68367659202020000800149aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a280280004e57a3bcf"
# RFC 5769 section 2.2: sample IPv4 response, mapped address 192.0.2.1:32853.
comptime RFC5769_RESPONSE = "0101003c2112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563746f7220002000080001a147e112a643000800142b91f599fd9e90c38c7489f92af9ba53f06be7d780280004c07d4c96"


def test_rfc5769_request() raises:
    var raw = hex_decode(RFC5769_REQUEST)
    assert_true(is_stun(Span(raw)))
    var msg = parse_stun(Span(raw))
    assert_equal(msg.msg_type, STUN_BINDING_REQUEST)
    assert_equal(msg.username().value(), "evtj:h6vY")
    assert_equal(msg.priority().value(), 0x6E0001FF)
    assert_equal(msg.ice_controlled().value(), 0x932FF9B151263B36)
    assert_true(msg.ice_controlling() is None)
    var key = bytes_of("VOkJxbRl1RmTxUk/WvJxBt")
    assert_true(verify_message_integrity(Span(raw), Span(key)))
    assert_true(verify_fingerprint(Span(raw)))
    var wrong = bytes_of("VOkJxbRl1RmTxUk/WvJxBu")
    assert_false(verify_message_integrity(Span(raw), Span(wrong)))
    raw[30] ^= 1
    assert_false(verify_fingerprint(Span(raw)))
    assert_false(verify_message_integrity(Span(raw), Span(key)))


def test_rfc5769_response() raises:
    var raw = hex_decode(RFC5769_RESPONSE)
    var msg = parse_stun(Span(raw))
    assert_equal(msg.msg_type, STUN_BINDING_SUCCESS)
    var addr = msg.xor_mapped_address().value()
    assert_equal(String(addr), "192.0.2.1:32853")
    var key = bytes_of("VOkJxbRl1RmTxUk/WvJxBt")
    assert_true(verify_message_integrity(Span(raw), Span(key)))
    assert_true(verify_fingerprint(Span(raw)))


def test_build_round_trip() raises:
    var tid = Array[UInt8, 12](fill=0)
    for i in range(12):
        tid[i] = UInt8(i + 1)
    var b = StunBuilder(STUN_BINDING_REQUEST, tid)
    b.add_username("remote:local")
    b.add_priority(1845501695)
    b.add_ice_controlling(0x0102030405060708)
    b.add_use_candidate()
    var key = bytes_of("the-remote-password")
    var raw = b.finish(Span(key))
    assert_true(is_stun(Span(raw)))
    assert_equal(len(raw) % 4, 0)
    var msg = parse_stun(Span(raw))
    assert_equal(msg.msg_type, STUN_BINDING_REQUEST)
    assert_equal(msg.username().value(), "remote:local")
    assert_equal(msg.priority().value(), 1845501695)
    assert_equal(msg.ice_controlling().value(), 0x0102030405060708)
    assert_true(msg.has(STUN_ATTR_USE_CANDIDATE))
    for i in range(12):
        assert_equal(msg.transaction_id[i], UInt8(i + 1))
    assert_true(verify_message_integrity(Span(raw), Span(key)))
    assert_true(verify_fingerprint(Span(raw)))


def test_build_matches_rfc5769_response() raises:
    # Rebuilding the RFC response without its SOFTWARE attribute must still
    # verify, and the XOR-MAPPED-ADDRESS encoding must match the vector.
    var tid = Array[UInt8, 12](fill=0)
    var raw_tid = hex_decode("b7e7a701bc34d686fa87dfae")
    for i in range(12):
        tid[i] = raw_tid[i]
    var b = StunBuilder(STUN_BINDING_SUCCESS, tid)
    b.add_xor_mapped_address(SocketAddr.v4(192, 0, 2, 1, 32853))
    var key = bytes_of("VOkJxbRl1RmTxUk/WvJxBt")
    var raw = b.finish(Span(key))
    assert_equal(hex_encode(Span(raw)[20:32]), "002000080001a147e112a643")
    assert_true(verify_message_integrity(Span(raw), Span(key)))
    assert_true(verify_fingerprint(Span(raw)))


def test_error_code_and_no_integrity() raises:
    var tid = Array[UInt8, 12](fill=7)
    var b = StunBuilder(STUN_BINDING_ERROR, tid)
    b.add_error_code(487, "Role Conflict")
    var empty = List[UInt8]()
    var raw = b.finish(Span(empty), fingerprint=False)
    var msg = parse_stun(Span(raw))
    assert_equal(msg.error_code().value(), 487)
    assert_false(verify_fingerprint(Span(raw)))
    assert_false(verify_message_integrity(Span(raw), Span(empty)))


def test_rejects_malformed() raises:
    var short = hex_decode("0001000021")
    assert_false(is_stun(Span(short)))
    var dtls = hex_decode("16feff000000000000000000360100002a000000000000002a")
    assert_false(is_stun(Span(dtls)))
    var raw = hex_decode(RFC5769_REQUEST)
    with assert_raises(contains="length"):
        _ = parse_stun(Span(raw)[0 : len(raw) - 4])
    # An attribute length that runs past the end.
    var bad = hex_decode(
        "000100082112a442000000000000000000000000000600ff61626364"
    )
    with assert_raises():
        _ = parse_stun(Span(bad))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
