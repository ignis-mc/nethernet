from nethernet.datachannel.dcep import (
    CHANNEL_PARTIAL_RELIABLE_REXMIT_UNORDERED,
    CHANNEL_RELIABLE,
    ChannelOpen,
    encode_dcep_ack,
    is_dcep_ack,
)
from nethernet.wire import hex_decode, hex_encode
from std.testing import TestSuite, assert_equal, assert_false, assert_raises, assert_true

# The exact bytes pion sends for NetherNet's two channels.
comptime PION_RELIABLE_OPEN = "03000100000000000013000052656c6961626c65446174614368616e6e656c"
comptime PION_UNRELIABLE_OPEN = "038101000000000000150000556e72656c6961626c65446174614368616e6e656c"


def test_encode_matches_pion() raises:
    var a = List[UInt8]()
    ChannelOpen.reliable().encode(a)
    assert_equal(hex_encode(Span(a)), PION_RELIABLE_OPEN)
    assert_equal(len(a), 31)
    var b = List[UInt8]()
    ChannelOpen.unreliable().encode(b)
    assert_equal(hex_encode(Span(b)), PION_UNRELIABLE_OPEN)
    assert_equal(len(b), 33)


def test_decode_pion_bytes() raises:
    var raw = hex_decode(PION_RELIABLE_OPEN)
    var open = ChannelOpen.decode(Span(raw))
    assert_equal(open.channel_type, CHANNEL_RELIABLE)
    assert_equal(open.priority, 256)
    assert_equal(open.label, "ReliableDataChannel")
    assert_equal(open.protocol, "")
    assert_false(open.is_unordered())
    assert_equal(open.max_retransmits(), -1)

    var raw2 = hex_decode(PION_UNRELIABLE_OPEN)
    var open2 = ChannelOpen.decode(Span(raw2))
    assert_equal(open2.channel_type, CHANNEL_PARTIAL_RELIABLE_REXMIT_UNORDERED)
    assert_equal(open2.reliability, 0)
    assert_equal(open2.label, "UnreliableDataChannel")
    assert_true(open2.is_unordered())
    assert_equal(open2.max_retransmits(), 0)


def test_decode_rejects_malformed() raises:
    var raw = hex_decode(PION_RELIABLE_OPEN)
    with assert_raises():
        _ = ChannelOpen.decode(Span(raw)[0:20])
    var extra = raw.copy()
    extra.append(0)
    with assert_raises(contains="trailing"):
        _ = ChannelOpen.decode(Span(extra))
    var ack = hex_decode("02")
    with assert_raises(contains="not a DATA_CHANNEL_OPEN"):
        _ = ChannelOpen.decode(Span(ack))
    var empty = List[UInt8]()
    with assert_raises():
        _ = ChannelOpen.decode(Span(empty))


def test_ack() raises:
    var out = List[UInt8]()
    encode_dcep_ack(out)
    assert_equal(hex_encode(Span(out)), "02")
    assert_true(is_dcep_ack(Span(out)))
    var pion_ack = hex_decode("02000000")
    assert_true(is_dcep_ack(Span(pion_ack)))
    var open = hex_decode(PION_RELIABLE_OPEN)
    assert_false(is_dcep_ack(Span(open)))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
