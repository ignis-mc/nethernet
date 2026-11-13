from nethernet.sctp.cause import (
    CAUSE_UNRECOGNIZED_CHUNK,
    CAUSE_USER_INITIATED_ABORT,
    ErrorCause,
    decode_causes,
    encode_abort,
    encode_error,
)
from nethernet.sctp.packet import parse_packet
from nethernet.wire import hex_decode, hex_encode, string_of
from std.testing import TestSuite, assert_equal, assert_raises, assert_true

# Packets recorded from pion/sctp v1.12.0 (two associations over a pipe).
comptime A_ABORT = "13881388aa764be4a9a60bbd0600000b000c000762796500"


def _chunk(packet: List[UInt8], index: Int) raises -> List[UInt8]:
    """Returns chunk `index` of a packet: header, value and padding."""
    var view = parse_packet(Span(packet))
    var ref_ = view.chunks[index]
    var end = ref_.offset + ref_.length
    while end % 4 != 0 and end < len(packet):
        end += 1
    return List[UInt8](Span(packet)[ref_.offset - 4 : end])


def _value(packet: List[UInt8], index: Int) raises -> List[UInt8]:
    var view = parse_packet(Span(packet))
    var ref_ = view.chunks[index]
    return List[UInt8](Span(packet)[ref_.offset : ref_.offset + ref_.length])


def test_abort_matches_pion() raises:
    var p = hex_decode(A_ABORT)
    var causes = decode_causes(Span(_value(p, 0)))
    assert_equal(len(causes), 1)
    assert_true(causes[0].code == CAUSE_USER_INITIATED_ABORT)
    assert_equal(string_of(Span(causes[0].info)), "bye")
    var out = List[UInt8]()
    encode_abort(out, False, Span(causes))
    assert_equal(hex_encode(Span(out)), hex_encode(Span(_chunk(p, 0))))
    var reflected = List[UInt8]()
    var none = List[ErrorCause]()
    encode_abort(reflected, True, Span(none))
    assert_equal(hex_encode(Span(reflected)), "06010004")
    # pion's Stop(): an ABORT with one empty user-initiated cause.
    var stop = hex_decode("000c0004")
    var sc = decode_causes(Span(stop))
    assert_equal(len(sc), 1)
    assert_equal(len(sc[0].info), 0)
    var bad = hex_decode("000c0009aabb")
    with assert_raises():
        _ = decode_causes(Span(bad))


def test_error_chunk() raises:
    var err = List[UInt8]()
    var causes: List[ErrorCause] = []
    var unrec = hex_decode("40000004")
    causes.append(ErrorCause(CAUSE_UNRECOGNIZED_CHUNK, Span(unrec)))
    encode_error(err, Span(causes))
    assert_equal(hex_encode(Span(err)), "0900000c0006000840000004")
    var back = decode_causes(Span(err)[4:12])
    assert_equal(len(back), 1)
    assert_true(back[0].code == CAUSE_UNRECOGNIZED_CHUNK)
    assert_equal(hex_encode(Span(back[0].info)), "40000004")
    # Two causes: the first is padded, the last is not counted as padded.
    var two: List[ErrorCause] = []
    var a = hex_decode("aa")
    var b = hex_decode("bbcc")
    two.append(ErrorCause(1, Span(a)))
    two.append(ErrorCause(2, Span(b)))
    var out = List[UInt8]()
    encode_error(out, Span(two))
    assert_equal(hex_encode(Span(out)), "0900001200010005aa00000000020006bbcc0000")
    var parsed = decode_causes(Span(out)[4:18])
    assert_equal(len(parsed), 2)
    assert_equal(parsed[1].code, 2)
    assert_equal(len(parsed[1].info), 2)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
